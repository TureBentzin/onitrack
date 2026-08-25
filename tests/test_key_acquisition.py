import asyncio
import base64
import gzip
import plistlib
import struct
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

import onitrack.key_acquisition as acquisition
import onitrack.people as people_module
from onitrack.key_acquisition import (
    APNS_INTEREST_TOPICS,
    DirectoryIdentity,
    KeyAcquisitionError,
    KeyAcquisitionTimeout,
    PeopleKeyAcquirer,
    VerifiedKeyDelivery,
    decrypt_pair_ec,
    parse_findmy_key_payload,
    select_directory_identity,
)
from onitrack.people import (
    DebugLogger,
    DeviceIdentity,
    PeopleClient,
    PersonRelationship,
    _FMFSession,
    parse_people_private_key_blob,
)


def test_valid_pair_ec_delivery_and_findmy_key_payload():
    fixture = _pair_ec_fixture()

    identity = select_directory_identity(
        fixture.directory,
        sender=fixture.sender,
        sender_token=fixture.sender_token,
    )
    plaintext = decrypt_pair_ec(
        fixture.envelope,
        receiver_identity=fixture.receiver_state,
        sender_identity=identity,
    )
    advertised_id, private_key_blob = parse_findmy_key_payload(
        plaintext,
        expected_fm_id=fixture.fm_id,
    )

    assert advertised_id == base64.b64encode(fixture.advertised).decode("ascii")
    assert private_key_blob == fixture.private_key_blob
    assert parse_people_private_key_blob(private_key_blob)


def test_pair_ec_rejects_invalid_signature():
    fixture = _pair_ec_fixture(bad_message_signature=True)
    identity = select_directory_identity(
        fixture.directory,
        sender=fixture.sender,
        sender_token=fixture.sender_token,
    )

    with pytest.raises(KeyAcquisitionError, match="message signature is invalid"):
        decrypt_pair_ec(
            fixture.envelope,
            receiver_identity=fixture.receiver_state,
            sender_identity=identity,
        )


def test_pair_ec_rejects_validator_mismatch():
    fixture = _pair_ec_fixture(bad_validator=True)
    identity = select_directory_identity(
        fixture.directory,
        sender=fixture.sender,
        sender_token=fixture.sender_token,
    )

    with pytest.raises(KeyAcquisitionError, match="validator mismatch"):
        decrypt_pair_ec(
            fixture.envelope,
            receiver_identity=fixture.receiver_state,
            sender_identity=identity,
        )


def test_directory_rejects_unknown_sender_token_and_bad_prekey_signature():
    fixture = _pair_ec_fixture()
    with pytest.raises(KeyAcquisitionError, match="push token is unknown"):
        select_directory_identity(
            fixture.directory,
            sender=fixture.sender,
            sender_token=b"unknown-token",
        )

    bad = _pair_ec_fixture(bad_prekey_signature=True)
    with pytest.raises(KeyAcquisitionError, match="prekey signature is invalid"):
        select_directory_identity(
            bad.directory,
            sender=bad.sender,
            sender_token=bad.sender_token,
        )


def test_findmy_payload_rejects_wrong_relationship_and_malformed_layers():
    fixture = _pair_ec_fixture()
    identity = select_directory_identity(
        fixture.directory,
        sender=fixture.sender,
        sender_token=fixture.sender_token,
    )
    plaintext = decrypt_pair_ec(
        fixture.envelope,
        receiver_identity=fixture.receiver_state,
        sender_identity=identity,
    )

    with pytest.raises(KeyAcquisitionError, match="wrong relationship"):
        parse_findmy_key_payload(plaintext, expected_fm_id="another-share")
    with pytest.raises(KeyAcquisitionError, match="plist is malformed"):
        parse_findmy_key_payload(b"not-a-plist", expected_fm_id=fixture.fm_id)
    with pytest.raises(KeyAcquisitionError, match="protobuf is malformed"):
        decrypt_pair_ec(
            b"\x0a\xff",
            receiver_identity=fixture.receiver_state,
            sender_identity=identity,
        )


def test_findmy_payload_rejects_malformed_p224_point_and_scalar_mismatch():
    fixture = _pair_ec_fixture()
    application = plistlib.dumps(
        [
            {
                "entityIdentifier": fixture.fm_id,
                "hashedAdvertisement": {"key": {"data": fixture.advertised}},
                "privateKey": {"key": {"data": b"\x04" + b"\0" * 84}},
            },
        ],
        fmt=plistlib.FMT_BINARY,
    )
    wrapped = plistlib.dumps(
        {"T": 10, "V": 1, "P": application},
        fmt=plistlib.FMT_BINARY,
    )
    _advertised_id, private_key_blob = parse_findmy_key_payload(
        wrapped,
        expected_fm_id=fixture.fm_id,
    )

    with pytest.raises(Exception, match="public point mismatch|invalid"):
        parse_people_private_key_blob(private_key_blob)


def test_fmf_sequence_carries_contexts_model_and_exact_fetch(monkeypatch, tmp_path):
    calls = []
    responses = iter(
        [
            {
                "following": [{"id": "fm-selected"}],
                "serverContext": {"server": 1},
                "dataContext": {"data": 1},
            },
            {"serverContext": {"server": 2}, "dataContext": {"data": 2}},
            {"serverContext": {"server": 3}, "dataContext": {"data": 3}},
            {},
        ],
    )

    def fake_post(url, *, headers, auth, body):
        calls.append((url, headers, auth, body))
        return next(responses)

    monkeypatch.setattr(people_module, "_post_json", fake_post)
    account = SimpleNamespace(
        get_anisette_headers=lambda **_kwargs: {"X-Test": "anisette"},
    )
    state = {
        "account": {"username": "receiver@example.invalid"},
        "login": {
            "data": {
                "dsid": "12345",
                "mobileme_data": {
                    "friendsToken": "friends-token",
                    "searchPartyToken": "search-token",
                },
            },
        },
    }
    device = DeviceIdentity(
        udid="00000000-0000-0000-0000-000000000001",
        display_name="synthetic",
    )
    session = _FMFSession(
        account=account,
        state=state,
        device=device,
        debug_logger=DebugLogger(tmp_path, enabled=False),
        aps_token="base-courier-token",
    )

    session.initialize()
    session.refresh()
    session.refresh(selected_fm_id="fm-selected")
    PeopleClient(tmp_path)._fetch_searchparty(
        account,
        state,
        device,
        "fm-selected",
        None,
        "base-courier-token",
        intent="distributeKeys",
        mode="proactive",
    )

    assert [call[0].rsplit("/", 1)[-1] for call in calls[:3]] == [
        "initClient",
        "refreshClient",
        "refreshClient",
    ]
    assert "/minCallback/refreshClient" in calls[1][0]
    assert "/minCallback/selFriend/refreshClient" in calls[2][0]
    assert all(call[1]["X-FMF-Model-Version"] == "1" for call in calls[:3])
    assert calls[1][3]["serverContext"] == {"server": 1}
    assert calls[1][3]["dataContext"] == {"data": 1}
    assert calls[2][3]["serverContext"] == {"server": 2}
    assert calls[2][3]["dataContext"] == {"data": 2}
    assert calls[2][3]["clientContext"]["selectedFriend"] == "fm-selected"
    assert calls[3][3]["clientContext"]["apsToken"] == "base-courier-token"
    assert calls[3][3]["fetch"] == [
        {
            "fmId": "fm-selected",
            "intent": "distributeKeys",
            "mode": "proactive",
            "ids": [],
        },
    ]


def test_acquirer_subscribes_before_trigger_and_acknowledges_after_accept(
    monkeypatch,
):
    events = []
    command = SimpleNamespace(
        payload=plistlib.dumps({"c": 242}, fmt=plistlib.FMT_BINARY),
    )
    connection = _FakeConnection(command, events)
    delivery = VerifiedKeyDelivery(
        advertised_id="synthetic-advertised-id",
        private_key_blob=b"synthetic-key",
        sender="mailto:sender@example.invalid",
        sender_token=b"sender-token",
        target="mailto:receiver@example.invalid",
        message_uuid=b"u" * 16,
        directory_identity=DirectoryIdentity(
            push_token=b"sender-token",
            session_token=b"session-token",
            device_public_key=None,
            prekey_public_key=None,
        ),
    )

    async def fake_verify(*_args, **_kwargs):
        events.append("verified")
        return delivery

    async def fake_app_ack(*_args, **_kwargs):
        events.append("application_ack")

    monkeypatch.setattr(acquisition, "_load_apns_material", lambda _state: (1, 2, b"t"))
    monkeypatch.setattr(acquisition, "verify_key_delivery", fake_verify)
    acquirer = PeopleKeyAcquirer(
        people_state={},
        user_agent="synthetic",
        connection_factory=lambda *_args, **_kwargs: connection.context(),
    )
    monkeypatch.setattr(acquirer.directory, "send_application_ack", fake_app_ack)

    def prepare(base_token):
        assert base_token == b"base-token"
        assert connection.subscribed == list(APNS_INTEREST_TOPICS)
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        events.append("trigger")
        return PersonRelationship(
            fm_id="fm-selected",
            accepted_handles=("sender@example.invalid",),
            secure_locations_capable=True,
            fallback_to_legacy_allowed=False,
        )

    def accept(received):
        assert received is delivery
        events.append("persisted")

    result = asyncio.run(
        acquirer.acquire(
            wait_seconds=1,
            prepare_delivery=prepare,
            accept_delivery=accept,
        ),
    )

    assert result is delivery
    assert events == [
        "trigger",
        "verified",
        "persisted",
        "transport_ack",
        "application_ack",
    ]


def test_acquirer_timeout_is_readiness_result_without_ack(monkeypatch):
    events = []
    connection = _FakeConnection(None, events)
    monkeypatch.setattr(acquisition, "_load_apns_material", lambda _state: (1, 2, b"t"))
    acquirer = PeopleKeyAcquirer(
        people_state={},
        user_agent="synthetic",
        connection_factory=lambda *_args, **_kwargs: connection.context(),
    )
    relationship = PersonRelationship(
        fm_id="fm-selected",
        accepted_handles=("sender@example.invalid",),
        secure_locations_capable=True,
        fallback_to_legacy_allowed=False,
    )

    with pytest.raises(KeyAcquisitionTimeout, match="may be offline"):
        asyncio.run(
            acquirer.acquire(
                wait_seconds=0.01,
                prepare_delivery=lambda _token: relationship,
                accept_delivery=lambda _delivery: events.append("persisted"),
            ),
        )
    assert "transport_ack" not in events
    assert "persisted" not in events


def test_apns_connection_is_marked_active_before_topic_filters():
    commands = []

    class Connection:
        async def _send(self, command):
            commands.append(command)

    asyncio.run(acquisition._set_apns_active(Connection()))

    assert len(commands) == 1
    assert commands[0].state == 1
    assert commands[0].unknown2 == 0x7FFFFFFF


class _FakeStream:
    def __init__(self, command):
        self.command = command

    async def receive(self):
        if self.command is not None:
            command = self.command
            self.command = None
            return command
        await asyncio.Future()


class _FakeConnection:
    def __init__(self, command, events):
        self.command = command
        self.events = events
        self.subscribed = []

    @property
    async def base_token(self):
        return b"base-token"

    @asynccontextmanager
    async def context(self):
        yield self

    @asynccontextmanager
    async def notification_stream(self, topic, token):
        assert token == b"base-token"
        self.subscribed.append(topic)
        selected = self.command if topic == "com.apple.private.alloy.fmd" else None
        yield _FakeStream(selected)

    async def ack(self, _command):
        self.events.append("transport_ack")

    async def _send(self, _command):
        return None


class _Fixture(SimpleNamespace):
    pass


def _pair_ec_fixture(
    *,
    bad_message_signature=False,
    bad_validator=False,
    bad_prekey_signature=False,
):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    receiver_device = _compact_p256_key()
    receiver_prekey = _compact_p256_key()
    sender_device = _compact_p256_key()
    sender_prekey = _compact_p256_key()
    ephemeral = _compact_p256_key()
    sender = "mailto:sender@example.invalid"
    sender_token = b"synthetic-sender-token"
    fm_id = "synthetic-fm-id"
    advertised = bytes(range(32))
    p224 = ec.generate_private_key(ec.SECP224R1())
    p224_public = p224.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    private_key_blob = p224_public + p224.private_numbers().private_value.to_bytes(
        28,
        "big",
    )

    application = plistlib.dumps(
        [
            {
                "entityIdentifier": fm_id,
                "hashedAdvertisement": {"key": {"data": advertised}},
                "identifier": "synthetic-identifier",
                "index": 0,
                "privateKey": {"key": {"data": private_key_blob}},
            },
        ],
        fmt=plistlib.FMT_BINARY,
    )
    findmy = gzip.compress(
        plistlib.dumps({"T": 10, "V": 1, "P": application}, fmt=plistlib.FMT_BINARY),
        mtime=0,
    )
    inner = _proto_bytes(1, findmy)
    padding_length = (-len(inner)) % 16
    padded = inner + b"\0" * padding_length + padding_length.to_bytes(4, "little")

    receiver_prekey_x = _x(receiver_prekey)
    receiver_device_x = _x(receiver_device)
    sender_device_x = _x(sender_device)
    ephemeral_x = _x(ephemeral)
    secret = ephemeral.exchange(ec.ECDH(), receiver_prekey.public_key())
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=b"LastPawn-MessageKeys",
        info=b"",
    ).derive(secret)
    encryptor = Cipher(
        algorithms.AES(material[:32]),
        modes.CTR(material[32:]),
    ).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    signed = (
        secret
        + receiver_prekey_x
        + ephemeral_x
        + receiver_device_x
        + encrypted
    )
    message_signature = _raw_signature(sender_device, signed)
    if bad_message_signature:
        message_signature = bytes([message_signature[0] ^ 1]) + message_signature[1:]
    validator = (
        sender_device_x[:2]
        + receiver_device_x[:2]
        + receiver_prekey_x[:2]
        + b"\x0c"
    )
    if bad_validator:
        validator = bytes([validator[0] ^ 1]) + validator[1:]
    envelope = (
        _proto_bytes(1, encrypted)
        + _proto_bytes(2, ephemeral_x)
        + _proto_bytes(3, message_signature)
        + _proto_bytes(99, validator)
    )

    timestamp = 809222400.0
    timestamp_bytes = struct.pack("<d", timestamp)
    prekey_signature = _raw_signature(
        sender_device,
        b"NGMPrekeySignature" + _x(sender_prekey) + timestamp_bytes,
    )
    if bad_prekey_signature:
        prekey_signature = bytes([prekey_signature[0] ^ 1]) + prekey_signature[1:]
    prekey_data = (
        _proto_bytes(1, _x(sender_prekey))
        + _proto_bytes(2, prekey_signature)
        + _proto_fixed64(3, timestamp_bytes)
    )
    kt_data = _proto_bytes(1, _proto_bytes(1, sender_device_x))
    directory = {
        "status": 0,
        "results": {
            sender: {
                "identities": [
                    {
                        "push-token": sender_token,
                        "session-token": b"synthetic-session-token",
                        "kt-loggable-data": kt_data,
                        "client-data": {
                            "public-message-ngm-device-prekey-data-key": prekey_data,
                        },
                    },
                ],
            },
        },
    }
    receiver_state = {
        "device_private_key_pem": _private_pem(receiver_device),
        "pre_private_key_pem": _private_pem(receiver_prekey),
    }
    return _Fixture(
        advertised=advertised,
        directory=directory,
        envelope=envelope,
        fm_id=fm_id,
        private_key_blob=private_key_blob,
        receiver_state=receiver_state,
        sender=sender,
        sender_token=sender_token,
    )


def _compact_p256_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    prime = (2**256) - (2**224) + (2**192) + (2**96) - 1
    while True:
        key = ec.generate_private_key(ec.SECP256R1())
        if key.public_key().public_numbers().y * 2 <= prime:
            return key


def _x(key):
    return key.public_key().public_numbers().x.to_bytes(32, "big")


def _private_pem(key):
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _raw_signature(key, data):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    der = key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _proto_bytes(field, value):
    return _varint(field << 3 | 2) + _varint(len(value)) + value


def _proto_fixed64(field, value):
    return _varint(field << 3 | 1) + value


def _varint(value):
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)
