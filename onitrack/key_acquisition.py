from __future__ import annotations

import asyncio
import base64
import gzip
import hmac
import os
import plistlib
import uuid
from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any

from onitrack.ids import (
    IDS_PROTOCOL_VERSION,
    MULTIPLEX_SUB_SERVICES,
    _bag,
    _sign_headers,
)

IDS_PARENT_TOPIC = "com.apple.private.ids"
SEARCHPARTY_CONTAINER_TOPIC = (
    "com.apple.icloud-container.com.apple.icloud.searchpartyuseragent"
)
KEY_DELIVERY_TOPICS = frozenset(MULTIPLEX_SUB_SERVICES)
APNS_INTEREST_TOPICS = (
    IDS_PARENT_TOPIC,
    *MULTIPLEX_SUB_SERVICES,
    SEARCHPARTY_CONTAINER_TOPIC,
)
NGM_HKDF_SALT = b"LastPawn-MessageKeys"


class KeyAcquisitionError(RuntimeError):
    pass


class KeyAcquisitionTimeout(KeyAcquisitionError):
    pass


@dataclass(frozen=True)
class DirectoryIdentity:
    push_token: bytes
    session_token: bytes
    device_public_key: Any
    prekey_public_key: Any


@dataclass(frozen=True)
class VerifiedKeyDelivery:
    advertised_id: str
    private_key_blob: bytes
    sender: str
    sender_token: bytes
    target: str
    message_uuid: bytes
    directory_identity: DirectoryIdentity


class IDSDirectoryClient:
    def __init__(
        self,
        ids_state: dict[str, Any],
        *,
        user_agent: str,
        request_timeout_s: float = 30,
    ) -> None:
        self.ids_state = ids_state
        self.user_agent = user_agent
        self.request_timeout_s = request_timeout_s

    async def query_sender(
        self,
        connection: Any,
        *,
        base_token: bytes,
        topic: str,
        sender: str,
        target: str,
        sender_token: bytes,
    ) -> DirectoryIdentity:
        user = _registered_user_for_target(self.ids_state, target)
        body = gzip.compress(
            plistlib.dumps({"uris": [sender]}, fmt=plistlib.FMT_BINARY),
            mtime=0,
        )
        headers = {
            "content-type": "application/x-apple-plist",
            "user-agent": f"com.apple.madrid-lookup {self.user_agent}",
            "x-id-self-uri": target,
            "x-id-sub-service": topic,
            "x-protocol-version": IDS_PROTOCOL_VERSION,
            "x-push-token": base64.b64encode(base_token).decode("ascii"),
            "x-result-expected": "true",
        }
        registration = _dict_value(user.get("registration"))
        cert = _base64_bytes(registration.get("cert"), "IDS registration cert")
        private_key = _load_private_key(
            user.get("auth_private_key_pem"),
            "IDS authentication private key",
        )
        _sign_headers(
            headers,
            "id-query",
            body,
            base_token,
            "id",
            private_key,
            cert,
        )

        request_uuid = os.urandom(16)
        tunnel_request = {
            "cT": "application/x-apple-plist",
            "U": request_uuid,
            "c": 96,
            "u": _bag("id-query"),
            "h": headers,
            "v": 2,
            "b": body,
        }
        async with connection.notification_stream(topic, base_token) as stream:
            await _send_plist(connection, topic, base_token, tunnel_request)
            deadline = asyncio.get_running_loop().time() + self.request_timeout_s
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise KeyAcquisitionError("IDS directory query timed out")
                command = await asyncio.wait_for(stream.receive(), remaining)
                response = _load_plist(command.payload, "IDS web tunnel response")
                if response.get("U") != request_uuid:
                    continue
                encoded = response.get("b")
                if not isinstance(encoded, bytes):
                    status = response.get("s")
                    raise KeyAcquisitionError(
                        "IDS directory query failed with status "
                        f"{_safe_status(status)}",
                    )
                decoded = _maybe_gunzip(encoded, "IDS directory response")
                directory = _load_plist(decoded, "IDS directory response")
                identity = select_directory_identity(
                    directory,
                    sender=sender,
                    sender_token=sender_token,
                )
                await connection.ack(command)
                return identity

    async def send_application_ack(
        self,
        connection: Any,
        *,
        base_token: bytes,
        topic: str,
        delivery: VerifiedKeyDelivery,
    ) -> None:
        ack_uuid = uuid.uuid4().bytes
        payload = {
            "fcn": 1,
            "c": 244,
            "ua": self.user_agent,
            "v": 8,
            "i": int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF,
            "U": ack_uuid,
            "dtl": [
                {
                    "tP": delivery.sender,
                    "D": False,
                    "sT": delivery.directory_identity.session_token,
                    "t": delivery.sender_token,
                },
            ],
            "sP": delivery.target,
            "nr": True,
            "rI": delivery.message_uuid,
        }
        await _send_plist(connection, topic, base_token, payload)


class PeopleKeyAcquirer:
    def __init__(
        self,
        *,
        people_state: dict[str, Any],
        user_agent: str,
        debug_emit: Callable[[str, dict[str, Any]], None] | None = None,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.people_state = people_state
        self.ids_state = _dict_value(people_state.get("ids"))
        self.apns_state = _dict_value(people_state.get("apns"))
        self.directory = IDSDirectoryClient(
            self.ids_state,
            user_agent=user_agent,
        )
        self.debug_emit = debug_emit or (lambda _step, _fields: None)
        self.connection_factory = connection_factory

    async def acquire(
        self,
        *,
        wait_seconds: float,
        prepare_delivery: Callable[[bytes], Any],
        accept_delivery: Callable[[VerifiedKeyDelivery], None],
    ) -> VerifiedKeyDelivery:
        certificate, private_key, stored_token = _load_apns_material(self.apns_state)
        connection_factory = self.connection_factory
        if connection_factory is None:
            try:
                from pypush import apns
            except ImportError as exc:
                raise KeyAcquisitionError("pypush is required for APNs") from exc
            connection_factory = apns.create_apns_connection

        async with connection_factory(
            certificate,
            private_key,
            token=stored_token,
        ) as connection:
            base_token = await connection.base_token
            async with AsyncExitStack() as stack:
                streams: dict[str, Any] = {}
                for topic in APNS_INTEREST_TOPICS:
                    streams[topic] = await stack.enter_async_context(
                        connection.notification_stream(topic, base_token),
                    )
                self.debug_emit(
                    "people_key_subscribed",
                    {"topic_count": len(streams), "apns_token": base_token.hex()},
                )
                relationship = prepare_delivery(base_token)
                self.debug_emit(
                    "people_key_delivery_requested",
                    {"fmId": relationship.fm_id, "wait_seconds": wait_seconds},
                )
                return await self._wait_for_delivery(
                    connection,
                    streams=streams,
                    base_token=base_token,
                    relationship=relationship,
                    wait_seconds=wait_seconds,
                    accept_delivery=accept_delivery,
                )

    async def _wait_for_delivery(
        self,
        connection: Any,
        *,
        streams: dict[str, Any],
        base_token: bytes,
        relationship: Any,
        wait_seconds: float,
        accept_delivery: Callable[[VerifiedKeyDelivery], None],
    ) -> VerifiedKeyDelivery:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_seconds
        tasks = {
            asyncio.create_task(stream.receive()): topic
            for topic, stream in streams.items()
        }
        try:
            while tasks:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise KeyAcquisitionTimeout(
                        "key delivery timed out; the sharing device may be offline",
                    )
                done, _pending = await asyncio.wait(
                    tasks,
                    timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    raise KeyAcquisitionTimeout(
                        "key delivery timed out; the sharing device may be offline",
                    )
                for task in done:
                    topic = tasks.pop(task)
                    command = task.result()
                    tasks[asyncio.create_task(streams[topic].receive())] = topic
                    if topic not in KEY_DELIVERY_TOPICS:
                        continue
                    try:
                        envelope = _load_plist(command.payload, "IDS message")
                    except KeyAcquisitionError:
                        continue
                    if envelope.get("c") != 242:
                        continue
                    try:
                        delivery = await verify_key_delivery(
                            envelope,
                            relationship=relationship,
                            topic=topic,
                            connection=connection,
                            base_token=base_token,
                            directory=self.directory,
                            ids_state=self.ids_state,
                        )
                        accept_delivery(delivery)
                    except KeyAcquisitionError as exc:
                        self.debug_emit(
                            "people_key_delivery_rejected",
                            {"topic": topic, "category": str(exc)},
                        )
                        continue
                    await connection.ack(command)
                    await self.directory.send_application_ack(
                        connection,
                        base_token=base_token,
                        topic=topic,
                        delivery=delivery,
                    )
                    self.debug_emit(
                        "people_key_delivery_accepted",
                        {
                            "topic": topic,
                            "sender": delivery.sender,
                            "advertised_id": delivery.advertised_id,
                        },
                    )
                    return delivery
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)


async def verify_key_delivery(
    envelope: dict[str, Any],
    *,
    relationship: Any,
    topic: str,
    connection: Any,
    base_token: bytes,
    directory: IDSDirectoryClient,
    ids_state: dict[str, Any],
) -> VerifiedKeyDelivery:
    if envelope.get("E") != "pair-ec":
        raise KeyAcquisitionError("IDS envelope is not pair-ec")
    sender = _required_string(envelope.get("sP"), "IDS sender")
    target = _required_string(envelope.get("tP"), "IDS target")
    sender_token = _required_bytes(envelope.get("t"), "IDS sender token")
    encrypted = _required_bytes(envelope.get("P"), "IDS encrypted payload")
    message_uuid = _required_bytes(envelope.get("U"), "IDS message UUID")
    if len(message_uuid) != 16:
        raise KeyAcquisitionError("IDS message UUID is malformed")
    if not sender_matches_relationship(sender, relationship.accepted_handles):
        raise KeyAcquisitionError("IDS sender does not match selected relationship")

    identity = await directory.query_sender(
        connection,
        base_token=base_token,
        topic=topic,
        sender=sender,
        target=target,
        sender_token=sender_token,
    )
    plaintext = decrypt_pair_ec(
        encrypted,
        receiver_identity=_dict_value(ids_state.get("identity")),
        sender_identity=identity,
    )
    advertised_id, private_key_blob = parse_findmy_key_payload(
        plaintext,
        expected_fm_id=relationship.fm_id,
    )
    return VerifiedKeyDelivery(
        advertised_id=advertised_id,
        private_key_blob=private_key_blob,
        sender=sender,
        sender_token=sender_token,
        target=target,
        message_uuid=message_uuid,
        directory_identity=identity,
    )


def select_directory_identity(
    response: dict[str, Any],
    *,
    sender: str,
    sender_token: bytes,
) -> DirectoryIdentity:
    if response.get("status") != 0:
        raise KeyAcquisitionError(
            f"IDS directory response status is {_safe_status(response.get('status'))}",
        )
    results = _dict_value(response.get("results"))
    sender_result = results.get(sender)
    if not isinstance(sender_result, dict):
        raise KeyAcquisitionError("IDS directory has no selected sender")
    identities = sender_result.get("identities")
    if not isinstance(identities, list):
        raise KeyAcquisitionError("IDS directory sender identities are malformed")
    matches = [
        identity
        for identity in identities
        if isinstance(identity, dict)
        and _optional_bytes(identity.get("push-token")) == sender_token
    ]
    if len(matches) != 1:
        raise KeyAcquisitionError("IDS sender push token is unknown or ambiguous")

    selected = matches[0]
    client_data = _dict_value(selected.get("client-data"))
    device_data = selected.get("kt-loggable-data")
    if not isinstance(device_data, bytes):
        device_data = client_data.get("ngm-public-identity")
    device_x = _parse_kt_device_key(device_data)
    device_key = _p256_public_from_x(device_x)
    prekey_data = _required_bytes(
        client_data.get("public-message-ngm-device-prekey-data-key"),
        "IDS sender prekey data",
    )
    prekey_x, signature, timestamp_bytes = _parse_prekey_data(prekey_data)
    _verify_raw_ecdsa(
        device_key,
        signature,
        b"NGMPrekeySignature" + prekey_x + timestamp_bytes,
        "IDS sender prekey signature",
    )
    return DirectoryIdentity(
        push_token=sender_token,
        session_token=_required_bytes(
            selected.get("session-token"),
            "IDS sender session token",
        ),
        device_public_key=device_key,
        prekey_public_key=_p256_public_from_x(prekey_x),
    )


def decrypt_pair_ec(
    envelope: bytes,
    *,
    receiver_identity: dict[str, Any],
    sender_identity: DirectoryIdentity,
) -> bytes:
    fields = _parse_protobuf(envelope, "NGM outer message")
    encrypted = _one_bytes(fields, 1, "NGM ciphertext")
    ephemeral_x = _one_bytes(fields, 2, "NGM ephemeral key")
    signature = _one_bytes(fields, 3, "NGM signature")
    validator = _one_bytes(fields, 99, "NGM validator")
    if len(ephemeral_x) != 32 or len(signature) != 64:
        raise KeyAcquisitionError("NGM outer message key or signature is malformed")

    receiver_prekey = _load_ec_private_key(
        receiver_identity.get("pre_private_key_pem"),
        "receiver NGM prekey",
    )
    receiver_device = _load_ec_private_key(
        receiver_identity.get("device_private_key_pem"),
        "receiver NGM device key",
    )
    receiver_prekey_x = _public_x(receiver_prekey.public_key())
    receiver_device_x = _public_x(receiver_device.public_key())
    sender_device_x = _public_x(sender_identity.device_public_key)
    expected_validator = (
        sender_device_x[:2]
        + receiver_device_x[:2]
        + receiver_prekey_x[:2]
        + b"\x0c"
    )
    if not hmac.compare_digest(validator, expected_validator):
        raise KeyAcquisitionError("NGM validator mismatch")

    ephemeral = _p256_public_from_x(ephemeral_x)
    from cryptography.hazmat.primitives.asymmetric import ec

    secret = receiver_prekey.exchange(ec.ECDH(), ephemeral)
    signed = (
        secret
        + receiver_prekey_x
        + ephemeral_x
        + receiver_device_x
        + encrypted
    )
    _verify_raw_ecdsa(
        sender_identity.device_public_key,
        signature,
        signed,
        "NGM message signature",
    )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    material = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=NGM_HKDF_SALT,
        info=b"",
    ).derive(secret)
    decryptor = Cipher(
        algorithms.AES(material[:32]),
        modes.CTR(material[32:]),
    ).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    if len(padded) < 4:
        raise KeyAcquisitionError("NGM plaintext padding is malformed")
    padding_length = int.from_bytes(padded[-4:], "little")
    if padding_length > len(padded) - 4:
        raise KeyAcquisitionError("NGM plaintext padding is malformed")
    inner = padded[: len(padded) - padding_length - 4]
    inner_fields = _parse_protobuf(inner, "NGM inner message")
    return _one_bytes(inner_fields, 1, "NGM application message")


def parse_findmy_key_payload(
    payload: bytes,
    *,
    expected_fm_id: str,
) -> tuple[str, bytes]:
    decoded = _load_plist(_maybe_gunzip(payload, "Find My message"), "Find My message")
    if decoded.get("T") != 10 or decoded.get("V") != 1:
        raise KeyAcquisitionError("Find My message type or version is unsupported")
    application = _required_bytes(decoded.get("P"), "Find My application payload")
    try:
        root = plistlib.loads(_maybe_gunzip(application, "Find My key payload"))
    except plistlib.InvalidFileException as exc:
        raise KeyAcquisitionError("Find My key payload is malformed") from exc
    if not isinstance(root, list):
        raise KeyAcquisitionError("Find My key payload root is not an array")

    matching = [
        item
        for item in root
        if isinstance(item, dict) and item.get("entityIdentifier") == expected_fm_id
    ]
    if len(matching) != 1:
        raise KeyAcquisitionError("Find My key payload has wrong relationship")
    item = matching[0]
    advertised = _nested_bytes(item, "hashedAdvertisement", "key", "data")
    if len(advertised) != 32:
        raise KeyAcquisitionError("Find My advertised identifier is malformed")
    private_key = _nested_bytes(item, "privateKey", "key", "data")
    return base64.b64encode(advertised).decode("ascii"), private_key


def sender_matches_relationship(sender: str, handles: tuple[str, ...]) -> bool:
    normalized_sender = _normalize_handle(sender)
    return any(_normalize_handle(handle) == normalized_sender for handle in handles)


async def _send_plist(
    connection: Any,
    topic: str,
    base_token: bytes,
    payload: dict[str, Any],
) -> None:
    try:
        from pypush.apns.protocol import SendMessageCommand
    except ImportError as exc:
        raise KeyAcquisitionError("pypush is required for APNs") from exc
    command = SendMessageCommand(
        payload=plistlib.dumps(payload, fmt=plistlib.FMT_BINARY),
        id=os.urandom(4),
        topic=topic,
        token=base_token,
        outgoing=True,
    )
    await connection._send(command)


def _load_apns_material(state: dict[str, Any]) -> tuple[Any, Any, bytes]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:
        raise KeyAcquisitionError("cryptography is required for APNs") from exc
    certificate_pem = _required_string(state.get("certificate_pem"), "APNs cert")
    private_key_pem = _required_string(state.get("private_key_pem"), "APNs key")
    token_text = _required_string(state.get("courier_token"), "APNs courier token")
    try:
        token = bytes.fromhex(token_text)
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("ascii"),
            password=None,
        )
    except (ValueError, TypeError) as exc:
        raise KeyAcquisitionError("stored APNs material is malformed") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise KeyAcquisitionError("stored APNs private key is not RSA")
    return certificate, private_key, token


def _registered_user_for_target(
    ids_state: dict[str, Any],
    target: str,
) -> dict[str, Any]:
    users = _dict_value(ids_state.get("users"))
    matches = []
    for user in users.values():
        if not isinstance(user, dict):
            continue
        handles = user.get("handles")
        if isinstance(handles, list) and target in handles:
            matches.append(user)
    if len(matches) != 1:
        raise KeyAcquisitionError("IDS target does not match one registered identity")
    return matches[0]


def _parse_prekey_data(value: bytes) -> tuple[bytes, bytes, bytes]:
    fields = _parse_protobuf(value, "IDS sender prekey data")
    key = _one_bytes(fields, 1, "IDS sender prekey")
    signature = _one_bytes(fields, 2, "IDS sender prekey signature")
    timestamps = fields.get(3, [])
    if len(key) != 32 or len(signature) != 64 or len(timestamps) != 1:
        raise KeyAcquisitionError("IDS sender prekey data is malformed")
    timestamp = timestamps[0]
    if not isinstance(timestamp, bytes) or len(timestamp) != 8:
        raise KeyAcquisitionError("IDS sender prekey timestamp is malformed")
    return key, signature, timestamp


def _parse_kt_device_key(value: Any) -> bytes:
    if not isinstance(value, bytes):
        raise KeyAcquisitionError("IDS sender device identity is missing")
    outer = _parse_protobuf(value, "IDS sender device identity")
    nested = _one_bytes(outer, 1, "IDS sender device identity")
    inner = _parse_protobuf(nested, "IDS sender device public key")
    key = _one_bytes(inner, 1, "IDS sender device public key")
    if len(key) != 32:
        raise KeyAcquisitionError("IDS sender device public key is malformed")
    return key


def _parse_protobuf(value: bytes, label: str) -> dict[int, list[Any]]:
    fields: dict[int, list[Any]] = {}
    offset = 0
    try:
        while offset < len(value):
            key, offset = _read_varint(value, offset)
            field_number = key >> 3
            wire_type = key & 7
            if field_number == 0:
                raise ValueError
            if wire_type == 0:
                decoded, offset = _read_varint(value, offset)
            elif wire_type == 1:
                if offset + 8 > len(value):
                    raise ValueError
                decoded = value[offset : offset + 8]
                offset += 8
            elif wire_type == 2:
                length, offset = _read_varint(value, offset)
                if length < 0 or offset + length > len(value):
                    raise ValueError
                decoded = value[offset : offset + length]
                offset += length
            elif wire_type == 5:
                if offset + 4 > len(value):
                    raise ValueError
                decoded = value[offset : offset + 4]
                offset += 4
            else:
                raise ValueError
            fields.setdefault(field_number, []).append(decoded)
    except (IndexError, ValueError) as exc:
        raise KeyAcquisitionError(f"{label} protobuf is malformed") from exc
    return fields


def _read_varint(value: bytes, offset: int) -> tuple[int, int]:
    result = 0
    for shift in range(0, 70, 7):
        if offset >= len(value):
            raise ValueError
        byte = value[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
    raise ValueError


def _one_bytes(fields: dict[int, list[Any]], field: int, label: str) -> bytes:
    values = fields.get(field, [])
    if len(values) != 1 or not isinstance(values[0], bytes):
        raise KeyAcquisitionError(f"{label} is missing or duplicated")
    return values[0]


def _p256_public_from_x(value: bytes) -> Any:
    if len(value) != 32:
        raise KeyAcquisitionError("compact P-256 key is malformed")
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b"\x02" + value,
        )
    except ValueError as exc:
        raise KeyAcquisitionError("compact P-256 key is invalid") from exc


def _verify_raw_ecdsa(key: Any, signature: bytes, data: bytes, label: str) -> None:
    if len(signature) != 64:
        raise KeyAcquisitionError(f"{label} is malformed")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    der = utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"),
        int.from_bytes(signature[32:], "big"),
    )
    try:
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise KeyAcquisitionError(f"{label} is invalid") from exc


def _public_x(key: Any) -> bytes:
    return key.public_numbers().x.to_bytes(32, "big")


def _load_private_key(value: Any, label: str) -> Any:
    if not isinstance(value, str) or not value:
        raise KeyAcquisitionError(f"{label} is missing")
    from cryptography.hazmat.primitives import serialization

    try:
        return serialization.load_pem_private_key(value.encode("ascii"), password=None)
    except (TypeError, ValueError) as exc:
        raise KeyAcquisitionError(f"{label} is malformed") from exc


def _load_ec_private_key(value: Any, label: str) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec

    key = _load_private_key(value, label)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve,
        ec.SECP256R1,
    ):
        raise KeyAcquisitionError(f"{label} is not P-256")
    return key


def _load_plist(value: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = plistlib.loads(value)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise KeyAcquisitionError(f"{label} plist is malformed") from exc
    if not isinstance(decoded, dict):
        raise KeyAcquisitionError(f"{label} plist root is not a dictionary")
    return decoded


def _maybe_gunzip(value: bytes, label: str) -> bytes:
    if not value.startswith(b"\x1f\x8b"):
        return value
    try:
        return gzip.decompress(value)
    except (EOFError, OSError) as exc:
        raise KeyAcquisitionError(f"{label} gzip layer is malformed") from exc


def _nested_bytes(value: dict[str, Any], *path: str) -> bytes:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            raise KeyAcquisitionError("Find My key payload is malformed")
        current = current.get(key)
    return _required_bytes(current, "Find My key data")


def _normalize_handle(value: str) -> str:
    normalized = value.strip()
    for prefix in ("mailto:", "tel:"):
        if normalized.lower().startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    return normalized.casefold()


def _base64_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise KeyAcquisitionError(f"{label} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise KeyAcquisitionError(f"{label} is malformed") from exc


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise KeyAcquisitionError(f"{label} is missing")
    return value


def _optional_bytes(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    return None


def _required_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise KeyAcquisitionError(f"{label} is missing")
    return value


def _safe_status(value: Any) -> str:
    return str(value) if isinstance(value, int) else "unknown"


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
