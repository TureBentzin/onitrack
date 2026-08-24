import base64
import json
import os
from datetime import UTC, datetime

import pytest

from onitrack.main import main
from onitrack.people import (
    DebugRedactor,
    LocationFix,
    PeopleClient,
    PeopleLocationError,
    PeopleProtocolError,
    PersonRelationship,
    anonymize_value,
    anonymized_relationships,
    decrypt_searchparty_location,
    load_or_create_device_identity,
    parse_following,
    parse_location_plaintext,
    parse_people_private_key_blob,
    plain_relationships,
    select_searchparty_report,
    x963_sha256,
)
from onitrack.state import (
    CONFIG_FILE_MODE,
    account_config_path,
    device_config_path,
    people_config_path,
    privacy_config_path,
    read_json,
    write_json_atomic,
)


def test_anonymized_output_contains_no_raw_handles_or_fmids(tmp_path):
    relationships = [
        PersonRelationship(
            fm_id="fm-id-raw",
            accepted_handles=("person@example.com", "+15555550100"),
            secure_locations_capable=True,
            fallback_to_legacy_allowed=False,
        ),
    ]

    output = json.dumps(anonymized_relationships(tmp_path, relationships))

    assert "fm-id-raw" not in output
    assert "person@example.com" not in output
    assert "+15555550100" not in output
    assert "handle_count" in output
    assert "handle_hashes" in output
    assert privacy_config_path(tmp_path).stat().st_mode & 0o777 == CONFIG_FILE_MODE


def test_anonymized_ids_are_stable_with_same_local_salt(tmp_path):
    relationships = [
        PersonRelationship(
            fm_id="fm-id-raw",
            accepted_handles=("person@example.com",),
            secure_locations_capable=None,
            fallback_to_legacy_allowed=None,
        ),
    ]

    first = anonymized_relationships(tmp_path, relationships)
    second = anonymized_relationships(tmp_path, relationships)

    assert first == second


def test_plain_output_includes_raw_relationship_identifiers():
    relationships = [
        PersonRelationship(
            fm_id="fm-id-raw",
            accepted_handles=("person@example.com",),
            secure_locations_capable=True,
            fallback_to_legacy_allowed=False,
        ),
    ]

    assert plain_relationships(relationships) == [
        {
            "accepted_handles": ["person@example.com"],
            "fallback_to_legacy_allowed": False,
            "fm_id": "fm-id-raw",
            "secure_locations_capable": True,
        },
    ]


def test_people_list_prints_anonymized_mode(monkeypatch, tmp_path, capsys):
    def fake_list_relationships(self):
        return [
            PersonRelationship(
                fm_id="fm-id-raw",
                accepted_handles=("person@example.com",),
                secure_locations_capable=True,
                fallback_to_legacy_allowed=False,
            ),
        ]

    monkeypatch.setattr(PeopleClient, "list_relationships", fake_list_relationships)

    assert (
        main(["people", "--config-dir", os.fspath(tmp_path), "list", "--anonomyse"])
        == 0
    )
    output = capsys.readouterr().out

    assert "fm-id-raw" not in output
    assert "person@example.com" not in output
    assert "person_id" in output


def test_people_list_prints_plain_mode(monkeypatch, tmp_path, capsys):
    def fake_list_relationships(self):
        return [
            PersonRelationship(
                fm_id="fm-id-raw",
                accepted_handles=("person@example.com",),
                secure_locations_capable=True,
                fallback_to_legacy_allowed=False,
            ),
        ]

    monkeypatch.setattr(PeopleClient, "list_relationships", fake_list_relationships)

    assert main(["people", "--config-dir", os.fspath(tmp_path), "list", "--plain"]) == 0
    output = capsys.readouterr().out

    assert "fm-id-raw" in output
    assert "person@example.com" in output


def test_people_alias_set_stores_only_anonymized_person_id(
    monkeypatch,
    tmp_path,
    capsys,
):
    relationship = PersonRelationship(
        fm_id="fm-id-raw",
        accepted_handles=("person@example.com",),
        secure_locations_capable=True,
        fallback_to_legacy_allowed=False,
    )
    person_id = anonymized_relationships(tmp_path, [relationship])[0]["person_id"]

    def fake_list_relationships(self):
        return [relationship]

    monkeypatch.setattr(PeopleClient, "list_relationships", fake_list_relationships)

    assert (
        main(
            [
                "people",
                "--config-dir",
                os.fspath(tmp_path),
                "alias",
                "set",
                "home",
                person_id,
            ],
        )
        == 0
    )

    output = capsys.readouterr().out
    stored = people_config_path(tmp_path).read_text(encoding="utf-8")
    state = read_json(people_config_path(tmp_path))

    assert state == {"aliases": {"home": {"person_id": person_id}}}
    assert people_config_path(tmp_path).stat().st_mode & 0o777 == CONFIG_FILE_MODE
    assert "fm-id-raw" not in stored
    assert "person@example.com" not in stored
    assert "home" in stored
    assert "home" not in output


def test_people_alias_setup_interactively_stores_alias(
    monkeypatch,
    tmp_path,
    capsys,
):
    relationships = [
        PersonRelationship(
            fm_id="fm-one",
            accepted_handles=("one@example.com", "+15555550100"),
            secure_locations_capable=True,
            fallback_to_legacy_allowed=False,
        ),
        PersonRelationship(
            fm_id="fm-two",
            accepted_handles=("two@example.com",),
            secure_locations_capable=True,
            fallback_to_legacy_allowed=False,
        ),
    ]
    expected_id = anonymized_relationships(tmp_path, relationships)[1]["person_id"]

    def fake_list_relationships(self):
        return relationships

    answers = iter(["2", "office"])
    monkeypatch.setattr(PeopleClient, "list_relationships", fake_list_relationships)
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))

    assert (
        main(["people", "--config-dir", os.fspath(tmp_path), "alias", "setup"]) == 0
    )

    output = capsys.readouterr().out
    assert read_json(people_config_path(tmp_path)) == {
        "aliases": {"office": {"person_id": expected_id}},
    }
    assert "one@example.com" in output
    assert "+15555550100" in output
    assert "two@example.com" in output
    assert "fm-one" not in output
    assert "fm-two" not in output


def test_people_location_prints_anonymized_mode(monkeypatch, tmp_path, capsys):
    def fake_get_location(self, alias):
        return LocationFix(
            alias=alias,
            person_id="a" * 64,
            fm_id="fm-id-raw",
            advertised_id="advertised-raw",
            latitude=12.3456789,
            longitude=-98.7654321,
            horizontal_accuracy_m=14.5,
            source_timestamp=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
            received_timestamp=datetime(2026, 8, 24, 12, 1, tzinfo=UTC),
        )

    monkeypatch.setattr(PeopleClient, "get_location", fake_get_location)

    assert (
        main(
            [
                "people",
                "--config-dir",
                os.fspath(tmp_path),
                "location",
                "get",
                "--alias",
                "home",
                "--anonomyse",
            ],
        )
        == 0
    )

    output = capsys.readouterr().out
    payload = json.loads(output)
    location = payload["locations"][0]

    assert location["alias_id"] == anonymize_value(tmp_path, "home")
    assert location["person_id"] == "a" * 64
    assert location["source_age_seconds"] == 60
    assert location["horizontal_accuracy_m"] == 14.5
    assert location["status"] == "location_available"
    assert "home" not in output
    assert "fm-id-raw" not in output
    assert "advertised-raw" not in output
    assert "12.3456789" not in output
    assert "-98.7654321" not in output


def test_people_location_prints_plain_mode(monkeypatch, tmp_path, capsys):
    def fake_get_location(self, alias):
        return LocationFix(
            alias=alias,
            person_id="a" * 64,
            fm_id="fm-id-raw",
            advertised_id="advertised-raw",
            latitude=12.5,
            longitude=-98.25,
            horizontal_accuracy_m=14.5,
            source_timestamp=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
            received_timestamp=datetime(2026, 8, 24, 12, 1, tzinfo=UTC),
        )

    monkeypatch.setattr(PeopleClient, "get_location", fake_get_location)

    assert (
        main(
            [
                "people",
                "--config-dir",
                os.fspath(tmp_path),
                "location",
                "get",
                "--alias",
                "home",
                "--plain",
            ],
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "home" in output
    assert "fm-id-raw" in output
    assert "advertised-raw" in output
    assert "12.5" in output
    assert "-98.25" in output


def test_people_location_missing_alias_returns_clear_error(
    monkeypatch,
    tmp_path,
    capsys,
):
    def fake_get_location(self, alias):
        raise PeopleLocationError("alias is not configured")

    monkeypatch.setattr(PeopleClient, "get_location", fake_get_location)

    assert (
        main(
            [
                "people",
                "--config-dir",
                os.fspath(tmp_path),
                "location",
                "get",
                "--alias",
                "home",
                "--anonomyse",
            ],
        )
        == 1
    )
    assert (
        "people: provisioning_error: alias is not configured"
        in capsys.readouterr().out
    )


def test_redactor_hashes_sensitive_fields_and_removes_forbidden_values(tmp_path):
    salt = b"0" * 32
    redactor = DebugRedactor(salt)

    output = json.dumps(
        redactor.redact(
            {
                "fmId": "fm-id-raw",
                "dsid": "12345",
                "nested": {"advertised_id": "adv-raw", "latitude": 12.5},
                "count": 1,
            },
        ),
        sort_keys=True,
    )

    assert output == json.dumps(
        redactor.redact(
            {
                "fmId": "fm-id-raw",
                "dsid": "12345",
                "nested": {"advertised_id": "adv-raw", "latitude": 12.5},
                "count": 1,
            },
        ),
        sort_keys=True,
    )
    assert "fm-id-raw" not in output
    assert "12345" not in output
    assert "adv-raw" not in output
    assert "12.5" not in output
    assert "fmId_hmac" in output
    assert '"latitude": "<redacted>"' in output


def test_missing_account_state_returns_clear_provisioning_error(tmp_path, capsys):
    assert (
        main(["people", "--config-dir", os.fspath(tmp_path), "list", "--anonomyse"])
        == 1
    )

    assert "people: provisioning_error: run `onitrack auth provision` first" in (
        capsys.readouterr().out
    )


def test_non_logged_in_account_state_returns_clear_provisioning_error(
    monkeypatch,
    tmp_path,
    capsys,
):
    class Account:
        login_state = "LOGGED_OUT"

        def close(self):
            return None

    class AppleAccount:
        @classmethod
        def from_json(cls, state, *, anisette_libs_path=None):
            return Account()

    monkeypatch.setitem(
        __import__("sys").modules,
        "findmy",
        type("FindMy", (), {"AppleAccount": AppleAccount}),
    )
    write_json_atomic(account_config_path(tmp_path), {"login": {"state": 0}})

    assert (
        main(["people", "--config-dir", os.fspath(tmp_path), "list", "--anonomyse"])
        == 1
    )

    assert (
        "people: provisioning_error: account is not logged in"
        in capsys.readouterr().out
    )


def test_protocol_error_is_sanitized(monkeypatch, tmp_path, capsys):
    def fake_list_relationships(self):
        raise PeopleProtocolError("auth_or_client_context_rejected", status=401)

    monkeypatch.setattr(PeopleClient, "list_relationships", fake_list_relationships)

    assert (
        main(["people", "--config-dir", os.fspath(tmp_path), "list", "--anonomyse"])
        == 1
    )

    output = capsys.readouterr().out
    assert output.strip() == (
        "people: protocol_error: status=401 "
        "category=auth_or_client_context_rejected"
    )


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"following": []}, []),
        ({"following": [{"id": "fm1"}]}, [("fm1", (), None, None)]),
        (
            {
                "following": [
                    {
                        "id": "fm1",
                        "invitationAcceptedHandles": ["a@example.com"],
                        "secureLocationsCapable": True,
                        "fallbackToLegacyAllowed": False,
                    },
                    {
                        "id": "fm2",
                        "invitationAcceptedHandles": ["+15555550100", None, 3],
                    },
                ],
            },
            [
                ("fm1", ("a@example.com",), True, False),
                ("fm2", ("+15555550100",), None, None),
            ],
        ),
    ],
)
def test_parse_following_handles_empty_partial_and_multi_person(response, expected):
    parsed = parse_following(response)

    assert [
        (
            item.fm_id,
            item.accepted_handles,
            item.secure_locations_capable,
            item.fallback_to_legacy_allowed,
        )
        for item in parsed
    ] == expected


def test_searchparty_parser_selects_newest_matching_report():
    old_ciphertext = b"\x04" + (b"a" * 56) + b"old"
    new_ciphertext = b"\x04" + (b"b" * 56) + b"new"
    response = {
        "locationPayload": [
            {
                "id": "wrong",
                "locationInfo": [
                    {
                        "location": base64.b64encode(new_ciphertext).decode("ascii"),
                        "locationTs": 999,
                    },
                ],
            },
            {
                "id": "expected",
                "locationInfo": [
                    {
                        "location": base64.b64encode(old_ciphertext).decode("ascii"),
                        "locationTs": 100,
                    },
                    {"location": "not-base64", "locationTs": 200},
                    {
                        "location": base64.b64encode(new_ciphertext).decode("ascii"),
                        "locationTs": 300,
                    },
                ],
            },
        ],
    }

    report = select_searchparty_report(response, "expected")

    assert report is not None
    assert report.ciphertext == new_ciphertext
    assert report.location_ts == 300


def test_searchparty_parser_returns_none_for_empty_partial_and_wrong_id():
    assert select_searchparty_report({}, "expected") is None
    assert (
        select_searchparty_report(
            {"locationPayload": [{"id": "wrong"}]},
            "expected",
        )
        is None
    )
    assert (
        select_searchparty_report(
            {"locationPayload": [{"id": "expected", "locationInfo": [{}]}]},
            "expected",
        )
        is None
    )


def test_people_key_parser_accepts_valid_p224_blob_and_rejects_mismatch():
    cryptography = pytest.importorskip("cryptography")
    assert cryptography is not None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP224R1())
    scalar = private_key.private_numbers().private_value.to_bytes(28, "big")
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    parsed = parse_people_private_key_blob(public + scalar)
    assert parsed.private_numbers().private_value
    with pytest.raises(PeopleLocationError, match="public point mismatch"):
        parse_people_private_key_blob((b"\x04" + (b"\x00" * 56)) + scalar)


def test_searchparty_decryption_fixture_and_apple_timestamp_conversion():
    cryptography = pytest.importorskip("cryptography")
    assert cryptography is not None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    recipient = ec.generate_private_key(ec.SECP224R1())
    sender = ec.generate_private_key(ec.SECP224R1())
    ephemeral = sender.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    secret = sender.exchange(ec.ECDH(), recipient.public_key())
    material = x963_sha256(secret, 32, shared_info=ephemeral)
    plaintext = json.dumps(
        {
            "latitude": 51.5,
            "longitude": -0.12,
            "horizontalAccuracy": 8.0,
            "timestamp": 809222400,
        },
    ).encode("utf-8")
    ciphertext = ephemeral + AESGCM(material[:16]).encrypt(
        material[16:32],
        plaintext,
        None,
    )

    decrypted = decrypt_searchparty_location(ciphertext, recipient)
    parsed = parse_location_plaintext(decrypted, None)

    assert parsed["latitude"] == 51.5
    assert parsed["longitude"] == -0.12
    assert parsed["horizontal_accuracy_m"] == 8.0
    assert parsed["source_timestamp"] == datetime(2026, 8, 24, tzinfo=UTC)


def test_device_identity_is_persisted_with_private_mode(tmp_path):
    identity = load_or_create_device_identity(tmp_path)

    assert identity.display_name == "Onitrack"
    assert identity.product_type == "MacBookPro18,3"
    assert identity.os_version == "14.6"
    assert load_or_create_device_identity(tmp_path) == identity
    assert device_config_path(tmp_path).stat().st_mode & 0o777 == CONFIG_FILE_MODE
