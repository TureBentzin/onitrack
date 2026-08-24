import json
import os

import pytest

from onitrack.main import main
from onitrack.people import (
    PeopleClient,
    PeopleProtocolError,
    PersonRelationship,
    anonymized_relationships,
    load_or_create_device_identity,
    parse_following,
    plain_relationships,
)
from onitrack.state import (
    CONFIG_FILE_MODE,
    account_config_path,
    device_config_path,
    privacy_config_path,
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


def test_device_identity_is_persisted_with_private_mode(tmp_path):
    identity = load_or_create_device_identity(tmp_path)

    assert identity.display_name == "Onitrack"
    assert identity.product_type == "MacBookPro18,3"
    assert identity.os_version == "14.6"
    assert load_or_create_device_identity(tmp_path) == identity
    assert device_config_path(tmp_path).stat().st_mode & 0o777 == CONFIG_FILE_MODE
