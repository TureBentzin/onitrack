import json
import os
from pathlib import Path

import pytest

from onitrack.state import (
    AGE_IDENTITY_FILE,
    CONFIG_DIR_MODE,
    CONFIG_FILE_MODE,
    SECRETS_FILE,
    SecretStoreError,
    account_config_path,
    config_status,
    default_config_dir,
    ensure_config_dir,
    migrate_legacy_secrets,
    privacy_config_path,
    read_secrets,
    sanitize_account_state,
    secrets_path,
    write_json_atomic,
    write_secrets,
)


def test_default_config_dir_resolves_to_repo_local_config(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ONITRACK_CONFIG_DIR", raising=False)

    assert default_config_dir() == tmp_path / ".config" / "onitrack"


def test_default_config_dir_honors_environment(monkeypatch, tmp_path):
    configured = tmp_path / "service-config"
    monkeypatch.setenv("ONITRACK_CONFIG_DIR", os.fspath(configured))

    assert default_config_dir() == configured


def test_config_directory_permissions_are_enforced(tmp_path):
    config_dir = tmp_path / "config"

    ensure_config_dir(config_dir)

    assert config_dir.stat().st_mode & 0o777 == CONFIG_DIR_MODE


def test_json_write_is_atomic_and_private(tmp_path):
    config_dir = ensure_config_dir(tmp_path / "config")
    account_path = account_config_path(config_dir)

    write_json_atomic(account_path, {"login": {"state": 3}})

    assert account_path.stat().st_mode & 0o777 == CONFIG_FILE_MODE
    assert json.loads(account_path.read_text(encoding="utf-8")) == {
        "login": {"state": 3}
    }
    assert list(config_dir.glob("*.tmp-*")) == []


def test_password_fields_are_scrubbed_before_persistence():
    state = {
        "account": {
            "username": "person@example.com",
            "password": "secret",
        },
        "nested": [{"Password": "also-secret"}],
    }

    assert sanitize_account_state(state) == {
        "account": {
            "username": "person@example.com",
            "password": None,
        },
        "nested": [{"Password": None}],
    }


def test_status_redacts_sensitive_fields(tmp_path, capsys):
    from onitrack.main import main

    config_dir = ensure_config_dir(tmp_path / "config")
    write_json_atomic(
        account_config_path(config_dir),
        {
            "account": {
                "username": "person@example.com",
                "password": None,
                "info": {"dsid": "12345"},
            },
            "ids": {"uid": "sensitive-user-id"},
            "login": {"state": 3},
        },
    )

    assert main(["auth", "--config-dir", os.fspath(config_dir), "status"]) == 0
    output = capsys.readouterr().out

    assert "account: logged_in" in output
    assert "config_dir: ok" in output
    assert "password_persisted: no" in output
    assert "person@example.com" not in output
    assert "12345" not in output
    assert "sensitive-user-id" not in output


def test_config_status_detects_persisted_password(tmp_path):
    config_dir = ensure_config_dir(tmp_path / "config")
    write_json_atomic(
        account_config_path(config_dir),
        {"account": {"password": "secret"}, "login": {"state": 3}},
    )

    assert config_status(Path(config_dir))["password_persisted"] == "yes"


def test_anisette_libs_template_is_copied_to_writable_config(monkeypatch, tmp_path):
    from onitrack.auth import ANISETTE_LIBS_FILE, _anisette_libs_path

    template = tmp_path / "store-template.tar"
    template.write_bytes(b"template")
    config_dir = ensure_config_dir(tmp_path / "config")
    monkeypatch.setenv("ONITRACK_ANISETTE_LIBS_TEMPLATE", os.fspath(template))

    libs_path = _anisette_libs_path(config_dir)

    assert libs_path == config_dir / ANISETTE_LIBS_FILE
    assert libs_path.read_bytes() == b"template"
    assert libs_path.stat().st_mode & 0o777 == CONFIG_FILE_MODE


def test_encrypted_secret_store_creates_private_identity_and_round_trips(tmp_path):
    config_dir = ensure_config_dir(tmp_path / "config")

    write_secrets(config_dir, {"privacy": {"anonymization_salt": "salt"}})

    assert read_secrets(config_dir) == {"privacy": {"anonymization_salt": "salt"}}
    assert (config_dir / AGE_IDENTITY_FILE).stat().st_mode & 0o777 == CONFIG_FILE_MODE
    assert (config_dir / SECRETS_FILE).stat().st_mode & 0o777 == CONFIG_FILE_MODE
    assert "salt" not in secrets_path(config_dir).read_text(encoding="utf-8")


def test_migration_scrubs_legacy_plaintext_only_after_encrypted_readback(tmp_path):
    config_dir = ensure_config_dir(tmp_path / "config")
    write_json_atomic(
        account_config_path(config_dir),
        {"login": {"state": 3, "data": {"dsid": "123"}}, "account": {"username": "a"}},
    )
    write_json_atomic(
        privacy_config_path(config_dir),
        {"anonymization_salt": "plain-salt"},
    )

    migrate_legacy_secrets(config_dir)

    secrets = read_secrets(config_dir)
    assert secrets["account"]["login"]["data"]["dsid"] == "123"
    assert secrets["privacy"]["anonymization_salt"] == "plain-salt"
    assert "dsid" not in account_config_path(config_dir).read_text(encoding="utf-8")
    assert "plain-salt" not in privacy_config_path(config_dir).read_text(
        encoding="utf-8",
    )


def test_metadata_only_account_file_is_not_promoted_to_secrets(tmp_path):
    config_dir = ensure_config_dir(tmp_path / "config")
    write_json_atomic(
        account_config_path(config_dir),
        {"login": {"state": 3}, "account": {"username": "a"}},
    )

    migrate_legacy_secrets(config_dir)

    assert "account" not in read_secrets(config_dir)


def test_missing_age_tools_produce_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", os.fspath(tmp_path / "empty"))

    with pytest.raises(SecretStoreError, match="age-keygen"):
        write_secrets(tmp_path, {"privacy": {}})
