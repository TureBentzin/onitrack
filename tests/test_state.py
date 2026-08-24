import json
import os
from pathlib import Path

from onitrack.state import (
    STATE_DIR_MODE,
    STATE_FILE_MODE,
    account_state_path,
    default_state_dir,
    ensure_state_dir,
    sanitize_account_state,
    state_status,
    write_json_atomic,
)


def test_default_state_dir_resolves_to_repo_local_state(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    assert default_state_dir() == tmp_path / ".state" / "onitrack"


def test_state_directory_permissions_are_enforced(tmp_path):
    state_dir = tmp_path / "state"

    ensure_state_dir(state_dir)

    assert state_dir.stat().st_mode & 0o777 == STATE_DIR_MODE


def test_json_write_is_atomic_and_private(tmp_path):
    state_dir = ensure_state_dir(tmp_path / "state")
    account_path = account_state_path(state_dir)

    write_json_atomic(account_path, {"login": {"state": 3}})

    assert account_path.stat().st_mode & 0o777 == STATE_FILE_MODE
    assert json.loads(account_path.read_text(encoding="utf-8")) == {
        "login": {"state": 3}
    }
    assert list(state_dir.glob("*.tmp-*")) == []


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

    state_dir = ensure_state_dir(tmp_path / "state")
    write_json_atomic(
        account_state_path(state_dir),
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

    assert main(["auth", "--state-dir", os.fspath(state_dir), "status"]) == 0
    output = capsys.readouterr().out

    assert "account: logged_in" in output
    assert "password_persisted: no" in output
    assert "person@example.com" not in output
    assert "12345" not in output
    assert "sensitive-user-id" not in output


def test_state_status_detects_persisted_password(tmp_path):
    state_dir = ensure_state_dir(tmp_path / "state")
    write_json_atomic(
        account_state_path(state_dir),
        {"account": {"password": "secret"}, "login": {"state": 3}},
    )

    assert state_status(Path(state_dir))["password_persisted"] == "yes"
