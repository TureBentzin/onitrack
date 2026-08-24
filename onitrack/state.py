from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_DIR_ENV = "ONITRACK_CONFIG_DIR"
CONFIG_DIR_MODE = 0o700
CONFIG_FILE_MODE = 0o600
ACCOUNT_CONFIG_FILE = "account.json"
DEVICE_CONFIG_FILE = "device.json"
PRIVACY_CONFIG_FILE = "privacy.json"
PEOPLE_CONFIG_FILE = "people.json"


def default_config_dir() -> Path:
    env_path = os.environ.get(CONFIG_DIR_ENV)
    if env_path:
        return Path(env_path)
    return Path.cwd() / ".config" / "onitrack"


def resolve_config_dir(path: Path | None = None) -> Path:
    return path if path is not None else default_config_dir()


def ensure_config_dir(path: Path) -> Path:
    path.mkdir(mode=CONFIG_DIR_MODE, parents=True, exist_ok=True)
    path.chmod(CONFIG_DIR_MODE)
    return path


def account_config_path(config_dir: Path) -> Path:
    return config_dir / ACCOUNT_CONFIG_FILE


def device_config_path(config_dir: Path) -> Path:
    return config_dir / DEVICE_CONFIG_FILE


def privacy_config_path(config_dir: Path) -> Path:
    return config_dir / PRIVACY_CONFIG_FILE


def people_config_path(config_dir: Path) -> Path:
    return config_dir / PEOPLE_CONFIG_FILE


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        msg = f"state file must contain a JSON object: {path}"
        raise ValueError(msg)

    return data


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    ensure_config_dir(path.parent)
    tmp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    encoded = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    encoded += b"\n"

    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        CONFIG_FILE_MODE,
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        path.chmod(CONFIG_FILE_MODE)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def sanitize_account_state(data: dict[str, Any]) -> dict[str, Any]:
    sanitized = _scrub_passwords(data)
    if not isinstance(sanitized, dict):
        msg = "account state must be a JSON object"
        raise ValueError(msg)
    return sanitized


def _scrub_passwords(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: None if key.lower() == "password" else _scrub_passwords(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_scrub_passwords(item) for item in value]
    return value


def state_file_mode(path: Path) -> int | None:
    if not path.exists():
        return None
    return path.stat().st_mode & 0o777


def config_status(config_dir: Path) -> dict[str, str]:
    account_path = account_config_path(config_dir)
    dir_mode = state_file_mode(config_dir)
    file_mode = state_file_mode(account_path)
    account_state = read_json(account_path)

    login = "missing"
    password_persisted = "unknown"
    if account_state is not None:
        login = _login_status(account_state)
        password_persisted = "yes" if _contains_password(account_state) else "no"

    return {
        "account": login,
        "config_dir": "ok" if dir_mode == CONFIG_DIR_MODE else "missing_or_bad_mode",
        "account_file": (
            "ok" if file_mode == CONFIG_FILE_MODE else "missing_or_bad_mode"
        ),
        "password_persisted": password_persisted,
    }


def _login_status(account_state: dict[str, Any]) -> str:
    login = account_state.get("login")
    if not isinstance(login, dict):
        return "unknown"

    state = login.get("state")
    if state == 3:
        return "logged_in"
    if state == 2:
        return "authenticated"
    if state == 1:
        return "requires_2fa"
    if state == 0:
        return "logged_out"
    return "unknown"


def _contains_password(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() == "password" and child is not None:
                return True
            if _contains_password(child):
                return True
    elif isinstance(value, list):
        return any(_contains_password(item) for item in value)
    return False
