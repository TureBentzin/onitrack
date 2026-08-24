from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

CONFIG_DIR_ENV = "ONITRACK_CONFIG_DIR"
CONFIG_DIR_MODE = 0o700
CONFIG_FILE_MODE = 0o600
ACCOUNT_CONFIG_FILE = "account.json"
DEVICE_CONFIG_FILE = "device.json"
PRIVACY_CONFIG_FILE = "privacy.json"
PEOPLE_CONFIG_FILE = "people.json"
AGE_IDENTITY_FILE = "age-identity.txt"
SECRETS_FILE = "secrets.age"


class SecretStoreError(RuntimeError):
    pass


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


def age_identity_path(config_dir: Path) -> Path:
    return config_dir / AGE_IDENTITY_FILE


def secrets_path(config_dir: Path) -> Path:
    return config_dir / SECRETS_FILE


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


def ensure_age_identity(config_dir: Path) -> Path:
    ensure_config_dir(config_dir)
    path = age_identity_path(config_dir)
    if path.exists():
        path.chmod(CONFIG_FILE_MODE)
        return path

    age_keygen = _require_tool("age-keygen")
    try:
        result = subprocess.run(
            [age_keygen],
            check=True,
            capture_output=True,
        )
    except OSError as exc:
        raise SecretStoreError("failed to run age-keygen") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        msg = "age-keygen failed"
        if detail:
            msg = f"{msg}: {detail}"
        raise SecretStoreError(msg) from exc

    _write_private_bytes_atomic(path, result.stdout)
    return path


def read_secrets(config_dir: Path) -> dict[str, Any]:
    path = secrets_path(config_dir)
    if not path.exists():
        return {}

    age = _require_tool("age")
    identity_path = ensure_age_identity(config_dir)
    try:
        result = subprocess.run(
            [age, "--decrypt", "--identity", os.fspath(identity_path)],
            input=path.read_bytes(),
            check=True,
            capture_output=True,
        )
    except OSError as exc:
        raise SecretStoreError("failed to run age") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        msg = "failed to decrypt encrypted Onitrack secrets"
        if detail:
            msg = f"{msg}: {detail}"
        raise SecretStoreError(msg) from exc

    if not result.stdout:
        return {}
    try:
        data = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecretStoreError("encrypted Onitrack secrets are malformed") from exc
    if not isinstance(data, dict):
        raise SecretStoreError("encrypted Onitrack secrets must be a JSON object")
    return data


def write_secrets(config_dir: Path, data: dict[str, Any]) -> None:
    ensure_config_dir(config_dir)
    identity_path = ensure_age_identity(config_dir)
    public_key = _age_public_key(identity_path)
    age = _require_tool("age")
    encoded = json.dumps(data, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    try:
        result = subprocess.run(
            [age, "--encrypt", "--recipient", public_key],
            input=encoded,
            check=True,
            capture_output=True,
        )
    except OSError as exc:
        raise SecretStoreError("failed to run age") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        msg = "failed to encrypt Onitrack secrets"
        if detail:
            msg = f"{msg}: {detail}"
        raise SecretStoreError(msg) from exc

    _write_private_bytes_atomic(secrets_path(config_dir), result.stdout)


def secret_section(config_dir: Path, section: str) -> dict[str, Any]:
    data = read_secrets(config_dir).get(section)
    return data if isinstance(data, dict) else {}


def write_secret_section(config_dir: Path, section: str, value: dict[str, Any]) -> None:
    data = read_secrets(config_dir)
    data[section] = value
    write_secrets(config_dir, data)


def migrate_legacy_secrets(config_dir: Path) -> None:
    ensure_config_dir(config_dir)
    secrets = read_secrets(config_dir)
    changed = False

    account_path = account_config_path(config_dir)
    account_state = read_json(account_path)
    if (
        account_state
        and "account" not in secrets
        and account_state != account_metadata(account_state)
    ):
        secrets["account"] = account_state
        changed = True

    privacy_path = privacy_config_path(config_dir)
    privacy_state = read_json(privacy_path)
    if privacy_state:
        privacy_secrets = _dict_copy(secrets.get("privacy"))
        salt = privacy_state.get("anonymization_salt")
        if (
            isinstance(salt, str)
            and salt
            and "anonymization_salt" not in privacy_secrets
        ):
            privacy_secrets["anonymization_salt"] = salt
            secrets["privacy"] = privacy_secrets
            changed = True

    people_path = people_config_path(config_dir)
    people_state = read_json(people_path)
    if people_state:
        people_secret_keys = {
            "advertised_ids",
            "apns",
            "apple_tokens",
            "findmy",
            "ids",
            "keys",
            "registration",
        }
        secret_people = _dict_copy(secrets.get("people"))
        for key in people_secret_keys:
            if key in people_state and key not in secret_people:
                secret_people[key] = people_state[key]
                changed = True
        if secret_people:
            secrets["people"] = secret_people

    if changed:
        write_secrets(config_dir, secrets)
        read_secrets(config_dir)

    if account_state:
        metadata = account_metadata(account_state)
        if metadata != account_state:
            write_json_atomic(account_path, metadata)
    if privacy_state:
        write_json_atomic(privacy_path, {"encrypted": True})
    if people_state:
        metadata = {
            key: value
            for key, value in people_state.items()
            if key not in {
                "advertised_ids",
                "apns",
                "apple_tokens",
                "findmy",
                "ids",
                "keys",
                "registration",
            }
        }
        write_json_atomic(people_path, metadata)


def account_metadata(state: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    login = state.get("login")
    if isinstance(login, dict):
        metadata["login"] = {"state": login.get("state")}
    account = state.get("account")
    if isinstance(account, dict):
        username = account.get("username")
        metadata["account"] = {
            "username": username if isinstance(username, str) else None,
        }
    return metadata


def sanitize_account_state(data: dict[str, Any]) -> dict[str, Any]:
    sanitized = _scrub_passwords(data)
    if not isinstance(sanitized, dict):
        msg = "account state must be a JSON object"
        raise ValueError(msg)
    return sanitized


def _write_private_bytes_atomic(path: Path, data: bytes) -> None:
    ensure_config_dir(path.parent)
    tmp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        CONFIG_FILE_MODE,
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        path.chmod(CONFIG_FILE_MODE)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise SecretStoreError(
            f"`{name}` is required for encrypted Onitrack secret storage",
        )
    return path


def _age_public_key(identity_path: Path) -> str:
    content = identity_path.read_text(encoding="utf-8")
    match = re.search(r"^# public key: (age1[0-9a-z]+)$", content, re.MULTILINE)
    if match is None:
        raise SecretStoreError("age identity is missing its public recipient key")
    return match.group(1)


def _dict_copy(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


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
