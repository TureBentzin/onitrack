from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request

from onitrack.auth import _anisette_libs_path, _close_account, _login_state_name
from onitrack.state import (
    CONFIG_FILE_MODE,
    account_config_path,
    device_config_path,
    privacy_config_path,
    read_json,
    write_json_atomic,
)

FMF_ENDPOINT_TEMPLATE = (
    "https://{host}/fmipservice/friends/fmfd/{dsid}/{device_udid}/initClient"
)
DEFAULT_FMF_HOST = "p01-fmfmobile.icloud.com"
DEFAULT_DISPLAY_NAME = "Onitrack"
APPLE_PRODUCT_TYPE = "MacBookPro18,3"
APPLE_OS_VERSION = "14.6"
FINDMYLOCATED_BUNDLE = "com.apple.findmy.findmylocated"


class PeopleProvisioningError(RuntimeError):
    pass


class PeopleProtocolError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class PersonRelationship:
    fm_id: str
    accepted_handles: tuple[str, ...]
    secure_locations_capable: bool | None
    fallback_to_legacy_allowed: bool | None


@dataclass(frozen=True)
class DeviceIdentity:
    udid: str
    display_name: str
    product_type: str = APPLE_PRODUCT_TYPE
    os_version: str = APPLE_OS_VERSION


def list_people(config_dir: Path, *, anonymise: bool) -> int:
    try:
        relationships = PeopleClient(config_dir).list_relationships()
        payload = (
            anonymized_relationships(config_dir, relationships)
            if anonymise
            else plain_relationships(relationships)
        )
    except PeopleProvisioningError as exc:
        print(f"people: provisioning_error: {exc}")
        return 1
    except PeopleProtocolError as exc:
        status = "unknown" if exc.status is None else str(exc.status)
        print(f"people: protocol_error: status={status} category={exc}")
        return 1

    print(json.dumps({"following": payload}, indent=2, sort_keys=True))
    return 0


class PeopleClient:
    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir

    def list_relationships(self) -> list[PersonRelationship]:
        account = self._load_logged_in_account()
        try:
            state = account.to_json()
            device = load_or_create_device_identity(self.config_dir)
            response = self._init_client(account, state, device)
            return parse_following(response)
        finally:
            _close_account(account)

    def _load_logged_in_account(self) -> Any:
        account_path = account_config_path(self.config_dir)
        if not account_path.exists():
            raise PeopleProvisioningError("run `onitrack auth provision` first")

        from findmy import AppleAccount

        account = AppleAccount.from_json(
            read_json(account_path),
            anisette_libs_path=_anisette_libs_path(self.config_dir),
        )
        if _login_state_name(account.login_state) != "LOGGED_IN":
            _close_account(account)
            raise PeopleProvisioningError("account is not logged in")
        return account

    def _init_client(
        self,
        account: Any,
        state: dict[str, Any],
        device: DeviceIdentity,
    ) -> dict[str, Any]:
        login_data = _dict_path(state, "login", "data")
        mobileme_data = _dict_path(login_data, "mobileme_data")
        dsid = _string_value(login_data.get("dsid"))
        if dsid is None:
            raise PeopleProvisioningError("saved account is missing DSID")

        token = _find_first_string(
            mobileme_data,
            (
                "friendsToken",
                "mmeFMFToken",
                "fmfToken",
                "mmeFMFAppToken",
                "authToken",
            ),
        )
        if token is None:
            raise PeopleProvisioningError("saved account is missing an FMF token")

        host = (
            _find_first_string(
                mobileme_data,
                ("fmfHost", "friendsHost", "mmeFMFHost", "host", "url"),
            )
            or DEFAULT_FMF_HOST
        )
        host = _normalize_host(host)
        caller = _string_value(_dict_path(state, "account").get("username")) or ""

        headers = dict(account.get_anisette_headers(with_client_info=True))
        headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "findmylocated/1 CFNetwork/1496.0.7 Darwin/23.5.0",
            },
        )
        body = {
            "clientContext": {
                "appName": "findmylocated",
                "apsToken": "",
                "callerHandleId": caller,
                "contextBundleApp": FINDMYLOCATED_BUNDLE,
                "currentTime": int(time.time() * 1000),
                "deviceUDID": device.udid,
                "productType": device.product_type,
                "osVersion": device.os_version,
            },
            "serverContext": {
                "authToken": _base64_text(token),
                "clientId": _base64_text(device.udid),
                "prsId": dsid,
            },
        }
        return _post_json(
            FMF_ENDPOINT_TEMPLATE.format(
                host=host,
                dsid=dsid,
                device_udid=device.udid,
            ),
            headers=headers,
            auth=(dsid, token),
            body=body,
        )


def parse_following(response: dict[str, Any]) -> list[PersonRelationship]:
    following = response.get("following", [])
    if not isinstance(following, list):
        return []

    relationships: list[PersonRelationship] = []
    for item in following:
        if not isinstance(item, dict):
            continue

        fm_id = _string_value(item.get("id") or item.get("fmId"))
        if fm_id is None:
            continue

        handles = item.get("invitationAcceptedHandles") or []
        accepted_handles = tuple(
            handle for handle in (_string_value(value) for value in handles) if handle
        )
        relationships.append(
            PersonRelationship(
                fm_id=fm_id,
                accepted_handles=accepted_handles,
                secure_locations_capable=_optional_bool(
                    item.get("secureLocationsCapable"),
                ),
                fallback_to_legacy_allowed=_optional_bool(
                    item.get("fallbackToLegacyAllowed"),
                ),
            ),
        )

    return relationships


def anonymized_relationships(
    config_dir: Path,
    relationships: list[PersonRelationship],
) -> list[dict[str, Any]]:
    salt = load_or_create_privacy_salt(config_dir)
    return [
        {
            "person_id": _hmac_hex(salt, relationship.fm_id),
            "handle_count": len(relationship.accepted_handles),
            "handle_hashes": [
                _hmac_hex(salt, handle) for handle in relationship.accepted_handles
            ],
            "secure_locations_capable": relationship.secure_locations_capable,
            "fallback_to_legacy_allowed": relationship.fallback_to_legacy_allowed,
        }
        for relationship in relationships
    ]


def plain_relationships(
    relationships: list[PersonRelationship],
) -> list[dict[str, Any]]:
    return [
        {
            "fm_id": relationship.fm_id,
            "accepted_handles": list(relationship.accepted_handles),
            "secure_locations_capable": relationship.secure_locations_capable,
            "fallback_to_legacy_allowed": relationship.fallback_to_legacy_allowed,
        }
        for relationship in relationships
    ]


def load_or_create_privacy_salt(config_dir: Path) -> bytes:
    path = privacy_config_path(config_dir)
    state = read_json(path)
    if state is not None:
        salt = _string_value(state.get("anonymization_salt"))
        if salt:
            return base64.b64decode(salt)

    salt_bytes = os.urandom(32)
    write_json_atomic(
        path,
        {"anonymization_salt": base64.b64encode(salt_bytes).decode("ascii")},
    )
    path.chmod(CONFIG_FILE_MODE)
    return salt_bytes


def load_or_create_device_identity(config_dir: Path) -> DeviceIdentity:
    path = device_config_path(config_dir)
    state = read_json(path)
    if state is not None:
        udid = _string_value(state.get("udid"))
        display_name = _string_value(state.get("display_name")) or DEFAULT_DISPLAY_NAME
        if udid:
            return DeviceIdentity(udid=udid, display_name=display_name)

    identity = DeviceIdentity(
        udid=uuid.uuid4().hex.upper(),
        display_name=DEFAULT_DISPLAY_NAME,
    )
    write_json_atomic(
        path,
        {
            "display_name": identity.display_name,
            "os_version": identity.os_version,
            "product_type": identity.product_type,
            "udid": identity.udid,
        },
    )
    path.chmod(CONFIG_FILE_MODE)
    return identity


def _post_json(
    url: str,
    *,
    headers: dict[str, str],
    auth: tuple[str, str],
    body: dict[str, Any],
) -> dict[str, Any]:
    encoded_auth = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
    safe_headers = dict(headers)
    safe_headers["Authorization"] = f"Basic {encoded_auth}"
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = request.Request(url, data=data, headers=safe_headers, method="POST")

    try:
        with request.urlopen(req, timeout=30) as response:
            response_body = response.read()
    except error.HTTPError as exc:
        raise PeopleProtocolError(_status_category(exc.code), status=exc.code) from None
    except error.URLError as exc:
        raise PeopleProtocolError(exc.reason.__class__.__name__) from None

    try:
        decoded = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PeopleProtocolError("invalid_json") from exc

    if not isinstance(decoded, dict):
        raise PeopleProtocolError("invalid_json_root")
    return decoded


def _status_category(status: int) -> str:
    if status in {400, 401, 403}:
        return "auth_or_client_context_rejected"
    if 400 <= status < 500:
        return "client_rejected"
    if 500 <= status < 600:
        return "apple_server_error"
    return "unexpected_http_status"


def _dict_path(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _find_first_string(data: Any, keys: tuple[str, ...]) -> str | None:
    if isinstance(data, dict):
        for key in keys:
            value = _string_value(data.get(key))
            if value:
                return value
        for value in data.values():
            found = _find_first_string(value, keys)
            if found:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _find_first_string(value, keys)
            if found:
                return found
    return None


def _normalize_host(value: str) -> str:
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/", 1)[0]


def _string_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _base64_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _hmac_hex(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
