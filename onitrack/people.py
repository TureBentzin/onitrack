from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import plistlib
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib import error, request

from onitrack.auth import _anisette_libs_path, _close_account, _login_state_name
from onitrack.state import (
    CONFIG_FILE_MODE,
    SecretStoreError,
    account_config_path,
    account_metadata,
    device_config_path,
    ensure_config_dir,
    migrate_legacy_secrets,
    people_config_path,
    privacy_config_path,
    read_json,
    secret_section,
    write_json_atomic,
    write_secret_section,
)

FMF_ENDPOINT_TEMPLATE = (
    "https://{host}/fmipservice/friends/fmfd/{dsid}/{device_udid}/{path}"
)
DEFAULT_FMF_HOST = "p01-fmfmobile.icloud.com"
FMF_MODEL_VERSION = "1"
APPLE_PRODUCT_TYPE = "Macmini9,1"
APPLE_FALLBACK_PRODUCT_TYPE = "MacBookPro18,3"
APPLE_OS_VERSION = "14.6"
FINDMYLOCATED_BUNDLE = "com.apple.findmy.findmylocated"
SEARCHPARTY_ENDPOINT = "https://gateway.icloud.com/findmyservice/fetch"
APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
P224_PUBLIC_KEY_BYTES = 57
P224_SCALAR_BYTES = 28
P224_PRIVATE_BLOB_BYTES = P224_PUBLIC_KEY_BYTES + P224_SCALAR_BYTES


class PeopleProvisioningError(RuntimeError):
    pass


class PeopleProtocolError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class PeopleLocationError(RuntimeError):
    pass


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
    fmf_udid: str = ""


@dataclass(frozen=True)
class PeopleKey:
    person_id: str
    advertised_id: str
    private_key_blob: bytes


@dataclass(frozen=True)
class SearchPartyReport:
    advertised_id: str
    ciphertext: bytes
    location_ts: float | int | None


@dataclass(frozen=True)
class LocationFix:
    alias: str
    person_id: str
    fm_id: str
    advertised_id: str
    latitude: float
    longitude: float
    horizontal_accuracy_m: float | None
    source_timestamp: datetime | None
    received_timestamp: datetime
    key_status: str = "ready"


def list_people(config_dir: Path, *, anonymise: bool) -> int:
    try:
        migrate_legacy_secrets(config_dir)
        relationships = PeopleClient(config_dir).list_relationships()
        payload = (
            anonymized_relationships(config_dir, relationships)
            if anonymise
            else plain_relationships(relationships)
        )
    except SecretStoreError as exc:
        print(f"people: secret_store_error: {exc}")
        return 1
    except PeopleProvisioningError as exc:
        print(f"people: provisioning_error: {exc}")
        return 1
    except PeopleProtocolError as exc:
        status = "unknown" if exc.status is None else str(exc.status)
        print(f"people: protocol_error: status={status} category={exc}")
        return 1

    print(json.dumps({"following": payload}, indent=2, sort_keys=True))
    return 0


def set_people_alias(config_dir: Path, *, alias: str, person_id: str) -> int:
    if not alias or alias.strip() != alias:
        print("people: alias_error: alias must be non-empty without surrounding spaces")
        return 1
    if not _looks_like_hmac_id(person_id):
        print("people: alias_error: PERSON_ID must be an anonymized people list id")
        return 1

    try:
        migrate_legacy_secrets(config_dir)
        relationships = PeopleClient(config_dir).list_relationships()
    except SecretStoreError as exc:
        print(f"people: secret_store_error: {exc}")
        return 1
    except PeopleProvisioningError as exc:
        print(f"people: provisioning_error: {exc}")
        return 1
    except PeopleProtocolError as exc:
        status = "unknown" if exc.status is None else str(exc.status)
        print(f"people: protocol_error: status={status} category={exc}")
        return 1

    known_ids = {
        item["person_id"]
        for item in anonymized_relationships(config_dir, relationships)
    }
    if person_id not in known_ids:
        print("people: alias_error: PERSON_ID was not found in accepted relationships")
        return 1

    return _store_people_alias(config_dir, alias=alias, person_id=person_id)


def setup_people_alias(config_dir: Path) -> int:
    try:
        migrate_legacy_secrets(config_dir)
        relationships = PeopleClient(config_dir).list_relationships()
    except SecretStoreError as exc:
        print(f"people: secret_store_error: {exc}")
        return 1
    except PeopleProvisioningError as exc:
        print(f"people: provisioning_error: {exc}")
        return 1
    except PeopleProtocolError as exc:
        status = "unknown" if exc.status is None else str(exc.status)
        print(f"people: protocol_error: status={status} category={exc}")
        return 1

    anonymized = anonymized_relationships(config_dir, relationships)
    if not anonymized:
        print("people: alias_error: no accepted relationships found")
        return 1

    for index, (raw, anonymized_row) in enumerate(
        zip(relationships, anonymized, strict=True),
        start=1,
    ):
        handles = ", ".join(raw.accepted_handles) if raw.accepted_handles else "(none)"
        print(
            f"{index}. handles={handles} "
            f"person_id={anonymized_row['person_id']} "
            f"secure_locations_capable={anonymized_row['secure_locations_capable']}",
        )

    selected = input("Select relationship number: ").strip()
    try:
        selected_index = int(selected)
    except ValueError:
        print("people: alias_error: selection must be a number")
        return 1
    if selected_index < 1 or selected_index > len(anonymized):
        print("people: alias_error: selection is out of range")
        return 1

    alias = input("Alias label: ").strip()
    if not alias:
        print("people: alias_error: alias must be non-empty")
        return 1

    return _store_people_alias(
        config_dir,
        alias=alias,
        person_id=anonymized[selected_index - 1]["person_id"],
    )


def _store_people_alias(config_dir: Path, *, alias: str, person_id: str) -> int:
    state = load_people_state(config_dir)
    aliases = _dict_value(state.get("aliases"))
    aliases[alias] = {"person_id": person_id}
    state["aliases"] = aliases
    write_people_state(config_dir, state)
    print(
        json.dumps(
            {"alias_id": anonymize_value(config_dir, alias), "person_id": person_id},
            sort_keys=True,
        ),
    )
    return 0


def import_people_key(
    config_dir: Path,
    *,
    person_id: str,
    advertised_id: str,
    private_key_blob_base64: str | None = None,
) -> int:
    if not _looks_like_hmac_id(person_id):
        print("people: key_error: PERSON_ID must be an anonymized people list id")
        return 1
    if not advertised_id or advertised_id.strip() != advertised_id:
        print("people: key_error: advertised id must be non-empty without spaces")
        return 1

    encoded = private_key_blob_base64
    if encoded is None:
        encoded = sys.stdin.read()
    encoded = "".join(encoded.split())
    if not encoded:
        print("people: key_error: private key blob is required on stdin")
        return 1

    try:
        private_key_blob = base64.b64decode(encoded, validate=True)
        parse_people_private_key_blob(private_key_blob)
    except (binascii.Error, ValueError, PeopleLocationError) as exc:
        print(f"people: key_error: {exc}")
        return 1

    try:
        migrate_legacy_secrets(config_dir)
        _store_people_key(
            config_dir,
            person_id=person_id,
            advertised_id=advertised_id,
            private_key_blob=private_key_blob,
        )
    except SecretStoreError as exc:
        print(f"people: secret_store_error: {exc}")
        return 1

    print(
        json.dumps(
            {
                "person_id": person_id,
                "advertised_id_digest": anonymize_value(config_dir, advertised_id),
                "key_status": "ready",
            },
            sort_keys=True,
        ),
    )
    return 0


def acquire_people_key(
    config_dir: Path,
    *,
    alias: str,
    wait_seconds: int,
    debug_redacted: bool = False,
) -> int:
    if wait_seconds <= 0:
        print("people: key_error: wait seconds must be greater than zero")
        return 1

    try:
        migrate_legacy_secrets(config_dir)
        people_state = load_people_state(config_dir)
        person_id = _person_id_for_alias(people_state, alias)
        logger = DebugLogger(config_dir, enabled=debug_redacted)
        key = PeopleClient(config_dir, debug_logger=logger).acquire_key(
            alias,
            wait_seconds=wait_seconds,
        )
    except SecretStoreError as exc:
        print(f"people: secret_store_error: {exc}")
        return 1
    except PeopleProvisioningError as exc:
        print(f"people: provisioning_error: {exc}")
        return 1
    except PeopleProtocolError as exc:
        status = "unknown" if exc.status is None else str(exc.status)
        print(f"people: protocol_error: status={status} category={exc}")
        return 1
    except PeopleLocationError as exc:
        print(f"people: key_error: {exc}")
        return 1
    except Exception as exc:
        from onitrack.key_acquisition import (
            KeyAcquisitionError,
            KeyAcquisitionTimeout,
        )

        if isinstance(exc, KeyAcquisitionTimeout):
            print(
                json.dumps(
                    {
                        "alias_id": anonymize_value(config_dir, alias),
                        "person_id": person_id,
                        "key_status": "pending",
                        "readiness": "sharing_device_may_be_offline",
                    },
                    sort_keys=True,
                ),
            )
            return 0
        if isinstance(exc, KeyAcquisitionError):
            print(f"people: key_error: {exc}")
            return 1
        raise

    print(
        json.dumps(
            {
                "alias_id": anonymize_value(config_dir, alias),
                "person_id": key.person_id,
                "advertised_id_digest": anonymize_value(
                    config_dir,
                    key.advertised_id,
                ),
                "key_status": "ready",
            },
            sort_keys=True,
        ),
    )
    return 0


def _store_people_key(
    config_dir: Path,
    *,
    person_id: str,
    advertised_id: str,
    private_key_blob: bytes,
) -> None:
    state = load_people_state(config_dir)
    keys = _dict_value(state.get("keys"))
    keys[person_id] = {
        "advertised_id": advertised_id,
        "private_key": base64.b64encode(private_key_blob).decode("ascii"),
    }
    state["keys"] = keys
    write_people_state(config_dir, state)


def get_people_location(
    config_dir: Path,
    *,
    alias: str,
    anonymise: bool,
    debug_redacted: bool = False,
) -> int:
    try:
        migrate_legacy_secrets(config_dir)
        logger = DebugLogger(config_dir, enabled=debug_redacted)
        fix = PeopleClient(config_dir, debug_logger=logger).get_location(alias)
        payload = (
            anonymized_location(config_dir, fix)
            if anonymise
            else plain_location(fix)
        )
    except SecretStoreError as exc:
        print(f"people: secret_store_error: {exc}")
        return 1
    except (PeopleProvisioningError, PeopleLocationError) as exc:
        print(f"people: provisioning_error: {exc}")
        return 1
    except PeopleProtocolError as exc:
        status = "unknown" if exc.status is None else str(exc.status)
        print(f"people: protocol_error: status={status} category={exc}")
        return 1

    print(json.dumps({"locations": [payload]}, indent=2, sort_keys=True))
    return 0


class _FMFSession:
    def __init__(
        self,
        *,
        account: Any,
        state: dict[str, Any],
        device: DeviceIdentity,
        debug_logger: DebugLogger,
        aps_token: str = "",
    ) -> None:
        login_data = _dict_path(state, "login", "data")
        mobileme_data = _dict_path(login_data, "mobileme_data")
        self.dsid = _string_value(login_data.get("dsid"))
        if self.dsid is None:
            raise PeopleProvisioningError("saved account is missing DSID")
        self.token = _find_first_string(
            mobileme_data,
            (
                "friendsToken",
                "mmeFMFToken",
                "fmfToken",
                "mmeFMFAppToken",
                "authToken",
            ),
        )
        if self.token is None:
            raise PeopleProvisioningError("saved account is missing an FMF token")
        self.host = _normalize_host(
            _find_first_string(
                mobileme_data,
                ("fmfHost", "friendsHost", "mmeFMFHost", "host", "url"),
            )
            or DEFAULT_FMF_HOST,
        )
        self.account = account
        self.device = device
        self.client_udid = getattr(device, "fmf_udid", "") or device.udid
        self.debug_logger = debug_logger
        self.aps_token = aps_token
        self.caller = (
            _string_value(_dict_path(state, "account").get("username")) or ""
        )
        self.server_context: Any = {}
        self.data_context: Any = {}

    def initialize(self) -> dict[str, Any]:
        return self._request("initClient")

    def refresh(self, *, selected_fm_id: str | None = None) -> dict[str, Any]:
        path = (
            "minCallback/selFriend/refreshClient"
            if selected_fm_id is not None
            else "minCallback/refreshClient"
        )
        return self._request(path, selected_fm_id=selected_fm_id)

    def _request(
        self,
        path: str,
        *,
        selected_fm_id: str | None = None,
    ) -> dict[str, Any]:
        from onitrack.ids import _device_build

        headers = dict(self.account.get_anisette_headers(with_client_info=False))
        anisette_device_id = next(
            (
                str(value)
                for key, value in headers.items()
                if key.casefold() == "x-mme-device-id" and value
            ),
            "",
        )
        headers.update(
            {
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
                "Content-Type": "application/json",
                "User-Agent": "FMFD/1.0 com.apple.iCloudHelper/282",
                "X-Apple-AuthScheme": "Forever",
                "X-Apple-Find-API-Ver": "2.0",
                "X-Apple-I-Locale": "en_US",
                "X-Apple-Realm-Support": "1.0",
                "X-FMF-Model-Version": FMF_MODEL_VERSION,
                "X-MMe-Client-Info": (
                    f"<{self.device.product_type}> "
                    f"<macOS;{self.device.os_version};"
                    f"{_device_build(self.device)}> "
                    "<com.apple.AuthKit/1 (com.apple.findmy/375.20)>"
                ),
            },
        )
        client_context = {
            "appName": "fmfd",
            "appVersion": "7.0",
            "apsToken": self.aps_token,
            "buildVersion": _device_build(self.device),
            "countryCode": "US",
            "currentTime": time.time(),
            "deviceClass": "Mac",
            "deviceHasPasscode": True,
            "deviceUDID": self.client_udid.lower(),
            "fencingEnabled": True,
            "isFMFAppRemoved": False,
            "osVersion": self.device.os_version,
            "platform": "macosx",
            "processId": str(os.getpid()),
            "productType": self.device.product_type,
            "regionCode": "US",
            "selectedFriend": selected_fm_id,
            "signedInAs": self.caller,
            "timezone": "UTC, 0",
            "unlockState": 0,
        }
        body = {
            "clientContext": client_context,
            "dataContext": self.data_context,
            "serverContext": self.server_context,
        }
        response = _post_json(
            FMF_ENDPOINT_TEMPLATE.format(
                host=self.host,
                dsid=self.dsid,
                device_udid=self.client_udid,
                path=path,
            ),
            headers=headers,
            auth=(self.dsid, self.token),
            body=body,
        )
        if "serverContext" in response:
            self.server_context = response["serverContext"]
        if "dataContext" in response:
            self.data_context = response["dataContext"]
        devices = response.get("devices")
        matching_devices = [
            item
            for item in devices
            if isinstance(item, dict)
            and _contains_string(item, self.device.display_name)
        ] if isinstance(devices, list) else []
        self.debug_logger.emit(
            "fmf_request",
            {
                "status": 200,
                "path": path,
                "dsid": self.dsid,
                "fmf_host": self.host,
                "fmId": selected_fm_id,
                "model_version": FMF_MODEL_VERSION,
                "response_keys": sorted(response),
                "device_display_name": self.device.display_name,
                "device_profile": self.device.product_type,
                "device_profile_fallback": (
                    self.device.product_type == APPLE_FALLBACK_PRODUCT_TYPE
                ),
                "device_count": len(devices) if isinstance(devices, list) else 0,
                "client_device_present": _contains_string(
                    devices,
                    self.client_udid,
                ),
                "ids_device_present": _contains_identifier(
                    devices,
                    self.device.udid,
                ),
                "anisette_device_present": bool(anisette_device_id)
                and _contains_identifier(devices, anisette_device_id),
                "client_display_name_present": bool(matching_devices),
                "client_device_keys": sorted(
                    {
                        key
                        for item in matching_devices
                        for key in item
                        if isinstance(key, str)
                    },
                ),
                "client_device_identifiers": [
                    {
                        key: item[key]
                        for key in ("id", "deviceId", "deviceUDID", "udid")
                        if key in item
                    }
                    for item in matching_devices
                ],
                "following_count": len(response.get("following", []))
                if isinstance(response.get("following"), list)
                else 0,
            },
        )
        return response


class PeopleClient:
    def __init__(
        self,
        config_dir: Path,
        debug_logger: DebugLogger | None = None,
    ) -> None:
        self.config_dir = config_dir
        self.debug_logger = debug_logger or DebugLogger(config_dir, enabled=False)

    def list_relationships(self) -> list[PersonRelationship]:
        account = self._load_logged_in_account()
        try:
            state = account.to_json()
            device = load_or_create_device_identity(self.config_dir)
            response = self._init_client(account, state, device)
            return parse_following(response)
        finally:
            _close_account(account)

    def get_location(self, alias: str) -> LocationFix:
        people_state = load_people_state(self.config_dir)
        alias_config = _dict_value(_dict_value(people_state.get("aliases")).get(alias))
        person_id = _string_value(alias_config.get("person_id"))
        if person_id is None:
            raise PeopleLocationError("alias is not configured")

        account = self._load_logged_in_account()
        try:
            state = account.to_json()
            device = load_or_create_device_identity(self.config_dir)
            response = self._init_client(account, state, device)
            relationship = relationship_for_person_id(
                self.config_dir,
                parse_following(response),
                person_id,
            )
            if relationship is None:
                raise PeopleLocationError(
                    "configured alias no longer matches an accepted relationship",
                )

            key = load_people_key(people_state, person_id)
            if key is None:
                self.debug_logger.emit(
                    "people_key_missing",
                    {
                        "alias": alias,
                        "person_id": person_id,
                        "fmId": relationship.fm_id,
                    },
                )
                raise PeopleLocationError(
                    "People location key is pending; APNs/IDS provisioning is required",
                )

            apns_token = _string_value(
                _dict_path(people_state, "apns").get("courier_token"),
            )
            if apns_token is None:
                raise PeopleLocationError("APNs courier token is missing")

            searchparty = self._fetch_searchparty(
                account,
                state,
                device,
                relationship.fm_id,
                key.advertised_id,
                apns_token,
            )
            report = select_searchparty_report(searchparty, key.advertised_id)
            if report is None:
                raise PeopleLocationError("no SearchParty report for configured alias")
            private_key = parse_people_private_key_blob(key.private_key_blob)
            plaintext = decrypt_searchparty_location(report.ciphertext, private_key)
            decoded = parse_location_plaintext(plaintext, report.location_ts)
            return LocationFix(
                alias=alias,
                person_id=person_id,
                fm_id=relationship.fm_id,
                advertised_id=key.advertised_id,
                latitude=decoded["latitude"],
                longitude=decoded["longitude"],
                horizontal_accuracy_m=decoded.get("horizontal_accuracy_m"),
                source_timestamp=decoded.get("source_timestamp"),
                received_timestamp=datetime.now(UTC),
            )
        finally:
            _close_account(account)

    def acquire_key(self, alias: str, *, wait_seconds: int) -> PeopleKey:
        people_state = load_people_state(self.config_dir)
        person_id = _person_id_for_alias(people_state, alias)
        existing = load_people_key(people_state, person_id)
        if existing is not None:
            parse_people_private_key_blob(existing.private_key_blob)
            return existing

        account = self._load_logged_in_account()
        try:
            state = account.to_json()
            device = load_or_create_device_identity(self.config_dir)
            from onitrack.ids import _registration_device, _version_ua
            from onitrack.key_acquisition import PeopleKeyAcquirer

            registered_device = _registration_device(
                device,
                _dict_value(people_state.get("ids")),
            )
            acquirer = PeopleKeyAcquirer(
                people_state=people_state,
                user_agent=_version_ua(registered_device),
                debug_emit=self.debug_logger.emit,
                receiver_preflight=self.debug_logger.enabled,
            )

            def prepare_delivery(base_token: bytes) -> PersonRelationship:
                aps_token = base_token.hex().upper()
                session = _FMFSession(
                    account=account,
                    state=state,
                    device=registered_device,
                    debug_logger=self.debug_logger,
                    aps_token=aps_token,
                )
                response = session.initialize()
                relationship = relationship_for_person_id(
                    self.config_dir,
                    parse_following(response),
                    person_id,
                )
                if relationship is None:
                    raise PeopleLocationError(
                        "configured alias no longer matches an accepted relationship",
                    )
                session.refresh()
                session.refresh(selected_fm_id=relationship.fm_id)
                self._fetch_searchparty(
                    account,
                    state,
                    registered_device,
                    relationship.fm_id,
                    None,
                    aps_token,
                    intent="distributeKeys",
                    mode="proactive",
                )
                return relationship

            def accept_delivery(delivery: Any) -> None:
                from onitrack.key_acquisition import KeyAcquisitionError

                try:
                    parse_people_private_key_blob(delivery.private_key_blob)
                except PeopleLocationError as exc:
                    raise KeyAcquisitionError(
                        "Find My P-224 key is invalid",
                    ) from exc
                _store_people_key(
                    self.config_dir,
                    person_id=person_id,
                    advertised_id=delivery.advertised_id,
                    private_key_blob=delivery.private_key_blob,
                )

            delivery = asyncio.run(
                acquirer.acquire(
                    wait_seconds=wait_seconds,
                    prepare_delivery=prepare_delivery,
                    accept_delivery=accept_delivery,
                ),
            )
            return PeopleKey(
                person_id=person_id,
                advertised_id=delivery.advertised_id,
                private_key_blob=delivery.private_key_blob,
            )
        finally:
            _close_account(account)

    def _load_logged_in_account(self) -> Any:
        account_path = account_config_path(self.config_dir)
        account_state = secret_section(self.config_dir, "account")
        if not account_state and account_path.exists():
            legacy_account_state = read_json(account_path) or {}
            if legacy_account_state != account_metadata(legacy_account_state):
                account_state = legacy_account_state
        if not account_state:
            raise PeopleProvisioningError("run `onitrack auth provision` first")

        from findmy import AppleAccount

        account = AppleAccount.from_json(
            account_state,
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
        return _FMFSession(
            account=account,
            state=state,
            device=device,
            debug_logger=self.debug_logger,
        ).initialize()

    def _fetch_searchparty(
        self,
        account: Any,
        state: dict[str, Any],
        device: DeviceIdentity,
        fm_id: str,
        advertised_id: str | None,
        apns_token: str,
        *,
        intent: str = "startLocationUpdates",
        mode: str = "shallow",
    ) -> dict[str, Any]:
        from onitrack.ids import _device_build

        login_data = _dict_path(state, "login", "data")
        dsid = _string_value(login_data.get("dsid"))
        if dsid is None:
            raise PeopleProvisioningError("saved account is missing DSID")
        token = _find_first_string(
            _dict_path(login_data, "mobileme_data"),
            ("searchPartyToken", "mmeSearchPartyToken", "searchpartyToken"),
        )
        if token is None:
            raise PeopleProvisioningError(
                "saved account is missing a SearchParty token",
            )

        headers = dict(account.get_anisette_headers(with_client_info=False))
        headers.update(
            {
                "Accept": "application/json",
                "accept-version": "4",
                "Content-Type": "application/json",
                "User-Agent": (
                    f"searchpartyuseragent/1 {device.product_type}/"
                    f"{device.os_version}"
                ),
                "X-MMe-Client-Info": (
                    f"<{device.product_type}> <macOS;{device.os_version};"
                    f"{_device_build(device)}> "
                    "<com.apple.icloud.searchpartyuseragent/1.0>"
                ),
                "x-apple-i-device-type": "1",
                "x-apple-setup-proxy-request": "true",
            },
        )
        body = {
            "fetch": [
                {
                    "fmId": fm_id,
                    "intent": intent,
                    "mode": mode,
                    "ids": [] if advertised_id is None else [advertised_id],
                },
            ],
            "clientContext": {
                "apsToken": apns_token,
                "clientId": (
                    getattr(device, "fmf_udid", "") or device.udid
                ).lower(),
                "contextApp": FINDMYLOCATED_BUNDLE,
                "deviceDisplayName": device.display_name,
                "productType": device.product_type,
                "shallowStats": {},
                "liveStats": {},
                "nearbyWatchIdentifiers": [],
            },
        }
        response = _post_json(
            SEARCHPARTY_ENDPOINT,
            headers=headers,
            auth=(dsid, token),
            body=body,
        )
        payload = response.get("locationPayload", [])
        self.debug_logger.emit(
            "searchparty_fetch",
            {
                "status": 200,
                "dsid": dsid,
                "fmId": fm_id,
                "advertised_id": advertised_id,
                "device_display_name": device.display_name,
                "device_profile": device.product_type,
                "device_profile_fallback": (
                    device.product_type == APPLE_FALLBACK_PRODUCT_TYPE
                ),
                "response_keys": sorted(response),
                "apple_status_code": _safe_integer(response.get("statusCode")),
                "location_payload_count": len(payload)
                if isinstance(payload, list)
                else 0,
            },
        )
        return response


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


def anonymized_location(config_dir: Path, fix: LocationFix) -> dict[str, Any]:
    source_age_seconds = None
    if fix.source_timestamp is not None:
        source_age_seconds = max(
            0,
            int((fix.received_timestamp - fix.source_timestamp).total_seconds()),
        )
    return {
        "alias_id": anonymize_value(config_dir, fix.alias),
        "person_id": fix.person_id,
        "status": "location_available",
        "location_available": True,
        "source_age_seconds": source_age_seconds,
        "horizontal_accuracy_m": fix.horizontal_accuracy_m,
        "position_digest": anonymize_value(
            config_dir,
            _coordinate_digest_input(fix.latitude, fix.longitude),
        ),
        "report_digest": anonymize_value(
            config_dir,
            "|".join(
                [
                    _coordinate_digest_input(fix.latitude, fix.longitude),
                    fix.source_timestamp.isoformat()
                    if fix.source_timestamp is not None
                    else "",
                    ""
                    if fix.horizontal_accuracy_m is None
                    else str(fix.horizontal_accuracy_m),
                ],
            ),
        ),
        "key_status": fix.key_status,
    }


def plain_location(fix: LocationFix) -> dict[str, Any]:
    return {
        "alias": fix.alias,
        "person_id": fix.person_id,
        "fm_id": fix.fm_id,
        "advertised_id": fix.advertised_id,
        "status": "location_available",
        "location_available": True,
        "latitude": fix.latitude,
        "longitude": fix.longitude,
        "horizontal_accuracy_m": fix.horizontal_accuracy_m,
        "source_timestamp": fix.source_timestamp.isoformat()
        if fix.source_timestamp is not None
        else None,
        "received_timestamp": fix.received_timestamp.isoformat(),
        "key_status": fix.key_status,
    }


def relationship_for_person_id(
    config_dir: Path,
    relationships: list[PersonRelationship],
    person_id: str,
) -> PersonRelationship | None:
    salt = load_or_create_privacy_salt(config_dir)
    for relationship in relationships:
        if _hmac_hex(salt, relationship.fm_id) == person_id:
            return relationship
    return None


def load_people_state(config_dir: Path) -> dict[str, Any]:
    metadata = read_json(people_config_path(config_dir)) or {}
    secrets = secret_section(config_dir, "people")
    return _merge_dicts(secrets, metadata)


def _person_id_for_alias(state: dict[str, Any], alias: str) -> str:
    alias_config = _dict_value(_dict_value(state.get("aliases")).get(alias))
    person_id = _string_value(alias_config.get("person_id"))
    if person_id is None:
        raise PeopleLocationError("alias is not configured")
    return person_id


def write_people_state(config_dir: Path, state: dict[str, Any]) -> None:
    path = people_config_path(config_dir)
    secret_keys = {
        "advertised_ids",
        "apns",
        "apple_tokens",
        "findmy",
        "ids",
        "keys",
        "registration",
    }
    metadata = {key: value for key, value in state.items() if key not in secret_keys}
    secrets = secret_section(config_dir, "people")
    for key in secret_keys:
        if key in state:
            secrets[key] = state[key]
    if secrets:
        write_secret_section(config_dir, "people", secrets)
    write_json_atomic(path, metadata)
    path.chmod(CONFIG_FILE_MODE)


def load_people_key(state: dict[str, Any], person_id: str) -> PeopleKey | None:
    key_state = _dict_value(_dict_value(state.get("keys")).get(person_id))
    advertised_id = _string_value(key_state.get("advertised_id"))
    encoded_key = _string_value(key_state.get("private_key"))
    if advertised_id is None or encoded_key is None:
        return None
    try:
        private_key_blob = base64.b64decode(encoded_key, validate=True)
    except ValueError:
        raise PeopleLocationError("stored People location key is malformed") from None
    return PeopleKey(
        person_id=person_id,
        advertised_id=advertised_id,
        private_key_blob=private_key_blob,
    )


def select_searchparty_report(
    response: dict[str, Any],
    advertised_id: str,
) -> SearchPartyReport | None:
    candidates: list[SearchPartyReport] = []
    payloads = response.get("locationPayload", [])
    if not isinstance(payloads, list):
        return None

    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        if _string_value(payload.get("id")) != advertised_id:
            continue
        infos = payload.get("locationInfo", [])
        if not isinstance(infos, list):
            continue
        for info in infos:
            if not isinstance(info, dict):
                continue
            encoded_location = _string_value(info.get("location"))
            if encoded_location is None:
                continue
            try:
                ciphertext = base64.b64decode(encoded_location, validate=True)
            except ValueError:
                continue
            if len(ciphertext) <= P224_PUBLIC_KEY_BYTES:
                continue
            location_ts = _number_value(info.get("locationTs"))
            candidates.append(
                SearchPartyReport(
                    advertised_id=advertised_id,
                    ciphertext=ciphertext,
                    location_ts=location_ts,
                ),
            )

    if not candidates:
        return None
    return max(candidates, key=lambda report: report.location_ts or 0)


def parse_people_private_key_blob(blob: bytes) -> Any:
    if len(blob) != P224_PRIVATE_BLOB_BYTES:
        raise PeopleLocationError("stored People location key has invalid length")

    from cryptography.hazmat.primitives.asymmetric import ec

    public_bytes = blob[:P224_PUBLIC_KEY_BYTES]
    scalar = int.from_bytes(blob[P224_PUBLIC_KEY_BYTES:], "big")
    if scalar <= 0:
        raise PeopleLocationError("stored People location key has invalid scalar")

    try:
        from cryptography.hazmat.primitives import serialization

        private_key = ec.derive_private_key(scalar, ec.SECP224R1())
        derived_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
    except ValueError as exc:
        raise PeopleLocationError("stored People location key is invalid") from exc

    if not hmac.compare_digest(public_bytes, derived_public):
        raise PeopleLocationError("stored People location key public point mismatch")
    return private_key


def decrypt_searchparty_location(ciphertext: bytes, private_key: Any) -> bytes:
    if len(ciphertext) <= P224_PUBLIC_KEY_BYTES:
        raise PeopleLocationError("SearchParty location ciphertext is too short")

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ephemeral_bytes = ciphertext[:P224_PUBLIC_KEY_BYTES]
    payload = ciphertext[P224_PUBLIC_KEY_BYTES:]
    try:
        ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP224R1(),
            ephemeral_bytes,
        )
        secret = private_key.exchange(ec.ECDH(), ephemeral)
        material = x963_sha256(secret, 32, shared_info=ephemeral_bytes)
        return AESGCM(material[:16]).decrypt(material[16:32], payload, None)
    except ValueError as exc:
        raise PeopleLocationError(
            "SearchParty location could not be decrypted",
        ) from exc


def x963_sha256(secret: bytes, length: int, *, shared_info: bytes = b"") -> bytes:
    output = b""
    counter = 1
    while len(output) < length:
        output += hashlib.sha256(
            secret + counter.to_bytes(4, "big") + shared_info,
        ).digest()
        counter += 1
    return output[:length]


def parse_location_plaintext(
    plaintext: bytes,
    outer_location_ts: float | int | None,
) -> dict[str, Any]:
    decoded: Any
    try:
        decoded = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            decoded = plistlib.loads(plaintext)
        except plistlib.InvalidFileException as exc:
            raise PeopleLocationError(
                "SearchParty location plaintext is malformed",
            ) from exc

    if not isinstance(decoded, dict):
        raise PeopleLocationError("SearchParty location plaintext is malformed")

    latitude = _first_number(decoded, ("latitude", "lat"))
    longitude = _first_number(decoded, ("longitude", "lon", "lng"))
    if latitude is None or longitude is None:
        coordinate = _dict_value(decoded.get("coordinate") or decoded.get("location"))
        latitude = _first_number(coordinate, ("latitude", "lat"))
        longitude = _first_number(coordinate, ("longitude", "lon", "lng"))
    if latitude is None or longitude is None:
        raise PeopleLocationError(
            "SearchParty location plaintext is missing coordinates",
        )

    accuracy = _first_number(
        decoded,
        ("horizontalAccuracy", "horizontal_accuracy", "accuracy"),
    )
    timestamp_value = _first_number(
        decoded,
        ("timestamp", "timeStamp", "locationTs", "locationTimestamp"),
    )
    if timestamp_value is None:
        timestamp_value = outer_location_ts

    return {
        "latitude": float(latitude),
        "longitude": float(longitude),
        "horizontal_accuracy_m": None if accuracy is None else float(accuracy),
        "source_timestamp": apple_timestamp(timestamp_value),
    }


def apple_timestamp(value: float | int | None) -> datetime | None:
    if value is None:
        return None
    numeric = float(value)
    if numeric > 10_000_000_000:
        return datetime.fromtimestamp(numeric / 1000, tz=UTC)
    if numeric > 1_000_000_000:
        return datetime.fromtimestamp(numeric, tz=UTC)
    return APPLE_EPOCH + timedelta(seconds=numeric)


def anonymize_value(config_dir: Path, value: str) -> str:
    return _hmac_hex(load_or_create_privacy_salt(config_dir), value)


class DebugLogger:
    def __init__(self, config_dir: Path, *, enabled: bool) -> None:
        self.enabled = enabled
        self.redactor = DebugRedactor(load_or_create_privacy_salt(config_dir))

    def emit(self, step: str, fields: dict[str, Any]) -> None:
        if not self.enabled:
            return
        payload = {"step": step, **self.redactor.redact(fields)}
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)


class DebugRedactor:
    _sensitive_keys = {
        "handle",
        "handles",
        "accepted_handles",
        "fmId",
        "fm_id",
        "dsid",
        "apsToken",
        "apns_token",
        "courier_token",
        "push_token",
        "sender",
        "sender_handle",
        "advertised_id",
        "id",
        "key_id",
        "account_id",
        "alias",
        "apple_id",
        "device_display_name",
        "deviceId",
        "deviceUDID",
        "udid",
        "profile_id",
        "target",
    }
    _remove_keys = {
        "authToken",
        "authorization",
        "password",
        "private_key",
        "raw_response",
        "anisette_headers",
        "latitude",
        "longitude",
        "coordinates",
    }

    def __init__(self, salt: bytes) -> None:
        self.salt = salt

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            redacted = {}
            for key, child in value.items():
                if key in self._remove_keys or key.lower() in self._remove_keys:
                    redacted[key] = "<redacted>"
                elif key in self._sensitive_keys or key.lower() in self._sensitive_keys:
                    redacted[f"{key}_hmac"] = self._hash_value(child)
                else:
                    redacted[key] = self.redact(child)
            return redacted
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        return value

    def _hash_value(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._hash_value(item) for item in value]
        if isinstance(value, dict):
            return {
                key: self._hash_value(child)
                for key, child in sorted(value.items(), key=lambda item: item[0])
            }
        return _hmac_hex(self.salt, str(value))


def load_or_create_privacy_salt(config_dir: Path) -> bytes:
    state = secret_section(config_dir, "privacy")
    salt = _string_value(state.get("anonymization_salt"))
    if salt:
        return base64.b64decode(salt)

    path = privacy_config_path(config_dir)
    legacy_state = read_json(path)
    legacy_salt = (
        _string_value(legacy_state.get("anonymization_salt"))
        if legacy_state is not None
        else None
    )
    if legacy_salt:
        write_secret_section(
            config_dir,
            "privacy",
            {"anonymization_salt": legacy_salt},
        )
        if read_secrets := secret_section(config_dir, "privacy"):
            if read_secrets.get("anonymization_salt") == legacy_salt:
                write_json_atomic(path, {"encrypted": True})
                path.chmod(CONFIG_FILE_MODE)
                return base64.b64decode(legacy_salt)

    salt_bytes = os.urandom(32)
    write_secret_section(
        config_dir,
        "privacy",
        {"anonymization_salt": base64.b64encode(salt_bytes).decode("ascii")},
    )
    write_json_atomic(path, {"encrypted": True})
    path.chmod(CONFIG_FILE_MODE)
    return salt_bytes


def load_or_create_device_identity(config_dir: Path) -> DeviceIdentity:
    path = device_config_path(config_dir)
    state = read_json(path)
    if state is not None:
        udid = _string_value(state.get("udid"))
        display_name = (
            _string_value(state.get("display_name")) or default_display_name()
        )
        product_type = _string_value(state.get("product_type")) or APPLE_PRODUCT_TYPE
        os_version = _string_value(state.get("os_version")) or APPLE_OS_VERSION
        if udid:
            fmf_udid = _string_value(state.get("fmf_udid"))
            if fmf_udid is None:
                fmf_udid = os.urandom(32).hex().upper()
                write_json_atomic(path, {**state, "fmf_udid": fmf_udid})
                path.chmod(CONFIG_FILE_MODE)
            return DeviceIdentity(
                udid=udid,
                display_name=display_name,
                product_type=product_type,
                os_version=os_version,
                fmf_udid=fmf_udid,
            )

    ensure_config_dir(config_dir)
    identity = DeviceIdentity(
        udid=uuid.uuid4().hex.upper(),
        display_name=default_display_name(),
        fmf_udid=os.urandom(32).hex().upper(),
    )
    write_json_atomic(
        path,
        {
            "display_name": identity.display_name,
            "fmf_udid": identity.fmf_udid,
            "os_version": identity.os_version,
            "product_type": identity.product_type,
            "udid": identity.udid,
        },
    )
    path.chmod(CONFIG_FILE_MODE)
    return identity


def default_display_name() -> str:
    hostname = socket.gethostname().strip().split(".")[0]
    if not hostname:
        return "onitrack"
    safe_hostname = "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in hostname
    ).strip("-_")
    if not safe_hostname:
        return "onitrack"
    return f"onitrack@{safe_hostname}"


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


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _merge_dicts(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    merged = dict(first)
    for key, value in second.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _number_value(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    return None


def _first_number(data: dict[str, Any], keys: tuple[str, ...]) -> float | int | None:
    for key in keys:
        value = _number_value(data.get(key))
        if value is not None:
            return value
    return None


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


def _safe_integer(value: Any) -> int | str:
    if isinstance(value, bool):
        return "unknown"
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return "unknown"


def _contains_string(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value.casefold() == expected.casefold()
    if isinstance(value, dict):
        return any(_contains_string(child, expected) for child in value.values())
    if isinstance(value, list):
        return any(_contains_string(child, expected) for child in value)
    return False


def _contains_identifier(value: Any, expected: str) -> bool:
    normalized = "".join(character for character in expected if character.isalnum())
    if isinstance(value, str):
        candidate = "".join(character for character in value if character.isalnum())
        return bool(normalized) and candidate.casefold() == normalized.casefold()
    if isinstance(value, dict):
        return any(_contains_identifier(child, expected) for child in value.values())
    if isinstance(value, list):
        return any(_contains_identifier(child, expected) for child in value)
    return False


def _coordinate_digest_input(latitude: float, longitude: float) -> str:
    return f"{latitude:.6f},{longitude:.6f}"


def _looks_like_hmac_id(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _hmac_hex(salt: bytes, value: str) -> str:
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
