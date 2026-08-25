from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Any

from onitrack.auth import _anisette_libs_path, _close_account
from onitrack.ids import IDSRegistrationError, register_ids
from onitrack.people import load_or_create_device_identity
from onitrack.state import (
    SecretStoreError,
    migrate_legacy_secrets,
    secret_section,
    write_secret_section,
)
from onitrack.validation import ValidationDataError, load_validation_json

APNS_TOPICS = (
    "com.apple.private.ids",
    "com.apple.private.alloy.fmf",
    "com.apple.private.alloy.fmd",
    "com.apple.private.alloy.multiplex1",
)


class AppleRegistrationError(RuntimeError):
    pass


def register(
    config_dir: Path,
    *,
    debug_redacted: bool = False,
    validation_json: str | None = None,
) -> int:
    try:
        result = register_state(
            config_dir,
            debug_redacted=debug_redacted,
            validation_json=validation_json,
        )
    except SecretStoreError as exc:
        print(f"apple: secret_store_error: {exc}")
        return 1
    except ValidationDataError as exc:
        print(f"apple: validation_error: {exc}")
        return 1
    except AppleRegistrationError as exc:
        print(f"apple: registration_error: {exc}")
        return 1

    print(f"apple: {result['status']}")
    print(f"device: {result['device_display_name']} {result['device_profile']}")
    return 0


def register_state(
    config_dir: Path,
    *,
    debug_redacted: bool = False,
    validation_json: str | None = None,
) -> dict[str, Any]:
    migrate_legacy_secrets(config_dir)
    account = secret_section(config_dir, "account")
    if not account:
        raise AppleRegistrationError("run `onitrack auth provision` first")

    device = load_or_create_device_identity(config_dir)
    people = secret_section(config_dir, "people")
    if validation_json is not None:
        people = _merge_dicts(
            people,
            {"ids": {"external_validation": load_validation_json(validation_json)}},
        )
        write_secret_section(config_dir, "people", people)
    if _registered(people):
        return {
            "status": "registered",
            "device_display_name": device.display_name,
            "device_profile": device.product_type,
        }

    people = _merge_dicts(
        people,
        {
            "apns": asyncio.run(
                _register_apns(device, _dict_value(people.get("apns"))),
            ),
        },
    )
    write_secret_section(config_dir, "people", people)

    try:
        external_device_info = _dict_path(
            people,
            "ids",
            "external_validation",
            "device_info",
        )
        ids_result = register_ids(
            account_state=account,
            anisette_headers=_anisette_headers(
                config_dir,
                account,
                serial_number=_string_value(
                    external_device_info.get("serial_number"),
                ),
            ),
            apns_state=_dict_value(people.get("apns")),
            device=device,
            existing=_dict_value(people.get("ids")),
        )
    except IDSRegistrationError as exc:
        raise AppleRegistrationError(str(exc)) from exc

    people["ids"] = ids_result.ids_state
    write_secret_section(config_dir, "people", people)
    write_secret_section(config_dir, "account", ids_result.account_state)

    return {
        "status": "registered",
        "device_display_name": device.display_name,
        "device_profile": device.product_type,
    }


async def _register_apns(device: Any, existing: dict[str, Any]) -> dict[str, Any]:
    scoped = _dict_value(existing.get("scoped_tokens"))
    if (
        existing.get("courier_token")
        and existing.get("certificate_pem")
        and existing.get("private_key_pem")
        and all(topic in scoped for topic in APNS_TOPICS)
    ):
        return existing

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from pypush import apns
    except ImportError as exc:
        raise AppleRegistrationError(
            "`pypush` is required for APNs activation",
        ) from exc

    certificate_pem = _string_value(existing.get("certificate_pem"))
    private_key_pem = _string_value(existing.get("private_key_pem"))
    if certificate_pem and private_key_pem:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("ascii"),
            password=None,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise AppleRegistrationError("stored APNs private key is not RSA")
    else:
        certificate, private_key = await apns.activate(
            device_class="MacOS",
            udid=device.udid,
            serial=device.udid[:12],
            version=device.os_version,
            build=_macos_build_for_version(device.os_version),
            model=device.product_type,
        )
        certificate_pem = certificate.public_bytes(
            serialization.Encoding.PEM,
        ).decode("ascii")
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    token = _bytes_from_hex(_string_value(existing.get("courier_token")))
    async with apns.create_apns_connection(
        certificate,
        private_key,
        token=token,
    ) as conn:
        base_token = await _maybe_await(conn.base_token)
        scoped_tokens = dict(scoped)
        for topic in APNS_TOPICS:
            if topic not in scoped_tokens:
                scoped_tokens[topic] = (await conn.mint_scoped_token(topic)).hex()

    return {
        **existing,
        "certificate_pem": certificate_pem,
        "courier_token": base_token.hex(),
        "private_key_pem": private_key_pem,
        "scoped_tokens": scoped_tokens,
    }


def _anisette_headers(
    config_dir: Path,
    account_state: dict[str, Any],
    *,
    serial_number: str | None = None,
) -> dict[str, str]:
    from findmy import AppleAccount

    account = AppleAccount.from_json(
        account_state,
        anisette_libs_path=_anisette_libs_path(config_dir),
    )
    try:
        return dict(
            account.get_anisette_headers(
                with_client_info=False,
                serial=serial_number or "0",
            ),
        )
    finally:
        _close_account(account)


def _registered(people: dict[str, Any]) -> bool:
    return bool(_dict_path(people, "apns").get("courier_token")) and bool(
        _dict_path(people, "ids").get("registered"),
    )


def _dict_path(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _bytes_from_hex(value: str | None) -> bytes | None:
    if value is None:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise AppleRegistrationError("stored APNs token is malformed") from exc


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _macos_build_for_version(version: str) -> str:
    return {
        "14.6": "23G80",
    }.get(version, "23G80")


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
