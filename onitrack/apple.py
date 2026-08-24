from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from onitrack.people import load_or_create_device_identity
from onitrack.state import (
    SecretStoreError,
    migrate_legacy_secrets,
    secret_section,
    write_secret_section,
)

APPLE_HELPER_ENV = "ONITRACK_APPLE_HELPER"
APPLE_HELPER_DEFAULT = "onitrack-apple-helper"
APNS_TOPICS = (
    "com.apple.private.ids",
    "com.apple.private.alloy.fmf",
    "com.apple.private.alloy.fmd",
    "com.apple.private.alloy.multiplex1",
)


class AppleRegistrationError(RuntimeError):
    pass


def register(config_dir: Path, *, debug_redacted: bool = False) -> int:
    try:
        result = register_state(config_dir, debug_redacted=debug_redacted)
    except SecretStoreError as exc:
        print(f"apple: secret_store_error: {exc}")
        return 1
    except AppleRegistrationError as exc:
        print(f"apple: registration_error: {exc}")
        return 1

    print(f"apple: {result['status']}")
    print(f"device: {result['device_display_name']} {result['device_profile']}")
    return 0


def register_state(config_dir: Path, *, debug_redacted: bool = False) -> dict[str, Any]:
    migrate_legacy_secrets(config_dir)
    account = secret_section(config_dir, "account")
    if not account:
        raise AppleRegistrationError("run `onitrack auth provision` first")

    device = load_or_create_device_identity(config_dir)
    people = secret_section(config_dir, "people")
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

    helper = _helper_path()
    request = {
        "account": account,
        "debug_redacted": debug_redacted,
        "device": {
            "display_name": device.display_name,
            "os_version": device.os_version,
            "product_type": device.product_type,
            "udid": device.udid,
        },
        "existing_people_state": people,
    }
    response = _run_helper(helper, request)
    exported_people = _dict_value(response.get("people"))
    if not _registered(exported_people):
        raise AppleRegistrationError(
            "helper did not return APNs courier token and IDS registration state",
        )

    merged_people = _merge_dicts(people, exported_people)
    write_secret_section(config_dir, "people", merged_people)
    sanitized_account = _dict_value(response.get("account"))
    if sanitized_account:
        write_secret_section(config_dir, "account", sanitized_account)

    return {
        "status": "registered",
        "device_display_name": device.display_name,
        "device_profile": device.product_type,
    }


def _helper_path() -> str:
    configured = os.environ.get(APPLE_HELPER_ENV)
    helper = configured or APPLE_HELPER_DEFAULT
    path = shutil.which(helper) if os.path.basename(helper) == helper else helper
    if path is None:
        raise AppleRegistrationError(
            f"`{helper}` is required for APNs/IDS registration",
        )
    return path


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
        base_token = await conn.base_token
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


def _run_helper(helper: str, request: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(request, separators=(",", ":"), sort_keys=True).encode()
    try:
        result = subprocess.run(
            [helper, "register"],
            input=encoded,
            check=True,
            capture_output=True,
        )
    except OSError as exc:
        raise AppleRegistrationError("failed to run APNs/IDS helper") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        msg = "APNs/IDS helper failed"
        if detail:
            msg = f"{msg}: {detail}"
        raise AppleRegistrationError(msg) from exc

    try:
        decoded = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppleRegistrationError("APNs/IDS helper returned malformed JSON") from exc
    if not isinstance(decoded, dict):
        raise AppleRegistrationError("APNs/IDS helper returned non-object JSON")
    return decoded


def _registered(people: dict[str, Any]) -> bool:
    return bool(_dict_path(people, "apns").get("courier_token")) and bool(
        _dict_path(people, "ids"),
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
