import json
import os
import sys
import types
from datetime import UTC, datetime, timedelta

import pytest

from onitrack.apple import _anisette_headers, _register_apns, register_state
from onitrack.ids import IDSRegistrationError, IDSRegistrationResult
from onitrack.main import main
from onitrack.state import read_secrets, write_secret_section


def test_apple_register_persists_native_ids_state(
    monkeypatch,
    tmp_path,
    capsys,
):
    captured = {}

    def fake_register_ids(**kwargs):
        captured.update(kwargs)
        return IDSRegistrationResult(
            ids_state={
                "registered": True,
                "service": "com.apple.private.alloy.multiplex1",
            },
            account_state={
                "account": {"username": "person@example.com"},
                "login": {"state": 3, "data": {"dsid": "123"}},
            },
        )

    monkeypatch.setattr(
        "onitrack.apple._anisette_headers",
        lambda *args, **kwargs: {"h": "v"},
    )
    monkeypatch.setattr("onitrack.apple.register_ids", fake_register_ids)
    write_secret_section(
        tmp_path,
        "account",
        {
            "account": {"username": "person@example.com"},
            "login": {"state": 3, "data": {"idms_pet": "transient-pet"}},
        },
    )
    write_secret_section(
        tmp_path,
        "people",
        {
            "apns": {
                "certificate_pem": "cert",
                "courier_token": "00",
                "private_key_pem": "key",
                "scoped_tokens": {
                    "com.apple.private.ids": "01",
                    "com.apple.private.alloy.fmf": "02",
                    "com.apple.private.alloy.fmd": "03",
                    "com.apple.private.alloy.multiplex1": "04",
                },
            },
        },
    )

    result = register_state(tmp_path, debug_redacted=True)

    secrets = read_secrets(tmp_path)
    assert result["status"] == "registered"
    assert captured["anisette_headers"] == {"h": "v"}
    assert captured["account_state"]["login"]["data"]["idms_pet"] == "transient-pet"
    assert captured["apns_state"]["courier_token"] == "00"
    assert secrets["people"]["ids"]["registered"] is True
    assert "idms_pet" not in json.dumps(secrets["account"])
    assert capsys.readouterr().out == ""


def test_apple_register_imports_external_validation_json(
    monkeypatch,
    tmp_path,
):
    captured = {}

    def fake_register_ids(**kwargs):
        captured.update(kwargs)
        return IDSRegistrationResult(
            ids_state={"registered": True},
            account_state={"account": {"username": "person@example.com"}},
        )

    def fake_anisette_headers(*args, **kwargs):
        captured["anisette_serial"] = kwargs["serial_number"]
        return {}

    monkeypatch.setattr("onitrack.apple._anisette_headers", fake_anisette_headers)
    monkeypatch.setattr("onitrack.apple.register_ids", fake_register_ids)
    write_secret_section(
        tmp_path,
        "account",
        {"account": {"username": "person@example.com"}, "login": {"state": 3}},
    )
    write_secret_section(
        tmp_path,
        "people",
        {
            "apns": {
                "certificate_pem": "cert",
                "courier_token": "00",
                "private_key_pem": "key",
                "scoped_tokens": {
                    "com.apple.private.ids": "01",
                    "com.apple.private.alloy.fmf": "02",
                    "com.apple.private.alloy.fmd": "03",
                    "com.apple.private.alloy.multiplex1": "04",
                },
            },
        },
    )
    validation_path = tmp_path / "validation.json"
    validation_path.write_text(
        json.dumps(
            {
                "validation_data": "dmFsaWRhdGlvbg==",
                "valid_until": "2026-08-24T12:00:00Z",
                "device_info": {
                    "hardware_version": "Mac14,3",
                    "serial_number": "SYNTHETIC-SERIAL",
                    "software_name": "macOS",
                    "software_version": "14.3",
                    "software_build_id": "23D56",
                },
            },
        ),
        encoding="utf-8",
    )

    result = register_state(
        tmp_path,
        debug_redacted=True,
        validation_json=os.fspath(validation_path),
    )

    assert result["status"] == "registered"
    external = captured["existing"]["external_validation"]
    assert external["validation_data"] == "dmFsaWRhdGlvbg=="
    assert external["device_info"]["hardware_version"] == "Mac14,3"
    assert captured["anisette_serial"] == "SYNTHETIC-SERIAL"
    secrets = read_secrets(tmp_path)
    assert secrets["people"]["ids"]["registered"] is True


def test_apple_register_ids_error_returns_clear_error(
    monkeypatch,
    tmp_path,
    capsys,
):
    monkeypatch.setattr(
        "onitrack.apple._anisette_headers",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "onitrack.apple.register_ids",
        lambda **kwargs: (_ for _ in ()).throw(
            IDSRegistrationError("saved auth lacks delegate-capable IDMS PET"),
        ),
    )
    write_secret_section(
        tmp_path,
        "account",
        {"account": {"username": "person@example.com"}, "login": {"state": 3}},
    )
    write_secret_section(
        tmp_path,
        "people",
        {
            "apns": {
                "certificate_pem": "cert",
                "courier_token": "00",
                "private_key_pem": "key",
                "scoped_tokens": {
                    "com.apple.private.ids": "01",
                    "com.apple.private.alloy.fmf": "02",
                    "com.apple.private.alloy.fmd": "03",
                    "com.apple.private.alloy.multiplex1": "04",
                },
            },
        },
    )

    assert main(["apple", "--config-dir", os.fspath(tmp_path), "register"]) == 1

    output = capsys.readouterr().out
    assert "apple: registration_error:" in output
    assert "delegate-capable IDMS PET" in output


def test_register_apns_activates_and_mints_scoped_tokens(monkeypatch):
    cryptography = pytest.importorskip("cryptography")
    assert cryptography is not None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]),
        )
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )

    class FakeConnection:
        base_token = b"\xaa"

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def mint_scoped_token(self, topic):
            return topic.encode("utf-8")[:4]

    async def fake_activate(**kwargs):
        assert kwargs["device_class"] == "MacOS"
        assert kwargs["model"] == "Macmini9,1"
        return certificate, private_key

    fake_apns = types.SimpleNamespace(
        activate=fake_activate,
        create_apns_connection=(
            lambda certificate, private_key, token=None: FakeConnection()
        ),
    )
    monkeypatch.setitem(sys.modules, "pypush", types.SimpleNamespace(apns=fake_apns))

    state = asyncio_run_register_apns(
        types.SimpleNamespace(
            os_version="14.6",
            product_type="Macmini9,1",
            udid="ABCDEF123456",
        ),
    )

    assert state["courier_token"] == "aa"
    assert state["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert state["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")
    assert set(state["scoped_tokens"]) == {
        "com.apple.private.ids",
        "com.apple.private.alloy.fmf",
        "com.apple.private.alloy.fmd",
        "com.apple.private.alloy.multiplex1",
    }


def asyncio_run_register_apns(device):
    import asyncio

    return asyncio.run(_register_apns(device, {}))


def test_anisette_headers_uses_external_serial(monkeypatch, tmp_path):
    captured = {}

    class FakeAccount:
        @classmethod
        def from_json(cls, state, *, anisette_libs_path):
            captured["state"] = state
            captured["libs"] = anisette_libs_path
            return cls()

        def get_anisette_headers(self, *, with_client_info, serial):
            captured["with_client_info"] = with_client_info
            captured["serial"] = serial
            return {"X-Test": "value"}

        def close(self):
            pass

    monkeypatch.setitem(
        sys.modules,
        "findmy",
        types.SimpleNamespace(AppleAccount=FakeAccount),
    )

    headers = _anisette_headers(
        tmp_path,
        {"account": {"username": "person@example.com"}},
        serial_number="SYNTHETIC-SERIAL",
    )

    assert headers == {"X-Test": "value"}
    assert captured["with_client_info"] is False
    assert captured["serial"] == "SYNTHETIC-SERIAL"
