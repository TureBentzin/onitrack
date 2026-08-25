import gzip
import hashlib
import io
import plistlib
from urllib.error import HTTPError

import pytest

from onitrack.ids import (
    IDSRegistrationError,
    _authenticate_ds_id,
    _generate_auth_csr,
    _id_register,
    _login_ids_delegate,
    _mme_client_info,
    _nac_device,
    _registration_device,
    _registration_validation_data,
    _request_plist,
    _version_ua,
)


def test_request_plist_reports_redacted_http_error(monkeypatch):
    payload = plistlib.dumps(
        {
            "description": "bad delegate",
            "localizedError": "INVALID_REQUEST",
            "status": 1,
        },
    )

    def fake_urlopen(req, timeout, context):
        assert req.full_url == "https://example.invalid/login"
        assert timeout == 45
        assert context is not None
        raise HTTPError(
            req.full_url,
            400,
            "Bad Request",
            hdrs=None,
            fp=io.BytesIO(payload),
        )

    monkeypatch.setattr("onitrack.ids.request.urlopen", fake_urlopen)

    with pytest.raises(IDSRegistrationError) as exc_info:
        _request_plist(
            "https://example.invalid/login",
            headers={},
            body=b"request",
        )

    message = str(exc_info.value)
    assert "HTTP 400" in message
    assert "localizedError='INVALID_REQUEST'" in message
    assert "bad delegate" not in message


def test_login_ids_delegate_recommends_refresh_for_unauthorized(monkeypatch):
    def fake_request_plist(*args, **kwargs):
        raise IDSRegistrationError(
            "Apple request failed: HTTP 401 "
            "localizedError='UNAUTHORIZED'",
            http_status=401,
            apple_status=-20101,
            localized_error="UNAUTHORIZED",
        )

    monkeypatch.setattr("onitrack.ids._request_plist", fake_request_plist)

    with pytest.raises(IDSRegistrationError) as exc_info:
        _login_ids_delegate(
            username="person@example.com",
            idms_pet="pet",
            adsid="adsid",
            anisette_headers={},
            device=type(
                "Device",
                (),
                {"os_version": "13.6.4", "product_type": "MacBookAir8,1"},
            )(),
            validation_data=b"validation",
        )

    message = str(exc_info.value)
    assert "HTTP 401" in message
    assert "status=-20101" in message
    assert "localizedError=UNAUTHORIZED" in message
    assert "account credentials" not in message


def test_generate_auth_csr_matches_ids_sha1_shape():
    cryptography = pytest.importorskip("cryptography")
    assert cryptography is not None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509.oid import NameOID

    _key, csr_der = _generate_auth_csr("123456789")

    csr = x509.load_der_x509_csr(csr_der)
    assert isinstance(csr.signature_hash_algorithm, hashes.SHA1)
    csr.public_key().verify(
        csr.signature,
        csr.tbs_certrequest_bytes,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        hashlib.sha1(b"123456789").hexdigest().upper()
    )


def test_authenticate_ds_id_uses_article_request_shape(monkeypatch):
    captured = {}

    monkeypatch.setattr("onitrack.ids._bag", lambda key: f"https://example.invalid/{key}")
    monkeypatch.setattr(
        "onitrack.ids._generate_auth_csr",
        lambda user_id: (object(), b"csr"),
    )

    def fake_request_plist(url, *, headers, body, auth=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["body"] = body
        captured["auth"] = auth
        return {"status": 0, "cert": b"cert"}

    monkeypatch.setattr("onitrack.ids._request_plist", fake_request_plist)
    monkeypatch.setattr("onitrack.ids._private_key_pem", lambda key: "pem")

    _authenticate_ds_id(
        "123456789",
        "token",
        type(
            "Device",
            (),
            {"os_version": "13.6.4", "product_type": "MacBookAir8,1"},
        )(),
    )

    assert captured["url"].endswith("/id-authenticate-ds-id")
    assert captured["headers"]["x-protocol-version"] == "1660"
    assert captured["headers"]["Content-Encoding"] == "gzip"
    assert captured["headers"]["Content-Type"] == "application/x-apple-plist"
    assert captured["auth"] is None
    body = plistlib.loads(gzip.decompress(captured["body"]))
    assert body["authentication-data"] == {"auth-token": "token"}
    assert body["csr"] == b"csr"
    assert body["realm-user-id"] == "123456789"


def test_nac_device_uses_matching_macos_build_tuple():
    device = _nac_device(
        type(
            "Device",
            (),
            {
                "display_name": "onitrack@host",
                "os_version": "14.6",
                "product_type": "Macmini9,1",
                "udid": "ABC",
            },
        )(),
    )

    assert device.display_name == "onitrack@host"
    assert _version_ua(device) == "[macOS,13.6.4,22G513,MacBookAir8,1]"


def test_external_validation_selects_real_mac_device_tuple():
    state = {
        "external_validation": {
            "validation_data": "dmFsaWRhdGlvbg==",
            "device_info": {
                "hardware_version": "Mac14,3",
                "serial_number": "SYNTHETIC-SERIAL",
                "software_name": "macOS",
                "software_version": "14.3",
                "software_build_id": "23D56",
                "unique_device_id": "REAL-UUID",
            },
        },
    }

    device = _registration_device(
        type(
            "Device",
            (),
            {
                "display_name": "onitrack@host",
                "os_version": "14.6",
                "product_type": "Macmini9,1",
                "udid": "ONITRACK-UUID",
            },
        )(),
        state,
    )

    assert device.display_name == "onitrack@host"
    assert device.udid == "REAL-UUID"
    assert device.serial_number == "SYNTHETIC-SERIAL"
    assert device.software_name == "macOS"
    assert _mme_client_info(device).startswith("<Mac14,3> <macOS;14.3;23D56>")
    assert _version_ua(device) == "[macOS,14.3,23D56,Mac14,3]"
    assert _registration_validation_data(state) == b"validation"


def test_id_register_uses_xml_and_external_build_tuple(monkeypatch):
    captured = {}

    class FakeSigningKey:
        def sign(self, *args, **kwargs):
            return b"signature"

    class FakeIdentity:
        def legacy_public_identity(self):
            return b"legacy"

        def prekey_data(self):
            return b"prekey"

        def kt_loggable_data(self):
            return b"kt-data"

    def fake_request_plist(url, *, headers, body, auth=None):
        captured["body"] = body
        return {
            "status": 0,
            "services": [
                {
                    "service": "com.apple.private.alloy.multiplex1",
                    "users": [
                        {
                            "user-id": "synthetic-user",
                            "status": 0,
                            "cert": b"registration-cert",
                            "uris": [
                                {"status": 0, "uri": "mailto:test@example.invalid"},
                            ],
                        },
                    ],
                },
            ],
        }

    monkeypatch.setattr("onitrack.ids._bag", lambda key: "https://example.invalid")
    monkeypatch.setattr("onitrack.ids._request_plist", fake_request_plist)

    _id_register(
        user_id="synthetic-user",
        auth=type(
            "Auth",
            (),
            {"cert_der": b"auth-cert", "private_key": FakeSigningKey()},
        )(),
        handles=["mailto:test@example.invalid"],
        identity=FakeIdentity(),
        push_token=b"push-token",
        push_cert=b"push-cert",
        push_key=FakeSigningKey(),
        device=type(
            "Device",
            (),
            {
                "display_name": "synthetic-device",
                "os_build": "99Z999",
                "os_version": "99.1",
                "product_type": "MacTest1,1",
                "software_name": "macOS",
                "udid": "SYNTHETIC-UUID",
            },
        )(),
        validation_data=b"validation",
    )

    payload = gzip.decompress(captured["body"])
    assert payload.startswith(b"<?xml")
    body = plistlib.loads(payload)
    assert body["os-version"] == "macOS,99.1,99Z999"
    assert body["software-version"] == "99Z999"
