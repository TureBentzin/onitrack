import hashlib
import io
import plistlib
from urllib.error import HTTPError

import pytest

from onitrack.ids import (
    IDSRegistrationError,
    _generate_auth_csr,
    _login_ids_delegate,
    _request_plist,
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
    assert "description='bad delegate'" in message


def test_login_ids_delegate_recommends_refresh_for_unauthorized(monkeypatch):
    def fake_request_plist(*args, **kwargs):
        raise IDSRegistrationError(
            "Apple request failed: HTTP 401 "
            "localizedError='UNAUTHORIZED' "
            "description='These account credentials are unauthorized.'",
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

    assert "auth provision --refresh" in str(exc_info.value)


def test_generate_auth_csr_uses_supported_signature_algorithm():
    cryptography = pytest.importorskip("cryptography")
    assert cryptography is not None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    _key, csr_der = _generate_auth_csr("123456789")

    csr = x509.load_der_x509_csr(csr_der)
    assert isinstance(csr.signature_hash_algorithm, hashes.SHA256)
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        hashlib.sha1(b"123456789").hexdigest().upper()
    )
