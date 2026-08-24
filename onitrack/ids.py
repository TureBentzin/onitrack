from __future__ import annotations

import base64
import gzip
import hashlib
import os
import plistlib
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib import request

IDS_BAG_URL = "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3"
IDS_PROTOCOL_VERSION = "1750"
MULTIPLEX_SERVICE = "com.apple.private.alloy.multiplex1"
MULTIPLEX_SUB_SERVICES = (
    "com.apple.private.alloy.fmf",
    "com.apple.private.alloy.fmd",
    "com.apple.private.alloy.status.keysharing",
    "com.apple.private.alloy.status.personal",
    "com.apple.private.alloy.findmy.itemsharing-crossaccount",
    "com.apple.private.alloy.kcsharing.invite",
)
MULTIPLEX_CLIENT_DATA = {
    "supports-fmd-v2": True,
    "supports-incoming-fmd-v1": True,
    "supports-findmy-plugin-messages": True,
    "supports-beacon-sharing-v3": True,
    "supports-beacon-sharing-v2": True,
}
MULTIPLEX_CAPABILITIES_NAME = "com.apple.private.alloy"
IDS_BAG_CACHE: dict[str, str] = {}


class IDSRegistrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class IDSRegistrationResult:
    ids_state: dict[str, Any]
    account_state: dict[str, Any]


def register_ids(
    *,
    account_state: dict[str, Any],
    apns_state: dict[str, Any],
    anisette_headers: dict[str, str],
    device: Any,
    existing: dict[str, Any],
) -> IDSRegistrationResult:
    if _is_registered(existing):
        return IDSRegistrationResult(ids_state=existing, account_state=account_state)

    login_data = _dict_path(account_state, "login", "data")
    idms_pet = _string_value(login_data.get("idms_pet"))
    adsid = _string_value(login_data.get("adsid"))
    username = _string_value(_dict_path(account_state, "account").get("username"))
    if not idms_pet or not adsid or not username:
        raise IDSRegistrationError(
            "saved auth lacks delegate-capable IDMS PET; run `onitrack auth provision` "
            "again with this build",
        )

    push_token = _hex_bytes(
        _string_value(apns_state.get("courier_token")),
        "APNs token",
    )
    push_cert = _load_certificate_der(apns_state, "certificate_pem")
    push_key = _load_rsa_private_key(apns_state, "private_key_pem")
    state = dict(existing)
    identity = _load_or_create_identity(_dict_value(state.get("identity")))
    state["identity"] = identity.export_state()

    delegate = _login_ids_delegate(
        username=username,
        idms_pet=idms_pet,
        adsid=adsid,
        anisette_headers=anisette_headers,
        device=device,
        validation_data=_validation_data(state),
    )
    user_id = _string_value(delegate.get("profile-id"))
    auth_token = _string_value(delegate.get("auth-token"))
    if not user_id or not auth_token:
        raise IDSRegistrationError(
            "IDS delegate response is missing profile-id/auth-token",
        )

    auth = _authenticate_ds_id(user_id, auth_token, device)
    handles = _get_handles(
        user_id=user_id,
        auth=auth,
        push_token=push_token,
        push_cert=push_cert,
        push_key=push_key,
    )
    registration = _id_register(
        user_id=user_id,
        auth=auth,
        handles=handles,
        identity=identity,
        push_token=push_token,
        push_cert=push_cert,
        push_key=push_key,
        device=device,
        validation_data=_validation_data(state),
    )
    state["users"] = {
        user_id: {
            "auth_cert": base64.b64encode(auth.cert_der).decode("ascii"),
            "auth_private_key_pem": auth.private_key_pem,
            "handles": registration["handles"],
            "registration": registration,
        },
    }
    state["registered"] = True
    state["service"] = MULTIPLEX_SERVICE

    sanitized_account = _drop_idms_pet(account_state)
    return IDSRegistrationResult(ids_state=state, account_state=sanitized_account)


@dataclass(frozen=True)
class _AuthKeyPair:
    cert_der: bytes
    private_key: Any
    private_key_pem: str


class _IDSIdentity:
    def __init__(
        self,
        *,
        signing_key: Any,
        encryption_key: Any,
        device_key: Any,
        pre_key: Any,
    ) -> None:
        self.signing_key = signing_key
        self.encryption_key = encryption_key
        self.device_key = device_key
        self.pre_key = pre_key

    def export_state(self) -> dict[str, str]:
        from cryptography.hazmat.primitives import serialization

        return {
            "device_private_key_pem": self.device_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            "encryption_private_key_pem": self.encryption_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            "pre_private_key_pem": self.pre_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            "signing_private_key_pem": self.signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
        }

    def legacy_public_identity(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        signing = self.signing_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        encryption = self.encryption_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1,
        )
        return _der_sequence(
            _der_context_primitive(1, len(signing).to_bytes(2, "big") + signing),
            _der_context_primitive(2, len(encryption).to_bytes(2, "big") + encryption),
        )

    def prekey_data(self) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        timestamp = float(int(time.time()))
        key = _compact_public_key(self.pre_key)
        data = b"NGMPrekeySignature" + key + _f64_le(timestamp)
        signature_der = self.device_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature_der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return (
            _proto_bytes(1, key)
            + _proto_bytes(2, signature)
            + _proto_fixed64(3, timestamp)
        )

    def kt_loggable_data(self) -> bytes:
        public_key = _compact_public_key(self.device_key)
        device_identity = _proto_bytes(1, public_key)
        return (
            _proto_bytes(1, device_identity)
            + _proto_varint(2, 13)
            + _proto_varint(3, 5)
        )


def _login_ids_delegate(
    *,
    username: str,
    idms_pet: str,
    adsid: str,
    anisette_headers: dict[str, str],
    device: Any,
    validation_data: bytes,
) -> dict[str, Any]:
    body = plistlib.dumps(
        {
            "delegates": {"com.apple.private.ids": {"protocol-version": "4"}},
            "protocol-version": "1.0",
            "user-info": {
                "client-id": str(uuid.uuid4()).upper(),
                "language": "en-US",
                "timezone": "America/New_York",
            },
        },
        fmt=plistlib.FMT_XML,
    )
    headers = {
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-apple-plist",
        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1496.0.7 Darwin/23.5.0",
        "X-Apple-ADSID": adsid,
        "X-Mme-Client-Info": _mme_client_info(device),
    }
    if validation_data:
        headers["X-Mme-Nas-Qualify"] = base64.b64encode(validation_data).decode("ascii")
    headers.update(anisette_headers)
    response = _request_plist(
        "https://setup.icloud.com/setup/signin/v2/login",
        headers=headers,
        body=body,
        auth=(username, idms_pet),
    )
    if int(response.get("status", 1)) != 0:
        raise IDSRegistrationError(f"IDS delegate login failed with status {response}")
    delegate_root = _dict_path(response, "delegates", "com.apple.private.ids")
    if int(delegate_root.get("status", 1)) != 0:
        raise IDSRegistrationError(f"IDS delegate rejected: {delegate_root}")
    return _dict_value(delegate_root.get("service-data"))


def _authenticate_ds_id(user_id: str, auth_token: str, device: Any) -> _AuthKeyPair:
    key, csr_der = _generate_auth_csr(user_id)
    body = gzip.compress(
        plistlib.dumps(
            {
                "authentication-data": {"auth-token": auth_token},
                "csr": csr_der,
                "realm-user-id": user_id,
            },
            fmt=plistlib.FMT_BINARY,
        ),
    )
    response = _request_plist(
        _bag("id-authenticate-ds-id"),
        headers={
            "Content-Encoding": "gzip",
            "User-Agent": f"com.apple.invitation-registration {_version_ua(device)}",
            "x-protocol-version": IDS_PROTOCOL_VERSION,
        },
        body=body,
    )
    status = int(response.get("status", 1))
    if status != 0:
        raise IDSRegistrationError(f"IDS auth certificate request failed: {status}")
    cert = response.get("cert")
    if not isinstance(cert, bytes):
        raise IDSRegistrationError("IDS auth certificate response is missing cert")
    return _AuthKeyPair(
        cert_der=cert,
        private_key=key,
        private_key_pem=_private_key_pem(key),
    )


def _get_handles(
    *,
    user_id: str,
    auth: _AuthKeyPair,
    push_token: bytes,
    push_cert: bytes,
    push_key: Any,
) -> list[str]:
    headers: dict[str, str] = {
        "x-auth-user-id": user_id,
        "x-protocol-version": IDS_PROTOCOL_VERSION,
        "x-push-token": base64.b64encode(push_token).decode("ascii"),
    }
    _sign_headers(
        headers,
        "id-get-handles",
        b"",
        push_token,
        "auth",
        auth.private_key,
        auth.cert_der,
    )
    _sign_headers(
        headers,
        "id-get-handles",
        b"",
        push_token,
        "push",
        push_key,
        push_cert,
    )
    response = _request_plist(_bag("id-get-handles"), headers=headers, body=None)
    status = int(response.get("status", 1))
    handles = response.get("handles")
    if status != 0 or not isinstance(handles, list):
        raise IDSRegistrationError(f"IDS handle lookup failed: {status}")
    return [
        uri
        for item in handles
        if isinstance(item, dict) and isinstance((uri := item.get("uri")), str)
    ]


def _id_register(
    *,
    user_id: str,
    auth: _AuthKeyPair,
    handles: list[str],
    identity: _IDSIdentity,
    push_token: bytes,
    push_cert: bytes,
    push_key: Any,
    device: Any,
    validation_data: bytes,
) -> dict[str, Any]:
    body = gzip.compress(
        plistlib.dumps(
            _register_body(user_id, handles, identity, device, validation_data),
            fmt=plistlib.FMT_BINARY,
        ),
    )
    headers = {
        "accept-encoding": "gzip",
        "content-encoding": "gzip",
        "content-type": "application/x-apple-plist",
        "user-agent": f"com.apple.invitation-registration {_version_ua(device)}",
        "x-auth-user-id-0": user_id,
        "x-protocol-version": IDS_PROTOCOL_VERSION,
        "x-push-token": base64.b64encode(push_token).decode("ascii"),
    }
    _sign_headers(headers, "id-register", body, push_token, "push", push_key, push_cert)
    _sign_headers(
        headers,
        "id-register",
        body,
        push_token,
        "auth",
        auth.private_key,
        auth.cert_der,
        item=0,
    )
    response = _request_plist(_bag("id-register"), headers=headers, body=body)
    status = int(response.get("status", 1))
    if status != 0:
        raise IDSRegistrationError(f"IDS register failed: {status}")
    return _parse_registration_response(response, user_id)


def _register_body(
    user_id: str,
    handles: list[str],
    identity: _IDSIdentity,
    device: Any,
    validation_data: bytes,
) -> dict[str, Any]:
    client_data = {
        "public-message-identity-key": identity.legacy_public_identity(),
        "public-message-identity-version": 2,
        "ec-version": 1,
        "public-message-identity-ngm-version": 13,
        "public-message-ngm-device-prekey-data-key": identity.prekey_data(),
        "kt-version": 5,
        **MULTIPLEX_CLIENT_DATA,
    }
    return {
        "device-name": device.display_name,
        "hardware-version": device.product_type,
        "language": "en-US",
        "os-version": f"macOS,{device.os_version},{_macos_build(device.os_version)}",
        "private-device-data": _private_device_data(device),
        "services": [
            {
                "capabilities": [
                    {
                        "flags": 1,
                        "name": MULTIPLEX_CAPABILITIES_NAME,
                        "version": 1,
                    },
                ],
                "service": MULTIPLEX_SERVICE,
                "sub-services": list(MULTIPLEX_SUB_SERVICES),
                "users": [
                    {
                        "client-data": client_data,
                        "kt-loggable-data": identity.kt_loggable_data(),
                        "uris": [{"uri": handle} for handle in handles],
                        "user-id": user_id,
                    },
                ],
            },
        ],
        "software-version": _macos_build(device.os_version),
        "validation-data": validation_data,
    }


def _parse_registration_response(
    response: dict[str, Any],
    user_id: str,
) -> dict[str, Any]:
    services = response.get("services")
    if not isinstance(services, list):
        raise IDSRegistrationError("IDS register response is missing services")
    for service in services:
        if not isinstance(service, dict) or service.get("service") != MULTIPLEX_SERVICE:
            continue
        users = service.get("users")
        if not isinstance(users, list):
            continue
        for user in users:
            if not isinstance(user, dict) or user.get("user-id") != user_id:
                continue
            status = int(user.get("status", 1))
            if status != 0:
                raise IDSRegistrationError(f"IDS register user failed: {status}")
            cert = user.get("cert")
            if not isinstance(cert, bytes):
                raise IDSRegistrationError("IDS register user response missing cert")
            uris = user.get("uris")
            if not isinstance(uris, list):
                raise IDSRegistrationError("IDS register user response missing uris")
            handles = []
            for uri in uris:
                if not isinstance(uri, dict):
                    continue
                uri_status = int(uri.get("status", 1))
                if uri_status != 0:
                    raise IDSRegistrationError(f"IDS register URI failed: {uri_status}")
                raw_uri = uri.get("uri")
                if isinstance(raw_uri, str):
                    handles.append(raw_uri)
            return {
                "cert": base64.b64encode(cert).decode("ascii"),
                "data_hash": _service_data_hash(),
                "handles": handles,
                "heartbeat_interval_s": user.get("next-hbi"),
                "registered_at_s": int(time.time()),
            }
    raise IDSRegistrationError(
        "IDS register response did not include multiplex service",
    )


def _request_plist(
    url: str,
    *,
    headers: dict[str, str],
    body: bytes | None,
    auth: tuple[str, str] | None = None,
) -> dict[str, Any]:
    req_headers = dict(headers)
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
        req_headers["Authorization"] = f"Basic {token}"
    method = "POST" if body is not None else "GET"
    req = request.Request(url, data=body, headers=req_headers, method=method)
    with request.urlopen(req, timeout=45) as response:
        payload = response.read()
    if payload.startswith(b"\x1f\x8b"):
        payload = gzip.decompress(payload)
    decoded = plistlib.loads(payload)
    if not isinstance(decoded, dict):
        raise IDSRegistrationError("Apple returned a non-dictionary plist")
    return decoded


def _bag(key: str) -> str:
    if not IDS_BAG_CACHE:
        with request.urlopen(IDS_BAG_URL, timeout=30) as response:
            body = response.read()
        outer = plistlib.loads(body)
        if not isinstance(outer, dict) or not isinstance(outer.get("bag"), bytes):
            raise IDSRegistrationError("IDS bag response is malformed")
        bag = plistlib.loads(outer["bag"])
        if not isinstance(bag, dict):
            raise IDSRegistrationError("IDS bag content is malformed")
        for bag_key, value in bag.items():
            if isinstance(bag_key, str) and isinstance(value, str):
                IDS_BAG_CACHE[bag_key] = value
    value = IDS_BAG_CACHE.get(key)
    if value is None:
        raise IDSRegistrationError(f"IDS bag is missing {key}")
    return value


def _sign_headers(
    headers: dict[str, str],
    bag: str,
    body: bytes,
    push_token: bytes,
    name: str,
    private_key: Any,
    cert_der: bytes,
    *,
    item: int | None = None,
) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    postfix = "" if item is None else f"-{item}"
    nonce = b"\x01" + int(time.time() * 1000).to_bytes(8, "big") + os.urandom(8)
    payload = _signature_payload(nonce, [bag.encode(), b"", body, push_token])
    signature = b"\x01\x01" + private_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    headers[f"x-{name}-nonce{postfix}"] = base64.b64encode(nonce).decode("ascii")
    headers[f"x-{name}-sig{postfix}"] = base64.b64encode(signature).decode("ascii")
    headers[f"x-{name}-cert{postfix}"] = base64.b64encode(cert_der).decode("ascii")


def _signature_payload(nonce: bytes, fields: list[bytes]) -> bytes:
    return nonce + b"".join(len(field).to_bytes(4, "big") + field for field in fields)


def _generate_auth_csr(user_id: str) -> tuple[Any, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    common_name = hashlib.sha1(user_id.encode()).hexdigest().upper()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA1())
    )
    from cryptography.hazmat.primitives import serialization

    return key, csr.public_bytes(serialization.Encoding.DER)


def _load_or_create_identity(state: dict[str, Any]) -> _IDSIdentity:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    required = (
        "device_private_key_pem",
        "encryption_private_key_pem",
        "pre_private_key_pem",
        "signing_private_key_pem",
    )
    if all(isinstance(state.get(key), str) for key in required):
        return _IDSIdentity(
            device_key=serialization.load_pem_private_key(
                state["device_private_key_pem"].encode("ascii"),
                password=None,
            ),
            encryption_key=serialization.load_pem_private_key(
                state["encryption_private_key_pem"].encode("ascii"),
                password=None,
            ),
            pre_key=serialization.load_pem_private_key(
                state["pre_private_key_pem"].encode("ascii"),
                password=None,
            ),
            signing_key=serialization.load_pem_private_key(
                state["signing_private_key_pem"].encode("ascii"),
                password=None,
            ),
        )
    return _IDSIdentity(
        device_key=_generate_compact_p256(),
        encryption_key=rsa.generate_private_key(public_exponent=65537, key_size=1280),
        pre_key=_generate_compact_p256(),
        signing_key=ec.generate_private_key(ec.SECP256R1()),
    )


def _generate_compact_p256() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec

    prime = (2**256) - (2**224) + (2**192) + (2**96) - 1
    while True:
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        if numbers.y * 2 <= prime:
            return key


def _compact_public_key(key: Any) -> bytes:
    return key.public_key().public_numbers().x.to_bytes(32, "big")


def _private_key_pem(key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _load_rsa_private_key(state: dict[str, Any], key: str) -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = _string_value(state.get(key))
    if pem is None:
        raise IDSRegistrationError(f"APNs state is missing {key}")
    private_key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise IDSRegistrationError(f"APNs {key} is not RSA")
    return private_key


def _load_certificate_der(state: dict[str, Any], key: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pem = _string_value(state.get(key))
    if pem is None:
        raise IDSRegistrationError(f"APNs state is missing {key}")
    return x509.load_pem_x509_certificate(pem.encode("ascii")).public_bytes(
        serialization.Encoding.DER,
    )


def _validation_data(state: dict[str, Any]) -> bytes:
    encoded = _string_value(state.get("validation_data"))
    if not encoded:
        return b""
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise IDSRegistrationError("stored IDS validation data is malformed") from exc


def _private_device_data(device: Any) -> dict[str, Any]:
    return {
        "ap": "0",
        "d": f"{time.time() - 978307200:.6f}",
        "dt": 1,
        "gt": "0",
        "h": "1",
        "m": "0",
        "p": "0",
        "pb": _macos_build(device.os_version),
        "pn": "macOS",
        "pv": device.os_version,
        "s": "0",
        "t": "0",
        "u": device.udid.upper(),
        "v": "1",
    }


def _mme_client_info(device: Any) -> str:
    return (
        f"<{device.product_type}> <macOS;{device.os_version};"
        f"{_macos_build(device.os_version)}> "
        "<com.apple.AOSKit/282 (com.apple.accountsd/113)>"
    )


def _version_ua(device: Any) -> str:
    return (
        f"[macOS,{device.os_version},{_macos_build(device.os_version)},"
        f"{device.product_type}]"
    )


def _macos_build(version: str) -> str:
    return {"14.6": "23G80"}.get(version, "23G80")


def _drop_idms_pet(account_state: dict[str, Any]) -> dict[str, Any]:
    copied = json_copy(account_state)
    login_data = _dict_path(copied, "login", "data")
    login_data.pop("idms_pet", None)
    login_data.pop("adsid", None)
    return copied


def json_copy(value: dict[str, Any]) -> dict[str, Any]:
    import copy

    return copy.deepcopy(value)


def _is_registered(state: dict[str, Any]) -> bool:
    return bool(state.get("registered")) and bool(_dict_value(state.get("users")))


def _service_data_hash() -> str:
    digest = hashlib.sha256()
    digest.update(plistlib.dumps(MULTIPLEX_CLIENT_DATA, fmt=plistlib.FMT_BINARY))
    digest.update("\0".join(MULTIPLEX_SUB_SERVICES).encode())
    return digest.hexdigest()


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


def _hex_bytes(value: str | None, label: str) -> bytes:
    if value is None:
        raise IDSRegistrationError(f"{label} is missing")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise IDSRegistrationError(f"{label} is malformed") from exc


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_sequence(*children: bytes) -> bytes:
    payload = b"".join(children)
    return b"\x30" + _der_len(len(payload)) + payload


def _der_context_primitive(tag: int, payload: bytes) -> bytes:
    return bytes([0x80 | tag]) + _der_len(len(payload)) + payload


def _proto_varint(field: int, value: int) -> bytes:
    return _proto_key(field, 0) + _varint(value)


def _proto_fixed64(field: int, value: float) -> bytes:
    import struct

    return _proto_key(field, 1) + struct.pack("<d", value)


def _proto_bytes(field: int, value: bytes) -> bytes:
    return _proto_key(field, 2) + _varint(len(value)) + value


def _proto_key(field: int, wire_type: int) -> bytes:
    return _varint((field << 3) | wire_type)


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _f64_le(value: float) -> bytes:
    import struct

    return struct.pack("<d", value)
