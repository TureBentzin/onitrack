from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any


class ValidationDataError(RuntimeError):
    pass


def load_validation_json(path: str) -> dict[str, Any]:
    try:
        raw = (
            sys.stdin.read()
            if path == "-"
            else Path(path).read_text(encoding="utf-8")
        )
        data = json.loads(raw)
    except OSError as exc:
        raise ValidationDataError(f"failed to read validation JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationDataError("validation JSON is malformed") from exc
    if not isinstance(data, dict):
        raise ValidationDataError("validation JSON must be an object")

    validation_data = _string_value(data.get("validation_data"))
    if validation_data is None:
        raise ValidationDataError("validation JSON is missing validation_data")
    try:
        base64.b64decode(validation_data, validate=True)
    except ValueError as exc:
        raise ValidationDataError("validation_data must be base64") from exc

    device_info = _dict_value(data.get("device_info"))
    required_device_fields = (
        "hardware_version",
        "software_version",
        "software_build_id",
    )
    missing = [
        field
        for field in required_device_fields
        if _string_value(device_info.get(field)) is None
    ]
    if missing:
        raise ValidationDataError(
            "validation JSON is missing device_info fields: " + ", ".join(missing),
        )

    return {
        "device_info": device_info,
        "source": "mac-registration-provider",
        "valid_until": _string_value(data.get("valid_until")),
        "validation_data": validation_data,
    }


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
