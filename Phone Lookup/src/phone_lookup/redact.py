from __future__ import annotations

from typing import Any

SECRET_KEYS = {
    "password",
    "hashed_password",
    "hash",
    "secret",
    "token",
    "api_key",
    "apikey",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS and item not in (None, "", []):
                out[key] = "[redacted]"
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
