from __future__ import annotations

from typing import Any

from phone_lookup.http import get_json


def lookup(digits: str, api_key: str) -> dict[str, Any]:
    status, body = get_json(
        "https://api.apilayer.com/number_verification/validate",
        params={"number": digits},
        headers={"apikey": api_key},
    )
    return {
        "source": "numverify",
        "ok": status == 200 and bool(body.get("valid")) if isinstance(body, dict) else False,
        "http_status": status,
        "result": body,
    }
