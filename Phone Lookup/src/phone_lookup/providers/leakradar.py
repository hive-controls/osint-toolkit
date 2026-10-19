from __future__ import annotations

from typing import Any

from phone_lookup.http import post_json

# LeakRadar indexes stealer/combolist lines. There is no dedicated phone field;
# phone numbers show up as usernames. Advanced search, Bearer token.
URL = "https://api.leakradar.io/search/advanced"


def lookup(e164: str, digits: str, api_key: str) -> dict[str, Any]:
    status, body = post_json(
        URL,
        json_body={"username": [e164, digits], "page": 1},
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    return {
        "source": "leakradar",
        "ok": status == 200,
        "http_status": status,
        "hit": _has_hits(body),
        "result": body,
        "note": "No native phone index; queried as username (E.164 and digits).",
    }


def _has_hits(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    for key in ("total", "count", "found"):
        value = body.get(key)
        if isinstance(value, int) and value > 0:
            return True
    items = body.get("items") or body.get("results") or body.get("data") or []
    return bool(items)
