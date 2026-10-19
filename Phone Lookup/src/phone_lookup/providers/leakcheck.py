from __future__ import annotations

from typing import Any
from urllib.parse import quote

from phone_lookup.http import get_json


def lookup(digits: str, api_key: str, *, limit: int = 100) -> dict[str, Any]:
    status, body = get_json(
        f"https://leakcheck.io/api/v2/query/{quote(digits, safe='')}",
        params={"type": "phone", "limit": str(limit)},
        headers={"Accept": "application/json", "X-API-Key": api_key},
    )
    found = 0
    if isinstance(body, dict):
        found = int(body.get("found") or 0)
    return {
        "source": "leakcheck",
        "ok": status == 200 and bool(isinstance(body, dict) and body.get("success")),
        "http_status": status,
        "hit": found > 0,
        "found": found,
        "result": body,
        "attribution": "Powered by LeakCheck",
    }
