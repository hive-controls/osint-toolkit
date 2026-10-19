from __future__ import annotations

from typing import Any

from phone_lookup.http import get_json

# Hudson documents phone lookup via the free OSINT username endpoint
# (E.164 including +). No API key. They may log the query.
URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"


def lookup(e164: str) -> dict[str, Any]:
    status, body = get_json(URL, params={"username": e164})
    stealers = []
    if isinstance(body, dict):
        stealers = body.get("stealers") or []
    return {
        "source": "hudson_rock",
        "ok": status == 200,
        "http_status": status,
        "hit": bool(stealers),
        "stealer_count": len(stealers) if isinstance(stealers, list) else 0,
        "result": body,
        "note": "Free Cavalier OSINT endpoint; phone is queried as username (Hudson's documented path).",
    }
