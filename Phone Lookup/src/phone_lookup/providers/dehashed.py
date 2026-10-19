from __future__ import annotations

from typing import Any

from phone_lookup.http import post_json


def lookup(e164: str, digits: str, api_key: str, *, size: int = 25) -> dict[str, Any]:
    query = f'phone:"{e164}" OR phone:{digits}'
    status, body = post_json(
        "https://api.dehashed.com/v2/search",
        json_body={"query": query, "page": 1, "size": size, "de_dupe": True},
        headers={"Content-Type": "application/json", "DeHashed-Api-Key": api_key},
    )
    total = 0
    entries: list[Any] = []
    if isinstance(body, dict):
        total = int(body.get("total") or 0)
        entries = body.get("entries") if isinstance(body.get("entries"), list) else []
        if not total and entries:
            total = len(entries)
    return {
        "source": "dehashed",
        "ok": status == 200,
        "http_status": status,
        "hit": total > 0 or bool(entries),
        "total": total,
        "result": body,
    }
