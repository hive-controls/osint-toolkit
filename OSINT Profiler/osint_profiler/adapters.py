"""Versioned, offline adapters. A reported hit is never an identity assertion."""
from __future__ import annotations
import csv
import io
import json
from collections import Counter
from pathlib import Path

VERSION = "1"
STATUSES = {"Found": "hit", "Registered": "hit", "Claimed": "hit",
            "Not Found": "absent", "Not Registered": "absent", "Available": "absent",
            "Error": "error", "Skipped": "skipped", "Unknown": "unknown"}

def inspect(data: bytes, filename: str):
    result = {"adapter": "attachment", "version": VERSION, "observations": [],
              "issues": [], "queried_at": None, "tool_version": None}
    suffix = Path(filename).suffix.lower()
    if suffix not in (".json", ".csv"):
        result["issues"].append("Retained as evidence; this file type has no structured adapter.")
        return result
    try:
        text = data.decode("utf-8-sig")
        payload = json.loads(text) if suffix == ".json" else list(csv.DictReader(io.StringIO(text)))
    except (UnicodeError, ValueError, csv.Error) as exc:
        result["issues"].append("Unable to parse report: " + str(exc)[:200])
        return result

    def add(item, tool, selector):
        if not isinstance(item, dict):
            result["issues"].append(f"Skipped malformed record at {selector}")
            return
        if tool == "scanner":
            if item.get("status") == "status":  # repeated CSV header on append
                return
            query = item.get("email") or item.get("username")
            state = item.get("status", "Unknown")
            kind = "email" if item.get("email") or state in ("Registered", "Not Registered") else "username"
            site, url = item.get("site_name"), item.get("url")
            extra = {k: item[k] for k in ("extra", "media", "reason", "category") if item.get(k)}
        else:
            state_obj = item.get("status", item.get("exists", "Unknown"))
            state = state_obj.get("status", "Unknown") if isinstance(state_obj, dict) else state_obj
            query = item.get("username") or (state_obj.get("username") if isinstance(state_obj, dict) else "")
            site = item.get("_site") or item.get("name") or (state_obj.get("site_name") if isinstance(state_obj, dict) else "")
            url, kind = item.get("url_user"), "username"
            # Do not normalize cookies or raw request/site configuration into profiles.
            extra = {k: item[k] for k in ("ids_links", "ids_usernames", "keywords", "http_status", "error_reason") if item.get(k)}
            if isinstance(state_obj, dict) and state_obj.get("ids"):
                extra["ids"] = state_obj["ids"]
        if not query or not site:
            result["issues"].append(f"Missing target/site at {selector}; preserved in original file.")
            return
        result["observations"].append({"tool": tool, "selector": selector, "query": str(query),
            "identifier_kind": kind, "site": str(site), "url": str(url or ""),
            "status": STATUSES.get(str(state), "unknown"), "reported_status": str(state), "extra": extra})

    if isinstance(payload, dict) and payload.get("tool") == "phone-lookup" and isinstance(payload.get("local"), dict):
        result["adapter"] = "phone"
        result["queried_at"] = payload.get("queried_at")
        result["tool_version"] = payload.get("version")
        number = payload["local"].get("e164") or payload.get("input")
        if not number:
            result["issues"].append("Phone envelope has no number.")
        else:
            result["observations"].append({"tool": "phone", "selector": "/local", "query": str(number),
                "identifier_kind": "phone", "site": "numbering-plan", "url": "", "status": "metadata",
                "reported_status": "local metadata", "extra": payload["local"]})
            for name, response in (payload.get("sources") or {}).items():
                if not isinstance(response, dict):
                    result["issues"].append(f"Unrecognized provider payload: {name}")
                    continue
                # Interpret only the validated envelope, never assume provider record schemas.
                state = "error" if response.get("ok") is not True else (
                    "hit" if response.get("hit") is True else "absent" if response.get("hit") is False else "unknown")
                result["observations"].append({"tool": "phone", "selector": "/sources/" + name,
                    "query": str(number), "identifier_kind": "phone", "site": name, "url": "",
                    "status": state, "reported_status": state,
                    "extra": {k: response[k] for k in ("ok", "hit", "http_status", "note", "rate_limited", "retry_after") if k in response}})
            skipped = payload.get("skipped") or {}
            skipped_items = skipped.items() if isinstance(skipped, dict) else ((str(s), None) for s in skipped)
            result["issues"].extend(
                "Provider skipped: " + name + (f" ({reason})" if reason else "") for name, reason in skipped_items)
    elif isinstance(payload, list) and payload and isinstance(payload[0], dict) and "site_name" in payload[0] and "status" in payload[0]:
        result["adapter"] = "scanner"
        for i, item in enumerate(payload):
            add(item, "scanner", f"/{i}" if suffix == ".json" else f"row:{i+2}")
    elif isinstance(payload, list) and payload and isinstance(payload[0], dict) and "url_user" in payload[0] and "exists" in payload[0]:
        result["adapter"] = "maigret"
        for i, item in enumerate(payload):
            add(item, "maigret", f"row:{i+2}")
    elif isinstance(payload, dict) and payload and all(isinstance(v, dict) and "url_user" in v and "status" in v for v in payload.values()):
        result["adapter"] = "maigret"
        for site, item in payload.items():
            add(dict(item, _site=site), "maigret", "/" + site.replace("~", "~0").replace("/", "~1"))
    else:
        result["issues"].append("Unrecognized or empty structured report; retained without guessed results.")
    if result["adapter"] == "maigret" and suffix == ".json":
        result["issues"].append("Maigret JSON contains claimed accounts only; missing sites have unknown coverage.")
    result["counts"] = dict(Counter(o["status"] for o in result["observations"]))
    result["targets"] = sorted({o["query"] for o in result["observations"]})
    return result
