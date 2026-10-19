from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

DEFAULT_TIMEOUT = 20.0


def _unexpected_redirect(response: httpx.Response) -> tuple[int, Any]:
    location_host = urlsplit(response.headers.get("location", "")).hostname
    return response.status_code, {
        "ok": False,
        "error": "unexpected-redirect",
        "status": response.status_code,
        "location_host": location_host,
    }


def _parse_response(response: httpx.Response) -> tuple[int, Any]:
    if response.is_redirect:
        return _unexpected_redirect(response)
    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text[:2000]}
    return response.status_code, body


def get_json(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, Any]:
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        response = client.get(url, params=params, headers=headers)
        return _parse_response(response)


def post_json(
    url: str,
    *,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, Any]:
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        response = client.post(url, json=json_body, headers=headers)
        return _parse_response(response)
