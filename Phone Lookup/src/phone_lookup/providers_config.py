"""Opt-in policy for third-party providers.

A provider is called only when it is enabled AND its terms acknowledgement
matches the current PROVIDER-TERMS/<provider>.txt hash. An API key alone never
enables anything. The config holds no secrets (keys stay in secrets.json/env).
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROVIDER_IDS = ("numverify", "hudson_rock", "dehashed", "leakcheck", "leakradar")
KEY_NAME = {
    "numverify": "numverify_api_key",
    "hudson_rock": None,
    "dehashed": "dehashed_api_key",
    "leakcheck": "leakcheck_api_key",
    "leakradar": "leakradar_api_key",
}
REASON_DISABLED = "disabled"
REASON_NO_KEY = "no-key"
REASON_SKIPPED_FLAG = "skipped-flag"
REASON_ACK_STALE = "terms-ack-stale"


class ProviderConfigError(Exception):
    def __init__(self, problems: dict[str, str]):
        super().__init__(", ".join(f"{name}: {reason}" for name, reason in problems.items()))
        self.problems = problems


def required_phrase(provider: str) -> str:
    return f"I HAVE READ THE {provider.upper()} TERMS AND ACCEPT RESPONSIBILITY FOR MY QUERIES"


def terms_directory() -> Path:
    override = os.environ.get("PHONE_LOOKUP_TERMS_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[2] / "PROVIDER-TERMS"


def terms_version(provider: str) -> str:
    raw = (terms_directory() / f"{provider}.txt").read_bytes()
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def default_providers_path() -> Path:
    from phone_lookup.secrets import default_secrets_path

    override = os.environ.get("PHONE_LOOKUP_PROVIDERS_FILE")
    if override:
        return Path(override)
    return default_secrets_path().parent / "providers.json"


def _read_file_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"providers file is not JSON: {path} ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"providers file must be a JSON object: {path}")
    return {name: entry for name, entry in data.items() if name in PROVIDER_IDS and isinstance(entry, dict)}


def _config_from_env_list(value: str) -> dict[str, Any]:
    config: dict[str, Any] = {}
    for item in value.split(","):
        name, _, version = item.strip().partition("@")
        if name in PROVIDER_IDS:
            config[name] = {"enabled": True, "terms_ack": {"version": version}}
    return config


def load_effective_config() -> dict[str, Any]:
    """Host-computed env list (container) replaces the file; otherwise read the file."""
    env_value = os.environ.get("PHONE_LOOKUP_PROVIDERS")
    if env_value is not None:
        return _config_from_env_list(env_value)
    return _read_file_config(default_providers_path())


def load_file_config() -> dict[str, Any]:
    """The persisted config only (management commands never read the env list)."""
    return _read_file_config(default_providers_path())


def ack_state(provider: str, entry: dict[str, Any]) -> str:
    ack = entry.get("terms_ack")
    if not isinstance(ack, dict) or not ack.get("version"):
        return "missing"
    return "current" if ack["version"] == terms_version(provider) else "stale"


def plan_providers(
    config: dict[str, Any], secrets: dict[str, str], skip_flags: dict[str, bool]
) -> tuple[list[str], dict[str, str]]:
    """Return (providers to call, skipped reasons); raise ProviderConfigError on misconfiguration."""
    to_call: list[str] = []
    skipped: dict[str, str] = {}
    problems: dict[str, str] = {}
    for provider in PROVIDER_IDS:
        entry = config.get(provider, {})
        if entry.get("enabled") is not True:
            skipped[provider] = REASON_DISABLED
        elif skip_flags.get(provider):
            skipped[provider] = REASON_SKIPPED_FLAG
        elif KEY_NAME[provider] and not secrets.get(KEY_NAME[provider]):
            problems[provider] = REASON_NO_KEY
        elif ack_state(provider, entry) != "current":
            problems[provider] = REASON_ACK_STALE
        else:
            to_call.append(provider)
    if problems:
        raise ProviderConfigError(problems)
    return to_call, skipped


def describe_states(config: dict[str, Any], secrets: dict[str, str]) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    for provider in PROVIDER_IDS:
        entry = config.get(provider, {})
        key_name = KEY_NAME[provider]
        states[provider] = {
            "enabled": entry.get("enabled") is True,
            "key": "not-required" if key_name is None else ("present" if secrets.get(key_name) else "absent"),
            "terms_ack": ack_state(provider, entry),
        }
    return states


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _operator_name() -> str:
    explicit = os.environ.get("PHONE_LOOKUP_OPERATOR", "").strip()
    if explicit:
        return explicit
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def enable_provider(provider: str, phrase: str | None, path: Path | None = None) -> None:
    if provider not in PROVIDER_IDS:
        raise ValueError(f"unknown provider: {provider} (choose from {', '.join(PROVIDER_IDS)})")
    if phrase != required_phrase(provider):
        raise ValueError(f'--acknowledge-terms must be exactly: "{required_phrase(provider)}"')
    target = path or default_providers_path()
    data = _read_file_config(target)
    data[provider] = {
        "enabled": True,
        "terms_ack": {
            "version": terms_version(provider),
            "operator": _operator_name(),
            "ts": datetime.now(timezone.utc).isoformat(),
        },
    }
    _write_atomic(target, data)


def disable_provider(provider: str, path: Path | None = None) -> None:
    if provider not in PROVIDER_IDS:
        raise ValueError(f"unknown provider: {provider} (choose from {', '.join(PROVIDER_IDS)})")
    target = path or default_providers_path()
    data = _read_file_config(target)
    entry = dict(data.get(provider, {}))
    entry["enabled"] = False
    data[provider] = entry
    _write_atomic(target, data)
