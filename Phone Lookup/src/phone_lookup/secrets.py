from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SECRET_NAMES = (
    "numverify_api_key",
    "dehashed_api_key",
    "leakcheck_api_key",
    "leakradar_api_key",
)

ENV_MAP = {
    "numverify_api_key": ("NUMVERIFY_API_KEY", "APILAYER_API_KEY"),
    "dehashed_api_key": ("DEHASHED_API_KEY",),
    "leakcheck_api_key": ("LEAKCHECK_APIKEY", "LEAKCHECK_API_KEY"),
    "leakradar_api_key": ("LEAKRADAR_API_KEY", "LEAKRADAR_TOKEN"),
}


def default_secrets_path() -> Path:
    override = os.environ.get("PHONE_LOOKUP_SECRETS")
    if override:
        return Path(override)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "PhoneLookup" / "secrets.json"
    return Path.home() / ".config" / "phone-lookup" / "secrets.json"


def example_secrets() -> dict[str, str]:
    return {name: "" for name in SECRET_NAMES}


def load_secrets(path: Path | None = None) -> dict[str, str]:
    secrets = example_secrets()
    file_path = path or default_secrets_path()
    if file_path.is_file():
        try:
            data: Any = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"secrets file is not JSON: {file_path} ({exc})") from exc
        if isinstance(data, dict):
            for name in SECRET_NAMES:
                value = data.get(name)
                if isinstance(value, str) and value.strip():
                    secrets[name] = value.strip()
    for name, env_keys in ENV_MAP.items():
        for key in env_keys:
            value = os.environ.get(key, "").strip()
            if value:
                secrets[name] = value
                break
    return secrets


def write_example_secrets(path: Path | None = None) -> Path:
    file_path = path or default_secrets_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists():
        file_path.write_text(json.dumps(example_secrets(), indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass
    return file_path
