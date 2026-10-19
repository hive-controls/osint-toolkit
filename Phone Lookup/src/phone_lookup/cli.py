from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phone_lookup import __version__
from phone_lookup.normalize import PhoneParseError, describe, parse_number
from phone_lookup.providers import dehashed, hudson, leakcheck, leakradar, numverify
from phone_lookup.providers_config import (
    PROVIDER_IDS,
    ProviderConfigError,
    describe_states,
    disable_provider,
    enable_provider,
    load_effective_config,
    load_file_config,
    plan_providers,
)
from phone_lookup.redact import redact
from phone_lookup.secrets import default_secrets_path, load_secrets, write_example_secrets

EXIT_CONFIG = 78
EXIT_AUTHORIZATION = 77
SKIP_FLAG_NAMES = {
    "numverify": "numverify",
    "hudson_rock": "hudson",
    "dehashed": "dehashed",
    "leakcheck": "leakcheck",
    "leakradar": "leakradar",
}


def flag_rate_limit(payload: dict[str, Any]) -> dict[str, Any]:
    """Mark an HTTP 429 result; the caller never retries automatically."""
    if payload.get("http_status") != 429:
        return payload
    payload["rate_limited"] = True
    body = payload.get("result")
    if isinstance(body, dict):
        for key in ("retry_after", "retryAfter", "retry-after"):
            if body.get(key) is not None:
                payload["retry_after"] = body[key]
                break
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phone-lookup",
        description=(
            "Job 1: local numbering-plan parse (phonenumbers) plus optional Numverify. "
            "Job 4: Hudson Rock (free) and optional DeHashed / LeakCheck / LeakRadar. "
            "No registration probing (WhatsApp/Telegram/Ignorant)."
        ),
    )
    parser.add_argument("phone", nargs="?", help="Phone number (E.164 preferred, e.g. +14155552671)")
    parser.add_argument("--region", help="ISO country if the number is national (e.g. US, GB)")
    parser.add_argument("--output", "-o", help="Write JSON report (default: PHONE_LOOKUP_OUTPUT or cwd)")
    parser.add_argument("--json-only", action="store_true", help="Print JSON only")
    parser.add_argument(
        "--include-secrets",
        action="store_true",
        help="Leave passwords/hashes in the JSON (default redacts them)",
    )
    parser.add_argument("--skip-numverify", action="store_true")
    parser.add_argument("--skip-hudson", action="store_true")
    parser.add_argument("--skip-dehashed", action="store_true")
    parser.add_argument("--skip-leakcheck", action="store_true")
    parser.add_argument("--skip-leakradar", action="store_true")
    parser.add_argument("--init-secrets", action="store_true", help="Write an empty secrets.json and exit")
    parser.add_argument("--providers", action="store_true", help="List third-party provider state and exit")
    parser.add_argument("--json", action="store_true", help="With --providers: print JSON")
    parser.add_argument("--enable", metavar="PROVIDER", help=f"Enable a provider ({', '.join(PROVIDER_IDS)}); needs --acknowledge-terms")
    parser.add_argument("--acknowledge-terms", metavar="PHRASE", help="Exact acknowledgement phrase for --enable")
    parser.add_argument("--disable", metavar="PROVIDER", help="Disable a provider")
    parser.add_argument("--version", action="store_true")
    return parser


def _print(message: str, *, json_only: bool) -> None:
    if not json_only:
        print(message)


def run_lookup(args: argparse.Namespace) -> dict[str, Any]:
    secrets = load_secrets()
    parsed = parse_number(args.phone, args.region)
    local = describe(parsed)
    e164 = local["e164"]
    digits = local["digits"]
    report: dict[str, Any] = {
        "tool": "phone-lookup",
        "version": __version__,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "input": args.phone,
        "local": local,
        "sources": {},
        "skipped": {},
    }

    skip_flags = {provider: bool(getattr(args, f"skip_{flag}")) for provider, flag in SKIP_FLAG_NAMES.items()}
    to_call, report["skipped"] = plan_providers(load_effective_config(), secrets, skip_flags)
    callers = {
        "numverify": lambda: numverify.lookup(digits, secrets["numverify_api_key"]),
        "hudson_rock": lambda: hudson.lookup(e164),
        "dehashed": lambda: dehashed.lookup(e164, digits, secrets["dehashed_api_key"]),
        "leakcheck": lambda: leakcheck.lookup(digits, secrets["leakcheck_api_key"]),
        "leakradar": lambda: leakradar.lookup(e164, digits, secrets["leakradar_api_key"]),
    }
    for provider in to_call:
        report["sources"][provider] = flag_rate_limit(callers[provider]())

    if not args.include_secrets:
        report = redact(report)
    return report


def write_report(report: dict[str, Any], output_arg: str | None) -> Path:
    if output_arg:
        path = Path(output_arg)
        if path.suffix.lower() != ".json":
            path.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            digits = report["local"]["digits"]
            path = path / f"phone-{digits}-{stamp}.json"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
    else:
        root = Path.cwd()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = root / f"phone-{report['local']['digits']}-{stamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def manage_providers(args: argparse.Namespace) -> int | None:
    """Handle --enable/--disable/--providers; None means this is a lookup run."""
    try:
        if args.enable:
            enable_provider(args.enable, args.acknowledge_terms)
            print(f"Enabled {args.enable} (terms acknowledged).")
            return 0
        if args.disable:
            disable_provider(args.disable)
            print(f"Disabled {args.disable}.")
            return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not args.providers:
        return None
    states = describe_states(load_file_config(), load_secrets())
    if args.json:
        print(json.dumps({"providers": states}, indent=2))
        return 0
    for name, state in states.items():
        print(f"{name:12}: enabled={state['enabled']}  key={state['key']}  terms_ack={state['terms_ack']}")
    return 0


def subject_authorization_missing() -> bool:
    required = os.environ.get("PHONE_LOOKUP_REQUIRE_CASE") == "1"
    return required and not os.environ.get("OSINT_SUBJECT_AUTH", "").strip()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"phone-lookup {__version__}")
        return 0
    if args.init_secrets:
        path = write_example_secrets()
        print(f"Wrote {path}")
        return 0
    managed = manage_providers(args)
    if managed is not None:
        return managed
    if not args.phone:
        parser.print_help()
        return 2
    if subject_authorization_missing():
        print(json.dumps({"error": "subject-authorization-required"}))
        return EXIT_AUTHORIZATION
    try:
        report = run_lookup(args)
    except ProviderConfigError as exc:
        print(f"provider configuration error: {exc}", file=sys.stderr)
        print(json.dumps({"error": "provider-config", "problems": exc.problems}))
        return EXIT_CONFIG
    except PhoneParseError as exc:
        print(f"parse error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    out_dir = args.output or os.environ.get("PHONE_LOOKUP_OUTPUT")
    path = write_report(report, out_dir)

    if args.json_only:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    local = report["local"]
    print(f"phone-lookup {__version__}")
    print(f"E.164     : {local['e164']}")
    print(f"valid     : {local['valid']}  type={local['line_type']}  region={local['region']}")
    print(f"location  : {local['location'] or '-'}")
    print(f"carrier*  : {local['carrier_prefix'] or '-'}  (*prefix/issuer, not ported live network)")
    for name, payload in report["sources"].items():
        hit = payload.get("hit")
        extra = ""
        if payload.get("http_status") not in (None, 200):
            extra = f" HTTP {payload.get('http_status')}" + (" rate_limited" if payload.get("rate_limited") else "")
        if name == "numverify" and isinstance(payload.get("result"), dict):
            result = payload["result"]
            extra = f" carrier={result.get('carrier')} line={result.get('line_type')} loc={result.get('location')}"
        print(f"{name:12}: ok={payload.get('ok')} hit={hit}{extra}")
    if report["skipped"]:
        print("skipped   : " + "; ".join(f"{name} ({reason})" for name, reason in report["skipped"].items()))
    print(f"report    : {path}")
    print("Authorized targets only. Third-party APIs may log the number.")
    print(f"Secrets file: {default_secrets_path()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
