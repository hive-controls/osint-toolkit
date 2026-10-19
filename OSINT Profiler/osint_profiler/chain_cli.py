"""`osint-case chain run|show|list` command handlers."""
from __future__ import annotations
import json
from pathlib import Path
from .chainrefs import ChainError
from . import api
from .chains import list_chain_summaries, show_chain


def add_chain_parser(sub, common):
    parser = sub.add_parser("chain", help="Run, inspect and list declarative multi-tool chains")
    commands = parser.add_subparsers(dest="chain_command", required=True)
    run = commands.add_parser("run", help="Plan (default) or execute a JSON chain spec")
    run.add_argument("spec")
    run.add_argument("--dry-run", action="store_true", help="Print the resolved plan and never execute")
    run.add_argument("--resume", metavar="CHAIN_ID", help="Continue a recorded chain; completed steps with unchanged inputs are skipped")
    run.add_argument("--force", action="store_true", help="With --resume, re-run steps whose resolved inputs changed")
    run.add_argument("--confirm", choices=["RUN"])
    show = commands.add_parser("show", help="Show a chain's recorded state")
    show.add_argument("chain_id")
    show.add_argument("--case", dest="case_filter")
    commands.add_parser("list", help="List recorded chains")
    for command in commands.choices.values():
        common(command)


def load_spec(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise ChainError("spec-invalid", f"Cannot read chain spec {path}: {exc}") from None


def run_chain_command(store, args):
    """Returns (result, exit code)."""
    if args.chain_command == "list":
        return list_chain_summaries(store), 0
    if args.chain_command == "show":
        return show_chain(store, args.chain_id, args.case_filter), 0
    spec = load_spec(args.spec)
    if not isinstance(spec, dict):
        raise ChainError("spec-invalid", "A chain spec must be a JSON object.")
    result = api.run_chain_spec(store, spec, args.dry_run, args.resume, args.force, args.confirm)
    return result, (result.get("exit_code") or 0)
