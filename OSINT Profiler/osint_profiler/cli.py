from __future__ import annotations
import argparse
import contextlib
import json
import os
import shutil
import sys
from pathlib import Path
from . import __version__, api, errors
from .authorize_cli import ensure_scan_authorization, run_authorize
from .chain_cli import add_chain_parser, run_chain_command
from .parity_cli import PARITY_COMMANDS, add_parity_parsers, run_parity
from .store import Store
from .scans import Scanner, plan_scan
from .util import APP, clean, data_root, emit, json_text, legacy_cases_dir, legacy_data_found, legacy_data_warning
from .terminal import Back, ask, choose, collect, menu, selection, text_field

UsageError = errors.UsageError

def output(data):
    print(json.dumps(data, ensure_ascii=False, indent=2))

def planned_scan(store, args):
    store.db_path(args.case_id)
    try:
        return plan_scan(store, args.case_id, args.tool, args.target, args.kind, args.top, args.region, args.modules)
    except ValueError as exc:
        raise UsageError(str(exc)) from None

def failed_scan_exit_code(state):
    return state["exit_code"] or 1

def show_summary(store, case_id):
    data = store.summary(case_id)
    c = data["case"]
    print("\n" + "─" * 65)
    print(clean(f"{c['title']}  [{c['id']}]  · {c['status']}"))
    print("Problem: " + clean(c["question"]))
    print(f"Evidence {data['counts']['artifacts']} · Entities {data['counts']['entities']} · Connections to review {data['counts']['review']} · Contradictions {data['counts']['contradictions']}")
    labels = {e["id"]: f"{e['label']} ({e['platform'] or e['kind']})" for e in data["entities"]}
    print("\nFindings / notes:")
    for note in data["notes"][:5]:
        print(clean(f"  [{note['kind']}; user-declared] {note['text'][:240]}"))
    accepted = [r for r in data["relations"] if r["status"] == "accepted"]
    for relation in accepted[:5]:
        print(clean(f"  {labels[relation['source']]} — {relation['kind']} — {labels[relation['target']]} [{relation['basis']}]"))
    if not data["notes"] and not accepted:
        print("  No accepted findings yet. Add what you know or review imported leads.")
    print("\nCollection: " + clean(json_text(data["counts"]["statuses"])))
    for job in data["jobs"][:3]:
        print(clean(f"  {job['tool']} · {job['target']} · {job['state']} · {job['started']}"))
    return data

def interactive_new(store):
    values = collect([text_field("cid", "Case ID (short name)"),
        ("title", lambda v: ask("Title", v.get("title", v["cid"]))),
        text_field("question", "What question or problem is this case about?")])
    cid = values["cid"]
    store.create_case(cid, values["question"], values["title"])
    print("Created. Add identifiers with Append, or select Run scan.")
    return cid

def select_case(store):
    values = collect([selection("case", "Open case", store.list_cases(), display=lambda c: f"{c['id']} — {c['title']}" + (" (legacy notes)" if c["legacy"] else "")),
        ("question", lambda v: ask("Case question", v.get("question", "")) if v["case"]["legacy"] else "")])
    case = values["case"]
    if case["legacy"]:
        store.create_case(case["id"], values["question"], case["title"], adopt=True)
    return case["id"]

def interactive_import(store, case_id=None):
    def source_file(v):
        if v["source"] == "Discover OSINT reports":
            path = choose(store.discover(), "Report", lambda i: f"{i['lane']}: {i['name']}")["path"]
        else:
            path = ask("Report/evidence file path", str(v.get("path", "")))
        path = Path(path.strip('"'))
        if not path.is_file(): raise ValueError("File does not exist.")
        v["preview"] = store.preview_bytes(path.read_bytes(), path.name)
        print(clean(json_text({k: val for k, val in v["preview"].items() if k != "observations"})))
        return path
    def approval(v):
        items = v["preview"].get("targets", [])
        multiple = bool(case_id and len(items) > 1)
        while True:
            selected = None
            if multiple:
                print("Multiple targets; importing them does not declare a shared identity.")
                selected = choose([None, *items], "Results to include", lambda item: "All targets" if item is None else item)
            try:
                return {"targets": None if selected is None else [selected], "confirm": ask("Type IMPORT to preserve this report")}
            except Back:
                if not multiple: raise
    values = collect([selection("source", "Import source", ["Enter a file path", "Discover OSINT reports"]),
        ("path", source_file), ("approval", approval)])
    if values["approval"]["confirm"] != "IMPORT": return
    output(store.import_path(values["path"], case_id, values["approval"]["targets"]))

def interactive_inbox(store):
    items = store.list_inbox()
    if not items:
        interactive_import(store)
        return None
    while True:
        item = choose(items, "Inbox item", lambda x: f"{x['name']} · {x['preview']['adapter']} · {x['state']}")
        output(item["preview"])
        try:
            while True:
                choice = menu([("n", "New case"), ("e", "Existing case"), ("0", "Leave unassigned")], "Assign this import")
                if choice == "0": return None
                try:
                    cid = interactive_new(store) if choice == "n" else select_case(store)
                    output(store.assign_import(item["id"], cid))
                    return cid
                except Back:
                    continue
        except Back:
            continue

def interactive_append(store, case_id):
    choice = None
    while True:
        choice = menu([("1", "Import evidence"), ("2", "Add entity / identifier"), ("3", "Add note / finding"),
                       ("4", "Declare connection"), ("5", "Attach evidence to connection")], "Append to " + case_id, choice)
        try:
            append_action(store, case_id, choice)
            return
        except Back:
            continue

def append_action(store, case_id, choice):
    if choice == "1":
        interactive_import(store, case_id)
    elif choice == "2":
        values = collect([text_field("label", "Label / handle"),
            selection("kind", "Entity kind", ["account", "person", "persona", "group", "server", "email", "phone", "transaction", "incident", "other"]),
            text_field("platform", "Platform (e.g. telegram, roblox)"), text_field("identifier", "Stable ID or URL, if known")])
        output(store.add_entity(case_id, **values))
    elif choice == "3":
        values = collect([selection("kind", "Note kind", ["note", "finding", "allegation", "question"]), text_field("text", "Text")])
        output(store.add_note(case_id, **values))
    elif choice == "4":
        items = store.summary(case_id)["entities"]
        display = lambda e: f"{e['label']} · {e['platform']} · {e['id']}"
        values = collect([selection("source", "From entity", items, display=display),
            ("target", lambda v: choose([e for e in items if e["id"] != v["source"]["id"]], "To entity", display, v.get("target"))),
            selection("kind", "Relationship", ["associated_with", "same_entity", "owns", "purchased", "links_to", "advertises", "depicts"]),
            text_field("note", "Reason / context"), text_field("since", "Applies from YYYY-MM-DD (optional)"), text_field("until", "Applies through YYYY-MM-DD (optional)")])
        values["source"], values["target"] = values["source"]["id"], values["target"]["id"]
        output(store.add_relation(case_id, **values))
    elif choice == "5":
        data = store.summary(case_id)
        labels = {e["id"]: e["label"] for e in data["entities"]}
        values = collect([selection("relation", "Connection", data["relations"], display=lambda r: f"{labels[r['source']]} — {r['kind']} — {labels[r['target']]}"),
            selection("artifact", "Evidence", data["artifacts"], display=lambda a: a["name"]),
            selection("role", "Evidence role", ["supports", "contradicts", "context"]),
            text_field("selector", "Page / region / row / message locator"), text_field("note", "What does this show?")])
        output(store.attach_evidence(case_id, values.pop("relation")["id"], values.pop("artifact")["id"], **values))

def interactive_review(store, cid):
    data = store.summary(cid)
    labels = {e["id"]: e["label"] for e in data["entities"]}
    def decision(v):
        output(v["relation"])
        return choose(["accepted", "proposed", "rejected"], "Review decision", default=v.get("status", v["relation"]["status"]))
    values = collect([selection("relation", "Connection to review", data["relations"], display=lambda r: f"{labels[r['source']]} → {r['kind']} → {labels[r['target']]} [{r['status']}; {r['basis']}]"),
        ("status", decision), text_field("reason", "Reason")])
    output(store.review_relation(cid, values["relation"]["id"], values["status"], values["reason"]))

def interactive_scan(store, cid):
    ensure_scan_authorization(store, cid)
    tool = None
    while True:
        tool = choose(["maigret", "scanner", "phone"], "Scanner", default=tool)
        steps = ([selection("kind", "Identifier kind", ["username", "email"])] if tool == "scanner" else [])
        steps += [text_field("target", "Identifier in this case's authorized scope")]
        if tool == "maigret": steps += [text_field("top", "Top sites", "500")]
        if tool == "phone": steps += [text_field("region", "Country code (if needed)")]
        if tool == "scanner": steps += [text_field("modules", "Scanner modules (comma-separated, empty = default)")]
        def confirm(v):
            v["plan"] = plan_scan(store, cid, tool, v["target"], v.get("kind", "phone" if tool == "phone" else "username"), int(v.get("top", 500)), v.get("region", ""), v.get("modules", ""))
            output(v["plan"])
            return ask("Type RUN after checking authorization and network readiness")
        steps += [("confirm", confirm)]
        try:
            values = collect(steps)
            break
        except Back:
            continue
    if values["confirm"] != "RUN": return
    print("Running; output is saved in the case's run folder.")
    result = Scanner(store).start(values["plan"])
    output(result)
    show_summary(store, cid)

def interactive_collection(store, cid, tool=None, mode="auto"):
    from .native import launch_session
    ensure_scan_authorization(store, cid)
    if tool:
        output(launch_session(store, cid, tool, mode))
        return
    while True:
        choice = menu([("1", "Open scanner — full interactive menu"), ("2", "Quick scan — profiler presets")], "Scan / " + cid)
        try:
            if choice == "2":
                interactive_scan(store, cid)
            else:
                values = collect([selection("tool", "Scanner", ["maigret", "scanner", "phone"]),
                    selection("mode", "Open scanner in", ["auto", "split", "tab", "foreground"], display=lambda m: {"auto": "Split pane when available (recommended)", "split": "Split pane", "tab": "New terminal tab", "foreground": "This terminal; return when scanner closes"}[m])])
                output(launch_session(store, cid, values["tool"], values["mode"]))
                print("Use the scanner's own RUN confirmation. Reports import after each scan; press R to refresh this case.")
            return
        except Back:
            continue

def workbench(store, case_id=None):
    if not sys.stdin.isatty():
        raise UsageError("Open the workbench in a terminal, or use --help for noninteractive commands.")
    focus = {}
    while True:
        try:
            if not case_id:
                print("\nOSINT PROFILER  ·  local case workbench")
                try:
                    choice = menu([("1", "New case"), ("2", "Open case"), ("3", "Import report"), ("4", "Inbox"), ("q", "Quit")], "Home", focus.get("home"))
                except Back:
                    return
                focus["home"] = choice
                if choice == "1": case_id = interactive_new(store)
                elif choice == "2": case_id = select_case(store)
                elif choice == "3": interactive_import(store)
                elif choice == "4": case_id = interactive_inbox(store)
                elif choice in ("q", "quit"): return
            else:
                show_summary(store, case_id)
                emit("progress", store.case_dir(case_id))
                try:
                    choice = menu([("1", "Append"), ("2", "Open scanner / Quick scan"), ("3", "Review links"), ("4", "Browser editor"),
                        ("5", "Export"), ("6", "Inbox"), ("7", "Switch case / home"), ("8", "New case"), ("r", "Refresh"), ("q", "Quit")],
                        "Case / " + case_id, focus.get(case_id))
                except Back:
                    case_id = None
                    continue
                focus[case_id] = choice
                if choice == "1": interactive_append(store, case_id)
                elif choice == "2": interactive_collection(store, case_id)
                elif choice == "3": interactive_review(store, case_id)
                elif choice == "4":
                    from .web import launch_ui
                    output(launch_ui(store, case_id))
                elif choice == "5": output(store.export(case_id))
                elif choice == "6": case_id = interactive_inbox(store) or case_id
                elif choice == "7": case_id = None
                elif choice == "8": case_id = interactive_new(store)
                elif choice in ("q", "quit"): return
        except Back:
            continue
        except (ValueError, OSError) as exc:
            print("\n" + clean(str(exc)))
        except KeyboardInterrupt:
            print("\nCancelled. Saved case data remains available.")
            return

class ParseFailure(Exception):
    def __init__(self, usage, program, message):
        super().__init__(message)
        self.usage, self.program = usage, program


class QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise ParseFailure(self.format_usage(), self.prog, message)


def add_common(q):
    q.add_argument("--json", action="store_true", help="Print exactly one {ok, data, error} envelope on stdout")
    q.add_argument("--no-input", action="store_true", help="Never prompt; a missing value exits 2")
    return q


def parser():
    p = QuietParser(prog="osint-case", description="Local case workbench: terminal, imports, evidence, collection and browser review.")
    p.add_argument("--root", help="Data root (precedence: --root, then OSINT_ROOT, then the platform default)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")
    for cmd in ("new", "open", "append", "summary", "export", "scan", "ui", "serve", "entity", "link", "note", "review", "evidence"):
        q = add_common(sub.add_parser(cmd))
        q.add_argument("case_id", nargs="?" if cmd in ("new", "ui", "serve") else None)
        if cmd == "new":
            q.add_argument("--question"); q.add_argument("--title", default=""); q.add_argument("--adopt", action="store_true")
        if cmd == "append":
            q.add_argument("--file"); q.add_argument("--note")
        if cmd in ("ui", "serve"):
            q.add_argument("--port", type=int, default=0); q.add_argument("--no-browser", action="store_true")
        if cmd == "scan":
            q.add_argument("--quick", action="store_true", help="Use the profiler's guided presets instead of the full scanner menu")
            q.add_argument("--mode", choices=["auto", "split", "tab", "foreground"], default="auto", help="Interactive scanner terminal placement")
            q.add_argument("--tool", choices=["maigret", "scanner", "phone"]); q.add_argument("--target"); q.add_argument("--kind", default="username")
            q.add_argument("--top", type=int, default=500); q.add_argument("--region", default=""); q.add_argument("--modules", default=""); q.add_argument("--confirm", choices=["RUN"])
        if cmd == "entity":
            q.add_argument("--label", required=True); q.add_argument("--kind", default="account"); q.add_argument("--platform", default=""); q.add_argument("--identifier", default="")
        if cmd == "link":
            q.add_argument("--source", required=True); q.add_argument("--target", required=True); q.add_argument("--kind", default="associated_with"); q.add_argument("--note", default=""); q.add_argument("--since", default=""); q.add_argument("--until", default="")
        if cmd == "note":
            q.add_argument("--text", required=True); q.add_argument("--kind", default="note")
        if cmd == "review":
            q.add_argument("--relation", required=True); q.add_argument("--status", required=True); q.add_argument("--reason", default="")
        if cmd == "evidence":
            q.add_argument("rest", nargs="*", help="With 'remove' as the case argument: evidence remove <case> <evidence-id>")
            q.add_argument("--relation"); q.add_argument("--artifact"); q.add_argument("--role", default="supports"); q.add_argument("--selector", default=""); q.add_argument("--note", default="")
    add_chain_parser(sub, add_common)
    add_parity_parsers(sub, add_common)
    q = add_common(sub.add_parser("authorize", help="Record, show or revoke the subject-authorization attestation for a case"))
    q.add_argument("case_id")
    q.add_argument("--subject-label"); q.add_argument("--purpose"); q.add_argument("--purpose-note"); q.add_argument("--legal-basis"); q.add_argument("--basis-note")
    q.add_argument("--jurisdiction"); q.add_argument("--acknowledge", help="The exact typed acknowledgement phrase"); q.add_argument("--ack-file", help="JSON file with the same fields")
    q.add_argument("--revoke", action="store_true"); q.add_argument("--reason"); q.add_argument("--show", action="store_true")
    q = add_common(sub.add_parser("import")); q.add_argument("path"); q.add_argument("--case", dest="case_id"); q.add_argument("--target", action="append", dest="targets")
    q = add_common(sub.add_parser("assign")); q.add_argument("import_id"); q.add_argument("case_id"); q.add_argument("--target", action="append", dest="targets")
    q = add_common(sub.add_parser("migrate-root", help="Copy case data from one data root to another (never moves or deletes)"))
    q.add_argument("--from", dest="source_root", required=True, help="The existing data root to copy from")
    q.add_argument("--to", dest="target_root", required=True, help="The new data root to copy into")
    q.add_argument("--dry-run", action="store_true", help="List what would be copied, with sizes; copy nothing")
    q.add_argument("--force", action="store_true", help="Copy into a root that already has cases; still never overwrites or deletes")
    for cmd in ("list", "inbox", "discover", "doctor", "ui-stop"):
        q = add_common(sub.add_parser(cmd))
        if cmd == "doctor": q.add_argument("--offline", action="store_true")
    return p


def require_interactive(args, what):
    if not args.interactive:
        raise UsageError(f"{what} needs an interactive terminal; supply the values as options (see --help). No prompt is shown under --json, --no-input or a non-TTY stdin.")


def handle_new(store, args):
    if not (args.case_id and args.question):
        require_interactive(args, "new without a case ID and --question")
    result = store.create_case(args.case_id or ask("Case ID"), args.question or ask("Case question"), args.title, args.adopt)
    if args.interactive:
        workbench(store, result["case"]["id"])
        return None
    return result


def handle_append(store, args):
    if args.file: return store.import_path(args.file, args.case_id)
    if args.note: return store.add_note(args.case_id, args.note)
    require_interactive(args, "append without --file or --note")
    interactive_append(store, args.case_id)


def handle_summary(store, args):
    if args.json:
        return store.summary(args.case_id)
    show_summary(store, args.case_id)


def handle_evidence(store, args):
    if args.case_id == "remove" and len(args.rest) == 2:
        return api.open_case(args.rest[0], store=store).remove_evidence(args.rest[1])
    if args.rest or not (args.relation and args.artifact):
        raise UsageError("evidence needs --relation and --artifact, or: evidence remove <case> <evidence-id>.")
    return store.attach_evidence(args.case_id, args.relation, args.artifact, args.role, args.selector, args.note)


def handle_scan(store, args):
    if not args.tool or not args.target:
        require_interactive(args, "scan without --tool and --target")
        if args.quick: interactive_scan(store, args.case_id)
        else: interactive_collection(store, args.case_id, args.tool, args.mode)
        return None
    case = api.open_case(args.case_id, store=store)
    plan = case.plan(args.tool, args.target, args.kind, args.top, args.region, args.modules)
    if args.confirm != "RUN":
        return {"plan": plan, "executed": False, "next": "Review this plan, then repeat with --confirm RUN."}
    ensure_scan_authorization(store, args.case_id, args.interactive)
    result = case.run(plan, args.confirm)
    if result["state"] != "complete":
        return Outcome(result, result["exit_code"] or 1)
    return result


class Outcome:
    def __init__(self, result, exit_code):
        self.result, self.exit_code = result, exit_code


def handle_ui(store, args):
    from .web import launch_ui, serve
    if args.command == "serve":
        serve(store, args.port)
        return None
    return launch_ui(store, args.case_id, args.port, not args.no_browser)


def handle_open(store, args):
    require_interactive(args, "open")
    workbench(store, args.case_id)


def handle_chain(store, args):
    result, chain_code = run_chain_command(store, args)
    return Outcome(result, chain_code) if chain_code else result


def handle_ui_stop(store, args):
    from .web import stop_ui
    return stop_ui(store)


HANDLERS = {
    "new": handle_new, "open": handle_open, "append": handle_append, "summary": handle_summary, "list": lambda s, a: s.list_cases(),
    "inbox": lambda s, a: s.list_inbox(), "discover": lambda s, a: s.discover(), "import": lambda s, a: s.import_path(a.path, a.case_id, a.targets),
    "assign": lambda s, a: s.assign_import(a.import_id, a.case_id, a.targets), "entity": lambda s, a: s.add_entity(a.case_id, a.label, a.kind, a.platform, a.identifier),
    "link": lambda s, a: s.add_relation(a.case_id, a.source, a.target, a.kind, a.note, a.since, a.until), "note": lambda s, a: s.add_note(a.case_id, a.text, a.kind),
    "review": lambda s, a: s.review_relation(a.case_id, a.relation, a.status, a.reason), "evidence": handle_evidence, "export": lambda s, a: s.export(a.case_id),
    "authorize": run_authorize, "chain": handle_chain, "scan": handle_scan, "ui": handle_ui, "serve": handle_ui, "ui-stop": handle_ui_stop,
    **{name: run_parity for name in PARITY_COMMANDS},
}


def doctor_report(args):
    root = data_root(args.root)
    legacy = {"found": legacy_data_found(root), "path": str(legacy_cases_dir().parent), "next": "Run: osint-case migrate-root --from <old> --to <new>" if legacy_data_found(root) else ""}
    return {"version": __version__, "python": sys.version.split()[0], "sqlite": __import__("sqlite3").sqlite_version,
            "app": str(APP), "storage": str(root), "legacy_data": legacy,
            "pwsh": bool(shutil.which("pwsh.exe") or shutil.which("pwsh")), "docker_installed": bool(shutil.which("docker")), "offline": True}


def run_migrate_root(args):
    from .migrate import migrate_root
    result = migrate_root(args.source_root, args.target_root, args.dry_run, args.force)
    return result, 1 if result.get("corrupt") or result.get("conflicts") else 0


def execute(args):
    """(result, exit code); raises for failures that carry no result."""
    if args.command == "doctor":
        return doctor_report(args), 0
    if args.command == "migrate-root":
        return run_migrate_root(args)
    store = Store(args.root)
    if args.command is None:
        require_interactive(args, "The workbench")
        workbench(store)
        return None, 0
    outcome = HANDLERS[args.command](store, args)
    if isinstance(outcome, Outcome):
        return outcome.result, outcome.exit_code
    return outcome, 0


def result_error(result, exit_code):
    nested = result.get("error") if isinstance(result, dict) else None
    if isinstance(nested, dict) and "error" in nested:
        return nested["error"], nested.get("message", ""), nested.get("next", "")
    code = errors.code_for_exit(exit_code)
    message = (result.get("message") if isinstance(result, dict) else "") or errors.GATE_MESSAGES.get(code, "The operation did not complete.")
    return code, message, errors.DEFAULT_NEXT.get(code, errors.DEFAULT_NEXT["failed"])


def envelope_text(ok, data, error=None, legacy=None):
    body = {"ok": ok, "data": data, "error": error}
    if legacy is not None:
        body["legacy_error"] = legacy
    return json.dumps(body, ensure_ascii=False, indent=2)


def render_success(args, result):
    if args.json: print(envelope_text(True, result))
    elif result is not None: output(result)


def render_failure(args, code, message, following, details=None, result=None, legacy=None):
    if args.json:
        error = {"code": code, "message": message, "next": following, **({"details": details} if details else {})}
        print(envelope_text(False, result, error, legacy or {"error": code, "message": message, "next": following, **(details or {})}))
    elif result is not None:
        output(result)
    else:
        print("Error: " + clean(message), file=sys.stderr)
    return errors.exit_code_for(code)


def parse_failure_exit(failure, argv):
    wanted_json = "--json" in (sys.argv[1:] if argv is None else argv)
    if wanted_json:
        print(envelope_text(False, None, {"code": "usage", "message": str(failure), "next": errors.DEFAULT_NEXT["usage"]},
                            {"error": "usage", "message": str(failure)}))
    else:
        print(failure.usage + f"{failure.program}: error: {failure}", file=sys.stderr)
    return 2


def stdin_is_terminal():
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (ValueError, AttributeError):
        return False


def run_guarded(args):
    """execute() with stdout diverted to stderr under --json so only the envelope reaches stdout."""
    guard = contextlib.redirect_stdout(sys.stderr) if args.json else contextlib.nullcontext()
    with guard:
        return execute(args)


def warn_legacy_data(args):
    if args.command in ("doctor", "migrate-root"):
        return
    message = legacy_data_warning(data_root(args.root))
    if message:
        print(message, file=sys.stderr)


def main(argv=None):
    try:
        args = parser().parse_args(argv)
    except ParseFailure as failure:
        return parse_failure_exit(failure, argv)
    args.json = getattr(args, "json", False)
    args.interactive = stdin_is_terminal() and not args.json and not getattr(args, "no_input", False)
    emit("started")
    warn_legacy_data(args)
    try:
        result, exit_code = run_guarded(args)
    except Back:
        print("Cancelled. No pending form was saved.")
        emit("ok")
        return 0
    except (ValueError, OSError, __import__("sqlite3").Error, KeyboardInterrupt) as exc:
        code, message, following, details = errors.describe(exc)
        emit("needs-human" if code == "interrupted" else "failed")
        legacy = exc.payload() if hasattr(exc, "payload") and (code == "usage" or not isinstance(exc, errors.ProfilerError)) else {"error": message}
        return render_failure(args, code, message, following, details, legacy=legacy)
    artifact = Store(args.root).case_dir(args.case_id) if getattr(args, "case_id", None) and args.command != "doctor" else None
    if exit_code:
        code, message, following = result_error(result, exit_code)
        emit("failed", artifact or "")
        render_failure(args, code, message, following, result=result)
        return exit_code
    render_success(args, result)
    emit("ok", artifact or "")
    return 0


def console_main():
    sys.exit(main())
