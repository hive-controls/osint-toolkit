"""Non-interactive twins of workbench operations: job, observation, case, undo, relations, catalog, plan."""
from __future__ import annotations
from . import api
from .errors import UsageError

VERDICTS = ["relevant", "excluded", "unreviewed"]


def add_parity_parsers(sub, common):
    def command(name, *positionals, parent=sub, **kwargs):
        parser = parent.add_parser(name, **kwargs)
        for positional in positionals:
            parser.add_argument(positional)
        common(parser)
        return parser

    job = sub.add_parser("job", help="List, inspect, cancel or wait for scan jobs")
    jobs = job.add_subparsers(dest="job_command", required=True)
    command("list", "case_id", parent=jobs)
    command("show", "case_id", "job_id", parent=jobs)
    command("cancel", "case_id", "job_id", parent=jobs, help="Cancel a job started by this same process (library use)")
    command("wait", "case_id", "job_id", parent=jobs).add_argument("--timeout", type=float)
    observation = sub.add_parser("observation", help="Review scanner observations")
    reviewing = command("review", "case_id", "fingerprint", parent=observation.add_subparsers(dest="observation_command", required=True))
    reviewing.add_argument("--verdict", required=True, choices=VERDICTS)
    reviewing.add_argument("--reason", default="")
    case = sub.add_parser("case", help="Edit case metadata")
    updating = command("update", "case_id", parent=case.add_subparsers(dest="case_command", required=True))
    updating.add_argument("--title"); updating.add_argument("--question"); updating.add_argument("--status", choices=["open", "closed"])
    command("undo", "case_id", "event_id")
    command("list", "case_id", parent=sub.add_parser("relations", help="List a case's connections").add_subparsers(dest="relations_command", required=True))
    tools = sub.add_parser("catalog", help="Inspect and validate the tool catalog").add_subparsers(dest="catalog_command", required=True)
    command("list", parent=tools)
    command("show", "tool", parent=tools)
    command("validate", parent=tools)
    planning = command("plan", "case_id", "tool", help="Validated scan plan with authorization and gate requirements; never executes")
    planning.add_argument("--target", required=True); planning.add_argument("--kind", default="username")
    planning.add_argument("--top", type=int, default=500); planning.add_argument("--region", default=""); planning.add_argument("--modules", default="")


def catalog_list():
    loaded = api.catalog()
    return [{"id": entry["id"], "version": entry["version"], "interactive_only": entry["interactive_only"], "runner": entry["runner"]} for entry in loaded["tools"]]


def catalog_show(tool_name):
    from . import catalog
    entry = catalog.tool(tool_name, api.catalog())
    if entry is None:
        raise api.NotFoundError(f"Tool {tool_name!r} is not in the catalog.", "Run: osint-case catalog list --json")
    return entry


def catalog_validate():
    loaded = api.catalog()
    return {"valid": True, "catalog_version": loaded["catalog_version"], "tools": len(loaded["tools"])}


def run_job(case, args):
    action = args.job_command
    if action == "list": return case.jobs()
    if action == "show": return case.job_detail(args.job_id)
    if action == "cancel": return case.cancel_job(args.job_id)
    return case.wait_job(args.job_id, args.timeout)


def run_parity(store, args):
    command = args.command
    if command == "catalog":
        if args.catalog_command == "list": return catalog_list()
        if args.catalog_command == "show": return catalog_show(args.tool)
        return catalog_validate()
    case = api.open_case(args.case_id, store=store)
    if command == "job": return run_job(case, args)
    if command == "observation": return case.review_observation(args.fingerprint, args.verdict, args.reason)
    if command == "case": return case.update(args.title, args.question, args.status)
    if command == "undo": return case.undo(args.event_id)
    if command == "relations": return case.relations()
    if command == "plan": return case.plan(args.tool, args.target, args.kind, args.top, args.region, args.modules)
    raise UsageError(f"Unknown command {command!r}.")


PARITY_COMMANDS = ("job", "observation", "case", "undo", "relations", "catalog", "plan")
