---
name: osint-profiler
title: OSINT Profiler
purpose: Operate the local terminal workbench and browser evidence editor.
---

# OSINT Profiler

> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md](../LEGAL-USE.md).

Installs `osint-case` for the current user. Open a **new PowerShell terminal** after installation so it receives the updated user PATH. The application uses Python's standard library and SQLite; offline case work needs neither Docker nor a model.

```powershell
osint-case                        # Guided terminal workbench
osint-case new demo --question "Which accounts belong together?"
osint-case append demo --note "Starting with a user-supplied account identifier."
osint-case append demo --file 'C:\path\results.json'
osint-case summary demo
osint-case ui demo                 # Local graph, review and evidence editor
```

For scripting, use explicit options and `--json` (see Command-line reference). `new` enters the workbench in an interactive terminal unless `--json` is supplied. `open demo` resumes that workbench. `append demo` opens its append menu. Every command supports `--help`.

### Terminal navigation

- **Up / Down:** move the highlighted selection. Home / End jump to the first / last item; long lists scroll automatically.
- **Right or Enter:** open the highlighted selection. Number and letter shortcuts still work: type the displayed shortcut, then Enter (or Right).
- **Left or Esc:** return from a selection to its parent screen. From the case menu this returns home; from home it exits.
- **Text fields:** type normally; Left / Right move the cursor, Home / End and Delete / Backspace edit. Enter continues; **Esc returns to the previous field**, keeping completed values for editing. Backing out of the first field returns to its menu.
- Imports still require typed `IMPORT`; collection still requires typed `RUN`. Arrow navigation alone cannot authorize either.

The installed command reads this workspace's current code; no reinstall is needed after updates. Restart an already-open workbench to load them. For a plain line-input interface, set `$env:OSINT_PLAIN_TERMINAL = '1'` before launching; use `:back` to return in that mode. Explicit noninteractive command arguments are unchanged.

## A useful case workflow

1. Create a case with a concrete question. Add known accounts using **Append** or the browser's **Entities** view. Keep allegations in notes marked as allegations.
2. Import existing scanner exports or collect new results. Inspect the import preview before accepting a file in the guided interfaces. Files imported without a case stay in the inbox until assigned.
3. Review proposed connections. An identical handle is a lead, not proof of a shared identity. Accept, reject or change the relationship type and record why.
4. Add your own connections where the scanners cannot observe them. `same_entity` joins personas into a profile; `associated_with`, `owns`, `purchased`, `links_to`, `advertises`, and `depicts` preserve separate entities. Ownership and identity claims can have start/end dates.
5. Attach supporting, contradicting or contextual evidence to each claim. Import screenshots as evidence; use a row/JSON selector, timestamp, or image-region locator to identify the relevant part. The original bytes and SHA-256 are retained.
6. Exclude irrelevant findings from the working view without deleting evidence. Review decisions are recorded and can be undone. Export a readable profile when ready.

User-declared claims are labeled as such; accepting a claim is a review decision, not independent verification. Contradictory evidence stays visible. Multiple reports of the same finding retain their separate source citations without duplicating the displayed finding.

## Import before a case exists

```powershell
osint-case import 'C:\path\results.json'
osint-case inbox
osint-case assign IMPORT_ID demo
osint-case discover                # Existing top-level reports in OSINT lanes
osint-case import 'C:\path\mixed.json' --case demo --target selected_handle
```

Supported structured inputs: Maigret JSON/CSV, User-Scanner JSON/CSV, and this workspace's Phone Lookup JSON envelope. Unknown formats, empty reports, screenshots, and other files are retained as evidence attachments; their contents are not guessed into identities. Individual imports are limited to 32 MiB. Re-importing the same file is idempotent. Changed snapshots remain separate evidence. Raw provider payloads are preserved even when an adapter cannot interpret them.

The browser accepts files through the OS file picker. CLI imports can use paths directly. Neither interface automatically imports the entire legacy report tree.

## Run scanners for a case

**Open scanner** is the default interactive experience. In the workbench select **Open scanner / Quick scan → Open scanner**, choose Maigret, User Scanner, or Phone Lookup, then choose terminal placement. The browser's **Activity & scans → Open scanner** uses the same case-bound launch path.

The original scanner menu retains its supported options, favorites, progress display and typed RUN confirmations. A Windows Terminal split is preferred when the current host supports it; launch errors fall back to a tab, then the current terminal (CLI) or a separate terminal window (browser). Foreground mode hands over the terminal until you exit the scanner menu. Opening a menu does not start a scan.

```powershell
osint-case scan demo               # Open scanner or choose Quick scan
osint-case scan demo --tool scanner                # Full menu; prefer split
osint-case scan demo --tool maigret --mode tab
osint-case scan demo --tool phone --mode foreground
osint-case scan demo --quick       # Existing guided profiler presets
osint-case scan demo --tool maigret --target example_handle --top 100
# Review the printed plan, then repeat with --confirm RUN to execute.
osint-case scan demo --tool scanner --target example_handle --confirm RUN
osint-case scan demo --tool phone --target '+15555550123' --confirm RUN
```

Collection uses the hardened runners, each of which applies the network gate (same VPN-route check); a refused scan ends with exit 75. Each run records its arguments, console log, exit status and report snapshots. Outputs go to `<data root>/cases/<id>/runs/<run-id>/output`, then are imported into that case **after each scan**, while the scanner menu can remain open. Switching the profiler to another case cannot change that session's destination. Refresh the profiler (R in the terminal) to see the newly imported findings.

Case mode retains machine-readable output: Maigret writes a JSON sidecar even when its optional report bundle is disabled; User Scanner's terminal-only selection also writes JSON while retaining its display settings; CSV remains available. Phone Lookup retains its JSON envelope. Bulk input selected by User Scanner is copied from session staging into that run's mount and is not imported as scanner findings. These additions apply only to case-bound sessions; standalone scanner behavior is unchanged.

A failed or cancelled run can still preserve partial output. Missing reports are visible in the run outcome; parser issues remain in artifact metadata. A successful menu exit is recorded separately from individual scan success. One profiler session or Quick scan per scanner can own its Compose project at a time. An interactive session keeps that reservation until its menu closes; existing running containers cause a refusal.

Use the scanner terminal to interrupt a native scan or exit its menu. Quick scans retain their existing CLI/background behavior and browser cancel control. Closing the browser or profiler workbench does not stop a separate scanner terminal; it keeps its fixed case context and imports results itself. Abruptly closing/killing its terminal can prevent final import/cleanup: an abandoned running job is marked interrupted on a later case read, and saved outputs can be imported manually after checking Docker state.

## Tool catalog

`shared/catalog/tools.json` is the single declarative catalog of the tools the profiler can launch (`maigret`, `user-scanner`, `phone-lookup`, `osint-case`, and `torbot`, which is listed `interactive_only: true` and is not runnable through `scan --confirm`). Each entry carries its version, runner and menu paths, inputs, options (bounds, patterns, defaults, flags), `fixed_argv` and `argv_template`, outputs, exit codes, gates and interactive equivalents. It is validated on load against `shared/catalog/schema/catalog.schema.json` by the stdlib-only validator in `osint_profiler/schemacheck.py` (a JSON Schema subset; any unsupported keyword raises rather than being ignored). `OSINT_TOOLKIT_ROOT` selects a different toolkit root; the default is this checkout.

Validators are catalog-driven: `plan_scan` reads identifier rules, kind restrictions, option bounds and patterns from the catalog and builds argv from `argv_template` plus `fixed_argv`, so changing a regex or bound means editing `tools.json`, not Python. The legacy ids `scanner` and `phone` are still accepted (`legacy_ids` maps them to `user-scanner` and `phone-lookup`); the jobs table and runners keep the legacy ids. `tests/test_plan_scan_golden.py` pins the behavior with a recorded corpus.

To add a tool: add an entry to `tools.json` (all fields in `catalog.schema.json` are required, including the `formic` block that drives the generated `.formic/` manifests; regenerate them with `python -I shared/build/generate_formic.py`), keep its runner under the tool's own folder, add an `output_env` if it writes reports, and run `python -m pytest -q tests`. A tool is runnable through the profiler only when it is not `interactive_only` and has an `output_env`.

## Result envelope

Every profiler or menu-launched run writes `<data root>/cases/<id>/runs/<job>/result.json` after it ends, on success and failure alike, validated against `shared/catalog/schema/result.schema.json`. Fields: `schema_version` (1), `tool_id`, `tool_version`, `catalog_version`, `case_id`, `job_id`, `chain` (null for now), `started`, `finished`, `exit_code`, `gate` (`network.code` is `PASS`, 75, 78 or null, derived from the exit code; `network.mode` is null; `authorization` carries `status` and `attestation_id`), `inputs`, `artifacts` (path relative to the run folder, `sha256`, `bytes`, `adapter`), `entities` and `errors`.

Entities are derived from the report adapters and never assert identity (`identity_assertion` is always false). Hits become `account` entities (value is the profile URL) and the queried identifier becomes a `username` or `email` entity whose `attrs.counts` holds the hit/absent/error/unknown tallies; absent, error and unknown results appear only in those counts. Maigret `ids_usernames` become `username` entities with provenance `derived`. Phone runs yield `phone.e164`, `phone.meta` and one `breach.signal` (`source`, `state`) per provider; provider response bodies are never extracted.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed (a scan exits 0 only when its job state is `complete`) |
| 1 | Operation failed, or a scan ended `partial` |
| 2 | Invalid arguments or a missing required value (also: no prompt is ever shown under `--json`, `--no-input` or a non-TTY stdin) |
| 64 | Runner usage error (propagated from a scan runner) |
| 75 | Network gate refused the run |
| 77 | Subject authorization required |
| 78 | Network gate configuration error |
| 130 | Interrupted or cancelled |

`scan --confirm RUN` returns the runner's real code, so 75, 77 and 78 propagate instead of collapsing to 1. `osint_profiler/errors.py` holds the one table mapping each stable `error.code` slug to its exit code.

## Command-line reference

Every subcommand accepts `--json` and `--no-input`. Under `--json` exactly one object is printed on stdout and nothing else (human text goes to stderr):

```json
{"ok": true, "data": {}, "error": null}
{"ok": false, "data": null, "error": {"code": "usage", "message": "...", "next": "..."}}
```

`data` is the command's result (for a failed run it still carries the partial result). `error.code` is a stable slug: `usage`, `not-found`, `subject-authorization-required`, `network-gate`, `config-provider`, `interrupted`, `derived-input-refused`, `spec-invalid`, `ambiguous-input`, plus the chain codes in the Chains section. `error.details` carries extra fields (for example `case_id` and `reason` for authorization). Schema: `shared/catalog/schema/cli-envelope.schema.json`. Without `--json`, results print as before and errors go to stderr as `Error: ...`.

Deprecated: failures under `--json` also carry a top-level `legacy_error` object with the pre-envelope error shape. It is removed after one release; read `error` instead.

| Command | Purpose | `--json` | Exit codes |
|---------|---------|----------|------------|
| `new [case] --question Q [--title T] [--adopt]` | Create a case (opens the workbench on a TTY without `--json`) | yes | 0, 1, 2 |
| `open <case>` | Workbench for a case (terminal only) | no (2 without a TTY) | 0, 2 |
| `list`, `inbox`, `discover`, `doctor [--offline]` | Cases, inbox items, discoverable reports, environment check | yes | 0, 1 |
| `summary <case>` | Case summary | yes | 0, 1 |
| `append <case> --file F` or `--note N` | Import evidence or add a note | yes | 0, 1, 2 |
| `import <path> [--case C] [--target T]`, `assign <import-id> <case>` | Preserve a report, assign it to a case | yes | 0, 1 |
| `entity`, `link`, `note`, `review` | Add an entity, declare a connection, add a note, review a connection | yes | 0, 1, 2 |
| `evidence <case> --relation R --artifact A` | Attach evidence to a connection | yes | 0, 1, 2 |
| `evidence remove <case> <evidence-id>` | Remove an evidence association | yes | 0, 1, 2 |
| `observation review <case> <fingerprint> --verdict relevant\|excluded\|unreviewed` | Review a scanner observation | yes | 0, 1, 2 |
| `case update <case> [--title T] [--question Q] [--status open\|closed]` | Edit case metadata | yes | 0, 1, 2 |
| `undo <case> <event-id>` | Undo the latest review decision | yes | 0, 1, 2 |
| `relations list <case>` | List connections with their evidence | yes | 0, 1 |
| `export <case>` | Write the export | yes | 0, 1 |
| `authorize <case> [flags] [--show] [--revoke]` | Subject-authorization attestation | yes | 0, 1, 2 |
| `migrate-root --from <old> --to <new> [--dry-run] [--force]` | Copy case data to a new data root with SHA-256 verification; never moves or deletes | yes | 0, 1, 2 |
| `catalog list`, `catalog show <tool>`, `catalog validate` | Inspect or validate the tool catalog | yes | 0, 1, 78 |
| `plan <case> <tool> --target T [--kind K] [--top N] [--region R] [--modules M]` | Catalog-validated plan with authorization status and gate requirement; never runs | yes | 0, 1, 2 |
| `scan <case> --tool T --target X [--confirm RUN]` | Plan (default) or run a scan | yes | 0, 1, 2, 75, 77, 78, 130 |
| `job list <case>`, `job show <case> <job>`, `job wait <case> <job> [--timeout S]` | Inspect scan jobs, wait for one to finish (`timeout` exits 1) | yes | 0, 1, 2 |
| `job cancel <case> <job>` | Cancel a job started by the same process (library use); a finished or foreign job exits 1 | yes | 0, 1, 2 |
| `chain run\|show\|list` | Declarative chains (see Chains) | yes | 0, 1, 2, 75, 77, 78, 130 |
| `ui`, `serve`, `ui-stop` | Browser editor | yes | 0, 1 |

## Library API

`osint_profiler/api.py` is the same surface without printing or prompting: plain dicts in and out, and typed exceptions whose `code` is an `error.code` slug from `errors.py`.

```python
from osint_profiler import api

api.configure(toolkit_root="<toolkit checkout>")        # only for an installed copy outside the repo
case = api.open_case("demo", root="<OSINT root>")        # NotFoundError if the case does not exist
case.authorize(subject_label="Subject A", purpose="security-research", legal_basis="legitimate-interest",
               jurisdiction="US-CA", acknowledgement="<the exact phrase from ACKNOWLEDGEMENT.txt>")
plan = case.plan("maigret", "alice", top=50)             # dict with arguments, authorization, gates
result = case.run(plan, confirm="RUN")                   # UsageError unless confirm == "RUN"
print(result["state"], [job["id"] for job in case.jobs()])
```

`authorize` never defaults the phrase and writes nothing when it does not match. `case.chain(spec, dry_run=False, resume=None, force=False, confirm=None)` runs a chain spec dict; `case.run(plan, "RUN", background=True)` returns immediately and `case.cancel_job` / `case.wait_job` operate on it from the same process.

## Subject authorization

See [LEGAL-USE.md](../LEGAL-USE.md) for permitted use. Before any scan runs, the case needs a subject-authorization attestation. It is an **accountability record, not a security boundary**: it documents who declared what and when. It does not stop anyone who runs the tools outside this workflow (bare `python` outside Docker, a hand-edited sidecar, direct `docker compose`).

```powershell
osint-case authorize demo                 # interactive: shows the acknowledgement, collects fields, requires the typed phrase
osint-case authorize demo --subject-label "Subject A" --purpose security-research --legal-basis legitimate-interest `
  --jurisdiction US-CA --acknowledge "I AUTHORIZE THIS CASE AND ACCEPT RESPONSIBILITY FOR LAWFUL USE"
osint-case authorize demo --ack-file ack.json   # same fields as JSON: subject_label, purpose, purpose_note, legal_basis, basis_note, jurisdiction, acknowledge
osint-case authorize demo --show [--json]
osint-case authorize demo --revoke --reason "engagement ended"
```

- **What is recorded** (append-only `authorizations` table in `case.sqlite`): an alias for the subject (`Subject A`; phone numbers, emails and `@handles` are refused, so identifiers are never stored here), purpose and legal basis (`other` requires a note), jurisdiction, the operating-system user, a timestamp, the SHA-256 of the shipped `osint_profiler/ACKNOWLEDGEMENT.txt`, and the SHA-256 of the typed phrase. Recording, revoking and every pre-run check add `authorization_recorded` / `authorization_revoked` / `authorization_check` events to the case log.
- **The phrase** must match exactly, case-sensitively: `I AUTHORIZE THIS CASE AND ACCEPT RESPONSIBILITY FOR LAWFUL USE`. A mismatch writes nothing.
- **Validity**: 180 days from the attestation, until revoked, or until the acknowledgement text changes (a new text hash makes older attestations `stale-ack`; re-run `authorize`).
- **Exit code 77** means subject authorization is required. `reason` is `missing`, `expired`, `revoked` or `stale-ack`. Under `--json` the envelope's `error` has `code` `subject-authorization-required`, `next` `osint-case authorize <id>`, and `details` with `case_id` and `reason`. The first `scan` on a case with no attestation prompts inline when stdin is a terminal; otherwise it exits 77. The browser editor shows the same error and offers the same fields in a dialog.
- **Re-checks, not re-prompts**: the ledger is checked when a scan starts, when a scanner session opens, and again for every run request from a scanner menu, so a revocation stops the next run in an open session.
- **Derived sidecar**: `cases/<id>/authorization.json` (`attestation_id`, `case_id`, `ack_version_hash`, `expires_ts`, `revoked`, `subject_label`) is rewritten on every record or revoke. The four PowerShell runners (Maigret, User Scanner, Phone Lookup, TorBot) verify it after the network gate and exit 77 if it is missing, expired, revoked or stale; informational invocations such as `--help` are exempt. A verified attestation is passed to the container as `OSINT_SUBJECT_AUTH=<case>:<attestation_id>:<hash>`. The runners locate the case through `OSINT_CASE_ID` (or the session file) and the data root through `OSINT_ROOT` (or the shared default, see Data location), both set by the profiler; the scanner menus refuse to run without an open case.

## Storage and local editor

### Data location

Case data lives in the **data root**, outside the repository. The root is resolved in this order, by one function (`osint_profiler.util.data_root`) with a PowerShell twin (`Get-OsintDataRoot` in `shared/OsintTool.Common.ps1`) used by the runners and menus:

1. `--root <dir>` (the explicit argument)
2. the `OSINT_ROOT` environment variable
3. the platform default: `%LOCALAPPDATA%\OsintToolkit\data` on Windows (on POSIX, `$XDG_DATA_HOME/osint-toolkit`, else `~/.local/share/osint-toolkit`)

`OSINT_ROOT` is an input as well as an output: the profiler exports it to the runners it launches, and a persistent user-level `OSINT_ROOT` redirects every case, scan and report to that folder, so set it deliberately. Tool output lanes (`maigret`, `scanner`, `phone`, `torbot`) live under the same root; TorBot output now defaults to `<data root>\torbot`.

Case data is never moved automatically. If the legacy `OSINT/cases/` folder inside your clone still holds cases while the resolved root has none, every command prints a one-time warning on stderr and `osint-case doctor` reports it under `legacy_data`. To bring the old data across:

```powershell
osint-case migrate-root --from <repo>\OSINT --to <new data root> --dry-run   # list files and sizes
osint-case migrate-root --from <repo>\OSINT --to <new data root>             # copy, verify, rewrite
```

`migrate-root` copies `cases/`, `inbox/` and the lane folders that exist, verifies every file's SHA-256 after copying, and rewrites absolute run paths in the copied ledgers only. It refuses a destination that already has cases (`--force` copies only files that do not exist there). It never moves, overwrites or deletes: the original stays in place for you to delete after you have checked the copy. Run paths are stored relative to the case folder from now on; older absolute values are still read correctly.

Layout of the data root:

```text
inbox/                         Unassigned immutable imports + inbox.sqlite
cases/<id>/case.sqlite         Entities, observations, relationships and audit log
cases/<id>/authorization.json  Derived subject-authorization sidecar (ledger is the source of truth)
cases/<id>/imports/            Source snapshots, verified by hash
cases/<id>/runs/               Per-run plans, logs, receipts and output
cases/<id>/sessions/           Native menu context, startup status and bulk staging
cases/<id>/exports/            profile.md, profile.json, safe static profile.html
.profiler/                     Local server state and log
```

Existing `New-OsintCase` folders can be explicitly adopted; existing `case.md` is preserved. New cases use the database as their source of truth. `osint-case export demo` regenerates the three profile exports. These are reports, not self-contained evidence backups. To back up, finish scans, stop the editor, and copy the entire data root (or use `migrate-root` to copy it to a new location with hash verification). No automated backup/restore command ships yet.

The editor listens only on `127.0.0.1`, with same-origin/session checks for writes. No external fonts, CDNs, analytics, or model calls are used. Imported HTML is downloaded as evidence, never embedded as executable report HTML. Open untrusted source pages only in an isolated browser profile or VM. `osint-case ui --no-browser` prints the address; `osint-case ui-stop` stops the editor when it has no active scans. CLI and browser share the same database.

## Installation and optional Formic launcher

`formic launch osint-case` (if Formic is installed) opens the interactive workbench in the current terminal. Status events are appended to `FORMIC_STATUS_FILE` when supplied, with case/root artifact paths. Child scanners cannot overwrite that parent status stream. The offline health command does not run Docker or make network requests.

```powershell
& '<repo>\OSINT Profiler\install.ps1'
osint-case doctor --offline
# Direct entrypoint if the current terminal has an old PATH:
& '<repo>\OSINT Profiler\osint-case.ps1'
```

Alternatively, from a Python 3.11+ environment, `pip install -e "OSINT Profiler"` installs the `osint-casework` distribution (no runtime dependencies) and puts an `osint-case` command on the environment's PATH; `python -m osint_profiler` keeps working. An installed copy outside this repository finds the runners and the catalog through `OSINT_TOOLKIT_ROOT` (or `api.configure(toolkit_root=...)`); a checkout install needs nothing. `install.ps1` and `runtime.json` remain the supported Windows install path.

Installer requirements: Python 3.11+ with SQLite and PowerShell 7. It creates a user command shim under `%LOCALAPPDATA%\Programs\OsintProfiler` and adds that folder to the user PATH. It installs no Python packages. The shim points at this workspace; rerun installation after moving it. Docker and the existing scanner images are required only for collection.

### Development

Run the tests with `python -m pytest -q tests` from this folder. `install.ps1` and `Invoke-CaseScan.ps1` honor `OSINT_PROFILER_RUNTIME_FILE` to read or write `runtime.json` somewhere other than this folder (the PowerShell bridge test uses it with a temporary file).

## First-release boundaries

This release includes the terminal workflow, local browser editor, deterministic imports/proposals, manual claims with evidence, review history, exports, and scanner launch integration. Optional model-assisted review, OCR of evidence images, editable entity identifiers, and automated backup/restore of a data root remain future work. No LLM may silently accept identity links or discard evidence.

Validation uses synthetic cases and mocked collection processes.

## Chains

A chain runs several catalog tools in order from one JSON spec (JSON only, no fan-out: every input is a single value). Schema: `shared/catalog/schema/chain.schema.json`. Each step is launched through the same scanner path as `osint-case scan`, so every hop still hits the real runner gates and the subject-authorization check. The chain never sets gate environment itself. TorBot is interactive-only and is rejected when the chain is planned.

```json
{
  "version": 1,
  "id": "example-chain",
  "case_id": "my-case",
  "steps": [
    {"id": "find", "tool": "maigret", "inputs": {"target": "alice"}, "options": {"top": 200}},
    {"id": "check", "tool": "user-scanner", "derived_ok": true, "on_error": "continue",
     "inputs": {"target": "${steps.find.entities[kind=username].value|first}"}}
  ]
}
```

```
osint-case chain run spec.json                       # prints the plan, exits 0
osint-case chain run spec.json --confirm RUN         # executes
osint-case chain run spec.json --resume example-chain --confirm RUN [--force]
osint-case chain show example-chain --json           # recorded state
osint-case chain list --json
```

Without `--confirm RUN`, or with `--dry-run`, nothing runs: the plan is printed and the exit code is 0. The plan shows fully resolved arguments for literal and `case` inputs, the unresolved reference and expected kind for inputs that depend on an earlier step, the provenance of every input, every derived value, the chain-level gate set (the union of the steps' requirements, with authorization required if any step requires it), and the note that the network is not probed: the network gate is enforced per hop by each runner, not pre-probed. `--confirm RUN` is typed once per chain.

### Reference syntax

A whole input string is either a literal or exactly one reference; text such as `x${...}`, nesting, arithmetic and other filters are rejected as `spec-invalid`. References are parsed by a single pattern and never evaluated.

| Part | Allowed |
|------|---------|
| Namespace | `steps.<id>` (earlier steps only) or `case` |
| Path | `entities`, `inputs` or `artifacts` |
| Filter | optionally exactly `[kind=<name>]` |
| Terminal | `.value` or `.attrs.<key>` |
| Pipe | `\|first` or `\|only` (`only` errors unless exactly one value matches) |

A scalar input that selects several values without a pipe fails with `ambiguous-input` and lists the candidates; one that selects nothing fails with `empty-reference`. A reference with a `kind` filter is checked against the tool's accepted input kinds when the chain is planned. `case.entities` uses every case entity (entities carry no review-accepted flag): those declared by the user have provenance `user`, imported or scanner-reported ones are `derived`.

### Derived inputs are default-deny

An input value with provenance `derived` (for example a username a scanner extracted) is refused unless the receiving step sets `derived_ok: true`. The dry run lists every derived value; the refusal is `derived-input-refused`. Provenance is not laundered: `steps.<id>.inputs` keeps the provenance the step actually received. Each launched hop records its input provenance in `result.json` and in a `chain_step` ledger event (`chain_id`, `step`, `job_id`, `input_hash`, `exit_code`, `result_sha256`, provenance per input). Chain state is `chains/<chain-id>/state.json` under the case folder.

### Chain exit codes

| Code | Meaning |
|------|---------|
| 0 | Every step completed |
| first failing hop's code | A hop failed; `75`, `77`, `78`, `130` and `64` from a hop always stop the chain regardless of `on_error` |
| 77 | Authorization missing, expired or revoked before the first hop, or between hops (each hop re-checks) |
| 2 | Spec or usage errors, and `derived-input-refused` (a spec-level policy refusal, not a runner gate) |

`--json` errors use the envelope: `error.code`, `error.message`, `error.next`. `on_error: continue` only applies to ordinary failures; a step that depends on a failed step is skipped.

### Resume

`--resume <chain-id>` re-reads the recorded state. A step is skipped when its recorded `input_hash` equals the recomputed one and its `result.json` still has the recorded SHA-256. A step whose resolved inputs changed is a hard error (`input-changed`) unless `--force`. A step recorded as `running` with no result is re-run as a new job and the old job is marked `interrupted`. Resuming never reuses an authorization decision: every re-run hop checks authorization again.
