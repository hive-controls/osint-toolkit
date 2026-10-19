"""Case-bound native scanner menus in a real terminal, with per-scan receipts."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from . import envelope
from .authorization import AuthorizationRequired, require_authorization
from .scans import TOOLS
from .store import Store
from .util import APP, WORKSPACE, clean, database, json_text, now, process_alive, uid

MENUS = {"maigret": "maigret-menu.ps1", "scanner": "scanner-menu.ps1", "phone": "phone-menu.ps1"}


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json_text(value), encoding="utf-8")
    temporary.replace(path)


def child_environment():
    return {k: v for k, v in os.environ.items() if not k.startswith(("FORMIC_", "HIVEDECK_", "OSINT_CASE_"))}


def powershell():
    executable = shutil.which("pwsh.exe") or shutil.which("pwsh")
    if not executable: raise ValueError("PowerShell 7 is required for scanner menus.")
    return executable


def terminal_executable():
    executable = shutil.which("wt.exe")
    alias = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/WindowsApps/wt.exe"
    return executable or (str(alias) if alias.is_file() else None)


def tool_lock(tool, root):
    folder = Path(root) / ".profiler-locks"
    folder.mkdir(parents=True, exist_ok=True)
    lock = open(folder / (tool + ".lock"), "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            if not lock.read(1): lock.write(b"0"); lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock
    except OSError:
        lock.close()
        raise ValueError("This scanner is already reserved by another profiler run or interactive session. Close that session first.") from None


def project_busy(tool, require_ready=False):
    docker = shutil.which("docker")
    if not docker:
        if require_ready: raise ValueError("Docker is not installed.")
        return
    result = subprocess.run([docker, "compose", "ps", "--status", "running", "-q"], cwd=WORKSPACE / TOOLS[tool][0], capture_output=True, text=True, timeout=15)
    if result.returncode == 0 and result.stdout.strip():
        raise ValueError("This scanner's Docker project is already active. Finish that run before opening this session.")
    if require_ready and result.returncode:
        raise ValueError("Docker is not ready.")


def context(path):
    path = Path(path).resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    store = Store(data["root"])
    store.db_path(data["case_id"])
    if data["tool"] not in MENUS or not data["id"].isalnum(): raise ValueError("Invalid scanner session.")
    expected = store.case_dir(data["case_id"]) / "sessions" / data["id"] / "session.json"
    if path != expected.resolve(): raise ValueError("Session file is outside its case.")
    return store, data, path.parent


def set_job(store, case_id, job_id, state, message="", code=None, plan=None):
    with database(store.db_path(case_id)) as con:
        con.execute("UPDATE jobs SET state=?,message=?,exit_code=?,ended=? WHERE id=?", (state, message, code, None if state in ("running", "launching") else now(), job_id))
        if plan is not None: con.execute("UPDATE jobs SET plan=? WHERE id=?", (json_text(plan), job_id))


def launch_session(store, case_id, tool, mode="auto", allow_foreground=True):
    store.db_path(case_id)
    if tool not in MENUS or mode not in ("auto", "split", "tab", "foreground"):
        raise ValueError("Choose a supported scanner and terminal mode.")
    if mode == "foreground" and (not allow_foreground or not sys.stdin.isatty()):
        raise ValueError("Foreground scanner menus need an interactive terminal.")
    require_authorization(store, case_id, "open_scanner")
    # Fast refusal before creating a pane. The child acquires the same lock for
    # the entire session; that acquisition resolves concurrent launch races.
    check = tool_lock(tool, store.root); check.close()
    session_id = uid()
    folder = store.case_dir(case_id) / "sessions" / session_id
    folder.mkdir(parents=True)
    (folder / "staging").mkdir()
    data = {"id": session_id, "case_id": case_id, "root": str(store.root), "tool": tool,
            "mode": "interactive_session", "created": now(), "formic_run_id": os.environ.get("FORMIC_RUN_ID", "")}
    path = folder / "session.json"
    save(path, data)
    with database(store.db_path(case_id)) as con:
        con.execute("INSERT INTO jobs(id,tool,target,state,plan,path,started) VALUES(?,?,?,?,?,?,?)", (session_id, tool, "Interactive scanner session", "launching", json_text(data), store.run_reference(case_id, folder), now()))
    command = [powershell(), "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(APP / "open-scanner.ps1"), "-SessionFile", str(path)]
    env = child_environment()
    routes = []
    wt = terminal_executable() if os.name == "nt" else None
    if mode != "foreground" and wt:
        if mode in ("auto", "split") and os.environ.get("WT_SESSION"):
            routes.append(("split", [wt, "-w", os.environ.get("WT_WINDOW_ID", "0"), "sp", "-d", str(APP), *command]))
        routes.append(("tab", [wt, "-w", "0", "nt", "-d", str(APP), *command]))
    failures = []
    try:
        for route, argv in routes:
            try:
                result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=12)
                if result.returncode:
                    failures.append(route + " could not open")
                    continue
            except subprocess.TimeoutExpired:
                # Launch acceptance is uncertain: never create a duplicate worker.
                route = route + " (startup pending)"
            except OSError:
                failures.append(route + " is unavailable")
                continue
            break
        else:
            if allow_foreground and sys.stdin.isatty():
                route = "foreground"
                result = subprocess.run(command, cwd=APP, env=env)
                if result.returncode:
                    raise ValueError(f"Scanner menu exited with code {result.returncode}; see the terminal output and case session record.")
                return {"session_id": session_id, "mode": route, "exit_code": result.returncode, "case_id": case_id}
            if os.name != "nt": raise ValueError("Open this scanner from an interactive terminal.")
            route = "window"
            subprocess.Popen(command, cwd=APP, env=env, creationflags=subprocess.CREATE_NEW_CONSOLE)
        status = folder / "status.json"
        for _ in range(60):
            if status.exists():
                state = json.loads(status.read_text(encoding="utf-8"))
                if state["state"] == "failed": raise ValueError(state["message"])
                return {"session_id": session_id, "mode": route, "case_id": case_id, "state": state["state"], "fallbacks": failures}
            time.sleep(.1)
        return {"session_id": session_id, "mode": route, "case_id": case_id, "state": "launching", "message": "Waiting for the terminal worker. Check the opened terminal; do not relaunch while it is pending."}
    except Exception as exc:
        set_job(store, case_id, session_id, "failed", str(exc))
        raise


def session_worker(session_file):
    store, data, folder = context(session_file)
    lock = None
    code = 1
    status = folder / "status.json"
    try:
        lock = tool_lock(data["tool"], store.root)
        # Refuse before any menu maintenance could stop an unrelated run.
        project_busy(data["tool"])
        data["supervisor_pid"] = os.getpid()
        save(folder / "session.json", data)
        set_job(store, data["case_id"], data["id"], "running", "Use the scanner terminal; reports import after each run.", plan=data)
        save(status, {"state": "running", "pid": os.getpid()})
        env = child_environment()
        env["OSINT_CASE_SESSION"] = str(folder / "session.json")
        env["OSINT_CASE_ID"] = data["case_id"]
        env["OSINT_CASE_RUNS"] = str(store.case_dir(data["case_id"]) / "runs")
        env[TOOLS[data["tool"]][2]] = str(folder / "staging")
        print(clean(f"OSINT case: {data['case_id']} | scanner: {data['tool']}\nEach completed run is saved and imported automatically. This session stays attached to this case."), flush=True)
        menu = WORKSPACE / TOOLS[data["tool"]][0] / MENUS[data["tool"]]
        process = subprocess.Popen([powershell(), "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(menu)], cwd=menu.parent, env=env)
        while True:
            try:
                code = process.wait()
                break
            except KeyboardInterrupt:
                # Ctrl-C also reaches the child. Let its per-run finalizer import
                # partial files; a surviving menu remains in charge of this pane.
                print("\nInterrupt sent to scanner. Exit its menu to close the session.", flush=True)
        state = "closed" if code == 0 else "failed"
        set_job(store, data["case_id"], data["id"], state, "Scanner menu closed; see individual run outcomes.", code)
        save(status, {"state": state, "exit_code": code})
        return code
    except Exception as exc:
        set_job(store, data["case_id"], data["id"], "failed", str(exc), 1)
        save(status, {"state": "failed", "message": str(exc)})
        print("Scanner session: " + clean(str(exc)), file=sys.stderr)
        return 1
    finally:
        if lock: lock.close()


def run_request(request_file):
    request_path = Path(request_file).resolve()
    request = json.loads(request_path.read_text(encoding="utf-8-sig"))
    store, session, session_dir = context(request["session_file"])
    if request_path.parent != (session_dir / "requests").resolve(): raise ValueError("Invalid request location.")
    if not process_alive(session.get("supervisor_pid")): raise ValueError("The scanner session is no longer running.")
    arguments = request["arguments"]
    if not isinstance(arguments, list) or not all(isinstance(a, str) and "\x00" not in a for a in arguments): raise ValueError("Invalid scanner argument list.")
    # Each request is single-use, even if a callback is accidentally repeated.
    with request_path.with_suffix(".claimed").open("x") as claimed: claimed.write(now())
    tool, cid, job_id = session["tool"], session["case_id"], uid()
    attestation = require_authorization(store, cid, "run_request")
    project_busy(tool, require_ready=True)
    folder = store.case_dir(cid) / "runs" / job_id
    output = folder / "output"
    output.mkdir(parents=True)
    # The scanner's bulk picker stages its input before review. Preserve that
    # exact input inside this run's mount without importing it as scan findings.
    bulk_inputs = set()
    if tool == "scanner":
        for flag in ("-uf", "-ef"):
            if flag in arguments:
                value = arguments[arguments.index(flag)+1]
                if not value.startswith("/output/"): raise ValueError("Bulk input must be inside the scanner staging folder.")
                relative = Path(value.removeprefix("/output/"))
                source = (session_dir / "staging" / relative).resolve()
                destination = (output / relative).resolve()
                if not source.is_relative_to((session_dir / "staging").resolve()) or not destination.is_relative_to(output.resolve()): raise ValueError("Bulk input escapes its folder.")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                bulk_inputs.add(destination)
    plan = {"case_id": cid, "tool": tool, "target": request.get("target", ""), "arguments": arguments,
            "mode": "native_run", "session_id": session["id"], "supervisor_pid": os.getpid(), "output": store.run_reference(cid, output), "formic_run_id": session.get("formic_run_id", "")}
    save(folder / "plan.json", plan)
    save(request_path.with_suffix(".result.json"), {"job_id": job_id, "output": str(output)})
    started = now()
    with database(store.db_path(cid)) as con:
        con.execute("INSERT INTO jobs(id,tool,target,state,plan,path,started) VALUES(?,?,?,?,?,?,?)", (job_id, tool, plan["target"], "running", json_text(plan), store.run_reference(cid, folder), started))
    code, issues, imports = 1, [], []
    try:
        env = child_environment(); env[TOOLS[tool][2]] = str(output)
        env["OSINT_CASE_ID"] = cid; env["OSINT_ROOT"] = str(store.root)
        process = subprocess.Popen([powershell(), "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(APP / "run-native-scan.ps1"), "-PlanFile", str(folder / "plan.json")], cwd=APP, env=env)
        try:
            code = process.wait()
        except KeyboardInterrupt:
            code = 130
            try: process.wait(timeout=10)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                from .scans import Scanner
                Scanner(store)._terminate(process)
                process.wait(timeout=10)
            cleanup = subprocess.run(["docker", "compose", "down", "--remove-orphans"], cwd=WORKSPACE / TOOLS[tool][0], capture_output=True, timeout=45)
            if cleanup.returncode: issues.append("Docker cleanup needs attention.")
    except Exception as exc:
        issues.append(str(exc))
    finally:
        for report in output.rglob("*"):
            if report.is_file() and report.resolve() not in bulk_inputs and report.suffix.lower() in (".json", ".csv", ".md", ".html"):
                try: imports.append(store.import_path(report, cid))
                except (ValueError, OSError, __import__("sqlite3").Error) as exc: issues.append(str(exc))
        if not imports: issues.append("No importable report produced.")
        try:
            run_plan = {**plan, "kind": envelope.infer_kind(tool, arguments)}
            authorization = {"status": "valid", "attestation_id": attestation["id"]}
            envelope.write_result(folder, envelope.build_envelope(run_plan, job_id, started, now(), code, " ".join(issues), authorization, folder))
        except Exception as exc:
            issues.append(f"Result envelope issue: {exc}")
        state = "cancelled" if code == 130 else "failed" if code else "partial" if issues else "complete"
        message = f"Imported {len(imports)} report(s). " + " ".join(issues)
        save(folder / "receipt.json", {"job_id": job_id, "session_id": session["id"], "exit_code": code, "state": state, "imports": imports, "issues": issues, "ended": now()})
        set_job(store, cid, job_id, state, message, code)
        with database(store.db_path(cid)) as con: store.event(con, "scan_finished", job_id, after={"state": state, "message": message})
        print(clean(f"\nCase {cid}: {state}. {message}\nSaved in {folder}"), flush=True)
    return code if code else (1 if issues else 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["session", "run"])
    parser.add_argument("path")
    args = parser.parse_args()
    try: return session_worker(args.path) if args.operation == "session" else run_request(args.path)
    except AuthorizationRequired as exc:
        print("Error: " + clean(str(exc)), file=sys.stderr); return 77
    except (ValueError, OSError, KeyError) as exc:
        print("Error: " + clean(str(exc)), file=sys.stderr); return 1


if __name__ == "__main__": sys.exit(main())
