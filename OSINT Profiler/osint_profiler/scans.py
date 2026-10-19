"""Reviewed, bounded collection through the existing hardened Docker runners."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from . import catalog, envelope
from .authorization import authorization_status, require_authorization
from .util import app_dir, database, json_text, now, toolkit_root, uid

GATE_REFUSAL_MESSAGES = {
    75: "Network gate refused the run (no allowlisted VPN carrying internet traffic)",
    77: "Subject authorization refused the run (record one with: osint-case authorize <case>)",
    78: "Network gate configuration error",
}
_tool_table = None
ACTIVE_JOBS = {}
ACTIVE_GUARD = threading.Lock()

def __getattr__(name):
    global _tool_table
    if name == "TOOLS":
        if _tool_table is None:
            _tool_table = catalog.scan_tools()
        return _tool_table
    raise AttributeError(name)

def reset_tool_cache():
    global _tool_table
    _tool_table = None

def tool_table():
    return __getattr__("TOOLS")

def _runnable_entry(loaded, tool):
    entry = catalog.tool(tool, loaded) if isinstance(tool, str) else None
    internal = catalog.internal_id(entry, loaded) if entry else None
    if not entry or internal not in catalog.scan_tools(loaded):
        names = list(catalog.scan_tools(loaded))
        raise ValueError("Choose " + ", ".join(names[:-1]) + ", or " + names[-1] + ".")
    return entry, internal

def plan_scan(store, case_id, tool, target, kind="username", top=500, region="", modules=""):
    store.db_path(case_id)
    loaded = catalog.load_catalog()
    entry, tool = _runnable_entry(loaded, tool)
    target = str(target).strip()
    kind = catalog.validate_request(entry, loaded["identifier_rules"], target, kind, {"top": top, "region": region, "modules": modules})
    args = catalog.build_argv(entry, {"target": target, "kind": kind}, {"top": top, "region": region, "modules": modules})
    status = authorization_status(store, case_id)
    return {"case_id": case_id, "tool": tool, "target": target, "kind": kind, "top": int(top), "region": region, "modules": modules,
            "arguments": args, "authorization": {"status": status["status"], "expires_ts": status["expires_ts"]}, "notice":"Confirm authorization and host VPN/proxy readiness. This sends the identifier to selected sites/providers. Loud scanner modules and automatic recursion are disabled. Phone providers run according to your existing configuration."}

class Scanner:
    def __init__(self, store):
        self.store = store
        self.processes = ACTIVE_JOBS
        self.guard = ACTIVE_GUARD

    def cancel(self, job_id):
        with self.guard:
            job = self.processes.get(job_id)
            if not job:
                raise ValueError("This server does not own an active job with that ID.")
            job["cancel"].set()
            process = job.get("process")
        if process and process.poll() is None:
            self._terminate(process)
        return {"job_id": job_id, "state": "cancelling"}

    def _terminate(self, process):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=15)
        else:
            import signal
            os.killpg(process.pid, signal.SIGTERM)

    def start(self, plan, background=False, job_id=None, input_origin=None):
        # Rebuild, do not trust caller-supplied argv.
        plan = plan_scan(self.store, **{k: plan[k] for k in ("case_id", "tool", "target", "kind", "top", "region", "modules")})
        if input_origin:
            plan["input_origin"] = input_origin
        attestation = require_authorization(self.store, plan["case_id"], "scan")
        tool = plan["tool"]
        tools = tool_table()
        executable = shutil.which("pwsh.exe") or shutil.which("pwsh")
        if not executable or not shutil.which("docker"):
            raise ValueError("PowerShell 7 and Docker must be installed before running a scan.")
        # Cross-process lock held by the OS; released automatically after a crash.
        lock_dir = self.store.root / ".profiler-locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock = open(lock_dir / (tool + ".lock"), "a+b")
        try:
            lock.seek(0)
            if os.name == "nt":
                import msvcrt
                if not lock.read(1):
                    lock.write(b"0"); lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            raise ValueError("Another profiler scan is using this tool. Wait for it to finish.") from None
        try:
            existing = subprocess.run(["docker", "compose", "ps", "--status", "running", "-q"], cwd=toolkit_root() / tools[tool][0], capture_output=True, text=True, timeout=15)
            if existing.returncode:
                raise ValueError("Docker is not ready. Start Docker Desktop, then review and retry this scan.")
            if existing.stdout.strip():
                raise ValueError("This tool's Docker project is already active outside this job. Finish that run first.")
        except BaseException:
            lock.close()
            raise
        job_id = job_id or uid()
        folder = self.store.case_dir(plan["case_id"]) / "runs" / job_id
        folder.mkdir(parents=True)
        output_folder = folder / "output"
        plan["output"] = self.store.run_reference(plan["case_id"], output_folder)
        plan["supervisor_pid"] = os.getpid()
        plan["formic_run_id"] = os.environ.get("FORMIC_RUN_ID", "")
        plan["configured_tool_version"] = catalog.tool(tool)["version"]
        (folder / "output").mkdir()
        (folder / "plan.json").write_text(json_text(plan), encoding="utf-8")
        started = now()
        with database(self.store.db_path(plan["case_id"])) as con:
            con.execute("INSERT INTO jobs(id,tool,target,state,plan,path,started) VALUES(?,?,?,?,?,?,?)", (job_id, tool, plan["target"], "running", json_text(plan), self.store.run_reference(plan["case_id"], folder), started))
        control = {"process": None, "cancel": threading.Event()}
        with self.guard:
            self.processes[job_id] = control
        def execute():
            code, message = 1, ""
            cleanup_done = False
            def cleanup_cancelled():
                try:
                    result = subprocess.run(["docker", "compose", "down", "--remove-orphans"], cwd=toolkit_root() / tools[tool][0], capture_output=True, timeout=45)
                    return "" if result.returncode == 0 else " Docker cleanup needs attention."
                except (OSError, subprocess.TimeoutExpired):
                    return " Docker cleanup needs attention."
            try:
                env = dict(os.environ)
                for key in list(env):
                    if key.startswith(("FORMIC_", "HIVEDECK_")):
                        del env[key]
                env[tools[tool][2]] = str(output_folder)
                env["OSINT_CASE_ID"] = plan["case_id"]
                env["OSINT_ROOT"] = str(self.store.root)
                command = [executable, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(app_dir() / "run-reviewed-scan.ps1"), "-PlanFile", str(folder / "plan.json")]
                with open(folder / "console.log", "w", encoding="utf-8") as log:
                    process = subprocess.Popen(command, cwd=app_dir(), env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0, start_new_session=os.name != "nt")
                    with self.guard:
                        control["process"] = process
                    if control["cancel"].is_set():
                        self._terminate(process)
                    try:
                        code = process.wait()
                    except KeyboardInterrupt:
                        control["cancel"].set()
                        self._terminate(process)
                        code = process.wait(timeout=20)
                if control["cancel"].is_set():
                    # Stop container writers before snapshotting partial output.
                    message += cleanup_cancelled()
                    cleanup_done = True
                imports = []
                for report in (folder / "output").rglob("*"):
                    if report.is_file() and report.suffix.lower() in (".json", ".csv", ".md", ".html"):
                        try:
                            imports.append(self.store.import_path(report, plan["case_id"]))
                        except (OSError, ValueError) as exc:
                            message += f" Import issue: {exc}"
                (folder / "receipt.json").write_text(json_text({"job_id": job_id, "exit_code": code, "ended": now(), "imports": imports}), encoding="utf-8")
            except Exception as exc:
                message = str(exc)
            finally:
                if code in GATE_REFUSAL_MESSAGES and not message:
                    message = GATE_REFUSAL_MESSAGES[code]
                if control["cancel"].is_set():
                    code = 130
                    message = "Cancelled; completed outputs were retained." + message
                    if not cleanup_done:
                        message += cleanup_cancelled()
                try:
                    authorization = {"status": "valid", "attestation_id": attestation["id"]}
                    envelope.write_result(folder, envelope.build_envelope(plan, job_id, started, now(), code, message, authorization, folder))
                except Exception as exc:
                    message += f" Result envelope issue: {exc}"
                with self.guard:
                    self.processes.pop(job_id, None)
                with database(self.store.db_path(plan["case_id"])) as con:
                    con.execute("UPDATE jobs SET state=?,ended=?,exit_code=?,message=? WHERE id=?", ("cancelled" if code == 130 else "complete" if code == 0 and not message else "partial" if code == 0 else "failed", now(), code, message, job_id))
                    self.store.event(con, "scan_finished", job_id, after={"exit_code": code, "message": message})
                lock.close()
        if background:
            threading.Thread(target=execute, daemon=False).start()
        else:
            try:
                execute()
            except KeyboardInterrupt:
                # The child wrapper handles Ctrl-C when possible; do not discard outputs.
                raise
        return {"job_id": job_id, "case_id": plan["case_id"], "folder": str(folder)}
