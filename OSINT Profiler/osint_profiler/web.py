"""Loopback-only local editor. No arbitrary filesystem or shell endpoints."""
from __future__ import annotations
import base64
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from . import __version__
from .authorization import BANNER, REQUIRED_PHRASE, AuthorizationRequired, acknowledgement_text, record_authorization
from .scans import Scanner, plan_scan
from .util import APP, MAX_FILE, digest, json_text, slug

class Application:
    def __init__(self, store):
        self.store = store
        self.token = secrets.token_urlsafe(32)
        self.scanner = Scanner(store)
        self.plans = {}
        self.plan_lock = threading.Lock()
        names = ("create_case", "update_case", "add_entity", "add_note", "add_relation", "review_relation", "review_observation", "undo", "import_upload", "assign_import", "attach_evidence", "remove_evidence", "export", "summary", "list_cases", "list_inbox", "discover")
        self.actions = {name: getattr(store, name) for name in names}

    def action(self, name, args):
        if not isinstance(args, dict):
            raise ValueError("Action arguments must be an object.")
        if name == "preview_upload":
            data = base64.b64decode(args["data"], validate=True)
            result = self.store.preview_bytes(data, args["filename"])
            result.pop("observations", None)
            return result
        if name == "authorization_text":
            return {"banner": BANNER, "text": acknowledgement_text(), "phrase": REQUIRED_PHRASE}
        if name == "authorize":
            record = record_authorization(self.store, **args)
            return {key: record[key] for key in ("case_id", "subject_label", "expires_ts")} | {"attestation_id": record["id"]}
        if name == "open_scanner":
            from .native import launch_session
            return launch_session(self.store, args["case_id"], args["tool"], args.get("mode", "auto"), allow_foreground=False)
        if name == "plan_scan":
            plan = plan_scan(self.store, **args)
            plan_id = secrets.token_urlsafe(20)
            with self.plan_lock:
                self.plans = {key: val for key, val in self.plans.items() if time.monotonic() - val[0] < 600}
                self.plans[plan_id] = (time.monotonic(), plan)
            return {**plan, "plan_id": plan_id}
        if name == "start_scan":
            if args.get("confirm") != "RUN":
                raise ValueError("Review the plan and confirm RUN before collection.")
            with self.plan_lock:
                entry = self.plans.pop(args.get("plan_id"), None)
            if not entry or time.monotonic() - entry[0] > 600:
                raise ValueError("The scan preview expired. Review a fresh plan.")
            return self.scanner.start(entry[1], background=True)
        if name == "cancel_scan":
            return self.scanner.cancel(args["job_id"])
        if name == "job_log":
            job = next((j for j in self.store.summary(args["case_id"])["jobs"] if j["id"] == args["job_id"]), None)
            if not job:
                raise ValueError("Run not found.")
            path = self.store.case_dir(args["case_id"]) / "runs" / job["id"] / "console.log"
            if not path.exists():
                return {"text": "No console output yet."}
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - 64000))
                return {"text": stream.read(64000).decode("utf-8", errors="replace")}
        if name not in self.actions:
            raise ValueError("Unsupported operation.")
        return self.actions[name](**args)

def create_server(store, port=0):
    app = Application(store)
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass  # URL and report identifiers should not enter generic server logs.

        def host_ok(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def send(self, status, body, content_type="application/json; charset=utf-8", extra=None):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def result(self, data):
            self.send(200, json_text({"ok": True, "data": data}))

        def do_GET(self):
            if not self.host_ok():
                self.send(403, json_text({"ok": False, "error": "Invalid local host."})); return
            parsed = urlsplit(self.path)
            try:
                if parsed.path == "/api/health":
                    self.result({"app": "osint-profiler", "version": __version__, "root_id": digest(str(store.root).encode())}); return
                if parsed.path == "/api/session":
                    self.result({"token": app.token}); return
                if parsed.path == "/api/bootstrap":
                    self.result({"cases": store.list_cases(), "inbox": store.list_inbox(), "version": __version__}); return
                if parsed.path.startswith("/api/case/"):
                    self.result(store.summary(parsed.path.removeprefix("/api/case/"))); return
                if parsed.path == "/api/artifact":
                    params = parse_qs(parsed.query)
                    record, path = store.artifact(params["case"][0], params["id"][0])
                    data = path.read_bytes()
                    image_type = None
                    if data.startswith(b"\x89PNG\r\n\x1a\n"): image_type = "image/png"
                    elif data.startswith(b"\xff\xd8\xff"): image_type = "image/jpeg"
                    elif data.startswith((b"GIF87a", b"GIF89a")): image_type = "image/gif"
                    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP": image_type = "image/webp"
                    if params.get("preview") == ["1"] and image_type:
                        self.send(200, data, image_type)
                    else:
                        self.send(200, data, "application/octet-stream", {"Content-Disposition": "attachment; filename=\"evidence-" + record["id"] + ".bin\""})
                    return
                static = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/app.css": "app.css"}
                if parsed.path in static:
                    name = static[parsed.path]
                    content = (APP / "osint_profiler" / "static" / name).read_bytes()
                    mime = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8"}[Path(name).suffix]
                    self.send(200, content, mime); return
                self.send(404, json_text({"ok": False, "error": "Not found."}))
            except (ValueError, OSError, KeyError) as exc:
                self.send(400, json_text({"ok": False, "error": str(exc)}))

        def do_POST(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if not self.host_ok() or self.headers.get("Origin") not in (None, origin) or not hmac.compare_digest(self.headers.get("X-Profiler-Token", ""), app.token):
                self.close_connection = True
                self.send(403, json_text({"ok": False, "error": "Invalid session or origin."})); return
            if self.path != "/api/action" or self.headers.get_content_type() != "application/json":
                self.close_connection = True
                self.send(400, json_text({"ok": False, "error": "Use a JSON action request."})); return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= int(MAX_FILE * 1.4) + 65536:
                    self.close_connection = True
                    self.send(413, json_text({"ok": False, "error": "Request is too large."})); return
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("Request must be an object.")
                if data.get("action") == "stop_server":
                    with app.scanner.guard:
                        if app.scanner.processes:
                            raise ValueError("Finish or cancel this editor's active scans before stopping it.")
                    self.result({"stopping": True})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                self.result(app.action(data["action"], data.get("args", {})))
            except AuthorizationRequired as exc:
                self.send(400, json_text({"ok": False, **exc.payload()}))
            except (ValueError, TypeError, KeyError, OSError, __import__("sqlite3").Error) as exc:
                self.send(400, json_text({"ok": False, "error": str(exc)}))

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.app = app
    return server

def state_path(store):
    directory = store.root / ".profiler"
    directory.mkdir(exist_ok=True)
    return directory / "server.json"

def _healthy(store, state):
    try:
        port = int(state["port"])
        if not 1 <= port <= 65535:
            return False
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=1) as response:
            result = json.load(response)["data"]
        return result.get("app") == "osint-profiler" and result.get("root_id") == digest(str(store.root).encode())
    except (ValueError, KeyError, OSError):
        return False

def serve(store, port=0):
    state_file = state_path(store)
    lock = open(state_file.with_suffix(".lock"), "a+b")
    if os.name == "nt":
        import msvcrt
        if lock.tell() == 0: lock.write(b"0"); lock.flush()
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    server = create_server(store, port)
    state = {"pid": os.getpid(), "port": server.server_port, "root_id": digest(str(store.root).encode())}
    state_file.write_text(json_text(state), encoding="utf-8")
    print(json_text({"url": f"http://127.0.0.1:{server.server_port}", "pid": os.getpid()}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        lock.close()

def launch_ui(store, case_id=None, port=0, open_browser=True):
    if case_id:
        store.db_path(case_id)
    path = state_path(store)
    state = {}
    try: state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError): pass
    if not _healthy(store, state):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("FORMIC_", "HIVEDECK_"))}
        env["PYTHONUTF8"] = "1"
        with open(path.with_suffix(".log"), "a", encoding="utf-8") as log:
            command = [sys.executable, "-m", "osint_profiler", "--root", str(store.root), "serve", "--port", str(port)]
            process = subprocess.Popen(command, cwd=APP, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        for _ in range(60):
            time.sleep(0.1)
            try: state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError): continue
            if _healthy(store, state): break
            if process.poll() is not None: break
        else:
            raise ValueError(f"Local editor did not become ready; inspect {path.with_suffix('.log')}.")
        if not _healthy(store, state):
            raise ValueError(f"Local editor could not start; inspect {path.with_suffix('.log')}.")
    url = f"http://127.0.0.1:{state['port']}/" + (f"?case={slug(case_id)}" if case_id else "")
    opened = webbrowser.open(url) if open_browser else False
    return {"url": url, "browser_opened": opened, "pid": state["pid"]}

def stop_ui(store):
    try:
        state = json.loads(state_path(store).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"stopped": False, "message": "No local editor recorded."}
    if not _healthy(store, state):
        return {"stopped": False, "message": "Local editor is not running."}
    base = f"http://127.0.0.1:{state['port']}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(base + "/api/session", timeout=3) as response:
        token = json.load(response)["data"]["token"]
    request = urllib.request.Request(base + "/api/action", json_text({"action": "stop_server"}).encode(),
        {"Content-Type": "application/json", "X-Profiler-Token": token, "Origin": base})
    try:
        with opener.open(request, timeout=5) as response:
            return json.load(response)["data"]
    except urllib.error.HTTPError as exc:
        with exc:
            raise ValueError(json.load(exc).get("error", "Could not stop editor.")) from None
