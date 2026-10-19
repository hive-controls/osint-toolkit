from __future__ import annotations
import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

def toolkit_root():
    configured = os.environ.get("OSINT_TOOLKIT_ROOT")
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[2]

def app_dir():
    if os.environ.get("OSINT_TOOLKIT_ROOT"):
        return toolkit_root() / "OSINT Profiler"
    return Path(__file__).resolve().parents[1]

APP = app_dir()
WORKSPACE = toolkit_root()
MAX_FILE = 32 * 1024 * 1024
LEGACY_LANES = ("maigret", "maigret_saved_reports", "phone", "scanner", "torbot")

def _home_directory():
    configured = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    return Path(configured) if configured else Path.home()

def default_data_root(os_name=None):
    """Platform default data root: %LOCALAPPDATA%\\OsintToolkit\\data on Windows, XDG data home elsewhere."""
    if (os_name or os.name) == "nt":
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else _home_directory() / "AppData" / "Local"
        return (base / "OsintToolkit" / "data").resolve()
    data_home = os.environ.get("XDG_DATA_HOME")
    base = Path(data_home) if data_home else _home_directory() / ".local" / "share"
    return (base / "osint-toolkit").resolve()

def data_root(explicit=None, os_name=None):
    """The one data-root resolution: explicit (--root) > OSINT_ROOT > platform default."""
    if explicit:
        return Path(explicit).expanduser().resolve()
    configured = os.environ.get("OSINT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return default_data_root(os_name)

def legacy_cases_dir():
    return toolkit_root() / "OSINT" / "cases"

def has_cases(folder):
    """True when the cases folder holds at least one case; `_`-prefixed entries (the shipped template) are not cases."""
    try:
        return folder.is_dir() and any(not entry.name.startswith("_") for entry in folder.iterdir())
    except OSError:
        return False

def legacy_data_found(root):
    """True when the legacy in-repo OSINT/cases has entries but the resolved root's cases folder has none."""
    legacy = legacy_cases_dir()
    if Path(root).resolve() == legacy.parent.resolve():
        return False
    return has_cases(legacy) and not has_cases(Path(root) / "cases")

def legacy_data_warning(root):
    if not legacy_data_found(root):
        return None
    return (f"Legacy case data found under {legacy_cases_dir().parent}; the data root is now {Path(root).resolve()}. "
            "Run `osint-case migrate-root --from <old> --to <new>` (copies, never moves) or set OSINT_ROOT to keep using the old location.")

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def uid():
    return uuid.uuid4().hex[:16]

def slug(value):
    value = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", value):
        raise ValueError("Case ID: 1–63 letters, numbers, hyphens or underscores; start with a letter or number.")
    return value

def required(value, name, limit=10000):
    value = str(value or "").strip()
    if not value or len(value) > limit:
        raise ValueError(f"{name} is required (maximum {limit} characters).")
    return value

def digest(data):
    return hashlib.sha256(data).hexdigest()

def json_text(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)

def url_key(value):
    try:
        p = urlsplit(str(value).strip())
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            return ""
        # Preserve path case and query semantics; only normalize scheme/host.
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))
    except ValueError:
        return ""

def clean(value):
    """Strip terminal control sequences from untrusted display text."""
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", str(value))

@contextmanager
def database(path):
    con = sqlite3.connect(path, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()

def rows(con, sql, args=()):
    return [dict(row) for row in con.execute(sql, args)]

def emit(event, artifact=""):
    path = os.environ.get("FORMIC_STATUS_FILE")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as stream:
                stream.write(json_text({"event": event, "artifact": str(artifact)}) + "\n")
        except OSError:
            pass  # Standalone case operations must not depend on platform telemetry.

def process_alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            # Access denied is not evidence the process exited.
            return ctypes.get_last_error() == 5
        try:
            code = wintypes.DWORD()
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except ProcessLookupError:
        return False
