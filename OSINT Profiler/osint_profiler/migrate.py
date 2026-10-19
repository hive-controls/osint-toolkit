"""migrate-root: copy case data from one data root to another. Copies, verifies, rewrites the copy; never moves or deletes."""
from __future__ import annotations
import hashlib
import json
import shutil
from pathlib import Path
from .store import Store
from .util import LEGACY_LANES, database, has_cases, json_text

TOP_LEVEL = ("cases", "inbox") + LEGACY_LANES
SKIPPED_NAMES = (".profiler", ".profiler-locks")
CHUNK = 1024 * 1024


def copy_file(source, destination):
    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def file_digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _is_scaffolding(relative):
    parts = relative.parts
    return parts[0] == "cases" and len(parts) > 1 and parts[1].startswith("_")


def enumerate_files(source):
    """(relative path, size) for every regular file under the migratable folders; symlinks and scaffolding are skipped."""
    found = []
    for name in TOP_LEVEL:
        folder = Path(source) / name
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            relative = path.relative_to(source)
            if path.is_symlink() or not path.is_file() or _is_scaffolding(relative) or any(part in SKIPPED_NAMES for part in relative.parts):
                continue
            found.append((relative, path.stat().st_size))
    return found


def _check_roots(source, destination, force):
    if not source.is_dir():
        raise ValueError(f"Source data root not found: {source}")
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("Source and destination data roots must be separate folders (neither may contain the other).")
    if has_cases(destination / "cases") and not force:
        raise ValueError("Destination already has cases; migrate-root refuses to merge. Use --force to copy only files that do not exist there (nothing is ever overwritten or deleted).")


def _copy_verified(source, destination, files):
    copied, corrupt, conflicts, identical = [], [], [], 0
    for relative, _size in files:
        origin, target = source / relative, destination / relative
        if target.exists():
            if file_digest(origin) == file_digest(target):
                identical += 1
            else:
                conflicts.append(relative.as_posix())
            continue
        copy_file(origin, target)
        if file_digest(origin) != file_digest(target):
            corrupt.append(relative.as_posix())
        else:
            copied.append(relative)
    return copied, corrupt, conflicts, identical


def _rewrite_ledger(store, case_id, ledger):
    changed = 0
    with database(ledger) as con:
        for row in con.execute("SELECT id,plan,path FROM jobs").fetchall():
            plan = json.loads(row["plan"])
            new_path = store.run_reference(case_id, row["path"])
            output = plan.get("output")
            new_output = store.run_reference(case_id, output) if isinstance(output, str) else output
            if new_path != row["path"] or new_output != output:
                if isinstance(output, str):
                    plan["output"] = new_output
                con.execute("UPDATE jobs SET path=?,plan=? WHERE id=?", (new_path, json_text(plan), row["id"]))
                changed += 1
    return changed


def _rewrite_plan_file(store, case_id, plan_file):
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    output = plan.get("output")
    if not isinstance(output, str) or store.run_reference(case_id, output) == output:
        return 0
    plan["output"] = store.run_reference(case_id, output)
    plan_file.write_text(json_text(plan), encoding="utf-8")
    return 1


def _rewrite_copies(destination, copied):
    store = Store(destination)
    rewritten = {"jobs": 0, "plans": 0}
    for relative in copied:
        parts = relative.parts
        if parts[0] != "cases" or len(parts) < 3:
            continue
        case_id = parts[1]
        if parts[2:] == ("case.sqlite",):
            rewritten["jobs"] += _rewrite_ledger(store, case_id, destination / relative)
        elif len(parts) == 5 and parts[2] == "runs" and parts[4] == "plan.json":
            rewritten["plans"] += _rewrite_plan_file(store, case_id, destination / relative)
    return rewritten


def migrate_root(source, destination, dry_run=False, force=False):
    source, destination = Path(source).expanduser().resolve(), Path(destination).expanduser().resolve()
    _check_roots(source, destination, force)
    files = enumerate_files(source)
    listing = [{"path": relative.as_posix(), "bytes": size} for relative, size in files]
    summary = {"from": str(source), "to": str(destination), "dry_run": bool(dry_run), "files": listing, "bytes": sum(size for _, size in files)}
    if dry_run:
        return {**summary, "next": "Dry run only; nothing was copied."}
    copied, corrupt, conflicts, identical = _copy_verified(source, destination, files)
    rewritten = _rewrite_copies(destination, copied)
    result = {**summary, "copied": len(copied), "verified": len(copied), "already_present": identical, "corrupt": corrupt, "conflicts": conflicts,
              "rewritten": rewritten, "next": f"Original left in place at {source}; verify the copy, then delete the original yourself."}
    if corrupt or conflicts:
        result["message"] = f"{len(corrupt)} file(s) failed hash verification and {len(conflicts)} conflicted with existing files; nothing was deleted or overwritten."
    return result
