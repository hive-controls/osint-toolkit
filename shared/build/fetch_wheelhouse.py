"""Fetch and verify the hash-pinned wheelhouse each tool image is built from (stdlib only).

The wheelhouse (`<tool>/artifacts/wheelhouse/`) is gitignored. This script downloads it inside a
throwaway container of the Dockerfile's own pinned base image (so wheel tags match), then verifies
it on the host, independently of pip, against the tool's `requirements.lock`.

Exit codes: 0 ok, 1 verify failure, 2 usage, 3 Docker unavailable.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import sys
from dataclasses import dataclass
from pathlib import Path

EXIT_OK, EXIT_VERIFY_FAILED, EXIT_USAGE, EXIT_NO_DOCKER = 0, 1, 2, 3
MANIFEST_NAME = "wheelhouse.manifest.txt"
SDIST_LOCK_NAME = "requirements-sdist.lock"
BUILD_LOCK_NAME = "requirements-build.lock"
SOURCE_DATE_EPOCH = "315532800"
SDIST_BUILD_SCRIPT = (
    "set -e; "
    "pip download -q --disable-pip-version-check --no-deps --require-hashes --no-binary=:all: "
    "-r /in/requirements-sdist.lock -d /tmp/sdist && "
    "pip install -q --disable-pip-version-check --user --no-warn-script-location "
    "--require-hashes --only-binary=:all: -r /in/requirements-build.lock && "
    "pip wheel -q --disable-pip-version-check --no-deps --no-build-isolation --no-index "
    "/tmp/sdist/* -w /out"
)
FROM_PATTERN = re.compile(
    r"^FROM\s+(python:(\d+\.\d+)-slim-bookworm@sha256:[0-9a-f]{64})(?:\s+AS\s+(\S+))?\s*$",
    re.IGNORECASE,
)
PIN_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+?)\s*\\?$")
HASH_PATTERN = re.compile(r"--hash=sha256:([0-9a-f]{64})")


@dataclass(frozen=True)
class BaseImage:
    python_version: str
    reference: str


@dataclass(frozen=True)
class Pin:
    name: str
    version: str
    hashes: frozenset


@dataclass(frozen=True)
class ManifestRow:
    name: str
    version: str
    sha256: str
    filename: str


@dataclass
class VerifyResult:
    rows: list
    problems: list


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_from_line(dockerfile_text: str) -> BaseImage:
    """Digest-pinned python base of the `builder` stage (else the first FROM)."""
    candidates = []
    for line in dockerfile_text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            match = FROM_PATTERN.match(stripped)
            if match is None:
                raise ValueError(f"FROM is not a digest-pinned python slim-bookworm image: {stripped}")
            candidates.append(match)
    if not candidates:
        raise ValueError("no FROM line found")
    chosen = next((m for m in candidates if (m.group(3) or "").lower() == "builder"), candidates[0])
    return BaseImage(python_version=chosen.group(2), reference=chosen.group(1))


def parse_lock(lock_text: str) -> list:
    """Parse `name==version \\ --hash=sha256:...` entries into Pin records."""
    pins, current = [], None
    for raw_line in lock_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pin_match = PIN_PATTERN.match(line)
        if pin_match and "--hash=" not in line:
            current = [normalize_name(pin_match.group(1)), pin_match.group(2), set()]
            pins.append(current)
        if current is not None:
            current[2].update(HASH_PATTERN.findall(line))
    return [Pin(name, version, frozenset(hashes)) for name, version, hashes in pins]


def lock_without(lock_text: str, excluded_names: set) -> str:
    """Drop whole pin entries (pin line + its hash lines) whose normalized name is excluded."""
    kept, skipping = [], False
    for raw_line in lock_text.splitlines():
        pin_match = PIN_PATTERN.match(raw_line.strip())
        if pin_match and "--hash=" not in raw_line:
            skipping = normalize_name(pin_match.group(1)) in excluded_names
        if not skipping:
            kept.append(raw_line)
    return "\n".join(kept) + "\n"


def read_sdist_pins(tool_dir: Path) -> list:
    sdist_lock = Path(tool_dir) / "artifacts" / SDIST_LOCK_NAME
    if not sdist_lock.is_file():
        return []
    return parse_lock(sdist_lock.read_text(encoding="utf-8"))


def wheel_identity(filename: str) -> tuple:
    parts = filename[: -len(".whl")].split("-")
    return normalize_name(parts[0]), parts[1].lower()


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_wheels(wheelhouse: Path) -> tuple:
    """Return ({(name, version): [Path]}, [non-wheel or unparseable entries])."""
    by_identity, stray = {}, []
    entries = sorted(wheelhouse.iterdir()) if wheelhouse.is_dir() else []
    for entry in entries:
        if entry.is_file() and entry.name.endswith(".whl") and entry.name.count("-") >= 4:
            by_identity.setdefault(wheel_identity(entry.name), []).append(entry)
        else:
            stray.append(entry.name)
    return by_identity, stray


def check_pin(pin: Pin, candidates: list) -> tuple:
    """Return (row or None, problem or None) for one pin."""
    label = f"{pin.name}=={pin.version}"
    if not candidates:
        return None, f"MISSING: {label} has no wheel"
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        return None, f"DUPLICATE: {label} matched by several wheels: {names}"
    wheel = candidates[0]
    actual = sha256_of(wheel)
    if actual not in pin.hashes:
        return None, f"SHA MISMATCH: {wheel.name} sha256 {actual} not in lock for {label}"
    return ManifestRow(pin.name, pin.version, actual, wheel.name), None


def verify_wheelhouse(lock_path: Path, wheelhouse: Path) -> VerifyResult:
    pins = parse_lock(lock_path.read_text(encoding="utf-8"))
    by_identity, stray = collect_wheels(wheelhouse)
    rows, problems = [], []
    for pin in pins:
        row, problem = check_pin(pin, by_identity.get((pin.name, pin.version.lower()), []))
        if row:
            rows.append(row)
        if problem:
            problems.append(problem)
    pinned = {(pin.name, pin.version.lower()) for pin in pins}
    for identity, paths in sorted(by_identity.items()):
        if identity not in pinned:
            problems.extend(f"EXTRA: {path.name} is not pinned in the lock" for path in paths)
    problems.extend(f"EXTRA: {name} is not a wheel (would be COPY'd into the image)" for name in stray)
    rows.sort(key=lambda row: (row.name, row.version))
    return VerifyResult(rows=rows, problems=problems)


def verify_duplicate_lock(tool_dir: Path) -> list:
    root_lock, copy_lock = tool_dir / "requirements.lock", tool_dir / "artifacts" / "requirements.lock"
    if copy_lock.is_file() and copy_lock.read_bytes() != root_lock.read_bytes():
        return [f"DUPLICATE LOCK: {copy_lock} differs from {root_lock}"]
    return []


def build_docker_command(
    tool_dir: Path, image: str, user_flag: str | None, lock_path: Path | None = None
) -> list:
    """argv list for the download container; lock is mounted read-only, never put on argv."""
    tool_dir = Path(tool_dir).resolve()
    wheelhouse = tool_dir / "artifacts" / "wheelhouse"
    command = ["docker", "run", "--rm"]
    if user_flag:
        command += ["--user", user_flag]
    command += [
        "-v", f"{lock_path or tool_dir / 'requirements.lock'}:/in/requirements.lock:ro",
        "-v", f"{wheelhouse}:/out",
        image,
        "pip", "download", "-q", "--disable-pip-version-check",
        "--no-deps", "--require-hashes", "--only-binary=:all:",
        "-r", "/in/requirements.lock", "-d", "/out",
    ]
    return command


def build_sdist_command(tool_dir: Path, out_dir: Path, image: str, user_flag: str | None) -> list:
    """Container that builds sdist-only pins into wheels deterministically (fixed epoch + hashseed)."""
    artifacts = Path(tool_dir).resolve() / "artifacts"
    command = ["docker", "run", "--rm"]
    if user_flag:
        command += ["--user", user_flag]
    command += [
        "-e", f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}", "-e", "PYTHONHASHSEED=0", "-e", "HOME=/tmp",
        "-v", f"{artifacts / SDIST_LOCK_NAME}:/in/requirements-sdist.lock:ro",
        "-v", f"{artifacts / BUILD_LOCK_NAME}:/in/requirements-build.lock:ro",
        "-v", f"{Path(out_dir).resolve()}:/out",
        image, "sh", "-c", SDIST_BUILD_SCRIPT,
    ]
    return command


def check_reproducible(build_once) -> tuple:
    """Run a builder twice; it returns {wheel filename: sha256}. Returns (identical, [run1, run2])."""
    runs = [build_once(), build_once()]
    return runs[0] == runs[1] and bool(runs[0]), runs


def format_command(command: list) -> str:
    return " ".join(shlex.quote(part) for part in command)


def docker_available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def posix_user_flag() -> str | None:
    if os.name == "posix":
        return f"{os.getuid()}:{os.getgid()}"
    return None


def discover_tools(repo_root: Path) -> list:
    return sorted(
        child for child in repo_root.iterdir()
        if (child / "Dockerfile").is_file() and (child / "requirements.lock").is_file()
    )


def verify_tool(tool_dir: Path) -> VerifyResult:
    result = verify_wheelhouse(tool_dir / "requirements.lock", tool_dir / "artifacts" / "wheelhouse")
    result.problems.extend(verify_duplicate_lock(tool_dir))
    return result


class DockerUnavailable(RuntimeError):
    pass


def run_logged(tool_dir: Path, command: list) -> int:
    print(f"[{tool_dir.name}] {format_command(command)}")
    return subprocess.run(command).returncode


def build_sdist_wheels(tool_dir: Path, image: str) -> bool:
    """Build sdist-only pins twice in fresh containers; install into the wheelhouse only if identical."""
    out_dirs = []
    with tempfile.TemporaryDirectory() as scratch:
        def build_once() -> dict:
            out_dir = Path(tempfile.mkdtemp(dir=scratch))
            out_dirs.append(out_dir)
            command = build_sdist_command(tool_dir, out_dir, image, posix_user_flag())
            if run_logged(tool_dir, command) != 0:
                return {}
            return {w.name: sha256_of(w) for w in sorted(out_dir.glob("*.whl"))}

        identical, runs = check_reproducible(build_once)
        for index, run in enumerate(runs, 1):
            print(f"[{tool_dir.name}] sdist build run {index}: {run}")
        if not identical:
            print(f"[{tool_dir.name}] FAIL: sdist build is not reproducible (or failed)", file=sys.stderr)
            return False
        for wheel in out_dirs[0].glob("*.whl"):
            shutil.copy2(wheel, tool_dir / "artifacts" / "wheelhouse" / wheel.name)
    return True


def download_wheelhouse(tool_dir: Path) -> int:
    if not docker_available():
        raise DockerUnavailable("Docker is not available (docker info failed); start Docker Desktop")
    base = parse_from_line((tool_dir / "Dockerfile").read_text(encoding="utf-8"))
    (tool_dir / "artifacts" / "wheelhouse").mkdir(parents=True, exist_ok=True)
    sdist_names = {pin.name for pin in read_sdist_pins(tool_dir)}
    lock_text = (tool_dir / "requirements.lock").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as scratch:
        filtered_lock = Path(scratch) / "requirements.lock"
        filtered_lock.write_text(lock_without(lock_text, sdist_names), encoding="utf-8", newline="\n")
        command = build_docker_command(tool_dir, base.reference, posix_user_flag(), filtered_lock)
        if run_logged(tool_dir, command) != 0:
            return 1
    if sdist_names and not build_sdist_wheels(tool_dir, base.reference):
        return 1
    return 0


def write_manifest(tool_dir: Path, rows: list) -> None:
    lines = [f"{r.name} {r.version} {r.sha256} {r.filename}" for r in rows]
    manifest = tool_dir / "artifacts" / MANIFEST_NAME
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def process_tool(tool_dir: Path, verify_only: bool, force: bool) -> bool:
    result = verify_tool(tool_dir)
    if not verify_only and (force or result.problems):
        if download_wheelhouse(tool_dir) != 0:
            print(f"[{tool_dir.name}] FAIL: pip download in container failed", file=sys.stderr)
            return False
        result = verify_tool(tool_dir)
    for row in result.rows:
        print(f"{row.name} {row.version} {row.sha256} {row.filename}")
    for problem in result.problems:
        print(f"[{tool_dir.name}] {problem}", file=sys.stderr)
    if result.problems:
        return False
    write_manifest(tool_dir, result.rows)
    print(f"[{tool_dir.name}] OK: {len(result.rows)} wheels verified")
    return True


def resolve_tools(args, repo_root: Path) -> list:
    if args.all:
        return discover_tools(repo_root)
    tool_dir = Path(args.tool)
    tool_dir = tool_dir if tool_dir.is_absolute() else repo_root / tool_dir
    if not (tool_dir / "requirements.lock").is_file() or not (tool_dir / "Dockerfile").is_file():
        return []
    return [tool_dir.resolve()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--tool", help="tool directory (relative to repo root, or absolute)")
    target.add_argument("--all", action="store_true", help="every tool with a Dockerfile + lock")
    parser.add_argument("--verify-only", action="store_true", help="never touch Docker or the network")
    parser.add_argument("--force", action="store_true", help="re-download even if verify passes")
    parser.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[2]))
    return parser


def main(argv: list | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exit_request:
        return EXIT_USAGE if exit_request.code else EXIT_OK
    repo_root = Path(args.repo_root).resolve()
    tools = resolve_tools(args, repo_root)
    if not tools:
        print("no matching tool directory (needs Dockerfile + requirements.lock)", file=sys.stderr)
        return EXIT_USAGE
    try:
        outcomes = [process_tool(tool, args.verify_only, args.force) for tool in tools]
    except DockerUnavailable as error:
        print(str(error), file=sys.stderr)
        return EXIT_NO_DOCKER
    return EXIT_OK if all(outcomes) else EXIT_VERIFY_FAILED


if __name__ == "__main__":
    sys.exit(main())
