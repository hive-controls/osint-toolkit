"""Generate <tool>/THIRD-PARTY-NOTICES.md from each tool's hash-pinned lock and wheelhouse.

For every pin in <tool>/requirements.lock the matching wheel in <tool>/artifacts/wheelhouse is
located and its SHA-256 compared with the lock. The generator REFUSES (exit 2) when a wheel is
missing, extra, or does not match the lock. License resolution order per package:

    license-overrides.json entry  >  License-Expression  >  License field (not UNKNOWN, <100 chars)
    >  trove classifier  >  first line of a bundled license file

A package that resolves through none of these, or whose override is still ``"status": "pending"``,
makes the run exit 3: an unknown license is never printed as UNKNOWN. Bundled license/NOTICE files
under ``*.dist-info`` are reproduced verbatim (CRLF normalised to LF).

Standard library only. Usage (from the repo root):

    python -I shared/build/gen_third_party_notices.py [--root DIR] [--tool NAME ...] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass, field
from email.parser import Parser
from pathlib import Path

GENERATOR_VERSION = "1"
EXIT_REFUSED = 2
EXIT_UNKNOWN_LICENSE = 3
EXIT_DRIFT = 4

OVERRIDES_FILE = Path("shared/build/license-overrides.json")
LICENSE_TEXTS_DIR = Path("shared/build/license-texts")

TOOL_TRIMMED: dict[str, list[str]] = {
    "Maigret Docker": [],
    "Phone Lookup": ["setuptools"],
    "TorBot Docker": [
        "iniconfig",
        "packaging",
        "pluggy",
        "pygments",
        "pyinstaller",
        "pyinstaller-hooks-contrib",
        "pytest",
        "setuptools",
    ],
    "User-Scanner Docker": [],
}

LICENSE_FILE_NAME = re.compile(r"^(licen[cs]e|copying|notice)", re.IGNORECASE)
LOCK_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+?)\s*\\?\s*$")
LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
MAX_LICENSE_FIELD_LENGTH = 100


class RefusedError(Exception):
    """The lock and the wheelhouse disagree; nothing may be generated."""


class UnknownLicenseError(Exception):
    """One or more packages have no resolvable license and no usable override."""


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class LockPin:
    name: str
    version: str
    hashes: tuple[str, ...]


@dataclass
class WheelInfo:
    path: Path
    sha256: str
    name: str
    version: str
    metadata: dict[str, list[str]]
    license_files: list[tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class Resolution:
    license_id: str
    source: str
    override_texts: tuple[tuple[str, str], ...] = ()
    override_note: str | None = None


def parse_lock(text: str) -> list[LockPin]:
    pins: list[LockPin] = []
    current: list | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pin_match = LOCK_PIN.match(line)
        if pin_match:
            current = [pin_match.group(1), pin_match.group(2), []]
            pins.append(current)  # type: ignore[arg-type]
        hash_match = LOCK_HASH.search(line)
        if hash_match and current is not None:
            current[2].append(hash_match.group(1))
    return [LockPin(canonical_name(p[0]), p[1], tuple(p[2])) for p in pins]


def decode_text(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def is_license_member(member: str) -> bool:
    if member.endswith("/"):
        return False
    parts = member.split("/")
    if not parts[0].endswith(".dist-info"):
        return False
    if len(parts) > 2 and parts[1] == "licenses":
        return True
    return len(parts) == 2 and bool(LICENSE_FILE_NAME.match(parts[1]))


def read_wheel(path: Path) -> WheelInfo:
    raw = path.read_bytes()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_member = next(
            n for n in names if n.endswith(".dist-info/METADATA") and n.count("/") == 1
        )
        message = Parser().parsestr(archive.read(metadata_member).decode("utf-8", "replace"))
        metadata = {key: message.get_all(key) or [] for key in set(message.keys())}
        files = sorted(
            (member, decode_text(archive.read(member)))
            for member in names
            if is_license_member(member)
        )
    return WheelInfo(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        name=canonical_name((metadata.get("Name") or [""])[0]),
        version=(metadata.get("Version") or [""])[0],
        metadata=metadata,
        license_files=files,
    )


def verify_wheelhouse(pins: list[LockPin], wheels: list[WheelInfo]) -> dict[str, WheelInfo]:
    by_key = {(w.name, w.version): w for w in wheels}
    pin_keys = {(p.name, p.version) for p in pins}
    problems: list[str] = []
    matched: dict[str, WheelInfo] = {}
    for pin in pins:
        wheel = by_key.get((pin.name, pin.version))
        if wheel is None:
            problems.append(f"missing wheel for {pin.name}=={pin.version}")
        elif wheel.sha256 not in pin.hashes:
            problems.append(f"sha256 mismatch for {pin.name}=={pin.version} ({wheel.path.name})")
        else:
            matched[pin.name] = wheel
    for wheel in wheels:
        if (wheel.name, wheel.version) not in pin_keys:
            problems.append(f"extra wheel not in lock: {wheel.path.name}")
    if problems:
        raise RefusedError("; ".join(sorted(problems)))
    return matched


def load_overrides(root: Path) -> dict[str, dict]:
    path = root / OVERRIDES_FILE
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        f"{canonical_name(key.split('==')[0])}=={key.split('==')[1]}": value
        for key, value in data.get("overrides", {}).items()
    }


def classifier_license(metadata: dict[str, list[str]]) -> str | None:
    found = sorted(
        {
            c.split("::")[-1].strip()
            for c in metadata.get("Classifier", [])
            if c.startswith("License ::") and not c.endswith("OSI Approved")
        }
    )
    return " / ".join(found) if found else None


def metadata_license(info: WheelInfo) -> tuple[str, str] | None:
    expression = (info.metadata.get("License-Expression") or [""])[0].strip()
    if expression:
        return expression, "License-Expression"
    field_value = " ".join((info.metadata.get("License") or [""])[0].split())
    if field_value and field_value.upper() != "UNKNOWN" and len(field_value) < MAX_LICENSE_FIELD_LENGTH:
        return field_value, "License field"
    classifier = classifier_license(info.metadata)
    if classifier:
        return classifier, "trove classifier"
    for _member, text in info.license_files:
        first_line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        if first_line:
            return first_line[:MAX_LICENSE_FIELD_LENGTH], "license file first line"
    return None


def override_resolution(entry: dict, root: Path, key: str) -> Resolution:
    if entry.get("status") == "pending":
        raise UnknownLicenseError(f"{key}: override is pending (license text not yet fetched)")
    override_texts: list[tuple[str, str]] = []
    for text_entry in entry.get("texts", []):
        text_file = root / LICENSE_TEXTS_DIR / text_entry["path"]
        if not text_file.is_file():
            raise UnknownLicenseError(f"{key}: override text file missing: {text_entry['path']}")
        raw = text_file.read_bytes()
        if hashlib.sha256(raw).hexdigest() != text_entry.get("sha256"):
            raise RefusedError(f"{key}: sha256 of {text_entry['path']} does not match license-overrides.json")
        title = f"{text_entry['path']} (source: {text_entry['url']}; sha256 {text_entry['sha256']})"
        override_texts.append((title, decode_text(raw)))
    return Resolution(entry["spdx"], "override", tuple(override_texts), entry.get("note"))


def resolve_license(info: WheelInfo, overrides: dict[str, dict], root: Path) -> Resolution:
    key = f"{info.name}=={info.version}"
    if key in overrides:
        return override_resolution(overrides[key], root, key)
    found = metadata_license(info)
    if found is None:
        raise UnknownLicenseError(f"{key}: no license metadata, classifier or license file; add an override")
    return Resolution(found[0], found[1])


def markdown_fence(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def render_text_block(title: str, text: str) -> list[str]:
    fence = markdown_fence(text)
    return [f"#### {title}", "", fence + "text", text.rstrip("\n"), fence, ""]


def render_package_section(info: WheelInfo, resolution: Resolution) -> list[str]:
    lines = [f"### {info.name} {info.version}", "", f"License: {resolution.license_id} (via {resolution.source})", ""]
    if resolution.override_note:
        lines += [f"Note: {resolution.override_note}", ""]
    for title, text in resolution.override_texts:
        lines += render_text_block(title, text)
    for member, text in info.license_files:
        lines += render_text_block(member.split("/", 1)[1], text)
    if not info.license_files and not resolution.override_texts:
        lines += ["No license or notice file is bundled in this wheel; the license above comes from package metadata.", ""]
    return lines


def render_notice(
    tool: str,
    lock_label: str,
    pins: list[LockPin],
    wheels: dict[str, WheelInfo],
    resolutions: dict[str, Resolution],
    trimmed: list[str],
) -> str:
    trimmed_set = {canonical_name(n) for n in trimmed}
    lines = [
        f"# Third-party notices: {tool}",
        "",
        f"- Tool: {tool}",
        f"- Lock: {lock_label}",
        f"- Pinned packages: {len(pins)}",
        f"- Generator: shared/build/gen_third_party_notices.py v{GENERATOR_VERSION}",
        "",
        "Generated file; do not edit. Regenerate with the generator named above.",
        "",
    ]
    shipped = [p for p in sorted(pins, key=lambda p: p.name) if p.name not in trimmed_set]
    removed = [p for p in sorted(pins, key=lambda p: p.name) if p.name in trimmed_set]
    lines += ["## Packages in the runtime image", "", "| Package | Version | License | Determined by |", "|---|---|---|---|"]
    for pin in shipped:
        res = resolutions[pin.name]
        lines.append(f"| {pin.name} | {pin.version} | {res.license_id.replace('|', '/')} | {res.source} |")
    lines.append("")
    if removed:
        lines += ["## Build-time only — removed from the runtime image", "", "| Package | Version | License |", "|---|---|---|"]
        for pin in removed:
            lines.append(f"| {pin.name} | {pin.version} | {resolutions[pin.name].license_id.replace('|', '/')} |")
        lines.append("")
    lines += ["## License and notice texts", ""]
    for pin in shipped:
        lines += render_package_section(wheels[pin.name], resolutions[pin.name])
    return "\n".join(lines).rstrip("\n") + "\n"


def generate_tool_notice(
    tool: str,
    lock_path: Path,
    wheelhouse: Path,
    overrides: dict[str, dict],
    root: Path,
    trimmed: list[str],
    lock_label: str | None = None,
) -> str:
    pins = parse_lock(lock_path.read_text(encoding="utf-8"))
    wheel_files = sorted(wheelhouse.glob("*.whl")) if wheelhouse.is_dir() else []
    matched = verify_wheelhouse(pins, [read_wheel(p) for p in wheel_files])
    unknown_trimmed = {canonical_name(n) for n in trimmed} - set(matched)
    if unknown_trimmed:
        raise RefusedError(f"trimmed packages not in lock: {sorted(unknown_trimmed)}")
    resolutions: dict[str, Resolution] = {}
    problems: list[str] = []
    for pin in pins:
        try:
            resolutions[pin.name] = resolve_license(matched[pin.name], overrides, root)
        except UnknownLicenseError as error:
            problems.append(str(error))
    if problems:
        raise UnknownLicenseError("; ".join(sorted(problems)))
    return render_notice(tool, lock_label or lock_path.as_posix(), pins, matched, resolutions, trimmed)


def run_tool(root: Path, tool: str, check: bool, overrides: dict[str, dict]) -> int:
    notice_path = root / tool / "THIRD-PARTY-NOTICES.md"
    content = generate_tool_notice(
        tool,
        root / tool / "requirements.lock",
        root / tool / "artifacts" / "wheelhouse",
        overrides,
        root,
        TOOL_TRIMMED.get(tool, []),
        lock_label=f"{tool}/requirements.lock",
    )
    if check:
        current = notice_path.read_text(encoding="utf-8") if notice_path.is_file() else ""
        if current != content:
            print(f"DRIFT: {notice_path} differs from generated output", file=sys.stderr)
            return EXIT_DRIFT
        return 0
    with open(notice_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    print(f"wrote {notice_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--tool", action="append", choices=sorted(TOOL_TRIMMED))
    parser.add_argument("--check", action="store_true", help="fail (exit 4) if committed notices differ")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    overrides = load_overrides(root)
    exit_code = 0
    for tool in args.tool or sorted(TOOL_TRIMMED):
        try:
            exit_code = max(exit_code, run_tool(root, tool, args.check, overrides))
        except RefusedError as error:
            print(f"REFUSED [{tool}]: {error}", file=sys.stderr)
            return EXIT_REFUSED
        except UnknownLicenseError as error:
            print(f"UNKNOWN LICENSE [{tool}]: {error}", file=sys.stderr)
            return EXIT_UNKNOWN_LICENSE
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
