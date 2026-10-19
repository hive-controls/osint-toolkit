"""Generate the Formic manifests (.formic/toolkit.yaml, profile.yaml, tools/<id>.yaml) from shared/catalog/tools.json.

The catalog is the single source of truth: each tool's `formic` block carries what is not derivable
(title, description, config files, status, pane, exit text), everything else (name, menu launch,
health tag) is derived from the tool entry. Output is rendered by template, with no YAML library.
Private tools (the browsing lab) are not in the catalog, so they are never generated or listed.

Standard library only. Usage (from the repo root):

    python -I shared/build/generate_formic.py [--root DIR] [--check]

Exit codes: 0 written / clean, 4 drift found by --check.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath

EXIT_DRIFT = 4
CATALOG_PATH = Path("shared/catalog/tools.json")
PLAIN_UNSAFE = re.compile(r"(^[\s\-?:,\[\]{}#&*!|>'\"%@`])|(: )|( #)|(:$)|(\s$)")
LAUNCH_ARGS = ["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]


def plain(value: str) -> str:
    """A plain YAML scalar; refuses anything that would need quoting so output never silently changes meaning."""
    if not value or PLAIN_UNSAFE.search(value):
        raise ValueError(f"Not safe as a plain YAML scalar: {value!r}")
    return value


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def flow_quoted(items: list[str]) -> str:
    return "[" + ", ".join(quoted(item) for item in items) + "]"


def health_check(entry: dict) -> list[str]:
    health = entry["formic"]["health"]
    if "image" in health:
        return ["docker", "image", "inspect", f"{health['image']}:{entry['version']}"]
    return ["pwsh", "-NoProfile", "-File", entry["menu"], *health["menu_args"]]


def render_status(status: dict) -> list[str]:
    lines = ["status:", f"  kind: {plain(status['kind'])}"]
    if status.get("events"):
        lines.append("  events: [" + ", ".join(plain(event) for event in status["events"]) + "]")
    return lines


def render_tool(entry: dict) -> str:
    block = entry["formic"]
    menu = entry["menu"]
    working_directory = str(PurePosixPath(menu).parent)
    lines = ["formic: 1", f"name: {plain(entry['id'])}", f"title: {plain(block['title'])}", f"description: {plain(block['description'])}",
             "launch:", "  command: pwsh", "  args:"]
    lines += [f"    - {quoted(argument)}" for argument in LAUNCH_ARGS]
    lines += [f"    - {quoted('{repo}/' + menu)}", f"  cwd: {quoted('{repo}/' + working_directory)}", "config:", "  files:"]
    lines += [f"    - {quoted(path)}" for path in block["config_files"]]
    lines += render_status(block["status"])
    lines += ["health:", f"  check: {flow_quoted(health_check(entry))}"]
    lines += ["pane:", f"  prefer: {plain(block['pane']['prefer'])}", f"  interactive: {'true' if block['pane']['interactive'] else 'false'}"]
    if block.get("exit"):
        lines.append("exit:")
        lines += [f"  {quoted(code)}: {plain(text)}" for code, text in block["exit"].items()]
    return "\n".join(lines) + "\n"


def render_profile(catalog: dict) -> str:
    ordered = sorted(catalog["tools"], key=lambda entry: entry["formic"]["profile_order"])
    lines = ["tools:"]
    for entry in ordered:
        lines += [f"  {plain(entry['id'])}:", f"    mode: {plain(entry['formic']['mode'])}"]
    return "\n".join(lines) + "\n"


def render_toolkit(catalog: dict) -> str:
    toolkit = catalog["toolkit"]
    return f"toolkit: 1\nname: {plain(toolkit['name'])}\ntitle: {plain(toolkit['title'])}\n"


def generate(catalog: dict) -> dict[str, str]:
    """Relative path -> file text for every generated manifest."""
    files = {".formic/toolkit.yaml": render_toolkit(catalog), ".formic/profile.yaml": render_profile(catalog)}
    for entry in catalog["tools"]:
        files[f".formic/tools/{entry['id']}.yaml"] = render_tool(entry)
    return files


def load_catalog(root: Path) -> dict:
    return json.loads((root / CATALOG_PATH).read_text(encoding="utf-8-sig"))


def write_all(root: Path) -> list[str]:
    written = []
    for relative, text in generate(load_catalog(root)).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        written.append(relative)
    return written


def check(root: Path) -> list[str]:
    """Relative paths whose committed bytes differ from the generated text (or are missing)."""
    drifted = []
    for relative, text in generate(load_catalog(root)).items():
        target = root / relative
        if not target.is_file() or target.read_bytes() != text.encode("utf-8"):
            drifted.append(relative)
    return drifted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate .formic manifests from shared/catalog/tools.json")
    parser.add_argument("--root", default=".", help="Repository root (default: current directory)")
    parser.add_argument("--check", action="store_true", help="Write nothing; exit 4 when a committed manifest differs")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.check:
        drifted = check(root)
        for relative in drifted:
            print(f"drift: {relative}", file=sys.stderr)
        return EXIT_DRIFT if drifted else 0
    for relative in write_all(root):
        print(f"wrote {relative}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
