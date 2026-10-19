import hashlib
import subprocess
import sys
from pathlib import Path

wheelhouse = Path("/out/wheelhouse")
files = sorted(wheelhouse.glob("*.whl"))


def parse(wh: Path) -> tuple[str, str]:
    stem = wh.name[:-4]
    parts = stem.split("-")
    for i, p in enumerate(parts):
        if p and p[0].isdigit():
            name = "-".join(parts[:i]).replace("_", "-")
            return name, p
    raise SystemExit(f"cannot parse {wh.name}")


by_name: dict[str, tuple[str, str, str, str]] = {}
for wh in files:
    name, ver = parse(wh)
    digest = hashlib.sha256(wh.read_bytes()).hexdigest()
    by_name[name.lower()] = (name, ver, digest, wh.name)

subprocess.check_call([sys.executable, "-m", "venv", "/tmp/v"])
pip = "/tmp/v/bin/pip"
subprocess.check_call(
    [pip, "install", "-q", "--no-index", "--find-links", str(wheelhouse), "maigret==0.6.4"]
)
freeze = subprocess.check_output([pip, "freeze"], text=True)
print("FREEZE_BEGIN")
print(freeze)
print("FREEZE_END")

lock_lines = [
    "# Linux x86_64 / CPython 3.12 runtime lock.",
    "# Generated from PyPI maigret==0.6.4 (binary wheels only) on 2026-09-17.",
    "# PDF extras (xhtml2pdf/cairo) omitted. Upgrades remain manual.",
]
missing = []
for line in freeze.splitlines():
    if not line or line.startswith("#") or " @ " in line:
        continue
    pkg, ver = line.split("==", 1)
    key = pkg.replace("_", "-").lower()
    rec = by_name.get(key) or by_name.get(pkg.lower())
    if not rec:
        missing.append(line)
        continue
    _name, _wver, digest, _fname = rec
    lock_lines.append(f"{pkg}=={ver} \\")
    lock_lines.append(f"    --hash=sha256:{digest}")

if missing:
    print("MISSING", missing)
    raise SystemExit(2)

Path("/out/requirements.lock").write_text("\n".join(lock_lines) + "\n", encoding="utf-8")
maig = by_name["maigret"]
Path("/out/MAIGRET_SHA256.txt").write_text(f"{maig[2]}\n{maig[3]}\n", encoding="utf-8")
print("LOCK_OK", maig)
print("PACKAGES", len(by_name))
