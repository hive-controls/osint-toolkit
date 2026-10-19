# Maigret (Hardened Docker)

> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md](../LEGAL-USE.md).

To use this menu within a case, run `osint-case scan <case-id> --tool maigret`. The profiler opens the supported menu in a terminal split/tab, binds each scan to that case, retains a JSON sidecar, and imports reports after completion. Standalone `maigret` behavior remains unchanged. See the [case workflow](../OSINT%20Profiler/README.md).

Clearnet **username dossier** OSINT via pinned `maigret==0.6.4`, Squid-filtered egress, and a PowerShell launcher.

Upstream: [soxoj/maigret](https://github.com/soxoj/maigret)  
This folder is **investigative packaging** — hash-pinned image, not `pip install -U maigret` on Windows.

---

## Requirements

| Dependency | Notes |
|---|---|
| **Docker Desktop** | Engine running |
| **PowerShell 7 (`pwsh`)** | Launcher / menu |
| **Host VPN (allowlisted adapter)** | Automated gate + typed `RUN` |
| Disk space | Image is larger than User-Scanner (graphs, reportlab, pyvis) |

**No host Maigret installation is required.** The image builds entirely from this folder's pinned wheelhouse (fetched on demand from PyPI by exact version and sha256; not committed).
---

## Config / environment

`<repo>` in paths below is your clone directory. Hardening notes: see [`README-docker.md`](./README-docker.md).

| Item | Default / location |
|---|---|
| Output bind | `<data root>\maigret` (default root `%LOCALAPPDATA%\OsintToolkit\data`; override: `$env:MAIGRET_OUTPUT` or `$env:OSINT_ROOT`) |
| Gate config | `%LOCALAPPDATA%\MaigretLauncher\maigret-gate.json` |
| Launcher shim | `%LOCALAPPDATA%\Programs\MaigretLauncher\maigret.cmd` |
| Images | `maigret-hardened:0.6.4`, `maigret-egress-proxy:local` |
| Wheel pin | SHA256 `ac7169d74c4997ab7f4b42b4ed64ba2436ebde57ad2258b1e682baa350948d51` |

On macOS/Linux, the gate config resolves to `~/.config/MaigretLauncher/maigret-gate.json` instead (see `shared/OsintTool.Common.ps1`).

Entrypoint **forces** `--no-autoupdate --proxy http://egress-proxy:3128 --folderoutput /output`.

**Blocked (exit 64):** `--web`, `--force-update`, `--tor-proxy`, `--i2p-proxy`.

---

## Network gate

Before any search, the launcher refuses to run unless the host's route to the public internet leaves through an Up adapter matching the configured VPN name allowlist; `--help` and `--version` alone are exempt. There is no bypass flag. The menu additionally requires typing `RUN`.

The gate checks routing only. It does not verify the VPN provider, kill-switch, or DNS leakage. Squid blocks LAN/metadata destinations and does not hide your public IP.

---

## Routed-proxy mode

In routed-proxy mode the gate verified an HTTP CONNECT tunnel through the configured proxy (ip:port), and every request AND every destination name lookup leaves via the Squid sidecar, which can only forward through that proxy; if the proxy fails the scan fails rather than going direct. Loopback and host-local proxies are rejected; LAN proxies require `allowPrivate: true`; proxy authentication is not supported in this version.

How it is enforced: the launcher renders the upstream peer into a per-run file, starts the sidecar with `proxy/squid-routed.conf` (`never_direct`; a `squid -k parse` preflight failure exits 78), and after startup sends one CONNECT through the sidecar and requires Squid's access log to show a `*_PARENT` hierarchy code. `HIER_DIRECT` or no log line tears the run down and exits 75 ("routed-proxy enforcement probe failed"). If the gate passes in routed mode without enforcement details, the launcher exits 78.

Reduced destination filtering: `squid-routed.conf` cannot resolve names locally, so the private/metadata destination blocklist of `squid.conf` is not applied. IP-literal destinations are denied, and `localhost` / `*.docker.internal` / `*.local` names are blocked by URL text only. The operator-asserted upstream proxy is responsible for refusing private ranges. Squid 5.7 still issues one lookup per CONNECT target after reaching the parent; the routed config parks its resolver on the container's own loopback so that lookup cannot leave the sidecar.

## Install launcher (once)

```powershell
Set-Location '<repo>\Maigret Docker'
.\install-launcher.ps1
```

```powershell
maigret
maigret --help
maigret --status
maigret --selftest
maigret --cleanup
.\uninstall-launcher.ps1
```

Desktop: **Maigret (Hardened)**.


---

## Build from a clean clone

Prerequisites: Docker Desktop (engine running), PowerShell 7 (`pwsh`), and network access for the wheel fetch (PyPI) and for apt inside the sidecar image build.

```powershell
python -I shared/build/fetch_wheelhouse.py --tool "Maigret Docker"   # from the repo root
Set-Location 'Maigret Docker'
docker compose build
```

Then run through the launcher. Maigret is the only tool with an image-freshness check (`image-freshness.ps1`): the launcher rebuilds when the hardening inputs change. The other three tools reuse a stale local image until `docker compose build` is re-run.

---

## Build images

The launcher rebuilds automatically: after the network gate passes, `run-maigret.ps1` compares a hash of the hardening files (`Dockerfile*`, `.dockerignore`, `requirements.lock`, `hardening/entrypoint.sh`, `proxy/squid.conf`) with the `maigret.build-inputs` label on both images and rebuilds on mismatch. `maigret --status` shows whether a rebuild is pending. Manual build:

```powershell
Set-Location '<repo>\Maigret Docker'
$env:MAIGRET_OUTPUT = "$env:LOCALAPPDATA\OsintToolkit\data\maigret"
New-Item -ItemType Directory -Path $env:MAIGRET_OUTPUT -Force | Out-Null
docker compose build --pull
```

---

## Key commands

```powershell
.\run-maigret.ps1 --help
.\run-maigret.ps1 --version

# After the VPN gate passes:
.\run-maigret.ps1 AUTHORIZED_USER --top-sites 500 -H -M -J simple -G
```

Reports land in `<data root>\maigret\` (or `$env:MAIGRET_OUTPUT`); the data root is `$env:OSINT_ROOT` when set, else `%LOCALAPPDATA%\OsintToolkit\data`. The menu and CLI helper resolve it the same way; direct Compose falls back to `../OSINT/maigret` only when no launcher exports the variable. `/output` is the container view of that Windows folder. `-H` requests HTML; `-P` requests PDF, whose optional dependencies are omitted here.

For a case, set `$env:MAIGRET_OUTPUT = '<data root>\cases\<id>\maigret'` before launching. Remove that environment variable to restore the default. Reports from the old in-repo `OSINT\maigret` location can be copied across with `osint-case migrate-root`.

---

## Operator vigilance (short)

- This is a **clearnet** dossier tool, not Tor Browser and not TorBot.
- Open HTML reports only in an isolated browser profile or VM, never your daily browser.
- Squid filters LAN; it does not hide your public IP. Host VPN is hygiene.
- Permitted use: see [LEGAL-USE.md](../LEGAL-USE.md). Do not `pip install -U maigret` for investigative use.

---

## More detail

Digests, Compose topology, re-pin: [`README-docker.md`](./README-docker.md).  
Design notes: [`design/specs/maigret-hardened.md`](./design/specs/maigret-hardened.md).
