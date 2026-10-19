# TorBot (Hardened Docker)

> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md](../LEGAL-USE.md).

Dark-web / onion **crawler** via pinned `torbot==4.3.0`, Tor SOCKS sidecar, VPN gate, and PowerShell launcher.

Upstream: [DedSecInside/TorBot](https://github.com/DedSecInside/TorBot)  
This folder is a **local hardened packaging** — TorBot has no default route; only `tor:9050`.

---

## Requirements

| Dependency | Notes |
|---|---|
| **Docker Desktop** | Engine running |
| **PowerShell 7 (`pwsh`)** | Launcher / menu |
| **Host VPN (allowlisted adapter)** | Automated gate + typed `RUN` for crawls |
| Disk space | Hardened image is large (scipy/sklearn pulled in by upstream) |

**Not required on Windows:** pip-installing TorBot.

---

## Config / environment

`<repo>` in paths below is your clone directory. Hardening notes: see [`README-docker.md`](./README-docker.md).

| Item | Default / location |
|---|---|
| Output bind | `<data root>\torbot` (default root `%LOCALAPPDATA%\OsintToolkit\data`; override: `$env:TORBOT_OUTPUT` or `$env:OSINT_ROOT`); older installs wrote to a folder under `%USERPROFILE%` |
| Gate config | `%LOCALAPPDATA%\TorBotLauncher\torbot-gate.json` (from `gate/torbot-gate.example.json`) |
| Launcher shim | `%LOCALAPPDATA%\Programs\TorBotLauncher\torbot.cmd` |
| Images | `torbot-hardened:4.3.0`, `torbot-tor:local` |
| Wheel pin | SHA256 `e5db3109a201a1cc197f75c9903ddce0cd265affb72faa97ee370920d381a160` |

On macOS/Linux, the data root falls back to `$XDG_DATA_HOME/osint-toolkit` (else `~/.local/share/osint-toolkit`) and the gate config resolves to `~/.config/TorBotLauncher/torbot-gate.json` (see `shared/OsintTool.Common.ps1`).
| Tor package | Debian `tor=0.4.9.11-0+deb12u1` |

Entrypoint **forces** `--host tor --port 9050`.

**Blocked (exit 64):** `--disable-socks5`, `--update`, `--app`, `--allow-remote`.

---

## Network gate

Before any crawl, the launcher refuses to run unless the host's route to the public internet leaves through an Up adapter matching the configured VPN name allowlist; `--help` and `--version` alone are exempt. There is no bypass flag. Tor traffic exits via the Tor sidecar, which is separate from the host VPN. The menu additionally requires typing `RUN`.

The gate checks routing only. It does not verify the VPN provider, kill-switch, or DNS leakage. Squid blocks LAN/metadata destinations and does not hide your public IP.

---

## Routed-proxy mode

Routed-proxy mode is not available for TorBot; VPN route gate only. A gate config that selects it makes the launcher exit 78.

## Install launcher (once)

```powershell
Set-Location '<repo>\TorBot Docker'
.\install-launcher.ps1
```

```powershell
torbot
torbot --help
torbot --status
torbot --selftest
torbot --cleanup
.\uninstall-launcher.ps1
```

Desktop: **TorBot (Hardened)**.

---

## Build from a clean clone

Prerequisites: Docker Desktop (engine running), PowerShell 7 (`pwsh`), and network access for the wheel fetch (PyPI) and for apt inside the sidecar image build.

```powershell
python -I shared/build/fetch_wheelhouse.py --tool "TorBot Docker"   # from the repo root
Set-Location 'TorBot Docker'
docker compose build
```

Two pins (`unipath`, `yattag`) have no py3 wheel on PyPI. The fetcher builds them from the sha256-pinned sdists in `artifacts/requirements-sdist.lock`, inside the same digest-pinned base image, with the hashed toolchain in `artifacts/requirements-build.lock`, `SOURCE_DATE_EPOCH=315532800` and `PYTHONHASHSEED=0`. It builds twice in fresh containers and refuses to continue unless both wheels are byte-identical; the resulting wheel hashes are the ones pinned in `requirements.lock`.

Then run through the launcher. TorBot has no image-freshness check (only Maigret does): a stale local image is reused until `docker compose build` is re-run.

---

## Build images

```powershell
Set-Location '<repo>\TorBot Docker'
$env:TORBOT_OUTPUT = "$env:LOCALAPPDATA\OsintToolkit\data\torbot"
New-Item -ItemType Directory -Path $env:TORBOT_OUTPUT -Force | Out-Null
docker compose build --pull
```

---

## Key commands

```powershell
.\run-torbot.ps1 --help
.\run-torbot.ps1 --version

# After the VPN gate passes:
.\run-torbot.ps1 -u 'http://AUTHORIZED.onion' --depth 1 --info
.\run-torbot.ps1 -u 'http://AUTHORIZED.onion' --depth 1 --save json --visualize tree
.\run-torbot.ps1 -u 'http://AUTHORIZED.onion' --html save
```

Tor must become **healthy** (bootstrap 100%) before TorBot runs.

---

## Important arguments

| Flag | Purpose | Hardened note |
|---|---|---|
| `-u` / `--url` | Start URL | Required for crawls |
| `--depth` | Max crawl depth (default 1) | Keep low |
| `--host` / `--port` | SOCKS endpoint | **Forced** to `tor:9050` |
| `--save` | `tree` \| `json` | Writes under `/output` |
| `--visualize` | `table` \| `tree` \| `json` | Display/collection viz |
| `--info` | Basic site info (single URL) | |
| `--html` | `save` \| `display` | Treat saved HTML as untrusted |
| `-v` | Verbose logging | |
| `-q` / `--quiet` | Quiet | |
| `--version` | Version | Allowed without VPN probe |
| `--update` | Upstream self-update | **Blocked** |
| `--disable-socks5` | Clearnet HTTP | **Blocked** |
| `--app` / `--app-dir` | Desktop TorBotApp | **Blocked** |

---

## Operator vigilance (short)

- This is a **crawler**, not Tor Browser. `--app` / TorBotApp is blocked on purpose.
- Don’t open crawl artifacts in a normal host browser. Index outputs from `<data root>/cases/<id>/`; open HTML only in an isolated browser profile or VM, never your daily browser.
- Host VPN ≠ Tor anonymity; Tor exit (or onion path) is what destinations see.
- Permitted use: see [LEGAL-USE.md](../LEGAL-USE.md). See the "What was reviewed" and "Limits" sections of `README-docker.md` for the hardening scope.

---

## More detail

Digests, Compose topology, re-pin procedure: [`README-docker.md`](./README-docker.md).  
Design notes: [`design/specs/torbot-hardened.md`](./design/specs/torbot-hardened.md).
