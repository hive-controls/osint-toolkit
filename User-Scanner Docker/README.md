# User-Scanner (Hardened Docker)

> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md](../LEGAL-USE.md).

To use this menu within a case, run `osint-case scan <case-id> --tool scanner`. Its existing menus, favorites and options run in a real terminal split/tab. Each scan saves into its own case run folder and imports automatically; terminal-only display additionally saves JSON in case mode. Standalone `user-scanner` behavior remains unchanged. See the [case workflow](../OSINT%20Profiler/README.md).

Clearnet **email + username** OSINT via pinned `user-scanner==1.5.1.3`, Squid-filtered egress, and a PowerShell launcher.

Upstream project: [kaifcodec/user-scanner](https://github.com/kaifcodec/user-scanner)  
This folder is a **local hardened packaging** — not a Windows pip install.

---

## Requirements

| Dependency | Notes |
|---|---|
| **Docker Desktop** | Engine must be running (`docker version` shows Server) |
| **PowerShell 7 (`pwsh`)** | Required for launcher install / menu |
| **Host VPN (allowlisted adapter)** | The launcher and the menu refuse to run unless the host route goes through an allowlisted VPN adapter; the menu additionally requires typing RUN. |
| Disk space | Images ~400MB scanner + ~220MB Squid proxy |

The gate checks routing only. It does not verify the VPN provider, kill-switch, or DNS leakage. Squid blocks LAN/metadata destinations and does not hide your public IP.

**Not required on Windows:** Python packages for user-scanner (all deps are inside the image).

---

## Config / environment

`<repo>` in paths below is your clone directory. Hardening notes: see [`README-docker.md`](./README-docker.md).

| Item | Default / location |
|---|---|
| Output bind | `<data root>\scanner` (default root `%LOCALAPPDATA%\OsintToolkit\data`; override: `$env:SCANNER_OUTPUT` or `$env:OSINT_ROOT`) |
| Favorites | `%LOCALAPPDATA%\UserScannerLauncher\favorites.json` |
| Launcher shim | `%LOCALAPPDATA%\Programs\UserScannerLauncher\user-scanner.cmd` |
| Images | `user-scanner-hardened:1.5.1.3`, `user-scanner-egress-proxy:local` |
| Pin | Wheel SHA256 `1716434f26ee7547e0814e6b4eaa5b1b0e34aa7caaf2343031be4cf6e6ffbfcb` |

On macOS/Linux, favorites resolve to `~/.config/UserScannerLauncher/favorites.json` instead (see `shared/OsintTool.Common.ps1`).

Entrypoint always adds `--no-pdf-media`. Rejects `-U` / `--update` and MCP args.

---

## Routed-proxy mode

In routed-proxy mode the gate verified an HTTP CONNECT tunnel through the configured proxy (ip:port), and every request AND every destination name lookup leaves via the Squid sidecar, which can only forward through that proxy; if the proxy fails the scan fails rather than going direct. Loopback and host-local proxies are rejected; LAN proxies require `allowPrivate: true`; proxy authentication is not supported in this version.

How it is enforced: the launcher renders the upstream peer into a per-run file, starts the sidecar with `proxy/squid-routed.conf` (`never_direct`; a `squid -k parse` preflight failure exits 78), and after startup sends one CONNECT through the sidecar and requires Squid's access log to show a `*_PARENT` hierarchy code. `HIER_DIRECT` or no log line tears the run down and exits 75 ("routed-proxy enforcement probe failed"). If the gate passes in routed mode without enforcement details, the launcher exits 78.

Reduced destination filtering: `squid-routed.conf` cannot resolve names locally, so the private/metadata destination blocklist of `squid.conf` is not applied. IP-literal destinations are denied, and `localhost` / `*.docker.internal` / `*.local` names are blocked by URL text only. The operator-asserted upstream proxy is responsible for refusing private ranges. Squid 5.7 still issues one lookup per CONNECT target after reaching the parent; the routed config parks its resolver on the container's own loopback so that lookup cannot leave the sidecar.

## Install launcher (once)

```powershell
Set-Location '<repo>\User-Scanner Docker'
.\install-launcher.ps1
```

Open a **new** PowerShell window, then:

```powershell
user-scanner
```

Desktop shortcut: **User Scanner (Hardened)**.

```powershell
user-scanner --help
user-scanner --selftest
user-scanner --cleanup
.\uninstall-launcher.ps1
```

---

## Build from a clean clone

Prerequisites: Docker Desktop (engine running), PowerShell 7 (`pwsh`), and network access for the wheel fetch (PyPI) and for apt inside the sidecar image build.

```powershell
python -I shared/build/fetch_wheelhouse.py --tool "User-Scanner Docker"   # from the repo root
Set-Location 'User-Scanner Docker'
docker compose build
```

Then run through the launcher. User-Scanner has no image-freshness check (only Maigret does): a stale local image is reused until `docker compose build` is re-run.

---

## Build images

```powershell
Set-Location '<repo>\User-Scanner Docker'
$env:SCANNER_OUTPUT = "$env:LOCALAPPDATA\OsintToolkit\data\scanner"
New-Item -ItemType Directory -Path $env:SCANNER_OUTPUT -Force | Out-Null
docker compose build --pull
```

---

## Key commands

### Guided menu
```powershell
user-scanner
```

### CLI helper (`run-scanner.ps1`)
Starts Squid → waits healthy → `compose run --rm scanner` → tears down.

```powershell
.\run-scanner.ps1 --help
.\run-scanner.ps1 --version
.\run-scanner.ps1 -lu                          # list username modules (NSFW included)
.\run-scanner.ps1 -le                          # list email modules
.\run-scanner.ps1 -u 'AUTHORIZED_USER' -m github -f json -o /output/out.json
.\run-scanner.ps1 -e 'authorized@example.com' -f csv -o /output/out.csv
.\run-scanner.ps1 -u 'AUTHORIZED_USER' --hudson     # only after `phone-lookup --enable hudson_rock` (opt-in, shared providers.json)
.\run-scanner.ps1 -u 'AUTHORIZED_USER' --cross-scan --cross-depth 1
```

Output paths are **inside the container** under `/output` (= Windows `<data root>\scanner`, or host `SCANNER_OUTPUT`; the data root is `$env:OSINT_ROOT` when set, else `%LOCALAPPDATA%\OsintToolkit\data`). The menu and CLI helper resolve it the same way; direct Compose falls back to `../OSINT/scanner` only when no launcher exports the variable. Choose JSON or CSV in the menu to save a report; **Terminal only does not save a file**. CLI exports need `-f json -o /output/name.json` (or CSV).

For a case, set `$env:SCANNER_OUTPUT = '<data root>\cases\<id>\scanner'` before launching. Remove that environment variable to restore the default. Reports from the old in-repo `OSINT\scanner` location can be copied across with `osint-case migrate-root`.

---

## Important arguments

| Flag | Purpose |
|---|---|
| `-u` / `--username` | Single username |
| `-e` / `--email` | Single email |
| `-uf` / `--username-file` | Usernames file (one per line) |
| `-ef` / `--email-file` | Emails file (one per line) |
| `-c` / `--category` | Category filter(s) |
| `-m` / `--module` | Module filter(s), e.g. `github` |
| `-lu` / `-le` | List username / email modules |
| `-v` / `--verbose` | Show URLs |
| `--all` | Include not-found / errors |
| `-f` / `--format` | `csv` \| `json` \| `pdf` (PDF media disabled here) |
| `-o` / `--output` | Output path (use `/output/...`) |
| `-t` / `--timeout` | Per-request timeout (seconds) |
| `-C` / `--concurrency` | Concurrency override |
| `-d` / `--delay` | Delay between requests |
| `-P` / `--proxy-file` | Extra proxy list (optional; Squid already used) |
| `--validate-proxies` | Probe proxies before scan |
| `--no-nsfw` | Exclude adult modules (**off by default** in launcher Standard) |
| `--allow-loud` | Allow modules that may notify the target |
| `--cross-scan` | Pivot to discovered handles/emails |
| `--cross-links` | `all` \| `verified` \| `none` |
| `--cross-emails` | `all` \| `verified` \| `none` |
| `--cross-depth` | Link-follow rounds |
| `--cross-sweep` | Sweep budget (`0` disables) |
| `--hudson` | Hudson Rock infostealer query. **Opt-in:** refused (exit 78 from `run-scanner.ps1`, 64 from the container) unless `hudson_rock` is enabled with a current terms acknowledgement in Phone Lookup's `providers.json` (`.\run-phone.ps1 --enable hudson_rock --acknowledge-terms "<phrase>"`; see `Phone Lookup/PROVIDERS.md`) |
| `--version` | Print version |
| `-U` / `--update` | **Blocked** in this image |

---

## Safety defaults (this packaging)

- NSFW **on** unless `--no-nsfw`
- Loud modules **off** unless `--allow-loud`
- Cross-scan **off** unless requested
- Type **`RUN`** in the menu before every real scan (VPN/proxy reminder)
- Manual image upgrades only (see `README-docker.md` re-pin section)

---

## More detail

Hardening notes, digests, and threat-model limits: [`README-docker.md`](./README-docker.md).
