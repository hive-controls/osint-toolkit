# Hardened Docker setup for TorBot 4.3.0

> **Start here for day-to-day use:** [`README.md`](./README.md) (commands, args, deps, config).

This workspace builds a hash-pinned `torbot==4.3.0` image and a Tor SOCKS
sidecar. The TorBot container has **no default route**; it can only reach
`tor:9050` on an internal Compose network.

Upgrades are **manual only**. Self-update, clearnet mode (`--disable-socks5`),
and TorBotApp are rejected by the entrypoint.

## Network gate (required for crawls)

Before any crawl, the launcher refuses to run unless the host's route to the
public internet leaves through an Up adapter matching the configured VPN name
allowlist; `--help` and `--version` alone are exempt. There is no bypass flag.
Tor traffic exits via the Tor sidecar, which is separate from the host VPN.

The gate checks routing only. It does not verify the VPN provider, kill-switch,
or DNS leakage. Squid blocks LAN/metadata destinations and does not hide your
public IP.

Copy and edit the allowlist if needed:

`%LOCALAPPDATA%\TorBotLauncher\torbot-gate.json`

(from `gate/torbot-gate.example.json`).

## Install the guided launcher

`<repo>` is your clone directory.

```powershell
Set-Location '<repo>\TorBot Docker'
.\install-launcher.ps1
```

Then open a **new** PowerShell window:

```powershell
torbot
```

Useful commands:

```powershell
torbot --help
torbot --status
torbot --selftest
torbot --cleanup
```

## Quick start (CLI helper)

Start Docker Desktop. Connect your VPN. Then:

```powershell
Set-Location '<repo>\TorBot Docker'
# Optional: the helper defaults to <data root>\torbot; set this only to redirect (for example into a case)
$env:TORBOT_OUTPUT = '<data root>\cases\<id>\torbot'
New-Item -ItemType Directory -Path $env:TORBOT_OUTPUT -Force | Out-Null
docker compose build --pull
.\run-torbot.ps1 --version
```

Authorized crawl example (after the VPN is up):

```powershell
.\run-torbot.ps1 -u 'http://exampleonion.onion' --depth 1 --info
```

Reports land in `<data root>\torbot` (`TORBOT_OUTPUT` overrides this; the data root is `$env:OSINT_ROOT` when set, else `%LOCALAPPDATA%\OsintToolkit\data`). Running `docker compose` directly without the helper falls back to a legacy folder under your user profile, so prefer the helper or set the override.

## Why Compose

```text
torbot (internal only) --socks5--> tor:9050 --tor-egress--> Internet
```

- TorBot joins only `torbot-internal` (`internal: true`).
- Tor joins `torbot-internal` and `tor-egress`.
- Port 9050 is **not** published to Windows.

## What was reviewed

```text
torbot-4.3.0-py3-none-any.whl
SHA256 e5db3109a201a1cc197f75c9903ddce0cd265affb72faa97ee370920d381a160
```

Upstream release tag: `v4.3.0`. Upstream Dockerfile (live `git clone`) is not used.

Entrypoint forces `--host tor --port 9050` and rejects `--update`,
`--disable-socks5`, `--app`, and `--allow-remote`.

## Limits

This setup limits filesystem access, privilege escalation, accidental
clearnet bypass, and unreviewed self-mutation. It does **not** make dark-web
crawling safe or legal by itself. Tor exits can see traffic; operators must
use authorized targets only. Host VPN/proxy is a hygiene gate for the Windows
host path into Docker — it is not the same as Tor anonymity.

## Updating

Never float on GitHub `main`. Refresh `requirements.lock` from a reviewed wheel
(SHA-256 verified), re-run `shared/build/fetch_wheelhouse.py --tool "TorBot Docker" --force`
(wheels are fetched on demand from PyPI by exact version and sha256; not committed), rebuild images, and re-run gate
smoke tests.
