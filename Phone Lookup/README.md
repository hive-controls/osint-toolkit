# Phone lookup (Hardened Docker)

> People-focused OSINT. Authorized, lawful use only — see [LEGAL-USE.md](../LEGAL-USE.md).

To use this menu within a case, run `osint-case scan <case-id> --tool phone`. The profiler opens the supported menu in a terminal split/tab and saves/imports each lookup's JSON into that case. Standalone `phone-lookup` behavior remains unchanged. See the [case workflow](../OSINT%20Profiler/README.md).

Jobs **1 and 4** only: numbering-plan / carrier metadata, then optional breach/infostealer hits.

Not a Maigret-for-phones. No WhatsApp, Telegram, Ignorant, or people-search aggregators.

---

## What it does

| Job | Source | Key? | Notes |
|---|---|---|---|
| 1 local | Google `libphonenumber` via Python `phonenumbers` | No | E.164, country, prefix-grade carrier, line type |
| 1 API | Numverify / APILayer Number Verification | `NUMVERIFY_API_KEY` | Carrier, location, line type (still not live HLR) |
| 4 opt-in | Hudson Rock Cavalier OSINT `search-by-username` | No | Hudson’s documented phone path; they may log the query |
| 4 opt-in | DeHashed v2 `phone:` | `DEHASHED_API_KEY` | Paid |
| 4 opt-in | LeakCheck Pro v2 `type=phone` | `LEAKCHECK_APIKEY` | Paid. Phone-search support depends on your plan; not independently confirmed (see [Providers](#providers-opt-in)) |
| 4 opt-in | LeakRadar advanced search | `LEAKRADAR_API_KEY` | No native phone field; queried as **username** |

Every third-party provider (Numverify and all of Job 4) is **off by default** and must be enabled explicitly; see [Providers](#providers-opt-in) and [PROVIDERS.md](PROVIDERS.md).

Passwords/hashes in JSON are **`[redacted]`** unless `--include-secrets`.

---

## Providers (opt-in)

A provider is called only if it is **enabled** and its **terms acknowledgement is current**. An API key alone never enables anything, and nothing on a lookup command line can add a provider for one run (`--skip-<provider>` can only remove one).

Config is the non-secret `providers.json`, beside `secrets.json` (`%LOCALAPPDATA%\PhoneLookup\providers.json`; template `providers.example.json`, all `enabled: false`). Entry shape: `{"<provider>": {"enabled": true, "terms_ack": {"version": "<sha256 of PROVIDER-TERMS/<provider>.txt>", "operator": "...", "ts": "..."}}}`. Provider ids: `numverify`, `hudson_rock`, `dehashed`, `leakcheck`, `leakradar`.

```powershell
.\run-phone.ps1 --providers [--json]                     # state: enabled / key / terms_ack (current|stale|missing)
.\run-phone.ps1 --enable hudson_rock --acknowledge-terms "I HAVE READ THE HUDSON_ROCK TERMS AND ACCEPT RESPONSIBILITY FOR MY QUERIES"
.\run-phone.ps1 --disable hudson_rock
```

The phrase is `I HAVE READ THE <PROVIDER> TERMS AND ACCEPT RESPONSIBILITY FOR MY QUERIES` (provider id upper-cased) and is checked only by the Python CLI; a mismatch writes nothing. Read `PROVIDER-TERMS/<provider>.txt` first. Editing a terms file changes its hash, so previous acknowledgements go stale and must be repeated.

Lookup outcomes (checked before any network call):

| State | Result |
|---|---|
| not enabled (key or no key) | not called; `skipped.<provider> = "disabled"` |
| `--skip-<provider>` on an enabled provider | not called; `skipped.<provider> = "skipped-flag"` |
| enabled, no key (Hudson Rock exempt: keyless) | exit **78**, JSON `{"error":"provider-config","problems":{"<provider>":"no-key"}}`; nothing is sent |
| enabled, acknowledgement missing or for an older terms version | exit **78**, problem `"terms-ack-stale"`; nothing is sent |
| enabled, key present, acknowledgement current | called |

`skipped` in the report is an object `{provider: reason}`, not a list. HTTP 429 from a provider sets `rate_limited: true` (plus `retry_after` when the response body carries one) on that source; there is no automatic retry. Only the response body is inspected: the `Retry-After` header is not exposed by `http.py`.

**Container source of truth:** `run-phone.ps1` reads `providers.json` on the host and passes the container `PHONE_LOOKUP_PROVIDERS=name@terms-version,...` (empty = none). In that mode the env list replaces the file; the container still compares each version to its own `PROVIDER-TERMS` copy. Management commands mount the config directory at `/config` for that one invocation and read/write the file.

**Case requirement:** compose sets `PHONE_LOOKUP_REQUIRE_CASE=1`; a lookup without a non-empty `OSINT_SUBJECT_AUTH` is refused with exit **77** `{"error":"subject-authorization-required"}`. `--help`, `--version`, `--init-secrets`, `--providers`, `--enable` and `--disable` are exempt.

LeakCheck phone search is implemented as a v2 `query/<digits>` request with `type=phone` (`providers/leakcheck.py:12`); the provider's documented behaviour for phone queries was not independently confirmed when this was written. Confirm against your LeakCheck plan before relying on a miss.

---

## Requirements

Docker Desktop, PowerShell 7, host VPN (allowlisted adapter; typed `RUN` in the menu).

### Network gate

Before any lookup, the launcher refuses to run unless the host's route to the public internet leaves through an Up adapter matching the configured VPN name allowlist; `--help` and `--version` alone are exempt, and `--init-secrets` alone is exempt. There is no bypass flag.

The gate checks routing only. It does not verify the VPN provider, kill-switch, or DNS leakage. Squid blocks LAN/metadata destinations and does not hide your public IP.

Secrets (never in git):

`%LOCALAPPDATA%\PhoneLookup\secrets.json` (copied from `secrets.example.json` on install). On macOS/Linux this resolves to `~/.config/PhoneLookup/secrets.json` instead (see `shared/OsintTool.Common.ps1`).

```json
{
  "numverify_api_key": "",
  "dehashed_api_key": "",
  "leakcheck_api_key": "",
  "leakradar_api_key": ""
}
```

Env vars override the file: `NUMVERIFY_API_KEY`, `DEHASHED_API_KEY`, `LEAKCHECK_APIKEY`, `LEAKRADAR_API_KEY`.

---

## Routed-proxy mode

In routed-proxy mode the gate verified an HTTP CONNECT tunnel through the configured proxy (ip:port), and every request AND every destination name lookup leaves via the Squid sidecar, which can only forward through that proxy; if the proxy fails the scan fails rather than going direct. Loopback and host-local proxies are rejected; LAN proxies require `allowPrivate: true`; proxy authentication is not supported in this version.

How it is enforced: the launcher renders the upstream peer into a per-run file, starts the sidecar with `proxy/squid-routed.conf` (`never_direct`; a `squid -k parse` preflight failure exits 78), and after startup sends one CONNECT through the sidecar and requires Squid's access log to show a `*_PARENT` hierarchy code. `HIER_DIRECT` or no log line tears the run down and exits 75 ("routed-proxy enforcement probe failed"). If the gate passes in routed mode without enforcement details, the launcher exits 78.

Reduced destination filtering: `squid-routed.conf` cannot resolve names locally, so the private/metadata destination blocklist of `squid.conf` is not applied. IP-literal destinations are denied, and `localhost` / `*.docker.internal` / `*.local` names are blocked by URL text only. The operator-asserted upstream proxy is responsible for refusing private ranges. Squid 5.7 still issues one lookup per CONNECT target after reaching the parent; the routed config parks its resolver on the container's own loopback so that lookup cannot leave the sidecar.

## Build from a clean clone

Prerequisites: Docker Desktop (engine running), PowerShell 7 (`pwsh`), and network access for the wheel fetch (PyPI) and for apt inside the sidecar image build.

```powershell
python -I shared/build/fetch_wheelhouse.py --tool "Phone Lookup"   # from the repo root
Set-Location 'Phone Lookup'
docker compose build
```

Then run through the launcher. Phone Lookup has no image-freshness check (only Maigret does): a stale local image is reused until `docker compose build` is re-run. The project itself builds from `src`; only third-party wheels are fetched.

---

## Install

`<repo>` is your clone directory.

```powershell
Set-Location '<repo>\Phone Lookup'
.\install-launcher.ps1
docker compose build
```

New terminal:

```powershell
phone-lookup
phone-lookup --selftest
```

CLI:

```powershell
.\run-phone.ps1 --version
.\run-phone.ps1 '+12025550123'
.\run-phone.ps1 '2025550123' --region US --skip-hudson
```

Output: `<data root>\phone` (override: `$env:PHONE_LOOKUP_OUTPUT`); the data root is `$env:OSINT_ROOT` when set, else `%LOCALAPPDATA%\OsintToolkit\data`. The menu and CLI helper resolve it the same way; direct Compose falls back to `../OSINT/phone` only when no launcher exports the variable. Container `/output` is a bind mount of that Windows folder, so JSON reports persist after container cleanup.

For a case, set `$env:PHONE_LOOKUP_OUTPUT = '<data root>\cases\<id>\phone'` before launching. Remove that environment variable to restore the default. Reports from the old in-repo `OSINT\phone` location can be copied across with `osint-case migrate-root`.

Host venv (dev):

```powershell
Set-Location '<repo>\Phone Lookup'
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m unittest discover -s tests
.\.venv\Scripts\phone-lookup.exe --version
```

### Development

Tests import the `phone_lookup` package, so install it into a venv first (without this, `unittest discover` fails with an import error). From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # POSIX: source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests
```

---

## Operator notes

- Permitted use and third-party disclosure: see [LEGAL-USE.md](../LEGAL-USE.md). Enabled providers receive the queried number and may log it.
- Hudson is infostealer intelligence, not a people-search. A miss is not “clean.”
- Prefix carrier ≠ ported live network. Numverify is numbering-plan grade, not SS7 HLR.
- LeakRadar may 404/422 if their advanced-search body changes; paid keys are optional.
