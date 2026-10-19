# Hardened Docker setup for user-scanner 1.5.1.3

> **Start here for day-to-day use:** [`README.md`](./README.md) (commands, args, deps, config).

This workspace builds the exact PyPI `user-scanner==1.5.1.3` wheel into a
non-root, read-only Linux container. All Python dependencies are fetched on demand
from PyPI by exact version and sha256; not committed, and SHA-256 locked. A separate non-root Squid container is the only component with
public egress; the scanner itself has no default route. Upgrades are always
manual: rebuild from a newly reviewed, hash-pinned wheel — never auto-update.

No scanner package or dependency is installed into Windows. Squid is also
containerized; it is not installed on the host.

## Recommended: install the guided launcher

The native PowerShell launcher replaces memorized query parameters with four
organized steps:

1. **Target & scope** — username/email, single/batch, standard/Hudson, and
   all/category/module scope.
2. **Safety & expansion** — standard preset includes NSFW; loud and cross-scan
   stay off unless you choose Custom. Minimal opts out of NSFW (`--no-nsfw`).
3. **Output & pace** — terminal/JSON/CSV, result detail, and gentle/standard/
   custom pacing.
4. **Review & run** — full command review, optional favorite save, loud-module
   acknowledgement when applicable, and the mandatory network-readiness gate.

The launcher and the menu refuse to run unless the host route goes through an
allowlisted VPN adapter; the menu additionally requires typing RUN. The gate
checks routing only. It does not verify the VPN provider, kill-switch, or DNS
leakage. Squid blocks LAN/metadata destinations and does not hide your public
IP.

Install it once from PowerShell (no administrator account is required; `<repo>` is your clone directory):

```powershell
Set-Location '<repo>\User-Scanner Docker'
.\install-launcher.ps1
```

Open a new PowerShell window and launch it with:

```powershell
user-scanner
```

Useful commands:

```powershell
user-scanner --help
user-scanner --selftest
user-scanner --cleanup
```

`--cleanup` runs `docker compose down --remove-orphans` for this project. The
menu also closes the project environment on exit and asks separately before
stopping Docker Desktop, because Docker Desktop may be serving other projects.

Immediately before every execution, the launcher requires you to type `RUN`
to confirm that the host VPN is on or that an approved proxy route is
established. This confirmation cannot be stored in a favorite. The built-in
Squid service filters LAN and metadata destinations, but it does not conceal
or rotate the public IP.

Up to four favorites can store reusable scan scope, safety, output, and pace
settings. Favorites are stored in
`%LOCALAPPDATA%\UserScannerLauncher\favorites.json`. They deliberately exclude
targets, batch-file paths, output names, and proxy credentials; every favorite
run asks for a fresh target. Remove the shortcut and command while preserving
favorites with:

```powershell
.\uninstall-launcher.ps1
```

Add `-RemoveFavorites` only when the four saved configurations should also be
deleted. Docker images and scan reports are never removed by the uninstaller.

## Quick start from PowerShell

Start Docker Desktop and, if desired, connect the Windows host VPN first. Then:

```powershell
Set-Location '<repo>\User-Scanner Docker'

# Optional: the helper defaults to <data root>\scanner; set this only to redirect (for example into a case)
$env:SCANNER_OUTPUT = '<data root>\cases\<id>\scanner'
New-Item -ItemType Directory -Path $env:SCANNER_OUTPUT -Force | Out-Null

docker compose build --pull
```

Use the helper for each invocation. It starts the filtered proxy, waits for it
to become healthy, runs one ephemeral scanner container, and tears the network
and proxy down afterward:

```powershell
.\run-scanner.ps1 --help
.\run-scanner.ps1 --version
.\run-scanner.ps1 -lu
```

Adult/NSFW modules are included unless you pass `--no-nsfw`. The first real
scan should be an explicitly authorized, narrow module scan. The command below
is an example only; replace the placeholder after deciding to perform the scan:

```powershell
.\run-scanner.ps1 -u 'AUTHORIZED_USERNAME' -m github `
  -f json -o /output/github-result.json
```

For CSV output:

```powershell
.\run-scanner.ps1 -u 'AUTHORIZED_USERNAME' -m github `
  -f csv -o /output/github-result.csv
```


Reports appear in `<data root>\scanner` by default (`SCANNER_OUTPUT` overrides this; the data root is
`$env:OSINT_ROOT` when set, else `%LOCALAPPDATA%\OsintToolkit\data`). Running `docker compose` directly
without the helper falls back to a legacy in-repo folder, so prefer the helper or set the override. JSON and CSV are
supported in this minimal image. PDF extras were intentionally omitted, and
the entrypoint forces `--no-pdf-media` to remove remote-media SSRF exposure.

Do not pass `--allow-loud` or `--cross-scan` casually. Loud modules are skipped
unless `--allow-loud` appears explicitly. Cross-scan runs only when explicitly
requested and can greatly expand the number of identifiers and sites queried.

## Why Compose is the safe invocation

The scanner joins only an `internal: true` Docker network. That network has no
default route. It can reach the `egress-proxy` service on the same subnet, and
nothing else directly. Squid joins both that internal network and a separate
network with public egress.

Squid permits destination ports 80 and 443 and denies:

- IPv4 loopback, RFC1918, carrier-grade NAT, link-local/metadata, benchmarking,
  documentation, multicast, and reserved ranges;
- IPv6 unspecified, loopback, NAT64 well-known prefix, discard-only,
  documentation, ULA, link-local, and multicast ranges;
- `localhost`, `.local`, `host.docker.internal`, and
  `gateway.docker.internal` names.

This was tested on Docker Desktop 29.5.3 for Windows: public HTTP/HTTPS worked
through both `httpx` and `curl_cffi`; every private range listed above was
denied; a hostname resolving to loopback was denied; a public redirect to
`169.254.169.254` was denied; and direct proxy bypass returned “network is
unreachable.”

Your VPN and the Squid filter have complementary jobs:

```text
scanner -> containerized Squid filter -> Docker Desktop -> host VPN -> Internet
```

Docker Desktop normally sends container egress through its host-side backend,
so the VPN should determine the public exit IP. The VPN exit IP/rotation was
not tested here. A VPN alone is not a LAN boundary; the internal network and
Squid ACLs provide that boundary.

Do not use a plain `docker run` for real scans unless you deliberately accept
unfiltered bridge-network access. The image-level filesystem/process
hardening would remain, but LAN filtering would not.

## What was reviewed

The exact runtime wheel is:

```text
user_scanner-1.5.1.3-py3-none-any.whl
SHA256 1716434f26ee7547e0814e6b4eaa5b1b0e34aa7caaf2343031be4cf6e6ffbfcb
```

Matching Git commit (version bump for this release):
`9c970172a0c42c9ea6795a57514649037e030c6a` (`chore: bump version to 1.5.1.3`).
There is no dedicated `v1.5.1.3` Git tag. GitHub `main` may move ahead of this
PyPI wheel with unreleased module commits; this image deliberately ignores
floating `main` and pins only the reviewed PyPI artifact. Module coverage in
this wheel: 188 email + 532 username validators (720 total).

Static findings for the wheel:

- Scanner categories dynamically execute every module file with `importlib`.
  Even module listing imports all modules; validators are not run by listing.
- The only subprocess path found was the self-updater, which called pip to
  uninstall/install the package. It is replaced in this image, update checks
  are disabled, and `-U`/`--update` are rejected by the entrypoint.
- Upstream's packaged config enables update checks by default.
- Upstream's saved loud-module preference is unsafe for this threat model:
  “do not ask again” subsequently permits loud modules. The image replaces
  that policy so only the explicit `--allow-loud` flag can enable them.
- One Myspace validator used `verify=False`. The build removes it and fails if
  any remaining Python source disables certificate verification.
- PDF media export follows result-provided remote image URLs. PDF dependencies
  are omitted and media fetching is forced off.
- The wheel ships MCP server source and a `user-scanner-mcp` console script,
  but the optional `mcp` dependency is not installed, the console script is
  removed at build time, and the entrypoint rejects MCP-oriented arguments.
- No Docker-socket access, host-home discovery, SSH-key or browser-profile
  reads, Windows registry/command execution, unsafe pickle/YAML
  deserialization, or dedicated telemetry client was found.
- The runtime report writes are JSON/CSV paths chosen by the operator. Config
  is redirected to `/tmp` and recreated with update checks disabled on every
  run.

The wheel is pure Python and built with Flit. Installing the wheel does not run
a custom `setup.py` hook.

## Dependency audit

The built runtime contains:

```text
anyio==4.15.1
certifi==2026.7.22
cffi==2.1.1
colorama==0.4.6
curl_cffi==0.16.3
h11==0.16.0
h2==4.4.1
hpack==4.2.0
httpcore==1.0.9
httpx==0.28.1
hyperframe==6.1.0
idna==3.19
markdown-it-py==4.2.0
mdurl==0.1.2
pycparser==3.0
Pygments==2.21.0
rich==15.0.0
socksio==1.0.0
typing-extensions==4.16.0
user-scanner==1.5.1.3
```

`pip check` is required to pass in the built image. Re-run `pip-audit` in a
disposable audit image after each pin. The high-severity redirect-based SSRF
advisory affects `curl_cffi <0.15.0`; this image pins `0.16.3`. Network
filtering is still required because other application paths can fetch remote
URLs.

An external Docker Scout upload/analysis was not authorized, so no claim is
made that the Debian OS layers are free of every CVE. The scanner base is the
official Python 3.13.15 Bookworm slim image pinned to:

```text
sha256:c45a22ea000adfd9cda29364bbe7edd23001ce5cc2ad15857cfbf7766943b9ca
```

The proxy uses Debian Bookworm slim pinned to
`sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`
and Debian security package `squid=5.7-2+deb12u6`.

## Runtime controls validated

The scanner was observed with:

- UID/GID `10001:10001`, no supplementary groups;
- read-only root filesystem and writable tmpfs only at `/tmp`;
- exactly one host bind: the dedicated output directory at `/output`;
- `Privileged=false`, all capability sets zero, and `NoNewPrivs=1`;
- PID limit 128, memory 1 GiB, CPU 2;
- no published ports and no application-owned listening socket;
- only Docker's embedded DNS stub at `127.0.0.11` in the network namespace;
- no Docker socket, host mount tree, home directory, SSH directory, or root SSH
  directory visible;
- writes denied on `/` and accepted only in `/tmp` and `/output`.

The proxy is also non-root (`proxy`), read-only, capability-free,
`NoNewPrivs`, limited to 64 PIDs/256 MiB/0.5 CPU, and has no published port.

## Stop, destroy, and rebuild

The helper tears down runtime containers and networks automatically. To clean
up manually while keeping images and reports:

```powershell
docker compose down --remove-orphans
```

Rebuild every layer from the pinned inputs:

```powershell
docker compose build --pull --no-cache
```

Remove the local images as well (reports remain on the host):

```powershell
docker compose down --remove-orphans
docker image rm user-scanner-hardened:1.5.1.3 user-scanner-egress-proxy:local
```

Delete reports only when intended:

```powershell
Remove-Item -LiteralPath '<data root>\scanner' -Recurse -Force
```

## Updating to a newer pinned scanner release

Upgrades are **manual only**. The container never self-updates: pip upgrade is
disabled in config, `update_self()` is replaced with a hard failure, and
`-U`/`--update` are rejected by the entrypoint. Do not enable
`auto_update_status`, do not install from floating GitHub `main`, and do not
use an unbounded PyPI version range.

For a candidate release, download without installing it into Windows:

```powershell
$Version = 'REVIEWED_VERSION'
New-Item -ItemType Directory -Path '.\candidate' -Force | Out-Null
py -m pip download --only-binary=:all: --no-deps `
  --dest '.\candidate' "user-scanner==$Version"
Get-FileHash -Algorithm SHA256 ".\candidate\user_scanner-$Version-py3-none-any.whl"
```

Then, before changing this image:

1. Extract and statically review the candidate wheel, including all checks
   listed in the original threat model.
2. Compare it with a signed/immutable tag or commit; record any mismatch.
3. Resolve dependencies in a disposable Linux container with binary wheels
   only; pin every version and hash in `requirements.lock`, then re-run
   `shared/build/fetch_wheelhouse.py --tool "User-Scanner Docker" --force`
   (wheels are fetched on demand from PyPI by exact version and sha256; not committed).
4. Require `curl_cffi>=0.15,<1` and prefer the latest audited compatible pin.
5. Run `pip check`, `pip freeze --all`, and current `pip-audit` in a disposable
   audit image.
6. Update the version label/image tag, rebuild, and repeat every harmless,
   runtime-boundary, and network test documented above.

## What this protects—and what it does not

This setup materially limits filesystem access, privilege escalation,
process/resource abuse, accidental persistence, direct LAN/metadata access,
and unreviewed self-mutation. It prevents the scanner from reading the Windows
profile because that profile is never mounted.

It does not make the scanner trustworthy. The process can still send supplied
identifiers and any data it holds to arbitrary public HTTP/HTTPS services. It
can produce target-visible traffic on ordinary modules, and an explicitly
enabled loud module can send reset/verification notifications. Third-party
sites, the VPN provider, DNS path, and the public egress proxy path may log
traffic. Docker/WSL2/kernel/container-runtime vulnerabilities, public-service
compromise, dependency zero-days, and malicious future wheels remain possible.
Treat generated CSV/JSON as untrusted data, especially before opening CSV in a
spreadsheet application.

## Primary references

- [PyPI release metadata for user-scanner](https://pypi.org/pypi/user-scanner/json)
- [curl_cffi redirect-SSRF advisory GHSA-qw2m-4pqf-rmpp](https://github.com/advisories/GHSA-qw2m-4pqf-rmpp)
- [Docker Compose `internal` network reference](https://docs.docker.com/reference/compose-file/networks/#internal)
- [Docker Desktop network/VM security FAQ](https://docs.docker.com/security/faqs/networking-and-vms/)
- [Docker Desktop host-network aliases](https://docs.docker.com/desktop/features/networking/networking-how-tos/#connect-to-a-service-on-the-host)
