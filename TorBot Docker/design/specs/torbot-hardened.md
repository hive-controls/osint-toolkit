# TorBot hardened Docker

## Outcome

Provide a pin-locked TorBot 4.3.0 runtime that:

- can only talk to a Tor SOCKS sidecar on an internal Compose network;
- refuses clearnet (`--disable-socks5`), self-update, and desktop UI flags;
- blocks crawls unless a host VPN adapter or approved proxy passes an automated probe and the operator types `RUN`.

## Networks

- `torbot-internal` (`internal: true`): `torbot` ↔ `tor:9050`
- `tor-egress`: Tor daemon only

No published ports. Do not use bare `docker run` for real crawls.

## Gate

1. Automated: VPN name allowlist match (adapter Up) **or** TCP reachability to configured/env proxy.
2. Typed: exact `RUN`.

Informational `--help` / `--version` may skip the host VPN probe in `run-torbot.ps1`.

## Pins

- App: `torbot==4.3.0` wheel SHA256 `e5db3109a201a1cc197f75c9903ddce0cd265affb72faa97ee370920d381a160`
- Python base: `python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254`
- Tor base: `debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`
- Tor package: `0.4.9.11-0+deb12u1`

Upgrades are manual only.
