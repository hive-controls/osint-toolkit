# Maigret hardened Docker

## Outcome

Provide a pin-locked Maigret 0.6.4 runtime that:

- can only talk to a Squid sidecar on an internal Compose network;
- refuses `--web`, `--force-update`, `--tor-proxy`, and `--i2p-proxy`;
- always uses `--no-autoupdate`, `--proxy http://egress-proxy:3128`, and `--folderoutput /output`;
- blocks searches unless a host VPN adapter or approved proxy passes a probe and the operator types `RUN`.

Maigret runs entirely from this image. The runner binds `/output` to `<data root>\maigret` (or `MAIGRET_OUTPUT`, which may select a case folder); Compose alone falls back to a legacy in-repo folder.

## Networks

- `maigret-internal` (`internal: true`): `maigret` ↔ `egress-proxy:3128`
- `proxy-egress`: Squid only

No published ports.

## Pins

- App: `maigret==0.6.4` wheel SHA256 `ac7169d74c4997ab7f4b42b4ed64ba2436ebde57ad2258b1e682baa350948d51`
- Python base: `python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254`
- Squid base: `debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171`
- Squid package: `5.7-2+deb12u6`

PDF extras (xhtml2pdf/cairo) are omitted. Upgrades are manual only.
