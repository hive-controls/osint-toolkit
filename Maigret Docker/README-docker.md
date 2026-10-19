# Hardened Docker setup for Maigret 0.6.4

> **Start here for day-to-day use:** [`README.md`](./README.md).

This workspace builds a hash-pinned `maigret==0.6.4` image and a Squid sidecar.
The Maigret container has **no default route**; it can only reach
`egress-proxy:3128` on an internal Compose network.

Upgrades are **manual only**. Site-DB auto-update (`--force-update`), the web UI
(`--web`), and Tor/I2P proxy flags are rejected by the entrypoint.

## Why Compose

```text
maigret (internal only) --http--> egress-proxy:3128 --filtered--> Internet
```

- Maigret joins only `maigret-internal` (`internal: true`).
- Squid joins `maigret-internal` and `proxy-egress`.
- Port 3128 is **not** published to Windows.

## What was reviewed

```text
maigret-0.6.4-py3-none-any.whl
SHA256 ac7169d74c4997ab7f4b42b4ed64ba2436ebde57ad2258b1e682baa350948d51
```

PyPI `maigret==0.6.4`, fetched on demand from PyPI by exact version and sha256; not committed. No sibling checkout is required. Upstream Dockerfile
is not used (unpinned, root, `--web` on `0.0.0.0`).

PDF extras (`xhtml2pdf` / cairo) are omitted. Graph HTML (`-G`) and JSON/MD/HTML
reports stay.

## Updating

Never float on GitHub `main` or `pip install -U maigret`. Refresh
`requirements.lock` hashes from a reviewed wheel set, re-run
`python -I shared/build/fetch_wheelhouse.py --tool "Maigret Docker" --force`,
rebuild images, and re-run `--version` plus a `--help` smoke.

The generator used for this pin:

```text
docker run --rm -v "${PWD}/artifacts:/out" python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 python /out/_gen_lock.py
```

(`artifacts/_gen_lock.py` after `pip download maigret==0.6.4 --only-binary=:all:`.)
