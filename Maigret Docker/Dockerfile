# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.lock /build/requirements.lock
COPY artifacts/wheelhouse/ /build/wheelhouse/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
        --no-index \
        --only-binary=:all: \
        --require-hashes \
        --find-links=/build/wheelhouse \
        --requirement /build/requirements.lock \
    && /opt/venv/bin/python -m pip check \
    && /opt/venv/bin/python -c "from importlib.metadata import version; v=version('maigret'); assert v=='0.6.4', v"

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

LABEL org.opencontainers.image.title="maigret-hardened" \
      org.opencontainers.image.version="0.6.4" \
      org.opencontainers.image.source="https://github.com/soxoj/maigret" \
      org.opencontainers.image.description="Locally hardened, hash-pinned maigret runtime"

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/tmp/home \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    XDG_CACHE_HOME=/tmp/cache \
    XDG_CONFIG_HOME=/tmp/config
# No HTTP(S)_PROXY env here: see compose.yaml. The entrypoint's --proxy is the only
# proxy setting; stacking env proxies double-tunnels and Squid rejects it.

RUN groupadd --gid 10001 maigret \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin maigret \
    && install -d -o maigret -g maigret -m 0700 /output

COPY --from=builder /opt/venv /opt/venv
COPY hardening/entrypoint.sh /usr/local/bin/maigret-hardened

RUN chmod 0555 /usr/local/bin/maigret-hardened \
    && find /opt/venv -type d -exec chmod a-w {} + \
    && find /opt/venv -type f -exec chmod a-w {} +

USER 10001:10001
WORKDIR /output

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/maigret-hardened"]
