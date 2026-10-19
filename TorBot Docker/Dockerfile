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
    && /opt/venv/bin/python -m pip uninstall -y \
        pyinstaller \
        pyinstaller-hooks-contrib \
        pytest \
        pluggy \
        iniconfig \
        packaging \
        pygments \
        setuptools \
    && /opt/venv/bin/python -c "import importlib.util,sys; sys.exit(1 if importlib.util.find_spec('PyInstaller') or importlib.util.find_spec('pytest') else 0)" \
    && /opt/venv/bin/python -c "import torbot; print('torbot-import-ok')"

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

LABEL org.opencontainers.image.title="torbot-hardened" \
      org.opencontainers.image.version="4.3.0" \
      org.opencontainers.image.source="https://github.com/DedSecInside/TorBot" \
      org.opencontainers.image.description="Locally hardened, hash-pinned TorBot runtime (Tor SOCKS mandatory)"

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    XDG_CACHE_HOME=/tmp/cache

RUN groupadd --gid 10002 torbot \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin torbot \
    && install -d -o torbot -g torbot -m 0700 /output

COPY --from=builder /opt/venv /opt/venv
COPY hardening/entrypoint.sh /usr/local/bin/torbot-hardened

RUN chmod 0555 /usr/local/bin/torbot-hardened \
    && find /opt/venv -type d -exec chmod a-w {} + \
    && find /opt/venv -type f -exec chmod a-w {} +

USER 10002:10002
WORKDIR /output

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/torbot-hardened"]
