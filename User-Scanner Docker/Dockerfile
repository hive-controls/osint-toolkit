# syntax=docker/dockerfile:1.7
FROM python:3.13-slim-bookworm@sha256:c45a22ea000adfd9cda29364bbe7edd23001ce5cc2ad15857cfbf7766943b9ca AS builder

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
    && /opt/venv/bin/python -m pip check

COPY hardening/loud_prompt.py /opt/venv/lib/python3.13/site-packages/user_scanner/core/loud_prompt.py
COPY hardening/update.py /opt/venv/lib/python3.13/site-packages/user_scanner/utils/update.py

# The published 1.5.1.3 wheel still contains one verify=False call in the Myspace
# module. Remove it, then fail the build if any Python source still disables TLS.
RUN sed -i 's/, verify=False)/)/' /opt/venv/lib/python3.13/site-packages/user_scanner/user_scan/music/myspace.py \
    && ! grep -R --include='*.py' -E 'verify[[:space:]]*=[[:space:]]*False|CERT_NONE|check_hostname[[:space:]]*=[[:space:]]*False' /opt/venv/lib/python3.13/site-packages/user_scanner \
    && rm -f /opt/venv/bin/user-scanner-mcp \
    && /opt/venv/bin/python -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('mcp') is None else 1)"

FROM python:3.13-slim-bookworm@sha256:c45a22ea000adfd9cda29364bbe7edd23001ce5cc2ad15857cfbf7766943b9ca

LABEL org.opencontainers.image.title="user-scanner-hardened" \
      org.opencontainers.image.version="1.5.1.3" \
      org.opencontainers.image.source="https://github.com/kaifcodec/user-scanner" \
      org.opencontainers.image.description="Locally hardened, hash-pinned user-scanner runtime"

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    USER_SCANNER_CONFIG=/tmp/user-scanner/config.json \
    XDG_CACHE_HOME=/tmp/cache

RUN groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin scanner \
    && install -d -o scanner -g scanner -m 0700 /output /opt/user-scanner

COPY --from=builder /opt/venv /opt/venv
COPY hardening/config.json /opt/user-scanner/config.json
COPY hardening/entrypoint.sh /usr/local/bin/user-scanner-hardened

RUN chmod 0555 /usr/local/bin/user-scanner-hardened \
    && chmod 0444 /opt/user-scanner/config.json \
    && find /opt/venv -type d -exec chmod a-w {} + \
    && find /opt/venv -type f -exec chmod a-w {} +

USER 10001:10001
WORKDIR /output

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/user-scanner-hardened"]
