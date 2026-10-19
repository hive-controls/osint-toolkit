# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.lock /build/requirements.lock
COPY artifacts/wheelhouse/ /build/wheelhouse/
COPY pyproject.toml /build/pyproject.toml
COPY src /build/src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
        --no-index \
        --only-binary=:all: \
        --require-hashes \
        --find-links=/build/wheelhouse \
        --requirement /build/requirements.lock \
    && /opt/venv/bin/python -m pip install \
        --no-deps \
        --no-index \
        --no-build-isolation \
        --find-links=/build/wheelhouse \
        /build \
    && /opt/venv/bin/python -m pip uninstall -y setuptools \
    && /opt/venv/bin/python -c "from importlib.metadata import version; assert version('phone-lookup')=='0.1.0'"

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

LABEL org.opencontainers.image.title="phone-lookup-hardened" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.description="Local numbering-plan parse plus optional Numverify and breach APIs"

ENV PATH=/opt/venv/bin:$PATH \
    HOME=/tmp/home \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHONE_LOOKUP_OUTPUT=/output \
    PHONE_LOOKUP_TERMS_DIR=/opt/provider-terms \
    HTTP_PROXY=http://egress-proxy:3128 \
    HTTPS_PROXY=http://egress-proxy:3128 \
    ALL_PROXY=http://egress-proxy:3128 \
    NO_PROXY=localhost,127.0.0.1

RUN groupadd --gid 10001 phonelookup \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin phonelookup \
    && install -d -o phonelookup -g phonelookup -m 0700 /output

COPY --from=builder /opt/venv /opt/venv
COPY hardening/entrypoint.sh /usr/local/bin/phone-lookup-hardened
COPY PROVIDER-TERMS/ /opt/provider-terms/

RUN chmod 0555 /usr/local/bin/phone-lookup-hardened \
    && find /opt/venv -type d -exec chmod a-w {} + \
    && find /opt/venv -type f -exec chmod a-w {} +

USER 10001:10001
WORKDIR /output

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/phone-lookup-hardened"]
