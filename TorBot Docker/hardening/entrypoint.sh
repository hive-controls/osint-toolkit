#!/bin/sh
set -eu

umask 077

# Fail closed on disallowed flags. SOCKS is forced to the compose Tor sidecar.
filtered=""
skip_next=0
for argument in "$@"; do
    if [ "$skip_next" -eq 1 ]; then
        skip_next=0
        continue
    fi
    case "$argument" in
        --update|-U)
            echo "Self-update is disabled. Rebuild the pinned image instead." >&2
            exit 64
            ;;
        --disable-socks5)
            echo "Clearnet mode is disabled. Tor SOCKS is mandatory in the hardened image." >&2
            exit 64
            ;;
        --app)
            echo "TorBotApp/desktop UI is not included in the hardened image." >&2
            exit 64
            ;;
        --host)
            # Drop operator-supplied host; forced below.
            skip_next=1
            continue
            ;;
        --host=*)
            continue
            ;;
        --port)
            skip_next=1
            continue
            ;;
        --port=*)
            continue
            ;;
        --allow-remote)
            echo "Remote AI providers are disabled in the hardened image." >&2
            exit 64
            ;;
    esac
    filtered="$filtered $argument"
done

# shellcheck disable=SC2086
set -- $filtered

if [ "$#" -eq 0 ]; then
    set -- --help
fi

exec /opt/venv/bin/torbot --host tor --port 9050 "$@"
