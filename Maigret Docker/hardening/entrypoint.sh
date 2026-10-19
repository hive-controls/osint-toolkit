#!/bin/sh
set -eu

umask 077

# Fail closed on disallowed flags. Egress is forced through the Squid sidecar.
filtered=""
skip_next=0
for argument in "$@"; do
    if [ "$skip_next" -eq 1 ]; then
        skip_next=0
        continue
    fi
    case "$argument" in
        --web|--web=*)
            echo "The Maigret web UI is disabled in the hardened image (CLI reports only)." >&2
            exit 64
            ;;
        --force-update)
            echo "Site-DB auto-update is disabled. Rebuild the pinned image instead." >&2
            exit 64
            ;;
        --tor-proxy|--tor-proxy=*|--i2p-proxy|--i2p-proxy=*)
            echo "Tor/I2P proxies are disabled here. Clearnet Maigret uses the Squid sidecar only." >&2
            exit 64
            ;;
        --proxy|-p)
            skip_next=1
            continue
            ;;
        --proxy=*|-p=*)
            continue
            ;;
        --folderoutput|-fo)
            skip_next=1
            continue
            ;;
        --folderoutput=*|-fo=*)
            continue
            ;;
        --db)
            skip_next=1
            continue
            ;;
        --db=*)
            continue
            ;;
        --no-autoupdate)
            continue
            ;;
    esac
    filtered="$filtered $argument"
done

# shellcheck disable=SC2086
set -- $filtered

if [ "$#" -eq 0 ]; then
    set -- --help
fi

# Maigret writes its site DB back after every run; the image is read-only, so work
# from a per-run copy of the pinned DB in tmpfs (discarded with the container).
runtime_db=/tmp/maigret-data.json
cp "$(/opt/venv/bin/python -c 'import maigret, os; print(os.path.join(os.path.dirname(maigret.__file__), "resources", "data.json"))')" "$runtime_db"
# cp keeps the image's read-only mode; maigret must be able to rewrite its copy.
chmod 0600 "$runtime_db"

exec /opt/venv/bin/maigret \
    --no-autoupdate \
    --db "$runtime_db" \
    --proxy http://egress-proxy:3128 \
    --folderoutput /output \
    "$@"
