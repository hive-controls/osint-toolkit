#!/bin/sh
set -eu

umask 077

config_dir=$(dirname "$USER_SCANNER_CONFIG")
mkdir -p "$config_dir"
cp /opt/user-scanner/config.json "$USER_SCANNER_CONFIG"

for argument in "$@"; do
    case "$argument" in
        -U|--update)
            echo "Self-update is disabled. Rebuild the pinned image instead." >&2
            exit 64
            ;;
        --hu*)
            if [ "${SCANNER_HUDSON_ALLOWED:-}" != "1" ]; then
                echo "--hudson is blocked: Hudson Rock is opt-in. Enable it with phone-lookup --enable hudson_rock (see Phone Lookup/PROVIDERS.md)." >&2
                exit 64
            fi
            ;;
        --mcp|user-scanner-mcp)
            echo "MCP server support is not included in the hardened image." >&2
            exit 64
            ;;
    esac
done

if [ "$#" -eq 0 ]; then
    set -- --help
fi

# Remote PDF media URLs are an unnecessary SSRF surface. JSON and CSV exports
# are fully supported; PDF media stays disabled even if PDF extras are added.
# Auto-update stays off via /opt/user-scanner/config.json; never pip-upgrade here.
exec /opt/venv/bin/user-scanner "$@" --no-pdf-media
