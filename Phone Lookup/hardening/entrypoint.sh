#!/bin/sh
set -eu
umask 077

if [ "$#" -eq 0 ]; then
    set -- --help
fi

exec /opt/venv/bin/phone-lookup "$@"
