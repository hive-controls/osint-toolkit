#!/bin/sh
set -eu
# Require full Tor bootstrap before marking the sidecar healthy.
printf 'AUTHENTICATE\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' \
  | nc -w 2 127.0.0.1 9051 \
  | grep -q 'PROGRESS=100'
