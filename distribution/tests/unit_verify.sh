#!/bin/sh

set -eu

application_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
temporary_unit=$(mktemp /tmp/acmemux-unit-verify.XXXXXX.service)
trap 'rm -f -- "$temporary_unit"' EXIT HUP INT TERM

sed \
    -e "s|User=acmemux|User=$(id -un)|" \
    -e "s|Group=acmemux|Group=$(id -gn)|" \
    -e "s|EnvironmentFile=/etc/acmemux/acmemux.env|EnvironmentFile=-/etc/acmemux/acmemux.env|" \
    -e "s|ExecStart=/usr/local/bin/acmemux serve|ExecStart=$application_directory/dist/acmemux serve --state-dir /var/lib/acmemux --public-origin https://acmemux.example.test|" \
    "$application_directory/distribution/systemd/acmemux.service" >"$temporary_unit"

systemd-analyze verify "$temporary_unit"
