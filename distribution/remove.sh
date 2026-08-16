#!/bin/sh

set -eu

distribution_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=distribution/lib.sh
. "$distribution_directory/lib.sh"

[ "$#" -eq 0 ] || fail "remove.sh accepts no options; application state and the service identity are always preserved"
require_root_or_staging

binary_path=$(root_path /usr/local/bin/acmemux)
unit_path=$(root_path /etc/systemd/system/acmemux.service)
dropin_directory=$(root_path /etc/systemd/system/acmemux.service.d)
example_path=$(root_path /usr/local/share/doc/acmemux/acmemux.env.example)

if [ -z "$install_root" ]; then
    systemctl disable --now acmemux.service 2>/dev/null || true
fi
rm -f -- "$binary_path" "$unit_path" "$dropin_directory/identity.conf" "$example_path"
rmdir -- "$dropin_directory" 2>/dev/null || true
rmdir -- "$(dirname -- "$example_path")" 2>/dev/null || true

if [ -z "$install_root" ]; then
    systemctl daemon-reload
    systemctl reset-failed acmemux.service 2>/dev/null || true
fi

printf '%s\n' "AcmeMux executable and service assets were removed. /etc/acmemux, /var/lib/acmemux, the service identity, and every adopted lego workspace were preserved."
