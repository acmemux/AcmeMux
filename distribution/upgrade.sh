#!/bin/sh

set -eu

distribution_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=distribution/lib.sh
. "$distribution_directory/lib.sh"

candidate=$source_directory/dist/acmemux
checksum_file=$source_directory/dist/acmemux.sha256

usage() {
    cat <<'EOF'
Usage: sudo distribution/upgrade.sh [options]

Build and verify the new source revision before running this command. Preserve
a matching pre-upgrade state backup and the prior source revision separately.

Options:
  --binary PATH    source-built AcmeMux executable
  --checksum PATH  SHA-256 file produced by make distribution
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) [ "$#" -ge 2 ] || fail "--binary requires a value"; candidate=$2; shift 2 ;;
        --checksum) [ "$#" -ge 2 ] || fail "--checksum requires a value"; checksum_file=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

require_root_or_staging
require_supported_platform
verify_candidate "$candidate" "$checksum_file"

binary_path=$(root_path /usr/local/bin/acmemux)
unit_path=$(root_path /etc/systemd/system/acmemux.service)
environment_path=$(root_path /etc/acmemux/acmemux.env)
identity_path=$(root_path /etc/systemd/system/acmemux.service.d/identity.conf)

if [ ! -f "$binary_path" ] || [ -L "$binary_path" ]; then
    fail "AcmeMux is not installed"
fi
if [ ! -f "$environment_path" ] || [ ! -f "$identity_path" ]; then
    fail "installed service configuration is incomplete"
fi

binary_parent=$(dirname -- "$binary_path")
next_binary=$(mktemp "$binary_parent/acmemux.next.XXXXXX")
trap 'rm -f -- "$next_binary"' EXIT HUP INT TERM
if [ -n "$install_root" ]; then
    install -m 0755 -- "$candidate" "$next_binary"
else
    install -o root -g root -m 0755 -- "$candidate" "$next_binary"
fi
[ "$(sha256sum "$next_binary" | awk '{ print $1 }')" = "$(sha256sum "$candidate" | awk '{ print $1 }')" ] || fail "staged upgrade executable changed during installation"

if [ -z "$install_root" ]; then
    systemctl stop acmemux.service
fi
mv -f -- "$next_binary" "$binary_path"
trap - EXIT HUP INT TERM
atomic_install "$distribution_directory/systemd/acmemux.service" "$unit_path" 0644

if [ -z "$install_root" ]; then
    systemd-analyze verify "$unit_path"
    systemctl daemon-reload
    if ! systemctl start acmemux.service; then
        printf '%s\n' "AcmeMux did not start. Do not downgrade against migrated state; inspect the journal and use the documented matching state-and-executable recovery boundary." >&2
        exit 1
    fi
    printf '%s\n' "AcmeMux was upgraded and is ready."
else
    printf '%s\n' "AcmeMux staged installation was upgraded under $install_root."
fi
