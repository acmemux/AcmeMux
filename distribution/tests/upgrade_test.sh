#!/bin/sh

set -eu

application_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
staging_directory=$(mktemp -d)
workspace_directory=$(mktemp -d)

cleanup() {
    case "$staging_directory" in /tmp/*) rm -rf -- "$staging_directory" ;; esac
    case "$workspace_directory" in /tmp/*) rm -rf -- "$workspace_directory" ;; esac
}
trap cleanup EXIT HUP INT TERM

DESTDIR=$staging_directory "$application_directory/distribution/install.sh" \
    --public-origin https://acmemux.example.test
mkdir -p "$staging_directory/var/lib/acmemux"
printf '%s\n' state-preserved >"$staging_directory/var/lib/acmemux/state-marker"
printf '%s\n' workspace-preserved >"$workspace_directory/native-marker"
configuration_hash=$(sha256sum "$staging_directory/etc/acmemux/acmemux.env" | awk '{ print $1 }')
installed_hash=$(sha256sum "$staging_directory/usr/local/bin/acmemux" | awk '{ print $1 }')

bad_checksum=$(mktemp)
trap 'rm -f -- "$bad_checksum"; cleanup' EXIT HUP INT TERM
printf '%064d  acmemux\n' 0 >"$bad_checksum"
if DESTDIR=$staging_directory "$application_directory/distribution/upgrade.sh" \
    --checksum "$bad_checksum" >/dev/null 2>&1; then
    printf '%s\n' 'upgrade accepted a mismatched checksum' >&2
    exit 1
fi
test "$(sha256sum "$staging_directory/usr/local/bin/acmemux" | awk '{ print $1 }')" = "$installed_hash"

DESTDIR=$staging_directory "$application_directory/distribution/upgrade.sh"
test "$(sha256sum "$staging_directory/etc/acmemux/acmemux.env" | awk '{ print $1 }')" = "$configuration_hash"
grep -Fx state-preserved "$staging_directory/var/lib/acmemux/state-marker" >/dev/null
grep -Fx workspace-preserved "$workspace_directory/native-marker" >/dev/null

rm -f -- "$bad_checksum"
trap cleanup EXIT HUP INT TERM
