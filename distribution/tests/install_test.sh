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

printf '%s\n' workspace-preserved >"$workspace_directory/native-marker"
DESTDIR=$staging_directory "$application_directory/distribution/install.sh" \
    --public-origin https://acmemux.example.test \
    --service-user existing-operator \
    --service-group existing-operator

test -x "$staging_directory/usr/local/bin/acmemux"
test -f "$staging_directory/etc/systemd/system/acmemux.service"
test -f "$staging_directory/etc/systemd/system/acmemux.service.d/identity.conf"
test -f "$staging_directory/etc/acmemux/acmemux.env"
test "$(stat -c %a "$staging_directory/etc/acmemux/acmemux.env")" = 640
grep -Fx 'ACMEMUX_PUBLIC_ORIGIN=https://acmemux.example.test' "$staging_directory/etc/acmemux/acmemux.env" >/dev/null
grep -Fx 'User=existing-operator' "$staging_directory/etc/systemd/system/acmemux.service.d/identity.conf" >/dev/null
grep -Fx 'Type=notify' "$staging_directory/etc/systemd/system/acmemux.service" >/dev/null
grep -Fx 'NoNewPrivileges=yes' "$staging_directory/etc/systemd/system/acmemux.service" >/dev/null
grep -Fx 'CapabilityBoundingSet=' "$staging_directory/etc/systemd/system/acmemux.service" >/dev/null
configuration_hash=$(sha256sum "$staging_directory/etc/acmemux/acmemux.env" | awk '{ print $1 }')

if DESTDIR=$staging_directory "$application_directory/distribution/install.sh" \
    --public-origin https://acmemux.example.test >/dev/null 2>&1; then
    printf '%s\n' 'second fresh installation unexpectedly succeeded' >&2
    exit 1
fi

DESTDIR=$staging_directory "$application_directory/distribution/remove.sh"
test ! -e "$staging_directory/usr/local/bin/acmemux"
test ! -e "$staging_directory/etc/systemd/system/acmemux.service"
test -f "$staging_directory/etc/acmemux/acmemux.env"
grep -Fx workspace-preserved "$workspace_directory/native-marker" >/dev/null

DESTDIR=$staging_directory "$application_directory/distribution/install.sh" \
    --service-user existing-operator \
    --service-group existing-operator
test "$(sha256sum "$staging_directory/etc/acmemux/acmemux.env" | awk '{ print $1 }')" = "$configuration_hash"
grep -Fx workspace-preserved "$workspace_directory/native-marker" >/dev/null

if find "$application_directory/distribution" -type f \( -name '*.deb' -o -name '*.rpm' -o -name 'Dockerfile*' -o -name '*compose*.yml' \) | grep -q .; then
    printf '%s\n' 'unsupported package or container artifact found' >&2
    exit 1
fi
