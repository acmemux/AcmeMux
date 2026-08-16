#!/bin/sh

set -eu

application_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

if [ ! -r /etc/os-release ]; then
    printf '%s\n' 'SKIP: native install smoke requires Debian 13 amd64'
    exit 0
fi
# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ] || \
    [ "$(dpkg --print-architecture 2>/dev/null || true)" != "amd64" ]; then
    printf '%s\n' 'SKIP: native install smoke is qualified only on Debian 13 amd64'
    exit 0
fi
sudo -n true >/dev/null 2>&1 || {
    printf '%s\n' 'passwordless sudo is required for the native install smoke' >&2
    exit 1
}

for path in \
    /usr/local/bin/acmemux \
    /usr/local/share/doc/acmemux \
    /etc/acmemux \
    /etc/systemd/system/acmemux.service \
    /etc/systemd/system/acmemux.service.d \
    /var/lib/acmemux; do
    if sudo -n test -e "$path"; then
        printf 'SKIP: native install smoke will not disturb existing path %s\n' "$path"
        exit 0
    fi
done

workspace_directory=$(mktemp -d "$(getent passwd "$(id -u)" | cut -d: -f6)/acmemux-install-workspace.XXXXXX")
printf '%s\n' workspace-preserved >"$workspace_directory/native-marker"

cleanup() {
    sudo -n "$application_directory/distribution/remove.sh" >/dev/null 2>&1 || true
    for created_path in /etc/acmemux /var/lib/acmemux; do
        if sudo -n test -e "$created_path"; then
            sudo -n find "$created_path" -depth -delete
        fi
    done
    case "$workspace_directory" in */acmemux-install-workspace.*) rm -rf -- "$workspace_directory" ;; esac
}
trap cleanup EXIT HUP INT TERM

sudo -n "$application_directory/distribution/install.sh" \
    --public-origin https://acmemux.example.test \
    --service-user "$(id -un)" \
    --service-group "$(id -gn)"
test "$(systemctl show --property=User --value acmemux.service)" = "$(id -un)"
test "$(systemctl show --property=ActiveState --value acmemux.service)" = active
curl --fail --silent --show-error http://127.0.0.1:8080/readyz | grep -F '"ready"' >/dev/null
sudo -n test -f /var/lib/acmemux/acmemux.db
sudo -n test -f /etc/acmemux/acmemux.env
grep -Fx workspace-preserved "$workspace_directory/native-marker" >/dev/null

sudo -n "$application_directory/distribution/remove.sh"
sudo -n test -f /var/lib/acmemux/acmemux.db
sudo -n test -f /etc/acmemux/acmemux.env

sudo -n "$application_directory/distribution/install.sh" \
    --service-user "$(id -un)" \
    --service-group "$(id -gn)"
curl --fail --silent --show-error http://127.0.0.1:8080/readyz | grep -F '"ready"' >/dev/null
grep -Fx workspace-preserved "$workspace_directory/native-marker" >/dev/null
