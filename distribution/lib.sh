#!/bin/sh

set -eu

umask 077

distribution_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC2034
source_directory=$(CDPATH='' cd -- "$distribution_directory/.." && pwd)
install_root=${DESTDIR:-}

fail() {
    printf 'acmemux distribution: %s\n' "$*" >&2
    exit 1
}

root_path() {
    printf '%s%s\n' "$install_root" "$1"
}

require_root_or_staging() {
    if [ -n "$install_root" ]; then
        case "$install_root" in
            /*) ;;
            *) fail "DESTDIR must be an absolute path" ;;
        esac
        [ "$install_root" != "/" ] || fail "DESTDIR must not be /"
        return
    fi
    [ "$(id -u)" -eq 0 ] || fail "run as root or set an absolute non-root DESTDIR for staging"
}

require_supported_platform() {
    [ -z "$install_root" ] || return 0
    [ -r /etc/os-release ] || fail "Debian 13 amd64 is required"
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
        fail "Debian 13 amd64 is required"
    fi
    [ "$(dpkg --print-architecture 2>/dev/null || true)" = "amd64" ] || fail "Debian 13 amd64 is required"
    command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
}

verify_candidate() {
    candidate=$1
    checksum_file=$2
    if [ ! -f "$candidate" ] || [ -L "$candidate" ] || [ ! -x "$candidate" ]; then
        fail "candidate must be a regular executable, not a symbolic link"
    fi
    if [ ! -f "$checksum_file" ] || [ -L "$checksum_file" ]; then
        fail "checksum file must be a regular file"
    fi
    expected=$(awk 'NF == 2 && $2 == "acmemux" { print $1 }' "$checksum_file")
    case "$expected" in
        *[!0-9a-f]*|'') fail "checksum file does not contain the acmemux SHA-256" ;;
    esac
    [ "${#expected}" -eq 64 ] || fail "checksum file does not contain a complete SHA-256"
    actual=$(sha256sum "$candidate" | awk '{ print $1 }')
    [ "$actual" = "$expected" ] || fail "candidate SHA-256 does not match the release checksum"
}

atomic_install() {
    source=$1
    destination=$2
    mode=$3
    parent=$(dirname -- "$destination")
    mkdir -p -- "$parent"
    temporary=$(mktemp "$destination.next.XXXXXX")
    trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
    if [ -n "$install_root" ]; then
        install -m "$mode" -- "$source" "$temporary"
    else
        install -o root -g root -m "$mode" -- "$source" "$temporary"
    fi
    mv -f -- "$temporary" "$destination"
    trap - EXIT HUP INT TERM
}

validate_identity_name() {
    value=$1
    label=$2
    printf '%s' "$value" | grep -Eq '^[a-z_][a-z0-9_-]{0,30}$' || fail "$label is not a bounded system identity name"
}

validate_public_origin() {
    value=$1
    printf '%s' "$value" | grep -Eq '^https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$' || fail "--public-origin must be one canonical HTTPS origin without a path"
}

validate_trusted_proxies() {
    value=$1
    printf '%s' "$value" | grep -Eq '^[0-9A-Fa-f:.,/]*$' || fail "--trusted-proxies contains unsafe characters"
}
