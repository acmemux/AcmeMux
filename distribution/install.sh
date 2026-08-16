#!/bin/sh

set -eu

distribution_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=distribution/lib.sh
. "$distribution_directory/lib.sh"

candidate=$source_directory/dist/acmemux
checksum_file=$source_directory/dist/acmemux.sha256
public_origin=
trusted_proxies=127.0.0.1/32,::1/128
service_user=acmemux
service_group=acmemux

usage() {
    cat <<'EOF'
Usage: sudo distribution/install.sh --public-origin https://acmemux.example.net [options]

Options:
  --binary PATH          source-built AcmeMux executable
  --checksum PATH        SHA-256 file produced by make distribution
  --public-origin URL    exact HTTPS browser origin (required for first install)
  --trusted-proxies LIST comma-separated loopback proxy addresses or CIDRs
  --service-user NAME    existing service user, or acmemux to create the default
  --service-group NAME   existing service group, or acmemux with the default user
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) [ "$#" -ge 2 ] || fail "--binary requires a value"; candidate=$2; shift 2 ;;
        --checksum) [ "$#" -ge 2 ] || fail "--checksum requires a value"; checksum_file=$2; shift 2 ;;
        --public-origin) [ "$#" -ge 2 ] || fail "--public-origin requires a value"; public_origin=$2; shift 2 ;;
        --trusted-proxies) [ "$#" -ge 2 ] || fail "--trusted-proxies requires a value"; trusted_proxies=$2; shift 2 ;;
        --service-user) [ "$#" -ge 2 ] || fail "--service-user requires a value"; service_user=$2; shift 2 ;;
        --service-group) [ "$#" -ge 2 ] || fail "--service-group requires a value"; service_group=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

require_root_or_staging
require_supported_platform
validate_trusted_proxies "$trusted_proxies"
validate_identity_name "$service_user" "service user"
validate_identity_name "$service_group" "service group"
verify_candidate "$candidate" "$checksum_file"

binary_path=$(root_path /usr/local/bin/acmemux)
unit_path=$(root_path /etc/systemd/system/acmemux.service)
environment_path=$(root_path /etc/acmemux/acmemux.env)
identity_path=$(root_path /etc/systemd/system/acmemux.service.d/identity.conf)
example_path=$(root_path /usr/local/share/doc/acmemux/acmemux.env.example)

if [ -e "$binary_path" ] || [ -e "$unit_path" ]; then
    fail "AcmeMux is already installed; use distribution/upgrade.sh"
fi
if [ -e "$environment_path" ]; then
    if [ ! -f "$environment_path" ] || [ -L "$environment_path" ]; then
        fail "preserved service configuration must be a regular file, not a symbolic link"
    fi
else
    [ -n "$public_origin" ] || fail "--public-origin is required for a first installation"
    validate_public_origin "$public_origin"
fi

if [ -z "$install_root" ]; then
    if ! getent group "$service_group" >/dev/null; then
        [ "$service_group" = "acmemux" ] || fail "service group does not exist: $service_group"
        groupadd --system "$service_group"
    fi
    if ! id "$service_user" >/dev/null 2>&1; then
        [ "$service_user" = "acmemux" ] || fail "service user does not exist: $service_user"
        useradd --system --gid "$service_group" --home-dir /var/lib/acmemux --shell /usr/sbin/nologin "$service_user"
    fi
    [ "$(id -u "$service_user")" -ne 0 ] || fail "the service user must not be root"
    id -nG "$service_user" | tr ' ' '\n' | grep -Fx "$service_group" >/dev/null || fail "service user is not a member of service group"
fi

atomic_install "$candidate" "$binary_path" 0755
atomic_install "$distribution_directory/systemd/acmemux.service" "$unit_path" 0644
atomic_install "$distribution_directory/systemd/acmemux.env.example" "$example_path" 0644

identity_temporary=$(mktemp)
trap 'rm -f -- "$identity_temporary"' EXIT HUP INT TERM
if [ ! -e "$environment_path" ]; then
    environment_temporary=$(mktemp)
    trap 'rm -f -- "$environment_temporary" "$identity_temporary"' EXIT HUP INT TERM
    cat >"$environment_temporary" <<EOF
ACMEMUX_LISTEN_ADDRESS=127.0.0.1:8080
ACMEMUX_STATE_DIRECTORY=/var/lib/acmemux
ACMEMUX_PUBLIC_ORIGIN=$public_origin
ACMEMUX_TRUSTED_PROXIES=$trusted_proxies
EOF
    atomic_install "$environment_temporary" "$environment_path" 0640
    rm -f -- "$environment_temporary"
fi
cat >"$identity_temporary" <<EOF
[Service]
User=$service_user
Group=$service_group
EOF
atomic_install "$identity_temporary" "$identity_path" 0644
rm -f -- "$identity_temporary"
trap - EXIT HUP INT TERM

if [ -z "$install_root" ]; then
    systemd-analyze verify "$unit_path"
    systemctl daemon-reload
    systemctl enable --now acmemux.service
    printf '%s\n' "AcmeMux is installed and running. Bootstrap the administrator locally as $service_user."
else
    printf '%s\n' "AcmeMux staged under $install_root."
fi
