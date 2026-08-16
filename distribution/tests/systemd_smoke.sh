#!/bin/sh

set -eu

application_directory=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
binary=$application_directory/dist/acmemux

if [ ! -r /etc/os-release ]; then
    printf '%s\n' 'SKIP: native systemd smoke requires Debian 13 amd64'
    exit 0
fi
# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ] || \
    [ "$(dpkg --print-architecture 2>/dev/null || true)" != "amd64" ]; then
    printf '%s\n' 'SKIP: native systemd smoke is qualified only on Debian 13 amd64'
    exit 0
fi
systemctl is-system-running >/dev/null 2>&1 || {
    printf '%s\n' 'systemd is not running on the qualified platform' >&2
    exit 1
}
sudo -n true >/dev/null 2>&1 || {
    printf '%s\n' 'passwordless sudo is required for the native systemd smoke' >&2
    exit 1
}

smoke_parent=$(getent passwd "$(id -u)" | cut -d: -f6)
case "$smoke_parent" in /*) ;; *) printf '%s\n' 'test identity has no absolute home directory' >&2; exit 1 ;; esac
temporary_directory=$(mktemp -d "$smoke_parent/acmemux-systemd-smoke.XXXXXX")
unit_base=acmemux-source-smoke-$$
unit=$unit_base.service
port=$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)

cleanup() {
    sudo -n systemctl stop "$unit" >/dev/null 2>&1 || true
    sudo -n systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    case "$temporary_directory" in "$smoke_parent"/acmemux-systemd-smoke.*) rm -rf -- "$temporary_directory" ;; esac
}
trap cleanup EXIT HUP INT TERM

start_service() {
    sudo -n systemd-run --unit="$unit" --service-type=notify \
        --uid="$(id -u)" --gid="$(id -g)" \
        --property=NoNewPrivileges=yes \
        --property=PrivateDevices=yes \
        --property=PrivateTmp=yes \
        --property=ProtectSystem=full \
        --property=CapabilityBoundingSet= \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
        --property=TimeoutStartSec=90s \
        --property=TimeoutStopSec=100s \
        --property=KillMode=mixed \
        "$binary" serve \
        --listen "127.0.0.1:$port" \
        --state-dir "$temporary_directory/state" \
        --public-origin https://acmemux.example.test \
        --trusted-proxies 127.0.0.1/32
}

start_service
curl --fail --silent --show-error "http://127.0.0.1:$port/healthz" | grep -F '"healthy"' >/dev/null
curl --fail --silent --show-error "http://127.0.0.1:$port/readyz" | grep -F '"ready"' >/dev/null
test "$(systemctl show --property=Type --value "$unit")" = notify
test "$(systemctl show --property=ActiveState --value "$unit")" = active

sudo -n systemctl restart "$unit"
curl --fail --silent --show-error "http://127.0.0.1:$port/readyz" | grep -F '"ready"' >/dev/null
sudo -n systemctl stop "$unit"

python3 - "$temporary_directory/state/acmemux.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("INSERT INTO schema_migrations(version, applied_at) VALUES ('999_future.sql', CURRENT_TIMESTAMP)")
PY
unit=$unit_base-failed.service
if start_service >/dev/null 2>&1; then
    printf '%s\n' 'service started with an unknown forward migration' >&2
    exit 1
fi
sudo -n systemctl reset-failed "$unit" >/dev/null 2>&1 || true
python3 - "$temporary_directory/state/acmemux.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("DELETE FROM schema_migrations WHERE version = '999_future.sql'")
PY
unit=$unit_base-recovered.service
start_service
curl --fail --silent --show-error "http://127.0.0.1:$port/readyz" | grep -F '"ready"' >/dev/null
