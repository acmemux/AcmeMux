# Installation and first start

AcmeMux is currently available as pre-release source code. It does not yet ship an installer, operating-system package, or systemd unit. These instructions are suitable for evaluation on a Linux amd64 host; wait for a published release before treating this as a stable production installation.

## Requirements

- Linux on amd64
- Go 1.26.6
- Node.js 20.19.2
- npm 9.2.0
- GNU Make
- an exact supported lego executable from [runtime compatibility](runtime-compatibility.md)
- a dedicated non-root operating-system account
- an HTTPS reverse proxy on the same host

AcmeMux and lego must run as the same dedicated account so they see the same native workspace permissions. Do not share that account with unrelated services.

## Build from source

From the checked-out AcmeMux repository:

```sh
make web-deps
make build
```

The resulting executable is `dist/acmemux`. Install it at a root-owned path that the service account can execute, for example:

```sh
sudo install -o root -g root -m 0755 dist/acmemux /usr/local/bin/acmemux
```

## Create the service account and state directory

Account-management commands vary by distribution. The resulting account must be non-root, have no unrelated supplementary groups, and own a private state directory. One common layout is:

```sh
sudo useradd --system --home-dir /var/lib/acmemux --shell /usr/sbin/nologin acmemux
sudo install -d -o acmemux -g acmemux -m 0700 /var/lib/acmemux
```

Prepare the lego executable and native workspace separately. The service account needs execute access to lego and the exact read or write access required by the workspace. AcmeMux will report unsafe paths or insufficient access; it will not change ownership or permissions for you.

## Create the administrator

Run the bootstrap command from a local controlling terminal as the service account:

```sh
sudo -u acmemux /usr/local/bin/acmemux admin bootstrap \
  --state-dir /var/lib/acmemux
```

The password is prompted twice without terminal echo. Bootstrap succeeds only when no administrator exists.

## Configure HTTPS

AcmeMux listens on loopback and requires one exact public HTTPS origin. Give it a dedicated hostname. A minimal Nginx location includes:

```nginx
location / {
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://127.0.0.1:8080;
}
```

Terminate TLS at the proxy and keep its certificate and cipher policy current. Do not publish the AcmeMux loopback port directly.

## Start AcmeMux

Until a supported service unit is published, start the process under your own service manager as the dedicated account:

```sh
sudo -u acmemux /usr/local/bin/acmemux serve \
  --listen 127.0.0.1:8080 \
  --state-dir /var/lib/acmemux \
  --public-origin https://acmemux.example.net \
  --trusted-proxies 127.0.0.1/32
```

The equivalent environment settings are `ACMEMUX_LISTEN_ADDRESS`, `ACMEMUX_STATE_DIRECTORY`, `ACMEMUX_PUBLIC_ORIGIN`, and `ACMEMUX_TRUSTED_PROXIES`. Command-line values take precedence.

Check `http://127.0.0.1:8080/healthz` for process liveness and `/readyz` for readiness. Use the configured HTTPS address for sign-in and all browser activity.

## First browser setup

1. Sign in with the local administrator password.
2. Enter the absolute path to a [supported lego executable](runtime-compatibility.md), inspect it, and acknowledge the exact evidence.
3. Follow [workspace adoption](workspace-adoption.md) to select an existing native configuration or prepare a new supported one.
4. Configure a supported certificate authority and challenge method.
5. Review a manual operation before starting it.
6. Configure [automatic renewal evaluation](automatic-renewal.md) after the manual path is understood.

## Upgrades and backups

Before replacing a pre-release build, stop AcmeMux and back up both `/var/lib/acmemux` and the complete native lego workspace. Database migrations move forward when a newer executable starts; downgrading an already migrated state directory is not supported. Restoring native certificates without their matching lego account and resource files can leave the workspace inconsistent, so back up the workspace as one unit.
