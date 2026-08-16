# Source installation and systemd operation

AcmeMux is installed from source and runs as one native systemd service. The qualified MVP platform is Debian 13 amd64. A successful build or installation on another distribution or architecture does not add support for it.

AcmeMux does not publish `.deb`, RPM, package-repository, container, or Compose artifacts. Those distribution integrations remain roadmap work and can be prioritized when operators request them.

## Requirements

- Debian 13 on amd64 with systemd
- Go 1.26.6
- Node.js 20.19.2
- npm 9.2.0
- GNU Make and `sha256sum`
- an exact supported lego executable from [runtime compatibility](runtime-compatibility.md)
- an HTTPS reverse proxy on the same host
- root access for installation and systemd administration

Use a tagged AcmeMux source release for an installed system. Before the first tagged release, a source checkout is evaluation software. The build needs access to the locked Go and npm dependencies, either from their normal sources or from caches populated before an offline build; dependencies are not vendored into the repository.

## Build and verify

From the selected source checkout:

```sh
make web-deps
make distribution
(cd dist && sha256sum --check acmemux.sha256)
```

The build checks the pinned toolchain versions, compiles the browser into the CGO-free Go executable, and writes `dist/acmemux` plus `dist/acmemux.sha256`. Go and Node.js are not needed after installation.

## Choose the service identity

The default installation creates the non-login `acmemux` system account. AcmeMux, the selected lego executable, and the adopted native workspace must use compatible filesystem access. Do not share this account with unrelated services.

If an existing workspace must retain its current non-root owner, install AcmeMux with that existing user and group:

```sh
sudo distribution/install.sh \
  --public-origin https://acmemux.example.net \
  --service-user lego-operator \
  --service-group lego-operator
```

The installer never changes ownership or permissions on an existing workspace. The selected identity must already be able to traverse the working directory, execute lego, read the native configuration and credentials, update certificate storage, and write configured webroots.

## Install and start

For the default service identity:

```sh
sudo distribution/install.sh \
  --public-origin https://acmemux.example.net
```

The exact HTTPS origin is required on first installation. The installer verifies the built checksum, creates or validates the service identity, installs root-owned service files, validates the unit, enables it, and waits for AcmeMux startup recovery to report ready.

| Purpose | Path |
| --- | --- |
| Executable | `/usr/local/bin/acmemux` |
| Service unit | `/etc/systemd/system/acmemux.service` |
| Service settings | `/etc/acmemux/acmemux.env` |
| Identity override | `/etc/systemd/system/acmemux.service.d/identity.conf` |
| Application state | `/var/lib/acmemux` |
| Runtime directory | `/run/acmemux` |
| Service logs | systemd journal for `acmemux.service` |
| Adopted workspace | administrator-selected native path; never copied into AcmeMux state |

Systemd owns the private state and runtime directories. The unit runs without root, Linux capabilities, writable system directories, devices, namespace creation, or privilege escalation. It allows ordinary host and network access required by the selected lego executable, DNS providers, cloud identity helpers, native storage, and webroots.

`ProtectSystem=full` makes `/usr`, `/boot`, and `/etc` read-only inside the service. Prefer a native workspace under `/var/lib`, `/srv`, or the service identity's home. If an existing workspace must write beneath a protected system path, add only its exact reviewed directory through a systemd drop-in:

```ini
[Service]
ReadWritePaths=/exact/native/workspace
```

Then reload and restart the service. AcmeMux still applies its own no-symlink, ownership, mode, and access review.

## Bootstrap and reverse proxy

Create the only administrator from a local controlling terminal as the configured service identity:

```sh
sudo -u acmemux /usr/local/bin/acmemux admin bootstrap \
  --state-dir /var/lib/acmemux
```

Replace `acmemux` when an existing identity was selected. The password is prompted twice without terminal echo.

AcmeMux listens on `127.0.0.1:8080` by default. A minimal Nginx location is:

```nginx
location / {
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://127.0.0.1:8080;
}
```

Terminate TLS at the proxy, preserve the configured public `Host`, and do not expose the loopback service directly. If the proxy uses another loopback address, update `ACMEMUX_TRUSTED_PROXIES` in `/etc/acmemux/acmemux.env`, then restart AcmeMux.

## Operate and diagnose the service

```sh
sudo systemctl status acmemux.service
sudo journalctl -u acmemux.service
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

`healthz` reports process liveness. `readyz` reports access to application state. Systemd does not consider startup complete until database migrations, interrupted-operation reconciliation, and scheduler recovery finish. Startup and shutdown are bounded; graceful shutdown has time to terminate a managed lego process and persist its conservative result.

The service restarts after unexpected failure. A configuration or migration error remains visible in the journal and can leave the unit failed rather than hiding the problem in a restart loop.

## HTTP-01 and low ports

AcmeMux itself receives no low-port capability. Prefer an existing webroot or forward only ACME challenge traffic to an unprivileged lego listener. If direct port 80 binding is unavoidable, the separately selected lego executable may receive the exact reviewed `cap_net_bind_service=ep` file capability. AcmeMux reviews that capability but never grants it. See [HTTP-01 modes](ca-certificate-http.md#http-01-modes).

## Upgrade safely

Upgrades are forward-only. They preserve `/etc/acmemux`, `/var/lib/acmemux`, the service identity, and every adopted workspace. A newer executable applies embedded transactional migrations during startup; a binary downgrade against migrated state is unsupported.

Before upgrading:

1. Let active certificate or configuration work reach a terminal state.
2. Build and verify the new tagged source revision with `make distribution`.
3. Retain the prior source revision or its verified executable.
4. Stop the service and back up `/var/lib/acmemux` as one private unit.
5. Back up the complete native lego workspace separately, including account, resource, certificate, archive, configuration, and credential files.

Then run from the new source checkout:

```sh
sudo distribution/upgrade.sh
```

The upgrade verifies and stages the complete new executable before stopping the service, replaces it atomically, updates the unit, and waits for readiness after restart. If the command is interrupted, rerun it from the same verified source revision; the executable path contains either the complete prior file or the complete new file, never a partial copy.

If startup fails, inspect the journal first. Do not restore only the old executable after a migration ran. Recovery requires stopping the service and restoring the retained prior executable together with its matching pre-upgrade `/var/lib/acmemux` backup. Restore the native workspace only when evidence shows the failed or interrupted service lifetime changed it; an ambiguous lego operation can have external effects even when AcmeMux startup or shutdown reports failure.

## Remove or reinstall

From the installed source revision:

```sh
sudo distribution/remove.sh
```

Removal disables the service and removes the executable, unit, identity override, and installed example. It deliberately preserves `/etc/acmemux`, `/var/lib/acmemux`, the service identity, and every adopted workspace. These may contain access paths, administrator state, redacted results, credentials, accounts, certificates, and private keys.

Reinstall from a verified source checkout with `distribution/install.sh`. A preserved `/etc/acmemux/acmemux.env` is reused rather than overwritten; supply the same service user and group that own the retained state and workspace. Permanent data destruction is a separate manual host-administration decision and is not performed by AcmeMux automation.

## Platform limitations

- Debian 13 amd64 is the only qualified systemd platform.
- No SELinux distribution is currently supported. AcmeMux ships no SELinux policy.
- Debian's ordinary AppArmor environment is compatible, but AcmeMux ships no custom profile. A locally added profile must permit the exact executable, state, runtime, lego, workspace, credential, webroot, cloud-helper, and network access in use.
- Operating-system packages and package repositories are not release artifacts.
- Containers and remote runners are not supported deployment models.
