# Security and trusted-host responsibilities

AcmeMux is a single-administrator application for a host you control. It manages security-sensitive native configuration and starts an administrator-selected lego executable. Protect the host, service account, reverse proxy, state directory, and complete lego workspace as one trust boundary.

## Administrator account

The administrator can be created or recovered only from a local controlling terminal:

```sh
/usr/local/bin/acmemux admin bootstrap --state-dir /var/lib/acmemux
/usr/local/bin/acmemux admin reset-password --state-dir /var/lib/acmemux
/usr/local/bin/acmemux admin revoke-sessions --state-dir /var/lib/acmemux
```

- `bootstrap` creates the only administrator and succeeds once.
- `reset-password` replaces the password and revokes all browser sessions.
- `revoke-sessions` keeps the password and revokes all sessions.

Run these commands as the AcmeMux service account against the same state directory used by the service. Passwords are prompted twice without terminal echo and must contain at least 12 Unicode characters. They are never accepted as command-line arguments or environment variables.

There is no browser bootstrap, email recovery, invitation, user management, or role system.

## HTTPS and reverse proxy

Authenticated browser use requires a dedicated HTTPS origin and a loopback reverse proxy:

```sh
/usr/local/bin/acmemux serve \
  --listen 127.0.0.1:8080 \
  --state-dir /var/lib/acmemux \
  --public-origin https://acmemux.example.net \
  --trusted-proxies 127.0.0.1/32
```

The public origin must be one exact HTTPS origin without a path. Give AcmeMux a dedicated hostname; browser cookies are scoped to hostnames rather than ports. The proxy must preserve that public `Host` value.

Only explicitly trusted loopback proxies can supply `X-Forwarded-For`, and that value is used only for login limiting. Forwarded protocol or host headers never override the configured public origin. Direct HTTP is suitable only for local `/healthz` and `/readyz` checks.

The reverse proxy operator remains responsible for TLS certificates, current cipher policy, internet exposure, access controls, and request limits outside AcmeMux.

## Sessions and browser requests

Sessions use Secure, HttpOnly, SameSite cookies and server-side expiry and revocation. State-changing browser requests require the configured origin and an additional request-integrity token. Password reset and session revocation invalidate existing sessions.

Do not place authentication material in URLs, browser storage, scripts, proxy logs, or monitoring labels. A request-integrity error usually indicates an incorrect public origin, proxy `Host`, cookie, or HTTPS configuration.

## Service account and filesystem

Run AcmeMux under a dedicated non-root account with no unrelated supplementary groups or Linux capabilities. Do not share that account with other applications. Another process running as the same account can read or change service-owned files and is inside the trusted-host boundary.

Protect:

- the AcmeMux state directory;
- the selected lego executable;
- native YAML and credential files;
- ACME account and certificate storage;
- HTTP webroots and any cloud credential files; and
- backups, snapshots, swap, crash dumps, and service logs.

AcmeMux never changes ownership or permissions to make an unsafe host layout work. Correct host access deliberately and inspect it again.

## Executable and workspace review

Only adopt lego from a source you trust. AcmeMux requires an exact supported binary digest and reviews the file's canonical path, ownership, permissions, capability, platform, version, and build identity. Prefer a root-owned executable that the service account can execute but cannot modify.

Managed workspace paths cannot traverse symbolic links. Configuration and credential files must be private regular files and cannot be hard linked. AcmeMux checks reviewed paths again before reads, saves, and operations. A material change blocks managed use until you review it.

See [supported lego executables](runtime-compatibility.md) and [workspace adoption](workspace-adoption.md) for the current requirements.

## Secrets and native data

Native YAML and credential files can contain EAB and provider secrets. Existing secret values are write-only in the browser: AcmeMux shows only whether they are present and whether a save will keep, replace, or remove them.

AcmeMux state contains the administrator password verifier, hashed session metadata, reviewed path and executable evidence, the current schedule, recovery state, and the latest bounded redacted operation result. It does not contain native YAML or credential contents, ACME account files, certificates, private keys, archives, or a copied certificate inventory.

Secret redaction reduces accidental disclosure in retained operation output, but it does not make the host untrusted. Review access to native files, process memory, swap, dumps, snapshots, and any process sharing the service account.

## Certificate operations

AcmeMux starts the selected lego executable directly without a shell or arbitrary user-supplied flags. Only supported provider credentials are made available to the operation. Standard input is disconnected, output is bounded and redacted, and only one workspace operation or edit can run at a time.

Accepted operations continue independently of the browser. There is no browser cancellation or automatic retry. After a timeout, interruption, provider error, partial result, or ambiguity, review native inventory and the redacted result before deciding whether another operation is safe.

Cloud identity modes can widen host trust:

- Azure CLI uses the explicitly reviewed helper and cache.
- Azure managed identity and AWS instance role enable their documented metadata path only when selected.
- AWS shared profiles are limited to a reviewed credentials file and do not use implicit home-directory discovery.

Grant provider identities only the DNS permissions required for the selected zones and challenge records.

## Incident response

If you suspect administrator-session exposure, run `revoke-sessions`. If the password may be exposed, run `reset-password`. If the lego executable or workspace may have been replaced, stop AcmeMux and other writers, preserve evidence, restore from a trusted backup, and repeat runtime and workspace review before any certificate operation.

For an interrupted configuration change, follow [configuration recovery](native-configuration.md#interrupted-change-recovery). Do not delete staging files with a wildcard or blindly retry an ACME operation whose external effect is uncertain.

The project does not yet publish a dedicated security-reporting channel. That process will be defined before the first stable public release.
