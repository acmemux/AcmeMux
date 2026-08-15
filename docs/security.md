# Administrator and browser security

AcmeMux has one local administrator. The administrator password is established
or replaced only by an operator who already controls the service host. There is
no HTTP bootstrap, password-reset, recovery, invitation, user-management, or
role-management path.

## Local administrator commands

Build the native executable, stop interactive prompts from being redirected,
and run the command from a controlling terminal:

```sh
./dist/acmemux admin bootstrap --state-dir /var/lib/acmemux
./dist/acmemux admin reset-password --state-dir /var/lib/acmemux
./dist/acmemux admin revoke-sessions --state-dir /var/lib/acmemux
```

`bootstrap` succeeds exactly once. `reset-password` replaces the verifier and
revokes every browser session. `revoke-sessions` retains the password and
revokes every session. Passwords are read twice without terminal echo and are
not accepted in arguments or environment variables. New passwords must be
valid UTF-8, contain at least 12 Unicode characters, and occupy no more than
1024 bytes.

The password verifier is a versioned, salted Argon2id record. Successful
authentication upgrades weaker recognized parameters without downgrading
stronger records. SQLite stores only that verifier, an authentication epoch,
and SHA-256 digests and expiry metadata for sessions. A reset or global
revocation advances the epoch transactionally, so a login that began against
older authentication state cannot create a valid session afterward.

## HTTPS and public origin

The service listens on a loopback IP literal. Authenticated browser access
requires an administrator-managed HTTPS reverse proxy and an explicit public
origin:

```sh
./dist/acmemux serve \
  --listen 127.0.0.1:8080 \
  --state-dir /var/lib/acmemux \
  --public-origin https://acmemux.example.net \
  --trusted-proxies 127.0.0.1/32
```

The corresponding environment settings are `ACMEMUX_LISTEN_ADDRESS`,
`ACMEMUX_STATE_DIRECTORY`, `ACMEMUX_PUBLIC_ORIGIN`, and
`ACMEMUX_TRUSTED_PROXIES`. Command-line values take precedence. The public
origin must be one canonical HTTPS origin with no path, query, fragment, or
userinfo. Give AcmeMux a dedicated, trusted hostname rather than sharing its
hostname with unrelated HTTPS applications on other ports: cookies are scoped
to a hostname, not a port. The proxy must preserve the public `Host` value.

Forwarded host and protocol headers are ignored even when a proxy is trusted;
they cannot relax the configured origin or Secure-cookie behavior. A bounded
`X-Forwarded-For` chain affects login-rate identity only when the immediate
peer is in the explicit trusted loopback allowlist. All forwarded data from
other peers is ignored.

Example reverse-proxy request headers are:

```nginx
proxy_set_header Host $http_host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_pass http://127.0.0.1:8080;
```

TLS certificates, cipher policy, and public listener hardening remain the
reverse proxy administrator's responsibility. Direct HTTP can be used for
local `/healthz` and `/readyz` probes, not for authenticated browser operation.

## Sessions and request integrity

Successful sign-in always creates a fresh cryptographically random session and
CSRF pair. The session cookie uses the `__Host-` prefix, `Secure`, `HttpOnly`,
`SameSite=Strict`, and `Path=/`; it has no Domain attribute. The readable CSRF
cookie is separately random, bound to the server-side session digest, and must
match the custom request header on authenticated state changes.

Sessions have bounded idle and absolute expiry, rotate during use with a short
concurrency grace period, persist across ordinary service restart, and are
revoked server-side by logout, password reset, or the local revocation command.
Reset and revocation prevent requests that begin after the transaction commits
from authenticating. They do not retroactively cancel a handler that was
already authorized; future privileged mutation handlers must revalidate the
authentication epoch immediately before committing their side effect.
Passwords and raw session tokens are not logged, rendered, returned in JSON,
or stored in SQLite. The browser keeps password input local to the current form
and does not place authentication material in URLs or Web Storage.

Every unsafe browser request requires the exact configured Origin. Browser and
API requests require the configured Host, while local health and readiness
probes remain minimal and unauthenticated. Unknown `/api/` routes return JSON
errors and never fall through to the browser application.

## Upstream executable trust

Only an authenticated administrator can inspect or adopt a `lego` executable.
Inspection accepts one absolute canonical path and follows no symbolic links.
The retained file must be a nonempty regular executable owned by root or the
service identity, no larger than 512 MiB, free of special mode bits, and not
writable by group or others. File capabilities are rejected except exact
`cap_net_bind_service=ep`. The service itself refuses to start with any real,
effective, saved, or filesystem root user or group identity, supplementary
group 0, mismatched process identities, or any inheritable, permitted,
effective, or ambient Linux capability.

The dedicated service identity is part of the host trust boundary. A different
local process running under that same identity can mutate a service-owned inode
even while AcmeMux retains an open descriptor. Operators should not share the
service account with unrelated processes and should prefer a root-owned,
non-writable `lego` executable when practical.

AcmeMux hashes the retained file before execution and runs `--version` only
when the bytes match an independently qualified, executed artifact digest. The
probe uses a fixed environment and no shell; bounded embedded build evidence
must match the exact manifest. The administrator explicitly reviews path,
times, ownership, mode, capability, binary and dependency digests, exact
output, version or commit, platform, build provenance, and manifest. A stable
review fingerprint binds all displayed evidence to adoption, and the session
and CSRF pair are revalidated immediately before persistence.

The selected executable is re-opened and compared with all reviewed evidence.
A changed path, inode, owner, mode, capability, time, size, digest, output,
build identity, version, or platform blocks managed use until the replacement
is inspected and adopted. Operation preparation loads the validated persisted
singleton, requires the current compatibility result to retain the exact
reviewed manifest, and owns the retained descriptor through a one-shot child
start so concurrent close or descriptor reuse cannot redirect execution. The runtime flow
never downloads, upgrades, registers with an ACME server, accesses a provider,
or performs certificate work. See
`runtime-compatibility.md` for supported identities and host-permission
troubleshooting.

## Failed sign-in and recovery

Wrong passwords and an uninitialized service use the same credential failure
response. Login work is bounded per client and globally, and concurrent
Argon2id evaluation is capped to protect service memory. The limiter is
in-memory and resets on service restart; restarting is not an administrator
recovery mechanism.

When the browser reports that setup is required, run local `bootstrap`. When a
password is lost, use local `reset-password`; there is no remote recovery. A
request-integrity failure indicates an Origin, Host, cookie, CSRF, or proxy
configuration problem rather than a missing role.
