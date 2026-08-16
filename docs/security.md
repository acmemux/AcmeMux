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
already authorized. Native configuration save and recovery handlers therefore
retain the original session and CSRF pair and revalidate both immediately
before the first filesystem activation or recovery finalization.
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

## Native workspace and inventory trust

Only an authenticated administrator can inspect or adopt a workspace. Every
request names an absolute canonical effective working directory and either an
explicit native YAML path or conventional `.lego.yml`-before-`.lego.yaml`
discovery. Storage, DNS dotenv, and HTTP webroot references are resolved from
the effective working directory, matching native `lego` behavior even when an
explicit YAML file lives elsewhere.

AcmeMux opens every selected path component without following symbolic links.
It requires trusted ownership, safe types and modes, the exact service access
needed by each role, single-link confidential YAML and dotenv files, and
writable replacement parents where later atomic edits require them. The
bounded browser review exposes stable component identity and permission
evidence plus final-object link and timestamp metadata. A fingerprint binds
that displayed evidence; external changes block later access until reviewed.
AcmeMux never repairs, relocates, changes ownership, or changes permissions on
the native workspace.

Certificate inventory first revalidates the exact persisted runtime and
workspace. It starts the retained executable directly, without a shell, using
the fixed `certificates list --path <absolute-storage> --json` argument vector,
a private configuration-free working directory, an allowlisted environment,
and bounded time, output, process-group, tree, count, and one-at-a-time limits.
Native JSON resource and certificate paths must reconcile with no-follow
filesystem evidence, and the full workspace is rechecked after inventory,
before metadata reaches the browser. A stable storage that has not created its
`certificates` directory yet is reported as empty only for the exact upstream
missing-directory failure record; the directory is not created automatically.

Workspace adoption revalidates the session and original CSRF pair immediately
before saving. SQLite stores only reviewed paths, non-content filesystem
observations, fingerprints, and times. It does not store native YAML or dotenv
contents, certificate resource JSON, certificate or chain bytes, private keys,
account material, child stderr, or inventory results. See
`workspace-adoption.md` for layouts, permissions, states, and limits.

## Native configuration editing trust

Configuration inspection and preview require the same authenticated,
same-origin browser boundary. Preview does not write a native file. Save
accepts only stable logical field IDs and typed values declared by the exact
runtime integration manifest; it never accepts a YAML selector, environment
variable name, shell fragment, executable argument, or arbitrary native file
path from a browser change.

The browser receives an opaque base-revision token and, after a valid preview,
an opaque reviewed-preview token. These are memory-keyed HMACs over the full
runtime review, workspace review, source identities and contents, logical
changes, and exact candidate replacements. They reveal no native digest or
secret value and are invalid after service restart. They do not replace the
administrator session, Origin, Host, or CSRF checks. Save reconstructs the
candidate, compares the tokens, rereads all native sources, repeats no-follow
path audits, re-verifies the runtime, and performs the immediate session and
CSRF reauthorization before any active rename.

Secret fields are write-only. Existing YAML or dotenv secrets are represented
to the browser only as present, absent, or present but outside the curated
contract. A preview reports a secret replacement or removal without returning
the before or after value. Replacing a secret always prepares a replacement,
even when the submitted bytes might match the stored bytes, so the service
does not disclose equality. Configuration diagnostics contain stable codes,
logical identities, and bounded native locations, never source values or raw
parser errors.

Every manifest-owned dotenv key is classified as either a write-only secret or
a bounded public provider setting. Other keys remain byte-for-byte
authoritative but block managed execution. Secret values exist transiently in
bounded request and candidate memory and in native files; they are not written
to SQLite, journal phases, review summaries, errors, URLs, or responses.
Public TTL, timing, and endpoint values can be projected and reviewed. Memory
clearing is best effort. Host swap, crash dumps, filesystem snapshots, and
another process sharing the AcmeMux service UID are within the trusted-host
boundary and must be protected operationally.

Candidates are created beside their targets as service-owned, single-link
regular files with mode `0600`, then synchronized and activated with
same-directory `renameat2`. Source content and metadata, candidate paths,
replacement parents, the working directory, storage, dotenv references, and
webroots are checked around the commit guard. An edited active YAML or dotenv
file is consequently owned by and readable only to the intended service
identity. AcmeMux never changes ownership or permissions to make an unsafe
existing workspace eligible for editing.

First-configuration creation uses the same boundary without treating an
absent file as an implicit workspace. The server binds a reviewed safe working
directory, explicit or conventional target, missing-target evidence, and every
candidate storage, dotenv, and HTTP webroot path to opaque review tokens. The
durable journal exists before candidate staging, and activation uses
same-directory `RENAME_NOREPLACE`; creation never overwrites a target that
appeared after review. A workspace selection is inserted only after fresh
content and path inspection. An interrupted applied creation cannot use the
ordinary edit finalization path and requires explicit adopt-current review.

SQLite can retain one secret-free interrupted-edit journal containing target
paths and inode placement metadata. It contains no source bytes, content
digest, field ID, summary, or secret. Recovery classifies placement but never
replays staged bytes. A wholly unapplied edit can discard recognized stages;
a wholly applied edit can be revalidated and finalized. Partial or ambiguous
placement requires explicit host repair and confirmed adoption of the current
active files. While that journal exists, the same coordinator and a journal
check prevent runtime or workspace re-adoption from rebinding the recovery
operation. A substituted or foreign staging entry is preserved and keeps
recovery blocked. See `native-configuration.md` for the exact recovery states,
operator procedure, resource limits, and filesystem assumptions.

## Manual operation trust

Only an authenticated same-origin administrator can request a manual
whole-workspace preview. The preview is non-writing and contains only the
reviewed runtime identity and manifest, canonical native paths, configured
certificate names and public intent, possible native effects, and a fixed
operation policy. It never contains credentials, raw YAML, an argument vector,
or native artifact bytes. A memory-keyed HMAC binds it to complete runtime,
workspace, source, certificate, and policy evidence. Enqueue reconstructs that
evidence, compares the token in constant time, and revalidates the original
session and CSRF pair immediately before committing work to SQLite.

Automatic schedule reads require the same authenticated browser boundary, and
schedule changes additionally require Origin, CSRF, and immediate session
reauthorization. The mutation accepts only an enable flag, bounded IANA zone,
and exact local `HH:MM` time; it is not a cron, command, flag, environment, or
per-certificate execution surface. SQLite retains only that singleton policy,
UTC trigger instants, a local-date replay guard, and bounded reason state.

The scheduler can accept work without a live browser only after the policy has
been saved. It waits for durable-operation startup reconciliation, shares the
latest-only operation slot and workspace coordinator, and cannot overlap a
manual run or native edit. Crash-window claims and interrupted processes
advance without automatic replay. Scheduled operations use the identical
controlled environment, secret redaction, timeout, termination, and inventory
reconciliation boundary described below.

For Azure DNS and Route 53, the preview also names the selected authentication
mode and every non-secret file, helper, or metadata consequence. The broker
inherits no service environment and supplies no default `HOME`. Credential
files use the workspace no-follow ownership, permission, hard-link, size, and
concurrent-change policy. Azure CLI is limited to one audited `az` helper and
explicit cache. Azure managed identity and AWS instance role are the only modes
that enable their metadata path. AWS shared profiles reject helpers, SSO,
config loading, and role recursion and are materialized as sensitive
operation-scoped variables. Sensitive values join the bounded redaction set
and are cleared with the execution plan.

The durable worker, not the request context, owns accepted process lifetime.
Browser disconnect, logout, or session expiry after the commit cannot signal
the child. There is no browser cancellation mutation and no automatic retry.
A queued request survives service restart; a request found running after
restart is marked interrupted, treated as potentially changed, reconciled
against native inventory, and not replayed.

The broker consumes a freshly revalidated retained executable descriptor and
starts the exact file directly with arguments `--config` and the canonical
absolute native configuration path. The adopted working directory preserves
native relative-path meaning. No shell, inherited standard input, arbitrary
flag, environment name, hook, or command enters the boundary. The current
HTTP-01 operation has `LANG=C`, `LC_ALL=C`, `TZ=UTC`, and one randomized
broker-owned lineage-marker variable; later supported integrations can add
only exact variables selected by trusted manifest code.

The process starts in its own group with a parent-death signal. AcmeMux acts as
a child subreaper; process-group signals and identity-bound `/proc` descendant
tracking use the internal lineage marker to cover children that change group
or session without adopting unrelated children. The current 30-minute limit
triggers `SIGTERM`, a five-second grace, and then `SIGKILL`; uncertain tree
cleanup is an ambiguous result. Service shutdown uses the same controlled
worker cancellation path.

Captured stdout is limited to 192 KiB, stderr to 64 KiB, and the combined
result to 256 KiB. Overflow stops the tree and discards the captured transcript
rather than persisting a partial redaction context. Observed YAML and dotenv
secret values plus sensitive integration values are redacted before durable
state. Invalid text and terminal controls are sanitized, followed by a second
value-redaction pass. Jobs persistence accepts only bounded safe text and
stable codes, never raw child bytes or input-derived operating-system errors.

A preflight inventory provides a native baseline. Terminal inventory refresh
and final runtime, workspace, and source revalidation occur while the shared
lease is still held after every started result. Timeout, interruption, output
overflow, descendant uncertainty, evidence change, or unavailable inventory
can therefore report that external state may have changed. The safe action is
to review native storage, refreshed inventory when available, certificate-level
evidence, and the redacted transcript before preparing a new preview. See
`manual-operations.md` for result states and operator actions.

## Failed sign-in and administrator recovery

Wrong passwords and an uninitialized service use the same credential failure
response. Login work is bounded per client and globally, and concurrent
Argon2id evaluation is capped to protect service memory. The limiter is
in-memory and resets on service restart; restarting is not an administrator
recovery mechanism.

When the browser reports that setup is required, run local `bootstrap`. When a
password is lost, use local `reset-password`; there is no remote recovery. A
request-integrity failure indicates an Origin, Host, cookie, CSRF, or proxy
configuration problem rather than a missing role.
