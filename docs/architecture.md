# Application architecture

AcmeMux is one native Go service with an embedded React application and
embedded forward-only SQLite migrations. The process listens only on loopback
in the current foundation and is designed for systemd supervision under a
non-root operating-system identity.

## Boundaries

- `cmd/acmemux` owns process startup, signal handling, and graceful shutdown.
- `internal/httpapi` owns same-origin transport, authenticated JSON routes,
  request-integrity checks, health, readiness, and browser asset delivery.
- `internal/identity` owns the single administrator's versioned Argon2id
  verifier, authentication epoch, hashed server-side sessions, expiry,
  rotation, and revocation.
- `internal/runtime` owns canonical executable auditing, the one bounded
  `--version` probe, durable reviewed evidence, replacement detection, and
  exact-file-descriptor preparation for later broker operations.
- `internal/compatibility` owns exact source-backed `lego` manifests, the
  licensed upstream schema, deliberately smaller supported integration
  catalogs, and fail-closed classification.
- `internal/workspace` owns conventional and explicit native configuration
  discovery, bounded path projection, no-follow filesystem evidence, review
  continuity, the shared workspace coordinator, journaled native-file
  replacement, and explicit interrupted-edit recovery.
- `internal/inventory` owns the one bounded, read-only upstream certificate
  listing and reconciliation with audited native certificate artifacts.
- `internal/integrations` owns immutable runtime-bound manifests that map
  stable logical field IDs to exact native selectors, typed value rules,
  sensitivity, and preservation policy.
- `internal/nativeconfig` owns the authoritative YAML node tree, secret-safe
  typed projection, exact Draft 7 schema and source-backed semantic validation,
  supported-field patches, unsupported-content classification, and review
  summaries.
- `internal/dotenv` owns bounded, line-preserving parsing and exact-key,
  write-only credential edits.
- `internal/configuration` coordinates the reviewed runtime, native sources,
  manifest, preview tokens, candidate validation, transaction, and recovery.
- `internal/redaction` owns bounded exact-value and curated-field filtering for
  broker output; callers remain responsible for supplying every observed
  secret and sensitive field.
- `internal/broker` owns the one exact no-shell file-mode process contract,
  bounded environment and output, process-tree lifetime, timeout, termination,
  and display-safe redacted results.
- `internal/jobs` owns the latest-only durable manual or scheduled operation
  record and the one service-lifetime worker whose context is independent of browser requests.
- `internal/operation` owns non-writing whole-workspace review, durable enqueue,
  execution revalidation, broker coordination, certificate-level result
  classification, and mandatory native-inventory reconciliation.
- `internal/scheduler` owns the singleton typed daily schedule, IANA-zone
  calculation, UTC persistence, missed-date coalescing, contention wakeup, and
  non-replay restart recovery.
- `internal/state` owns application-only SQLite state and migrations.
- `internal/webassets` owns the browser build embedded into the executable.
- `internal/reporting` remains the explicit boundary for the later health and
  latest-reporting delivery task.

SQLite contains the migration ledger, service metadata, the Argon2id
administrator verifier, an authentication epoch, and hashed session and expiry
metadata. It also contains the non-secret metadata, digest, build evidence,
manifest identifier, and review time for the one adopted executable, plus the
reviewed workspace paths and bounded filesystem observations required to
recheck that selection after restart. It may also contain one secret-free
native-edit journal with transaction phase, target paths, parent placement,
and staged or active inode metadata. The executable itself, passwords, raw
session or CSRF tokens, configuration review-token key, native content
digests, field changes, and credential values are never stored. Certificate
inventory is refreshed from native evidence and is not persisted. SQLite also
contains the one current automatic schedule, next UTC evaluation, last trigger,
and bounded recovery state, plus the one accepted manual or scheduled operation scope and its active or latest
bounded result: stable secret-free reviewed evidence, certificate names,
phases and times, stable reason codes, redacted output, certificate-level
states, and inventory reconciliation status. It is not long-term job history.
Native YAML, provider credentials, EAB secrets, ACME accounts, certificates,
chains, private keys, archives, and desired configuration do not belong in
application state.

The browser is a same-origin client gated by the local administrator session.
An explicit HTTPS public origin is the authority for Host and Origin checks;
forwarded host and protocol fields never change security decisions. Only an
explicitly trusted loopback proxy can contribute a bounded client-address
chain for login limiting. Node.js is used only to build and verify the browser;
no Node.js runtime is part of the production topology.

Runtime selection is a separate trust boundary. The service opens every path
component without following symbolic links, audits the retained regular file,
hashes it with a context checked between bounded reads, and rejects bytes outside the
independently qualified executable allowlist before execution. It then runs
only that retained file with `--version` under strict limits and compares its
bounded command, module, dependency, toolchain, source, and platform evidence
with an exact compatibility manifest. The administrator reviews all resulting
evidence before adoption. Selection does not browse for, download, replace, or
upgrade `lego`, and it does not perform an ACME or provider operation. A later
managed operation can obtain an executable handle only by loading and
preparing the validated persisted selection, reclassifying the retained
descriptor, and matching its exact current manifest. The one-shot start owns
that descriptor until the child begins. A path, inode, metadata, capability, digest, output,
build, version, platform, or manifest change blocks use until review is
repeated.

Workspace adoption is a separate native-filesystem boundary. The service
discovers `.lego.yml` before `.lego.yaml` or accepts an explicit configuration
with an explicit effective working directory. It resolves storage, DNS dotenv,
and HTTP webroot references exactly from that directory, opens every component
without following symbolic links, and displays bounded type, identity,
ownership, mode, access, and final-object metadata before adoption. The
administrator-reviewed fingerprint is rechecked on every later access. A
trusted retained executable then runs only `certificates list --path <storage>
--json` from a private neutral directory; execution is one at a time, bounded
JSON must reconcile with the audited native certificate tree, and workspace
evidence is checked again before a current result is returned. No YAML,
credential-file, resource, certificate, or key bytes enter SQLite. Inventory
returns no such bytes to the browser; configuration mediation returns only
curated public projections and secret presence, never a raw native document or
credential value.

Native configuration mediation is another layer on the same runtime and
workspace trust boundaries. One exact-runtime integration manifest projects
only stable logical fields from the authoritative YAML node tree. The current
production manifest manages storage, the accepted CA account choices,
certificates, renewal behavior, and HTTP-01 listener or webroot challenges.
Recognized but unmanaged native content remains in the tree and blocks
execution. Unknown fields or YAML structures whose meaning cannot be preserved
safely block replacement as well. Secret values are projected only as presence
and validity, and only manifest-owned secret fields can be changed.

Preview is non-writing. Memory-only HMAC tokens bind the reviewed runtime,
workspace, source files, logical changes, and exact candidate replacements.
Save reconstructs the candidate, rechecks all source and candidate path
evidence, revalidates the administrator immediately before replacement, and
uses restrictive same-directory candidates with file and directory
synchronization. Per-file `renameat2` activation is atomic; a multi-file edit
is not. A durable secret-free journal classifies interruption without replaying
candidate content. Wholly unapplied or wholly applied outcomes have bounded
resolution paths; partial or ambiguous results require explicit host repair
and validated adoption of the current files. See `native-configuration.md`.

When no workspace has been selected, the same service can create one complete
curated configuration at a reviewed absent target. It binds the safe working
directory, target precedence, pre-existing storage and webroots, and exact
candidate sources before using the same secret-free journal and
same-directory no-replace activation. No workspace selection is stored until
a fresh inspection proves the active native files and full path boundary.
Interrupted creation is identified separately in recovery; applied creation
requires explicit validated adoption because no pre-edit selection exists.

Manual and scheduled native execution build on all of these boundaries. A non-writing
preview shows the exact runtime, native paths, configured certificate targets,
and possible account, storage, backup, and external ACME effects. An opaque
token binds that view to the complete current sources. Enqueue replays the
review, immediately reauthorizes the administrator, and commits the request
before notifying the worker. The browser does not own operation lifetime;
disconnect and session expiry after acceptance do not stop it, and no browser
cancel or automatic retry path exists.

The worker holds the shared workspace lease across preflight inventory,
direct execution of exactly `--config <absolute-configuration>` from the
adopted working directory, and terminal reconciliation. The broker uses a
fixed and integration-allowlisted environment, a 30-minute timeout, bounded
stdout and stderr, a dedicated process group plus descendant tracking, and a
five-second `SIGTERM` grace before forced `SIGKILL`. Observed secrets are
redacted and output is sanitized before crossing into durable jobs state.
Inventory refresh and runtime, workspace, and source rechecks are mandatory
after the process; uncertain cleanup, evidence change, or incomplete
reconciliation stays explicit rather than being converted into success. A
queued operation can continue after service restart, while a previously
running operation is interrupted, reconciled, and never replayed. See
`manual-operations.md`.

The automatic scheduler is disabled until explicitly configured. It stores
one daily local wall-clock time and IANA zone while presenting the exact next
UTC instant. Missed dates coalesce, contention defers one due evaluation, and
an interrupted operation advances to the next ordinary occurrence. Scheduled
work enters the same durable operation and broker path; upstream `lego`
retains ARI, lifetime, and random-delay authority. See `automatic-renewal.md`.

The browser shell is composed from authored tokens and semantic components.
React Aria supplies headless interaction behavior, while the application owns
all visual styling and repository-authored SVG. The in-application component
catalog and Playwright visual and accessibility suites are shared contracts for
later feature screens; see `visual-system.md`.
