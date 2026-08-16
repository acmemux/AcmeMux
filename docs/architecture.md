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
  later broker output; callers remain responsible for supplying every observed
  secret and sensitive field.
- `internal/state` owns application-only SQLite state and migrations.
- `internal/webassets` owns the browser build embedded into the executable.
- `jobs` and `reporting` remain explicit product boundaries for later delivery
  tasks.

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
inventory is refreshed from native evidence and is not persisted.
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
base manifest manages only root `storage`; later CA, challenge, certificate,
and provider tasks extend the manifest deliberately. Recognized but unmanaged
native content remains in the tree and blocks execution. Unknown fields or
YAML structures whose meaning cannot be preserved safely block replacement as
well. Dotenv values are projected only as presence and validity, and only
manifest-owned secret keys can be changed.

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

The browser shell is composed from authored tokens and semantic components.
React Aria supplies headless interaction behavior, while the application owns
all visual styling and repository-authored SVG. The in-application component
catalog and Playwright visual and accessibility suites are shared contracts for
later feature screens; see `visual-system.md`.
