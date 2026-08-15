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
  continuity, and durable non-content workspace selection.
- `internal/inventory` owns the one bounded, read-only upstream certificate
  listing and reconciliation with audited native certificate artifacts.
- `internal/state` owns application-only SQLite state and migrations.
- `internal/webassets` owns the browser build embedded into the executable.
- `nativeconfig`, `integrations`, `jobs`, `redaction`, and `reporting` reserve
  explicit product boundaries. Their behavior is added only by the governing
  delivery tasks.

SQLite contains the migration ledger, service metadata, the Argon2id
administrator verifier, an authentication epoch, and hashed session and expiry
metadata. It also contains the non-secret metadata, digest, build evidence,
manifest identifier, and review time for the one adopted executable, plus the
reviewed workspace paths and bounded filesystem observations required to
recheck that selection after restart. The executable itself, passwords, and
raw session or CSRF tokens are never stored. Certificate inventory is refreshed
from native evidence and is not persisted.
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
credential, resource, certificate, or key bytes enter SQLite or the browser.

The browser shell is composed from authored tokens and semantic components.
React Aria supplies headless interaction behavior, while the application owns
all visual styling and repository-authored SVG. The in-application component
catalog and Playwright visual and accessibility suites are shared contracts for
later feature screens; see `visual-system.md`.
