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
- `internal/state` owns application-only SQLite state and migrations.
- `internal/webassets` owns the browser build embedded into the executable.
- `internal/identity`, `workspace`, `nativeconfig`, `compatibility`,
  `integrations`, `jobs`, `inventory`, `redaction`, and `reporting` reserve
  explicit product boundaries. Their behavior is added only by the governing
  delivery tasks.

SQLite contains the migration ledger, service metadata, the Argon2id
administrator verifier, an authentication epoch, and hashed session and expiry
metadata. Passwords and raw session or CSRF tokens are never stored. Native
YAML, provider credentials, EAB secrets, ACME accounts, certificates, chains,
private keys, archives, and desired configuration do not belong in application
state.

The browser is a same-origin client gated by the local administrator session.
An explicit HTTPS public origin is the authority for Host and Origin checks;
forwarded host and protocol fields never change security decisions. Only an
explicitly trusted loopback proxy can contribute a bounded client-address
chain for login limiting. Node.js is used only to build and verify the browser;
no Node.js runtime is part of the production topology.

The browser shell is composed from authored tokens and semantic components.
React Aria supplies headless interaction behavior, while the application owns
all visual styling and repository-authored SVG. The in-application component
catalog and Playwright visual and accessibility suites are shared contracts for
later feature screens; see `visual-system.md`.
