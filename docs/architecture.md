# Application architecture

AcmeMux is one native Go service with an embedded React application and
embedded forward-only SQLite migrations. The process listens only on loopback
in the current foundation and is designed for systemd supervision under a
non-root operating-system identity.

## Boundaries

- `cmd/acmemux` owns process startup, signal handling, and graceful shutdown.
- `internal/httpapi` owns same-origin transport, health, readiness, and browser
  asset delivery.
- `internal/state` owns application-only SQLite state and migrations.
- `internal/webassets` owns the browser build embedded into the executable.
- `internal/identity`, `workspace`, `nativeconfig`, `compatibility`,
  `integrations`, `jobs`, `inventory`, `redaction`, and `reporting` reserve
  explicit product boundaries. Their behavior is added only by the governing
  delivery tasks.

SQLite currently contains only a migration ledger and service creation
metadata. Native YAML, provider credentials, EAB secrets, ACME accounts,
certificates, chains, private keys, archives, and desired configuration do not
belong in application state.

The browser is a same-origin client. Node.js is used only to build and verify
it; no Node.js runtime is part of the production topology.
