# Development

Run commands from the application repository. `make bootstrap` installs the
locked npm dependency graph, the pinned Chromium browser used by Playwright,
and its standard Linux runtime packages (using the platform package manager).
It does not install Go or Node.js; the exact supported host toolchains are
listed in the repository README and checked before every aggregate verification.

`make verify` runs:

- Go formatting, vet, Staticcheck, unit tests, race tests, and govulncheck;
- npm audit at every reported severity, Prettier, ESLint, TypeScript, Vitest,
  and Playwright;
- the React production build; and
- a CGO-free native Go build that embeds the compiled browser and migrations.

Task-specific browser targets include `make test-web`,
`make test-accessibility`, and `make test-visual`. `make catalog` opens the
isolated component catalog at `/?catalog=components`. When an accepted visual
change intentionally updates the baselines, `make test-visual-update`
regenerates them for review.

`make test-identity` runs the focused administrator, password, session,
request-security, command, and persistence checks. Browser tests mock the
typed same-origin session API to exercise visual states; Go integration tests
remain authoritative for Secure and HttpOnly cookies, origin, CSRF, proxy,
rate-limit, restart, and SQLite behavior.

`make test-runtime` runs the executable audit, bounded probe, retained-file,
replacement, persistence, authenticated API, and startup integration checks.
`make test-compatibility` verifies exact manifest classification, the bundled
upstream schema and license, commit-labelled source inventories, provider
trees and descriptors, and executable evidence fixtures. It uses immutable
checked-in evidence and does not fetch upstream during ordinary verification.
The trusted-local-checkout qualification and update procedure is in
`runtime-compatibility.md`.

`make test-workspace` runs native configuration discovery, bounded YAML path
projection, component and permission auditing, review continuity, shared
workspace coordination, journaled per-file replacement, interruption
classification, recovery, and SQLite selection checks. `make test-inventory`
runs the no-shell upstream inventory, native artifact reconciliation, output
and tree bounds, and empty-storage behavior. Opt-in real-executable inventory
checks use an explicit qualified path through `ACMEMUX_TEST_LEGO`.

The native configuration boundary also has focused package suites:

```sh
make test-integrations
make test-nativeconfig
make test-configuration

go test ./internal/integrations/... \
  ./internal/nativeconfig/... \
  ./internal/dotenv/... \
  ./internal/configuration/... \
  ./internal/redaction/... \
  ./internal/httpapi/...
```

These cover manifest validation, YAML round trips and unsupported structures,
dotenv preservation and write-only values, schema and semantic checks, opaque
review continuity, authenticated preview and save, redaction, concurrent
changes, crash boundaries, and non-replay recovery. The aggregate
`make verify` remains authoritative.

The manual-operation boundary has focused suites as well:

```sh
make test-broker
make test-jobs
make test-redaction
ACMEMUX_TEST_LEGO=/absolute/path/to/source-built/lego \
ACMEMUX_TEST_PEBBLE=/absolute/path/to/pebble-v2.10.1 \
ACMEMUX_TEST_CHALLTESTSRV=/absolute/path/to/pebble-challtestsrv-v2.10.1 \
ACMEMUX_TEST_LEGO_SOURCE=/absolute/path/to/lego-source \
make test-lego-integration
```

The broker suite covers exact direct arguments and environment, no-shell
execution, path and input bounds, split-stream value redaction, output limits,
timeouts, signals, process groups, escaped descendants, and prepared-runtime
ownership. The jobs and operation suites cover durable enqueue, browser-context
separation, restart behavior, shared-lock exclusion, fresh native preflight,
result classification, and mandatory inventory reconciliation. The opt-in
source-built check requires explicit canonical paths for the reviewed
executable, pinned Pebble v2.10.1 and challenge-server executables, and the
matching upstream source fixtures; none are selected from the host `PATH`.
It starts the local upstream ACME infrastructure, obtains a real test
certificate through the broker, verifies native account and certificate
artifacts, then runs file mode again and proves upstream evaluated and skipped
a not-due renewal without rewriting the issued artifacts.

`make run` requires `ACMEMUX_PUBLIC_ORIGIN` to name the HTTPS address served by
the local reverse proxy. Direct HTTP remains available for health probes, but
it is deliberately not an authenticated browser-development mode.

The application repository contains only product source, tests, configuration,
and user-facing application documentation. Product lifecycle documents,
agent guidance, and harness scripts belong to the separate harness repository.
