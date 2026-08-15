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

`make run` requires `ACMEMUX_PUBLIC_ORIGIN` to name the HTTPS address served by
the local reverse proxy. Direct HTTP remains available for health probes, but
it is deliberately not an authenticated browser-development mode.

The application repository contains only product source, tests, configuration,
and user-facing application documentation. Product lifecycle documents,
agent guidance, and harness scripts belong to the separate harness repository.
