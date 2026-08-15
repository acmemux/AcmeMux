# Development

Run commands from the application repository. `make bootstrap` installs the
locked npm dependency graph, the pinned Chromium browser used by Playwright,
and its standard Linux runtime packages (using the platform package manager).
It does not install Go or Node.js; the exact supported host toolchains are
listed in the repository README and checked before every aggregate verification.

`make verify` runs:

- Go formatting, vet, Staticcheck, unit tests, race tests, and govulncheck;
- npm high-severity audit, Prettier, ESLint, TypeScript, Vitest, and Playwright;
- the React production build; and
- a CGO-free native Go build that embeds the compiled browser and migrations.

Task-specific browser targets include `make test-web`,
`make test-accessibility`, and `make test-visual`. `make catalog` opens the
isolated component catalog at `/?catalog=components`. When an accepted visual
change intentionally updates the baselines, `make test-visual-update`
regenerates them for review.

The application repository contains only product source, tests, configuration,
and user-facing application documentation. Product lifecycle documents,
agent guidance, and harness scripts belong to the separate harness repository.
