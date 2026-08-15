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

The application repository contains only product source, tests, configuration,
and user-facing application documentation. Product lifecycle documents,
agent guidance, and harness scripts belong to the separate harness repository.
