# Dependency baseline

The foundation uses a deliberately small production dependency set.

| Dependency | Pinned version | Role | License and maintenance evidence |
|---|---:|---|---|
| Go | 1.26.6 | Native service toolchain | BSD-3-Clause; maintained Go release with the current standard-library security fixes |
| Node.js / npm | 20.19.2 / 9.2.0 | Browser build and test toolchain only | MIT / Artistic-2.0; Debian security-maintained Node.js package and locked npm CLI |
| modernc.org/sqlite | 1.56.0 | Pure-Go SQLite driver | BSD-3-Clause; current canonical release with active release history |
| React / React DOM | 19.2.8 | Browser component runtime | MIT; current npm releases |
| React Aria Components | 1.20.0 | Headless accessible component behavior | Apache-2.0; current Adobe React Spectrum release with React 19 support |

Direct build and verification dependencies are also exact-pinned:

| Dependency group | Pinned versions | License and maintenance evidence |
|---|---|---|
| Vite / React plugin | 8.2.1 / 6.0.5 | MIT; current releases supporting Node.js 20.19.2 |
| TypeScript / Node, React, and React DOM types | 5.9.3 / 20.19.43 / 19.2.18 / 19.2.4 | Apache-2.0 / MIT; active canonical packages |
| Vitest / jsdom | 4.1.10 / 27.4.0 | MIT; current compatible releases |
| Testing Library React / jest-dom | 16.3.2 / 6.9.1 | MIT; active canonical packages |
| ESLint / JavaScript config / TypeScript ESLint / React Hooks / globals | 10.8.1 / 10.0.1 / 8.67.0 / 7.1.1 / 17.11.0 | MIT; active canonical packages |
| Prettier | 3.9.6 | MIT; current canonical release |
| Playwright Test | 1.62.1 | Apache-2.0; current canonical release |
| axe Playwright | 4.13.0 | MPL-2.0; current Deque browser accessibility integration, used only for verification |
| Staticcheck | 0.7.0 | MIT; current tagged release |
| govulncheck | 1.7.0 | BSD-3-Clause; current tagged release |

Direct verification dependencies are pinned in `web/package.json` and the
application Makefile. `go.sum` and `package-lock.json` lock the complete
dependency graphs. `govulncheck` and `npm audit --audit-level=high` are
mandatory verification gates.

Dependency changes require review of upstream maintenance, licenses, supported
toolchains, and vulnerability results before acceptance.

The visual system uses system fonts and repository-authored CSS and SVG. It has
no external font, icon, image, dashboard-template, or component-workshop asset
dependency.
