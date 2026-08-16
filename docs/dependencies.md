# Dependency baseline

The foundation uses a deliberately small production dependency set.

| Dependency | Pinned version | Role | License and maintenance evidence |
|---|---:|---|---|
| Go | 1.26.6 | Native service toolchain | BSD-3-Clause; maintained Go release with the current standard-library security fixes |
| Node.js / npm | 20.19.2 / 9.2.0 | Browser build and test toolchain only | MIT / Artistic-2.0; Debian security-maintained Node.js package and locked npm CLI |
| modernc.org/sqlite | 1.56.0 | Pure-Go SQLite driver | BSD-3-Clause; current canonical release with active release history |
| golang.org/x/crypto | 0.55.0 | Argon2id password verification | BSD-3-Clause; current Go cryptography subrepository release maintained by the Go project |
| golang.org/x/sys | 0.47.0 | Linux file-capability inspection at the executable trust boundary | BSD-3-Clause; current Go system-interface subrepository release maintained by the Go project |
| golang.org/x/term | 0.45.0 | No-echo local administrator password input | BSD-3-Clause; current Go terminal subrepository release maintained by the Go project |
| go.yaml.in/yaml/v3 | 3.0.5 | Bounded native YAML path discovery plus authoritative node-tree projection and editing | MIT / Apache-2.0; current canonical go-yaml v3 release with active maintenance |
| github.com/joho/godotenv | 1.5.1 | Upstream-compatible parsing inside the bounded, line-preserving exact-key dotenv editor | MIT; stable feature-complete library whose upstream scope accepts compatibility and bug fixes |
| github.com/santhosh-tekuri/jsonschema/v6 | 6.0.3 | Offline compilation and validation of the exact bundled upstream Draft 7 schema | Apache-2.0; exact v6 release from a standards-conformance project with Draft 7 test-suite coverage |
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
dependency graphs. `govulncheck` and `npm audit --audit-level=low` are
mandatory verification gates.

Dependency changes require review of upstream maintenance, licenses, supported
toolchains, and vulnerability results before acceptance.

The visual system uses system fonts and repository-authored CSS and SVG. It has
no external font, icon, image, dashboard-template, or component-workshop asset
dependency.

The compatibility package embeds upstream `lego`'s v5.3.1 JSON Schema and full
MIT license notice as reviewed data assets. AcmeMux does not link or embed the
`lego` library or executable. Asset provenance and deliberate update checks are
documented in `runtime-compatibility.md`.

`godotenv` is not used to load arbitrary process environment into AcmeMux. The
application first applies its own UTF-8, size, line, duplicate-key,
manifest-key, and expansion checks, then invokes the parser only for one
bounded managed statement at a time. `jsonschema/v6` is configured for Draft 7
and a rejecting resource loader; schema validation performs no network or
filesystem resolution.
