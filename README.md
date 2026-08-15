# AcmeMux

AcmeMux is a native graphical control plane for one administrator-provisioned
upstream `lego` executable and one authoritative native `lego` workspace. It
does not implement ACME, embed `lego`, or copy native account, certificate, or
private-key material into its own state.

The production artifact is one Go executable. It embeds the React browser
application and forward-only SQLite migrations, listens on loopback by
default, and is intended to run as a non-root systemd service.

## Prerequisites

- Go 1.26.6
- Node.js 20.19.2
- npm 9.2.0
- GNU Make

Install the pinned project dependencies and browser test runtime:

```sh
make bootstrap
```

Run every repository quality gate:

```sh
make verify
```

Build the native executable at `dist/acmemux`:

```sh
make build
```

Start a local development instance with application-owned state under
`./var`:

```sh
make run
```

The service exposes liveness at `/healthz`, readiness at `/readyz`, and the
embedded browser application at `/`. The default listener is
`127.0.0.1:8080`; a non-loopback listener is deliberately rejected.

See [docs/architecture.md](docs/architecture.md),
[docs/development.md](docs/development.md), and
[docs/dependencies.md](docs/dependencies.md) for the current application
boundaries and contributor workflow. The accepted visual and component rules
are documented in [docs/visual-system.md](docs/visual-system.md); run
`make catalog` to inspect the isolated component catalog.
