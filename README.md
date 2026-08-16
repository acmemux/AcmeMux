# AcmeMux

AcmeMux is a native graphical control plane for one administrator-provisioned
upstream `lego` executable and one authoritative native `lego` workspace. It
does not implement ACME, embed `lego`, or copy native account, certificate, or
private-key material into its own state.

The production artifact is one Go executable. It embeds the React browser
application and forward-only SQLite migrations, listens on loopback by
default, and refuses to serve with root user or group identities, supplementary
group 0, or process capabilities.

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

Bootstrap the only administrator from a local terminal, then start a local
development instance with application-owned state under `./var` and an
explicit HTTPS browser origin:

```sh
./dist/acmemux admin bootstrap --state-dir ./var
./dist/acmemux serve \
  --state-dir ./var \
  --public-origin https://acmemux.example.test \
  --trusted-proxies 127.0.0.1/32
```

The authenticated browser is intentionally unavailable over direct HTTP. A
local HTTPS reverse proxy must preserve the public `Host` and can supply the
client chain only from an explicitly trusted loopback address.

The service exposes liveness at `/healthz`, readiness at `/readyz`, and the
embedded browser application at `/`. The default listener is
`127.0.0.1:8080`; a non-loopback listener is deliberately rejected.

See [docs/architecture.md](docs/architecture.md),
[docs/development.md](docs/development.md), and
[docs/dependencies.md](docs/dependencies.md) for the current application
boundaries and contributor workflow. The accepted visual and component rules
are documented in [docs/visual-system.md](docs/visual-system.md); run
`make catalog` to inspect the isolated component catalog. Administrator,
session, HTTPS, and reverse-proxy operation is documented in
[docs/security.md](docs/security.md). Exact upstream executable support,
selection, permissions, and upgrade qualification are documented in
[docs/runtime-compatibility.md](docs/runtime-compatibility.md). Native workspace
selection, path review, persistence, and certificate inventory are documented
in [docs/workspace-adoption.md](docs/workspace-adoption.md). Curated native
field projection, write-only credentials, reviewed replacement, bounds, and
interrupted-edit recovery are documented in
[docs/native-configuration.md](docs/native-configuration.md). Accepted CA
presets, account registration prerequisites, certificate and renewal fields,
HTTP-01 listener or webroot setup, and first-workspace creation are documented
in [docs/ca-certificate-http.md](docs/ca-certificate-http.md). Reviewed manual
workspace runs, durable browser-independent execution, the exact constrained
process boundary, reconciliation, and safe failure handling are documented in
[docs/manual-operations.md](docs/manual-operations.md). Cloudflare,
DigitalOcean, and DuckDNS authentication, least privilege, native mappings,
rotation, optional settings, and troubleshooting are documented in
[docs/dns-providers.md](docs/dns-providers.md).
