# AcmeMux

AcmeMux is a graphical control plane for one existing [lego](https://go-acme.github.io/lego/) ACME client and one native lego workspace. It helps a self-hosted administrator configure supported certificate authorities and challenge providers, run certificate operations, schedule daily renewal evaluation, and inspect safe results without replacing lego or copying its certificates and private keys into another store.

## Project status

AcmeMux is pre-release software. The current build supports Linux amd64 and only the exact lego executables listed in [runtime compatibility](docs/runtime-compatibility.md). A packaged installer and systemd unit are not yet available, so evaluation currently requires a source build and an administrator-managed service process.

Do not treat the current branch as a stable release or expose it directly to the internet. AcmeMux must listen on loopback behind an HTTPS reverse proxy.

## Install

The current source installation requires Go 1.26.6, Node.js 20.19.2, npm 9.2.0, GNU Make, and a supported lego executable. Follow the [installation guide](docs/installation.md) to build the single AcmeMux executable, create its state directory, configure HTTPS, and start it under a dedicated non-root account.

## First setup

After installation:

1. Create the single administrator from a local terminal.
2. Sign in through the configured HTTPS address.
3. Inspect and adopt a supported lego executable.
4. Adopt an existing native workspace or create a supported configuration.
5. Review the certificate inventory and configuration before starting an operation.
6. Enable the daily automatic schedule only after its time zone and next UTC evaluation are correct.

The browser does not download lego, repair host permissions, or move native workspace files. Those host prerequisites remain under the operator's control.

## Use AcmeMux

AcmeMux supports one administrator, one lego executable, and one native workspace. Native YAML, credential files, ACME accounts, certificates, chains, private keys, archives, and renewal behavior remain owned by lego. AcmeMux provides reviewed forms and constrained operations around that workspace.

The current product covers:

- Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, and the fixed GoDaddy ACME service;
- HTTP-01 through an unprivileged listener or an existing webroot;
- DNS-01 through Azure DNS, Cloudflare, DigitalOcean, DuckDNS, and Amazon Route 53;
- manual whole-workspace certificate evaluation; and
- one persistent daily automatic evaluation schedule; and
- current native certificate health with one bounded latest redacted result.

Unsupported native fields and integrations are preserved but block AcmeMux-managed edits and operations. AcmeMux does not offer arbitrary commands, raw YAML editing, multiple users or workspaces, certificate deployment, notifications, or long-term operation history.

## Documentation

- [Installation and first start](docs/installation.md)
- [Security and trusted-host responsibilities](docs/security.md)
- [Supported lego executables](docs/runtime-compatibility.md)
- [Native workspace adoption](docs/workspace-adoption.md)
- [Configuration editing and recovery](docs/native-configuration.md)
- [Certificate authorities, certificates, renewal, and HTTP-01](docs/ca-certificate-http.md)
- [DNS-01 providers](docs/dns-providers.md)
- [Manual certificate operations](docs/manual-operations.md)
- [Automatic renewal evaluation](docs/automatic-renewal.md)
- [Certificate health and latest reporting](docs/certificate-health-and-reporting.md)

## Support

AcmeMux is currently maintained by one owner and does not yet publish a contribution or community-support process. Use the browser's reported state and the troubleshooting sections in these guides before changing the native workspace. Security reporting and public issue-handling details will be published before the first stable release.
