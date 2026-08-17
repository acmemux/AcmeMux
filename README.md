# AcmeMux

AcmeMux is an open-source, self-hosted graphical control plane for one
qualified upstream [lego](https://go-acme.github.io/lego/) runtime and one
native workspace. The current pre-release foundation gives one administrator
typed configuration, constrained issuance and renewal evaluation, one durable
daily schedule, certificate health, and a bounded redacted result. Lego remains
the ACME client and owns its native accounts, certificates, and private keys.

The destination is a broader certificate lifecycle control plane for
discovery, public and private issuance, deployment, policy, team access,
integrations, audit evidence, and recovery. Those capabilities will arrive only
as separately accepted and verified slices; they are direction, not current
support.

[Website](https://acmemux.com) | [Live dogfood](https://acmemux.com/certificate-status/) | [Documentation](docs/installation.md) | [Roadmap](https://acmemux.com/roadmap/) | [Discussions](https://github.com/acmemux/AcmeMux/discussions) | [Sponsor](https://acmemux.com/sponsor/)

## Why AcmeMux

Lego is a capable command-line ACME client with broad provider support. AcmeMux
adds a deliberately narrow operational layer for administrators who want to:

- review supported configuration through typed forms instead of raw YAML;
- run constrained certificate operations without exposing an arbitrary shell;
- persist one daily renewal-evaluation schedule across restarts;
- inspect current certificate health and one bounded, redacted result; and
- keep the existing native lego workspace as the source of truth.

AcmeMux does not reimplement ACME, copy private keys into a second store, or
claim support merely because a provider is compiled into lego.

## Project status

AcmeMux is pre-release software. The qualified deployment is a source build on
Debian 13 amd64 under the supplied systemd service, using only the exact lego
executables listed in [runtime compatibility](docs/runtime-compatibility.md).
Passing on another Linux distribution or architecture does not imply support.

There are no Debian, RPM, package-repository, or container artifacts yet. Do
not treat the current branch as a stable release or expose AcmeMux directly to
the internet. It must listen on loopback behind an HTTPS reverse proxy.

## Current supported scope

| Area | Supported now |
| --- | --- |
| Operator model | One administrator, one lego executable, one native workspace |
| Certificate authorities | Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, and the fixed GoDaddy ACME service |
| HTTP-01 | Unprivileged listener or existing webroot |
| DNS-01 | Azure DNS, Cloudflare, DigitalOcean, DuckDNS, and Amazon Route 53 |
| Operations | Manual whole-workspace certificate evaluation and one persistent daily automatic evaluation schedule |
| Reporting | Current native certificate health and one bounded latest redacted result |

Unsupported native fields and integrations are preserved, but they block
AcmeMux-managed edits and operations. The current product does not provide raw
YAML editing, arbitrary commands, multiple users or workspaces, certificate
deployment, notifications, or long-term operation history.

## Install and first setup

The source installation requires Go 1.26.6, Node.js 20.19.2, npm 9.2.0, GNU
Make, and a supported lego executable. Follow the
[installation guide](docs/installation.md) to build and verify the single
executable, install the hardened systemd service, configure HTTPS, and run it
under a dedicated or compatible existing non-root account.

After installation:

1. Create the single administrator from a local terminal.
2. Sign in through the configured HTTPS address.
3. Inspect and adopt a supported lego executable.
4. Adopt an existing native workspace or create a supported configuration.
5. Review certificate inventory and configuration before starting an operation.
6. Enable daily automatic evaluation only after checking its time zone and next UTC evaluation.

The browser does not download lego, repair host permissions, or move native
workspace files. Those host prerequisites remain under the operator's control.

## Security boundary

AcmeMux is intended to run as a non-root service on the same trusted host as
the lego workspace. Browser requests map to typed, reviewed operations. Host
filesystem ownership, DNS credentials, ACME account keys, certificate private
keys, reverse-proxy TLS, backups, and deployment into consuming services remain
operator responsibilities. Read the full [security model](docs/security.md)
before installation.

Security vulnerabilities should be reported through the
[GitHub private vulnerability process](https://github.com/acmemux/AcmeMux/security/advisories/new),
not by email or in a public issue or Discussion.

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

## Dogfooding and product direction

The production website uses an internal AcmeMux instance, upstream lego,
Let's Encrypt DNS-01, and a narrowly scoped Route 53 identity. AcmeMux
evaluates the native workspace, and upstream lego performs issuance; separate
least-privilege automation validates and activates the certificate served by
acmemux.com. The
[live status page](https://acmemux.com/certificate-status/) publishes the dates,
fingerprint, and next expected replacement so visitors can verify the result.

The current one-workspace control plane is the trusted foundation, not the end
goal. The [public roadmap](https://acmemux.com/roadmap/) describes the path
toward self-hosted certificate lifecycle management: discovery and unified
inventory; public, private, and external issuance; renewal and constrained
deployment; ownership, policy, templates, and approvals; team identity and
access; alerts, APIs, and integrations; audit and reporting evidence; and
backup, recovery, and resilience. Roadmap horizons do not promise a date,
order, support level, or architecture.

## Contributing, support, and sponsorship

- Read the [contribution guide](https://github.com/acmemux/.github/blob/main/CONTRIBUTING.md) before a large change.
- Use [Discussions](https://github.com/acmemux/AcmeMux/discussions) for questions, workflows, and roadmap proposals.
- Use [Issues](https://github.com/acmemux/AcmeMux/issues) for reproducible defects with redacted diagnostics.
- Read the [support policy](https://github.com/acmemux/.github/blob/main/SUPPORT.md); free support has no guaranteed response time.
- Review [sponsorship](https://acmemux.com/sponsor/). Support helps
  maintenance and qualified roadmap work; it does not provide an SLA or
  guarantee feature delivery.

## License

AcmeMux is licensed under the [Apache License 2.0](LICENSE).
