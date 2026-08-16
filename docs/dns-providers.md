# DNS-01 providers

AcmeMux supports DNS-01 through the upstream `lego` provider codes
`azuredns`, `cloudflare`, `digitalocean`, `duckdns`, and `route53` in the current cloud provider
manifest. The exact admitted Linux amd64 `lego` artifacts are the same
v5.3.1 and reviewed source-revision artifacts documented in
`runtime-compatibility.md`. A provider compiled into another executable is not
automatically supported.

Each DNS challenge writes its provider code, resolver behavior, propagation
policy, and one `envFile` reference into native YAML. Credentials and provider
overrides remain only in that restrictive native dotenv file. AcmeMux never
copies them into SQLite, returns secret values to the browser, or places them
in process arguments. Upstream `lego` loads the file and performs every DNS API
request.

The service process environment is never inherited. Cloud authentication is
an explicit union: selecting one mode removes variables belonging to other
modes. AcmeMux audits every selected credential or token file without following
links, requires confidential ownership and mode, and rechecks its identity
before execution. It does not supply a default `HOME`. Azure CLI mode names one
audited `az` helper directory and cache directory; AWS shared-profile mode names
one audited credentials file and profile. Managed and instance identity modes
are the only modes that permit their documented metadata service.

## Azure DNS

Azure DNS maps public, US Government, and China clouds; subscription, resource
group, exact zone, and public/private-zone selection to upstream `AZURE_*`
variables. Choose exactly one service-principal secret or certificate,
workload identity, managed identity, Azure CLI, OIDC, or Azure Pipelines mode.
Certificate, workload, and assertion files are audited confidential files.
Azure Arc endpoints must be a complete loopback-HTTP pair. CLI mode uses an
audited executable in a single-directory `PATH` and an explicit
`AZURE_CONFIG_DIR`. OIDC accepts exactly one inline assertion, audited assertion
file, or HTTPS assertion endpoint plus write-only bearer token.

AcmeMux always sets upstream `AZURE_AUTH_METHOD`; the SDK's broad default chain
is not exposed. For an OIDC assertion file, AcmeMux snapshots the audited bytes
into sensitive operation memory while retaining the file path, satisfying
upstream's equality check and preventing a file-only assertion race.

Grant Reader on the exact DNS zone and DNS Zone Contributor only on required
`_acme-challenge` TXT record sets. Private DNS uses the corresponding
private-zone scope. Avoid subscription-wide Contributor.

## Amazon Route 53

Route 53 requires an explicit region and one base identity: static or temporary
credentials, one audited shared profile, or an explicitly acknowledged EC2
instance role. Static and shared modes set `AWS_EC2_METADATA_DISABLED=true`;
only instance-role mode enables metadata. `AWS_SDK_LOAD_CONFIG=false` and the
absence of `HOME` prevent implicit config, SSO, nested profile, and helper
discovery. A shared profile may contain only an access key, secret key, and
optional session token. AcmeMux snapshots those selected values into sensitive
broker variables so the SDK cannot race or recurse through the file.

Any base identity may assume one explicit role; an external ID is accepted only
with that role. Hosted-zone override, public/private zone, change waiting,
retry count, TTL, propagation timeout, and polling interval map to upstream.
For least privilege, allow `route53:GetChange`, and constrain
`ListResourceRecordSets` and `ChangeResourceRecordSets` to the selected zone,
TXT type, and normalized `_acme-challenge` names. `ListHostedZonesByName` is
needed only without a hosted-zone override. A separate base identity needs only
`sts:AssumeRole` when the DNS role owns those permissions.

## Cloudflare

Prefer a scoped API token. The normal single-token path uses
`CLOUDFLARE_DNS_API_TOKEN` with both `Zone / DNS / Edit` and `Zone / Zone /
Read`, scoped only to the zones used by this workspace. For tighter separation,
use a DNS token with `Zone / DNS / Edit` and a second
`CLOUDFLARE_ZONE_API_TOKEN` with `Zone / Zone / Read`.

The legacy account-email plus Global API Key flow is supported for existing
operators, but the form warns that the key grants broad account access. The
Origin CA Key is not accepted. AcmeMux understands upstream `CF_*` fallback
spellings in adopted files, prevents duplicate spellings and mixed token and
legacy modes, and writes the preferred `CLOUDFLARE_*` names on replacement.

Optional exact upstream overrides cover TXT TTL, propagation timeout, polling
interval, HTTP timeout, and API base URL. Cloudflare requires a TXT TTL of at
least 120 seconds. Endpoint overrides require HTTPS, except loopback HTTP used
by an isolated test service.

## DigitalOcean

Create a token able to manage DNS records for the intended account and supply
it as the write-only `DO_AUTH_TOKEN`. Optional exact upstream overrides cover
the API URL, TXT TTL, propagation timeout, polling interval, and HTTP timeout.
Endpoint overrides require HTTPS, except loopback HTTP for isolated tests.

## DuckDNS

Supply the account token as the write-only `DUCKDNS_TOKEN`. DuckDNS has one TXT
record shared by a registered domain and its subdomains. Upstream `lego`
therefore performs DuckDNS challenges sequentially; the form exposes the
source-backed sequence interval along with propagation, polling, and HTTP
timeouts.

## Credential rotation

Open the existing DNS challenge, choose Replace for the credential being
rotated, and preview the change. Secret summaries show only that a value will
be replaced. Saving uses the shared workspace lock and the journaled
same-directory `0600` replacement flow. For split Cloudflare tokens, rotate
the DNS and zone tokens together when the provider change requires both.

Changing an adopted challenge to a different provider is intentionally not an
in-place form operation. Add a new challenge with its own credential file,
reassign certificates, review and save, then remove the old native integration
in a separately reviewed cleanup. This keeps every credential-file transition
explicit and auditable.

Rotate Azure secrets, certificates, assertions, CLI caches, AWS static
sessions, or shared-profile files at their native source, then preview the
native field or file identity change before running. Temporary sessions must
remain valid for the complete operation timeout. Changing a cloud
authentication mode removes obsolete variables in the same journaled dotenv
replacement; review the operation preview for file, helper, and metadata
consequences.

Upstream `_FILE` environment variants are not an AcmeMux credential path: they
would introduce an additional secret file outside the adopted manifest-owned
dotenv boundary. Import the credential through the write-only field instead.

## Troubleshooting

- An incomplete or mixed authentication mode is rejected before native files
  change. Choose exactly one Cloudflare token or legacy-key mode and avoid
  duplicate `CF_*` and `CLOUDFLARE_*` spellings.
- An unsupported dotenv key is preserved but blocks managed execution. Remove
  it only after confirming it is not required outside AcmeMux.
- Azure files must be absolute, confidential, single-link regular files. Azure
  Arc metadata endpoints are loopback-only; CLI mode fails if `az` or its cache
  directory is untrusted.
- Route 53 shared profiles reject config keys, role recursion, SSO, and helper
  processes. An instance role must be selected explicitly; other AWS modes
  cannot fall back to metadata.
- Resolver overrides accept at most eight host or IP values with optional
  ports. A fixed propagation wait cannot be mixed with disabled authoritative
  or recursive checks.
- A provider error may follow an external DNS change. Inspect the refreshed
  native inventory and redacted result before retrying.
- DuckDNS names must ultimately map to the account's registered DuckDNS domain;
  upstream reports provider-specific naming failures.

The credentialed release smoke is deliberately separate from ordinary tests.
`make test-provider-core-smoke` requires an isolated native configuration and
explicit `ACMEMUX_PROVIDER_SMOKE=1`; it discards upstream output so provider
responses cannot enter routine logs or fixtures.
