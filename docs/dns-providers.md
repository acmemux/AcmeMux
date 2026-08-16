# Core DNS-01 providers

AcmeMux supports DNS-01 through the upstream `lego` provider codes
`cloudflare`, `digitalocean`, and `duckdns` in the current core provider
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

Upstream `_FILE` environment variants are not an AcmeMux credential path: they
would introduce an additional secret file outside the adopted manifest-owned
dotenv boundary. Import the credential through the write-only field instead.

## Troubleshooting

- An incomplete or mixed authentication mode is rejected before native files
  change. Choose exactly one Cloudflare token or legacy-key mode and avoid
  duplicate `CF_*` and `CLOUDFLARE_*` spellings.
- An unsupported dotenv key is preserved but blocks managed execution. Remove
  it only after confirming it is not required outside AcmeMux.
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
