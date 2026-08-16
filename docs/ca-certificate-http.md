# CA, certificate, and HTTP-01 configuration

AcmeMux exposes reviewed typed forms for the accepted ACME account,
certificate, renewal, storage, and HTTP-01 fields in native `lego` YAML. The
native file remains authoritative. AcmeMux does not keep a desired copy in
SQLite, accept an arbitrary directory URL, or expose a raw YAML editor.

The forms are available only with an exact supported Linux amd64 `lego`
runtime. Existing native content outside this integration is preserved, but an
unsupported CA, challenge, hook, output, CSR, PFX, custom server, or unknown
field blocks managed execution.

## Create or edit a workspace

To create the first native configuration, provide an existing absolute working
directory and either use conventional `.lego.yml` discovery or name an
explicit absolute configuration path. The configuration target must be absent,
its parent must be safe and writable by the service identity, and every
referenced storage or webroot directory must already exist and pass the native
path review. AcmeMux does not create, relocate, change ownership of, or change
permissions on those directories.

Creation uses the same preview, immediate session reauthorization, restrictive
staging, synchronization, no-replace activation, and durable recovery boundary
as an edit. An existing target is never overwritten by creation. If activation
is interrupted, the configuration screen reports recovery even though no
workspace selection existed before the attempt.

For an adopted workspace, the screen projects the supported fields from the
current native YAML. A preview identifies the logical fields and safe public
before and after values. Saving rereads and revalidates the runtime, source
bytes, filesystem evidence, and candidate path set before any native rename.

## Accepted certificate authorities

New forms write the upstream shortcode where one exists. The equivalent exact
upstream directory URL is also recognized in an adopted file and is preserved
until the administrator changes the selection.

| Form choice | Native value written | Exact directory | Environment and prerequisite |
| --- | --- | --- | --- |
| Let's Encrypt production | `letsencrypt` | `https://acme-v02.api.letsencrypt.org/directory` | Publicly trusted production service |
| Let's Encrypt staging | `letsencrypt-staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` | Untrusted staging certificates; keep staging account material separate |
| ZeroSSL production | `zerossl` | `https://acme.zerossl.com/v2/DV90` | Account email assistance or explicit External Account Binding |
| Google Trust Services production | `googletrust` | `https://dv.acme-v02.api.pki.goog/directory` | Account-issued EAB credentials |
| Google Trust Services staging | `googletrust-staging` | `https://dv.acme-v02.test-api.pki.goog/directory` | Separate staging EAB credentials; untrusted staging certificates |
| SSL.com RSA production | `sslcomrsa` | `https://acme.ssl.com/sslcom-dv-rsa` | Account-issued EAB credentials |
| SSL.com ECDSA production | `sslcomecc` | `https://acme.ssl.com/sslcom-dv-ecc` | Account-issued EAB credentials |
| GoDaddy CA production | `https://acme.godaddy.com/v1/acme/directory` | `https://acme.godaddy.com/v1/acme/directory` | Entitled GoDaddy ACME account and account-issued EAB credentials |

GoDaddy CA is the fixed ACME directory above. It is unrelated to the upstream
`godaddy` DNS provider, which is not an accepted DNS integration. AcmeMux does
not accept another custom URL through this exception.

The Google Trust Services, SSL.com, and GoDaddy choices require EAB when a new
native account will be registered. ZeroSSL can use its upstream email-assisted
registration when an email is present or explicit EAB when supplied. Terms
acknowledgement is required for a new account, and new Let's Encrypt accounts
require the contact email shown in the form. An unchanged, already-registered
native account can remain usable after registration-only inputs have been
removed; changing its CA or creating another account repeats the registration
prerequisite checks.

The EAB key identifier is a public native field. The HMAC is accepted only as
bounded URL-safe base64 and is write-only: responses and review summaries show
presence or replacement, never the value. Both fields live in native YAML.
They are not copied into SQLite, a journal, a URL, or a diagnostic.

GoDaddy compatibility here means that the exact native mapping and admitted
`lego` source path are tested. Ordinary verification has no GoDaddy
entitlement or account secret and does not claim a live credentialed issuance.

## Accounts and certificates

Account, challenge, and certificate names use a conservative native-safe ASCII
identifier. The restriction prevents traversal and prevents two logical
certificate names from collapsing to the same upstream artifact filename.
Names are stable native map keys; changing a name is modeled as creating a new
entry rather than silently moving native account or certificate material.

The account form selects its CA, contact email, account-key type, terms
acknowledgement, and optional or required EAB. Account and certificate key
choices are limited to the intersection supported by the exact upstream
schema and source model: `EC256`, `EC384`, `RSA2048`, `RSA4096`, and `RSA8192`.
Changing the YAML key type does not rotate an already stored ACME account key.
Create a new account name when changing account-key identity. Also use a new
account name when moving between the SSL.com RSA and ECDSA directories: both
directories share one storage host, so reusing the name would address the same
native account directory.

Each certificate has a native name, one or more unique lowercase ASCII DNS
names, an account reference, an HTTP challenge reference, and a certificate-key
type. A wildcard can be represented by a leftmost `*.` label, but it cannot be
saved with HTTP-01 because ACME wildcard authorization requires DNS-01. Use a
supported DNS integration when it becomes available; AcmeMux does not attempt
an HTTP fallback.

External CSR, preferred-chain, profile, requested validity, common-name,
bundle, must-staple, authorization-deactivation, and PFX controls are outside
this integration. If present in an adopted file, they are preserved and
reported as unsupported rather than silently removed.

## HTTP-01 modes

An HTTP challenge uses one of two native modes:

- Built-in listener: `address` is `:port`, `IPv4:port`, or
  `[IPv6]:port`. Public ACME validation still reaches TCP port 80. When lego
  listens on another port, a reverse proxy or port forward must send only the
  challenge traffic to that listener and preserve the validation host.
- Webroot: `webroot` names an existing safe directory. lego writes the token
  under `.well-known/acme-challenge/`; the administrator's existing web server
  must publish that directory at the domain root. Relative paths resolve from
  the reviewed effective working directory.

Webroot mode disables the built-in listener, so an explicit listener address
or proxy-header setting cannot remain active with it. A validation delay can
be used in either mode. The optional proxy header accepts a canonical HTTP
field-name token of at most 64 bytes; `Host`, `Forwarded`, and
`X-Forwarded-Host` cover the common transparent and reverse-proxy cases.

Binding directly to port 80 requires the selected `lego` executable, not the
AcmeMux service, to have the necessary host permission. The runtime review can
admit only the exact `cap_net_bind_service=ep` file capability; AcmeMux itself
runs without capabilities. The usual home-lab setup is an unprivileged
listener behind an explicit port forward or reverse proxy, or a reviewed
webroot.

HTTP memcached, HTTP S3, TLS-ALPN-01, DNS-PERSIST-01, and arbitrary challenge
fields are not selectable. They remain preserved but block managed execution.

## Renewal controls

The certificate form can set a days-remaining threshold, key reuse, random
sleep behavior, ACME Renewal Information (ARI) enablement, and a bounded ARI
wait duration. Leaving the days threshold at zero retains upstream's dynamic
lifetime-based decision. Random delay remains enabled by default and helps
avoid synchronized renewal load. ARI remains enabled by default; a CA that does
not advertise it falls back to the ordinary renewal threshold. AcmeMux limits
the configured ARI wait to ten minutes so later broker operations remain
bounded while holding the single native workspace lease.

Changing domains causes upstream lego to obtain replacement certificate
material even when the existing certificate is outside its ordinary renewal
window. AcmeMux previews the native configuration change but does not issue or
renew a certificate until a later constrained operation is explicitly run.

## Troubleshooting

- `unsupported_ca` means the adopted account uses a shortcode, custom URL, or
  named `servers` entry outside the accepted choices.
- A registration-prerequisite finding means a new account or changed CA needs
  terms acknowledgement, email-assisted ZeroSSL registration, or EAB.
- A wildcard finding means the certificate must use DNS-01 rather than the
  selected HTTP challenge.
- An unsafe-path finding means the configuration parent, storage, or webroot
  does not meet the reviewed ownership, mode, access, or no-symlink policy.
- A low-port notice means lego needs a host port forward, reverse proxy,
  webroot, or its separately reviewed low-port file capability.
- `recovery_required` means an interrupted native-file activation must be
  classified and resolved before another workspace mutation or managed run.

See `native-configuration.md` for review tokens, write-only secret handling,
atomic replacement, and recovery details; `workspace-adoption.md` for path and
permission rules; and `runtime-compatibility.md` for the exact executable
boundary.
