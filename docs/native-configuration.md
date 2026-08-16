# Native configuration mediation

AcmeMux treats the adopted native `lego` YAML and its referenced credential
files as authoritative. It does not keep a second desired-state document in
SQLite and does not provide a raw YAML editor, arbitrary environment-variable
editor, or generic command interface.

The production `native-cloud-dns-providers-v1` integration manifest projects
the curated storage, account, accepted CA, certificate, renewal, HTTP-01, and
Azure DNS, Cloudflare, DigitalOcean, DuckDNS, and Route 53 DNS-01 fields documented in
`ca-certificate-http.md` and `dns-providers.md`. It can create a first native
configuration or edit an adopted compatible one. The browser still receives
only logical field identifiers, bounded typed values, and server-derived
entity bindings; it never receives a native selector or a generic YAML edit
surface.

The integration is intentionally narrower than the upstream schema. DNS
providers other than those three, arbitrary servers, other CA endpoints,
TLS-ALPN, HTTP memcached or S3, hooks, CSR, PFX, output controls, and unknown
fields remain preserved but unsupported. Later integration manifests extend
this same reviewed boundary; no feature-specific raw API substitutes for a
curated manifest.

## Projection and preservation

The editor parses one UTF-8 YAML document into a `go.yaml.in/yaml/v3` node
tree. That tree, not the browser projection, remains the write source. A
curated manifest maps stable logical field IDs to server-owned YAML selectors
or exact dotenv keys. Browser requests contain only those logical IDs, typed
values, and declared entity bindings; native selectors and environment keys
are never supplied by the browser.

When a managed YAML value changes, AcmeMux edits only its node and encodes the
complete tree. Unedited mappings and sequences retain their logical ordering,
scalar representation, and comments where the YAML library can represent
them. Exact whitespace and byte formatting are not promised after a YAML
change. Dotenv edits are surgical byte-span replacements: unedited lines,
comments, export syntax, line endings, and unsupported keys remain unchanged.

The configuration state has these meanings:

- `creation_required`: no workspace is selected and the server has reviewed a
  safe working directory plus an absent conventional or explicit
  configuration target. The typed creation form can prepare the first native
  file.
- `ready`: the exact runtime schema, source-backed semantic checks, curated
  manifest, and referenced managed credential files all pass.
- `unsupported`: recognized native content is preserved but falls outside the
  current manifest. Supported fields can remain reviewable, but managed
  `lego` execution is blocked.
- `invalid`: the current document does not meet the complete managed contract.
  Structural, schema, credential-file, or path failures block editing. A
  schema-valid curated-field constraint can remain editable through the typed
  form so the administrator can repair it, but execution stays blocked and no
  candidate can be saved until the resulting document is valid.
- `recovery_required`: a durable edit journal has not been reconciled. No new
  edit can start.

Schema-recognized CA, provider, challenge, hook, output, PFX, and other native
settings outside the manifest are reported and preserved. An unrecognized
field blocks both replacement and execution because AcmeMux cannot prove its
meaning. YAML aliases, merge keys, custom tags, duplicate mapping keys,
multiple documents, invalid UTF-8, and excessive structure also block editing
rather than being normalized. The exact bundled Draft 7 schema is selected by
the reviewed runtime manifest and is compiled without filesystem or network
schema resolution. Source-backed semantic checks apply upstream defaults and
cross-field rules without invoking a mutating `lego` command.

## Preview and save continuity

Preview performs no native-file write. It reloads and fingerprints the exact
runtime, reviewed workspace, YAML, and referenced dotenv sources; builds the
candidate in memory; validates its schema, semantics, manifest rules, and
resolved paths; and returns a human-readable change summary.

The browser receives opaque HMAC review tokens, not source digests or native
values. The base-revision token binds the runtime manifest and complete runtime
review, workspace review, source paths, file identities, metadata, and source
content. The preview token additionally binds the logical changes and exact
candidate replacements. The token key is random and memory-only, so a service
restart invalidates outstanding tokens. Tokens are concurrency handles, not
authentication credentials: every request still requires the administrator
session, exact Origin and Host, and CSRF pair.

Save reconstructs the candidate and compares both tokens. Immediately before
the first active rename it revalidates the administrator session and original
CSRF pair, re-verifies the runtime, rereads every source, repeats candidate path
audits, and rejects any content, metadata, identity, reference, or placement
change. A stale browser review therefore cannot overwrite an external edit.

The review summary identifies the affected logical field and native file.
Public values show safe before and after values. A public value already
present but outside its curated contract is described as hidden unsupported
content so it can be repaired without echoing it. Secret changes show only
present, replaced, removed, or absent state.

## Write-only secrets and dotenv files

Manifest-owned dotenv fields are either write-only credentials or public
provider settings. Existing credential values are decoded only inside the
service long enough to check their curated length and text contract. The
browser receives presence and validity, never the secret value. Public timing,
TTL, and endpoint settings are projected as bounded strings so the form can
edit them. Secret controls offer keep, replace, or remove. A replacement is
written even when it might equal the stored value, so preview behavior does
not provide a secret equality oracle.

Only exact uppercase keys declared by the selected integration manifest can
be changed. Other syntactically valid keys are preserved and make the
configuration unsupported for managed execution. Duplicate keys, malformed
statements, invalid UTF-8, and variable expansion in a managed value block the
edit. New or replaced values are quoted and parsed back to prove their exact
round trip. A newly referenced credential file can be created only when its
resolved parent and missing target pass the same no-follow path audit.

Secret values can exist transiently in the password input, HTTPS request,
bounded process memory, candidate file, and later the allowlisted `lego` child
environment. Configuration responses, diagnostics, review summaries, journal
records, URLs, and SQLite application state omit them. Owned byte buffers are
cleared when practical, but Go strings, operating-system memory, swap, crash
dumps, filesystem snapshots, and a hostile process sharing the service UID
remain inside the trusted-host boundary.

The shared redaction primitive for later broker reporting accepts only a
bounded set of observed secret values and manifest-supplied sensitive field
keys. It filters exact raw values plus common URL, base64, and JSON encodings.
Its default construction limit is 128 values, 64 KiB per value, and 1 MiB of
derived variants; a caller must refuse to persist output when a complete
filter cannot be built. Redaction is defense in depth and does not replace the
configuration API's value-free responses and diagnostics.

## First configuration creation

Creation begins from a server-issued `creation_required` snapshot. The request
names one canonical absolute working directory and either an explicit absent
configuration path or the conventional `.lego.yml` target. With conventional
selection, AcmeMux proves that both `.lego.yml` and `.lego.yaml` are absent so
upstream precedence cannot change underneath the review. The browser repeats
the opaque base token with logical changes; it cannot select a different
native target, selector, environment key, or integration manifest.

The resulting configuration must be complete under the curated manifest.
Storage and every HTTP webroot directory must already exist and pass the
no-follow ownership, mode, and access policy. A referenced provider dotenv
file can be created in the same reviewed operation only when the manifest owns
its exact keys and its parent and absent target pass the same audit. AcmeMux
does not create or repair directories as a side effect of configuration
creation.

Preview is non-writing. Save reconstructs the exact candidate, rechecks the
review token and missing targets, immediately reauthorizes the administrator,
creates the durable journal, and activates restrictive same-directory files
with `RENAME_NOREPLACE`. An existing target is never overwritten. Fresh
inspection must prove the active bytes and the complete working, storage,
webroot, and source boundary before the first workspace selection is stored.

## Journaled per-file replacement

Preview, save, recovery, runtime and workspace adoption, inventory, and later
manual or scheduled runs share one workspace coordinator. A pending recovery
journal blocks either adopted boundary from changing. Save uses this sequence:

1. Audit the complete candidate path set, including storage, every dotenv
   reference, and every HTTP webroot.
2. Create a secret-free SQLite journal containing transaction phase, target
   paths, parent identity, and staged or active inode metadata. It contains no
   native bytes, content digest, field ID, change summary, or credential.
3. Create each candidate beside its target as a single-link, service-owned
   regular file with mode `0600`; write and synchronize the file and its
   directory.
4. Recheck every reviewed source, replacement parent, staged candidate,
   working directory, and candidate path, then reauthorize the administrator.
5. Activate each candidate with same-directory Linux `renameat2`, using an
   exchange for an existing file or no-replace semantics for a new file.
   Synchronize the directory and record the actual placement before removing
   the displaced source.
6. Inspect the complete active workspace again, compare active bytes with the
   validated candidates, refresh the durable workspace review, and clear the
   journal in the same SQLite finalization transaction.

Each rename is atomic for one file. A YAML-plus-dotenv edit is deliberately
not described as an all-filesystem transaction. A successful replacement is
owned by the AcmeMux service identity and has mode `0600`; direct `lego` use
must therefore run under the same intended identity. If a failure occurs
before any activation and cleanup can be proved, AcmeMux removes only its
identified staging files. Once an activation may have happened, it retains
the journal and fails closed instead of guessing or automatically rolling
back.

The filesystem must support same-directory `renameat2`, regular-file and
directory synchronization, stable inode evidence, and the adopted no-symlink
model. Disk exhaustion, a read-only or unavailable mount, unsupported rename
semantics, or a failed synchronization can leave recovery required. AcmeMux
does not provide backup and restore; operators remain responsible for native
workspace backups appropriate to their filesystem.

## Interrupted edit recovery

At restart or the next configuration read, AcmeMux classifies every journaled
target from current parent, target, staged-file, and inode metadata. Recovery
evidence identifies whether the interrupted operation was a creation or an
edit. It never replays a candidate and never assumes that a multi-file edit was
atomic.

| Recovery state | Safe action                                                                                                                                                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unapplied`    | No candidate is active. `discard_unapplied` rechecks the original workspace, removes only recognized staged candidates, synchronizes their directories, and clears the journal.                                                 |
| `applied`      | Every candidate is active. `finalize_applied` validates the active native sources and accepts them only when every non-target path still matches the pre-edit review.                                                           |
| `partial`      | Some targets are applied and others are not. Repair the active YAML and dotenv files on the host, remove the recognized interrupted staging entries, then explicitly use `adopt_current`.                                       |
| `ambiguous`    | Current placement does not match a safe journal classification. Inspect and repair the active files on the host, remove only staging entries attributable to this interrupted transaction, then explicitly use `adopt_current`. |

`adopt_current` is also available for an applied edit that intentionally
changed storage, webroot, or source membership. It never moves a staged file
into place. After explicit confirmation, AcmeMux freshly audits the path set,
reads the active sources, applies the exact runtime schema and semantic
validation, rechecks all evidence around administrator reauthorization,
removes only recognized residual staging entries, refreshes workspace review,
and clears the journal. Invalid, unsafe, changing, or unrecognized files leave
recovery blocked.

An interrupted creation has no previously adopted workspace against which an
ordinary applied placement can be finalized. A wholly unapplied creation can
be discarded back to `creation_required`. Any applied, partial, or ambiguous
creation requires explicit `adopt_current`, which performs the complete fresh
runtime, native-content, and filesystem review before creating the first
selection. The recovery screen labels that distinction and never implies that
inode placement alone proves the originally reviewed creation boundary.

Treat an interrupted `.acmemux-edit-*` file as confidential native material.
Do not use a broad wildcard deletion and do not promote a staging file into an
active path. Stop other writers, inspect the target directories and active
files, identify only entries attributable to the displayed incident, and use
the host's appropriate secure handling. A foreign or substituted staging
entry is intentionally left untouched and keeps recovery blocked.

All recovery resolutions require a fresh opaque recovery token and immediate
administrator reauthorization. A stale runtime, journal, source, path, or
session returns a changed or unauthorized result rather than accepting it.

## Production bounds and residual trust

Important fail-closed production bounds are:

| Surface                    |                                                                                            Bound |
| -------------------------- | -----------------------------------------------------------------------------------------------: |
| Native YAML                |                      1 MiB; depth 64; workspace path discovery 32,768 nodes; editor 50,000 nodes |
| Projection and diagnostics |                                                       1,024 projected fields and 256 diagnostics |
| Referenced native paths    |                                                   128 per adopted workspace; 4095 bytes per path |
| Dotenv file                |                                                  1 MiB, 8192 lines, 64 KiB decoded managed value |
| Browser mutation           |                                          1 MiB body, 128 logical changes, 16 bindings per change |
| Typed values               | 4096-byte public strings or list items, 256 list items, 64 KiB secrets, JavaScript-safe integers |
| Observed-secret redaction  |                                   128 values, 64 KiB per value, 1 MiB aggregate encoded variants |
| Filesystem edit            |                 At most 257 replacement targets and five minutes of manager-owned operation time |

The smaller applicable manifest, browser, workspace, or engine bound wins. A
limit failure leaves active files unchanged unless a prior per-file rename has
already made recovery necessary.

Directory size and modification or change timestamps are volatile when
same-directory staging occurs, so they are not used as persisted directory
review identity. Canonical path, device, inode, type, ownership, mode, access,
final-object link count, and component placement evidence remain bound; final
regular-file content plus metadata is fingerprinted. An unrelated process with
the same service UID can still mutate service-owned files and is inside the documented
trust boundary. The kernel also cannot cancel one filesystem syscall stuck in
an unresponsive mount even though the surrounding operation has a deadline.

When the screen reports changed evidence, reload and review the current native
files. When it reports invalid or unsupported content, use the displayed
stable diagnostic and native location; AcmeMux deliberately omits native and
credential values from error text. When it reports recovery required, resolve
that journal before attempting another edit or managed run.
