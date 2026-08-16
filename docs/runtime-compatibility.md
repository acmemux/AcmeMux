# Upstream lego runtime compatibility

AcmeMux brokers one administrator-provisioned upstream `lego` executable. It
does not install, download, upgrade, embed, or discover an executable on the
administrator's behalf. Selecting a runtime establishes identity only; it does
not load a workspace, contact an ACME server or DNS provider, register an
account, or issue or renew a certificate.

## Selecting and reviewing an executable

Sign in, enter the absolute host path to the intended executable, and request
inspection. AcmeMux accepts only a canonical path whose components are not
symbolic links. The final file must be:

- a nonempty regular file no larger than 512 MiB;
- owned by root or the operating-system identity running AcmeMux;
- free of setuid, setgid, and sticky mode bits and not writable by group or
  others;
- without Linux file capabilities, except the exact reviewed
  `cap_net_bind_service=ep` capability; and
- executable by the AcmeMux service identity.

An administrator-provisioned build commonly needs mode `0755`, `0750`, or
`0700`, depending on its owner and service group. Do not make an executable
group-writable merely to make it executable. Correct the owner, group, and mode
outside AcmeMux, then inspect it again.

The inspection page shows the canonical path, exact version output, version or
commit, operating system and architecture, size, modification and metadata
change times, mode, file capability, owner and group identifiers, device and
inode, binary digest, embedded command and module identity, toolchain, source
revision, source state, and dependency-graph digest. Adoption requires an
explicit review acknowledgement and is enabled only for an exact supported
manifest and independently qualified executable digest.

AcmeMux stores this reviewed non-secret evidence and the exact manifest ID in
its SQLite state. It stores neither executable bytes nor any native `lego`
configuration, credential, account, certificate, chain, or private key.

## Audit and identity probe

The Linux audit opens each path component without following symbolic links,
pins the final component with a non-reading `O_PATH` descriptor, rejects a
symlink or non-regular object before any read open, then reopens that exact
object through the retained descriptor. It compares metadata and file
capabilities before and after context-aware hashing. Before executing anything, AcmeMux
requires the binary SHA-256 to match an independently qualified, executed
artifact in an exact manifest and reads bounded Go build information from the
retained file. Only then does it invoke that same descriptor with the sole
argument `--version`, and audit and hash the path again. At most one inspection
runs at a time. A 30-second context bounds the inspection between filesystem
reads and forcibly stops the child probe. Linux cannot cancel a kernel read
stalled inside a faulty or unavailable filesystem, so the trusted host and its
mounted filesystem availability remain an operational prerequisite. The probe:

- uses no shell and accepts no browser-supplied argument or environment name;
- has a five-second deadline and bounded standard output and error;
- uses only `LANG=C`, `LC_ALL=C`, `PATH=/usr/bin:/bin`, and `TZ=UTC`;
- runs from an inert root working directory; and
- accepts exactly one newline-terminated `lego version <identity> linux/<arch>`
  line.

Embedded command package, module, toolchain, dependency graph, build platform,
source revision, and modified-source evidence must agree with the exact
qualified artifact. Sparse or contradictory build information fails closed.
A familiar filename, semver string, or self-reported build identity never
qualifies new bytes; another build from the same source remains unsupported
until its exact digest and behavior are independently reviewed.

Before a managed operation, AcmeMux re-opens the selected path, repeats the
audit and identity probe, and compares the canonical path, device, inode, mode,
owner, group, size, modification and change times, digest, reported version,
platform, embedded build evidence, file capability, and exact output. The only
operation preparation API also reclassifies the retained descriptor and
requires the currently compatible manifest to equal the stored reviewed
manifest. Any difference or withdrawn manifest blocks use until the
administrator reviews and adopts a qualified replacement.

The selected path may be root-owned or owned by the dedicated AcmeMux service
identity. Host administrators and every process sharing that service identity
are therefore inside the executable trust boundary: a retained regular-file
descriptor does not make a same-inode file immutable. Prefer a root-owned,
non-writable executable when other processes share the service account. Do not
share the AcmeMux service identity with unrelated workloads.

The candidate response includes a SHA-256 review fingerprint over every
displayed observation field except the observation timestamp plus the exact
manifest ID. Adoption must echo the canonical path, binary digest, manifest ID,
and this full-evidence fingerprint. The service re-inspects and recomputes all
four values before persisting; the fingerprint is not an authentication token
and is bound again by the authenticated session and CSRF check.

## Exact supported manifests

There is no version range or automatic nearest-version fallback. Current
runtime support is Linux amd64 only and is limited to the exact executed binary
digests recorded by these manifests:

| Manifest | Exact source | Accepted identity output | Embedded module |
|---|---|---|---|
| `lego-v5.3.1` | tag `v5.3.1`, tag object `78840cf9121240982d4b43f81b24c28253d61585`, commit `589c84af4f26629fbdaa7fbca712f806632ccb7e` | `5.3.1` or `v5.3.1` | `github.com/go-acme/lego/v5` at `v5.3.1` |
| `lego-revision-2a58c3522708` | commit `2a58c3522708e4c7393a67be691bd0c3a16d8441` | the same 40-character commit | `github.com/go-acme/lego/v5` at `v5.3.2-0.20260803101616-2a58c3522708` |

The v5.3.1 evidence set admits two executed Linux amd64 artifacts. The local
tag-source fixture was built with Go 1.26.6 and has executable digest
`e55089f626ffe1725de10b71bac366a6f6ee8d88cddc7fbff8fdb1cd3ad4897f`.
The official GitHub release fixture was built with Go 1.26.5. Its published
amd64 archive digest is
`b3c71b122ee1947eacfe0b809b955647f6377239fe4bfc49f73b1a091ae1252a`;
its executable digest is
`36c97b1ed369c2c46d7a4dde0d635d8e742b080c27c36d58933a8029f7811624`.
The published arm64 archive digest is
`58db563a2b97c2259516fa9910b4a9e1634a0737723d0381a65af1bf93a4b433`;
its executable digest is
`24cf7a3b11e4c262937fc15c6f31d4f31501a1abe20142327822771113426a1b`.
Both archive digests match upstream's `lego_5.3.1_checksums.txt`; the amd64
fixture was executed locally. The cross-architecture arm64 fixture was only
inspected, so it is evidence for a future qualification and is not currently
admitted or advertised as supported. The checksum-file digest and exact fixture
records are bundled as test evidence; no local GitHub attestation verification
is claimed.

The source-revision fixture reports the exact commit on Linux amd64 and has
executable digest
`ef3819a069a79e8b79306665cac076b9ce53e31f63c60b953d62740f8f4b59b4`.
That particular host fixture is mode `0775`, so it is useful as source and
behavior evidence but is intentionally unsafe for adoption until the operator
places identical bytes at a private non-writable path.

The manifests distinguish what upstream compiles from what AcmeMux supports.
The current AcmeMux allowlist is the accepted CA set, built-in HTTP-01 listener
and webroot, and DNS-01 through Azure DNS, Cloudflare, DigitalOcean, DuckDNS,
or Route 53. Other compiled providers and challenge modes do not become usable
through AcmeMux merely because they appear in upstream source.

## Bundled schema and license

`internal/compatibility/assets/lego-v5.3.1.schema.json` is the exact upstream
draft-07 schema from `docs/static/lego.jsonschema.json` at both supported source
identities. Its SHA-256 digest is
`0264c4d7e0f3f95b91ed5235db8270cc4f284e2e096e4425e4e207a88978373d`.
The adjacent `lego.LICENSE.txt` is the complete upstream MIT license notice,
with SHA-256
`bf12923e71046c564f4163c00c3aa6b3581b51858f099a035f5baf2216addf6e`.

The native configuration engine compiles this exact schema as Draft 7 with
external resource loading disabled and combines it with source-backed semantic
checks before preview or replacement. Passing the upstream schema is not a
promise that every field or compiled integration is supported by AcmeMux; the
separate curated integration manifest remains the editing and execution
allowlist.

## Diagnostics

- `missing` means the selected path cannot be opened. Restore the intended file
  at the reviewed path or inspect a new absolute path.
- `unsafe` identifies an unqualified digest, symlink, wrong file type or owner,
  writable or special mode, disallowed file capability, missing execute
  permission, unsupported platform, or another host audit failure. Correct the
  host condition or qualify the exact artifact rather than weakening the
  service.
- `malformed_output` means the bounded probe failed, exceeded output limits,
  returned an unknown shape, or contradicted embedded build evidence.
- `timed_out` means the bounded probe or complete inspection exceeded its
  deadline and was stopped.
- `unverified` and `incompatible` are fail-closed compatibility states reserved
  for independently qualified bytes whose identity or current manifest policy
  does not resolve to support. An unknown executable digest is rejected as
  `unsafe` before it can run, so an arbitrary candidate never reaches these
  states merely by self-reporting a version.
- `changed` means adopted evidence no longer matches the path and all managed
  operations remain blocked pending review.

If another inspection already owns the single inspection slot, the API
returns a retryable service-unavailable response with `Retry-After: 1`; it does
not blame or reclassify the executable.

AcmeMux deliberately reports bounded diagnostics and does not return raw probe
error text to the browser.

## Qualifying an upstream update

An update is deliberate compatibility work, not a semver edit:

1. Start from a clean exact upstream tag or commit and record the tag object,
   peeled commit, module version, release checksums, supported platforms, and
   build provenance. Verify upstream signatures or attestations when the local
   trust tooling and keys are available; document any limitation.
2. Build a clean source fixture and inspect official artifacts for each target
   platform. Capture bounded `--version` output, executable and archive
   digests, Go version, module identity, platform, VCS revision, and modified
   state. An artifact is not admitted until it is safely executed on its native
   platform (or an accepted equivalent runner) and its exact digest is recorded.
3. Compare the upstream JSON Schema, CA registry, challenge configuration and
   flags, generated provider help and registry, provider descriptors, relevant
   implementation and tests, and every curated supported provider directory.
4. Update the exact manifest, bundled schema and license if needed, source
   catalogs, fixture records, and support documentation together. A compiled
   capability remains unsupported until its product schema, native mapping,
   redaction, tests, and documentation are complete.
5. Run `make test-runtime`, `make test-compatibility`, and `make verify`. Digest,
   schema, provider-catalog, source-bundle, or fixture drift must fail until it
   has been reviewed and deliberately recorded.

Standard verification recomputes every manifest digest and provider tree from
the checked-in, commit-labelled Git inventories and exact descriptor bytes. The
update tool must be run against a trusted local upstream Git checkout to
regenerate those inventories; ordinary verification deliberately performs no
network fetch and does not treat a mutable external checkout as test input.

Never broaden an existing manifest to an unreviewed release or revision, and
never acquire or upgrade the runtime from a browser request.
