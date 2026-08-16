# Native workspace adoption

AcmeMux operates one native `lego` workspace. It can adopt an existing safe
workspace or create the first complete supported configuration through the
typed configuration screen. The native configuration,
credential files, storage directory, certificate artifacts, and private keys
remain authoritative on the host. AcmeMux records reviewed path evidence; it
does not import those files into SQLite.

## Prerequisites

- Select and adopt an exact supported `lego` executable first.
- Run AcmeMux and `lego` under the dedicated non-root service identity.
- Give that identity the access required by the native workspace before
  adoption. AcmeMux reports unsafe or insufficient access and never runs
  `chown`, `chmod`, path relocation, or another automatic repair.

Do not share the service account with unrelated processes. A process with the
same operating-system identity is inside the local workspace trust boundary.

## Selecting the workspace

An adoption request always names an absolute effective working directory. It
uses one of two configuration modes:

- Conventional discovery checks `.lego.yml` first and `.lego.yaml` second in
  the working directory, matching upstream `lego` behavior. When both files
  exist, `.lego.yml` is selected and the ignored `.lego.yaml` is reported.
  A directory using either name is skipped as upstream skips it; any other
  failure to inspect the higher-priority name blocks fallback.
- Explicit selection names one absolute configuration path and separately
  retains the effective working directory. The configuration can be outside
  that directory.

Relative `storage`, DNS `envFile`, and HTTP `webroot` values are resolved from
the adopted working directory, not from the configuration file's parent. The
review screen shows both the configured value and resolved canonical path so
this behavior is explicit before adoption. A missing `storage` setting uses
upstream's `.lego` default beneath the working directory.

Task-specific configuration support is evaluated separately. Adoption reads
only the bounded YAML structure needed to locate native paths; it does not
silently treat unknown CA, challenge, provider, hook, or certificate content as
supported.

## Filesystem review

AcmeMux opens path components without following symbolic links and reviews the
complete adopted path set:

- effective working directory;
- selected native YAML file and its parent replacement boundary;
- resolved storage directory;
- every referenced DNS credential file; and
- every referenced HTTP webroot.

The review includes canonical path, object type, owner and group identifiers,
mode, device, inode, access, and stable component identity. Every selected
final object binds its link count; selected regular files additionally bind
size, modification time, and change time.
Managed regular files cannot be hard linked. Native YAML and credential files are
treated as confidential because they can contain EAB or provider secrets.
Unsafe ownership, write access by an untrusted identity, special files,
symbolic-link traversal, missing required objects, or insufficient service
access blocks adoption. Directory write access is required only where the
native role needs it, including atomic configuration replacement, storage, and
webroot challenge files.

First creation requires an existing safe working directory and pre-existing
safe storage and webroot directories. Conventional mode creates only
`.lego.yml` after proving both conventional names absent; explicit mode creates
only the reviewed absolute target. Creation uses restrictive no-replace file
activation and does not select the workspace until a fresh adoption inspection
passes. Interrupted creation is recovered through the native configuration
screen rather than by a second workspace-adoption attempt.

The administrator acknowledges a fingerprint of the complete stable evidence.
Volatile ancestor-directory link counts are audited internally but are not
displayed, persisted, or fingerprinted. Directory size, modification time, and
change time can change merely because AcmeMux creates a same-directory staging
file, so those fields are observations rather than persisted revision identity.
Directory canonical path, device, inode, type, ownership, mode, access, and
component placement remain bound; final regular-file link and time evidence
also remains bound. AcmeMux reopens and reviews the paths before saving that selection.
Every later workspace read repeats the audit. A material path, inode, owner,
mode, link, or configuration-content change is reported instead of being
hidden by the stored review.

Traversal evidence is bounded to 64 components and 32 KiB of cumulative
component-path text for each selected path. Configuration references and
diagnostics also have aggregate limits. An over-deep or over-complex candidate
is reported as blocked and never partially adopted.

Mounted filesystem availability remains an operational prerequisite. AcmeMux
checks cancellation between bounded traversal and read operations, but the
kernel cannot cancel an individual filesystem syscall that is stalled by an
unresponsive mount.

## Certificate inventory

Inventory uses the already reviewed executable with this fixed command shape:

```text
lego certificates list --path <absolute-storage-path> --json
```

The command runs directly without a shell, from a private AcmeMux directory
that cannot contain a conventional `lego` configuration. Its environment,
runtime, output, process group, certificate count, and one-at-a-time execution
are bounded. Supplying the absolute storage path and neutral working directory
prevents an unrelated configuration file from overriding the inventory target.
This command reads native certificate evidence; it does not register an
account, contact an ACME server or provider, issue or renew a certificate,
download software, or edit the workspace.

Before and after execution, AcmeMux checks the bounded certificate tree for
links, unsafe types, ownership, permissions, replacement, and count or depth
limits. The JSON result must reconcile with the native resource and
certificate paths. The browser receives only certificate name, DNS names,
issuer, expiration, native certificate path, and bounded artifact metadata.
PEM, resource JSON, account data, and private-key bytes are never returned or
stored by AcmeMux.

Upstream `lego` exits unsuccessfully when an otherwise safe new storage has no
`certificates` directory. AcmeMux normalizes only exit status 1 with the exact
bounded upstream missing-directory record and an empty error stream, while the
directory is absent in both the pre-command and post-command audits. It returns
an empty inventory without creating or repairing native paths. Every other
command failure remains blocking.

## Configuration editing and recovery

Configuration mediation reuses the adopted path set and one shared workspace
coordinator. It projects only logical fields declared by the exact runtime
integration manifest; the authoritative YAML node tree and dotenv lines remain
the write source. Preview is non-writing. Save rereads and fingerprints the
reviewed sources, audits the candidate storage, dotenv, and webroot paths,
stages mode-`0600` files beside their targets, and activates one file at a time
only after immediate administrator reauthorization.

One file rename is atomic, but a YAML-plus-dotenv edit is not atomic as a set.
A secret-free SQLite journal makes every phase detectable without storing
native bytes or credentials. A pending journal blocks another edit, runtime or
workspace re-adoption, and later managed execution. AcmeMux never replays an
interrupted candidate. Wholly
unapplied and wholly applied states have explicit discard or finalize actions;
partial or ambiguous state requires host repair followed by confirmed,
freshly validated adoption of the current files. See
`native-configuration.md` before handling an interrupted edit.

## Application-owned state

SQLite may contain the selected working-directory and configuration request,
resolved native path references, bounded filesystem observations, review
fingerprint, review time, and one secret-free edit journal containing target
paths and inode placement metadata. It does not contain YAML or dotenv contents,
certificate or chain bytes, private keys, ACME account material, archives, or
an application-owned certificate inventory.

The browser distinguishes an unadopted workspace from ready, changed, missing,
read-only, unsafe, incompatible, and inventory-unavailable states. Correct the
host condition explicitly and repeat the review; AcmeMux does not mask the
change or continue from stale evidence.
