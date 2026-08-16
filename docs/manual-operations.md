# Manual native workspace operations

AcmeMux can review and durably enqueue one constrained upstream `lego`
file-mode run for the adopted native workspace. The run obtains certificates
that are missing and lets upstream `lego` decide whether existing certificates
are due for renewal. AcmeMux does not calculate a competing renewal date and
does not copy native account, certificate, chain, key, resource, archive, or
configuration-backup data into SQLite.

The current manual operation supports the complete curated HTTP-01
configuration delivered by the application. A compatible reviewed runtime, a
safe adopted workspace, no unresolved native-edit recovery, and a fully
supported valid configuration are required before a preview is available.

## Review before enqueue

Preparing a preview is non-writing. The review shows:

- the exact reviewed runtime identity and compatibility manifest;
- the adopted working directory, native configuration, and storage paths;
- every configured certificate name, DNS name, account, CA, and HTTP-01
  challenge name and mode; and
- the native and external effects that the upstream process may cause.

Those effects include registering or updating native ACME account material,
changing certificate, chain, key, resource, or archive files, replacing the
native `.lego.bck.yaml` effective-configuration backup, and changing ACME or
challenge-endpoint state even when the process later fails.

The preview contains no credential value, raw YAML, command, argument vector,
environment, certificate, or private key. An opaque memory-keyed review token
binds the displayed intent to the complete current runtime, workspace, native
source, and operation policy evidence. A service restart invalidates an
unaccepted preview. Enqueue reconstructs the intent, rejects changed evidence,
and revalidates the administrator session and CSRF pair immediately before the
SQLite commit.

## Durable lifetime

The accepted request is committed before the worker is notified. Closing the
dialog, navigating away, losing the browser connection, or letting the browser
session expire after that commit does not cancel or erase the request. Status
can be observed later from another authenticated browser session.

One latest-only SQLite record retains the accepted certificate scope, active
phase, terminal classification, bounded redacted transcript, and inventory
reconciliation summary. AcmeMux does not provide long-term job history. A
queued request that never started remains eligible for the worker after a
service restart. A request that was already running is instead marked
interrupted and potentially changed; it is reconciled with native inventory
and is never replayed automatically.

The review dialog can be dismissed before enqueue, but there is no browser
cancellation endpoint or cancel button for accepted work. AcmeMux also does not
retry automatically after a failure, timeout, interruption, unknown enqueue
response, output-limit result, or other ambiguous outcome. Reopening a queued
request after restart is continuation of accepted work, not a retry of a
started process.

## Exact process boundary

The broker consumes a freshly revalidated retained handle to the reviewed
executable and starts it directly. It never invokes a shell. The current
file-mode process contract is:

| Boundary | Current behavior |
| --- | --- |
| Executable | Exact retained reviewed file; the path cannot redirect process start |
| Arguments | Exactly `--config <absolute-native-configuration-path>` |
| Working directory | The adopted effective working directory |
| Broker environment | `LANG=C`, `LC_ALL=C`, `TZ=UTC`, and one per-operation random `ACMEMUX_BROKER_PROCESS_GUARD_<hex>=1` lineage marker |
| Additional environment | No inherited provider credentials or `HOME`; DNS-01 credentials load from the exact reviewed native `envFile`, except sensitive snapshots used to pin an Azure OIDC assertion file or an audited AWS shared profile |
| Standard input | Not connected |
| Concurrency | One shared workspace lease across preflight, process execution, and reconciliation |
| Runtime limit | 1,800 seconds |
| Termination | The process tree receives `SIGTERM`, has 5 seconds to stop, and is then sent `SIGKILL` |

The child starts in its own process group with a Linux parent-death signal.
AcmeMux acts as a child subreaper and tracks descendants through `/proc` using
process start identities and the internal lineage marker, so a child that
changes process group or session cannot be mistaken for a recycled or
unrelated process ID. A surviving or unverifiable descendant makes the result
ambiguous even if the original process reported success.

Service shutdown cancels the service-owned worker context and uses the same
controlled process-tree termination boundary. Browser activity never sends a
process signal.

## Output and secret boundary

Standard output is limited to 192 KiB, standard error to 64 KiB, and their
combined retained size to 256 KiB. Crossing any limit stops the process,
discards the captured transcript instead of retaining a potentially unsafe
fragment, and reports an ambiguous output-limit result.

Before any transcript can be persisted or rendered, AcmeMux redacts observed
native secret values and sensitive integration values. It sanitizes invalid
UTF-8, terminal controls, and bidirectional formatting controls, then applies
value redaction again so sanitization cannot reconstruct a secret. The latest
result labels retained stdout and stderr, but never exposes raw child bytes or
an unredacted operating-system error.

Host swap, crash dumps, filesystem snapshots, the native workspace, and
another process sharing the AcmeMux service identity remain inside the trusted
host boundary described in `security.md`.

## Inventory reconciliation and result states

AcmeMux inventories native certificates before launch to establish an
observable baseline. After every started process result, including failure,
timeout, interruption, forced termination, and output overflow, it performs a
mandatory inventory refresh while still holding the shared workspace lease.
It then rechecks the runtime, workspace, and complete native sources. A worker
interrupted by service restart also enters inventory-only reconciliation
before a terminal result is exposed.

The browser receives only the latest bounded result:

- `succeeded` means the upstream process exited successfully and terminal
  reconciliation completed;
- `failed` or `partial` reflects a nonzero upstream result plus the native and
  bounded upstream evidence available for individual certificates;
- `not_attempted` means current evidence proves the broker did not start;
- `incompatible` means runtime or supported-configuration revalidation blocked
  execution;
- `timed_out` and `interrupted` mean a started process was stopped under the
  controlled termination policy; and
- `ambiguous` means native or external change cannot be ruled out, including
  uncertain process cleanup, lost phase persistence, output overflow, or
  runtime, workspace, or source change after execution.

Certificate rows are equally conservative. A successful evaluation or an
observed native artifact change can be marked completed. Exact supported
upstream evidence can identify a failed renewal. Work that was prevented
before start can be marked not attempted. AcmeMux reports all other unproven
certificate outcomes as ambiguous rather than inferring an upstream action
that the available evidence cannot establish.

An inventory refresh can itself be unavailable. The terminal result then says
that native state may have changed and does not present a trusted certificate
count. Inventory rows are refreshed from native storage and are not copied
into application-owned persistence.

## Safe operator actions

- If an operation is queued or running, let the durable worker finish. Do not
  edit or re-adopt the workspace from another process while it owns the shared
  lease.
- If the enqueue response is unknown, check active status and the latest result
  before preparing anything else. Do not submit the preview again as a retry.
- After `succeeded`, confirm the refreshed native inventory and use the
  retained redacted transcript only as supporting evidence.
- After `not_attempted` or `incompatible`, resolve the reported runtime,
  workspace, configuration, or recovery condition and prepare a fresh review.
- After `failed`, `partial`, `timed_out`, `interrupted`, or `ambiguous`, do not
  retry blindly. Review certificate-level states, the redacted transcript,
  native storage, and the inventory reconciliation first. Resolve any runtime,
  workspace, or source change and obtain a fresh preview before choosing a new
  manual run.
- If inventory refresh failed, restore safe access to the reviewed runtime and
  workspace and refresh native evidence before deciding whether another ACME
  operation is appropriate.

See `runtime-compatibility.md`, `workspace-adoption.md`, and
`native-configuration.md` for the prerequisites that can block a preview or
run. See `ca-certificate-http.md` for the native account, certificate, renewal,
and HTTP-01 fields evaluated by this operation. See `dns-providers.md` for the
curated DNS-01 credential and provider boundary.
