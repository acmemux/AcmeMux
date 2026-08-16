# Manual certificate operations

A manual operation asks upstream lego to evaluate the complete adopted workspace. Lego obtains missing certificates and decides whether existing certificates are due for renewal. AcmeMux does not calculate a competing renewal date or copy native certificate material into its own state.

Before an operation is available, AcmeMux requires a supported executable, a reviewed workspace, a supported valid configuration, and no unresolved configuration recovery.

## Review before starting

Preparing a review does not change the workspace. Confirm:

- the selected lego executable;
- the working directory, configuration file, and storage directory;
- every configured certificate name and DNS name;
- the selected account, certificate authority, and challenge method; and
- the possible native and external effects.

Lego may register or update an ACME account, present and remove challenge records, and change certificate, chain, key, resource, archive, or native backup files. A later failure does not prove that none of those changes occurred.

The review does not display credential values, raw YAML, certificates, or private keys. If the runtime, workspace, or configuration changes before you confirm, AcmeMux rejects the stale review and asks you to prepare a new one.

## After acceptance

Once accepted, an operation belongs to the service rather than the browser. Closing the tab, signing out, or losing the network connection does not cancel it. Return through another authenticated session to inspect its status.

Only one workspace operation or configuration edit can be active. There is no browser cancel button and no automatic retry after failure, timeout, interruption, or an unknown response. A queued operation can start after service restart; an operation that had already started is marked interrupted, reconciled with native inventory, and never replayed automatically.

AcmeMux retains only the active operation or latest result. It does not provide long-term job history.

The latest result also retains bounded secret-free identity for the reviewed lego runtime, native configuration and storage paths, and selected account, CA, challenge, or provider. It does not retain native configuration contents or certificate and key material.

## Runtime boundary

AcmeMux starts the reviewed lego executable directly, without a shell, using the adopted native configuration and working directory. Provider credentials come only from supported reviewed configuration. Standard input is disconnected, output is bounded and redacted, and the operation is limited to 30 minutes.

If the limit is reached or the service stops, AcmeMux asks the process tree to terminate and then forces remaining processes to stop. An uncertain cleanup result is reported as ambiguous rather than success.

Do not run another lego process against the same workspace while AcmeMux shows an operation or edit in progress. External processes do not participate in AcmeMux's workspace lock.

## Result states

- **Succeeded:** Lego exited successfully and AcmeMux refreshed native inventory.
- **Failed or partially completed:** Lego reported a failure, and available evidence distinguishes failed work from work that completed or was not attempted.
- **Not attempted:** A prerequisite stopped the operation before lego started.
- **Incompatible:** The executable or native configuration no longer meets the supported contract.
- **Timed out or interrupted:** A started operation was stopped by the service boundary or a restart.
- **Ambiguous:** Native or external change cannot be ruled out, including uncertain cleanup, evidence changes, or unavailable reconciliation.

Certificate rows are conservative. If AcmeMux cannot prove what happened to one certificate, it reports that outcome as ambiguous.

## Safe follow-up

- While work is queued or running, let it finish.
- If the start response is unknown, check active status and the latest result before doing anything else. Do not submit the same review again.
- After success, confirm the refreshed native inventory.
- After a prerequisite failure, correct the displayed condition and prepare a fresh review.
- After failure, partial completion, timeout, interruption, or ambiguity, inspect certificate-level states, the redacted output, native storage, and inventory status before choosing another operation.
- If inventory refresh is unavailable, restore safe access to lego and the workspace before retrying.

See [certificate health and latest reporting](certificate-health-and-reporting.md) for health, time, stale-inventory, and latest-only behavior; [automatic renewal](automatic-renewal.md) for scheduled behavior; [workspace adoption](workspace-adoption.md) for path prerequisites; and [configuration recovery](native-configuration.md#interrupted-change-recovery) for blocked edits.
