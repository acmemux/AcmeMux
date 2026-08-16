# Certificate health and latest reporting

The Certificates view reports current evidence from the adopted native lego storage. AcmeMux does not copy certificate, chain, account, resource, or private-key files into its own database, and it does not back up or deploy those files.

## Health states

Health is evaluated when a native inventory refresh succeeds, using the AcmeMux service host clock:

- **Healthy:** expiration is more than 30 complete days away.
- **Expiring:** expiration is later than the observation time and no more than 30 complete days away.
- **Expired:** expiration is at or before the observation time.

The exact 30-day boundary is expiring. Health is an attention signal only. It is not a prediction of when lego will renew a certificate. Lego remains responsible for ARI, lifetime-based renewal rules, configured thresholds, and renewal eligibility.

Keep the service host clock synchronized. After correcting clock skew, refresh the workspace to obtain a new health observation.

## Time display

Each certificate shows its exact expiration in the browser's local time zone and in UTC. The inventory also shows the exact UTC observation time used for health classification. Use UTC when comparing evidence across the AcmeMux host, reverse proxy, lego output, or provider systems.

## Stale or unavailable inventory

If a refresh fails, AcmeMux does not present the previous inventory as current. The open browser may retain the last successful view in memory, but the whole view is labeled **Stale evidence** with its original observation time. Stale health values are not recomputed and should not be used to decide whether native state is current.

Restore safe access to the reviewed lego executable and native storage, then select **Check workspace again**. A service restart or browser reload discards the in-memory stale view because certificate inventory is not stored in AcmeMux state.

## Latest result

AcmeMux retains one active operation or the latest bounded result, not operation history. The latest result identifies:

- manual or automatic origin and terminal state;
- requested, started, and finished UTC instants;
- current inventory reconciliation or refresh failure;
- completed, failed, not-attempted, or ambiguous certificate evidence where it can be proven;
- the reviewed lego identity and compatibility manifest;
- the native configuration and storage paths;
- the selected account, CA, challenge, and DNS provider where retained; and
- a state-specific safe next action and bounded redacted upstream transcript.

A failed, timed-out, interrupted, partial, or ambiguous operation may have changed native or external state. Review current inventory and native storage before choosing another run. Never treat a failed process as proof that no provider, account, or certificate change occurred.

## Redaction and safe handling

Operation output is bounded and redacted before retention and checked again before display. This reduces accidental disclosure but does not turn output into a safe place for credentials. Do not paste secrets into certificate names, native paths, or other non-secret configuration fields, and continue to protect the service host, process memory, swap, dumps, logs, and native workspace.

See [manual certificate operations](manual-operations.md) for state meanings and retry guidance, [workspace adoption](workspace-adoption.md) for native path requirements, and [security](security.md) for the trusted-host boundary.
