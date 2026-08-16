# Automatic renewal evaluation

AcmeMux can run one automatic evaluation of the complete native lego workspace each day. Scheduling is disabled until the administrator explicitly enables and saves it.

AcmeMux chooses when to start an evaluation. Upstream lego still decides which certificates are missing or due by using ACME Renewal Information (ARI), the configured renewal threshold, and its normal random delay.

## Configure the schedule

The schedule has three controls:

- enable or disable automatic evaluation;
- choose an IANA time zone such as `America/Denver` or `UTC`; and
- choose one local `HH:MM` time.

The form initially suggests `03:35` in the browser's detected time zone, but nothing runs until you save it. The screen shows both the local time and the exact next UTC evaluation. AcmeMux does not accept cron expressions, sub-daily intervals, or separate schedules per certificate.

## Daylight-saving and clock behavior

The named IANA time zone controls daylight-saving changes:

- If a local time occurs twice, AcmeMux uses the earlier occurrence and runs only once for that local date.
- If a local time does not exist because the clock moves forward, AcmeMux uses the first valid time after the gap.
- A backward clock adjustment cannot run the same local date twice.

Keep the host's UTC clock synchronized. If the displayed UTC instant is unexpected, check the selected zone, local time, and host clock, then save the schedule again.

## Downtime and other operations

Missed days are combined into one due evaluation rather than a backlog. A due evaluation waits while a manual operation or configuration edit is active, then starts once the workspace is available.

Changing or disabling the schedule does not cancel an operation that has already been accepted or started. The new schedule applies to future occurrences.

If AcmeMux restarts while a certificate operation is running, it marks that result interrupted, refreshes the native inventory, and does not replay the operation. The scheduler advances to the next ordinary daily occurrence. This avoids repeating an ACME or provider action whose external result may be uncertain.

## What a scheduled operation does

A scheduled operation uses the same supported native configuration and safety boundary as a manual operation. It can obtain missing certificates and evaluate existing certificates, but it does not force renewal or override native renewal settings.

An operation can remain active while lego waits for ARI, provider propagation, or its random renewal delay. The overall operation is limited to 30 minutes, during which manual runs and configuration edits remain unavailable.

## Troubleshooting

- **Deferred:** Let the active operation or edit finish. One evaluation remains due; do not run a parallel lego process against the workspace.
- **Needs attention:** Correct the reported runtime, workspace, configuration, or recovery problem. AcmeMux will wait for the next ordinary occurrence rather than repeatedly hitting the failing boundary.
- **Interrupted, failed, partial, timed out, or ambiguous:** Review the refreshed inventory and latest redacted result before deciding whether a manual operation is safe.
- **Successful but no certificate changed:** This is often correct. Lego may have determined that every certificate was outside its renewal window.

See [manual operations](manual-operations.md) for result states and safe retry guidance, and [certificate renewal controls](ca-certificate-http.md#renewal-controls) for the settings evaluated by lego.
