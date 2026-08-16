# Automatic renewal evaluation

AcmeMux can persist one daily automatic evaluation schedule for the adopted native `lego` workspace. Scheduling is disabled until the administrator explicitly enables and saves it. The schedule replaces private cron or timer scripts; it does not replace upstream renewal decisions.

Every automatic trigger enters the same latest-only durable worker, constrained broker, shared workspace lease, redaction path, result classification, and native inventory reconciliation used by a manual operation. The operation kind identifies the automatic trigger, but its upstream invocation remains exactly `lego --config <absolute-native-configuration-path>` from the adopted working directory.

## Controls and time presentation

The typed schedule has three controls:

- enable or disable automatic evaluation;
- select one IANA time-zone name, such as `America/Denver` or `UTC`; and
- select one local `HH:MM` wall-clock time.

The initial form suggests `03:35` in the browser's detected IANA zone. Nothing is scheduled until the administrator saves the form. AcmeMux does not accept cron syntax, arbitrary intervals, sub-daily schedules, or per-certificate schedules.

The browser always shows the configured local time and zone together with the exact next UTC evaluation instant. SQLite stores that next evaluation, the last scheduler trigger, update time, and bounded recovery state as UTC instants. It retains one current schedule rather than schedule history.

Daylight-saving behavior follows the selected IANA zone. A local time that occurs twice triggers at its earlier instant and only once for that local date. A local time skipped by a forward transition moves to the first valid instant after the gap. A backward system-clock adjustment cannot trigger the same local date twice.

## Missed, deferred, and interrupted work

Downtime and forward clock jumps coalesce every missed local date into one due evaluation. AcmeMux never creates a backlog of one operation per missed day.

A due evaluation that encounters an already accepted manual or automatic operation, or an active native-file edit, remains deferred. It is retried after contention clears and still represents only one coalesced occurrence. Editing or disabling the schedule does not cancel work that was already durably accepted or running; the new schedule applies to later occurrences.

If service restart interrupts a running operation, the durable worker marks it interrupted and potentially changed, refreshes native inventory, and never replays it. The scheduler advances to the next ordinary daily occurrence instead of triggering immediately. If the service stops after claiming a schedule occurrence but before durable operation acceptance is confirmed, recovery also advances safely and reports the recovered trigger state rather than risking a blind provider or ACME retry.

A due evaluation that cannot be accepted because the runtime, workspace, native configuration, or edit-recovery state is invalid records a bounded attention state and advances to the next ordinary occurrence. The administrator should correct the displayed prerequisite; AcmeMux does not hammer the failing boundary.

## Upstream renewal authority and runtime length

An automatic AcmeMux run evaluates the complete native file configuration. Upstream `lego` decides independently for each certificate whether it is missing or due:

- ACME Renewal Information is used when the configured CA advertises it and native configuration has not disabled it;
- otherwise upstream applies the configured renewal days or its certificate-lifetime calculation; and
- a non-interactive renewal can add up to eight minutes of upstream random delay unless the native certificate configuration explicitly disables that behavior.

AcmeMux does not predict a certificate due date, disable ARI, set a forced-renewal flag, or suppress upstream jitter for scheduled work. The common broker timeout remains 30 minutes. A long ARI wait, provider propagation wait, or upstream random delay therefore consumes that same bounded runtime and keeps manual runs and edits excluded until terminal reconciliation completes.

## System clock and troubleshooting

The host's system clock and IANA zone database are operational dependencies. AcmeMux embeds the Go time-zone database for schedule calculation, but certificate validation, ACME exchanges, SQLite timestamps, and systemd logs still require a trustworthy UTC system clock.

- If the displayed next UTC instant is unexpected, verify the selected IANA zone, local time, and host UTC clock. Saving the schedule recomputes the next future occurrence.
- If state is `deferred`, allow the active operation or edit to finish. One occurrence remains due; do not start a parallel external `lego` process.
- If state needs attention, restore the reviewed runtime, workspace access, supported native configuration, or edit recovery condition before the next occurrence.
- After an interrupted, timed-out, partial, failed, or ambiguous automatic result, inspect the refreshed native inventory and redacted latest result. Do not force an immediate retry.
- If an automatic run appears idle before certificate replacement, inspect the redacted transcript for upstream ARI, lifetime, and random-delay messages. A successful evaluation can correctly renew nothing.

See `manual-operations.md` for the exact process, output, termination, and reconciliation boundaries. See `ca-certificate-http.md` for native ARI and renewal fields, and `security.md` for the schedule mutation and application-state trust boundary.
