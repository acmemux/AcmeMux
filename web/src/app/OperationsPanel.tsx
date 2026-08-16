import { useCallback, useEffect, useRef, useState } from "react";

import {
  OperationRequestError,
  browserOperationClient,
  type AutomaticSchedule,
  type AutomaticScheduleUpdate,
  type LatestOperation,
  type ManualOperationPreview,
  type OperationClient,
  type OperationPolicy,
  type OperationStatus,
  type TerminalOperationResult,
} from "../api/operations";
import { useAuthenticatedSession } from "../auth/AuthBoundary";
import { ActionButton } from "../components/ActionButton";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { OperationReviewDialog } from "../components/OperationReviewDialog";
import { StatusBadge, type StatusTone } from "../components/StatusBadge";

type OperationPhase = "loading" | "idle" | "previewing" | "enqueueing";

export type OperationController = {
  actionError: string | null;
  blocksWorkspaceMutations: boolean;
  completionRevision: number;
  enqueueOutcomeUnknown: boolean;
  error: string | null;
  latest: LatestOperation | null;
  phase: OperationPhase;
  policy: OperationPolicy | null;
  preview: ManualOperationPreview | null;
  status: OperationStatus | null;
  schedule: AutomaticSchedule | null;
  scheduleError: string | null;
  scheduleSaving: boolean;
  dismissPreview(): void;
  enqueueManual(): Promise<void>;
  previewManual(): Promise<void>;
  refresh(): Promise<void>;
  saveSchedule(update: AutomaticScheduleUpdate): Promise<void>;
};

function safeRequestMessage(error: unknown): string {
  if (!(error instanceof OperationRequestError)) {
    return "Operation evidence is unavailable. No new operation was started.";
  }
  switch (error.code) {
    case "operation_active":
      return "A native workspace operation is already active. Current status was not replaced.";
    case "operation_changed":
      return "The reviewed runtime or native workspace changed. Prepare a new operation review from current evidence.";
    case "recovery_required":
      return "Native configuration recovery must be resolved before a manual operation can start.";
    case "workspace_invalid":
      return "The selected native workspace must be reviewed again before execution.";
    case "configuration_invalid":
      return "The native configuration is not supported and valid for managed execution.";
    case "service_busy":
      return "Another native workspace action owns the shared lock. Check current evidence after it finishes.";
    case "invalid_request":
      return "AcmeMux rejected the operation request. No automatic retry was attempted.";
    case "service_unavailable":
    case "network_failure":
      return "Operation evidence is temporarily unavailable.";
    case "invalid_response":
      return "Operation evidence could not be verified from the service response.";
    case "authentication_required":
    case "request_not_allowed":
      return "The protected operation request could not continue.";
  }
}

function enqueueUnknownMessage(): string {
  return "The enqueue response did not confirm whether the durable request was accepted. AcmeMux did not retry. Current status and the latest result were checked once; review native evidence before preparing another operation.";
}

function latestID(latest: LatestOperation | null): string | null {
  return latest?.state === "available" ? latest.result.id : null;
}

export function useOperationController(
  client: OperationClient = browserOperationClient,
  startEligible = false,
): OperationController {
  const { endSession, rejectRequest } = useAuthenticatedSession();
  const [status, setStatus] = useState<OperationStatus | null>(null);
  const [latest, setLatest] = useState<LatestOperation | null>(null);
  const [policy, setPolicy] = useState<OperationPolicy | null>(null);
  const [preview, setPreview] = useState<ManualOperationPreview | null>(null);
  const [phase, setPhase] = useState<OperationPhase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [enqueueOutcomeUnknown, setEnqueueOutcomeUnknown] = useState(false);
  const [completionRevision, setCompletionRevision] = useState(0);
  const [schedule, setSchedule] = useState<AutomaticSchedule | null>(null);
  const [scheduleError, setScheduleError] = useState<string | null>(null);
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const mounted = useRef(true);
  const loadVersion = useRef(0);
  const actionActive = useRef(false);
  const activeOperationID = useRef<string | null>(null);
  const observedLatestID = useRef<string | null>(null);
  const initialLoadComplete = useRef(false);

  const handleProtectedError = useCallback(
    (requestError: unknown): boolean => {
      if (!(requestError instanceof OperationRequestError)) return false;
      if (requestError.code === "authentication_required") {
        endSession();
        return true;
      }
      if (requestError.code === "request_not_allowed") {
        rejectRequest();
        return true;
      }
      return false;
    },
    [endSession, rejectRequest],
  );

  const applyLatest = useCallback(
    (next: LatestOperation, countNewResult: boolean) => {
      const nextID = latestID(next);
      if (
        countNewResult &&
        nextID !== null &&
        nextID !== observedLatestID.current
      ) {
        setCompletionRevision((revision) => revision + 1);
      }
      observedLatestID.current = nextID;
      setLatest(next);
    },
    [],
  );

  const loadEvidence = useCallback(
    async (force = false) => {
      if (actionActive.current && !force) return;
      const version = ++loadVersion.current;
      setPhase("loading");
      setError(null);
      const [statusResult, latestResult, policyResult, scheduleResult] =
        await Promise.allSettled([
          client.getStatus(),
          client.getLatest(),
          client.getCancelPolicy(),
          client.getAutomaticSchedule(),
        ]);
      if (!mounted.current || loadVersion.current !== version) return;

      const failures = [
        statusResult,
        latestResult,
        policyResult,
        scheduleResult,
      ].filter(
        (result): result is PromiseRejectedResult =>
          result.status === "rejected",
      );
      const protectedFailure = failures.find(({ reason }) =>
        handleProtectedError(reason),
      );
      if (protectedFailure) {
        setPhase("idle");
        return;
      }

      if (statusResult.status === "fulfilled") {
        setStatus(statusResult.value);
        activeOperationID.current =
          statusResult.value.state === "active"
            ? statusResult.value.operation.id
            : null;
      }
      if (latestResult.status === "fulfilled") {
        applyLatest(latestResult.value, initialLoadComplete.current);
      }
      if (policyResult.status === "fulfilled") setPolicy(policyResult.value);
      if (scheduleResult.status === "fulfilled") {
        setSchedule(scheduleResult.value);
        setScheduleError(null);
      } else {
        setScheduleError(safeRequestMessage(scheduleResult.reason));
      }
      const operationFailures = [
        statusResult,
        latestResult,
        policyResult,
      ].filter(
        (result): result is PromiseRejectedResult =>
          result.status === "rejected",
      );
      if (operationFailures.length > 0) {
        setError(safeRequestMessage(operationFailures[0]?.reason));
      }
      initialLoadComplete.current = true;
      setPhase("idle");
    },
    [applyLatest, client, handleProtectedError],
  );

  useEffect(() => {
    mounted.current = true;
    const timer = window.setTimeout(() => void loadEvidence(), 0);
    return () => {
      window.clearTimeout(timer);
      mounted.current = false;
      loadVersion.current += 1;
    };
  }, [loadEvidence]);

  const polledOperationID =
    status?.state === "active" ? status.operation.id : null;

  useEffect(() => {
    if (polledOperationID === null) return;
    let canceled = false;
    let timer: number | undefined;
    const operationID = polledOperationID;

    async function poll() {
      try {
        const nextStatus = await client.getStatus();
        if (canceled || !mounted.current) return;
        setError(null);
        if (nextStatus.state === "active") {
          setStatus(nextStatus);
          activeOperationID.current = nextStatus.operation.id;
          timer = window.setTimeout(() => void poll(), 1500);
          return;
        }

        const completed = activeOperationID.current === operationID;
        activeOperationID.current = null;
        try {
          const nextLatest = await client.getLatest();
          if (canceled || !mounted.current) return;
          setStatus(nextStatus);
          applyLatest(nextLatest, false);
        } catch (requestError) {
          if (canceled || handleProtectedError(requestError)) return;
          setStatus(nextStatus);
          setError(safeRequestMessage(requestError));
        }
        if (completed) {
          setCompletionRevision((revision) => revision + 1);
        }
      } catch (requestError) {
        if (canceled || handleProtectedError(requestError)) return;
        setError(
          "Live operation status is temporarily unavailable. The durable operation may still be running; no cancellation or retry was sent.",
        );
        timer = window.setTimeout(() => void poll(), 1500);
      }
    }

    timer = window.setTimeout(() => void poll(), 1000);
    return () => {
      canceled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [applyLatest, client, handleProtectedError, polledOperationID]);

  const automaticPollingEnabled =
    schedule?.enabled === true && polledOperationID === null;

  useEffect(() => {
    if (!automaticPollingEnabled) return;
    let canceled = false;
    let timer: number | undefined;

    async function pollAutomaticEvidence() {
      if (actionActive.current) {
        timer = window.setTimeout(() => void pollAutomaticEvidence(), 15_000);
        return;
      }
      const [statusResult, scheduleResult] = await Promise.allSettled([
        client.getStatus(),
        client.getAutomaticSchedule(),
      ]);
      if (canceled || !mounted.current) return;
      const failure = [statusResult, scheduleResult].find(
        (result): result is PromiseRejectedResult =>
          result.status === "rejected",
      );
      if (failure && handleProtectedError(failure.reason)) return;

      if (scheduleResult.status === "fulfilled") {
        setSchedule(scheduleResult.value);
        setScheduleError(null);
      } else {
        setScheduleError(safeRequestMessage(scheduleResult.reason));
      }
      if (statusResult.status === "fulfilled") {
        setStatus(statusResult.value);
        if (statusResult.value.state === "active") {
          activeOperationID.current = statusResult.value.operation.id;
          return;
        }
        activeOperationID.current = null;
        try {
          const nextLatest = await client.getLatest();
          if (canceled || !mounted.current) return;
          applyLatest(nextLatest, true);
          setError(null);
        } catch (requestError) {
          if (canceled || handleProtectedError(requestError)) return;
          setError(safeRequestMessage(requestError));
        }
      } else {
        setError(safeRequestMessage(statusResult.reason));
      }
      timer = window.setTimeout(() => void pollAutomaticEvidence(), 15_000);
    }

    timer = window.setTimeout(() => void pollAutomaticEvidence(), 15_000);
    return () => {
      canceled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [applyLatest, automaticPollingEnabled, client, handleProtectedError]);

  const previewManual = useCallback(async () => {
    if (
      !startEligible ||
      actionActive.current ||
      phase !== "idle" ||
      status?.state !== "idle" ||
      enqueueOutcomeUnknown
    ) {
      return;
    }
    actionActive.current = true;
    setPhase("previewing");
    setActionError(null);
    try {
      const next = await client.previewManual();
      if (!mounted.current) return;
      setPreview(next);
      setPolicy(next.policy);
    } catch (requestError) {
      if (!handleProtectedError(requestError)) {
        setActionError(safeRequestMessage(requestError));
      }
    } finally {
      actionActive.current = false;
      if (mounted.current) setPhase("idle");
    }
  }, [
    client,
    enqueueOutcomeUnknown,
    handleProtectedError,
    phase,
    startEligible,
    status,
  ]);

  const reconcileUnknownEnqueue = useCallback(
    async (previousLatestID: string | null) => {
      const [statusResult, latestResult] = await Promise.allSettled([
        client.getStatus(),
        client.getLatest(),
      ]);
      if (!mounted.current) return;
      if (
        statusResult.status === "rejected" &&
        handleProtectedError(statusResult.reason)
      ) {
        return;
      }
      if (
        latestResult.status === "rejected" &&
        handleProtectedError(latestResult.reason)
      ) {
        return;
      }
      if (statusResult.status === "fulfilled") {
        setStatus(statusResult.value);
        activeOperationID.current =
          statusResult.value.state === "active"
            ? statusResult.value.operation.id
            : null;
      }
      const acceptedActive =
        statusResult.status === "fulfilled" &&
        statusResult.value.state === "active";
      const acceptedLatest =
        latestResult.status === "fulfilled" &&
        latestID(latestResult.value) !== null &&
        latestID(latestResult.value) !== previousLatestID;
      if (latestResult.status === "fulfilled") {
        applyLatest(latestResult.value, acceptedLatest && !acceptedActive);
      }
      const accepted = acceptedActive || acceptedLatest;
      setEnqueueOutcomeUnknown(!accepted);
      setActionError(accepted ? null : enqueueUnknownMessage());
    },
    [applyLatest, client, handleProtectedError],
  );

  const enqueueManual = useCallback(async () => {
    if (
      !startEligible ||
      actionActive.current ||
      phase !== "idle" ||
      preview === null ||
      status?.state !== "idle"
    ) {
      return;
    }
    actionActive.current = true;
    setPhase("enqueueing");
    setActionError(null);
    const previousLatestID = latestID(latest);
    const token = preview.reviewedPreviewToken;
    try {
      const operation = await client.enqueueManual(token);
      if (!mounted.current) return;
      setPreview(null);
      setStatus({ state: "active", operation });
      activeOperationID.current = operation.id;
      setEnqueueOutcomeUnknown(false);
    } catch (requestError) {
      if (handleProtectedError(requestError)) return;
      setPreview(null);
      const ambiguous =
        !(requestError instanceof OperationRequestError) ||
        requestError.code === "network_failure" ||
        requestError.code === "service_unavailable" ||
        requestError.code === "invalid_response";
      if (ambiguous) {
        setEnqueueOutcomeUnknown(true);
        setActionError(enqueueUnknownMessage());
        await reconcileUnknownEnqueue(previousLatestID);
      } else {
        setActionError(safeRequestMessage(requestError));
        if (
          requestError instanceof OperationRequestError &&
          requestError.code === "operation_active"
        ) {
          await loadEvidence(true);
        }
      }
    } finally {
      actionActive.current = false;
      if (mounted.current) setPhase("idle");
    }
  }, [
    client,
    handleProtectedError,
    latest,
    loadEvidence,
    phase,
    preview,
    reconcileUnknownEnqueue,
    startEligible,
    status,
  ]);

  const dismissPreview = useCallback(() => {
    if (!actionActive.current) setPreview(null);
  }, []);

  const saveSchedule = useCallback(
    async (update: AutomaticScheduleUpdate) => {
      if (scheduleSaving) return;
      setScheduleSaving(true);
      setScheduleError(null);
      try {
        const saved = await client.updateAutomaticSchedule(update);
        if (mounted.current) setSchedule(saved);
      } catch (requestError) {
        if (!handleProtectedError(requestError) && mounted.current) {
          setScheduleError(safeRequestMessage(requestError));
        }
      } finally {
        if (mounted.current) setScheduleSaving(false);
      }
    },
    [client, handleProtectedError, scheduleSaving],
  );

  const blocksWorkspaceMutations =
    phase !== "idle" ||
    status === null ||
    status.state === "active" ||
    preview !== null ||
    enqueueOutcomeUnknown ||
    error !== null;

  return {
    actionError,
    blocksWorkspaceMutations,
    completionRevision,
    dismissPreview,
    enqueueManual,
    enqueueOutcomeUnknown,
    error,
    latest,
    phase,
    policy,
    preview,
    previewManual,
    refresh: loadEvidence,
    saveSchedule,
    schedule,
    scheduleError,
    scheduleSaving,
    status,
  };
}

function stateLabel(state: TerminalOperationResult["state"]): string {
  switch (state) {
    case "succeeded":
      return "Succeeded";
    case "failed":
      return "Failed";
    case "partial":
      return "Partially completed";
    case "not_attempted":
      return "Not attempted";
    case "timed_out":
      return "Timed out";
    case "interrupted":
      return "Interrupted";
    case "incompatible":
      return "Incompatible";
    case "ambiguous":
      return "Outcome ambiguous";
  }
}

function stateTone(state: TerminalOperationResult["state"]): StatusTone {
  switch (state) {
    case "succeeded":
      return "success";
    case "partial":
      return "partial";
    case "not_attempted":
      return "not-attempted";
    case "interrupted":
    case "timed_out":
    case "ambiguous":
      return "interrupted";
    case "incompatible":
      return "unsupported";
    case "failed":
      return "danger";
  }
}

function certificateTone(
  state: TerminalOperationResult["certificates"][number]["state"],
): StatusTone {
  switch (state) {
    case "completed":
      return "success";
    case "failed":
      return "danger";
    case "ambiguous":
      return "interrupted";
    case "not_attempted":
      return "not-attempted";
  }
}

function words(code: string): string {
  return code.replaceAll("_", " ");
}

function scheduleStateLabel(state: AutomaticSchedule["state"]): string {
  switch (state) {
    case "disabled":
      return "Disabled";
    case "scheduled":
      return "Scheduled";
    case "due":
      return "Due";
    case "deferred":
      return "Deferred";
    case "blocked":
      return "Needs attention";
  }
}

function scheduleTone(state: AutomaticSchedule["state"]): StatusTone {
  switch (state) {
    case "scheduled":
      return "success";
    case "due":
      return "info";
    case "deferred":
      return "warning";
    case "blocked":
      return "danger";
    case "disabled":
      return "not-attempted";
  }
}

function detectedTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

function AutomaticScheduleControl({
  controller,
}: {
  controller: OperationController;
}) {
  const schedule = controller.schedule;
  const formKey = `${schedule?.enabled ?? false}:${schedule?.timeZone ?? ""}:${schedule?.localTime ?? ""}`;
  return (
    <section
      className="am-automatic-schedule"
      aria-labelledby="automatic-schedule-heading"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">OPS / daily automatic evaluation</p>
          <h3 id="automatic-schedule-heading">Automatic renewal evaluation</h3>
          <p>
            AcmeMux schedules one native workspace evaluation each local day.
            Upstream lego alone applies ARI, certificate lifetime rules, and its
            renewal delay.
          </p>
        </div>
        <StatusBadge
          tone={
            schedule === null ? "not-attempted" : scheduleTone(schedule.state)
          }
        >
          {schedule === null
            ? "Unavailable"
            : scheduleStateLabel(schedule.state)}
        </StatusBadge>
      </div>

      {controller.scheduleError ? (
        <FeedbackPanel tone="warning" title="Schedule evidence unavailable">
          <p>{controller.scheduleError}</p>
        </FeedbackPanel>
      ) : null}

      <form
        className="am-schedule-form"
        key={formKey}
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          void controller.saveSchedule({
            enabled: form.get("enabled") === "on",
            timeZone: String(form.get("timeZone") ?? ""),
            localTime: String(form.get("localTime") ?? ""),
          });
        }}
      >
        <label className="am-schedule-toggle">
          <input
            defaultChecked={schedule?.enabled ?? false}
            disabled={controller.scheduleSaving || schedule === null}
            name="enabled"
            type="checkbox"
          />
          <span>
            <strong>Enable daily evaluation</strong>
            <small>Disabled schedules never start background operations.</small>
          </span>
        </label>
        <label className="am-schedule-field">
          <span>IANA time zone</span>
          <input
            autoComplete="off"
            disabled={controller.scheduleSaving || schedule === null}
            defaultValue={schedule?.timeZone ?? detectedTimeZone()}
            maxLength={128}
            name="timeZone"
            placeholder="America/Denver"
            required
            type="text"
          />
          <small>Daily wall-clock behavior follows this named zone.</small>
        </label>
        <label className="am-schedule-field">
          <span>Local evaluation time</span>
          <input
            disabled={controller.scheduleSaving || schedule === null}
            defaultValue={schedule?.localTime ?? "03:35"}
            name="localTime"
            required
            step={60}
            type="time"
          />
          <small>
            One occurrence per local date; no cron syntax or backlog.
          </small>
        </label>
        <ActionButton
          isDisabled={schedule === null || controller.scheduleSaving}
          isPending={controller.scheduleSaving}
          type="submit"
        >
          {controller.scheduleSaving
            ? "Saving schedule"
            : "Save automatic schedule"}
        </ActionButton>
      </form>

      {schedule !== null ? (
        <dl className="am-schedule-facts">
          <div>
            <dt>Daily local time</dt>
            <dd>
              {schedule.timeZone === null || schedule.localTime === null
                ? "Not configured"
                : `${schedule.localTime} ${schedule.timeZone}`}
            </dd>
          </div>
          <div>
            <dt>Next exact UTC evaluation</dt>
            <dd>
              {schedule.nextEvaluationAt === null ? (
                "Not scheduled"
              ) : (
                <time dateTime={schedule.nextEvaluationAt}>
                  {schedule.nextEvaluationAt}
                </time>
              )}
            </dd>
          </div>
          <div>
            <dt>Last scheduler trigger</dt>
            <dd>
              {schedule.lastTriggeredAt === null ? (
                "Not yet triggered"
              ) : (
                <time dateTime={schedule.lastTriggeredAt}>
                  {schedule.lastTriggeredAt}
                </time>
              )}
            </dd>
          </div>
          <div>
            <dt>Scheduler state</dt>
            <dd>{words(schedule.reasonCode)}</dd>
          </div>
        </dl>
      ) : null}

      {schedule?.state === "deferred" ? (
        <FeedbackPanel tone="warning" title="Due evaluation is deferred">
          <p>
            Another accepted workspace action owns the operation boundary. One
            coalesced evaluation remains due and will run after contention
            clears.
          </p>
        </FeedbackPanel>
      ) : null}
      {schedule?.state === "blocked" ? (
        <FeedbackPanel
          tone="danger"
          title="Automatic evaluation needs attention"
        >
          <p>
            The due evaluation could not be accepted from current runtime,
            workspace, or configuration evidence. AcmeMux did not retry it
            blindly; the next ordinary daily occurrence remains scheduled.
          </p>
        </FeedbackPanel>
      ) : null}
      <p className="am-operation-boundary">
        Missed dates coalesce into one evaluation. A service-interrupted run is
        reconciled and never replayed automatically.
      </p>
    </section>
  );
}

function LatestResult({ result }: { result: TerminalOperationResult }) {
  return (
    <section
      className="am-operation-result"
      aria-labelledby="latest-operation-heading"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">
            Latest bounded{" "}
            {result.kind === "scheduled" ? "automatic" : "manual"} result
          </p>
          <h3 id="latest-operation-heading">{stateLabel(result.state)}</h3>
        </div>
        <StatusBadge tone={stateTone(result.state)}>
          {stateLabel(result.state)}
        </StatusBadge>
      </div>

      <dl className="am-operation-result__facts">
        <div>
          <dt>Trigger</dt>
          <dd>
            {result.kind === "scheduled"
              ? "Automatic schedule"
              : "Administrator"}
          </dd>
        </div>
        <div>
          <dt>Requested</dt>
          <dd>
            <time dateTime={result.requestedAt}>{result.requestedAt}</time>
          </dd>
        </div>
        <div>
          <dt>Started</dt>
          <dd>
            {result.startedAt === null ? (
              "Not started"
            ) : (
              <time dateTime={result.startedAt}>{result.startedAt}</time>
            )}
          </dd>
        </div>
        <div>
          <dt>Finished</dt>
          <dd>
            <time dateTime={result.finishedAt}>{result.finishedAt}</time>
          </dd>
        </div>
        <div>
          <dt>Result code</dt>
          <dd>{words(result.reasonCode)}</dd>
        </div>
      </dl>

      <FeedbackPanel tone={stateTone(result.state)} title={result.summary}>
        <p>
          <strong>Safe next action:</strong> {result.nextAction}
        </p>
      </FeedbackPanel>

      <details className="am-disclosure am-operation-evidence">
        <summary>Show runtime and native configuration identity</summary>
        {result.runtime === null ? (
          <p>This retained result predates bounded reporting identity.</p>
        ) : (
          <dl className="am-operation-result__facts">
            <div>
              <dt>Upstream lego identity</dt>
              <dd>{result.runtime.identity}</dd>
            </div>
            <div>
              <dt>Compatibility manifest</dt>
              <dd>{result.runtime.manifestId}</dd>
            </div>
            <div>
              <dt>Native configuration</dt>
              <dd>{result.configurationPath}</dd>
            </div>
            <div>
              <dt>Native storage</dt>
              <dd>{result.storagePath}</dd>
            </div>
          </dl>
        )}
        <p>
          Certificate, chain, account, and private-key files remain owned by
          upstream lego in native storage. AcmeMux does not back up or deploy
          them.
        </p>
      </details>

      <FeedbackPanel
        tone={result.inventory.state === "refreshed" ? "success" : "warning"}
        title={
          result.inventory.state === "refreshed"
            ? "Native inventory refreshed"
            : "Inventory refresh unavailable"
        }
      >
        <p>{result.inventory.summary}</p>
        {result.inventory.state === "refreshed" ? (
          <p>
            {result.inventory.certificateCount.toLocaleString("en-US")} native
            {result.inventory.certificateCount === 1
              ? " certificate was"
              : " certificates were"}{" "}
            observed.
          </p>
        ) : null}
      </FeedbackPanel>

      {result.mayHaveChanged ? (
        <FeedbackPanel
          tone="interrupted"
          title="External state may have changed"
        >
          <p>
            Do not retry blindly. Review the refreshed native inventory and
            upstream diagnostic before preparing another operation.
          </p>
        </FeedbackPanel>
      ) : null}

      {result.certificates.length > 0 ? (
        <div
          className="am-table-frame am-operation-result__certificates"
          role="region"
          aria-label="Latest certificate operation results"
          tabIndex={0}
        >
          <table>
            <caption>
              Evidence available from the upstream fail-fast run
            </caption>
            <thead>
              <tr>
                <th scope="col">Certificate</th>
                <th scope="col">State</th>
                <th scope="col">Reason</th>
                <th scope="col">Account</th>
                <th scope="col">CA</th>
                <th scope="col">Challenge / provider</th>
              </tr>
            </thead>
            <tbody>
              {result.certificates.map((certificate) => (
                <tr key={certificate.name}>
                  <th scope="row">{certificate.name}</th>
                  <td>
                    <StatusBadge tone={certificateTone(certificate.state)}>
                      {words(certificate.state)}
                    </StatusBadge>
                  </td>
                  <td>{words(certificate.reasonCode)}</td>
                  <td>{certificate.account ?? "Not retained"}</td>
                  <td>{certificate.ca ?? "Not retained"}</td>
                  <td>
                    {certificate.challenge === null
                      ? "Not retained"
                      : `${certificate.challenge.kind} / ${certificate.challenge.mode}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <details className="am-disclosure am-operation-output">
        <summary>Show redacted upstream transcript</summary>
        {result.output.truncated ? (
          <StatusBadge tone="warning">Output limit reached</StatusBadge>
        ) : null}
        <pre>
          {result.output.text.length > 0
            ? result.output.text
            : "No upstream output was retained."}
        </pre>
      </details>
    </section>
  );
}

export function operationSignal(controller: OperationController): string {
  if (controller.phase === "loading") return "Checking";
  if (controller.status?.state === "active") {
    return controller.status.operation.state === "queued"
      ? "Queued"
      : "Running";
  }
  if (controller.enqueueOutcomeUnknown) return "Outcome unknown";
  if (controller.error && controller.status === null) return "Unavailable";
  if (controller.latest?.state === "available") {
    return stateLabel(controller.latest.result.state);
  }
  return "Ready";
}

export function automaticScheduleSignal(
  controller: OperationController,
): string {
  if (controller.schedule === null) return "Checking";
  return scheduleStateLabel(controller.schedule.state);
}

export function OperationsPanel({
  controller,
  executionReady,
}: {
  controller: OperationController;
  executionReady: boolean;
}) {
  const active =
    controller.status?.state === "active" ? controller.status.operation : null;
  const canPreview =
    executionReady &&
    controller.status?.state === "idle" &&
    controller.phase === "idle" &&
    !controller.enqueueOutcomeUnknown &&
    controller.error === null;

  return (
    <section
      className="am-operations"
      aria-labelledby="operations-heading"
      id="manual-operation"
    >
      <div className="am-operations__heading">
        <div>
          <p className="am-kicker">OPS / automatic and manual workspace runs</p>
          <h2 id="operations-heading">Certificate operations</h2>
          <p>
            Schedule or review one constrained upstream lego file-mode run for
            the entire native workspace. Every accepted run is durable.
          </p>
        </div>
        <StatusBadge
          tone={
            active
              ? "info"
              : controller.enqueueOutcomeUnknown
                ? "interrupted"
                : executionReady && controller.error === null
                  ? "success"
                  : "not-attempted"
          }
        >
          {operationSignal(controller)}
        </StatusBadge>
      </div>

      {controller.phase === "loading" && controller.status === null ? (
        <div className="am-operation-progress" role="status" aria-busy="true">
          <span className="am-spinner" aria-hidden="true" />
          <p>Checking durable operation state and cancellation policy</p>
        </div>
      ) : null}

      {controller.error ? (
        <FeedbackPanel tone="warning" title="Operation evidence incomplete">
          <p>{controller.error}</p>
          <ActionButton
            isDisabled={controller.phase !== "idle"}
            onPress={() => void controller.refresh()}
            variant="secondary"
          >
            Check operation evidence
          </ActionButton>
        </FeedbackPanel>
      ) : null}

      {controller.actionError ? (
        <FeedbackPanel
          announcement="assertive"
          tone={controller.enqueueOutcomeUnknown ? "interrupted" : "danger"}
          title={
            controller.enqueueOutcomeUnknown
              ? "Enqueue outcome unknown"
              : "Operation not started"
          }
        >
          <p>{controller.actionError}</p>
        </FeedbackPanel>
      ) : null}

      <AutomaticScheduleControl controller={controller} />

      {active ? (
        <section
          className="am-operation-active"
          aria-labelledby="active-operation-heading"
          aria-live="polite"
        >
          <div>
            <p className="am-kicker">Durable worker state</p>
            <h3 id="active-operation-heading">
              {active.state === "queued"
                ? active.kind === "scheduled"
                  ? "Automatic evaluation queued"
                  : "Operation queued"
                : active.kind === "scheduled"
                  ? "Automatic evaluation running"
                  : "Operation running"}
            </h3>
            <p>
              Phase: <strong>{words(active.phase)}</strong>. Closing or
              navigating away from this browser does not stop the worker.
            </p>
          </div>
          <span className="am-spinner" aria-hidden="true" />
          <dl>
            <div>
              <dt>Requested</dt>
              <dd>{active.requestedAt}</dd>
            </div>
            <div>
              <dt>Started</dt>
              <dd>{active.startedAt ?? "Waiting for worker"}</dd>
            </div>
          </dl>
          <p className="am-operation-active__boundary">
            There is no browser cancel action. AcmeMux applies the bounded
            timeout and controlled process-tree termination policy, then
            refreshes native inventory.
          </p>
        </section>
      ) : (
        <div className="am-operation-start">
          {executionReady ? (
            <FeedbackPanel tone="success" title="Ready for a safe review">
              <p>
                Runtime, workspace, and curated native configuration evidence
                currently permit a reviewed managed operation.
              </p>
            </FeedbackPanel>
          ) : (
            <FeedbackPanel tone="not-attempted" title="Operation unavailable">
              <p>
                A supported runtime, safe adopted workspace, and valid fully
                supported configuration are required before preview.
              </p>
            </FeedbackPanel>
          )}
          <ActionButton
            isDisabled={!canPreview}
            isPending={controller.phase === "previewing"}
            onPress={() => void controller.previewManual()}
          >
            {controller.phase === "previewing"
              ? "Preparing secret-safe review"
              : "Preview manual workspace operation"}
          </ActionButton>
        </div>
      )}

      {controller.policy ? (
        <div className="am-operation-policy">
          <div>
            <strong>Browser disconnect</strong>
            <span>Operation continues</span>
          </div>
          <div>
            <strong>Browser cancellation</strong>
            <span>Not supported</span>
          </div>
          <div>
            <strong>Automatic retry</strong>
            <span>Never</span>
          </div>
          <div>
            <strong>Maximum runtime</strong>
            <span>
              {controller.policy.timeoutSeconds.toLocaleString("en-US")} seconds
            </span>
          </div>
        </div>
      ) : null}

      {controller.latest?.state === "available" ? (
        <LatestResult result={controller.latest.result} />
      ) : controller.latest?.state === "empty" ? (
        <p className="am-operation-empty">
          No completed manual operation has been retained. AcmeMux stores only
          the bounded latest result, not long-term job history.
        </p>
      ) : null}

      <p className="am-operation-boundary">
        AcmeMux never returns a raw command, argument vector, environment,
        credential value, YAML document, certificate, or private key to this
        view. Upstream output is bounded and redacted before persistence.
      </p>

      {controller.preview ? (
        <OperationReviewDialog
          isEnqueueing={controller.phase === "enqueueing"}
          onCancel={controller.dismissPreview}
          onConfirm={() => void controller.enqueueManual()}
          preview={controller.preview}
        />
      ) : null}
    </section>
  );
}
