import { useCallback, useEffect, useRef, useState } from "react";

import {
  ConfigurationRequestError,
  type ConfigurationChange,
  type ConfigurationClient,
  type ConfigurationDiagnostic,
  type ConfigurationPreview,
  type ConfigurationSnapshot,
  type ProjectedField,
  type RecoveryResolution,
} from "../api/configuration";
import { useAuthenticatedSession } from "../auth/AuthBoundary";
import { ActionButton } from "../components/ActionButton";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { StatusBadge, type StatusTone } from "../components/StatusBadge";
import {
  NativeConfigurationEditor,
  type ConfigurationCreationLocation,
  type PreparedConfiguration,
} from "./NativeConfigurationEditor";

type ConfigurationPhase = "loading" | "idle";
type ConfigurationMutationPhase = "idle" | "previewing" | "saving";

export type ConfigurationController = {
  error: string | null;
  mutationError: string | null;
  mutationPhase: ConfigurationMutationPhase;
  phase: ConfigurationPhase;
  recoveryEvidenceStale: boolean;
  recoveryOutcomeUnknown: boolean;
  requestRevision: number;
  snapshot: ConfigurationSnapshot | null;
  refresh(): Promise<void>;
  previewChanges(
    changes: ConfigurationChange[],
    location?: ConfigurationCreationLocation,
  ): Promise<ConfigurationPreview | null>;
  savePrepared(prepared: PreparedConfiguration): Promise<boolean>;
  resolveRecovery(resolution: RecoveryResolution): Promise<void>;
};

function safeRequestMessage(error: unknown): string {
  if (!(error instanceof ConfigurationRequestError)) {
    return "Configuration status is unavailable. No native files were changed.";
  }
  switch (error.code) {
    case "configuration_changed":
      return "The native configuration changed while it was being checked. Load current evidence before preparing another change.";
    case "service_busy":
      return "Another native workspace action is in progress. Check configuration again after it finishes.";
    case "invalid_request":
      return "AcmeMux rejected the configuration request. No native files were changed.";
    case "service_unavailable":
    case "network_failure":
      return "Configuration status is unavailable. No native files were changed.";
    case "invalid_response":
      return "Configuration status could not be verified from the service response.";
    case "authentication_required":
    case "request_not_allowed":
      return "The protected configuration request could not continue.";
  }
}

function recoveryOutcomeMessage(evidenceReloaded: boolean): string {
  if (evidenceReloaded) {
    return "The recovery request outcome could not be confirmed. Current native configuration evidence was reloaded; review it before another recovery action.";
  }
  return "The recovery request outcome is unknown. Native files or recovery state may have changed. The recovery evidence below predates that request and is read-only until you check configuration again.";
}

function mutationMessage(
  error: unknown,
  save: boolean,
  evidenceReloaded = false,
): string {
  if (
    error instanceof ConfigurationRequestError &&
    error.code === "configuration_changed"
  ) {
    return "Native workspace evidence changed after review. No reviewed replacement was applied; load current evidence and prepare a new review.";
  }
  if (!save) {
    return safeRequestMessage(error);
  }
  if (evidenceReloaded) {
    return "The save response could not confirm its outcome. Current native evidence was reloaded; inspect it before preparing another change.";
  }
  return "The save outcome is unknown. Native files may have changed. Check configuration before preparing another change.";
}

export function useConfigurationController(
  client: ConfigurationClient,
  activationKey: string | null,
  interactionsEnabled = activationKey !== null,
): ConfigurationController {
  const { endSession, rejectRequest } = useAuthenticatedSession();
  const [snapshot, setSnapshot] = useState<ConfigurationSnapshot | null>(null);
  const [phase, setPhase] = useState<ConfigurationPhase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutationPhase, setMutationPhase] =
    useState<ConfigurationMutationPhase>("idle");
  const [loadedActivationKey, setLoadedActivationKey] = useState<string | null>(
    null,
  );
  const [recoveryOutcomeUnknown, setRecoveryOutcomeUnknown] = useState(false);
  const [recoveryEvidenceStale, setRecoveryEvidenceStale] = useState(false);
  const [requestRevision, setRequestRevision] = useState(0);
  const requestVersion = useRef(0);
  const refreshActive = useRef(false);

  const handleProtectedError = useCallback(
    (requestError: unknown): boolean => {
      if (!(requestError instanceof ConfigurationRequestError)) {
        return false;
      }
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

  const refresh = useCallback(async () => {
    if (
      activationKey === null ||
      !interactionsEnabled ||
      refreshActive.current
    ) {
      return;
    }
    refreshActive.current = true;
    const version = ++requestVersion.current;
    setPhase("loading");
    setError(null);
    try {
      const next = await client.getConfiguration();
      if (requestVersion.current === version) {
        setSnapshot(next);
        setRecoveryEvidenceStale(false);
        setRecoveryOutcomeUnknown(false);
        setRequestRevision(version);
      }
    } catch (requestError) {
      if (
        requestVersion.current !== version ||
        handleProtectedError(requestError)
      ) {
        return;
      }
      if (recoveryOutcomeUnknown && snapshot?.state === "recovery_required") {
        setRecoveryEvidenceStale(true);
        setError(recoveryOutcomeMessage(false));
      } else {
        setSnapshot(null);
        setError(safeRequestMessage(requestError));
      }
    } finally {
      refreshActive.current = false;
      if (requestVersion.current === version) {
        setPhase("idle");
      }
    }
  }, [
    activationKey,
    client,
    handleProtectedError,
    interactionsEnabled,
    recoveryOutcomeUnknown,
    snapshot,
  ]);

  const resolveRecovery = useCallback(
    async (resolution: RecoveryResolution) => {
      if (
        activationKey === null ||
        !interactionsEnabled ||
        refreshActive.current ||
        recoveryEvidenceStale ||
        snapshot?.state !== "recovery_required"
      ) {
        return;
      }
      refreshActive.current = true;
      const version = ++requestVersion.current;
      setPhase("loading");
      setError(null);
      try {
        const next = await client.resolveRecovery(
          snapshot.source.baseRevisionToken,
          resolution,
          snapshot.recovery.operation,
          snapshot.source.configurationPath,
          snapshot.source.runtimeManifestId,
        );
        if (requestVersion.current === version) {
          setSnapshot(next);
          setRecoveryEvidenceStale(false);
          setRecoveryOutcomeUnknown(false);
          setRequestRevision(version);
        }
      } catch (requestError) {
        if (
          requestVersion.current !== version ||
          handleProtectedError(requestError)
        ) {
          return;
        }
        setRecoveryEvidenceStale(true);
        setRecoveryOutcomeUnknown(true);
        try {
          const current = await client.getConfiguration();
          if (requestVersion.current === version) {
            setSnapshot(current);
            setRecoveryEvidenceStale(false);
            setRequestRevision(version);
            setError(recoveryOutcomeMessage(true));
          }
        } catch (reloadError) {
          if (
            requestVersion.current !== version ||
            handleProtectedError(reloadError)
          ) {
            return;
          }
          setError(recoveryOutcomeMessage(false));
        }
      } finally {
        refreshActive.current = false;
        if (requestVersion.current === version) {
          setPhase("idle");
        }
      }
    },
    [
      activationKey,
      client,
      handleProtectedError,
      interactionsEnabled,
      recoveryEvidenceStale,
      snapshot,
    ],
  );

  const previewChanges = useCallback(
    async (
      changes: ConfigurationChange[],
      location?: ConfigurationCreationLocation,
    ): Promise<ConfigurationPreview | null> => {
      if (
        activationKey === null ||
        !interactionsEnabled ||
        refreshActive.current ||
        snapshot === null
      ) {
        return null;
      }
      const creation = snapshot.state === "creation_required";
      if (
        (creation && location === undefined) ||
        (!creation &&
          (snapshot.state === "recovery_required" ||
            !snapshot.capabilities.editing))
      ) {
        return null;
      }
      refreshActive.current = true;
      const version = requestVersion.current;
      setMutationPhase("previewing");
      setMutationError(null);
      try {
        const result = creation
          ? await client.previewCreation(
              snapshot.source.baseRevisionToken,
              location!.workingDirectory,
              location!.configurationPath,
              changes,
            )
          : await client.previewChanges(
              snapshot.source.baseRevisionToken,
              changes,
            );
        return requestVersion.current === version ? result : null;
      } catch (requestError) {
        if (
          requestVersion.current === version &&
          !handleProtectedError(requestError)
        ) {
          setMutationError(mutationMessage(requestError, false));
        }
        return null;
      } finally {
        refreshActive.current = false;
        if (requestVersion.current === version) {
          setMutationPhase("idle");
        }
      }
    },
    [
      activationKey,
      client,
      handleProtectedError,
      interactionsEnabled,
      snapshot,
    ],
  );

  const savePrepared = useCallback(
    async (prepared: PreparedConfiguration): Promise<boolean> => {
      if (
        activationKey === null ||
        !interactionsEnabled ||
        refreshActive.current ||
        snapshot === null ||
        prepared.preview.state !== "review_required"
      ) {
        return false;
      }
      const creation = snapshot.state === "creation_required";
      if (
        (creation && prepared.location === undefined) ||
        prepared.preview.baseRevisionToken !==
          snapshot.source.baseRevisionToken ||
        (!creation &&
          (snapshot.state === "recovery_required" ||
            !snapshot.capabilities.editing))
      ) {
        return false;
      }
      refreshActive.current = true;
      const version = requestVersion.current;
      setMutationPhase("saving");
      setMutationError(null);
      try {
        const next = creation
          ? await client.createConfiguration(
              prepared.location!.workingDirectory,
              prepared.location!.configurationPath,
              prepared.preview.baseRevisionToken,
              snapshot.source.runtimeManifestId,
              prepared.changes,
              prepared.preview.reviewedPreviewToken,
            )
          : await client.saveChanges(
              snapshot.source.baseRevisionToken,
              snapshot.source.configurationPath,
              snapshot.source.runtimeManifestId,
              prepared.changes,
              prepared.preview.reviewedPreviewToken,
            );
        if (requestVersion.current !== version) return false;
        setSnapshot(next);
        setRecoveryEvidenceStale(false);
        setRecoveryOutcomeUnknown(false);
        setRequestRevision((current) => current + 1);
        return true;
      } catch (requestError) {
        if (
          requestVersion.current !== version ||
          handleProtectedError(requestError)
        ) {
          return false;
        }
        if (
          requestError instanceof ConfigurationRequestError &&
          requestError.code === "configuration_changed"
        ) {
          setMutationError(mutationMessage(requestError, true));
          return false;
        }
        try {
          const current = await client.getConfiguration();
          if (requestVersion.current === version) {
            setSnapshot(current);
            setRequestRevision((revision) => revision + 1);
            setMutationError(mutationMessage(requestError, true, true));
          }
        } catch (reloadError) {
          if (
            requestVersion.current === version &&
            !handleProtectedError(reloadError)
          ) {
            setMutationError(mutationMessage(requestError, true));
          }
        }
        return false;
      } finally {
        refreshActive.current = false;
        if (requestVersion.current === version) {
          setMutationPhase("idle");
        }
      }
    },
    [
      activationKey,
      client,
      handleProtectedError,
      interactionsEnabled,
      snapshot,
    ],
  );

  useEffect(() => {
    if (activationKey === null) {
      requestVersion.current += 1;
      return;
    }
    const version = ++requestVersion.current;
    async function load() {
      try {
        const next = await client.getConfiguration();
        if (requestVersion.current === version) {
          setSnapshot(next);
          setMutationError(null);
          setRecoveryEvidenceStale(false);
          setRecoveryOutcomeUnknown(false);
          setRequestRevision(version);
          setLoadedActivationKey(activationKey);
        }
      } catch (requestError) {
        if (
          requestVersion.current !== version ||
          handleProtectedError(requestError)
        ) {
          return;
        }
        setSnapshot(null);
        setError(safeRequestMessage(requestError));
        setLoadedActivationKey(activationKey);
      } finally {
        if (requestVersion.current === version) {
          setPhase("idle");
        }
      }
    }
    void load();
    return () => {
      requestVersion.current += 1;
    };
  }, [activationKey, client, handleProtectedError]);

  const active =
    activationKey !== null && loadedActivationKey === activationKey;
  return {
    error: active ? error : null,
    mutationError: active ? mutationError : null,
    mutationPhase: active ? mutationPhase : "idle",
    phase: activationKey === null ? "idle" : active ? phase : "loading",
    recoveryEvidenceStale: active && recoveryEvidenceStale,
    recoveryOutcomeUnknown: active && recoveryOutcomeUnknown,
    refresh,
    previewChanges,
    savePrepared,
    resolveRecovery,
    requestRevision,
    snapshot: active && phase !== "loading" ? snapshot : null,
  };
}

function DiagnosticsView({
  diagnostics,
}: {
  diagnostics: ConfigurationDiagnostic[];
}) {
  if (diagnostics.length === 0) return null;
  return (
    <section
      className="am-configuration-diagnostics"
      aria-labelledby="configuration-diagnostics-heading"
    >
      <h3 id="configuration-diagnostics-heading">Configuration findings</h3>
      <ul>
        {diagnostics.map((diagnostic, index) => (
          <li
            key={`${diagnostic.code}:${diagnostic.fieldId ?? "none"}:${JSON.stringify(diagnostic.bindings)}:${diagnostic.path ?? "none"}:${index}`}
          >
            <div>
              <code>{diagnostic.code}</code>
              <StatusBadge
                tone={
                  diagnostic.severity === "blocking" ? "unsupported" : "info"
                }
              >
                {diagnostic.severity === "blocking" ? "Blocking" : "Notice"}
              </StatusBadge>
            </div>
            <p>{diagnostic.message}</p>
            <small>
              {diagnostic.role.replace("_", " ")}
              {diagnostic.line !== null
                ? ` / line ${diagnostic.line}, column ${diagnostic.column}`
                : ""}
            </small>
            {diagnostic.bindings.length > 0 ? (
              <small>
                Logical identity:{" "}
                {diagnostic.bindings
                  .map((binding) => `${binding.id}=${binding.value}`)
                  .join(", ")}
              </small>
            ) : null}
            {diagnostic.path ? (
              <small>Native path: {diagnostic.path}</small>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

function ProjectionSummary({ projection }: { projection: ProjectedField[] }) {
  const secretFields = projection.filter((field) => field.kind === "secret");
  const presentSecrets = secretFields.filter(
    (field) => field.presenceKnown && field.present,
  ).length;
  const presentFields = projection.filter((field) => field.present).length;
  return (
    <section
      className="am-configuration-projection"
      aria-labelledby="configuration-projection-heading"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">Secret-safe projection</p>
          <h3 id="configuration-projection-heading">Supported native fields</h3>
        </div>
        <StatusBadge tone="info">
          {projection.length.toLocaleString("en-US")} known
        </StatusBadge>
      </div>
      <dl>
        <div>
          <dt>Present supported fields</dt>
          <dd>{presentFields.toLocaleString("en-US")}</dd>
        </div>
        <div>
          <dt>Write-only secret fields</dt>
          <dd>{secretFields.length.toLocaleString("en-US")}</dd>
        </div>
        <div>
          <dt>Stored secret values present</dt>
          <dd>{presentSecrets.toLocaleString("en-US")}</dd>
        </div>
      </dl>
      <p>
        Secret values are represented only as present or absent. Raw YAML,
        dotenv lines, and stored secret values are never returned to this
        browser view.
      </p>
    </section>
  );
}

function RecoveryView({
  snapshot,
  interactionsEnabled,
  onResolve,
}: {
  snapshot: Extract<ConfigurationSnapshot, { state: "recovery_required" }>;
  interactionsEnabled: boolean;
  onResolve(resolution: RecoveryResolution): void;
}) {
  const [adoptConfirmed, setAdoptConfirmed] = useState(false);

  return (
    <section
      className="am-configuration-recovery"
      aria-labelledby="configuration-recovery-heading"
    >
      <h3 id="configuration-recovery-heading">
        Secret-free replacement phases
      </h3>
      <p>
        Journal phase: <code>{snapshot.recovery.phase}</code>. Durable state:{" "}
        <code>{snapshot.recovery.state}</code>. Interrupted operation:{" "}
        <code>{snapshot.recovery.operation}</code>. AcmeMux will not replay or
        roll back an ambiguous native change automatically.
      </p>
      <ul>
        {snapshot.recovery.targets.map((target) => (
          <li key={target.path}>
            <code>{target.path}</code>
            <span>{target.role}</span>
            <StatusBadge
              tone={target.state === "ambiguous" ? "interrupted" : "neutral"}
            >
              {target.state}
            </StatusBadge>
          </li>
        ))}
      </ul>
      {snapshot.recovery.state === "unapplied" ? (
        <div className="am-configuration-recovery__actions">
          <p>
            No candidate reached an active path. Discarding removes only the
            recognized staged candidates after one final evidence check.
          </p>
          <ActionButton
            isDisabled={!interactionsEnabled}
            onPress={() => onResolve("discard_unapplied")}
            variant="secondary"
          >
            Discard unapplied candidates
          </ActionButton>
        </div>
      ) : null}
      {snapshot.recovery.state === "applied" &&
      snapshot.recovery.operation === "edit" ? (
        <div className="am-configuration-recovery__actions">
          <p>
            Every reviewed candidate is active. Finalizing revalidates the
            current native sources before accepting the replacement.
          </p>
          <ActionButton
            isDisabled={!interactionsEnabled}
            onPress={() => onResolve("finalize_applied")}
            variant="secondary"
          >
            Validate and finalize replacement
          </ActionButton>
        </div>
      ) : null}
      {snapshot.recovery.state === "applied" ||
      snapshot.recovery.state === "partial" ||
      snapshot.recovery.state === "ambiguous" ? (
        <div className="am-configuration-recovery__actions">
          <p>
            {snapshot.recovery.operation === "creation"
              ? "This interrupted creation has no previously adopted workspace to finalize. Review the active native files, then explicitly accept the current workspace without replaying staged content."
              : snapshot.recovery.state === "applied"
                ? "If the reviewed edit intentionally changed native path references, explicitly accept the freshly validated active files instead of using the pre-edit finalization boundary."
                : "Repair the active native files outside AcmeMux and remove every recognized .acmemux-edit-* staging entry. AcmeMux can then validate and adopt the active files exactly as they are. It never replays a staged candidate."}
          </p>
          <label>
            <input
              checked={adoptConfirmed}
              disabled={!interactionsEnabled}
              onChange={(event) => setAdoptConfirmed(event.target.checked)}
              type="checkbox"
            />
            {snapshot.recovery.operation === "creation"
              ? "I reviewed the active native files and explicitly accept this workspace without replaying staged content."
              : snapshot.recovery.state === "applied"
                ? "I reviewed the active native files and accept their current path references without replaying staged content."
                : "I repaired the active files and removed the interrupted staging entries. Accept the current native files without replaying them."}
          </label>
          <ActionButton
            isDisabled={!interactionsEnabled || !adoptConfirmed}
            onPress={() => onResolve("adopt_current")}
            variant="secondary"
          >
            Validate and adopt current files
          </ActionButton>
        </div>
      ) : null}
    </section>
  );
}

function presentation(snapshot: ConfigurationSnapshot): {
  copy: string;
  label: string;
  tone: StatusTone;
} {
  switch (snapshot.state) {
    case "creation_required":
      return {
        copy: "No native configuration is adopted. Prepare a supported CA, HTTP-01 challenge, and certificate definition, then review the exact native intent before AcmeMux creates a restrictive .lego.yml file.",
        label: "Native configuration required",
        tone: "warning",
      };
    case "ready":
      return {
        copy: "The current native files were projected without unsupported or invalid content. Typed forms can prepare reviewed changes through this boundary.",
        label: "Configuration engine ready",
        tone: "success",
      };
    case "unsupported":
      return {
        copy: "Unimplemented or unknown native content remains authoritative and preserved. Managed execution stays blocked.",
        label: "Native content unsupported",
        tone: "unsupported",
      };
    case "invalid":
      return {
        copy: snapshot.capabilities.editing
          ? "Curated native values violate a supported constraint. Typed forms remain available to prepare a complete repair; execution stays blocked until the reviewed result is valid."
          : "The current native content cannot be projected or edited safely. Active files were not changed.",
        label: snapshot.capabilities.editing
          ? "Configuration needs repair"
          : "Configuration invalid",
        tone: "danger",
      };
    case "recovery_required":
      return {
        copy: "A prior multi-file replacement may have completed only in part. Managed edits and runs remain blocked pending reconciliation.",
        label: "Recovery required",
        tone: "interrupted",
      };
  }
}

export function configurationSignal(
  controller: ConfigurationController,
): string {
  if (controller.phase === "loading") return "Checking";
  if (controller.error) return "Unavailable";
  switch (controller.snapshot?.state) {
    case "creation_required":
      return "Creation required";
    case "ready":
      return "Ready";
    case "unsupported":
      return "Unsupported";
    case "invalid":
      return "Invalid";
    case "recovery_required":
      return "Recovery required";
    case undefined:
      return "Unavailable";
  }
}

export function ConfigurationPanel({
  controller,
  interactionsEnabled = true,
}: {
  controller: ConfigurationController;
  interactionsEnabled?: boolean;
}) {
  const snapshot = controller.snapshot;
  const statePresentation = snapshot ? presentation(snapshot) : null;
  return (
    <section
      className="am-configuration"
      aria-labelledby="configuration-heading"
    >
      <div className="am-configuration__heading">
        <div>
          <p className="am-kicker">Native editing boundary</p>
          <h2 id="configuration-heading">Configuration mediation</h2>
          <p>
            AcmeMux projects only curated fields from the authoritative node
            tree. It does not expose a raw YAML editor or a generic environment
            variable interface.
          </p>
        </div>
        <StatusBadge tone={snapshot?.state === "ready" ? "success" : "warning"}>
          {configurationSignal(controller)}
        </StatusBadge>
      </div>

      {controller.phase === "loading" ? (
        <div
          className="am-configuration-progress"
          aria-busy="true"
          aria-live="polite"
        >
          <span className="am-spinner" aria-hidden="true" />
          <p>Checking native configuration support</p>
        </div>
      ) : null}

      {controller.error ? (
        <FeedbackPanel
          announcement="assertive"
          tone="interrupted"
          title={
            controller.recoveryOutcomeUnknown
              ? "Recovery outcome unknown"
              : "Configuration unavailable"
          }
        >
          <p>{controller.error}</p>
          <ActionButton
            isDisabled={!interactionsEnabled}
            onPress={() => void controller.refresh()}
            variant="secondary"
          >
            Check configuration again
          </ActionButton>
        </FeedbackPanel>
      ) : null}

      {controller.mutationError ? (
        <FeedbackPanel
          announcement="assertive"
          tone="interrupted"
          title="Configuration change needs attention"
        >
          <p>{controller.mutationError}</p>
          <ActionButton
            isDisabled={
              !interactionsEnabled || controller.mutationPhase !== "idle"
            }
            onPress={() => void controller.refresh()}
            variant="secondary"
          >
            Load current configuration evidence
          </ActionButton>
        </FeedbackPanel>
      ) : null}

      {snapshot && statePresentation ? (
        <div className="am-configuration-current">
          <FeedbackPanel
            announcement={snapshot.state === "ready" ? "polite" : "assertive"}
            tone={statePresentation.tone}
            title={statePresentation.label}
          >
            <p>{statePresentation.copy}</p>
            {!controller.error ? (
              <ActionButton
                isDisabled={!interactionsEnabled}
                onPress={() => void controller.refresh()}
                variant="secondary"
              >
                Check configuration again
              </ActionButton>
            ) : null}
          </FeedbackPanel>
          <DiagnosticsView diagnostics={snapshot.diagnostics} />
          {snapshot.state === "recovery_required" ? (
            <RecoveryView
              interactionsEnabled={
                interactionsEnabled && !controller.recoveryEvidenceStale
              }
              key={snapshot.source.baseRevisionToken}
              onResolve={(resolution) =>
                void controller.resolveRecovery(resolution)
              }
              snapshot={snapshot}
            />
          ) : snapshot.state === "creation_required" ? (
            <NativeConfigurationEditor
              interactionsEnabled={interactionsEnabled}
              key={
                snapshot.source.runtimeManifestId +
                ":" +
                String(controller.requestRevision)
              }
              mode="creation"
              onPreview={controller.previewChanges}
              onSave={controller.savePrepared}
              operationPending={controller.mutationPhase !== "idle"}
              projection={[]}
              revisionKey={
                snapshot.source.runtimeManifestId +
                ":" +
                String(controller.requestRevision)
              }
            />
          ) : (
            <>
              <ProjectionSummary projection={snapshot.projection} />
              {snapshot.capabilities.editing ? (
                <NativeConfigurationEditor
                  interactionsEnabled={interactionsEnabled}
                  key={snapshot.source.baseRevisionToken}
                  mode="edit"
                  onPreview={controller.previewChanges}
                  onSave={controller.savePrepared}
                  operationPending={controller.mutationPhase !== "idle"}
                  projection={snapshot.projection}
                  revisionKey={snapshot.source.baseRevisionToken}
                />
              ) : null}
            </>
          )}
          {snapshot.state !== "creation_required" ? (
            <details className="am-disclosure">
              <summary>Show native configuration source paths</summary>
              <dl>
                <div>
                  <dt>Configuration</dt>
                  <dd>{snapshot.source.configurationPath}</dd>
                </div>
                <div>
                  <dt>Runtime manifest</dt>
                  <dd>{snapshot.source.runtimeManifestId}</dd>
                </div>
                <div>
                  <dt>Referenced dotenv files</dt>
                  <dd>
                    {snapshot.source.dotenvPaths.length > 0
                      ? snapshot.source.dotenvPaths.join(", ")
                      : "None"}
                  </dd>
                </div>
              </dl>
            </details>
          ) : null}
        </div>
      ) : null}

      <p className="am-configuration-boundary">
        Preview is non-writing. Save will re-open every source under the shared
        workspace lock, repeat schema and semantic validation, compare opaque
        review continuity tokens, and record only secret-free replacement
        phases.
      </p>
    </section>
  );
}
