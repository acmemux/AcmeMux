import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  MAX_RUNTIME_PATH_LENGTH,
  RuntimeRequestError,
  runtimePathError,
  type RuntimeCandidate,
  type RuntimeClient,
  type RuntimeDiagnosticCode,
  type RuntimeCompatibility,
  type RuntimeDiagnosticState,
  type RuntimeEvidence,
  type RuntimeSnapshot,
} from "../api/runtime";
import { useAuthenticatedSession } from "../auth/AuthBoundary";
import { ActionButton } from "../components/ActionButton";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { StatusBadge, type StatusTone } from "../components/StatusBadge";

type RuntimePhase = "loading" | "idle" | "probing" | "adopting";

export type RuntimeController = {
  candidate: RuntimeCandidate | null;
  error: string | null;
  path: string;
  pathError: string | null;
  phase: RuntimePhase;
  requestRevision: number;
  snapshot: RuntimeSnapshot | null;
  adopt(): Promise<void>;
  inspect(): Promise<void>;
  refresh(): Promise<void>;
  setPath(path: string): void;
};

function safeRequestMessage(error: unknown): string {
  if (!(error instanceof RuntimeRequestError)) {
    return "Runtime status is unavailable. No executable was adopted or run.";
  }
  switch (error.code) {
    case "runtime_changed":
      return "The executable changed after review. Inspect it again before adoption.";
    case "invalid_request":
      return "AcmeMux rejected the runtime request. Review the host path and try again.";
    case "service_unavailable":
    case "network_failure":
      return "Runtime status is unavailable. No executable was adopted or run.";
    case "invalid_response":
      return "Runtime status could not be verified from the service response.";
    case "authentication_required":
    case "request_not_allowed":
      return "The protected runtime request could not continue.";
  }
}

function isSelectedSnapshot(
  snapshot: RuntimeSnapshot,
): snapshot is Extract<
  RuntimeSnapshot,
  { runtime: RuntimeEvidence; compatibility: RuntimeCompatibility }
> {
  return (
    snapshot.state === "supported" ||
    snapshot.state === "unverified" ||
    snapshot.state === "incompatible"
  );
}

export function useRuntimeController(client: RuntimeClient): RuntimeController {
  const { endSession, rejectRequest } = useAuthenticatedSession();
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot | null>(null);
  const [candidate, setCandidate] = useState<RuntimeCandidate | null>(null);
  const [phase, setPhase] = useState<RuntimePhase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [path, setPathValue] = useState("");
  const [pathError, setPathError] = useState<string | null>(null);
  const [requestRevision, setRequestRevision] = useState(0);
  const requestVersion = useRef(0);

  const handleProtectedError = useCallback(
    (requestError: unknown): boolean => {
      if (!(requestError instanceof RuntimeRequestError)) {
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
    const version = ++requestVersion.current;
    setPhase("loading");
    setError(null);
    setCandidate(null);
    setSnapshot(null);
    try {
      const next = await client.getRuntime();
      if (requestVersion.current !== version) {
        return;
      }
      setRequestRevision(version);
      setSnapshot(next);
      if (isSelectedSnapshot(next)) {
        setPathValue(next.runtime.canonicalPath);
      } else if (next.state !== "unselected") {
        setPathValue(next.path);
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
    } finally {
      if (requestVersion.current === version) {
        setPhase("idle");
      }
    }
  }, [client, handleProtectedError]);

  useEffect(() => {
    const version = ++requestVersion.current;
    async function load() {
      try {
        const next = await client.getRuntime();
        if (requestVersion.current !== version) {
          return;
        }
        setRequestRevision(version);
        setSnapshot(next);
        if (isSelectedSnapshot(next)) {
          setPathValue(next.runtime.canonicalPath);
        } else if (next.state !== "unselected") {
          setPathValue(next.path);
        }
      } catch (requestError) {
        if (
          requestVersion.current !== version ||
          handleProtectedError(requestError)
        ) {
          return;
        }
        setError(safeRequestMessage(requestError));
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
  }, [client, handleProtectedError]);

  function setPath(nextPath: string) {
    setPathValue(nextPath);
    setPathError(null);
    setCandidate(null);
    setError(null);
  }

  async function inspect() {
    const validationError = runtimePathError(path);
    if (validationError) {
      setPathError(validationError);
      return;
    }
    const version = ++requestVersion.current;
    setPathError(null);
    setError(null);
    setCandidate(null);
    setPhase("probing");
    try {
      const next = await client.inspectCandidate(path);
      if (requestVersion.current === version) {
        setCandidate(next);
        if (next.state === "review_required") {
          setPathValue(next.candidate.canonicalPath);
        }
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
    } finally {
      if (requestVersion.current === version) {
        setPhase("idle");
      }
    }
  }

  async function adopt() {
    if (
      candidate?.state !== "review_required" ||
      candidate.compatibility.state !== "supported" ||
      !candidate.compatibility.manifestId ||
      !candidate.reviewedEvidenceSha256
    ) {
      return;
    }
    const version = ++requestVersion.current;
    setError(null);
    setPhase("adopting");
    try {
      const next = await client.adoptCandidate(
        candidate.candidate,
        candidate.compatibility.manifestId,
        candidate.reviewedEvidenceSha256,
      );
      if (requestVersion.current === version) {
        setRequestRevision(version);
        setSnapshot(next);
        setCandidate(null);
        if (isSelectedSnapshot(next)) {
          setPathValue(next.runtime.canonicalPath);
        }
      }
    } catch (requestError) {
      if (
        requestVersion.current !== version ||
        handleProtectedError(requestError)
      ) {
        return;
      }
      setSnapshot(null);
      setCandidate(null);
      setError(safeRequestMessage(requestError));
    } finally {
      if (requestVersion.current === version) {
        setPhase("idle");
      }
    }
  }

  return {
    adopt,
    candidate,
    error,
    inspect,
    path,
    pathError,
    phase,
    requestRevision,
    refresh,
    setPath,
    snapshot,
  };
}

function compatibilityPresentation(state: RuntimeCompatibility["state"]): {
  label: string;
  tone: StatusTone;
} {
  switch (state) {
    case "supported":
      return { label: "Exact manifest supported", tone: "success" };
    case "unverified":
      return { label: "Support not verified", tone: "warning" };
    case "incompatible":
      return { label: "Incompatible runtime", tone: "unsupported" };
  }
}

function diagnosticCopy(
  state: RuntimeDiagnosticState,
  code: RuntimeDiagnosticCode,
): string {
  if (state === "missing") {
    return "No file is available at the selected host path. Nothing was adopted or run.";
  }
  if (state === "changed") {
    return "The selected file no longer matches its reviewed identity. Managed operations stay blocked until the new evidence is reviewed.";
  }
  if (state === "malformed_output") {
    if (code === "probe_output_limit") {
      return "The identity probe exceeded its bounded output limit and was stopped. No certificate operation was attempted.";
    }
    if (
      code === "probe_failed" ||
      code === "probe_canceled" ||
      code === "inspection_canceled"
    ) {
      return "The bounded identity probe did not complete successfully. No certificate operation was attempted.";
    }
    if (code === "build_identity_mismatch") {
      return "The reported lego identity conflicts with the executable's build metadata, so AcmeMux cannot establish trust.";
    }
    return "The bounded identity probe did not return a recognized lego release or source identity. No certificate operation was attempted.";
  }
  if (state === "timed_out") {
    return "The bounded runtime inspection exceeded its deadline and was stopped. No certificate operation was attempted.";
  }
  switch (code) {
    case "symlink_not_allowed":
      return "The selected path is a symlink or crosses one. AcmeMux accepts only a direct, canonical executable path.";
    case "path_required":
    case "path_not_absolute":
    case "path_not_canonical":
    case "path_too_long":
      return "The selected path is not an accepted canonical absolute host path. Nothing was adopted or run.";
    case "not_regular":
      return "The selected path is not a regular file and cannot be used as the managed runtime.";
    case "not_executable":
      return "The selected regular file is not executable by the AcmeMux service identity.";
    case "unsafe_permissions":
      return "The executable can be modified by an untrusted identity. Its fingerprint cannot establish a safe runtime boundary.";
    case "untrusted_owner":
      return "The executable is owned by an identity outside the accepted service or root ownership boundary.";
    case "unsafe_capabilities":
      return "The executable has Linux file capabilities outside the single reviewed cap_net_bind_service allowance.";
    case "executable_not_qualified":
      return "The executable bytes are not an independently qualified artifact. AcmeMux did not run the candidate.";
    case "empty_executable":
      return "The selected executable is empty and cannot provide a trusted lego identity.";
    case "executable_too_large":
      return "The selected file exceeds the bounded executable size accepted for fingerprinting.";
    case "unsupported_platform":
      return "The executable reports a platform outside the native Linux runtime policy.";
    case "platform_mismatch":
      return "The executable's reported platform does not match this AcmeMux host.";
    case "fingerprint_failed":
    case "changed_during_inspection":
      return "AcmeMux could not obtain one stable fingerprint for the selected executable, so it was not adopted.";
    default:
      return "The selected executable failed the ownership, permission, file-type, or path-safety audit.";
  }
}

function RuntimeEvidenceView({
  evidence,
  compatibility,
  label,
}: {
  evidence: RuntimeEvidence;
  compatibility?: RuntimeCompatibility;
  label: string;
}) {
  return (
    <div className="am-runtime-evidence">
      <h3>{label}</h3>
      <dl>
        <div className="am-runtime-evidence__wide">
          <dt>Canonical host path</dt>
          <dd>{evidence.canonicalPath}</dd>
        </div>
        <div>
          <dt>Release version</dt>
          <dd>{evidence.version ?? "Not reported"}</dd>
        </div>
        <div>
          <dt>Source commit</dt>
          <dd>{evidence.commit ?? "Not reported"}</dd>
        </div>
        <div className="am-runtime-evidence__wide">
          <dt>Exact version output</dt>
          <dd>{evidence.versionOutput}</dd>
        </div>
        <div>
          <dt>Platform</dt>
          <dd>
            {evidence.platform.os} / {evidence.platform.architecture}
          </dd>
        </div>
        <div>
          <dt>Owner</dt>
          <dd>
            uid {evidence.metadata.uid} / gid {evidence.metadata.gid}
          </dd>
        </div>
        <div>
          <dt>Mode</dt>
          <dd>{evidence.metadata.mode}</dd>
        </div>
        <div>
          <dt>File capabilities</dt>
          <dd>{evidence.metadata.capabilities}</dd>
        </div>
        <div>
          <dt>Size</dt>
          <dd>{evidence.metadata.sizeBytes.toLocaleString("en-US")} bytes</dd>
        </div>
        <div>
          <dt>Modified</dt>
          <dd>{evidence.metadata.modifiedAt}</dd>
        </div>
        <div>
          <dt>Metadata changed</dt>
          <dd>{evidence.metadata.changedAt}</dd>
        </div>
        <div>
          <dt>Device / inode</dt>
          <dd>
            {evidence.metadata.device} / {evidence.metadata.inode}
          </dd>
        </div>
        {compatibility?.manifestId ? (
          <div>
            <dt>Compatibility manifest</dt>
            <dd>{compatibility.manifestId}</dd>
          </div>
        ) : null}
        {compatibility ? (
          <div>
            <dt>Compatibility result</dt>
            <dd>{compatibility.code}</dd>
          </div>
        ) : null}
        <div>
          <dt>Go toolchain</dt>
          <dd>{evidence.build.goVersion}</dd>
        </div>
        <div>
          <dt>Build evidence</dt>
          <dd>
            {evidence.build.available && evidence.build.provenanceComplete
              ? "Available / complete"
              : "Incomplete"}
          </dd>
        </div>
        <div>
          <dt>Embedded build platform</dt>
          <dd>
            {evidence.build.goos} / {evidence.build.goarch}
          </dd>
        </div>
        <div>
          <dt>Module version</dt>
          <dd>{evidence.build.mainVersion}</dd>
        </div>
        <div className="am-runtime-evidence__wide">
          <dt>Command package</dt>
          <dd>{evidence.build.commandPath}</dd>
        </div>
        <div className="am-runtime-evidence__wide">
          <dt>Main module</dt>
          <dd>{evidence.build.mainPath}</dd>
        </div>
        <div className="am-runtime-evidence__wide">
          <dt>Dependency graph SHA-256</dt>
          <dd className="am-runtime-digest">
            {evidence.build.dependencyGraphSha256}
          </dd>
        </div>
        <div className="am-runtime-evidence__wide">
          <dt>Build source revision</dt>
          <dd className="am-runtime-digest">{evidence.build.vcsRevision}</dd>
        </div>
        <div>
          <dt>Build source state</dt>
          <dd>
            {evidence.build.vcsModifiedKnown &&
            evidence.build.vcsModifiedValid &&
            !evidence.build.vcsModified
              ? "Known / valid / clean"
              : "Incomplete or modified"}
          </dd>
        </div>
        <div className="am-runtime-evidence__wide">
          <dt>SHA-256</dt>
          <dd className="am-runtime-digest">{evidence.sha256}</dd>
        </div>
      </dl>
    </div>
  );
}

function SelectedRuntime({
  snapshot,
  trustBlocked,
}: {
  snapshot: RuntimeSnapshot;
  trustBlocked: boolean;
}) {
  if (snapshot.state === "unselected") {
    return (
      <FeedbackPanel tone="warning" title="No runtime selected">
        <p>
          Enter one absolute path to an administrator-provisioned lego
          executable on this host. Managed operations remain unavailable.
        </p>
      </FeedbackPanel>
    );
  }
  if (isSelectedSnapshot(snapshot)) {
    const presentation = compatibilityPresentation(
      snapshot.compatibility.state,
    );
    const recheckRequired = trustBlocked && snapshot.state === "supported";
    return (
      <div className="am-runtime-current">
        <FeedbackPanel
          announcement={recheckRequired ? "assertive" : "off"}
          tone={recheckRequired ? "warning" : presentation.tone}
          title={
            recheckRequired ? "Runtime recheck required" : presentation.label
          }
        >
          <p>
            {recheckRequired
              ? "Workspace verification could not prepare the selected runtime. Its evidence is now previously reviewed, and managed operations remain blocked until the runtime is checked again."
              : snapshot.compatibility.summary}
          </p>
          {snapshot.state !== "supported" && !recheckRequired ? (
            <p>
              Managed operations remain blocked until an exact supported
              manifest matches.
            </p>
          ) : null}
        </FeedbackPanel>
        <details className="am-disclosure">
          <summary>
            {recheckRequired
              ? "Show previously reviewed runtime evidence"
              : "Show reviewed runtime evidence"}
          </summary>
          <RuntimeEvidenceView
            compatibility={snapshot.compatibility}
            evidence={snapshot.runtime}
            label={
              recheckRequired
                ? "Previously reviewed executable identity"
                : "Selected executable identity"
            }
          />
        </details>
      </div>
    );
  }
  return (
    <div className="am-runtime-current">
      <FeedbackPanel
        announcement="assertive"
        tone={snapshot.state === "changed" ? "danger" : "warning"}
        title={
          snapshot.state === "changed"
            ? "Reviewed executable changed"
            : "Selected runtime is blocked"
        }
      >
        <p>{diagnosticCopy(snapshot.state, snapshot.diagnostic.code)}</p>
        <p className="am-runtime-path">Host path: {snapshot.path}</p>
      </FeedbackPanel>
      {snapshot.runtime ? (
        <details className="am-disclosure">
          <summary>Show previously reviewed runtime evidence</summary>
          <RuntimeEvidenceView
            evidence={snapshot.runtime}
            label="Previously reviewed executable identity"
          />
        </details>
      ) : null}
    </div>
  );
}

function CandidateReview({
  candidate,
  interactionDisabled,
  isAdopting,
  onAdopt,
}: {
  candidate: RuntimeCandidate;
  interactionDisabled: boolean;
  isAdopting: boolean;
  onAdopt: () => Promise<void>;
}) {
  const [reviewed, setReviewed] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, [candidate]);

  if (candidate.state !== "review_required") {
    return (
      <FeedbackPanel
        announcement="polite"
        tone="warning"
        title="Candidate blocked"
      >
        <p>{diagnosticCopy(candidate.state, candidate.diagnostic.code)}</p>
        <p className="am-runtime-path">Host path: {candidate.path}</p>
      </FeedbackPanel>
    );
  }

  const presentation = compatibilityPresentation(candidate.compatibility.state);
  const supported = candidate.compatibility.state === "supported";
  return (
    <section
      className="am-runtime-review"
      aria-labelledby="runtime-review-heading"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">Explicit review</p>
          <h2 id="runtime-review-heading" ref={headingRef} tabIndex={-1}>
            Review executable evidence
          </h2>
        </div>
        <StatusBadge tone={presentation.tone}>{presentation.label}</StatusBadge>
      </div>
      <p className="am-runtime-review__summary">
        {candidate.compatibility.summary}
      </p>
      <RuntimeEvidenceView
        compatibility={candidate.compatibility}
        evidence={candidate.candidate}
        label="Observed candidate"
      />
      {supported ? (
        <label className="am-runtime-confirmation">
          <input
            checked={reviewed}
            disabled={isAdopting || interactionDisabled}
            onChange={(event) => setReviewed(event.currentTarget.checked)}
            type="checkbox"
          />
          <span>
            I reviewed the canonical path, exact version output, release or
            commit, platform, ownership, mode, file capabilities, timestamps,
            binary and dependency digests, build provenance, and exact
            compatibility manifest.
          </span>
        </label>
      ) : (
        <FeedbackPanel tone={presentation.tone} title="Adoption blocked">
          <p>
            This evidence is available for diagnosis, but only an executable
            matched by an exact supported manifest can be adopted.
          </p>
        </FeedbackPanel>
      )}
      <div className="am-runtime-actions">
        <ActionButton
          isDisabled={
            !supported || !reviewed || isAdopting || interactionDisabled
          }
          isPending={isAdopting}
          onPress={() => void onAdopt()}
        >
          {isAdopting
            ? "Adopting reviewed executable"
            : supported
              ? "Adopt reviewed executable"
              : "Adoption blocked"}
        </ActionButton>
      </div>
    </section>
  );
}

export function runtimeSignal(controller: RuntimeController): string {
  if (controller.phase === "loading") {
    return "Checking";
  }
  if (controller.phase === "probing") {
    return "Inspecting";
  }
  if (controller.phase === "adopting") {
    return "Adopting";
  }
  if (controller.candidate?.state === "review_required") {
    return controller.candidate.compatibility.state === "supported"
      ? "Review required"
      : "Candidate blocked";
  }
  if (controller.candidate) {
    return "Candidate blocked";
  }
  if (controller.error) {
    return "Unavailable";
  }
  switch (controller.snapshot?.state) {
    case "supported":
      return "Supported";
    case "unverified":
      return "Unverified";
    case "incompatible":
      return "Incompatible";
    case "changed":
      return "Changed";
    case "missing":
      return "Missing";
    case "unsafe":
      return "Unsafe";
    case "malformed_output":
      return "Probe blocked";
    case "timed_out":
      return "Probe timed out";
    case "unselected":
    case undefined:
      return "Not connected";
  }
}

export function RuntimePanel({
  controller,
  externallyBusy = false,
  trustBlocked = false,
}: {
  controller: RuntimeController;
  externallyBusy?: boolean;
  trustBlocked?: boolean;
}) {
  const busy = controller.phase !== "idle" || externallyBusy;
  const inspectionDisabled =
    busy || (Boolean(controller.error) && !controller.snapshot);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void controller.inspect();
  }

  return (
    <section className="am-runtime" aria-labelledby="runtime-heading">
      <div className="am-runtime__heading">
        <div>
          <p className="am-kicker">Runtime trust boundary</p>
          <h2 id="runtime-heading">Connect an upstream lego executable</h2>
          <p>
            AcmeMux audits and fingerprints one explicit host path before it can
            be adopted. Exact compatibility evidence, not a broad version range,
            determines support.
          </p>
        </div>
        <StatusBadge
          tone={
            !trustBlocked &&
            !controller.error &&
            controller.snapshot?.state === "supported"
              ? "success"
              : "warning"
          }
        >
          {trustBlocked ? "Recheck required" : runtimeSignal(controller)}
        </StatusBadge>
      </div>

      {controller.phase === "loading" && !controller.snapshot ? (
        <div
          className="am-runtime-progress"
          aria-busy="true"
          aria-live="polite"
        >
          <span className="am-spinner" aria-hidden="true" />
          <p>Checking selected executable status</p>
        </div>
      ) : null}

      {controller.error ? (
        <FeedbackPanel
          announcement="assertive"
          tone="interrupted"
          title="Runtime unavailable"
        >
          <p>{controller.error}</p>
          <ActionButton
            isDisabled={externallyBusy}
            onPress={() => void controller.refresh()}
            variant="secondary"
          >
            Check runtime again
          </ActionButton>
        </FeedbackPanel>
      ) : null}

      {controller.snapshot && !controller.candidate ? (
        <SelectedRuntime
          snapshot={controller.snapshot}
          trustBlocked={trustBlocked}
        />
      ) : null}

      {controller.phase === "probing" ? (
        <FeedbackPanel
          announcement="polite"
          tone="info"
          title="Inspecting executable"
        >
          <p>
            AcmeMux is auditing the selected path, running only the bounded
            identity probe, and computing its SHA-256 fingerprint.
          </p>
        </FeedbackPanel>
      ) : null}

      {controller.candidate ? (
        <CandidateReview
          key={
            controller.candidate.state === "review_required"
              ? (controller.candidate.reviewedEvidenceSha256 ??
                controller.candidate.candidate.sha256)
              : `${controller.candidate.state}:${controller.candidate.path}`
          }
          candidate={controller.candidate}
          interactionDisabled={externallyBusy}
          isAdopting={controller.phase === "adopting"}
          onAdopt={controller.adopt}
        />
      ) : null}

      <form className="am-runtime-form" onSubmit={submit} aria-busy={busy}>
        <div
          className="am-field"
          data-invalid={controller.pathError ? true : undefined}
        >
          <label htmlFor="runtime-path">Host executable path</label>
          <input
            aria-describedby={
              controller.pathError
                ? "runtime-path-description runtime-path-error"
                : "runtime-path-description"
            }
            aria-invalid={controller.pathError ? true : undefined}
            autoCapitalize="none"
            autoComplete="off"
            disabled={inspectionDisabled}
            id="runtime-path"
            maxLength={MAX_RUNTIME_PATH_LENGTH}
            name="runtimePath"
            onChange={(event) => controller.setPath(event.currentTarget.value)}
            placeholder="/absolute/path/to/lego"
            required
            spellCheck={false}
            type="text"
            value={controller.path}
          />
          <span id="runtime-path-description" slot="description">
            Enter an absolute path visible to the AcmeMux service identity.
            AcmeMux does not expose a server filesystem browser.
          </span>
          {controller.pathError ? (
            <span id="runtime-path-error" role="alert">
              {controller.pathError}
            </span>
          ) : null}
        </div>
        <ActionButton
          isDisabled={inspectionDisabled}
          isPending={controller.phase === "probing"}
          type="submit"
          variant="secondary"
        >
          {controller.phase === "probing"
            ? "Inspecting executable"
            : "Inspect executable"}
        </ActionButton>
      </form>

      <p className="am-runtime-boundary">
        Inspection does not browse the host, register an account, issue or renew
        a certificate, contact a provider, download software, or upgrade lego. A
        supported runtime proves only this exact executable identity; provider
        support is established separately.
      </p>
    </section>
  );
}
