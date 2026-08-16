import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import {
  MAX_WORKSPACE_PATH_LENGTH,
  WorkspaceRequestError,
  workspacePathError,
  type CertificateInventoryItem,
  type WorkspaceCandidate,
  type WorkspaceClient,
  type WorkspaceConfigurationSource,
  type WorkspaceDiagnostic,
  type WorkspaceDiagnosticCode,
  type WorkspaceEvidence,
  type WorkspacePathEvidence,
  type WorkspaceSnapshot,
} from "../api/workspace";
import { useAuthenticatedSession } from "../auth/AuthBoundary";
import { ActionButton } from "../components/ActionButton";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { StatusBadge, type StatusTone } from "../components/StatusBadge";

type WorkspacePhase = "loading" | "idle" | "inspecting" | "adopting";

export type WorkspaceController = {
  candidate: WorkspaceCandidate | null;
  configurationPath: string;
  configurationPathError: string | null;
  error: string | null;
  phase: WorkspacePhase;
  readyFocusRequested: boolean;
  requestRevision: number;
  runtimeRecheckRequired: boolean;
  snapshot: WorkspaceSnapshot | null;
  staleInventory?: InventoryObservation | null;
  workingDirectory: string;
  workingDirectoryError: string | null;
  adopt(): Promise<void>;
  consumeReadyFocus(): void;
  inspect(): Promise<void>;
  refresh(): Promise<void>;
  setConfigurationPath(path: string): void;
  setWorkingDirectory(path: string): void;
};

export type InventoryObservation = {
  inventory: CertificateInventoryItem[];
  observedAt: string;
};

function safeRequestMessage(error: unknown): string {
  if (!(error instanceof WorkspaceRequestError)) {
    return "Workspace status is unavailable. No native artifacts were changed.";
  }
  switch (error.code) {
    case "workspace_changed":
      return "The workspace changed after review. Inspect every path again before adoption.";
    case "recovery_required":
      return "Native configuration recovery is required. Reconcile the interrupted edit before inspecting or adopting workspace paths.";
    case "service_busy":
      return "Another bounded workspace inspection is already running. Try again after it finishes.";
    case "invalid_request":
      return "AcmeMux rejected the workspace request. Review the host paths and try again.";
    case "service_unavailable":
    case "network_failure":
      return "Workspace status is unavailable. No native artifacts were changed.";
    case "invalid_response":
      return "Workspace status could not be verified from the service response.";
    case "authentication_required":
    case "request_not_allowed":
      return "The protected workspace request could not continue.";
  }
}

function snapshotEvidence(
  snapshot: WorkspaceSnapshot,
): WorkspaceEvidence | undefined {
  if (snapshot.state === "unadopted") {
    return undefined;
  }
  return snapshot.workspace;
}

function selectionFromEvidence(evidence: WorkspaceEvidence): {
  workingDirectory: string;
  configurationPath: string;
} {
  return {
    workingDirectory: evidence.workingDirectory.configuredPath ?? "",
    configurationPath:
      evidence.configuration.source === "explicit"
        ? (evidence.configuration.path.configuredPath ?? "")
        : "",
  };
}

export function useWorkspaceController(
  client: WorkspaceClient,
  activationKey: string | null = "standalone",
  mutationsEnabled = activationKey !== null,
  interactionsEnabled = activationKey !== null,
): WorkspaceController {
  const { endSession, rejectRequest } = useAuthenticatedSession();
  const [snapshot, setSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [staleInventory, setStaleInventory] =
    useState<InventoryObservation | null>(null);
  const [candidate, setCandidate] = useState<WorkspaceCandidate | null>(null);
  const [phase, setPhase] = useState<WorkspacePhase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [readyFocusRequested, setReadyFocusRequested] = useState(false);
  const [requestRevision, setRequestRevision] = useState(0);
  const [workingDirectory, setWorkingDirectoryValue] = useState("");
  const [configurationPath, setConfigurationPathValue] = useState("");
  const [workingDirectoryError, setWorkingDirectoryError] = useState<
    string | null
  >(null);
  const [configurationPathError, setConfigurationPathError] = useState<
    string | null
  >(null);
  const [loadedActivationKey, setLoadedActivationKey] = useState<string | null>(
    null,
  );
  const [runtimeBlockedActivationKey, setRuntimeBlockedActivationKey] =
    useState<string | null>(null);
  const requestVersion = useRef(0);
  const refreshActive = useRef(false);

  const consumeReadyFocus = useCallback(() => {
    setReadyFocusRequested(false);
  }, []);

  const handleProtectedError = useCallback(
    (requestError: unknown): boolean => {
      if (!(requestError instanceof WorkspaceRequestError)) {
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

  const applySnapshot = useCallback(
    (next: WorkspaceSnapshot) => {
      setSnapshot(next);
      if (
        next.state === "ready" &&
        typeof next.inventoryObservedAt === "string"
      ) {
        setStaleInventory({
          inventory: next.inventory,
          observedAt: next.inventoryObservedAt,
        });
      } else if (next.state === "unadopted") {
        setStaleInventory(null);
      }
      if (activationKey !== null) {
        setRuntimeBlockedActivationKey(
          next.state === "incompatible" ? activationKey : null,
        );
      }
      const evidence = snapshotEvidence(next);
      if (evidence) {
        const selection = selectionFromEvidence(evidence);
        setWorkingDirectoryValue(selection.workingDirectory);
        setConfigurationPathValue(selection.configurationPath);
      }
    },
    [activationKey],
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
    setCandidate(null);
    setReadyFocusRequested(false);
    try {
      const next = await client.getWorkspace();
      if (requestVersion.current === version) {
        applySnapshot(next);
        setRequestRevision(version);
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
      refreshActive.current = false;
      if (requestVersion.current === version) {
        setPhase("idle");
      }
    }
  }, [
    activationKey,
    applySnapshot,
    client,
    handleProtectedError,
    interactionsEnabled,
  ]);

  useEffect(() => {
    if (activationKey === null) {
      requestVersion.current += 1;
      return;
    }
    const version = ++requestVersion.current;
    async function load() {
      try {
        const next = await client.getWorkspace();
        if (requestVersion.current === version) {
          applySnapshot(next);
          setRequestRevision(version);
          setCandidate(null);
          setError(null);
          setReadyFocusRequested(false);
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
        setCandidate(null);
        setReadyFocusRequested(false);
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
  }, [activationKey, applySnapshot, client, handleProtectedError]);

  function clearReview() {
    setCandidate(null);
    setError(null);
    setReadyFocusRequested(false);
  }

  function setWorkingDirectory(path: string) {
    setWorkingDirectoryValue(path);
    setWorkingDirectoryError(null);
    clearReview();
  }

  function setConfigurationPath(path: string) {
    setConfigurationPathValue(path);
    setConfigurationPathError(null);
    clearReview();
  }

  async function inspect() {
    if (
      activationKey === null ||
      !interactionsEnabled ||
      !mutationsEnabled ||
      snapshot?.state === "incompatible"
    ) {
      return;
    }
    const nextWorkingDirectoryError = workspacePathError(
      workingDirectory,
      "working directory",
    );
    const nextConfigurationPathError = workspacePathError(
      configurationPath,
      "configuration path",
      true,
    );
    setWorkingDirectoryError(nextWorkingDirectoryError ?? null);
    setConfigurationPathError(nextConfigurationPathError ?? null);
    if (nextWorkingDirectoryError || nextConfigurationPathError) {
      return;
    }

    const version = ++requestVersion.current;
    setError(null);
    setCandidate(null);
    setReadyFocusRequested(false);
    setPhase("inspecting");
    try {
      const next = await client.inspectCandidate(
        workingDirectory,
        configurationPath || null,
      );
      if (requestVersion.current === version) {
        setCandidate(next);
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
      activationKey === null ||
      !interactionsEnabled ||
      !mutationsEnabled ||
      snapshot?.state === "incompatible" ||
      !candidate?.adoptable
    ) {
      return;
    }
    const version = ++requestVersion.current;
    setError(null);
    setPhase("adopting");
    try {
      const next = await client.adoptCandidate(
        workingDirectory,
        configurationPath || null,
        candidate.reviewedEvidenceSha256,
      );
      if (requestVersion.current === version) {
        if (next.state === "review_required") {
          setCandidate(next);
          setReadyFocusRequested(false);
        } else {
          applySnapshot(next);
          setRequestRevision(version);
          setCandidate(null);
          setReadyFocusRequested(next.state === "ready");
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

  const active =
    activationKey !== null && loadedActivationKey === activationKey;

  return {
    adopt,
    candidate: active ? candidate : null,
    configurationPath,
    configurationPathError,
    consumeReadyFocus,
    error: active ? error : null,
    inspect,
    phase: activationKey === null ? "idle" : active ? phase : "loading",
    readyFocusRequested: active && readyFocusRequested,
    requestRevision,
    refresh,
    runtimeRecheckRequired:
      active && runtimeBlockedActivationKey === activationKey,
    setConfigurationPath,
    setWorkingDirectory,
    snapshot: active && phase !== "loading" ? snapshot : null,
    staleInventory: active ? staleInventory : null,
    workingDirectory,
    workingDirectoryError,
  };
}

function sourceLabel(source: WorkspaceConfigurationSource): string {
  switch (source) {
    case "conventional_lego_yml":
      return "Conventional .lego.yml";
    case "conventional_lego_yaml":
      return "Conventional .lego.yaml";
    case "explicit":
      return "Explicit configuration path";
  }
}

function pathStatusLabel(path: WorkspacePathEvidence): string {
  if (path.safe) {
    return "Requirements satisfied";
  }
  switch (path.status) {
    case "available":
      return "Requirements not satisfied";
    case "missing":
      return "Missing";
    case "inaccessible":
      return "Inaccessible";
    case "unsafe":
      return "Unsafe";
    case "unresolved":
      return "Not resolved";
  }
}

function pathStatusTone(path: WorkspacePathEvidence): StatusTone {
  if (path.safe) {
    return "success";
  }
  return path.status === "unsafe" ? "danger" : "warning";
}

function accessSummary(access: {
  readable: boolean;
  writable: boolean;
  searchable: boolean;
}): string {
  const granted = [
    access.readable ? "read" : null,
    access.writable ? "write" : null,
    access.searchable ? "search" : null,
  ].filter((value): value is string => value !== null);
  return granted.length > 0 ? granted.join(" / ") : "none";
}

function PathEvidenceView({
  evidence,
  label,
}: {
  evidence: WorkspacePathEvidence;
  label: string;
}) {
  const [componentsOpen, setComponentsOpen] = useState(false);

  return (
    <article className="am-workspace-path">
      <header>
        <h4>{label}</h4>
        <StatusBadge tone={pathStatusTone(evidence)}>
          {pathStatusLabel(evidence)}
        </StatusBadge>
      </header>
      <dl>
        <div className="am-workspace-path__wide">
          <dt>Configured path</dt>
          <dd>{evidence.configuredPath ?? "Not resolved"}</dd>
        </div>
        <div className="am-workspace-path__wide">
          <dt>Canonical path</dt>
          <dd>{evidence.canonicalPath ?? "Not resolved"}</dd>
        </div>
        <div>
          <dt>Access</dt>
          <dd>{accessSummary(evidence.access)}</dd>
        </div>
        <div>
          <dt>File type</dt>
          <dd>{evidence.type.replace("_", " ")}</dd>
        </div>
        <div>
          <dt>Owner</dt>
          <dd>
            {evidence.metadata
              ? `uid ${evidence.metadata.uid} / gid ${evidence.metadata.gid}`
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>Mode / links</dt>
          <dd>
            {evidence.metadata
              ? `${evidence.metadata.mode} / ${evidence.metadata.nlink}`
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>Size</dt>
          <dd>
            {evidence.metadata
              ? `${evidence.metadata.sizeBytes.toLocaleString("en-US")} bytes`
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>Device / inode</dt>
          <dd>
            {evidence.metadata
              ? `${evidence.metadata.device} / ${evidence.metadata.inode}`
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>Modified</dt>
          <dd>{evidence.metadata?.modifiedAt ?? "Unavailable"}</dd>
        </div>
        <div>
          <dt>Metadata changed</dt>
          <dd>{evidence.metadata?.changedAt ?? "Unavailable"}</dd>
        </div>
      </dl>
      {evidence.components.length > 0 ? (
        <details
          className="am-workspace-components"
          onToggle={(event) => setComponentsOpen(event.currentTarget.open)}
          open={componentsOpen}
        >
          <summary>
            Show {evidence.components.length.toLocaleString("en-US")} traversed
            path {evidence.components.length === 1 ? "component" : "components"}
          </summary>
          {componentsOpen ? (
            <ol>
              {evidence.components.map((component) => (
                <li key={component.path}>
                  <div className="am-workspace-components__path">
                    <code>{component.path}</code>
                    <span>{component.type.replace("_", " ")}</span>
                  </div>
                  <dl>
                    <div>
                      <dt>Owner</dt>
                      <dd>
                        uid {component.uid} / gid {component.gid}
                      </dd>
                    </div>
                    <div>
                      <dt>Mode</dt>
                      <dd>{component.mode}</dd>
                    </div>
                    <div>
                      <dt>Device / inode</dt>
                      <dd>
                        {component.device} / {component.inode}
                      </dd>
                    </div>
                    <div>
                      <dt>Effective access</dt>
                      <dd>{accessSummary(component.access)}</dd>
                    </div>
                  </dl>
                </li>
              ))}
            </ol>
          ) : null}
        </details>
      ) : (
        <p className="am-workspace-components__empty">
          {evidence.status === "unresolved"
            ? "No path component evidence exists because this reference could not be resolved."
            : "No traversal component evidence was available for this resolved path audit."}
        </p>
      )}
    </article>
  );
}

function WorkspaceEvidenceView({
  evidence,
  label,
}: {
  evidence: WorkspaceEvidence;
  label: string;
}) {
  return (
    <div className="am-workspace-evidence">
      <div className="am-workspace-evidence__heading">
        <h3>{label}</h3>
        <p>
          Configuration source: {sourceLabel(evidence.configuration.source)}
        </p>
      </div>
      <div className="am-workspace-paths">
        <PathEvidenceView
          evidence={evidence.workingDirectory}
          label="Effective working directory"
        />
        <PathEvidenceView
          evidence={evidence.configuration.path}
          label="Selected native configuration"
        />
        <PathEvidenceView
          evidence={evidence.storage}
          label="Resolved native storage"
        />
        {evidence.dotenv.map((path, index) => (
          <PathEvidenceView
            evidence={path}
            key={`dotenv:${path.configuredPath}:${index}`}
            label={`Referenced dotenv ${String(index + 1).padStart(2, "0")}`}
          />
        ))}
        {evidence.webroots.map((path, index) => (
          <PathEvidenceView
            evidence={path}
            key={`webroot:${path.configuredPath}:${index}`}
            label={`Referenced webroot ${String(index + 1).padStart(2, "0")}`}
          />
        ))}
      </div>
      {evidence.dotenv.length === 0 && evidence.webroots.length === 0 ? (
        <p className="am-workspace-empty-reference">
          This native configuration references no dotenv or webroot paths.
        </p>
      ) : null}
    </div>
  );
}

function diagnosticCopy(code: WorkspaceDiagnosticCode): string {
  switch (code) {
    case "invalid_policy":
      return "Workspace inspection policy is unavailable, so adoption remains blocked.";
    case "context_required":
      return "Workspace inspection could not start without a bounded request context.";
    case "path_required":
      return "A required native path was not supplied.";
    case "path_not_absolute":
    case "path_not_canonical":
      return "A selected host path is not an accepted absolute canonical path.";
    case "path_too_long":
      return "A selected native path exceeds the bounded host path limit.";
    case "path_too_deep":
      return "A selected native path exceeds the bounded traversal depth.";
    case "path_missing":
      return "A required native path does not exist.";
    case "path_unavailable":
      return "A selected native path is unavailable to the service identity.";
    case "symlink_not_allowed":
      return "A managed path is a symlink or traverses one; symlink traversal is not adopted.";
    case "component_not_directory":
      return "A traversed parent component is not a directory.";
    case "path_type_unsafe":
      return "A managed path has a file type that is unsafe for its native role.";
    case "path_owner_untrusted":
      return "A managed path is owned outside the accepted service or root identity boundary.";
    case "path_permissions_unsafe":
      return "A managed path can be modified through permissions outside the accepted identity boundary.";
    case "path_hardlink_unsafe":
      return "A managed file has additional hard links and cannot be adopted safely.";
    case "path_not_readable":
      return "The service identity cannot read a required native path.";
    case "path_read_only":
      return "The service identity can read this workspace but cannot safely manage every required path.";
    case "path_not_searchable":
      return "The service identity cannot search a required native directory.";
    case "configuration_missing":
      return "No conventional native configuration was found in the effective working directory.";
    case "configuration_precedence":
      return "Both conventional names exist. Upstream priority selects .lego.yml and leaves .lego.yaml shadowed.";
    case "configuration_too_large":
      return "The native configuration exceeds the bounded inspection limit.";
    case "configuration_malformed":
      return "The native configuration could not be read far enough to resolve its referenced paths.";
    case "configuration_duplicate_key":
      return "The native configuration contains a duplicate key and cannot be interpreted safely.";
    case "configuration_too_complex":
      return "The native configuration exceeds bounded structural limits.";
    case "configuration_reference_invalid":
      return "A native configuration path reference is invalid or cannot be resolved safely.";
    case "changed_during_inspection":
      return "Native path evidence changed during inspection and must be inspected again.";
    case "inspection_canceled":
      return "The bounded workspace inspection was canceled before evidence was complete.";
    case "review_evidence_limit":
      return "Workspace inspection reached the bounded diagnostic display limit; adoption remains blocked.";
    case "review_evidence_changed":
      return "Native path evidence changed after the last review.";
    case "not_directory":
      return "A native inventory path expected to be a directory has another file type.";
    case "not_regular":
      return "A native certificate artifact expected to be a regular file has another file type.";
    case "untrusted_owner":
      return "A native inventory artifact has an owner outside the accepted identity boundary.";
    case "unsafe_permissions":
      return "A native inventory artifact has permissions outside the accepted identity boundary.";
    case "not_readable":
      return "The service identity cannot read a required native inventory artifact.";
    case "hard_link_not_allowed":
      return "A native inventory artifact has additional hard links and is not trusted.";
    case "artifact_size_invalid":
      return "A native certificate artifact is empty or exceeds the bounded size limit.";
    case "neutral_directory_not_private":
      return "The bounded inventory working directory is not private to the service identity.";
    case "neutral_configuration_present":
      return "The bounded inventory working directory unexpectedly contains lego configuration.";
    case "tree_entry_limit":
      return "The native storage tree exceeds the bounded inventory entry limit.";
    case "tree_depth_limit":
      return "The native storage tree exceeds the bounded inventory depth limit.";
    case "certificate_limit":
      return "The native workspace exceeds the bounded certificate inventory limit.";
    case "runtime_unavailable":
      return "The exact reviewed lego runtime is unavailable or incompatible.";
    case "inventory_busy":
      return "Another bounded native inventory inspection is running. Check this workspace again after it finishes.";
    case "inventory_timeout":
      return "The bounded native inventory request exceeded its deadline.";
    case "inventory_canceled":
      return "The bounded native inventory request was canceled before it completed.";
    case "inventory_output_limit":
      return "Upstream inventory output exceeded its bounded size limit.";
    case "inventory_command_failed":
      return "The bounded upstream inventory command did not complete successfully.";
    case "malformed_inventory_output":
      return "Upstream inventory output was not recognized as safe certificate evidence.";
    case "duplicate_inventory_entry":
      return "Upstream inventory reported the same native certificate more than once.";
    case "certificate_path_outside_storage":
      return "A reported certificate path resolves outside the adopted native storage tree.";
    case "inventory_artifacts_changed":
      return "Native certificate artifacts changed while bounded inventory evidence was collected.";
    case "prepared_executable_close_failed":
      return "The prepared lego runtime could not be closed cleanly after inventory.";
    case "service_busy":
      return "Another bounded workspace inspection is already running.";
  }
}

function DiagnosticsView({
  diagnostics,
  label = "Workspace diagnostics",
}: {
  diagnostics: WorkspaceDiagnostic[];
  label?: string;
}) {
  if (diagnostics.length === 0) {
    return null;
  }
  return (
    <section className="am-workspace-diagnostics" aria-label={label}>
      <h3>{label}</h3>
      <ul>
        {diagnostics.map((diagnostic, index) => (
          <li key={`${diagnostic.code}:${diagnostic.path ?? "none"}:${index}`}>
            <code>{diagnostic.code}</code>
            <span>{diagnosticCopy(diagnostic.code)}</span>
            <small>
              {diagnostic.severity === "blocking" ? "Blocking" : "Notice"} /{" "}
              {diagnostic.role.replace("_", " ")}
            </small>
            {diagnostic.path ? (
              <small>Selected path: {diagnostic.path}</small>
            ) : null}
            {diagnostic.component ? (
              <small>Relevant component: {diagnostic.component}</small>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

function formatUTC(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

function formatLocal(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  }).format(new Date(value));
}

function healthTone(health: CertificateInventoryItem["health"]): StatusTone {
  if (health === "expired") return "danger";
  if (health === "expiring") return "warning";
  return "success";
}

function CertificateCard({
  certificate,
}: {
  certificate: CertificateInventoryItem;
}) {
  return (
    <article className="am-certificate-card">
      <header>
        <div>
          <p className="am-kicker">Native certificate</p>
          <h3>{certificate.name}</h3>
        </div>
        <StatusBadge tone={healthTone(certificate.health)}>
          {certificate.health}
        </StatusBadge>
      </header>
      <dl className="am-certificate-card__summary">
        <div>
          <dt>DNS names</dt>
          <dd>
            {certificate.dnsNames.length > 0
              ? certificate.dnsNames.join(", ")
              : "None reported"}
          </dd>
        </div>
        <div>
          <dt>Issuer</dt>
          <dd>{certificate.issuer}</dd>
        </div>
        <div>
          <dt>Expiration</dt>
          <dd>
            <time dateTime={certificate.expiresAt}>
              {formatLocal(certificate.expiresAt)}
            </time>
            <small>Exact UTC: {formatUTC(certificate.expiresAt)}</small>
          </dd>
        </div>
        <div>
          <dt>Native certificate path</dt>
          <dd>{certificate.artifact.nativePath}</dd>
        </div>
        <div>
          <dt>Owner / mode</dt>
          <dd>
            uid {certificate.artifact.uid} / gid {certificate.artifact.gid} /{" "}
            {certificate.artifact.mode}
          </dd>
        </div>
      </dl>
      <details className="am-disclosure">
        <summary>Show complete native artifact evidence</summary>
        <dl className="am-certificate-card__detail">
          <div>
            <dt>Link count</dt>
            <dd>{certificate.artifact.nlink}</dd>
          </div>
          <div>
            <dt>Size</dt>
            <dd>
              {certificate.artifact.sizeBytes.toLocaleString("en-US")} bytes
            </dd>
          </div>
          <div>
            <dt>Device / inode</dt>
            <dd>
              {certificate.artifact.device} / {certificate.artifact.inode}
            </dd>
          </div>
          <div>
            <dt>Modified</dt>
            <dd>{certificate.artifact.modifiedAt}</dd>
          </div>
          <div>
            <dt>Metadata changed</dt>
            <dd>{certificate.artifact.changedAt}</dd>
          </div>
        </dl>
      </details>
    </article>
  );
}

function InventoryView({
  inventory,
  observedAt,
  stale = false,
}: {
  inventory: CertificateInventoryItem[];
  observedAt: string;
  stale?: boolean;
}) {
  const pageSize = 50;
  const [requestedPage, setRequestedPage] = useState(0);
  const healthOrder = { expired: 0, expiring: 1, healthy: 2 } as const;
  const orderedInventory = [...inventory].sort(
    (left, right) =>
      healthOrder[left.health] - healthOrder[right.health] ||
      Date.parse(left.expiresAt) - Date.parse(right.expiresAt) ||
      left.name.localeCompare(right.name),
  );
  const counts = inventory.reduce(
    (result, certificate) => {
      result[certificate.health] += 1;
      return result;
    },
    { healthy: 0, expiring: 0, expired: 0 },
  );
  const pageCount = Math.max(1, Math.ceil(orderedInventory.length / pageSize));
  const page = Math.min(requestedPage, pageCount - 1);
  const start = page * pageSize;
  const visibleInventory = orderedInventory.slice(start, start + pageSize);
  const end = start + visibleInventory.length;
  return (
    <section
      className="am-inventory"
      aria-labelledby="inventory-heading"
      id="certificate-inventory"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">Native inventory</p>
          <h2 id="inventory-heading">Certificate evidence</h2>
        </div>
        <StatusBadge
          tone={
            stale
              ? "interrupted"
              : counts.expired > 0
                ? "danger"
                : counts.expiring > 0
                  ? "warning"
                  : inventory.length > 0
                    ? "success"
                    : "not-attempted"
          }
        >
          {stale
            ? "Stale evidence"
            : counts.expired > 0
              ? `${counts.expired.toLocaleString("en-US")} expired`
              : counts.expiring > 0
                ? `${counts.expiring.toLocaleString("en-US")} expiring`
                : inventory.length === 1
                  ? "1 healthy certificate"
                  : `${inventory.length.toLocaleString("en-US")} healthy certificates`}
        </StatusBadge>
      </div>
      {stale ? (
        <FeedbackPanel tone="interrupted" title="Inventory is stale">
          <p>
            The current refresh failed. These browser-memory values were last
            observed at {formatUTC(observedAt)} and are not current health.
          </p>
        </FeedbackPanel>
      ) : (
        <p className="am-inventory__observed">
          Health observed from the service host clock at {formatUTC(observedAt)}
          . Local time: {formatLocal(observedAt)}.
        </p>
      )}
      {!stale && inventory.length > 0 ? (
        <dl
          className="am-inventory__health-summary"
          aria-label="Certificate health summary"
        >
          <div>
            <dt>Expired</dt>
            <dd>{counts.expired.toLocaleString("en-US")}</dd>
          </div>
          <div>
            <dt>Expiring within 30 days</dt>
            <dd>{counts.expiring.toLocaleString("en-US")}</dd>
          </div>
          <div>
            <dt>Healthy beyond 30 days</dt>
            <dd>{counts.healthy.toLocaleString("en-US")}</dd>
          </div>
        </dl>
      ) : null}
      {inventory.length === 0 ? (
        <p className="am-inventory__empty">
          The adopted native storage currently reports no certificates.
        </p>
      ) : (
        <>
          <p className="am-inventory__range" aria-live="polite">
            Showing {(start + 1).toLocaleString("en-US")}-
            {end.toLocaleString("en-US")} of{" "}
            {inventory.length.toLocaleString("en-US")} certificates
          </p>
          <div className="am-inventory__list">
            {visibleInventory.map((certificate) => (
              <CertificateCard
                certificate={certificate}
                key={`${certificate.name}:${certificate.artifact.nativePath}`}
              />
            ))}
          </div>
          {pageCount > 1 ? (
            <nav
              aria-label="Certificate inventory pages"
              className="am-inventory__pagination"
            >
              <ActionButton
                isDisabled={page === 0}
                onPress={() => setRequestedPage((current) => current - 1)}
                variant="secondary"
              >
                Previous certificates
              </ActionButton>
              <span>
                Page {(page + 1).toLocaleString("en-US")} of{" "}
                {pageCount.toLocaleString("en-US")}
              </span>
              <ActionButton
                isDisabled={page === pageCount - 1}
                onPress={() => setRequestedPage((current) => current + 1)}
                variant="secondary"
              >
                Next certificates
              </ActionButton>
            </nav>
          ) : null}
        </>
      )}
      <p className="am-inventory__boundary">
        AcmeMux displays bounded upstream inventory and filesystem metadata. It
        does not copy certificate, chain, account, or private-key bytes into
        application state. Health is an attention threshold, not a lego
        renewal-due prediction.
      </p>
    </section>
  );
}

function snapshotPresentation(state: WorkspaceSnapshot["state"]): {
  title: string;
  tone: StatusTone;
  copy: string;
} {
  switch (state) {
    case "unadopted":
      return {
        title: "No workspace adopted",
        tone: "warning",
        copy: "Select an effective working directory and inspect every native path before adoption.",
      };
    case "ready":
      return {
        title: "Native workspace ready",
        tone: "success",
        copy: "Every adopted path still matches its reviewed evidence and native inventory is available.",
      };
    case "changed":
      return {
        title: "Workspace changed",
        tone: "danger",
        copy: "One or more native paths changed after review. Managed access remains blocked pending a new inspection.",
      };
    case "missing":
      return {
        title: "Workspace path missing",
        tone: "warning",
        copy: "An adopted native path is no longer present. AcmeMux did not repair or replace it.",
      };
    case "read_only":
      return {
        title: "Workspace is read only",
        tone: "warning",
        copy: "The service identity cannot safely manage every required native path. Fresh inventory remains hidden until workspace trust is restored.",
      };
    case "unsafe":
      return {
        title: "Workspace safety check failed",
        tone: "danger",
        copy: "A path, type, owner, permission, or link condition is outside the accepted native workspace boundary.",
      };
    case "incompatible":
      return {
        title: "Workspace runtime incompatible",
        tone: "unsupported",
        copy: "This workspace cannot be managed without its exact reviewed compatible lego runtime.",
      };
    case "inventory_unavailable":
      return {
        title: "Certificate inventory unavailable",
        tone: "interrupted",
        copy: "The workspace remains adopted, but bounded native certificate evidence could not be obtained.",
      };
  }
}

function SelectedWorkspace({
  focusReady,
  onRefresh,
  onReadyFocused,
  refreshEnabled,
  runtimeReady,
  snapshot,
  staleInventory,
}: {
  focusReady: boolean;
  onRefresh: () => Promise<void>;
  onReadyFocused: () => void;
  refreshEnabled: boolean;
  runtimeReady: boolean;
  snapshot: WorkspaceSnapshot;
  staleInventory: InventoryObservation | null;
}) {
  const runtimeTrustBlocked = snapshot.state === "ready" && !runtimeReady;
  const presentation = runtimeTrustBlocked
    ? {
        title: "Workspace recheck required",
        tone: "warning" as const,
        copy: "The adopted path evidence was previously reviewed, but it cannot be presented as current while runtime trust requires review.",
      }
    : snapshotPresentation(snapshot.state);
  const readyHeadingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (focusReady && snapshot.state === "ready" && runtimeReady) {
      readyHeadingRef.current?.focus();
      onReadyFocused();
    }
  }, [focusReady, onReadyFocused, runtimeReady, snapshot.state]);

  if (snapshot.state === "unadopted") {
    return (
      <FeedbackPanel tone={presentation.tone} title={presentation.title}>
        <p>{presentation.copy}</p>
      </FeedbackPanel>
    );
  }
  const failedRecheck =
    snapshot.state === "changed" ||
    snapshot.state === "missing" ||
    snapshot.state === "read_only" ||
    snapshot.state === "unsafe";
  const persistedReview = snapshot.state === "incompatible";
  return (
    <div className="am-workspace-current">
      <FeedbackPanel
        announcement={
          snapshot.state === "ready" && runtimeReady ? "polite" : "assertive"
        }
        headingRef={
          snapshot.state === "ready" && runtimeReady
            ? readyHeadingRef
            : undefined
        }
        headingTabIndex={
          snapshot.state === "ready" && runtimeReady ? -1 : undefined
        }
        tone={presentation.tone}
        title={presentation.title}
      >
        <p>{presentation.copy}</p>
        <ActionButton
          isDisabled={!refreshEnabled}
          onPress={() => void onRefresh()}
          variant="secondary"
        >
          Check workspace again
        </ActionButton>
      </FeedbackPanel>
      <DiagnosticsView diagnostics={snapshot.diagnostics} />
      <details className="am-disclosure">
        <summary>
          {runtimeTrustBlocked
            ? "Show previously reviewed workspace evidence"
            : failedRecheck
              ? "Show current failed workspace recheck evidence"
              : persistedReview
                ? "Show previously reviewed workspace evidence"
                : "Show current reviewed workspace evidence"}
        </summary>
        <WorkspaceEvidenceView
          evidence={snapshot.workspace}
          label={
            runtimeTrustBlocked
              ? "Previously reviewed native paths requiring runtime recheck"
              : failedRecheck
                ? "Current failed native path evidence"
                : persistedReview
                  ? "Persisted previously reviewed native paths"
                  : "Current reviewed and verified native paths"
          }
        />
      </details>
      {snapshot.state === "ready" && runtimeReady ? (
        <InventoryView
          inventory={snapshot.inventory}
          observedAt={snapshot.inventoryObservedAt ?? "1970-01-01T00:00:00Z"}
        />
      ) : snapshot.state === "inventory_unavailable" && staleInventory ? (
        <InventoryView
          inventory={staleInventory.inventory}
          observedAt={staleInventory.observedAt}
          stale
        />
      ) : null}
    </div>
  );
}

function CandidateReview({
  candidate,
  interactionsEnabled,
  isAdopting,
  onAdopt,
  runtimeReady,
}: {
  candidate: WorkspaceCandidate;
  interactionsEnabled: boolean;
  isAdopting: boolean;
  onAdopt: () => Promise<void>;
  runtimeReady: boolean;
}) {
  const [reviewed, setReviewed] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    headingRef.current?.focus();
  }, [candidate]);

  return (
    <section
      className="am-workspace-review"
      aria-labelledby="workspace-review-heading"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">Explicit path review</p>
          <h2 id="workspace-review-heading" ref={headingRef} tabIndex={-1}>
            Review native workspace evidence
          </h2>
        </div>
        <StatusBadge
          tone={candidate.adoptable && runtimeReady ? "success" : "warning"}
        >
          {!runtimeReady
            ? "Compatible runtime required"
            : candidate.adoptable
              ? "Ready for confirmation"
              : "Adoption blocked"}
        </StatusBadge>
      </div>
      <p className="am-workspace-review__summary">
        Review the effective working directory, selected configuration source,
        resolved storage, and every referenced dotenv and webroot path. AcmeMux
        will persist pointers and bounded observations, never native contents.
      </p>
      <DiagnosticsView
        diagnostics={candidate.diagnostics}
        label="Candidate diagnostics"
      />
      <WorkspaceEvidenceView
        evidence={candidate.candidate}
        label="Observed native path set"
      />
      {candidate.adoptable ? (
        <label className="am-workspace-confirmation">
          <input
            checked={reviewed}
            disabled={isAdopting || !interactionsEnabled || !runtimeReady}
            onChange={(event) => setReviewed(event.currentTarget.checked)}
            type="checkbox"
          />
          <span>
            I reviewed the effective working directory, configuration source,
            configured and canonical paths, every traversed component and its
            effective access and identity, plus file types, owners, modes, link
            counts, sizes, and timestamps for storage and every referenced
            dotenv and webroot.
          </span>
        </label>
      ) : (
        <FeedbackPanel tone="warning" title="Adoption blocked">
          <p>
            The evidence remains visible for diagnosis. AcmeMux will not repair
            ownership, permissions, path types, links, or native contents.
          </p>
        </FeedbackPanel>
      )}
      <div className="am-workspace-actions">
        <ActionButton
          isDisabled={
            !runtimeReady ||
            !candidate.adoptable ||
            !reviewed ||
            isAdopting ||
            !interactionsEnabled
          }
          isPending={isAdopting}
          onPress={() => void onAdopt()}
        >
          {isAdopting
            ? "Adopting reviewed workspace"
            : candidate.adoptable
              ? "Adopt reviewed workspace"
              : "Adoption blocked"}
        </ActionButton>
      </div>
    </section>
  );
}

export function workspaceSignal(controller: WorkspaceController): string {
  if (controller.phase === "loading") {
    return "Checking";
  }
  if (controller.phase === "inspecting") {
    return "Inspecting";
  }
  if (controller.phase === "adopting") {
    return "Adopting";
  }
  if (controller.candidate) {
    return controller.candidate.adoptable
      ? "Review required"
      : "Candidate blocked";
  }
  if (controller.error) {
    return "Unavailable";
  }
  switch (controller.snapshot?.state) {
    case "ready":
      return "Ready";
    case "changed":
      return "Changed";
    case "missing":
      return "Missing";
    case "read_only":
      return "Read only";
    case "unsafe":
      return "Unsafe";
    case "incompatible":
      return "Incompatible";
    case "inventory_unavailable":
      return "Inventory unavailable";
    case "unadopted":
    case undefined:
      return "Not adopted";
  }
}

export function WorkspacePanel({
  controller,
  interactionsEnabled = true,
  runtimeReady,
}: {
  controller: WorkspaceController;
  interactionsEnabled?: boolean;
  runtimeReady: boolean;
}) {
  const busy = controller.phase !== "idle";
  const inspectionDisabled =
    busy ||
    !interactionsEnabled ||
    !runtimeReady ||
    (Boolean(controller.error) && !controller.snapshot);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void controller.inspect();
  }

  return (
    <section className="am-workspace" aria-labelledby="workspace-heading">
      <div className="am-workspace__heading">
        <div>
          <p className="am-kicker">Native ownership boundary</p>
          <h2 id="workspace-heading">Adopt one authoritative lego workspace</h2>
          <p>
            AcmeMux resolves native paths exactly from an explicit effective
            working directory, audits them as the service identity, and leaves
            all configuration, credentials, account, certificate, and key
            material in place.
          </p>
        </div>
        <StatusBadge
          tone={
            runtimeReady &&
            !controller.error &&
            controller.snapshot?.state === "ready"
              ? "success"
              : "warning"
          }
        >
          {!runtimeReady && controller.snapshot?.state === "ready"
            ? "Recheck required"
            : workspaceSignal(controller)}
        </StatusBadge>
      </div>

      {!runtimeReady ? (
        <FeedbackPanel tone="warning" title="Compatible runtime required">
          <p>
            Adopt an exact supported lego executable before inspecting a native
            workspace. Existing workspace evidence remains read-only while the
            runtime trust boundary is blocked.
          </p>
        </FeedbackPanel>
      ) : null}

      {controller.phase === "loading" && !controller.snapshot ? (
        <div
          className="am-workspace-progress"
          aria-busy="true"
          aria-live="polite"
        >
          <span className="am-spinner" aria-hidden="true" />
          <p>Checking adopted workspace status</p>
        </div>
      ) : null}

      {controller.error ? (
        <FeedbackPanel
          announcement="assertive"
          tone="interrupted"
          title="Workspace unavailable"
        >
          <p>{controller.error}</p>
          <ActionButton
            isDisabled={!interactionsEnabled}
            onPress={() => void controller.refresh()}
            variant="secondary"
          >
            Check workspace again
          </ActionButton>
        </FeedbackPanel>
      ) : null}

      {controller.error && controller.staleInventory ? (
        <InventoryView
          inventory={controller.staleInventory.inventory}
          observedAt={controller.staleInventory.observedAt}
          stale
        />
      ) : null}

      {controller.snapshot && !controller.candidate && !controller.error ? (
        <SelectedWorkspace
          focusReady={controller.readyFocusRequested}
          onRefresh={controller.refresh}
          onReadyFocused={controller.consumeReadyFocus}
          refreshEnabled={
            interactionsEnabled &&
            (runtimeReady || controller.snapshot.state !== "ready")
          }
          runtimeReady={runtimeReady}
          snapshot={controller.snapshot}
          staleInventory={controller.staleInventory ?? null}
        />
      ) : null}

      {controller.phase === "inspecting" ? (
        <FeedbackPanel
          announcement="polite"
          tone="info"
          title="Inspecting native workspace"
        >
          <p>
            AcmeMux is resolving and auditing only the native path set.
            Certificate inventory follows successful adoption; no provider or
            ACME operation is being attempted.
          </p>
        </FeedbackPanel>
      ) : null}

      {controller.candidate ? (
        <CandidateReview
          candidate={controller.candidate}
          interactionsEnabled={interactionsEnabled}
          isAdopting={controller.phase === "adopting"}
          key={`${controller.candidate.reviewedEvidenceSha256}:${controller.candidate.adoptable ? "adoptable" : "blocked"}:${runtimeReady ? "runtime-ready" : "runtime-blocked"}`}
          onAdopt={controller.adopt}
          runtimeReady={runtimeReady}
        />
      ) : null}

      <form className="am-workspace-form" onSubmit={submit} aria-busy={busy}>
        <div
          className="am-field"
          data-invalid={controller.workingDirectoryError ? true : undefined}
        >
          <label htmlFor="workspace-working-directory">
            Effective working directory
          </label>
          <input
            aria-describedby={
              controller.workingDirectoryError
                ? "workspace-working-directory-description workspace-working-directory-error"
                : "workspace-working-directory-description"
            }
            aria-invalid={controller.workingDirectoryError ? true : undefined}
            autoCapitalize="none"
            autoComplete="off"
            disabled={inspectionDisabled}
            id="workspace-working-directory"
            maxLength={MAX_WORKSPACE_PATH_LENGTH}
            name="workingDirectory"
            onChange={(event) =>
              controller.setWorkingDirectory(event.currentTarget.value)
            }
            placeholder="/srv/lego"
            required
            spellCheck={false}
            type="text"
            value={controller.workingDirectory}
          />
          <span id="workspace-working-directory-description">
            Relative storage, dotenv, and webroot references resolve from this
            host directory exactly as upstream lego resolves them.
          </span>
          {controller.workingDirectoryError ? (
            <span id="workspace-working-directory-error" role="alert">
              {controller.workingDirectoryError}
            </span>
          ) : null}
        </div>
        <div
          className="am-field"
          data-invalid={controller.configurationPathError ? true : undefined}
        >
          <label htmlFor="workspace-configuration-path">
            Explicit configuration path (optional)
          </label>
          <input
            aria-describedby={
              controller.configurationPathError
                ? "workspace-configuration-path-description workspace-configuration-path-error"
                : "workspace-configuration-path-description"
            }
            aria-invalid={controller.configurationPathError ? true : undefined}
            autoCapitalize="none"
            autoComplete="off"
            disabled={inspectionDisabled}
            id="workspace-configuration-path"
            maxLength={MAX_WORKSPACE_PATH_LENGTH}
            name="configurationPath"
            onChange={(event) =>
              controller.setConfigurationPath(event.currentTarget.value)
            }
            placeholder="Leave empty to detect .lego.yml or .lego.yaml"
            spellCheck={false}
            type="text"
            value={controller.configurationPath}
          />
          <span id="workspace-configuration-path-description">
            Leave empty for conventional discovery. Upstream priority chooses
            .lego.yml before .lego.yaml when both exist.
          </span>
          {controller.configurationPathError ? (
            <span id="workspace-configuration-path-error" role="alert">
              {controller.configurationPathError}
            </span>
          ) : null}
        </div>
        <ActionButton
          isDisabled={inspectionDisabled}
          isPending={controller.phase === "inspecting"}
          type="submit"
          variant="secondary"
        >
          {controller.phase === "inspecting"
            ? "Inspecting workspace"
            : "Inspect workspace"}
        </ActionButton>
      </form>

      <p className="am-workspace-boundary">
        Inspection does not write YAML, read or display credential values, copy
        certificates or private keys, register an account, contact a provider,
        issue, or renew. AcmeMux never browses the host or repairs ownership and
        permissions automatically.
      </p>
    </section>
  );
}
