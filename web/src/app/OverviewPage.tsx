import { AppShell } from "./AppShell";
import {
  browserRuntimeClient,
  type RuntimeCandidate,
  type RuntimeClient,
  type RuntimeSnapshot,
} from "../api/runtime";
import {
  browserWorkspaceClient,
  type WorkspaceCandidate,
  type WorkspaceClient,
  type WorkspaceSnapshot,
} from "../api/workspace";
import { StatusBadge } from "../components/StatusBadge";
import {
  RuntimePanel,
  runtimeSignal,
  useRuntimeController,
} from "./RuntimePanel";
import {
  WorkspacePanel,
  useWorkspaceController,
  workspaceSignal,
} from "./WorkspacePanel";

function decodedEvidenceMatches(left: unknown, right: unknown): boolean {
  // Both values have already crossed strict decoders that construct fields in
  // one canonical order, so this compares every review-visible field.
  return JSON.stringify(left) === JSON.stringify(right);
}

function runtimeCandidateInvalidatesCurrent(
  snapshot: RuntimeSnapshot | null,
  candidate: RuntimeCandidate | null,
): boolean {
  if (snapshot?.state !== "supported" || candidate === null) {
    return false;
  }
  const candidatePath =
    candidate.state === "review_required"
      ? candidate.candidate.canonicalPath
      : candidate.path;
  if (candidatePath !== snapshot.runtime.canonicalPath) {
    return false;
  }
  return (
    candidate.state !== "review_required" ||
    candidate.compatibility.state !== snapshot.compatibility.state ||
    candidate.compatibility.code !== snapshot.compatibility.code ||
    candidate.compatibility.manifestId !== snapshot.compatibility.manifestId ||
    !decodedEvidenceMatches(candidate.candidate, snapshot.runtime)
  );
}

function workspaceCandidateInvalidatesCurrent(
  snapshot: WorkspaceSnapshot | null,
  candidate: WorkspaceCandidate | null,
): boolean {
  if (snapshot?.state !== "ready" || candidate === null) {
    return false;
  }
  const sameSelection =
    candidate.candidate.workingDirectory.canonicalPath ===
      snapshot.workspace.workingDirectory.canonicalPath &&
    candidate.candidate.configuration.path.canonicalPath ===
      snapshot.workspace.configuration.path.canonicalPath;
  return (
    sameSelection &&
    (!candidate.adoptable ||
      !decodedEvidenceMatches(candidate.candidate, snapshot.workspace))
  );
}

export function OverviewPage({
  runtimeClient = browserRuntimeClient,
  workspaceClient = browserWorkspaceClient,
}: {
  runtimeClient?: RuntimeClient;
  workspaceClient?: WorkspaceClient;
} = {}) {
  const runtime = useRuntimeController(runtimeClient);
  const runtimeCandidateInvalidates = runtimeCandidateInvalidatesCurrent(
    runtime.snapshot,
    runtime.candidate,
  );
  const runtimeSnapshotReady =
    runtime.phase === "idle" &&
    runtime.snapshot?.state === "supported" &&
    !runtimeCandidateInvalidates &&
    runtime.error === null;
  const workspaceActivationKey =
    runtime.snapshot !== null && runtime.error === null
      ? `${runtime.requestRevision}:${runtime.snapshot.state}`
      : null;
  const runtimeInteractionsEnabled =
    runtime.phase === "idle" && runtime.error === null;
  const workspace = useWorkspaceController(
    workspaceClient,
    workspaceActivationKey,
    runtimeSnapshotReady,
    runtimeInteractionsEnabled,
  );
  const workspaceBlocksRuntime = workspace.runtimeRecheckRequired;
  const runtimeReady = runtimeSnapshotReady && !workspaceBlocksRuntime;
  const signal = workspaceBlocksRuntime
    ? "Recheck required"
    : runtimeSignal(runtime);
  const nativeSignal =
    !runtimeReady && workspace.snapshot?.state === "ready"
      ? "Recheck required"
      : workspaceSignal(workspace);
  const workspaceCandidateInvalidates = workspaceCandidateInvalidatesCurrent(
    workspace.snapshot,
    workspace.candidate,
  );
  const workspaceReady =
    runtimeReady &&
    workspace.phase === "idle" &&
    workspace.snapshot?.state === "ready" &&
    !workspaceCandidateInvalidates &&
    workspace.error === null;
  const showWorkspace =
    runtimeReady ||
    workspace.phase === "loading" ||
    workspace.error !== null ||
    (workspace.snapshot !== null && workspace.snapshot.state !== "unadopted");
  const inventoryCount =
    workspaceReady && workspace.snapshot?.state === "ready"
      ? workspace.snapshot.inventory.length
      : null;
  const foundations = [
    {
      label: "Runtime trust",
      state: signal,
      detail: runtimeReady
        ? "Exact executable and compatibility manifest reviewed."
        : "Managed operations wait for an exact supported runtime.",
    },
    {
      label: "Native workspace",
      state: nativeSignal,
      detail: workspaceReady
        ? "Reviewed native paths remain authoritative and unchanged."
        : "Managed operations wait for safe workspace adoption.",
    },
    {
      label: "Certificate inventory",
      state:
        inventoryCount === null
          ? "Unavailable"
          : inventoryCount === 1
            ? "1 certificate"
            : `${inventoryCount.toLocaleString("en-US")} certificates`,
      detail: workspaceReady
        ? "Bounded upstream evidence from native storage."
        : "Inventory appears only after safe workspace adoption.",
    },
    {
      label: "Automatic evaluation",
      state: "Not scheduled",
      detail: "No background certificate operation is enabled.",
    },
  ];

  return (
    <AppShell runtimeStatus={signal}>
      <main className="am-main" id="main-content">
        <header className="am-page-heading">
          <div>
            <p className="am-kicker">Workspace overview</p>
            <h1>Certificate operations</h1>
            <p className="am-lede">
              Establish trust in one administrator-provisioned lego executable,
              then connect the authoritative native workspace it will operate.
            </p>
          </div>
          {import.meta.env.DEV ? (
            <a className="am-link-button" href="/?catalog=components">
              View component catalog
              <span aria-hidden="true">-&gt;</span>
            </a>
          ) : null}
        </header>

        <RuntimePanel
          controller={runtime}
          externallyBusy={workspace.phase !== "idle"}
          trustBlocked={workspaceBlocksRuntime}
        />
        {showWorkspace ? (
          <WorkspacePanel
            controller={workspace}
            interactionsEnabled={runtimeInteractionsEnabled}
            runtimeReady={runtimeReady}
          />
        ) : null}

        <section className="am-readiness" aria-labelledby="readiness-heading">
          <div className="am-section-heading">
            <div>
              <p className="am-kicker">Current state</p>
              <h2 id="readiness-heading">
                {workspaceReady
                  ? "Native workspace connected"
                  : runtimeReady
                    ? "Runtime ready for workspace adoption"
                    : "Managed operations remain blocked"}
              </h2>
            </div>
            <StatusBadge tone={workspaceReady ? "success" : "not-attempted"}>
              {workspaceReady ? "Workspace trusted" : "Setup incomplete"}
            </StatusBadge>
          </div>
          <div className="am-readiness__grid">
            {foundations.map((foundation, index) => (
              <article key={foundation.label}>
                <span className="am-card-index" aria-hidden="true">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <p>{foundation.label}</p>
                <h3>{foundation.state}</h3>
                <small>{foundation.detail}</small>
              </article>
            ))}
          </div>
        </section>

        <div className="am-overview-grid">
          <section className="am-panel" aria-labelledby="boundary-heading">
            <div className="am-panel__heading">
              <div>
                <p className="am-kicker">Ownership boundary</p>
                <h2 id="boundary-heading">Native remains authoritative</h2>
              </div>
              <StatusBadge tone="success">Enforced</StatusBadge>
            </div>
            <ul className="am-rule-list">
              <li>
                <strong>Upstream lego performs ACME operations.</strong>
                <span>AcmeMux never reimplements provider protocols.</span>
              </li>
              <li>
                <strong>One native workspace owns desired state.</strong>
                <span>No certificate or private-key material is copied.</span>
              </li>
              <li>
                <strong>Managed actions are constrained and reviewable.</strong>
                <span>No shell or arbitrary command interface is exposed.</span>
              </li>
            </ul>
          </section>

          <section className="am-panel" aria-labelledby="detail-heading">
            <div className="am-panel__heading">
              <div>
                <p className="am-kicker">Progressive detail</p>
                <h2 id="detail-heading">What this screen knows</h2>
              </div>
            </div>
            <details className="am-disclosure">
              <summary>Show current application evidence</summary>
              <dl>
                <div>
                  <dt>Application state</dt>
                  <dd>SQLite foundation available</dd>
                </div>
                <div>
                  <dt>Runtime identity</dt>
                  <dd>{signal}</dd>
                </div>
                <div>
                  <dt>Native paths</dt>
                  <dd>{nativeSignal}</dd>
                </div>
              </dl>
            </details>
            <p className="am-panel__note">
              No illustrative certificate counts or operation results are shown
              as live product data.
            </p>
          </section>
        </div>
      </main>
    </AppShell>
  );
}
