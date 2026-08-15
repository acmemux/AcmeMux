import { AppShell } from "./AppShell";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { StatusBadge } from "../components/StatusBadge";

const foundations = [
  {
    label: "Runtime trust",
    state: "Not configured",
    detail: "Executable selection arrives with the runtime task.",
  },
  {
    label: "Native workspace",
    state: "Not adopted",
    detail: "No configuration or certificate evidence is connected.",
  },
  {
    label: "Certificate inventory",
    state: "Unavailable",
    detail: "Inventory appears only after safe workspace adoption.",
  },
  {
    label: "Automatic evaluation",
    state: "Not scheduled",
    detail: "No background certificate operation is enabled.",
  },
];

export function OverviewPage() {
  return (
    <AppShell>
      <main className="am-main" id="main-content">
        <header className="am-page-heading">
          <div>
            <p className="am-kicker">Workspace overview</p>
            <h1>Certificate operations</h1>
            <p className="am-lede">
              A clear control plane for one authoritative upstream lego
              workspace, with technical evidence available when it matters.
            </p>
          </div>
          <a className="am-link-button" href="/?catalog=components">
            View component catalog
            <span aria-hidden="true">-&gt;</span>
          </a>
        </header>

        <FeedbackPanel tone="info" title="Foundation ready">
          <p>
            The visual and accessibility system is active. Runtime, workspace,
            and certificate features remain unavailable until their delivery
            tasks establish the corresponding trust boundaries.
          </p>
        </FeedbackPanel>

        <section className="am-readiness" aria-labelledby="readiness-heading">
          <div className="am-section-heading">
            <div>
              <p className="am-kicker">Current state</p>
              <h2 id="readiness-heading">No native workspace connected</h2>
            </div>
            <StatusBadge tone="not-attempted">Setup not attempted</StatusBadge>
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
                  <dd>Not observed</dd>
                </div>
                <div>
                  <dt>Native paths</dt>
                  <dd>None selected</dd>
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
