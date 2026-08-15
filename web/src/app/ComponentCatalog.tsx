import { AppShell } from "./AppShell";
import { ActionButton } from "../components/ActionButton";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { FormField } from "../components/FormField";
import { StatusBadge, type StatusTone } from "../components/StatusBadge";
import "../styles/catalog.css";

const states: Array<{ tone: StatusTone; label: string }> = [
  { tone: "neutral", label: "Normal" },
  { tone: "info", label: "Loading" },
  { tone: "success", label: "Success" },
  { tone: "warning", label: "Warning" },
  { tone: "danger", label: "Error" },
  { tone: "unsupported", label: "Unsupported" },
  { tone: "partial", label: "Partial" },
  { tone: "interrupted", label: "Interrupted" },
  { tone: "not-attempted", label: "Not attempted" },
];

export function ComponentCatalog() {
  return (
    <AppShell>
      <main className="am-main am-catalog" id="main-content">
        <header className="am-page-heading">
          <div>
            <p className="am-kicker">Isolated workshop / Task 02</p>
            <h1>Component catalog</h1>
            <p className="am-lede">
              The coded states and controls later feature screens must compose.
              Demonstration content is explicitly isolated from live product
              state.
            </p>
          </div>
          <a className="am-link-button" href="/">
            Return to overview
            <span aria-hidden="true">-&gt;</span>
          </a>
        </header>

        <section
          className="am-catalog-section"
          aria-labelledby="status-heading"
        >
          <div className="am-section-heading">
            <div>
              <p className="am-kicker">Language</p>
              <h2 id="status-heading">Operational status</h2>
            </div>
            <p>Every state combines a mark, label, and contrast.</p>
          </div>
          <div className="am-state-grid">
            {states.map((state) => (
              <div key={state.label}>
                <StatusBadge tone={state.tone}>{state.label}</StatusBadge>
              </div>
            ))}
          </div>
        </section>

        <section
          className="am-catalog-section"
          aria-labelledby="controls-heading"
        >
          <div className="am-section-heading">
            <div>
              <p className="am-kicker">Interaction</p>
              <h2 id="controls-heading">Controls and forms</h2>
            </div>
          </div>
          <div className="am-catalog-grid">
            <article className="am-catalog-card">
              <h3>Actions</h3>
              <div className="am-button-row">
                <ActionButton>Primary action</ActionButton>
                <ActionButton demoState="hover">Hover state</ActionButton>
                <ActionButton demoState="focus">Focus state</ActionButton>
                <ActionButton variant="secondary">Secondary</ActionButton>
                <ActionButton variant="quiet">Quiet action</ActionButton>
                <ActionButton variant="danger">Destructive</ActionButton>
                <ActionButton isDisabled>Disabled</ActionButton>
                <ActionButton isPending>Saving</ActionButton>
              </div>
              <ConfirmDialog />
            </article>

            <article className="am-catalog-card">
              <h3>Fields</h3>
              <div className="am-field-stack">
                <FormField
                  label="Working directory"
                  description="Resolved relative native paths begin here."
                  defaultValue="/srv/acme/lego"
                />
                <FormField
                  label="Configuration file"
                  description="A regular native YAML file is required."
                  defaultValue=".lego.yml"
                  isInvalid
                  errorMessage="The example path has not been inspected."
                />
                <FormField
                  label="Detected storage"
                  description="Unavailable until a workspace is adopted."
                  defaultValue="Not available"
                  isDisabled
                />
              </div>
            </article>
          </div>
        </section>

        <section
          className="am-catalog-section"
          aria-labelledby="feedback-heading"
        >
          <div className="am-section-heading">
            <div>
              <p className="am-kicker">Feedback</p>
              <h2 id="feedback-heading">Complete and ambiguous outcomes</h2>
            </div>
          </div>
          <div className="am-feedback-grid">
            <FeedbackPanel tone="success" title="Configuration valid">
              <p>
                The candidate passed the declared schema and semantic checks.
              </p>
            </FeedbackPanel>
            <FeedbackPanel tone="warning" title="Review required">
              <p>The selected certificate enters its renewal window soon.</p>
            </FeedbackPanel>
            <FeedbackPanel tone="danger" title="Replacement blocked">
              <p>The native file changed after this review was prepared.</p>
            </FeedbackPanel>
            <FeedbackPanel tone="unsupported" title="Provider unsupported">
              <p>
                The native configuration is preserved; managed runs are blocked.
              </p>
            </FeedbackPanel>
            <FeedbackPanel tone="partial" title="Operation partially complete">
              <p>
                One certificate changed before upstream lego stopped on failure.
              </p>
            </FeedbackPanel>
            <FeedbackPanel tone="interrupted" title="Operation interrupted">
              <p>
                External state may have changed. Inventory must be refreshed.
              </p>
            </FeedbackPanel>
            <FeedbackPanel tone="not-attempted" title="Not attempted">
              <p>A prior certificate failed before this item was reached.</p>
            </FeedbackPanel>
            <FeedbackPanel tone="neutral" title="Empty workspace">
              <p>No authoritative native workspace has been selected.</p>
            </FeedbackPanel>
          </div>
        </section>

        <section className="am-catalog-section" aria-labelledby="table-heading">
          <div className="am-section-heading">
            <div>
              <p className="am-kicker">Structured evidence</p>
              <h2 id="table-heading">Responsive data table</h2>
            </div>
          </div>
          <div
            className="am-table-frame"
            tabIndex={0}
            role="region"
            aria-label="Certificate state example table"
          >
            <table>
              <caption>
                Illustrative state vocabulary, not certificate inventory
              </caption>
              <thead>
                <tr>
                  <th scope="col">Certificate</th>
                  <th scope="col">Evidence</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">gateway.example</th>
                  <td>Expiry and issuer observed</td>
                  <td>
                    <StatusBadge tone="success">Healthy</StatusBadge>
                  </td>
                </tr>
                <tr>
                  <th scope="row">media.example</th>
                  <td>Evaluation stopped before attempt</td>
                  <td>
                    <StatusBadge tone="not-attempted">
                      Not attempted
                    </StatusBadge>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </AppShell>
  );
}

export default ComponentCatalog;
