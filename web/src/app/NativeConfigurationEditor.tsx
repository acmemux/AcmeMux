import { useMemo, useState } from "react";

import type {
  ConfigurationChange,
  ConfigurationDiagnostic,
  ConfigurationPreview,
  ProjectedField,
} from "../api/configuration";
import { ActionButton } from "../components/ActionButton";
import { ConfigurationReviewDialog } from "../components/ConfigurationReviewDialog";
import { FeedbackPanel } from "../components/FeedbackPanel";
import { StatusBadge } from "../components/StatusBadge";
import {
  AccountsEditor,
  CertificatesEditor,
  ChallengesEditor,
  ConfigurationField,
  inputDescription,
  issueFor,
} from "./NativeConfigurationFields";
import {
  acknowledgeUnsupportedField,
  canAcknowledgeUnsupportedField,
  changesFromDraft,
  initialConfigurationDraft,
  managedFieldIds,
  resolveCA,
  unsupportedFieldControlId,
  validateChangeBudget,
  validateDraft,
  type DraftIssue,
  type NativeConfigurationDraft,
} from "./nativeConfigurationModel";

export type ConfigurationCreationLocation = {
  workingDirectory: string;
  configurationPath: string | null;
};

export type PreparedConfiguration = {
  changes: ConfigurationChange[];
  location?: ConfigurationCreationLocation;
  preview: Extract<ConfigurationPreview, { state: "review_required" }>;
};

export type NativeConfigurationEditorProps = {
  interactionsEnabled: boolean;
  mode: "creation" | "edit";
  operationPending: boolean;
  projection: ProjectedField[];
  revisionKey: string;
  onPreview(
    changes: ConfigurationChange[],
    location?: ConfigurationCreationLocation,
  ): Promise<ConfigurationPreview | null>;
  onSave(prepared: PreparedConfiguration): Promise<boolean>;
};

function canonicalAbsolutePath(value: string): boolean {
  if (
    new TextEncoder().encode(value).length > 4095 ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point < 0x20 || point === 0x7f;
    })
  ) {
    return false;
  }
  if (value === "/") return true;
  if (!value.startsWith("/") || value.endsWith("/")) return false;
  return !value
    .slice(1)
    .split("/")
    .some(
      (component) =>
        component === "" || component === "." || component === "..",
    );
}

function ValidationSummary({ issues }: { issues: DraftIssue[] }) {
  if (issues.length === 0) return null;
  const unique = issues.filter(
    (issue, index) =>
      issues.findIndex(
        (candidate) =>
          candidate.fieldId === issue.fieldId &&
          candidate.message === issue.message,
      ) === index,
  );
  return (
    <section
      aria-labelledby="configuration-form-findings"
      className="am-configuration-editor__validation"
      role="alert"
    >
      <h3 id="configuration-form-findings" tabIndex={-1}>
        Review {unique.length.toLocaleString("en-US")} form{" "}
        {unique.length === 1 ? "finding" : "findings"}
      </h3>
      <ul>
        {unique.map((issue) => (
          <li key={issue.fieldId + ":" + issue.message}>
            <a href={"#" + issue.fieldId}>{issue.message}</a>
          </li>
        ))}
      </ul>
    </section>
  );
}

function CandidateDiagnostics({
  diagnostics,
}: {
  diagnostics: ConfigurationDiagnostic[];
}) {
  if (diagnostics.length === 0) return null;
  return (
    <section
      aria-labelledby="configuration-candidate-findings"
      className="am-configuration-editor__findings"
    >
      <h4 id="configuration-candidate-findings">Candidate findings</h4>
      <ul>
        {diagnostics.map((diagnostic, index) => (
          <li
            key={
              diagnostic.code +
              ":" +
              (diagnostic.fieldId ?? "none") +
              ":" +
              String(index)
            }
          >
            <div>
              <code>{diagnostic.code}</code>
              <StatusBadge
                tone={diagnostic.severity === "blocking" ? "danger" : "info"}
              >
                {diagnostic.severity}
              </StatusBadge>
            </div>
            <p>{diagnostic.message}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function NativeConfigurationEditor({
  interactionsEnabled,
  mode,
  operationPending,
  projection,
  revisionKey,
  onPreview,
  onSave,
}: NativeConfigurationEditorProps) {
  const creation = mode === "creation";
  const [draft, setDraft] = useState<NativeConfigurationDraft>(() =>
    initialConfigurationDraft(projection, creation),
  );
  const [workingDirectory, setWorkingDirectory] = useState("");
  const [useExplicitConfiguration, setUseExplicitConfiguration] =
    useState(false);
  const [configurationPath, setConfigurationPath] = useState("");
  const [issues, setIssues] = useState<DraftIssue[]>([]);
  const [preview, setPreview] = useState<ConfigurationPreview | null>(null);
  const [preparedChanges, setPreparedChanges] = useState<ConfigurationChange[]>(
    [],
  );
  const [preparedLocation, setPreparedLocation] = useState<
    ConfigurationCreationLocation | undefined
  >();

  const stagingAccounts = useMemo(
    () =>
      draft.accounts.filter(
        (account) => resolveCA(account.server)?.environment === "staging",
      ),
    [draft.accounts],
  );

  function mutate(
    update: (current: NativeConfigurationDraft) => NativeConfigurationDraft,
  ) {
    setDraft((current) => update(current));
    setIssues([]);
    setPreview(null);
    setPreparedChanges([]);
    setPreparedLocation(undefined);
  }

  function updateLocation() {
    setIssues([]);
    setPreview(null);
    setPreparedChanges([]);
    setPreparedLocation(undefined);
  }

  function locationIssues(): DraftIssue[] {
    if (!creation) return [];
    const result: DraftIssue[] = [];
    if (!canonicalAbsolutePath(workingDirectory)) {
      result.push({
        fieldId: "configuration-working-directory",
        message: "Enter an existing canonical absolute working directory.",
      });
    }
    if (useExplicitConfiguration && !canonicalAbsolutePath(configurationPath)) {
      result.push({
        fieldId: "configuration-explicit-path",
        message: "Enter a canonical absolute configuration file path.",
      });
    }
    return result;
  }

  async function prepareReview() {
    const nextIssues = [...locationIssues(), ...validateDraft(draft)];
    setIssues(nextIssues);
    setPreview(null);
    if (nextIssues.length > 0) {
      requestAnimationFrame(() =>
        document.getElementById("configuration-form-findings")?.focus(),
      );
      return;
    }
    const changes = changesFromDraft(draft, projection, creation);
    const budgetIssues = validateChangeBudget(changes);
    if (budgetIssues.length > 0) {
      setIssues(budgetIssues);
      requestAnimationFrame(() =>
        document.getElementById("configuration-form-findings")?.focus(),
      );
      return;
    }
    if (changes.length === 0) {
      setPreview({ state: "unchanged", baseRevisionToken: revisionKey });
      return;
    }
    const location = creation
      ? {
          workingDirectory,
          configurationPath: useExplicitConfiguration
            ? configurationPath
            : null,
        }
      : undefined;
    const result = await onPreview(changes, location);
    if (result === null) return;
    setPreview(result);
    if (result.state === "review_required") {
      setPreparedChanges(changes);
      setPreparedLocation(location);
    }
  }

  const disabled = !interactionsEnabled || operationPending;
  const reviewed: PreparedConfiguration | null =
    preview?.state === "review_required"
      ? {
          changes: preparedChanges,
          location: preparedLocation,
          preview,
        }
      : null;

  return (
    <section
      aria-labelledby="managed-configuration-heading"
      className="am-configuration-editor"
    >
      <div className="am-panel__heading">
        <div>
          <p className="am-kicker">
            {creation ? "Create native workspace" : "Typed native forms"}
          </p>
          <h3 id="managed-configuration-heading">
            {creation
              ? "Prepare the first supported configuration"
              : "CA, certificate, and HTTP-01 configuration"}
          </h3>
        </div>
        <StatusBadge tone={creation ? "warning" : "info"}>
          {creation ? "Not written" : "Native source"}
        </StatusBadge>
      </div>
      <p className="am-configuration-editor__intro">
        These controls map to curated logical fields. Names select native map
        entries; the service retains every YAML selector and resolves accepted
        CA choices to exact upstream endpoints.
      </p>

      {draft.unsupportedFields.length > 0 ? (
        <section
          aria-labelledby="configuration-unsupported-repairs"
          className="am-configuration-editor__unsupported-repairs"
        >
          <FeedbackPanel
            announcement="assertive"
            tone="unsupported"
            title="Hidden native values require explicit repair"
          >
            <p>
              Each item below is present in native configuration but outside its
              typed contract. The value stays hidden and retained until you
              change its linked control or explicitly accept the currently
              displayed supported replacement.
            </p>
          </FeedbackPanel>
          <h4 id="configuration-unsupported-repairs">Required field repairs</h4>
          <ul>
            {draft.unsupportedFields.map((field) => {
              const controlId = unsupportedFieldControlId(draft, field);
              const canAcknowledge = canAcknowledgeUnsupportedField(
                draft,
                field,
              );
              return (
                <li key={JSON.stringify([field.fieldId, field.bindings])}>
                  <div>
                    <strong>{field.label}</strong>
                    <code>{field.fieldId}</code>
                    {field.bindings.length > 0 ? (
                      <span>
                        {field.bindings
                          .map((binding) => `${binding.id}=${binding.value}`)
                          .join(", ")}
                      </span>
                    ) : null}
                  </div>
                  <a href={`#${controlId}`}>Go to replacement control</a>
                  <ActionButton
                    isDisabled={disabled || !canAcknowledge}
                    onPress={() =>
                      mutate((current) =>
                        acknowledgeUnsupportedField(
                          current,
                          field.fieldId,
                          field.bindings,
                        ),
                      )
                    }
                    variant="secondary"
                  >
                    Use displayed replacement
                  </ActionButton>
                  {!canAcknowledge ? (
                    <small>
                      Choose a supported value in the linked control first.
                    </small>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}

      {creation ? (
        <fieldset className="am-configuration-editor__group">
          <legend>Native workspace destination</legend>
          <div className="am-configuration-editor__grid">
            <ConfigurationField
              description="The existing directory from which lego resolves relative paths."
              error={issueFor(issues, "configuration-working-directory")}
              id="configuration-working-directory"
              label="Working directory"
            >
              <input
                aria-describedby={inputDescription(
                  issues,
                  "configuration-working-directory",
                )}
                aria-invalid={Boolean(
                  issueFor(issues, "configuration-working-directory"),
                )}
                autoCapitalize="none"
                disabled={disabled}
                id="configuration-working-directory"
                maxLength={4095}
                onChange={(event) => {
                  setWorkingDirectory(event.currentTarget.value);
                  updateLocation();
                }}
                placeholder="/srv/lego"
                spellCheck={false}
                value={workingDirectory}
              />
            </ConfigurationField>
            <label className="am-configuration-editor__check">
              <input
                checked={useExplicitConfiguration}
                disabled={disabled}
                onChange={(event) => {
                  setUseExplicitConfiguration(event.currentTarget.checked);
                  updateLocation();
                }}
                type="checkbox"
              />
              <span>
                Use an explicit configuration path instead of conventional{" "}
                <code>.lego.yml</code>
              </span>
            </label>
            {useExplicitConfiguration ? (
              <ConfigurationField
                description="The parent directory must exist and the target file must not."
                error={issueFor(issues, "configuration-explicit-path")}
                id="configuration-explicit-path"
                label="Configuration file"
              >
                <input
                  aria-describedby={inputDescription(
                    issues,
                    "configuration-explicit-path",
                  )}
                  aria-invalid={Boolean(
                    issueFor(issues, "configuration-explicit-path"),
                  )}
                  autoCapitalize="none"
                  disabled={disabled}
                  id="configuration-explicit-path"
                  maxLength={4095}
                  onChange={(event) => {
                    setConfigurationPath(event.currentTarget.value);
                    updateLocation();
                  }}
                  placeholder="/srv/lego/config/acme.yml"
                  spellCheck={false}
                  value={configurationPath}
                />
              </ConfigurationField>
            ) : null}
          </div>
        </fieldset>
      ) : null}

      <fieldset className="am-configuration-editor__group">
        <legend>Native storage</legend>
        <ConfigurationField
          description="Relative paths remain relative to the working directory. The storage directory must already exist and be safe for the service identity."
          error={issueFor(issues, "configuration-storage")}
          id="configuration-storage"
          label="Storage directory"
        >
          <input
            aria-describedby={inputDescription(issues, "configuration-storage")}
            aria-invalid={Boolean(issueFor(issues, "configuration-storage"))}
            autoCapitalize="none"
            disabled={disabled}
            id="configuration-storage"
            maxLength={4095}
            onChange={(event) => {
              const storage = event.currentTarget.value;
              mutate((current) =>
                acknowledgeUnsupportedField(
                  { ...current, storage },
                  managedFieldIds.storage,
                  [],
                ),
              );
            }}
            spellCheck={false}
            value={draft.storage}
          />
        </ConfigurationField>
      </fieldset>

      <AccountsEditor
        creation={creation}
        disabled={disabled}
        draft={draft}
        issues={issues}
        mutate={mutate}
      />
      {stagingAccounts.length > 0 ? (
        <FeedbackPanel
          announcement="polite"
          tone="warning"
          title="Staging account material selected"
        >
          <p>
            {stagingAccounts.map((account) => account.name).join(", ")} will use
            a staging directory. Staging certificates are not publicly trusted,
            and staging credentials must stay separate from production material.
          </p>
        </FeedbackPanel>
      ) : null}
      <ChallengesEditor
        creation={creation}
        disabled={disabled}
        draft={draft}
        issues={issues}
        mutate={mutate}
      />
      <CertificatesEditor
        creation={creation}
        disabled={disabled}
        draft={draft}
        issues={issues}
        mutate={mutate}
      />

      <ValidationSummary issues={issues} />
      {preview?.state === "invalid" ? (
        <>
          <FeedbackPanel
            announcement="assertive"
            tone="danger"
            title="Candidate configuration is not valid"
          >
            <p>
              No native file was changed. Correct the server-validated findings
              and prepare a new review.
            </p>
          </FeedbackPanel>
          <CandidateDiagnostics diagnostics={preview.diagnostics} />
        </>
      ) : null}
      {preview?.state === "unchanged" ? (
        <FeedbackPanel tone="info" title="No native changes to review">
          <p>The typed values already match the current native projection.</p>
        </FeedbackPanel>
      ) : null}
      {reviewed ? (
        <ConfigurationReviewDialog
          executionAllowed={reviewed.preview.executionAllowed}
          isSaving={operationPending}
          onCancel={() => {
            setPreview(null);
            setPreparedChanges([]);
            setPreparedLocation(undefined);
          }}
          onConfirm={() => {
            void onSave(reviewed).then((saved) => {
              if (!saved) {
                setPreview(null);
                setPreparedChanges([]);
                setPreparedLocation(undefined);
              }
            });
          }}
          summary={reviewed.preview.summary}
        />
      ) : (
        <ActionButton
          isDisabled={disabled}
          isPending={operationPending}
          onPress={() => void prepareReview()}
        >
          {operationPending
            ? "Preparing secret-safe review"
            : creation
              ? "Preview native workspace creation"
              : "Preview native configuration changes"}
        </ActionButton>
      )}
      <p className="am-configuration-editor__boundary">
        Preview performs no write. Save reopens native sources under the shared
        lock and rejects changed evidence. EAB HMAC values never appear in
        projections or summaries.
      </p>
    </section>
  );
}
