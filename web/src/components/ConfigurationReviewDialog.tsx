import { useState } from "react";
import {
  Dialog,
  DialogTrigger,
  Heading,
  Modal,
  ModalOverlay,
} from "react-aria-components";

import type { ChangeSummary } from "../api/configuration";
import { ActionButton } from "./ActionButton";
import { StatusBadge } from "./StatusBadge";

function summaryValue(
  value: ChangeSummary["before"],
  sensitive: boolean,
): string {
  if (value.state === "absent") return "Not set";
  if (sensitive || value.state === "present_secret") {
    return "Stored value present (hidden)";
  }
  if (value.state === "present_unsupported") {
    return "Unsupported native value present (hidden)";
  }
  if (Array.isArray(value.value)) return value.value.join(", ");
  return String(value.value);
}

export function ConfigurationReviewDialog({
  executionAllowed,
  isSaving = false,
  onCancel,
  onConfirm,
  summary,
}: {
  executionAllowed: boolean;
  isSaving?: boolean;
  onCancel(): void;
  onConfirm(): void;
  summary: ChangeSummary[];
}) {
  const [acknowledged, setAcknowledged] = useState(false);

  return (
    <DialogTrigger
      onOpenChange={(open) => {
        if (!open) {
          setAcknowledged(false);
          onCancel();
        }
      }}
    >
      <ActionButton variant="secondary">
        Review {summary.length.toLocaleString("en-US")} native{" "}
        {summary.length === 1 ? "change" : "changes"}
      </ActionButton>
      <ModalOverlay className="am-modal-overlay" isDismissable={!isSaving}>
        <Modal className="am-modal am-configuration-review-modal">
          <Dialog className="am-dialog">
            {({ close }) => (
              <>
                <p className="am-kicker">Secret-safe native intent</p>
                <Heading slot="title">Review configuration changes</Heading>
                <StatusBadge
                  tone={executionAllowed ? "success" : "unsupported"}
                >
                  {executionAllowed
                    ? "Managed execution remains eligible"
                    : "Managed execution remains blocked"}
                </StatusBadge>
                <ul className="am-configuration-review-list">
                  {summary.map((change) => (
                    <li
                      key={JSON.stringify([
                        change.fieldId,
                        change.bindings.map(({ id, value }) => [id, value]),
                      ])}
                    >
                      <div>
                        <strong>{change.label}</strong>
                        <code>{change.file}</code>
                      </div>
                      {change.bindings.length > 0 ? (
                        <dl className="am-configuration-review-bindings">
                          {change.bindings.map((binding) => (
                            <div key={binding.id}>
                              <dt>{binding.id.replaceAll("_", " ")}</dt>
                              <dd>{binding.value}</dd>
                            </div>
                          ))}
                        </dl>
                      ) : null}
                      <dl>
                        <div>
                          <dt>Before</dt>
                          <dd>
                            {summaryValue(change.before, change.sensitive)}
                          </dd>
                        </div>
                        <div>
                          <dt>After</dt>
                          <dd>
                            {summaryValue(change.after, change.sensitive)}
                          </dd>
                        </div>
                      </dl>
                    </li>
                  ))}
                </ul>
                <label className="am-configuration-review-confirmation">
                  <input
                    checked={acknowledged}
                    disabled={isSaving}
                    onChange={(event) =>
                      setAcknowledged(event.currentTarget.checked)
                    }
                    type="checkbox"
                  />
                  <span>
                    I reviewed every affected native file and the secret-safe
                    intent. Save will revalidate the current sources before
                    replacement.
                  </span>
                </label>
                <div className="am-dialog__actions">
                  <ActionButton
                    isDisabled={isSaving}
                    onPress={() => close()}
                    variant="quiet"
                  >
                    Cancel
                  </ActionButton>
                  <ActionButton
                    isDisabled={!acknowledged || isSaving}
                    isPending={isSaving}
                    onPress={() => onConfirm()}
                  >
                    {isSaving
                      ? "Saving reviewed changes"
                      : "Save reviewed changes"}
                  </ActionButton>
                </div>
              </>
            )}
          </Dialog>
        </Modal>
      </ModalOverlay>
    </DialogTrigger>
  );
}
