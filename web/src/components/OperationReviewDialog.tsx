import { useState } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";

import type { ManualOperationPreview } from "../api/operations";
import { ActionButton } from "./ActionButton";
import { StatusBadge } from "./StatusBadge";

const effectLabels: Record<
  ManualOperationPreview["intent"]["nativeEffects"][number],
  string
> = {
  acme_accounts_may_change:
    "Upstream lego may register or update native ACME account material.",
  certificate_artifacts_may_change:
    "Missing or due certificates, chains, keys, resources, and archives may change in native storage.",
  native_configuration_backup_may_change:
    "Upstream lego may replace its effective .lego.bck.yaml backup.",
  external_acme_state_may_change:
    "The ACME server and challenge endpoint may change even if the process later fails.",
};

export function OperationReviewDialog({
  isEnqueueing,
  onCancel,
  onConfirm,
  preview,
}: {
  isEnqueueing: boolean;
  onCancel(): void;
  onConfirm(): void;
  preview: ManualOperationPreview;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const intent = preview.intent;

  return (
    <ModalOverlay
      className="am-modal-overlay"
      isOpen
      isDismissable={!isEnqueueing}
      onOpenChange={(open) => {
        if (!open && !isEnqueueing) {
          setAcknowledged(false);
          onCancel();
        }
      }}
    >
      <Modal className="am-modal am-operation-review-modal">
        <Dialog className="am-dialog">
          {({ close }) => (
            <>
              <p className="am-kicker">Reviewed whole-workspace intent</p>
              <Heading slot="title">Review manual lego operation</Heading>
              <StatusBadge tone="warning">
                Native and external state may change
              </StatusBadge>

              <p className="am-operation-review__intro">
                AcmeMux will enqueue one durable upstream file-mode run. It
                obtains missing certificates and lets upstream lego decide
                whether existing certificates are due for renewal.
              </p>

              <dl className="am-operation-review__scope">
                <div>
                  <dt>Runtime identity</dt>
                  <dd>{intent.runtime.identity}</dd>
                </div>
                <div>
                  <dt>Compatibility manifest</dt>
                  <dd>{intent.runtime.manifestId}</dd>
                </div>
                <div>
                  <dt>Working directory</dt>
                  <dd>{intent.workingDirectory}</dd>
                </div>
                <div>
                  <dt>Native configuration</dt>
                  <dd>{intent.configurationPath}</dd>
                </div>
                <div>
                  <dt>Native storage</dt>
                  <dd>{intent.storagePath}</dd>
                </div>
              </dl>

              <section
                className="am-operation-review__certificates"
                aria-labelledby="operation-review-certificates"
              >
                <div className="am-operation-review__section-heading">
                  <h3 id="operation-review-certificates">
                    Configured certificates
                  </h3>
                  <StatusBadge tone="info">
                    {intent.certificates.length.toLocaleString("en-US")}{" "}
                    name-sorted
                  </StatusBadge>
                </div>
                <ul
                  aria-label="Reviewed configured certificate targets"
                  tabIndex={0}
                >
                  {intent.certificates.map((certificate) => (
                    <li key={certificate.name}>
                      <div>
                        <strong>{certificate.name}</strong>
                        <StatusBadge tone="neutral">
                          {certificate.challenge.kind} /{" "}
                          {certificate.challenge.mode}
                        </StatusBadge>
                      </div>
                      <dl>
                        <div>
                          <dt>DNS names</dt>
                          <dd>{certificate.domains.join(", ")}</dd>
                        </div>
                        <div>
                          <dt>Account</dt>
                          <dd>{certificate.account}</dd>
                        </div>
                        <div>
                          <dt>CA</dt>
                          <dd>{certificate.ca}</dd>
                        </div>
                        <div>
                          <dt>Challenge</dt>
                          <dd>{certificate.challenge.name}</dd>
                        </div>
                      </dl>
                    </li>
                  ))}
                </ul>
              </section>

              <section
                className="am-operation-review__effects"
                aria-labelledby="operation-review-effects"
              >
                <h3 id="operation-review-effects">Possible native effects</h3>
                <ul>
                  {intent.nativeEffects.map((effect) => (
                    <li key={effect}>{effectLabels[effect]}</li>
                  ))}
                </ul>
              </section>

              <div className="am-operation-review__policy">
                <strong>Browser cancellation is not supported.</strong>
                <p>
                  Closing this page does not stop the operation. The service
                  enforces a{" "}
                  {preview.policy.timeoutSeconds.toLocaleString("en-US")}
                  -second timeout and will not retry automatically after an
                  ambiguous result.
                </p>
              </div>

              <label className="am-operation-review__confirmation">
                <input
                  checked={acknowledged}
                  disabled={isEnqueueing}
                  onChange={(event) =>
                    setAcknowledged(event.currentTarget.checked)
                  }
                  type="checkbox"
                />
                <span>
                  I reviewed the runtime, native paths, configured certificate
                  targets, and the possible external effects. I understand that
                  AcmeMux revalidates the complete native sources before
                  execution and that this durable operation cannot be canceled
                  from the browser.
                </span>
              </label>

              <div className="am-dialog__actions">
                <ActionButton
                  isDisabled={isEnqueueing}
                  onPress={() => close()}
                  variant="quiet"
                >
                  Cancel
                </ActionButton>
                <ActionButton
                  isDisabled={!acknowledged || isEnqueueing}
                  isPending={isEnqueueing}
                  onPress={onConfirm}
                >
                  {isEnqueueing
                    ? "Enqueueing durable operation"
                    : "Start reviewed operation"}
                </ActionButton>
              </div>
            </>
          )}
        </Dialog>
      </Modal>
    </ModalOverlay>
  );
}
