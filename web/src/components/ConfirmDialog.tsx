import {
  Dialog,
  DialogTrigger,
  Heading,
  Modal,
  ModalOverlay,
} from "react-aria-components";

import { ActionButton } from "./ActionButton";

export function ConfirmDialog() {
  return (
    <DialogTrigger>
      <ActionButton variant="secondary">Review confirmation</ActionButton>
      <ModalOverlay className="am-modal-overlay" isDismissable>
        <Modal className="am-modal">
          <Dialog className="am-dialog">
            {({ close }) => (
              <>
                <p className="am-kicker">Confirm native change</p>
                <Heading slot="title">Review before applying</Heading>
                <p>
                  AcmeMux will show the affected native files and a secret-safe
                  summary here before any replacement begins.
                </p>
                <div className="am-dialog__actions">
                  <ActionButton variant="quiet" onPress={close}>
                    Cancel
                  </ActionButton>
                  <ActionButton onPress={close}>Acknowledge</ActionButton>
                </div>
              </>
            )}
          </Dialog>
        </Modal>
      </ModalOverlay>
    </DialogTrigger>
  );
}
