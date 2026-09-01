import { Modal } from './Modal';

interface ConfirmDangerDialogProps {
  title: string;
  /** What the confirmation destroys, in the member's own terms. */
  message: string;
  /** The confirm control's label, and the one it wears while in flight. */
  verb: string;
  busyVerb: string;
  /** Test id for the confirm control; the body carries `${testId}-dialog`. */
  testId: string;
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
}

/** The one confirmation an irreversible command takes before it dispatches. */
export function ConfirmDangerDialog({
  title,
  message,
  verb,
  busyVerb,
  testId,
  onClose,
  onConfirm,
  busy,
  error,
}: ConfirmDangerDialogProps) {
  return (
    <Modal onClose={onClose} title={title} error={error} busy={busy}>
      <div className="dialog-content" data-testid={`${testId}-dialog`}>
        <p className="dialog-message">{message}</p>
        <div className="dialog-actions">
          <button type="button" className="dialog-button" onClick={onClose} disabled={busy}>
            cancel
          </button>
          <button
            type="button"
            className="dialog-button dialog-button--danger"
            onClick={onConfirm}
            disabled={busy}
            data-testid={`${testId}-confirm`}
          >
            {busy ? busyVerb : verb}
          </button>
        </div>
      </div>
    </Modal>
  );
}
