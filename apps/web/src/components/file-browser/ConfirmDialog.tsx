import { Modal } from '../ui/Modal';
import '../../styles/dialogs.css';

type ConfirmDialogProps = {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when dialog is closed (cancel or backdrop click) */
  onClose: () => void;
  /** Callback when action is confirmed */
  onConfirm: () => void;
  /** Dialog title */
  title: string;
  /** Dialog message/body */
  message: string;
  /** Confirm button label */
  confirmLabel?: string;
  /** Whether the action is destructive (styles confirm button as danger) */
  isDestructive?: boolean;
  /** Loading state - disables buttons */
  isLoading?: boolean;
};

/**
 * Confirmation dialog for destructive actions.
 *
 * Used for confirming file/folder deletion.
 * Shows title, message, and Cancel/Confirm buttons.
 *
 * @example
 * ```tsx
 * function DeleteButton() {
 *   const [isOpen, setIsOpen] = useState(false);
 *
 *   return (
 *     <>
 *       <button onClick={() => setIsOpen(true)}>Delete</button>
 *       <ConfirmDialog
 *         open={isOpen}
 *         onClose={() => setIsOpen(false)}
 *         onConfirm={() => { deleteItem(); setIsOpen(false); }}
 *         title="Delete File?"
 *         message="Are you sure you want to delete 'document.pdf'? This cannot be undone."
 *         confirmLabel="Delete"
 *         isDestructive
 *       />
 *     </>
 *   );
 * }
 * ```
 */
export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = 'Delete',
  isDestructive = true,
  isLoading = false,
}: ConfirmDialogProps) {
  const handleConfirm = () => {
    if (!isLoading) {
      onConfirm();
    }
  };

  const handleCancel = () => {
    if (!isLoading) {
      onClose();
    }
  };

  return (
    <Modal open={open} onClose={handleCancel} title={title}>
      <div className="dialog-content">
        <p className="dialog-message">{message}</p>
        <div className="dialog-actions">
          <button
            type="button"
            className="dialog-button dialog-button--secondary"
            onClick={handleCancel}
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            type="button"
            className={`dialog-button ${isDestructive ? 'dialog-button--destructive' : 'dialog-button--primary'}`}
            onClick={handleConfirm}
            disabled={isLoading}
          >
            {isLoading ? 'Deleting...' : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
