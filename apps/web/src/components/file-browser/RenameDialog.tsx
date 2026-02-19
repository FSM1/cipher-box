import { useState, useEffect, useRef, useCallback, type FormEvent } from 'react';
import { Modal } from '../ui/Modal';
import '../../styles/dialogs.css';

type RenameDialogProps = {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when dialog is closed (cancel or backdrop click) */
  onClose: () => void;
  /** Callback when rename is confirmed */
  onConfirm: (newName: string) => void;
  /** Current name of the item */
  currentName: string;
  /** Type of item being renamed */
  itemType: 'file' | 'folder';
  /** Loading state - disables buttons */
  isLoading?: boolean;
};

/**
 * Dialog for renaming files and folders.
 *
 * Shows an input field pre-filled with the current name, selected for easy replacement.
 * Validates that name is not empty and different from current.
 *
 * @example
 * ```tsx
 * function RenameButton({ item }) {
 *   const [isOpen, setIsOpen] = useState(false);
 *
 *   return (
 *     <>
 *       <button onClick={() => setIsOpen(true)}>Rename</button>
 *       <RenameDialog
 *         open={isOpen}
 *         onClose={() => setIsOpen(false)}
 *         onConfirm={(newName) => { renameItem(newName); setIsOpen(false); }}
 *         currentName={item.name}
 *         itemType={item.type}
 *       />
 *     </>
 *   );
 * }
 * ```
 */
export function RenameDialog({
  open,
  onClose,
  onConfirm,
  currentName,
  itemType,
  isLoading = false,
}: RenameDialogProps) {
  const [newName, setNewName] = useState(currentName);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset form when dialog opens
  useEffect(() => {
    if (open) {
      setNewName(currentName);
      setError(null);
      // Focus and select input after render
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.focus();
          inputRef.current.select();
        }
      }, 0);
    }
  }, [open, currentName]);

  const validate = (name: string): string | null => {
    const trimmed = name.trim();
    if (!trimmed) {
      return 'Name cannot be empty';
    }
    if (trimmed === currentName) {
      return 'Name is the same as current';
    }
    // Check for invalid characters (basic)
    if (/[/\\:*?"<>|]/.test(trimmed)) {
      return 'Name contains invalid characters';
    }
    return null;
  };

  const handleSubmit = useCallback(
    (e: FormEvent) => {
      e.preventDefault();
      const validationError = validate(newName);
      if (validationError) {
        setError(validationError);
        return;
      }
      if (!isLoading) {
        onConfirm(newName.trim());
      }
    },
    [newName, currentName, isLoading, onConfirm]
  );

  const handleCancel = useCallback(() => {
    if (!isLoading) {
      onClose();
    }
  }, [isLoading, onClose]);

  const handleChange = (value: string) => {
    setNewName(value);
    // Clear error when user starts typing
    if (error) {
      setError(null);
    }
  };

  const title = itemType === 'folder' ? 'Rename Folder' : 'Rename File';

  return (
    <Modal open={open} onClose={handleCancel} title={title}>
      <form className="dialog-content" onSubmit={handleSubmit}>
        <div className="dialog-field">
          <label htmlFor="rename-input" className="dialog-label">
            New name
          </label>
          <input
            ref={inputRef}
            id="rename-input"
            type="text"
            className={`dialog-input ${error ? 'dialog-input--error' : ''}`}
            value={newName}
            onChange={(e) => handleChange(e.target.value)}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
          />
          {error && <span className="dialog-error">{error}</span>}
        </div>
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
            type="submit"
            className="dialog-button dialog-button--primary"
            disabled={isLoading || !!validate(newName)}
          >
            {isLoading ? 'Renaming...' : 'Rename'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
