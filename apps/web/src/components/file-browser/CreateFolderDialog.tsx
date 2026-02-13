import { useState, useEffect, useRef, useCallback, type FormEvent } from 'react';
import { Modal } from '../ui/Modal';
import '../../styles/dialogs.css';

type CreateFolderDialogProps = {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when dialog is closed (cancel or backdrop click) */
  onClose: () => void;
  /** Callback when folder creation is confirmed */
  onConfirm: (name: string) => void;
  /** Loading state - disables buttons */
  isLoading?: boolean;
};

/**
 * Dialog for creating new folders.
 *
 * Shows an input field for the folder name, validates that name is not empty
 * and doesn't contain invalid characters.
 *
 * @example
 * ```tsx
 * function NewFolderButton() {
 *   const [isOpen, setIsOpen] = useState(false);
 *   const { createFolder } = useFolder();
 *
 *   return (
 *     <>
 *       <button onClick={() => setIsOpen(true)}>New Folder</button>
 *       <CreateFolderDialog
 *         open={isOpen}
 *         onClose={() => setIsOpen(false)}
 *         onConfirm={async (name) => {
 *           await createFolder(name, currentFolderId);
 *           setIsOpen(false);
 *         }}
 *       />
 *     </>
 *   );
 * }
 * ```
 */
export function CreateFolderDialog({
  open,
  onClose,
  onConfirm,
  isLoading = false,
}: CreateFolderDialogProps) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset form when dialog opens
  useEffect(() => {
    if (open) {
      setName('');
      setError(null);
      // Focus input after render
      setTimeout(() => {
        inputRef.current?.focus();
      }, 0);
    }
  }, [open]);

  const validate = (value: string): string | null => {
    const trimmed = value.trim();
    if (!trimmed) {
      return 'Name cannot be empty';
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
      const validationError = validate(name);
      if (validationError) {
        setError(validationError);
        return;
      }
      if (!isLoading) {
        onConfirm(name.trim());
      }
    },
    [name, isLoading, onConfirm]
  );

  const handleCancel = useCallback(() => {
    if (!isLoading) {
      onClose();
    }
  }, [isLoading, onClose]);

  const handleChange = (value: string) => {
    setName(value);
    // Clear error when user starts typing
    if (error) {
      setError(null);
    }
  };

  return (
    <Modal open={open} onClose={handleCancel} title="New Folder">
      <form className="dialog-content" onSubmit={handleSubmit}>
        <div className="dialog-field">
          <label htmlFor="folder-name-input" className="dialog-label">
            Folder name
          </label>
          <input
            ref={inputRef}
            id="folder-name-input"
            type="text"
            className={`dialog-input ${error ? 'dialog-input--error' : ''}`}
            value={name}
            onChange={(e) => handleChange(e.target.value)}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
            placeholder="Enter folder name"
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
            disabled={isLoading || !!validate(name)}
          >
            {isLoading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
