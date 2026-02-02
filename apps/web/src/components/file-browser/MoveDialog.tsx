import { useState, useEffect, useCallback, useMemo, type KeyboardEvent } from 'react';
import type { FolderChild } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFolderStore, type FolderNode } from '../../stores/folder.store';
import { getDepth, isDescendantOf } from '../../services/folder.service';
import '../../styles/dialogs.css';

/** Maximum folder nesting depth per FOLD-03 */
const MAX_FOLDER_DEPTH = 20;

type MoveDialogProps = {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when dialog is closed */
  onClose: () => void;
  /** Callback when move is confirmed with destination folder ID */
  onConfirm: (destinationFolderId: string) => void;
  /** The item being moved */
  item: FolderChild | null;
  /** Current parent folder ID of the item */
  currentFolderId: string;
  /** Loading state - disables buttons */
  isLoading?: boolean;
};

type FolderListItem = {
  id: string;
  name: string;
  depth: number;
  isDisabled: boolean;
  disabledReason?: string;
};

/**
 * Build a flat list of folders for the move dialog.
 * Includes root + all loaded subfolders with depth information.
 */
function buildFolderList(
  folders: Record<string, FolderNode>,
  itemId: string,
  itemType: 'file' | 'folder',
  currentFolderId: string
): FolderListItem[] {
  const result: FolderListItem[] = [];

  // Add root folder
  const rootFolder = folders['root'];
  if (rootFolder) {
    const isCurrentFolder = currentFolderId === 'root';

    result.push({
      id: 'root',
      name: 'My Vault',
      depth: 0,
      isDisabled: isCurrentFolder,
      disabledReason: isCurrentFolder ? 'Item is already here' : undefined,
    });
  }

  // Build sorted list of all folders (excluding root)
  const folderEntries = Object.values(folders).filter((f) => f.id !== 'root');

  // Sort by depth then name for predictable display
  folderEntries.sort((a, b) => {
    const depthA = getDepth(a.id, folders);
    const depthB = getDepth(b.id, folders);
    if (depthA !== depthB) return depthA - depthB;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });

  for (const folder of folderEntries) {
    const depth = getDepth(folder.id, folders);
    let isDisabled = false;
    let disabledReason: string | undefined;

    // Disable if this is the current folder
    if (folder.id === currentFolderId) {
      isDisabled = true;
      disabledReason = 'Item is already here';
    }
    // Disable if moving to self (for folders)
    else if (itemType === 'folder' && folder.id === itemId) {
      isDisabled = true;
      disabledReason = "Can't move folder into itself";
    }
    // Disable if moving folder into its own descendant
    else if (itemType === 'folder' && isDescendantOf(folder.id, itemId, folders)) {
      isDisabled = true;
      disabledReason = "Can't move folder into its subfolder";
    }
    // Disable if depth would exceed limit (for folders with subtrees)
    else if (itemType === 'folder') {
      const itemFolder = folders[itemId];
      if (itemFolder) {
        // Calculate potential new depth: dest depth + 1 (for moved folder) + subtree depth
        const destDepth = depth;
        // For simplicity, assume subtree depth is 0 for validation display
        // Real validation happens on submit
        if (destDepth >= MAX_FOLDER_DEPTH - 1) {
          isDisabled = true;
          disabledReason = 'Would exceed maximum folder depth';
        }
      }
    }

    result.push({
      id: folder.id,
      name: folder.name,
      depth,
      isDisabled,
      disabledReason,
    });
  }

  return result;
}

/**
 * Check if a name already exists in the destination folder.
 */
function checkNameCollision(
  destFolder: FolderNode | undefined,
  itemName: string,
  itemId: string
): boolean {
  if (!destFolder) return false;
  return destFolder.children.some((child) => child.name === itemName && child.id !== itemId);
}

/**
 * Dialog for moving files and folders to a different location.
 *
 * Shows a scrollable list of available folders with depth-based indentation.
 * Disables invalid targets (current location, self, descendants).
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const [moveItem, setMoveItem] = useState<FolderChild | null>(null);
 *
 *   return (
 *     <MoveDialog
 *       open={!!moveItem}
 *       onClose={() => setMoveItem(null)}
 *       onConfirm={(destId) => handleMove(destId)}
 *       item={moveItem}
 *       currentFolderId={currentFolderId}
 *     />
 *   );
 * }
 * ```
 */
export function MoveDialog({
  open,
  onClose,
  onConfirm,
  item,
  currentFolderId,
  isLoading = false,
}: MoveDialogProps) {
  const [selectedFolderId, setSelectedFolderId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Get folders from store
  const folders = useFolderStore((state) => state.folders);

  // Build folder list
  const folderList = useMemo(() => {
    if (!item) return [];
    return buildFolderList(folders, item.id, item.type, currentFolderId);
  }, [folders, item, currentFolderId]);

  // Reset selection when dialog opens
  useEffect(() => {
    if (open) {
      setSelectedFolderId(null);
      setError(null);
    }
  }, [open]);

  // Validate selection
  const validate = useCallback((): string | null => {
    if (!selectedFolderId) {
      return 'Please select a destination folder';
    }

    if (!item) {
      return 'No item selected';
    }

    const selectedItem = folderList.find((f) => f.id === selectedFolderId);
    if (selectedItem?.isDisabled) {
      return selectedItem.disabledReason ?? 'Invalid destination';
    }

    // Check for name collision
    const destFolder = folders[selectedFolderId];
    if (checkNameCollision(destFolder, item.name, item.id)) {
      return `An item named "${item.name}" already exists in the destination`;
    }

    return null;
  }, [selectedFolderId, item, folderList, folders]);

  const handleSubmit = useCallback(() => {
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }

    if (selectedFolderId && !isLoading) {
      onConfirm(selectedFolderId);
    }
  }, [validate, selectedFolderId, isLoading, onConfirm]);

  const handleCancel = useCallback(() => {
    if (!isLoading) {
      onClose();
    }
  }, [isLoading, onClose]);

  const handleSelectFolder = useCallback(
    (folderId: string) => {
      const folderItem = folderList.find((f) => f.id === folderId);
      if (folderItem && !folderItem.isDisabled) {
        setSelectedFolderId(folderId);
        // Clear error when selecting a new folder
        if (error) {
          setError(null);
        }
      }
    },
    [folderList, error]
  );

  const handleKeyDown = useCallback(
    (event: KeyboardEvent, folderId: string) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        handleSelectFolder(folderId);
      }
    },
    [handleSelectFolder]
  );

  const title = item?.type === 'folder' ? 'Move Folder' : 'Move File';
  const isValid = !validate();

  return (
    <Modal open={open} onClose={handleCancel} title={title}>
      <div className="dialog-content">
        <div className="dialog-field">
          <label className="dialog-label">Move "{item?.name}" to:</label>
          <div className="move-dialog-folder-list" role="listbox" aria-label="Select destination">
            {folderList.length === 0 && (
              <div className="move-dialog-empty">No folders available</div>
            )}
            {folderList.map((folder) => (
              <div
                key={folder.id}
                className={`move-dialog-folder-item ${
                  selectedFolderId === folder.id ? 'move-dialog-folder-item--selected' : ''
                } ${folder.isDisabled ? 'move-dialog-folder-item--disabled' : ''}`}
                style={{ paddingLeft: `${12 + folder.depth * 16}px` }}
                onClick={() => handleSelectFolder(folder.id)}
                onKeyDown={(e) => handleKeyDown(e, folder.id)}
                role="option"
                aria-selected={selectedFolderId === folder.id}
                aria-disabled={folder.isDisabled}
                tabIndex={folder.isDisabled ? -1 : 0}
                title={folder.disabledReason}
              >
                <span className="move-dialog-folder-icon">[DIR]</span>
                <span className="move-dialog-folder-name">{folder.name}</span>
              </div>
            ))}
          </div>
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
            type="button"
            className="dialog-button dialog-button--primary"
            onClick={handleSubmit}
            disabled={isLoading || !isValid}
          >
            {isLoading ? 'Moving...' : 'Move'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
