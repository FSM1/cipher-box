import { useState, useEffect, useCallback, useRef } from 'react';
import type { FolderChild } from '@cipherbox/core';
import { Modal } from '../ui/Modal';
import { getSdkClient } from '../../lib/sdk-provider';
import { useAuthStore } from '../../stores/auth.store';
import { fetchShareKeys } from '../../services/share.service';
import '../../styles/dialogs.css';

type SharedPickerNode = {
  id: string;
  name: string;
  ipnsName: string;
  writable: boolean;
};

type SharedMoveDialogProps = {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when dialog is closed */
  onClose: () => void;
  /** Callback when move is confirmed with destination folder ID and IPNS name */
  onConfirm: (destFolderId: string, destIpnsName: string) => void;
  /** The item being moved */
  item: FolderChild | null;
  /** Current parent folder ID of the item (disabled as a destination) */
  currentFolderId: string;
  /** Active share ID (required to load the subtree) */
  shareId: string | null;
  /** Loading state from the caller — disables confirm button */
  isLoading?: boolean;
};

/**
 * Destination picker dialog for intra-share file moves.
 *
 * Loads the full shared subtree via enumerateSharedSubtree on open. Disables
 * read-only folders (writable === false) and the current folder so the
 * recipient cannot select invalid destinations. The caller owns the move call
 * (moveItemHandler) and the post-move state refresh (sharedFolder:updated
 * projection — this component reads nothing back).
 */
export function SharedMoveDialog({
  open,
  onClose,
  onConfirm,
  item,
  currentFolderId,
  shareId,
  isLoading = false,
}: SharedMoveDialogProps) {
  const [pickerNodes, setPickerNodes] = useState<SharedPickerNode[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isLoadingTree, setIsLoadingTree] = useState(false);

  // Ref for async-ref safety: re-check after each await
  const openRef = useRef(open);
  openRef.current = open;

  // Load the shared subtree when the dialog opens
  useEffect(() => {
    if (!open || !shareId) return;
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) return;

    setIsLoadingTree(true);
    setLoadError(null);
    setPickerNodes([]);
    setSelectedId(null);

    getSdkClient()
      .enumerateSharedSubtree(shareId, {
        getShareKeysFn: fetchShareKeys,
        vaultPrivateKey: auth.vaultKeypair.privateKey,
      })
      .then((nodes) => {
        // Re-check after await: dialog may have been closed
        if (!openRef.current) return;
        setPickerNodes(nodes);
      })
      .catch(() => {
        if (!openRef.current) return;
        setLoadError('Failed to load folder tree');
      })
      .finally(() => {
        if (!openRef.current) return;
        setIsLoadingTree(false);
      });
  }, [open, shareId]);

  // Reset state when dialog closes
  useEffect(() => {
    if (!open) {
      setSelectedId(null);
      setLoadError(null);
      setPickerNodes([]);
    }
  }, [open]);

  const handleSelectNode = useCallback(
    (node: SharedPickerNode) => {
      const isDisabled = !node.writable || node.id === currentFolderId;
      if (isDisabled) return;
      setSelectedId(node.id);
    },
    [currentFolderId]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent, node: SharedPickerNode) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleSelectNode(node);
      }
    },
    [handleSelectNode]
  );

  const handleConfirm = useCallback(() => {
    if (!selectedId) return;
    const node = pickerNodes.find((n) => n.id === selectedId);
    if (!node) return;
    onConfirm(node.id, node.ipnsName);
  }, [selectedId, pickerNodes, onConfirm]);

  const handleCancel = useCallback(() => {
    if (!isLoading) {
      onClose();
    }
  }, [isLoading, onClose]);

  const title = item?.type === 'folder' ? 'Move Folder' : 'Move File';
  const label = item ? `Move "${item.name}" to:` : 'Move to:';

  const selectedNode = pickerNodes.find((n) => n.id === selectedId);
  const isValid = !!selectedNode && selectedNode.writable && selectedNode.id !== currentFolderId;

  return (
    <Modal open={open} onClose={handleCancel} title={title}>
      <div className="dialog-content">
        <div className="dialog-field">
          <label className="dialog-label">{label}</label>

          {isLoadingTree && (
            <div className="move-dialog-empty">{'// loading shared folders...'}</div>
          )}

          {loadError && <span className="dialog-error">{loadError}</span>}

          {!isLoadingTree && !loadError && (
            <div
              className="move-dialog-folder-list"
              role="listbox"
              aria-label="Select destination folder"
            >
              {pickerNodes.length === 0 && (
                <div className="move-dialog-empty">No writable folders available</div>
              )}
              {pickerNodes.map((node) => {
                const isDisabled = !node.writable || node.id === currentFolderId;
                const isSelected = selectedId === node.id;
                const disabledReason = !node.writable
                  ? 'Read-only folder'
                  : node.id === currentFolderId
                    ? 'Item is already here'
                    : undefined;

                return (
                  <div
                    key={node.id}
                    className={[
                      'move-dialog-folder-item',
                      'shared-move-dialog-folder-item',
                      isSelected ? 'move-dialog-folder-item--selected' : '',
                      isDisabled ? 'move-dialog-folder-item--disabled' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    role="button"
                    tabIndex={isDisabled ? -1 : 0}
                    aria-disabled={isDisabled}
                    aria-pressed={isSelected}
                    title={disabledReason}
                    onClick={() => handleSelectNode(node)}
                    onKeyDown={(e) => handleKeyDown(e, node)}
                  >
                    <span className="move-dialog-folder-icon">[DIR]</span>
                    <span className="move-dialog-folder-name">{node.name}</span>
                    {!node.writable && (
                      <span className="shared-move-dialog-readonly-badge">{'[RO]'}</span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
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
            onClick={handleConfirm}
            disabled={isLoading || !isValid}
          >
            {isLoading ? 'Moving...' : 'Move'}
          </button>
        </div>
      </div>
    </Modal>
  );
}
