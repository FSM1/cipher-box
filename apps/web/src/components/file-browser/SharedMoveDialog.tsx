import { useState, useEffect, useCallback, useMemo, useRef, type KeyboardEvent } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { Modal } from '../ui/Modal';
import { getSdkClient } from '../../lib/sdk-provider';
import { isFileRefResolved } from '../../utils/fileTypes';
import '../../styles/dialogs.css';

type SharedPickerNode = {
  id: string;
  name: string;
  ipnsName: string;
  writable: boolean;
  /** Containing folder id (null for share-root children) — used for the cycle guard. */
  parentId: string | null;
};

type SharedMoveDialogProps = {
  /** Whether the dialog is open */
  open: boolean;
  /** Callback when dialog is closed */
  onClose: () => void;
  /** Callback when move is confirmed with destination folder ID and IPNS name */
  onConfirm: (destFolderId: string, destIpnsName: string) => void;
  /** The item being moved (single-item mode) */
  item: SealedChildRef | null;
  /** Multiple items being moved (batch mode — takes precedence over item when length > 1) */
  items?: SealedChildRef[];
  /** Resolved-kind lookup for the item(s) being moved, keyed by ipnsName. */
  resolvedByIpnsName: Map<string, ResolvedChild>;
  /** Current parent folder ID of the item(s) (disabled as a destination) */
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
  items,
  resolvedByIpnsName,
  currentFolderId,
  shareId,
  isLoading = false,
}: SharedMoveDialogProps) {
  // Batch mode when items prop is provided with more than one item
  const isBatchMode = Array.isArray(items) && items.length > 1;
  const [pickerNodes, setPickerNodes] = useState<SharedPickerNode[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isLoadingTree, setIsLoadingTree] = useState(false);

  // Ref for async-ref safety: re-check after each await
  const openRef = useRef(open);
  openRef.current = open;

  // Reset on close; load the shared subtree on open.
  useEffect(() => {
    if (!open) {
      setSelectedId(null);
      setLoadError(null);
      setPickerNodes([]);
      return;
    }
    if (!shareId) return;

    setIsLoadingTree(true);
    setLoadError(null);
    setPickerNodes([]);
    setSelectedId(null);

    getSdkClient()
      .enumerateSharedSubtree(shareId)
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

  // Folders being moved (only folders can create a cycle); their own subtree
  // must be excluded as a destination. A file cannot create a folder cycle, so
  // it must not disable any destinations here.
  const movedFolderIds = useMemo(() => {
    const moved = isBatchMode ? (items ?? []) : item ? [item] : [];
    return new Set(
      moved.filter((m) => !isFileRefResolved(m, resolvedByIpnsName)).map((m) => m.ipnsName)
    );
  }, [isBatchMode, items, item, resolvedByIpnsName]);

  // A moved folder and every node beneath it cannot be a destination — moving a
  // folder into its own subtree would orphan/cycle the tree.
  const disabledDestIds = useMemo(() => {
    const disabled = new Set(movedFolderIds);
    if (movedFolderIds.size === 0) return disabled;
    const byId = new Map(pickerNodes.map((n) => [n.id, n]));
    for (const node of pickerNodes) {
      let ancestor = node.parentId;
      while (ancestor) {
        if (movedFolderIds.has(ancestor)) {
          disabled.add(node.id);
          break;
        }
        ancestor = byId.get(ancestor)?.parentId ?? null;
      }
    }
    return disabled;
  }, [pickerNodes, movedFolderIds]);

  const isNodeDisabled = useCallback(
    (node: SharedPickerNode) =>
      !node.writable || node.id === currentFolderId || disabledDestIds.has(node.id),
    [currentFolderId, disabledDestIds]
  );

  const handleSelectNode = useCallback(
    (node: SharedPickerNode) => {
      if (isNodeDisabled(node)) return;
      setSelectedId(node.id);
    },
    [isNodeDisabled]
  );

  const handleKeyDown = useCallback(
    (e: KeyboardEvent, node: SharedPickerNode) => {
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

  // Auto-adapt title/label for batch vs single mode (mirrors private MoveDialog :174-179).
  // Single-item title reflects the moved item's real kind — a shared file move
  // must not read "Move Folder".
  const title = isBatchMode
    ? `Move ${items!.length} items`
    : item && isFileRefResolved(item, resolvedByIpnsName)
      ? 'Move File'
      : 'Move Folder';
  const label = isBatchMode
    ? `Move ${items!.length} items to:`
    : item
      ? `Move "${item.name}" to:`
      : 'Move to:';

  // selectedId is only ever set by handleSelectNode, which refuses disabled
  // nodes — so a resolved selectedNode is always a valid destination.
  const selectedNode = pickerNodes.find((n) => n.id === selectedId);
  const isValid = !!selectedNode;

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
                const isDisabled = isNodeDisabled(node);
                const isSelected = selectedId === node.id;
                const disabledReason = !node.writable
                  ? 'Read-only folder'
                  : node.id === currentFolderId
                    ? 'Item is already here'
                    : disabledDestIds.has(node.id)
                      ? 'Cannot move into itself or a subfolder'
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
                    role="option"
                    tabIndex={isDisabled ? -1 : 0}
                    aria-disabled={isDisabled}
                    aria-selected={isSelected}
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
