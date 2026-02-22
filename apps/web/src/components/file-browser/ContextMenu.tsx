import { useRef, useEffect, useMemo } from 'react';
import {
  useFloating,
  offset,
  flip,
  shift,
  autoUpdate,
  type VirtualElement,
} from '@floating-ui/react';
import type { FolderChild } from '@cipherbox/crypto';
import { Portal } from '../ui/Portal';
import '../../styles/context-menu.css';

type ContextMenuProps = {
  /** X position (client coordinates) */
  x: number;
  /** Y position (client coordinates) */
  y: number;
  /** The file or folder item */
  item: FolderChild;
  /** Number of selected items (for multi-selection context) */
  selectedCount: number;
  /** Callback to close the menu */
  onClose: () => void;
  /** Callback when download is clicked (files only) */
  onDownload?: () => void;
  /** Callback when edit is clicked (text files only) */
  onEdit?: () => void;
  /** Callback when preview is clicked (image, PDF, audio, video files) */
  onPreview?: () => void;
  /** Callback when rename is clicked */
  onRename: () => void;
  /** Callback when move is clicked */
  onMove?: () => void;
  /** Callback when share is clicked */
  onShare?: () => void;
  /** Callback when delete is clicked */
  onDelete: () => void;
  /** Callback when details is clicked */
  onDetails: () => void;
  /** Callback for batch download (multi-selection) */
  onBatchDownload?: () => void;
  /** Callback for batch move (multi-selection) */
  onBatchMove?: () => void;
  /** Callback for batch delete (multi-selection) */
  onBatchDelete?: () => void;
  /** Read-only mode: hides Rename, Move, Delete, Edit, Share actions */
  readOnly?: boolean;
  /** Callback when hide is clicked (shared items -- removes from view) */
  onHide?: () => void;
};

/**
 * Context menu for file/folder actions.
 *
 * Uses @floating-ui/react for positioning with edge detection.
 * Renders in a portal to avoid z-index and overflow issues.
 *
 * Actions:
 * - Download (files only)
 * - Rename
 * - Details
 * - Delete
 */
export function ContextMenu({
  x,
  y,
  item,
  selectedCount,
  onClose,
  onDownload,
  onEdit,
  onPreview,
  onRename,
  onMove,
  onShare,
  onDelete,
  onDetails,
  onBatchDownload,
  onBatchMove,
  onBatchDelete,
  readOnly,
  onHide,
}: ContextMenuProps) {
  const menuRef = useRef<HTMLDivElement | null>(null);
  const isFile = item.type === 'file';

  // Create virtual reference element at click position
  const virtualReference = useMemo<VirtualElement>(
    () => ({
      getBoundingClientRect() {
        return {
          x,
          y,
          top: y,
          left: x,
          bottom: y,
          right: x,
          width: 0,
          height: 0,
        };
      },
    }),
    [x, y]
  );

  const { refs, floatingStyles } = useFloating({
    placement: 'bottom-start',
    middleware: [offset(4), flip({ padding: 8 }), shift({ padding: 8 })],
    whileElementsMounted: autoUpdate,
  });

  // Set the virtual reference
  useEffect(() => {
    refs.setReference(virtualReference);
  }, [refs, virtualReference]);

  // Handle click outside to close
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    // Use capture phase to handle before other click handlers
    document.addEventListener('mousedown', handleClickOutside, true);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside, true);
    };
  }, [onClose]);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [onClose]);

  // Focus the menu on mount for keyboard accessibility
  useEffect(() => {
    const firstButton = menuRef.current?.querySelector('button');
    firstButton?.focus();
  }, []);

  const handleDownload = () => {
    onDownload?.();
    onClose();
  };

  const handleEdit = () => {
    onEdit?.();
    onClose();
  };

  const handlePreview = () => {
    onPreview?.();
    onClose();
  };

  const handleRename = () => {
    onRename();
    onClose();
  };

  const handleMove = () => {
    onMove?.();
    onClose();
  };

  const handleShare = () => {
    onShare?.();
    onClose();
  };

  const handleDelete = () => {
    onDelete();
    onClose();
  };

  const handleDetails = () => {
    onDetails();
    onClose();
  };

  const handleBatchDownload = () => {
    onBatchDownload?.();
    onClose();
  };

  const handleBatchMove = () => {
    onBatchMove?.();
    onClose();
  };

  const handleBatchDelete = () => {
    onBatchDelete?.();
    onClose();
  };

  const handleHide = () => {
    onHide?.();
    onClose();
  };

  // Combine refs for menu
  const setMenuRef = (node: HTMLDivElement | null) => {
    menuRef.current = node;
    refs.setFloating(node);
  };

  // Multi-selection mode: show batch actions
  const isMultiSelect = selectedCount > 1;

  return (
    <Portal>
      <div
        ref={setMenuRef}
        className="context-menu"
        style={floatingStyles}
        role="menu"
        aria-label={
          isMultiSelect ? `Actions for ${selectedCount} items` : `Actions for ${item.name}`
        }
      >
        {isMultiSelect ? (
          <>
            {/* Multi-selection header */}
            <div className="context-menu-header">{selectedCount} items selected</div>
            <div className="context-menu-divider" role="separator" />

            {/* Batch Download */}
            {onBatchDownload && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleBatchDownload}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#8595;</span>
                Download files
              </button>
            )}

            {/* Batch Move */}
            {onBatchMove && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleBatchMove}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#8594;</span>
                Move to...
              </button>
            )}

            {/* Divider before destructive action */}
            <div className="context-menu-divider" role="separator" />

            {/* Batch Delete */}
            {onBatchDelete && (
              <button
                type="button"
                className="context-menu-item context-menu-item--destructive"
                onClick={handleBatchDelete}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#128465;</span>
                Delete {selectedCount} items
              </button>
            )}
          </>
        ) : (
          <>
            {/* Download - files only */}
            {isFile && onDownload && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleDownload}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#8595;</span>
                Download
              </button>
            )}

            {/* Edit - text files only */}
            {isFile && onEdit && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleEdit}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#9998;</span>
                Edit
              </button>
            )}

            {/* Preview - image files only */}
            {isFile && onPreview && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handlePreview}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#128444;</span>
                Preview
              </button>
            )}

            {/* Rename - hidden in readOnly mode */}
            {!readOnly && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleRename}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#9998;</span>
                Rename
              </button>
            )}

            {/* Move to... - hidden in readOnly mode */}
            {!readOnly && onMove && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleMove}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#8594;</span>
                Move to...
              </button>
            )}

            {/* Share - hidden in readOnly mode */}
            {!readOnly && onShare && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleShare}
                role="menuitem"
              >
                <span className="context-menu-item-icon">@</span>
                Share
              </button>
            )}

            {/* Details */}
            <button
              type="button"
              className="context-menu-item"
              onClick={handleDetails}
              role="menuitem"
            >
              <span className="context-menu-item-icon">&#9432;</span>
              Details
            </button>

            {/* Hide - shared items only */}
            {readOnly && onHide && (
              <button
                type="button"
                className="context-menu-item"
                onClick={handleHide}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#10005;</span>
                Hide
              </button>
            )}

            {/* Divider before destructive action - only if delete is shown */}
            {!readOnly && <div className="context-menu-divider" role="separator" />}

            {/* Delete - hidden in readOnly mode */}
            {!readOnly && (
              <button
                type="button"
                className="context-menu-item context-menu-item--destructive"
                onClick={handleDelete}
                role="menuitem"
              >
                <span className="context-menu-item-icon">&#128465;</span>
                Delete
              </button>
            )}
          </>
        )}
      </div>
    </Portal>
  );
}
