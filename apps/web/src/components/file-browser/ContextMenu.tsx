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
  /** Callback to close the menu */
  onClose: () => void;
  /** Callback when download is clicked (files only) */
  onDownload?: () => void;
  /** Callback when rename is clicked */
  onRename: () => void;
  /** Callback when delete is clicked */
  onDelete: () => void;
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
 * - Delete
 */
export function ContextMenu({
  x,
  y,
  item,
  onClose,
  onDownload,
  onRename,
  onDelete,
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

  const handleRename = () => {
    onRename();
    onClose();
  };

  const handleDelete = () => {
    onDelete();
    onClose();
  };

  // Combine refs for menu
  const setMenuRef = (node: HTMLDivElement | null) => {
    menuRef.current = node;
    refs.setFloating(node);
  };

  return (
    <Portal>
      <div
        ref={setMenuRef}
        className="context-menu"
        style={floatingStyles}
        role="menu"
        aria-label={`Actions for ${item.name}`}
      >
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

        {/* Rename */}
        <button type="button" className="context-menu-item" onClick={handleRename} role="menuitem">
          <span className="context-menu-item-icon">&#9998;</span>
          Rename
        </button>

        {/* Divider before destructive action */}
        <div className="context-menu-divider" role="separator" />

        {/* Delete */}
        <button
          type="button"
          className="context-menu-item context-menu-item--destructive"
          onClick={handleDelete}
          role="menuitem"
        >
          <span className="context-menu-item-icon">&#128465;</span>
          Delete
        </button>
      </div>
    </Portal>
  );
}
