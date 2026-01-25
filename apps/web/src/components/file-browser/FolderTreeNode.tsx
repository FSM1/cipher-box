import { useState, useCallback, type DragEvent } from 'react';
import { useFolderStore, type FolderNode } from '../../stores/folder.store';
import type { FolderChild } from '@cipherbox/crypto';

type FolderTreeNodeProps = {
  /** Folder ID to render */
  folderId: string;
  /** Nesting level (0 for root) */
  level: number;
  /** Currently selected/active folder ID */
  currentFolderId: string;
  /** Callback when folder is clicked */
  onNavigate: (folderId: string) => void;
  /** Callback when item is dropped on this folder */
  onDrop?: (targetFolderId: string, dataTransfer: DataTransfer) => void;
};

/**
 * Recursive folder tree node component.
 *
 * Renders a single folder with expand/collapse toggle and
 * recursively renders child folders.
 *
 * Supports drag-drop operations - acts as a drop target for
 * files and folders being moved.
 */
export function FolderTreeNode({
  folderId,
  level,
  currentFolderId,
  onNavigate,
  onDrop,
}: FolderTreeNodeProps) {
  const [isExpanded, setIsExpanded] = useState(level === 0); // Root expanded by default
  const [isDragOver, setIsDragOver] = useState(false);

  // Get folder from store
  const folders = useFolderStore((state) => state.folders);
  const folder: FolderNode | undefined = folders[folderId];

  // If folder not found in store, don't render
  if (!folder) {
    return null;
  }

  // Get child folders from this folder's children
  const childFolders = folder.children.filter(
    (child): child is FolderChild & { type: 'folder' } => child.type === 'folder'
  );

  const hasChildren = childFolders.length > 0;
  const isActive = currentFolderId === folderId;
  const indent = level * 16;

  /**
   * Toggle expand/collapse state.
   */
  const handleToggle = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    setIsExpanded((prev) => !prev);
  }, []);

  /**
   * Handle folder click - navigate to this folder.
   */
  const handleClick = useCallback(() => {
    onNavigate(folderId);
  }, [folderId, onNavigate]);

  /**
   * Handle drag enter.
   */
  const handleDragEnter = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  /**
   * Handle drag over - allow drop.
   */
  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  /**
   * Handle drag leave.
   */
  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  /**
   * Handle drop.
   */
  const handleDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);
      if (onDrop) {
        onDrop(folderId, e.dataTransfer);
      }
    },
    [folderId, onDrop]
  );

  return (
    <div className="folder-tree-node">
      <div
        className={`folder-tree-item ${isActive ? 'folder-tree-item--active' : ''} ${isDragOver ? 'folder-tree-item--drag-over' : ''}`}
        style={{ paddingLeft: `${indent + 8}px` }}
        onClick={handleClick}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            handleClick();
          }
        }}
      >
        {/* Expand/collapse toggle */}
        <span
          className={`folder-tree-toggle ${hasChildren ? '' : 'folder-tree-toggle--hidden'}`}
          onClick={hasChildren ? handleToggle : undefined}
          role={hasChildren ? 'button' : undefined}
          tabIndex={hasChildren ? 0 : undefined}
          onKeyDown={
            hasChildren
              ? (e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    handleToggle(e as unknown as React.MouseEvent);
                  }
                }
              : undefined
          }
        >
          {hasChildren ? (isExpanded ? '▼' : '▶') : ''}
        </span>

        {/* Folder icon */}
        <span className="folder-tree-icon">[DIR]</span>

        {/* Folder name */}
        <span className="folder-tree-name">{folder.name}</span>

        {/* Loading indicator */}
        {folder.isLoading && <span className="folder-tree-loading">...</span>}
      </div>

      {/* Recursively render child folders */}
      {isExpanded && hasChildren && (
        <div className="folder-tree-children">
          {childFolders.map((childFolder) => (
            <FolderTreeNode
              key={childFolder.id}
              folderId={childFolder.id}
              level={level + 1}
              currentFolderId={currentFolderId}
              onNavigate={onNavigate}
              onDrop={onDrop}
            />
          ))}
        </div>
      )}
    </div>
  );
}
