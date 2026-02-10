import { Fragment, useState, useCallback, type DragEvent, type KeyboardEvent } from 'react';
import type { Breadcrumb } from '../../hooks/useFolderNavigation';
import { isExternalFileDrag } from '../../hooks/useDropUpload';

type BreadcrumbsProps = {
  /** Breadcrumb trail from root to current folder */
  breadcrumbs: Breadcrumb[];
  /** Callback to navigate to a folder */
  onNavigate: (folderId: string) => void;
  /** @deprecated Callback to navigate up - use onNavigate with parent ID instead */
  onNavigateUp?: () => void;
  /** Callback when an item is dropped onto a breadcrumb segment */
  onDrop?: (
    sourceId: string,
    sourceType: 'file' | 'folder',
    sourceParentId: string,
    destFolderId: string
  ) => void;
  /** Callback when external files are dropped onto a breadcrumb segment */
  onExternalFileDrop?: (files: File[], destFolderId: string) => void;
};

/**
 * Interactive breadcrumb navigation component.
 *
 * Features:
 * - Clickable segments to navigate to any parent folder
 * - Drop targets on each segment for quick moves to parent folders
 * - Terminal-style path format: ~/root/documents/projects
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { breadcrumbs, navigateTo, navigateUp } = useFolderNavigation();
 *   const { moveItem } = useFolder();
 *
 *   const handleDrop = (sourceId, sourceType, sourceParentId, destFolderId) => {
 *     moveItem(sourceId, sourceType, sourceParentId, destFolderId);
 *   };
 *
 *   return (
 *     <Breadcrumbs
 *       breadcrumbs={breadcrumbs}
 *       onNavigate={navigateTo}
 *       onNavigateUp={navigateUp}
 *       onDrop={handleDrop}
 *     />
 *   );
 * }
 * ```
 */
export function Breadcrumbs({
  breadcrumbs,
  onNavigate,
  onDrop,
  onExternalFileDrop,
}: BreadcrumbsProps) {
  // Track which breadcrumb is being dragged over
  const [dragOverId, setDragOverId] = useState<string | null>(null);

  /**
   * Handle click on breadcrumb segment.
   */
  const handleClick = useCallback(
    (folderId: string) => {
      onNavigate(folderId);
    },
    [onNavigate]
  );

  /**
   * Handle keyboard navigation.
   */
  const handleKeyDown = useCallback(
    (event: KeyboardEvent, folderId: string) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        onNavigate(folderId);
      }
    },
    [onNavigate]
  );

  /**
   * Handle drag over breadcrumb segment.
   * Accepts both internal drags (move) and external file drags (upload).
   */
  const handleDragOver = useCallback(
    (e: DragEvent, folderId: string) => {
      if (!onDrop && !onExternalFileDrop) return;
      e.preventDefault();
      e.stopPropagation();

      e.dataTransfer.dropEffect = isExternalFileDrag(e.dataTransfer) ? 'copy' : 'move';
      setDragOverId(folderId);
    },
    [onDrop, onExternalFileDrop]
  );

  /**
   * Handle drag leave breadcrumb segment.
   */
  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverId(null);
  }, []);

  /**
   * Handle drop on breadcrumb segment.
   * Routes external files to upload, internal items to move.
   */
  const handleDrop = useCallback(
    (e: DragEvent, destFolderId: string) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOverId(null);

      // Check for external file drop first
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const jsonData = e.dataTransfer.getData('application/json');
        if (!jsonData && onExternalFileDrop) {
          const files = Array.from(e.dataTransfer.files);
          onExternalFileDrop(files, destFolderId);
          return;
        }
      }

      // Internal move operation
      if (!onDrop) return;

      try {
        const data = e.dataTransfer.getData('application/json');
        if (!data) return;

        const parsed = JSON.parse(data) as {
          id: string;
          type: 'file' | 'folder';
          parentId: string;
        };

        // Don't allow dropping onto self
        if (parsed.id === destFolderId) return;

        // Don't allow dropping if already in this folder
        if (parsed.parentId === destFolderId) return;

        onDrop(parsed.id, parsed.type, parsed.parentId, destFolderId);
      } catch {
        // Invalid drag data, ignore
      }
    },
    [onDrop, onExternalFileDrop]
  );

  // Handle empty breadcrumbs
  if (breadcrumbs.length === 0) {
    return (
      <nav className="breadcrumb-nav" aria-label="Current location" data-testid="breadcrumbs">
        <span className="breadcrumb-prefix">~</span>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-text">root</span>
      </nav>
    );
  }

  return (
    <nav className="breadcrumb-nav" aria-label="Current location" data-testid="breadcrumbs">
      <span className="breadcrumb-prefix">~</span>
      <span className="breadcrumb-separator">/</span>
      {breadcrumbs.map((crumb, index) => {
        const isLast = index === breadcrumbs.length - 1;
        const isDragOver = dragOverId === crumb.id;

        return (
          <Fragment key={crumb.id}>
            <button
              type="button"
              className={`breadcrumb-item ${isDragOver ? 'breadcrumb-item--drag-over' : ''} ${isLast ? 'breadcrumb-item--current' : ''}`}
              onClick={() => handleClick(crumb.id)}
              onKeyDown={(e) => handleKeyDown(e, crumb.id)}
              onDragOver={
                onDrop || onExternalFileDrop ? (e) => handleDragOver(e, crumb.id) : undefined
              }
              onDragLeave={onDrop || onExternalFileDrop ? handleDragLeave : undefined}
              onDrop={onDrop || onExternalFileDrop ? (e) => handleDrop(e, crumb.id) : undefined}
              aria-current={isLast ? 'page' : undefined}
              data-folder-id={crumb.id}
            >
              {crumb.name.toLowerCase()}
            </button>
            {!isLast && <span className="breadcrumb-separator">/</span>}
          </Fragment>
        );
      })}
    </nav>
  );
}
