import { Fragment, useState, useCallback, type DragEvent } from 'react';
import type { Breadcrumb } from '../../hooks/useFolderNavigation';

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
export function Breadcrumbs({ breadcrumbs, onNavigate, onDrop }: BreadcrumbsProps) {
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
    (event: React.KeyboardEvent, folderId: string) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        onNavigate(folderId);
      }
    },
    [onNavigate]
  );

  /**
   * Handle drag over breadcrumb segment.
   */
  const handleDragOver = useCallback(
    (e: DragEvent, folderId: string) => {
      if (!onDrop) return;
      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = 'move';
      setDragOverId(folderId);
    },
    [onDrop]
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
   */
  const handleDrop = useCallback(
    (e: DragEvent, destFolderId: string) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOverId(null);

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
    [onDrop]
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
              onDragOver={onDrop ? (e) => handleDragOver(e, crumb.id) : undefined}
              onDragLeave={onDrop ? handleDragLeave : undefined}
              onDrop={onDrop ? (e) => handleDrop(e, crumb.id) : undefined}
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
