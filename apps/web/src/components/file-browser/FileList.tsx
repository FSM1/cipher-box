import { type DragEvent, type MouseEvent } from 'react';
import type { FolderChild } from '@cipherbox/crypto';
import { FileListItem, type DragItem } from './FileListItem';
import { ParentDirRow } from './ParentDirRow';

type FileListProps = {
  /** Items to display (files and folders) */
  items: FolderChild[];
  /** Set of currently selected item IDs */
  selectedIds: Set<string>;
  /** Parent folder ID (for drag operations) */
  parentId: string;
  /** Whether to show [..] PARENT_DIR row (non-root folders) */
  showParentRow?: boolean;
  /** Callback when [..] row is clicked to navigate up */
  onNavigateUp?: () => void;
  /** Callback when an item is selected (with modifier key info) */
  onSelect: (
    itemId: string,
    event: { ctrlKey: boolean; shiftKey: boolean; metaKey: boolean }
  ) => void;
  /** Callback to select/deselect all items */
  onSelectAll: () => void;
  /** Callback when navigating into a folder */
  onNavigate: (folderId: string) => void;
  /** Callback when context menu is requested */
  onContextMenu: (event: MouseEvent, item: FolderChild) => void;
  /** Callback when drag starts */
  onDragStart: (event: DragEvent, item: FolderChild) => void;
  /** Callback when items are dropped onto a folder */
  onDropOnFolder?: (items: DragItem[], sourceParentId: string, destFolderId: string) => void;
  /** Callback when external files are dropped onto a folder */
  onExternalFileDrop?: (files: File[], destFolderId: string) => void;
};

/**
 * Sort items: folders first, then files, both alphabetically.
 */
function sortItems(items: FolderChild[]): FolderChild[] {
  return [...items].sort((a, b) => {
    // Folders come first
    if (a.type === 'folder' && b.type !== 'folder') return -1;
    if (a.type !== 'folder' && b.type === 'folder') return 1;

    // Within same type, sort alphabetically (case-insensitive)
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}

/**
 * File list component displaying files and folders in a columnar layout.
 *
 * Renders items sorted by type (folders first) then alphabetically.
 * Supports selection, navigation, context menu, and drag operations.
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { currentFolder } = useFolderNavigation();
 *   const [selectedId, setSelectedId] = useState<string | null>(null);
 *
 *   return (
 *     <FileList
 *       items={currentFolder?.children ?? []}
 *       selectedId={selectedId}
 *       parentId={currentFolder?.id ?? 'root'}
 *       onSelect={setSelectedId}
 *       onNavigate={navigateTo}
 *       onContextMenu={handleContextMenu}
 *       onDragStart={handleDragStart}
 *     />
 *   );
 * }
 * ```
 */
export function FileList({
  items,
  selectedIds,
  parentId,
  showParentRow,
  onNavigateUp,
  onSelect,
  onSelectAll,
  onNavigate,
  onContextMenu,
  onDragStart,
  onDropOnFolder,
  onExternalFileDrop,
}: FileListProps) {
  const sortedItems = sortItems(items);
  const allSelected = items.length > 0 && selectedIds.size === items.length;

  return (
    <div className="file-list" role="grid">
      {/* Header row */}
      <div className="file-list-header" role="row">
        <div className="file-list-header-name" role="columnheader">
          <span
            className="file-list-header-checkbox"
            onClick={onSelectAll}
            role="checkbox"
            aria-checked={allSelected}
            aria-label={allSelected ? 'Deselect all' : 'Select all'}
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onSelectAll();
              }
            }}
          >
            {allSelected ? '[x]' : '[ ]'}
          </span>
          [NAME]
        </div>
        <div className="file-list-header-size" role="columnheader">
          [SIZE]
        </div>
        <div className="file-list-header-date" role="columnheader">
          [MODIFIED]
        </div>
        {/* Empty header cell for mobile action column - hidden on desktop via CSS */}
        <div className="file-list-header-actions" role="columnheader" aria-hidden="true" />
      </div>

      {/* Item rows */}
      <div className="file-list-body" role="rowgroup">
        {showParentRow && onNavigateUp && <ParentDirRow onActivate={onNavigateUp} />}
        {sortedItems.map((item) => (
          <FileListItem
            key={item.id}
            item={item}
            isSelected={selectedIds.has(item.id)}
            parentId={parentId}
            selectedIds={selectedIds}
            allItems={items}
            onSelect={onSelect}
            onNavigate={onNavigate}
            onContextMenu={onContextMenu}
            onDragStart={onDragStart}
            onDrop={
              onDropOnFolder && item.type === 'folder'
                ? (dragItems, sourceParentId) => onDropOnFolder(dragItems, sourceParentId, item.id)
                : undefined
            }
            onExternalFileDrop={item.type === 'folder' ? onExternalFileDrop : undefined}
          />
        ))}
      </div>
    </div>
  );
}
