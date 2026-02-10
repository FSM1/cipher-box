import { type DragEvent, type MouseEvent } from 'react';
import type { FolderChild } from '@cipherbox/crypto';
import { FileListItem } from './FileListItem';
import { ParentDirRow } from './ParentDirRow';

type FileListProps = {
  /** Items to display (files and folders) */
  items: FolderChild[];
  /** Currently selected item ID */
  selectedId: string | null;
  /** Parent folder ID (for drag operations) */
  parentId: string;
  /** Whether to show [..] PARENT_DIR row (non-root folders) */
  showParentRow?: boolean;
  /** Callback when [..] row is clicked to navigate up */
  onNavigateUp?: () => void;
  /** Callback when an item is selected */
  onSelect: (itemId: string) => void;
  /** Callback when navigating into a folder */
  onNavigate: (folderId: string) => void;
  /** Callback when context menu is requested */
  onContextMenu: (event: MouseEvent, item: FolderChild) => void;
  /** Callback when drag starts */
  onDragStart: (event: DragEvent, item: FolderChild) => void;
  /** Callback when an item is dropped onto a folder */
  onDropOnFolder?: (
    sourceId: string,
    sourceType: 'file' | 'folder',
    sourceParentId: string,
    destFolderId: string
  ) => void;
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
  selectedId,
  parentId,
  showParentRow,
  onNavigateUp,
  onSelect,
  onNavigate,
  onContextMenu,
  onDragStart,
  onDropOnFolder,
  onExternalFileDrop,
}: FileListProps) {
  const sortedItems = sortItems(items);

  return (
    <div className="file-list" role="grid">
      {/* Header row */}
      <div className="file-list-header" role="row">
        <div className="file-list-header-name" role="columnheader">
          [NAME]
        </div>
        <div className="file-list-header-size" role="columnheader">
          [SIZE]
        </div>
        <div className="file-list-header-date" role="columnheader">
          [MODIFIED]
        </div>
      </div>

      {/* Item rows */}
      <div className="file-list-body" role="rowgroup">
        {showParentRow && onNavigateUp && <ParentDirRow onClick={onNavigateUp} />}
        {sortedItems.map((item) => (
          <FileListItem
            key={item.id}
            item={item}
            isSelected={selectedId === item.id}
            parentId={parentId}
            onSelect={onSelect}
            onNavigate={onNavigate}
            onContextMenu={onContextMenu}
            onDragStart={onDragStart}
            onDrop={
              onDropOnFolder && item.type === 'folder'
                ? (sourceId, sourceType, sourceParentId) =>
                    onDropOnFolder(sourceId, sourceType, sourceParentId, item.id)
                : undefined
            }
            onExternalFileDrop={item.type === 'folder' ? onExternalFileDrop : undefined}
          />
        ))}
      </div>
    </div>
  );
}
