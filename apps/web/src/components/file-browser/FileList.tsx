import { type DragEvent, type MouseEvent, useMemo, useRef } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { useUploadStore } from '../../stores/upload.store';
import type { PerFileUpload } from '../../stores/upload.store';
import { FileListItem, type DragItem } from './FileListItem';
import { UploadListItem } from './UploadListItem';
import { ParentDirRow } from './ParentDirRow';
import { isFileRefResolved } from '../../utils/fileTypes';

/**
 * 68.2-11: builds the `ResolvedChild` display projection `FileListItem`
 * renders from (SDK-READ-02, D-08 no-regression render repoint), keyed by
 * ipnsName off the caller-supplied `resolvedByIpnsName` map -- mirrors the
 * SharedFileBrowser/SharedFolderRow pattern (68.2-08) of looking up the
 * SDK-resolved listing (the folder store's `children: ResolvedChild[]`,
 * Plan 09) rather than falling back to the retired kind-cache. A miss (item
 * not yet present in the resolved listing, e.g. an in-flight sync race)
 * falls back to a folder-safe default with unknown size/modifiedAt --
 * `SealedChildRef` no longer carries a size/modifiedAt display mirror
 * (D-08/68.2-12 revert; size/modifiedAt are sourced from `ResolvedChild`
 * only).
 */
function toResolvedChildView(
  ref: SealedChildRef,
  resolved: ResolvedChild | undefined
): ResolvedChild {
  if (resolved) return resolved;
  return {
    ipnsName: ref.ipnsName,
    name: ref.name,
    kind: 'folder',
    size: undefined,
    modifiedAt: 0,
    createdAt: 0,
    sequence: 0,
  };
}

/**
 * Virtual entry representing an in-progress upload in the sorted file list.
 * The `_uploading` flag discriminates it from real SealedChildRef items.
 * Shape mirrors SealedChildRef for type-compatibility; ipnsName is empty during upload.
 */
type UploadVirtualEntry = {
  name: string;
  /** Empty during upload — real IPNS name assigned on completion. */
  ipnsName: string;
  generation: 0;
  versionFloor: 0n;
  readKeySealed: '';
  _uploading: true;
};

type FileListProps = {
  /** Items to display (files and folders) */
  items: SealedChildRef[];
  /**
   * The SDK-resolved display projection for `items` (SDK-READ-02) -- kind/
   * size/modifiedAt pre-resolved, looked up per-item by ipnsName. A miss
   * (item not yet present) falls back to a folder-safe default.
   */
  resolvedChildren: ResolvedChild[];
  /** Set of currently selected item IDs */
  selectedIds: Set<string>;
  /** Parent folder ID (for drag operations) */
  parentId: string;
  /** Parent folder's decrypted AES-256 key (for resolving file sizes) */
  folderKey: Uint8Array | null;
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
  onContextMenu: (event: MouseEvent, item: SealedChildRef) => void;
  /** Callback when drag starts */
  onDragStart: (event: DragEvent, item: SealedChildRef) => void;
  /** Callback when items are dropped onto a folder */
  onDropOnFolder?: (items: DragItem[], sourceParentId: string, destFolderId: string) => void;
  /** Callback when external files are dropped onto a folder */
  onExternalFileDrop?: (files: File[], destFolderId: string) => void;
  /** Callback to re-trigger upload for a failed file (retry button in UploadListItem) */
  onRetryUpload?: (file: File) => void;
};

/**
 * Sort items folders-first, then alphabetically by name.
 * `UploadVirtualEntry` rows (empty ipnsName) short-circuit to "file" before the
 * `resolvedByIpnsName` lookup, so in-progress uploads never get mis-sorted as
 * folders by the map-miss default.
 */
function sortItems(
  items: SealedChildRef[],
  resolvedByIpnsName: Map<string, ResolvedChild>
): SealedChildRef[] {
  return [...items].sort((a, b) => {
    const aIsFolder = '_uploading' in a ? false : !isFileRefResolved(a, resolvedByIpnsName);
    const bIsFolder = '_uploading' in b ? false : !isFileRefResolved(b, resolvedByIpnsName);
    if (aIsFolder !== bIsFolder) return aIsFolder ? -1 : 1;
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
  resolvedChildren,
  selectedIds,
  parentId,
  folderKey,
  showParentRow,
  onNavigateUp,
  onSelect,
  onSelectAll,
  onNavigate,
  onContextMenu,
  onDragStart,
  onDropOnFolder,
  onExternalFileDrop,
  onRetryUpload,
}: FileListProps) {
  // 68.2-11: per-ipnsName lookup into the SDK-resolved display projection
  // (mirrors SharedFileBrowser's resolvedByIpnsName, 68.2-08).
  const resolvedByIpnsName = useMemo(
    () => new Map(resolvedChildren.map((r) => [r.ipnsName, r])),
    [resolvedChildren]
  );

  // Subscribe to upload entries for this folder only (IDs + status, not progress).
  // Progress updates re-render individual UploadListItem rows via their own fine-grained selectors.
  // Custom equality via ref prevents re-renders on every progress tick.
  type UploadEntry = { id: string; filename: string; status: PerFileUpload['status'] };
  const prevEntriesRef = useRef<UploadEntry[]>([]);
  const uploadEntries = useUploadStore((s) => {
    const entries: UploadEntry[] = [];
    for (const f of s.files.values()) {
      if (f.targetFolderId === parentId) {
        entries.push({ id: f.id, filename: f.filename, status: f.status });
      }
    }
    const prev = prevEntriesRef.current;
    if (
      prev.length === entries.length &&
      prev.every((p, i) => p.id === entries[i].id && p.status === entries[i].status)
    ) {
      return prev;
    }
    prevEntriesRef.current = entries;
    return entries;
  });

  // Create virtual entries for sorting alongside real items
  const uploadVirtualEntries: UploadVirtualEntry[] = uploadEntries.map((f) => ({
    name: f.filename,
    ipnsName: f.id, // placeholder: real ipnsName assigned on completion
    generation: 0 as const,
    versionFloor: 0n as const,
    readKeySealed: '' as const,
    _uploading: true as const,
  }));

  // Prevent duplicate rows: when a real file already exists, hide the completing
  // upload row instead of the real file row. (Pitfall 5)
  const realFileNames = new Set(items.map((item) => item.name));
  const completeUploadIds = new Set(
    uploadEntries
      .filter((e) => e.status === 'complete' && realFileNames.has(e.filename))
      .map((e) => e.id)
  );
  const filteredUploadEntries = uploadVirtualEntries.filter(
    (entry) => !completeUploadIds.has(entry.ipnsName)
  );

  // Merge and sort all items together
  const allItems = [...items, ...filteredUploadEntries];
  const sortedItems = sortItems(allItems as SealedChildRef[], resolvedByIpnsName);

  // Select-all uses real item count only (upload rows are not selectable)
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
        <div className="file-list-header-actions" aria-hidden="true" />
      </div>

      {/* Item rows */}
      <div className="file-list-body" role="rowgroup">
        {showParentRow && onNavigateUp && <ParentDirRow onActivate={onNavigateUp} />}
        {sortedItems.map((item) =>
          '_uploading' in item ? (
            <UploadListItem key={item.ipnsName} fileId={item.ipnsName} onRetry={onRetryUpload} />
          ) : (
            <FileListItem
              key={item.ipnsName}
              item={item}
              resolved={toResolvedChildView(item, resolvedByIpnsName.get(item.ipnsName))}
              resolvedByIpnsName={resolvedByIpnsName}
              isSelected={selectedIds.has(item.ipnsName)}
              parentId={parentId}
              selectedIds={selectedIds}
              allItems={items}
              folderKey={folderKey}
              onSelect={onSelect}
              onNavigate={onNavigate}
              onContextMenu={onContextMenu}
              onDragStart={onDragStart}
              onDrop={
                isFileRefResolved(item, resolvedByIpnsName)
                  ? undefined
                  : onDropOnFolder &&
                    ((dragItems, sourceParentId) =>
                      onDropOnFolder(dragItems, sourceParentId, item.ipnsName))
              }
              onExternalFileDrop={
                isFileRefResolved(item, resolvedByIpnsName)
                  ? undefined
                  : onExternalFileDrop && ((files) => onExternalFileDrop(files, item.ipnsName))
              }
            />
          )
        )}
      </div>
    </div>
  );
}
