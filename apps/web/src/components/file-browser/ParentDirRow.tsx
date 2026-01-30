type ParentDirRowProps = {
  /** Callback when row is clicked to navigate up */
  onClick: () => void;
};

/**
 * Parent directory navigation row.
 *
 * Displays [..] PARENT_DIR row as first item in file list for non-root folders.
 * Clicking navigates up to parent folder.
 *
 * @example
 * ```tsx
 * function FileList({ showParentRow, onNavigateUp }) {
 *   return (
 *     <div className="file-list-body">
 *       {showParentRow && <ParentDirRow onClick={onNavigateUp} />}
 *       {items.map(item => <FileListItem key={item.id} item={item} />)}
 *     </div>
 *   );
 * }
 * ```
 */
export function ParentDirRow({ onClick }: ParentDirRowProps) {
  return (
    <div
      className="file-list-item file-list-item--parent"
      onClick={onClick}
      role="row"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onClick()}
      data-testid="parent-dir-row"
    >
      {/* Row 1: Icon + Name */}
      <div className="file-list-item-row-top" role="gridcell">
        <span className="file-list-item-icon" aria-hidden="true">
          [..]
        </span>
        <span className="file-list-item-name">PARENT_DIR</span>
      </div>

      {/* Row 2: Empty size and date columns */}
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-date" role="gridcell">
          --
        </span>
        <span className="file-list-item-size" role="gridcell">
          --
        </span>
      </div>
    </div>
  );
}
