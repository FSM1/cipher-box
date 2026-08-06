import type { ListingRow } from '../../vault/listing';
import type { Selection } from '../../vault/selection';
import { FileListItem } from './FileListItem';
import { ParentDirRow } from './ParentDirRow';

interface FileListProps {
  rows: ListingRow[];
  selection: Selection;
  /** False at the vault root, which has no parent to step up to. */
  showParentRow: boolean;
  onOpen: (node: Uint8Array) => void;
  onNavigateUp: () => void;
  onRowMenu: (event: React.MouseEvent<HTMLElement>, row: ListingRow) => void;
}

/** The routed folder's direct children, in columns. */
export function FileList({
  rows,
  selection,
  showParentRow,
  onOpen,
  onNavigateUp,
  onRowMenu,
}: FileListProps) {
  const partial = selection.rows.length > 0 && !selection.allSelected;

  return (
    <div className="file-list" role="grid" data-testid="file-list">
      <div className="file-list-header" role="row">
        <div className="file-list-header-name" role="columnheader">
          <input
            type="checkbox"
            className="file-list-select-all"
            checked={selection.allSelected}
            ref={(node) => {
              if (node) node.indeterminate = partial;
            }}
            disabled={rows.length === 0}
            aria-label="select all"
            data-testid="select-all"
            onChange={selection.toggleAll}
          />
          [NAME]
        </div>
        <div className="file-list-header-size" role="columnheader">
          [SIZE]
        </div>
        <div className="file-list-header-date" role="columnheader">
          [MODIFIED]
        </div>
      </div>
      <div className="file-list-body" role="rowgroup">
        {showParentRow && <ParentDirRow onActivate={onNavigateUp} />}
        {rows.map((row) => (
          <FileListItem
            key={row.key}
            row={row}
            selected={selection.has(row.key)}
            onToggle={selection.toggle}
            onOpen={onOpen}
            onRowMenu={onRowMenu}
          />
        ))}
      </div>
    </div>
  );
}
