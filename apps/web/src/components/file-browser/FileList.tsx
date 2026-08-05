import type { ListingRow } from '../../vault/listing';
import { FileListItem } from './FileListItem';
import { ParentDirRow } from './ParentDirRow';

interface FileListProps {
  rows: ListingRow[];
  /** False at the vault root, which has no parent to step up to. */
  showParentRow: boolean;
  onOpen: (node: Uint8Array) => void;
  onNavigateUp: () => void;
  onRowMenu: (event: React.MouseEvent, row: ListingRow) => void;
}

/** The routed folder's direct children, in columns. */
export function FileList({ rows, showParentRow, onOpen, onNavigateUp, onRowMenu }: FileListProps) {
  return (
    <div className="file-list" role="grid" data-testid="file-list">
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
      <div className="file-list-body" role="rowgroup">
        {showParentRow && <ParentDirRow onActivate={onNavigateUp} />}
        {rows.map((row) => (
          <FileListItem key={row.key} row={row} onOpen={onOpen} onRowMenu={onRowMenu} />
        ))}
      </div>
    </div>
  );
}
