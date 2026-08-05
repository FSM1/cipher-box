import type { ListingRow } from '../../vault/listing';

interface FileListItemProps {
  row: ListingRow;
  /** Opens a folder. */
  onOpen: (node: Uint8Array) => void;
  /** Raises the row's action menu, from a right-click or the menu key. */
  onRowMenu: (event: React.MouseEvent<HTMLElement>, row: ListingRow) => void;
}

/** One direct child: kind marker, name, size, mtime, and its queue status. */
export function FileListItem({ row, onOpen, onRowMenu }: FileListItemProps) {
  const isFolder = row.kind === 'folder';
  const open = () => {
    if (isFolder) onOpen(row.id);
  };

  return (
    <div
      className="file-list-item"
      data-node-id={row.key}
      data-testid="file-list-item"
      role="row"
      tabIndex={0}
      onDoubleClick={open}
      onContextMenu={(event) => onRowMenu(event, row)}
      onKeyDown={(event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        open();
      }}
    >
      <div className="file-list-item-row-top" role="gridcell">
        <span className="file-list-item-icon" aria-hidden="true">
          {row.icon}
        </span>
        <span className="file-list-item-name">{row.name}</span>
        <ItemStatus row={row} />
        <button
          type="button"
          className="file-list-item-menu"
          aria-label={`actions for ${row.name}`}
          data-testid="file-list-item-menu"
          onClick={(event) => {
            event.stopPropagation();
            onRowMenu(event, row);
          }}
        >
          [...]
        </button>
      </div>
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">
          {row.size}
        </span>
        <span className="file-list-item-date" role="gridcell">
          {row.modified}
        </span>
      </div>
    </div>
  );
}

/** The engine's per-node queue flags, rendered as the engine reports them. */
function ItemStatus({ row }: { row: ListingRow }) {
  if (row.deadLetter) {
    return (
      <span className="file-list-item-status file-list-item-status--dead" title="will not publish">
        [!]
      </span>
    );
  }
  if (row.pending === 'none') return null;
  return (
    <span className="file-list-item-status" title={`${row.pending} change not published yet`}>
      [~]
    </span>
  );
}
