import type { ListingRow } from '../../vault/listing';

interface FileListItemProps {
  row: ListingRow;
  selected: boolean;
  /** Adds or drops this row from the batch selection. */
  onToggle: (key: string) => void;
  /** Opens a folder. */
  onOpen: (node: Uint8Array) => void;
  /** Raises the row's action menu, wherever on the row the request came from. */
  onRowMenu: (event: React.MouseEvent<HTMLElement>, row: ListingRow) => void;
}

/** One direct child: kind marker, name, size, mtime, and its queue status. */
export function FileListItem({ row, selected, onToggle, onOpen, onRowMenu }: FileListItemProps) {
  const isFolder = row.kind === 'folder';
  const open = () => {
    if (isFolder) onOpen(row.id);
  };

  return (
    <div
      className={`file-list-item${selected ? ' file-list-item--selected' : ''}`}
      data-node-id={row.key}
      data-testid="file-list-item"
      role="row"
      tabIndex={0}
      onDoubleClick={open}
      onContextMenu={(event) => onRowMenu(event, row)}
      onKeyDown={(event) => {
        // The action button's own Enter/Space bubbles here; swallowing it would
        // navigate away instead of raising that button's menu.
        if (event.target !== event.currentTarget) return;
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        open();
      }}
    >
      <div className="file-list-item-row-top" role="gridcell">
        {/* Its own click, not the row's: selecting must not also open. */}
        <input
          type="checkbox"
          className="file-list-item-select"
          checked={selected}
          aria-label={`select ${row.name}`}
          data-testid="file-list-item-select"
          onClick={(event) => event.stopPropagation()}
          onDoubleClick={(event) => event.stopPropagation()}
          onChange={() => onToggle(row.key)}
        />
        <span className="file-list-item-icon" aria-hidden="true">
          {row.icon}
        </span>
        <span className="file-list-item-name">{row.name}</span>
        <ItemStatus row={row} />
      </div>
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">
          {row.size}
        </span>
        <span className="file-list-item-date" role="gridcell">
          {row.modified}
        </span>
      </div>
      <div className="file-list-item-actions" role="gridcell">
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
