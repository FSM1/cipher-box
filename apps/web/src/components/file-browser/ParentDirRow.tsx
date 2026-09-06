interface ParentDirRowProps {
  onActivate: () => void;
}

/** The `[..]` row that opens the parent folder, first in every non-root list. */
export function ParentDirRow({ onActivate }: ParentDirRowProps) {
  return (
    <div
      className="file-list-item file-list-item--parent"
      role="row"
      tabIndex={0}
      onDoubleClick={onActivate}
      onKeyDown={(event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        onActivate();
      }}
      data-testid="parent-dir-row"
    >
      <div className="file-list-item-row-top" role="gridcell">
        {/* `[..]` is not selectable, so it holds the column open instead. A
            flex item, not padding: it inherits the row's gap rather than
            restating it. */}
        <span className="file-list-item-select-gap" aria-hidden="true" />
        <span className="file-list-item-icon" aria-hidden="true">
          [..]
        </span>
        <span className="file-list-item-name">PARENT_DIR</span>
      </div>
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">
          -
        </span>
        <span className="file-list-item-date" role="gridcell">
          -
        </span>
      </div>
      {/* No actions on `[..]`, but the grid still owes the header a fourth cell. */}
      <div className="file-list-item-actions" role="gridcell" />
    </div>
  );
}
