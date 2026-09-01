import type { FolderPicker } from '../../hooks/useFolderPicker';

/** The destination walk a move dialog and a restore dialog both put in a Modal. */
export function FolderPickerBody({ picker }: { picker: FolderPicker }) {
  return (
    <>
      <p className="dialog-label">
        {'destination: '}
        <span className="folder-picker-destination" data-testid="folder-picker-destination">
          {picker.destinationName === null ? '...' : picker.destinationName || '/'}
        </span>
      </p>
      <div className="folder-picker-list" role="group" aria-label="destination folder">
        {picker.canLeave && (
          <button
            type="button"
            className="folder-picker-entry"
            onClick={picker.leave}
            data-testid="folder-picker-up"
          >
            [..]
          </button>
        )}
        {picker.isLoading && <p className="folder-picker-empty">{'// loading...'}</p>}
        {picker.error !== null && (
          <p className="folder-picker-empty" role="alert">
            {picker.error}
          </p>
        )}
        {!picker.isLoading && picker.folders.length === 0 && picker.error === null && (
          <p className="folder-picker-empty">{'// no subfolders'}</p>
        )}
        {picker.folders.map((folder) => (
          <button
            key={folder.key}
            type="button"
            className="folder-picker-entry"
            onClick={() => picker.enter(folder.id)}
            data-testid="folder-picker-entry"
          >
            <span aria-hidden="true">[DIR]</span> {folder.name}
          </button>
        ))}
      </div>
    </>
  );
}
