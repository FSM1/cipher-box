/**
 * The vault browser's interaction layer: the listing, the menu that acts on a
 * row, and the dialogs that dispatch one facade command each. It holds dialog
 * state and nothing else — the listing it renders is still the engine's.
 */

import { useState } from 'react';
import { useContextMenu } from '../../hooks/useContextMenu';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useVaultActions } from '../../hooks/useVaultActions';
import type { ListingRow } from '../../vault/listing';
import { previewKind } from '../../vault/previewKind';
import { ConfirmDeleteDialog } from './ConfirmDeleteDialog';
import { ContextMenu, type ContextMenuItem } from './ContextMenu';
import { DetailsDialog } from './DetailsDialog';
import { FileList } from './FileList';
import { FilePreviewDialog } from './FilePreviewDialog';
import { MoveDialog } from './MoveDialog';
import { NamePromptDialog } from './NamePromptDialog';

type Dialog =
  | { kind: 'create' }
  | { kind: 'rename' | 'move' | 'delete' | 'details' | 'preview'; row: ListingRow };

interface FileBrowserActionsProps {
  rows: ListingRow[];
  /** The folder on screen, or `null` before the first snapshot lands. */
  folder: Uint8Array | null;
  showParentRow: boolean;
  onOpen: (node: Uint8Array) => void;
  onNavigateUp: () => void;
}

export function FileBrowserActions({
  rows,
  folder,
  showParentRow,
  onOpen,
  onNavigateUp,
}: FileBrowserActionsProps) {
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const menu = useContextMenu();
  const actions = useVaultActions();
  const downloads = useFileDownload();
  const failure = actions.error ?? downloads.error;

  const close = () => setDialog(null);
  /** A dispatch the engine accepted closes its dialog; a rejected one stays up. */
  const closeOnSuccess = (dispatched: Promise<boolean>) =>
    void dispatched.then((accepted) => {
      if (accepted) close();
    });

  const menuItems = (row: ListingRow): ContextMenuItem[] => {
    const items: ContextMenuItem[] = [];
    if (row.kind === 'file') {
      if (previewKind(row.name) !== 'none') {
        items.push({ label: 'preview', onSelect: () => setDialog({ kind: 'preview', row }) });
      }
      items.push({ label: 'download', onSelect: () => void downloads.save(row.id, row.name) });
    }
    items.push(
      { label: 'rename', onSelect: () => setDialog({ kind: 'rename', row }) },
      { label: 'move to...', onSelect: () => setDialog({ kind: 'move', row }) },
      { label: 'details', onSelect: () => setDialog({ kind: 'details', row }) },
      {
        label: 'delete',
        destructive: true,
        onSelect: () => setDialog({ kind: 'delete', row }),
      }
    );
    return items;
  };

  return (
    <>
      <div className="file-browser-toolbar">
        <button
          type="button"
          className="file-browser-toolbar-button"
          onClick={() => setDialog({ kind: 'create' })}
          disabled={folder === null}
          data-testid="new-folder-button"
        >
          [+ NEW FOLDER]
        </button>
      </div>
      {failure !== null && (
        <p className="file-browser-error" role="alert" data-testid="vault-action-error">
          {failure}
        </p>
      )}

      {/* An empty non-root folder still lists, so `[..]` remains reachable. */}
      {(rows.length > 0 || showParentRow) && (
        <FileList
          rows={rows}
          showParentRow={showParentRow}
          onOpen={onOpen}
          onNavigateUp={onNavigateUp}
          onRowMenu={menu.open}
        />
      )}

      {menu.state !== null && (
        <ContextMenu
          x={menu.state.x}
          y={menu.state.y}
          label={`actions for ${menu.state.row.name}`}
          items={menuItems(menu.state.row)}
          onClose={menu.close}
        />
      )}

      {dialog?.kind === 'create' && folder !== null && (
        <NamePromptDialog
          title="new folder"
          fieldLabel="folder name"
          initialName=""
          confirmLabel="create"
          busyLabel="creating..."
          testId="create-folder"
          onClose={close}
          busy={actions.busy === 'create'}
          error={actions.error}
          onConfirm={(name) => closeOnSuccess(actions.createFolder(folder, name))}
        />
      )}
      {dialog?.kind === 'rename' && (
        <NamePromptDialog
          title={`rename ${dialog.row.name}`}
          fieldLabel="new name"
          initialName={dialog.row.name}
          confirmLabel="rename"
          busyLabel="renaming..."
          testId="rename"
          onClose={close}
          busy={actions.busy === 'rename'}
          error={actions.error}
          onConfirm={(name) => closeOnSuccess(actions.rename(dialog.row.id, name))}
        />
      )}
      {dialog?.kind === 'move' && (
        <MoveDialog
          row={dialog.row}
          parent={folder}
          onClose={close}
          busy={actions.busy === 'relink'}
          error={actions.error}
          onConfirm={(newParent) => closeOnSuccess(actions.move(dialog.row.id, newParent))}
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDeleteDialog
          row={dialog.row}
          onClose={close}
          busy={actions.busy === 'delete'}
          error={actions.error}
          onConfirm={() => closeOnSuccess(actions.remove(dialog.row.id))}
        />
      )}
      {dialog?.kind === 'details' && <DetailsDialog row={dialog.row} onClose={close} />}
      {dialog?.kind === 'preview' && (
        <FilePreviewDialog
          row={dialog.row}
          onClose={close}
          onDownload={() => void downloads.save(dialog.row.id, dialog.row.name)}
        />
      )}
    </>
  );
}
