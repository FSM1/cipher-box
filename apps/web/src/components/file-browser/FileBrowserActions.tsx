/**
 * The vault browser's interaction layer: the listing, the menu that acts on a
 * row, and the dialogs that dispatch one facade command each. It holds dialog
 * state and nothing else — the listing it renders is still the engine's.
 */

import { useState } from 'react';
import { toHex } from '@cipherbox/client';
import { useContextMenu } from '../../hooks/useContextMenu';
import { useFileDownload } from '../../hooks/useFileDownload';
import { useVaultActions, type BatchOutcome } from '../../hooks/useVaultActions';
import type { ListingRow } from '../../vault/listing';
import { previewKind } from '../../vault/previewKind';
import { useSelection } from '../../vault/selection';
import { ConfirmDeleteDialog } from './ConfirmDeleteDialog';
import { ContextMenu, type ContextMenuItem } from './ContextMenu';
import { DetailsDialog } from './DetailsDialog';
import { FileList } from './FileList';
import { FilePreviewDialog } from './FilePreviewDialog';
import { MoveDialog } from './MoveDialog';
import { NamePromptDialog } from './NamePromptDialog';
import { SelectionActionBar } from './SelectionActionBar';
import { TextEditorDialog } from './TextEditorDialog';

type Dialog =
  | { kind: 'create' }
  | { kind: 'rename' | 'details' | 'preview' | 'edit'; row: ListingRow }
  | { kind: 'move' | 'delete'; rows: ListingRow[] };

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
  const [downloading, setDownloading] = useState(false);
  const menu = useContextMenu();
  const actions = useVaultActions();
  const downloads = useFileDownload();
  const selection = useSelection(rows, folder);
  const failure = actions.error ?? downloads.error;

  const close = () => setDialog(null);
  /**
   * A dispatch the engine accepted closes its dialog; a refused one stays up.
   * The banner reports one failure, so a dispatch also retires the last read's.
   */
  const closeOnSuccess = (dispatched: Promise<boolean>) => {
    downloads.clearError();
    void dispatched.then((accepted) => {
      if (accepted) close();
    });
  };

  /**
   * A batch retires only what the engine took, from both the selection and the
   * dialog: a retry must not re-dispatch an accepted node, which the engine
   * would journal a second time and dead-letter.
   */
  const closeOnBatch = (dispatched: Promise<BatchOutcome>) => {
    downloads.clearError();
    void dispatched.then((outcome) => {
      const retired = outcome.accepted.map(toHex);
      selection.drop(retired);
      if (outcome.ok) {
        close();
        return;
      }
      setDialog((current) => {
        if (current?.kind !== 'move' && current?.kind !== 'delete') return current;
        const gone = new Set(retired);
        return { ...current, rows: current.rows.filter((row) => !gone.has(row.key)) };
      });
    });
  };

  const downloadSelection = async (): Promise<void> => {
    setDownloading(true);
    try {
      await downloads.saveAll(
        selection.rows
          .filter((row) => row.kind === 'file')
          .map((row) => ({ node: row.id, name: row.name, size: row.bytes }))
      );
    } finally {
      setDownloading(false);
    }
  };

  const menuItems = (row: ListingRow): ContextMenuItem[] => {
    const items: ContextMenuItem[] = [];
    if (row.kind === 'file') {
      const kind = previewKind(row.name);
      if (kind !== 'none') {
        items.push({ label: 'preview', onSelect: () => setDialog({ kind: 'preview', row }) });
      }
      if (kind === 'text') {
        items.push({ label: 'edit', onSelect: () => setDialog({ kind: 'edit', row }) });
      }
      items.push({
        label: 'download',
        onSelect: () => void downloads.save(row.id, row.name, row.bytes),
      });
    }
    items.push(
      { label: 'rename', onSelect: () => setDialog({ kind: 'rename', row }) },
      { label: 'move to...', onSelect: () => setDialog({ kind: 'move', rows: [row] }) },
      { label: 'details', onSelect: () => setDialog({ kind: 'details', row }) },
      {
        label: 'delete',
        destructive: true,
        onSelect: () => setDialog({ kind: 'delete', rows: [row] }),
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
      <SelectionActionBar
        rows={selection.rows}
        busy={actions.busy !== null || downloading}
        onClear={selection.clear}
        onDownload={() => void downloadSelection()}
        onMove={() => setDialog({ kind: 'move', rows: selection.rows })}
        onDelete={() => setDialog({ kind: 'delete', rows: selection.rows })}
      />
      {failure !== null && (
        <p className="file-browser-error" role="alert" data-testid="vault-action-error">
          {failure}
        </p>
      )}

      {/* An empty non-root folder still lists, so `[..]` remains reachable. */}
      {(rows.length > 0 || showParentRow) && (
        <FileList
          rows={rows}
          selection={selection}
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
          rows={dialog.rows}
          parent={folder}
          onClose={close}
          busy={actions.busy === 'relink'}
          error={actions.error}
          onConfirm={(newParent) =>
            closeOnBatch(
              actions.move(
                dialog.rows.map((row) => row.id),
                newParent
              )
            )
          }
        />
      )}
      {dialog?.kind === 'delete' && (
        <ConfirmDeleteDialog
          rows={dialog.rows}
          onClose={close}
          busy={actions.busy === 'delete'}
          error={actions.error}
          onConfirm={() => closeOnBatch(actions.remove(dialog.rows.map((row) => row.id)))}
        />
      )}
      {dialog?.kind === 'details' && <DetailsDialog row={dialog.row} onClose={close} />}
      {dialog?.kind === 'edit' && <TextEditorDialog row={dialog.row} onClose={close} />}
      {dialog?.kind === 'preview' && (
        <FilePreviewDialog
          row={dialog.row}
          onClose={close}
          onDownload={() => void downloads.save(dialog.row.id, dialog.row.name, dialog.row.bytes)}
        />
      )}
    </>
  );
}
