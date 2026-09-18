/**
 * The vault browser's interaction layer: the listing, the menu that acts on a
 * row, and the dialogs that dispatch one facade command each. It holds dialog
 * state and nothing else — the listing it renders is still the engine's.
 */

import { useState } from 'react';
import { toHex } from '@cipherbox/client';
import { useContextMenu } from '../../hooks/useContextMenu';
import { useFileDownload, type SaveRequest } from '../../hooks/useFileDownload';
import { useVaultActions, type BatchOutcome } from '../../hooks/useVaultActions';
import { ShareDialog } from '../sharing/ShareDialog';
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

const saveRequest = (row: ListingRow): SaveRequest => ({
  node: row.id,
  name: row.storedName,
  size: row.bytes,
});

type Dialog =
  | { kind: 'create' }
  | { kind: 'rename' | 'details' | 'preview' | 'edit' | 'share'; row: ListingRow }
  | { kind: 'move' | 'delete'; rows: ListingRow[] };

/** The dialogs whose confirm dispatches a write. The rest only read. */
const MUTATIONS: ReadonlySet<Dialog['kind']> = new Set([
  'create',
  'rename',
  'move',
  'delete',
  'share',
  'edit',
]);

interface FileBrowserActionsProps {
  rows: ListingRow[];
  /** The folder on screen, or `null` before the first snapshot lands. */
  folder: Uint8Array | null;
  /** False in a scope this vault only holds a read grant over. */
  writable: boolean;
  showParentRow: boolean;
  onOpen: (node: Uint8Array) => void;
  onNavigateUp: () => void;
}

export function FileBrowserActions({
  rows,
  folder,
  writable,
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
  // A scope the engine reports read-only under an already-open dialog takes the
  // dialog down with it: its confirm is a write, and a gated menu entry does not
  // reach one the user opened while the scope was still writable.
  const open = dialog !== null && !writable && MUTATIONS.has(dialog.kind) ? null : dialog;

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
      await downloads.saveAll(selection.rows.filter((row) => row.kind === 'file').map(saveRequest));
    } finally {
      setDownloading(false);
    }
  };

  const menuItems = (row: ListingRow): ContextMenuItem[] => {
    const items: ContextMenuItem[] = [];
    if (row.kind === 'file') {
      const kind = previewKind(row.storedName);
      if (kind !== 'none') {
        items.push({ label: 'preview', onSelect: () => setDialog({ kind: 'preview', row }) });
      }
      if (kind === 'text' && writable) {
        items.push({ label: 'edit', onSelect: () => setDialog({ kind: 'edit', row }) });
      }
      items.push({
        label: 'download',
        onSelect: () => void downloads.save(saveRequest(row)),
      });
    }
    if (writable) {
      items.push(
        { label: 'rename', onSelect: () => setDialog({ kind: 'rename', row }) },
        { label: 'move to...', onSelect: () => setDialog({ kind: 'move', rows: [row] }) },
        ...(row.kind === 'folder'
          ? [{ label: 'share...', onSelect: () => setDialog({ kind: 'share' as const, row }) }]
          : [])
      );
    }
    items.push({ label: 'details', onSelect: () => setDialog({ kind: 'details', row }) });
    if (writable) {
      items.push({
        label: 'delete',
        destructive: true,
        onSelect: () => setDialog({ kind: 'delete', rows: [row] }),
      });
    }
    return items;
  };

  return (
    <>
      {writable && (
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
      )}
      <SelectionActionBar
        rows={selection.rows}
        busy={actions.busy !== null || downloading}
        writable={writable}
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
          right={menu.state.right}
          top={menu.state.top}
          label={`actions for ${menu.state.row.name}`}
          items={menuItems(menu.state.row)}
          onClose={menu.close}
        />
      )}

      {open?.kind === 'create' && folder !== null && (
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
      {open?.kind === 'rename' && (
        <NamePromptDialog
          title={`rename ${open.row.name}`}
          fieldLabel="new name"
          initialName={open.row.storedName}
          confirmLabel="rename"
          busyLabel="renaming..."
          testId="rename"
          onClose={close}
          busy={actions.busy === 'rename'}
          error={actions.error}
          onConfirm={(name) => closeOnSuccess(actions.rename(open.row.id, name))}
        />
      )}
      {open?.kind === 'move' && (
        <MoveDialog
          rows={open.rows}
          parent={folder}
          onClose={close}
          busy={actions.busy === 'relink'}
          error={actions.error}
          onConfirm={(newParent) =>
            closeOnBatch(
              actions.move(
                open.rows.map((row) => row.id),
                newParent
              )
            )
          }
        />
      )}
      {open?.kind === 'delete' && (
        <ConfirmDeleteDialog
          rows={open.rows}
          onClose={close}
          busy={actions.busy === 'delete'}
          error={actions.error}
          onConfirm={() => closeOnBatch(actions.remove(open.rows.map((row) => row.id)))}
        />
      )}
      {open?.kind === 'share' && <ShareDialog row={open.row} onClose={close} />}
      {open?.kind === 'details' && (
        <DetailsDialog row={open.row} writable={writable} onClose={close} />
      )}
      {open?.kind === 'edit' && <TextEditorDialog row={open.row} onClose={close} />}
      {open?.kind === 'preview' && (
        <FilePreviewDialog
          row={open.row}
          onClose={close}
          onDownload={() => void downloads.save(saveRequest(open.row))}
        />
      )}
    </>
  );
}
