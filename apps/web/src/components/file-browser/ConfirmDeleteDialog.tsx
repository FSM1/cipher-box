import { useVaultStorage } from '../../providers/VaultStorageProvider';
import type { ListingRow } from '../../vault/listing';
import { describeRows, plural } from '../../vault/selection';
import { ConfirmDangerDialog } from '../ui/ConfirmDangerDialog';

interface ConfirmDeleteDialogProps {
  /** The rows the delete will retire, named as one or counted as many. */
  rows: ListingRow[];
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
  /** The last dispatch's failure, which is why the dialog is still up. */
  error: string | null;
}

export function ConfirmDeleteDialog({
  rows,
  onClose,
  onConfirm,
  busy,
  error,
}: ConfirmDeleteDialogProps) {
  const { storage } = useVaultStorage();
  const what = describeRows(rows);
  const inside = rows.some((row) => row.kind === 'folder')
    ? rows.length === 1
      ? ' and everything inside it'
      : ' and everything inside'
    : '';
  const asked = rows.length === 1 ? `delete "${what}"${inside}?` : `delete ${what}${inside}?`;
  const outcome = deleteOutcome(storage?.settings.binRetentionDays ?? null);

  return (
    <ConfirmDangerDialog
      title={`delete ${what}`}
      message={outcome === null ? asked : `${asked} ${outcome}`}
      verb="delete"
      busyVerb="deleting..."
      testId="delete"
      onClose={onClose}
      onConfirm={onConfirm}
      busy={busy}
      error={error}
    />
  );
}

/**
 * What the vault does with the bytes, in the member's own retention (ADR 0010:
 * `0` makes every delete a hard delete). An unread retention states nothing:
 * the dialog must not wait on the read, and must not promise a bin either.
 */
function deleteOutcome(retentionDays: number | null): string | null {
  if (retentionDays === null) return null;
  if (retentionDays === 0) return 'this vault deletes outright, so this cannot be undone.';
  return `this vault keeps it in the bin for ${plural(retentionDays, 'day')}.`;
}
