import type { ListingRow } from '../../vault/listing';
import { describeRows } from '../../vault/selection';
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
  const what = describeRows(rows);
  const inside = rows.some((row) => row.kind === 'folder')
    ? rows.length === 1
      ? ' and everything inside it'
      : ' and everything inside'
    : '';

  return (
    <ConfirmDangerDialog
      title={`delete ${what}`}
      message={rows.length === 1 ? `delete "${what}"${inside}?` : `delete ${what}${inside}?`}
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
