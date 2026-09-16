import { useRef, useState } from 'react';
import { toHex, type VersionEntryDescriptor } from '@cipherbox/client';
import { useFileVersions, type VersionWrite } from '../../hooks/useFileVersions';
import type { ListingRow } from '../../vault/listing';
import { ConfirmDangerDialog } from '../ui/ConfirmDangerDialog';
import { Modal } from '../ui/Modal';
import { FileDetails } from './details/FileDetails';
import { FolderDetails } from './details/FolderDetails';
import { shortCid } from './details/VersionHistory';

interface DetailsDialogProps {
  row: ListingRow;
  onClose: () => void;
}

/** A version write the member has been asked to confirm. */
interface PendingWrite {
  command: VersionWrite;
  entry: VersionEntryDescriptor;
}

/** What the engine reports about one node, verbatim. */
export function DetailsDialog({ row, onClose }: DetailsDialogProps) {
  const isFile = row.kind === 'file';
  const node = isFile ? row.id : null;
  const versions = useFileVersions(node, row.storedName);
  const [pending, setPending] = useState<PendingWrite | null>(null);
  // A confirmed write spans two engine calls, the write and its re-read, and
  // `versions.busy` falls to null between them. Only this holds for both.
  const [confirming, setConfirming] = useState(false);
  // A confirmation names one node's version, but the row is a prop the parent
  // swaps in place. The swap must retire it in that same render, or the answer
  // sends the previous node's version against the new one.
  const shown = useRef(node);
  if (shown.current !== node) {
    shown.current = node;
    setPending(null);
    setConfirming(false);
  }

  const confirm = (write: PendingWrite) => {
    const target = node;
    setConfirming(true);
    void versions.write(write.command, write.entry.contentCid).then((accepted) => {
      if (shown.current !== target) return;
      setConfirming(false);
      if (accepted) setPending(null);
    });
  };

  return (
    <>
      <Modal
        onClose={onClose}
        title={row.name}
        // The read is the dialog's own, so only a command whose outcome it owes
        // the member holds the dismissal.
        busy={versions.busy !== null && versions.busy !== 'versions'}
        // A confirmation the member has not answered outlives its own dialog if
        // one Escape dismisses both.
        dismissible={pending === null}
      >
        <div data-testid="details-dialog">
          {isFile ? (
            <FileDetails
              row={row}
              versions={versions}
              onRestore={(entry) => setPending({ command: 'restore', entry })}
              onDelete={(entry) => setPending({ command: 'delete', entry })}
            />
          ) : (
            <FolderDetails row={row} />
          )}
        </div>
      </Modal>
      {pending !== null && (
        <ConfirmDangerDialog
          {...writePrompt(pending)}
          testId={`version-${pending.command}`}
          onClose={() => setPending(null)}
          onConfirm={() => confirm(pending)}
          busy={confirming}
          error={versions.error}
        />
      )}
    </>
  );
}

/** What each write does to the file, in the member's own terms. */
function writePrompt({ command, entry }: PendingWrite) {
  const named = shortCid(toHex(entry.contentCid));
  return command === 'restore'
    ? {
        title: 'restore version',
        message:
          'put this version back at the head of the file? the current version becomes the newest prior one.',
        verb: 'restore',
        busyVerb: 'restoring...',
      }
    : {
        title: 'delete version',
        message: `delete version ${named}? this cannot be undone.`,
        verb: 'delete',
        busyVerb: 'deleting...',
      };
}
