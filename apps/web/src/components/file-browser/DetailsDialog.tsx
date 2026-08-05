import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';
import { FileDetails } from './details/FileDetails';
import { FolderDetails } from './details/FolderDetails';

interface DetailsDialogProps {
  row: ListingRow;
  onClose: () => void;
}

/** What the engine reports about one node, verbatim. */
export function DetailsDialog({ row, onClose }: DetailsDialogProps) {
  return (
    <Modal onClose={onClose} title={row.name}>
      <div data-testid="details-dialog">
        {row.kind === 'file' ? <FileDetails row={row} /> : <FolderDetails row={row} />}
      </div>
    </Modal>
  );
}
