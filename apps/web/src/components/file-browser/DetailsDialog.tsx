import type { ListingRow } from '../../vault/listing';
import { Modal } from '../ui/Modal';

interface DetailsDialogProps {
  row: ListingRow;
  onClose: () => void;
}

/** What the engine reports about one node, verbatim. */
export function DetailsDialog({ row, onClose }: DetailsDialogProps) {
  const fields: [string, string][] = [
    ['name', row.name],
    ['kind', row.kind],
    ['size', row.size],
    ['modified', row.modified],
    ['node id', row.key],
    ['queued', row.pending === 'none' ? 'nothing pending' : `${row.pending} change`],
  ];
  if (row.deadLetter) fields.push(['dead letter', 'this change will not publish']);

  return (
    <Modal onClose={onClose} title={row.name}>
      <dl className="details-list" data-testid="details-dialog">
        {fields.map(([label, value]) => (
          <div className="details-row" key={label}>
            <dt className="details-label">{label}</dt>
            <dd className="details-value">{value}</dd>
          </div>
        ))}
      </dl>
    </Modal>
  );
}
