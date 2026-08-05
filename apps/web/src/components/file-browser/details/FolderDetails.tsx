import type { ListingRow } from '../../../vault/listing';
import { CopyableValue, DetailRow, DetailSection } from './DetailsPrimitives';
import { StateRows } from './StateRows';

/** One folder as the engine snapshot reports it; a folder carries no content. */
export function FolderDetails({ row }: { row: ListingRow }) {
  return (
    <dl className="details-list" data-testid="folder-details">
      <DetailSection label="node" />
      <DetailRow label="name">
        <CopyableValue value={row.name} label="name" />
      </DetailRow>
      <DetailRow label="type">
        <span className="details-badge">{row.icon}</span>
      </DetailRow>
      <DetailRow label="node id">
        <CopyableValue value={row.key} label="node id" />
      </DetailRow>
      <DetailRow label="modified">{row.modified}</DetailRow>

      <StateRows row={row} />
    </dl>
  );
}
