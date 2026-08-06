import type { ListingRow } from '../../../vault/listing';
import { NodeRows, StateRows } from './DetailsPrimitives';

/** One folder as the engine snapshot reports it; a folder carries no content. */
export function FolderDetails({ row }: { row: ListingRow }) {
  return (
    <dl className="details-list" data-testid="folder-details">
      <NodeRows row={row} />
      <StateRows row={row} />
    </dl>
  );
}
