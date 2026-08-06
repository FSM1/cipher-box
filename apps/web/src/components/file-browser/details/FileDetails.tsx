import type { ListingRow } from '../../../vault/listing';
import {
  DetailRow,
  DetailSection,
  DimValue,
  NodeRows,
  StateRows,
  UNKNOWN,
} from './DetailsPrimitives';

/** One file's current version, as the engine snapshot reports it. */
export function FileDetails({ row }: { row: ListingRow }) {
  return (
    <dl className="details-list" data-testid="file-details">
      <NodeRows row={row} />

      <DetailSection label="content" />
      <DetailRow label="size">
        {row.bytes === null ? <DimValue>{UNKNOWN}</DimValue> : row.size}
      </DetailRow>
      <DetailRow label="bytes">
        {row.bytes === null ? <DimValue>{UNKNOWN}</DimValue> : row.bytes.toString()}
      </DetailRow>
      <DetailRow label="version">
        {row.contentVersion === null ? (
          <DimValue>{UNKNOWN}</DimValue>
        ) : (
          row.contentVersion.toString()
        )}
      </DetailRow>

      <StateRows row={row} />
    </dl>
  );
}
