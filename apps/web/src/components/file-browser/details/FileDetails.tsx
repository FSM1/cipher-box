import type { ListingRow } from '../../../vault/listing';
import { CopyableValue, DetailRow, DetailSection, DimValue, UNKNOWN } from './DetailsPrimitives';
import { StateRows } from './StateRows';

/** One file's current version, as the engine snapshot reports it. */
export function FileDetails({ row }: { row: ListingRow }) {
  return (
    <dl className="details-list" data-testid="file-details">
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

      <DetailSection label="content" />
      <DetailRow label="size">
        {row.bytes === null ? <DimValue>{UNKNOWN}</DimValue> : row.size}
      </DetailRow>
      <DetailRow label="bytes">
        {row.bytes === null ? <DimValue>{UNKNOWN}</DimValue> : row.bytes.toString()}
      </DetailRow>
      <DetailRow label="modified">{row.modified}</DetailRow>

      <StateRows row={row} />
    </dl>
  );
}
