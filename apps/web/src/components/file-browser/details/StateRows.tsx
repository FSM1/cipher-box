import type { ListingRow } from '../../../vault/listing';
import { DetailRow, DetailSection, DimValue } from './DetailsPrimitives';

/** What the op queue holds for this node — identical for a file and a folder. */
export function StateRows({ row }: { row: ListingRow }) {
  return (
    <>
      <DetailSection label="queue" />
      <DetailRow label="queued">
        {row.pending === 'none' ? <DimValue>nothing pending</DimValue> : `${row.pending} change`}
      </DetailRow>
      {row.deadLetter && <DetailRow label="dead letter">this change will not publish</DetailRow>}
    </>
  );
}
