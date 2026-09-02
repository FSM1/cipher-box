/**
 * The `/bin` route's rows. Retention is the vault's own setting and expiry is
 * read off it, so the UI carries no default of its own (ADR 0010: retention is
 * engine behavior).
 */

import { toHex } from '@cipherbox/client';
import type { BinOriginDescriptor, BinRowDescriptor, NodeKind } from '@cipherbox/client';
import { formatEpochMillis } from '../utils/format';
import { displayName } from './displayName';
import { kindIcon } from './listing';

const MILLIS_PER_DAY = 86_400_000n;

/** A date `Intl` cannot format. */
const OUT_OF_RANGE = '-';

const ROOT_FOLDER = 'root';
const GONE_FOLDER = 'a folder that is gone';
const UNNAMED_FOLDER = 'a folder with no readable name';

export interface BinRow {
  id: Uint8Array;
  /** Hex node id: React key and `data-node`. */
  key: string;
  /** The name the node carried in the folder it was unlinked from. */
  name: string;
  /** That folder, in words: two rows of one name read apart by this. */
  origin: string;
  kind: NodeKind;
  icon: string;
  deleted: string;
  /** Formatted expiry, or `null` where no retention sets one. */
  expires: string | null;
}

interface SortedRow {
  deletedAt: bigint;
  row: BinRow;
}

/**
 * Newest deletion first, then by name.
 *
 * @param retentionDays days the vault keeps a deleted node, or `null` where the
 * settings read has not landed. `0` keeps the hard delete, so it sets no expiry.
 */
export function binRows(
  entries: readonly BinRowDescriptor[],
  retentionDays: number | null
): BinRow[] {
  return entries
    .map((entry) => ({ deletedAt: entry.deletedAt, row: toRow(entry, retentionDays) }))
    .sort(byDeletedThenName)
    .map(({ row }) => row);
}

function toRow(entry: BinRowDescriptor, retentionDays: number | null): BinRow {
  return {
    id: entry.node,
    key: toHex(entry.node),
    name: displayName(entry.originName),
    origin: originOf(entry.originFolder),
    kind: entry.kind,
    icon: kindIcon(entry.kind),
    deleted: formatEpochMillis(entry.deletedAt, OUT_OF_RANGE),
    expires: expiryOf(entry.deletedAt, retentionDays),
  };
}

/** A folder name is peer-authored text, so it is neutralised as a row name is. */
function originOf(origin: BinOriginDescriptor): string {
  switch (origin.kind) {
    case 'root':
      return ROOT_FOLDER;
    case 'gone':
      return GONE_FOLDER;
    case 'folder': {
      const shown = displayName(origin.name);
      return shown === '' ? UNNAMED_FOLDER : shown;
    }
  }
}

function expiryOf(deletedAt: bigint, retentionDays: number | null): string | null {
  if (retentionDays === null || !Number.isInteger(retentionDays) || retentionDays <= 0) {
    return null;
  }
  return formatEpochMillis(deletedAt + BigInt(retentionDays) * MILLIS_PER_DAY, OUT_OF_RANGE);
}

/**
 * The tie-break reads the shown name, not the stored one. A leading tab or line
 * break sorts ahead of every letter but renders as nothing, so a stored-name
 * order puts a row where its own name says it does not belong. Rows of one name
 * then order by the origin the page shows, so the pair reads in a set order.
 */
function byDeletedThenName(a: SortedRow, b: SortedRow): number {
  if (a.deletedAt !== b.deletedAt) return a.deletedAt > b.deletedAt ? -1 : 1;
  const byName = a.row.name.localeCompare(b.row.name, undefined, { sensitivity: 'base' });
  if (byName !== 0) return byName;
  return a.row.origin.localeCompare(b.row.origin, undefined, { sensitivity: 'base' });
}
