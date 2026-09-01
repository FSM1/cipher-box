/**
 * The `/bin` route's rows. Retention is the vault's own setting and expiry is
 * read off it, so the UI carries no default of its own (ADR 0010: retention is
 * engine behavior).
 */

import { toHex } from '@cipherbox/client';
import type { BinRowDescriptor, NodeKind } from '@cipherbox/client';
import { formatEpochMillis } from '../utils/format';
import { kindIcon } from './listing';

const MILLIS_PER_DAY = 86_400_000n;

/** A date `Intl` cannot format. */
const OUT_OF_RANGE = '-';

export interface BinRow {
  id: Uint8Array;
  /** Hex node id: React key and `data-node`. */
  key: string;
  /** The name the node carried in the folder it was unlinked from. */
  name: string;
  kind: NodeKind;
  icon: string;
  deleted: string;
  /** Formatted expiry, or `null` where no retention sets one. */
  expires: string | null;
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
  return [...entries].sort(byDeletedThenName).map((entry) => toRow(entry, retentionDays));
}

function toRow(entry: BinRowDescriptor, retentionDays: number | null): BinRow {
  return {
    id: entry.node,
    key: toHex(entry.node),
    name: entry.originName,
    kind: entry.kind,
    icon: kindIcon(entry.kind),
    deleted: formatEpochMillis(entry.deletedAt, OUT_OF_RANGE),
    expires: expiryOf(entry.deletedAt, retentionDays),
  };
}

function expiryOf(deletedAt: bigint, retentionDays: number | null): string | null {
  if (retentionDays === null || !Number.isInteger(retentionDays) || retentionDays <= 0) {
    return null;
  }
  return formatEpochMillis(deletedAt + BigInt(retentionDays) * MILLIS_PER_DAY, OUT_OF_RANGE);
}

function byDeletedThenName(a: BinRowDescriptor, b: BinRowDescriptor): number {
  if (a.deletedAt !== b.deletedAt) return a.deletedAt > b.deletedAt ? -1 : 1;
  return a.originName.localeCompare(b.originName, undefined, { sensitivity: 'base' });
}
