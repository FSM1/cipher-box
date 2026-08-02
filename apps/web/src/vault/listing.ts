/**
 * The engine's direct-children projection as list rows. Ordering and labels are
 * the UI's; every value is the engine's word verbatim
 * (blueprint/web-client.md "UI state law").
 */

import { toHex } from '@cipherbox/client';
import type { NodeKind, PendingClass, SnapshotChildDescriptor } from '@cipherbox/client';
import { formatBytes, formatDate } from '../utils/format';

/** Stands in for a projection the child ref does not carry yet (#27 D7). */
const UNRESOLVED = '...';

/** A column with nothing to show for this kind of node. */
const NOT_APPLICABLE = '-';

export interface ListingRow {
  id: Uint8Array;
  /** Hex node id: React key, route target, and `data-node-id`. */
  key: string;
  name: string;
  kind: NodeKind;
  /** Terminal-style kind marker. */
  icon: string;
  /** Formatted size, or `...` while the projection is still resolving. */
  size: string;
  /** Formatted mtime, or `...` while the projection is still resolving. */
  modified: string;
  pending: PendingClass;
  deadLetter: boolean;
}

/**
 * Sorts folders first, then by name, and labels each row. The engine orders
 * children by node id, which is stable but meaningless to a reader.
 */
export function listingRows(children: readonly SnapshotChildDescriptor[]): ListingRow[] {
  return children.map(toRow).sort(byKindThenName);
}

function toRow(child: SnapshotChildDescriptor): ListingRow {
  const isFolder = child.kind === 'folder';
  return {
    id: child.id,
    key: toHex(child.id),
    name: child.name,
    kind: child.kind,
    icon: isFolder ? '[DIR]' : '[FILE]',
    size: isFolder ? NOT_APPLICABLE : projected(child.size, formatBytes),
    modified: projected(child.mtime, formatDate),
    pending: child.pending,
    deadLetter: child.deadLetter,
  };
}

function projected(value: bigint | null, format: (value: number) => string): string {
  return value === null ? UNRESOLVED : format(Number(value));
}

function byKindThenName(a: ListingRow, b: ListingRow): number {
  if (a.kind !== b.kind) return a.kind === 'folder' ? -1 : 1;
  return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
}
