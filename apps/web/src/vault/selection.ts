/**
 * Which listed rows a batch command will act on. Selection is UI-owned state
 * carrying node ids only (blueprint/web-client.md "UI state law"): it is held as
 * hex keys and read back through the listing, so a row the engine has retired
 * leaves the selection with it.
 */

import { useEffect, useMemo, useState } from 'react';
import { toHex } from '@cipherbox/client';
import type { ListingRow } from './listing';

const EMPTY: ReadonlySet<string> = new Set();

export interface Selection {
  /** The selected rows, in listing order. */
  rows: ListingRow[];
  has(key: string): boolean;
  toggle(key: string): void;
  /** Selects every listed row, or clears once they all already are. */
  toggleAll(): void;
  /** Retires the rows a command has just acted on, and nothing else. */
  drop(keys: readonly string[]): void;
  clear(): void;
  allSelected: boolean;
}

/**
 * @param rows the listing on screen
 * @param folder the folder that listing belongs to; a change to it starts over
 */
export function useSelection(rows: ListingRow[], folder: Uint8Array | null): Selection {
  const [keys, setKeys] = useState<ReadonlySet<string>>(EMPTY);
  const folderKey = folder === null ? '' : toHex(folder);

  useEffect(() => setKeys(EMPTY), [folderKey]);

  const selected = useMemo(() => rows.filter((row) => keys.has(row.key)), [keys, rows]);
  const allSelected = rows.length > 0 && selected.length === rows.length;
  const clear = () => setKeys(EMPTY);

  return {
    rows: selected,
    allSelected,
    clear,
    has: (key) => keys.has(key),
    toggle: (key) =>
      setKeys((current) => {
        const next = new Set(current);
        if (!next.delete(key)) next.add(key);
        return next;
      }),
    toggleAll: () => (allSelected ? clear() : setKeys(new Set(rows.map((row) => row.key)))),
    drop: (dropped) =>
      setKeys((current) => {
        const next = new Set(current);
        return dropped.filter((key) => next.delete(key)).length > 0 ? next : current;
      }),
  };
}

/** How a command names what it acts on: one row by name, several by count. */
export function describeRows(rows: readonly ListingRow[]): string {
  if (rows.length === 1) return rows[0].name;
  const files = rows.filter((row) => row.kind === 'file').length;
  return [plural(files, 'file'), plural(rows.length - files, 'folder')]
    .filter((part) => part !== null)
    .join(', ');
}

function plural(count: number, noun: string): string | null {
  if (count === 0) return null;
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}
