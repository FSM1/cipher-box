import type { SnapshotChildDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import { listingRows } from './listing';

function child(overrides: Partial<SnapshotChildDescriptor> = {}): SnapshotChildDescriptor {
  return {
    id: new Uint8Array(16).fill(1),
    name: 'notes.txt',
    kind: 'file',
    size: null,
    mtime: null,
    pending: 'none',
    deadLetter: false,
    contentVersion: null,
    contentCid: null,
    ...overrides,
  };
}

describe('listingRows', () => {
  it('puts folders first, then sorts by name case-insensitively', () => {
    const rows = listingRows([
      child({ id: new Uint8Array(16).fill(1), name: 'beta.txt' }),
      child({ id: new Uint8Array(16).fill(2), name: 'Alpha.txt' }),
      child({ id: new Uint8Array(16).fill(3), name: 'zeta', kind: 'folder' }),
      child({ id: new Uint8Array(16).fill(4), name: 'archive', kind: 'folder' }),
    ]);

    expect(rows.map((row) => row.name)).toEqual(['archive', 'zeta', 'Alpha.txt', 'beta.txt']);
  });

  it('neutralises a name for display, and keeps the stored one beside it', () => {
    const [row] = listingRows([child({ name: 'report\u202Efdp.exe' })]);

    expect(row.name).toBe('reportfdp.exe');
    expect(row.storedName).toBe('report\u202Efdp.exe');
  });

  it('renders name and kind before the projection lands', () => {
    const [row] = listingRows([child({ name: 'holiday.jpg' })]);

    expect(row.name).toBe('holiday.jpg');
    expect(row.icon).toBe('[FILE]');
    expect(row.size).toBe('...');
    expect(row.modified).toBe('...');
  });

  it('renders size and mtime once the projection lands', () => {
    const [row] = listingRows([child({ size: 1536n, mtime: 1_700_000_000_000n })]);

    expect(row.size).toBe('1.5 KB');
    expect(row.modified).not.toBe('...');
  });

  it('carries the content version the snapshot projected, and its absence', () => {
    const rows = listingRows([
      child({ id: new Uint8Array(16).fill(1), name: 'a', contentVersion: 7n }),
      child({ id: new Uint8Array(16).fill(2), name: 'b', contentVersion: null }),
    ]);

    expect(rows.map((row) => row.contentVersion)).toEqual([7n, null]);
  });

  it('renders an mtime past the Date range rather than throwing out of Intl', () => {
    // A u64 mtime authored elsewhere must not blank the listing.
    const [row] = listingRows([child({ mtime: 8_640_000_000_000_001n })]);

    expect(row.modified).toBe('-');
  });

  it('renders the largest mtime the Date range still admits', () => {
    const [row] = listingRows([child({ mtime: 8_640_000_000_000_000n })]);

    expect(row.modified).not.toBe('-');
  });

  it('has no size column for a folder', () => {
    const [row] = listingRows([child({ kind: 'folder', name: 'docs' })]);

    expect(row.icon).toBe('[DIR]');
    expect(row.size).toBe('-');
  });

  it('carries the engine queue flags verbatim', () => {
    const rows = listingRows([
      child({ id: new Uint8Array(16).fill(1), name: 'a', pending: 'content' }),
      child({ id: new Uint8Array(16).fill(2), name: 'b', deadLetter: true }),
    ]);

    expect(rows[0].pending).toBe('content');
    expect(rows[1].deadLetter).toBe(true);
  });

  it('keys each row by its hex node id', () => {
    const [row] = listingRows([child({ id: new Uint8Array(16).fill(0xcd) })]);

    expect(row.key).toBe('cd'.repeat(16));
  });
});
