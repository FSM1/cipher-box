import { describe, expect, it } from 'vitest';
import { binRows } from './binRows';
import { binEntry as entry } from '../test/authFakes';

/** The factory's own deletion time, so every expiry below is a fixed date. */
const NEW_YEAR = 1_767_225_600_000n;
const DAY = 86_400_000n;

describe('the bin rows', () => {
  it('names each entry by the name it carried where it was deleted', () => {
    const [row] = binRows([entry({ originName: 'invoice.pdf', kind: 'file' })], 30);

    expect(row.name).toBe('invoice.pdf');
    expect(row.icon).toBe('[FILE]');
    expect(row.key).toBe('07'.repeat(16));
  });

  it('neutralises the name a purge dialog reads back', () => {
    const [row] = binRows([entry({ originName: 'report\u202Efdp.exe' })], 30);

    expect(row.name).toBe('reportfdp.exe');
  });

  it('marks a folder apart from a file', () => {
    expect(binRows([entry({ kind: 'folder' })], 30)[0].icon).toBe('[DIR]');
  });

  it('dates the expiry off the vault retention rather than a figure of its own', () => {
    const [thirty] = binRows([entry()], 30);
    const [seven] = binRows([entry()], 7);

    expect(thirty.expires).not.toBeNull();
    expect(seven.expires).not.toBeNull();
    expect(thirty.expires).not.toBe(seven.expires);
    expect(thirty.expires).toBe(
      binRows([entry({ deletedAt: NEW_YEAR + 23n * DAY })], 7)[0].expires
    );
  });

  it('dates no expiry before the retention has been read', () => {
    expect(binRows([entry()], null)[0].expires).toBeNull();
  });

  it('dates no expiry where the vault deletes outright', () => {
    // Retention 0 keeps the hard delete, so nothing it left behind ages out.
    expect(binRows([entry()], 0)[0].expires).toBeNull();
  });

  it('dates no expiry off a retention that is not a whole count of days', () => {
    // `BigInt` throws on a fraction, and the throw would take the route down.
    expect(binRows([entry()], 7.5)[0].expires).toBeNull();
  });

  it('keeps a deletion time out of range from taking the whole list down', () => {
    const rows = binRows([entry({ deletedAt: 9_000_000_000_000_000n }), entry()], 30);

    expect(rows).toHaveLength(2);
    expect(rows[0].deleted).toBe('-');
    expect(rows[0].expires).toBe('-');
  });

  it('lists the newest deletion first, then by name', () => {
    const rows = binRows(
      [
        entry({ originName: 'b', deletedAt: NEW_YEAR }),
        entry({ originName: 'a', deletedAt: NEW_YEAR }),
        entry({ originName: 'c', deletedAt: NEW_YEAR + DAY }),
      ],
      30
    );

    expect(rows.map((row) => row.name)).toEqual(['c', 'a', 'b']);
  });

  it('names the origin folder, so one name deleted from two folders reads apart', () => {
    const rows = binRows(
      [
        entry({ originFolder: { kind: 'folder', name: 'work' } }),
        entry({ originFolder: { kind: 'folder', name: 'holiday' } }),
      ],
      30
    );

    expect(rows.map((row) => row.origin)).toEqual(['holiday', 'work']);
  });

  it('names the root and a gone folder in words, never as a blank', () => {
    const originOf = (originFolder: Parameters<typeof entry>[0]) =>
      binRows([entry(originFolder)], 30)[0].origin;

    expect(originOf({ originFolder: { kind: 'root' } })).toBe('root');
    expect(originOf({ originFolder: { kind: 'gone' } })).toBe('a folder that is gone');
    // A name that neutralises away entirely would otherwise render as nothing.
    expect(originOf({ originFolder: { kind: 'folder', name: '\u202E' } })).toBe(
      'a folder with no readable name'
    );
  });

  it('neutralises the origin folder name, which another vault may have authored', () => {
    const [row] = binRows([entry({ originFolder: { kind: 'folder', name: 'we\u202Elrok' } })], 30);

    expect(row.origin).toBe('welrok');
  });

  it('ties by the name it shows, so a stripped control cannot move a row', () => {
    // A leading tab sorts ahead of every letter but renders as nothing.
    const rows = binRows(
      [
        entry({ originName: '\tzebra', deletedAt: NEW_YEAR }),
        entry({ originName: 'apple', deletedAt: NEW_YEAR }),
      ],
      30
    );

    expect(rows.map((row) => row.name)).toEqual(['apple', 'zebra']);
  });
});
