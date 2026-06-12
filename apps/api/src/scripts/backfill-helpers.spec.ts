import { selectRowsToDelete, parseKuboPinLs } from './backfill-helpers';

type Row = { id: string; userId: string; cid: string; isByoUser: boolean };

describe('selectRowsToDelete', () => {
  const nonByoRow: Row = { id: '1', userId: 'u1', cid: 'cid-a', isByoUser: false };
  const byoRow: Row = { id: '2', userId: 'u2', cid: 'cid-b', isByoUser: true };
  const nonByoPinnedRow: Row = { id: '3', userId: 'u3', cid: 'cid-c', isByoUser: false };

  it('selects non-BYO rows whose CID is absent from the Kubo set', () => {
    const kuboPinSet = new Set<string>(['cid-c']);
    const result = selectRowsToDelete([nonByoRow], kuboPinSet);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('1');
  });

  it('never selects BYO rows even when CID is absent from the Kubo set (D-09 exclusion)', () => {
    const kuboPinSet = new Set<string>(); // cid-b is absent
    const result = selectRowsToDelete([byoRow], kuboPinSet);
    expect(result).toHaveLength(0);
  });

  it('does not select a non-BYO row whose CID is present in the Kubo set (legitimately pinned)', () => {
    const kuboPinSet = new Set<string>(['cid-c']);
    const result = selectRowsToDelete([nonByoPinnedRow], kuboPinSet);
    expect(result).toHaveLength(0);
  });

  it('selects only the phantom non-BYO rows from a mixed array', () => {
    const kuboPinSet = new Set<string>(['cid-c']); // cid-c is legitimately pinned
    const result = selectRowsToDelete([nonByoRow, byoRow, nonByoPinnedRow], kuboPinSet);
    // nonByoRow (cid-a absent, non-BYO) => selected
    // byoRow (cid-b absent, BYO) => not selected
    // nonByoPinnedRow (cid-c present, non-BYO) => not selected
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('1');
  });

  it('returns empty array when all non-BYO rows have their CIDs in the Kubo set', () => {
    const kuboPinSet = new Set<string>(['cid-a', 'cid-c']);
    const result = selectRowsToDelete([nonByoRow, nonByoPinnedRow], kuboPinSet);
    expect(result).toHaveLength(0);
  });
});

describe('parseKuboPinLs', () => {
  it('parses NDJSON lines and returns the set of CIDs from Keys', () => {
    const ndjson =
      JSON.stringify({ Keys: { 'cid-x': {}, 'cid-y': {} } }) +
      '\n' +
      JSON.stringify({ Keys: { 'cid-z': {} } });
    const result = parseKuboPinLs(ndjson);
    expect(result).toEqual(new Set(['cid-x', 'cid-y', 'cid-z']));
  });

  it('returns an empty Set for empty input', () => {
    expect(parseKuboPinLs('')).toEqual(new Set());
    expect(parseKuboPinLs('   ')).toEqual(new Set());
    expect(parseKuboPinLs('\n\n')).toEqual(new Set());
  });

  it('tolerates blank lines between NDJSON entries', () => {
    const ndjson =
      '\n' +
      JSON.stringify({ Keys: { 'cid-a': {} } }) +
      '\n\n' +
      JSON.stringify({ Keys: { 'cid-b': {} } }) +
      '\n';
    const result = parseKuboPinLs(ndjson);
    expect(result).toEqual(new Set(['cid-a', 'cid-b']));
  });

  it('handles a single NDJSON line with no trailing newline', () => {
    const ndjson = JSON.stringify({ Keys: { 'cid-only': {} } });
    const result = parseKuboPinLs(ndjson);
    expect(result).toEqual(new Set(['cid-only']));
  });

  it('handles lines that do not have a Keys field gracefully', () => {
    const ndjson =
      JSON.stringify({ Progress: 10 }) + '\n' + JSON.stringify({ Keys: { 'cid-present': {} } });
    const result = parseKuboPinLs(ndjson);
    expect(result).toEqual(new Set(['cid-present']));
  });
});
