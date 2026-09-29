import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { isSoakReason, reasonKind, SOAK_REASONS, SoakFailure } from './reasons';
import {
  encodeRecord,
  parseRecords,
  record,
  renderSummary,
  shortDetail,
  type SoakRecord,
} from './summary';

describe('the reason codes', () => {
  it('are kebab-case, and only post-deploy-window is a skip', () => {
    const codes = Object.keys(SOAK_REASONS);
    for (const code of codes) expect(code).toMatch(/^[a-z]+(-[a-z0-9]+)*$/);
    expect(codes.filter((code) => isSoakReason(code) && reasonKind(code) === 'skip')).toEqual([
      'post-deploy-window',
    ]);
  });

  it('refuse a code outside the list', () => {
    expect(isSoakReason('unbootstrapped-or-wiped')).toBe(true);
    expect(isSoakReason('toString')).toBe(false);
    expect(isSoakReason('marker unreadable')).toBe(false);
  });

  it('lead the failure message', () => {
    expect(new SoakFailure('marker-unreadable', 'day 3').message).toBe('[marker-unreadable] day 3');
  });
});

describe('the soak records', () => {
  const records: SoakRecord[] = [
    { kind: 'check', check: 'owner sign-in', outcome: 'passed' },
    {
      kind: 'check',
      check: 'owner ledger',
      outcome: 'failed',
      reason: 'unbootstrapped-or-wiped',
      detail: 'the owner vault has no soak/ledger.txt',
    },
    {
      kind: 'check',
      check: 'counters',
      outcome: 'skipped',
      reason: 'post-deploy-window',
      detail: 'up 3 h',
    },
    { kind: 'fact', label: 'owner ledger markers', value: '0' },
  ];

  it('round-trip through the results lines', () => {
    const text = `${records.map(encodeRecord).join('\n')}\n`;
    expect(parseRecords(text)).toEqual(records);
  });

  it.each([
    [
      'a passed check with a reason',
      { kind: 'check', check: 'a', outcome: 'passed', reason: 'purge-missed' },
    ],
    [
      'a failed check with a skip reason',
      { kind: 'check', check: 'a', outcome: 'failed', reason: 'post-deploy-window', detail: '' },
    ],
    [
      'a skipped check with a failure reason',
      { kind: 'check', check: 'a', outcome: 'skipped', reason: 'purge-missed', detail: '' },
    ],
    [
      'an unknown reason',
      { kind: 'check', check: 'a', outcome: 'failed', reason: 'gone', detail: '' },
    ],
    [
      'a failed check with no detail',
      { kind: 'check', check: 'a', outcome: 'failed', reason: 'purge-missed' },
    ],
    ['an unnamed check', { kind: 'check', check: ' ', outcome: 'passed' }],
    ['an unknown outcome', { kind: 'check', check: 'a', outcome: 'flaky' }],
    ['a fact with no label', { kind: 'fact', label: '', value: '1' }],
  ])('refuse %s on both sides', (_label, value) => {
    expect(() => encodeRecord(value as unknown as SoakRecord)).toThrow(/not writable/);
    expect(() => parseRecords(JSON.stringify(value))).toThrow(/results line 1/);
  });

  it('refuse a line that is not JSON', () => {
    expect(() => parseRecords('{"kind":"check"\n')).toThrow('results line 1 is not JSON');
  });

  describe('in a results file', () => {
    let dir = '';
    afterEach(async () => {
      if (dir !== '') await rm(dir, { recursive: true, force: true });
    });

    it('append one line per record', async () => {
      dir = await mkdtemp(join(tmpdir(), 'soak-results-'));
      const file = join(dir, 'nested', 'soak-results.jsonl');
      for (const entry of records) await record(entry, file);
      expect(parseRecords(await readFile(file, 'utf8'))).toEqual(records);
    });
  });
});

describe('the job summary', () => {
  it('says so when no check recorded a result', () => {
    expect(renderSummary([])).toBe('## Staging soak\n\nNo soak check recorded a result.\n');
  });

  it('counts the failed checks and names each reason with its meaning', () => {
    const summary = renderSummary([
      { kind: 'check', check: 'owner sign-in', outcome: 'passed' },
      {
        kind: 'check',
        check: 'owner ledger',
        outcome: 'failed',
        reason: 'unbootstrapped-or-wiped',
        detail: 'no ledger | at all',
      },
      { kind: 'fact', label: 'owner ledger markers', value: '0' },
    ]);
    expect(summary).toContain('1 of 2 soak checks failed.');
    expect(summary).toContain('| owner sign-in | passed |  |  |');
    expect(summary).toContain(
      `| owner ledger | failed | \`unbootstrapped-or-wiped\`: ${SOAK_REASONS['unbootstrapped-or-wiped'].meaning} | no ledger \\| at all |`
    );
    expect(summary).toContain('| owner ledger markers | 0 |');
  });

  it('passes a night whose checks passed or skipped', () => {
    expect(
      renderSummary([
        { kind: 'check', check: 'a', outcome: 'passed' },
        { kind: 'check', check: 'b', outcome: 'skipped', reason: 'post-deploy-window', detail: '' },
      ])
    ).toContain('All 2 soak checks passed or skipped.');
  });

  it('cuts a detail to its first line and the budget', () => {
    expect(shortDetail('first\nsecond')).toBe('first');
    const long = shortDetail('x'.repeat(500));
    expect(long).toHaveLength(300);
    expect(long.endsWith('...')).toBe(true);
  });
});
