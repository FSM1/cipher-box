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
  unrecordedFailure,
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
    { kind: 'fact', label: 'owner ledger markers', value: '0' },
    {
      kind: 'check',
      check: 'walks in 24 hours',
      outcome: 'skipped',
      reason: 'post-deploy-window',
      detail: 'the API is up 3.0 hours',
    },
    { kind: 'test', test: 'the owner vault', phase: 'started' },
    { kind: 'test', test: 'the owner vault', phase: 'ended' },
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
      { kind: 'check', check: 'a', outcome: 'skipped', reason: 'no-walk-in-window', detail: '' },
    ],
    [
      'a skipped check with no detail',
      { kind: 'check', check: 'a', outcome: 'skipped', reason: 'post-deploy-window' },
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
    ['a test line with no phase', { kind: 'test', test: 't' }],
    ['a test line with no title', { kind: 'test', test: '', phase: 'started' }],
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
    expect(renderSummary([])).toBe(
      '## Staging soak\n\nThe soak failed: no check recorded a result.\n'
    );
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

  it('passes a night whose checks all passed', () => {
    expect(
      renderSummary([
        { kind: 'check', check: 'a', outcome: 'passed' },
        { kind: 'check', check: 'b', outcome: 'passed' },
      ])
    ).toContain('All 2 soak checks passed.');
  });

  it('counts a skipped check apart, and names its reason', () => {
    const skip: SoakRecord = {
      kind: 'check',
      check: 'walks in 24 hours',
      outcome: 'skipped',
      reason: 'post-deploy-window',
      detail: 'the API is up 3.0 hours',
    };
    const passed = renderSummary([{ kind: 'check', check: 'a', outcome: 'passed' }, skip]);
    expect(passed).toContain('All 1 soak checks passed. 1 skipped.');
    expect(passed).toContain(
      `| walks in 24 hours | skipped | \`post-deploy-window\`: ${SOAK_REASONS['post-deploy-window'].meaning} | the API is up 3.0 hours |`
    );
    const failed = renderSummary([
      { kind: 'check', check: 'a', outcome: 'failed', reason: 'purge-missed', detail: 'x' },
      skip,
    ]);
    expect(failed).toContain('1 of 2 soak checks failed. 1 skipped.');
  });

  it('cuts a detail to its first line and the budget', () => {
    expect(shortDetail('first\nsecond')).toBe('first');
    const long = shortDetail('x'.repeat(500));
    expect(long).toHaveLength(300);
    expect(long.endsWith('...')).toBe(true);
  });
});

describe('an unrecorded failure', () => {
  it('records a test that failed outside every check', () => {
    const missed = unrecordedFailure(
      { title: 'the owner vault', status: 'timedOut', expectedStatus: 'passed' },
      0
    );
    expect(missed).toEqual({
      kind: 'check',
      check: 'the owner vault',
      outcome: 'failed',
      reason: 'unrecorded-failure',
      detail: 'the test ended timedOut',
    });
    expect(renderSummary([missed!])).toContain('1 of 1 soak checks failed.');
  });

  it('adds nothing when the test ended as expected or a check recorded the failure', () => {
    expect(
      unrecordedFailure({ title: 't', status: 'passed', expectedStatus: 'passed' }, 0)
    ).toBeNull();
    expect(
      unrecordedFailure({ title: 't', status: 'failed', expectedStatus: 'passed' }, 1)
    ).toBeNull();
  });
});

describe('an unfinished test', () => {
  const passed: SoakRecord = { kind: 'check', check: 'owner ledger', outcome: 'passed' };

  it('fails a test that started and wrote no end line', () => {
    const summary = renderSummary([
      { kind: 'test', test: 'the owner vault', phase: 'started' },
      passed,
      { kind: 'test', test: 'the owner vault', phase: 'ended' },
      { kind: 'test', test: 'the grantee vault', phase: 'started' },
      passed,
    ]);
    expect(summary).toContain('1 of 3 soak checks failed.');
    expect(summary).toContain('| the grantee vault | failed | `test-unfinished`');
    expect(summary).not.toContain('| the owner vault | failed');
  });

  it('passes a night whose every test ended', () => {
    expect(
      renderSummary([
        { kind: 'test', test: 'a', phase: 'started' },
        passed,
        { kind: 'test', test: 'a', phase: 'ended' },
      ])
    ).toContain('All 1 soak checks passed.');
  });
});
