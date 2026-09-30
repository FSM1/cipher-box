import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  classifyLeg,
  classifyNight,
  issueBody,
  jobResults,
  readLegResults,
  renderNight,
  resultsArtifact,
  SOAK_LEGS,
  unbootstrapped,
  type JobResults,
  type LegResults,
  type SoakLeg,
} from './night';
import { encodeRecord, type SoakRecord } from './summary';

const RUN = 'https://github.example/runs/1';

const passed: SoakRecord = { kind: 'check', check: 'owner sign-in', outcome: 'passed' };
const failed: SoakRecord = {
  kind: 'check',
  check: 'owner markers',
  outcome: 'failed',
  reason: 'marker-unreadable',
  detail: 'day 3 did not open',
};
const wiped: SoakRecord = {
  kind: 'check',
  check: 'owner vault',
  outcome: 'failed',
  reason: 'unbootstrapped-or-wiped',
  detail: 'the owner vault has no soak/ledger.txt',
};
const started: SoakRecord = { kind: 'test', test: 'macos desktop leg', phase: 'started' };
const ended: SoakRecord = { kind: 'test', test: 'macos desktop leg', phase: 'ended' };

const lines = (...records: SoakRecord[]): LegResults => ({ kind: 'records', records });

function everyLeg<T>(value: T): Record<SoakLeg, T> {
  return Object.fromEntries(SOAK_LEGS.map((leg) => [leg, value])) as Record<SoakLeg, T>;
}

const results = (legs: Record<SoakLeg, string>, guard = 'success'): JobResults => ({ guard, legs });

describe('the job results', () => {
  it('read the guard and each leg from the needs context, and mark an absent job', () => {
    const needs = JSON.stringify({
      guard: { result: 'success', outputs: {} },
      'web-vault': { result: 'failure', outputs: { unbootstrapped: 'true' } },
      'web-shares': { result: 'skipped', outputs: {} },
    });
    const found = jobResults(needs);
    expect(found.guard).toBe('success');
    expect(found.legs['web-vault']).toBe('failure');
    expect(found.legs['web-shares']).toBe('skipped');
    expect(found.legs['desktop-windows']).toBe('missing');
    expect(jobResults('{}').guard).toBe('missing');
  });
});

describe('the unbootstrapped verdict', () => {
  it('holds only for a failed check with the unbootstrapped reason', () => {
    expect(unbootstrapped([passed, wiped])).toBe(true);
    expect(unbootstrapped([passed, failed])).toBe(false);
    expect(unbootstrapped([])).toBe(false);
  });
});

describe('a leg', () => {
  it('passes when its job passed and every check it recorded passed', () => {
    const leg = classifyLeg('web-vault', 'success', lines(passed));
    expect(leg).toMatchObject({ verdict: 'passed', checks: 1, note: '' });
  });

  it('fails when its job failed', () => {
    expect(classifyLeg('web-vault', 'failure', lines(passed, failed)).verdict).toBe('failed');
    expect(classifyLeg('web-vault', 'failure', { kind: 'missing' })).toMatchObject({
      verdict: 'failed',
      note: 'The leg uploaded no result lines.',
    });
  });

  it('fails closed on a passed job with a failed check, no check, or lines that do not parse', () => {
    expect(classifyLeg('web-vault', 'success', lines(passed, failed)).verdict).toBe('failed');
    expect(classifyLeg('web-vault', 'success', { kind: 'missing' }).verdict).toBe('failed');
    expect(classifyLeg('web-vault', 'success', lines()).verdict).toBe('failed');
    const unparsable = classifyLeg('web-vault', 'success', {
      kind: 'unparsable',
      problem: 'results line 2 is not JSON',
    });
    expect(unparsable.verdict).toBe('failed');
    expect(unparsable.note).toContain('results line 2 is not JSON');
  });

  it('fails closed on a job result GitHub does not document', () => {
    expect(classifyLeg('desktop-linux', 'missing', lines(passed)).verdict).toBe('failed');
  });

  it('is skipped when its job was cancelled or skipped, and keeps its lines', () => {
    for (const result of ['cancelled', 'skipped']) {
      const leg = classifyLeg('desktop-macos', result, lines(started, failed));
      expect(leg.verdict).toBe('skipped');
      expect(leg.records).toEqual([started, failed]);
    }
  });

  it('that stopped under a test says a write can still land, and never passes', () => {
    const timedOut = classifyLeg('desktop-macos', 'failure', lines(started, passed));
    expect(timedOut.verdict).toBe('failed');
    expect(timedOut.note).toContain('can still land on staging');

    const cancelled = classifyLeg('desktop-macos', 'cancelled', lines(started, passed));
    expect(cancelled.verdict).toBe('skipped');
    expect(cancelled.note).toContain('can still land on staging');

    expect(classifyLeg('desktop-macos', 'success', lines(started, passed)).verdict).toBe('failed');
    expect(classifyLeg('desktop-macos', 'success', lines(started, passed, ended))).toMatchObject({
      verdict: 'passed',
      note: '',
    });
  });
});

describe('a night', () => {
  it('passes when every leg passed, and opens no issue', () => {
    const night = classifyNight(results(everyLeg('success')), everyLeg(lines(passed)));
    expect(night.verdict).toBe('passed');
    expect(issueBody(night, RUN)).toBeNull();
  });

  it('with a cancelled leg and no failure is skipped, and opens no issue', () => {
    const night = classifyNight(
      results({ ...everyLeg('success'), 'desktop-linux': 'cancelled' }),
      everyLeg(lines(passed))
    );
    expect(night.verdict).toBe('skipped');
    expect(issueBody(night, RUN)).toBeNull();
    expect(renderNight(night, RUN)).toContain('| desktop-linux | cancelled | skipped |');
  });

  it('with one failed leg fails, and the issue names the leg and its reason code', () => {
    const night = classifyNight(results({ ...everyLeg('skipped'), 'web-vault': 'failure' }), {
      ...everyLeg<LegResults>({ kind: 'missing' }),
      'web-vault': lines(wiped),
    });
    expect(night.verdict).toBe('failed');
    const body = issueBody(night, RUN);
    expect(body).toContain(RUN);
    expect(body).toContain('| web-vault | failure | failed | 1 |');
    expect(body).toContain('| desktop-macos | skipped | skipped | 0 |');
    expect(body).toContain('- web-vault: owner vault: `unbootstrapped-or-wiped`');
  });

  it('names a test that a stopped leg left unfinished in the issue', () => {
    const night = classifyNight(results({ ...everyLeg('success'), 'desktop-macos': 'failure' }), {
      ...everyLeg(lines(passed)),
      'desktop-macos': lines(started, passed),
    });
    expect(issueBody(night, RUN)).toContain(
      '- desktop-macos: macos desktop leg: `test-unfinished`'
    );
  });

  it('joins the checks of every leg into one summary, a skipped leg too', () => {
    const night = classifyNight(
      results({ ...everyLeg('success'), 'web-shares': 'failure', 'desktop-windows': 'cancelled' }),
      {
        ...everyLeg(lines(passed)),
        'web-shares': lines(failed),
        'desktop-windows': lines(failed),
      }
    );
    const summary = renderNight(night, RUN);
    expect(summary).toContain('The soak night failed.');
    expect(summary).toContain('| desktop-windows | cancelled | skipped | 1 |');
    // Three legs gave a passed check, and two legs a failed check.
    expect(summary).toContain('2 of 5 soak checks failed.');
    // Only the failed leg reaches the issue.
    const body = issueBody(night, RUN)!;
    expect(body).toContain('- web-shares: owner markers');
    expect(body).not.toContain('- desktop-windows:');
  });

  it('names the suite ref in the summary and the issue when the report has it', () => {
    const night = classifyNight(
      results({ ...everyLeg('success'), 'web-vault': 'failure' }),
      everyLeg(lines(failed))
    );
    const suite = 'staging-20260928-release-1 at abc';
    expect(renderNight(night, RUN, suite)).toContain(`Suite: ${suite}`);
    expect(issueBody(night, RUN, suite)).toContain(`Suite: ${suite}`);
    expect(renderNight(night, RUN)).not.toContain('Suite:');
  });

  it('fails when the input check failed, and skips when it was cancelled', () => {
    const none = everyLeg<LegResults>({ kind: 'missing' });
    const refused = classifyNight(results(everyLeg('skipped'), 'failure'), none);
    expect(refused.verdict).toBe('failed');
    expect(issueBody(refused, RUN)).toContain('The input check ended `failure`');

    const cancelled = classifyNight(results(everyLeg('skipped'), 'cancelled'), none);
    expect(cancelled.verdict).toBe('skipped');
    expect(issueBody(cancelled, RUN)).toBeNull();
  });
});

describe('the result files', () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  });

  it('read per leg artifact, and tell a missing file from lines that do not parse', async () => {
    dir = await mkdtemp(join(tmpdir(), 'soak-night-'));
    const write = async (leg: SoakLeg, text: string) => {
      await mkdir(join(dir!, resultsArtifact(leg)), { recursive: true });
      await writeFile(join(dir!, resultsArtifact(leg), 'soak-results.jsonl'), text);
    };
    await write('web-vault', `${encodeRecord(passed)}\n${encodeRecord(failed)}\n`);
    await write('desktop-linux', 'not json\n');

    const found = await readLegResults(dir);
    expect(found['web-vault']).toEqual(lines(passed, failed));
    expect(found['desktop-linux'].kind).toBe('unparsable');
    expect(found['desktop-macos']).toEqual({ kind: 'missing' });
  });
});
