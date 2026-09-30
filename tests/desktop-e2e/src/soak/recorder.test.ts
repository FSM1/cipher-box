import { describe, expect, it } from 'vitest';
import { SoakFailure } from '../../../web-e2e/staging/soak/reasons';
import { parseRecords, renderSummary } from '../../../web-e2e/staging/soak/summary';
import { Recorder } from './recorder';

function recorder(): { recorder: Recorder; lines: string[] } {
  const lines: string[] = [];
  return {
    recorder: new Recorder(async (line) => {
      lines.push(line);
    }),
    lines,
  };
}

describe('the leg recorder', () => {
  it('writes lines the web soak summary reads', async () => {
    const { recorder: leg, lines } = recorder();
    await leg.phase('macos desktop leg', 'started');
    await leg.check('macos sign-in', 'sign-in-failed', async () => 'signed in');
    await leg.fact('macos markers read', 'linux 2, web 1');
    await leg.phase('macos desktop leg', 'ended');

    expect(parseRecords(lines.join('\n'))).toEqual(leg.records);
    expect(leg.failures).toBe(0);
    expect(renderSummary(leg.records)).toContain('All 1 soak checks passed.');
  });

  it('records the reason of the step, or the one a soak failure names', async () => {
    const { recorder: leg } = recorder();
    await expect(
      leg.check('linux markers', 'desktop-marker-missing', async () => {
        throw new Error('the mount refused the read\nwith a second line');
      })
    ).rejects.toMatchObject({ reason: 'desktop-marker-missing' });
    await expect(
      leg.check('linux ledger', 'ledger-unreadable', async () => {
        throw new SoakFailure('unbootstrapped-or-wiped', 'no ledger');
      })
    ).rejects.toBeInstanceOf(SoakFailure);

    expect(leg.records).toEqual([
      {
        kind: 'check',
        check: 'linux markers',
        outcome: 'failed',
        reason: 'desktop-marker-missing',
        detail: 'the mount refused the read',
      },
      {
        kind: 'check',
        check: 'linux ledger',
        outcome: 'failed',
        reason: 'unbootstrapped-or-wiped',
        detail: 'no ledger',
      },
    ]);
    expect(leg.failures).toBe(2);
  });

  it('tells a failure a check recorded from one that ended the leg outside every check', async () => {
    const { recorder: leg } = recorder();
    const recorded = await leg
      .check('windows marker write', 'desktop-marker-unpublished', async () => {
        throw new Error('EIO');
      })
      .catch((error: unknown) => error);
    expect(leg.recorded(recorded)).toBe(true);
    expect(leg.recorded(new Error('elsewhere'))).toBe(false);

    await leg.unrecorded('windows desktop leg', new Error('the host exited'));
    expect(leg.records.at(-1)).toEqual({
      kind: 'check',
      check: 'windows desktop leg',
      outcome: 'failed',
      reason: 'unrecorded-failure',
      detail: 'the host exited',
    });
  });

  it('leaves a leg that never ended as an unfinished test in the summary', async () => {
    const { recorder: leg } = recorder();
    await leg.phase('linux desktop leg', 'started');
    expect(renderSummary(leg.records)).toContain('`test-unfinished`');
  });
});
