import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { measure, type RunOutcome } from './measure';
import { parseOptions } from './options';

const BINARY = '/somewhere/cipherbox-load';

function report(p50: number): string {
  return JSON.stringify({
    scenario: 'mixed',
    breaches: [],
    operations: [
      {
        op: 'content-upload',
        count: 1,
        throttled: 0,
        failed: 0,
        p50Ms: p50,
        p95Ms: p50,
        p99Ms: p50,
        opsPerSec: 1,
      },
    ],
  });
}

describe('measure', () => {
  let dir: string;
  let path: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'cipherbox-perf-'));
    path = join(dir, 'metrics-mixed-local.json');
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function options() {
    return parseOptions(['--target', 'local', '--report-dir', dir]);
  }

  /** A harness that writes `p50` on each phase it is told to succeed at. */
  function harness(phases: readonly (number | 'fails')[]) {
    const announced: string[] = [];
    let call = 0;
    const spawn = (): RunOutcome => {
      const phase = phases[call];
      call += 1;
      if (phase === 'fails') return { status: 1 };
      writeFileSync(path, report(phase));
      return { status: 0 };
    };
    return { deps: { spawn, announce: (phase: string) => announced.push(phase) }, announced };
  }

  it('records the second run and not the first', () => {
    const { deps, announced } = harness([999, 42]);
    const measured = measure(options(), 'mixed', BINARY, deps);
    expect(measured.operations[0].p50Ms).toBe(42);
    expect(announced).toEqual(['mixed (warm-up)', 'mixed (measured)']);
  });

  it('refuses the warm-up numbers when the measured run wrote no report', () => {
    const { deps } = harness([999, 'fails']);
    expect(() => measure(options(), 'mixed', BINARY, deps)).toThrow(/wrote no report/);
  });

  it('refuses a report left behind by an earlier session', () => {
    writeFileSync(path, report(7));
    const { deps } = harness(['fails', 'fails']);
    expect(() => measure(options(), 'mixed', BINARY, deps)).toThrow(/wrote no report/);
  });

  it('reports the signal that killed a run', () => {
    const deps = { spawn: (): RunOutcome => ({ status: null }), announce: () => undefined };
    expect(() => measure(options(), 'mixed', BINARY, deps)).toThrow(/killed by a signal/);
  });

  it('reports a harness that could not be started', () => {
    const boom = new Error('spawnSync ENOENT');
    const deps = {
      spawn: (): RunOutcome => ({ status: 1, error: boom }),
      announce: () => undefined,
    };
    expect(() => measure(options(), 'mixed', BINARY, deps)).toThrow(boom);
  });

  it('keeps the measured report on disk for the run that follows', () => {
    const { deps } = harness([999, 42]);
    measure(options(), 'mixed', BINARY, deps);
    expect(JSON.parse(readFileSync(path, 'utf8')).operations[0].p50Ms).toBe(42);
  });
});
