/** One scenario's measured run, apart from the entry point so the unit suite drives it. */

import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { command, type Options } from './options';
import { parseLoadReport, type BaselineScenario, type LoadReport } from './report';

/** What a harness invocation answered. `status` is null when a signal killed it. */
export interface RunOutcome {
  status: number | null;
  error?: Error;
}

export type Spawn = (file: string, args: string[]) => RunOutcome;

export interface MeasureDeps {
  spawn: Spawn;
  announce(phase: string): void;
}

/**
 * Two runs per scenario, and only the second is recorded.
 *
 * A first run against a cold stack measures the cold start: the database pool,
 * the Kubo repository and the API process all settle on it. On 2026-09-15 the
 * same local `content-ingest` retire leg read 8.6 s cold and 1.1 s warm, so a
 * one-run baseline records the warm-up rather than the system.
 *
 * Both phases write one report path, and the harness writes no report at all
 * when a run ends before it finishes — an unreachable API exits 1 with nothing
 * on disk. The measured phase therefore starts from a cleared path, so an
 * absent report is a refusal and never the warm-up read as the measurement.
 */
export function measure(
  options: Options,
  scenario: BaselineScenario,
  loadBinary: string | undefined,
  deps: MeasureDeps
): LoadReport {
  const { file, args } = command(options, scenario, loadBinary);
  const path = join(options.reportDir, `metrics-${scenario}-${options.target}.json`);

  for (const phase of ['warm-up', 'measured'] as const) {
    if (phase === 'measured') rmSync(path, { force: true });
    deps.announce(`${scenario} (${phase})`);
    const run = deps.spawn(file, args);
    if (run.error) throw run.error;
    if (run.status === null) throw new Error(`${scenario} ${phase} run was killed by a signal`);
  }

  if (!existsSync(path)) {
    throw new Error(
      `the measured ${scenario} run wrote no report to ${path}; the run did not finish`
    );
  }
  return parseLoadReport(readFileSync(path, 'utf8'));
}
