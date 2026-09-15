/**
 * The recorded-baseline runner (`tools/perf/RESULTS.md`).
 *
 * It drives `cipherbox-load`, which drives `cipherbox-engine`'s real API client
 * over the desktop `Http` seam — so a baseline measures the shipping client
 * path, and this runner holds no HTTP client, no percentile arithmetic and no
 * credential of its own.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { command, parseOptions, USAGE, type Options } from './options';
import { breachesOf, parseLoadReport, renderTable, type BaselineScenario } from './report';

/**
 * Two runs per scenario, and only the second is recorded.
 *
 * A first run against a cold stack measures the cold start: the database pool,
 * the Kubo repository and the API process all settle on it. On 2026-09-15 the
 * same local `content-ingest` retire leg read 8.6 s cold and 1.1 s warm, so a
 * one-run baseline records the warm-up rather than the system.
 */
function measure(options: Options, scenario: BaselineScenario) {
  const { file, args } = command(options, scenario, process.env.CIPHERBOX_LOAD_BIN);
  for (const phase of ['warm-up', 'measured']) {
    process.stderr.write(`\n>> ${scenario} (${phase})\n`);
    const run = spawnSync(file, args, { stdio: 'inherit' });
    if (run.error) throw run.error;
    if (run.status === null) throw new Error(`${scenario} ${phase} run was killed by a signal`);
  }
  const path = join(options.reportDir, `metrics-${scenario}-${options.target}.json`);
  return parseLoadReport(readFileSync(path, 'utf8'));
}

function main(argv: readonly string[]): number {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }
  const options = parseOptions(argv);
  if (!process.env.LOAD_TEST_SECRET) {
    throw new Error('LOAD_TEST_SECRET is unset; it must equal the API TEST_LOGIN_SECRET');
  }

  const reports = options.scenarios.map((scenario) => measure(options, scenario));
  process.stdout.write(`\n${renderTable(reports)}\n`);

  const breaches = breachesOf(reports);
  if (breaches.length === 0) return 0;
  for (const breach of breaches) process.stderr.write(`threshold breach: ${breach}\n`);
  // The rows above stay the run's record: a breach names a collapse detector,
  // and a baseline is taken to see one rather than to hide it.
  return 1;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`baseline: ${error instanceof Error ? error.message : String(error)}\n\n`);
  process.stderr.write(USAGE);
  process.exitCode = 1;
}
