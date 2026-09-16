/**
 * The recorded-baseline runner (`tools/perf/RESULTS.md`).
 *
 * It drives `cipherbox-load`, which drives `cipherbox-engine`'s real API client
 * over the desktop `Http` seam — so a baseline measures the shipping client
 * path, and this runner holds no HTTP client, no percentile arithmetic and no
 * credential of its own.
 */

import { spawnSync } from 'node:child_process';
import { measure } from './measure';
import { parseOptions, USAGE } from './options';
import { breachesOf, renderTable } from './report';

function main(argv: readonly string[]): number {
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }
  const options = parseOptions(argv);
  if (!process.env.LOAD_TEST_SECRET) {
    throw new Error('LOAD_TEST_SECRET is unset; it must equal the API TEST_LOGIN_SECRET');
  }

  const deps = {
    spawn: (file: string, args: string[]) => spawnSync(file, args, { stdio: 'inherit' as const }),
    announce: (phase: string) => process.stderr.write(`\n>> ${phase}\n`),
  };
  const reports = options.scenarios.map((scenario) =>
    measure(options, scenario, process.env.CIPHERBOX_LOAD_BIN, deps)
  );
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
