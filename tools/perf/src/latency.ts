/**
 * Summarizes one cross-client run's wait samples into the RESULTS.md
 * convergence-latency table.
 *
 * usage: pnpm --filter @cipherbox/perf latency <samples.jsonl>
 */

import { readFileSync } from 'node:fs';
import { group, parseSamples, renderWaits } from './waits';

const path = process.argv.slice(2).find((argument) => argument !== '--');
if (!path) {
  process.stderr.write('usage: pnpm --filter @cipherbox/perf latency <samples.jsonl>\n');
  process.exitCode = 1;
} else {
  const samples = parseSamples(readFileSync(path, 'utf8'));
  if (samples.length === 0) {
    process.stderr.write(`${path} holds no wait sample; the run measured nothing\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`${renderWaits(group(samples))}\n`);
  }
}
