/**
 * Prints the soak job summary to stdout, for the workflow to append:
 * `pnpm exec tsx staging/soak/writeSummary.ts >> "$GITHUB_STEP_SUMMARY"`.
 * A run that recorded nothing still prints a summary that says so.
 */

import { readFile } from 'node:fs/promises';
import { parseRecords, renderSummary, RESULTS_FILE } from './summary';

let text = '';
try {
  text = await readFile(RESULTS_FILE, 'utf8');
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
}

try {
  process.stdout.write(renderSummary(parseRecords(text)));
} catch (error) {
  process.stdout.write(
    `## Staging soak\n\nThe soak results do not parse: ${(error as Error).message}\n`
  );
  process.exitCode = 1;
}
