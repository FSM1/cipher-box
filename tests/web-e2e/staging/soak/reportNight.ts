/**
 * The soak workflow's entry to `night.ts`:
 *
 * - `unbootstrapped <results-file>` prints `unbootstrapped=true|false` for
 *   `GITHUB_OUTPUT`.
 * - `report <results-dir> <out-dir>` reads `SOAK_NEEDS` (`toJSON(needs)`) and
 *   `SOAK_RUN_URL`, writes `summary.md`, and writes `issue.md` only for a
 *   failed night.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  classifyNight,
  issueBody,
  jobResults,
  readLegResults,
  renderNight,
  unbootstrapped,
} from './night';
import { parseRecords } from './summary';

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') throw new Error(`${name} is not set`);
  return value;
}

async function readOrEmpty(file: string): Promise<string> {
  try {
    return await readFile(file, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return '';
    throw error;
  }
}

const [command, first, second] = process.argv.slice(2);

if (command === 'unbootstrapped' && first !== undefined) {
  const found = unbootstrapped(parseRecords(await readOrEmpty(first)));
  process.stdout.write(`unbootstrapped=${found}\n`);
} else if (command === 'report' && first !== undefined && second !== undefined) {
  const runUrl = required('SOAK_RUN_URL');
  const night = classifyNight(jobResults(required('SOAK_NEEDS')), await readLegResults(first));
  await mkdir(second, { recursive: true });
  await writeFile(join(second, 'summary.md'), renderNight(night, runUrl));
  const body = issueBody(night, runUrl);
  if (body !== null) await writeFile(join(second, 'issue.md'), body);
  process.stdout.write(`The soak night: ${night.verdict}.\n`);
} else {
  process.stderr.write(
    'Usage: reportNight.ts unbootstrapped <results-file> | report <results-dir> <out-dir>\n'
  );
  process.exitCode = 2;
}
