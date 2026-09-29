/**
 * The soak results and the job summary. Each check appends one JSON line to the
 * results file as it settles; the writer renders the file as the markdown the
 * workflow appends to `GITHUB_STEP_SUMMARY`. The summary is public, so a detail
 * is one short line of assertion text and never carries a key or a token.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSoakReason, reasonKind, SOAK_REASONS, type FailureReason } from './reasons';

/** Inside Playwright's output folder, which a run clears when it starts. */
export const RESULTS_FILE = fileURLToPath(
  new URL('../../test-results/soak-results.jsonl', import.meta.url)
);

const DETAIL_CHARS = 300;

export type SoakRecord =
  | { readonly kind: 'check'; readonly check: string; readonly outcome: 'passed' }
  | {
      readonly kind: 'check';
      readonly check: string;
      readonly outcome: 'failed';
      readonly reason: FailureReason;
      readonly detail: string;
    }
  | { readonly kind: 'fact'; readonly label: string; readonly value: string };

/** One results line. Refuses a record that {@link parseRecords} would reject. */
export function encodeRecord(record: SoakRecord): string {
  const problem = invalid(record);
  if (problem !== null) throw new Error(`a soak record is not writable: ${problem}`);
  return JSON.stringify(record);
}

export function parseRecords(text: string): SoakRecord[] {
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line, index) => {
      let value: unknown;
      try {
        value = JSON.parse(line);
      } catch {
        throw new Error(`results line ${index + 1} is not JSON`);
      }
      const problem = invalid(value);
      if (problem !== null) throw new Error(`results line ${index + 1}: ${problem}`);
      return value as SoakRecord;
    });
}

export async function record(entry: SoakRecord, file = RESULTS_FILE): Promise<void> {
  const line = encodeRecord(entry);
  await mkdir(dirname(file), { recursive: true });
  await appendFile(file, `${line}\n`);
}

/**
 * The failed line for a test that did not end as expected and whose failure no
 * check recorded, such as a fixture error or a timeout; `null` otherwise.
 */
export function unrecordedFailure(
  title: string,
  status: string | undefined,
  expectedStatus: string,
  recordedFailures: number
): SoakRecord | null {
  if (status === expectedStatus || recordedFailures > 0) return null;
  return {
    kind: 'check',
    check: title,
    outcome: 'failed',
    reason: 'unrecorded-failure',
    detail: `the test ended ${status ?? 'without a status'}`,
  };
}

/** The first line of `text`, cut to the summary's budget. */
export function shortDetail(text: string): string {
  const first = text.split('\n', 1)[0]!.trim();
  return first.length > DETAIL_CHARS ? `${first.slice(0, DETAIL_CHARS - 3)}...` : first;
}

export function renderSummary(records: readonly SoakRecord[]): string {
  const checks = records.filter((entry) => entry.kind === 'check');
  const facts = records.filter((entry) => entry.kind === 'fact');
  const failed = checks.filter((entry) => entry.outcome === 'failed').length;

  const verdict =
    checks.length === 0
      ? 'The soak failed: no check recorded a result.'
      : failed > 0
        ? `${failed} of ${checks.length} soak checks failed.`
        : `All ${checks.length} soak checks passed.`;

  const out = ['## Staging soak', '', verdict];
  if (checks.length > 0) {
    out.push('', '| Check | Outcome | Reason | Detail |', '| --- | --- | --- | --- |');
    for (const entry of checks) {
      const [reason, detail] =
        entry.outcome === 'passed'
          ? ['', '']
          : [`\`${entry.reason}\`: ${SOAK_REASONS[entry.reason].meaning}`, entry.detail];
      out.push(`| ${cell(entry.check)} | ${entry.outcome} | ${cell(reason)} | ${cell(detail)} |`);
    }
  }
  if (facts.length > 0) {
    out.push('', '| Fact | Value |', '| --- | --- |');
    for (const entry of facts) out.push(`| ${cell(entry.label)} | ${cell(entry.value)} |`);
  }
  return `${out.join('\n')}\n`;
}

function cell(text: string): string {
  return text.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
}

function invalid(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return 'not an object';
  const entry = value as Record<string, unknown>;
  if (entry.kind === 'fact') {
    return nonEmpty(entry.label) && typeof entry.value === 'string'
      ? null
      : 'a fact needs a label and a value';
  }
  if (entry.kind !== 'check' || !nonEmpty(entry.check)) return 'a check needs a name';
  if (entry.outcome === 'passed') {
    return entry.reason === undefined ? null : 'a passed check names no reason';
  }
  if (entry.outcome !== 'failed') return 'an unknown outcome';
  if (!isSoakReason(entry.reason)) return 'an unknown reason code';
  if (reasonKind(entry.reason) !== 'failure') return 'a failed check needs a failure reason';
  return typeof entry.detail === 'string' ? null : 'a detail must be text';
}

function nonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim() !== '';
}
