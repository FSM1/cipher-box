/**
 * The night of the staging soak (`.github/workflows/staging-soak.yml`): the
 * verdict of each leg from its job result and its result lines, the joined
 * summary, and the body of the `ci: the staging soak failed` issue. A `failure`
 * is a failed night; a `cancelled` or `skipped` leg is a skipped night that
 * shows in the summary only (blueprint/deploy.md "Scheduled tier").
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { cell, parseRecords, renderSummary, unfinishedTests, type SoakRecord } from './summary';

/** The job ids of the soak workflow, in the order the legs run. */
export const SOAK_LEGS = [
  'web-vault',
  'web-shares',
  'desktop-macos',
  'desktop-linux',
  'desktop-windows',
] as const;

/** The job that checks the inputs before any leg reaches staging. */
export const GUARD_JOB = 'guard';

export type SoakLeg = (typeof SOAK_LEGS)[number];

export type Verdict = 'passed' | 'failed' | 'skipped';

/** What the report found of one leg's result lines. */
export type LegResults =
  | { readonly kind: 'records'; readonly records: readonly SoakRecord[] }
  | { readonly kind: 'missing' }
  | { readonly kind: 'unparsable'; readonly problem: string };

export interface LegReport {
  readonly leg: SoakLeg;
  /** The job result; a value GitHub did not document shows as it came. */
  readonly result: string;
  readonly verdict: Verdict;
  readonly checks: number;
  readonly note: string;
  readonly records: readonly SoakRecord[];
}

export interface Night {
  readonly verdict: Verdict;
  /** The result of the input check. */
  readonly guard: string;
  readonly legs: readonly LegReport[];
}

/** The job results of the soak workflow, from `toJSON(needs)`. */
export interface JobResults {
  readonly guard: string;
  readonly legs: Readonly<Record<SoakLeg, string>>;
}

/** The artifact each leg uploads its result lines under. */
export function resultsArtifact(leg: SoakLeg): string {
  return `soak-results-${leg}`;
}

/** The result of each job, from `toJSON(needs)`. A job with no result is `missing`. */
export function jobResults(needsJson: string): JobResults {
  const needs = JSON.parse(needsJson) as Record<string, { result?: unknown } | undefined>;
  const result = (job: string): string => {
    const value = needs[job]?.result;
    return typeof value === 'string' ? value : 'missing';
  };
  return {
    guard: result(GUARD_JOB),
    legs: Object.fromEntries(SOAK_LEGS.map((leg) => [leg, result(leg)])) as Record<SoakLeg, string>,
  };
}

/** Whether the run found a vault with no soak ledger: this skips `web-shares` and the desktop legs. */
export function unbootstrapped(records: readonly SoakRecord[]): boolean {
  return records.some(
    (entry) =>
      entry.kind === 'check' &&
      entry.outcome === 'failed' &&
      entry.reason === 'unbootstrapped-or-wiped'
  );
}

// A stopped step killed its host or browser at an unknown point, so an op it
// had queued or sent can still reach staging after the job ended.
const STOPPED_NOTE =
  'The leg stopped before its end line. A write it started can still land on staging.';

export function classifyLeg(leg: SoakLeg, result: string, found: LegResults): LegReport {
  const records = found.kind === 'records' ? found.records : [];
  const checks = records.filter((entry) => entry.kind === 'check');
  const failedChecks = checks.filter((entry) => entry.outcome === 'failed').length;
  const stopped = unfinishedTests(records).length > 0;
  const notes: string[] = [];
  if (found.kind === 'unparsable') notes.push(`The result lines do not parse: ${found.problem}.`);
  if (stopped) notes.push(STOPPED_NOTE);

  let verdict: Verdict;
  if (result === 'cancelled' || result === 'skipped') {
    verdict = 'skipped';
  } else if (result === 'success') {
    if (found.kind === 'missing' || checks.length === 0) {
      notes.push('The job passed and recorded no check.');
      verdict = 'failed';
    } else {
      verdict = failedChecks > 0 || found.kind === 'unparsable' || stopped ? 'failed' : 'passed';
    }
  } else {
    // `failure`, and every result GitHub does not document, fail closed.
    if (found.kind === 'missing') notes.push('The leg uploaded no result lines.');
    verdict = 'failed';
  }

  return { leg, result, verdict, checks: checks.length, note: notes.join(' '), records };
}

export function classifyNight(
  results: JobResults,
  found: Readonly<Record<SoakLeg, LegResults>>
): Night {
  const legs = SOAK_LEGS.map((leg) => classifyLeg(leg, results.legs[leg], found[leg]));
  const guardFailed = results.guard !== 'success' && results.guard !== 'cancelled';
  const verdict: Verdict =
    guardFailed || legs.some((leg) => leg.verdict === 'failed')
      ? 'failed'
      : results.guard === 'cancelled' || legs.some((leg) => leg.verdict === 'skipped')
        ? 'skipped'
        : 'passed';
  return { verdict, guard: results.guard, legs };
}

/** The result lines of each leg, from the directory the report downloads the artifacts to. */
export async function readLegResults(dir: string): Promise<Record<SoakLeg, LegResults>> {
  const entries = await Promise.all(
    SOAK_LEGS.map(async (leg): Promise<[SoakLeg, LegResults]> => {
      let text: string;
      try {
        text = await readFile(join(dir, resultsArtifact(leg), 'soak-results.jsonl'), 'utf8');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [leg, { kind: 'missing' }];
        throw error;
      }
      try {
        return [leg, { kind: 'records', records: parseRecords(text) }];
      } catch (error) {
        return [leg, { kind: 'unparsable', problem: (error as Error).message }];
      }
    })
  );
  return Object.fromEntries(entries) as Record<SoakLeg, LegResults>;
}

const VERDICT_LINE: Readonly<Record<Verdict, string>> = {
  passed: 'The soak night passed.',
  failed: 'The soak night failed.',
  skipped: 'The soak night was skipped in part. A skipped leg opens no issue.',
};

function guardLine(night: Night): string[] {
  return night.guard === 'success'
    ? []
    : [`The input check ended \`${night.guard}\`, so no leg ran against staging.`, ''];
}

function legTable(night: Night): string[] {
  return [
    '| Leg | Job | Verdict | Checks | Note |',
    '| --- | --- | --- | --- | --- |',
    ...night.legs.map(
      (leg) => `| ${leg.leg} | ${leg.result} | ${leg.verdict} | ${leg.checks} | ${cell(leg.note)} |`
    ),
  ];
}

/** The job summary of the report: the legs, then every check that a leg recorded. */
export function renderNight(night: Night, runUrl: string): string {
  const out = ['## Staging soak night', '', VERDICT_LINE[night.verdict], '', `Run: ${runUrl}`, ''];
  out.push(...guardLine(night), ...legTable(night), '', '');
  const joined = night.legs.flatMap((leg) => leg.records);
  return `${out.join('\n')}${renderSummary(joined)}`;
}

/** The issue text of a failed night; `null` for a night that did not fail. */
export function issueBody(night: Night, runUrl: string): string | null {
  if (night.verdict !== 'failed') return null;
  const out = [
    `The staging soak failed. Run: ${runUrl}`,
    '',
    ...guardLine(night),
    ...legTable(night),
  ];
  const failures = night.legs
    .filter((leg) => leg.verdict === 'failed')
    .flatMap((leg) =>
      [...leg.records, ...unfinishedTests(leg.records)].flatMap((entry) =>
        entry.kind === 'check' && entry.outcome === 'failed'
          ? [`- ${leg.leg}: ${entry.check}: \`${entry.reason}\`: ${entry.detail}`]
          : []
      )
    );
  if (failures.length > 0) out.push('', 'Failed checks:', '', ...failures);
  return `${out.join('\n')}\n`;
}
