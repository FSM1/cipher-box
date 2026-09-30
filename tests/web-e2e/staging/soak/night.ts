/**
 * The night of the staging soak (`.github/workflows/staging-soak.yml`): the
 * verdict of each leg from its job result and its result lines, the joined
 * summary, and the body of the `ci: the staging soak failed` issue. A `failure`
 * is a failed night; a `cancelled` or `skipped` leg is a skipped night that
 * shows in the summary only (blueprint/deploy.md "Scheduled tier").
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseRecords, renderSummary, type SoakRecord } from './summary';

/** The job ids of the soak workflow, in the order the legs run. */
export const SOAK_LEGS = [
  'web-vault',
  'web-shares',
  'desktop-macos',
  'desktop-linux',
  'desktop-windows',
] as const;

export type SoakLeg = (typeof SOAK_LEGS)[number];

export type JobResult = 'success' | 'failure' | 'cancelled' | 'skipped';

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
  /** The result lines that go into the joined summary: a skipped leg gives none. */
  readonly records: readonly SoakRecord[];
}

export interface Night {
  readonly verdict: Verdict;
  readonly legs: readonly LegReport[];
}

/** The artifact each leg uploads its result lines under. */
export function resultsArtifact(leg: SoakLeg): string {
  return `soak-results-${leg}`;
}

/** The job result of each leg, from `toJSON(needs)`. A leg with no result is `missing`. */
export function jobResults(needsJson: string): Record<SoakLeg, string> {
  const needs = JSON.parse(needsJson) as Record<string, { result?: unknown } | undefined>;
  return Object.fromEntries(
    SOAK_LEGS.map((leg) => {
      const result = needs[leg]?.result;
      return [leg, typeof result === 'string' ? result : 'missing'];
    })
  ) as Record<SoakLeg, string>;
}

/** Whether the run found a vault with no soak ledger: only this skips the desktop legs. */
export function unbootstrapped(records: readonly SoakRecord[]): boolean {
  return records.some(
    (entry) =>
      entry.kind === 'check' &&
      entry.outcome === 'failed' &&
      entry.reason === 'unbootstrapped-or-wiped'
  );
}

/** Tests that wrote a `started` line and no `ended` line: the step was stopped under them. */
function stoppedMidRun(records: readonly SoakRecord[]): boolean {
  const open = new Map<string, number>();
  for (const entry of records) {
    if (entry.kind !== 'test') continue;
    open.set(entry.test, (open.get(entry.test) ?? 0) + (entry.phase === 'started' ? 1 : -1));
  }
  return [...open.values()].some((count) => count > 0);
}

// A stopped step killed its host or browser at an unknown point, so an op it
// had queued or sent can still reach staging after the job ended.
const STOPPED_NOTE =
  'The leg stopped before its end line. A write it started can still land on staging.';

export function classifyLeg(leg: SoakLeg, result: string, found: LegResults): LegReport {
  const records = found.kind === 'records' ? found.records : [];
  const checks = records.filter((entry) => entry.kind === 'check');
  const failedChecks = checks.filter((entry) => entry.outcome === 'failed').length;
  const stopped = stoppedMidRun(records);
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

  return {
    leg,
    result,
    verdict,
    checks: checks.length,
    note: notes.join(' '),
    records: verdict === 'skipped' ? [] : records,
  };
}

export function classifyNight(
  results: Readonly<Record<SoakLeg, string>>,
  found: Readonly<Record<SoakLeg, LegResults>>
): Night {
  const legs = SOAK_LEGS.map((leg) => classifyLeg(leg, results[leg], found[leg]));
  const verdict: Verdict = legs.some((leg) => leg.verdict === 'failed')
    ? 'failed'
    : legs.some((leg) => leg.verdict === 'skipped')
      ? 'skipped'
      : 'passed';
  return { verdict, legs };
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

function legTable(night: Night): string[] {
  return [
    '| Leg | Job | Verdict | Checks | Note |',
    '| --- | --- | --- | --- | --- |',
    ...night.legs.map(
      (leg) => `| ${leg.leg} | ${leg.result} | ${leg.verdict} | ${leg.checks} | ${cell(leg.note)} |`
    ),
  ];
}

/** The job summary of the report: the legs, then every check of the legs that ran. */
export function renderNight(night: Night, runUrl: string): string {
  const out = ['## Staging soak night', '', VERDICT_LINE[night.verdict], '', `Run: ${runUrl}`, ''];
  out.push(...legTable(night), '', '');
  const joined = night.legs.flatMap((leg) => leg.records);
  return `${out.join('\n')}${renderSummary(joined)}`;
}

/** The issue text of a failed night; `null` for a night that did not fail. */
export function issueBody(night: Night, runUrl: string): string | null {
  if (night.verdict !== 'failed') return null;
  const out = [`The staging soak failed. Run: ${runUrl}`, '', ...legTable(night)];
  const failures = night.legs.flatMap((leg) =>
    leg.records.flatMap((entry) =>
      entry.kind === 'check' && entry.outcome === 'failed'
        ? [`- ${leg.leg}: ${entry.check}: \`${entry.reason}\`: ${entry.detail}`]
        : []
    )
  );
  if (failures.length > 0) out.push('', 'Failed checks:', '', ...failures);
  return `${out.join('\n')}\n`;
}

function cell(text: string): string {
  return text.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
}
