import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Refusals that the Web3Auth sapphire devnet nodes raise under their own load.
 * A fault window outlasts one attempt, so a match waits and tries again; any
 * other refusal is a real failure and ends the sign-in at once.
 */
export type DevnetFault =
  | 'nonce'
  | 'rss-round'
  | 'poly-commits'
  | 'node-quorum'
  | 'node-5xx'
  | 'node-busy';

const DEVNET_FAULTS: ReadonlyArray<readonly [DevnetFault, RegExp]> = [
  ['nonce', /could not retrieve nonce|failed to get nonce/i],
  ['rss-round', /cannot perform rss round/i],
  ['poly-commits', /master poly commits inconsistent/i],
  ['node-quorum', /unable to resolve enough promises/i],
  ['node-5xx', /request to \S*web3auth\.io failed with status 5\d\d/i],
  ['node-busy', /all auth network nodes are currently busy/i],
];

export function devnetFault(refusal: string): DevnetFault | null {
  return DEVNET_FAULTS.find(([, pattern]) => pattern.test(refusal))?.[0] ?? null;
}

/** The wait before each retry of a devnet fault. */
export const DEVNET_BACKOFF_MS: readonly number[] = [15_000, 30_000, 60_000, 105_000];

/**
 * The time one sign-in may spend on its retries. An attempt can wait minutes
 * for a refusal, so the backoff alone does not bound a sign-in.
 */
export const SIGN_IN_RETRY_BUDGET_MS = 480_000;

/**
 * The default run window. A Playwright project overrides it under
 * {@link RUN_RETRY_BUDGET_KEY}; each project's window stays below the hard
 * limit of the step that runs it.
 */
export const RUN_SIGN_IN_RETRY_BUDGET_MS = 3_600_000;

/** The project metadata key that carries a project's run window. */
export const RUN_RETRY_BUDGET_KEY = 'runSignInRetryBudgetMs';

/** The run window `metadata` names, or the default. */
export function runRetryBudget(metadata: Readonly<Record<string, unknown>>): number {
  const budget = metadata[RUN_RETRY_BUDGET_KEY];
  if (budget === undefined) return RUN_SIGN_IN_RETRY_BUDGET_MS;
  if (typeof budget !== 'number' || !Number.isSafeInteger(budget) || budget <= 0) {
    throw new Error(`the project metadata ${RUN_RETRY_BUDGET_KEY} is invalid`);
  }
  return budget;
}

export type RetryStop = 'attempts-exhausted' | 'sign-in-budget' | 'run-budget';

/** What a sign-in does after a refused attempt. */
export type NextStep =
  | { action: 'retry'; fault: DevnetFault; waitMs: number }
  | { action: 'fail'; fault: DevnetFault | null; result: 'refused' | RetryStop };

/**
 * Decides the step after refused `attempt` (0-based), `elapsedMs` into the
 * sign-in. A wait must leave time for another attempt inside both deadlines.
 */
export function nextStep(
  attempt: number,
  refusal: string,
  runRemainingMs: number,
  elapsedMs: number
): NextStep {
  const fault = devnetFault(refusal);
  if (fault === null) return { action: 'fail', fault, result: 'refused' };
  const waitMs = DEVNET_BACKOFF_MS[attempt];
  if (waitMs === undefined) return { action: 'fail', fault, result: 'attempts-exhausted' };
  if (elapsedMs + waitMs >= SIGN_IN_RETRY_BUDGET_MS) {
    return { action: 'fail', fault, result: 'sign-in-budget' };
  }
  if (waitMs >= runRemainingMs) return { action: 'fail', fault, result: 'run-budget' };
  return { action: 'retry', fault, waitMs };
}

// A file, not module state: Playwright starts a new worker after a failed
// test, and the output directory is emptied at the start of each run.
export const DEADLINE_FILE = 'devnet-retry-deadline';

/** The first login starts the window; later logins and replacement workers keep that deadline. */
export function runRetryDeadline(
  outputDir: string,
  now: number,
  budgetMs = RUN_SIGN_IN_RETRY_BUDGET_MS
): number {
  mkdirSync(outputDir, { recursive: true });
  const file = join(outputDir, DEADLINE_FILE);
  try {
    writeFileSync(file, String(now + budgetMs), { flag: 'wx' });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  const deadline = Number(readFileSync(file, 'utf8'));
  if (!Number.isSafeInteger(deadline) || deadline <= 0) {
    throw new Error('the sign-in retry deadline is invalid');
  }
  return deadline;
}

/** A devnet fault observed on a 1-based attempt, including a terminal refusal. */
export interface SignInFault {
  fault: DevnetFault;
  attempt: number;
}

/**
 * One sign-in, as the stats see it: the faults it observed, by attempt, and how
 * it ended. It holds no identity, path or token.
 */
export interface SignInRecord {
  faults: readonly SignInFault[];
  result: 'signed-in' | 'recovered' | RetryStop | 'refused';
}

/** The annotation type a sign-in record travels under to the reporter. */
export const SIGN_IN_ANNOTATION = 'devnet-sign-in';

/** The one summary line a staging run prints. */
export function summarize(records: readonly SignInRecord[]): string {
  const byFault = new Map<DevnetFault, number>();
  for (const { faults } of records) {
    for (const { fault } of faults) byFault.set(fault, (byFault.get(fault) ?? 0) + 1);
  }
  const observed = [...byFault].map(([fault, count]) => `${fault}=${count}`).join(' ') || 'none';
  const count = (result: SignInRecord['result']) =>
    records.filter((record) => record.result === result).length;
  return (
    `sign-ins: ${records.length}, recovered: ${count('recovered')}, ` +
    `observed faults: ${observed}, attempts exhausted: ${count('attempts-exhausted')}, ` +
    `sign-in budget exhausted: ${count('sign-in-budget')}, ` +
    `retries suppressed by run budget: ${count('run-budget')}, ` +
    `refused: ${count('refused')}`
  );
}
