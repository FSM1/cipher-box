import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Refusals that the Web3Auth sapphire devnet nodes raise under their own load.
 * A fault window outlasts one attempt, so a match waits and tries again; any
 * other refusal is a real failure and ends the sign-in at once.
 */
export type DevnetFault = 'nonce' | 'rss-round' | 'poly-commits' | 'node-quorum' | 'node-5xx';

const DEVNET_FAULTS: ReadonlyArray<readonly [DevnetFault, RegExp]> = [
  ['nonce', /could not retrieve nonce|failed to get nonce/i],
  ['rss-round', /cannot perform rss round/i],
  ['poly-commits', /master poly commits inconsistent/i],
  ['node-quorum', /unable to resolve enough promises/i],
  ['node-5xx', /request to \S*web3auth\.io failed with status 5\d\d/i],
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

/** What a sign-in does after a refused attempt. */
export type NextStep =
  | { action: 'retry'; fault: DevnetFault; waitMs: number }
  | { action: 'fail'; fault: DevnetFault | null; result: 'refused' | 'exhausted' };

/**
 * Decides the step after refused `attempt` (0-based), `elapsedMs` into the
 * sign-in. Once a sign-in in this run has exhausted the backoff or its budget,
 * the devnet is down for the run, and a later sign-in that waits again only
 * pushes the run past its step timeout.
 */
export function nextStep(
  attempt: number,
  refusal: string,
  runExhausted: boolean,
  elapsedMs: number
): NextStep {
  const fault = devnetFault(refusal);
  if (fault === null) return { action: 'fail', fault, result: 'refused' };
  const waitMs = DEVNET_BACKOFF_MS[attempt];
  if (runExhausted || waitMs === undefined || elapsedMs + waitMs > SIGN_IN_RETRY_BUDGET_MS) {
    return { action: 'fail', fault, result: 'exhausted' };
  }
  return { action: 'retry', fault, waitMs };
}

// A file, not module state: Playwright starts a new worker after a failed
// test, and the output directory is emptied at the start of each run.
const EXHAUSTED_FILE = 'devnet-exhausted';

export function runExhausted(outputDir: string): boolean {
  return existsSync(join(outputDir, EXHAUSTED_FILE));
}

export function markRunExhausted(outputDir: string): void {
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(join(outputDir, EXHAUSTED_FILE), '');
}

/** A devnet fault that a sign-in waited out, on its 1-based attempt. */
export interface AbsorbedFault {
  fault: DevnetFault;
  attempt: number;
}

/**
 * One sign-in, as the stats see it: the faults it absorbed, by attempt, and how
 * it ended. `exhausted` failed on a devnet fault after the last wait or past
 * the budget; `refused`
 * failed at once on any other refusal. It holds no identity, path or token.
 */
export interface SignInRecord {
  faults: readonly AbsorbedFault[];
  result: 'signed-in' | 'recovered' | 'exhausted' | 'refused';
}

/** The annotation type a sign-in record travels under to the reporter. */
export const SIGN_IN_ANNOTATION = 'devnet-sign-in';

/** The one summary line a staging run prints. */
export function summarize(records: readonly SignInRecord[]): string {
  const byFault = new Map<DevnetFault, number>();
  for (const { faults } of records) {
    for (const { fault } of faults) byFault.set(fault, (byFault.get(fault) ?? 0) + 1);
  }
  const absorbed = [...byFault].map(([fault, count]) => `${fault}=${count}`).join(' ') || 'none';
  const count = (result: SignInRecord['result']) =>
    records.filter((record) => record.result === result).length;
  return (
    `sign-ins: ${records.length}, recovered: ${count('recovered')}, ` +
    `absorbed faults: ${absorbed}, failed after all retries: ${count('exhausted')}, ` +
    `refused: ${count('refused')}`
  );
}
