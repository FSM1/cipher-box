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

/** The wait before each retry of a devnet fault: 3.5 minutes in total. */
export const DEVNET_BACKOFF_MS: readonly number[] = [15_000, 30_000, 60_000, 105_000];

/**
 * One sign-in, as the stats see it: the faults it absorbed, by attempt, and how
 * it ended. `exhausted` failed on a devnet fault after the last wait; `refused`
 * failed at once on any other refusal. It holds no identity, path or token.
 */
export interface SignInRecord {
  faults: ReadonlyArray<{ fault: DevnetFault; attempt: number }>;
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
