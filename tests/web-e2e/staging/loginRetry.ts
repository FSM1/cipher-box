/**
 * Refusals that the Web3Auth sapphire devnet nodes raise under their own load.
 * A fault window outlasts one attempt, so a match waits and tries again; any
 * other refusal is a real failure and ends the sign-in at once.
 */
const DEVNET_FAULTS: readonly RegExp[] = [
  /could not retrieve nonce/i,
  /failed to get nonce/i,
  /cannot perform rss round/i,
  /master poly commits inconsistent/i,
  /unable to resolve enough promises/i,
  /request to \S*web3auth\.io failed with status 5\d\d/i,
];

export function isDevnetFault(refusal: string): boolean {
  return DEVNET_FAULTS.some((fault) => fault.test(refusal));
}

/** The wait before each retry of a devnet fault: 3.5 minutes in total. */
export const DEVNET_BACKOFF_MS: readonly number[] = [15_000, 30_000, 60_000, 105_000];
