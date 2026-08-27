/** Display formatting for the vault browser. */

// One byte formatter for the app: the storage pane's chrome derives its figures
// in `@cipherbox/client`, which is where it therefore lives.
export { formatBytes } from '@cipherbox/client';

/** Past this, `Intl` throws on the `Date` rather than formatting it. */
export const MAX_DATE_MILLIS = 8_640_000_000_000_000n;

/** Locale-aware date for a Unix-millisecond timestamp. */
export function formatDate(timestampMillis: number): string {
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(new Date(timestampMillis));
}

/**
 * An account id is a secp256k1 public point written as two hex coordinates
 * (`packages/login` `accountIdFromTssPoint`) — 129 characters, unreadable in a
 * banner. This is the form a user can compare against another tab's, taken from
 * both ends so two accounts sharing a leading run still read apart.
 */
const HEAD = 6;
const TAIL = 4;

export function shortAccountId(accountId: string): string {
  if (accountId.length <= HEAD + TAIL + 1) return accountId;
  return `${accountId.slice(0, HEAD)}…${accountId.slice(-TAIL)}`;
}
