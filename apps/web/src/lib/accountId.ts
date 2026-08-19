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
