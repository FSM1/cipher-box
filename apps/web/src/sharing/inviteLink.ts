/** The claim route, so the mint and the router name one destination. */
export const INVITE_ROUTE = '/invite';

/**
 * The link an owner hands out. The engine mints base64url, so the fragment
 * survives the URL unescaped and reaches the claim verbatim.
 */
export function inviteUrl(fragment: string): string {
  return `${window.location.origin}${INVITE_ROUTE}#${fragment}`;
}

/**
 * How long a minted link stays claimable. A link is a bearer capability with no
 * named recipient, so the default is bounded — `never` is the deliberate choice,
 * not the one a member falls into.
 */
export const LINK_LIFETIMES = {
  '7 days': 7,
  '30 days': 30,
  never: null,
} as const;

export type LinkLifetime = keyof typeof LINK_LIFETIMES;

/** The unix-millis deadline the engine takes, or `undefined` for no expiry. */
export function expiryAt(lifetime: LinkLifetime, now: number): bigint | undefined {
  const days = LINK_LIFETIMES[lifetime];
  return days === null ? undefined : BigInt(now + days * 86_400_000);
}
