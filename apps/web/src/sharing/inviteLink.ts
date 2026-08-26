import type { SharingInviteLinksDescriptor } from '@cipherbox/client';
import type { ScopeSharing } from '../stores/sharing.store';
import { formatDate, MAX_DATE_MILLIS } from '../utils/format';

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

/**
 * How the engine's link standing reads to its owner. Whether the deadline has
 * passed is the engine's verdict, read against its own clock — this only draws
 * it.
 */
export function expiryLabel(links: SharingInviteLinksDescriptor): string {
  if (links.expired) return 'expired';
  if (links.expiresAt === null) return 'never expires';
  return links.expiresAt > MAX_DATE_MILLIS
    ? 'expires beyond any date'
    : `expires ${formatDate(Number(links.expiresAt))}`;
}

/** Which of the owner's four link situations a scope is in. */
export type InviteLinkState =
  | { kind: 'unavailable' }
  | { kind: 'live'; links: SharingInviteLinksDescriptor }
  | { kind: 'mintable' }
  | { kind: 'refused'; check: string };

/**
 * A scope the engine reached carries a live link, takes a mint, or takes
 * neither. `unavailable` is the owner's link records refusing to open, which a
 * render must not spell as "no link here"; `refused` carries the engine's own
 * check name, because which ground refuses is the engine's to say.
 */
export function inviteLinkState(scope: ScopeSharing): InviteLinkState {
  const links = scope.inviteLinks;
  if (links === null) return { kind: 'unavailable' };
  if (links.live) return { kind: 'live', links };
  const refusal = scope.inviteLinkRefusal;
  return refusal === null ? { kind: 'mintable' } : { kind: 'refused', check: refusal };
}
