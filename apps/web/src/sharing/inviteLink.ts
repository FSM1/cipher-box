import { toHex } from '@cipherbox/client';
import type { Permission, SharingInviteLinkDescriptor } from '@cipherbox/client';
import type { GrantRow } from '../stores/sharing.store';
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
 * How long a minted link stays claimable. Every link entry carries an
 * owner-signed deadline, so no choice is unbounded.
 */
export const LINK_LIFETIMES = {
  '7 days': 7,
  '30 days': 30,
} as const;

export type LinkLifetime = keyof typeof LINK_LIFETIMES;

/** The unix-millis deadline the engine takes. */
export function expiryAt(lifetime: LinkLifetime, now: number): bigint {
  return BigInt(now + LINK_LIFETIMES[lifetime] * 86_400_000);
}

/**
 * How the engine's link standing reads to its owner. Whether the deadline has
 * passed is the engine's verdict, read against its own clock — this only draws
 * it.
 */
export function expiryLabel(expired: boolean, expiresAt: bigint): string {
  if (expired) return 'expired';
  return expiresAt > MAX_DATE_MILLIS
    ? 'expires beyond any date'
    : `expires ${formatDate(Number(expiresAt))}`;
}

/** How a permission reads on the share dialog. */
export function accessLabel(permission: Permission): string {
  return permission === 'write' ? 'edit' : 'view';
}

/** A link names itself by what it grants and when it ends, since it carries no name. */
export function linkLabel(link: SharingInviteLinkDescriptor): string {
  return `${accessLabel(link.permission)} link, ${expiryLabel(link.expired, link.expiresAt)}`;
}

/** The grants a link admitted, by the via-link tag each row carries. */
export function joinedThrough(
  grants: readonly GrantRow[],
  link: SharingInviteLinkDescriptor
): GrantRow[] {
  const tag = toHex(link.tag);
  return grants.filter((grant) => grant.viaLink === tag);
}
