import type { SharingInviteLinkDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import type { ScopeSharing } from '../stores/sharing.store';
import { expiryAt, expiryLabel, inviteLinkState, inviteUrl } from './inviteLink';

const NO_LINKS: SharingInviteLinkDescriptor[] = [];
const LINK: SharingInviteLinkDescriptor = {
  tag: new Uint8Array(32).fill(1),
  permission: 'read',
  expiresAt: 1_000n,
  expired: false,
  admissionCap: 5,
  pendingClaims: 0,
  contactBudgetFull: false,
};

const scope = (
  inviteLinks: SharingInviteLinkDescriptor[],
  inviteLinkRefusal: string | null = null
): ScopeSharing => ({ grants: [], grantRefusal: null, inviteLinkRefusal, inviteLinks });

describe('the link URL', () => {
  it('carries the capability in the fragment, which reaches no server', () => {
    const url = new URL(inviteUrl('a-fragment'));

    expect(url.pathname).toBe('/invite');
    expect(url.hash).toBe('#a-fragment');
    expect(url.search).toBe('');
  });
});

describe('the deadline a mint sends', () => {
  it('is the engine bigint for each lifetime', () => {
    expect(expiryAt('7 days', 1_000)).toBe(BigInt(1_000 + 7 * 86_400_000));
    expect(expiryAt('30 days', 1_000)).toBe(BigInt(1_000 + 30 * 86_400_000));
  });
});

describe('the deadline label', () => {
  it('takes the engine verdict rather than re-deciding it against a browser clock', () => {
    // A deadline far in the future, which a clock comparison would draw as live.
    expect(expiryLabel(true, 4_000_000_000_000n)).toBe('expired');
  });

  it('refuses a deadline no date can hold rather than rendering an invalid one', () => {
    expect(expiryLabel(false, 2n ** 63n)).toBe('expires beyond any date');
  });
});

describe('which link situation a scope is in', () => {
  it('reports the link a scope carries over any mint verdict', () => {
    expect(inviteLinkState(scope([LINK], 'invite-parent-envelope-version-unsupported'))).toEqual({
      kind: 'live',
      link: LINK,
    });
  });

  it('draws the first link still claimable, past one that expired', () => {
    const expired = { ...LINK, tag: new Uint8Array(32).fill(2), expired: true };
    const fresh = { ...LINK, tag: new Uint8Array(32).fill(3) };

    expect(inviteLinkState(scope([expired, fresh]))).toEqual({ kind: 'live', link: fresh });
  });

  it('offers a mint where every link the scope carries has expired', () => {
    expect(inviteLinkState(scope([{ ...LINK, expired: true }]))).toEqual({ kind: 'mintable' });
  });

  it('offers a mint only where the engine would take one', () => {
    expect(inviteLinkState(scope(NO_LINKS))).toEqual({ kind: 'mintable' });
  });

  it('carries the engine’s own ground for a refusal, whichever rule it was', () => {
    for (const check of [
      'invite-target-is-the-vault-root',
      'invite-parent-envelope-version-unsupported',
    ]) {
      expect(inviteLinkState(scope(NO_LINKS, check))).toEqual({ kind: 'refused', check });
    }
  });
});
