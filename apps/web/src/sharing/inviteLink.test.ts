import type { SharingInviteLinksDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import type { ScopeSharing } from '../stores/sharing.store';
import { expiryAt, expiryLabel, inviteLinkState, inviteUrl } from './inviteLink';

const NO_LINKS: SharingInviteLinksDescriptor = {
  live: false,
  expired: false,
  expiresAt: null,
  spent: 0,
};

const scope = (
  inviteLinks: SharingInviteLinksDescriptor | null,
  canMintShare = true
): ScopeSharing => ({ grants: [], canMintShare, inviteLinks });

describe('the link URL', () => {
  it('carries the capability in the fragment, which reaches no server', () => {
    const url = new URL(inviteUrl('a-fragment'));

    expect(url.pathname).toBe('/invite');
    expect(url.hash).toBe('#a-fragment');
    expect(url.search).toBe('');
  });
});

describe('the deadline a mint sends', () => {
  it('is the engine bigint for a bounded lifetime, and absent for none', () => {
    expect(expiryAt('7 days', 1_000)).toBe(BigInt(1_000 + 7 * 86_400_000));
    expect(expiryAt('never', 1_000)).toBeUndefined();
  });
});

describe('the deadline label', () => {
  it('takes the engine verdict rather than re-deciding it against a browser clock', () => {
    // A deadline far in the future, which a clock comparison would draw as live.
    const links = { ...NO_LINKS, live: true, expired: true, expiresAt: 4_000_000_000_000n };

    expect(expiryLabel(links)).toBe('expired');
  });

  it('names a link that never expires rather than showing a date', () => {
    expect(expiryLabel({ ...NO_LINKS, live: true })).toBe('never expires');
  });

  it('refuses a deadline no date can hold rather than rendering an invalid one', () => {
    const beyond = { ...NO_LINKS, live: true, expiresAt: 2n ** 63n };

    expect(expiryLabel(beyond)).toBe('expires beyond any date');
  });
});

describe('which link situation a scope is in', () => {
  it('withholds a verdict where the owner’s records would not open', () => {
    expect(inviteLinkState(scope(null))).toEqual({ kind: 'unavailable' });
  });

  it('reports the link a scope carries over any mint verdict', () => {
    const links = { ...NO_LINKS, live: true };

    expect(inviteLinkState(scope(links, true))).toEqual({ kind: 'live', links });
  });

  it('offers a mint only where the engine would take one', () => {
    expect(inviteLinkState(scope(NO_LINKS, true))).toEqual({ kind: 'mintable' });
    expect(inviteLinkState(scope(NO_LINKS, false))).toEqual({ kind: 'refused' });
  });
});
