import { toHex } from '@cipherbox/client';
import type { SharingInviteLinkDescriptor } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import type { GrantRow } from '../stores/sharing.store';
import {
  accessLabel,
  expiryAt,
  expiryLabel,
  inviteUrl,
  joinedThrough,
  linkLabel,
  unclearGrants,
} from './inviteLink';

const LINK: SharingInviteLinkDescriptor = {
  tag: new Uint8Array(32).fill(1),
  permission: 'read',
  expiresAt: 1_000n,
  expired: false,
  admissionCap: 5,
  pendingClaims: 0,
  contactBudgetFull: false,
  refusedClaims: 0,
};

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

describe('how a link names itself', () => {
  it('says what it grants and when it ends', () => {
    expect(linkLabel({ ...LINK, permission: 'write', expired: true })).toBe('edit link, expired');
    expect(accessLabel('read')).toBe('view');
  });
});

describe('who joined through a link', () => {
  const row = (seed: number, viaLink: Uint8Array | null): GrantRow => ({
    contact: { key: toHex(new Uint8Array(33).fill(seed)), identityPublicKey: new Uint8Array(33) },
    permission: 'read',
    name: null,
    viaLink: viaLink === null ? null : toHex(viaLink),
    fingerprint: null,
  });

  it('takes the rows whose via-link tag is that link, and no direct grant', () => {
    const joined = row(1, LINK.tag);
    const other = row(2, new Uint8Array(32).fill(9));
    const direct = row(3, null);

    expect(joinedThrough([joined, other, direct], LINK)).toEqual([joined]);
  });

  it('holds unclear only a row with no link and no name', () => {
    const linked = row(1, LINK.tag);
    const named = { ...row(2, null), name: { name: 'Ada', source: 'owner' as const } };
    const bare = row(3, null);

    expect(unclearGrants([linked, named, bare])).toEqual([bare]);
  });
});
