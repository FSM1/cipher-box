import { toHex } from '@cipherbox/client';
import type {
  Permission,
  SharingDescriptor,
  SharingInviteLinksDescriptor,
} from '@cipherbox/client';
import { afterEach, describe, expect, it } from 'vitest';
import { sharingFor, sharingStore, type GrantRow } from './sharing.store';

const DOCS = new Uint8Array(16).fill(7);
const PHOTOS = new Uint8Array(16).fill(9);
const DOCS_KEY = toHex(DOCS);
const PHOTOS_KEY = toHex(PHOTOS);
const NO_LINKS: SharingInviteLinksDescriptor = {
  live: false,
  expired: false,
  expiresAt: null,
  spent: 0,
};

function identity(seed: number): Uint8Array {
  return new Uint8Array(33).fill(seed);
}

function key(seed: number): string {
  return toHex(identity(seed));
}

function grantsFor(scopeKey: string): readonly GrantRow[] | null {
  return sharingFor(sharingStore.getState(), scopeKey)?.grants ?? null;
}

/**
 * One engine sharing read: `contacts` by seed, `grants` by seed and permission.
 * A `null` ledger is a scope the read could not reach.
 */
function view(
  scope: Uint8Array,
  contacts: number[],
  grants: Array<[number, Permission]> | null = [],
  scopeState: Partial<{
    grantRefusal: string | null;
    inviteLinkRefusal: string | null;
    inviteLinks: SharingInviteLinksDescriptor | null;
  }> = {}
): SharingDescriptor {
  return {
    scope,
    contacts: contacts.map((seed) => ({
      identityPublicKey: identity(seed),
    })),
    state:
      grants === null
        ? null
        : {
            grants: grants.map(([seed, permission]) => ({
              recipientIdentityPublicKey: identity(seed),
              permission,
            })),
            grantRefusal: null,
            inviteLinkRefusal: null,
            inviteLinks: NO_LINKS,
            ...scopeState,
          },
  };
}

afterEach(() => sharingStore.clear());

describe('contacts', () => {
  it('holds the book the engine reported, keyed by identity', () => {
    sharingStore.reported(view(DOCS, [1, 2]));

    expect(sharingStore.getState().contacts).toEqual([
      { key: key(1), identityPublicKey: identity(1) },
      { key: key(2), identityPublicKey: identity(2) },
    ]);
  });

  it('replaces the book on the next read rather than accumulating across reads', () => {
    sharingStore.reported(view(DOCS, [1, 2]));
    sharingStore.reported(view(DOCS, [2]));

    expect(sharingStore.getState().contacts).toEqual([
      { key: key(2), identityPublicKey: identity(2) },
    ]);
  });
});

describe('grants', () => {
  it('lists the rows the engine reported under the scope it read', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'write']]));

    expect(grantsFor(DOCS_KEY)).toEqual([
      { contact: { key: key(1), identityPublicKey: identity(1) }, permission: 'write' },
    ]);
    expect(grantsFor(PHOTOS_KEY)).toBeNull();
  });

  it('holds no row a later read of the same scope stopped reporting', () => {
    sharingStore.reported(
      view(
        DOCS,
        [1, 2],
        [
          [1, 'write'],
          [2, 'read'],
        ]
      )
    );
    sharingStore.reported(view(DOCS, [1, 2], [[2, 'read']]));

    expect(grantsFor(DOCS_KEY)).toEqual([
      { contact: { key: key(2), identityPublicKey: identity(2) }, permission: 'read' },
    ]);
  });

  it('takes the permission the engine reported, not the one it last held', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'write']]));
    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));

    expect(grantsFor(DOCS_KEY)).toEqual([
      { contact: { key: key(1), identityPublicKey: identity(1) }, permission: 'read' },
    ]);
  });

  it('answers with no ledger at all for a scope no read has covered', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));

    expect(grantsFor(PHOTOS_KEY)).toBeNull();
  });

  it('leaves every other scope reference-equal when one scope is re-read', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));
    const docs = grantsFor(DOCS_KEY);
    sharingStore.reported(view(PHOTOS, [1], [[1, 'write']]));

    expect(grantsFor(DOCS_KEY)).toBe(docs);
  });

  it('keeps the rows standing when a read could not reach the scope root', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'write']]));
    sharingStore.reported(view(DOCS, [1], null));

    expect(grantsFor(DOCS_KEY)).toEqual([
      { contact: { key: key(1), identityPublicKey: identity(1) }, permission: 'write' },
    ]);
  });

  it('reports the emptiness of a scope that commits no grant', () => {
    sharingStore.reported(view(DOCS, [1]));

    expect(grantsFor(DOCS_KEY)).toEqual([]);
  });

  it('separates a first read that could not reach the root from a confirmed empty set', () => {
    sharingStore.reported(view(DOCS, [1], null));

    expect(grantsFor(DOCS_KEY)).toBeNull();
  });
});

describe('invite links', () => {
  const LIVE: SharingInviteLinksDescriptor = {
    live: true,
    expired: false,
    expiresAt: 1_700_000_000_000n,
    spent: 2,
  };
  const linked = () =>
    view(DOCS, [1], [[1, 'read']], {
      grantRefusal: 'grant-target-already-names-a-scope',
      inviteLinkRefusal: 'invite-target-already-names-a-scope',
      inviteLinks: LIVE,
    });

  it('holds the standing the engine reported alongside that scope’s grants', () => {
    sharingStore.reported(linked());

    expect(sharingFor(sharingStore.getState(), DOCS_KEY)).toMatchObject({
      grantRefusal: 'grant-target-already-names-a-scope',
      inviteLinkRefusal: 'invite-target-already-names-a-scope',
      inviteLinks: LIVE,
    });
  });

  it('keeps the standing that stood when a read could not reach the scope root', () => {
    sharingStore.reported(linked());
    sharingStore.reported(view(DOCS, [1], null));

    expect(sharingFor(sharingStore.getState(), DOCS_KEY)?.inviteLinks).toEqual(LIVE);
  });

  it('answers with no standing at all for a scope no read has covered', () => {
    sharingStore.reported(linked());

    expect(sharingFor(sharingStore.getState(), PHOTOS_KEY)).toBeNull();
  });

  it('takes fresh grants from a read whose link records the engine could not open', () => {
    sharingStore.reported(linked());
    sharingStore.reported(view(DOCS, [1], [], { inviteLinks: null }));

    const docs = sharingFor(sharingStore.getState(), DOCS_KEY);
    expect(docs?.grants).toEqual([]);
    // The standing is unknown now, which a render must not draw as "no link".
    expect(docs?.inviteLinks).toBeNull();
  });
});

describe('session', () => {
  it('notifies subscribers once per read and holds a stable state', () => {
    let changes = 0;
    const drop = sharingStore.subscribe(() => (changes += 1));

    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));
    sharingStore.reported(view(PHOTOS, [1]));

    expect(changes).toBe(2);
    expect(sharingStore.getState()).toBe(sharingStore.getState());
    drop();
  });

  it('drops every contact and grant when the session goes away', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'write']]));
    sharingStore.clear();

    const state = sharingStore.getState();
    expect(state.contacts).toEqual([]);
    expect(grantsFor(DOCS_KEY)).toBeNull();
  });
});
