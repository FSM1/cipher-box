import { toHex } from '@cipherbox/client';
import type { Permission, SharingDescriptor } from '@cipherbox/client';
import { afterEach, describe, expect, it } from 'vitest';
import { grantsFor, sharingStore } from './sharing.store';

const DOCS = new Uint8Array(16).fill(7);
const PHOTOS = new Uint8Array(16).fill(9);
const DOCS_KEY = toHex(DOCS);
const PHOTOS_KEY = toHex(PHOTOS);

function identity(seed: number): Uint8Array {
  return new Uint8Array(33).fill(seed);
}

function key(seed: number): string {
  return toHex(identity(seed));
}

/** One engine sharing read: `contacts` by seed, `grants` by seed and permission. */
function view(
  scope: Uint8Array,
  contacts: number[],
  grants: Array<[number, Permission]> = []
): SharingDescriptor {
  return {
    scope,
    contacts: contacts.map((seed) => ({
      identityPublicKey: identity(seed),
      encryptionPublicKey: new Uint8Array(32).fill(seed),
    })),
    grants: grants.map(([seed, permission]) => ({
      recipientIdentityPublicKey: identity(seed),
      permission,
      expiresAt: null,
    })),
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

    const state = sharingStore.getState();
    expect(grantsFor(state, DOCS_KEY)).toEqual([
      { contact: { key: key(1), identityPublicKey: identity(1) }, permission: 'write' },
    ]);
    expect(grantsFor(state, PHOTOS_KEY)).toEqual([]);
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

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: { key: key(2), identityPublicKey: identity(2) }, permission: 'read' },
    ]);
  });

  it('takes the permission the engine reported, not the one it last held', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'write']]));
    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: { key: key(1), identityPublicKey: identity(1) }, permission: 'read' },
    ]);
  });

  it('has no rows for a scope no read has covered', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));

    expect(grantsFor(sharingStore.getState(), PHOTOS_KEY)).toEqual([]);
  });

  it('leaves every other scope reference-equal when one scope is re-read', () => {
    sharingStore.reported(view(DOCS, [1], [[1, 'read']]));
    const docs = grantsFor(sharingStore.getState(), DOCS_KEY);
    sharingStore.reported(view(PHOTOS, [1], [[1, 'write']]));

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toBe(docs);
  });

  it('reports the emptiness of a scope that commits no grant', () => {
    sharingStore.reported(view(DOCS, [1]));

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
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
    expect(grantsFor(state, DOCS_KEY)).toEqual([]);
  });
});
