import { toHex } from '@cipherbox/client';
import type { ImportedContact } from '@cipherbox/client';
import { afterEach, describe, expect, it } from 'vitest';
import { grantsFor, sharingStore, type VerifiedContact } from './sharingStore';

const DOCS = new Uint8Array(16).fill(7);
const PHOTOS = new Uint8Array(16).fill(9);

function imported(seed: number, subkey = seed): ImportedContact {
  return {
    kind: 'contactImported',
    identityPublicKey: new Uint8Array(33).fill(seed),
    encPublicKey: new Uint8Array(32).fill(subkey),
  };
}

function contact(seed: number): VerifiedContact {
  return sharingStore.contactImported(imported(seed));
}

afterEach(() => sharingStore.clear());

describe('contacts', () => {
  it('records the keys the engine returned, keyed by identity', () => {
    const outcome = imported(1);
    const recorded = contact(1);

    expect(recorded.key).toBe(toHex(outcome.identityPublicKey));
    expect(sharingStore.getState().contacts).toEqual([recorded]);
  });

  it('replaces the entry for an identity that re-imports a rotated subkey', () => {
    contact(1);
    sharingStore.contactImported(imported(1, 2));

    const { contacts } = sharingStore.getState();
    expect(contacts).toHaveLength(1);
    expect(contacts[0].encPublicKey).toEqual(new Uint8Array(32).fill(2));
  });

  it('holds a distinct entry per identity', () => {
    contact(1);
    contact(2);

    expect(sharingStore.getState().contacts).toHaveLength(2);
  });
});

describe('grants', () => {
  it('lists a granted recipient under the scope it was granted on', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');

    const state = sharingStore.getState();
    expect(grantsFor(state, DOCS)).toEqual([{ contact: alice, permission: 'write' }]);
    expect(grantsFor(state, PHOTOS)).toEqual([]);
  });

  it('leaves no row for a grant that was revoked', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.revoked(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS)).toEqual([]);
  });

  it('revokes only the named recipient', () => {
    const alice = contact(1);
    const bob = contact(2);
    sharingStore.granted(DOCS, alice, 'read');
    sharingStore.granted(DOCS, bob, 'read');
    sharingStore.revoked(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS)).toEqual([
      { contact: bob, permission: 'read' },
    ]);
  });

  it('renders a downgrade as the standing row changing permission', () => {
    const alice = contact(1);
    const bob = contact(2);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.granted(DOCS, bob, 'read');
    sharingStore.downgraded(DOCS, alice);

    // Same rows, same order, same recipients — only alice's permission moved.
    expect(grantsFor(sharingStore.getState(), DOCS)).toEqual([
      { contact: alice, permission: 'read' },
      { contact: bob, permission: 'read' },
    ]);
  });

  it('records nothing for a downgrade of a recipient holding no grant', () => {
    const alice = contact(1);
    sharingStore.downgraded(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS)).toEqual([]);
  });

  it('changes the permission of a re-granted recipient rather than doubling the row', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    sharingStore.granted(DOCS, alice, 'write');

    expect(grantsFor(sharingStore.getState(), DOCS)).toEqual([
      { contact: alice, permission: 'write' },
    ]);
  });

  it('leaves every other scope reference-equal when one scope changes', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    const docs = grantsFor(sharingStore.getState(), DOCS);
    sharingStore.granted(PHOTOS, alice, 'write');

    expect(grantsFor(sharingStore.getState(), DOCS)).toBe(docs);
  });

  it('has no rows for a scope before anything is granted on it', () => {
    expect(grantsFor(sharingStore.getState(), null)).toEqual([]);
    expect(grantsFor(sharingStore.getState(), DOCS)).toEqual([]);
  });
});

describe('session', () => {
  it('notifies subscribers once per recorded change and holds a stable state', () => {
    let changes = 0;
    const drop = sharingStore.subscribe(() => (changes += 1));

    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    sharingStore.downgraded(PHOTOS, alice);

    expect(changes).toBe(2);
    expect(sharingStore.getState()).toBe(sharingStore.getState());
    drop();
  });

  it('drops every contact and grant when the session goes away', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.clear();

    const state = sharingStore.getState();
    expect(state.contacts).toEqual([]);
    expect(grantsFor(state, DOCS)).toEqual([]);
  });
});
