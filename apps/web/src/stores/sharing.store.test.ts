import { toHex } from '@cipherbox/client';
import type { ImportedContact } from '@cipherbox/client';
import { afterEach, describe, expect, it } from 'vitest';
import { grantsFor, sharingStore, type VerifiedContact } from './sharing.store';

const DOCS = new Uint8Array(16).fill(7);
const PHOTOS = new Uint8Array(16).fill(9);
const DOCS_KEY = toHex(DOCS);
const PHOTOS_KEY = toHex(PHOTOS);

function imported(seed: number): ImportedContact {
  return {
    kind: 'contactImported',
    identityPublicKey: new Uint8Array(33).fill(seed),
    encPublicKey: new Uint8Array(32).fill(seed),
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

  it('holds one entry per identity however often its code is re-imported', () => {
    contact(1);
    contact(1);

    expect(sharingStore.getState().contacts).toHaveLength(1);
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
    expect(grantsFor(state, DOCS_KEY)).toEqual([{ contact: alice, permission: 'write' }]);
    expect(grantsFor(state, PHOTOS_KEY)).toEqual([]);
  });

  it('leaves no row for a grant that was revoked', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.revoked(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
  });

  it('revokes only the named recipient', () => {
    const alice = contact(1);
    const bob = contact(2);
    sharingStore.granted(DOCS, alice, 'read');
    sharingStore.granted(DOCS, bob, 'read');
    sharingStore.revoked(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: bob, permission: 'read' },
    ]);
  });

  it('renders a downgrade as the standing row changing permission', () => {
    const alice = contact(1);
    const bob = contact(2);
    sharingStore.granted(DOCS, alice, 'write');
    sharingStore.granted(DOCS, bob, 'read');
    sharingStore.downgraded(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: alice, permission: 'read' },
      { contact: bob, permission: 'read' },
    ]);
  });

  it('records nothing for a downgrade of a recipient holding no grant', () => {
    const alice = contact(1);
    sharingStore.downgraded(DOCS, alice);

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
  });

  it('changes the permission of a re-granted recipient rather than doubling the row', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    sharingStore.granted(DOCS, alice, 'write');

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([
      { contact: alice, permission: 'write' },
    ]);
  });

  it('leaves every other scope reference-equal when one scope changes', () => {
    const alice = contact(1);
    sharingStore.granted(DOCS, alice, 'read');
    const docs = grantsFor(sharingStore.getState(), DOCS_KEY);
    sharingStore.granted(PHOTOS, alice, 'write');

    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toBe(docs);
  });

  it('has no rows for a scope before anything is granted on it', () => {
    expect(grantsFor(sharingStore.getState(), DOCS_KEY)).toEqual([]);
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
    expect(grantsFor(state, DOCS_KEY)).toEqual([]);
  });
});
