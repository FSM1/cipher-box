import { afterEach, describe, expect, it, vi } from 'vitest';

import { makeBrowserSeams, reclaimOtherAccountStores } from './browserSeams.js';

const CONFIG = {
  recordEndpoints: ['https://routing.example.test'],
  apiBaseUrl: 'https://api.test',
};

/**
 * Records every database an opened seam asks for. The request never settles, so
 * the seam's promise stays pending — the name is what these tests read.
 */
function openedDatabases(): string[] {
  const names: string[] = [];
  vi.stubGlobal('indexedDB', {
    open: (name: string) => {
      names.push(name);
      return {} as IDBOpenDBRequest;
    },
  });
  return names;
}

afterEach(() => vi.unstubAllGlobals());

describe('makeBrowserSeams', () => {
  it('opens a different floor store for each account on the profile', async () => {
    const names = openedDatabases();

    void makeBrowserSeams(CONFIG, 'aa11').floorStore.epochFloor(new Uint8Array(16));
    void makeBrowserSeams(CONFIG, 'bb22').floorStore.epochFloor(new Uint8Array(16));
    await Promise.resolve();

    expect(names).toEqual(['cipherbox-aa11-floors', 'cipherbox-bb22-floors']);
  });

  it('keeps the deployment prefix in front of the account', async () => {
    const names = openedDatabases();

    const seams = makeBrowserSeams({ ...CONFIG, dbPrefix: 'engine-7' }, 'aa11');
    void seams.floorStore.epochFloor(new Uint8Array(16));
    await Promise.resolve();

    expect(names).toEqual(['engine-7-aa11-floors']);
  });

  it('accepts the account id a real login produces', async () => {
    const names = openedDatabases();
    // Two 64-character secp256k1 coordinates and a separator.
    const real = `${'ab'.repeat(32)}-${'cd'.repeat(32)}`;

    void makeBrowserSeams(CONFIG, real).floorStore.epochFloor(new Uint8Array(16));
    await Promise.resolve();

    expect(names).toEqual([`cipherbox-${real}-floors`]);
  });

  it.each([
    ['nothing at all', ''],
    ['a path separator', 'aa/../bb'],
    ['a leading dot, as a staged temp entry has', '.cbtmp.aa11'],
    ['a case a store name need not preserve', 'AA11'],
    ['more than a public key of hex', 'a'.repeat(200)],
  ])('refuses an account named with %s', (_case, accountId) => {
    expect(() => makeBrowserSeams(CONFIG, accountId)).toThrow(
      'account id is not a store namespace'
    );
  });
});

/**
 * A stub origin: `existing` names every database on it, `staged` every OPFS
 * entry, and `queued` how many ops each account's op queue still holds. Records
 * what the sweep asked to delete, which is what these assert.
 */
function stubOrigin(
  existing: string[],
  staged: string[] = [],
  queued: Record<string, number> = {}
): { deleted: string[]; removed: string[] } {
  const deleted: string[] = [];
  const removed: string[] = [];
  vi.stubGlobal('indexedDB', {
    databases: () => Promise.resolve(existing.map((name) => ({ name, version: 1 }))),
    deleteDatabase: (name: string) => {
      deleted.push(name);
      const request: { onsuccess?: () => void } = {};
      queueMicrotask(() => request.onsuccess?.());
      return request as unknown as IDBOpenDBRequest;
    },
    open: (name: string) => {
      const count = { result: queued[name] ?? 0, onsuccess: undefined as (() => void) | undefined };
      const request: { onsuccess?: () => void; result?: unknown } = {
        result: {
          transaction: () => ({
            objectStore: () => ({
              count: () => {
                queueMicrotask(() => count.onsuccess?.());
                return count;
              },
            }),
          }),
          close: () => undefined,
        },
      };
      queueMicrotask(() => request.onsuccess?.());
      return request as unknown as IDBOpenDBRequest;
    },
  });
  vi.stubGlobal('navigator', {
    storage: {
      getDirectory: () =>
        Promise.resolve({
          keys: async function* () {
            for (const name of staged) yield name;
          },
          removeEntry: (name: string) => {
            removed.push(name);
            return Promise.resolve();
          },
        }),
    },
  });
  return { deleted, removed };
}

describe('reclaimOtherAccountStores', () => {
  const live = 'aa11';
  const gone = 'bb22';
  const liveStores = [`cipherbox-${live}-staging`, `cipherbox-${live}-snapshot-cache`];
  const goneStores = [`cipherbox-${gone}-staging`, `cipherbox-${gone}-snapshot-cache`];
  // Floors are rollback protection, durable across logout, and are never swept.
  const floorStores = [`cipherbox-${live}-floors`, `cipherbox-${gone}-floors`];

  it('takes a drained account snapshot cache and staged bytes, and no live one', async () => {
    const origin = stubOrigin(
      [...liveStores, ...goneStores, ...floorStores],
      [`cipherbox-${live}-staging-staged`, `cipherbox-${gone}-staging-staged`]
    );

    const reclaimed = await reclaimOtherAccountStores(CONFIG, live);

    expect(reclaimed.sort()).toEqual(
      [`cipherbox-${gone}-snapshot-cache`, `cipherbox-${gone}-staging-staged`].sort()
    );
    expect(origin.deleted).toEqual([`cipherbox-${gone}-snapshot-cache`]);
    expect(origin.removed).toEqual([`cipherbox-${gone}-staging-staged`]);
  });

  it('leaves the staged bytes of an account whose op queue is not drained', async () => {
    const origin = stubOrigin(
      [...liveStores, ...goneStores],
      [`cipherbox-${gone}-staging-staged`],
      { [`cipherbox-${gone}-staging`]: 2 }
    );

    const reclaimed = await reclaimOtherAccountStores(CONFIG, live);

    // A second account's login must not destroy an unpublished queue, and its
    // staged root counts as referenced for just as long.
    expect(reclaimed).not.toContain(`cipherbox-${gone}-staging-staged`);
    expect(origin.removed).toEqual([]);
    expect(origin.deleted).toEqual([`cipherbox-${gone}-snapshot-cache`]);
  });

  it('never deletes an op queue, drained or not', async () => {
    const origin = stubOrigin([...liveStores, ...goneStores], [], {
      [`cipherbox-${gone}-staging`]: 0,
    });

    await reclaimOtherAccountStores(CONFIG, live);

    expect(origin.deleted).not.toContain(`cipherbox-${gone}-staging`);
  });

  it('sweeps nothing at all for an account id it cannot spell a store name from', async () => {
    const origin = stubOrigin(
      [...liveStores, ...goneStores, ...floorStores],
      [`cipherbox-${live}-staging-staged`, `cipherbox-${gone}-staging-staged`]
    );

    // `live` matches nothing, so every real namespace would read as foreign.
    expect(await reclaimOtherAccountStores(CONFIG, 'NOT-AN-ACCOUNT')).toEqual([]);
    expect(origin.deleted).toEqual([]);
    expect(origin.removed).toEqual([]);
  });

  it('leaves alone every name that is not one account namespace of this deployment', async () => {
    const origin = stubOrigin(
      [
        ...liveStores,
        ...floorStores,
        'cb-leadership-journal',
        'cipherbox-floors', // no account segment at all
        'cipherbox-AA11-floors', // outside the account-id class
        'engine-7-bb22-floors', // another deployment's prefix
      ],
      ['cipherbox-staging-staged', 'unrelated-directory']
    );

    expect(await reclaimOtherAccountStores(CONFIG, live)).toEqual([]);
    expect(origin.deleted).toEqual([]);
    expect(origin.removed).toEqual([]);
  });

  it('keeps the live account whole even where another account id spells its store name', async () => {
    // `cipherbox-aa11-snapshot-cache` reads as account `aa11-snapshot` too; the
    // live names are the exact ones `makeBrowserSeams` opens, never a parse.
    const origin = stubOrigin(
      [...liveStores, ...floorStores],
      [`cipherbox-${live}-staging-staged`]
    );

    expect(await reclaimOtherAccountStores(CONFIG, live)).toEqual([]);
    expect(origin.deleted).toEqual([]);
    expect(origin.removed).toEqual([]);
  });

  it('never sweeps a floor store, whichever account it belongs to', async () => {
    const origin = stubOrigin([...liveStores, ...goneStores, ...floorStores]);

    const reclaimed = await reclaimOtherAccountStores(CONFIG, live);

    expect(reclaimed).not.toContain(`cipherbox-${gone}-floors`);
    expect(origin.deleted).not.toContain(`cipherbox-${gone}-floors`);
  });

  it('reclaims nothing where the browser cannot enumerate its databases', async () => {
    vi.stubGlobal('indexedDB', { deleteDatabase: () => ({}) });

    await expect(reclaimOtherAccountStores(CONFIG, live)).resolves.toEqual([]);
  });

  it('reports nothing for a delete it could not see complete', async () => {
    vi.stubGlobal('indexedDB', {
      databases: () =>
        Promise.resolve([...liveStores, ...goneStores].map((name) => ({ name, version: 1 }))),
      deleteDatabase: (_name: string) => {
        const request: { onblocked?: () => void } = {};
        // A store another tab still holds open blocks rather than clears.
        queueMicrotask(() => request.onblocked?.());
        return request as unknown as IDBOpenDBRequest;
      },
    });

    await expect(reclaimOtherAccountStores(CONFIG, live)).resolves.toEqual([]);
  });
});
