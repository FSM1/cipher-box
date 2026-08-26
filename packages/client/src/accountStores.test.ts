import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  eraseAccountStores,
  reclaimOtherAccountStores,
  type AccountStoreNaming,
} from './accountStores.js';

/** The default deployment prefix: every name below is spelled `cipherbox-…`. */
const CONFIG: AccountStoreNaming = {};

afterEach(() => vi.unstubAllGlobals());

/**
 * A stub origin: `existing` names every database on it, `staged` every OPFS
 * entry, and `queued` how many ops each account's op queue still holds — or
 * `'unreadable'` for one that will not open. Records what the sweep asked to
 * delete, which is what these assert.
 */
function stubOrigin(
  existing: string[],
  staged: string[] = [],
  queued: Record<string, number | 'unreadable'> = {}
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
      if (queued[name] === 'unreadable') {
        const failing: { onerror?: () => void; error?: unknown } = {
          error: new Error('IndexedDB open failed'),
        };
        queueMicrotask(() => failing.onerror?.());
        return failing as unknown as IDBOpenDBRequest;
      }
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

  it('takes the staged bytes of an account whose op queue database is gone', async () => {
    // No queue database at all: nothing was ever enqueued, so nothing is owed.
    const origin = stubOrigin([...liveStores], [`cipherbox-${gone}-staging-staged`]);

    expect(await reclaimOtherAccountStores(CONFIG, live)).toEqual([
      `cipherbox-${gone}-staging-staged`,
    ]);
    expect(origin.removed).toEqual([`cipherbox-${gone}-staging-staged`]);
  });

  it('leaves the staged bytes of an op queue it cannot read', async () => {
    const origin = stubOrigin(
      [...liveStores, ...goneStores],
      [`cipherbox-${gone}-staging-staged`],
      {
        [`cipherbox-${gone}-staging`]: 'unreadable',
      }
    );

    // A queue this sweep cannot read is not one it can prove drained, so the
    // bytes stay rather than take unpublished work with them.
    expect(await reclaimOtherAccountStores(CONFIG, live)).not.toContain(
      `cipherbox-${gone}-staging-staged`
    );
    expect(origin.removed).toEqual([]);
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

describe('eraseAccountStores', () => {
  const forgotten = 'aa11';
  const other = 'bb22';
  const databasesOf = (account: string): string[] => [
    `cipherbox-${account}-floors`,
    `cipherbox-${account}-staging`,
    `cipherbox-${account}-snapshot-cache`,
  ];
  const stagedOf = (account: string): string => `cipherbox-${account}-staging-staged`;

  it('takes every container the forgotten account named, floors and op queue included', async () => {
    const origin = stubOrigin(databasesOf(forgotten), [stagedOf(forgotten)]);

    const erased = await eraseAccountStores(forgotten);

    expect(erased.sort()).toEqual([...databasesOf(forgotten), stagedOf(forgotten)].sort());
    expect(origin.deleted.sort()).toEqual(databasesOf(forgotten).sort());
    expect(origin.removed).toEqual([stagedOf(forgotten)]);
  });

  it('leaves every container another account on the profile named', async () => {
    const origin = stubOrigin(
      [...databasesOf(forgotten), ...databasesOf(other)],
      [stagedOf(forgotten), stagedOf(other)]
    );

    await eraseAccountStores(forgotten);

    expect(origin.deleted.filter((name) => name.includes(other))).toEqual([]);
    expect(origin.removed.filter((name) => name.includes(other))).toEqual([]);
  });

  it('names the containers under the deployment prefix', async () => {
    const origin = stubOrigin([]);

    await eraseAccountStores(forgotten, { dbPrefix: 'engine-7' });

    expect(origin.deleted.sort()).toEqual(
      [
        `engine-7-${forgotten}-floors`,
        `engine-7-${forgotten}-staging`,
        `engine-7-${forgotten}-snapshot-cache`,
      ].sort()
    );
    expect(origin.removed).toEqual([`engine-7-${forgotten}-staging-staged`]);
  });

  it('erases nothing for an account id it cannot spell a container name from', async () => {
    const origin = stubOrigin(databasesOf(forgotten), [stagedOf(forgotten)]);

    expect(await eraseAccountStores('NOT-AN-ACCOUNT')).toEqual([]);
    expect(origin.deleted).toEqual([]);
    expect(origin.removed).toEqual([]);
  });

  it('reports nothing for a delete it could not see complete', async () => {
    vi.stubGlobal('indexedDB', {
      deleteDatabase: (_name: string) => {
        const request: { onblocked?: () => void } = {};
        queueMicrotask(() => request.onblocked?.());
        return request as unknown as IDBOpenDBRequest;
      },
    });
    vi.stubGlobal('navigator', {});

    await expect(eraseAccountStores(forgotten)).resolves.toEqual([]);
  });
});
