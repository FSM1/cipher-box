import { afterEach, describe, expect, it, vi } from 'vitest';

import { makeBrowserSeams } from './browserSeams.js';

const CONFIG = {
  recordEndpoints: ['https://routing.example.test'],
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
