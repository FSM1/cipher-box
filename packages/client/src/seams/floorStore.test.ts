import { afterEach, describe, expect, it, vi } from 'vitest';

import { IdbFloorStore } from './floorStore.js';

afterEach(() => vi.unstubAllGlobals());

/** An IndexedDB stub over one in-memory map per object store, keyed by hex. */
function stubIndexedDb(
  seed: Record<string, Record<string, unknown>>
): Map<string, Map<string, unknown>> {
  const stores = new Map(
    Object.entries(seed).map(([name, rows]) => [name, new Map(Object.entries(rows))])
  );
  const settle = <T>(result: T) => {
    const request: { result: T; onsuccess?: () => void } = { result };
    queueMicrotask(() => request.onsuccess?.());
    return request;
  };
  const db = {
    transaction: () => ({
      objectStore: (name: string) => {
        const rows = stores.get(name) ?? new Map<string, unknown>();
        stores.set(name, rows);
        return {
          get: (key: string) => settle(rows.get(key)),
          put: (value: unknown, key: string) => settle(rows.set(key, value)),
        };
      },
      set oncomplete(done: () => void) {
        setTimeout(done, 0);
      },
    }),
  };
  vi.stubGlobal('indexedDB', { open: () => settle(db) });
  return stores;
}

const KEY = new Uint8Array([0xab]);

describe('IdbFloorStore', () => {
  const unreadable = ['7', Number.NaN, -1, 1.5, 2 ** 53, { floor: 7 }, true];

  it.each(unreadable)('refuses to read the stored floor %s', async (stored) => {
    stubIndexedDb({ epoch: { ab: stored }, sequence: { ab: stored } });
    const floors = new IdbFloorStore('floors');
    await expect(floors.epochFloor(KEY)).rejects.toThrow(RangeError);
    await expect(floors.sequenceFloor(KEY)).rejects.toThrow(RangeError);
  });

  it.each(unreadable)('refuses to raise over the stored floor %s', async (stored) => {
    const stores = stubIndexedDb({ epoch: { ab: stored }, sequence: { ab: stored } });
    const floors = new IdbFloorStore('floors');
    await expect(floors.raiseEpochFloor(KEY, 3)).rejects.toThrow(RangeError);
    await expect(floors.raiseSequenceFloor(KEY, 3)).rejects.toThrow(RangeError);
    expect(stores.get('epoch')?.get('ab')).toBe(stored);
    expect(stores.get('sequence')?.get('ab')).toBe(stored);
  });

  it('reads an absent floor as null and raises a readable floor to the max', async () => {
    stubIndexedDb({ epoch: { ab: 9 } });
    const floors = new IdbFloorStore('floors');
    expect(await floors.sequenceFloor(KEY)).toBeNull();
    expect(await floors.raiseEpochFloor(KEY, 3)).toBe(9);
    expect(await floors.raiseSequenceFloor(KEY, 4)).toBe(4);
    expect(await floors.sequenceFloor(KEY)).toBe(4);
  });
});
