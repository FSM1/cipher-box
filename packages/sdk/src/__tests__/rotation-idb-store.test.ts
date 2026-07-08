/**
 * Tests for state/rotation-idb-store.ts (70.1-02, CI-covered)
 *
 * The rotation IndexedDB adapter + DB_VERSION-2 schema-collapse migration were
 * hoisted out of apps/web into the SDK so they run under
 * `pnpm --filter @cipherbox/sdk test` (which IS in CI) -- apps/web's own
 * `*.test.ts` files are NOT run by CI (web is web-e2e-gated).
 *
 * `fake-indexeddb` provides a real, in-memory IndexedDB implementation so these
 * tests exercise the actual `onupgradeneeded` migration, cursor fold, and
 * transactional max-preserving writes against a real (faked) store, not a mock.
 * A fresh `IDBFactory` is installed as `globalThis.indexedDB` per test for full
 * isolation.
 *
 * Coverage:
 *   - Test C (Pitfall 4): onupgradeneeded folds the OLD two-store shape into the
 *     combined record, preserving max floors and deleting the two legacy stores.
 *   - max-preserving put: a concurrent higher write is never clobbered by a
 *     lower one.
 *   - Test B (SC#3/D-07): wrapped-key persist/get/delete round trip; delete
 *     preserves floors.
 *   - D-08 degradation: an open failure latches the store to an in-memory
 *     session floor and flips isRotationStateDegraded().
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';
import { createIndexedDbHighWaterStore, openRotationDB } from '../state/rotation-idb-store';

const DB_NAME = 'cipherbox-rotation-state';
const LEGACY_GENERATION_STORE = 'generation-high-water';
const LEGACY_SEQ_STORE = 'seq-high-water';
const FLOOR_STORE_NAME = 'rotation-floor';

/** Installs a fresh in-memory fake IndexedDB as the global for full test isolation. */
function installFreshIndexedDB() {
  (globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
}

/** Seeds the OLD (pre-70.1-02) two-store shape directly via raw IndexedDB, bypassing the adapter. */
function seedLegacyStores(
  entries: Array<{ nodeId: string; generation?: number; seq?: number }>
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const openReq = indexedDB.open(DB_NAME, 1);
    openReq.onupgradeneeded = () => {
      const db = openReq.result;
      db.createObjectStore(LEGACY_GENERATION_STORE);
      db.createObjectStore(LEGACY_SEQ_STORE);
    };
    openReq.onsuccess = () => {
      const db = openReq.result;
      const tx = db.transaction([LEGACY_GENERATION_STORE, LEGACY_SEQ_STORE], 'readwrite');
      const genStore = tx.objectStore(LEGACY_GENERATION_STORE);
      const seqStore = tx.objectStore(LEGACY_SEQ_STORE);
      for (const entry of entries) {
        if (entry.generation !== undefined) genStore.put(entry.generation, entry.nodeId);
        if (entry.seq !== undefined) seqStore.put(entry.seq, entry.nodeId);
      }
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    };
    openReq.onerror = () => reject(openReq.error);
  });
}

describe('rotation-idb-store — wrapped-key round trip (SC#3/D-07, Test B)', () => {
  beforeEach(() => {
    installFreshIndexedDB();
  });

  it('persistWrappedKey then getWrappedKey round-trips the ciphertext', async () => {
    const idb = createIndexedDbHighWaterStore();

    await idb.persistWrappedKey('node-a', 'ZmFrZS13cmFwcGVkLWNpcGhlcnRleHQ=');
    expect(await idb.getWrappedKey('node-a')).toBe('ZmFrZS13cmFwcGVkLWNpcGhlcnRleHQ=');
  });

  it('deleteWrappedKey clears only the wrappedKeyCheckpoint field, leaving generation/seq floors intact', async () => {
    const idb = createIndexedDbHighWaterStore();

    await idb.store.put('node-a', { generation: 3, seq: 7 });
    await idb.persistWrappedKey('node-a', 'ZmFrZS13cmFwcGVkLWNpcGhlcnRleHQ=');

    await idb.deleteWrappedKey('node-a');

    expect(await idb.getWrappedKey('node-a')).toBeUndefined();
    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(3);
    expect(record?.seq).toBe(7);
  });

  it('persisting a wrapped key does not disturb pre-existing generation/seq floors', async () => {
    const idb = createIndexedDbHighWaterStore();

    await idb.store.put('node-a', { generation: 4, seq: 9 });
    await idb.persistWrappedKey('node-a', 'd3JhcHBlZC1rZXk=');

    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(4);
    expect(record?.seq).toBe(9);
    expect(record?.wrappedKeyCheckpoint).toBe('d3JhcHBlZC1rZXk=');
  });

  it('getWrappedKey returns undefined for an unseen nodeId', async () => {
    const idb = createIndexedDbHighWaterStore();
    expect(await idb.getWrappedKey('never-seen')).toBeUndefined();
  });
});

describe('rotation-idb-store — max-preserving put (concurrent-write safety)', () => {
  beforeEach(() => {
    installFreshIndexedDB();
  });

  it('a lower generation/seq write never clobbers a higher stored value', async () => {
    const idb = createIndexedDbHighWaterStore();

    await idb.store.put('node-a', { generation: 5, seq: 20 });
    // Simulate a stale writer racing in with lower values.
    await idb.store.put('node-a', { generation: 2, seq: 10 });

    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(5);
    expect(record?.seq).toBe(20);
  });

  it('a higher write raises each field independently (monotonic-max per field)', async () => {
    const idb = createIndexedDbHighWaterStore();

    await idb.store.put('node-a', { generation: 5, seq: 20 });
    // generation regresses (kept at 5) but seq advances (raised to 30).
    await idb.store.put('node-a', { generation: 3, seq: 30 });

    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(5);
    expect(record?.seq).toBe(30);
  });

  it('a malformed stored floor is treated as absent, not coerced to a low value', async () => {
    const idb = createIndexedDbHighWaterStore();

    // Force a malformed record straight into the store, bypassing the adapter.
    const db = await openRotationDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(FLOOR_STORE_NAME, 'readwrite');
      tx.objectStore(FLOOR_STORE_NAME).put({ generation: -1, seq: 3.5 }, 'node-a');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });

    // A subsequent legitimate write must win over the malformed value.
    await idb.store.put('node-a', { generation: 1, seq: 1 });
    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(1);
    expect(record?.seq).toBe(1);
  });
});

describe('rotation-idb-store — old-schema migration preserves floors (Pitfall 4, Test C)', () => {
  beforeEach(() => {
    installFreshIndexedDB();
  });

  it('folds the OLD two-store shape into the combined record and deletes the legacy stores', async () => {
    await seedLegacyStores([{ nodeId: 'node-a', generation: 6, seq: 42 }]);

    const idb = createIndexedDbHighWaterStore();

    // Triggers openRotationDB() -> onupgradeneeded (oldVersion=1 -> DB_VERSION=2),
    // which folds the legacy two-store data into the combined record BEFORE this
    // read resolves.
    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(6);
    expect(record?.seq).toBe(42);

    // The two legacy stores must be gone; only the combined store remains.
    const db = await openRotationDB();
    expect(db.objectStoreNames.contains(LEGACY_GENERATION_STORE)).toBe(false);
    expect(db.objectStoreNames.contains(LEGACY_SEQ_STORE)).toBe(false);
    expect(db.objectStoreNames.contains(FLOOR_STORE_NAME)).toBe(true);
  });

  it('migration preserves floors for MULTIPLE nodeIds independently', async () => {
    await seedLegacyStores([
      { nodeId: 'node-a', generation: 1, seq: 10 },
      { nodeId: 'node-b', generation: 5, seq: 50 },
    ]);

    const idb = createIndexedDbHighWaterStore();

    const a = await idb.store.get('node-a');
    const b = await idb.store.get('node-b');
    expect(a).toEqual({ generation: 1, seq: 10, wrappedKeyCheckpoint: undefined });
    expect(b).toEqual({ generation: 5, seq: 50, wrappedKeyCheckpoint: undefined });
  });

  it('migration folds a nodeId present in only ONE legacy store', async () => {
    await seedLegacyStores([
      { nodeId: 'gen-only', generation: 7 },
      { nodeId: 'seq-only', seq: 13 },
    ]);

    const idb = createIndexedDbHighWaterStore();

    const genOnly = await idb.store.get('gen-only');
    const seqOnly = await idb.store.get('seq-only');
    expect(genOnly?.generation).toBe(7);
    expect(genOnly?.seq).toBeUndefined();
    expect(seqOnly?.seq).toBe(13);
    expect(seqOnly?.generation).toBeUndefined();
  });

  it('a fresh DB with no legacy data opens cleanly with an empty combined store', async () => {
    const idb = createIndexedDbHighWaterStore();

    expect(await idb.store.get('never-seen')).toBeUndefined();

    const db = await openRotationDB();
    expect(db.objectStoreNames.contains(FLOOR_STORE_NAME)).toBe(true);
    expect(db.objectStoreNames.contains(LEGACY_GENERATION_STORE)).toBe(false);
  });
});

describe('rotation-idb-store — D-08 degradation on IndexedDB failure', () => {
  afterEach(() => {
    installFreshIndexedDB();
  });

  it('latches to an in-memory session floor and flips isRotationStateDegraded when open throws', async () => {
    // Remove IndexedDB entirely so every open throws.
    (globalThis as { indexedDB: unknown }).indexedDB = undefined;

    const idb = createIndexedDbHighWaterStore();
    expect(idb.isRotationStateDegraded()).toBe(false);

    // The first put fails against (missing) IndexedDB and degrades to memory.
    await idb.store.put('node-a', { generation: 4, seq: 9 });
    expect(idb.isRotationStateDegraded()).toBe(true);

    // Reads/writes now hit the in-memory session floor, still monotonic-max.
    const record = await idb.store.get('node-a');
    expect(record?.generation).toBe(4);
    expect(record?.seq).toBe(9);

    await idb.store.put('node-a', { generation: 2, seq: 3 });
    const afterLower = await idb.store.get('node-a');
    expect(afterLower?.generation).toBe(4);
    expect(afterLower?.seq).toBe(9);
  });

  it('degraded wrapped-key persist/get round-trips against the in-memory session floor', async () => {
    (globalThis as { indexedDB: unknown }).indexedDB = undefined;

    const idb = createIndexedDbHighWaterStore();
    await idb.persistWrappedKey('node-a', 'ZGVncmFkZWQtY2lwaGVydGV4dA==');

    expect(idb.isRotationStateDegraded()).toBe(true);
    expect(await idb.getWrappedKey('node-a')).toBe('ZGVncmFkZWQtY2lwaGVydGV4dA==');
  });
});
