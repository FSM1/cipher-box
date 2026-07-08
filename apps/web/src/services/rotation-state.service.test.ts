/**
 * Tests for rotation-state.service.ts (70.1-02)
 *
 * apps/web's vitest environment is `node` (no browser globals) -- these tests
 * install `fake-indexeddb` as `globalThis.indexedDB` so the service's
 * IndexedDB-backed persistence and migration logic run against a REAL (faked)
 * IndexedDB implementation, not a mock.
 *
 * A colocated file (not `packages/sdk/src/__tests__/rotation-high-water.test.ts`)
 * is deliberate: this module owns the browser-only IndexedDB adapter and its
 * `onupgradeneeded` migration -- packages/sdk (a published, browser-agnostic
 * package) must not depend on apps/web internals to be tested. The plan's own
 * research flagged this exact placement ambiguity and pre-authorized "a new
 * colocated test file if the fake-indexeddb setup lives elsewhere" (Claude's
 * Discretion). The pure store-seam atomicity case (Task 1 Test A) is covered
 * in packages/sdk's own test file using a Map-backed fake -- no IndexedDB
 * needed there.
 *
 * Test B (SC#3/D-07): persistWrappedKey/getWrappedKey/deleteWrappedKey round
 * trip, deleteWrappedKey preserves floors.
 * Test C (Pitfall 4): seed the OLD two-store shape, open the DB (triggering
 * the onupgradeneeded migration), assert floors survive.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { IDBFactory } from 'fake-indexeddb';

const DB_NAME = 'cipherbox-rotation-state';
const LEGACY_GENERATION_STORE = 'generation-high-water';
const LEGACY_SEQ_STORE = 'seq-high-water';

/** Seeds the OLD (pre-70.1-02) two-store shape directly via raw IndexedDB, bypassing the service. */
function seedLegacyStores(entries: Array<{ nodeId: string; generation?: number; seq?: number }>) {
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

describe('rotation-state.service — wrapped-key round trip (SC#3/D-07, Task 1 Test B)', () => {
  beforeEach(() => {
    // Fresh in-memory fake IndexedDB per test -- full isolation, no cross-test bleed.
    (globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
    // Re-import fresh so the module's lazy `openRotationDB` calls use the new factory.
    // (The service reads the global `indexedDB` identifier at call time, not import
    // time, so re-importing is not strictly required, but vitest's module cache is
    // reset per test file run, and resetModules keeps this test independent of
    // import order relative to other describe blocks in this file.)
  });

  it('persistWrappedKey then getWrappedKey round-trips the ciphertext', async () => {
    const { persistWrappedKey, getWrappedKey } = await import('./rotation-state.service');

    await persistWrappedKey('node-a', 'ZmFrZS13cmFwcGVkLWNpcGhlcnRleHQ=');
    expect(await getWrappedKey('node-a')).toBe('ZmFrZS13cmFwcGVkLWNpcGhlcnRleHQ=');
  });

  it('deleteWrappedKey clears only the wrappedKeyCheckpoint field, leaving generation/seq floors intact', async () => {
    const { persistWrappedKey, getWrappedKey, deleteWrappedKey, rotationHighWater } =
      await import('./rotation-state.service');

    await rotationHighWater.bumpGeneration('node-a', 3);
    await rotationHighWater.bumpSeq('node-a', 7);
    await persistWrappedKey('node-a', 'ZmFrZS13cmFwcGVkLWNpcGhlcnRleHQ=');

    await deleteWrappedKey('node-a');

    expect(await getWrappedKey('node-a')).toBeUndefined();
    expect(await rotationHighWater.getGenerationFloor('node-a')).toBe(3);
    expect(await rotationHighWater.getSeqFloor('node-a')).toBe(7);
  });

  it('persisting a wrapped key does not disturb pre-existing generation/seq floors', async () => {
    const { persistWrappedKey, rotationHighWater } = await import('./rotation-state.service');

    await rotationHighWater.bumpGeneration('node-a', 4);
    await rotationHighWater.bumpSeq('node-a', 9);

    await persistWrappedKey('node-a', 'd3JhcHBlZC1rZXk=');

    expect(await rotationHighWater.getGenerationFloor('node-a')).toBe(4);
    expect(await rotationHighWater.getSeqFloor('node-a')).toBe(9);
  });
});

describe('rotation-state.service — old-schema migration preserves floors (Pitfall 4, Task 1 Test C)', () => {
  beforeEach(() => {
    (globalThis as { indexedDB: IDBFactory }).indexedDB = new IDBFactory();
  });

  it('seeding the OLD two-store shape then opening the DB migrates both floors into the combined record', async () => {
    await seedLegacyStores([{ nodeId: 'node-a', generation: 6, seq: 42 }]);

    const { rotationHighWater } = await import('./rotation-state.service');

    // Triggers openRotationDB() -> onupgradeneeded (oldVersion=1 -> DB_VERSION=2),
    // which must fold the legacy two-store data into the combined record
    // BEFORE this read resolves.
    expect(await rotationHighWater.getGenerationFloor('node-a')).toBe(6);
    expect(await rotationHighWater.getSeqFloor('node-a')).toBe(42);
  });

  it('migration preserves floors for MULTIPLE nodeIds independently', async () => {
    await seedLegacyStores([
      { nodeId: 'node-a', generation: 1, seq: 10 },
      { nodeId: 'node-b', generation: 5, seq: 50 },
    ]);

    const { rotationHighWater } = await import('./rotation-state.service');

    expect(await rotationHighWater.getGenerationFloor('node-a')).toBe(1);
    expect(await rotationHighWater.getSeqFloor('node-a')).toBe(10);
    expect(await rotationHighWater.getGenerationFloor('node-b')).toBe(5);
    expect(await rotationHighWater.getSeqFloor('node-b')).toBe(50);
  });

  it('a subsequent enforceResolved on a migrated floor still rejects a regression fail-closed', async () => {
    await seedLegacyStores([{ nodeId: 'node-a', generation: 5, seq: 20 }]);

    const { rotationHighWater } = await import('./rotation-state.service');

    await expect(
      rotationHighWater.enforceResolved({
        nodeId: 'node-a',
        seq: 30,
        generation: 2,
        versionFloor: 0,
      })
    ).rejects.toThrow();

    // Rejected attempt must not have disturbed the migrated floor.
    expect(await rotationHighWater.getGenerationFloor('node-a')).toBe(5);
    expect(await rotationHighWater.getSeqFloor('node-a')).toBe(20);
  });

  it('a fresh DB with no legacy data migrates cleanly to an empty combined store', async () => {
    const { rotationHighWater } = await import('./rotation-state.service');

    expect(await rotationHighWater.getGenerationFloor('never-seen')).toBeUndefined();
    expect(await rotationHighWater.getSeqFloor('never-seen')).toBeUndefined();
  });
});
