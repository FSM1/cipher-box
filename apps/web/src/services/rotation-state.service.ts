/**
 * Rotation State Service — durable anti-rollback high-water floors (ROT-07)
 *
 * Supplies the CONCRETE, browser-only IndexedDB `HighWaterStore` adapter behind
 * the `@cipherbox/sdk` `createRotationHighWater` seam (68-01). This module owns
 * NO monotonic-max or fail-closed comparison logic — that lives in the SDK and
 * is unit-tested there. This adapter is a thin get/put persistence layer, hand-
 * rolled over raw `indexedDB` (no `idb` package), following the pattern in
 * `apps/web/src/lib/device/identity.ts` and `apps/web/src/services/search-index.service.ts`.
 *
 * One database, two object stores, both keyed explicitly by `nodeId` (no
 * `keyPath`):
 *   - `generation-high-water` — the M1 cross-generation rollback defense (design §4.3)
 *   - `seq-high-water` — the within-generation sequence rollback defense (design §6.5)
 *
 * D-08 degradation: if `indexedDB.open` (or any subsequent transaction) throws
 * or rejects — unavailable, private-mode, cleared mid-session — this module
 * falls back to an in-memory, module-scoped `Map` per store for the remainder
 * of the session and latches a one-time `warnedOnce` flag. Once degraded, a
 * store never re-attempts IndexedDB for the rest of the session: mixing IDB
 * and memory reads for the same store would let a floor observed via one
 * backend silently disagree with a floor written via the other, undermining
 * the monotonic-max guarantee this store exists to provide.
 *
 * This is a thin adapter with NO unit test — the monotonic-max/fail-closed
 * logic is already unit-proven in the SDK (68-01); the real-reload durability
 * and the D-08 degraded-session behavior are proven by the 68-10 web-e2e spec.
 */

import { createRotationHighWater, type HighWaterStore } from '@cipherbox/sdk';

const DB_NAME = 'cipherbox-rotation-state';
const DB_VERSION = 1;
const GENERATION_STORE_NAME = 'generation-high-water';
const SEQ_STORE_NAME = 'seq-high-water';

/**
 * Open the rotation-state IndexedDB database, creating both object stores on
 * upgrade. Both stores are keyed by `nodeId` passed explicitly to `get`/`put`
 * (no `keyPath`).
 */
function openRotationDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(GENERATION_STORE_NAME)) {
        db.createObjectStore(GENERATION_STORE_NAME);
      }
      if (!db.objectStoreNames.contains(SEQ_STORE_NAME)) {
        db.createObjectStore(SEQ_STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * V5 fail-closed validation for a value read back from IndexedDB: anything
 * that is not a non-negative safe integer is treated as absent rather than
 * coerced to a low floor. Matches the SDK's own `isValidFloorValue` guard —
 * this is defense-in-depth at the storage boundary, not a replacement for it.
 */
function isValidFloorValue(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function idbGet(storeName: string, nodeId: string): Promise<number | undefined> {
  return openRotationDB().then(
    (db) =>
      new Promise<number | undefined>((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const store = tx.objectStore(storeName);
        const request = store.get(nodeId);
        request.onsuccess = () => {
          const raw = request.result as unknown;
          resolve(isValidFloorValue(raw) ? raw : undefined);
        };
        request.onerror = () => reject(request.error);
      })
  );
}

function idbPut(storeName: string, nodeId: string, value: number): Promise<void> {
  return openRotationDB().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const store = tx.objectStore(storeName);
        // Max-preserving write inside ONE readwrite transaction: the SDK's
        // bumpFloor maxes against its own read, but another tab may have
        // raised the floor since — a blind put would regress it (T-68-82's
        // safety claim holds only if the write itself is monotonic).
        const readBack = store.get(nodeId);
        readBack.onsuccess = () => {
          const existing = readBack.result as unknown;
          const floor = isValidFloorValue(existing) ? Math.max(existing, value) : value;
          store.put(floor, nodeId);
        };
        readBack.onerror = () => reject(readBack.error);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      })
  );
}

/**
 * D-08: one-time notice flag. Set the first time either store degrades to the
 * in-memory session floor. Read via `isRotationStateDegraded()` so 68-09 can
 * surface a single toast rather than one per resolve.
 */
let warnedOnce = false;

/** Whether the rotation-state store has degraded to an in-memory session floor this session. */
export function isRotationStateDegraded(): boolean {
  return warnedOnce;
}

/**
 * Builds a `HighWaterStore` over one IndexedDB object store, degrading to an
 * in-memory `Map` (call-site try/catch, per identity.ts) the first time an
 * IndexedDB operation fails. Once degraded, the store latches to memory-only
 * for the rest of the session so a single logical floor never splits across
 * two disagreeing backends.
 */
function createDegradableHighWaterStore(storeName: string): HighWaterStore {
  const sessionFloor = new Map<string, number>();
  let degraded = false;

  return {
    async get(nodeId) {
      if (degraded) {
        return sessionFloor.get(nodeId);
      }
      try {
        return await idbGet(storeName, nodeId);
      } catch {
        // IndexedDB unavailable/cleared mid-session — degrade for the rest of the session (D-08).
        degraded = true;
        warnedOnce = true;
        return sessionFloor.get(nodeId);
      }
    },
    async put(nodeId, value) {
      const maxIntoSession = () => {
        const existing = sessionFloor.get(nodeId);
        sessionFloor.set(nodeId, existing !== undefined ? Math.max(existing, value) : value);
      };
      if (degraded) {
        maxIntoSession();
        return;
      }
      try {
        await idbPut(storeName, nodeId, value);
      } catch {
        degraded = true;
        warnedOnce = true;
        maxIntoSession();
      }
    },
  };
}

const generationStore = createDegradableHighWaterStore(GENERATION_STORE_NAME);
const seqStore = createDegradableHighWaterStore(SEQ_STORE_NAME);

/**
 * Shared durable rotation high-water state machine (ROT-07) over the two
 * IndexedDB-backed stores above. All monotonic-max/enforcement logic is
 * owned by `@cipherbox/sdk` (68-01) — this module supplies only the stores.
 */
export const rotationHighWater = createRotationHighWater(generationStore, seqStore);

/** Owner-vouched first-contact seed (e.g. from a share grant's `rootGeneration`). */
export const seedFromGrant = rotationHighWater.seedFromGrant;

/** Fail-closed pre-unseal gate — see `@cipherbox/sdk`'s `RotationHighWater.enforceResolved`. */
export const enforceResolved = rotationHighWater.enforceResolved;
