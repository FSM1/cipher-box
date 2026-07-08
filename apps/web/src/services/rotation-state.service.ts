/**
 * Rotation State Service — durable anti-rollback high-water floors (ROT-07)
 * + SC#3 ECIES wrapped-key checkpoint (D-07)
 *
 * Supplies the CONCRETE, browser-only IndexedDB `HighWaterStore` adapter behind
 * the `@cipherbox/sdk` `createRotationHighWater` seam (68-01). This module owns
 * NO monotonic-max or fail-closed comparison logic — that lives in the SDK and
 * is unit-tested there. This adapter is a thin get/put persistence layer, hand-
 * rolled over raw `indexedDB` (no `idb` package), following the pattern in
 * `apps/web/src/lib/device/identity.ts` and `apps/web/src/services/search-index.service.ts`.
 *
 * One database, ONE combined object store (SC#4/D-06, 70.1-02), keyed
 * explicitly by `nodeId` (no `keyPath`), holding
 * `{ generation?, seq?, wrappedKeyCheckpoint? }`:
 *   - `generation` — the M1 cross-generation rollback defense (design §4.3)
 *   - `seq` — the within-generation sequence rollback defense (design §6.5)
 *   - `wrappedKeyCheckpoint` — the SC#3 ECIES-wrapped rotation key checkpoint
 *     ciphertext (D-07). Client-side only — NEVER routed through any API
 *     endpoint (CLAUDE.md Rule 6, zero-knowledge). This is a DIFFERENT plane
 *     from `rotation-driver.service.ts`'s per-rootNodeId `DurableJobCheckpoint`
 *     (`cipherbox-rotation-jobs` DB), which explicitly documents "never key
 *     material" — the wrapped key belongs here, keyed by nodeId, alongside
 *     that node's own floor.
 *
 * Prior to 70.1-02 this DB held TWO separate object stores
 * (`generation-high-water`, `seq-high-water`, `DB_VERSION = 1`). `DB_VERSION`
 * is bumped to 2 and `onupgradeneeded` folds any existing two-store data into
 * the new combined store (Pitfall 4 — floors are safety-critical, a silent
 * reset is a real regression even though it is safe-directional) before
 * retiring the old stores.
 *
 * D-08 degradation: if `indexedDB.open` (or any subsequent transaction) throws
 * or rejects — unavailable, private-mode, cleared mid-session — this module
 * falls back to an in-memory, module-scoped `Map` for the remainder of the
 * session and latches a one-time `warnedOnce` flag. Once degraded, the store
 * never re-attempts IndexedDB for the rest of the session: mixing IDB and
 * memory reads for the same store would let a floor observed via one backend
 * silently disagree with a floor written via the other, undermining the
 * monotonic-max guarantee this store exists to provide.
 *
 * This is a thin adapter with NO unit test for the monotonic-max/fail-closed
 * comparison logic — that is already unit-proven in the SDK (68-01). The
 * combined-record persistence/migration behavior owned by THIS module is
 * unit-tested in `rotation-state.service.test.ts` (70.1-02) against a real
 * (faked) IndexedDB via `fake-indexeddb`. Real-reload durability and the D-08
 * degraded-session behavior remain proven by the 68-10 web-e2e spec.
 */

import {
  createRotationHighWater,
  type HighWaterStore,
  type CombinedFloorRecord,
} from '@cipherbox/sdk';

const DB_NAME = 'cipherbox-rotation-state';
const DB_VERSION = 2;
/** Legacy (pre-70.1-02) store names -- migration SOURCE only, retired after the fold. */
const GENERATION_STORE_NAME = 'generation-high-water';
const SEQ_STORE_NAME = 'seq-high-water';
/** SC#4/D-06/D-07 combined store: `{ generation?, seq?, wrappedKeyCheckpoint? }` per nodeId. */
const FLOOR_STORE_NAME = 'rotation-floor';

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

/** Sanitizes a raw record read back from IndexedDB -- V5 per-field, never coerced. */
function sanitizeRecord(raw: CombinedFloorRecord | undefined): CombinedFloorRecord | undefined {
  if (!raw) return undefined;
  return {
    generation: isValidFloorValue(raw.generation) ? raw.generation : undefined,
    seq: isValidFloorValue(raw.seq) ? raw.seq : undefined,
    wrappedKeyCheckpoint:
      typeof raw.wrappedKeyCheckpoint === 'string' ? raw.wrappedKeyCheckpoint : undefined,
  };
}

/** Monotonic-max of two possibly-undefined/malformed numeric floor values. */
function maxFloor(existing: unknown, candidate: unknown): number | undefined {
  const validExisting = isValidFloorValue(existing) ? existing : undefined;
  const validCandidate = isValidFloorValue(candidate) ? candidate : undefined;
  if (validExisting === undefined) return validCandidate;
  if (validCandidate === undefined) return validExisting;
  return Math.max(validExisting, validCandidate);
}

/**
 * Folds the OLD two-store shape (`generation-high-water` + `seq-high-water`)
 * into the new combined `FLOOR_STORE_NAME` store, then retires the old
 * stores (Pitfall 4). A no-op if the old stores are absent (fresh DB, or a
 * DB that has already been migrated on a prior session).
 *
 * Runs entirely inside the versionchange transaction supplied by
 * `onupgradeneeded` -- both legacy stores are drained via cursor, folded into
 * an in-memory Map keyed by nodeId, then written into the combined store and
 * the legacy stores deleted, all before the transaction completes.
 */
function foldLegacyStoresIntoCombined(db: IDBDatabase, tx: IDBTransaction): void {
  if (
    !db.objectStoreNames.contains(GENERATION_STORE_NAME) ||
    !db.objectStoreNames.contains(SEQ_STORE_NAME)
  ) {
    return; // Fresh DB, or already migrated -- nothing to fold.
  }

  const combinedStore = db.objectStoreNames.contains(FLOOR_STORE_NAME)
    ? tx.objectStore(FLOOR_STORE_NAME)
    : db.createObjectStore(FLOOR_STORE_NAME);

  const genStore = tx.objectStore(GENERATION_STORE_NAME);
  const seqStore = tx.objectStore(SEQ_STORE_NAME);
  const folded = new Map<string, CombinedFloorRecord>();

  const mergeInto = (nodeId: string, field: 'generation' | 'seq', value: unknown) => {
    if (!isValidFloorValue(value)) return;
    const existing = folded.get(nodeId) ?? {};
    folded.set(nodeId, { ...existing, [field]: value });
  };

  let pendingCursors = 2;
  const finalizeWhenDrained = () => {
    pendingCursors -= 1;
    if (pendingCursors > 0) return;
    // Both legacy cursors drained -- write every folded record, then retire
    // the old stores. The floors are the safety-critical payload here (a
    // dropped floor is a real regression, Pitfall 4) -- writes happen before
    // deletion so a mid-migration failure never loses data silently.
    for (const [nodeId, record] of folded) {
      combinedStore.put(record, nodeId);
    }
    db.deleteObjectStore(GENERATION_STORE_NAME);
    db.deleteObjectStore(SEQ_STORE_NAME);
  };

  genStore.openCursor().onsuccess = (event) => {
    const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
    if (cursor) {
      mergeInto(cursor.key as string, 'generation', cursor.value);
      cursor.continue();
    } else {
      finalizeWhenDrained();
    }
  };
  seqStore.openCursor().onsuccess = (event) => {
    const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
    if (cursor) {
      mergeInto(cursor.key as string, 'seq', cursor.value);
      cursor.continue();
    } else {
      finalizeWhenDrained();
    }
  };
}

/**
 * Open the rotation-state IndexedDB database. `onupgradeneeded` folds any
 * legacy two-store data into the combined store (Pitfall 4) before ensuring
 * the combined store exists.
 */
function openRotationDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      const tx = request.transaction;
      if (tx) {
        foldLegacyStoresIntoCombined(db, tx);
      }
      if (!db.objectStoreNames.contains(FLOOR_STORE_NAME)) {
        db.createObjectStore(FLOOR_STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbGetCombined(nodeId: string): Promise<CombinedFloorRecord | undefined> {
  return openRotationDB().then(
    (db) =>
      new Promise<CombinedFloorRecord | undefined>((resolve, reject) => {
        const tx = db.transaction(FLOOR_STORE_NAME, 'readonly');
        const store = tx.objectStore(FLOOR_STORE_NAME);
        const request = store.get(nodeId);
        request.onsuccess = () => {
          resolve(sanitizeRecord(request.result as CombinedFloorRecord | undefined));
        };
        request.onerror = () => reject(request.error);
      })
  );
}

/**
 * Max-preserving write of the `generation`/`seq` fields only -- inside ONE
 * readwrite transaction (read-back-then-put, per the pre-existing `idbPut`
 * pattern). The `wrappedKeyCheckpoint` field is always PRESERVED here, never
 * touched -- only `persistWrappedKey`/`deleteWrappedKey` touch it.
 */
function idbPutFloors(
  nodeId: string,
  generation: number | undefined,
  seq: number | undefined
): Promise<void> {
  return openRotationDB().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(FLOOR_STORE_NAME, 'readwrite');
        const store = tx.objectStore(FLOOR_STORE_NAME);
        const readBack = store.get(nodeId);
        readBack.onsuccess = () => {
          const existing = sanitizeRecord(readBack.result as CombinedFloorRecord | undefined);
          const merged: CombinedFloorRecord = {
            generation: maxFloor(existing?.generation, generation),
            seq: maxFloor(existing?.seq, seq),
            wrappedKeyCheckpoint: existing?.wrappedKeyCheckpoint,
          };
          store.put(merged, nodeId);
        };
        readBack.onerror = () => reject(readBack.error);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      })
  );
}

/**
 * Writes ONLY the `wrappedKeyCheckpoint` field (set to `wrappedKeyB64`, or
 * cleared if `undefined`), preserving the existing `generation`/`seq` floors
 * untouched -- inside ONE readwrite transaction.
 */
function idbPutWrappedKey(nodeId: string, wrappedKeyB64: string | undefined): Promise<void> {
  return openRotationDB().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(FLOOR_STORE_NAME, 'readwrite');
        const store = tx.objectStore(FLOOR_STORE_NAME);
        const readBack = store.get(nodeId);
        readBack.onsuccess = () => {
          const existing = sanitizeRecord(readBack.result as CombinedFloorRecord | undefined);
          const merged: CombinedFloorRecord = {
            generation: existing?.generation,
            seq: existing?.seq,
            wrappedKeyCheckpoint: wrappedKeyB64,
          };
          store.put(merged, nodeId);
        };
        readBack.onerror = () => reject(readBack.error);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      })
  );
}

/**
 * D-08: one-time notice flag. Set the first time the store degrades to the
 * in-memory session floor. Read via `isRotationStateDegraded()` so 68-09 can
 * surface a single toast rather than one per resolve.
 */
let warnedOnce = false;

/** Whether the rotation-state store has degraded to an in-memory session floor this session. */
export function isRotationStateDegraded(): boolean {
  return warnedOnce;
}

/**
 * Builds the combined `HighWaterStore` (SC#4/D-06/D-07) over IndexedDB,
 * degrading to an in-memory `Map` (call-site try/catch, per identity.ts) the
 * first time an IndexedDB operation fails. Once degraded, the store latches
 * to memory-only for the rest of the session so a single logical record
 * never splits across two disagreeing backends.
 */
function createDegradableCombinedStore() {
  const sessionMap = new Map<string, CombinedFloorRecord>();
  let degraded = false;

  return {
    async get(nodeId: string): Promise<CombinedFloorRecord | undefined> {
      if (degraded) {
        return sessionMap.get(nodeId);
      }
      try {
        return await idbGetCombined(nodeId);
      } catch {
        // IndexedDB unavailable/cleared mid-session — degrade for the rest of the session (D-08).
        degraded = true;
        warnedOnce = true;
        return sessionMap.get(nodeId);
      }
    },
    async putFloors(nodeId: string, generation: number | undefined, seq: number | undefined) {
      const applyToSession = () => {
        const existing = sessionMap.get(nodeId) ?? {};
        sessionMap.set(nodeId, {
          ...existing,
          generation: maxFloor(existing.generation, generation),
          seq: maxFloor(existing.seq, seq),
        });
      };
      if (degraded) {
        applyToSession();
        return;
      }
      try {
        await idbPutFloors(nodeId, generation, seq);
      } catch {
        degraded = true;
        warnedOnce = true;
        applyToSession();
      }
    },
    async putWrappedKey(nodeId: string, wrappedKeyB64: string | undefined) {
      const applyToSession = () => {
        const existing = sessionMap.get(nodeId) ?? {};
        sessionMap.set(nodeId, { ...existing, wrappedKeyCheckpoint: wrappedKeyB64 });
      };
      if (degraded) {
        applyToSession();
        return;
      }
      try {
        await idbPutWrappedKey(nodeId, wrappedKeyB64);
      } catch {
        degraded = true;
        warnedOnce = true;
        applyToSession();
      }
    },
  };
}

const combinedFloorStore = createDegradableCombinedStore();

const highWaterStoreAdapter: HighWaterStore = {
  get: (nodeId) => combinedFloorStore.get(nodeId),
  put: (nodeId, record) => combinedFloorStore.putFloors(nodeId, record.generation, record.seq),
};

/**
 * Shared durable rotation high-water state machine (ROT-07) over the
 * combined IndexedDB-backed store above. All monotonic-max/enforcement logic
 * is owned by `@cipherbox/sdk` (68-01, 70.1-02) — this module supplies only
 * the store.
 */
export const rotationHighWater = createRotationHighWater(highWaterStoreAdapter);

/** Owner-vouched first-contact seed (e.g. from a share grant's `rootGeneration`). */
export const seedFromGrant = rotationHighWater.seedFromGrant;

/** Fail-closed pre-unseal gate — see `@cipherbox/sdk`'s `RotationHighWater.enforceResolved`. */
export const enforceResolved = rotationHighWater.enforceResolved;

/**
 * Persists the SC#3 ECIES-wrapped rotation key checkpoint ciphertext for
 * `nodeId`, preserving that node's generation/seq floors untouched. Client-
 * side IndexedDB storage only — MUST NOT be routed through any API endpoint
 * (CLAUDE.md Rule 6, zero-knowledge).
 */
export async function persistWrappedKey(nodeId: string, wrappedKeyB64: string): Promise<void> {
  await combinedFloorStore.putWrappedKey(nodeId, wrappedKeyB64);
}

/** Reads back the SC#3 wrapped-key checkpoint ciphertext for `nodeId`, if any. */
export async function getWrappedKey(nodeId: string): Promise<string | undefined> {
  const record = await combinedFloorStore.get(nodeId);
  return record?.wrappedKeyCheckpoint;
}

/** Clears the SC#3 wrapped-key checkpoint for `nodeId`, preserving its generation/seq floors. */
export async function deleteWrappedKey(nodeId: string): Promise<void> {
  await combinedFloorStore.putWrappedKey(nodeId, undefined);
}
