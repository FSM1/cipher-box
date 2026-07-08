/**
 * @cipherbox/sdk - Browser IndexedDB adapter for the rotation high-water plane
 *
 * The CONCRETE, browser-only IndexedDB `HighWaterStore` (the `get`/`put` seam
 * from `rotation-high-water.ts`) plus the SC#3 ECIES wrapped-key checkpoint
 * accessors (D-07). Hoisted OUT of `apps/web` (68-06) into the SDK (70.1-02)
 * so the schema-collapse migration and max-preserving persistence are
 * unit-tested in a CI-covered suite -- `apps/web`'s `*.test.ts` files are NOT
 * run by CI (web is web-e2e-gated), whereas `pnpm --filter @cipherbox/sdk test`
 * IS. `apps/web`'s `rotation-state.service.ts` is now thin wiring over this
 * factory.
 *
 * This module owns NO monotonic-max or fail-closed comparison logic beyond the
 * store-boundary max-preserving `put` -- the enforcement/regression logic lives
 * in `rotation-high-water.ts` (68-01, unit-proven there).
 *
 * One database, ONE combined object store (SC#4/D-06), keyed explicitly by
 * `nodeId` (no `keyPath`), holding `{ generation?, seq?, wrappedKeyCheckpoint? }`:
 *   - `generation` -- the M1 cross-generation rollback defense (design §4.3)
 *   - `seq` -- the within-generation sequence rollback defense (design §6.5)
 *   - `wrappedKeyCheckpoint` -- the SC#3 ECIES-wrapped rotation key checkpoint
 *     ciphertext (D-07). Client-side only -- NEVER routed through any API
 *     endpoint (CLAUDE.md Rule 6, zero-knowledge). This is a DIFFERENT plane
 *     from the per-rootNodeId job-checkpoint plane (`cipherbox-rotation-jobs`),
 *     which explicitly documents "never key material" -- the wrapped key
 *     belongs here, keyed by nodeId, alongside that node's own floor. Only ever
 *     ciphertext at rest; this module never sees, persists, or logs plaintext
 *     key bytes.
 *
 * Prior to 70.1-02 the DB held TWO separate object stores
 * (`generation-high-water`, `seq-high-water`, `DB_VERSION = 1`). `DB_VERSION`
 * is 2 and `onupgradeneeded` folds any existing two-store data into the new
 * combined store (Pitfall 4 -- floors are safety-critical, a silent reset is a
 * real regression even though it is safe-directional) before retiring the old
 * stores.
 *
 * D-08 degradation: if `indexedDB.open` (or any subsequent transaction) throws
 * or rejects -- unavailable, private-mode, cleared mid-session -- the store
 * falls back to an in-memory `Map` for the remainder of the session and latches
 * a one-time degraded flag. Once degraded, the store never re-attempts
 * IndexedDB for the rest of the session: mixing IDB and memory reads for the
 * same record would let a floor observed via one backend silently disagree with
 * a floor written via the other, undermining the monotonic-max guarantee.
 *
 * The global `indexedDB` is referenced LAZILY (only inside function bodies, on
 * first open) -- importing this module in a non-browser (Node) context without
 * a polyfill never throws at import time. This module is intentionally NOT part
 * of the SDK's main `index.ts` barrel: it is imported via its own module path
 * (`@cipherbox/sdk/state/rotation-idb-store`) so IndexedDB is never pulled into
 * desktop/node consumers and the module stays tree-shakeable.
 */

import { type CombinedFloorRecord, type HighWaterStore } from './rotation-high-water';

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
 * coerced to a low floor. Matches the SDK's own `isValidFloorValue` guard --
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
 * into the new combined `FLOOR_STORE_NAME` store, then retires the old stores
 * (Pitfall 4). A no-op if the old stores are absent (fresh DB, or a DB that has
 * already been migrated on a prior session).
 *
 * Runs entirely inside the versionchange transaction supplied by
 * `onupgradeneeded` -- both legacy stores are drained via cursor, folded into
 * an in-memory Map keyed by nodeId, then written into the combined store and
 * the legacy stores deleted, all before the transaction completes.
 */
export function foldLegacyStoresIntoCombined(db: IDBDatabase, tx: IDBTransaction): void {
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
    // Both legacy cursors drained -- write every folded record, then retire the
    // old stores. The floors are the safety-critical payload here (a dropped
    // floor is a real regression, Pitfall 4) -- writes happen before deletion so
    // a mid-migration failure never loses data silently.
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
 * Opens the rotation-state IndexedDB database. `onupgradeneeded` folds any
 * legacy two-store data into the combined store (Pitfall 4) before ensuring the
 * combined store exists. References the global `indexedDB` lazily (here, on
 * first open) so importing this module in Node without a polyfill never throws.
 */
export function openRotationDB(): Promise<IDBDatabase> {
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
 * readwrite transaction (read-back-then-put). The `wrappedKeyCheckpoint` field
 * is always PRESERVED here, never touched -- only `persistWrappedKey`/
 * `deleteWrappedKey` touch it. A concurrent tab's higher write can never be
 * clobbered by a lower one because the max is computed against the value read
 * back INSIDE the same transaction.
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
 * The IndexedDB-backed rotation store: the combined `HighWaterStore` seam for
 * `createRotationHighWater`, the SC#3 wrapped-key checkpoint accessors, and the
 * D-08 degradation flag accessor.
 */
export interface IndexedDbHighWaterStore {
  /** The combined `HighWaterStore` seam to pass to `createRotationHighWater`. */
  store: HighWaterStore;
  /**
   * Persists the SC#3 ECIES-wrapped rotation key checkpoint CIPHERTEXT for
   * `nodeId`, preserving that node's generation/seq floors untouched. Client-
   * side IndexedDB storage only -- MUST NOT be routed through any API endpoint
   * (CLAUDE.md Rule 6, zero-knowledge). Input is base64 ciphertext, never
   * plaintext key bytes.
   */
  persistWrappedKey(nodeId: string, wrappedKeyB64: string): Promise<void>;
  /** Reads back the SC#3 wrapped-key checkpoint ciphertext for `nodeId`, if any. */
  getWrappedKey(nodeId: string): Promise<string | undefined>;
  /** Clears the SC#3 wrapped-key checkpoint for `nodeId`, preserving its floors. */
  deleteWrappedKey(nodeId: string): Promise<void>;
  /** Whether the store has degraded to an in-memory session floor this session (D-08). */
  isRotationStateDegraded(): boolean;
}

/**
 * Builds the IndexedDB-backed rotation store (SC#4/D-06/D-07). Degrades to an
 * in-memory `Map` the first time an IndexedDB operation fails (D-08); once
 * degraded, it latches to memory-only for the rest of the session so a single
 * logical record never splits across two disagreeing backends. All degradation
 * state is instance-scoped to this factory call.
 */
export function createIndexedDbHighWaterStore(): IndexedDbHighWaterStore {
  const sessionMap = new Map<string, CombinedFloorRecord>();
  let degraded = false;

  async function get(nodeId: string): Promise<CombinedFloorRecord | undefined> {
    if (degraded) {
      return sessionMap.get(nodeId);
    }
    try {
      return await idbGetCombined(nodeId);
    } catch {
      // IndexedDB unavailable/cleared mid-session -- degrade for the rest of the session (D-08).
      degraded = true;
      return sessionMap.get(nodeId);
    }
  }

  async function putFloors(
    nodeId: string,
    generation: number | undefined,
    seq: number | undefined
  ): Promise<void> {
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
      applyToSession();
    }
  }

  async function putWrappedKey(nodeId: string, wrappedKeyB64: string | undefined): Promise<void> {
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
      applyToSession();
    }
  }

  const store: HighWaterStore = {
    get: (nodeId) => get(nodeId),
    put: (nodeId, record) => putFloors(nodeId, record.generation, record.seq),
  };

  return {
    store,
    async persistWrappedKey(nodeId, wrappedKeyB64) {
      await putWrappedKey(nodeId, wrappedKeyB64);
    },
    async getWrappedKey(nodeId) {
      const record = await get(nodeId);
      return record?.wrappedKeyCheckpoint;
    },
    async deleteWrappedKey(nodeId) {
      await putWrappedKey(nodeId, undefined);
    },
    isRotationStateDegraded() {
      return degraded;
    },
  };
}
