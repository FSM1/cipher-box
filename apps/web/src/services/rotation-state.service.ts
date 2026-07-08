/**
 * Rotation State Service — durable anti-rollback high-water floors (ROT-07)
 * + SC#3 ECIES wrapped-key checkpoint (D-07)
 *
 * Thin wiring over the SDK's browser IndexedDB rotation adapter. As of 70.1-02
 * the concrete IndexedDB store, the DB_VERSION-2 schema-collapse migration, the
 * max-preserving persistence, the SC#3 wrapped-key accessors, and the D-08
 * degradation tracking all live in `@cipherbox/sdk`'s
 * `state/rotation-idb-store` module -- hoisted OUT of apps/web so they are
 * unit-tested in a CI-covered suite (`pnpm --filter @cipherbox/sdk test`),
 * since apps/web's own `*.test.ts` files are NOT run by CI (web is
 * web-e2e-gated). This module now only constructs the state machine over that
 * store and re-exports the public surface the rest of the web app consumes.
 *
 * All monotonic-max/enforcement logic is owned by `@cipherbox/sdk`
 * (`createRotationHighWater`, 68-01/70.1-02). The wrapped-key checkpoint is
 * ciphertext-only at rest, client-side IndexedDB only -- never routed through
 * any API (CLAUDE.md Rule 6, zero-knowledge).
 */

import { createRotationHighWater } from '@cipherbox/sdk';
import { createIndexedDbHighWaterStore } from '@cipherbox/sdk/state/rotation-idb-store';

const idbStore = createIndexedDbHighWaterStore();

/**
 * Shared durable rotation high-water state machine (ROT-07) over the combined
 * IndexedDB-backed store. All monotonic-max/enforcement logic is owned by
 * `@cipherbox/sdk`; this module supplies only the wiring.
 */
export const rotationHighWater = createRotationHighWater(idbStore.store);

/** Owner-vouched first-contact seed (e.g. from a share grant's `rootGeneration`). */
export const seedFromGrant = rotationHighWater.seedFromGrant;

/** Fail-closed pre-unseal gate — see `@cipherbox/sdk`'s `RotationHighWater.enforceResolved`. */
export const enforceResolved = rotationHighWater.enforceResolved;

/** Whether the rotation-state store has degraded to an in-memory session floor this session (D-08). */
export function isRotationStateDegraded(): boolean {
  return idbStore.isRotationStateDegraded();
}

/**
 * Persists the SC#3 ECIES-wrapped rotation key checkpoint ciphertext for
 * `nodeId`, preserving that node's generation/seq floors untouched. Client-side
 * IndexedDB storage only — MUST NOT be routed through any API endpoint
 * (CLAUDE.md Rule 6, zero-knowledge).
 */
export function persistWrappedKey(nodeId: string, wrappedKeyB64: string): Promise<void> {
  return idbStore.persistWrappedKey(nodeId, wrappedKeyB64);
}

/** Reads back the SC#3 wrapped-key checkpoint ciphertext for `nodeId`, if any. */
export function getWrappedKey(nodeId: string): Promise<string | undefined> {
  return idbStore.getWrappedKey(nodeId);
}

/** Clears the SC#3 wrapped-key checkpoint for `nodeId`, preserving its generation/seq floors. */
export function deleteWrappedKey(nodeId: string): Promise<void> {
  return idbStore.deleteWrappedKey(nodeId);
}
