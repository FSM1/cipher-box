/**
 * The one subscription store the UI holds (blueprint/web-client.md "UI state
 * law"): a `useSyncExternalStore` adapter over the engine event stream with no
 * independent writers. It caches the descriptor the engine handed it and never
 * derives, merges, or patches one.
 */

import { EngineRequestError } from '@cipherbox/client';
import type { EngineClient, SnapshotDescriptor, Staleness } from '@cipherbox/client';

/**
 * The folder the first pull asks for, before any view names a root: the
 * engine's cold-start anchor (`crates/engine/src/facade.rs`, `Snapshot::new`).
 * Every later pull uses the root the engine reported. Retiring this seed needs
 * a snapshot seam that takes no folder — #900.
 */
const VAULT_ROOT_SEED_ID: Uint8Array = new Uint8Array(16);

/** A failed pull, carrying the engine's stable code so the UI can classify it. */
export interface SnapshotError {
  message: string;
  /** The engine's `EngineError` variant name, absent for transport faults. */
  code?: string;
}

export interface SnapshotState {
  /** The focused folder, or `null` until the first pull lands. */
  view: SnapshotDescriptor | null;
  /** The last pull's failure, or `null`. Last-known-good `view` survives it. */
  error: SnapshotError | null;
}

export interface SnapshotStore {
  /** `useSyncExternalStore` subscribe: fires on every committed change. */
  subscribe(onStoreChange: () => void): () => void;
  /** `useSyncExternalStore` getSnapshot: the cache, synchronously. */
  getSnapshot(): SnapshotState;
  /** The staleness ladder's current rung. */
  getStaleness(): Staleness;
  /** Points the adapter (and the engine's focus window) at a folder. */
  setFocus(node: Uint8Array | null): void;
  /** Releases the event subscription. */
  dispose(): void;
}

const IDLE: SnapshotState = { view: null, error: null };

/** A store-shaped no-op for consumers mounted before the engine client exists. */
export const idleSnapshotStore: SnapshotStore = {
  subscribe: () => () => undefined,
  getSnapshot: () => IDLE,
  getStaleness: () => 'reconciling',
  setFocus: () => undefined,
  dispose: () => undefined,
};

interface Commit {
  view?: SnapshotDescriptor | null;
  error?: SnapshotError | null;
  staleness?: Staleness;
}

export function createSnapshotStore(client: EngineClient): SnapshotStore {
  const listeners = new Set<() => void>();
  let state: SnapshotState = IDLE;
  let staleness: Staleness = 'reconciling';
  let focus: Uint8Array | null = null;
  // Any newer intent — a landed pull or a focus change — supersedes whatever is
  // in flight, so an older folder's late answer never lands over a newer one.
  let generation = 0;
  // `stalenessChanged` is edge-triggered while a descriptor's rung is computed
  // at read time, so a pull that started before an event must not re-assert the
  // rung that event superseded.
  let stalenessSeq = 0;
  // At most one pull in flight: the engine emits `snapshotUpdated` per op stage,
  // so an N-file upload would otherwise cost N queue-scan round trips for one
  // final view.
  let inFlight = false;
  let coalesced = false;

  const commit = (next: Commit): void => {
    const view = next.view === undefined ? state.view : next.view;
    const error = next.error === undefined ? state.error : next.error;
    const stateChanged = view !== state.view || error !== state.error;
    const rungChanged = next.staleness !== undefined && next.staleness !== staleness;
    if (!stateChanged && !rungChanged) return;
    if (stateChanged) state = { view, error };
    if (next.staleness !== undefined) staleness = next.staleness;
    for (const listener of listeners) listener();
  };

  const pull = (): void => {
    if (inFlight) {
      coalesced = true;
      return;
    }
    inFlight = true;
    const id = ++generation;
    const seq = stalenessSeq;
    const folder = focus ?? state.view?.root ?? VAULT_ROOT_SEED_ID;
    void client.facade
      .snapshot(folder)
      .then(
        (view) => {
          if (id !== generation) return;
          commit({
            view,
            error: null,
            staleness: seq === stalenessSeq ? view.staleness : undefined,
          });
        },
        (error: unknown) => {
          if (id === generation) commit({ error: describe(error) });
        }
      )
      .finally(() => {
        inFlight = false;
        if (!coalesced) return;
        coalesced = false;
        pull();
      });
  };

  const unsubscribe = client.facade.subscribe((event) => {
    if (event.kind === 'snapshotUpdated') {
      pull();
    } else if (event.kind === 'stalenessChanged') {
      stalenessSeq += 1;
      commit({ staleness: event.staleness });
    }
  });

  return {
    subscribe(onStoreChange) {
      listeners.add(onStoreChange);
      return () => listeners.delete(onStoreChange);
    },
    getSnapshot: () => state,
    getStaleness: () => staleness,
    setFocus(node) {
      if (sameNode(focus, node)) return;
      focus = node;
      client.reportFocus(node);
      const id = ++generation;
      client.facade.setFocus(node).then(
        () => {
          if (id === generation) pull();
        },
        (error: unknown) => {
          if (id === generation) commit({ error: describe(error) });
        }
      );
    },
    dispose() {
      unsubscribe();
      listeners.clear();
    },
  };
}

function describe(error: unknown): SnapshotError {
  if (error instanceof EngineRequestError) return { message: error.message, code: error.code };
  return { message: error instanceof Error ? error.message : String(error) };
}

/** Node ids compare by value: callers hand in a fresh array per render. */
function sameNode(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
