/**
 * The one subscription store the UI holds (blueprint/web-client.md "UI state
 * law"): a `useSyncExternalStore` adapter over the engine event stream with no
 * independent writers. Every rendered field is the engine's word verbatim —
 * the store caches the descriptor it was handed and never derives, merges, or
 * patches one, so the v1 two-store desync class has no second writer to desync.
 */

import type { EngineClient, SnapshotDescriptor, Staleness } from '@cipherbox/client';

/**
 * The vault's own root node id: the engine's anchored all-zero id16 cold-start
 * bootstrap anchor (`crates/engine/src/facade.rs`, `Snapshot::new`).
 */
export const VAULT_ROOT_NODE_ID: Uint8Array = new Uint8Array(16);

export interface SnapshotState {
  /** The focused folder, or `null` until the first pull lands. */
  view: SnapshotDescriptor | null;
  /** The last pull's failure, or `null`. Last-known-good `view` survives it. */
  error: string | null;
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

export function createSnapshotStore(client: EngineClient): SnapshotStore {
  const listeners = new Set<() => void>();
  let state: SnapshotState = IDLE;
  let staleness: Staleness = 'reconciling';
  let focus: Uint8Array | null = null;
  // Only the newest pull may commit: `snapshot()` is async, so a burst of
  // events can otherwise land an older folder's view over a newer one.
  let pullId = 0;
  // Bumped by every `stalenessChanged`, so a pull that started before one
  // cannot re-assert the rung the event has already superseded.
  let stalenessSeq = 0;

  const notify = (): void => {
    for (const listener of listeners) listener();
  };

  // One engine word, one notification: a landed pull carries both the view and
  // a rung, and React must not re-render twice for it.
  const commit = (
    view: SnapshotDescriptor | null,
    error: string | null,
    rung: Staleness | undefined
  ): void => {
    const viewChanged = view !== state.view || error !== state.error;
    const rungChanged = rung !== undefined && rung !== staleness;
    if (!viewChanged && !rungChanged) return;
    if (viewChanged) state = { view, error };
    if (rung !== undefined) staleness = rung;
    notify();
  };

  const pull = (): void => {
    const id = ++pullId;
    const seq = stalenessSeq;
    const folder = focus ?? state.view?.root ?? VAULT_ROOT_NODE_ID;
    client.facade.snapshot(folder).then(
      (view) => {
        if (id !== pullId) return;
        commit(view, null, seq === stalenessSeq ? view.staleness : undefined);
      },
      (error: unknown) => {
        if (id !== pullId) return;
        commit(state.view, describe(error), undefined);
      }
    );
  };

  const unsubscribe = client.facade.subscribe((event) => {
    if (event.kind === 'snapshotUpdated') {
      pull();
    } else if (event.kind === 'stalenessChanged') {
      stalenessSeq += 1;
      commit(state.view, state.error, event.staleness);
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
      focus = node;
      // The origin-wide focus-window union drives cross-tab freshness hints.
      client.reportFocus(node);
      const id = ++pullId;
      client.facade.setFocus(node).then(
        () => {
          if (id === pullId) pull();
        },
        (error: unknown) => {
          if (id === pullId) commit(state.view, describe(error), undefined);
        }
      );
    },
    dispose() {
      unsubscribe();
      listeners.clear();
    },
  };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
