/**
 * The one subscription store the UI holds (blueprint/web-client.md "UI state
 * law"): a `useSyncExternalStore` adapter over the engine event stream with no
 * independent writers. It caches the descriptor the engine handed it and never
 * derives, merges, or patches one.
 *
 * It is also the stream's only listener, so the trust warnings that must never
 * read as staleness are projected from here onto their own surface — a second
 * subscription would open a render later than the engine starts, and drop the
 * cold-start escalations that land in the gap.
 */

import { EngineRequestError, toHex } from '@cipherbox/client';
import type { EngineClient, SnapshotDescriptor, Staleness } from '@cipherbox/client';
import { sameNode } from '../lib/nodeId';
import { notificationStore } from '../stores/notification.store';

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

/**
 * Whether a later pull clears this on its own: `tooManyStreams` is a ceiling,
 * not a verdict. Named codes only, so a codeless transport fault and every code
 * this does not name — trust verdicts among them — stay fatal.
 */
export function isRecoverable(error: SnapshotError): boolean {
  return error.code === 'tooManyStreams';
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
  /** Re-asserts the cached focus after a consumer drove `facade.setFocus` itself. */
  refocus(): void;
  /** Re-pulls the focused folder, behind a best-effort nocache resolve. */
  refresh(): void;
  /** Releases the event subscription. */
  dispose(): void;
}

/** The pinned name identifies the scope for de-duplication, never for reading. */
const WITHHELD =
  'a shared folder stopped serving updates you are entitled to see - what it shows may be behind';

const IDLE: SnapshotState = { view: null, error: null };

/** A store-shaped no-op for consumers mounted before the engine client exists. */
export const idleSnapshotStore: SnapshotStore = {
  subscribe: () => () => undefined,
  getSnapshot: () => IDLE,
  getStaleness: () => 'reconciling',
  setFocus: () => undefined,
  refocus: () => undefined,
  refresh: () => undefined,
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
  // The provider disposes this store and its client together, and a logout
  // rebuild does so with the tab still live — so a continuation still holding an
  // older intent must not reach a closed facade.
  let disposed = false;

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
    if (disposed) return;
    if (inFlight) {
      coalesced = true;
      return;
    }
    inFlight = true;
    const id = ++generation;
    const seq = stalenessSeq;
    void client.facade
      .snapshot(focus)
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

  const assertFocus = (): void => {
    if (disposed) return;
    client.reportFocus(focus);
    const id = ++generation;
    client.facade.setFocus(focus).then(
      () => {
        if (id === generation) pull();
      },
      (error: unknown) => {
        if (id === generation) commit({ error: describe(error) });
      }
    );
  };

  const unsubscribe = client.facade.subscribe((event) => {
    if (event.kind === 'snapshotUpdated') {
      pull();
    } else if (event.kind === 'stalenessChanged') {
      stalenessSeq += 1;
      commit({ staleness: event.staleness });
    } else if (event.kind === 'withheldUpdateEscalation') {
      notificationStore.warn(`withheld:${toHex(event.ipnsName)}`, WITHHELD);
    } else if (event.kind === 'attributableAbuse') {
      notificationStore.warn(
        `abuse:${event.description}`,
        `verification refused an update: ${event.description}`
      );
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
      assertFocus();
    },
    refocus: assertFocus,
    refresh() {
      if (disposed) return;
      const id = generation;
      const again = (): void => {
        if (id === generation) pull();
      };
      // The nocache hint is best-effort: only the pull it precedes sets `error`.
      void client.facade.manualRefresh().then(again, again);
    },
    dispose() {
      disposed = true;
      // Supersede every in-flight intent, so a late answer commits nothing.
      generation += 1;
      unsubscribe();
      listeners.clear();
      // A warning names the scope it came from; it must not outlive its engine.
      notificationStore.clear();
    },
  };
}

function describe(error: unknown): SnapshotError {
  if (error instanceof EngineRequestError) return { message: error.message, code: error.code };
  return { message: error instanceof Error ? error.message : String(error) };
}
