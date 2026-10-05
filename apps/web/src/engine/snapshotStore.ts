/**
 * The one subscription store the UI holds (blueprint/web-client.md "UI state
 * law"): a `useSyncExternalStore` adapter over the engine event stream with no
 * independent writers. It caches the descriptor the engine handed it and never
 * derives, merges, or patches one.
 *
 * The trust warnings that must never read as staleness are projected from here
 * onto their own surface, because this is the subscription the provider opens
 * with the client: one taken a render later drops the cold-start escalations
 * that land in the gap.
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
 * Whether a later pull clears this on its own: `tooManyStreams` is a ceiling
 * and `refreshFailed` is an unreachable record plane, neither a verdict about
 * what is rendered. Named codes only, so a codeless transport fault and every
 * code this does not name — trust verdicts among them — stay fatal.
 */
export function isRecoverable(error: SnapshotError): boolean {
  return error.code === 'tooManyStreams' || error.code === 'refreshFailed';
}

/**
 * Bytes the drain must free before it will start `opId`, or `null` when that op
 * is not the one held. A hold clears, which is why `blueprint/engine.md` makes
 * it a snapshot field rather than an event.
 */
export function heldBytes(state: SnapshotState, opId: bigint | null): bigint | null {
  const hold = state.view?.queueHold;
  if (hold == null || hold.reason !== 'quota' || opId === null || hold.opId !== opId) return null;
  return hold.neededBytes;
}

/** Durable queue entries this session cannot read but whose bytes it is charged for. */
export function retainedRecords(state: SnapshotState): number {
  return Number(state.view?.retainedRecords ?? 0n);
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
  /** Forces a nocache pass, then re-pulls the focused folder. */
  refresh(): void;
  /** Releases the event subscription. */
  dispose(): void;
}

/** The pinned name identifies the scope for de-duplication, never for reading. */
const WITHHELD =
  'a shared folder stopped serving updates you are entitled to see - what it shows may be behind';

/** A revoke, a permission change or a share stopped part of the way; each pass retries it. */
const ROTATION_OWED =
  'a change to who can open a shared folder is not finished yet - CipherBox keeps retrying it on this device';

/** A revoke or permission change stopped on a record that failed verification; it cannot finish past it. */
const ROTATION_TRUST_STOP =
  'a change to who can open a shared folder did not complete because a record in that folder failed verification - CipherBox will not finish it while that record stands';

/** Owed sharing work that can never finish was dropped; the change it made stands as it is. */
const ROTATION_ABANDONED =
  'a change to who can open a shared folder could not be finished and was stopped - check the folder sharing and try again';

/** Another device started a write cut that has not finished; any owner device can finish it. */
const WRITE_CUT_UNFINISHED =
  'a shared folder has a write-access change that another of your devices has not finished - finish it here, or open CipherBox on that device';

const FINISH_WRITE_CUT = 'finish it here';

/** The engine refused the write cut this device asked for. */
const WRITE_CUT_FAILED =
  'the write-access change of a shared folder did not finish on this device - try again later';

/** The write cut met a record that failed verification; no retry clears that. */
const WRITE_CUT_TRUST_STOP =
  'the write-access change of a shared folder stopped because a record in that folder failed verification - CipherBox will not finish it while that record stands';

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
  // `undefined` until the first `setFocus`, which reaches the engine even when it
  // names the root: a cold start at the root has sent no focus yet.
  let focus: Uint8Array | null | undefined = undefined;
  // Any newer intent — a new pull, or `supersedePulls` — supersedes whatever is
  // in flight, so an older folder's late answer never lands over a newer one.
  let generation = 0;
  // `stalenessChanged` is edge-triggered while a descriptor's rung is computed
  // at read time, so a pull that started before an event must not re-assert the
  // rung that event superseded.
  let stalenessSeq = 0;
  // At most one pull in flight: the engine emits `snapshotUpdated` per op stage,
  // so an N-file upload would otherwise cost N queue-scan round trips for one
  // final view. Holds the in-flight pull's generation, so a focus change can
  // supersede it rather than wait it out.
  let inFlight: number | null = null;
  let coalesced = false;
  // The provider disposes this store and its client together, and a logout
  // rebuild does so with the tab still live — so a continuation still holding an
  // older intent must not reach a closed facade.
  let disposed = false;
  // Counts focus changes alone, since every pull bumps `generation`. While the
  // latest one's `setFocus` runs, the engine may still be listing its way down
  // to a folder a reload routed to, so `unknownNode` is not yet a verdict.
  let focusSeq = 0;
  let locating = false;

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

  // A failure only lands if no newer intent has superseded the call that raised it.
  const failIfCurrent =
    (id: number) =>
    (error: unknown): void => {
      if (id === generation) commit({ error: describe(error) });
    };

  // Drops the pull in flight and any re-pull it owes, so their late answer
  // never lands over a newer intent.
  const supersedePulls = (): void => {
    generation += 1;
    inFlight = null;
    coalesced = false;
  };

  const pull = (): void => {
    if (disposed) return;
    if (inFlight !== null) {
      coalesced = true;
      return;
    }
    const id = ++generation;
    inFlight = id;
    const seq = stalenessSeq;
    void client.facade
      .snapshot(focus ?? null)
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
          if (id !== generation) return;
          const described = describe(error);
          commit({ error: locating && described.code === 'unknownNode' ? null : described });
        }
      )
      .finally(() => {
        if (inFlight !== id) return;
        inFlight = null;
        if (!coalesced) return;
        coalesced = false;
        pull();
      });
  };

  const assertFocus = (): void => {
    if (disposed) return;
    const id = ++focusSeq;
    locating = true;
    // The engine runs commands in arrival order: the relay's forced pass must see this focus.
    const node = focus ?? null;
    client.facade.setFocus(node).then(
      () => {
        if (id !== focusSeq) return;
        locating = false;
        pull();
      },
      (error: unknown) => {
        if (id !== focusSeq) return;
        locating = false;
        supersedePulls();
        commit({ error: describe(error) });
      }
    );
    client.reportFocus(node);
    // Cache-first: what the engine already holds paints now, and the focus
    // refresh repaints behind it. A pull of the folder left behind is superseded.
    supersedePulls();
    pull();
  };

  const unsubscribe = client.facade.subscribe((event) => {
    if (event.kind === 'snapshotUpdated') {
      pull();
    } else if (event.kind === 'stalenessChanged') {
      stalenessSeq += 1;
      commit({ staleness: event.staleness });
    } else if (event.kind === 'withheldUpdateEscalation') {
      notificationStore.warn(`withheld:${toHex(event.ipnsName)}`, WITHHELD);
    } else if (event.kind === 'rotationWorkOwed') {
      if (event.class === 'trust') {
        notificationStore.warn(`owed-trust:${toHex(event.scopeRoot)}`, ROTATION_TRUST_STOP);
      } else {
        notificationStore.warn(`owed:${toHex(event.scopeRoot)}`, ROTATION_OWED);
      }
    } else if (event.kind === 'rotationWorkAbandoned') {
      notificationStore.warn(`abandoned:${toHex(event.scopeRoot)}`, ROTATION_ABANDONED);
    } else if (event.kind === 'writeCutUnfinished') {
      const scope = toHex(event.scopeRoot);
      const key = `unfinished:${scope}`;
      const failed = `unfinished-failed:${scope}`;
      notificationStore.warn(key, WRITE_CUT_UNFINISHED, {
        label: FINISH_WRITE_CUT,
        run: () =>
          client.facade.rotateWriteNow(event.scopeRoot).then(
            () => {
              if (disposed) return;
              notificationStore.dismiss(key);
              notificationStore.dismiss(failed);
            },
            (refusal: unknown) => {
              if (disposed) return;
              if (refusal instanceof EngineRequestError && refusal.code === 'trustViolation') {
                // The same key, so a later report of the scope offers no retry.
                notificationStore.dismiss(key);
                notificationStore.dismiss(failed);
                notificationStore.warn(key, WRITE_CUT_TRUST_STOP);
              } else {
                notificationStore.warn(failed, WRITE_CUT_FAILED);
              }
            }
          ),
      });
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
      if (focus !== undefined && sameNode(focus, node)) return;
      focus = node;
      assertFocus();
    },
    refocus: assertFocus,
    refresh() {
      if (disposed) return;
      const id = generation;
      // A refused pass leaves the rendered view exactly where it was, so it is
      // reported rather than repainted over as though it had landed.
      void client.facade.manualRefresh().then(() => {
        if (id === generation) pull();
      }, failIfCurrent(id));
    },
    dispose() {
      disposed = true;
      // Supersede every in-flight intent, so a late answer commits nothing.
      generation += 1;
      focusSeq += 1;
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
