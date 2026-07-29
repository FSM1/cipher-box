import type {
  EngineClient,
  EventDescriptor,
  SnapshotDescriptor,
  Staleness,
} from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import { VAULT_ROOT_NODE_ID, createSnapshotStore, idleSnapshotStore } from './snapshotStore';

function view(folder: Uint8Array, staleness: Staleness = 'fresh'): SnapshotDescriptor {
  return {
    root: VAULT_ROOT_NODE_ID,
    folder,
    children: [],
    ancestors: [],
    deadLetters: [],
    retainedRecords: 0,
    staleness,
  };
}

/**
 * The engine as the store sees it: an event stream plus a `snapshot` the test
 * settles by hand, so pull ordering is observable rather than timing-dependent.
 */
function fakeEngine() {
  const listeners = new Set<(event: EventDescriptor) => void>();
  const pulls: {
    folder: Uint8Array;
    resolve: (view: SnapshotDescriptor) => void;
    reject: (error: Error) => void;
  }[] = [];
  const focus: (Uint8Array | null)[] = [];
  const reported: (Uint8Array | null)[] = [];
  let settleFocus: (() => void) | null = null;

  const client = {
    facade: {
      subscribe(listener: (event: EventDescriptor) => void) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      snapshot(folder: Uint8Array) {
        return new Promise<SnapshotDescriptor>((resolve, reject) => {
          pulls.push({ folder, resolve, reject });
        });
      },
      setFocus(node: Uint8Array | null) {
        focus.push(node);
        return new Promise<void>((resolve) => {
          settleFocus = resolve;
        });
      },
    },
    reportFocus(node: Uint8Array | null) {
      reported.push(node);
    },
  } as unknown as EngineClient;

  return {
    client,
    pulls,
    focus,
    reported,
    emit: (event: EventDescriptor) => {
      for (const listener of listeners) listener(event);
    },
    ackFocus: () => settleFocus?.(),
    subscriberCount: () => listeners.size,
  };
}

/** Lets every pending promise callback in the store run. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('snapshotStore', () => {
  it('caches the engine view and returns it synchronously', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    const changes: number[] = [];
    store.subscribe(() => changes.push(1));

    expect(store.getSnapshot()).toEqual({ view: null, error: null });

    engine.emit({ kind: 'snapshotUpdated' });
    const emitted = view(VAULT_ROOT_NODE_ID);
    engine.pulls[0].resolve(emitted);
    await flush();

    // Verbatim: the store holds the engine's descriptor, not a derived copy.
    expect(store.getSnapshot().view).toBe(emitted);
    expect(changes).toHaveLength(1);
    // The `useSyncExternalStore` contract: a repeat read is reference-stable.
    expect(store.getSnapshot()).toBe(store.getSnapshot());
  });

  it('re-emits to every subscriber and stops after unsubscribe', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    let first = 0;
    let second = 0;
    const drop = store.subscribe(() => (first += 1));
    store.subscribe(() => (second += 1));

    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[0].resolve(view(VAULT_ROOT_NODE_ID));
    await flush();
    expect([first, second]).toEqual([1, 1]);

    drop();
    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[1].resolve(view(VAULT_ROOT_NODE_ID, 'reconciling'));
    await flush();
    expect([first, second]).toEqual([1, 2]);
  });

  it('pulls the vault root until a focus is set', () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    engine.emit({ kind: 'snapshotUpdated' });
    expect(engine.pulls[0].folder).toEqual(VAULT_ROOT_NODE_ID);
    expect(store.getSnapshot().view).toBeNull();
  });

  it('sets the engine focus window and the cross-tab hint before pulling', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    const folder = new Uint8Array(16).fill(7);

    store.setFocus(folder);
    expect(engine.focus).toEqual([folder]);
    expect(engine.reported).toEqual([folder]);
    expect(engine.pulls).toHaveLength(0);

    engine.ackFocus();
    await flush();
    expect(engine.pulls[0].folder).toBe(folder);

    const focused = view(folder);
    engine.pulls[0].resolve(focused);
    await flush();
    expect(store.getSnapshot().view).toBe(focused);
  });

  it('drops a superseded pull so an older folder never lands over a newer one', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    const older = new Uint8Array(16).fill(1);
    const newer = new Uint8Array(16).fill(2);

    store.setFocus(older);
    engine.ackFocus();
    await flush();

    store.setFocus(newer);
    engine.ackFocus();
    await flush();

    const newest = view(newer);
    engine.pulls[1].resolve(newest);
    await flush();
    engine.pulls[0].resolve(view(older));
    await flush();

    expect(store.getSnapshot().view).toBe(newest);
  });

  it('keeps the last engine view when a pull fails', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    engine.emit({ kind: 'snapshotUpdated' });
    const good = view(VAULT_ROOT_NODE_ID);
    engine.pulls[0].resolve(good);
    await flush();

    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[1].reject(new Error('trust violation'));
    await flush();

    expect(store.getSnapshot().view).toBe(good);
    expect(store.getSnapshot().error).toBe('trust violation');
  });

  it('tracks the staleness ladder from the event stream', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    expect(store.getStaleness()).toBe('reconciling');

    engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    expect(store.getStaleness()).toBe('offline');

    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[0].resolve(view(VAULT_ROOT_NODE_ID, 'fresh'));
    await flush();
    expect(store.getStaleness()).toBe('fresh');
  });

  it('does not let an in-flight pull re-assert a superseded staleness rung', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    engine.pulls[0].resolve(view(VAULT_ROOT_NODE_ID, 'fresh'));
    await flush();

    expect(store.getStaleness()).toBe('offline');
  });

  it('changes rendered state only when the engine speaks', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    let changes = 0;
    store.subscribe(() => (changes += 1));

    // Everything the UI may do, short of the engine answering.
    store.setFocus(new Uint8Array(16).fill(3));
    engine.ackFocus();
    await flush();
    engine.emit({ kind: 'deadLetter', opId: 1n });
    engine.emit({ kind: 'attributableAbuse', description: 'x' });
    await flush();

    expect(changes).toBe(0);
    expect(store.getSnapshot()).toEqual({ view: null, error: null });
    expect(store.getStaleness()).toBe('reconciling');

    engine.pulls[0].resolve(view(new Uint8Array(16).fill(3)));
    await flush();
    expect(changes).toBe(1);
  });

  it('serves a stable empty state before an engine client exists', () => {
    expect(idleSnapshotStore.getSnapshot()).toBe(idleSnapshotStore.getSnapshot());
    expect(idleSnapshotStore.getSnapshot()).toEqual({ view: null, error: null });
    expect(idleSnapshotStore.getStaleness()).toBe('reconciling');
  });

  it('releases the engine subscription on dispose', () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    expect(engine.subscriberCount()).toBe(1);

    store.dispose();
    expect(engine.subscriberCount()).toBe(0);

    engine.emit({ kind: 'snapshotUpdated' });
    expect(engine.pulls).toHaveLength(0);
  });
});
