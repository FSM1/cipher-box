import { EngineRequestError } from '@cipherbox/client';
import { describe, expect, it } from 'vitest';
import { createSnapshotStore, idleSnapshotStore, isRecoverable } from './snapshotStore';
import { ROOT_ID, fakeEngine, flush, view } from './testFakes';

describe('snapshotStore', () => {
  it('caches the engine view and returns it synchronously', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    let changes = 0;
    store.subscribe(() => (changes += 1));

    expect(store.getSnapshot()).toEqual({ view: null, error: null });

    engine.emit({ kind: 'snapshotUpdated' });
    const emitted = view();
    engine.pulls[0].resolve(emitted);
    await flush();

    // Verbatim: the store holds the engine's descriptor, not a derived copy.
    expect(store.getSnapshot().view).toBe(emitted);
    // One engine word, one notification — the view and its rung land together.
    expect(changes).toBe(1);
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
    engine.pulls[0].resolve(view());
    await flush();
    expect([first, second]).toEqual([1, 1]);

    drop();
    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[1].resolve(view(ROOT_ID, 'reconciling'));
    await flush();
    expect([first, second]).toEqual([1, 2]);
  });

  it('asks for the vault root rather than naming it until a focus is set', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    // A cold start whose adopted base roots at a non-anchor id: that engine
    // knows no all-zero node, so naming one would be `unknownNode`.
    const adopted = new Uint8Array(16).fill(0xa7);

    engine.emit({ kind: 'snapshotUpdated' });
    expect(engine.pulls[0].folder).toBeNull();
    expect(store.getSnapshot().view).toBeNull();

    engine.pulls[0].resolve({ ...view(adopted), root: adopted });
    await flush();
    expect(store.getSnapshot().error).toBeNull();
    expect(store.getSnapshot().view?.root).toEqual(adopted);
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

  it('surfaces a rejected focus change and pulls nothing', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    store.setFocus(new Uint8Array(16).fill(7));
    engine.rejectFocus(new Error('focus denied'));
    await flush();

    expect(store.getSnapshot()).toEqual({ view: null, error: { message: 'focus denied' } });
    expect(engine.pulls).toHaveLength(0);
  });

  it('ignores a focus change to the folder already focused', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    store.setFocus(new Uint8Array(16).fill(7));
    engine.ackFocus();
    await flush();
    // A fresh array with identical bytes: the route re-rendered, nothing moved.
    store.setFocus(new Uint8Array(16).fill(7));

    expect(engine.focus).toHaveLength(1);
    expect(engine.reported).toHaveLength(1);
    expect(engine.pulls).toHaveLength(1);
  });

  it('coalesces an event burst into one re-pull', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    // One `snapshotUpdated` per op stage, all while the first pull is in flight.
    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'snapshotUpdated' });
    expect(engine.pulls).toHaveLength(1);

    engine.pulls[0].resolve(view());
    await flush();

    // Exactly one re-pull, not one per event.
    expect(engine.pulls).toHaveLength(2);
    const final = view(ROOT_ID, 'fresh', 2);
    engine.pulls[1].resolve(final);
    await flush();

    expect(engine.pulls).toHaveLength(2);
    expect(store.getSnapshot().view).toBe(final);
  });

  it('drops a superseded pull so an older folder never lands over a newer one', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    const older = new Uint8Array(16).fill(1);
    const newer = new Uint8Array(16).fill(2);

    store.setFocus(older);
    engine.ackFocus();
    await flush();
    expect(engine.pulls[0].folder).toBe(older);

    // Navigate away while the first folder's pull is still outstanding.
    store.setFocus(newer);
    engine.ackFocus();
    await flush();

    engine.pulls[0].resolve(view(older, 'fresh', 9));
    await flush();
    // The stale answer is discarded, and its settlement releases the coalesced
    // re-pull — which targets the folder now focused.
    expect(store.getSnapshot().view).toBeNull();
    expect(engine.pulls[1].folder).toBe(newer);

    const newest = view(newer);
    engine.pulls[1].resolve(newest);
    await flush();
    expect(store.getSnapshot().view).toBe(newest);
  });

  it('keeps the last engine view when a pull fails, with the engine error code', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    engine.emit({ kind: 'snapshotUpdated' });
    const good = view();
    engine.pulls[0].resolve(good);
    await flush();

    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[1].reject(
      new EngineRequestError('root failed the adoption gate', 'trustViolation')
    );
    await flush();

    expect(store.getSnapshot().view).toBe(good);
    // Classified, not string-matched: the UI renders trust violations apart
    // from staleness (blueprint/web-client.md "UI state law").
    expect(store.getSnapshot().error).toEqual({
      message: 'root failed the adoption gate',
      code: 'trustViolation',
    });
  });

  it('tracks the staleness ladder from the event stream', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    expect(store.getStaleness()).toBe('reconciling');

    engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    expect(store.getStaleness()).toBe('offline');

    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[0].resolve(view(ROOT_ID, 'fresh'));
    await flush();
    expect(store.getStaleness()).toBe('fresh');
  });

  it('does not let an in-flight pull re-assert a superseded staleness rung', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'stalenessChanged', staleness: 'offline' });
    engine.pulls[0].resolve(view(ROOT_ID, 'fresh'));
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
    engine.emit({ kind: 'deadLetter', opId: 1n, reason: 'targetGone' });
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

describe('the focus window', () => {
  const FOLDER = new Uint8Array(16).fill(3);

  it('re-asserts the cached focus after a consumer borrowed the window', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    store.setFocus(FOLDER);
    engine.ackFocus();
    await flush();

    // A folder picker drove `facade.setFocus` itself; the store's cache is
    // unchanged, so asking it for the same folder short-circuits.
    store.setFocus(FOLDER);
    expect(engine.focus).toEqual([FOLDER]);

    store.refocus();
    expect(engine.focus).toEqual([FOLDER, FOLDER]);
    expect(engine.reported).toEqual([FOLDER, FOLDER]);
  });

  it('pulls its own folder after taking the window back', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    store.setFocus(FOLDER);
    engine.ackFocus();
    await flush();
    engine.pulls[0].resolve(view(FOLDER));
    await flush();

    store.refocus();
    engine.ackFocus();
    await flush();

    expect(engine.pulls[1].folder).toBe(FOLDER);
  });
});

describe('a manual refresh', () => {
  it('resolves nocache, then re-pulls the focused folder', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);

    store.refresh();
    await flush();

    expect(engine.refreshes()).toBe(1);
    expect(engine.pulls).toHaveLength(1);
    const refreshed = view();
    engine.pulls[0].resolve(refreshed);
    await flush();
    expect(store.getSnapshot().view).toBe(refreshed);
  });

  it('still pulls, and keeps the listing, when the engine refuses the refresh', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    engine.emit({ kind: 'snapshotUpdated' });
    const listed = view(ROOT_ID, 'fresh', 2);
    engine.pulls[0].resolve(listed);
    await flush();

    // A refused hint is a verdict on the hint, never on the listing.
    engine.refuseRefresh(new EngineRequestError('not implemented yet', 'unimplemented'));
    store.refresh();
    await flush();

    expect(engine.pulls).toHaveLength(2);
    expect(store.getSnapshot()).toEqual({ view: listed, error: null });
  });

  it('clears a failure the retry cleared', async () => {
    const engine = fakeEngine();
    const store = createSnapshotStore(engine.client);
    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[0].reject(new EngineRequestError('at the ceiling', 'tooManyStreams'));
    await flush();
    expect(store.getSnapshot().error).toEqual({
      message: 'at the ceiling',
      code: 'tooManyStreams',
    });

    store.refresh();
    await flush();
    engine.pulls[1].resolve(view());
    await flush();

    expect(store.getSnapshot().error).toBeNull();
  });
});

describe('failure classification', () => {
  it('treats the stream ceiling as recoverable', () => {
    expect(isRecoverable({ message: 'ceiling', code: 'tooManyStreams' })).toBe(true);
  });

  it('fails closed on anything it does not name', () => {
    // A verdict, an unmapped future engine code, and a codeless transport fault
    // all read as fatal rather than as something a retry would clear.
    expect(isRecoverable({ message: 'refused', code: 'trustViolation' })).toBe(false);
    expect(isRecoverable({ message: 'gone', code: 'unknownNode' })).toBe(false);
    expect(isRecoverable({ message: 'new', code: 'someFutureCeiling' })).toBe(false);
    expect(isRecoverable({ message: 'no room', code: 'overBudget' })).toBe(false);
    expect(isRecoverable({ message: 'worker died' })).toBe(false);
  });
});
