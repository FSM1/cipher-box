import { describe, expect, it, vi } from 'vitest';

import { BROADCAST_CHANNEL_NAME } from './broadcast.js';
import { EngineClient, type EngineClientConfig, type LoginSecret } from './engineClient.js';
import { LeaderRelay } from './leaderRelay.js';
import type { LockManagerLike } from './leadership.js';
import {
  abortError,
  FakeBus,
  FakeCourierNetwork,
  FakeEngineTransport,
  FakeEngineWorker,
  FakeLockManager,
  fakeLoginSecret,
  TEST_ACCOUNT_ID,
} from './testkit.js';
import type { EventDescriptor } from './worker/protocol.js';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * Pins a tab as a follower: the engine lock is never granted, so it is never
 * promoted. The request still settles on abort, so `dispose()` can await its
 * election. Every other name — the tab's presence lock — takes the origin's own
 * manager, which the leader relay watches.
 */
function pinnedFollower(locks: FakeLockManager): LockManagerLike {
  return {
    request: (name, options, callback) =>
      name === BROADCAST_CHANNEL_NAME
        ? new Promise((_resolve, reject) => {
            options.signal?.addEventListener('abort', () => reject(abortError()));
          })
        : locks.request(name, options, callback),
  };
}

/** A shared origin: one lock manager, one broadcast bus, one worker registry. */
function origin() {
  const bus = new FakeBus();
  const locks = bus.locks;
  const ports = new FakeCourierNetwork();
  let tabs = 0;
  const workers: FakeEngineWorker[] = [];
  const spawnWorker = (): FakeEngineWorker => {
    const worker = new FakeEngineWorker();
    workers.push(worker);
    setTimeout(() => worker.ready(), 0);
    return worker;
  };
  const liveWorkers = (): number => workers.filter((w) => !w.terminated).length;

  const tab = (overrides?: Partial<EngineClientConfig>): EngineClient =>
    new EngineClient({
      locks,
      createChannel: () => bus.channel(),
      spawnWorker,
      courier: ports.courier(`tab${(tabs += 1)}`),
      ...overrides,
    });

  return { tab, workers, liveWorkers };
}

/** The origin's engine holds one account, so every tab in a test starts on it. */
const startTab = (client: EngineClient, secret: number[] = [1]): Promise<void> =>
  client.facade.start(Uint8Array.from(secret).buffer, TEST_ACCOUNT_ID);

describe('EngineClient leadership + transport swap', () => {
  it('elects the first tab leader and spawns exactly one worker', async () => {
    const { tab, liveWorkers } = origin();
    const a = tab();
    const b = tab();
    await tick();

    expect(a.currentRole()).toBe('leader');
    expect(b.currentRole()).toBe('follower');
    expect(liveWorkers()).toBe(1); // the single writer per origin
    await a.dispose();
    await b.dispose();
  });

  it('routes a follower command through the broadcast wire to the leader worker', async () => {
    const { tab, workers } = origin();
    const leader = tab();
    const follower = tab();
    await tick();
    await startTab(leader, [1, 2, 3]);
    await startTab(follower, [4]);

    await follower.facade.delete(new Uint8Array(16));
    // The command reached the leader's worker (a `command` request was posted).
    const posted = workers[0].posted.filter((m) => (m as { type?: string }).type === 'command');
    expect(posted.length).toBe(1);
    await leader.dispose();
    await follower.dispose();
  });

  it('never spawns a worker on a follower tab', async () => {
    const { tab, workers } = origin();
    const leader = tab();
    const follower = tab();
    await tick();

    expect(workers.length).toBe(1); // only the leader spawned one
    void leader;
    await follower.dispose();
    await leader.dispose();
  });

  it('fails a follower over to leader on lock release, spawning a fresh worker with a re-derived secret', async () => {
    const { tab, liveWorkers, workers } = origin();
    let secretCalls = 0;
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => {
        secretCalls += 1;
        return Promise.resolve({
          secret: new Uint8Array([7, 7, 7, 7]).buffer,
          accountId: TEST_ACCOUNT_ID,
        });
      },
    };

    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    // The follower is an active session (logged in via the leader).
    await startTab(leader);
    await startTab(follower, [9]);
    expect(follower.currentRole()).toBe('follower');

    // Kill the leader → the follower is promoted.
    await leader.dispose();
    await tick();
    await tick();

    expect(follower.currentRole()).toBe('leader');
    expect(liveWorkers()).toBe(1); // still exactly one writer
    expect(secretCalls).toBe(1); // failover re-derived the secret
    // The fresh worker was cold-started with the re-derived secret.
    const startPosted = workers[workers.length - 1].posted.some(
      (m) => (m as { type?: string }).type === 'start'
    );
    expect(startPosted).toBe(true);
    await follower.dispose();
  });

  it('refuses a stream handle minted by a leadership that has been replaced', async () => {
    const { tab, workers } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret()),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await startTab(leader);
    await startTab(follower, [9]);

    const stale = await follower.openContentStream(new Uint8Array(16).fill(1));

    await leader.dispose();
    await tick();
    await tick();
    expect(follower.currentRole()).toBe('leader');

    // The promoted tab's engine mints from 1 too, so a carried-over handle would
    // alias the next stream it opens (`EngineClient.streams`).
    const reopened = await follower.openContentStream(new Uint8Array(16).fill(2));
    expect(reopened).not.toBe(stale);
    await follower.readStream(reopened, 0, 8);
    const promoted = workers[workers.length - 1];
    expect(promoted.posted).toContainEqual(
      expect.objectContaining({ type: 'readStream', handle: 1n, offset: 0, length: 8 })
    );

    await expect(follower.readStream(stale, 0, 8)).rejects.toMatchObject({
      code: 'unknownStreamHandle',
    });

    await follower.dispose();
  });

  it('moves an upload chunk into the leader worker rather than copying it', async () => {
    const { tab, workers } = origin();
    const leader = tab();
    await tick();
    await startTab(leader);

    const handle = await leader.beginWrite({ node: new Uint8Array(16) }, 4);
    const chunk = Uint8Array.of(9, 9, 9, 9).buffer;
    await leader.pushChunk(handle, chunk);

    // Transferred, not cloned: the plaintext leaves this realm's heap for the
    // worker's instead of lingering in both.
    expect(chunk.byteLength).toBe(0);
    expect(workers[0].posted).toContainEqual(expect.objectContaining({ type: 'pushChunk' }));

    await leader.dispose();
  });

  it('scrubs the login secret a closed client refuses', async () => {
    const { tab } = origin();
    const client = tab();
    await client.dispose();
    const secret = Uint8Array.of(1, 2, 3, 4);

    await expect(client.start(secret.buffer as ArrayBuffer, TEST_ACCOUNT_ID)).rejects.toThrow(
      'closed'
    );

    expect(secret).toEqual(new Uint8Array(4));
  });

  it('refuses a write handle minted by a leadership that has been replaced', async () => {
    const { tab, workers } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret()),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await startTab(leader);
    await startTab(follower, [9]);

    const stale = await follower.beginWrite({ node: new Uint8Array(16).fill(1) }, 4);

    await leader.dispose();
    await tick();
    await tick();
    expect(follower.currentRole()).toBe('leader');

    // The promoted tab's engine mints from 1 too, so a carried-over handle would
    // alias the next write it opens — pushing one file's bytes into another
    // file's staging, where they seal correctly and nothing downstream notices.
    const reopened = await follower.beginWrite({ parent: new Uint8Array(16), name: 'b.txt' }, 4);
    expect(reopened).not.toBe(stale);
    await follower.pushChunk(reopened, Uint8Array.of(1, 2, 3, 4).buffer);
    const promoted = workers[workers.length - 1];
    expect(promoted.posted).toContainEqual(
      expect.objectContaining({ type: 'pushChunk', handle: 1n })
    );

    const refused = Uint8Array.of(9, 9, 9, 9);
    await expect(follower.pushChunk(stale, refused.buffer as ArrayBuffer)).rejects.toMatchObject({
      code: 'unknownWriteHandle',
    });
    expect(refused).toEqual(new Uint8Array(4));
    await expect(follower.commitWrite(stale)).rejects.toMatchObject({
      code: 'unknownWriteHandle',
    });
    // Only the live handle's chunk ever reached the promoted worker.
    expect(
      promoted.posted.filter((m) => (m as { type?: string }).type === 'pushChunk')
    ).toHaveLength(1);

    await follower.dispose();
  });

  it('keeps the UI event subscription alive across a leadership swap', async () => {
    const { tab, workers } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret()),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await startTab(leader);
    await startTab(follower, [2]);

    const received: EventDescriptor[] = [];
    follower.facade.subscribe((event) => received.push(event));

    await leader.dispose();
    await tick();
    await tick();
    expect(follower.currentRole()).toBe('leader');

    // The subscription registered *before* the swap must still be live: an event
    // emitted by the promoted tab's own worker reaches it. A swap that dropped
    // the subscription would leave `received` empty and fail here.
    const promoted = workers[workers.length - 1];
    promoted.emit({ type: 'event', event: { kind: 'snapshotUpdated' } });
    await tick();
    expect(received).toContainEqual({ kind: 'snapshotUpdated' });

    await follower.dispose();
  });

  it('scrubs the secret at the client seam and hands none to the keyless follower transport (P1-1)', async () => {
    const { tab } = origin();
    const leader = tab();
    const follower = tab();
    await tick();
    expect(follower.currentRole()).toBe('follower');
    await startTab(leader);

    // The follower holds no keys: the EngineClient (the secret's terminal owner)
    // scrubs the buffer it decided not to use, and the BroadcastTransport — a
    // callee — never receives its bytes.
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
    await follower.facade.start(secret, TEST_ACCOUNT_ID);
    expect([...new Uint8Array(secret)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);

    await leader.dispose();
    await follower.dispose();
  });

  it('zeroes the re-derived failover secret when the promoted worker never starts', async () => {
    const { tab } = origin();
    const secret = new Uint8Array([7, 7, 7, 7]).buffer;
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> =>
        Promise.resolve({ secret, accountId: TEST_ACCOUNT_ID }),
    };
    const errors: Error[] = [];

    const leader = tab();
    const follower = tab({
      secretSource,
      // The promoted tab's fresh worker dies before it is ready, so `start`
      // rejects without ever posting — the buffer stays attached and this frame
      // remains its terminal owner.
      spawnWorker: (): FakeEngineWorker => {
        const worker = new FakeEngineWorker();
        setTimeout(() => worker.emit({ type: 'fatal', error: 'engine construction failed' }), 0);
        return worker;
      },
      onError: (error) => errors.push(error),
    });
    await tick();
    await startTab(leader);
    await startTab(follower, [9]);

    await leader.dispose();
    await tick();
    await tick();
    await tick();

    expect(errors.map((error) => error.message)).toContain('engine construction failed');
    expect(secret.byteLength).toBe(4); // never transferred
    expect([...new Uint8Array(secret)]).toEqual([0, 0, 0, 0]);

    await follower.dispose();
  });

  it('does not advertise leadership or start the worker until the cold-start secret resolves (P1-2)', async () => {
    const { tab, workers } = origin();
    let releaseSecret!: () => void;
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> =>
        new Promise<LoginSecret>((resolve) => {
          releaseSecret = () => resolve(fakeLoginSecret());
        }),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await startTab(leader);
    await startTab(follower, [2]);

    // Promote the follower, but stall it on the pending re-derived secret.
    await leader.dispose();
    await tick();
    await tick();

    // Promotion has spawned the fresh worker but is stalled on the secret.
    expect(workers.length).toBe(2);
    const promoted = workers[workers.length - 1];
    // Leadership is not yet advertised and the worker has not been cold-started:
    // a command in this window cannot reach an uninitialized worker.
    expect(follower.currentRole()).not.toBe('leader');
    expect(promoted.posted.some((m) => (m as { type?: string }).type === 'start')).toBe(false);

    // The secret resolves → the worker cold-starts → only now is leadership live.
    releaseSecret();
    await tick();
    await tick();
    expect(follower.currentRole()).toBe('leader');
    expect(promoted.posted.some((m) => (m as { type?: string }).type === 'start')).toBe(true);

    await follower.dispose();
  });

  it('releases the election lock and surfaces onError when the worker spawn throws synchronously (P1-5)', async () => {
    const { tab } = origin();
    const errors: Error[] = [];
    const spawnFailure = new Error('worker spawn failed');

    // This tab wins the lock first but its worker spawn throws synchronously
    // during promotion: it must not sit on a dead-leader lock. It releases the
    // lock, falls back to a follower, and surfaces the fault via onError.
    const doomed = tab({
      spawnWorker: (): never => {
        throw spawnFailure;
      },
      onError: (error) => errors.push(error),
    });
    const healthy = tab();
    await tick();
    await tick();

    expect(doomed.currentRole()).not.toBe('leader');
    expect(errors).toContain(spawnFailure);
    // The released lock was handed to the healthy tab, proving it was never held
    // by the doomed leader after the throw.
    expect(healthy.currentRole()).toBe('leader');

    await doomed.dispose();
    await healthy.dispose();
  });

  it('rejects a command in flight at a leadership swap so the UI can retry', async () => {
    const { tab } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret()),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await startTab(leader);
    await startTab(follower, [2]);

    // Issue a follower command, then kill the leader before it can respond. The
    // command rejects retryably (the leader stepped down / the transport closed)
    // so the UI retries against the new leader instead of hanging forever.
    const inFlight = follower.facade.manualRefresh();
    await leader.dispose();

    await expect(inFlight).rejects.toThrow(/retry|closed/);
    await follower.dispose();
  });

  it('reports the origin storage-persistence grant to the host, follower tabs included', async () => {
    vi.stubGlobal('navigator', {
      storage: { persisted: () => Promise.resolve(false), persist: () => Promise.resolve(true) },
    });
    const { tab } = origin();
    const seen: boolean[] = [];
    const leader = tab({ onStoragePersistence: (persisted) => seen.push(persisted) });
    const follower = tab({ onStoragePersistence: (persisted) => seen.push(persisted) });
    await tick();

    expect(leader.currentRole()).toBe('leader');
    expect(follower.currentRole()).toBe('follower');
    expect(seen).toEqual([true, true]);
    await leader.dispose();
    await follower.dispose();
    vi.unstubAllGlobals();
  });

  it('routes a throwing storage-persistence callback to onError, not an unhandled rejection', async () => {
    vi.stubGlobal('navigator', { storage: { persist: () => Promise.resolve(true) } });
    const { tab } = origin();
    const errors: Error[] = [];
    const client = tab({
      onStoragePersistence: () => {
        throw new Error('host blew up');
      },
      onError: (error) => errors.push(error),
    });
    await tick();

    expect(errors.map((error) => error.message)).toEqual(['host blew up']);
    await client.dispose();
    vi.unstubAllGlobals();
  });

  it('publishes the account the engine holds, and clears it when the client goes', async () => {
    const { tab } = origin();
    const client = tab();
    const changes: Array<string | null> = [];
    client.subscribeSession(() => changes.push(client.signedInAccount()));
    await tick();

    // Nothing is signed in until an engine has answered a start for it.
    expect(client.signedInAccount()).toBeNull();
    await startTab(client);
    expect(client.signedInAccount()).toBe(TEST_ACCOUNT_ID);

    await client.dispose();

    expect(client.signedInAccount()).toBeNull();
    expect(changes).toEqual([TEST_ACCOUNT_ID, null]);
  });

  it('drops the session when a promotion cannot cold-start the engine it hosts', async () => {
    const { tab } = origin();
    const errors: Error[] = [];
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.reject(new Error('no session to export')),
    };
    const leader = tab();
    const follower = tab({ secretSource, onError: (error) => errors.push(error) });
    await tick();
    await startTab(leader);
    await startTab(follower, [9]);
    expect(follower.signedInAccount()).toBe(TEST_ACCOUNT_ID);

    // The leader goes; this tab wins the lock but cannot re-derive its keys, so
    // the engine its UI was rendering over no longer exists anywhere.
    await leader.dispose();
    await tick();
    await tick();

    expect(follower.signedInAccount()).toBeNull();
    expect(errors.map((error) => error.message)).toEqual(['no session to export']);
    await follower.dispose();
  });

  it('gives the lock up when a tab with a session greets an engine-less leader', async () => {
    const { tab, liveWorkers } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret([5])),
    };
    // The lock winner never signs in — a stale front-door tab, or one that just
    // logged out — so it holds no keys to serve anyone with.
    const idle = tab();
    const signingIn = tab({ secretSource });
    await tick();
    expect(idle.currentRole()).toBe('leader');

    await startTab(signingIn);

    // The sign-in lands rather than being refused: the engine-less leader stood
    // down and this tab cold-started the origin's engine itself.
    expect(signingIn.currentRole()).toBe('leader');
    expect(signingIn.signedInAccount()).toBe(TEST_ACCOUNT_ID);
    expect(idle.currentRole()).toBe('follower');
    expect(idle.signedInAccount()).toBeNull();
    expect(liveWorkers()).toBe(1); // still exactly one writer per origin

    await signingIn.dispose();
    await idle.dispose();
  });

  it('signs a second tab in on the engine the first one won the lock and started', async () => {
    const { tab, liveWorkers } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret([5])),
    };
    const idle = tab();
    const first = tab({ secretSource });
    const second = tab({ secretSource });
    await tick();
    expect(idle.currentRole()).toBe('leader');

    // Both greet the engine-less leader, which stands down once — so only one
    // of them is promoted. The other is served by it, and a start that resolves
    // is the proof: the wait for an engine rejects, it never resolves.
    await Promise.all([startTab(first), startTab(second)]);

    expect([first.currentRole(), second.currentRole()].sort()).toEqual(['follower', 'leader']);
    expect(first.signedInAccount()).toBe(TEST_ACCOUNT_ID);
    expect(second.signedInAccount()).toBe(TEST_ACCOUNT_ID);
    expect(liveWorkers()).toBe(1);

    await first.dispose();
    await second.dispose();
    await idle.dispose();
  });

  it('lets its own cold start outrun the wait for a leader to step aside', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { tab } = origin();
      let release!: (secret: LoginSecret) => void;
      const secretSource = {
        provideSecret: (): Promise<LoginSecret> =>
          new Promise<LoginSecret>((resolve) => (release = resolve)),
      };
      const idle = tab();
      const signingIn = tab({ secretSource });
      await tick();

      const started = startTab(signingIn);
      // The engine-less leader has stood down and this tab is opening the engine
      // its own start waits for; a cold start is network-bound work, so the
      // hand-off deadline no longer applies to it.
      for (let i = 0; i < 20 && release === undefined; i += 1) await tick();
      expect(release).toBeTypeOf('function');
      await vi.advanceTimersByTimeAsync(60_000);
      release(fakeLoginSecret([5]));

      // A rejection here would tell the login flow to end a Core Kit session the
      // engine coming up behind it is about to serve.
      await expect(started).resolves.toBeUndefined();
      expect(signingIn.signedInAccount()).toBe(TEST_ACCOUNT_ID);

      await signingIn.dispose();
      await idle.dispose();
    } finally {
      vi.useRealTimers();
    }
  });

  it('hosts again after standing down, once the tab it stepped aside for goes', async () => {
    const { tab } = origin();
    const secretSource = {
      provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret([5])),
    };
    const idle = tab();
    const signingIn = tab({ secretSource });
    await tick();
    await startTab(signingIn);
    expect(idle.currentRole()).toBe('follower');

    // Standing down re-queues rather than retiring: a member who signs in here
    // next has a tab that can still host the origin's engine.
    await signingIn.dispose();
    await tick();
    await tick();

    expect(idle.currentRole()).toBe('leader');
    await idle.dispose();
  });

  it('stops asking leaders to step aside once its sign-in has given up', async () => {
    const { tab, workers } = origin();
    const errors: Error[] = [];
    const host = tab();
    // Signed in through the host, but unable to host itself: when the host goes,
    // its promotion aborts, which retires it from the election for good.
    const stranded = tab({
      secretSource: {
        provideSecret: (): Promise<LoginSecret> => Promise.reject(new Error('no session')),
      },
      onError: (error) => errors.push(error),
    });
    await tick();
    await startTab(host);
    await startTab(stranded, [9]);

    await host.dispose();
    for (let i = 0; i < 6; i += 1) await tick();
    expect(errors).toHaveLength(1);
    expect(stranded.signedInAccount()).toBeNull();

    const idle = tab();
    for (let i = 0; i < 6; i += 1) await tick();
    expect(idle.currentRole()).toBe('leader');
    const spawned = workers.length;

    await expect(startTab(stranded)).rejects.toThrow();
    for (let i = 0; i < 20; i += 1) await tick();

    // Without this the tab greets every new leadership under an account nothing
    // here holds, each stands down and is elected again, and the origin churns
    // a fresh engine worker per cycle for as long as both tabs are open.
    expect(workers.length).toBeLessThanOrEqual(spawned + 1);
    expect(idle.currentRole()).toBe('leader');

    await stranded.dispose();
    await idle.dispose();
  });

  it('holds the lock steady between two tabs that have no session to host', async () => {
    const { tab } = origin();
    const a = tab();
    const b = tab();
    await tick();
    const leader = a.currentRole() === 'leader' ? a : b;

    // Only a greeting that names an account asks a leader to stand down, and a
    // tab with no session never sends one — so two engine-less tabs have no way
    // to pass the lock back and forth between them.
    for (let i = 0; i < 10; i += 1) await tick();

    expect(leader.currentRole()).toBe('leader');
    expect((leader === a ? b : a).currentRole()).toBe('follower');
    await a.dispose();
    await b.dispose();
  });

  it('keeps a refusal that names another account, engine-less or not', async () => {
    const { tab } = origin();
    const leader = tab();
    const other = tab({
      secretSource: {
        provideSecret: (): Promise<LoginSecret> => Promise.resolve(fakeLoginSecret()),
      },
    });
    await tick();
    await startTab(leader);

    // The origin's engine holds someone else's vault: no step-aside, no wait —
    // the tab is told where the engine went so it can say so.
    await expect(other.facade.start(new ArrayBuffer(0), 'acct02')).rejects.toMatchObject({
      name: 'EngineHeldElsewhereError',
      heldBy: TEST_ACCOUNT_ID,
    });
    expect(leader.currentRole()).toBe('leader');
    expect(other.signedInAccount()).toBeNull();

    await leader.dispose();
    await other.dispose();
  });

  it('refuses a stream handle across a leader change while this tab stays a follower', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engineA = new FakeEngineTransport();
    const relayA = new LeaderRelay(bus.channel(), engineA, ports.courier('leaderA'), bus.locks);
    const follower = new EngineClient({
      locks: pinnedFollower(bus.locks),
      createChannel: () => bus.channel(),
      spawnWorker: () => {
        throw new Error('follower never spawns');
      },
      courier: ports.courier('f'),
      clientId: 'f',
    });
    await tick();

    const stale = await follower.openContentStream(new Uint8Array(16).fill(1));
    relayA.close();
    await tick();

    const engineB = new FakeEngineTransport();
    const relayB = new LeaderRelay(bus.channel(), engineB, ports.courier('leaderB'), bus.locks);
    for (let i = 0; i < 4; i += 1) await tick();
    expect(follower.currentRole()).toBe('follower');

    // The fence has to fire on a leadership this tab merely observed, not only
    // on one it was promoted through (`EngineClient.streams`).
    const fresh = await follower.openContentStream(new Uint8Array(16).fill(2));
    const window_ = await follower.readStream(fresh, 0, 8);
    expect(window_.byteLength).toBe(8);
    expect(engineB.reads).toEqual([{ handle: 1n, offset: 0, length: 8 }]);

    await expect(follower.readStream(stale, 0, 8)).rejects.toMatchObject({
      code: 'unknownStreamHandle',
    });
    // The refused stale read never reached the replacement engine.
    expect(engineB.reads).toHaveLength(1);

    await follower.dispose();
    relayB.close();
  });
});
