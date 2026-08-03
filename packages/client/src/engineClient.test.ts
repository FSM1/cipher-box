import { describe, expect, it, vi } from 'vitest';

import { EngineClient, type EngineClientConfig } from './engineClient.js';
import { LeaderRelay } from './leaderRelay.js';
import type { LockManagerLike } from './leadership.js';
import {
  FakeBus,
  FakeCourierNetwork,
  FakeEngineTransport,
  FakeEngineWorker,
  FakeLockManager,
} from './testkit.js';
import type { EventDescriptor } from './worker/protocol.js';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * Pins a tab as a follower: the lock is never granted, so it is never promoted.
 * The request still settles on abort, so `dispose()` can await its election.
 */
const neverGrant: LockManagerLike = {
  request: (_name, options) =>
    new Promise((_resolve, reject) => {
      options.signal?.addEventListener('abort', () =>
        reject(new DOMException('aborted', 'AbortError'))
      );
    }),
};

/** A shared origin: one lock manager, one broadcast bus, one worker registry. */
function origin() {
  const locks = new FakeLockManager();
  const bus = new FakeBus();
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
    await leader.facade.start(new Uint8Array([1, 2, 3]).buffer);

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
      provideSecret: (): Promise<ArrayBuffer> => {
        secretCalls += 1;
        return Promise.resolve(new Uint8Array([7, 7, 7, 7]).buffer);
      },
    };

    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    // The follower is an active session (logged in via the leader).
    await follower.facade.start(new Uint8Array([9]).buffer);
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
      provideSecret: (): Promise<ArrayBuffer> => Promise.resolve(new Uint8Array([1]).buffer),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await follower.facade.start(new Uint8Array([9]).buffer);

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

  it('keeps the UI event subscription alive across a leadership swap', async () => {
    const { tab, workers } = origin();
    const secretSource = {
      provideSecret: (): Promise<ArrayBuffer> => Promise.resolve(new Uint8Array([1]).buffer),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await follower.facade.start(new Uint8Array([2]).buffer);

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

    // The follower holds no keys: the EngineClient (the secret's terminal owner)
    // scrubs the buffer it decided not to use, and the BroadcastTransport — a
    // callee — never receives it (its `start` takes no secret argument).
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
    await follower.facade.start(secret);
    expect([...new Uint8Array(secret)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);

    await leader.dispose();
    await follower.dispose();
  });

  it('zeroes the re-derived failover secret when the promoted worker never starts', async () => {
    const { tab } = origin();
    const secret = new Uint8Array([7, 7, 7, 7]).buffer;
    const secretSource = { provideSecret: (): Promise<ArrayBuffer> => Promise.resolve(secret) };
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
    await follower.facade.start(new Uint8Array([9]).buffer);

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
      provideSecret: (): Promise<ArrayBuffer> =>
        new Promise<ArrayBuffer>((resolve) => {
          releaseSecret = () => resolve(new Uint8Array([1]).buffer);
        }),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await follower.facade.start(new Uint8Array([2]).buffer);

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
      provideSecret: (): Promise<ArrayBuffer> => Promise.resolve(new Uint8Array([1]).buffer),
    };
    const leader = tab();
    const follower = tab({ secretSource });
    await tick();
    await follower.facade.start(new Uint8Array([2]).buffer);

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

  it('refuses a stream handle across a leader change while this tab stays a follower', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engineA = new FakeEngineTransport();
    const relayA = new LeaderRelay(bus.channel(), engineA, ports.courier('leaderA'));
    const follower = new EngineClient({
      locks: neverGrant,
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
    const relayB = new LeaderRelay(bus.channel(), engineB, ports.courier('leaderB'));
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
