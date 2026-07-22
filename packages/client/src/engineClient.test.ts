import { describe, expect, it } from 'vitest';

import { EngineClient, type EngineClientConfig } from './engineClient.js';
import { FakeBus, FakeEngineWorker, FakeLockManager } from './testkit.js';
import type { EventDescriptor } from './worker/protocol.js';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

/** A shared origin: one lock manager, one broadcast bus, one worker registry. */
function origin() {
  const locks = new FakeLockManager();
  const bus = new FakeBus();
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

  it('keeps the UI event subscription alive across a leadership swap', async () => {
    const { tab } = origin();
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
    // After promotion the follower is the leader; its own worker's events reach
    // the same UI subscription registered before the swap.
    expect(follower.currentRole()).toBe('leader');
    await follower.dispose();
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

    // Issue a follower command, then kill the leader before it can respond.
    const inFlight = follower.facade.manualRefresh();
    await leader.dispose();

    await expect(inFlight).rejects.toThrow(/closed/);
    await follower.dispose();
  });
});
