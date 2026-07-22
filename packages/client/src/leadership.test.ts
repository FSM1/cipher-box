import { describe, expect, it } from 'vitest';

import { LeaderElection } from './leadership.js';
import { FakeLockManager } from './testkit.js';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

describe('LeaderElection', () => {
  it('elects the first requester as leader and queues the rest as followers', async () => {
    const locks = new FakeLockManager();
    const acquired: string[] = [];
    const a = new LeaderElection(locks, 'engine', () => acquired.push('a'));
    const b = new LeaderElection(locks, 'engine', () => acquired.push('b'));
    await tick();

    expect(acquired).toEqual(['a']);
    expect(a.role).toBe('leader');
    expect(b.role).toBe('follower');
  });

  it('hands leadership to a queued follower when the leader releases', async () => {
    const locks = new FakeLockManager();
    const acquired: string[] = [];
    const a = new LeaderElection(locks, 'engine', () => acquired.push('a'));
    const b = new LeaderElection(locks, 'engine', () => acquired.push('b'));
    await tick();
    expect(acquired).toEqual(['a']);

    // The leader dies (lock releases) → the follower is elected.
    await a.close();
    await tick();

    expect(acquired).toEqual(['a', 'b']);
    expect(b.role).toBe('leader');
  });

  it('never runs the acquire callback for a follower cancelled before election', async () => {
    const locks = new FakeLockManager();
    const acquired: string[] = [];
    const a = new LeaderElection(locks, 'engine', () => acquired.push('a'));
    const b = new LeaderElection(locks, 'engine', () => acquired.push('b'));
    await tick();

    // Cancel the queued follower, then the leader releases: b must not be elected.
    await b.close();
    await a.close();
    await tick();

    expect(acquired).toEqual(['a']);
    expect(b.role).toBe('closed');
  });

  it('enforces a single leader across many tabs at once', async () => {
    const locks = new FakeLockManager();
    let liveLeaders = 0;
    let maxConcurrent = 0;
    const tabs = Array.from(
      { length: 5 },
      () =>
        new LeaderElection(locks, 'engine', () => {
          liveLeaders += 1;
          maxConcurrent = Math.max(maxConcurrent, liveLeaders);
        })
    );
    await tick();

    // Roll leadership down the queue; at no point are two leaders live.
    for (const tab of tabs) {
      const leader = tabs.find((t) => t.role === 'leader');
      if (!leader) break;
      liveLeaders -= 1;
      await leader.close();
      await tick();
      void tab;
    }

    expect(maxConcurrent).toBe(1);
  });
});
