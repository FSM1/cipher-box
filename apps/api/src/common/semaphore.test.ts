import { describe, expect, it } from 'vitest';
import { Semaphore } from './semaphore';

const flush = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

describe('Semaphore', () => {
  it('never lets more than `permits` bodies run at once', async () => {
    const permits = 3;
    const total = 10;
    const sem = new Semaphore(permits);
    let running = 0;
    let peak = 0;
    let completed = 0;
    const gates: Array<() => void> = [];

    const tasks = Array.from({ length: total }, () =>
      sem.run(async () => {
        running += 1;
        peak = Math.max(peak, running);
        await new Promise<void>((resolve) => gates.push(resolve));
        running -= 1;
        completed += 1;
      })
    );

    // Let the event loop settle, assert the ceiling holds, then release one
    // holder so a queued waiter is admitted — repeat until all have run.
    while (completed < total) {
      await flush();
      expect(running).toBeLessThanOrEqual(permits);
      expect(gates.length).toBeLessThanOrEqual(permits);
      gates.shift()?.();
    }

    await Promise.all(tasks);
    expect(peak).toBe(permits);
  });

  it('admits waiters in FIFO order as permits free up', async () => {
    const sem = new Semaphore(1);
    const order: number[] = [];
    const gates: Array<() => void> = [];

    const run = (id: number): Promise<void> =>
      sem.run(async () => {
        order.push(id);
        await new Promise<void>((resolve) => gates.push(resolve));
      });

    const tasks = [run(1), run(2), run(3)];
    await flush();

    // Release the holder; the next queued waiter is admitted, in order.
    while (gates.length > 0) {
      gates.shift()!();
      await flush();
    }
    await Promise.all(tasks);
    expect(order).toEqual([1, 2, 3]);
  });

  it('releases the permit even when the body throws', async () => {
    const sem = new Semaphore(1);
    await expect(
      sem.run(async () => {
        throw new Error('boom');
      })
    ).rejects.toThrow('boom');

    // A later caller still acquires — the permit was not leaked.
    await expect(sem.run(async () => 'ok')).resolves.toBe('ok');
  });

  it('floors a non-positive permit count to 1', async () => {
    const sem = new Semaphore(0);
    let running = 0;
    let peak = 0;
    const gates: Array<() => void> = [];

    const tasks = [0, 1].map(() =>
      sem.run(async () => {
        running += 1;
        peak = Math.max(peak, running);
        await new Promise<void>((resolve) => gates.push(resolve));
        running -= 1;
      })
    );

    await flush();
    while (gates.length > 0) {
      gates.shift()!();
      await flush();
    }
    await Promise.all(tasks);
    expect(peak).toBe(1);
  });
});
