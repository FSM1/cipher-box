import { describe, expect, it } from 'vitest';

import { WriteQueue } from './writeQueue.js';

/** A step that settles only when the test releases it, recording its order. */
function gate(log: string[], label: string, outcome: 'resolve' | 'reject' = 'resolve') {
  let release: () => void = () => undefined;
  const gated = new Promise<void>((resolve) => {
    release = resolve;
  });
  const step = async (): Promise<string> => {
    log.push(`start:${label}`);
    await gated;
    log.push(`end:${label}`);
    if (outcome === 'reject') throw new Error(label);
    return label;
  };
  return { step, release: () => release() };
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

describe('WriteQueue', () => {
  it('runs one handle steps in call order without blocking another handle', async () => {
    const log: string[] = [];
    const queue = new WriteQueue();
    const a1 = gate(log, 'a1');
    const a2 = gate(log, 'a2');
    const b1 = gate(log, 'b1');

    const pendingA1 = queue.run(1n, a1.step);
    const pendingA2 = queue.run(1n, a2.step);
    const pendingB1 = queue.run(2n, b1.step);
    await tick();

    // Handle 2 is not stuck behind handle 1's still-running first step.
    expect(log).toEqual(['start:a1', 'start:b1']);

    b1.release();
    await expect(pendingB1).resolves.toBe('b1');
    expect(log).not.toContain('start:a2');

    a1.release();
    await tick();
    a2.release();
    await expect(pendingA1).resolves.toBe('a1');
    await expect(pendingA2).resolves.toBe('a2');
    expect(log).toEqual(['start:a1', 'start:b1', 'end:b1', 'end:a1', 'start:a2', 'end:a2']);
  });

  it('rejects only the failing step and still runs the handle next step', async () => {
    const log: string[] = [];
    const queue = new WriteQueue();
    const failing = gate(log, 'boom', 'reject');
    const next = gate(log, 'after');

    const pendingFailure = queue.run(1n, failing.step);
    const pendingNext = queue.run(1n, next.step);
    await tick();

    failing.release();
    await expect(pendingFailure).rejects.toThrow('boom');
    await tick();
    next.release();

    await expect(pendingNext).resolves.toBe('after');
    expect(log).toEqual(['start:boom', 'end:boom', 'start:after', 'end:after']);
  });
});
