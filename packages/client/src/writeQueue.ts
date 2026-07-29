/**
 * Per-handle serialization for streaming writes. The engine appends a version's
 * chunks in arrival order, so two `pushChunk`s in flight for one handle must not
 * race: an out-of-order apply scrambles the plaintext while every integrity
 * check still passes (declared size, leaf CIDs, manifest) — silent corruption
 * with no signal. Distinct handles never queue behind each other.
 *
 * Ordering is by call order, so callers must enqueue synchronously on message
 * arrival, before any `await`.
 */

import type { WriteHandle } from './worker/protocol.js';

export class WriteQueue {
  private readonly chains = new Map<WriteHandle, Promise<void>>();

  /** Runs `step` after everything already queued for `handle`. */
  run<T>(handle: WriteHandle, step: () => Promise<T>): Promise<T> {
    const previous = this.chains.get(handle) ?? Promise.resolve();
    // A rejected step must not stall the handle's remaining steps.
    const result = previous.then(step, step);
    const chain = result.then(
      () => undefined,
      () => undefined
    );
    this.chains.set(handle, chain);
    // Prune once this handle drains: the map holds live work only.
    void chain.then(() => {
      if (this.chains.get(handle) === chain) this.chains.delete(handle);
    });
    return result;
  }
}
