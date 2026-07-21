/**
 * `RefreshHintSource` — a queue of host events that force an immediate sync tick
 * (blueprint/web-client.md seam table).
 *
 * The host pushes a hint on UI navigation, `visibilitychange` regain, `online`
 * reconnect, or a cross-tab focus signal; the engine awaits `nextHint`. Hints
 * carry no payload (v2.0) and are best-effort accelerators — a dropped hint
 * costs staleness bounded by the poll cadence, never correctness.
 */

import type { RefreshHintSourceSeam } from './types.js';

export class QueueRefreshHintSource implements RefreshHintSourceSeam {
  private pending = 0;
  private waiters: Array<(hint: true | null) => void> = [];
  private closed = false;

  /** Signals one refresh hint (coalesced only by the engine, never dropped here). */
  pushHint(): void {
    if (this.closed) return;
    const waiter = this.waiters.shift();
    if (waiter) waiter(true);
    else this.pending += 1;
  }

  /** Closes the source for good; the engine stops listening. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    const waiters = this.waiters;
    this.waiters = [];
    for (const waiter of waiters) waiter(null);
  }

  nextHint(): Promise<true | null> {
    if (this.pending > 0) {
      this.pending -= 1;
      return Promise.resolve(true);
    }
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push(resolve));
  }
}
