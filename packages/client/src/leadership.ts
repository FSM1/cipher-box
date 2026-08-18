/**
 * Tab-leadership election over the Web Locks API (blueprint/web-client.md
 * "Engine hosting and tab leadership"). The invariant is #28 D4: **one engine
 * writer per origin**. Every tab requests the same exclusive lock
 * (`cipherbox-engine`); the browser grants it to exactly one holder — the
 * leader. The rest queue as followers.
 *
 * Web Locks auto-release on tab close, crash, or discard, so the release itself
 * is the failover primitive — no heartbeat, no liveness poll. When the leader's
 * lock releases (for any reason), the browser hands it to the next queued tab,
 * which becomes the new leader.
 */

/** A granted lock handle (the fields we read of a real `Lock`). */
export interface LockGrant {
  readonly name: string;
}

/** The callback a lock request runs while it holds the lock. */
export type LockRequestCallback = (lock: LockGrant | null) => Promise<unknown>;

/** The subset of `navigator.locks` the election drives (injectable for tests). */
export interface LockManagerLike {
  request(
    name: string,
    options: { signal?: AbortSignal; mode?: 'exclusive' },
    callback: LockRequestCallback
  ): Promise<unknown>;
}

/** What `query()` reports; only the names are read. */
export interface LockStateLike {
  readonly held?: readonly { readonly name?: string }[];
}

/**
 * The manager plus the origin-wide read. Read-only, so it answers who holds a
 * presence name without queueing behind the watch already waiting on it — which
 * is what lets the leader relay tell a live follower from a departed one.
 */
export interface LockReaderLike extends LockManagerLike {
  query(): Promise<LockStateLike>;
}

/** Election lifecycle: a tab is a follower until it acquires the lock. */
export type ElectionRole = 'follower' | 'leader' | 'closed';

/**
 * Requests the engine lock once and holds it for the tab's lifetime. `onAcquire`
 * fires when this tab becomes the leader; the lock is then held until `close()`
 * relinquishes it (logout) or the tab dies (the browser releases it), at which
 * point some other tab's queued request wins.
 */
export class LeaderElection {
  private state: ElectionRole = 'follower';
  private releaseHeld: (() => void) | null = null;
  private readonly controller = new AbortController();
  private readonly settled: Promise<unknown>;

  constructor(
    private readonly locks: LockManagerLike,
    private readonly lockName: string,
    private readonly onAcquire: () => void,
    private readonly onError?: (error: Error) => void
  ) {
    this.settled = this.elect();
  }

  get role(): ElectionRole {
    return this.state;
  }

  private elect(): Promise<unknown> {
    return this.locks
      .request(this.lockName, { signal: this.controller.signal, mode: 'exclusive' }, () => {
        // Acquired. If close() already ran while we were queued, drop it
        // immediately so a live follower can take the lock instead.
        if (this.state === 'closed') return Promise.resolve();
        this.state = 'leader';
        this.onAcquire();
        // Hold the lock until close() resolves this. Returning a pending promise
        // keeps the Web Lock held; resolving it releases the lock cleanly.
        return new Promise<void>((resolve) => {
          this.releaseHeld = resolve;
        });
      })
      .catch((error: unknown) => {
        // Aborting a still-queued follower request is the normal close path, not
        // a failure to report.
        if (this.controller.signal.aborted) return;
        this.onError?.(error instanceof Error ? error : new Error(String(error)));
      });
  }

  /**
   * Relinquishes leadership (or cancels a queued follower request). Returns when
   * the underlying lock request has fully settled, so the caller can sequence a
   * clean handoff.
   */
  async close(): Promise<void> {
    if (this.state === 'closed') return;
    this.state = 'closed';
    if (this.releaseHeld) {
      // We hold the lock: release it so the next queued tab is elected.
      this.releaseHeld();
      this.releaseHeld = null;
    } else {
      // Still queued: abort the pending request.
      this.controller.abort();
    }
    await this.settled.catch(() => undefined);
  }
}
