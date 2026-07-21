/**
 * A minimal FIFO counting semaphore bounding how many `run()` bodies execute
 * concurrently. The content path uses it as an admission ceiling so a burst of
 * uploads cannot each hold a pooled DB connection across the ~30s Kubo pin and
 * starve the shared pool (the connection is held for the pin's whole span; see
 * ContentService). Permits hand off directly to the next waiter on release, so a
 * saturated ceiling applies backpressure in-process instead of exhausting the
 * pool. Per-process, which matches the per-process connection pool it protects.
 */
export class Semaphore {
  private available: number;
  private readonly waiters: Array<() => void> = [];

  constructor(permits: number) {
    this.available = Math.max(1, Math.trunc(permits));
  }

  async run<T>(work: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await work();
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.available > 0) {
      this.available -= 1;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private release(): void {
    const next = this.waiters.shift();
    // Hand the permit straight to the next waiter; only return it to the pool
    // of free permits when no one is waiting.
    if (next) {
      next();
    } else {
      this.available += 1;
    }
  }
}
