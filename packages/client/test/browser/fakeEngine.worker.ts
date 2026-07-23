/**
 * A protocol-speaking fake engine host (no WASM), driven through the real
 * `serveEngine` server and the real `LocalTransport`. It exists to exercise two
 * properties the real engine cannot yet drive deterministically: out-of-order
 * response correlation, and ordered/no-drop event delivery.
 *
 * - Any command answers after a delay that shrinks with each call, so the
 *   second command's response arrives before the first's.
 * - `manualRefresh` emits ten ordered `deadLetter` events (op ids 1..10) that
 *   the single event pump streams in order.
 */
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import type { EngineHostLike } from '../../src/worker/engineHost.js';
import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
} from '../../src/worker/protocol.js';

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

class FakeHost implements EngineHostLike {
  private commandCount = 0;
  private queued: EventDescriptor[] = [];
  private waiters: Array<(event: EventDescriptor | null) => void> = [];
  private closed = false;

  start(): Promise<void> {
    return Promise.resolve();
  }

  async command(descriptor: CommandDescriptor): Promise<void> {
    this.commandCount += 1;
    if (descriptor.kind === 'manualRefresh') {
      for (let opId = 1n; opId <= 10n; opId += 1n) this.pushEvent({ kind: 'deadLetter', opId });
      return;
    }
    // First call is slow, later calls fast → responses arrive out of order.
    await sleep(this.commandCount === 1 ? 40 : 5);
  }

  snapshot(): Promise<SnapshotDescriptor> {
    return Promise.reject(new Error('fake host serves no snapshots'));
  }

  download(): Promise<ArrayBuffer> {
    return Promise.reject(new Error('fake host serves no downloads'));
  }

  nextEvent(): Promise<EventDescriptor | null> {
    const next = this.queued.shift();
    if (next) return Promise.resolve(next);
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  private pushEvent(event: EventDescriptor): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter(event);
    else this.queued.push(event);
  }
}

serveEngine(self as unknown as WorkerScopeLike, new FakeHost());
