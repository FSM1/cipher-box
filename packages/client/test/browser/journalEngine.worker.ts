/**
 * A protocol-speaking engine worker (no WASM) for the leadership browser suite.
 * It stands in for the real engine to exercise leadership, the broadcast relay,
 * and failover against real Web Locks and a real BroadcastChannel.
 *
 * The one behavior that matters for the failover gate: every write command is
 * **journaled durably to IndexedDB before it is acked** (the doctrine's
 * ack-after-journal ordering, blueprint/web-client.md "Failover"). Because the
 * journal is origin-shared, a fresh worker spawned by a promoted follower sees
 * every op the dead leader had already accepted — no accepted work is lost.
 */
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import { StubEngineHost } from '../../src/testkit.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  EventDescriptor,
  WriteTarget,
} from '../../src/worker/protocol.js';

const DB_NAME = 'cb-leadership-journal';
const STORE = 'ops';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE, { autoIncrement: true });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('idb open failed'));
  });
}

async function journal(kind: string): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).add({ kind, at: Date.now() });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('journal write failed'));
    });
  } finally {
    db.close();
  }
}

class JournalHost extends StubEngineHost {
  private readonly queued: EventDescriptor[] = [];
  private readonly waiters: Array<(event: EventDescriptor) => void> = [];
  private nextHandle = 1n;
  // Op ids are a separate id space from write handles; keep them disjoint so a
  // client that conflates the two cannot pass against this fake.
  private nextOpId = 1000n;
  private readonly open = new Map<bigint, { size: number; received: number }>();

  start(): Promise<void> {
    return Promise.resolve();
  }

  async command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    // Durable journal BEFORE the ack: the resolved promise is the UI-visible
    // ack, and it only settles once the op is on disk.
    if (command.kind !== 'manualRefresh' && command.kind !== 'setFocus') {
      await journal(command.kind);
      return { kind: 'queued', opId: this.nextOpId++ };
    }
    return { kind: 'done' };
  }

  beginWrite(_target: WriteTarget, size: number): Promise<bigint> {
    const handle = this.nextHandle++;
    this.open.set(handle, { size, received: 0 });
    return Promise.resolve(handle);
  }

  /** Staged content is never journaled — only the op that commits it is. */
  pushChunk(handle: bigint, chunk: ArrayBuffer): Promise<void> {
    const write = this.open.get(handle);
    if (!write) return Promise.reject(new Error('unknown write handle'));
    write.received += chunk.byteLength;
    return Promise.resolve();
  }

  async commitWrite(handle: bigint): Promise<bigint> {
    const write = this.open.get(handle);
    if (!write) throw new Error('unknown write handle');
    if (write.received !== write.size) throw new Error('content size mismatch');
    this.open.delete(handle);
    await journal('commitWrite');
    const opId = this.nextOpId++;
    // A descriptor carrying the metadata the spec scans every wire for: a node
    // id and a block count, as the real engine reports an upload.
    this.publish({
      kind: 'opProgress',
      opId,
      node: new Uint8Array(16).fill(0xa7),
      phase: 'uploadCompleted',
      blocksConfirmed: 4,
      blocksTotal: 4,
      error: null,
    });
    return opId;
  }

  abortWrite(handle: bigint): Promise<void> {
    this.open.delete(handle);
    return Promise.resolve();
  }

  nextEvent(): Promise<EventDescriptor | null> {
    const next = this.queued.shift();
    if (next) return Promise.resolve(next);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  private publish(event: EventDescriptor): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter(event);
    else this.queued.push(event);
  }
}

serveEngine(self as unknown as WorkerScopeLike, new JournalHost());
