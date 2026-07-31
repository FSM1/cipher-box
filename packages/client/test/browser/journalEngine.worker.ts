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
import type { EngineHostLike } from '../../src/worker/engineHost.js';
import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
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

class JournalHost implements EngineHostLike {
  private nextHandle = 1n;
  // Op ids are a separate id space from write handles; keep them disjoint so a
  // client that conflates the two cannot pass against this fake.
  private nextOpId = 1000n;
  private readonly open = new Map<bigint, { size: number; received: number }>();

  start(): Promise<void> {
    return Promise.resolve();
  }

  async command(command: CommandDescriptor): Promise<void> {
    // Durable journal BEFORE the ack: the resolved promise is the UI-visible
    // ack, and it only settles once the op is on disk.
    if (command.kind !== 'manualRefresh' && command.kind !== 'setFocus') {
      await journal(command.kind);
    }
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
    return this.nextOpId++;
  }

  abortWrite(handle: bigint): Promise<void> {
    this.open.delete(handle);
    return Promise.resolve();
  }

  snapshot(): Promise<SnapshotDescriptor> {
    return Promise.reject(new Error('journal host serves no snapshots'));
  }

  download(): Promise<ArrayBuffer> {
    return Promise.reject(new Error('journal host serves no downloads'));
  }

  nextEvent(): Promise<EventDescriptor | null> {
    // No engine events in this fake; park the pump forever.
    return new Promise<EventDescriptor | null>(() => undefined);
  }
}

serveEngine(self as unknown as WorkerScopeLike, new JournalHost());
