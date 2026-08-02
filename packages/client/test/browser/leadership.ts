/**
 * Page harness for the tab-leadership browser suite. Each Playwright page is a
 * real tab in a shared browser context, so `navigator.locks` and
 * `BroadcastChannel` are the real origin-wide primitives — no mocks, no jsdom.
 *
 * The spec opens two pages, drives one `EngineClient` per page through these
 * entry points, and asserts election, the single-writer invariant, and
 * kill-the-leader failover with no accepted-op loss.
 */
import { EngineClient } from '../../src/engineClient.js';
import type { PendingClass } from '../../src/worker/protocol.js';
import { awaitElection } from './election.js';
import { hex, unhex } from './hexUtil.js';

/** The dev server transpiles TS per module, so the worker must be a module worker. */
const SW_SCRIPT = '/sw.ts';

const JOURNAL_DB = 'cb-leadership-journal';
const JOURNAL_STORE = 'ops';

export interface HarnessOptions {
  lockName: string;
  channelName: string;
  /**
   * Which engine worker the leader spawns: the journal fake (default), the real
   * WASM engine, or the fake that serves ranged plaintext.
   */
  worker?: 'journal' | 'engine' | 'media';
}

/** A page.evaluate-safe ranged-read projection; bytes as hex. */
export interface RangeResult {
  bytesHex?: string;
  error?: string;
}

/** One message a second same-origin context saw on the engine channel. */
export interface ObservedMessage {
  type: string;
  /** Every byte the message carries anywhere in its shape, as one hex run. */
  bytesHex: string;
}

/** A page.evaluate-safe download projection; `code` is the engine's stable error code. */
export interface DownloadResult {
  bytes?: number[];
  error?: string;
  code?: string;
}

/** A page.evaluate-safe snapshot projection (bytes as hex, bigints dropped). */
export interface SnapshotResult {
  error?: string;
  rootHex?: string;
  folderHex?: string;
  children?: Array<{
    idHex: string;
    name: string;
    kind: string;
    pending: PendingClass;
    sizeNull: boolean;
    mtimeNull: boolean;
  }>;
  ancestors?: Array<{ idHex: string; name: string }>;
}

declare global {
  interface Window {
    cbCreate(options: HarnessOptions): Promise<void>;
    cbObserve(channelName: string): void;
    cbObserved(): ObservedMessage[];
    cbDownloadRange(offset: number, length: number): Promise<RangeResult>;
    cbRole(): string;
    cbStart(): Promise<string>;
    cbCreateFile(name: string): Promise<string>;
    cbCreateNode(name: string, kind: 'file' | 'folder'): Promise<string>;
    cbSnapshot(folderHex: string): Promise<SnapshotResult>;
    cbDownload(nodeHex: string): Promise<DownloadResult>;
    cbDispose(): Promise<void>;
    cbJournalCount(): Promise<number>;
    cbJournalRecords(): Promise<unknown[]>;
    cbHeldLocks(lockName: string): Promise<number>;
    cbResetJournal(): Promise<void>;
  }
}

let client: EngineClient | null = null;
const observed: ObservedMessage[] = [];

const rootNode = new Uint8Array(16);

/** Every byte anywhere in a message, as one hex run a plaintext search can scan. */
function collectBytes(value: unknown, into: number[] = []): string {
  if (value instanceof ArrayBuffer) into.push(...new Uint8Array(value));
  else if (ArrayBuffer.isView(value)) {
    into.push(...new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  } else if (Array.isArray(value)) for (const entry of value) collectBytes(entry, into);
  else if (value && typeof value === 'object') {
    for (const entry of Object.values(value)) collectBytes(entry, into);
  }
  return hex(Uint8Array.from(into));
}

function settle(error: unknown): string {
  if (error === undefined) return 'ok';
  return error instanceof Error ? error.message : String(error);
}

// A valid secp256k1 identity scalar placeholder (the journal fake ignores it).
const secret = (): ArrayBuffer => new Uint8Array(32).fill(1).buffer;

const WORKER_URLS: Record<NonNullable<HarnessOptions['worker']>, () => URL> = {
  engine: () => new URL('./engine.worker.ts', import.meta.url),
  media: () => new URL('./mediaEngine.worker.ts', import.meta.url),
  journal: () => new URL('./journalEngine.worker.ts', import.meta.url),
};

/** A follower reads over a Service-Worker-brokered port, so every tab needs one. */
async function awaitServiceWorker(): Promise<void> {
  await navigator.serviceWorker.register(SW_SCRIPT, { scope: '/', type: 'module' });
  await navigator.serviceWorker.ready;
  for (
    let attempt = 0;
    attempt < 200 && navigator.serviceWorker.controller === null;
    attempt += 1
  ) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

window.cbCreate = async ({ lockName, channelName, worker }: HarnessOptions): Promise<void> => {
  await awaitServiceWorker();
  const workerUrl = WORKER_URLS[worker ?? 'journal']();
  client = new EngineClient({
    locks: navigator.locks,
    lockName,
    createChannel: () => new BroadcastChannel(channelName),
    spawnWorker: () => new Worker(workerUrl, { type: 'module' }),
    // Failover re-derivation: a real login re-exports this from Core Kit.
    secretSource: { provideSecret: () => Promise.resolve(secret()) },
  });
  await awaitElection(client, lockName);
};

window.cbRole = (): string => client?.currentRole() ?? 'none';

window.cbStart = async (): Promise<string> => {
  try {
    await client!.facade.start(secret());
    return 'ok';
  } catch (error) {
    return settle(error);
  }
};

window.cbCreateFile = async (name: string): Promise<string> => {
  const content = new Uint8Array([1, 2, 3]);
  try {
    const handle = await client!.facade.beginWrite({ parent: rootNode, name }, content.byteLength);
    try {
      await client!.facade.pushChunk(handle, content.buffer);
      await client!.facade.commitWrite(handle);
    } catch (error) {
      // A failed abort must not mask the write failure that triggered it.
      await client!.facade.abortWrite(handle).catch(() => undefined);
      throw error;
    }
    return 'ok';
  } catch (error) {
    return settle(error);
  }
};

window.cbCreateNode = async (name: string, kind: 'file' | 'folder'): Promise<string> => {
  try {
    await client!.facade.create(rootNode, name, kind);
    return 'ok';
  } catch (error) {
    return settle(error);
  }
};

window.cbSnapshot = async (folderHex: string): Promise<SnapshotResult> => {
  try {
    const view = await client!.facade.snapshot(unhex(folderHex));
    return {
      rootHex: hex(view.root),
      folderHex: hex(view.folder),
      children: view.children.map((child) => ({
        idHex: hex(child.id),
        name: child.name,
        kind: child.kind,
        pending: child.pending,
        sizeNull: child.size === null,
        mtimeNull: child.mtime === null,
      })),
      ancestors: view.ancestors.map((ancestor) => ({
        idHex: hex(ancestor.id),
        name: ancestor.name,
      })),
    };
  } catch (error) {
    return { error: settle(error) };
  }
};

window.cbDownloadRange = async (offset: number, length: number): Promise<RangeResult> => {
  try {
    const window_ = await client!.downloadRange(rootNode, offset, length);
    return { bytesHex: hex(new Uint8Array(window_)) };
  } catch (error) {
    return { error: settle(error) };
  }
};

/**
 * Opens the engine channel from a context that drives no engine at all — the
 * same-origin eavesdropper the read port exists to shut out.
 */
window.cbObserve = (channelName: string): void => {
  const channel = new BroadcastChannel(channelName);
  channel.addEventListener('message', (event: MessageEvent) => {
    const message = event.data as { type?: unknown };
    observed.push({
      type: typeof message?.type === 'string' ? message.type : '(untyped)',
      bytesHex: collectBytes(message),
    });
  });
};

window.cbObserved = (): ObservedMessage[] => observed;

window.cbDownload = async (nodeHex: string): Promise<DownloadResult> => {
  try {
    const content = await client!.facade.download(unhex(nodeHex));
    return { bytes: [...new Uint8Array(content)] };
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    return { error: settle(error), code: typeof code === 'string' ? code : undefined };
  }
};

window.cbDispose = async (): Promise<void> => {
  await client?.dispose();
  client = null;
};

window.cbHeldLocks = async (lockName: string): Promise<number> => {
  const state = await navigator.locks.query();
  return (state.held ?? []).filter((lock) => lock.name === lockName).length;
};

function openJournal(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(JOURNAL_DB, 1);
    request.onupgradeneeded = () =>
      request.result.createObjectStore(JOURNAL_STORE, { autoIncrement: true });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('idb open failed'));
  });
}

window.cbJournalCount = async (): Promise<number> => {
  const db = await openJournal();
  try {
    return await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(JOURNAL_STORE, 'readonly');
      const count = tx.objectStore(JOURNAL_STORE).count();
      count.onsuccess = () => resolve(count.result);
      count.onerror = () => reject(count.error ?? new Error('journal count failed'));
    });
  } finally {
    db.close();
  }
};

window.cbJournalRecords = async (): Promise<unknown[]> => {
  const db = await openJournal();
  try {
    return await new Promise<unknown[]>((resolve, reject) => {
      const tx = db.transaction(JOURNAL_STORE, 'readonly');
      const all = tx.objectStore(JOURNAL_STORE).getAll();
      all.onsuccess = () => resolve(all.result);
      all.onerror = () => reject(all.error ?? new Error('journal read failed'));
    });
  } finally {
    db.close();
  }
};

window.cbResetJournal = (): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(JOURNAL_DB);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error('journal delete failed'));
    request.onblocked = () => resolve();
  });

const status = document.getElementById('leadership-status');
if (status) status.textContent = 'Tab leadership harness ready.';
