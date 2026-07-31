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
import { hex, unhex } from './hexUtil.js';

const JOURNAL_DB = 'cb-leadership-journal';
const JOURNAL_STORE = 'ops';

export interface HarnessOptions {
  lockName: string;
  channelName: string;
  /** Which engine worker the leader spawns: the journal fake (default) or the real WASM engine. */
  worker?: 'journal' | 'engine';
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

const rootNode = new Uint8Array(16);

function settle(error: unknown): string {
  if (error === undefined) return 'ok';
  return error instanceof Error ? error.message : String(error);
}

// A valid secp256k1 identity scalar placeholder (the journal fake ignores it).
const secret = (): ArrayBuffer => new Uint8Array(32).fill(1).buffer;

window.cbCreate = ({ lockName, channelName, worker }: HarnessOptions): Promise<void> => {
  const workerUrl =
    worker === 'engine'
      ? new URL('./engine.worker.ts', import.meta.url)
      : new URL('./journalEngine.worker.ts', import.meta.url);
  client = new EngineClient({
    locks: navigator.locks,
    lockName,
    createChannel: () => new BroadcastChannel(channelName),
    spawnWorker: () => new Worker(workerUrl, { type: 'module' }),
    // Failover re-derivation: a real login re-exports this from Core Kit.
    secretSource: { provideSecret: () => Promise.resolve(secret()) },
  });
  // Let the lock election settle so role() is meaningful to the caller.
  return new Promise<void>((resolve) => setTimeout(resolve, 50));
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
