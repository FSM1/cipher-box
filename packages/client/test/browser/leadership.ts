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

const JOURNAL_DB = 'cb-leadership-journal';
const JOURNAL_STORE = 'ops';

interface HarnessOptions {
  lockName: string;
  channelName: string;
}

declare global {
  interface Window {
    cbCreate(options: HarnessOptions): Promise<void>;
    cbRole(): string;
    cbStart(): Promise<string>;
    cbCreateFile(name: string): Promise<string>;
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

window.cbCreate = ({ lockName, channelName }: HarnessOptions): Promise<void> => {
  client = new EngineClient({
    locks: navigator.locks,
    lockName,
    createChannel: () => new BroadcastChannel(channelName),
    spawnWorker: () =>
      new Worker(new URL('./journalEngine.worker.ts', import.meta.url), { type: 'module' }),
    // Failover re-derivation: a real login re-exports this from Core Kit; the
    // suite only needs a non-key placeholder to drive the cold-start path.
    secretSource: { provideSecret: () => Promise.resolve(new ArrayBuffer(8)) },
  });
  // Let the lock election settle so role() is meaningful to the caller.
  return new Promise<void>((resolve) => setTimeout(resolve, 50));
};

window.cbRole = (): string => client?.currentRole() ?? 'none';

window.cbStart = async (): Promise<string> => {
  try {
    await client!.facade.start(new ArrayBuffer(8));
    return 'ok';
  } catch (error) {
    return settle(error);
  }
};

window.cbCreateFile = async (name: string): Promise<string> => {
  try {
    await client!.facade.create(rootNode, name, 'file', new Uint8Array([1, 2, 3]).buffer);
    return 'ok';
  } catch (error) {
    return settle(error);
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
