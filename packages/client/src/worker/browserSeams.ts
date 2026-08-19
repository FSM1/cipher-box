/**
 * Constructs the eight browser seams for one engine instance, inside the worker
 * realm (blueprint/web-client.md "Browser seams"). The seam bag's property names
 * are the constructor contract the WASM `EngineHandle` reads.
 */

import { deleteDatabase } from '../seams/idb.js';
import {
  ApiMailbox,
  FetchHttp,
  FetchRecordTransport,
  IdbFloorStore,
  IdbSnapshotCache,
  NoopCredentialStore,
  OpfsStagingStore,
  WorkerScheduler,
} from '../seams/index.js';

export interface BrowserSeamsConfig {
  /** Delegated-routing endpoint set for `RecordTransport` (someguy + public). */
  recordEndpoints: string[];
  /** Absolute base URL of the API; `Mailbox` appends its own routes. */
  apiBaseUrl: string;
  /** Prefix for the IndexedDB/OPFS store names (namespaces per origin/test). */
  dbPrefix?: string;
}

/**
 * Store names are built from the account id, so it is bounded and path-free.
 * The bound clears a secp256k1 point written as two 64-character hex
 * coordinates and a separator.
 */
const ACCOUNT_ID = /^[0-9a-z][0-9a-z-]{0,159}$/;

const DEFAULT_DB_PREFIX = 'cipherbox';

/** The IndexedDB databases one account's seams open, by name suffix. */
const STORE_SUFFIXES = ['floors', 'staging', 'snapshot-cache'] as const;

/** OPFS holds an account's staged bytes beside its staging database's name. */
const STAGED_SUFFIX = '-staged';

/** The seam bag the WASM `EngineHandle` constructor reads. */
export interface BrowserSeams {
  floorStore: IdbFloorStore;
  recordTransport: FetchRecordTransport;
  http: FetchHttp;
  mailbox: ApiMailbox;
  scheduler: WorkerScheduler;
  stagingStore: OpfsStagingStore;
  snapshotCache: IdbSnapshotCache;
  credentialStore: NoopCredentialStore;
}

function storeNames(dbPrefix: string, accountId: string): string[] {
  return STORE_SUFFIXES.map((suffix) => `${dbPrefix}-${accountId}-${suffix}`);
}

/** Whether `name` is `<dbPrefix>-<accountId>-<suffix>` for some account id. */
function namesAccountStore(dbPrefix: string, name: string): boolean {
  const head = `${dbPrefix}-`;
  return STORE_SUFFIXES.some((suffix) => {
    const tail = `-${suffix}`;
    if (!name.startsWith(head) || !name.endsWith(tail)) return false;
    return ACCOUNT_ID.test(name.slice(head.length, name.length - tail.length));
  });
}

/**
 * `accountId` namespaces every durable store, so two accounts signed in on one
 * browser profile cannot share an epoch floor keyed by the constant root scope
 * id — which would refuse the lower-epoch account's cold start as a rollback,
 * with no way back (blueprint/engine.md "Floor law").
 */
export function makeBrowserSeams(config: BrowserSeamsConfig, accountId: string): BrowserSeams {
  if (!ACCOUNT_ID.test(accountId)) throw new Error('account id is not a store namespace');
  const prefix = `${config.dbPrefix ?? DEFAULT_DB_PREFIX}-${accountId}`;
  const http = new FetchHttp();
  return {
    floorStore: new IdbFloorStore(`${prefix}-floors`),
    recordTransport: new FetchRecordTransport(config.recordEndpoints),
    http,
    mailbox: new ApiMailbox(http, config.apiBaseUrl),
    scheduler: new WorkerScheduler(),
    stagingStore: new OpfsStagingStore(`${prefix}-staging`),
    snapshotCache: new IdbSnapshotCache(`${prefix}-snapshot-cache`),
    credentialStore: new NoopCredentialStore(),
  };
}

/**
 * Deletes the durable stores every account *but* `accountId` left on this
 * origin, and resolves with the names it reclaimed.
 *
 * An abandoned account's staged op bodies are upload-sized and are charged
 * against the same origin quota the live account measures its staging budget
 * from (`measureStorageHeadroomBytes`), so without this one sign-in taxes every
 * later one for good. Best-effort per store: one still open elsewhere blocks
 * its delete, and the next cold start sweeps again.
 */
export async function reclaimOtherAccountStores(
  config: BrowserSeamsConfig,
  accountId: string
): Promise<string[]> {
  const dbPrefix = config.dbPrefix ?? DEFAULT_DB_PREFIX;
  // The live account's names, spelled exactly as `makeBrowserSeams` opens them
  // — never parsed back out of a walked name, which two account ids could spell.
  const live = new Set(storeNames(dbPrefix, accountId));
  const reclaimed: string[] = [];

  for (const name of await databaseNames()) {
    if (live.has(name) || !namesAccountStore(dbPrefix, name)) continue;
    if (await succeeds(deleteDatabase(name))) reclaimed.push(name);
  }

  const root = await stagedRoot();
  if (root) {
    for (const name of await stagedDirectoryNames(root)) {
      const backing = name.slice(0, -STAGED_SUFFIX.length);
      if (live.has(backing) || !namesAccountStore(dbPrefix, backing)) continue;
      if (await succeeds(root.removeEntry(name, { recursive: true }))) reclaimed.push(name);
    }
  }
  return reclaimed;
}

function succeeds(step: Promise<unknown>): Promise<boolean> {
  return step.then(
    () => true,
    () => false
  );
}

/** Every database on this origin, or none where the browser cannot enumerate them. */
async function databaseNames(): Promise<string[]> {
  if (typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function') return [];
  const databases = await indexedDB.databases().catch(() => []);
  return databases.map((database) => database.name).filter((name) => name !== undefined);
}

async function stagedRoot(): Promise<FileSystemDirectoryHandle | null> {
  if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined) {
    return null;
  }
  return navigator.storage.getDirectory().catch(() => null);
}

/** The staged directories on this origin; a walk that faults yields what it saw. */
async function stagedDirectoryNames(root: FileSystemDirectoryHandle): Promise<string[]> {
  const names: string[] = [];
  try {
    for await (const name of root.keys()) {
      if (name.endsWith(STAGED_SUFFIX)) names.push(name);
    }
  } catch {
    // best-effort, like every other step of the sweep
  }
  return names;
}
