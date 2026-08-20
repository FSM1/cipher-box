/**
 * Constructs the eight browser seams for one engine instance, inside the worker
 * realm (blueprint/web-client.md "Browser seams"). The seam bag's property names
 * are the constructor contract the WASM `EngineHandle` reads.
 */

import { deleteDatabase, openDatabase, requestResult } from '../seams/idb.js';
import {
  ApiMailbox,
  FetchHttp,
  FetchRecordTransport,
  IdbFloorStore,
  IdbSnapshotCache,
  NoopCredentialStore,
  OpfsStagingStore,
  STAGED_DIR_SUFFIX,
  STAGING_DB_VERSION,
  STAGING_OPS_STORE,
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

/**
 * What the sweep reclaims for an account the profile no longer holds, by name
 * suffix. Two of an account's four stores are deliberately absent: the `floors`
 * database is rollback protection, durable across logout by design
 * (`IdbFloorStore`) and what bounds replay on a device with none to compare
 * against (blueprint/engine.md "Floor law"); the `staging` database is the
 * durable op queue, whose records were acked to that account's UI. Neither is
 * bytes worth reclaiming, and an op whose staged body is gone dead-letters where
 * its own account can see it — which a deleted queue never would.
 */
const RECLAIMED_DATABASES = ['snapshot-cache'] as const;
const RECLAIMED_DIRECTORIES = [`staging${STAGED_DIR_SUFFIX}`] as const;

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

/** Whether `name` is `<dbPrefix>-<accountId>-<suffix>` for some account id. */
function namesAccountStore(dbPrefix: string, name: string, suffixes: readonly string[]): boolean {
  const head = `${dbPrefix}-`;
  if (!name.startsWith(head)) return false;
  return suffixes.some((suffix) => {
    const tail = `-${suffix}`;
    if (!name.endsWith(tail)) return false;
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
 * Reclaims what every account *but* `accountId` left on this origin, and
 * resolves with the names it took.
 *
 * An abandoned account's staged op bodies are upload-sized and are charged
 * against the same origin quota the live account measures its staging budget
 * from (`measureStorageHeadroomBytes`), so without this one sign-in taxes every
 * later one for good. They go only once that account's op queue has drained:
 * a second account's login must never destroy an unpublished queue, and its
 * staged root counts as referenced for exactly as long (`CONTEXT.md` "Retained
 * record"). Best-effort per store — an unconfirmed delete is not reported, and
 * the next cold start sweeps again.
 */
export async function reclaimOtherAccountStores(
  config: BrowserSeamsConfig,
  accountId: string
): Promise<string[]> {
  // A name this sweep cannot spell is one it must not sweep against: the live
  // account's own stores are excluded by name, and nothing else bounds it.
  if (!ACCOUNT_ID.test(accountId)) return [];
  const dbPrefix = config.dbPrefix ?? DEFAULT_DB_PREFIX;
  const prefix = `${dbPrefix}-${accountId}`;
  // Spelled exactly as this account opens them — never parsed back out of a
  // walked name, which two account ids could spell.
  const live = new Set(
    [...RECLAIMED_DATABASES, ...RECLAIMED_DIRECTORIES].map((suffix) => `${prefix}-${suffix}`)
  );
  const foreign = (name: string, suffixes: readonly string[]): boolean =>
    !live.has(name) && namesAccountStore(dbPrefix, name, suffixes);

  const [root, names] = await Promise.all([stagedRoot(), databaseNames()]);
  const entries = root ? await directoryNames(root) : [];
  const staged = entries.filter((name) => foreign(name, RECLAIMED_DIRECTORIES));
  const drained = await Promise.all(staged.map((name) => queueDrained(backingQueue(name), names)));

  const [databases, directories] = await Promise.all([
    reclaim(
      names.filter((name) => foreign(name, RECLAIMED_DATABASES)),
      deleteDatabase
    ),
    root
      ? reclaim(
          staged.filter((_name, index) => drained[index]),
          (name) => root.removeEntry(name, { recursive: true })
        )
      : [],
  ]);
  return [...databases, ...directories];
}

/** The op-queue database behind a staged directory. */
function backingQueue(directory: string): string {
  return directory.slice(0, -STAGED_DIR_SUFFIX.length);
}

/**
 * Whether that account's op queue holds nothing. A queue with no database never
 * held anything; one this sweep cannot read is not one it can prove is drained,
 * so it answers no and the bytes stay.
 */
async function queueDrained(dbName: string, databases: string[]): Promise<boolean> {
  if (!databases.includes(dbName)) return true;
  try {
    const db = await openDatabase(dbName, STAGING_DB_VERSION, () => undefined);
    try {
      const tx = db.transaction(STAGING_OPS_STORE, 'readonly');
      return (await requestResult(tx.objectStore(STAGING_OPS_STORE).count())) === 0;
    } finally {
      db.close();
    }
  } catch {
    return false;
  }
}

/** Removes each name, answering with the ones it saw go; the rest wait for a later sweep. */
async function reclaim(
  names: string[],
  remove: (name: string) => Promise<unknown>
): Promise<string[]> {
  const gone = await Promise.all(
    names.map((name) =>
      remove(name).then(
        () => true,
        () => false
      )
    )
  );
  return names.filter((_name, index) => gone[index]);
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

/** The OPFS root's entries; a walk that faults yields what it saw. */
async function directoryNames(root: FileSystemDirectoryHandle): Promise<string[]> {
  const names: string[] = [];
  try {
    for await (const name of root.keys()) names.push(name);
  } catch {
    // best-effort, like every other step of the sweep
  }
  return names;
}
