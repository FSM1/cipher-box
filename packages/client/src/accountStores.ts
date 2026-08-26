/**
 * How the durable containers one account names on this origin are spelled, and
 * the two sweeps over them: one for the accounts this profile no longer holds,
 * one for the account a forget just erased.
 *
 * Realm-neutral by design — the worker builds the live seams over these names
 * (`worker/browserSeams.ts`), while the erase runs in the UI realm, after the
 * worker holding them is gone.
 */

import { deleteDatabase, openDatabase, requestResult } from './seams/idb.js';
import { STAGED_DIR_SUFFIX, STAGING_DB_VERSION, STAGING_OPS_STORE } from './seams/stagingStore.js';

/** What either sweep needs to spell a container name. */
export interface AccountStoreNaming {
  /** Prefix for the IndexedDB/OPFS container names (namespaces per origin/test). */
  dbPrefix?: string;
}

/**
 * Container names are built from the account id, so it is bounded and path-free.
 * The bound clears a secp256k1 point written as two 64-character hex
 * coordinates and a separator.
 */
export const ACCOUNT_ID = /^[0-9a-z][0-9a-z-]{0,159}$/;

export const DEFAULT_DB_PREFIX = 'cipherbox';

/** The name suffix of each durable store an account opens, spelled once. */
export const FLOORS = 'floors';
export const STAGING = 'staging';
export const SNAPSHOT_CACHE = 'snapshot-cache';

/** Every container one account names; {@link eraseAccountStores} takes them all. */
const ACCOUNT_DATABASES = [FLOORS, STAGING, SNAPSHOT_CACHE] as const;
const ACCOUNT_DIRECTORIES = [`${STAGING}${STAGED_DIR_SUFFIX}`] as const;

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
const RECLAIMED_DATABASES = [SNAPSHOT_CACHE] as const;

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
  config: AccountStoreNaming,
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
    [...ACCOUNT_DATABASES, ...ACCOUNT_DIRECTORIES].map((suffix) => `${prefix}-${suffix}`)
  );
  const foreign = (name: string, suffixes: readonly string[]): boolean =>
    !live.has(name) && namesAccountStore(dbPrefix, name, suffixes);

  const [root, names] = await Promise.all([stagedRoot(), databaseNames()]);
  const entries = root ? await directoryNames(root) : [];
  const staged = entries.filter((name) => foreign(name, ACCOUNT_DIRECTORIES));
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

/**
 * Erases every container `accountId` names on this origin, and resolves with
 * the names it took.
 *
 * It takes the floors database and the op queue that
 * {@link reclaimOtherAccountStores} spares, because this account asked for the
 * erase — the other sweep runs on some *other* account's behalf and must never
 * destroy a queue this one never acked. Emptying the stores is not enough: a
 * container still named `<dbPrefix>-<accountPublicKey>-…` is a durable
 * fingerprint binding the profile to an account, which is what the erase exists
 * to remove.
 *
 * An IndexedDB delete blocks while any connection to it is open, so this runs
 * only once the engine holding them is torn down. Best-effort per container,
 * like the other sweep.
 */
export async function eraseAccountStores(
  accountId: string,
  config: AccountStoreNaming = {}
): Promise<string[]> {
  if (!ACCOUNT_ID.test(accountId)) return [];
  const prefix = `${config.dbPrefix ?? DEFAULT_DB_PREFIX}-${accountId}`;
  const named = (suffix: string): string => `${prefix}-${suffix}`;
  // Spelled rather than enumerated: a browser that cannot list its databases
  // (`databaseNames`) must still lose these ones.
  const root = await stagedRoot();
  const [databases, directories] = await Promise.all([
    reclaim(ACCOUNT_DATABASES.map(named), deleteDatabase),
    root
      ? reclaim(ACCOUNT_DIRECTORIES.map(named), (name) =>
          root.removeEntry(name, { recursive: true })
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
