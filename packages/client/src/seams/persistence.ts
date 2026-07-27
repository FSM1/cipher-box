/**
 * Origin storage persistence for the durable seams (blueprint/web-client.md
 * "Browser seams").
 *
 * Without persistent-storage permission a browser may evict the origin's
 * storage — which is the whole durable op queue and every staged byte, not just
 * cache — breaking the offline-parity premise the staging design rests on. The
 * grant is best-effort: a denial is reported, never thrown, so the host can warn
 * instead of promising durability it does not have.
 */

/** The subset of `StorageManager` this module drives (absent on old browsers). */
interface StoragePersistence {
  persisted?: () => Promise<boolean>;
  persist?: () => Promise<boolean>;
}

/** Requests persistent storage for this origin; resolves the granted state. */
export async function requestStoragePersistence(): Promise<boolean> {
  const storage: StoragePersistence | undefined = globalThis.navigator?.storage;
  if (typeof storage?.persist !== 'function') return false;
  try {
    // Check first: a browser that prompts for the permission must not re-prompt
    // on every worker start once the origin is already persistent.
    if (typeof storage.persisted === 'function' && (await storage.persisted())) return true;
    return await storage.persist();
  } catch {
    return false;
  }
}
