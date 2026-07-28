/**
 * Measured origin headroom for the engine's storage policy.
 *
 * Lives apart from the worker bootstrap so the fail-closed rule below is
 * reachable from a test without loading a module that installs listeners.
 */

/** The subset of the Storage Standard estimate this reads. */
export interface StorageEstimateLike {
  quota?: number;
  usage?: number;
}

/**
 * Quota minus usage, or `undefined` when the environment does not report a
 * complete estimate.
 *
 * **Both figures are required.** A partial estimate is not a measurement: with
 * `usage` absent, treating it as zero hands back the entire quota as free space
 * and the engine builds a *measured* policy on a number nothing measured —
 * admitting uploads until the staging writes themselves fail. That is the same
 * conflation as reporting an unmeasurable origin as full, in the opposite
 * direction. Unknown stays unknown; `StoragePolicy::UNMEASURED` says so.
 */
export function storageHeadroomBytes(
  estimate: StorageEstimateLike | undefined
): number | undefined {
  if (estimate?.quota === undefined || estimate.usage === undefined) return undefined;
  return Math.max(0, estimate.quota - estimate.usage);
}

/** Read the live origin estimate, treating an absent or throwing API as unmeasured. */
export async function measureStorageHeadroomBytes(): Promise<number | undefined> {
  const estimate = await navigator.storage?.estimate?.().catch(() => undefined);
  return storageHeadroomBytes(estimate);
}
