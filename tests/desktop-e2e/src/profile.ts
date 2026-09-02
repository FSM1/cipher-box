/**
 * The deadlines every wait in this suite runs against.
 *
 * They derive from the sync timing profile the binary runs under, so a profile
 * change moves the suite with it. `crates/engine/src/profile.rs` holds the
 * authoritative values; these mirror the fields the suite waits on.
 */

export interface SyncTimingProfile {
  recordTtlMs: number;
  pollCadenceMs: number;
  staleAfterMs: number;
}

/** Mirrors `SyncTimingProfile::CI`. Only an `e2e-hook` build runs under it. */
export const CI_PROFILE: SyncTimingProfile = {
  recordTtlMs: 2_000,
  pollCadenceMs: 1_000,
  staleAfterMs: 3_000,
};

/** Mirrors `SyncTimingProfile::PRODUCTION`. The suite never runs against it. */
export const PRODUCTION_PROFILE: SyncTimingProfile = {
  recordTtlMs: 60_000,
  pollCadenceMs: 30_000,
  staleAfterMs: 90_000,
};

export interface Deadlines {
  /** Gap between two reads of the same signal. */
  intervalMs: number;
  /** The API answers its health probe. */
  apiReadyMs: number;
  /** The shell writes its control file. */
  controlFileMs: number;
  /** The status reaches `mounted`. */
  mountMs: number;
  /** A manual refresh resolves. */
  refreshMs: number;
  /**
   * Gap between two reads of one file through a mount. Uncapped, unlike
   * [`intervalMs`](Deadlines.intervalMs): a host caches a refused read, and a
   * loop tighter than that cache re-reads the cache rather than the mount.
   */
  readIntervalMs: number;
  /** A file this instance wrote itself reads back through its own mount. */
  readMs: number;
  /**
   * A file one client published reaches another client's mount. Wide, because
   * the name arrives with the parent's listing and the length needs the child's
   * own record — a second publish to resolve.
   */
  convergeMs: number;
  /** The process exits after `quit`. */
  shutdownMs: number;
  /**
   * One whole scenario. A kernel call on a mount carries no timeout, so this
   * is what turns a mount that stops answering into a reported failure.
   */
  scenarioMs: number;
}

const MIN_INTERVAL_MS = 50;
const MAX_INTERVAL_MS = 500;

/**
 * Each budget is a multiple of a profile duration. A generous multiple is
 * deliberate: these bound a hang, and they never pace a scenario, because the
 * suite polls a real signal rather than a clock.
 */
export function deadlines(profile: SyncTimingProfile = CI_PROFILE): Deadlines {
  const tick = profile.pollCadenceMs;
  return {
    intervalMs: clamp(Math.round(tick / 10), MIN_INTERVAL_MS, MAX_INTERVAL_MS),
    apiReadyMs: 60 * tick,
    controlFileMs: 30 * tick,
    mountMs: 60 * tick,
    refreshMs: 30 * tick,
    readIntervalMs: tick,
    readMs: 30 * tick,
    convergeMs: 100 * tick,
    shutdownMs: 20 * tick,
    scenarioMs: 240 * tick,
  };
}

function clamp(value: number, low: number, high: number): number {
  return Math.min(high, Math.max(low, value));
}
