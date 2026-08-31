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
  /** A write through the mount drains to the network. */
  publishMs: number;
  /** A manual refresh resolves. */
  refreshMs: number;
  /** The staleness ladder reaches `offline`. */
  offlineMs: number;
  /** The process exits after `quit`. */
  shutdownMs: number;
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
    publishMs: 40 * tick,
    refreshMs: 30 * tick,
    // The rung itself takes `staleAfterMs` to arrive, so the wait must clear it
    // by a wide margin or it could never observe the state it names.
    offlineMs: 10 * profile.staleAfterMs,
    shutdownMs: 20 * tick,
  };
}

function clamp(value: number, low: number, high: number): number {
  return Math.min(high, Math.max(low, value));
}
