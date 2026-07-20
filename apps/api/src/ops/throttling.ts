/**
 * Per-surface rate limits (blueprint/api.md Ops: a working global throttler
 * with per-surface limits — v1's inert decorators are a named defect, so
 * effectiveness is asserted by tests driving real 429s).
 *
 * The global default comes from THROTTLE_LIMIT / THROTTLE_TTL_MS (see
 * OpsModule); these named surfaces tighten specific routes.
 */
export const THROTTLE_SURFACES = {
  /** Login-shaped endpoints: challenge issuance and credential presentation. */
  auth: { default: { limit: 10, ttl: 60_000 } },
  /** Refresh rotation: chattier than login, still bounded. */
  refresh: { default: { limit: 30, ttl: 60_000 } },
} as const;
