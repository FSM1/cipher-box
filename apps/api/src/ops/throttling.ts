import { positiveIntConfig } from '../common/config-int';

/**
 * The auth surface's per-IP limit; mirrored by the contract suite's
 * `PRODUCTION_AUTH_LIMIT` (crates/contract/tests/contract.rs).
 */
const AUTH_LIMIT = 10;

/**
 * The undeployed profiles, where the API only ever answers a test harness — the
 * same pair `AuthController` treats as not needing secure cookies.
 */
const TEST_PROFILES = ['test', 'development'];

/**
 * The effective per-IP auth limit, resolved per request by the throttler guard.
 *
 * A whole test suite logs in from ONE IP, so this bucket silently caps how many
 * tests can exist; `THROTTLE_AUTH_LIMIT` raises it, but ONLY on an
 * undeployed profile — an allowlist rather than a production denylist, so no
 * internet-facing deployment can be configured out of a live rate limit. The
 * env is read directly because the guard resolves this outside Nest's DI graph,
 * as `account-throttler.guard.ts` already does for the JWT secret.
 */
export function resolveAuthLimit(): number {
  if (!TEST_PROFILES.includes(process.env.NODE_ENV ?? '')) {
    return AUTH_LIMIT;
  }
  return positiveIntConfig(process.env.THROTTLE_AUTH_LIMIT, AUTH_LIMIT);
}

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
  auth: { default: { limit: resolveAuthLimit, ttl: 60_000 } },
  /** Refresh rotation: chattier than login, still bounded. */
  refresh: { default: { limit: 30, ttl: 60_000 } },
  /**
   * The gateway front's forward_auth leg, per client address — the front
   * forwards it, and `TRUST_PROXY_HOPS` is what lets the tracker read it
   * instead of the front's own.
   *
   * 50 presentations/s: the read leg presents once per sealed leaf, leaves are
   * 1 MiB, so this caps one member's sustained read at ~50 MiB/s — above the
   * hosted accelerator's own serving rate, and the focus-window poll's handful
   * of resolves per tick sits inside the rounding. It doubles as the abuse
   * bound: a refused token costs one indexed lookup per distinct token per
   * second, so this is also what one address can push at the database.
   */
  gatewayVerify: { default: { limit: 3_000, ttl: 60_000 } },
  /**
   * Mailbox post: per SENDER account (AccountThrottlerGuard keys by the
   * authenticated account). This same bucket rate-limits the unknown-recipient
   * existence oracle — an account can only probe pubkeys at the post rate.
   */
  mailboxPost: { default: { limit: 30, ttl: 60_000 } },
  /** Mailbox poll: per RECIPIENT mailbox; chattier on the sync cadence. */
  mailboxPoll: { default: { limit: 60, ttl: 60_000 } },
  /** Mailbox ack: per RECIPIENT mailbox; one delete per delivered message. */
  mailboxAck: { default: { limit: 120, ttl: 60_000 } },
  /**
   * Registry register/retire: per account. Ordinary writes send single-item
   * batches; name waves and sweeps send a few bulk batches — so the cap is on
   * request count, not item count, and sits well above the sync cadence.
   */
  registry: { default: { limit: 120, ttl: 60_000 } },
  /** Account quota/BYO: per account; quota is polled on the statfs path. */
  account: { default: { limit: 120, ttl: 60_000 } },
  /**
   * Account hard-delete: per account. A rare, deliberate, destructive
   * operation (client-confirmed), so the cap sits low — a handful of retries is
   * plenty; anything above that is abuse.
   */
  accountDelete: { default: { limit: 5, ttl: 60_000 } },
  /** Content upload: per account; bounded above the write cadence, below abuse. */
  content: { default: { limit: 60, ttl: 60_000 } },
  /**
   * Pre-reconstruction session mint: per IP, because the caller has no account
   * yet. Login-shaped in cost and consequence, so it shares the auth cap.
   */
  deviceApprovalSession: { default: { limit: resolveAuthLimit, ttl: 60_000 } },
  /**
   * Opening a rendezvous: per account. Deliberately the tightest surface here —
   * every request costs a member an approval prompt, so this is the cap that
   * blunts approval fatigue, not just load.
   */
  deviceApprovalRequest: { default: { limit: 3, ttl: 60_000 } },
  /** Rendezvous polling, both sides: per account, at the few-seconds cadence. */
  deviceApprovalPoll: { default: { limit: 60, ttl: 60_000 } },
  /** Answering a rendezvous: per account; one answer per prompt, plus retries. */
  deviceApprovalRespond: { default: { limit: 30, ttl: 60_000 } },
  /** Device registry: per account. Registration is once per device, list is chattier. */
  deviceRegistry: { default: { limit: 30, ttl: 60_000 } },
  /**
   * Recovery fetch: per account. The revival aid after a >EOL lapse is a rare,
   * deliberate operation (extract the last CID, mint a fresh record), so the cap
   * sits low — enough to sweep a handful of scope names, far below abuse rates.
   */
  recovery: { default: { limit: 30, ttl: 60_000 } },
} as const;
