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
  /** Content upload: per account; bounded above the write cadence, below abuse. */
  content: { default: { limit: 60, ttl: 60_000 } },
} as const;
