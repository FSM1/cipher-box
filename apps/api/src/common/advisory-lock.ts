import { ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'node:crypto';
import { DataSource, EntityManager, QueryFailedError } from 'typeorm';

/**
 * Default bound on how long an advisory-lock acquire may WAIT while holding its
 * pooled connection before it aborts and releases it. `pg_advisory_xact_lock`
 * blocks on a held connection, so an unbounded wait under sustained same-key
 * contention fills the shared pool with blocked waiters and starves unrelated
 * queries — the cap/refcount control degrades into a service-wide DoS.
 */
const DEFAULT_LOCK_TIMEOUT_MS = 3000;

/** Postgres `lock_not_available`: a statement aborted by `lock_timeout`. */
const LOCK_NOT_AVAILABLE = '55P03';

/**
 * Read the advisory-lock wait bound (ms) from config, failing closed to the
 * safe default for an unset OR garbage value. `0` is a valid explicit value —
 * it disables the bound (the pre-hardening, unbounded-wait behavior).
 */
export function resolveAdvisoryLockTimeoutMs(configService: ConfigService): number {
  const raw = configService.get<string | number>('DB_ADVISORY_LOCK_TIMEOUT_MS');
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return DEFAULT_LOCK_TIMEOUT_MS;
  }
  const value = Number(raw);
  return Number.isInteger(value) && value >= 0 ? value : DEFAULT_LOCK_TIMEOUT_MS;
}

/**
 * Bound advisory-lock waits to `timeoutMs` for the current transaction. Call
 * once before acquiring any key; registry batches lock several keys under a
 * single bound. `set_config('lock_timeout', …, true)` is the transaction-local
 * (`is_local = true`) equivalent of `SET LOCAL`, taking the value as a bind
 * parameter. `0` leaves the wait unbounded.
 */
export async function setAdvisoryLockTimeout(
  manager: EntityManager,
  timeoutMs: number
): Promise<void> {
  if (timeoutMs > 0) {
    await manager.query('SELECT set_config($1, $2, true)', [
      'lock_timeout',
      Math.trunc(timeoutMs).toString(),
    ]);
  }
}

/**
 * Acquire one transaction-scoped advisory lock, mapping a `lock_timeout` abort
 * to a retryable 503 so a contended caller degrades gracefully instead of
 * holding its connection until the pool starves. The lock auto-releases at
 * commit or rollback.
 */
export async function acquireAdvisoryLock(manager: EntityManager, key: bigint): Promise<void> {
  try {
    await manager.query('SELECT pg_advisory_xact_lock($1::bigint)', [key.toString()]);
  } catch (error) {
    if (isLockNotAvailable(error)) {
      throw new ServiceUnavailableException('Contended resource; retry shortly');
    }
    throw error;
  }
}

/**
 * A Postgres `lock_not_available` (55P03) — a statement aborted by
 * `lock_timeout`, whether the advisory-lock acquire or a row lock taken later
 * under the same transaction-scoped bound. TypeORM wraps it as a
 * `QueryFailedError` carrying the driver code.
 */
export function isLockNotAvailable(error: unknown): boolean {
  if (!(error instanceof QueryFailedError)) {
    return false;
  }
  const code =
    (error.driverError as { code?: string } | undefined)?.code ??
    (error as unknown as { code?: string }).code;
  return code === LOCK_NOT_AVAILABLE;
}

/**
 * Stable 64-bit advisory-lock key for an opaque token — a content CID, an IPNS
 * name, or a namespaced account key: the first 8 bytes of its sha256 read
 * big-endian as a signed 64-bit int for `pg_advisory_xact_lock($1::bigint)`.
 * The registry and the upload path MUST share this function so the same CID
 * locked from either serializes against the other.
 */
export function advisoryLockKey(token: string): bigint {
  return createHash('sha256').update(token).digest().readBigInt64BE(0);
}

/**
 * Namespaced per-account advisory key: `account:` prevents any collision with a
 * bare CID or IPNS-name key in the shared bigint lock space. The upload quota
 * gate and the account hard-delete cascade MUST share this function so an
 * in-flight upload serializes against the account's deletion on the same key.
 */
export function accountLockKey(accountId: string): bigint {
  return advisoryLockKey(`account:${accountId}`);
}

/**
 * Namespaced session-lock key for the post-commit pin-durability window: the
 * upload's commit → pin → compensate span AND the account hard-delete cascade's
 * post-commit unpin. A DISTINCT key from the plain CID xact lock — a holder takes
 * both (this session lock on its own connection, the xact lock on the tx
 * connection), and same-key session-vs-xact locks across connections would
 * self-deadlock. The upload and hard-delete paths MUST share this key so a
 * physical unpin serializes against a concurrent same-CID pin.
 */
export function pinDurabilityLockKey(cid: string): bigint {
  return advisoryLockKey(`pin-durability:${cid}`);
}

/**
 * Acquire a batch of transaction-scoped advisory locks in one deadlock-free
 * order: keys are de-duplicated and sorted, so any two overlapping batches take
 * their shared keys in the same sequence and cannot form a cycle. Set the
 * `lock_timeout` bound (setAdvisoryLockTimeout) once before calling.
 */
export async function acquireAdvisoryLocks(manager: EntityManager, keys: bigint[]): Promise<void> {
  const sorted = [...new Set(keys)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const key of sorted) {
    await acquireAdvisoryLock(manager, key);
  }
}

/**
 * Run `work` in a transaction, mapping any `lock_timeout` abort (55P03) — the
 * advisory acquire OR any row lock taken later under the same bound — to the
 * retryable 503, so a contended caller degrades gracefully instead of escaping
 * as a 500. A 503 an inner helper already raised passes through unchanged.
 */
export async function runLockGuardedTransaction<T>(
  dataSource: DataSource,
  work: (manager: EntityManager) => Promise<T>
): Promise<T> {
  try {
    return await dataSource.transaction(work);
  } catch (error) {
    if (isLockNotAvailable(error)) {
      throw new ServiceUnavailableException('Contended resource; retry shortly');
    }
    throw error;
  }
}

/**
 * Run `work` while holding a SESSION-level advisory lock on `key`, on a
 * dedicated connection held for the whole span and released in a `finally`.
 * Unlike the xact lock (auto-released at COMMIT), a session lock spans several
 * transactions PLUS an external side effect — the caller uses it to serialize a
 * commit → external effect → compensation window that a xact lock would leave
 * unguarded once it releases at commit. A `lock_timeout` abort maps to the
 * retryable 503; the bound is set session-local on the dedicated connection and
 * RESET before release so it never leaks to the next pool borrower.
 */
export async function withSessionAdvisoryLock<T>(
  dataSource: DataSource,
  key: bigint,
  timeoutMs: number,
  work: () => Promise<T>
): Promise<T> {
  const runner = dataSource.createQueryRunner();
  await runner.connect();
  const bounded = timeoutMs > 0;
  try {
    if (bounded) {
      await runner.query('SELECT set_config($1, $2, false)', [
        'lock_timeout',
        Math.trunc(timeoutMs).toString(),
      ]);
    }
    let acquired = false;
    try {
      await runner.query('SELECT pg_advisory_lock($1::bigint)', [key.toString()]);
      acquired = true;
      return await work();
    } catch (error) {
      if (isLockNotAvailable(error)) {
        throw new ServiceUnavailableException('Contended resource; retry shortly');
      }
      throw error;
    } finally {
      // Unlock failure implies a dead connection, whose session lock Postgres
      // has already dropped — the pool discards it on release.
      if (acquired) {
        await runner.query('SELECT pg_advisory_unlock($1::bigint)', [key.toString()]).catch(() => {
          /* noop */
        });
      }
    }
  } finally {
    if (bounded) {
      await runner.query('RESET lock_timeout').catch(() => {
        /* noop */
      });
    }
    await runner.release();
  }
}
