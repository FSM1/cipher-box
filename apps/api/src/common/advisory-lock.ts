import { ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EntityManager, QueryFailedError } from 'typeorm';

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
 * single bound. `SET LOCAL` is transaction-scoped and takes no bind parameters,
 * so the validated integer is inlined. `0` leaves the wait unbounded.
 */
export async function setAdvisoryLockTimeout(
  manager: EntityManager,
  timeoutMs: number
): Promise<void> {
  if (timeoutMs > 0) {
    await manager.query(`SET LOCAL lock_timeout = ${Math.trunc(timeoutMs)}`);
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

function isLockNotAvailable(error: unknown): boolean {
  if (!(error instanceof QueryFailedError)) {
    return false;
  }
  const code =
    (error.driverError as { code?: string } | undefined)?.code ??
    (error as unknown as { code?: string }).code;
  return code === LOCK_NOT_AVAILABLE;
}
