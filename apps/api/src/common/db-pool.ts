import { ConfigService } from '@nestjs/config';

/** node-postgres' own default pool ceiling; kept explicit so it can be reasoned about. */
export const DEFAULT_DB_POOL_SIZE = 10;

/**
 * The connection-pool ceiling (`DB_POOL_SIZE`), failing closed to the default
 * for an unset OR garbage value and flooring at 1. The single source of this
 * number for both the DataSource that sizes the pool and the content path that
 * sizes its admission ceiling against it, so the two can never drift apart.
 */
export function resolveDbPoolSize(configService: ConfigService): number {
  const raw = configService.get<string | number>('DB_POOL_SIZE');
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return DEFAULT_DB_POOL_SIZE;
  }
  const value = Number(raw);
  return Number.isInteger(value) && value >= 1 ? value : DEFAULT_DB_POOL_SIZE;
}
