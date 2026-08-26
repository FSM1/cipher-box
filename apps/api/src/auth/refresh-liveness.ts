import { RefreshToken } from './entities/refresh-token.entity';

/**
 * A refresh row is live while it is unspent and unexpired, and a family is live
 * while it still holds one such row (CONTEXT.md, Accelerator token — every
 * session revocation revokes the pseudonym with it).
 *
 * Stated once here because two paths read it: rotation classifies the presented
 * row in TypeScript, and the accelerator verify path joins on it in SQL.
 * `refresh-liveness.itest.ts` fails the moment the two answers disagree.
 */
export type RefreshRowState = 'live' | 'spent' | 'expired';

export function refreshRowState(
  row: Pick<RefreshToken, 'usedAt' | 'expiresAt'>,
  now: Date
): RefreshRowState {
  if (row.usedAt !== null) {
    return 'spent';
  }
  return row.expiresAt.getTime() <= now.getTime() ? 'expired' : 'live';
}

/**
 * The same rule as a SQL predicate over `alias`, binding `:now`. The alias is
 * interpolated, so it is refused unless it is a bare identifier — a caller can
 * only ever pass one of its own literals, and nothing else may reach here.
 */
export function liveRefreshRowSql(alias: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(alias)) {
    throw new Error(`Invalid SQL alias: ${alias}`);
  }
  return `${alias}.used_at IS NULL AND ${alias}.expires_at > :now`;
}
