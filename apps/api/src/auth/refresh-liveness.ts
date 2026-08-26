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

/** The join alias the SQL reading below is written against; bind it with `:now`. */
export const REFRESH_ALIAS = 'refresh';

export const LIVE_REFRESH_ROW_SQL = `${REFRESH_ALIAS}.used_at IS NULL AND ${REFRESH_ALIAS}.expires_at > :now`;
