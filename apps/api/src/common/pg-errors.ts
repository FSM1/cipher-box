import { QueryFailedError } from 'typeorm';

/** Postgres `unique_violation`. */
export const UNIQUE_VIOLATION = '23505';

/** A unique violation on `constraint` alone; any other fault must surface, not read as a lost race. */
export function isUniqueViolation(error: unknown, constraint: string): boolean {
  if (!(error instanceof QueryFailedError)) return false;
  const driver = error.driverError as { code?: string; constraint?: string } | undefined;
  return driver?.code === UNIQUE_VIOLATION && driver?.constraint === constraint;
}
