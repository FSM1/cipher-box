import { Request } from 'express';

/**
 * Express request with authenticated user payload attached by JwtAuthGuard.
 * Shared across all controllers that require authentication.
 */
export interface RequestWithUser extends Request {
  user: { id: string; scope?: string[] };
}
