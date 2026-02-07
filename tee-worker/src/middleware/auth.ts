/**
 * Shared Secret Authentication Middleware
 *
 * Validates requests against the TEE_WORKER_SECRET environment variable.
 * Uses Bearer token authentication in the Authorization header.
 */

import { timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

/**
 * Express middleware that validates the Authorization: Bearer <secret> header.
 *
 * Compares the provided token against TEE_WORKER_SECRET env var.
 * Returns 401 if missing or mismatched.
 */
export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const expectedSecret = process.env.TEE_WORKER_SECRET;

  if (!expectedSecret) {
    res.status(500).json({ error: 'TEE_WORKER_SECRET not configured' });
    return;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.slice(7); // Remove 'Bearer ' prefix

  // Constant-time comparison to prevent timing attacks
  if (
    token.length !== expectedSecret.length ||
    !cryptoTimingSafeEqual(Buffer.from(token), Buffer.from(expectedSecret))
  ) {
    res.status(401).json({ error: 'Invalid authentication token' });
    return;
  }

  next();
}
