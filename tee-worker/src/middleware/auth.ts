/**
 * Shared Secret Authentication Middleware
 *
 * Validates requests against the TEE_WORKER_SECRET environment variable.
 * Uses Bearer token authentication in the Authorization header.
 */

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
  if (token.length !== expectedSecret.length || !timingSafeEqual(token, expectedSecret)) {
    res.status(401).json({ error: 'Invalid authentication token' });
    return;
  }

  next();
}

/**
 * Simple constant-time string comparison.
 * Prevents timing attacks on secret comparison.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
