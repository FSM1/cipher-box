/**
 * Auth Middleware Tests
 *
 * Tests the Bearer token authentication middleware.
 * Validates correct handling of valid tokens, missing headers,
 * wrong tokens, and malformed authorization headers.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { authMiddleware } from '../middleware/auth.js';

/** Create a minimal mock Request */
function mockRequest(headers: Record<string, string> = {}): Partial<Request> {
  return { headers };
}

/** Create a mock Response with spies on status and json */
function mockResponse(): Partial<Response> & {
  statusCode: number;
  jsonBody: unknown;
} {
  const res = {
    statusCode: 0,
    jsonBody: null as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.jsonBody = body;
      return res;
    },
  };
  return res as Partial<Response> & { statusCode: number; jsonBody: unknown };
}

describe('authMiddleware', () => {
  const TEST_SECRET = 'test-secret-token-abc123';

  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_WORKER_SECRET = TEST_SECRET;
  });

  it('calls next() for valid Bearer token', () => {
    const req = mockRequest({ authorization: `Bearer ${TEST_SECRET}` });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(0); // status() not called
  });

  it('returns 401 for missing Authorization header', () => {
    const req = mockRequest({});
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.jsonBody).toEqual({ error: 'Missing or invalid Authorization header' });
  });

  it('returns 401 for wrong token', () => {
    const req = mockRequest({ authorization: 'Bearer wrong-token' });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.jsonBody).toEqual({ error: 'Invalid authentication token' });
  });

  it('returns 401 for malformed header without Bearer prefix', () => {
    const req = mockRequest({ authorization: TEST_SECRET });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.jsonBody).toEqual({ error: 'Missing or invalid Authorization header' });
  });

  it('returns 401 for Basic auth (not Bearer)', () => {
    const req = mockRequest({
      authorization: `Basic ${Buffer.from('user:pass').toString('base64')}`,
    });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });

  it('returns 500 when TEE_WORKER_SECRET is not configured', () => {
    delete process.env.TEE_WORKER_SECRET;

    const req = mockRequest({ authorization: 'Bearer some-token' });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(500);
    expect(res.jsonBody).toEqual({ error: 'TEE_WORKER_SECRET not configured' });
  });

  it('returns 401 for token with different length (timing-safe comparison)', () => {
    // The middleware checks length first, then does timingSafeEqual
    const req = mockRequest({ authorization: 'Bearer short' });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.jsonBody).toEqual({ error: 'Invalid authentication token' });
  });

  it('returns 401 for empty Bearer token', () => {
    const req = mockRequest({ authorization: 'Bearer ' });
    const res = mockResponse();
    const next = vi.fn();

    authMiddleware(req as Request, res as unknown as Response, next as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
  });
});
