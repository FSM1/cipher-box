import type { IncomingMessage, ServerResponse } from 'node:http';

import { readBody } from './mockMailbox.js';

/**
 * In-memory mock of the API's identity-login exchange (blueprint/api.md
 * "Auth"), for the browser suite's engine cold start.
 *
 * It mints tokens for whatever signature it is handed — the signature itself is
 * checked where the crypto lives, in `crates/engine` and against the real API in
 * the contract suite. What it does enforce is the exchange: `/auth/login` is
 * refused unless it echoes a challenge this mock issued, so an engine that came
 * up without logging in fails its cold start here.
 */

/** Challenges issued and not yet spent, by the publicKey that asked for one. */
const issued = new Map<string, string>();

export function mockAuthRequest(req: IncomingMessage, res: ServerResponse): boolean {
  const url = (req.url ?? '').split('?')[0];
  if (req.method !== 'POST' || !url.startsWith('/mock-api/')) return false;

  if (url.endsWith('/auth/challenge')) {
    void readBody(req).then(
      (body) => challenge(res, body),
      () => send(res, 400, { error: 'request aborted' })
    );
    return true;
  }
  if (url.endsWith('/auth/login')) {
    void readBody(req).then(
      (body) => login(res, body),
      () => send(res, 400, { error: 'request aborted' })
    );
    return true;
  }
  return false;
}

function challenge(res: ServerResponse, body: Buffer): void {
  const publicKey = field(body, 'publicKey');
  if (publicKey === null) {
    send(res, 400, { error: 'publicKey must be a string' });
    return;
  }
  const value = `cipherbox-login:v2:${publicKey.slice(0, 16)}`;
  issued.set(publicKey, value);
  send(res, 200, { challenge: value, expiresAt: '2099-01-01T00:00:00Z' });
}

function login(res: ServerResponse, body: Buffer): void {
  const publicKey = field(body, 'publicKey');
  const echoed = field(body, 'challenge');
  const signature = field(body, 'signature');
  if (publicKey === null || echoed === null || signature === null) {
    send(res, 400, { error: 'publicKey, challenge and signature are required' });
    return;
  }
  if (issued.get(publicKey) !== echoed) {
    send(res, 401, { message: 'no such challenge' });
    return;
  }
  issued.delete(publicKey);
  send(res, 200, {
    accessToken: 'browser-suite-access',
    refreshToken: 'r'.repeat(64),
    isNewUser: true,
  });
}

function field(body: Buffer, name: string): string | null {
  let dto: Record<string, unknown>;
  try {
    dto = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
  const value = dto[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}
