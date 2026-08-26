import type { IncomingMessage, ServerResponse } from 'node:http';

import { readBody, send } from './mockHttp.js';

/**
 * In-memory mock of the API's identity-login exchange (blueprint/api.md
 * "Auth"), for the browser suite's engine cold start. `/auth/login` is refused
 * unless it echoes a challenge this mock issued, so an engine that came up
 * without logging in fails its cold start here. The signature itself is checked
 * where the crypto lives, in `crates/engine` and the contract suite.
 *
 * It owns the whole `/mock-api/` prefix: an unserved route under it answers 404
 * rather than falling through to the dev server's HTML, so a call the mock does
 * not implement fails as a missing route instead of a decode error.
 */

/** Challenges issued and not yet spent, by the publicKey that asked for one. */
const issued = new Map<string, string>();
/** Exchanges completed, so a suite can assert the engine logged in at all. */
const completed = { challenges: 0, logins: 0 };

export function mockAuthRequest(req: IncomingMessage, res: ServerResponse): boolean {
  const url = (req.url ?? '').split('?')[0];
  if (!url.startsWith('/mock-api/')) return false;
  if (req.method === 'GET' && url.endsWith('/auth/seen')) {
    send(res, 200, completed);
    return true;
  }
  let respond;
  if (req.method === 'POST') {
    if (url.endsWith('/auth/challenge')) respond = challenge;
    else if (url.endsWith('/auth/login')) respond = login;
  }
  if (!respond) {
    send(res, 404, { error: 'no such mock-api route' });
    return true;
  }

  void readBody(req).then(
    (body) => respond(res, parse(body)),
    () => send(res, 400, { error: 'request aborted' })
  );
  return true;
}

function challenge(res: ServerResponse, dto: Fields): void {
  const publicKey = field(dto, 'publicKey');
  if (publicKey === null) {
    send(res, 400, { error: 'publicKey must be a string' });
    return;
  }
  // Shaped as the API issues one — the domain tag plus 32 bytes of lowercase
  // hex — because the engine refuses to sign anything else.
  const value = `cipherbox-login:v2:${publicKey.slice(0, 64).padEnd(64, '0')}`;
  issued.set(publicKey, value);
  completed.challenges += 1;
  send(res, 200, { challenge: value, expiresAt: '2099-01-01T00:00:00Z' });
}

function login(res: ServerResponse, dto: Fields): void {
  const publicKey = field(dto, 'publicKey');
  const echoed = field(dto, 'challenge');
  if (publicKey === null || echoed === null || field(dto, 'signature') === null) {
    send(res, 400, { error: 'publicKey, challenge and signature are required' });
    return;
  }
  if (issued.get(publicKey) !== echoed) {
    send(res, 401, { message: 'no such challenge' });
    return;
  }
  issued.delete(publicKey);
  completed.logins += 1;
  send(res, 200, {
    accessToken: 'browser-suite-access',
    refreshToken: 'r'.repeat(64),
    gatewayToken: 'g'.repeat(64),
    isNewUser: true,
  });
}

type Fields = Record<string, unknown>;

function parse(body: Buffer): Fields {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return {};
  }
  // `JSON.parse('null')` is a valid parse of a non-object: reading a field off
  // it throws inside the response callback, and the request never answers.
  return typeof parsed === 'object' && parsed !== null ? (parsed as Fields) : {};
}

function field(dto: Fields, name: string): string | null {
  const value = dto[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}
