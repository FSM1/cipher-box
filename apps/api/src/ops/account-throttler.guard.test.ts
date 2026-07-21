import { createHmac } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  verifiedSubjectFromBearer,
  verifiedUnexpiredSubjectFromBearer,
} from './account-throttler.guard';

const SECRET = 'account-throttler-test-secret';

function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

/** Mint an HS256 JWT signed with `secret`. */
function token(claims: Record<string, unknown>, secret = SECRET): string {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify(claims));
  const signature = b64url(createHmac('sha256', secret).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${signature}`;
}

function bearer(value: string): Record<string, unknown> {
  return { authorization: `Bearer ${value}` };
}

describe('verifiedSubjectFromBearer', () => {
  let priorSecret: string | undefined;

  beforeAll(() => {
    priorSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;
  });

  afterAll(() => {
    if (priorSecret === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = priorSecret;
    }
  });

  it('returns the sub of a token carrying our own HS256 signature', () => {
    expect(verifiedSubjectFromBearer(bearer(token({ sub: 'user-1' })))).toBe('user-1');
  });

  it('rejects a token signed with a different secret (no forged-sub bucket)', () => {
    expect(verifiedSubjectFromBearer(bearer(token({ sub: 'victim' }, 'attacker-secret')))).toBe(
      undefined
    );
  });

  it('rejects a token with a tampered payload (signature no longer matches)', () => {
    const valid = token({ sub: 'user-1' });
    const [header, , signature] = valid.split('.');
    const forgedPayload = b64url(JSON.stringify({ sub: 'someone-else' }));
    expect(verifiedSubjectFromBearer(bearer(`${header}.${forgedPayload}.${signature}`))).toBe(
      undefined
    );
  });

  it('rejects an unsigned (alg:none-style) token with an empty signature', () => {
    const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ sub: 'user-1' }));
    expect(verifiedSubjectFromBearer(bearer(`${header}.${payload}.`))).toBe(undefined);
  });

  it('returns undefined for a validly-signed token with no sub claim', () => {
    expect(verifiedSubjectFromBearer(bearer(token({ publicKey: 'abc' })))).toBe(undefined);
  });

  it('returns undefined when there is no bearer or the header is malformed', () => {
    expect(verifiedSubjectFromBearer(undefined)).toBe(undefined);
    expect(verifiedSubjectFromBearer({})).toBe(undefined);
    expect(verifiedSubjectFromBearer({ authorization: 'Basic abc' })).toBe(undefined);
    expect(verifiedSubjectFromBearer(bearer('not-a-jwt'))).toBe(undefined);
  });

  it('still returns the sub of a signed-but-EXPIRED token (expiry ignored for rate-limit keying)', () => {
    const past = Math.floor(Date.now() / 1000) - 60;
    expect(verifiedSubjectFromBearer(bearer(token({ sub: 'user-1', exp: past })))).toBe('user-1');
  });
});

describe('verifiedUnexpiredSubjectFromBearer', () => {
  let priorSecret: string | undefined;

  beforeAll(() => {
    priorSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;
  });

  afterAll(() => {
    if (priorSecret === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = priorSecret;
    }
  });

  const now = 1_000_000;

  it('returns the sub of a validly-signed, unexpired token', () => {
    expect(
      verifiedUnexpiredSubjectFromBearer(bearer(token({ sub: 'user-1', exp: now + 60 })), now)
    ).toBe('user-1');
  });

  it('fails closed on a validly-signed but EXPIRED token (unlike the rate-limit keyer)', () => {
    const expired = bearer(token({ sub: 'user-1', exp: now - 1 }));
    // The signature is genuine, so the rate-limit keyer still trusts the sub...
    expect(verifiedSubjectFromBearer(expired)).toBe('user-1');
    // ...but the pre-buffer gate rejects it (must not buffer for an expired token).
    expect(verifiedUnexpiredSubjectFromBearer(expired, now)).toBe(undefined);
  });

  it('rejects at the exact expiry boundary (now >= exp), matching jsonwebtoken', () => {
    expect(
      verifiedUnexpiredSubjectFromBearer(bearer(token({ sub: 'user-1', exp: now })), now)
    ).toBe(undefined);
  });

  it('treats a token with no exp as unexpired (matching the guard)', () => {
    expect(verifiedUnexpiredSubjectFromBearer(bearer(token({ sub: 'user-1' })), now)).toBe(
      'user-1'
    );
  });

  it('rejects a token signed with a different secret regardless of expiry', () => {
    expect(
      verifiedUnexpiredSubjectFromBearer(
        bearer(token({ sub: 'victim', exp: now + 60 }, 'attacker-secret')),
        now
      )
    ).toBe(undefined);
  });
});
