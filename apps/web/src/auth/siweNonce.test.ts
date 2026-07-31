import { afterEach, describe, expect, it, vi } from 'vitest';
import { requestSiweNonce } from './siweNonce';

// A fresh Response per call: a body can only be read once.
function respond(body: unknown, status = 200) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      })
    )
  );
}

describe('requestSiweNonce', () => {
  afterEach(() => vi.restoreAllMocks());

  it('posts to the API challenge endpoint under a timeout and returns the nonce', async () => {
    const fetchSpy = respond({ nonce: 'abc12345', expiresAt: '2026-01-01T00:00:00.000Z' });

    await expect(requestSiweNonce('https://api.test')).resolves.toBe('abc12345');

    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toBe('https://api.test/auth/siwe/challenge');
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });

  it('resolves the endpoint against a base with a path or a trailing slash', async () => {
    const fetchSpy = respond({ nonce: 'abc12345' });

    await requestSiweNonce('https://api.test/');
    await requestSiweNonce('https://api.test/ignored');

    for (const [url] of fetchSpy.mock.calls) {
      expect(String(url)).toBe('https://api.test/auth/siwe/challenge');
    }
  });

  it('refuses a nonce too weak, too long, or too malformed to sign over', async () => {
    respond({ nonce: 'short' });
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);

    respond({ nonce: 'not a nonce!' });
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);

    // A hostile API must not push an unbounded string into the signing prompt.
    respond({ nonce: 'a'.repeat(129) });
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);

    respond({});
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);
  });

  it('surfaces a refused challenge by status, without echoing its body', async () => {
    respond({ message: '<script>alert(1)</script>' }, 429);
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(
      /^siwe challenge refused with 429$/
    );
  });
});
