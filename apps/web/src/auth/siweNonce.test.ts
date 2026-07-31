import { afterEach, describe, expect, it, vi } from 'vitest';
import { requestSiweNonce } from './siweNonce';

function respond(body: unknown, status = 200) {
  const response = new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue(response);
}

describe('requestSiweNonce', () => {
  afterEach(() => vi.restoreAllMocks());

  it('posts to the API challenge endpoint and returns the nonce', async () => {
    const fetchSpy = respond({ nonce: 'abc12345', expiresAt: '2026-01-01T00:00:00.000Z' });

    await expect(requestSiweNonce('https://api.test')).resolves.toBe('abc12345');
    expect(fetchSpy).toHaveBeenCalledWith('https://api.test/auth/siwe/challenge', {
      method: 'POST',
    });
  });

  it('refuses a nonce too weak or too malformed to sign over', async () => {
    respond({ nonce: 'short' });
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);

    respond({ nonce: 'not a nonce!' });
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);

    respond({});
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/unusable nonce/);
  });

  it('surfaces a refused challenge by status', async () => {
    respond({ message: 'Too Many Requests' }, 429);
    await expect(requestSiweNonce('https://api.test')).rejects.toThrow(/refused with 429/);
  });
});
