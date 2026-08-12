import { collectedMethods } from '@cipherbox/login';
import { describe, expect, it } from 'vitest';
import { webCollector } from './webCollector';

describe('web credential collection', () => {
  it('offers every method a browser can collect', () => {
    expect(collectedMethods(webCollector('google-client-id'))).toEqual([
      'google',
      'email',
      'wallet',
    ]);
  });

  // The missing variable disables one method, never the session: a build
  // without it still logs in by email and wallet (`engine/config`).
  it('drops only google when the build carries no client ID', () => {
    expect(collectedMethods(webCollector(undefined))).toEqual(['email', 'wallet']);
  });

  it('passes the material the page already collected straight through', async () => {
    const collector = webCollector('google-client-id');
    const proof = { message: 'siwe-message', signature: '0xabc' };

    await expect(collector.google?.('google.id.token')).resolves.toBe('google.id.token');
    await expect(collector.wallet?.(proof)).resolves.toBe(proof);
  });
});
