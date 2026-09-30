import { describe, expect, it } from 'vitest';
import { soakWalletKey, WALLET_KEY_ENV } from './accounts';

// Synthetic values only: none of these is, or derives, a real account.
const KEY = '22'.repeat(32);

describe('the soak accounts', () => {
  it('reads each role from its own variable', () => {
    const env = { [WALLET_KEY_ENV.owner]: KEY, [WALLET_KEY_ENV.grantee]: `0x${'33'.repeat(32)}` };
    expect(soakWalletKey(env, 'owner')).toBe(`0x${KEY}`);
    expect(soakWalletKey(env, 'grantee')).toBe(`0x${'33'.repeat(32)}`);
  });

  it.each(['owner', 'grantee'] as const)(
    'refuses a missing %s key rather than mint one',
    (role) => {
      expect(() => soakWalletKey({}, role)).toThrow(`${WALLET_KEY_ENV[role]} is not set`);
      expect(() => soakWalletKey({ [WALLET_KEY_ENV[role]]: ' ' }, role)).toThrow(/is not set/);
    }
  );

  it('refuses a malformed key without repeating it', () => {
    const raw = `${KEY}ff`;
    let message = '';
    try {
      soakWalletKey({ [WALLET_KEY_ENV.owner]: raw }, 'owner');
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/^SOAK_OWNER_WALLET_KEY: /);
    expect(message.includes(KEY)).toBe(false);
  });
});
