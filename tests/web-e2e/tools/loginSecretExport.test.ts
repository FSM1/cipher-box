import { describe, expect, it } from 'vitest';
import {
  formatLoginSecret,
  parseInvocation,
  parseWalletKey,
  readConfig,
  renderOutput,
  UsageError,
  WALLET_KEY_ENV,
} from './loginSecretExport';

// Synthetic values only: none of these is, or derives, a real account.
const KEY = '11'.repeat(32);
const SECRET = 'ab'.repeat(32);
const SECP256K1_ORDER = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

const CONFIG_ENV = {
  VITE_API_URL: 'https://api.example.test/',
  E2E_BASE_URL: 'https://app.example.test/some/path',
  VITE_WEB3AUTH_CLIENT_ID: 'client-id',
  VITE_WEB3AUTH_VERIFIER: 'verifier',
};

/** Runs `act`, which must throw, and returns what it threw. */
function thrown(act: () => unknown): Error {
  try {
    act();
  } catch (failure) {
    return failure as Error;
  }
  throw new Error('expected a refusal');
}

describe('parseInvocation', () => {
  it('reads the key from the environment when the variable is set', () => {
    expect(parseInvocation([], { [WALLET_KEY_ENV]: KEY })).toEqual({
      kind: 'export',
      source: 'env',
    });
  });

  it('treats an empty variable as a key to check, never as a request to mint', () => {
    expect(parseInvocation([], { [WALLET_KEY_ENV]: '' })).toEqual({
      kind: 'export',
      source: 'env',
    });
  });

  it('mints only when the variable is absent', () => {
    expect(parseInvocation([], {})).toEqual({ kind: 'export', source: 'mint' });
  });

  it('reads standard input under --stdin', () => {
    expect(parseInvocation(['--stdin'], {})).toEqual({ kind: 'export', source: 'stdin' });
  });

  it('refuses two key sources at once', () => {
    expect(() => parseInvocation(['--stdin'], { [WALLET_KEY_ENV]: KEY })).toThrow(UsageError);
  });

  it('answers --help and -h', () => {
    expect(parseInvocation(['--help'], {})).toEqual({ kind: 'help' });
    expect(parseInvocation(['-h'], {})).toEqual({ kind: 'help' });
  });

  it('refuses an unknown argument without repeating it', () => {
    const failure = thrown(() => parseInvocation([KEY], {}));
    expect(failure).toBeInstanceOf(UsageError);
    expect(failure.message.includes(KEY), 'the refusal repeats its argument').toBe(false);
  });
});

describe('readConfig', () => {
  it('reads the four variables and trims the API URL and the origin', () => {
    expect(readConfig(CONFIG_ENV)).toEqual({
      apiUrl: 'https://api.example.test',
      siweOrigin: 'https://app.example.test',
      web3AuthClientId: 'client-id',
      verifier: 'verifier',
    });
  });

  it.each(Object.keys(CONFIG_ENV))('refuses a missing %s', (name) => {
    const env = { ...CONFIG_ENV, [name]: undefined };
    expect(() => readConfig(env)).toThrow(`${name} is not set`);
  });

  it('refuses a plain-http API', () => {
    expect(() => readConfig({ ...CONFIG_ENV, VITE_API_URL: 'http://api.example.test' })).toThrow(
      'VITE_API_URL must be an https: URL'
    );
  });

  it('refuses an origin that is not a URL', () => {
    expect(() => readConfig({ ...CONFIG_ENV, E2E_BASE_URL: 'app.example.test' })).toThrow(
      'E2E_BASE_URL is not a URL'
    );
  });
});

describe('parseWalletKey', () => {
  it('takes the key with or without the 0x prefix, and around whitespace', () => {
    expect(parseWalletKey(`0x${KEY}`)).toBe(`0x${KEY}`);
    expect(parseWalletKey(`${KEY}\n`)).toBe(`0x${KEY}`);
  });

  it('lowercases the hex', () => {
    expect(parseWalletKey(`0x${'AB'.repeat(32)}`)).toBe(`0x${'ab'.repeat(32)}`);
  });

  it.each([
    ['empty', ''],
    ['short', KEY.slice(2)],
    ['long', `${KEY}11`],
    ['non-hex', `${KEY.slice(2)}zz`],
    ['zero', '00'.repeat(32)],
    ['the curve order', SECP256K1_ORDER],
  ])('refuses a %s key without repeating it', (_, raw) => {
    const failure = thrown(() => parseWalletKey(raw));
    expect(failure).toBeInstanceOf(UsageError);
    if (raw.length > 0) {
      expect(failure.message.includes(raw), 'the refusal repeats the key').toBe(false);
    }
  });
});

describe('formatLoginSecret', () => {
  it('drops a 0x prefix and lowercases', () => {
    expect(formatLoginSecret(`0x${SECRET.toUpperCase()}`)).toBe(SECRET);
  });

  it.each([
    ['short', SECRET.slice(2)],
    ['non-hex', `${SECRET.slice(2)}zz`],
  ])('refuses a %s export without repeating it', (_, exported) => {
    const failure = thrown(() => formatLoginSecret(exported));
    expect(failure.message.includes(exported), 'the refusal repeats the export').toBe(false);
  });
});

describe('renderOutput', () => {
  it('prints an export as the bare secret on one line', () => {
    expect(renderOutput(SECRET)).toBe(`${SECRET}\n`);
  });

  it('prints a mint as both values under the 1Password field names', () => {
    expect(renderOutput(SECRET, `0x${KEY}`)).toBe(`walletKey=0x${KEY}\nloginSecret=${SECRET}\n`);
  });
});
