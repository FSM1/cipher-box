import { handOffLoginSecret, type LoginFacade, type LoginSecretExporter } from '@cipherbox/login';
import { beforeEach, describe, expect, it } from 'vitest';
import { LoginSecretSource } from './loginHandoff';

const SECRET_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const SECRET_BYTES = Uint8Array.from({ length: 32 }, (_, i) =>
  Number.parseInt(SECRET_HEX.slice(i * 2, i * 2 + 2), 16)
);

function exporter(key: string, accountId = 'acct01'): LoginSecretExporter {
  return { _UNSAFE_exportTssKey: () => Promise.resolve(key), accountId: () => accountId };
}

/** `postMessage(msg, [secret])` detaches the sender's buffer; so does this. */
const facade: LoginFacade = {
  start(secret) {
    structuredClone(secret, { transfer: [secret] });
    return Promise.resolve();
  },
  logout: () => Promise.resolve(),
};

describe('LoginSecretSource', () => {
  it('re-exports the secret for a failover promotion', async () => {
    const source = new LoginSecretSource();
    source.use(exporter(SECRET_HEX));

    const { secret, accountId } = await source.provideSecret();
    expect(new Uint8Array(secret)).toEqual(SECRET_BYTES);
    expect(accountId).toBe('acct01');
  });

  it('refuses to provide a secret with no live session', async () => {
    const source = new LoginSecretSource();
    await expect(source.provideSecret()).rejects.toThrow(/no login session/);

    source.use(exporter(SECRET_HEX));
    source.use(null);
    await expect(source.provideSecret()).rejects.toThrow(/no login session/);
  });
});

describe('secret containment in the browser', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('writes no secret to origin storage', async () => {
    const source = new LoginSecretSource();
    source.use(exporter(SECRET_HEX));

    await handOffLoginSecret(facade, exporter(SECRET_HEX));
    const reExported = await source.provideSecret();

    expect(new Uint8Array(reExported.secret)).toEqual(SECRET_BYTES);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
