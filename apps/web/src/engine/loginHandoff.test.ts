import type { EngineClient } from '@cipherbox/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  LoginSecretSource,
  exportLoginSecret,
  handOffLoginSecret,
  type LoginSecretExporter,
} from './loginHandoff';

const SECRET_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const SECRET_BYTES = Uint8Array.from({ length: 32 }, (_, i) =>
  Number.parseInt(SECRET_HEX.slice(i * 2, i * 2 + 2), 16)
);

function exporter(key: string | Error): LoginSecretExporter {
  return {
    _UNSAFE_exportTssKey: () => (key instanceof Error ? Promise.reject(key) : Promise.resolve(key)),
  };
}

/** A client whose `start` transfers, exactly as `LocalTransport.postMessage` does. */
function transferringClient() {
  const received: ArrayBuffer[] = [];
  const client = {
    facade: {
      start(secret: ArrayBuffer) {
        received.push(secret);
        // structuredClone with a transfer list detaches the sender's buffer,
        // which is what `postMessage(msg, [secret])` does to it.
        structuredClone(secret, { transfer: [secret] });
        return Promise.resolve();
      },
    },
  } as unknown as EngineClient;
  return { client, received };
}

function rejectingClient(error: Error) {
  const seen: ArrayBuffer[] = [];
  const client = {
    facade: {
      start(secret: ArrayBuffer) {
        seen.push(secret);
        return Promise.reject(error);
      },
    },
  } as unknown as EngineClient;
  return { client, seen };
}

describe('exportLoginSecret', () => {
  it('decodes the Core Kit hex export, with or without the 0x prefix', async () => {
    expect(new Uint8Array(await exportLoginSecret(exporter(SECRET_HEX)))).toEqual(SECRET_BYTES);
    expect(new Uint8Array(await exportLoginSecret(exporter(`0x${SECRET_HEX}`)))).toEqual(
      SECRET_BYTES
    );
  });

  it('rejects a malformed export without echoing it', async () => {
    await expect(exportLoginSecret(exporter('nothex'))).rejects.toThrow(
      /^login secret export is not hex$/
    );
    await expect(exportLoginSecret(exporter(''))).rejects.toThrow(/^login secret export is empty$/);
  });
});

describe('handOffLoginSecret', () => {
  it('leaves the sender buffer detached after the transfer', async () => {
    const { client, received } = transferringClient();

    await handOffLoginSecret(client, exporter(SECRET_HEX));

    expect(received).toHaveLength(1);
    expect(received[0].byteLength).toBe(0);
  });

  it('zeroes the buffer when the engine never took it', async () => {
    const { client, seen } = rejectingClient(new Error('engine client closed'));

    await expect(handOffLoginSecret(client, exporter(SECRET_HEX))).rejects.toThrow(
      'engine client closed'
    );

    expect(seen[0].byteLength).toBe(32);
    expect(new Uint8Array(seen[0])).toEqual(new Uint8Array(32));
  });

  it('never starts the engine when the export fails', async () => {
    const { client, received } = transferringClient();

    await expect(
      handOffLoginSecret(client, exporter(new Error('core kit locked')))
    ).rejects.toThrow('core kit locked');

    expect(received).toEqual([]);
  });
});

describe('secret containment', () => {
  const consoleMethods = ['log', 'info', 'warn', 'error', 'debug'] as const;
  let logged: string[];

  beforeEach(() => {
    logged = [];
    for (const method of consoleMethods) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        logged.push(args.map((arg) => String(arg)).join(' '));
      });
    }
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => vi.restoreAllMocks());

  it('writes no secret to storage and logs none', async () => {
    const { client } = transferringClient();

    await handOffLoginSecret(client, exporter(SECRET_HEX));
    await new LoginSecretSource().provideSecret().catch(() => undefined);

    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(logged.join('\n')).not.toContain(SECRET_HEX);
  });

  it('keeps the secret out of a failure message', async () => {
    const { client } = rejectingClient(new Error('boom'));

    const failure = await handOffLoginSecret(client, exporter(SECRET_HEX)).catch(
      (error: unknown) => error
    );
    const malformed = await exportLoginSecret(exporter(`0x${SECRET_HEX}zz`)).catch(
      (error: unknown) => error
    );

    for (const error of [failure, malformed]) {
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toContain(SECRET_HEX);
      expect((error as Error).stack ?? '').not.toContain(SECRET_HEX);
    }
  });
});

describe('LoginSecretSource', () => {
  it('re-exports the secret for a failover promotion', async () => {
    const source = new LoginSecretSource();
    source.use(exporter(SECRET_HEX));

    expect(new Uint8Array(await source.provideSecret())).toEqual(SECRET_BYTES);
  });

  it('refuses to provide a secret with no live session', async () => {
    const source = new LoginSecretSource();
    await expect(source.provideSecret()).rejects.toThrow(/no login session/);

    source.use(exporter(SECRET_HEX));
    source.use(null);
    await expect(source.provideSecret()).rejects.toThrow(/no login session/);
  });
});
