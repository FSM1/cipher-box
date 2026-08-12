import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  exportLoginSecret,
  handOffLoginSecret,
  type LoginFacade,
  type LoginSecretExporter,
} from './secret';

const SECRET_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const SECRET_BYTES = Uint8Array.from({ length: 32 }, (_, i) =>
  Number.parseInt(SECRET_HEX.slice(i * 2, i * 2 + 2), 16)
);

function exporter(key: string | Error): LoginSecretExporter {
  return {
    _UNSAFE_exportTssKey: () => (key instanceof Error ? Promise.reject(key) : Promise.resolve(key)),
  };
}

/** A facade whose `start` behaviour the test scripts; records what it was handed. */
function fakeFacade(start: (secret: ArrayBuffer) => Promise<void>) {
  const received: ArrayBuffer[] = [];
  const facade: LoginFacade = {
    start(secret) {
      received.push(secret);
      return start(secret);
    },
    logout: () => Promise.resolve(),
  };
  return { facade, received };
}

/** `postMessage(msg, [secret])` detaches the sender's buffer; so does this. */
const transferring = (secret: ArrayBuffer): Promise<void> => {
  structuredClone(secret, { transfer: [secret] });
  return Promise.resolve();
};

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
    await expect(exportLoginSecret(exporter(''))).rejects.toThrow(/32-byte scalar/);
    // Short of a full secp256k1 scalar: rejected here, not after a transfer.
    await expect(exportLoginSecret(exporter(SECRET_HEX.slice(2)))).rejects.toThrow(
      /32-byte scalar/
    );
  });
});

describe('handOffLoginSecret', () => {
  it('hands the engine the exported secret', async () => {
    const seen: number[] = [];
    const { facade } = fakeFacade((secret) => {
      seen.push(...new Uint8Array(secret));
      return transferring(secret);
    });

    await handOffLoginSecret(facade, exporter(SECRET_HEX));

    expect(Uint8Array.from(seen)).toEqual(SECRET_BYTES);
  });

  it('tolerates the buffer the transport already detached', async () => {
    const { facade, received } = fakeFacade(transferring);

    await handOffLoginSecret(facade, exporter(SECRET_HEX));

    // Post-transfer the buffer is neutered, so the `finally` must not re-view it.
    expect(received[0].byteLength).toBe(0);
  });

  it('zeroes the buffer when the engine never took it', async () => {
    const { facade, received } = fakeFacade(() =>
      Promise.reject(new Error('engine client closed'))
    );

    await expect(handOffLoginSecret(facade, exporter(SECRET_HEX))).rejects.toThrow(
      'engine client closed'
    );

    expect(received[0].byteLength).toBe(32);
    expect(new Uint8Array(received[0])).toEqual(new Uint8Array(32));
  });

  it('zeroes the buffer when start throws synchronously', async () => {
    const { facade, received } = fakeFacade(() => {
      throw new Error('transport gone');
    });

    await expect(handOffLoginSecret(facade, exporter(SECRET_HEX))).rejects.toThrow(
      'transport gone'
    );

    expect(new Uint8Array(received[0])).toEqual(new Uint8Array(32));
  });

  it('never starts the engine when the export fails', async () => {
    const { facade, received } = fakeFacade(transferring);

    await expect(
      handOffLoginSecret(facade, exporter(new Error('core kit locked')))
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
  });

  afterEach(() => vi.restoreAllMocks());

  it('logs nothing at all, so no encoding of the secret can reach a log', async () => {
    const { facade } = fakeFacade(transferring);

    await handOffLoginSecret(facade, exporter(SECRET_HEX));

    expect(logged).toEqual([]);
  });

  it('parks no copy of the secret in the realm-global RegExp statics', async () => {
    const { facade } = fakeFacade(transferring);
    /(sentinel)/.exec('sentinel');

    await handOffLoginSecret(facade, exporter(SECRET_HEX));

    expect(RegExp.input).toBe('sentinel');
    expect(RegExp.lastMatch).toBe('sentinel');
  });

  it('keeps the secret out of a failure message, in any encoding', async () => {
    const { facade } = fakeFacade(() => Promise.reject(new Error('boom')));

    const failure = await handOffLoginSecret(facade, exporter(SECRET_HEX)).catch(
      (error: unknown) => error
    );
    const malformed = await exportLoginSecret(exporter(`0x${SECRET_HEX}zz`)).catch(
      (error: unknown) => error
    );

    const decimal = [...SECRET_BYTES].join(',');
    for (const error of [failure, malformed]) {
      expect(error).toBeInstanceOf(Error);
      const text = `${String(error)}\n${(error as Error).stack ?? ''}`;
      expect(text).not.toContain(SECRET_HEX);
      expect(text).not.toContain(SECRET_HEX.toUpperCase());
      expect(text).not.toContain(decimal);
    }
  });
});
