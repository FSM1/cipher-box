import { describe, expect, it } from 'vitest';
import { fakeWasmEnums } from '../testkit.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';
import type { WriteTarget } from './protocol.js';

/** The arguments one `EngineHandle` construction crossed the WASM boundary with. */
interface Constructed {
  seams: unknown;
  profile: unknown;
  apiBaseUrl: unknown;
  acceleratorBaseUrl: unknown;
  acceleratorBearer: unknown;
  publicGateways: unknown;
  storageHeadroomBytes: unknown;
}

/** A wasm module whose `EngineHandle` records what it was constructed with. */
function recordingWasm(): { wasm: EngineWasm; constructed: Constructed[] } {
  const constructed: Constructed[] = [];
  const wasm = {
    EngineHandle: class {
      constructor(
        seams: unknown,
        profile: unknown,
        apiBaseUrl: unknown,
        acceleratorBaseUrl: unknown,
        acceleratorBearer: unknown,
        publicGateways: unknown,
        storageHeadroomBytes: unknown
      ) {
        constructed.push({
          seams,
          profile,
          apiBaseUrl,
          acceleratorBaseUrl,
          acceleratorBearer,
          publicGateways,
          storageHeadroomBytes,
        });
      }
    },
  } as unknown as EngineWasm;
  return { wasm, constructed };
}

const emptyView = {
  root: new Uint8Array(16),
  folder: new Uint8Array(16),
  folderName: '',
  children: [],
  ancestors: [],
  deadLetters: [],
  retainedRecords: 0,
  staleness: fakeWasmEnums.Staleness.Fresh,
};

/**
 * A host over a wasm whose every call succeeds and records its arguments, so
 * only the host's own field checks can refuse a request.
 */
function permissiveHost(): { host: EngineHost; calls: unknown[][] } {
  const calls: unknown[][] = [];
  const record =
    (name: string, result: unknown = new Uint8Array(0)) =>
    (...args: unknown[]): Promise<unknown> => {
      calls.push([name, ...args]);
      return Promise.resolve(result);
    };
  const wasm = {
    ...fakeWasmEnums,
    EngineHandle: class {
      start = record('start');
      pushChunk = record('pushChunk');
      beginWrite = record('beginWrite');
      snapshot = record('snapshot', emptyView);
      download = record('download');
      openContentStream = record('openContentStream');
      readStream = record('readStream');
    },
    NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
  } as unknown as EngineWasm;
  return { host: new EngineHost(wasm, {}, { apiBaseUrl: 'https://api.example.test' }), calls };
}

/** A host whose WASM `pushChunk` hands the view it was given to `onPush`. */
function pushingHost(onPush: (chunk: Uint8Array) => Promise<void>): EngineHost {
  const wasm = {
    EngineHandle: class {
      pushChunk(_handle: bigint, chunk: Uint8Array): Promise<void> {
        return onPush(chunk);
      }
    },
  } as unknown as EngineWasm;
  return new EngineHost(wasm, {}, { apiBaseUrl: 'https://api.example.test' });
}

describe('EngineHost', () => {
  it('hands the engine the API base URL so cold start can log in', () => {
    const { wasm, constructed } = recordingWasm();

    new EngineHost(
      wasm,
      { seam: true },
      {
        apiBaseUrl: 'https://api.example.test',
        profile: 'ci',
        storageHeadroomBytes: 1024,
      }
    );

    expect(constructed[0]).toMatchObject({
      seams: { seam: true },
      profile: 'ci',
      apiBaseUrl: 'https://api.example.test',
      storageHeadroomBytes: 1024,
    });
  });

  it('forwards the content gateway configuration, bearerless', () => {
    const { wasm, constructed } = recordingWasm();

    new EngineHost(
      wasm,
      {},
      {
        apiBaseUrl: 'https://api.example.test',
        acceleratorBaseUrl: 'https://accelerator.example.test',
        publicGateways: ['https://gateway.example.test'],
      }
    );

    expect(constructed[0]).toMatchObject({
      acceleratorBaseUrl: 'https://accelerator.example.test',
      publicGateways: ['https://gateway.example.test'],
    });
    expect(constructed[0].acceleratorBearer).toBeUndefined();
  });

  it('leaves the gateway dormant when no endpoint is configured', () => {
    const { wasm, constructed } = recordingWasm();

    new EngineHost(wasm, {}, { apiBaseUrl: 'https://api.example.test' });

    expect(constructed[0].acceleratorBaseUrl).toBeUndefined();
    expect(constructed[0].publicGateways).toBeUndefined();
  });

  it('wipes the transferred upload chunk once WASM has copied it', async () => {
    const plaintext = Uint8Array.of(1, 2, 3, 4);
    let copied: Uint8Array | undefined;
    const host = pushingHost((chunk) => {
      copied = Uint8Array.from(chunk);
      return Promise.resolve();
    });

    await host.pushChunk(7n, plaintext.buffer as ArrayBuffer);

    expect(copied).toEqual(Uint8Array.of(1, 2, 3, 4));
    expect(plaintext).toEqual(new Uint8Array(4));
  });

  it('wipes the transferred upload chunk when the push rejects', async () => {
    const plaintext = Uint8Array.of(5, 6, 7, 8);
    const host = pushingHost(() => Promise.reject(new Error('staging full')));

    await expect(host.pushChunk(7n, plaintext.buffer as ArrayBuffer)).rejects.toThrow(
      'staging full'
    );

    expect(plaintext).toEqual(new Uint8Array(4));
  });
});

/** Untrusted request fields, refused rather than coerced (`invalidField`). */
describe('EngineHost request fields', () => {
  const node = new Uint8Array(16).fill(3);

  it('opens a write on well-typed fields', async () => {
    const { host, calls } = permissiveHost();

    await host.beginWrite({ parent: node, name: 'a.txt' }, 4);
    await host.beginWrite({ node }, 8);

    expect(calls[0]).toEqual(['beginWrite', { bytes: node }, 'a.txt', undefined, 4]);
    expect(calls[1]).toEqual(['beginWrite', undefined, undefined, { bytes: node }, 8]);
  });

  it('reads a stream window on well-typed bounds', async () => {
    const { host, calls } = permissiveHost();

    await host.readStream(7n, 0, 1024);

    expect(calls[0]).toEqual(['readStream', 7n, 0, 1024]);
  });

  it.each([
    ['a string parent', { parent: 'sixteen bytes!!!', name: 'a.txt' }, 4, 'parent: string'],
    ['a numeric name', { parent: node, name: 12345 }, 4, 'name: number'],
    ['a string node', { node: 'sixteen bytes!!!' }, 4, 'node: string'],
    ['a non-object target', 'a.txt', 4, 'target: string'],
    ['a null target', null, 4, 'target: null'],
    ['a string size', { node }, '4', 'size: string'],
    ['a NaN size', { node }, Number.NaN, 'size: number'],
    ['a fractional size', { node }, 1.5, 'size: number'],
    ['a negative size', { node }, -1, 'size: number'],
  ])('refuses a beginWrite carrying %s', async (_case, target, size, message) => {
    const { host, calls } = permissiveHost();

    await expect(host.beginWrite(target as WriteTarget, size as number)).rejects.toThrow(
      `invalid request field ${message}`
    );
    expect(calls).toEqual([]);
  });

  it('refuses a transferred payload that is not a buffer', async () => {
    const { host, calls } = permissiveHost();

    await expect(host.start('hunter2' as unknown as ArrayBuffer)).rejects.toThrow(
      'invalid request field secret: string'
    );
    // A view is not the transfer the wire declares, and `new Uint8Array(view)`
    // would copy it — leaving the sender's plaintext for the scrub to miss.
    await expect(host.pushChunk(7n, Uint8Array.of(1, 2) as unknown as ArrayBuffer)).rejects.toThrow(
      'invalid request field chunk: object'
    );
    expect(calls).toEqual([]);
  });

  it('lists the vault root for the one folder that is not bytes', async () => {
    const { host, calls } = permissiveHost();

    await host.snapshot(null);

    expect(calls).toEqual([['snapshot', undefined]]);
  });

  it('refuses a snapshot of a folder that is not bytes', async () => {
    const { host, calls } = permissiveHost();

    await expect(host.snapshot('root' as unknown as Uint8Array)).rejects.toThrow(
      'invalid request field folder: string'
    );
    await expect(host.snapshot(undefined as unknown as Uint8Array)).rejects.toThrow(
      'invalid request field folder: undefined'
    );
    expect(calls).toEqual([]);
  });

  it.each(['download', 'openContentStream'] as const)(
    'refuses a %s of a non-node',
    async (call) => {
      const { host, calls } = permissiveHost();

      await expect(host[call]('sixteen bytes!!!' as unknown as Uint8Array)).rejects.toThrow(
        'invalid request field node: string'
      );
      expect(calls).toEqual([]);
    }
  );

  it.each([
    ['offset', '0', 1024, 'offset: string'],
    ['offset', Number.NaN, 1024, 'offset: number'],
    ['length', 0, Number.POSITIVE_INFINITY, 'length: number'],
    ['length', 0, -1, 'length: number'],
  ])(
    'refuses a stream window whose %s is not a byte count',
    async (_field, offset, length, message) => {
      const { host, calls } = permissiveHost();

      await expect(host.readStream(7n, offset as number, length as number)).rejects.toThrow(
        `invalid request field ${message}`
      );
      expect(calls).toEqual([]);
    }
  );
});
