import { describe, expect, it } from 'vitest';
import { byoSettings, fakeWasmEnums, TEST_ACCOUNT_ID } from '../testkit.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm, WasmCommandOutcome } from './engineWasm.js';
import type { DeviceRendezvousStep, WriteTarget } from './protocol.js';

/** A second account on the same device — the lockout this namespacing prevents. */
const OTHER_ACCOUNT_ID = 'acct02';

/** The arguments one `EngineHandle` construction crossed the WASM boundary with. */
interface Constructed {
  seams: unknown;
  profile: unknown;
  apiBaseUrl: unknown;
  acceleratorBaseUrl: unknown;
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
        publicGateways: unknown,
        storageHeadroomBytes: unknown
      ) {
        constructed.push({
          seams,
          profile,
          apiBaseUrl,
          acceleratorBaseUrl,
          publicGateways,
          storageHeadroomBytes,
        });
      }

      start(): Promise<void> {
        return Promise.resolve();
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
/** A host whose engine is already built, as every call but `start` requires. */
async function started(wasm: EngineWasm): Promise<EngineHost> {
  const host = new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' });
  await host.start(new ArrayBuffer(32), TEST_ACCOUNT_ID);
  return host;
}

async function permissiveHost(): Promise<{ host: EngineHost; calls: unknown[][] }> {
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
  const host = await started(wasm);
  calls.length = 0;
  return { host, calls };
}

/** A host whose WASM `pushChunk` hands the view it was given to `onPush`. */
function pushingHost(onPush: (chunk: Uint8Array) => Promise<void>): Promise<EngineHost> {
  const wasm = {
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }

      pushChunk(_handle: bigint, chunk: Uint8Array): Promise<void> {
        return onPush(chunk);
      }
    },
  } as unknown as EngineWasm;
  return started(wasm);
}

describe('EngineHost', () => {
  it('builds no engine until a start names the account whose stores it opens', async () => {
    const { wasm, constructed } = recordingWasm();
    const named: string[] = [];
    const host = new EngineHost(
      wasm,
      (accountId) => {
        named.push(accountId);
        return { accountId };
      },
      { apiBaseUrl: 'https://api.example.test', profile: 'ci', storageHeadroomBytes: 1024 }
    );

    expect(constructed).toEqual([]);
    expect(named).toEqual([]);

    await host.start(new ArrayBuffer(32), TEST_ACCOUNT_ID);

    expect(named).toEqual([TEST_ACCOUNT_ID]);
    expect(constructed[0]).toMatchObject({
      seams: { accountId: TEST_ACCOUNT_ID },
      profile: 'ci',
      apiBaseUrl: 'https://api.example.test',
      storageHeadroomBytes: 1024,
    });
  });

  it('refuses every call until the engine has been started', async () => {
    const { wasm } = recordingWasm();
    const host = new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' });

    await expect(host.snapshot(null)).rejects.toMatchObject({ code: 'notStarted' });
  });

  it('scrubs a BYO bearer on a command it refuses before the codec is reached', async () => {
    const { wasm } = recordingWasm();
    const host = new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' });
    const bearer = new TextEncoder().encode('s3cret');

    // The bearer arrived transferred, so this realm holds the only copy — and
    // the codec that would scrub it never runs on a pre-start refusal.
    await expect(
      host.command({
        kind: 'saveVaultSettings',
        settings: byoSettings(bearer.buffer as ArrayBuffer),
      })
    ).rejects.toMatchObject({ code: 'notStarted' });

    expect([...bearer]).toEqual(new Array(bearer.length).fill(0));
  });

  it('refuses a second account rather than reopening the first account stores', async () => {
    const { wasm, constructed } = recordingWasm();
    const host = new EngineHost(wasm, (accountId) => ({ accountId }), {
      apiBaseUrl: 'https://api.example.test',
    });
    await host.start(new ArrayBuffer(32), TEST_ACCOUNT_ID);
    const secret = new Uint8Array(32).fill(9);

    await expect(host.start(secret.buffer as ArrayBuffer, OTHER_ACCOUNT_ID)).rejects.toMatchObject({
      code: 'alreadyStarted',
    });
    expect(constructed).toHaveLength(1);
    // The refused start left this frame the secret's terminal owner.
    expect(secret).toEqual(new Uint8Array(32));
  });

  // `EngineWasm` is hand-written, so a positional slot shift is invisible to
  // `tsc`; assert the trailing arguments together instead.
  it('forwards the content gateway configuration', async () => {
    const { wasm, constructed } = recordingWasm();

    await new EngineHost(wasm, () => ({}), {
      apiBaseUrl: 'https://api.example.test',
      acceleratorBaseUrl: 'https://accelerator.example.test',
      publicGateways: ['https://gateway.example.test'],
      storageHeadroomBytes: 2048,
    }).start(new ArrayBuffer(32), TEST_ACCOUNT_ID);

    expect(constructed[0]).toMatchObject({
      acceleratorBaseUrl: 'https://accelerator.example.test',
      publicGateways: ['https://gateway.example.test'],
      storageHeadroomBytes: 2048,
    });
  });

  it('leaves the gateway dormant when no endpoint is configured', async () => {
    const { wasm, constructed } = recordingWasm();

    await new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' }).start(
      new ArrayBuffer(32),
      TEST_ACCOUNT_ID
    );

    expect(constructed[0].acceleratorBaseUrl).toBeUndefined();
    expect(constructed[0].publicGateways).toBeUndefined();
  });

  it('wipes the transferred upload chunk once WASM has copied it', async () => {
    const plaintext = Uint8Array.of(1, 2, 3, 4);
    let copied: Uint8Array | undefined;
    const host = await pushingHost((chunk) => {
      copied = Uint8Array.from(chunk);
      return Promise.resolve();
    });

    await host.pushChunk(7n, plaintext.buffer as ArrayBuffer);

    expect(copied).toEqual(Uint8Array.of(1, 2, 3, 4));
    expect(plaintext).toEqual(new Uint8Array(4));
  });

  it('wipes the transferred upload chunk when the push rejects', async () => {
    const plaintext = Uint8Array.of(5, 6, 7, 8);
    const host = await pushingHost(() => Promise.reject(new Error('staging full')));

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
    const { host, calls } = await permissiveHost();

    const readAt = new Uint8Array([0xc1, 0xd0]);
    await host.beginWrite({ parent: node, name: 'a.txt' }, 4);
    await host.beginWrite({ node }, 8);
    await host.beginWrite({ node, expectedVersion: readAt }, 8);

    expect(calls[0]).toEqual(['beginWrite', { bytes: node }, 'a.txt', undefined, 4, undefined]);
    expect(calls[1]).toEqual(['beginWrite', undefined, undefined, { bytes: node }, 8, undefined]);
    expect(calls[2]).toEqual(['beginWrite', undefined, undefined, { bytes: node }, 8, readAt]);
  });

  it('reads a stream window on well-typed bounds', async () => {
    const { host, calls } = await permissiveHost();

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
    const { host, calls } = await permissiveHost();

    await expect(host.beginWrite(target as WriteTarget, size as number)).rejects.toThrow(
      `invalid request field ${message}`
    );
    expect(calls).toEqual([]);
  });

  it.each([
    ['pushChunk', (host: EngineHost) => host.pushChunk('7' as never, new ArrayBuffer(2))],
    ['commitWrite', (host: EngineHost) => host.commitWrite(7 as never)],
    ['abortWrite', (host: EngineHost) => host.abortWrite(null as never)],
    ['readStream', (host: EngineHost) => host.readStream('7' as never, 0, 8)],
    ['closeStream', (host: EngineHost) => host.closeStream(undefined as never)],
  ])('refuses a %s carrying a handle the engine never minted', async (_case, call) => {
    const { host, calls } = await permissiveHost();

    // A handle is a bigint the engine minted. The number ABI would coerce one
    // of another type into a plausible table index rather than refuse it.
    await expect(call(host)).rejects.toThrow('invalid request field handle');
    expect(calls).toEqual([]);
  });

  it('refuses a transferred payload that is not a buffer', async () => {
    const { host, calls } = await permissiveHost();

    await expect(host.start('hunter2' as unknown as ArrayBuffer, TEST_ACCOUNT_ID)).rejects.toThrow(
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
    const { host, calls } = await permissiveHost();

    await host.snapshot(null);

    expect(calls).toEqual([['snapshot', undefined]]);
  });

  it('refuses a snapshot of a folder that is not bytes', async () => {
    const { host, calls } = await permissiveHost();

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
      const { host, calls } = await permissiveHost();

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
      const { host, calls } = await permissiveHost();

      await expect(host.readStream(7n, offset as number, length as number)).rejects.toThrow(
        `invalid request field ${message}`
      );
      expect(calls).toEqual([]);
    }
  );
});

/** A wasm `CommandOutcome` that records whether the host released it. */
function outcomeHandle(fields: Record<string, unknown>): {
  outcome: WasmCommandOutcome;
  freed: () => number;
} {
  let frees = 0;
  const outcome = {
    ...fields,
    free: () => {
      frees += 1;
    },
  } as unknown as WasmCommandOutcome;
  return { outcome, freed: () => frees };
}

/** A host whose WASM `command` answers with `outcome`. */
function commandingHost(outcome: WasmCommandOutcome): Promise<EngineHost> {
  const wasm = {
    ...fakeWasmEnums,
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }

      command(): Promise<WasmCommandOutcome> {
        return Promise.resolve(outcome);
      }
    },
    Command: { manualRefresh: () => ({}), importContact: (code: Uint8Array) => ({ code }) },
    NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
  } as unknown as EngineWasm;
  return started(wasm);
}

describe('EngineHost command outcomes', () => {
  it('carries the imported contact keys back and releases the boundary object', async () => {
    const identityPublicKey = new Uint8Array(33).fill(2);
    const encPublicKey = new Uint8Array(32).fill(3);
    const { outcome, freed } = outcomeHandle({
      kind: 'contactImported',
      identityPublicKey,
      encPublicKey,
    });

    await expect(
      (await commandingHost(outcome)).command({
        kind: 'importContact',
        contactCode: new Uint8Array([1]),
      })
    ).resolves.toEqual({ kind: 'contactImported', identityPublicKey, encPublicKey });
    expect(freed()).toBe(1);
  });

  it('keeps the queued op id flowing', async () => {
    const { outcome, freed } = outcomeHandle({ kind: 'queued', opId: 9007199254740993n });

    await expect(
      (await commandingHost(outcome)).command({ kind: 'manualRefresh' })
    ).resolves.toEqual({
      kind: 'queued',
      opId: 9007199254740993n,
    });
    expect(freed()).toBe(1);
  });

  it('refuses an outcome missing the field its own kind names, still releasing it', async () => {
    const { outcome, freed } = outcomeHandle({ kind: 'queued' });

    await expect(
      (await commandingHost(outcome)).command({ kind: 'manualRefresh' })
    ).rejects.toThrow('command outcome queued carries no opId');
    expect(freed()).toBe(1);
  });

  it('carries the minted link fragment back and releases the boundary object', async () => {
    // A stand-in for the real fragment, which is the whole bearer capability.
    const fragment = 'placeholder-invite-fragment';
    const { outcome, freed } = outcomeHandle({ kind: 'inviteLinkMinted', fragment });

    await expect(
      (await commandingHost(outcome)).command({ kind: 'manualRefresh' })
    ).resolves.toEqual({ kind: 'inviteLinkMinted', fragment });
    expect(freed()).toBe(1);
  });

  it('refuses a minted link outcome carrying no fragment, still releasing it', async () => {
    const { outcome, freed } = outcomeHandle({ kind: 'inviteLinkMinted' });

    await expect(
      (await commandingHost(outcome)).command({ kind: 'manualRefresh' })
    ).rejects.toThrow('command outcome inviteLinkMinted carries no fragment');
    expect(freed()).toBe(1);
  });

  it('carries the forget residual back, and reads an unread ledger as null', async () => {
    const paid = outcomeHandle({
      kind: 'forgotten',
      unsettledBytes: 4096n,
      unsettledStalls: 2,
    });

    await expect(
      (await commandingHost(paid.outcome)).command({ kind: 'manualRefresh' })
    ).resolves.toEqual({ kind: 'forgotten', unsettledBytes: 4096, stalls: 2 });
    expect(paid.freed()).toBe(1);

    const unread = outcomeHandle({ kind: 'forgotten', unsettledStalls: 0 });

    await expect(
      (await commandingHost(unread.outcome)).command({ kind: 'manualRefresh' })
    ).resolves.toEqual({ kind: 'forgotten', unsettledBytes: null, stalls: 0 });
  });

  it('refuses an outcome kind this build does not know, still releasing it', async () => {
    const { outcome, freed } = outcomeHandle({ kind: 'teleported' });

    await expect(
      (await commandingHost(outcome)).command({ kind: 'manualRefresh' })
    ).rejects.toThrow('unknown command outcome teleported');
    expect(freed()).toBe(1);
  });
});

/** The device-registry rows the read host answers with. */
const DEVICE_ROW = {
  id: '7c1e-uuid',
  publicKey: 'ed25519hex',
  label: 'Work laptop',
  createdAt: '2026-08-27T10:00:00.000Z',
  lastSeenAt: '2026-08-27T11:00:00.000Z',
};

const PENDING_ROW = {
  requestId: 'req-1',
  requesterDevicePublicKey: 'ed25519hex',
  ephemeralPublicKey: '02beef',
  comparisonValue: '482913',
  createdAt: '2026-08-27T10:00:00.000Z',
  expiresAt: '2026-08-27T10:05:00.000Z',
};

/** A host whose engine answers the three device reads with fixed rows. */
function deviceReadHost(): Promise<{ host: EngineHost; challenged: string[] }> {
  const challenged: string[] = [];
  const wasm = {
    ...fakeWasmEnums,
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }

      devices(): Promise<unknown[]> {
        return Promise.resolve([DEVICE_ROW, { ...DEVICE_ROW, id: '9a2b-uuid', label: undefined }]);
      }

      pendingApprovals(): Promise<unknown[]> {
        return Promise.resolve([PENDING_ROW]);
      }

      deviceRegistrationChallenge(devicePublicKey: string): Promise<Uint8Array> {
        challenged.push(devicePublicKey);
        return Promise.resolve(Uint8Array.of(9, 9));
      }
    },
  } as unknown as EngineWasm;
  return started(wasm).then((host) => ({ host, challenged }));
}

/** A wasm module whose rendezvous free functions record what they were called with. */
function rendezvousWasm(): { wasm: EngineWasm; calls: unknown[][]; freed: () => number } {
  const calls: unknown[][] = [];
  let frees = 0;
  const releasable = (fields: Record<string, unknown>): unknown => ({
    ...fields,
    free: () => {
      frees += 1;
    },
  });
  // A buffer argument is snapshotted at the call, because the host scrubs the
  // step it was handed: recording the view itself would compare zeroes to
  // zeroes and assert nothing.
  const record =
    (name: string, answer: () => unknown) =>
    (...args: unknown[]): unknown => {
      calls.push([name, ...args.map((arg) => (arg instanceof Uint8Array ? arg.slice() : arg))]);
      return answer();
    };
  const wasm = {
    ...fakeWasmEnums,
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }
    },
    openDeviceRendezvous: record('openDeviceRendezvous', () =>
      releasable({
        ephemeralPublicKey: '02beef',
        requestPayload: Uint8Array.of(1, 2),
        comparisonValue: '482913',
      })
    ),
    approveDeviceRendezvous: record('approveDeviceRendezvous', () =>
      releasable({ sealedFactor: 'c2VhbA==', payload: Uint8Array.of(3) })
    ),
    denyDeviceRendezvous: record('denyDeviceRendezvous', () =>
      releasable({ sealedFactor: undefined, payload: Uint8Array.of(4) })
    ),
    openDeviceFactor: record('openDeviceFactor', () => Uint8Array.of(7, 7)),
  } as unknown as EngineWasm;
  return { wasm, calls, freed: () => frees };
}

/**
 * Minted per use, never shared: a step's buffers are scrubbed by the host, so
 * one array reused across cases would leave every later case asserting zeroes.
 */
const scalarBytes = (): Uint8Array => new Uint8Array(32).fill(5);
const factorKeyBytes = (): Uint8Array => new Uint8Array(32).fill(6);

describe('EngineHost device reads', () => {
  it('reads the registry rows through, and an absent label as null', async () => {
    const { host } = await deviceReadHost();

    await expect(host.devices()).resolves.toEqual([
      { ...DEVICE_ROW },
      { ...DEVICE_ROW, id: '9a2b-uuid', label: null },
    ]);
  });

  it('reads the pending rows through with the digits each screen must show', async () => {
    const { host } = await deviceReadHost();

    await expect(host.pendingApprovals()).resolves.toEqual([PENDING_ROW]);
  });

  it('names the device key the registration challenge is issued for', async () => {
    const { host, challenged } = await deviceReadHost();

    await expect(host.deviceRegistrationChallenge('ed25519hex')).resolves.toEqual(
      Uint8Array.of(9, 9)
    );
    expect(challenged).toEqual(['ed25519hex']);
  });

  it('refuses a registration challenge for a key that is not a string', async () => {
    const { host, challenged } = await deviceReadHost();

    await expect(host.deviceRegistrationChallenge(42 as unknown as string)).rejects.toThrow(
      'invalid request field devicePublicKey: number'
    );
    expect(challenged).toEqual([]);
  });
});

describe('EngineHost device rendezvous', () => {
  // Security rule 7: the realm that holds a copy erases it. The caller keeps
  // and erases its own, and a transferred buffer is already detached.
  it('scrubs the rendezvous scalar, the seal scalar and the factor key it was handed', async () => {
    const { wasm } = rendezvousWasm();
    const host = await started(wasm);
    const scalar = scalarBytes();
    const sealScalar = scalarBytes();
    const factorKey = factorKeyBytes();
    const factorScalar = scalarBytes();
    const zeros = (length: number) => new Uint8Array(length);

    await host.deviceRendezvous({ kind: 'open', devicePublicKey: 'ed25519hex', scalar });
    await host.deviceRendezvous({
      kind: 'approve',
      devicePublicKey: 'ed25519hex',
      requestId: 'req-1',
      requesterDevicePublicKey: 'reqhex',
      ephemeralPublicKey: '02beef',
      sealScalar,
      factorKey,
    });
    await host.deviceRendezvous({
      kind: 'openFactor',
      sealedFactor: 'c2VhbA==',
      requestId: 'req-1',
      requesterDevicePublicKey: 'reqhex',
      responderDevicePublicKey: 'apprhex',
      responseSignature: 'sighex',
      scalar: factorScalar,
    });

    expect(scalar).toEqual(zeros(scalar.length));
    expect(sealScalar).toEqual(zeros(sealScalar.length));
    expect(factorKey).toEqual(zeros(factorKey.length));
    expect(factorScalar).toEqual(zeros(factorScalar.length));
  });

  it.each([
    [
      'open',
      { kind: 'open', devicePublicKey: 'ed25519hex', scalar: scalarBytes() },
      ['openDeviceRendezvous', 'ed25519hex', scalarBytes()],
      {
        kind: 'opened',
        ephemeralPublicKey: '02beef',
        requestPayload: Uint8Array.of(1, 2),
        comparisonValue: '482913',
      },
    ],
    [
      'approve',
      {
        kind: 'approve',
        devicePublicKey: 'ed25519hex',
        requestId: 'req-1',
        requesterDevicePublicKey: 'reqhex',
        ephemeralPublicKey: '02beef',
        sealScalar: scalarBytes(),
        factorKey: factorKeyBytes(),
      },
      [
        'approveDeviceRendezvous',
        'ed25519hex',
        'req-1',
        'reqhex',
        '02beef',
        scalarBytes(),
        factorKeyBytes(),
      ],
      { kind: 'response', sealedFactor: 'c2VhbA==', payload: Uint8Array.of(3) },
    ],
    [
      'deny',
      {
        kind: 'deny',
        devicePublicKey: 'ed25519hex',
        requestId: 'req-1',
        ephemeralPublicKey: '02beef',
      },
      ['denyDeviceRendezvous', 'ed25519hex', 'req-1', '02beef'],
      { kind: 'response', sealedFactor: null, payload: Uint8Array.of(4) },
    ],
    [
      'openFactor',
      {
        kind: 'openFactor',
        sealedFactor: 'c2VhbA==',
        requestId: 'req-1',
        requesterDevicePublicKey: 'reqhex',
        responderDevicePublicKey: 'apprhex',
        responseSignature: 'sighex',
        scalar: scalarBytes(),
      },
      ['openDeviceFactor', 'c2VhbA==', 'req-1', 'reqhex', 'apprhex', 'sighex', scalarBytes()],
      { kind: 'factor', factorKey: Uint8Array.of(7, 7) },
    ],
  ] as const)(
    'runs the %s step against its own free function',
    async (_case, step, call, result) => {
      const { wasm, calls } = rendezvousWasm();
      const host = await started(wasm);

      await expect(host.deviceRendezvous(step as DeviceRendezvousStep)).resolves.toEqual(result);
      expect(calls).toEqual([call]);
    }
  );

  it('releases the boundary object each answering step mints', async () => {
    const { wasm, freed } = rendezvousWasm();
    const host = await started(wasm);

    await host.deviceRendezvous({
      kind: 'open',
      devicePublicKey: 'ed25519hex',
      scalar: scalarBytes(),
    });
    await host.deviceRendezvous({
      kind: 'deny',
      devicePublicKey: 'ed25519hex',
      requestId: 'req-1',
      ephemeralPublicKey: '02beef',
    });

    expect(freed()).toBe(2);
  });

  it.each([
    ['an unknown kind', { kind: 'bogus' }, 'unknown rendezvous step kind: bogus'],
    ['no shape at all', null, 'invalid request field step: null'],
    [
      'a numeric device key',
      { kind: 'open', devicePublicKey: 42, scalar: scalarBytes() },
      'invalid request field devicePublicKey: number',
    ],
    [
      'a string scalar',
      { kind: 'open', devicePublicKey: 'ed25519hex', scalar: 'thirty-two bytes' },
      'invalid request field scalar: string',
    ],
    [
      'a numeric factor key',
      {
        kind: 'approve',
        devicePublicKey: 'ed25519hex',
        requestId: 'req-1',
        requesterDevicePublicKey: 'reqhex',
        ephemeralPublicKey: '02beef',
        sealScalar: scalarBytes(),
        factorKey: 42,
      },
      'invalid request field factorKey: number',
    ],
  ])('refuses a step carrying %s', async (_case, step, message) => {
    const { wasm, calls } = rendezvousWasm();
    const host = await started(wasm);

    await expect(host.deviceRendezvous(step as unknown as DeviceRendezvousStep)).rejects.toThrow(
      message
    );
    expect(calls).toEqual([]);
  });
});
