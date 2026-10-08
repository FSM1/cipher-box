import { describe, expect, it } from 'vitest';
import { byoSettings, emptySnapshot, TEST_ACCOUNT_ID } from '../testkit.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  DeviceRendezvousStep,
  ReadAnswer,
  ReadDescriptor,
  WriteTarget,
} from './protocol.js';

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

/**
 * A host over a wasm whose every call succeeds and records its arguments, so
 * only the host's own field checks can refuse a request.
 */
/** A host that no `start` has reached, so it has built no engine. */
function unstarted(wasm: EngineWasm): EngineHost {
  return new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' });
}

/** A host whose engine is already built, as every call but `start` requires. */
async function started(wasm: EngineWasm): Promise<EngineHost> {
  const host = unstarted(wasm);
  await host.start(new ArrayBuffer(32), TEST_ACCOUNT_ID);
  return host;
}

describe('EngineHost start', () => {
  it('hands the engine the identity token beside the secret', async () => {
    const calls: unknown[][] = [];
    const wasm = {
      EngineHandle: class {
        start(...args: unknown[]): Promise<void> {
          calls.push(args);
          return Promise.resolve();
        }
      },
      NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
    } as unknown as EngineWasm;
    const host = new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' });

    await host.start(new ArrayBuffer(32), TEST_ACCOUNT_ID, 'identity.jwt');

    expect(calls).toHaveLength(1);
    expect(calls[0][1]).toBe('identity.jwt');
  });
});

async function permissiveHost(): Promise<{ host: EngineHost; calls: unknown[][] }> {
  const calls: unknown[][] = [];
  const record =
    (name: string, result: unknown = new Uint8Array(0)) =>
    (...args: unknown[]): Promise<unknown> => {
      calls.push([name, ...args]);
      return Promise.resolve(result);
    };
  const wasm = {
    EngineHandle: class {
      start = record('start');
      pushChunk = record('pushChunk');
      beginWrite = record('beginWrite');
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

  it('scrubs a BYO bearer on a command it refuses before the engine is reached', async () => {
    const { wasm } = recordingWasm();
    const host = new EngineHost(wasm, () => ({}), { apiBaseUrl: 'https://api.example.test' });
    const bearer = new TextEncoder().encode('s3cret');

    // The bearer arrived transferred, so this realm holds the only copy.
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

  // The URL slots of the generated constructor share a type, so a positional
  // slot shift is invisible to `tsc`; assert the trailing arguments together.
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

  // The target is the engine's own `WriteTarget`, which the engine decodes.
  it('hands a write target to the engine as it arrived', async () => {
    const { host, calls } = await permissiveHost();

    const readAt = new Uint8Array([0xc1, 0xd0]);
    await host.beginWrite({ parent: node, name: 'a.txt' }, 4);
    await host.beginWrite({ node, expectedVersion: readAt }, 8);

    expect(calls).toEqual([
      ['beginWrite', { parent: node, name: 'a.txt' }, 4],
      ['beginWrite', { node, expectedVersion: readAt }, 8],
    ]);
  });

  it('reads a stream window on well-typed bounds', async () => {
    const { host, calls } = await permissiveHost();

    await host.readStream(7n, 0, 1024);

    expect(calls[0]).toEqual(['readStream', 7n, 0, 1024]);
  });

  it.each([
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

  it('refuses an openContentStream of a non-node', async () => {
    const { host, calls } = await permissiveHost();

    await expect(
      host.openContentStream('sixteen bytes!!!' as unknown as Uint8Array)
    ).rejects.toThrow('invalid request field node: string');
    expect(calls).toEqual([]);
  });

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

/** A host whose WASM `command` records what it was handed and answers with `answer`. */
function commandingHost(
  answer: (command: CommandDescriptor) => Promise<CommandOutcomeDescriptor>
): Promise<EngineHost> {
  const wasm = {
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }

      command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
        return answer(command);
      }
    },
  } as unknown as EngineWasm;
  return started(wasm);
}

describe('EngineHost commands', () => {
  it('hands the engine the command as it arrived and answers with its outcome', async () => {
    const handed: CommandDescriptor[] = [];
    const host = await commandingHost((command) => {
      handed.push(command);
      return Promise.resolve({ kind: 'queued', opId: 9007199254740993n });
    });
    const command: CommandDescriptor = { kind: 'cancelUpload', opId: 9007199254740993n };

    await expect(host.command(command)).resolves.toEqual({
      kind: 'queued',
      opId: 9007199254740993n,
    });
    expect(handed).toEqual([command]);
  });

  it('scrubs the transferred BYO bearer once the engine has taken it', async () => {
    const bearer = new TextEncoder().encode('s3cret');
    const seen: number[][] = [];
    const host = await commandingHost((command) => {
      const token = command.kind === 'saveVaultSettings' ? command.settings.byo?.accessToken : null;
      seen.push(token instanceof ArrayBuffer ? [...new Uint8Array(token)] : []);
      return Promise.resolve({ kind: 'done' });
    });

    await host.command({
      kind: 'saveVaultSettings',
      settings: byoSettings(bearer.buffer as ArrayBuffer),
    });

    expect(seen).toEqual([[...new TextEncoder().encode('s3cret')]]);
    expect([...bearer]).toEqual(new Array(bearer.length).fill(0));
  });

  it('scrubs the transferred BYO bearer before the command settles', async () => {
    const bearer = new TextEncoder().encode('s3cret');
    const host = await commandingHost(() => new Promise<CommandOutcomeDescriptor>(() => undefined));

    void host.command({
      kind: 'saveVaultSettings',
      settings: byoSettings(bearer.buffer as ArrayBuffer),
    });

    expect([...bearer]).toEqual(new Array(bearer.length).fill(0));
  });

  it('scrubs the transferred BYO bearer when the engine refuses the command', async () => {
    const bearer = new TextEncoder().encode('s3cret');
    const host = await commandingHost(() => Promise.reject(new Error('refused')));

    await expect(
      host.command({
        kind: 'saveVaultSettings',
        settings: byoSettings(bearer.buffer as ArrayBuffer),
      })
    ).rejects.toThrow('refused');

    expect([...bearer]).toEqual(new Array(bearer.length).fill(0));
  });
});

type ReadPath = 'engine' | 'unstarted';

/**
 * A wasm whose engine `read` and session-free `readUnstarted` record each read
 * and answer with `value`, under the read's own kind.
 */
function readingWasm(value: (read: ReadDescriptor) => Promise<unknown>): {
  wasm: EngineWasm;
  reads: [ReadPath, ReadDescriptor][];
} {
  const reads: [ReadPath, ReadDescriptor][] = [];
  // Snapshotted at the call, because the host scrubs the step it was handed:
  // recording the read itself would compare zeroes to zeroes.
  const serve =
    (path: ReadPath) =>
    (read: ReadDescriptor): Promise<ReadAnswer> => {
      reads.push([path, structuredClone(read)]);
      return value(read).then((answer) => ({ kind: read.kind, value: answer }) as ReadAnswer);
    };
  const wasm = {
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }

      read = serve('engine');
    },
    readUnstarted: serve('unstarted'),
  } as unknown as EngineWasm;
  return { wasm, reads };
}

/** A started host over {@link readingWasm}. */
async function startedReading(
  value: (read: ReadDescriptor) => Promise<unknown>
): Promise<{ host: EngineHost; reads: [ReadPath, ReadDescriptor][] }> {
  const { wasm, reads } = readingWasm(value);
  return { host: await started(wasm), reads };
}

describe('EngineHost reads', () => {
  it('serves a read before start from the session-free reads', async () => {
    const { wasm, reads } = readingWasm(() => Promise.resolve('e686 bdd6 b44e 05c4 4db0'));
    const identityPublicKey = new Uint8Array(33).fill(2);

    await expect(
      unstarted(wasm).read({ kind: 'identityFingerprint', identityPublicKey })
    ).resolves.toBe('e686 bdd6 b44e 05c4 4db0');
    expect(reads).toEqual([['unstarted', { kind: 'identityFingerprint', identityPublicKey }]]);
  });

  it('refuses an engine read before start as the session-free reads refuse it', async () => {
    const { wasm, reads } = readingWasm(() =>
      Promise.reject(Object.assign(new Error('engine not started'), { code: 'notStarted' }))
    );

    await expect(unstarted(wasm).read({ kind: 'snapshot', folder: null })).rejects.toMatchObject({
      code: 'notStarted',
    });
    expect(reads).toEqual([['unstarted', { kind: 'snapshot', folder: null }]]);
  });

  it('hands a read after start to the engine as it arrived', async () => {
    const { host, reads } = await startedReading(() => Promise.resolve(emptySnapshot()));

    await expect(host.read({ kind: 'snapshot', folder: null })).resolves.toEqual(emptySnapshot());
    expect(reads).toEqual([['engine', { kind: 'snapshot', folder: null }]]);
  });

  it('previews the fragment verbatim and reads the preview back', async () => {
    const preview = {
      scope: new Uint8Array([9]),
      names: null,
      permission: null,
      state: 'revoked',
      joined: false,
      listing: [],
    };
    const { host, reads } = await startedReading(() => Promise.resolve(preview));

    await expect(host.read({ kind: 'invitePreview', fragment: 'abc-_' })).resolves.toEqual(preview);
    expect(reads).toEqual([['engine', { kind: 'invitePreview', fragment: 'abc-_' }]]);
  });

  it.each([
    ['download', { kind: 'download', node: new Uint8Array(16) }],
    [
      'downloadVersion',
      { kind: 'downloadVersion', node: new Uint8Array(16), contentCid: Uint8Array.of(1) },
    ],
    ['deviceRegistrationChallenge', { kind: 'deviceRegistrationChallenge', devicePublicKey: 'k' }],
  ] as [string, ReadDescriptor][])(
    'answers a %s with a buffer of the same bytes',
    async (_kind, read) => {
      const { host } = await startedReading(() => Promise.resolve(Uint8Array.of(7, 8, 9)));

      const answer = await host.read(read);

      expect(answer).toBeInstanceOf(ArrayBuffer);
      expect(new Uint8Array(answer as ArrayBuffer)).toEqual(Uint8Array.of(7, 8, 9));
    }
  );

  it('answers a byte view with only the bytes it spans', async () => {
    const { host } = await startedReading(() =>
      Promise.resolve(Uint8Array.of(0, 1, 2, 3).subarray(1, 3))
    );

    const answer = await host.read({ kind: 'download', node: new Uint8Array(16) });

    expect(new Uint8Array(answer)).toEqual(Uint8Array.of(1, 2));
  });

  it('refuses a snapshot carrying a permission this build does not know', async () => {
    const { host } = await startedReading(() =>
      Promise.resolve({ ...emptySnapshot(), permission: 'admin' })
    );

    await expect(host.read({ kind: 'snapshot', folder: null })).rejects.toThrow(
      'unknown WASM permission: admin'
    );
  });
});

function rendezvousAnswer(read: ReadDescriptor): Promise<unknown> {
  const step = read.kind === 'deviceRendezvous' ? read.step : null;
  switch (step?.kind) {
    case 'open':
      return Promise.resolve({
        kind: 'opened',
        ephemeralPublicKey: '02beef',
        requestPayload: Uint8Array.of(1, 2),
        comparisonValue: '482913',
      });
    case 'openFactor':
      return Promise.resolve({ kind: 'factor', factorKey: Uint8Array.of(7, 7) });
    default:
      return Promise.resolve({ kind: 'response', sealedFactor: null, payload: Uint8Array.of(4) });
  }
}

/**
 * Minted per use, never shared: a step's buffers are scrubbed by the host, so
 * one array reused across cases would leave every later case asserting zeroes.
 */
const scalarBytes = (): Uint8Array => new Uint8Array(32).fill(5);
const factorKeyBytes = (): Uint8Array => new Uint8Array(32).fill(6);

describe('EngineHost device rendezvous', () => {
  const approve = (): Extract<DeviceRendezvousStep, { kind: 'approve' }> => ({
    kind: 'approve',
    devicePublicKey: 'ed25519hex',
    requestId: 'req-1',
    requesterDevicePublicKey: 'reqhex',
    ephemeralPublicKey: '02beef',
    sealScalar: scalarBytes(),
    factorKey: factorKeyBytes(),
  });

  // Security rule 7: the realm that holds a copy erases it. The caller keeps
  // and erases its own, and a transferred buffer is already detached.
  it('scrubs the rendezvous scalar, the seal scalar and the factor key it was handed', async () => {
    const { wasm } = readingWasm(rendezvousAnswer);
    const host = unstarted(wasm);
    const scalar = scalarBytes();
    const sealScalar = scalarBytes();
    const factorKey = factorKeyBytes();
    const factorScalar = scalarBytes();
    const zeros = (length: number) => new Uint8Array(length);

    await host.read({
      kind: 'deviceRendezvous',
      step: { kind: 'open', devicePublicKey: 'ed25519hex', scalar },
    });
    await host.read({
      kind: 'deviceRendezvous',
      step: { ...approve(), sealScalar, factorKey },
    });
    await host.read({
      kind: 'deviceRendezvous',
      step: {
        kind: 'openFactor',
        sealedFactor: 'c2VhbA==',
        requestId: 'req-1',
        requesterDevicePublicKey: 'reqhex',
        responderDevicePublicKey: 'apprhex',
        responseSignature: 'sighex',
        scalar: factorScalar,
      },
    });

    expect(scalar).toEqual(zeros(scalar.length));
    expect(sealScalar).toEqual(zeros(sealScalar.length));
    expect(factorKey).toEqual(zeros(factorKey.length));
    expect(factorScalar).toEqual(zeros(factorScalar.length));
  });

  it.each([
    [
      'throws',
      (): Promise<unknown> => {
        throw new Error('the rendezvous step does not decode');
      },
    ],
    ['rejects', () => Promise.reject(new Error('the rendezvous step does not decode'))],
  ])('scrubs the step when the wasm call %s', async (_case, value) => {
    const { host } = await startedReading(value);
    const step = approve();

    await expect(host.read({ kind: 'deviceRendezvous', step })).rejects.toThrow(
      'the rendezvous step does not decode'
    );
    expect(step.factorKey).toEqual(new Uint8Array(32));
    expect(step.sealScalar).toEqual(new Uint8Array(32));
  });

  it('hands the step to the wasm and answers with its result', async () => {
    const { host, reads } = await startedReading(rendezvousAnswer);

    await expect(host.read({ kind: 'deviceRendezvous', step: approve() })).resolves.toEqual({
      kind: 'response',
      sealedFactor: null,
      payload: Uint8Array.of(4),
    });
    expect(reads).toEqual([['engine', { kind: 'deviceRendezvous', step: approve() }]]);
  });

  it('refuses a result kind this build does not know', async () => {
    const { host } = await startedReading(() => Promise.resolve({ kind: 'bogus' }));

    await expect(host.read({ kind: 'deviceRendezvous', step: approve() })).rejects.toThrow(
      'unknown WASM rendezvous result kind: bogus'
    );
  });
});
