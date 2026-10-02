import { describe, expect, it } from 'vitest';
import { byoSettings, emptySnapshot, TEST_ACCOUNT_ID } from '../testkit.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';
import { MAX_FRAGMENT_CHARS } from './protocol.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  DeviceRendezvousStep,
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
    EngineHandle: class {
      start = record('start');
      pushChunk = record('pushChunk');
      beginWrite = record('beginWrite');
      snapshot = record('snapshot', emptySnapshot());
      previewInviteLink = record('previewInviteLink', {
        scope: new Uint8Array([9]),
        names: null,
        permission: null,
        state: 'revoked',
        joined: false,
        listing: [],
      });
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

    await expect(host.read({ kind: 'snapshot', folder: null })).rejects.toMatchObject({
      code: 'notStarted',
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

  it('lists the vault root for the one folder that is not bytes', async () => {
    const { host, calls } = await permissiveHost();

    await host.read({ kind: 'snapshot', folder: null });

    expect(calls).toEqual([['snapshot', undefined]]);
  });

  it('refuses a snapshot of a folder that is not bytes', async () => {
    const { host, calls } = await permissiveHost();

    await expect(
      host.read({ kind: 'snapshot', folder: 'root' as unknown as Uint8Array })
    ).rejects.toThrow('invalid request field folder: string');
    await expect(
      host.read({ kind: 'snapshot', folder: undefined as unknown as Uint8Array })
    ).rejects.toThrow('invalid request field folder: undefined');
    expect(calls).toEqual([]);
  });

  it('previews the fragment verbatim and reads the preview back', async () => {
    const { host, calls } = await permissiveHost();

    await expect(host.read({ kind: 'invitePreview', fragment: 'abc-_' })).resolves.toEqual({
      scope: new Uint8Array([9]),
      names: null,
      permission: null,
      state: 'revoked',
      joined: false,
      listing: [],
    });
    expect(calls).toEqual([['previewInviteLink', 'abc-_']]);
  });

  it('refuses a preview fragment that is not text or is past the bound', async () => {
    const { host, calls } = await permissiveHost();

    await expect(
      host.read({ kind: 'invitePreview', fragment: 7 as unknown as string })
    ).rejects.toThrow('invalid request field fragment: number');
    await expect(
      host.read({ kind: 'invitePreview', fragment: 'x'.repeat(MAX_FRAGMENT_CHARS + 1) })
    ).rejects.toThrow('invalid request field fragment');
    expect(calls).toEqual([]);
  });

  it('refuses a download of a non-node', async () => {
    const { host, calls } = await permissiveHost();

    await expect(
      host.read({ kind: 'download', node: 'sixteen bytes!!!' as unknown as Uint8Array })
    ).rejects.toThrow('invalid request field node: string');
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
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }

      devices(): Promise<unknown[]> {
        return Promise.resolve([DEVICE_ROW, { ...DEVICE_ROW, id: '9a2b-uuid', label: null }]);
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

/** A wasm module whose rendezvous export records each step and answers `answer`. */
function rendezvousWasm(answer: (step: { kind: string }) => unknown = rendezvousAnswer): {
  wasm: EngineWasm;
  calls: unknown[];
} {
  const calls: unknown[] = [];
  const wasm = {
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }
    },
    // The step is snapshotted at the call, because the host scrubs the step it
    // was handed: recording the step itself would compare zeroes to zeroes.
    deviceRendezvous: (step: { kind: string }): unknown => {
      calls.push(structuredClone(step));
      return answer(step);
    },
  } as unknown as EngineWasm;
  return { wasm, calls };
}

function rendezvousAnswer(step: { kind: string }): unknown {
  switch (step.kind) {
    case 'open':
      return {
        kind: 'opened',
        ephemeralPublicKey: '02beef',
        requestPayload: Uint8Array.of(1, 2),
        comparisonValue: '482913',
      };
    case 'openFactor':
      return { kind: 'factor', factorKey: Uint8Array.of(7, 7) };
    default:
      return { kind: 'response', sealedFactor: null, payload: Uint8Array.of(4) };
  }
}

/**
 * Minted per use, never shared: a step's buffers are scrubbed by the host, so
 * one array reused across cases would leave every later case asserting zeroes.
 */
const scalarBytes = (): Uint8Array => new Uint8Array(32).fill(5);
const factorKeyBytes = (): Uint8Array => new Uint8Array(32).fill(6);

describe('EngineHost device reads', () => {
  it('reads the registry rows through, an unlabelled one included', async () => {
    const { host } = await deviceReadHost();

    await expect(host.read({ kind: 'devices' })).resolves.toEqual([
      { ...DEVICE_ROW },
      { ...DEVICE_ROW, id: '9a2b-uuid', label: null },
    ]);
  });

  it('reads the pending rows through with the digits each screen must show', async () => {
    const { host } = await deviceReadHost();

    await expect(host.read({ kind: 'pendingApprovals' })).resolves.toEqual([PENDING_ROW]);
  });

  it('names the device key the registration challenge is issued for', async () => {
    const { host, challenged } = await deviceReadHost();

    await expect(
      host.read({ kind: 'deviceRegistrationChallenge', devicePublicKey: 'ed25519hex' })
    ).resolves.toEqual(Uint8Array.of(9, 9));
    expect(challenged).toEqual(['ed25519hex']);
  });

  it('refuses a registration challenge for a key that is not a string', async () => {
    const { host, challenged } = await deviceReadHost();

    await expect(
      host.read({ kind: 'deviceRegistrationChallenge', devicePublicKey: 42 as unknown as string })
    ).rejects.toThrow('invalid request field devicePublicKey: number');
    expect(challenged).toEqual([]);
  });
});

/** A wasm module whose fingerprint free function records the key it was handed. */
function fingerprintWasm(): { wasm: EngineWasm; keys: Uint8Array[] } {
  const keys: Uint8Array[] = [];
  const wasm = {
    EngineHandle: class {
      start(): Promise<void> {
        return Promise.resolve();
      }
    },
    identityFingerprint: (identityPublicKey: Uint8Array): string => {
      keys.push(identityPublicKey);
      return 'e686 bdd6 b44e 05c4 4db0';
    },
  } as unknown as EngineWasm;
  return { wasm, keys };
}

describe('EngineHost identity fingerprint', () => {
  it('hands the key bytes to the wasm export and answers with its string', async () => {
    const { wasm, keys } = fingerprintWasm();
    const host = await started(wasm);
    const identityPublicKey = new Uint8Array(33).fill(2);

    await expect(host.read({ kind: 'identityFingerprint', identityPublicKey })).resolves.toBe(
      'e686 bdd6 b44e 05c4 4db0'
    );
    expect(keys).toEqual([identityPublicKey]);
  });

  it('refuses a key that is not bytes before the wasm export is reached', async () => {
    const { wasm, keys } = fingerprintWasm();
    const host = await started(wasm);

    await expect(
      host.read({ kind: 'identityFingerprint', identityPublicKey: '02ab' as unknown as Uint8Array })
    ).rejects.toThrow('invalid request field identityPublicKey: string');
    expect(keys).toEqual([]);
  });
});

describe('EngineHost device rendezvous', () => {
  const approve = (): DeviceRendezvousStep => ({
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
    const { wasm } = rendezvousWasm();
    const host = await started(wasm);
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
      step: { ...approve(), sealScalar, factorKey } as DeviceRendezvousStep,
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

  it('scrubs the step when the wasm export refuses it', async () => {
    const { wasm } = rendezvousWasm(() => {
      throw new Error('the rendezvous step does not decode');
    });
    const host = await started(wasm);
    const step = approve() as Extract<DeviceRendezvousStep, { kind: 'approve' }>;

    await expect(host.read({ kind: 'deviceRendezvous', step })).rejects.toThrow(
      'the rendezvous step does not decode'
    );
    expect(step.factorKey).toEqual(new Uint8Array(32));
    expect(step.sealScalar).toEqual(new Uint8Array(32));
  });

  it('hands the step to the wasm export and answers with its result', async () => {
    const { wasm, calls } = rendezvousWasm();
    const host = await started(wasm);

    await expect(host.read({ kind: 'deviceRendezvous', step: approve() })).resolves.toEqual({
      kind: 'response',
      sealedFactor: null,
      payload: Uint8Array.of(4),
    });
    expect(calls).toEqual([approve()]);
  });

  it('refuses a result kind this build does not know', async () => {
    const { wasm } = rendezvousWasm(() => ({ kind: 'bogus' }));
    const host = await started(wasm);

    await expect(host.read({ kind: 'deviceRendezvous', step: approve() })).rejects.toThrow(
      'unknown WASM rendezvous result kind: bogus'
    );
  });
});
