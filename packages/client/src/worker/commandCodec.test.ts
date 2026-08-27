import { describe, expect, it } from 'vitest';

import { fakeWasmEnums } from '../testkit.js';
import {
  buildCommand,
  readAuthMethods,
  readEvent,
  readReceivedShare,
  readSharing,
  readSnapshot,
  readVaultStorage,
} from './commandCodec.js';
import type { CommandDescriptor } from './protocol.js';
import type {
  EngineWasm,
  WasmEvent,
  WasmSnapshotView,
  WasmVaultStorageView,
} from './engineWasm.js';

/**
 * A structural stand-in for the wasm-bindgen namespace: only the mirror-enum
 * value tables the codec's read paths consult.
 */
const fakeWasm = fakeWasmEnums as unknown as EngineWasm;

describe('buildCommand', () => {
  it('builds a create from parent, name and kind alone — no content argument', () => {
    const calls: unknown[][] = [];
    const wasm = {
      ...fakeWasmEnums,
      NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
      Command: {
        create: (...args: unknown[]) => {
          calls.push(args);
          return {};
        },
      },
    } as unknown as EngineWasm;

    buildCommand(wasm, {
      kind: 'create',
      parent: new Uint8Array(16).fill(1),
      name: 'a.txt',
      nodeKind: 'file',
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toHaveLength(3);
    expect(calls[0][0]).toEqual({ bytes: new Uint8Array(16).fill(1) });
    expect(calls[0][1]).toBe('a.txt');
    expect(calls[0][2]).toBe(fakeWasmEnums.NodeKind.File);
  });

  it('passes an upload cancel through as the bigint op id, not a number', () => {
    const calls: unknown[][] = [];
    const wasm = {
      ...fakeWasmEnums,
      Command: {
        cancelUpload: (...args: unknown[]) => {
          calls.push(args);
          return {};
        },
      },
    } as unknown as EngineWasm;

    buildCommand(wasm, { kind: 'cancelUpload', opId: 2n ** 60n });

    expect(calls).toEqual([[2n ** 60n]]);
  });

  it('maps the second literal of each mirror enum, not just the first', () => {
    const calls: unknown[][] = [];
    const record = (...args: unknown[]): object => {
      calls.push(args);
      return {};
    };
    const wasm = {
      ...fakeWasmEnums,
      NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
      Command: { create: record, createInviteLink: record },
    } as unknown as EngineWasm;

    buildCommand(wasm, {
      kind: 'create',
      parent: new Uint8Array(16),
      name: 'docs',
      nodeKind: 'folder',
    });
    buildCommand(wasm, {
      kind: 'createInviteLink',
      node: new Uint8Array(16),
      permission: 'write',
      expiresAt: null,
    });

    expect(calls[0][2]).toBe(fakeWasmEnums.NodeKind.Folder);
    expect(calls[1][1]).toBe(fakeWasmEnums.Permission.Write);
  });

  /** Every builder succeeds, so only the codec's own checks can reject. */
  const permissiveWasm = {
    ...fakeWasmEnums,
    NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
    Command: new Proxy({}, { get: () => () => ({}) }),
  } as unknown as EngineWasm;

  const refuses =
    (descriptor: unknown): (() => unknown) =>
    () =>
      buildCommand(permissiveWasm, descriptor as CommandDescriptor);

  /** An erase routed to the logout beside it would silently keep the seams. */
  it('routes each zero-argument command to the builder of its own name', () => {
    const built: string[] = [];
    const wasm = {
      ...fakeWasmEnums,
      Command: new Proxy({}, { get: (_target, name: string) => () => built.push(name) }),
    } as unknown as EngineWasm;

    buildCommand(wasm, { kind: 'forgetDevice' });
    buildCommand(wasm, { kind: 'logout' });
    buildCommand(wasm, { kind: 'manualRefresh' });

    expect(built).toEqual(['forgetDevice', 'logout', 'manualRefresh']);
  });

  it('fails closed on an unknown command kind', () => {
    expect(refuses({ kind: 'telepathy' })).toThrow('unknown command kind: telepathy');
  });

  it('refuses an envelope that is not a command before it reads a kind off it', () => {
    // A non-object answers `undefined` for every field, so without this the
    // refusal is a TypeError on null, or an unknown-kind error naming
    // `undefined` — neither of which tells a peer which field was wrong.
    expect(refuses(null)).toThrow('invalid request field command: null');
    expect(refuses(42)).toThrow('invalid request field command: number');
    expect(refuses('rename')).toThrow('invalid request field command: string');
    expect(refuses({ kind: 12345 })).toThrow('invalid request field command.kind: number');
    expect(refuses({})).toThrow('invalid request field command.kind: undefined');
  });

  it('rejects a wrong-typed string field rather than letting wasm-bindgen coerce it', () => {
    expect(refuses({ kind: 'rename', node: new Uint8Array(16), newName: 12345 })).toThrow(
      'invalid request field newName: number'
    );
    expect(
      refuses({ kind: 'create', parent: new Uint8Array(16), name: null, nodeKind: 'file' })
    ).toThrow('invalid request field name: null');
  });

  it('rejects a wrong-typed byte-array field', () => {
    expect(
      refuses({
        kind: 'grant',
        node: new Uint8Array(16),
        recipientIdentityPublicKey: 'deadbeef',
        permission: 'read',
      })
    ).toThrow('invalid request field recipientIdentityPublicKey: string');
    expect(refuses({ kind: 'delete', node: [1, 2, 3] })).toThrow('invalid request field node');
  });

  it('rejects an unknown node kind or permission rather than defaulting one', () => {
    expect(
      refuses({ kind: 'create', parent: new Uint8Array(16), name: 'a', nodeKind: 'symlink' })
    ).toThrow('invalid request field nodeKind: string');
    expect(
      refuses({ kind: 'createInviteLink', node: new Uint8Array(16), permission: 'admin' })
    ).toThrow('invalid request field permission: string');
  });

  it('rejects an op id that is not the engine bigint', () => {
    expect(refuses({ kind: 'cancelUpload', opId: 7 })).toThrow(
      'invalid request field opId: number'
    );
  });

  describe('invite links', () => {
    /** Stands in for a real fragment, which is a bearer capability. */
    const FRAGMENT = 'placeholder-invite-fragment';
    const node = new Uint8Array(16).fill(7);

    /**
     * Records every builder call by name, whichever builder the arm reaches
     * for. `NodeId.fromBytes` records too: minting a handle is what a refusal
     * after it would strand, so the guard against that has to see the call.
     */
    const spyWasm = (): { wasm: EngineWasm; calls: Record<string, unknown[][]> } => {
      const calls: Record<string, unknown[][]> = {};
      const wasm = {
        ...fakeWasmEnums,
        NodeId: {
          fromBytes: (bytes: Uint8Array) => {
            (calls.NodeId ??= []).push([bytes]);
            return { bytes };
          },
        },
        Command: new Proxy(
          {},
          {
            get:
              (_target, name: string) =>
              (...args: unknown[]): object => {
                (calls[name] ??= []).push(args);
                return {};
              },
          }
        ),
      } as unknown as EngineWasm;
      return { wasm, calls };
    };

    it('carries the link deadline through as the engine bigint', () => {
      const { wasm, calls } = spyWasm();

      buildCommand(wasm, {
        kind: 'createInviteLink',
        node,
        permission: 'read',
        expiresAt: 1_800_000_000_000n,
      });

      expect(calls.createInviteLink).toEqual([
        [{ bytes: node }, fakeWasmEnums.Permission.Read, 1_800_000_000_000n],
      ]);
    });

    it('spells an absent link deadline as undefined, never as null', () => {
      const { wasm, calls } = spyWasm();

      buildCommand(wasm, {
        kind: 'createInviteLink',
        node,
        permission: 'write',
        expiresAt: null,
      });

      expect(calls.createInviteLink).toEqual([
        [{ bytes: node }, fakeWasmEnums.Permission.Write, undefined],
      ]);
    });

    it.each(['revokeInviteLink', 'pruneInviteLinks', 'convertInviteClaims'] as const)(
      'builds a %s from the node alone',
      (kind) => {
        const { wasm, calls } = spyWasm();

        buildCommand(wasm, { kind, node });

        expect(calls[kind]).toEqual([[{ bytes: node }]]);
      }
    );

    it('hands the claim its URL fragment verbatim, as the one argument', () => {
      const { wasm, calls } = spyWasm();

      buildCommand(wasm, { kind: 'claimInviteLink', fragment: FRAGMENT });

      expect(calls.claimInviteLink).toEqual([[FRAGMENT]]);
    });

    it('rejects a link deadline that is not the engine bigint', () => {
      expect(
        refuses({
          kind: 'createInviteLink',
          node,
          permission: 'read',
          expiresAt: 1_800_000_000_000,
        })
      ).toThrow('invalid request field expiresAt: number');
      expect(
        refuses({ kind: 'createInviteLink', node, permission: 'read', expiresAt: '2030' })
      ).toThrow('invalid request field expiresAt: string');
    });

    it.each([0n, -1n, 2n ** 64n])(
      'rejects the out-of-range link deadline %s the engine would refuse',
      (expiresAt) => {
        const { wasm, calls } = spyWasm();

        expect(() =>
          buildCommand(wasm, { kind: 'createInviteLink', node, permission: 'read', expiresAt })
        ).toThrow('invalid request field expiresAt: bigint');
        // Refused before the node was minted, so no wasm handle is stranded.
        expect(calls.NodeId).toBeUndefined();
        expect(calls.createInviteLink).toBeUndefined();
      }
    );

    it('refuses a fragment past the length a real one can reach', () => {
      const { wasm, calls } = spyWasm();

      expect(() =>
        buildCommand(wasm, { kind: 'claimInviteLink', fragment: 'A'.repeat(4097) })
      ).toThrow('invalid request field fragment: string');
      expect(calls.claimInviteLink).toBeUndefined();
    });

    it('rejects a claim fragment that is not a string', () => {
      expect(refuses({ kind: 'claimInviteLink', fragment: 12345 })).toThrow(
        'invalid request field fragment: number'
      );
      expect(refuses({ kind: 'claimInviteLink', fragment: null })).toThrow(
        'invalid request field fragment: null'
      );
    });

    it.each(['revokeInviteLink', 'pruneInviteLinks', 'convertInviteClaims'] as const)(
      'rejects a %s whose node is not bytes',
      (kind) => {
        expect(refuses({ kind, node: 'sixteen bytes!!!' })).toThrow(
          'invalid request field node: string'
        );
      }
    );
  });

  describe('saveVaultSettings', () => {
    /** A fresh bearer, since the codec scrubs the view it is handed. */
    const tokenBytes = (): Uint8Array => new TextEncoder().encode('s3cret');
    /** The bearer as it crosses the boundary: transferred, so an `ArrayBuffer`. */
    const token = (): ArrayBuffer => tokenBytes().buffer as ArrayBuffer;

    /** Records builder args, copying byte views before the codec scrubs them. */
    const spyWasm = (): { wasm: EngineWasm; byo: unknown[][]; settings: unknown[][] } => {
      const byo: unknown[][] = [];
      const settings: unknown[][] = [];
      const wasm = {
        ...fakeWasmEnums,
        ByoIpfsConfig: class {
          constructor(...args: unknown[]) {
            byo.push(args.map((arg) => (arg instanceof Uint8Array ? new Uint8Array(arg) : arg)));
          }
        },
        VaultSettings: class {
          constructor(...args: unknown[]) {
            settings.push(args);
          }
        },
        Command: { saveVaultSettings: (value: unknown) => ({ value }) },
      } as unknown as EngineWasm;
      return { wasm, byo, settings };
    };

    it('carries the provider config and the retention count through', () => {
      const { wasm, byo, settings } = spyWasm();

      buildCommand(wasm, {
        kind: 'saveVaultSettings',
        settings: {
          pinMode: 'dual',
          byo: { endpoint: 'https://kubo.example', kind: 'pinata', accessToken: token() },
          keepLatestVersions: 3,
        },
      });

      expect(byo).toEqual([['https://kubo.example', fakeWasmEnums.ByoKind.Pinata, tokenBytes()]]);
      expect(settings).toHaveLength(1);
      expect(settings[0][0]).toBe(fakeWasmEnums.PinMode.Dual);
      expect(settings[0][2]).toBe(3);
    });

    it('spells an absent provider and an absent retention cap as undefined', () => {
      const { wasm, byo, settings } = spyWasm();

      buildCommand(wasm, {
        kind: 'saveVaultSettings',
        settings: { pinMode: 'hosted', byo: null, keepLatestVersions: null },
      });

      expect(byo).toEqual([]);
      expect(settings[0][1]).toBeUndefined();
      expect(settings[0][2]).toBeUndefined();
    });

    it('spells a null credential as absent, never as the string "null"', () => {
      const { wasm, byo } = spyWasm();

      buildCommand(wasm, {
        kind: 'saveVaultSettings',
        settings: {
          pinMode: 'external',
          byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: null },
          keepLatestVersions: null,
        },
      });

      expect(byo).toEqual([['https://kubo.example', fakeWasmEnums.ByoKind.Kubo, undefined]]);
    });

    it('scrubs the worker copy of the bearer once the builder holds it', () => {
      const { wasm } = spyWasm();
      const bearer = token();

      buildCommand(wasm, {
        kind: 'saveVaultSettings',
        settings: {
          pinMode: 'dual',
          byo: { endpoint: 'https://kubo.example', kind: 'pinata', accessToken: bearer },
          keepLatestVersions: null,
        },
      });

      expect([...new Uint8Array(bearer)]).toEqual(new Array(bearer.byteLength).fill(0));
    });

    it('scrubs the bearer even when the builder refuses', () => {
      const { wasm } = spyWasm();
      const bearer = token();
      (wasm as { ByoIpfsConfig: unknown }).ByoIpfsConfig = class {
        constructor() {
          throw new Error('accessToken must be a sendable bearer');
        }
      };

      expect(() =>
        buildCommand(wasm, {
          kind: 'saveVaultSettings',
          settings: {
            pinMode: 'dual',
            byo: { endpoint: 'https://kubo.example', kind: 'pinata', accessToken: bearer },
            keepLatestVersions: null,
          },
        })
      ).toThrow('accessToken must be a sendable bearer');
      expect([...new Uint8Array(bearer)]).toEqual(new Array(bearer.byteLength).fill(0));
    });

    it('scrubs the bearer when a refusal lands before the provider is built', () => {
      const { wasm, byo } = spyWasm();
      const bearer = token();

      // `pinMode` and the retention cap are checked first, so these refusals
      // never reach the builder that would otherwise spend the bearer.
      for (const settings of [
        { pinMode: 'nowhere', keepLatestVersions: null },
        { pinMode: 'hosted', keepLatestVersions: 0 },
      ]) {
        new Uint8Array(bearer).set(tokenBytes());
        expect(() =>
          buildCommand(wasm, {
            kind: 'saveVaultSettings',
            settings: {
              ...settings,
              byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: bearer },
            },
          } as unknown as CommandDescriptor)
        ).toThrow();
        expect([...new Uint8Array(bearer)]).toEqual(new Array(bearer.byteLength).fill(0));
      }
      expect(byo).toEqual([]);
    });

    it('refuses a bearer sent as a string, which no owner could scrub', () => {
      const { wasm, byo } = spyWasm();

      expect(() =>
        buildCommand(wasm, {
          kind: 'saveVaultSettings',
          settings: {
            pinMode: 'dual',
            byo: { endpoint: 'https://kubo.example', kind: 'pinata', accessToken: 's3cret' },
            keepLatestVersions: null,
          },
        } as unknown as CommandDescriptor)
      ).toThrow('invalid request field settings.byo.accessToken: string');
      expect(byo).toEqual([]);
    });

    it('refuses a retention cap past the u32 the builder takes', () => {
      const { wasm } = spyWasm();

      // The number ABI wraps rather than rejects, so 2**32 + 1 would arrive as
      // "keep only the newest" — a cap that retires every other version.
      expect(() =>
        buildCommand(wasm, {
          kind: 'saveVaultSettings',
          settings: { pinMode: 'hosted', byo: null, keepLatestVersions: 2 ** 32 + 1 },
        })
      ).toThrow('invalid request field settings.keepLatestVersions: number');
    });

    it('refuses a zero retention cap before it builds the provider config', () => {
      const { wasm, byo } = spyWasm();

      // The builder holds a `NonZeroU64`, so zero throws there — after this
      // provider config already minted a wasm object holding the token.
      expect(() =>
        buildCommand(wasm, {
          kind: 'saveVaultSettings',
          settings: {
            pinMode: 'hosted',
            byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: token() },
            keepLatestVersions: 0,
          },
        })
      ).toThrow('invalid request field settings.keepLatestVersions: number');
      expect(byo).toEqual([]);
    });

    it('refuses before it builds the credential-bearing provider config', () => {
      const { wasm, byo } = spyWasm();

      expect(() =>
        buildCommand(wasm, {
          kind: 'saveVaultSettings',
          settings: {
            pinMode: 'nowhere',
            byo: { endpoint: 'https://kubo.example', kind: 'kubo', accessToken: token() },
            keepLatestVersions: null,
          },
        } as unknown as CommandDescriptor)
      ).toThrow('invalid request field settings.pinMode: string');
      expect(byo).toEqual([]);
    });

    it('rejects an unknown pin mode or provider kind rather than defaulting one', () => {
      const { wasm } = spyWasm();
      const refusesSettings =
        (settings: unknown): (() => unknown) =>
        () =>
          buildCommand(wasm, { kind: 'saveVaultSettings', settings } as CommandDescriptor);

      expect(
        refusesSettings({ pinMode: 'somewhere-else', byo: null, keepLatestVersions: null })
      ).toThrow('invalid request field settings.pinMode: string');
      expect(
        refusesSettings({
          pinMode: 'dual',
          byo: { endpoint: 'https://kubo.example', kind: 'ipfs-cluster', accessToken: null },
          keepLatestVersions: null,
        })
      ).toThrow('invalid request field settings.byo.kind: string');
      expect(refusesSettings(null)).toThrow('invalid request field settings: null');
      expect(refusesSettings({ pinMode: 'hosted', byo: null, keepLatestVersions: -1 })).toThrow(
        'invalid request field settings.keepLatestVersions: number'
      );
    });
  });

  describe('auth', () => {
    const spyWasm = (): { wasm: EngineWasm; calls: Record<string, unknown[]> } => {
      const calls: Record<string, unknown[]> = {};
      const wasm = {
        ...fakeWasmEnums,
        Command: new Proxy(
          {},
          {
            get:
              (_target, name: string) =>
              (...args: unknown[]) => {
                calls[name] = args;
                return {};
              },
          }
        ),
      } as unknown as EngineWasm;
      return { wasm, calls };
    };

    it('builds a wallet link from the message and its raw signature bytes', () => {
      const { wasm, calls } = spyWasm();
      const signature = new Uint8Array(65).fill(9);

      buildCommand(wasm, { kind: 'siweLink', message: 'link me', signature });

      expect(calls.siweLink).toEqual(['link me', signature]);
    });

    it('builds an unlink from the method id alone', () => {
      const { wasm, calls } = spyWasm();

      buildCommand(wasm, { kind: 'unlinkAuthMethod', methodId: '3f2a-uuid' });

      expect(calls.unlinkAuthMethod).toEqual(['3f2a-uuid']);
    });

    it('refuses a link or an unlink whose fields are not what they claim', () => {
      const { wasm } = spyWasm();
      const refusesAuth =
        (descriptor: unknown): (() => unknown) =>
        () =>
          buildCommand(wasm, descriptor as CommandDescriptor);

      expect(
        refusesAuth({ kind: 'siweLink', message: 12345, signature: new Uint8Array() })
      ).toThrow('invalid request field message: number');
      expect(refusesAuth({ kind: 'siweLink', message: 'link me', signature: 'abcd' })).toThrow(
        'invalid request field signature: string'
      );
      expect(refusesAuth({ kind: 'unlinkAuthMethod', methodId: null })).toThrow(
        'invalid request field methodId: null'
      );
    });
  });
});

describe('readEvent', () => {
  it('maps renewalFailed instead of throwing (the transport-bricking bug)', () => {
    const event: WasmEvent = {
      kind: 'renewalFailed',
      routingKey: 'k51qzi5uqu5dr',
      detail: 'record rejected',
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'renewalFailed',
      routingKey: 'k51qzi5uqu5dr',
      detail: 'record rejected',
    });
  });

  it('maps a full opProgress payload to string-literal phase', () => {
    const node = new Uint8Array(16).fill(3);
    const event: WasmEvent = {
      kind: 'opProgress',
      opId: 7n,
      node,
      phase: 2,
      error: 'unavailable',
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'opProgress',
      opId: 7n,
      node,
      phase: 'downloadFailed',
      blocksConfirmed: null,
      blocksTotal: null,
      error: 'unavailable',
    });
  });

  it('maps an op-less, error-less opProgress to nulls', () => {
    const event: WasmEvent = { kind: 'opProgress', node: new Uint8Array(16), phase: 0 };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'opProgress',
      opId: null,
      node: new Uint8Array(16),
      phase: 'downloadStarted',
      blocksConfirmed: null,
      blocksTotal: null,
      error: null,
    });
  });

  it('carries an upload phase and its block counters through to the descriptor', () => {
    const node = new Uint8Array(16).fill(4);
    const event: WasmEvent = {
      kind: 'opProgress',
      opId: 9n,
      node,
      phase: fakeWasm.OpPhase.UploadProgress,
      blocksConfirmed: 3,
      blocksTotal: 8,
    };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'opProgress',
      opId: 9n,
      node,
      phase: 'uploadProgress',
      blocksConfirmed: 3,
      blocksTotal: 8,
      error: null,
    });
  });

  it('carries a dead letter reason through to the descriptor', () => {
    const event: WasmEvent = { kind: 'deadLetter', opId: 7n, deadLetterReason: 2 };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'deadLetter',
      opId: 7n,
      reason: 'destinationInsideTarget',
    });
  });

  it('maps the unrecoverable-content dead letter reason', () => {
    const event: WasmEvent = { kind: 'deadLetter', opId: 4n, deadLetterReason: 7 };
    expect(readEvent(fakeWasm, event)).toEqual({
      kind: 'deadLetter',
      opId: 4n,
      reason: 'contentUnrecoverable',
    });
  });

  it('maps the two reasons an abandonment reports about the record plane', () => {
    expect(readEvent(fakeWasm, { kind: 'deadLetter', opId: 1n, deadLetterReason: 10 })).toEqual({
      kind: 'deadLetter',
      opId: 1n,
      reason: 'preservationRefused',
    });
    expect(readEvent(fakeWasm, { kind: 'deadLetter', opId: 2n, deadLetterReason: 11 })).toEqual({
      kind: 'deadLetter',
      opId: 2n,
      reason: 'alreadyPublished',
    });
  });

  it('fails closed on an unknown or absent dead letter reason', () => {
    expect(() =>
      readEvent(fakeWasm, { kind: 'deadLetter', opId: 7n, deadLetterReason: 42 })
    ).toThrow('unknown WASM dead letter reason value: 42');
    expect(() => readEvent(fakeWasm, { kind: 'deadLetter', opId: 7n })).toThrow(
      'unknown WASM dead letter reason value: undefined'
    );
  });

  it('fails closed on an unknown opProgress phase', () => {
    const event: WasmEvent = { kind: 'opProgress', node: new Uint8Array(16), phase: 99 };
    expect(() => readEvent(fakeWasm, event)).toThrow('unknown WASM op phase value: 99');
    expect(() => readEvent(fakeWasm, { kind: 'opProgress', node: new Uint8Array(16) })).toThrow(
      'unknown WASM op phase value'
    );
  });
});

/** An empty view: nothing pending, nothing dead-lettered, nothing held. */
function baseView(): WasmSnapshotView {
  return {
    root: new Uint8Array(16),
    folder: new Uint8Array(16),
    folderName: '',
    children: [],
    ancestors: [],
    deadLetters: [],
    retainedRecords: 0,
    staleness: 0,
  };
}

describe('readSnapshot', () => {
  it('maps every field, including bigint dead letters and null size/mtime', () => {
    const view: WasmSnapshotView = {
      root: new Uint8Array(16).fill(1),
      folder: new Uint8Array(16).fill(2),
      folderName: 'holiday',
      children: [
        {
          id: new Uint8Array(16).fill(3),
          name: 'photo.jpg',
          kind: 0,
          size: 1024n,
          mtime: 1_700_000_000_000n,
          pending: 2,
          deadLetter: false,
          contentVersion: 2n,
        },
        {
          id: new Uint8Array(16).fill(4),
          name: 'docs',
          kind: 1,
          pending: 0,
          deadLetter: true,
        },
        {
          id: new Uint8Array(16).fill(5),
          name: 'renamed.txt',
          kind: 0,
          pending: 1,
          deadLetter: false,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: [
        { opId: 9n, reason: 4 },
        { opId: 9_007_199_254_740_993n, reason: 6 },
      ],
      blocked: {
        opId: 12n,
        node: new Uint8Array(16).fill(6),
        neededBytes: 9_007_199_254_740_993n,
      },
      retainedRecords: 2,
      staleness: 1,
    };

    expect(readSnapshot(fakeWasm, view)).toEqual({
      root: new Uint8Array(16).fill(1),
      folder: new Uint8Array(16).fill(2),
      folderName: 'holiday',
      children: [
        {
          id: new Uint8Array(16).fill(3),
          name: 'photo.jpg',
          kind: 'file',
          size: 1024n,
          mtime: 1_700_000_000_000n,
          pending: 'content',
          deadLetter: false,
          contentVersion: 2n,
        },
        {
          id: new Uint8Array(16).fill(4),
          name: 'docs',
          kind: 'folder',
          size: null,
          mtime: null,
          pending: 'none',
          deadLetter: true,
          contentVersion: null,
        },
        {
          id: new Uint8Array(16).fill(5),
          name: 'renamed.txt',
          kind: 'file',
          size: null,
          mtime: null,
          pending: 'metadata',
          deadLetter: false,
          contentVersion: null,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: [
        { opId: 9n, reason: 'undecodable' },
        { opId: 9_007_199_254_740_993n, reason: 'attemptsExhausted' },
      ],
      blocked: {
        opId: 12n,
        node: new Uint8Array(16).fill(6),
        neededBytes: 9_007_199_254_740_993n,
      },
      retainedRecords: 2,
      staleness: 'reconciling',
    });
  });

  it('maps an absent over-budget hold to null', () => {
    expect(readSnapshot(fakeWasm, baseView()).blocked).toBeNull();
  });

  it('fails closed on an unknown dead letter reason', () => {
    expect(() =>
      readSnapshot(fakeWasm, { ...baseView(), deadLetters: [{ opId: 1n, reason: 42 }] })
    ).toThrow('unknown WASM dead letter reason value: 42');
  });

  it('fails closed on an unknown child kind, pending class or staleness value', () => {
    const base = baseView();
    expect(() => readSnapshot(fakeWasm, { ...base, staleness: 42 })).toThrow(
      'unknown WASM staleness value: 42'
    );
    expect(() =>
      readSnapshot(fakeWasm, {
        ...base,
        children: [
          {
            id: new Uint8Array(16),
            name: 'x',
            kind: 42,
            pending: 0,
            deadLetter: false,
          },
        ],
      })
    ).toThrow('unknown WASM node kind value: 42');
    expect(() =>
      readSnapshot(fakeWasm, {
        ...base,
        children: [
          {
            id: new Uint8Array(16),
            name: 'x',
            kind: 0,
            pending: 42,
            deadLetter: false,
          },
        ],
      })
    ).toThrow('unknown WASM pending class value: 42');
  });
});

describe('readSharing', () => {
  const links = { live: true, expired: false, expiresAt: 1_700_000_000_000n, spent: 2 };
  const view = {
    scope: new Uint8Array(16).fill(3),
    contacts: [{ identityPublicKey: new Uint8Array([1]) }],
    state: {
      grants: [
        {
          recipientIdentityPublicKey: new Uint8Array([2]),
          permission: fakeWasmEnums.Permission.Read,
        },
      ],
      grantRefusal: 'grant-target-already-names-a-scope',
      inviteLinkRefusal: 'invite-target-already-names-a-scope',
      inviteLinks: links,
    },
  };

  it('carries the scope, its grants and its link standing through unchanged', () => {
    expect(readSharing(fakeWasm, view)).toEqual({
      scope: view.scope,
      contacts: [{ identityPublicKey: view.contacts[0].identityPublicKey }],
      state: {
        grants: [{ recipientIdentityPublicKey: new Uint8Array([2]), permission: 'read' }],
        grantRefusal: 'grant-target-already-names-a-scope',
        inviteLinkRefusal: 'invite-target-already-names-a-scope',
        inviteLinks: links,
      },
    });
  });

  it('reads a link with no deadline as null, never as a deadline', () => {
    const open = {
      ...view,
      state: { ...view.state, inviteLinks: { ...links, expiresAt: undefined } },
    };

    expect(readSharing(fakeWasm, open).state?.inviteLinks?.expiresAt).toBeNull();
  });

  it('reads unreadable link records as absent while the grants still stand', () => {
    const unreadable = { ...view, state: { ...view.state, inviteLinks: undefined } };

    const state = readSharing(fakeWasm, unreadable).state;
    expect(state?.grants).toHaveLength(1);
    expect(state?.inviteLinks).toBeNull();
  });

  it('reads an unreachable scope as absent, never as one granting nothing', () => {
    expect(readSharing(fakeWasm, { ...view, state: undefined }).state).toBeNull();
  });
});

describe('readReceivedShare', () => {
  const row = {
    scope: new Uint8Array(16).fill(7),
    sharerIdentityPublicKey: new Uint8Array([9]),
    displayName: 'shared-folder',
    permission: fakeWasmEnums.Permission.Read,
    resolution: 'revocation-signal',
  };

  it('carries the row and the engine verdict through unchanged', () => {
    expect(readReceivedShare(fakeWasm, row)).toEqual({
      scope: row.scope,
      sharerIdentityPublicKey: row.sharerIdentityPublicKey,
      displayName: 'shared-folder',
      permission: 'read',
      resolution: 'revocation-signal',
    });
  });

  it('reads an absent verdict as null, never as a verdict', () => {
    expect(readReceivedShare(fakeWasm, { ...row, resolution: undefined }).resolution).toBeNull();
  });

  it('fails closed on a class it cannot map', () => {
    // A guessed class would paint a revoked share as still granted.
    expect(() => readReceivedShare(fakeWasm, { ...row, resolution: 'granted-ish' })).toThrow(
      'unknown WASM resolution class: granted-ish'
    );
  });
});

describe('readVaultStorage', () => {
  const view = (): WasmVaultStorageView => ({
    settings: {
      pinMode: fakeWasmEnums.PinMode.Dual,
      byoEndpoint: 'https://kubo.example',
      byoKind: fakeWasmEnums.ByoKind.Psa,
      byoCredentialStored: true,
      keepLatestVersions: 5,
      origin: fakeWasmEnums.SettingsOrigin.Stale,
    },
    quota: { usedBytes: 512n, limitBytes: 2048n, advisory: true },
    pendingReclaimBytes: 0n,
    reclaimStalls: [
      {
        node: new Uint8Array(16).fill(3),
        target: 'bafyDoomedRoot',
        reason: fakeWasmEnums.ReclaimStallReason.TargetStillLive,
      },
    ],
  });

  it('reads the settings, the quota and the stalled debts through', () => {
    expect(readVaultStorage(fakeWasm, view())).toEqual({
      settings: {
        pinMode: 'dual',
        byoEndpoint: 'https://kubo.example',
        byoKind: 'psa',
        byoCredentialStored: true,
        keepLatestVersions: 5,
        origin: 'stale',
      },
      quota: { usedBytes: 512, limitBytes: 2048, advisory: true },
      pendingReclaimBytes: 0,
      reclaimStalls: [
        { node: new Uint8Array(16).fill(3), target: 'bafyDoomedRoot', reason: 'targetStillLive' },
      ],
    });
  });

  it('reads a vault with no provider and an unanswered probe as null, never as blank', () => {
    const bare = readVaultStorage(fakeWasm, {
      ...view(),
      settings: {
        pinMode: fakeWasmEnums.PinMode.Hosted,
        byoEndpoint: undefined,
        byoKind: undefined,
        byoCredentialStored: false,
        keepLatestVersions: undefined,
        origin: fakeWasmEnums.SettingsOrigin.Defaults,
      },
      quota: undefined,
    });

    expect(bare.settings.byoEndpoint).toBeNull();
    expect(bare.settings.byoKind).toBeNull();
    expect(bare.settings.keepLatestVersions).toBeNull();
    expect(bare.quota).toBeNull();
  });

  it.each([
    ['pin mode', { pinMode: 42 }, 'unknown WASM pin mode value: 42'],
    ['provider kind', { byoKind: 42 }, 'unknown WASM provider kind value: 42'],
    ['settings origin', { origin: 42 }, 'unknown WASM settings origin value: 42'],
  ])('fails closed on a %s it cannot map', (_name, override, message) => {
    const base = view();
    expect(() =>
      readVaultStorage(fakeWasm, { ...base, settings: { ...base.settings, ...override } })
    ).toThrow(message);
  });

  it('fails closed on a stall reason it cannot map', () => {
    // A guessed reason would tell a member the wrong thing about a debt that
    // never drains.
    const base = view();
    expect(() =>
      readVaultStorage(fakeWasm, {
        ...base,
        reclaimStalls: [{ ...base.reclaimStalls[0]!, reason: 42 }],
      })
    ).toThrow('unknown WASM reclaim stall reason value: 42');
  });
});

describe('readAuthMethods', () => {
  const row = {
    id: '3f2a-uuid',
    kind: fakeWasmEnums.AuthMethodKind.Wallet,
    identifierDisplay: '0x1234…abcd',
    createdAt: '2026-08-27T10:00:00.000Z',
    lastUsedAt: '2026-08-27T11:00:00.000Z',
  };

  it('reads the display form through, and an absent one as null', () => {
    // The second row is the kind this build does not know: the engine already
    // spells it `Unknown`, and a row is a display fact, not a trust decision.
    expect(
      readAuthMethods(fakeWasm, [
        row,
        {
          ...row,
          kind: fakeWasmEnums.AuthMethodKind.Unknown,
          identifierDisplay: undefined,
          lastUsedAt: undefined,
        },
      ])
    ).toEqual([
      {
        id: '3f2a-uuid',
        kind: 'wallet',
        identifierDisplay: '0x1234…abcd',
        createdAt: '2026-08-27T10:00:00.000Z',
        lastUsedAt: '2026-08-27T11:00:00.000Z',
      },
      {
        id: '3f2a-uuid',
        kind: 'unknown',
        identifierDisplay: null,
        createdAt: '2026-08-27T10:00:00.000Z',
        lastUsedAt: null,
      },
    ]);
  });

  it('fails closed on a kind value it cannot map', () => {
    expect(() => readAuthMethods(fakeWasm, [{ ...row, kind: 42 }])).toThrow(
      'unknown WASM auth method kind value: 42'
    );
  });
});
