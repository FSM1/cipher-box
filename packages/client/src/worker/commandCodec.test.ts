import { describe, expect, it } from 'vitest';

import { fakeWasmEnums } from '../testkit.js';
import { buildCommand, readEvent, readSnapshot } from './commandCodec.js';
import type { CommandDescriptor } from './protocol.js';
import type { EngineWasm, WasmEvent, WasmSnapshotView } from './engineWasm.js';

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
