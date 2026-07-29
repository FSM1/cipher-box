import { describe, expect, it } from 'vitest';

import { fakeWasmEnums } from '../testkit.js';
import { readEvent, readSnapshot } from './commandCodec.js';
import type { EngineWasm, WasmEvent, WasmSnapshotView } from './engineWasm.js';

/**
 * A structural stand-in for the wasm-bindgen namespace: only the mirror-enum
 * value tables the codec's read paths consult.
 */
const fakeWasm = fakeWasmEnums as unknown as EngineWasm;

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
