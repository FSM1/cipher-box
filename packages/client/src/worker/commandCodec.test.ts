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

  it('fails closed on an unknown opProgress phase', () => {
    const event: WasmEvent = { kind: 'opProgress', node: new Uint8Array(16), phase: 99 };
    expect(() => readEvent(fakeWasm, event)).toThrow('unknown WASM op phase value: 99');
    expect(() => readEvent(fakeWasm, { kind: 'opProgress', node: new Uint8Array(16) })).toThrow(
      'unknown WASM op phase value'
    );
  });
});

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
          pending: true,
          deadLetter: false,
          contentVersion: 2n,
        },
        {
          id: new Uint8Array(16).fill(4),
          name: 'docs',
          kind: 1,
          pending: false,
          deadLetter: true,
          contentVersion: 0n,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: new BigUint64Array([9n, 9_007_199_254_740_993n]),
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
          pending: true,
          deadLetter: false,
          contentVersion: 2n,
        },
        {
          id: new Uint8Array(16).fill(4),
          name: 'docs',
          kind: 'folder',
          size: null,
          mtime: null,
          pending: false,
          deadLetter: true,
          contentVersion: 0n,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: [9n, 9_007_199_254_740_993n],
      staleness: 'reconciling',
    });
  });

  it('fails closed on an unknown child kind or staleness value', () => {
    const base: WasmSnapshotView = {
      root: new Uint8Array(16),
      folder: new Uint8Array(16),
      children: [],
      ancestors: [],
      deadLetters: new BigUint64Array(0),
      staleness: 0,
    };
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
            pending: false,
            deadLetter: false,
            contentVersion: 0n,
          },
        ],
      })
    ).toThrow('unknown WASM node kind value: 42');
  });
});
