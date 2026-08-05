import { ServiceUnavailableException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { KuboPinStore, PinCidMismatchError } from './pin-store';

const RAW_CID = `bafkr4i${'a'.repeat(52)}`;
const OTHER_CID = `bafkr4i${'b'.repeat(52)}`;
const DAG_CBOR_CID = `bafyr4i${'a'.repeat(52)}`;

/** The Kubo RPC path (no query) of each call, in order. */
let calls: string[];
type Reply = { status?: number; body?: string };
let replies: Map<string, Reply>;

function store(apiUrl = 'http://kubo.test'): KuboPinStore {
  return new KuboPinStore(fakeConfig({ KUBO_API_URL: apiUrl }).service);
}

/**
 * The pin store's Kubo effects: the block is written under the declared
 * CID's own codec, pinned only once Kubo agrees on the address, and removed
 * again on every path that will not pin it — an unpinned block is not reclaimed,
 * so a refused upload must not leave one behind.
 */
describe('KuboPinStore.pin', () => {
  beforeEach(() => {
    calls = [];
    replies = new Map();
    vi.stubGlobal('fetch', (url: string) => {
      const path = new URL(url).pathname.replace('/api/v0/', '');
      calls.push(path);
      const reply = replies.get(path) ?? {};
      return Promise.resolve(new Response(reply.body ?? '{}', { status: reply.status ?? 200 }));
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('puts the block under the declared codec, then pins it direct', async () => {
    replies.set('block/put', { body: JSON.stringify({ Key: DAG_CBOR_CID, Size: 3 }) });
    await store().pin(DAG_CBOR_CID, new Uint8Array([1, 2, 3]));
    expect(calls).toEqual(['block/put', 'pin/add']);
  });

  it('removes the block and refuses when Kubo addresses the bytes differently', async () => {
    replies.set('block/put', { body: JSON.stringify({ Key: OTHER_CID, Size: 3 }) });
    await expect(store().pin(RAW_CID, new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(
      PinCidMismatchError
    );
    // The written block is dropped; nothing is pinned.
    expect(calls).toEqual(['block/put', 'block/rm']);
  });

  it('removes the block when the pin itself fails', async () => {
    replies.set('block/put', { body: JSON.stringify({ Key: RAW_CID, Size: 3 }) });
    replies.set('pin/add', { status: 500 });
    await expect(store().pin(RAW_CID, new Uint8Array([1, 2, 3]))).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
    expect(calls).toEqual(['block/put', 'pin/add', 'block/rm']);
  });

  it('reports a put that returned no address as a store fault, not a mismatch', async () => {
    // Kubo streams NDJSON and can trail an error object under a 200; reading
    // that as a disagreeing address would blame the caller for a store fault.
    replies.set('block/put', { body: JSON.stringify({ Message: 'boom', Type: 'error' }) });
    await expect(store().pin(RAW_CID, new Uint8Array([1]))).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
    expect(calls).toEqual(['block/put']);
  });

  it('refuses a CID outside the frozen content-plane shapes before any RPC', async () => {
    await expect(store().pin('not-a-cid', new Uint8Array([1]))).rejects.toBeInstanceOf(
      PinCidMismatchError
    );
    expect(calls).toEqual([]);
  });

  it('fails closed when Kubo is unconfigured — an upload with no pin store is not durable', async () => {
    await expect(store('').pin(RAW_CID, new Uint8Array([1]))).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
    expect(calls).toEqual([]);
  });
});
