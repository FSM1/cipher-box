/**
 * TDD tests for 68.1-18: resolveShareEncryptedWriteKey (SHARE-WRITE-KEY foundation).
 *
 * Closes the first half of the SHARE-WRITE-KEY web-wiring gap documented in
 * 68.1-11-SUMMARY.md's "Known Gaps": under the node/v3 write-chain, a shared
 * item's own writeKey is sealed inside its PARENT's write-body
 * (`WriteChildRef.writeKeySealed`, under the parent's writeKey) -- there is no
 * way to derive it from the parent's readKey alone. `resolveShareEncryptedWriteKey`
 * walks the owned write-chain (mirrors `resolveFileWriteChainKeys`'s write-key
 * walk) and ECIES-wraps the item's writeKey for a recipient, returning only the
 * wrapped hex encrypted key -- raw writeKey material never leaves the SDK.
 *
 * `wrapKey`/`unwrapKey` are mocked with a deterministic, INVERTIBLE fake
 * (prefix-tag + copy) instead of the real secp256k1/eciesjs stack -- @noble/secp256k1
 * is not a declared dependency of @cipherbox/sdk (only a devDependency of
 * @cipherbox/crypto), so this suite cannot mint a real secp256k1 keypair without
 * an undeclared cross-package import. The fake preserves the real round-trip
 * SEMANTICS wrapKey/unwrapKey provide (wrap then unwrap recovers the original
 * key) so Test 1 still proves the true behavior contract.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import { sealChildWriteKey } from '@cipherbox/core';
import type { WriteChildRef } from '@cipherbox/core';

// ── crypto mock -- keep every real helper (real hex codecs, AAD-bound seal
//    used to build fixtures) and only replace wrapKey/unwrapKey with a
//    deterministic, invertible fake so Test 1's round-trip assertion is real.
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  const WRAP_TAG = new Uint8Array([0xec, 0x1e]);
  return {
    ...actual,
    wrapKey: vi.fn(async (key: Uint8Array, _recipientPublicKey: Uint8Array) => {
      const out = new Uint8Array(WRAP_TAG.length + key.length);
      out.set(WRAP_TAG, 0);
      out.set(key, WRAP_TAG.length);
      return out;
    }),
    unwrapKey: vi.fn(async (wrapped: Uint8Array, _recipientPrivateKey: Uint8Array) => {
      return wrapped.slice(WRAP_TAG.length);
    }),
  };
});

// ── sdk-core mock -- override only the network-touching helper this method
//    reaches through `resolvePublishedNode` (resolveIpnsRecord + fetchFromIpfs).
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import * as cryptoMod from '@cipherbox/crypto';

const PARENT_IPNS = 'parent-ipns';
const ITEM_IPNS = 'k51item';
const ITEM_NODE_ID = '11111111-1111-4111-8111-111111111111';
const ITEM_GENERATION = 0;
const RECIPIENT_PUBLIC_KEY = new Uint8Array(65).fill(0x04);
const RECIPIENT_PRIVATE_KEY = new Uint8Array(32).fill(0x11);

/** Seed a write-capable parent FolderState carrying a real WriteChildRef for ITEM_NODE_ID. */
async function setupWriteCapableParentWithItem(
  client: CipherBoxClient,
  opts: {
    itemWriteKey?: Uint8Array;
    includeWriteChildRef?: boolean;
    parentWriteKey?: Uint8Array;
  } = {}
): Promise<{ itemWriteKey: Uint8Array }> {
  const parentWriteKey = opts.parentWriteKey ?? new Uint8Array(32).fill(9);
  const itemWriteKey = opts.itemWriteKey ?? new Uint8Array(32).fill(0x77);
  const includeWriteChildRef = opts.includeWriteChildRef ?? true;

  const writeChildren: WriteChildRef[] = [];
  if (includeWriteChildRef) {
    const writeKeySealed = await sealChildWriteKey(
      itemWriteKey,
      parentWriteKey,
      ITEM_NODE_ID,
      'file',
      ITEM_GENERATION
    );
    writeChildren.push({ childId: ITEM_NODE_ID, writeKeySealed });
  }

  const state: FolderState = {
    ipnsName: PARENT_IPNS,
    folderKey: new Uint8Array(32).fill(1),
    writeKey: parentWriteKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [
      {
        name: 'shared-item.txt',
        ipnsName: ITEM_IPNS,
        generation: ITEM_GENERATION,
        versionFloor: 1n,
        readKeySealed: 'unused-in-this-suite',
      },
    ],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'parent-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'parent-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(PARENT_IPNS, state);

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === ITEM_IPNS) {
      return { cid: 'bafyitem', sequenceNumber: 1n, signatureVerified: true };
    }
    return null;
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafyitem') {
      return new TextEncoder().encode(
        JSON.stringify({
          schema: 'node/v3',
          kind: 'file',
          id: ITEM_NODE_ID,
          generation: ITEM_GENERATION,
          createdAt: 0,
          modifiedAt: 0,
          readSealed: 'unused',
        })
      );
    }
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });

  return { itemWriteKey };
}

describe('CipherBoxClient.resolveShareEncryptedWriteKey (68.1-18)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns a wrapped hex encrypted key that unwraps to the child writeKey (round-trip)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const { itemWriteKey } = await setupWriteCapableParentWithItem(client);

    const encryptedWriteKeyHex = await client.resolveShareEncryptedWriteKey(
      PARENT_IPNS,
      ITEM_IPNS,
      RECIPIENT_PUBLIC_KEY
    );

    expect(typeof encryptedWriteKeyHex).toBe('string');
    expect(encryptedWriteKeyHex.length).toBeGreaterThan(0);
    expect(encryptedWriteKeyHex).toMatch(/^[0-9a-f]+$/);

    const wrappedBytes = new Uint8Array(
      encryptedWriteKeyHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
    );
    const unwrapped = await cryptoMod.unwrapKey(wrappedBytes, RECIPIENT_PRIVATE_KEY);
    expect(unwrapped).toEqual(itemWriteKey);
  });

  it('throws "no write-capable parent" when the parent has no writeKey (fail-closed)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    await setupWriteCapableParentWithItem(client, { parentWriteKey: new Uint8Array(32) });

    await expect(
      client.resolveShareEncryptedWriteKey(PARENT_IPNS, ITEM_IPNS, RECIPIENT_PUBLIC_KEY)
    ).rejects.toThrow(/no writeKey|write-capable parent/);
  });

  it('throws when the item has no WriteChildRef in the parent write-body (fail-closed)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    await setupWriteCapableParentWithItem(client, { includeWriteChildRef: false });

    await expect(
      client.resolveShareEncryptedWriteKey(PARENT_IPNS, ITEM_IPNS, RECIPIENT_PUBLIC_KEY)
    ).rejects.toThrow(/WriteChildRef/);
  });

  it('zeros the derived child writeKey after wrapping (terminal owner, D-09)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    await setupWriteCapableParentWithItem(client);

    let capturedKey: Uint8Array | null = null;
    vi.mocked(cryptoMod.wrapKey).mockImplementation(async (key: Uint8Array) => {
      capturedKey = key;
      const out = new Uint8Array(2 + key.length);
      out.set([0xec, 0x1e], 0);
      out.set(key, 2);
      return out;
    });

    await client.resolveShareEncryptedWriteKey(PARENT_IPNS, ITEM_IPNS, RECIPIENT_PUBLIC_KEY);

    expect(capturedKey).not.toBeNull();
    expect(capturedKey!.every((b) => b === 0)).toBe(true);
  });
});
