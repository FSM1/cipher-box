/**
 * TDD tests for 68.1-16: createFolder TEE enrollment on first IPNS publish.
 *
 * Closes the durable-registration gap identified in the phase 68.1 verification
 * addendum — client.createFolder was the one owned first-publish call site that
 * omitted the TEE enrollment block, so new subfolders never enrolled in
 * ipns_republish_schedule and only survived via the volatile routing store.
 *
 * Mirrors the enrollment block already proven in
 * packages/sdk-core/src/folder/registration.ts createSubfolder (lines 85-109):
 * fail-closed guards on teeKeys.currentPublicKey / teeKeys.currentEpoch, then
 * ECIES-wrap the freshly-minted childIpnsPrivateKey under the TEE public key
 * BEFORE any IPFS upload side effect.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';

// ── crypto mock — keep every real helper (real Ed25519 keygen, hex codecs),
//    spy only on wrapKey so the ECIES-wrap output is deterministic to assert on.
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xde, 0xad, 0xbe, 0xef])),
  };
});

// ── sdk-core mock — override only the network-touching helpers exercised here.
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    createAndPublishIpnsRecord: vi.fn().mockResolvedValue({ success: true, sequenceNumber: 1n }),
    addToIpfs: vi.fn().mockResolvedValue({ cid: 'bafychild', size: 10, recorded: true }),
    updateFolderMetadataAndPublish: vi.fn().mockResolvedValue({
      cid: 'bafyfolder',
      newSequenceNumber: 2n,
      publishedChildren: [],
    }),
    resolveIpnsRecord: vi.fn().mockResolvedValue(null),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import * as cryptoMod from '@cipherbox/crypto';

const PARENT_IPNS = 'parent-ipns';

/**
 * Seed a write-capable parent FolderState: non-zero writeKey plus an in-memory
 * writeBody so getWriteBodyParams resolves synchronously (no extra resolve/fetch
 * hop) and createFolder's write-capable-parent guard passes.
 */
function setupWriteCapableFolder(client: CipherBoxClient, ipnsName = PARENT_IPNS): void {
  const state: FolderState = {
    ipnsName,
    folderKey: new Uint8Array(32).fill(1),
    writeKey: new Uint8Array(32).fill(9),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'parent-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren: [] },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'parent-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(ipnsName, state);
}

describe('CipherBoxClient.createFolder — TEE enrollment (68.1-16)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('passes a hex encryptedIpnsPrivateKey + matching keyEpoch when config.teeKeys is set', async () => {
    const client = new CipherBoxClient(
      createTestConfig({ teeKeys: { currentPublicKey: 'aa'.repeat(33), currentEpoch: 5 } })
    );
    setupWriteCapableFolder(client);

    await client.createFolder(PARENT_IPNS, 'New Subfolder');

    expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        sequenceNumber: 1n,
        encryptedIpnsPrivateKey: 'deadbeef',
        keyEpoch: 5,
      })
    );
    expect(cryptoMod.wrapKey).toHaveBeenCalledTimes(1);
  });

  it('omits enrollment fields when config.teeKeys is unset — legacy path preserved', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupWriteCapableFolder(client);

    await client.createFolder(PARENT_IPNS, 'New Subfolder');

    expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        sequenceNumber: 1n,
        encryptedIpnsPrivateKey: undefined,
        keyEpoch: undefined,
      })
    );
    expect(cryptoMod.wrapKey).not.toHaveBeenCalled();
  });

  it('throws before addToIpfs when teeKeys.currentPublicKey is missing/empty (fail-closed)', async () => {
    const client = new CipherBoxClient(
      createTestConfig({ teeKeys: { currentPublicKey: '', currentEpoch: 5 } })
    );
    setupWriteCapableFolder(client);

    await expect(client.createFolder(PARENT_IPNS, 'New Subfolder')).rejects.toThrow(
      /createFolder.*teeKeys\.currentPublicKey/
    );
    expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
    expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });

  it('throws before addToIpfs when teeKeys.currentEpoch is not a positive integer (fail-closed)', async () => {
    const client = new CipherBoxClient(
      createTestConfig({ teeKeys: { currentPublicKey: 'aa'.repeat(33), currentEpoch: 0 } })
    );
    setupWriteCapableFolder(client);

    await expect(client.createFolder(PARENT_IPNS, 'New Subfolder')).rejects.toThrow(
      /createFolder.*teeKeys\.currentEpoch/
    );
    expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
    expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });
});
