/**
 * CipherBoxClient.resolveNodeIdentity tests (68.2-08 Rule-2 facade addition).
 *
 * `id`/`kind` are plaintext on the `PublishedNode` envelope (NODE-03), so
 * this resolves them WITHOUT any readKey/unsealing -- the facade replacement
 * for `useSharedWriteOps.ts`'s direct `resolveIpnsRecord`+`fetchFromIpfs`
 * usage (`resolveChildNodeId`).
 *
 * 73-04 SC3: `resolveNodeIdentity` now takes a full `SealedChildRef` (not a
 * bare ipnsName string) and routes through `gatedResolveChild` (ROT-07
 * anti-rollback floor), so a `signatureVerified:false` resolve must reject
 * (fail-closed) rather than silently return an unverified identity.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { sealNode, sealChildReadKey, type Node, type SealedChildRef } from '@cipherbox/core';
import type { RotationHighWater } from '../state/rotation-high-water';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const PARENT_READ_KEY = new Uint8Array(32).fill(0x01);
const NODE_READ_KEY = new Uint8Array(32).fill(0x03);
const NODE_IPNS = 'k51node-identity-test';
/** Unused by children (they carry no write-body) -- dummy zero key for sealNode's required param. */
const DUMMY_WRITE_KEY = new Uint8Array(32);

/** A fake RotationHighWater whose enforceResolved always succeeds -- required
 * so `gatedResolveChild`'s `signatureVerified` fail-closed branch is entered
 * (that branch is gated on `this.config.rotationHighWater` being set). */
function fakeRotationHighWater(): RotationHighWater {
  return {
    getGenerationFloor: vi.fn(),
    bumpGeneration: vi.fn(),
    seedFromGrant: vi.fn(),
    getSeqFloor: vi.fn(),
    bumpSeq: vi.fn(),
    enforceResolved: vi.fn(async () => undefined),
  };
}

async function buildChildFixture() {
  const node: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: '44444444-4444-4444-8444-444444444444',
    generation: 0,
    createdAt: 1000,
    modifiedAt: 1000,
    content: {
      cid: 'bafyidentity',
      fileIv: 'iv',
      size: 1,
      mimeType: 'text/plain',
      encryptionMode: 'GCM' as const,
      fileKey: new Uint8Array(32).fill(0x09),
      versions: [],
    },
  };
  const published = await sealNode(node, NODE_READ_KEY, DUMMY_WRITE_KEY);
  const readKeySealed = await sealChildReadKey(
    NODE_READ_KEY,
    PARENT_READ_KEY,
    node.id,
    node.kind,
    node.generation
  );
  const childRef: SealedChildRef = {
    name: 'report.pdf',
    ipnsName: NODE_IPNS,
    generation: node.generation,
    versionFloor: 0n,
    readKeySealed,
  };
  return { childRef, published, nodeId: node.id };
}

describe('CipherBoxClient.resolveNodeIdentity', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('resolves the plaintext id/kind of a node without any readKey', async () => {
    const fixture = await buildChildFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-envelope',
      sequenceNumber: 2n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(fixture.published))
    );

    const identity = await client.resolveNodeIdentity(fixture.childRef);

    expect(identity).toEqual({ nodeId: fixture.nodeId, kind: 'file' });
  });

  it('returns null when the IPNS record cannot be resolved', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    const childRef: SealedChildRef = {
      name: 'missing.txt',
      ipnsName: 'k51unreachable-identity-test',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'irrelevant',
    };

    const identity = await client.resolveNodeIdentity(childRef);

    expect(identity).toBeNull();
  });

  it('rejects when the resolved record has signatureVerified=false (fail-closed via gatedResolveChild)', async () => {
    const fixture = await buildChildFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-envelope',
      sequenceNumber: 2n,
      signatureVerified: false,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(fixture.published))
    );

    const gatedClient = new CipherBoxClient(
      createTestConfig({ rotationHighWater: fakeRotationHighWater() })
    );

    await expect(gatedClient.resolveNodeIdentity(fixture.childRef)).rejects.toThrow(
      /unverified record/
    );
  });
});
