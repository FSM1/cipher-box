/**
 * Phase 68.2 Plan 07 (Rule-2 deviation): proves `client.resolveChildIdentity`
 * -- the facade replacement for `apps/web/src/lib/crypto/key-wrapping.ts`'s
 * `resolveChildNodeIdentity` -- recovers a single child's own readKey +
 * plaintext node identity through the same gated resolve
 * (`gatedResolveChild`, ROT-07) every other per-child listing hop uses
 * (D-05 single gated read entrypoint), and fails closed when the child's
 * IPNS record cannot be resolved.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { sealNode, sealChildReadKey, type Node, type SealedChildRef } from '@cipherbox/core';

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
const CHILD_READ_KEY = new Uint8Array(32).fill(0x02);
const CHILD_IPNS = 'k51child-identity-test';
/** Unused by children (they carry no write-body) -- dummy zero key for sealNode's required param. */
const DUMMY_WRITE_KEY = new Uint8Array(32);

async function buildChildFixture() {
  const node: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: 'a1b2c3d4-0000-4000-8000-000000000001',
    generation: 5,
    createdAt: 1000,
    modifiedAt: 1000,
    content: {
      cid: 'bafyfile-identity',
      fileIv: 'iv',
      size: 42,
      mimeType: 'text/plain',
      encryptionMode: 'GCM' as const,
      fileKey: new Uint8Array(32).fill(0x09),
      versions: [],
    },
  };
  const published = await sealNode(node, CHILD_READ_KEY, DUMMY_WRITE_KEY);
  const readKeySealed = await sealChildReadKey(
    CHILD_READ_KEY,
    PARENT_READ_KEY,
    node.id,
    node.kind,
    node.generation
  );
  const childRef: SealedChildRef = {
    name: 'report.pdf',
    ipnsName: CHILD_IPNS,
    generation: node.generation,
    versionFloor: 0n,
    readKeySealed,
  };
  return { childRef, published, nodeId: node.id, generation: node.generation };
}

describe('CipherBoxClient.resolveChildIdentity', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("recovers the child's own readKey + plaintext node identity via one read-chain hop", async () => {
    const fixture = await buildChildFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-child-identity',
      sequenceNumber: 9n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(fixture.published))
    );

    const client = new CipherBoxClient(createTestConfig());

    const identity = await client.resolveChildIdentity(fixture.childRef, PARENT_READ_KEY);

    expect(identity.nodeId).toBe(fixture.nodeId);
    expect(identity.kind).toBe('file');
    expect(identity.generation).toBe(fixture.generation);
    expect(identity.readKey).toEqual(CHILD_READ_KEY);
    expect(identity.published).toEqual(fixture.published);
  });

  it('throws when the child IPNS record cannot be resolved (fail-closed, no gate bypass)', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

    const client = new CipherBoxClient(createTestConfig());
    const childRef: SealedChildRef = {
      name: 'missing.txt',
      ipnsName: 'k51unreachable-identity-test',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'irrelevant',
    };

    await expect(client.resolveChildIdentity(childRef, PARENT_READ_KEY)).rejects.toThrow(
      /IPNS record not found/
    );
  });
});
