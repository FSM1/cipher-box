/**
 * CipherBoxClient.resolveNodeIdentity tests (68.2-08 Rule-2 facade addition).
 *
 * `id`/`kind` are plaintext on the `PublishedNode` envelope (NODE-03), so
 * this resolves them WITHOUT any readKey/unsealing -- the facade replacement
 * for `useSharedWriteOps.ts`'s direct `resolveIpnsRecord`+`fetchFromIpfs`
 * usage (`resolveChildNodeId`).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { sealNode, type Node } from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const NODE_IPNS = 'k51node-identity-test';
const READ_KEY = new Uint8Array(32).fill(0x03);
const WRITE_KEY = new Uint8Array(32);

describe('CipherBoxClient.resolveNodeIdentity', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('resolves the plaintext id/kind of a node without any readKey', async () => {
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
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-envelope',
      sequenceNumber: 2n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(published))
    );

    const identity = await client.resolveNodeIdentity(NODE_IPNS);

    expect(identity).toEqual({ nodeId: node.id, kind: 'file' });
  });

  it('returns null when the IPNS record cannot be resolved', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

    const identity = await client.resolveNodeIdentity('k51unreachable-identity-test');

    expect(identity).toBeNull();
  });
});
