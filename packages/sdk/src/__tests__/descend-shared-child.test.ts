/**
 * CipherBoxClient.descendSharedChild tests (68.2-08 Rule-2 facade addition).
 *
 * Mirrors `resolve-child-identity.test.ts`'s mocking boundary (only
 * `resolveIpnsRecord`/`fetchFromIpfs` mocked; real `unsealChildReadKey`/
 * `unsealNode` exercise genuine crypto) -- this method additionally unseals
 * the child Node body to recover its OWN children (the RAW `SealedChildRef[]`
 * the web needs for nav-stack/write-op identity), where
 * `resolveChildIdentity` stops at readKey + plaintext identity only.
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
const CHILD_IPNS = 'k51child-descend-test';
const DUMMY_WRITE_KEY = new Uint8Array(32);

async function buildChildFolderFixture() {
  const grandchildRef: SealedChildRef = {
    name: 'nested.txt',
    ipnsName: 'k51grandchild',
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'irrelevant-not-unsealed-in-this-test',
  };
  const node: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: '33333333-3333-4333-8333-333333333333',
    generation: 3,
    createdAt: 1000,
    modifiedAt: 1000,
    children: [grandchildRef],
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
    name: 'subfolder',
    ipnsName: CHILD_IPNS,
    generation: node.generation,
    versionFloor: 0n,
    readKeySealed,
  };
  return { childRef, published, grandchildRef };
}

describe('CipherBoxClient.descendSharedChild', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it("recovers the child's readKey and its own RAW children via one read-chain hop", async () => {
    const { childRef, published, grandchildRef } = await buildChildFolderFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-child-descend',
      sequenceNumber: 11n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(published))
    );

    const result = await client.descendSharedChild(childRef, PARENT_READ_KEY);

    expect(result).not.toBeNull();
    expect(result!.readKey).toEqual(CHILD_READ_KEY);
    expect(result!.children).toEqual([grandchildRef]);
    expect(result!.sequenceNumber).toBe(11n);
    expect(result!.published).toEqual(published);
  });

  it('returns null when the child IPNS record cannot be resolved (fail-closed)', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    const childRef: SealedChildRef = {
      name: 'missing',
      ipnsName: 'k51unreachable-descend-test',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'irrelevant',
    };

    const result = await client.descendSharedChild(childRef, PARENT_READ_KEY);

    expect(result).toBeNull();
  });

  it('never zeroes the caller-owned parentReadKey (D-09)', async () => {
    const { childRef, published } = await buildChildFolderFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-child-descend-2',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(published))
    );
    const before = PARENT_READ_KEY.slice();

    await client.descendSharedChild(childRef, PARENT_READ_KEY);

    expect(PARENT_READ_KEY).toEqual(before);
  });
});
