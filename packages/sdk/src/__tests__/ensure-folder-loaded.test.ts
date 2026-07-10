/**
 * `CipherBoxClient.ensureFolderLoaded` unit tests -- current node/v3
 * self-bootstrap DFS (`dfsFindFolder` + `ensureRootFolderState`).
 *
 * The pre-Phase-65 version of this suite mocked `sdkCore.loadFolderMetadata`
 * directly to simulate a naive read-body-only DFS. That function/seam no
 * longer exists: `ensureFolderLoaded` now resolves each hop's real
 * `PublishedNode` (`resolveIpnsRecord` + `fetchFromIpfs`) and recovers BOTH
 * the child's readKey (`unsealChildReadKey`, sealed under the parent
 * readKey) AND its writeKey (`walkChildWriteKey`, sealed under the parent
 * writeKey) before it will descend into or register a folder -- a child with
 * no write-chain entry is not traversable (68.1-02/68.1-23). Only the
 * network-touching sdk-core seams are mocked; every `@cipherbox/core`
 * seal/unseal primitive stays real so fixtures are genuine AAD-bound
 * envelopes (mirrors client-write-plane-recovery.test.ts / delete-item.test.ts).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { generateEd25519Keypair } from '@cipherbox/crypto';
import {
  sealNode,
  sealChildReadKey,
  sealChildWriteKey,
  type Node,
  type SealedChildRef,
  type WriteChildRef,
} from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const ROOT = 'k51test'; // matches createTestConfig().rootIpnsName
const ROOT_NODE_ID = '00000000-0000-4000-8000-000000000000';

/** Register a (ipnsName -> {cid, published bytes}) network fixture. */
function mockNetwork(records: Record<string, { cid: string; published: unknown }>) {
  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    const rec = records[ipnsName];
    if (!rec) return null;
    return { cid: rec.cid, sequenceNumber: 1n, signatureVerified: true };
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    const rec = Object.values(records).find((r) => r.cid === cid);
    if (!rec) throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
    return new TextEncoder().encode(JSON.stringify(rec.published));
  });
}

describe('CipherBoxClient.ensureFolderLoaded', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the existing state without resolving IPNS when already loaded', async () => {
    const client = new CipherBoxClient(
      createTestConfig({ rootIpnsKeypair: generateEd25519Keypair() })
    );
    client.getFolderTree().set('k51a', {
      ipnsName: 'k51a',
      folderKey: new Uint8Array(32).fill(1),
      // Real (non-zero) writeKey so recoverWriteKeyIfNeeded's own
      // hasRealWriteKey short-circuit fires too -- this test only exercises
      // the cached-state fast path, not the recovery walk.
      writeKey: new Uint8Array(32).fill(6),
      ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64).fill(2) },
      sequenceNumber: 5n,
      children: [],
      metadata: null,
      lastLoadedAt: 1,
      nodeId: '',
      nodeGeneration: 0,
    });

    const result = await client.ensureFolderLoaded('k51a');

    expect(result?.ipnsName).toBe('k51a');
    expect(result?.sequenceNumber).toBe(5n);
    expect(sdkCore.resolveIpnsRecord).not.toHaveBeenCalled();
  });

  it('returns null without resolving IPNS when no root IPNS keypair is configured', async () => {
    const client = new CipherBoxClient(createTestConfig()); // no rootIpnsKeypair

    const result = await client.ensureFolderLoaded('k51missing');

    expect(result).toBeNull();
    expect(sdkCore.resolveIpnsRecord).not.toHaveBeenCalled();
  });

  it('bootstraps the root folder when the target IS the root', async () => {
    const rootFolderKey = new Uint8Array(32).fill(3); // matches createTestConfig() default
    const rootWriteKey = new Uint8Array(32).fill(0x20);
    const rootIpnsKeypair = generateEd25519Keypair();
    const client = new CipherBoxClient(createTestConfig({ rootWriteKey, rootIpnsKeypair }));

    const rootNode: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: ROOT_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: rootIpnsKeypair.privateKey, writeChildren: [] },
    };
    const publishedRoot = await sealNode(rootNode, rootFolderKey, rootWriteKey);
    mockNetwork({ [ROOT]: { cid: 'bafyroot', published: publishedRoot } });

    const result = await client.ensureFolderLoaded(ROOT);

    expect(result?.ipnsName).toBe(ROOT);
    expect(client.hasFolder(ROOT)).toBe(true);
    expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(1);
  });

  it('walks from root down to a deep target, registering every folder on the path', async () => {
    const rootFolderKey = new Uint8Array(32).fill(3);
    const rootWriteKey = new Uint8Array(32).fill(0x20);
    const rootIpnsKeypair = generateEd25519Keypair();
    const client = new CipherBoxClient(createTestConfig({ rootWriteKey, rootIpnsKeypair }));

    const A_IPNS = 'k51a';
    const B_IPNS = 'k51b';
    const A_NODE_ID = '11111111-1111-4111-8111-111111111111';
    const B_NODE_ID = '22222222-2222-4222-8222-222222222222';
    const aReadKey = new Uint8Array(32).fill(0x11);
    const aWriteKey = new Uint8Array(32).fill(0x12);
    const bReadKey = new Uint8Array(32).fill(0x21);
    const bWriteKey = new Uint8Array(32).fill(0x22);
    const aIpnsKeypair = generateEd25519Keypair();
    const bIpnsKeypair = generateEd25519Keypair();

    const aSealedRef: SealedChildRef = {
      name: 'A',
      ipnsName: A_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(aReadKey, rootFolderKey, A_NODE_ID, 'folder', 0),
    };
    const aWriteRef: WriteChildRef = {
      childId: A_NODE_ID,
      writeKeySealed: await sealChildWriteKey(aWriteKey, rootWriteKey, A_NODE_ID, 'folder', 0),
    };
    const rootNode: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: ROOT_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [aSealedRef],
      writeBody: { ipnsPrivateKey: rootIpnsKeypair.privateKey, writeChildren: [aWriteRef] },
    };

    const bSealedRef: SealedChildRef = {
      name: 'B',
      ipnsName: B_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(bReadKey, aReadKey, B_NODE_ID, 'folder', 0),
    };
    const bWriteRef: WriteChildRef = {
      childId: B_NODE_ID,
      writeKeySealed: await sealChildWriteKey(bWriteKey, aWriteKey, B_NODE_ID, 'folder', 0),
    };
    const aNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: A_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [bSealedRef],
      writeBody: { ipnsPrivateKey: aIpnsKeypair.privateKey, writeChildren: [bWriteRef] },
    };

    const bNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: B_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: bIpnsKeypair.privateKey, writeChildren: [] },
    };

    mockNetwork({
      [ROOT]: { cid: 'bafyroot', published: await sealNode(rootNode, rootFolderKey, rootWriteKey) },
      [A_IPNS]: { cid: 'bafya', published: await sealNode(aNode, aReadKey, aWriteKey) },
      [B_IPNS]: { cid: 'bafyb', published: await sealNode(bNode, bReadKey, bWriteKey) },
    });

    const result = await client.ensureFolderLoaded(B_IPNS);

    expect(result?.ipnsName).toBe(B_IPNS);
    // Whole path cached for cheap subsequent lookups.
    expect(client.hasFolder(ROOT)).toBe(true);
    expect(client.hasFolder(A_IPNS)).toBe(true);
    expect(client.hasFolder(B_IPNS)).toBe(true);
  });

  it('returns null when the target is not reachable from root', async () => {
    const rootFolderKey = new Uint8Array(32).fill(3);
    const rootWriteKey = new Uint8Array(32).fill(0x20);
    const rootIpnsKeypair = generateEd25519Keypair();
    const client = new CipherBoxClient(createTestConfig({ rootWriteKey, rootIpnsKeypair }));

    const A_IPNS = 'k51a';
    const A_NODE_ID = '11111111-1111-4111-8111-111111111111';
    const aReadKey = new Uint8Array(32).fill(0x11);
    const aWriteKey = new Uint8Array(32).fill(0x12);
    const aIpnsKeypair = generateEd25519Keypair();

    const aSealedRef: SealedChildRef = {
      name: 'A',
      ipnsName: A_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(aReadKey, rootFolderKey, A_NODE_ID, 'folder', 0),
    };
    const aWriteRef: WriteChildRef = {
      childId: A_NODE_ID,
      writeKeySealed: await sealChildWriteKey(aWriteKey, rootWriteKey, A_NODE_ID, 'folder', 0),
    };
    const rootNode: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: ROOT_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [aSealedRef],
      writeBody: { ipnsPrivateKey: rootIpnsKeypair.privateKey, writeChildren: [aWriteRef] },
    };
    // A has no further descendants; target k51zzz is absent from the whole tree.
    const aNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: A_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: aIpnsKeypair.privateKey, writeChildren: [] },
    };

    mockNetwork({
      [ROOT]: { cid: 'bafyroot', published: await sealNode(rootNode, rootFolderKey, rootWriteKey) },
      [A_IPNS]: { cid: 'bafya', published: await sealNode(aNode, aReadKey, aWriteKey) },
    });

    const result = await client.ensureFolderLoaded('k51zzz');

    expect(result).toBeNull();
    // Still cached what it walked.
    expect(client.hasFolder(A_IPNS)).toBe(true);
  });

  it('short-circuits a subfolder that has no IPNS record (skips, keeps walking)', async () => {
    const rootFolderKey = new Uint8Array(32).fill(3);
    const rootWriteKey = new Uint8Array(32).fill(0x20);
    const rootIpnsKeypair = generateEd25519Keypair();
    const client = new CipherBoxClient(createTestConfig({ rootWriteKey, rootIpnsKeypair }));

    const A_IPNS = 'k51a'; // unresolvable -- no network record at all
    const B_IPNS = 'k51b'; // target
    const A_NODE_ID = '11111111-1111-4111-8111-111111111111';
    const B_NODE_ID = '22222222-2222-4222-8222-222222222222';
    const aReadKey = new Uint8Array(32).fill(0x11);
    const aWriteKey = new Uint8Array(32).fill(0x12);
    const bReadKey = new Uint8Array(32).fill(0x21);
    const bWriteKey = new Uint8Array(32).fill(0x22);
    const bIpnsKeypair = generateEd25519Keypair();

    const aSealedRef: SealedChildRef = {
      name: 'A',
      ipnsName: A_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(aReadKey, rootFolderKey, A_NODE_ID, 'folder', 0),
    };
    const aWriteRef: WriteChildRef = {
      childId: A_NODE_ID,
      writeKeySealed: await sealChildWriteKey(aWriteKey, rootWriteKey, A_NODE_ID, 'folder', 0),
    };
    const bSealedRef: SealedChildRef = {
      name: 'B',
      ipnsName: B_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(bReadKey, rootFolderKey, B_NODE_ID, 'folder', 0),
    };
    const bWriteRef: WriteChildRef = {
      childId: B_NODE_ID,
      writeKeySealed: await sealChildWriteKey(bWriteKey, rootWriteKey, B_NODE_ID, 'folder', 0),
    };
    const rootNode: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: ROOT_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [aSealedRef, bSealedRef],
      writeBody: {
        ipnsPrivateKey: rootIpnsKeypair.privateKey,
        writeChildren: [aWriteRef, bWriteRef],
      },
    };
    const bNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: B_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: bIpnsKeypair.privateKey, writeChildren: [] },
    };

    // k51a intentionally absent from the network fixture -> resolveIpnsRecord
    // returns null (structurally unresolvable hop) -> `continue`, skip A.
    mockNetwork({
      [ROOT]: { cid: 'bafyroot', published: await sealNode(rootNode, rootFolderKey, rootWriteKey) },
      [B_IPNS]: { cid: 'bafyb', published: await sealNode(bNode, bReadKey, bWriteKey) },
    });

    const result = await client.ensureFolderLoaded(B_IPNS);

    expect(result?.ipnsName).toBe(B_IPNS);
    expect(client.hasFolder(A_IPNS)).toBe(false);
    expect(client.hasFolder(B_IPNS)).toBe(true);
  });

  it('fails closed (aborts the whole walk) when a sibling readKeySealed fails AEAD verification', async () => {
    // Current dfsFindFolder does NOT skip-and-continue on a corrupt sibling --
    // unsealChildReadKey's AEAD failure is intentionally left uncaught inside
    // the per-child try/finally (T-68.1-01-02: "a stale-CID relay serve fails
    // GCM auth closed... and propagates as a throw"), so it propagates out of
    // the ENTIRE dfsFindFolder call rather than being contained to one hop.
    // This replaces the old phase-63-era "skips a corrupt sibling and still
    // reaches the target" premise, which described a resilience behavior the
    // current fail-closed design deliberately does not provide.
    const rootFolderKey = new Uint8Array(32).fill(3);
    const rootWriteKey = new Uint8Array(32).fill(0x20);
    const rootIpnsKeypair = generateEd25519Keypair();
    const client = new CipherBoxClient(createTestConfig({ rootWriteKey, rootIpnsKeypair }));

    const A_IPNS = 'k51a';
    const B_IPNS = 'k51b';
    const A_NODE_ID = '11111111-1111-4111-8111-111111111111';
    const B_NODE_ID = '22222222-2222-4222-8222-222222222222';
    const aReadKey = new Uint8Array(32).fill(0x11);
    const aWriteKey = new Uint8Array(32).fill(0x12);
    const bReadKey = new Uint8Array(32).fill(0x21);
    const bWriteKey = new Uint8Array(32).fill(0x22);
    const aIpnsKeypair = generateEd25519Keypair();
    const bIpnsKeypair = generateEd25519Keypair();

    // A's readKeySealed is sealed under the WRONG parent key (a decoy, not
    // rootFolderKey) -- unsealChildReadKey will fail GCM auth when the walk
    // tries to recover it under the real rootFolderKey.
    const wrongParentKey = new Uint8Array(32).fill(0xff);
    const aSealedRef: SealedChildRef = {
      name: 'A',
      ipnsName: A_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(aReadKey, wrongParentKey, A_NODE_ID, 'folder', 0),
    };
    const aWriteRef: WriteChildRef = {
      childId: A_NODE_ID,
      writeKeySealed: await sealChildWriteKey(aWriteKey, rootWriteKey, A_NODE_ID, 'folder', 0),
    };
    const bSealedRef: SealedChildRef = {
      name: 'B',
      ipnsName: B_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(bReadKey, rootFolderKey, B_NODE_ID, 'folder', 0),
    };
    const bWriteRef: WriteChildRef = {
      childId: B_NODE_ID,
      writeKeySealed: await sealChildWriteKey(bWriteKey, rootWriteKey, B_NODE_ID, 'folder', 0),
    };
    const rootNode: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: ROOT_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [aSealedRef, bSealedRef],
      writeBody: {
        ipnsPrivateKey: rootIpnsKeypair.privateKey,
        writeChildren: [aWriteRef, bWriteRef],
      },
    };
    const aNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: A_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: aIpnsKeypair.privateKey, writeChildren: [] },
    };
    const bNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: B_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: bIpnsKeypair.privateKey, writeChildren: [] },
    };

    mockNetwork({
      [ROOT]: { cid: 'bafyroot', published: await sealNode(rootNode, rootFolderKey, rootWriteKey) },
      [A_IPNS]: { cid: 'bafya', published: await sealNode(aNode, aReadKey, aWriteKey) },
      [B_IPNS]: { cid: 'bafyb', published: await sealNode(bNode, bReadKey, bWriteKey) },
    });

    await expect(client.ensureFolderLoaded(B_IPNS)).rejects.toThrow();
    // The walk aborted before ever reaching/registering B.
    expect(client.hasFolder(B_IPNS)).toBe(false);
  });
});
