/**
 * TDD tests for 68.1-23: write-plane cold-load recovery + refresh mirror
 * preservation (Round-2 Addendum root-cause).
 *
 * Locks two invariants that closed the deterministic cross-device write-plane
 * clobber (conflict-detection.spec.ts:219 root cause):
 *
 * 1. `refreshFolderStateFromNetwork`, when it unseals a network-ahead record
 *    WITHOUT a real writeKey, must never REPLACE an already-populated local
 *    `metadata.writeBody` mirror with an absent one (D-03) -- a second
 *    device's bump must not silently strip this device's recovered
 *    WriteChildRefs from the wire.
 * 2. `ensureFolderLoaded`/`requireFolder` must recover a real writeKey +
 *    populated write-body mirror for a folder entry that was seeded
 *    read-only (zero writeKey, e.g. `registerFolder`/`loadFolder` without a
 *    `writeKey` argument -- the web-layer's parallel `navigateReadChain`
 *    walk, 68.1-05) but IS reachable from a write-capable root, instead of
 *    returning the write-crippled entry unchanged.
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`) are mocked -- every `@cipherbox/core` seal/unseal
 * primitive stays real so fixtures are genuine AAD-bound envelopes (mirrors
 * client-write-descriptor.test.ts / upload-batch.test.ts's 68.1-22 fixture).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import type { FolderTree } from '../state/folder-tree';
import {
  sealNode,
  sealChildReadKey,
  sealChildWriteKey,
  type Node,
  type SealedChildRef,
  type WriteChildRef,
} from '@cipherbox/core';
import { generateEd25519Keypair } from '@cipherbox/crypto';

// ── sdk-core mock -- override only the network-touching helpers reached
//    through `resolvePublishedNode` (resolveIpnsRecord + fetchFromIpfs).
//    Every other sdk-core export (unused here) stays real via importOriginal.
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

/** Expose the private method under test without loosening its production visibility. */
interface ClientInternals {
  folderTree: FolderTree;
  refreshFolderStateFromNetwork(folder: FolderState): Promise<void>;
}

const ROOT_IPNS = 'k51root';
const CHILD_IPNS = 'k51child';
const CHILD_NODE_ID = '22222222-2222-4222-8222-222222222222';
const TEST1_FOLDER_NODE_ID = '44444444-4444-4444-8444-444444444444';

describe('CipherBoxClient write-plane cold-load recovery + refresh preservation (68.1-23)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('refreshFolderStateFromNetwork write-body preservation', () => {
    it('preserves a populated metadata.writeBody when unsealing without a real writeKey', async () => {
      const client = new CipherBoxClient(createTestConfig());
      const folderKey = new Uint8Array(32).fill(1);
      const seededWriteChildren: WriteChildRef[] = [
        { childId: '11111111-1111-4111-8111-111111111111', writeKeySealed: 'seeded-sealed-key' },
      ];
      const originalChildren: SealedChildRef[] = [
        {
          name: 'old.txt',
          ipnsName: 'k51old',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'x',
        },
      ];

      const folder: FolderState = {
        ipnsName: 'folder-ipns',
        folderKey,
        // Zeroed -- this device never recovered the folder's writeKey.
        writeKey: new Uint8Array(32),
        ipnsKeypair: {
          publicKey: new Uint8Array(32).fill(2),
          privateKey: new Uint8Array(64).fill(3),
        },
        sequenceNumber: 1n,
        children: originalChildren,
        metadata: {
          schema: 'node/v3',
          kind: 'folder',
          id: TEST1_FOLDER_NODE_ID,
          generation: 0,
          createdAt: 0,
          modifiedAt: 0,
          children: originalChildren,
          writeBody: {
            ipnsPrivateKey: new Uint8Array(64).fill(3),
            writeChildren: seededWriteChildren,
          },
        },
        lastLoadedAt: Date.now(),
        nodeId: TEST1_FOLDER_NODE_ID,
        nodeGeneration: 0,
      };

      // A network-ahead record from ANOTHER device that never had this
      // device's write material -- no writeBody at all on the fresh node,
      // so sealNode omits `writeSealed` entirely.
      const freshReadOnlyNode: Node = {
        schema: 'node/v3',
        kind: 'folder',
        id: TEST1_FOLDER_NODE_ID,
        generation: 0,
        createdAt: 0,
        modifiedAt: 100,
        children: [
          {
            name: 'new.txt',
            ipnsName: 'k51new',
            generation: 0,
            versionFloor: 0n,
            readKeySealed: 'y',
          },
        ],
      };
      const published = await sealNode(freshReadOnlyNode, folderKey, new Uint8Array(32));

      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValueOnce({
        cid: 'bafyfresh',
        sequenceNumber: 2n,
        signatureVerified: true,
      });
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValueOnce(
        new TextEncoder().encode(JSON.stringify(published))
      );

      await (client as unknown as ClientInternals).refreshFolderStateFromNetwork(folder);

      // Write-body mirror preserved -- NOT wiped by the write-body-less network view.
      expect(folder.metadata?.writeBody?.writeChildren).toEqual(seededWriteChildren);
      // Read-body children/sequence DID adopt the fresher network view.
      expect(folder.children).toEqual(freshReadOnlyNode.children);
      expect(folder.sequenceNumber).toBe(2n);
    });

    it('anti-rollback: never adopts a record at or below the in-memory sequence', async () => {
      const client = new CipherBoxClient(createTestConfig());
      const originalChildren: SealedChildRef[] = [
        {
          name: 'keep.txt',
          ipnsName: 'k51keep',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'k',
        },
      ];
      const originalWriteBody = {
        ipnsPrivateKey: new Uint8Array(64).fill(9),
        writeChildren: [
          { childId: '33333333-3333-4333-8333-333333333333', writeKeySealed: 'unchanged' },
        ] as WriteChildRef[],
      };

      const folder: FolderState = {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32).fill(1),
        writeKey: new Uint8Array(32).fill(7),
        ipnsKeypair: {
          publicKey: new Uint8Array(32).fill(2),
          privateKey: new Uint8Array(64).fill(3),
        },
        sequenceNumber: 5n,
        children: originalChildren,
        metadata: {
          schema: 'node/v3',
          kind: 'folder',
          id: 'folder-node-id',
          generation: 0,
          createdAt: 0,
          modifiedAt: 0,
          children: originalChildren,
          writeBody: originalWriteBody,
        },
        lastLoadedAt: Date.now(),
        nodeId: 'folder-node-id',
        nodeGeneration: 0,
      };

      // Equal sequence -- NOT strictly newer, must be rejected before any fetch.
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValueOnce({
        cid: 'bafystale',
        sequenceNumber: 5n,
        signatureVerified: true,
      });

      await (client as unknown as ClientInternals).refreshFolderStateFromNetwork(folder);

      expect(sdkCore.fetchFromIpfs).not.toHaveBeenCalled();
      expect(folder.sequenceNumber).toBe(5n);
      expect(folder.children).toBe(originalChildren);
      expect(folder.metadata?.writeBody).toBe(originalWriteBody);
    });
  });

  describe('cold-load writeKey recovery (ensureFolderLoaded / requireFolder)', () => {
    it('recovers a real writeKey + populated writeBody for a read-only-seeded entry reachable from a write-capable root', async () => {
      const rootFolderKey = new Uint8Array(32).fill(0x10);
      const rootWriteKey = new Uint8Array(32).fill(0x20);
      const rootIpnsKeypair = generateEd25519Keypair();

      const client = new CipherBoxClient(
        createTestConfig({
          rootIpnsName: ROOT_IPNS,
          rootFolderKey,
          rootWriteKey,
          rootIpnsKeypair,
        })
      );

      // Real, freshly-recoverable child key material.
      const childReadKey = new Uint8Array(32).fill(0x11);
      const childWriteKey = new Uint8Array(32).fill(0x22);
      const childIpnsKeypair = generateEd25519Keypair();

      const childSealedRef: SealedChildRef = {
        name: 'child-folder',
        ipnsName: CHILD_IPNS,
        generation: 0,
        versionFloor: 1n,
        readKeySealed: await sealChildReadKey(
          childReadKey,
          rootFolderKey,
          CHILD_NODE_ID,
          'folder',
          0
        ),
      };
      const rootWriteChildRef: WriteChildRef = {
        childId: CHILD_NODE_ID,
        writeKeySealed: await sealChildWriteKey(
          childWriteKey,
          rootWriteKey,
          CHILD_NODE_ID,
          'folder',
          0
        ),
      };

      // Root FolderState pre-seeded directly (bypasses ensureRootFolderState's
      // own network resolve -- this test only exercises the DFS recovery hop).
      const rootState: FolderState = {
        ipnsName: ROOT_IPNS,
        folderKey: rootFolderKey,
        writeKey: rootWriteKey,
        ipnsKeypair: rootIpnsKeypair,
        sequenceNumber: 1n,
        children: [childSealedRef],
        metadata: {
          schema: 'node/v3',
          kind: 'root',
          id: 'root-node-id',
          generation: 0,
          createdAt: 0,
          modifiedAt: 0,
          children: [childSealedRef],
          writeBody: {
            ipnsPrivateKey: rootIpnsKeypair.privateKey,
            writeChildren: [rootWriteChildRef],
          },
        },
        lastLoadedAt: Date.now(),
        nodeId: 'root-node-id',
        nodeGeneration: 0,
      };
      client.getFolderTree().set(ROOT_IPNS, rootState);

      // The child's own on-wire published node (served by the mocked network
      // seams below) -- carries its own write-body so dfsFindFolder accepts it.
      const childNode: Node = {
        schema: 'node/v3',
        kind: 'folder',
        id: CHILD_NODE_ID,
        generation: 0,
        createdAt: 0,
        modifiedAt: 0,
        children: [],
        writeBody: { ipnsPrivateKey: childIpnsKeypair.privateKey, writeChildren: [] },
      };
      const publishedChild = await sealNode(childNode, childReadKey, childWriteKey);
      vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
        if (ipnsName === CHILD_IPNS) {
          return { cid: 'bafychild', sequenceNumber: 3n, signatureVerified: true };
        }
        return null;
      });
      vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
        if (cid === 'bafychild') {
          return new TextEncoder().encode(JSON.stringify(publishedChild));
        }
        throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
      });

      // Pre-existing read-only-seeded entry (registerFolder/loadFolder without
      // a writeKey -- the web-layer's parallel navigateReadChain walk).
      // Deliberately DISTINCT placeholder folderKey/ipnsKeypair from the
      // "correct" childReadKey above, so a passing preservation assertion
      // proves the recovery path did NOT overwrite the read-plane fields.
      const placeholderFolderKey = new Uint8Array(32).fill(0xab);
      const placeholderIpnsKeypair = {
        publicKey: new Uint8Array(32).fill(0xcd),
        privateKey: new Uint8Array(64).fill(0xef),
      };
      client.getFolderTree().set(CHILD_IPNS, {
        ipnsName: CHILD_IPNS,
        folderKey: placeholderFolderKey,
        writeKey: new Uint8Array(32), // zeroed -- read-only seed
        ipnsKeypair: placeholderIpnsKeypair,
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
        nodeId: CHILD_NODE_ID,
        nodeGeneration: 0,
      });

      const result = await client.ensureFolderLoaded(CHILD_IPNS);

      expect(result).not.toBeNull();
      // Real, non-zero writeKey recovered.
      expect(result!.writeKey.length).toBe(32);
      expect(result!.writeKey.every((b) => b === 0)).toBe(false);
      expect(result!.writeKey).toEqual(childWriteKey);
      // Write-body mirror populated.
      expect(result!.metadata?.writeBody).toBeDefined();
      expect(result!.metadata?.writeBody?.writeChildren).toEqual([]);
      // Read-plane fields (readKey/ipnsKeypair) preserved exactly as seeded --
      // NOT replaced by the DFS re-walk's own recovered values.
      expect(result!.folderKey).toEqual(placeholderFolderKey);
      expect(result!.ipnsKeypair.publicKey).toEqual(placeholderIpnsKeypair.publicKey);
      expect(result!.ipnsKeypair.privateKey).toEqual(placeholderIpnsKeypair.privateKey);

      // requireFolder (the mutation chokepoint) routes through the same
      // recovery path for an already-loaded entry.
      const viaRequireFolder = await client.ensureFolderLoaded(CHILD_IPNS);
      expect(viaRequireFolder!.writeKey.every((b) => b === 0)).toBe(false);
    });

    it('is a no-op when the entry already carries a real writeKey', async () => {
      const client = new CipherBoxClient(
        createTestConfig({
          rootIpnsName: ROOT_IPNS,
          rootWriteKey: new Uint8Array(32).fill(0x20),
          rootIpnsKeypair: generateEd25519Keypair(),
        })
      );
      const realWriteKey = new Uint8Array(32).fill(0x99);
      client.getFolderTree().set(CHILD_IPNS, {
        ipnsName: CHILD_IPNS,
        folderKey: new Uint8Array(32).fill(1),
        writeKey: realWriteKey,
        ipnsKeypair: {
          publicKey: new Uint8Array(32).fill(2),
          privateKey: new Uint8Array(64).fill(3),
        },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
        nodeId: CHILD_NODE_ID,
        nodeGeneration: 0,
      });

      const result = await client.ensureFolderLoaded(CHILD_IPNS);

      expect(result!.writeKey).toEqual(realWriteKey);
      // No DFS walk needed -- no network calls issued.
      expect(sdkCore.resolveIpnsRecord).not.toHaveBeenCalled();
    });

    it('is a no-op (stays read-only) when no root write material is configured', async () => {
      // createTestConfig defaults omit rootWriteKey/rootIpnsKeypair.
      const client = new CipherBoxClient(createTestConfig());
      client.getFolderTree().set(CHILD_IPNS, {
        ipnsName: CHILD_IPNS,
        folderKey: new Uint8Array(32).fill(1),
        writeKey: new Uint8Array(32), // zeroed
        ipnsKeypair: {
          publicKey: new Uint8Array(32).fill(2),
          privateKey: new Uint8Array(64).fill(3),
        },
        sequenceNumber: 1n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
        nodeId: CHILD_NODE_ID,
        nodeGeneration: 0,
      });

      const result = await client.ensureFolderLoaded(CHILD_IPNS);

      expect(result!.writeKey.every((b) => b === 0)).toBe(true);
      expect(sdkCore.resolveIpnsRecord).not.toHaveBeenCalled();
    });
  });
});
