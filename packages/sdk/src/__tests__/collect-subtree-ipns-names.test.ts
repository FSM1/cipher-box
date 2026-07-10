/**
 * `CipherBoxClient.deleteItem`'s fire-and-forget IPNS-unenroll subtree walk
 * (`collectRemovedItemIpnsNames` / `collectDescendantIpnsNames`, 68.1-02).
 *
 * The pre-Phase-65 version of this suite mocked `sdkCore.loadFolderMetadata`
 * directly to simulate an on-demand read-body-only DFS. That function/seam no
 * longer exists (Phase 68.1-02 rewrote the collector on top of the node/v3
 * read-chain): the walk now resolves each hop's real `PublishedNode`
 * (`resolveIpnsRecord` + `fetchFromIpfs`) and recovers its readKey via
 * `unsealChildReadKey` before descending. Only the network-touching sdk-core
 * seams and the unenroll API call are mocked; every `@cipherbox/core`
 * seal/unseal primitive stays real (mirrors delete-item.test.ts /
 * ensure-folder-loaded.test.ts).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import { sealNode, sealChildReadKey, type Node, type SealedChildRef } from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
  };
});

vi.mock('@cipherbox/api-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/api-client')>();
  return {
    ...actual,
    ipnsControllerUnenrollBatch: vi.fn().mockResolvedValue(undefined),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import { ipnsControllerUnenrollBatch } from '@cipherbox/api-client';

const DUMMY_WRITE_KEY = new Uint8Array(32); // sealNode requires a writeKey arg even when node.writeBody is absent

/** Register a (ipnsName -> {cid, published bytes}) network fixture; missing entries resolve null. */
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

function folderState(overrides: Partial<FolderState> & { ipnsName: string }): FolderState {
  return {
    folderKey: new Uint8Array(32).fill(1),
    // All-zero: legacy zero-fallback writeKey (FolderState doc comment,
    // types.ts) so getWriteBodyParams short-circuits to `{}` -- these
    // deleteItem-driven traversal tests don't exercise the write-chain trim.
    writeKey: new Uint8Array(32),
    ipnsKeypair: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(64).fill(2) },
    sequenceNumber: 1n,
    children: [],
    metadata: null,
    lastLoadedAt: Date.now(),
    nodeId: `${overrides.ipnsName}-node`,
    nodeGeneration: 0,
    ...overrides,
  };
}

describe('CipherBoxClient.deleteItem — fire-and-forget IPNS unenroll subtree walk', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The failure-path test intentionally exercises console.warn (e.g. "could
    // not load metadata ... skipping children"). Silence it to keep CI stderr
    // clean; the test that triggers it asserts on the call explicitly below.
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.mocked(ipnsControllerUnenrollBatch).mockResolvedValue(undefined as never);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      newSequenceNumber: 2n,
      publishedChildren: [],
      cid: 'cid-new',
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('Test A: collects names from an unloaded subfolder via on-demand fetch', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const PARENT = 'k51parent';
    const SUBFOLDER = 'k51sub';
    const SUBFOLDER_FILE = 'k51subfile';
    const SUBFOLDER_NODE_ID = '11111111-1111-4111-8111-111111111111';
    const FILE_NODE_ID = '22222222-2222-4222-8222-222222222222';

    const parentReadKey = new Uint8Array(32).fill(1);
    const subfolderReadKey = new Uint8Array(32).fill(2);

    const subfolderRef: SealedChildRef = {
      name: 'SubFolder',
      ipnsName: SUBFOLDER,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        subfolderReadKey,
        parentReadKey,
        SUBFOLDER_NODE_ID,
        'folder',
        0
      ),
    };
    client
      .getFolderTree()
      .set(
        PARENT,
        folderState({ ipnsName: PARENT, folderKey: parentReadKey, children: [subfolderRef] })
      );

    const fileRef: SealedChildRef = {
      name: 'file.txt',
      ipnsName: SUBFOLDER_FILE,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        new Uint8Array(32).fill(9),
        subfolderReadKey,
        FILE_NODE_ID,
        'file',
        0
      ),
    };
    const subfolderNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: SUBFOLDER_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [fileRef],
    };
    mockNetwork({
      [SUBFOLDER]: {
        cid: 'cid-subfolder',
        published: await sealNode(subfolderNode, subfolderReadKey, DUMMY_WRITE_KEY),
      },
      // SUBFOLDER_FILE resolves to a plain 'file' kind node -- collectDescendantIpnsNames
      // returns its own ipnsName without unsealing anything further.
      [SUBFOLDER_FILE]: {
        cid: 'cid-file',
        published: {
          schema: 'node/v3',
          kind: 'file',
          id: FILE_NODE_ID,
          generation: 0,
          aeadVersion: 1,
          readSealed: 'unused',
        },
      },
    });

    await client.deleteItem(PARENT, SUBFOLDER);

    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    const allNames = vi
      .mocked(ipnsControllerUnenrollBatch)
      .mock.calls.flatMap((call) => call[0].ipnsNames);

    expect(allNames).toContain(SUBFOLDER);
    expect(allNames).toContain(SUBFOLDER_FILE);
  });

  it('Test B: one sibling fetch failure does not abort collection of the other', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const GRANDPARENT = 'k51grand';
    const PARENT = 'k51parent';
    const SIBLING_A = 'k51sibA';
    const SIBLING_A_FILE = 'k51sibAfile';
    const SIBLING_B = 'k51sibB';
    const PARENT_NODE_ID = '33333333-3333-4333-8333-333333333333';
    const SIBLING_A_NODE_ID = '44444444-4444-4444-8444-444444444444';
    const SIBLING_A_FILE_NODE_ID = '55555555-5555-4555-8555-555555555555';
    const SIBLING_B_NODE_ID = '66666666-6666-4666-8666-666666666666';

    const grandparentReadKey = new Uint8Array(32).fill(1);
    const parentReadKey = new Uint8Array(32).fill(3);
    const siblingAReadKey = new Uint8Array(32).fill(4);

    const parentRef: SealedChildRef = {
      name: 'Parent',
      ipnsName: PARENT,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        parentReadKey,
        grandparentReadKey,
        PARENT_NODE_ID,
        'folder',
        0
      ),
    };
    client
      .getFolderTree()
      .set(
        GRANDPARENT,
        folderState({ ipnsName: GRANDPARENT, folderKey: grandparentReadKey, children: [parentRef] })
      );

    const siblingARef: SealedChildRef = {
      name: 'SibA',
      ipnsName: SIBLING_A,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        siblingAReadKey,
        parentReadKey,
        SIBLING_A_NODE_ID,
        'folder',
        0
      ),
    };
    const siblingBRef: SealedChildRef = {
      name: 'SibB',
      ipnsName: SIBLING_B,
      generation: 0,
      versionFloor: 0n,
      // SIBLING_B's own fetch throws below -- its readKeySealed content is
      // never reached, so a placeholder seal (under the wrong key) is fine.
      readKeySealed: await sealChildReadKey(
        new Uint8Array(32).fill(8),
        parentReadKey,
        SIBLING_B_NODE_ID,
        'folder',
        0
      ),
    };
    const parentNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: PARENT_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [siblingARef, siblingBRef],
    };

    const siblingAFileRef: SealedChildRef = {
      name: 'afile.txt',
      ipnsName: SIBLING_A_FILE,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        new Uint8Array(32).fill(9),
        siblingAReadKey,
        SIBLING_A_FILE_NODE_ID,
        'file',
        0
      ),
    };
    const siblingANode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: SIBLING_A_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [siblingAFileRef],
    };

    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === PARENT)
        return { cid: 'cid-parent', sequenceNumber: 1n, signatureVerified: true };
      if (ipnsName === SIBLING_A)
        return { cid: 'cid-sibA', sequenceNumber: 1n, signatureVerified: true };
      if (ipnsName === SIBLING_A_FILE)
        return { cid: 'cid-sibA-file', sequenceNumber: 1n, signatureVerified: true };
      if (ipnsName === SIBLING_B)
        return { cid: 'cid-sibB', sequenceNumber: 1n, signatureVerified: true };
      return null;
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'cid-parent') {
        return new TextEncoder().encode(
          JSON.stringify(await sealNode(parentNode, parentReadKey, DUMMY_WRITE_KEY))
        );
      }
      if (cid === 'cid-sibA') {
        return new TextEncoder().encode(
          JSON.stringify(await sealNode(siblingANode, siblingAReadKey, DUMMY_WRITE_KEY))
        );
      }
      if (cid === 'cid-sibA-file') {
        return new TextEncoder().encode(
          JSON.stringify({
            schema: 'node/v3',
            kind: 'file',
            id: SIBLING_A_FILE_NODE_ID,
            generation: 0,
            aeadVersion: 1,
            readSealed: 'unused',
          })
        );
      }
      // SIBLING_B's content fetch fails (simulated transient network error).
      if (cid === 'cid-sibB') {
        throw new Error(`simulated fetch failure for ${SIBLING_B}`);
      }
      throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
    });

    await expect(client.deleteItem(GRANDPARENT, PARENT)).resolves.not.toThrow();

    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining(`unreadable descendant ${SIBLING_B}`),
      expect.anything()
    );

    const allNames = vi
      .mocked(ipnsControllerUnenrollBatch)
      .mock.calls.flatMap((call) => call[0].ipnsNames);

    expect(allNames).toContain(PARENT);
    expect(allNames).toContain(SIBLING_A_FILE);
    expect(allNames).toContain(SIBLING_B);
  });

  it('Test C: on-demand traversal does not mutate folderTree', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const PARENT = 'k51parent';
    const SUBFOLDER = 'k51sub';
    const SUBFOLDER_NODE_ID = '11111111-1111-4111-8111-111111111111';

    const parentReadKey = new Uint8Array(32).fill(1);
    const subfolderReadKey = new Uint8Array(32).fill(2);

    const subfolderRef: SealedChildRef = {
      name: 'SubFolder',
      ipnsName: SUBFOLDER,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        subfolderReadKey,
        parentReadKey,
        SUBFOLDER_NODE_ID,
        'folder',
        0
      ),
    };
    client
      .getFolderTree()
      .set(
        PARENT,
        folderState({ ipnsName: PARENT, folderKey: parentReadKey, children: [subfolderRef] })
      );

    const subfolderNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: SUBFOLDER_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
    };
    mockNetwork({
      [SUBFOLDER]: {
        cid: 'cid-subfolder',
        published: await sealNode(subfolderNode, subfolderReadKey, DUMMY_WRITE_KEY),
      },
    });

    await client.deleteItem(PARENT, SUBFOLDER);

    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    // SUBFOLDER was fetched on demand but must NOT be written to folderTree --
    // the traversal keeps fetched metadata local to its own call stack.
    expect(client.getFolderTree().has(SUBFOLDER)).toBe(false);
    expect(client.getFolderTree().has(PARENT)).toBe(true);
  });

  // Test D (cycle guard): a cyclic folder graph A -> B -> A. Mirrors the
  // `visited: Set<string>` guard `dfsFindFolder` uses to survive "a
  // cyclic/malicious tree" -- `collectDescendantIpnsNames` now threads its own
  // `visited` set (seeded by both entry collectors) and checks-and-adds each
  // `childRef.ipnsName` before any await: an already-seen node contributes its
  // own name once but is NEVER re-walked. Folder A's node lists folder B as a
  // child, and B's node lists A back -- a folder's children are
  // attacker-influenced content once shared, so a malicious/corrupt back-edge
  // to an ancestor is a real input. Without the guard this recurses without
  // bound (RangeError: Maximum call stack size exceeded, or a hang bounded only
  // by pLimit concurrency); with it, the walk terminates and each node's
  // SUBTREE is expanded exactly once. Note B (whose only inbound path is A's
  // forward edge) is therefore collected exactly once, which is the precise
  // cycle-break witness -- A appears twice in the raw name list only because
  // deleteItem prepends the removed item's OWN name AND B's back-edge
  // contributes A once as a non-expanded leaf, NOT because A's subtree was
  // walked twice.
  it('Test D: a cyclic folder graph A->B->A terminates via the visited guard (B walked exactly once)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const PARENT = 'k51parent';
    const FOLDER_A = 'k51cycleA';
    const FOLDER_B = 'k51cycleB';
    const FOLDER_A_NODE_ID = '77777777-7777-4777-8777-777777777777';
    const FOLDER_B_NODE_ID = '88888888-8888-4888-8888-888888888888';

    const parentReadKey = new Uint8Array(32).fill(1);
    const folderAReadKey = new Uint8Array(32).fill(5);
    const folderBReadKey = new Uint8Array(32).fill(6);

    // PARENT holds FOLDER_A (the deleted item).
    const folderARef: SealedChildRef = {
      name: 'FolderA',
      ipnsName: FOLDER_A,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        folderAReadKey,
        parentReadKey,
        FOLDER_A_NODE_ID,
        'folder',
        0
      ),
    };
    client
      .getFolderTree()
      .set(
        PARENT,
        folderState({ ipnsName: PARENT, folderKey: parentReadKey, children: [folderARef] })
      );

    // A lists B (sealed under A's readKey).
    const folderBRefUnderA: SealedChildRef = {
      name: 'FolderB',
      ipnsName: FOLDER_B,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        folderBReadKey,
        folderAReadKey,
        FOLDER_B_NODE_ID,
        'folder',
        0
      ),
    };
    const folderANode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: FOLDER_A_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [folderBRefUnderA],
    };

    // B lists A back (sealed under B's readKey) -- the cycle.
    const folderARefUnderB: SealedChildRef = {
      name: 'FolderA',
      ipnsName: FOLDER_A,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: await sealChildReadKey(
        folderAReadKey,
        folderBReadKey,
        FOLDER_A_NODE_ID,
        'folder',
        0
      ),
    };
    const folderBNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: FOLDER_B_NODE_ID,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [folderARefUnderB],
    };

    mockNetwork({
      [FOLDER_A]: {
        cid: 'cid-cycleA',
        published: await sealNode(folderANode, folderAReadKey, DUMMY_WRITE_KEY),
      },
      [FOLDER_B]: {
        cid: 'cid-cycleB',
        published: await sealNode(folderBNode, folderBReadKey, DUMMY_WRITE_KEY),
      },
    });

    // Must terminate (no stack overflow / no hang) -- the guard breaks the cycle.
    await expect(client.deleteItem(PARENT, FOLDER_A)).resolves.not.toThrow();

    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    const allNames = vi
      .mocked(ipnsControllerUnenrollBatch)
      .mock.calls.flatMap((call) => call[0].ipnsNames);

    // Both cycle nodes collected.
    expect(allNames).toContain(FOLDER_A);
    expect(allNames).toContain(FOLDER_B);
    // Cycle-break witness: B's subtree is walked exactly once. Without the
    // visited guard, A<->B would re-expand unbounded and B would appear many
    // times (before the stack overflowed).
    expect(allNames.filter((n) => n === FOLDER_B)).toHaveLength(1);
    // The full name list is finite and small: the guard caps A's back-edge to a
    // single non-expanded leaf contribution, so the deterministic output is
    // exactly [FOLDER_A (removed item), FOLDER_B, FOLDER_A (B's back-edge leaf)].
    expect(allNames).toHaveLength(3);
    expect(allNames.filter((n) => n === FOLDER_A)).toHaveLength(2);
    // Only the two distinct nodes are ever named.
    expect(new Set(allNames)).toEqual(new Set([FOLDER_A, FOLDER_B]));
  });
});
