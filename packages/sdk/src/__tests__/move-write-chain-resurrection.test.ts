/**
 * Regression test for the write-chain-resurrection gap in
 * `CipherBoxClient.moveItem` (HIGH-severity, follow-up to Phase 72's
 * write-plane durability work).
 *
 * `moveItem` drops the moved child's `WriteChildRef` from the SOURCE
 * folder's write-body (72-08 write-link re-homing) but historically
 * published the SOURCE folder WITHOUT threading `baseWriteChildren` into
 * `updateFolderMetadataAndPublish`. Per `folder/registration.ts`'s
 * CAS-409 merge (see its `merge` closure), an absent `baseWriteChildren`
 * falls back to the legacy NAIVE UNION: a racing writer's stale remote
 * write-body snapshot (which still carries the just-dropped
 * `WriteChildRef`) gets unioned back in, resurrecting the dropped
 * write-link in the SOURCE folder even though the child has already moved
 * elsewhere. `deleteItem` (72-03) and `restoreFromBin`/
 * `permanentDeleteFromBin` (72-05) both thread `baseWriteChildren` already;
 * this test proves `moveItem`'s SOURCE publish does the same.
 *
 * Mock scaffolding mirrors `move-write-link-rehoming.test.ts` (the closest
 * existing `moveItem` unit test): `updateFolderMetadataAndPublish` is
 * mocked directly (network I/O is several bundled layers below it — see
 * `folder/registration.ts` — so mocking only the leaf IO seams from this
 * package cannot intercept its internal CAS-409 retry). The mock
 * implementation below reproduces `registration.ts`'s exact write-body
 * merge algorithm byte-for-byte (both the base-aware-prune branch and the
 * legacy-naive-union fallback) so the test genuinely exercises the same
 * merge semantics a real CAS-409 round would hit, keyed off whatever
 * `baseWriteChildren` value `moveItem`'s SOURCE-publish call site actually
 * threads through -- exactly the value this fix changes.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import {
  sealChildReadKey,
  sealChildWriteKey,
  type SealedChildRef,
  type WriteChildRef,
} from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const SRC_IPNS = 'k51src-resurrection';
const DEST_IPNS = 'k51dest-resurrection';
const CHILD_IPNS = 'k51child-resurrection';
const NODE_UUID = '66666666-6666-4666-8666-666666666666';
const GEN = 0;

interface CapturedPublishArgs {
  ipnsName: string;
  children: SealedChildRef[];
  writeKey?: Uint8Array;
  writeChildren?: WriteChildRef[];
  baseWriteChildren?: WriteChildRef[];
}

/**
 * Mock `updateFolderMetadataAndPublish` implementation: the DEST call always
 * publishes clean (no conflict -- moveItem's dest-before-source ordering
 * means dest never races). The SOURCE call simulates EXACTLY ONE CAS-409
 * round against a racing writer whose stale remote write-body snapshot still
 * carries the moved child's WriteChildRef (`racingRemoteWriteChildren`),
 * merged via registration.ts's real algorithm (copied verbatim from
 * `folder/registration.ts`'s `merge` closure -- see reference there for the
 * base-aware-prune vs. legacy-naive-union branches).
 */
function mockPublishWithSourceCas409(
  racingRemoteWriteChildren: WriteChildRef[]
): () => CapturedPublishArgs | null {
  const calls: CapturedPublishArgs[] = [];
  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (params) => {
    calls.push(params as unknown as CapturedPublishArgs);

    if (params.ipnsName === DEST_IPNS) {
      return {
        cid: 'bafydest',
        newSequenceNumber: 2n,
        publishedChildren: params.children,
        publishedWriteChildren: params.writeChildren,
      };
    }

    // SOURCE call: simulate the CAS-409 merge registration.ts performs.
    const localWriteChildren = params.writeChildren ?? [];
    let mergedWriteChildren: WriteChildRef[];
    if (params.baseWriteChildren) {
      // Base-aware prune (SC#1 Critical Finding 2 / T-72-03-01): a childId
      // present in base but absent from local is an intentional delete this
      // transaction already committed to -- never resurrected, even if the
      // racing writer's stale remote snapshot still carries it.
      const baseIds = new Set(params.baseWriteChildren.map((wc) => wc.childId));
      const mergedMap = new Map<string, WriteChildRef>();
      for (const wc of localWriteChildren) mergedMap.set(wc.childId, wc);
      for (const wc of racingRemoteWriteChildren) {
        if (!baseIds.has(wc.childId) || mergedMap.has(wc.childId)) {
          mergedMap.set(wc.childId, wc);
        }
      }
      mergedWriteChildren = Array.from(mergedMap.values());
    } else {
      // Legacy naive union (back-compat for callers that have not threaded
      // baseWriteChildren through) -- this is the bug: it resurrects any
      // childId the racing writer's stale remote snapshot still carries,
      // even one the local transaction just intentionally dropped.
      const byChildId = new Map<string, WriteChildRef>();
      for (const wc of localWriteChildren) byChildId.set(wc.childId, wc);
      for (const wc of racingRemoteWriteChildren) byChildId.set(wc.childId, wc);
      mergedWriteChildren = Array.from(byChildId.values());
    }

    return {
      cid: 'bafysrc',
      newSequenceNumber: 3n,
      publishedChildren: params.children,
      publishedWriteChildren: mergedWriteChildren,
    };
  });
  return () => calls.find((c) => c.ipnsName === SRC_IPNS) ?? null;
}

async function seedMove(client: CipherBoxClient): Promise<{
  sourceWriteChildren: WriteChildRef[];
}> {
  const srcFolderKey = new Uint8Array(32).fill(0x11);
  const destFolderKey = new Uint8Array(32).fill(0x22);
  const sourceWriteKey = new Uint8Array(32).fill(0x33);
  const destWriteKey = new Uint8Array(32).fill(0x44);
  const childWriteKey = new Uint8Array(32).fill(0x77);

  const readKeySealed = await sealChildReadKey(
    new Uint8Array(32).fill(0x55),
    srcFolderKey,
    NODE_UUID,
    'file',
    GEN
  );
  const movedEntry: SealedChildRef = {
    name: 'file.txt',
    ipnsName: CHILD_IPNS,
    generation: GEN,
    versionFloor: 1n,
    readKeySealed,
  };

  const writeKeySealed = await sealChildWriteKey(
    childWriteKey,
    sourceWriteKey,
    NODE_UUID,
    'file',
    GEN
  );
  const sourceWriteChildren: WriteChildRef[] = [{ childId: NODE_UUID, writeKeySealed }];

  const srcState: FolderState = {
    ipnsName: SRC_IPNS,
    folderKey: srcFolderKey,
    writeKey: sourceWriteKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [movedEntry],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'src-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [movedEntry],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren: sourceWriteChildren },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'src-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(SRC_IPNS, srcState);

  const destState: FolderState = {
    ipnsName: DEST_IPNS,
    folderKey: destFolderKey,
    writeKey: destWriteKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(4),
      privateKey: new Uint8Array(64).fill(5),
    },
    sequenceNumber: 1n,
    children: [],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'dest-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(5), writeChildren: [] },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'dest-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(DEST_IPNS, destState);

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === CHILD_IPNS) {
      return { cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true };
    }
    // src/dest reconcile calls -- null short-circuits reconcileFolderSequence.
    return null;
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafychild') {
      return new TextEncoder().encode(
        JSON.stringify({
          schema: 'node/v3',
          kind: 'file',
          id: NODE_UUID,
          generation: GEN,
          createdAt: 0,
          modifiedAt: 0,
        })
      );
    }
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });

  return { sourceWriteChildren };
}

describe('CipherBoxClient.moveItem -- write-chain resurrection guard (HIGH severity follow-up)', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('does not resurrect the moved child WriteChildRef in the SOURCE write-body after a CAS-409 with a racing writer stale snapshot', async () => {
    const { sourceWriteChildren } = await seedMove(client);

    // The racing writer's remote snapshot predates the move -- it still
    // carries the moved child's WriteChildRef (identical to the source
    // folder's pre-drop write-body).
    const getSourceCall = mockPublishWithSourceCas409(sourceWriteChildren);

    await client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS);

    const sourceCall = getSourceCall();
    expect(sourceCall).not.toBeNull();

    // The fix: moveItem's SOURCE publish must thread baseWriteChildren
    // (the pre-drop snapshot) so the CAS-409 merge is base-aware and never
    // resurrects an intentionally-dropped childId.
    expect(sourceCall!.baseWriteChildren).toBeDefined();
    expect(sourceCall!.baseWriteChildren).toEqual(sourceWriteChildren);

    // The moved child's WriteChildRef must NOT be present in the final
    // published SOURCE write-body -- not resurrected by the racing writer's
    // stale snapshot.
    const finalSource = client.getFolderTree().get(SRC_IPNS)!;
    const resurrected = finalSource.metadata?.writeBody?.writeChildren?.some(
      (wc) => wc.childId === NODE_UUID
    );
    expect(resurrected).toBe(false);
  });
});
