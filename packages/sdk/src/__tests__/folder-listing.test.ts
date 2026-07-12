/**
 * Phase 68.2 Plan 02 (TDD): failing-first proof of the SDK-owned resolved
 * folder-listing API -- `client.listFolder` / `client.listSharedFolder`
 * returning `ResolvedChild[]` (SC#2, D-02).
 *
 * Covers:
 *  - Test 1: listFolder(ipnsName) returns one ResolvedChild per child, with
 *    kind resolved from the child's PublishedNode.kind, name from the
 *    SealedChildRef, ipnsName from the ref, and sequence from the resolved
 *    record.
 *  - Test 2: a file child carries the plaintext byte size + last-modified
 *    time; a folder child's size is undefined.
 *  - Test 3: listSharedFolder(shareId, path) returns ResolvedChild[] for an
 *    INTERMEDIATE folder (not forced to a file leaf -- proving the hoisted
 *    walk, not navigateReadChain, is used; Pitfall 1).
 *  - Test 4: a second listFolder call for the same ipnsName at an unchanged
 *    sequence returns cached children without re-resolving (D-02 cache).
 *  - Test 5 (68.2-02 Task 3): folder:loaded carries ResolvedChild[] with
 *    kind pre-resolved (event payload retype).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import {
  sealNode,
  sealChildReadKey,
  type Node,
  type SealedChildRef,
  type PublishedNode,
  type NodeKind,
} from '@cipherbox/core';

// ── sdk-core mock (network-touching seams only) ─────────────────────────
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    loadFolderMetadata: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const FOLDER_IPNS = 'k51folder-listing-test';
const FILE_CHILD_IPNS = 'k51file-child-listing-test';
const FOLDER_CHILD_IPNS = 'k51folder-child-listing-test';
const SHARE_ID = 'share-listing-test';
const SHARED_ROOT_IPNS = 'k51shared-root-listing-test';
const SHARED_SUBFOLDER_IPNS = 'k51shared-subfolder-listing-test';
const SHARED_INNER_FILE_IPNS = 'k51shared-inner-file-listing-test';

const PARENT_READ_KEY = new Uint8Array(32).fill(0x01);
const FILE_READ_KEY = new Uint8Array(32).fill(0x02);
const FOLDER_READ_KEY = new Uint8Array(32).fill(0x03);
const SHARE_ROOT_READ_KEY = new Uint8Array(32).fill(0x30);
const SUBFOLDER_READ_KEY = new Uint8Array(32).fill(0x31);
/** Unused by children (they carry no write-body) -- dummy zero key for sealNode's required param. */
const DUMMY_WRITE_KEY = new Uint8Array(32);

type ChildFixture = {
  childRef: SealedChildRef;
  published: PublishedNode;
  sequenceNumber: bigint;
  signatureVerified?: boolean;
};

/** Builds a real (non-mocked-crypto) sealed child fixture: a SealedChildRef + the child's own PublishedNode envelope. */
async function buildChildFixture(opts: {
  id: string;
  ipnsName: string;
  name: string;
  kind: NodeKind;
  generation: number;
  parentReadKey: Uint8Array;
  childReadKey: Uint8Array;
  modifiedAt: number;
  /** Node createdAt; defaults to modifiedAt when omitted. Set distinct to
   *  prove resolveChildren does not project modifiedAt into createdAt. */
  createdAt?: number;
  sequenceNumber: bigint;
  size?: number;
  children?: SealedChildRef[];
  signatureVerified?: boolean;
}): Promise<ChildFixture> {
  const node: Node = {
    schema: 'node/v3',
    kind: opts.kind,
    id: opts.id,
    generation: opts.generation,
    createdAt: opts.createdAt ?? opts.modifiedAt,
    modifiedAt: opts.modifiedAt,
    ...(opts.kind === 'folder' || opts.kind === 'root' ? { children: opts.children ?? [] } : {}),
    ...(opts.kind === 'file'
      ? {
          content: {
            cid: `bafyfile-${opts.id}`,
            fileIv: 'iv',
            size: opts.size ?? 0,
            mimeType: 'text/plain',
            encryptionMode: 'GCM' as const,
            fileKey: new Uint8Array(32).fill(0x09),
            versions: [],
          },
        }
      : {}),
  };
  const published = await sealNode(node, opts.childReadKey, DUMMY_WRITE_KEY);
  const readKeySealed = await sealChildReadKey(
    opts.childReadKey,
    opts.parentReadKey,
    opts.id,
    opts.kind,
    opts.generation
  );
  const childRef: SealedChildRef = {
    name: opts.name,
    ipnsName: opts.ipnsName,
    generation: opts.generation,
    versionFloor: 0n,
    readKeySealed,
  };
  return {
    childRef,
    published,
    sequenceNumber: opts.sequenceNumber,
    signatureVerified: opts.signatureVerified,
  };
}

/** Wires resolveIpnsRecord/fetchFromIpfs mocks to serve a set of child fixtures keyed by ipnsName. */
function mockResolvesFor(fixtures: ChildFixture[]) {
  const byIpns = new Map(fixtures.map((f) => [f.childRef.ipnsName, f]));
  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    const fixture = byIpns.get(ipnsName);
    if (!fixture) return null;
    return {
      cid: `bafy-${ipnsName}`,
      sequenceNumber: fixture.sequenceNumber,
      signatureVerified: fixture.signatureVerified ?? true,
    };
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: unknown) => {
    const fixture = fixtures.find((f) => `bafy-${f.childRef.ipnsName}` === cid);
    if (!fixture) throw new Error(`No fixture wired for cid ${String(cid)}`);
    return new TextEncoder().encode(JSON.stringify(fixture.published));
  });
}

function seedFolder(
  client: CipherBoxClient,
  ipnsName: string,
  children: SealedChildRef[],
  sequenceNumber = 1n
) {
  client.getFolderTree().set(ipnsName, {
    ipnsName,
    folderKey: PARENT_READ_KEY,
    writeKey: new Uint8Array(32),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0x20),
      privateKey: new Uint8Array(64).fill(0x21),
    },
    sequenceNumber,
    children,
    metadata: null,
    lastLoadedAt: Date.now(),
    nodeId: 'folder-node-id',
    nodeGeneration: 0,
  });
}

function seedSharedFolder(
  client: CipherBoxClient,
  shareId: string,
  ipnsName: string,
  children: SealedChildRef[],
  sequenceNumber = 1n
) {
  client.loadSharedFolder(shareId, {
    shareId,
    ipnsName,
    folderKey: SHARE_ROOT_READ_KEY,
    ipnsPrivateKey: new Uint8Array(64).fill(0x32),
    writeKey: new Uint8Array(32),
    publishedNode: {
      schema: 'node/v3',
      kind: 'root',
      id: 'share-root-node-id',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'x',
    },
    sequenceNumber,
    children,
    ownerPublicKey: new Uint8Array(33).fill(0x33),
    recipientPublicKey: new Uint8Array(33).fill(0x34),
  });
}

describe('CipherBoxClient — listFolder / listSharedFolder ResolvedChild[] (folder-listing)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('listFolder returns one ResolvedChild per child (kind/name/ipnsName/sequence resolved); file carries size+modifiedAt, folder has size undefined', async () => {
    const now = Date.now();
    // Distinct createdAt (earlier than modifiedAt) so a modifiedAt->createdAt
    // projection swap in resolveChildren would fail this assertion.
    const fileCreatedAt = now - 10_000;
    const fileFixture = await buildChildFixture({
      id: 'd104a1eb-7822-4e6e-9cef-503cf3d74d77',
      ipnsName: FILE_CHILD_IPNS,
      name: 'report.pdf',
      kind: 'file',
      generation: 0,
      parentReadKey: PARENT_READ_KEY,
      childReadKey: FILE_READ_KEY,
      modifiedAt: now,
      createdAt: fileCreatedAt,
      sequenceNumber: 3n,
      size: 12345,
    });
    const folderFixture = await buildChildFixture({
      id: 'aa33ab87-b410-42c6-8d97-f58d494d4342',
      ipnsName: FOLDER_CHILD_IPNS,
      name: 'Photos',
      kind: 'folder',
      generation: 0,
      parentReadKey: PARENT_READ_KEY,
      childReadKey: FOLDER_READ_KEY,
      modifiedAt: now,
      sequenceNumber: 7n,
    });
    mockResolvesFor([fileFixture, folderFixture]);

    const client = new CipherBoxClient(createTestConfig());
    seedFolder(client, FOLDER_IPNS, [fileFixture.childRef, folderFixture.childRef]);

    const result = await client.listFolder(FOLDER_IPNS);

    expect(result).toHaveLength(2);
    const fileEntry = result.find((c) => c.ipnsName === FILE_CHILD_IPNS);
    const folderEntry = result.find((c) => c.ipnsName === FOLDER_CHILD_IPNS);

    expect(fileEntry).toEqual({
      ipnsName: FILE_CHILD_IPNS,
      name: 'report.pdf',
      kind: 'file',
      size: 12345,
      createdAt: fileCreatedAt,
      modifiedAt: now,
      sequence: 3,
    });
    expect(folderEntry).toEqual({
      ipnsName: FOLDER_CHILD_IPNS,
      name: 'Photos',
      kind: 'folder',
      createdAt: now,
      modifiedAt: now,
      sequence: 7,
    });
    expect(folderEntry?.size).toBeUndefined();
    // SC2 wiring proof: createdAt is threaded from the fixture Node through
    // resolveChildren() onto the ResolvedChild -- not just present but equal to
    // the source-of-truth Node.createdAt (distinct from modifiedAt, so a field
    // swap is caught) used to build the fixture.
    expect(fileEntry?.createdAt).toBe(fileCreatedAt);
    expect(fileEntry?.createdAt).not.toBe(fileEntry?.modifiedAt);
  });

  it('listSharedFolder(shareId, path) returns ResolvedChild[] for an INTERMEDIATE folder, not forced to a file leaf', async () => {
    const now = Date.now();
    const innerFileFixture = await buildChildFixture({
      id: '6dbb9248-481f-47a6-b6dd-db26a03e41de',
      ipnsName: SHARED_INNER_FILE_IPNS,
      name: 'notes.txt',
      kind: 'file',
      generation: 0,
      parentReadKey: SUBFOLDER_READ_KEY,
      childReadKey: new Uint8Array(32).fill(0x40),
      modifiedAt: now,
      sequenceNumber: 9n,
      size: 42,
    });
    const subfolderFixture = await buildChildFixture({
      id: '53dd5754-658b-4c0f-9640-ac92a12b64c1',
      ipnsName: SHARED_SUBFOLDER_IPNS,
      name: 'Docs',
      kind: 'folder',
      generation: 0,
      parentReadKey: SHARE_ROOT_READ_KEY,
      childReadKey: SUBFOLDER_READ_KEY,
      modifiedAt: now,
      sequenceNumber: 5n,
      children: [innerFileFixture.childRef],
    });
    mockResolvesFor([innerFileFixture, subfolderFixture]);

    const client = new CipherBoxClient(createTestConfig());
    seedSharedFolder(client, SHARE_ID, SHARED_ROOT_IPNS, [subfolderFixture.childRef]);

    const result = await client.listSharedFolder(SHARE_ID, [SHARED_SUBFOLDER_IPNS]);

    // Proves the walk stopped at the intermediate folder and returned ITS
    // children -- not forced into resolving to a single file leaf
    // (navigateReadChain's behavior, Pitfall 1).
    expect(result).toEqual([
      {
        ipnsName: SHARED_INNER_FILE_IPNS,
        name: 'notes.txt',
        kind: 'file',
        size: 42,
        createdAt: now,
        modifiedAt: now,
        sequence: 9,
      },
    ]);
  });

  it('caches resolved children per ipnsName+sequenceNumber -- a second listFolder call at the same sequence does not re-resolve', async () => {
    const now = Date.now();
    const fileFixture = await buildChildFixture({
      id: 'ff1b64a6-87e6-4581-a5f7-6833240a4194',
      ipnsName: FILE_CHILD_IPNS,
      name: 'report.pdf',
      kind: 'file',
      generation: 0,
      parentReadKey: PARENT_READ_KEY,
      childReadKey: FILE_READ_KEY,
      modifiedAt: now,
      sequenceNumber: 3n,
      size: 12345,
    });
    mockResolvesFor([fileFixture]);

    const client = new CipherBoxClient(createTestConfig());
    seedFolder(client, FOLDER_IPNS, [fileFixture.childRef]);

    const first = await client.listFolder(FOLDER_IPNS);
    const callCountAfterFirst = vi.mocked(sdkCore.resolveIpnsRecord).mock.calls.length;
    expect(callCountAfterFirst).toBeGreaterThan(0);

    const second = await client.listFolder(FOLDER_IPNS);
    expect(vi.mocked(sdkCore.resolveIpnsRecord).mock.calls.length).toBe(callCountAfterFirst);
    expect(second).toEqual(first);
  });

  it('emits ResolvedChild[] (kind pre-resolved) on folder:loaded', async () => {
    const now = Date.now();
    const fileFixture = await buildChildFixture({
      id: '38c02437-5dd8-4cf0-9c31-7782adedf13a',
      ipnsName: FILE_CHILD_IPNS,
      name: 'report.pdf',
      kind: 'file',
      generation: 0,
      parentReadKey: PARENT_READ_KEY,
      childReadKey: FILE_READ_KEY,
      modifiedAt: now,
      sequenceNumber: 3n,
      size: 12345,
    });
    mockResolvesFor([fileFixture]);

    const rootMetadata: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: 'f165d782-63a4-4091-ba32-94b3d09d15aa',
      generation: 0,
      createdAt: now,
      modifiedAt: now,
      children: [fileFixture.childRef],
    };
    vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
      metadata: rootMetadata,
      sequenceNumber: 1n,
      cid: 'bafyroot-event',
    });

    const client = new CipherBoxClient(createTestConfig());
    const events: Array<{ type: string; children?: unknown }> = [];
    client.on((event) => {
      if (event.type === 'folder:loaded') events.push(event);
    });

    await client.loadFolder(FOLDER_IPNS, PARENT_READ_KEY, {
      publicKey: new Uint8Array(32).fill(0x50),
      privateKey: new Uint8Array(64).fill(0x51),
    });

    expect(events).toHaveLength(1);
    expect(events[0].children).toEqual([
      {
        ipnsName: FILE_CHILD_IPNS,
        name: 'report.pdf',
        kind: 'file',
        size: 12345,
        createdAt: now,
        modifiedAt: now,
        sequence: 3,
      },
    ]);
  });
});
