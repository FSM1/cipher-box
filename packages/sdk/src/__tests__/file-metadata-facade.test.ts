/**
 * Phase 73 Plan 04 (TDD, SC3): proves `resolveFileMetadata` and
 * `downloadFromIpns` route through the `gatedResolveChild` ROT-07
 * anti-rollback floor -- closing two of the last three non-listing read
 * facades that previously bypassed it via a raw `resolvePublishedNode` call
 * (client.ts). A `signatureVerified:false` resolve must reject BOTH facades
 * (fail-closed), not return unverified metadata/content.
 *
 * Mirrors `resolve-child-identity.test.ts`'s fixture pattern (sealNode +
 * sealChildReadKey + SealedChildRef + vi.mock('@cipherbox/sdk-core', ...)).
 * Does NOT cover `getFolderMetadata` -- that's `folder-metadata-facade.test.ts`'s
 * existing scope.
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
    // sdk-core's OWN `resolveFileMetadata`/`downloadFileContent` are internal
    // calls within the SAME compiled bundle -- mocking the exported
    // `resolveIpnsRecord`/`fetchFromIpfs` bindings above does not intercept
    // them. Mock these directly too so the pre-fix (RED) code path -- which
    // still reaches these calls before the gate is added -- never makes a
    // real network request.
    resolveFileMetadata: vi.fn(),
    downloadFileContent: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const PARENT_READ_KEY = new Uint8Array(32).fill(0x01);
const FILE_READ_KEY = new Uint8Array(32).fill(0x02);
const FILE_IPNS = 'k51file-metadata-facade-test';
/** Unused by files (they carry no write-body) -- dummy zero key for sealNode's required param. */
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

async function buildFileFixture() {
  const node: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: 'b1b2c3d4-0000-4000-8000-000000000002',
    generation: 3,
    createdAt: 1000,
    modifiedAt: 1000,
    content: {
      cid: 'bafyfile-metadata-facade',
      fileIv: 'iv',
      size: 42,
      mimeType: 'text/plain',
      encryptionMode: 'GCM' as const,
      fileKey: new Uint8Array(32).fill(0x09),
      versions: [],
    },
  };
  const published = await sealNode(node, FILE_READ_KEY, DUMMY_WRITE_KEY);
  const readKeySealed = await sealChildReadKey(
    FILE_READ_KEY,
    PARENT_READ_KEY,
    node.id,
    node.kind,
    node.generation
  );
  const fileRef: SealedChildRef = {
    name: 'report.pdf',
    ipnsName: FILE_IPNS,
    generation: node.generation,
    versionFloor: 0n,
    readKeySealed,
  };
  return { fileRef, published, nodeId: node.id };
}

describe('CipherBoxClient -- resolveFileMetadata / downloadFromIpns fail-closed (SC3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('resolveFileMetadata rejects when the resolved record has signatureVerified=false (fail-closed via gatedResolveChild)', async () => {
    const fixture = await buildFileFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-file-metadata-facade',
      sequenceNumber: 5n,
      signatureVerified: false,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(fixture.published))
    );
    // Pre-fix (RED) code path still reaches sdk-core's OWN resolveFileMetadata
    // -- stub it to resolve so the RED failure is "did not reject" rather
    // than a real network error.
    vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
      metadata: {
        cid: 'bafyfile-metadata-facade',
        fileIv: 'iv',
        size: 42,
        mimeType: 'text/plain',
        encryptionMode: 'GCM',
        fileKey: new Uint8Array(32).fill(0x09),
        versions: [],
      },
      metadataCid: 'bafy-file-metadata-facade',
    });

    const client = new CipherBoxClient(
      createTestConfig({ rotationHighWater: fakeRotationHighWater() })
    );

    await expect(client.resolveFileMetadata(fixture.fileRef, PARENT_READ_KEY)).rejects.toThrow(
      /unverified record/
    );
  });

  it('downloadFromIpns rejects when the resolved record has signatureVerified=false (fail-closed via gatedResolveChild)', async () => {
    const fixture = await buildFileFixture();
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafy-file-metadata-facade',
      sequenceNumber: 5n,
      signatureVerified: false,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(fixture.published))
    );
    // Pre-fix (RED) code path still reaches sdk-core's OWN resolveFileMetadata
    // + downloadFileContent -- stub both so the RED failure is "did not
    // reject" rather than a real network error.
    vi.mocked(sdkCore.resolveFileMetadata).mockResolvedValue({
      metadata: {
        cid: 'bafyfile-metadata-facade',
        fileIv: 'iv',
        size: 42,
        mimeType: 'text/plain',
        encryptionMode: 'GCM',
        fileKey: new Uint8Array(32).fill(0x09),
        versions: [],
      },
      metadataCid: 'bafy-file-metadata-facade',
    });
    vi.mocked(sdkCore.downloadFileContent).mockResolvedValue(new Uint8Array([1, 2, 3]));

    const client = new CipherBoxClient(
      createTestConfig({ rotationHighWater: fakeRotationHighWater() })
    );

    await expect(client.downloadFromIpns(fixture.fileRef, PARENT_READ_KEY)).rejects.toThrow(
      /unverified record/
    );
  });

  it('resolveFileMetadata rejects when the IPNS record cannot be resolved (fail-closed, no gate bypass)', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    const client = new CipherBoxClient(createTestConfig());
    const fileRef: SealedChildRef = {
      name: 'missing.txt',
      ipnsName: 'k51unreachable-file-metadata-facade',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'irrelevant',
    };

    await expect(client.resolveFileMetadata(fileRef, PARENT_READ_KEY)).rejects.toThrow(
      /IPNS record not found/
    );
  });

  it('downloadFromIpns rejects when the IPNS record cannot be resolved (fail-closed, no gate bypass)', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    const client = new CipherBoxClient(createTestConfig());
    const fileRef: SealedChildRef = {
      name: 'missing.txt',
      ipnsName: 'k51unreachable-file-metadata-facade',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'irrelevant',
    };

    await expect(client.downloadFromIpns(fileRef, PARENT_READ_KEY)).rejects.toThrow(
      /IPNS record not found/
    );
  });
});
