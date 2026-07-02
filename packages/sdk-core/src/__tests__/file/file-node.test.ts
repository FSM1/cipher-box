/**
 * TDD tests for the owned per-file Node IPNS chain (Phase 68.1 Plan 07).
 *
 * Mock boundary: only network I/O (ipfs + ipns) is mocked; the @cipherbox/core codec
 * (sealNode/unsealNode/createIpnsRecord/marshalIpnsRecord) and @cipherbox/crypto run
 * for real (except `wrapKey`, mocked below to avoid needing a real on-curve secp256k1
 * fixture just to exercise the TEE-wrap branch) — matches the pattern established in
 * write-body.test.ts (68.1-01).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createFileMetadata, resolveFileMetadata, downloadFileContent } from '../../file';
import { unsealNode, unmarshalIpnsRecord } from '@cipherbox/core';
import type { PublishedNode } from '@cipherbox/core';
import { encryptAesGcm, encryptAesCtr } from '@cipherbox/crypto';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — only I/O layers + wrapKey; everything else in @cipherbox/core
// and @cipherbox/crypto runs real.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
  wrapKey: vi.fn(),
}));

vi.mock('../../ipfs', () => ({
  addToIpfs: mockFns.addToIpfs,
  fetchFromIpfs: mockFns.fetchFromIpfs,
}));

vi.mock('../../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  batchPublishIpnsRecords: mockFns.batchPublishIpnsRecords,
}));

vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return { ...actual, wrapKey: mockFns.wrapKey };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

describe('createFileMetadata', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => ({
      cid: 'QmFileNodeCid',
      size: data.length,
      recorded: true,
    }));
    mockFns.wrapKey.mockResolvedValue(new Uint8Array(80).fill(0x99));
  });

  it('builds a v3 file Node whose unseal round-trips content, and returns fresh readKey/writeKey/fileNodeId', async () => {
    const ctx = createMockContext();
    const cid = 'QmContentCid';
    const fileKey = new Uint8Array(32).fill(0x42);
    const fileIv = new Uint8Array(12).fill(0x11);
    let capturedBytes: Uint8Array | null = null;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedBytes = data;
      return { cid: 'QmFileNodeCid', size: data.length, recorded: true };
    });

    const result = await createFileMetadata({
      cid,
      fileKey,
      fileIv,
      size: 12345,
      mimeType: 'text/plain',
      ctx,
    });

    expect(result.fileReadKey).toHaveLength(32);
    expect(result.fileWriteKey).toHaveLength(32);
    expect(typeof result.fileNodeId).toBe('string');
    expect(result.fileNodeId.length).toBeGreaterThan(0);
    expect(typeof result.fileMetaIpnsName).toBe('string');
    expect(result.fileMetaIpnsName.length).toBeGreaterThan(0);

    expect(capturedBytes).not.toBeNull();
    const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;
    expect(publishedNode.kind).toBe('file');
    expect(publishedNode.id).toBe(result.fileNodeId);

    const unsealed = await unsealNode(publishedNode, result.fileReadKey, result.fileWriteKey);
    expect(unsealed.kind).toBe('file');
    expect(unsealed.content).toBeDefined();
    expect(unsealed.content!.cid).toBe(cid);
    expect(unsealed.content!.mimeType).toBe('text/plain');
    expect(unsealed.content!.size).toBe(12345);
    expect(unsealed.content!.encryptionMode).toBe('GCM');
    expect(unsealed.content!.versions).toEqual([]);
    expect(unsealed.content!.fileKey).toEqual(fileKey);
    expect(base64ToBytes(unsealed.content!.fileIv)).toEqual(fileIv);

    expect(unsealed.writeBody).toBeDefined();
    expect(unsealed.writeBody!.ipnsPrivateKey).toHaveLength(32);
    expect(unsealed.writeBody!.writeChildren).toEqual([]);
  });

  it('embeds sequenceNumber 1n in the built (not-yet-published) IPNS record and does not hit the network directly', async () => {
    const ctx = createMockContext();

    const result = await createFileMetadata({
      cid: 'QmContentCid2',
      fileKey: new Uint8Array(32).fill(0x77),
      fileIv: new Uint8Array(12).fill(0x22),
      size: 100,
      mimeType: 'application/octet-stream',
      ctx,
    });

    const recordBytes = base64ToBytes(result.ipnsRecord.recordBase64);
    const record = unmarshalIpnsRecord(recordBytes);
    expect(record.sequence).toBe(1n);

    // createFileMetadata builds the record locally — it must NOT publish directly.
    // The caller batch-publishes it (matches the pre-existing UploadResult.ipnsRecord
    // contract already wired in client.ts: batchPublishIpnsRecords([uploadResult.ipnsRecord])).
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });

  it('returns ipnsPrivateKeyEncrypted undefined when teeKeys is absent (never wraps under a missing TEE key)', async () => {
    const ctx = createMockContext();

    const result = await createFileMetadata({
      cid: 'QmContentCid3',
      fileKey: new Uint8Array(32).fill(0x33),
      fileIv: new Uint8Array(12).fill(0x44),
      size: 50,
      mimeType: 'text/plain',
      ctx,
    });

    expect(result.ipnsPrivateKeyEncrypted).toBeUndefined();
    expect(result.ipnsRecord.encryptedIpnsPrivateKey).toBeUndefined();
    expect(mockFns.wrapKey).not.toHaveBeenCalled();
  });

  it('ECIES-wraps the file ipnsPrivateKey under the TEE public key when teeKeys is supplied', async () => {
    const ctx = createMockContext();

    const result = await createFileMetadata({
      cid: 'QmContentCid4',
      fileKey: new Uint8Array(32).fill(0x55),
      fileIv: new Uint8Array(12).fill(0x66),
      size: 200,
      mimeType: 'text/plain',
      ctx,
      teeKeys: { currentPublicKey: 'aabbcc', currentEpoch: 3 },
    });

    expect(mockFns.wrapKey).toHaveBeenCalledTimes(1);
    expect(result.ipnsPrivateKeyEncrypted).toBeDefined();
    expect(result.ipnsRecord.encryptedIpnsPrivateKey).toBe(result.ipnsPrivateKeyEncrypted);
    expect(result.ipnsRecord.keyEpoch).toBe(3);
  });

  it('fails closed when teeKeys.currentPublicKey is missing', async () => {
    const ctx = createMockContext();

    await expect(
      createFileMetadata({
        cid: 'QmContentCid5',
        fileKey: new Uint8Array(32).fill(0x88),
        fileIv: new Uint8Array(12).fill(0x99),
        size: 10,
        mimeType: 'text/plain',
        ctx,
        teeKeys: { currentPublicKey: '', currentEpoch: 1 },
      })
    ).rejects.toThrow(/refusing to publish un-enrolled file/);
  });
});

describe('resolveFileMetadata', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('round-trips content published by createFileMetadata', async () => {
    const ctx = createMockContext();
    const cid = 'QmRoundTripCid';
    const fileKey = new Uint8Array(32).fill(0x64);
    const fileIv = new Uint8Array(12).fill(0x65);
    let capturedBytes: Uint8Array | null = null;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedBytes = data;
      return { cid: 'QmFileNodeCid', size: data.length, recorded: true };
    });

    const created = await createFileMetadata({
      cid,
      fileKey,
      fileIv,
      size: 999,
      mimeType: 'image/png',
      ctx,
    });

    expect(capturedBytes).not.toBeNull();
    mockFns.resolveIpnsRecord.mockResolvedValue({
      cid: 'QmFileNodeCid',
      sequenceNumber: 1n,
      signatureVerified: true,
    });
    mockFns.fetchFromIpfs.mockResolvedValue(capturedBytes!);

    const { metadata, metadataCid } = await resolveFileMetadata(
      created.fileMetaIpnsName,
      created.fileReadKey,
      ctx
    );

    expect(metadataCid).toBe('QmFileNodeCid');
    expect(metadata.cid).toBe(cid);
    expect(metadata.size).toBe(999);
    expect(metadata.mimeType).toBe('image/png');
    expect(metadata.fileKey).toEqual(fileKey);
    expect(metadata.versions).toEqual([]);
  });

  it('throws when the IPNS record is not found', async () => {
    const ctx = createMockContext();
    mockFns.resolveIpnsRecord.mockResolvedValue(null);

    await expect(resolveFileMetadata('k51-missing', new Uint8Array(32), ctx)).rejects.toThrow(
      /IPNS record not found/
    );
  });
});

describe('downloadFileContent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('decrypts GCM content encrypted with the raw fileKey (base64 iv)', async () => {
    const ctx = createMockContext();
    const fileKey = new Uint8Array(32).fill(0x21);
    const iv = new Uint8Array(12).fill(0x09);
    const plaintext = new TextEncoder().encode('hello gcm world');
    const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
    mockFns.fetchFromIpfs.mockResolvedValue(ciphertext);

    const ivBase64 = btoa(String.fromCharCode(...iv));
    const result = await downloadFileContent({
      cid: 'QmGcmCid',
      fileKey,
      fileIv: ivBase64,
      encryptionMode: 'GCM',
      ctx,
    });

    expect(result).toEqual(plaintext);
  });

  it('decrypts CTR content encrypted with the raw fileKey (base64 iv)', async () => {
    const ctx = createMockContext();
    const fileKey = new Uint8Array(32).fill(0x31);
    const iv = new Uint8Array(16).fill(0x08);
    const plaintext = new TextEncoder().encode('hello ctr world, streaming media test payload');
    const ciphertext = await encryptAesCtr(plaintext, fileKey, iv);
    mockFns.fetchFromIpfs.mockResolvedValue(ciphertext);

    const ivBase64 = btoa(String.fromCharCode(...iv));
    const result = await downloadFileContent({
      cid: 'QmCtrCid',
      fileKey,
      fileIv: ivBase64,
      encryptionMode: 'CTR',
      ctx,
    });

    expect(result).toEqual(plaintext);
  });
});
