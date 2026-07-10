/**
 * updateSharedSingleFile tests (68.1-32 WEB-03 direct single-file-share write
 * seam, closes writable-shares 10.3).
 *
 * A DIRECT single-file share (root `kind: 'file'`) has no parent folder write
 * chain to walk — the two grant encrypted keys (`encryptedReadKey`/
 * `encryptedWriteKey`) directly ECIES-wrap the file's own readKey/writeKey.
 * `updateSharedSingleFile` recovers both, validates-before-trust by unsealing
 * the file's own write-body, and publishes to the file's OWN IPNS at seq+1.
 *
 * `@cipherbox/core` seal/unseal stays fully real (genuine AAD-bound fixture
 * envelopes). `wrapKey`/`unwrapKey` are mocked with the SAME deterministic,
 * invertible fake used by client-write-descriptor.test.ts: @noble/secp256k1
 * is only a devDependency of @cipherbox/crypto (not a declared dependency of
 * @cipherbox/sdk), so this suite cannot mint a real secp256k1 keypair without
 * an undeclared phantom cross-package import. The fake preserves the real
 * wrap/unwrap round-trip SEMANTICS (wrap then unwrap recovers the original
 * key, and a corrupted wrapped value recovers a DIFFERENT key), which is all
 * the behavior under test here depends on.
 *
 * Only the network-touching `@cipherbox/sdk-core` seams (resolveIpnsRecord /
 * fetchFromIpfs) and the `../share` `shareOps.updateSharedFile` delegate are
 * mocked — mirrors resolve-shared-subfolder-write-key.test.ts and
 * client-shared-write.test.ts's mocking boundary.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { sealNode, type Node, type PublishedNode } from '@cipherbox/core';

// ── crypto mock — keep every real helper (real hex codecs, AAD-bound seal
//    used to build fixtures) and only replace wrapKey/unwrapKey with a
//    deterministic, invertible fake (see file header for rationale).
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  const WRAP_TAG = new Uint8Array([0xec, 0x1e]);
  return {
    ...actual,
    wrapKey: vi.fn(async (key: Uint8Array, _recipientPublicKey: Uint8Array) => {
      const out = new Uint8Array(WRAP_TAG.length + key.length);
      out.set(WRAP_TAG, 0);
      out.set(key, WRAP_TAG.length);
      return out;
    }),
    unwrapKey: vi.fn(async (wrapped: Uint8Array, _recipientPrivateKey: Uint8Array) => {
      return wrapped.slice(WRAP_TAG.length);
    }),
  };
});

// ── sdk-core mock — override only the network-touching seams reached through
//    the private resolvePublishedNode helper.
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

// ── share mock — stub only the shared-write delegate; buildSharedWriteContext
//    stays real so the swCtx wiring is genuinely exercised.
vi.mock('../share', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../share')>();
  return {
    ...actual,
    updateSharedFile: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import * as cryptoMod from '@cipherbox/crypto';
import * as shareOps from '../share';

// ── fixture ids ──────────────────────────────────────────────────────────────
const SHARE_ID = 'share-single-file-test';
const FILE_IPNS = 'k51file-single';
const FILE_NODE_ID = '33333333-3333-4333-8333-333333333333';
const OWNER_PUBLIC_KEY = new Uint8Array(33).fill(0x03);
const RECIPIENT_PUBLIC_KEY = new Uint8Array(33).fill(0x04);
const RECIPIENT_PRIVATE_KEY = new Uint8Array(32).fill(0x11);
const RESOLVED_SEQ = 7n;

// ── key material ─────────────────────────────────────────────────────────────
const fileReadKey = new Uint8Array(32).fill(0x21);
const fileWriteKey = new Uint8Array(32).fill(0x22);
const fileIpnsPrivateKey = new Uint8Array(32).fill(0x23);

type Fixture = {
  filePublished: PublishedNode;
  fileNode: Node;
};

/**
 * Builds a genuine node/v3 file node and its sealed envelope.
 *
 * @param opts.generation - the file node's generation (default 0).
 * @param opts.omitWriteBody - when true, the file node carries NO write-body
 *   (simulates a read-only encrypted-key pair / missing ipnsPrivateKey).
 */
async function buildFixture(
  opts: { generation?: number; omitWriteBody?: boolean } = {}
): Promise<Fixture> {
  const generation = opts.generation ?? 0;
  const fileNode: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: FILE_NODE_ID,
    generation,
    createdAt: 1000,
    modifiedAt: 1000,
    content: {
      cid: 'bafyoriginal',
      fileIv: 'aXY=',
      size: 11,
      mimeType: 'text/plain',
      encryptionMode: 'GCM',
      fileKey: new Uint8Array(32).fill(0x33),
      versions: [],
    },
    ...(opts.omitWriteBody
      ? {}
      : { writeBody: { ipnsPrivateKey: fileIpnsPrivateKey, writeChildren: [] } }),
  };
  const filePublished = await sealNode(fileNode, fileReadKey, fileWriteKey);
  return { filePublished, fileNode };
}

function mockResolution(filePublished: PublishedNode): void {
  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === FILE_IPNS) {
      return { cid: 'bafyenvelope', sequenceNumber: RESOLVED_SEQ, signatureVerified: true };
    }
    return null;
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafyenvelope') {
      return new TextEncoder().encode(JSON.stringify(filePublished));
    }
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });
}

async function buildArgs(overrides?: {
  encryptedWriteKey?: string;
  rootExpectedGeneration?: number;
}): Promise<{
  shareId: string;
  encryptedReadKey: string;
  encryptedWriteKey: string;
  fileIpnsName: string;
  ownerPublicKey: Uint8Array;
  recipientPrivateKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  rootExpectedGeneration: number;
  newContent: Uint8Array;
}> {
  const encryptedReadKey = cryptoMod.bytesToHex(
    await cryptoMod.wrapKey(fileReadKey, RECIPIENT_PUBLIC_KEY)
  );
  const encryptedWriteKey = cryptoMod.bytesToHex(
    await cryptoMod.wrapKey(fileWriteKey, RECIPIENT_PUBLIC_KEY)
  );
  return {
    shareId: SHARE_ID,
    encryptedReadKey,
    encryptedWriteKey: overrides?.encryptedWriteKey ?? encryptedWriteKey,
    fileIpnsName: FILE_IPNS,
    ownerPublicKey: OWNER_PUBLIC_KEY,
    recipientPrivateKey: RECIPIENT_PRIVATE_KEY,
    recipientPublicKey: RECIPIENT_PUBLIC_KEY,
    rootExpectedGeneration: overrides?.rootExpectedGeneration ?? 0,
    newContent: new TextEncoder().encode('new content'),
  };
}

describe('CipherBoxClient.updateSharedSingleFile', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it("resolves the file keys from the grant's encrypted keys and delegates to shareOps.updateSharedFile exactly once", async () => {
    const { filePublished, fileNode } = await buildFixture();
    mockResolution(filePublished);
    // Snapshot params INSIDE the mock implementation, before the method's own
    // `finally` zeroes the minted keys (D-09 terminal-owner zeroing runs on
    // every exit path — mirrors production, where the real shareOps.updateSharedFile
    // has already consumed the keys synchronously by the time it resolves).
    let captured: Parameters<typeof shareOps.updateSharedFile>[1] | null = null;
    vi.mocked(shareOps.updateSharedFile).mockImplementation(async (_swCtx, params) => {
      captured = {
        ...params,
        fileReadKey: params.fileReadKey.slice(),
        fileWriteKey: params.fileWriteKey.slice(),
        fileIpnsPrivateKey: params.fileIpnsPrivateKey.slice(),
      };
    });
    const args = await buildArgs();

    await client.updateSharedSingleFile(args);

    expect(shareOps.updateSharedFile).toHaveBeenCalledTimes(1);
    const params = captured!;
    expect(params.fileReadKey).toHaveLength(32);
    expect(params.fileWriteKey).toHaveLength(32);
    expect(params.fileIpnsPrivateKey).toHaveLength(32);
    expect(params.fileReadKey).toEqual(fileReadKey);
    expect(params.fileWriteKey).toEqual(fileWriteKey);
    expect(params.fileIpnsPrivateKey).toEqual(fileIpnsPrivateKey);
    expect(params.fileNodeId).toBe(FILE_NODE_ID);
    expect(params.fileRef.ipnsName).toBe(FILE_IPNS);
    expect(params.fileRef.generation).toBe(filePublished.generation);
    expect(params.fileSequenceNumber).toBe(RESOLVED_SEQ);
    expect(params.newData).toEqual(args.newContent);
    expect(params.originalCreatedAt).toBe(fileNode.createdAt);
    expect(params.originalVersions).toEqual(fileNode.content!.versions);
  });

  it('throws fail-closed (behind-retry) when the resolved generation exceeds rootExpectedGeneration, without delegating', async () => {
    const { filePublished } = await buildFixture({ generation: 5 });
    mockResolution(filePublished);
    const args = await buildArgs({ rootExpectedGeneration: 0 });

    await expect(client.updateSharedSingleFile(args)).rejects.toThrow(/reopen/i);
    expect(shareOps.updateSharedFile).not.toHaveBeenCalled();
  });

  it('throws fail-closed on a tampered encryptedWriteKey (AEAD auth), without delegating', async () => {
    const { filePublished } = await buildFixture();
    mockResolution(filePublished);
    const args = await buildArgs();

    // Corrupt the write encrypted-key hex (flip a char past the wrap-tag prefix)
    // so the fake unwrapKey recovers a DIFFERENT (wrong) 32-byte writeKey —
    // unsealNode's real AEAD auth then fails validating it against the file's
    // own write-body (never caught, never swallowed).
    const chars = args.encryptedWriteKey.split('');
    const idx = Math.floor(chars.length / 2);
    chars[idx] = chars[idx] === '0' ? '1' : '0';
    const tampered = { ...args, encryptedWriteKey: chars.join('') };

    await expect(client.updateSharedSingleFile(tampered)).rejects.toThrow();
    expect(shareOps.updateSharedFile).not.toHaveBeenCalled();
  });

  it('throws fail-closed when the file node has no write-body (missing ipnsPrivateKey), without delegating', async () => {
    const { filePublished } = await buildFixture({ omitWriteBody: true });
    mockResolution(filePublished);
    const args = await buildArgs();

    await expect(client.updateSharedSingleFile(args)).rejects.toThrow();
    expect(shareOps.updateSharedFile).not.toHaveBeenCalled();
  });

  it('zeroes the first unwrapped key when the SECOND unwrapKey call throws (72-06 zeroize fix)', async () => {
    const args = await buildArgs();
    // Tracked buffer returned by the FIRST unwrapKey call (fileReadKey) — the
    // real fix moves both unwrapKey calls inside the try/finally that owns
    // this buffer's zeroing, so a throw on the SECOND call must still zero it.
    const trackedFirstKey = new Uint8Array(32).fill(0xaa);
    vi.mocked(cryptoMod.unwrapKey)
      .mockImplementationOnce(async () => trackedFirstKey)
      .mockImplementationOnce(async () => {
        throw new Error('simulated second unwrap failure');
      });

    await expect(client.updateSharedSingleFile(args)).rejects.toThrow(
      'simulated second unwrap failure'
    );

    expect(trackedFirstKey).toEqual(new Uint8Array(32));
    expect(shareOps.updateSharedFile).not.toHaveBeenCalled();
  });

  it('never zeroes the caller-owned recipientPrivateKey (D-09)', async () => {
    const { filePublished } = await buildFixture();
    mockResolution(filePublished);
    vi.mocked(shareOps.updateSharedFile).mockResolvedValue(undefined);
    const args = await buildArgs();
    const before = args.recipientPrivateKey.slice();

    await client.updateSharedSingleFile(args);

    expect(args.recipientPrivateKey).toEqual(before);
  });
});
