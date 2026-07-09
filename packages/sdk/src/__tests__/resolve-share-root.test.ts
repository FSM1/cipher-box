/**
 * CipherBoxClient.resolveShareRoot tests (68.2-08 Rule-2 facade addition).
 *
 * Hoists the raw-crypto portion of `useSharedNavigationActions.ts`'s
 * `navigateToShare` (ONE ECIES unwrap of `encryptedReadKey` -> resolve+
 * unseal the root Node) into the SDK -- mirrors `resolveChildIdentity`'s
 * mocking boundary (only `resolveIpnsRecord`/`fetchFromIpfs` mocked). Uses
 * the SAME deterministic, invertible `wrapKey`/`unwrapKey` fake as
 * `update-shared-single-file.test.ts` (file header there explains why: real
 * secp256k1 is only a devDependency of `@cipherbox/crypto`, not a declared
 * dependency of `@cipherbox/sdk` -- an undeclared phantom cross-package
 * import). `@cipherbox/core` seal/unseal stays fully real.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { sealNode, type Node } from '@cipherbox/core';

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

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import * as cryptoMod from '@cipherbox/crypto';

const ROOT_IPNS = 'k51root-test';
const ROOT_READ_KEY = new Uint8Array(32).fill(0x07);
const DUMMY_WRITE_KEY = new Uint8Array(32);
const RECIPIENT_PUBLIC_KEY = new Uint8Array(33).fill(0x04);
const RECIPIENT_PRIVATE_KEY = new Uint8Array(32).fill(0x01);

async function buildRootFixture(kind: 'folder' | 'file', generation = 0) {
  const node: Node =
    kind === 'folder'
      ? {
          schema: 'node/v3',
          kind: 'folder',
          id: '11111111-1111-4111-8111-111111111111',
          generation,
          createdAt: 1000,
          modifiedAt: 1000,
          children: [],
        }
      : {
          schema: 'node/v3',
          kind: 'file',
          id: '22222222-2222-4222-8222-222222222222',
          generation,
          createdAt: 1000,
          modifiedAt: 1000,
          content: {
            cid: 'bafyroot',
            fileIv: 'iv',
            size: 1,
            mimeType: 'text/plain',
            encryptionMode: 'GCM' as const,
            fileKey: new Uint8Array(32).fill(0x08),
            versions: [],
          },
        };
  const published = await sealNode(node, ROOT_READ_KEY, DUMMY_WRITE_KEY);
  return { node, published };
}

function mockResolution(published: unknown, sequenceNumber = 3n) {
  vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
    cid: 'bafy-root-envelope',
    sequenceNumber,
    signatureVerified: true,
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
    new TextEncoder().encode(JSON.stringify(published))
  );
}

describe('CipherBoxClient.resolveShareRoot', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('recovers the root readKey via ECIES unwrap and unseals a FOLDER root', async () => {
    const { published } = await buildRootFixture('folder');
    mockResolution(published, 5n);
    const encryptedReadKey = cryptoMod.bytesToHex(
      await cryptoMod.wrapKey(ROOT_READ_KEY, RECIPIENT_PUBLIC_KEY)
    );

    const result = await client.resolveShareRoot({
      encryptedReadKey,
      recipientPrivateKey: RECIPIENT_PRIVATE_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
    });

    expect(result.status).toBe('ok');
    if (result.status !== 'ok') throw new Error('unreachable');
    expect(result.kind).toBe('folder');
    expect(result.children).toEqual([]);
    expect(result.sequenceNumber).toBe(5n);
    expect(result.readKey).toEqual(ROOT_READ_KEY);
  });

  it('resolves a single-file share root with kind "file"', async () => {
    const { published } = await buildRootFixture('file');
    mockResolution(published);
    const encryptedReadKey = cryptoMod.bytesToHex(
      await cryptoMod.wrapKey(ROOT_READ_KEY, RECIPIENT_PUBLIC_KEY)
    );

    const result = await client.resolveShareRoot({
      encryptedReadKey,
      recipientPrivateKey: RECIPIENT_PRIVATE_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
    });

    expect(result.status).toBe('ok');
    if (result.status !== 'ok') throw new Error('unreachable');
    expect(result.kind).toBe('file');
  });

  it('returns behind-retry when the resolved generation exceeds rootExpectedGeneration', async () => {
    const { published } = await buildRootFixture('folder', 5);
    mockResolution(published);
    const encryptedReadKey = cryptoMod.bytesToHex(
      await cryptoMod.wrapKey(ROOT_READ_KEY, RECIPIENT_PUBLIC_KEY)
    );

    const result = await client.resolveShareRoot({
      encryptedReadKey,
      recipientPrivateKey: RECIPIENT_PRIVATE_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
    });

    expect(result.status).toBe('behind-retry');
  });

  it('returns revoked when the root IPNS record cannot be resolved', async () => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    const encryptedReadKey = cryptoMod.bytesToHex(
      await cryptoMod.wrapKey(ROOT_READ_KEY, RECIPIENT_PUBLIC_KEY)
    );

    const result = await client.resolveShareRoot({
      encryptedReadKey,
      recipientPrivateKey: RECIPIENT_PRIVATE_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
    });

    expect(result.status).toBe('revoked');
  });

  it('never zeroes the caller-owned recipientPrivateKey (D-09)', async () => {
    const { published } = await buildRootFixture('file');
    mockResolution(published);
    const encryptedReadKey = cryptoMod.bytesToHex(
      await cryptoMod.wrapKey(ROOT_READ_KEY, RECIPIENT_PUBLIC_KEY)
    );
    const before = RECIPIENT_PRIVATE_KEY.slice();

    await client.resolveShareRoot({
      encryptedReadKey,
      recipientPrivateKey: RECIPIENT_PRIVATE_KEY,
      shareRootIpnsName: ROOT_IPNS,
      rootExpectedGeneration: 0,
    });

    expect(RECIPIENT_PRIVATE_KEY).toEqual(before);
  });
});
