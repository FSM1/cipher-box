/**
 * TDD tests for 68.2-04 Task 1: vault-bootstrap + device-registry facade
 * methods on CipherBoxClient (D-07 full boundary).
 *
 * These give useAuth.ts (vault-bootstrap crypto) and device-registry.service.ts
 * (registry crypto) a facade entrypoint so a later plan (the cutover wave) can
 * stop importing `initializeVault`/`encryptVaultKeys`/`serializeVaultBlobV3`/
 * `deserializeVaultBlobV3`/`deriveRegistryIpnsKeypair`/`encryptRegistry`/
 * `decryptRegistry` from `@cipherbox/core` directly.
 *
 * `wrapKey`/`unwrapKey` are mocked with a deterministic, INVERTIBLE fake
 * (prefix-tag + copy) instead of the real secp256k1/eciesjs stack --
 * @noble/secp256k1 is not a declared dependency of @cipherbox/sdk (only a
 * devDependency of @cipherbox/crypto), matching the precedent established in
 * client-write-descriptor.test.ts. The fake preserves the real round-trip
 * SEMANTICS wrapKey/unwrapKey provide (wrap then unwrap recovers the
 * original bytes), so the serialize->deserialize round-trip assertion below
 * is a real behavioral proof, not a mocked-away no-op.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';

const WRAP_TAG = new Uint8Array([0xec, 0x1e]);

vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    wrapKey: vi.fn(async (key: Uint8Array) => {
      const out = new Uint8Array(WRAP_TAG.length + key.length);
      out.set(WRAP_TAG, 0);
      out.set(key, WRAP_TAG.length);
      return out;
    }),
    unwrapKey: vi.fn(async (wrapped: Uint8Array) => wrapped.slice(WRAP_TAG.length)),
    clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  };
});

vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    initializeVault: vi.fn(actual.initializeVault),
    encryptVaultKeys: vi.fn(actual.encryptVaultKeys),
    deriveRegistryIpnsKeypair: vi.fn(actual.deriveRegistryIpnsKeypair),
    encryptRegistry: vi.fn(actual.encryptRegistry),
    decryptRegistry: vi.fn(actual.decryptRegistry),
  };
});

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    publishEmptyRootNode: vi.fn(),
  };
});

import * as cryptoMod from '@cipherbox/crypto';
import * as coreMod from '@cipherbox/core';
import * as sdkCore from '@cipherbox/sdk-core';
import type { DeviceRegistry } from '@cipherbox/core';

function makeUserPrivateKey(): Uint8Array {
  return new Uint8Array(32).fill(7);
}

function makeUserPublicKey(): Uint8Array {
  return new Uint8Array(65).fill(9);
}

function makeTestRegistry(): DeviceRegistry {
  const now = Date.now();
  return {
    version: 'v2',
    sequenceNumber: 1,
    devices: [
      {
        deviceId: 'a'.repeat(64),
        publicKey: 'b'.repeat(64),
        name: 'Test Device',
        platform: 'web',
        appVersion: '0.2.0',
        deviceModel: 'Chrome 123',
        ipHash: 'c'.repeat(64),
        status: 'authorized',
        createdAt: now,
        lastSeenAt: now,
        revokedAt: null,
        revokedBy: null,
      },
    ],
  };
}

describe('CipherBoxClient vault-bootstrap facade', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('bootstrapVaultKeys', () => {
    it('delegates to @cipherbox/core initializeVault and returns a VaultInit', async () => {
      const userPrivateKey = makeUserPrivateKey();

      const vault = await client.bootstrapVaultKeys(userPrivateKey);

      expect(coreMod.initializeVault).toHaveBeenCalledWith(userPrivateKey);
      expect(vault.rootReadKey).toBeInstanceOf(Uint8Array);
      expect(vault.rootWriteKey).toBeInstanceOf(Uint8Array);
      expect(vault.rootReadKey).not.toEqual(vault.rootWriteKey);
      expect(vault.rootIpnsKeypair.publicKey.length).toBeGreaterThan(0);
      expect(vault.rootIpnsKeypair.privateKey.length).toBeGreaterThan(0);
    });
  });

  describe('serializeVault -> deserializeVault round-trip', () => {
    it('recovers the original rootReadKey/rootWriteKey after a full serialize/deserialize cycle', async () => {
      const userPrivateKey = makeUserPrivateKey();
      const userPublicKey = makeUserPublicKey();

      const vault = await client.bootstrapVaultKeys(userPrivateKey);
      const blob = await client.serializeVault(vault, userPublicKey);

      // v3 version byte (BLOB_V3_VERSION)
      expect(blob[0]).toBe(0x03);
      // encryptVaultKeys wraps all three fields (read, write, ipns private
      // key) even though serializeVault only persists the first two into
      // the v3 blob -- ipnsKeypair is re-derived on load, never stored.
      expect(cryptoMod.wrapKey).toHaveBeenCalledTimes(3);

      const recovered = await client.deserializeVault(blob, userPrivateKey);

      expect(recovered.rootReadKey).toEqual(vault.rootReadKey);
      expect(recovered.rootWriteKey).toEqual(vault.rootWriteKey);
      expect(cryptoMod.unwrapKey).toHaveBeenCalledTimes(2);
    });

    it('zeroes the already-unwrapped rootReadKey if the second unwrapKey call fails (T-68.2-09)', async () => {
      const userPrivateKey = makeUserPrivateKey();
      const userPublicKey = makeUserPublicKey();

      const vault = await client.bootstrapVaultKeys(userPrivateKey);
      const blob = await client.serializeVault(vault, userPublicKey);

      let capturedReadKey: Uint8Array | undefined;
      const unwrapSpy = vi.mocked(cryptoMod.unwrapKey);
      unwrapSpy.mockImplementationOnce(async (wrapped: Uint8Array) => {
        capturedReadKey = wrapped.slice(WRAP_TAG.length);
        return capturedReadKey;
      });
      unwrapSpy.mockImplementationOnce(async () => {
        throw new Error('simulated unwrap failure');
      });

      await expect(client.deserializeVault(blob, userPrivateKey)).rejects.toThrow(
        'simulated unwrap failure'
      );

      expect(capturedReadKey).toBeDefined();
      expect(cryptoMod.clearBytes).toHaveBeenCalledWith(capturedReadKey);
      expect(capturedReadKey!.every((b) => b === 0)).toBe(true);
    });
  });

  describe('publishEmptyRootNode', () => {
    it('delegates to sdkCore.publishEmptyRootNode with this.ctx injected', async () => {
      vi.mocked(sdkCore.publishEmptyRootNode).mockResolvedValue({
        ipnsName: 'k51root',
        nodeId: 'node-1',
        sequenceNumber: 1n,
      });

      const rootIpnsKeypair = {
        publicKey: new Uint8Array(32).fill(1),
        privateKey: new Uint8Array(64).fill(2),
      };
      const rootReadKey = new Uint8Array(32).fill(3);
      const rootWriteKey = new Uint8Array(32).fill(4);

      const result = await client.publishEmptyRootNode({
        rootIpnsKeypair,
        rootReadKey,
        rootWriteKey,
      });

      expect(sdkCore.publishEmptyRootNode).toHaveBeenCalledWith({
        rootIpnsKeypair,
        rootReadKey,
        rootWriteKey,
        ctx: expect.anything(),
      });
      expect(result).toEqual({ ipnsName: 'k51root', nodeId: 'node-1', sequenceNumber: 1n });
    });
  });
});

describe('CipherBoxClient device-registry facade', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('deriveRegistryIpnsKeypair', () => {
    it('delegates to @cipherbox/core deriveRegistryIpnsKeypair', async () => {
      const userPrivateKey = makeUserPrivateKey();

      const result = await client.deriveRegistryIpnsKeypair(userPrivateKey);

      expect(coreMod.deriveRegistryIpnsKeypair).toHaveBeenCalledWith(userPrivateKey);
      expect(result.ipnsName).toMatch(/^k51/);
      expect(result.privateKey.length).toBe(32);
    });
  });

  describe('encryptRegistry -> decryptRegistry round-trip', () => {
    it('recovers the original DeviceRegistry after a full encrypt/decrypt cycle', async () => {
      const userPrivateKey = makeUserPrivateKey();
      const userPublicKey = makeUserPublicKey();
      const registry = makeTestRegistry();

      const encrypted = await client.encryptRegistry(registry, userPublicKey);
      expect(coreMod.encryptRegistry).toHaveBeenCalledWith(registry, userPublicKey);

      const decrypted = await client.decryptRegistry(encrypted, userPrivateKey);
      expect(coreMod.decryptRegistry).toHaveBeenCalledWith(encrypted, userPrivateKey);
      expect(decrypted).toEqual(registry);
    });
  });
});
