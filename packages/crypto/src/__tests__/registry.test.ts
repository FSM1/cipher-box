/**
 * @cipherbox/crypto - Device Registry Tests
 *
 * Tests for registry crypto operations: IPNS derivation, ECIES encryption/decryption,
 * schema validation, and device keypair generation.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { deriveRegistryIpnsKeypair } from '../registry/derive-ipns';
import { encryptRegistry, decryptRegistry } from '../registry/encrypt';
import { validateDeviceRegistry } from '../registry/schema';
import { generateDeviceKeypair, deriveDeviceId } from '../device/keygen';
import type { DeviceRegistry } from '../registry/types';

/**
 * Generate a secp256k1 keypair for testing (matches pattern from ecies.test.ts).
 */
function generateTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed, 65 bytes
  return { publicKey, privateKey };
}

/**
 * Create a minimal valid DeviceRegistry for testing.
 */
function createTestRegistry(deviceCount = 1): DeviceRegistry {
  const now = Date.now();
  const devices = Array.from({ length: deviceCount }, (_, i) => ({
    deviceId: `device${i}_${'a'.repeat(56)}`,
    publicKey: `pubkey${i}_${'b'.repeat(56)}`,
    name: `Test Device ${i}`,
    platform: 'web' as const,
    appVersion: '0.2.0',
    deviceModel: 'Chrome 123',
    ipHash: `iphash${i}_${'c'.repeat(56)}`,
    status: i === 0 ? ('authorized' as const) : ('pending' as const),
    createdAt: now - i * 1000,
    lastSeenAt: now,
    revokedAt: null,
    revokedBy: null,
  }));

  return {
    version: 'v1',
    sequenceNumber: deviceCount,
    devices,
  };
}

describe('deriveRegistryIpnsKeypair', () => {
  it('derives an IPNS name starting with k51 from a 32-byte key', async () => {
    const keypair = generateTestKeypair();
    const result = await deriveRegistryIpnsKeypair(keypair.privateKey);

    expect(result.ipnsName).toMatch(/^k51/);
    expect(result.privateKey).toBeInstanceOf(Uint8Array);
    expect(result.privateKey.length).toBe(32);
    expect(result.publicKey).toBeInstanceOf(Uint8Array);
    expect(result.publicKey.length).toBe(32);
  });

  it('produces the same IPNS name for the same privateKey (determinism)', async () => {
    const keypair = generateTestKeypair();

    const result1 = await deriveRegistryIpnsKeypair(keypair.privateKey);
    const result2 = await deriveRegistryIpnsKeypair(keypair.privateKey);

    expect(result1.ipnsName).toBe(result2.ipnsName);
    expect(result1.privateKey).toEqual(result2.privateKey);
    expect(result1.publicKey).toEqual(result2.publicKey);
  });

  it('produces different IPNS names for different privateKeys', async () => {
    const keypair1 = generateTestKeypair();
    const keypair2 = generateTestKeypair();

    const result1 = await deriveRegistryIpnsKeypair(keypair1.privateKey);
    const result2 = await deriveRegistryIpnsKeypair(keypair2.privateKey);

    expect(result1.ipnsName).not.toBe(result2.ipnsName);
  });

  it('throws CryptoError for invalid key length (not 32 bytes)', async () => {
    const shortKey = new Uint8Array(16);
    await expect(deriveRegistryIpnsKeypair(shortKey)).rejects.toThrow(
      'Invalid private key size for registry derivation'
    );

    const longKey = new Uint8Array(64);
    await expect(deriveRegistryIpnsKeypair(longKey)).rejects.toThrow(
      'Invalid private key size for registry derivation'
    );
  });
});

describe('encryptRegistry / decryptRegistry', () => {
  it('round-trips a DeviceRegistry with 1 device entry', async () => {
    const keypair = generateTestKeypair();
    const registry = createTestRegistry(1);

    const encrypted = await encryptRegistry(registry, keypair.publicKey);
    const decrypted = await decryptRegistry(encrypted, keypair.privateKey);

    expect(decrypted).toEqual(registry);
  });

  it('round-trips a DeviceRegistry with multiple devices', async () => {
    const keypair = generateTestKeypair();
    const registry = createTestRegistry(5);

    const encrypted = await encryptRegistry(registry, keypair.publicKey);
    const decrypted = await decryptRegistry(encrypted, keypair.privateKey);

    expect(decrypted).toEqual(registry);
    expect(decrypted.devices).toHaveLength(5);
  });

  it('throws CryptoError when decrypting with wrong privateKey', async () => {
    const keypair1 = generateTestKeypair();
    const keypair2 = generateTestKeypair();
    const registry = createTestRegistry(1);

    const encrypted = await encryptRegistry(registry, keypair1.publicKey);

    await expect(decryptRegistry(encrypted, keypair2.privateKey)).rejects.toThrow(
      'Key unwrapping failed'
    );
  });

  it('produces encrypted output different from plaintext', async () => {
    const keypair = generateTestKeypair();
    const registry = createTestRegistry(1);

    const plaintext = new TextEncoder().encode(JSON.stringify(registry));
    const encrypted = await encryptRegistry(registry, keypair.publicKey);

    // Encrypted output should not equal plaintext
    expect(encrypted).not.toEqual(plaintext);
  });

  it('produces encrypted output larger than plaintext by ECIES overhead', async () => {
    const keypair = generateTestKeypair();
    const registry = createTestRegistry(1);

    const plaintext = new TextEncoder().encode(JSON.stringify(registry));
    const encrypted = await encryptRegistry(registry, keypair.publicKey);

    // ECIES overhead: ~97 bytes (65 ephemeral pubkey + 16 nonce + 16 tag)
    const overhead = encrypted.length - plaintext.length;
    expect(overhead).toBeGreaterThanOrEqual(80);
    expect(overhead).toBeLessThanOrEqual(120);
  });

  it('produces different ciphertext on each encryption (ECIES nondeterminism)', async () => {
    const keypair = generateTestKeypair();
    const registry = createTestRegistry(1);

    const encrypted1 = await encryptRegistry(registry, keypair.publicKey);
    const encrypted2 = await encryptRegistry(registry, keypair.publicKey);

    // Different due to ephemeral key
    expect(encrypted1).not.toEqual(encrypted2);

    // Both decrypt to same registry
    const decrypted1 = await decryptRegistry(encrypted1, keypair.privateKey);
    const decrypted2 = await decryptRegistry(encrypted2, keypair.privateKey);
    expect(decrypted1).toEqual(decrypted2);
  });
});

describe('validateDeviceRegistry', () => {
  it('accepts a valid registry', () => {
    const registry = createTestRegistry(2);
    const result = validateDeviceRegistry(registry);

    expect(result).toEqual(registry);
  });

  it('throws on missing version field', () => {
    const registry = createTestRegistry(1);
    const invalid = { ...registry, version: undefined };

    expect(() => validateDeviceRegistry(invalid)).toThrow('Invalid registry format');
  });

  it('throws on wrong version value', () => {
    const invalid = { ...createTestRegistry(1), version: 'v2' };

    expect(() => validateDeviceRegistry(invalid)).toThrow('Invalid registry format');
  });

  it('throws on invalid status value', () => {
    const registry = createTestRegistry(1);
    registry.devices[0].status = 'unknown' as never;

    expect(() => validateDeviceRegistry(registry)).toThrow('Invalid registry format');
  });

  it('throws on invalid platform value', () => {
    const registry = createTestRegistry(1);
    registry.devices[0].platform = 'ios' as never;

    expect(() => validateDeviceRegistry(registry)).toThrow('Invalid registry format');
  });

  it('throws on non-array devices field', () => {
    const invalid = {
      version: 'v1',
      sequenceNumber: 0,
      devices: 'not-an-array',
    };

    expect(() => validateDeviceRegistry(invalid)).toThrow('Invalid registry format');
  });

  it('throws on missing required DeviceEntry fields', () => {
    const invalid = {
      version: 'v1',
      sequenceNumber: 0,
      devices: [{ deviceId: 'abc' }], // missing other required fields
    };

    expect(() => validateDeviceRegistry(invalid)).toThrow('Invalid registry format');
  });

  it('throws on non-object data', () => {
    expect(() => validateDeviceRegistry(null)).toThrow('Invalid registry format');
    expect(() => validateDeviceRegistry('string')).toThrow('Invalid registry format');
    expect(() => validateDeviceRegistry(42)).toThrow('Invalid registry format');
  });

  it('throws on negative sequenceNumber', () => {
    const registry = createTestRegistry(1);
    const invalid = { ...registry, sequenceNumber: -1 };

    expect(() => validateDeviceRegistry(invalid)).toThrow('Invalid registry format');
  });

  it('throws on non-integer sequenceNumber', () => {
    const registry = createTestRegistry(1);
    const invalid = { ...registry, sequenceNumber: 1.5 };

    expect(() => validateDeviceRegistry(invalid)).toThrow('Invalid registry format');
  });

  it('accepts a registry with revoked device', () => {
    const registry = createTestRegistry(1);
    registry.devices[0].status = 'revoked';
    registry.devices[0].revokedAt = Date.now();
    registry.devices[0].revokedBy = 'some-device-id';

    const result = validateDeviceRegistry(registry);
    expect(result.devices[0].status).toBe('revoked');
    expect(result.devices[0].revokedAt).toBeTypeOf('number');
    expect(result.devices[0].revokedBy).toBeTypeOf('string');
  });

  it('accepts an empty devices array', () => {
    const registry: DeviceRegistry = {
      version: 'v1',
      sequenceNumber: 0,
      devices: [],
    };

    const result = validateDeviceRegistry(registry);
    expect(result.devices).toHaveLength(0);
  });
});

describe('generateDeviceKeypair / deriveDeviceId', () => {
  it('generates keypair with 32-byte public and private keys', () => {
    const keypair = generateDeviceKeypair();

    expect(keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keypair.publicKey.length).toBe(32);
    expect(keypair.privateKey).toBeInstanceOf(Uint8Array);
    expect(keypair.privateKey.length).toBe(32);
  });

  it('deviceId is a 64-character hex string (SHA-256)', () => {
    const keypair = generateDeviceKeypair();

    expect(keypair.deviceId).toMatch(/^[0-9a-f]{64}$/);
  });

  it('deriveDeviceId(keypair.publicKey) matches keypair.deviceId', () => {
    const keypair = generateDeviceKeypair();
    const derivedId = deriveDeviceId(keypair.publicKey);

    expect(derivedId).toBe(keypair.deviceId);
  });

  it('two generated keypairs have different deviceIds', () => {
    const keypair1 = generateDeviceKeypair();
    const keypair2 = generateDeviceKeypair();

    expect(keypair1.deviceId).not.toBe(keypair2.deviceId);
    expect(keypair1.publicKey).not.toEqual(keypair2.publicKey);
    expect(keypair1.privateKey).not.toEqual(keypair2.privateKey);
  });

  it('deriveDeviceId is deterministic for the same public key', () => {
    const keypair = generateDeviceKeypair();

    const id1 = deriveDeviceId(keypair.publicKey);
    const id2 = deriveDeviceId(keypair.publicKey);

    expect(id1).toBe(id2);
  });
});
