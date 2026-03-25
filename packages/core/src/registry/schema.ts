/**
 * @cipherbox/core - Device Registry Schema Validation
 *
 * Runtime validation for DeviceRegistry JSON after decryption.
 * Uses manual checks consistent with existing codebase patterns
 * (see folder/metadata.ts validateFolderMetadata).
 *
 * Supports v1 -> v2 migration:
 * - v1 registries with empty ipHash are accepted and migrated to v2 with zero placeholder
 * - v2 registries are validated strictly (ipHash must be valid 64-char hex)
 */

import { CryptoError } from '@cipherbox/crypto';
import type { DeviceRegistry, DeviceAuthStatus, DevicePlatform, DeviceEntry } from './types';

const VALID_STATUSES: DeviceAuthStatus[] = ['pending', 'authorized', 'revoked'];
const VALID_PLATFORMS: DevicePlatform[] = ['web', 'macos', 'linux', 'windows'];
const HEX_REGEX = /^[0-9a-fA-F]+$/;

/**
 * Validate a parsed JSON object as a DeviceRegistry.
 *
 * Handles both v1 and v2 formats:
 * - v1: Migrated to v2 (lenient ipHash validation, fills zero placeholder)
 * - v2: Strict validation (ipHash must be valid 64-char hex)
 *
 * Throws CryptoError with code 'DECRYPTION_FAILED' on validation failure
 * to avoid leaking schema details to attackers.
 *
 * @param data - Unknown parsed JSON data
 * @returns Validated DeviceRegistry (always v2)
 * @throws CryptoError if validation fails
 */
export function validateDeviceRegistry(data: unknown): DeviceRegistry {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const obj = data as Record<string, unknown>;
  const version = obj.version;

  if (version === 'v1') {
    return migrateV1ToV2(obj);
  }
  if (version === 'v2') {
    return validateV2Registry(obj);
  }
  throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
}

/**
 * Migrate a v1 registry to v2 format.
 *
 * Lenient on ipHash: accepts empty strings from v1 (known bug in useAuth.ts)
 * and fills them with a 64-char zero placeholder.
 */
function migrateV1ToV2(obj: Record<string, unknown>): DeviceRegistry {
  if (
    typeof obj.sequenceNumber !== 'number' ||
    !Number.isInteger(obj.sequenceNumber) ||
    obj.sequenceNumber < 0
  ) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  if (!Array.isArray(obj.devices)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const devices = (obj.devices as Record<string, unknown>[]).map((d) => {
    validateDeviceEntryBase(d);
    const ipHash = d.ipHash as string;
    return {
      ...(d as unknown as DeviceEntry),
      // Accept empty ipHash from v1 (known bug) -- fill with zero placeholder
      ipHash: ipHash.length === 64 && HEX_REGEX.test(ipHash) ? ipHash : '0'.repeat(64),
    };
  }) as DeviceEntry[];

  return {
    version: 'v2',
    sequenceNumber: obj.sequenceNumber as number,
    devices,
  };
}

/**
 * Validate a v2 registry with strict validation.
 */
function validateV2Registry(obj: Record<string, unknown>): DeviceRegistry {
  if (
    typeof obj.sequenceNumber !== 'number' ||
    !Number.isInteger(obj.sequenceNumber) ||
    obj.sequenceNumber < 0
  ) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  if (!Array.isArray(obj.devices)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  for (const device of obj.devices) {
    validateDeviceEntry(device); // Strict v2 validation (ipHash must be valid 64 hex)
  }

  return obj as unknown as DeviceRegistry;
}

/**
 * Validate device entry base fields (everything EXCEPT ipHash length/hex).
 * Used by v1 migration where ipHash may be empty.
 */
function validateDeviceEntryBase(data: unknown): void {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const entry = data as Record<string, unknown>;

  // Required string fields
  const requiredStrings = [
    'deviceId',
    'publicKey',
    'name',
    'platform',
    'appVersion',
    'deviceModel',
    'ipHash',
    'status',
  ];
  for (const field of requiredStrings) {
    if (typeof entry[field] !== 'string') {
      throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
    }
  }

  // Hex format + length validation for cryptographic fields (except ipHash -- handled by caller)
  const deviceId = entry.deviceId as string;
  if (deviceId.length !== 64 || !HEX_REGEX.test(deviceId)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const publicKey = entry.publicKey as string;
  if (publicKey.length !== 64 || !HEX_REGEX.test(publicKey)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Max length for free-text fields
  if ((entry.name as string).length > 200) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  if ((entry.appVersion as string).length > 50) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  if ((entry.deviceModel as string).length > 200) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate status is a known value
  if (!VALID_STATUSES.includes(entry.status as DeviceAuthStatus)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate platform is a known value
  if (!VALID_PLATFORMS.includes(entry.platform as DevicePlatform)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate timestamp fields
  if (typeof entry.createdAt !== 'number' || typeof entry.lastSeenAt !== 'number') {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate nullable fields
  if (entry.revokedAt !== null && typeof entry.revokedAt !== 'number') {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
  if (entry.revokedBy !== null && typeof entry.revokedBy !== 'string') {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
}

/**
 * Validate an individual device entry with strict ipHash validation.
 * Used for v2 registries where ipHash must be a valid 64-char hex string.
 */
function validateDeviceEntry(data: unknown): void {
  validateDeviceEntryBase(data);
  const entry = data as Record<string, unknown>;
  const ipHash = entry.ipHash as string;
  if (ipHash.length !== 64 || !HEX_REGEX.test(ipHash)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }
}
