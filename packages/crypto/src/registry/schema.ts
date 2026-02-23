/**
 * @cipherbox/crypto - Device Registry Schema Validation
 *
 * Runtime validation for DeviceRegistry JSON after decryption.
 * Uses manual checks consistent with existing codebase patterns
 * (see folder/metadata.ts validateFolderMetadata).
 */

import { CryptoError } from '../types';
import type { DeviceRegistry, DeviceAuthStatus, DevicePlatform } from './types';

const VALID_STATUSES: DeviceAuthStatus[] = ['pending', 'authorized', 'revoked'];
const VALID_PLATFORMS: DevicePlatform[] = ['web', 'macos', 'linux', 'windows'];
const HEX_REGEX = /^[0-9a-fA-F]+$/;

/**
 * Validate a parsed JSON object as a DeviceRegistry.
 *
 * Throws CryptoError with code 'DECRYPTION_FAILED' on validation failure
 * to avoid leaking schema details to attackers.
 *
 * @param data - Unknown parsed JSON data
 * @returns Validated DeviceRegistry
 * @throws CryptoError if validation fails
 */
export function validateDeviceRegistry(data: unknown): DeviceRegistry {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const obj = data as Record<string, unknown>;

  // Validate version
  if (obj.version !== 'v1') {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate sequenceNumber
  if (
    typeof obj.sequenceNumber !== 'number' ||
    !Number.isInteger(obj.sequenceNumber) ||
    obj.sequenceNumber < 0
  ) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate devices array
  if (!Array.isArray(obj.devices)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  // Validate each device entry
  for (const device of obj.devices) {
    validateDeviceEntry(device);
  }

  return data as DeviceRegistry;
}

/**
 * Validate an individual device entry.
 */
function validateDeviceEntry(data: unknown): void {
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

  // Hex format + length validation for cryptographic fields
  const deviceId = entry.deviceId as string;
  if (deviceId.length !== 64 || !HEX_REGEX.test(deviceId)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const publicKey = entry.publicKey as string;
  if (publicKey.length !== 64 || !HEX_REGEX.test(publicKey)) {
    throw new CryptoError('Invalid registry format', 'DECRYPTION_FAILED');
  }

  const ipHash = entry.ipHash as string;
  if (ipHash.length !== 64 || !HEX_REGEX.test(ipHash)) {
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
