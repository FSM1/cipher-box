/**
 * @cipherbox/crypto - Recycle Bin Metadata Schema Validation
 *
 * Runtime validation for RecycleBinMetadata JSON after decryption.
 * Uses manual checks consistent with existing codebase patterns
 * (see registry/schema.ts validateDeviceRegistry).
 */

import { CryptoError } from '../types';
import type { RecycleBinMetadata } from './types';

const VALID_ITEM_TYPES = ['file', 'folder'];

/**
 * Validate a parsed JSON object as RecycleBinMetadata.
 *
 * Throws CryptoError with code 'DECRYPTION_FAILED' on validation failure
 * to avoid leaking schema details to attackers.
 *
 * @param data - Unknown parsed JSON data
 * @returns Validated RecycleBinMetadata
 * @throws CryptoError if validation fails
 */
export function validateBinMetadata(data: unknown): RecycleBinMetadata {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  const obj = data as Record<string, unknown>;

  // Validate version
  if (obj.version !== 'v1') {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate sequenceNumber
  if (
    typeof obj.sequenceNumber !== 'number' ||
    !Number.isInteger(obj.sequenceNumber) ||
    obj.sequenceNumber < 0
  ) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate entries array
  if (!Array.isArray(obj.entries)) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate each bin entry
  for (const entry of obj.entries) {
    validateBinEntry(entry);
  }

  return data as RecycleBinMetadata;
}

/**
 * Validate an individual bin entry.
 */
function validateBinEntry(data: unknown): void {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  const entry = data as Record<string, unknown>;

  // Validate id (non-empty string)
  if (typeof entry.id !== 'string' || entry.id.length === 0) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate itemType
  if (typeof entry.itemType !== 'string' || !VALID_ITEM_TYPES.includes(entry.itemType)) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate name (string)
  if (typeof entry.name !== 'string') {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate originalParentIpnsName (string)
  if (typeof entry.originalParentIpnsName !== 'string') {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate originalPath (string)
  if (typeof entry.originalPath !== 'string') {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate deletedAt (number)
  if (
    typeof entry.deletedAt !== 'number' ||
    !Number.isFinite(entry.deletedAt) ||
    entry.deletedAt < 0
  ) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate size (non-negative finite number)
  if (typeof entry.size !== 'number' || !Number.isFinite(entry.size) || entry.size < 0) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate mimeType (string)
  if (typeof entry.mimeType !== 'string') {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  // Validate optional contentCid (non-empty string if present)
  if (entry.contentCid !== undefined) {
    if (typeof entry.contentCid !== 'string' || entry.contentCid.length === 0) {
      throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
    }
  }

  // Validate optional contentSize (non-negative finite number if present)
  if (entry.contentSize !== undefined) {
    if (
      typeof entry.contentSize !== 'number' ||
      !Number.isFinite(entry.contentSize) ||
      entry.contentSize < 0
    ) {
      throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
    }
  }

  // Validate optional versionCids (array of {cid: string, size: number} if present)
  if (entry.versionCids !== undefined) {
    if (!Array.isArray(entry.versionCids)) {
      throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
    }
    for (const vc of entry.versionCids) {
      if (typeof vc !== 'object' || vc === null) {
        throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
      }
      const v = vc as Record<string, unknown>;
      if (typeof v.cid !== 'string' || v.cid.length === 0) {
        throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
      }
      if (typeof v.size !== 'number' || !Number.isFinite(v.size) || v.size < 0) {
        throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
      }
    }
  }

  // Validate filePointer/folderEntry: optional, but if present must be objects
  // Be lenient -- schema may evolve, so we don't enforce strict presence based on itemType
  if (
    entry.filePointer !== undefined &&
    (typeof entry.filePointer !== 'object' || entry.filePointer === null)
  ) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }

  if (
    entry.folderEntry !== undefined &&
    (typeof entry.folderEntry !== 'object' || entry.folderEntry === null)
  ) {
    throw new CryptoError('Invalid bin metadata format', 'DECRYPTION_FAILED');
  }
}
