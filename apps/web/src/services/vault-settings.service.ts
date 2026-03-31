/**
 * Vault Settings Service - Load and save encrypted vault settings via IPNS.
 *
 * Follows the exact same zero-knowledge pattern as BYO-IPFS config:
 * ECIES encrypt with user's publicKey, upload to IPFS, publish IPNS record.
 */

import { wrapKey, unwrapKey, clearBytes, deriveVaultSettingsIpnsKeypair } from '@cipherbox/crypto';
import { type VaultSettings, DEFAULT_VAULT_SETTINGS, validateVaultSettings } from '@cipherbox/core';
import { addToIpfs, fetchFromIpfs } from '../lib/api/ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from './ipns.service';

/** Timeout for loading vault settings from IPNS (matches BYO config timeout) */
const LOAD_TIMEOUT_MS = 10_000;

/**
 * Load vault settings from encrypted IPNS entry.
 *
 * Follows the exact BYO-IPFS config load pattern:
 * 1. Derive IPNS keypair via HKDF
 * 2. Resolve IPNS name to CID
 * 3. Fetch encrypted blob from IPFS
 * 4. ECIES-decrypt with user's privateKey
 * 5. Parse JSON and validate
 *
 * Returns DEFAULT_VAULT_SETTINGS on any failure (graceful degradation).
 *
 * @param userPrivateKey - User's secp256k1 private key
 * @returns Validated VaultSettings (defaults on failure)
 */
export async function loadVaultSettings(userPrivateKey: Uint8Array): Promise<VaultSettings> {
  const inner = async (): Promise<VaultSettings> => {
    const keypair = await deriveVaultSettingsIpnsKeypair(userPrivateKey);

    const resolved = await resolveIpnsRecord(keypair.ipnsName);
    if (!resolved?.cid) return { ...DEFAULT_VAULT_SETTINGS };

    const encrypted = await fetchFromIpfs(resolved.cid);
    const plaintext = await unwrapKey(encrypted, userPrivateKey);
    let parsed: unknown;
    try {
      const json = new TextDecoder().decode(plaintext);
      parsed = JSON.parse(json);
    } finally {
      clearBytes(plaintext);
    }

    return validateVaultSettings(parsed);
  };

  try {
    const result = await Promise.race([
      inner(),
      new Promise<VaultSettings>((resolve) =>
        setTimeout(() => resolve({ ...DEFAULT_VAULT_SETTINGS }), LOAD_TIMEOUT_MS),
      ),
    ]);
    return result;
  } catch {
    return { ...DEFAULT_VAULT_SETTINGS };
  }
}

/**
 * Save vault settings as an encrypted IPNS entry.
 *
 * Follows the exact BYO-IPFS config save pattern:
 * 1. Serialize settings JSON
 * 2. ECIES-encrypt with user's publicKey
 * 3. Upload encrypted blob to IPFS
 * 4. Derive IPNS keypair and resolve current sequence number
 * 5. Publish updated IPNS record
 *
 * @param params.settings - Validated VaultSettings to save
 * @param params.userPublicKey - User's secp256k1 public key
 * @param params.userPrivateKey - User's secp256k1 private key
 */
export async function saveVaultSettings(params: {
  settings: VaultSettings;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
}): Promise<void> {
  const { settings, userPublicKey, userPrivateKey } = params;

  // 1. Serialize and encrypt
  const plaintext = new TextEncoder().encode(JSON.stringify(settings));
  let encrypted: Uint8Array;
  try {
    encrypted = await wrapKey(plaintext, userPublicKey);
  } finally {
    clearBytes(plaintext);
  }

  // 2. Upload to IPFS (addToIpfs expects a Blob)
  const blob = new Blob([encrypted as BlobPart]);
  const { cid } = await addToIpfs(blob);

  // 3. Derive IPNS keypair
  const keypair = await deriveVaultSettingsIpnsKeypair(userPrivateKey);

  // 4. Resolve current sequence number for monotonic increment
  let sequenceNumber = 0n;
  try {
    const resolved = await resolveIpnsRecord(keypair.ipnsName);
    if (resolved) {
      sequenceNumber = BigInt(resolved.sequenceNumber ?? 0) + 1n;
    }
  } catch {
    // First publish -- start from 0
  }

  // 5. Create and publish IPNS record
  const result = await createAndPublishIpnsRecord({
    ipnsPrivateKey: keypair.privateKey,
    ipnsName: keypair.ipnsName,
    metadataCid: cid,
    sequenceNumber,
  });

  if (!result.success) {
    throw new Error('Failed to publish vault settings to IPNS');
  }
}
