/**
 * Vault Settings Service - Load and save encrypted vault settings via IPNS.
 *
 * Follows the exact same zero-knowledge pattern as BYO-IPFS config:
 * ECIES encrypt with user's publicKey, upload to IPFS, publish IPNS record.
 *
 * Resolve/publish/upload/download route through the injected `CipherBoxClient`
 * facade (`resolveConfigBlob`/`publishConfigBlob`/`uploadBytes`/`downloadBytes`,
 * D-07) instead of calling sdk-core/ipns.service directly. Callers pass either
 * the real SDK client (post-login) or a throwaway bootstrap client
 * (`createBootstrapClient`, pre-login) -- these facade methods don't depend on
 * which one is supplied.
 */

import {
  wrapKey,
  unwrapKey,
  clearBytes,
  deriveVaultSettingsIpnsKeypair,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import { type VaultSettings, DEFAULT_VAULT_SETTINGS, validateVaultSettings } from '@cipherbox/sdk';
import type { CipherBoxClient } from '@cipherbox/sdk';

/** Timeout for loading vault settings from IPNS (matches BYO config timeout) */
const LOAD_TIMEOUT_MS = 10_000;

/**
 * Load vault settings from encrypted IPNS entry.
 *
 * Follows the exact BYO-IPFS config load pattern:
 * 1. Derive IPNS keypair via HKDF
 * 2. Resolve IPNS name to CID (via client.resolveConfigBlob)
 * 3. Fetch encrypted blob from IPFS (via client.downloadBytes)
 * 4. ECIES-decrypt with user's privateKey
 * 5. Parse JSON and validate
 *
 * Returns DEFAULT_VAULT_SETTINGS on any failure (graceful degradation).
 *
 * @param client - SDK facade client (real or bootstrap)
 * @param userPrivateKey - User's secp256k1 private key
 * @returns Validated VaultSettings (defaults on failure)
 */
export async function loadVaultSettings(
  client: CipherBoxClient,
  userPrivateKey: Uint8Array
): Promise<VaultSettings> {
  const inner = async (): Promise<VaultSettings> => {
    const keypair = await deriveVaultSettingsIpnsKeypair(userPrivateKey);

    const resolved = await client.resolveConfigBlob(keypair.ipnsName);
    if (!resolved?.cid) return { ...DEFAULT_VAULT_SETTINGS };

    const encrypted = await client.downloadBytes(resolved.cid);
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
        setTimeout(() => resolve({ ...DEFAULT_VAULT_SETTINGS }), LOAD_TIMEOUT_MS)
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
 * 3. Upload encrypted blob to IPFS (via client.uploadBytes)
 * 4. Derive IPNS keypair and resolve current sequence number (via client.resolveConfigBlob)
 * 5. Publish updated IPNS record (via client.publishConfigBlob)
 *
 * @param params.client - SDK facade client (real or bootstrap)
 * @param params.settings - Validated VaultSettings to save
 * @param params.userPublicKey - User's secp256k1 public key
 * @param params.userPrivateKey - User's secp256k1 private key
 */
export async function saveVaultSettings(params: {
  client: CipherBoxClient;
  settings: VaultSettings;
  userPublicKey: Uint8Array;
  userPrivateKey: Uint8Array;
  teeKeys?: { currentEpoch: number; currentPublicKey: string } | null;
}): Promise<void> {
  const { client, settings, userPublicKey, userPrivateKey, teeKeys } = params;

  // 1. Serialize and encrypt
  const plaintext = new TextEncoder().encode(JSON.stringify(settings));
  let encrypted: Uint8Array;
  try {
    encrypted = await wrapKey(plaintext, userPublicKey);
  } finally {
    clearBytes(plaintext);
  }

  // 2. Upload to IPFS
  const { cid } = await client.uploadBytes(encrypted);

  // 3. Derive IPNS keypair
  const keypair = await deriveVaultSettingsIpnsKeypair(userPrivateKey);

  // 4. Resolve current sequence number for monotonic increment.
  // resolveConfigBlob returns null for a true not-found (first publish) and THROWS for
  // verification/transient failures — let those propagate so a tampered or unverifiable
  // existing record fails closed instead of being silently masked as a first publish (seq 1).
  let sequenceNumber = 1n;
  const resolved = await client.resolveConfigBlob(keypair.ipnsName);
  if (resolved) {
    sequenceNumber = BigInt(resolved.sequenceNumber ?? 0) + 1n;
  }

  // 5. Wrap IPNS private key for TEE republishing (if available)
  let encryptedIpnsPrivateKey: string | undefined;
  let keyEpoch: number | undefined;
  if (teeKeys?.currentPublicKey) {
    const teePublicKey = hexToBytes(teeKeys.currentPublicKey);
    const wrappedKey = await wrapKey(keypair.privateKey, teePublicKey);
    encryptedIpnsPrivateKey = bytesToHex(wrappedKey);
    keyEpoch = teeKeys.currentEpoch;
  }

  // 6. Create and publish IPNS record
  const result = await client.publishConfigBlob({
    ipnsPrivateKey: keypair.privateKey,
    ipnsName: keypair.ipnsName,
    metadataCid: cid,
    sequenceNumber,
    encryptedIpnsPrivateKey,
    keyEpoch,
  });

  if (!result.success) {
    throw new Error('Failed to publish vault settings to IPNS');
  }
}
