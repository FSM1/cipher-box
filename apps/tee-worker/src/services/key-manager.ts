/**
 * Key Manager Service
 *
 * ECIES decryption of IPNS private keys with epoch fallback and re-encryption.
 * - Derives the current epoch internally from the TEE clock (§6.7-1, D-03)
 * - Refuses to decrypt keys older than currentEpoch − 1 (hard stale floor)
 * - Emits ReEnrollRequiredError for stale keys (structured signal, no key material)
 * - Tries keyEpoch hint first, then internalCurrentEpoch (mid-rotation fallback)
 * - Re-encrypts old-epoch keys with the current epoch key
 *
 * SECURITY: Caller is responsible for zeroing returned IPNS private keys after use.
 */

import { unwrapKey, wrapKey } from '@cipherbox/crypto';
import {
  getKeypair,
  getInternalCurrentEpoch,
  getPublicKey,
  TeeKeyUnavailableError,
} from './tee-keys.js';

/**
 * Structured error emitted when a relay-supplied IPNS key is too old to renew.
 *
 * Thrown when keyEpoch < internalCurrentEpoch − 1. The client must re-enroll
 * (re-encrypt its IPNS private key with the current TEE epoch public key)
 * before republishing can continue.
 *
 * SECURITY: message names epoch integers ONLY — no key bytes or key material.
 */
export class ReEnrollRequiredError extends Error {
  readonly requiresReEnroll = true;

  constructor(
    readonly keyEpoch: number,
    readonly currentEpoch: number
  ) {
    super(
      `IPNS key epoch ${keyEpoch} is older than grace floor ${currentEpoch - 1} (current epoch: ${currentEpoch}). Re-enrollment required.`
    );
    this.name = 'ReEnrollRequiredError';
  }
}

/**
 * Decrypt an ECIES-encrypted IPNS private key using the specified epoch's private key.
 *
 * @param encryptedIpnsPrivateKey - ECIES ciphertext containing the IPNS Ed25519 private key
 * @param epoch - The key epoch to use for decryption
 * @returns 32-byte Ed25519 IPNS private key
 * @throws Error if decryption fails (wrong epoch or corrupted data)
 */
export async function decryptIpnsKey(
  encryptedIpnsPrivateKey: Uint8Array,
  epoch: number
): Promise<Uint8Array> {
  const keypair = await getKeypair(epoch);
  try {
    return await unwrapKey(encryptedIpnsPrivateKey, keypair.privateKey);
  } finally {
    keypair.privateKey.fill(0);
  }
}

/**
 * Decrypt an IPNS key with TEE-internal epoch authority.
 *
 * Derives the current epoch from the TEE's own clock (never from a relay scalar).
 * Refuses keys older than currentEpoch − 1 by throwing ReEnrollRequiredError
 * BEFORE any decryption attempt — the hard stale floor (D-03, §6.7-3).
 *
 * Trial order:
 *  1. keyEpoch (the epoch the key is encrypted for, from ipns_records.key_epoch)
 *  2. internalCurrentEpoch (mid-rotation fallback: key may have been re-encrypted)
 *
 * @param encryptedIpnsPrivateKey - ECIES ciphertext
 * @param keyEpoch - Epoch hint from ipns_records.key_epoch (never relay's currentEpoch)
 * @returns Object with decrypted key and which epoch succeeded
 * @throws ReEnrollRequiredError if keyEpoch < internalCurrentEpoch − 1 (stale)
 * @throws Error if all decryption trials fail (corrupted or unknown key)
 */
export async function decryptWithFallback(
  encryptedIpnsPrivateKey: Uint8Array,
  keyEpoch: number
): Promise<{ ipnsPrivateKey: Uint8Array; usedEpoch: number }> {
  const internalCurrentEpoch = getInternalCurrentEpoch();

  // Hard stale floor (D-03, §6.7-3): refuse keys older than currentEpoch − 1
  // BEFORE any unwrap attempt — a compromised relay cannot force re-encryption
  // to a wrong epoch by sending stale keys.
  if (keyEpoch < internalCurrentEpoch - 1) {
    throw new ReEnrollRequiredError(keyEpoch, internalCurrentEpoch);
  }

  // Trial 1: keyEpoch (the epoch the key is recorded as encrypted for)
  try {
    const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsPrivateKey, keyEpoch);
    return { ipnsPrivateKey, usedEpoch: keyEpoch };
  } catch (err) {
    // A config/infra failure from getKeypair (deployment misconfig, unexpected
    // SDK return shape) must NOT be masked as a corrupted user key — rethrow the
    // typed error via instanceof (mirrors the ReEnrollRequiredError convention,
    // never string-matching error.message). Any other error (e.g. an epoch
    // mismatch) falls through to the internal-current epoch trial.
    if (err instanceof TeeKeyUnavailableError) {
      throw new TeeKeyUnavailableError(err.message, { cause: err });
    }
    // keyEpoch trial failed — try the internal-current epoch next
  }

  // Trial 2: internalCurrentEpoch (mid-rotation: key may have been re-encrypted
  // to current epoch while keyEpoch still reflects the old DB value)
  if (keyEpoch !== internalCurrentEpoch) {
    try {
      const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsPrivateKey, internalCurrentEpoch);
      return { ipnsPrivateKey, usedEpoch: internalCurrentEpoch };
    } catch (err) {
      // Same typed-error rethrow: a config/infra failure is not a decrypt failure.
      if (err instanceof TeeKeyUnavailableError) {
        throw new TeeKeyUnavailableError(err.message, { cause: err });
      }
      // internal-current epoch also failed
    }
  }

  throw new Error('ECIES decryption failed: key may be corrupted or from an unknown epoch');
}

/**
 * Re-encrypt an IPNS private key for a target epoch.
 *
 * Used during epoch migration: when a key was decrypted with the previous epoch,
 * it gets re-encrypted with the target epoch's public key so future republishes
 * use the current epoch directly. Callers (e.g. republish route after 67-06)
 * should pass getInternalCurrentEpoch() as the targetEpoch.
 *
 * @param ipnsPrivateKey - Plaintext 32-byte Ed25519 IPNS private key
 * @param targetEpoch - The epoch to encrypt for
 * @returns ECIES ciphertext encrypted with target epoch's public key
 */
export async function reEncryptForEpoch(
  ipnsPrivateKey: Uint8Array,
  targetEpoch: number
): Promise<Uint8Array> {
  const targetPublicKey = await getPublicKey(targetEpoch);
  return await wrapKey(ipnsPrivateKey, targetPublicKey);
}
