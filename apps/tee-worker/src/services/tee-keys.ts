/**
 * TEE Key Derivation Service
 *
 * Derives deterministic secp256k1 keypairs per epoch.
 * - Simulator mode: HKDF-SHA256 from a fixed seed (development/testing)
 * - CVM mode: DstackClient.getKey() for hardware-backed derivation (production)
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';

/**
 * Structured error emitted when the TEE cannot produce a keypair because of a
 * deployment misconfiguration or an infrastructure/SDK failure — NOT because a
 * user's ciphertext is wrong or corrupted.
 *
 * Thrown from getKeypair's two config/infra guard sites:
 *  1. simulator-in-production guard (TEE_MODE=simulator in a production env)
 *  2. unexpected DstackClient.getKey() return shape (SDK contract violation)
 *
 * Callers (decryptWithFallback) MUST rethrow this via `instanceof` rather than
 * treating it as a decrypt failure — a misconfiguration must never be masked as
 * a corrupted user key. Mirrors the ReEnrollRequiredError typed-error convention.
 *
 * SECURITY: message names config/infra conditions ONLY — no key bytes or material.
 */
export class TeeKeyUnavailableError extends Error {
  readonly keyUnavailable = true;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TeeKeyUnavailableError';
  }
}

/** Cache public keys per epoch to avoid repeated derivation */
const publicKeyCache = new Map<number, Uint8Array>();
const MAX_CACHE_SIZE = 100;

/** Valid epoch range — epochs are small sequential integers (one per ~4 weeks) */
export const MIN_EPOCH = 1;
export const MAX_EPOCH = 10_000;

/**
 * 4-week epoch duration in milliseconds.
 * Must match the relay's epoch schedule configuration.
 */
export const EPOCH_DURATION_MS = 4 * 7 * 24 * 60 * 60 * 1000;

/**
 * Derive the current epoch from the TEE's own clock.
 *
 * Reads EPOCH_ZERO_TIMESTAMP_MS from the environment at call time (not module
 * load) so tests and staged rollouts can vary it without restarting the process.
 * Returns MIN_EPOCH (1) when the anchor is absent or in the future — a safe
 * fallback floor that never triggers the stale-key guard.
 *
 * This is the §6.7-1 internal-clock derivation — it never reads a relay-supplied
 * currentEpoch/previousEpoch scalar.
 *
 * @returns Current epoch number (≥ MIN_EPOCH)
 */
export function getInternalCurrentEpoch(): number {
  const anchor = parseInt(process.env.EPOCH_ZERO_TIMESTAMP_MS ?? '0', 10);
  // Treat unset (0), malformed (NaN), and non-positive anchors identically: fall
  // back to MIN_EPOCH before any Date.now() math so a bad env var can never
  // propagate a NaN epoch into the stale-key guard.
  if (!Number.isFinite(anchor) || anchor <= 0) {
    return MIN_EPOCH; // Safe fallback: no valid anchor configured → epoch 1
  }
  return Math.max(MIN_EPOCH, Math.floor((Date.now() - anchor) / EPOCH_DURATION_MS) + 1);
}

/**
 * Derive a deterministic secp256k1 keypair for a given epoch.
 *
 * In simulator mode, uses HKDF-SHA256 with a fixed seed.
 * In CVM mode, uses Phala dstack SDK for hardware-backed derivation.
 *
 * @param epoch - The key epoch number
 * @returns Object with publicKey (65 bytes, uncompressed) and privateKey (32 bytes)
 */
export async function getKeypair(
  epoch: number
): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  const mode = process.env.TEE_MODE || 'simulator';

  const env = process.env.CIPHERBOX_ENVIRONMENT;
  if (
    mode === 'simulator' &&
    (env === 'production' || (!env && process.env.NODE_ENV === 'production'))
  ) {
    throw new TeeKeyUnavailableError(
      'TEE_MODE=simulator is not allowed in production. Set TEE_MODE=cvm for production deployments, or set CIPHERBOX_ENVIRONMENT explicitly.'
    );
  }

  let privateKey: Uint8Array;

  if (mode === 'cvm') {
    // Production: Phala Cloud CVM with dstack SDK
    // Dynamic import -- @phala/dstack-sdk is only available inside CVM
    const { DstackClient } = await import('@phala/dstack-sdk');
    const client = new DstackClient();
    const keyResult = await client.getKey('cipherbox/ipns-republish', `epoch-${epoch}`);

    // Defensive handling: SDK v0.5+ returns { key: Uint8Array },
    // older versions returned { asUint8Array(): Uint8Array }
    const keyAny = keyResult as unknown as Record<string, unknown>;
    const rawKey =
      'key' in keyResult && keyResult.key instanceof Uint8Array
        ? keyResult.key
        : typeof keyAny.asUint8Array === 'function'
          ? (keyAny.asUint8Array as () => Uint8Array)()
          : (() => {
              throw new TeeKeyUnavailableError('Unexpected DstackClient.getKey() return type');
            })();
    privateKey = new Uint8Array(rawKey.slice(0, 32));
  } else {
    // Simulator: deterministic HKDF derivation from fixed seed
    const seed = new TextEncoder().encode('cipherbox-tee-simulator-seed');
    const salt = new TextEncoder().encode('cipherbox-dev');
    const info = new TextEncoder().encode(`epoch-${epoch}`);
    privateKey = hkdf(sha256, seed, salt, info, 32);
  }

  // Derive uncompressed public key (65 bytes, 0x04 prefix)
  const publicKey = secp.getPublicKey(privateKey, false);

  // Cache public key for this epoch (bounded to prevent memory DoS)
  if (publicKeyCache.size >= MAX_CACHE_SIZE) {
    const firstKey = publicKeyCache.keys().next().value;
    if (firstKey !== undefined) publicKeyCache.delete(firstKey);
  }
  publicKeyCache.set(epoch, publicKey);

  return { publicKey, privateKey };
}

/**
 * Get the cached public key for an epoch, or derive it.
 *
 * @param epoch - The key epoch number
 * @returns 65-byte uncompressed secp256k1 public key
 */
export async function getPublicKey(epoch: number): Promise<Uint8Array> {
  const cached = publicKeyCache.get(epoch);
  if (cached) {
    return cached;
  }

  const { publicKey } = await getKeypair(epoch);
  return publicKey;
}
