/**
 * TEE fail-closed enrollment wrap (SC#6, phase 72).
 *
 * ECIES-wraps an IPNS private key under the current TEE public key so it can be
 * safely republished by the TEE worker (CLAUDE.md security rule 7). This is the
 * single shared implementation of the sequence that was previously triplicated
 * verbatim across `packages/sdk-core/src/folder/registration.ts`,
 * `packages/sdk-core/src/vault/index.ts`, and `packages/sdk-core/src/file/index.ts`:
 * decode the hex-encoded TEE public key, wrap the IPNS private key under it, and
 * hex-encode the wrapped result.
 *
 * Each call site retains its own fail-closed enrollment gate (validating
 * `teeKeys.currentPublicKey` is non-empty and `teeKeys.currentEpoch` is a positive
 * integer) BEFORE calling this helper — only the shared wrap sequence itself is
 * extracted here. `hexToBytes` still throws on a malformed public key, so the
 * fail-closed contract holds end-to-end.
 */

import { wrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';

/**
 * ECIES-wrap `ipnsPrivateKey` under `currentPublicKey` (hex-encoded TEE public key)
 * and return the wrapped result as a hex string.
 *
 * Buffer ownership (D-09): this function BORROWS `ipnsPrivateKey` — it reads the
 * buffer but does NOT consume or zero it. The caller remains the terminal owner
 * and is responsible for zeroizing `ipnsPrivateKey` once it is no longer needed.
 * Never mutate or clear the borrowed buffer inside this helper.
 */
export async function wrapIpnsKeyForTee(
  ipnsPrivateKey: Uint8Array,
  currentPublicKey: string
): Promise<string> {
  const teePublicKeyBytes = hexToBytes(currentPublicKey);
  const wrappedBytes = await wrapKey(ipnsPrivateKey, teePublicKeyBytes);
  return bytesToHex(wrappedBytes);
}
