/**
 * Vault key blob operations (v3 two-key format, NODE-06 / D-05)
 *
 * The vault key blob stores ECIES-wrapped rootReadKey and rootWriteKey on IPFS,
 * published to a dedicated IPNS name derived via HKDF. This separates
 * key storage from folder metadata so folder updates don't overwrite the keys.
 *
 * - publishVaultKeyBlob: wraps rootReadKey + rootWriteKey and publishes to IPNS (called during vault init)
 * - loadVaultKeyBlob: resolves IPNS, fetches v3 blob, unwraps both keys (called on login)
 *
 * Phase 62 (D-05): hard-cut to v3 blob format (0x03 | u16_BE(readLen) | ECIES(rootReadKey) |
 * u16_BE(writeLen) | ECIES(rootWriteKey)). v2 / v1 paths are retired.
 */

import { deriveVaultKeyIpnsKeypair, wrapKey, unwrapKey } from '@cipherbox/crypto';
import { serializeVaultBlobV3, deserializeVaultBlobV3 } from '@cipherbox/core';
import type { SdkContext } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';

/**
 * Publish the vault key blob to IPNS.
 *
 * Wraps both rootReadKey and rootWriteKey with the user's publicKey via ECIES,
 * serializes as a v3 blob, uploads to IPFS, and publishes the CID to the vault
 * key IPNS name.
 *
 * @returns The vault key IPNS name
 */
export async function publishVaultKeyBlob(params: {
  userPrivateKey: Uint8Array;
  userPublicKey: Uint8Array;
  rootReadKey: Uint8Array;
  rootWriteKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{ ipnsName: string }> {
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(params.userPrivateKey);

  try {
    const encryptedRootReadKey = await wrapKey(params.rootReadKey, params.userPublicKey);
    const encryptedRootWriteKey = await wrapKey(params.rootWriteKey, params.userPublicKey);
    const v3Blob = serializeVaultBlobV3(encryptedRootReadKey, encryptedRootWriteKey);

    const { cid } = await addToIpfs(params.ctx, v3Blob);
    const result = await createAndPublishIpnsRecord({
      ipnsPrivateKey: vaultKeyKeypair.privateKey,
      ipnsPublicKey: vaultKeyKeypair.publicKey,
      ipnsName: vaultKeyKeypair.ipnsName,
      metadataCid: cid,
      sequenceNumber: 1n,
      ctx: params.ctx,
    });

    if (!result.success) {
      throw new Error('Failed to publish vault key blob to IPNS');
    }

    return { ipnsName: vaultKeyKeypair.ipnsName };
  } finally {
    // T-47-01 / D-05: this function derives vaultKeyKeypair and is its terminal owner —
    // zero the private key on all exit paths (success and failure).
    vaultKeyKeypair.privateKey.fill(0);
  }
}

/**
 * Load the vault key blob from IPNS and decrypt both root keys.
 *
 * Resolves the vault key IPNS name, fetches the v3 blob from IPFS,
 * and unwraps both rootReadKey and rootWriteKey using the user's privateKey.
 *
 * @returns The decrypted rootReadKey and rootWriteKey, or null if the IPNS record doesn't exist
 */
export async function loadVaultKeyBlob(params: {
  userPrivateKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{ rootReadKey: Uint8Array; rootWriteKey: Uint8Array; ipnsName: string } | null> {
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(params.userPrivateKey);

  const resolved = await resolveIpnsRecord(vaultKeyKeypair.ipnsName, params.ctx);
  if (!resolved) return null;

  const blobBytes = await fetchFromIpfs(params.ctx, resolved.cid);

  const { encryptedRootReadKey, encryptedRootWriteKey } = deserializeVaultBlobV3(blobBytes);
  const rootReadKey = await unwrapKey(encryptedRootReadKey, params.userPrivateKey);
  const rootWriteKey = await unwrapKey(encryptedRootWriteKey, params.userPrivateKey);

  return { rootReadKey, rootWriteKey, ipnsName: vaultKeyKeypair.ipnsName };
}
