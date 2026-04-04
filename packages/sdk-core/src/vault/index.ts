/**
 * Vault key blob operations
 *
 * The vault key blob stores the ECIES-wrapped rootFolderKey on IPFS,
 * published to a dedicated IPNS name derived via HKDF. This separates
 * key storage from folder metadata so folder updates don't overwrite the key.
 *
 * - publishVaultKeyBlob: wraps rootFolderKey and publishes to IPNS (called during vault init)
 * - loadVaultKeyBlob: resolves IPNS, fetches blob, unwraps rootFolderKey (called on login)
 */

import { deriveVaultKeyIpnsKeypair, wrapKey, unwrapKey } from '@cipherbox/crypto';
import { serializeVaultBlobV2, deserializeVaultBlobV2, detectBlobVersion } from '@cipherbox/core';
import type { SdkContext } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';

/**
 * Publish the vault key blob to IPNS.
 *
 * Wraps rootFolderKey with the user's publicKey via ECIES, serializes as a v2 blob,
 * uploads to IPFS, and publishes the CID to the vault key IPNS name.
 *
 * @returns The vault key IPNS name
 */
export async function publishVaultKeyBlob(params: {
  userPrivateKey: Uint8Array;
  userPublicKey: Uint8Array;
  rootFolderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{ ipnsName: string }> {
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(params.userPrivateKey);

  const encryptedRootFolderKey = await wrapKey(params.rootFolderKey, params.userPublicKey);
  const v2Blob = serializeVaultBlobV2(encryptedRootFolderKey);

  const { cid } = await addToIpfs(params.ctx, new Uint8Array(v2Blob));
  const result = await createAndPublishIpnsRecord({
    ipnsPrivateKey: vaultKeyKeypair.privateKey,
    ipnsPublicKey: vaultKeyKeypair.publicKey,
    ipnsName: vaultKeyKeypair.ipnsName,
    metadataCid: cid,
    sequenceNumber: 0n,
    ctx: params.ctx,
  });

  if (!result.success) {
    throw new Error('Failed to publish vault key blob to IPNS');
  }

  return { ipnsName: vaultKeyKeypair.ipnsName };
}

/**
 * Load the vault key blob from IPNS and decrypt the rootFolderKey.
 *
 * Resolves the vault key IPNS name, fetches the v2 blob from IPFS,
 * and unwraps the rootFolderKey using the user's privateKey.
 *
 * @returns The decrypted rootFolderKey, or null if the IPNS record doesn't exist
 */
export async function loadVaultKeyBlob(params: {
  userPrivateKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{ rootFolderKey: Uint8Array; ipnsName: string } | null> {
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(params.userPrivateKey);

  const resolved = await resolveIpnsRecord(vaultKeyKeypair.ipnsName, params.ctx);
  if (!resolved) return null;

  const blobBytes = await fetchFromIpfs(params.ctx, resolved.cid);

  if (detectBlobVersion(blobBytes) !== 2) {
    throw new Error('Vault key blob is not v2 format');
  }

  const encryptedKey = deserializeVaultBlobV2(blobBytes);
  const rootFolderKey = await unwrapKey(encryptedKey, params.userPrivateKey);

  return { rootFolderKey, ipnsName: vaultKeyKeypair.ipnsName };
}
