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

import {
  deriveVaultKeyIpnsKeypair,
  deriveIpnsName,
  wrapKey,
  unwrapKey,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import { serializeVaultBlobV3, deserializeVaultBlobV3, sealNode } from '@cipherbox/core';
import type { Node } from '@cipherbox/core';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';
import { wrapIpnsKeyForTee } from '../tee/wrap';

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

/**
 * Publish a new user's empty root Node (D-03 / WEB-01/WEB-02).
 *
 * Builds a `kind:'root'` Node with an empty `children` array and a write-body
 * carrying the root IPNS signing key (`rootIpnsKeypair.privateKey`), seals it
 * under `rootReadKey`/`rootWriteKey`, uploads to IPFS, and publishes the FIRST
 * IPNS record at sequenceNumber 1n (Phase-60 strict gate: a first publish with
 * an embedded seq != 1 is rejected with 400).
 *
 * Templated on `createSubfolder` (packages/sdk-core/src/folder/registration.ts):
 * same TEE-enrollment fail-closed validation, computed BEFORE any IPFS upload
 * side effect so a malformed `teeKeys` never leaves an orphaned blob behind.
 *
 * Does NOT zero `rootIpnsKeypair.privateKey` / `rootReadKey` / `rootWriteKey` —
 * the caller is the terminal owner (D-09).
 *
 * @returns The root's IPNS name, the underlying Node's UUID, and sequenceNumber 1n
 */
export async function publishEmptyRootNode(params: {
  rootIpnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  rootReadKey: Uint8Array;
  rootWriteKey: Uint8Array;
  ctx: SdkContext;
  teeKeys?: TeeKeys;
}): Promise<{ ipnsName: string; nodeId: string; sequenceNumber: bigint }> {
  const ipnsName = await deriveIpnsName(params.rootIpnsKeypair.publicKey);
  const now = Date.now();

  // Compute TEE enrollment fields (if teeKeys supplied) BEFORE any IPFS upload —
  // fail closed on incomplete config so a malformed teeKeys short-circuits before
  // the seal/upload side effects (mirrors createSubfolder).
  let encryptedIpnsPrivateKey: string | undefined;
  let keyEpoch: number | undefined;
  if (params.teeKeys) {
    const { currentPublicKey, currentEpoch } = params.teeKeys;
    if (!currentPublicKey) {
      throw new Error(
        'publishEmptyRootNode: teeKeys.currentPublicKey is missing or empty — refusing to publish un-enrolled root'
      );
    }
    if (!Number.isInteger(currentEpoch) || currentEpoch < 1) {
      throw new Error(
        'publishEmptyRootNode: teeKeys.currentEpoch must be a positive integer (>= 1) — refusing to publish un-enrolled root'
      );
    }
    // ECIES-wrap the root IPNS private key under the TEE public key. Do NOT zero
    // rootIpnsKeypair.privateKey here — wrapIpnsKeyForTee borrows the buffer, it
    // does not consume it; the caller is the terminal owner (D-09).
    const teePublicKeyBytes = hexToBytes(currentPublicKey);
    const wrappedBytes = await wrapIpnsKeyForTee(
      params.rootIpnsKeypair.privateKey,
      teePublicKeyBytes
    );
    encryptedIpnsPrivateKey = bytesToHex(wrappedBytes);
    keyEpoch = currentEpoch;
  }

  const node: Node = {
    schema: 'node/v3',
    kind: 'root',
    id: crypto.randomUUID(),
    generation: 0,
    createdAt: now,
    modifiedAt: now,
    children: [],
    writeBody: {
      ipnsPrivateKey: params.rootIpnsKeypair.privateKey,
      writeChildren: [],
    },
  };

  const publishedNode = await sealNode(node, params.rootReadKey, params.rootWriteKey);

  const { cid } = await addToIpfs(
    params.ctx,
    new TextEncoder().encode(JSON.stringify(publishedNode))
  );

  // First publish — sequenceNumber MUST be 1n (Phase-60 strict gate).
  const result = await createAndPublishIpnsRecord({
    ipnsPrivateKey: params.rootIpnsKeypair.privateKey,
    ipnsPublicKey: params.rootIpnsKeypair.publicKey,
    ipnsName,
    metadataCid: cid,
    sequenceNumber: 1n,
    ctx: params.ctx,
    encryptedIpnsPrivateKey,
    keyEpoch,
  });

  if (!result.success) {
    throw new Error('publishEmptyRootNode: failed to publish empty root Node to IPNS');
  }

  return { ipnsName, nodeId: node.id, sequenceNumber: 1n };
}
