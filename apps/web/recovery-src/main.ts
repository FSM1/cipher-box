/**
 * Recovery-tool entry point (SC1, spike-complete).
 *
 * Trust-nothing, infra-independent vault recovery (D-01/D-02): given ONLY the
 * user's `privateKey`, this walks the IPNS → IPFS link tree over a configurable
 * HTTP gateway and decrypts the whole folder/file tree with ZERO dependency on
 * the CipherBox API relay, Web3Auth, or the `@cipherbox/sdk` / `@cipherbox/sdk-core`
 * read chain. The only allowed workspace imports are the low-level primitives
 * from `@cipherbox/crypto` and `@cipherbox/core` (D-03) — no crypto/codec is
 * hand-rolled here.
 *
 * This module is intentionally spike-complete rather than DOM-complete: it
 * imports and exercises the FULL primitive set the finished tool will use so
 * the esbuild bundle Task 3 measures is representative of real weight (Open
 * Question 1). Full DOM/UI wiring lands in plan 78-02; the exported
 * `bootstrap()` here is the recovery walk those handlers will drive.
 */

import {
  base64ToBytes,
  decryptAesCtr,
  decryptAesGcm,
  deriveVaultIpnsKeypair,
  deriveVaultKeyIpnsKeypair,
  hexToBytes,
  unwrapKey,
} from '@cipherbox/crypto';
import {
  deserializeVaultBlobV3,
  unsealChildReadKey,
  unsealNode,
  type Node,
  type PublishedNode,
  type SealedChildRef,
} from '@cipherbox/core';
import { zipSync } from 'fflate';

import { fetchFromIpfs, resolveIpnsVerified } from './gateway';

/** User-supplied recovery inputs (the pasted key + the gateway endpoints, D-04). */
export interface RecoveryParams {
  /** The user's secp256k1 private key as a hex string — the sole credential (D-01). */
  privateKeyHex: string;
  /** Delegated-routing gateway base URL for IPNS resolution. */
  ipnsGatewayUrl: string;
  /** IPFS gateway base URL for content fetch. */
  ipfsGatewayUrl: string;
}

/** Recovered file bytes keyed by their tree path. */
export type RecoveredFiles = Record<string, Uint8Array>;

const decoder = new TextDecoder();

/** Resolve an IPNS name to its PublishedNode envelope over the configured gateway. */
async function fetchPublishedNode(
  ipnsName: string,
  params: RecoveryParams
): Promise<PublishedNode> {
  const cid = await resolveIpnsVerified(ipnsName, params.ipnsGatewayUrl, params.ipfsGatewayUrl);
  const envelopeBytes = await fetchFromIpfs(cid, params.ipfsGatewayUrl);
  return JSON.parse(decoder.decode(envelopeBytes)) as PublishedNode;
}

/** Decrypt a file node's content bytes, dispatching on its encryption mode. */
async function decryptFileContent(node: Node, params: RecoveryParams): Promise<Uint8Array> {
  const content = node.content;
  if (!content) {
    throw new Error(`File node ${node.id} has no content descriptor`);
  }
  const ciphertext = await fetchFromIpfs(content.cid, params.ipfsGatewayUrl);
  const iv = base64ToBytes(content.fileIv);
  // fileKey is a raw 32-byte AES key already unsealed inside the read-body — no ECIES here.
  return content.encryptionMode === 'CTR'
    ? decryptAesCtr(ciphertext, content.fileKey, iv)
    : decryptAesGcm(ciphertext, content.fileKey, iv);
}

/**
 * Recursively walk a folder node, decrypting every descendant file.
 *
 * Mirrors `packages/sdk/src/folder-listing.ts::resolveChildren`, swapping the
 * SDK's API-backed resolve for the gateway transport. The generation passed to
 * `unsealChildReadKey` MUST be the parent mirror (`childRef.generation`), never
 * the freshly-fetched child's own `published.generation` (§2.6 rule) — the wrong
 * source produces an AEAD auth-tag failure, not silent corruption.
 */
async function recoverFolder(
  node: Node,
  readKey: Uint8Array,
  pathPrefix: string,
  params: RecoveryParams,
  out: RecoveredFiles
): Promise<void> {
  for (const childRef of node.children ?? ([] as SealedChildRef[])) {
    const published = await fetchPublishedNode(childRef.ipnsName, params);

    const childReadKey = await unsealChildReadKey(
      childRef.readKeySealed,
      readKey,
      published.id,
      published.kind,
      childRef.generation // parent mirror — NEVER published.generation (§2.6)
    );
    const childNode = await unsealNode(published, childReadKey);
    const childPath = pathPrefix ? `${pathPrefix}/${childRef.name}` : childRef.name;

    if (childNode.kind === 'file') {
      out[childPath] = await decryptFileContent(childNode, params);
    } else {
      await recoverFolder(childNode, childReadKey, childPath, params, out);
    }
  }
}

/**
 * Recover the entire vault tree and return a ZIP of every decrypted file.
 *
 * Full read-only walk: derive the vault-key and root IPNS names from the
 * private key, unwrap the root read key from the v3 key blob, unseal the root
 * node, recurse the tree, and pack the result with fflate.
 */
export async function bootstrap(params: RecoveryParams): Promise<Uint8Array> {
  const privateKey = hexToBytes(params.privateKeyHex);

  // 1. Derive the two vault IPNS names (unchanged from v2 — real crypto, not hand-rolled).
  const rootKeypair = await deriveVaultIpnsKeypair(privateKey);
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(privateKey);

  // 2. Fetch + deserialize the v3 vault key blob, then ECIES-unwrap the root read key.
  const blobCid = await resolveIpnsVerified(
    vaultKeyKeypair.ipnsName,
    params.ipnsGatewayUrl,
    params.ipfsGatewayUrl
  );
  const blobBytes = await fetchFromIpfs(blobCid, params.ipfsGatewayUrl);
  const { encryptedRootReadKey } = deserializeVaultBlobV3(blobBytes);
  const rootReadKey = await unwrapKey(encryptedRootReadKey, privateKey);

  // 3. Unseal the root node and recurse (read-only — no writeKey argument).
  const rootPublished = await fetchPublishedNode(rootKeypair.ipnsName, params);
  const rootNode = await unsealNode(rootPublished, rootReadKey);

  const files: RecoveredFiles = {};
  await recoverFolder(rootNode, rootReadKey, '', params, files);

  // 4. Pack every recovered file into a single ZIP for download.
  return zipSync(files);
}
