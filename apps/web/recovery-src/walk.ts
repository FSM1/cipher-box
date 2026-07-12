/**
 * Recovery-tool recursive v3 walk (SC1 / D-01 / D-03).
 *
 * Mirrors `packages/sdk/src/folder-listing.ts::resolveChildren` (the canonical
 * v3 read-chain traversal), swapping the SDK's API-gated resolve for the plain
 * HTTP `gateway.ts` transport (D-02: no `@cipherbox/sdk` facade, no
 * `@cipherbox/sdk-core` runtime, no CipherBox API relay). Every seal/unseal and
 * decrypt is a bare passthrough to the shipped `@cipherbox/core` /
 * `@cipherbox/crypto` primitives — nothing crypto/codec is hand-rolled here
 * (D-03), so the recovery chain is byte-for-byte parity with the production
 * read chain.
 *
 * §2.6 generation-source rule (RESEARCH Pitfall 2 — the #1 porting bug): the
 * generation passed to `unsealChildReadKey` MUST be the PARENT MIRROR
 * (`childRef.generation`), NEVER the freshly-fetched child's own
 * `published.generation`. The wrong source is a hard AEAD auth-tag failure, not
 * silent corruption — but it would still break the whole walk, so it is called
 * out inline.
 */

import { base64ToBytes, decryptAesCtr, decryptAesGcm } from '@cipherbox/crypto';
import { unsealChildReadKey, unsealNode, type Node, type PublishedNode } from '@cipherbox/core';

import { fetchFromIpfs, resolveIpnsVerified } from './gateway';

/** Gateway endpoints for the trust-nothing HTTP transport (D-04). */
export interface RecoveryGatewayConfig {
  /** IPFS gateway base URL for content fetch (also the /ipns/ HEAD fallback). */
  ipfsGateway: string;
  /** Delegated-routing gateway base URL for verified IPNS resolution. */
  ipnsGateway: string;
}

/** One recovered plaintext file, keyed by its full tree path. */
export interface RecoveredFile {
  path: string;
  bytes: Uint8Array;
}

/** Severity levels for the progress stream (map onto the recovery-progress-log). */
export type RecoveryProgressLevel = 'info' | 'success' | 'error' | 'warn';

/** Human-readable step reporter, streamed to `recovery-progress-log`. */
export type RecoveryProgressFn = (message: string, level?: RecoveryProgressLevel) => void;

const decoder = new TextDecoder();

/** Truncate long ids/CIDs for readable progress lines. */
function truncate(value: string, len = 30): string {
  return value.length <= len ? value : `${value.slice(0, len)}...`;
}

/**
 * Resolve an IPNS name to its `PublishedNode` envelope over the configured
 * gateway: verified IPNS resolve → CID → IPFS fetch → JSON parse.
 */
export async function fetchPublishedNode(
  ipnsName: string,
  gatewayConfig: RecoveryGatewayConfig
): Promise<PublishedNode> {
  const cid = await resolveIpnsVerified(
    ipnsName,
    gatewayConfig.ipnsGateway,
    gatewayConfig.ipfsGateway
  );
  const envelopeBytes = await fetchFromIpfs(cid, gatewayConfig.ipfsGateway);
  return JSON.parse(decoder.decode(envelopeBytes)) as PublishedNode;
}

/**
 * Decrypt a file node's content bytes.
 *
 * The raw 32-byte `content.fileKey` is already unsealed inline in the node's
 * read-body (NODE-02) — there is NO ECIES unwrap here. `content.fileIv` is
 * base64-encoded under node/v3 (SC2 encoding lock). Mode selects GCM (default)
 * vs CTR (large-file range reads); both are AEAD/keystream passthroughs to
 * `@cipherbox/crypto` (D-03). GCM auth-tag verification fails closed on any
 * tampered IPFS content (T-78-04).
 */
async function decryptFileContent(
  node: Node,
  gatewayConfig: RecoveryGatewayConfig
): Promise<Uint8Array> {
  const content = node.content;
  if (!content) {
    throw new Error(`File node ${node.id} has no content descriptor`);
  }
  const ciphertext = await fetchFromIpfs(content.cid, gatewayConfig.ipfsGateway);
  const iv = base64ToBytes(content.fileIv);
  return content.encryptionMode === 'CTR'
    ? decryptAesCtr(ciphertext, content.fileKey, iv)
    : decryptAesGcm(ciphertext, content.fileKey, iv);
}

/**
 * Recursively walk a folder node, collecting every recovered descendant file.
 *
 * Best-effort recovery: any per-child failure (an unresolvable IPNS record, a
 * tampered/unopenable envelope, a decrypt error) is reported via `onProgress`
 * and skipped so one bad sibling never aborts the whole vault recovery — the
 * same graceful-degradation contract as `resolveChildren`. The per-child
 * `childReadKey` this function mints is zeroed once consumed (terminal owner,
 * D-09); `parentReadKey` is caller-owned and never zeroed here.
 */
async function walkFolder(
  node: Node,
  parentReadKey: Uint8Array,
  pathPrefix: string,
  gatewayConfig: RecoveryGatewayConfig,
  onProgress: RecoveryProgressFn,
  out: RecoveredFile[]
): Promise<void> {
  for (const childRef of node.children ?? []) {
    const childPath = pathPrefix ? `${pathPrefix}/${childRef.name}` : childRef.name;
    let childReadKey: Uint8Array | null = null;
    try {
      onProgress(`Resolving ${childPath} (${truncate(childRef.ipnsName)})...`, 'info');
      const published = await fetchPublishedNode(childRef.ipnsName, gatewayConfig);

      childReadKey = await unsealChildReadKey(
        childRef.readKeySealed,
        parentReadKey,
        published.id,
        published.kind,
        childRef.generation // parent mirror — NEVER published.generation (§2.6 rule)
      );
      const childNode = await unsealNode(published, childReadKey);

      if (childNode.kind === 'file') {
        const bytes = await decryptFileContent(childNode, gatewayConfig);
        out.push({ path: childPath, bytes });
        onProgress(`Recovered file ${childPath} (${bytes.length} bytes)`, 'success');
      } else {
        onProgress(`Entering folder ${childPath}/...`, 'info');
        await walkFolder(childNode, childReadKey, childPath, gatewayConfig, onProgress, out);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      onProgress(`Skipped ${childPath}: ${message}`, 'error');
    } finally {
      childReadKey?.fill(0);
    }
  }
}

/**
 * Recover a full v3 vault tree from its already-unsealed root node.
 *
 * @param rootNode - The decrypted root `Node` (unsealed by the caller).
 * @param rootReadKey - The root read key (caller-owned; never zeroed here, D-09).
 * @param gatewayConfig - IPFS/IPNS gateway endpoints (D-04).
 * @param onProgress - Step reporter streamed to the recovery UI progress log.
 * @returns Every recovered plaintext file keyed by its tree path.
 */
export async function recoverTree(
  rootNode: Node,
  rootReadKey: Uint8Array,
  gatewayConfig: RecoveryGatewayConfig,
  onProgress: RecoveryProgressFn
): Promise<RecoveredFile[]> {
  const out: RecoveredFile[] = [];
  await walkFolder(rootNode, rootReadKey, '', gatewayConfig, onProgress, out);
  return out;
}
