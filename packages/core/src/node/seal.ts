/**
 * @cipherbox/core - Node AAD-Bound Seal/Unseal
 *
 * Composes the Phase-61 AES-256-GCM AAD primitive (`sealAesGcmAad`,
 * `unsealAesGcmAad`, `buildNodeAad`) to produce and verify the `PublishedNode`
 * envelope defined in ADR 0003 / design §2.3-§2.9.
 *
 * Role byte table (frozen, D-00 / ADR 0003):
 *   0x01 body          — read-body and write-body sealed under their respective keys
 *   0x02 child-readkey — child readKey sealed under parent readKey (read chain)
 *   0x03 content       — NodeContent sealed under the file node's own readKey
 *   0x04 child-writekey — child writeKey sealed under parent writeKey (write chain)
 *
 * Kind byte table:
 *   0x01 folder / 0x02 file / 0x03 root
 *
 * Security invariants:
 *   - Never reimplement AES/AAD — always compose the Phase-61 primitive (D-00a).
 *   - Never zero a caller-supplied or returned key buffer (D-09: caller is terminal owner).
 *   - Never log key material (T-62-03).
 *   - sealAesGcmAad mints a fresh random IV per call (D-00a); the FULL-SEAL LOCK
 *     test uses encryptAesGcmAad(fixedIv) to reproduce deterministic bytes separately.
 *
 * Analog: packages/crypto/src/aes/seal.ts + packages/core/src/folder/metadata.ts
 */

import {
  sealAesGcmAad,
  unsealAesGcmAad,
  buildNodeAad,
  CryptoError,
  bytesToBase64,
  base64ToBytes,
} from '@cipherbox/crypto';
import { encodeReadBody, encodeWriteBody, serializeContentForWire } from './encode';
import { decodeReadBody, decodeWriteBody, deserializeContentFromWire } from './decode';
import type { Node, NodeContent, NodeKind, PublishedNode } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Returns the kind byte for a NodeKind value.
 * Throws CryptoError on unknown kind (fail-closed, D-03).
 */
function kindByte(kind: NodeKind): number {
  if (kind === 'folder') return 0x01;
  if (kind === 'file') return 0x02;
  if (kind === 'root') return 0x03;
  // Exhaustive — TypeScript already guards this, but fail-closed at runtime too.
  throw new CryptoError('Invalid node kind', 'INVALID_AAD_INPUT');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Seals a Node into a PublishedNode envelope.
 *
 * Produces two independently sealed bodies:
 *   - readSealed:  encodeReadBody(node)  sealed under `readKey`  with role 0x01
 *   - writeSealed: encodeWriteBody(node) sealed under `writeKey` with role 0x01
 *     (omitted when node.writeBody is absent)
 *
 * Both bodies share the same role byte (0x01 = body). The distinguishing factor
 * is the key: readKey vs writeKey. This matches design §2.5 and ADR 0003.
 *
 * Does NOT zero readKey or writeKey — caller is the terminal owner (D-09).
 * Never logs key material (T-62-03).
 *
 * @param node     - In-memory Node to seal
 * @param readKey  - 32-byte AES key for the read-body seal
 * @param writeKey - 32-byte AES key for the write-body seal (only used when node.writeBody is set)
 * @returns Published envelope with base64 sealed bodies
 */
export async function sealNode(
  node: Node,
  readKey: Uint8Array,
  writeKey: Uint8Array
): Promise<PublishedNode> {
  const kb = kindByte(node.kind);

  // Seal read-body (role 0x01)
  const readBodyBytes = encodeReadBody(node);
  const readAad = buildNodeAad(node.id, kb, node.generation, 0x01);
  const readSealedBytes = await sealAesGcmAad(readBodyBytes, readKey, readAad);

  const published: PublishedNode = {
    schema: 'node/v3',
    kind: node.kind,
    id: node.id,
    generation: node.generation,
    aeadVersion: 1,
    readSealed: bytesToBase64(readSealedBytes),
  };

  // Seal write-body if present (role 0x01 — same role byte, different key: D-00 ADR 0003 §2.5)
  if (node.writeBody) {
    const writeBodyBytes = encodeWriteBody(node);
    const writeAad = buildNodeAad(node.id, kb, node.generation, 0x01);
    const writeSealedBytes = await sealAesGcmAad(writeBodyBytes, writeKey, writeAad);
    published.writeSealed = bytesToBase64(writeSealedBytes);
  }

  return published;
}

/**
 * Unseals a PublishedNode back to an in-memory Node.
 *
 * Rebuilds the AADs identically to sealNode. Any mismatch (wrong generation,
 * wrong id, tampered body) causes the GCM auth tag to fail and throws CryptoError.
 *
 * @param published - Published envelope from sealNode or IPFS/IPNS
 * @param readKey   - 32-byte AES key matching the sealing readKey
 * @param writeKey  - 32-byte AES key for the write-body (optional; omit for read-only access)
 * @returns Plaintext in-memory Node; writeBody present only if writeSealed was unsealed
 */
export async function unsealNode(
  published: PublishedNode,
  readKey: Uint8Array,
  writeKey?: Uint8Array
): Promise<Node> {
  // Fail closed on an envelope we cannot interpret. `schema` and `aeadVersion`
  // are plaintext and NOT covered by the AAD, so a node/v3 reader must reject
  // anything else rather than blindly unseal it under v1 assumptions (forward-compat).
  if (published.schema !== 'node/v3' || published.aeadVersion !== 1) {
    throw new CryptoError('Unsupported PublishedNode envelope', 'INVALID_AAD_INPUT');
  }

  const kb = kindByte(published.kind);

  // Unseal read-body (role 0x01)
  const readSealedBytes = base64ToBytes(published.readSealed);
  const readAad = buildNodeAad(published.id, kb, published.generation, 0x01);
  const readBodyBytes = await unsealAesGcmAad(readSealedBytes, readKey, readAad);
  const node = decodeReadBody(readBodyBytes);

  // Unseal write-body if envelope has it and caller supplied writeKey
  if (published.writeSealed && writeKey) {
    const writeSealedBytes = base64ToBytes(published.writeSealed);
    const writeAad = buildNodeAad(published.id, kb, published.generation, 0x01);
    const writeBodyBytes = await unsealAesGcmAad(writeSealedBytes, writeKey, writeAad);
    const writeBody = decodeWriteBody(writeBodyBytes);
    return { ...node, writeBody };
  }

  return node;
}

/**
 * Seals a child node's readKey under the parent node's readKey.
 *
 * Used to build the SealedChildRef.readKeySealed field (role 0x02 child-readkey).
 * The AAD binds the child's id, kind, and generation so the sealed key can only
 * be unwrapped by a holder of the parent readKey presenting the correct child metadata.
 *
 * Does NOT zero childReadKey — the caller is the terminal owner (D-09).
 *
 * @param childReadKey     - 32-byte AES key of the child node to seal
 * @param parentReadKey    - 32-byte AES key of the parent node (wrapping key)
 * @param childId          - Hyphenated UUID of the child node
 * @param childKind        - NodeKind of the child
 * @param childGeneration  - Current generation of the child node
 * @returns Base64 of IV ‖ ciphertext ‖ tag (SealedChildRef.readKeySealed value)
 */
export async function sealChildReadKey(
  childReadKey: Uint8Array,
  parentReadKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<string> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x02 /* child-readkey */);
  const sealed = await sealAesGcmAad(childReadKey, parentReadKey, aad);
  // Do NOT zero childReadKey: caller is terminal owner (D-09)
  return bytesToBase64(sealed);
}

/**
 * Unseals a child node's readKey from SealedChildRef.readKeySealed.
 *
 * Inverse of sealChildReadKey. The AAD is rebuilt identically; any mismatch throws.
 *
 * @param sealedBase64    - Base64 sealed blob from SealedChildRef.readKeySealed
 * @param parentReadKey   - 32-byte AES key of the parent node (unwrapping key)
 * @param childId         - Hyphenated UUID of the child node (must match sealing metadata)
 * @param childKind       - NodeKind of the child (must match sealing metadata)
 * @param childGeneration - Current generation of the child (must match sealing metadata)
 * @returns Raw 32-byte AES readKey of the child node
 */
export async function unsealChildReadKey(
  sealedBase64: string,
  parentReadKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<Uint8Array> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x02 /* child-readkey */);
  const sealedBytes = base64ToBytes(sealedBase64);
  return unsealAesGcmAad(sealedBytes, parentReadKey, aad);
}

/**
 * Seals a child node's writeKey under the parent node's writeKey.
 *
 * Used to build the WriteChildRef.writeKeySealed field (role 0x04 child-writekey).
 * The AAD binds the child's id, kind, and generation so the sealed key can only
 * be unwrapped by a holder of the parent writeKey presenting the correct child metadata.
 *
 * Does NOT zero childWriteKey — the caller is the terminal owner (D-09).
 *
 * @param childWriteKey    - 32-byte AES key of the child node to seal
 * @param parentWriteKey   - 32-byte AES key of the parent node (wrapping key)
 * @param childId          - Hyphenated UUID of the child node
 * @param childKind        - NodeKind of the child
 * @param childGeneration  - Current generation of the child node
 * @returns Base64 of IV ‖ ciphertext ‖ tag (WriteChildRef.writeKeySealed value)
 */
export async function sealChildWriteKey(
  childWriteKey: Uint8Array,
  parentWriteKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<string> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x04 /* child-writekey */);
  const sealed = await sealAesGcmAad(childWriteKey, parentWriteKey, aad);
  // Do NOT zero childWriteKey: caller is terminal owner (D-09)
  return bytesToBase64(sealed);
}

/**
 * Unseals a child node's writeKey from WriteChildRef.writeKeySealed.
 *
 * Inverse of sealChildWriteKey. The AAD is rebuilt identically; any mismatch throws.
 *
 * @param sealedBase64     - Base64 sealed blob from WriteChildRef.writeKeySealed
 * @param parentWriteKey   - 32-byte AES key of the parent node (unwrapping key)
 * @param childId          - Hyphenated UUID of the child node (must match sealing metadata)
 * @param childKind        - NodeKind of the child (must match sealing metadata)
 * @param childGeneration  - Current generation of the child (must match sealing metadata)
 * @returns Raw 32-byte AES writeKey of the child node
 */
export async function unsealChildWriteKey(
  sealedBase64: string,
  parentWriteKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<Uint8Array> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x04 /* child-writekey */);
  const sealedBytes = base64ToBytes(sealedBase64);
  return unsealAesGcmAad(sealedBytes, parentWriteKey, aad);
}

/**
 * Seals a file node's content descriptor under the file node's own readKey.
 *
 * The content (including the raw 32-byte fileKey) is sealed under the file node's
 * own readKey with role 0x03 (content). This matches NODE-02 and design §2.9.
 *
 * Does NOT zero the keys inside `content` — caller is the terminal owner (D-09).
 *
 * @param content          - NodeContent to seal (includes raw fileKey Uint8Array)
 * @param fileNodeReadKey  - 32-byte AES key of the file node (sealing key)
 * @param nodeId           - Hyphenated UUID of the file node
 * @param generation       - Current generation of the file node
 * @returns Base64 sealed blob
 */
export async function sealContent(
  content: NodeContent,
  fileNodeReadKey: Uint8Array,
  nodeId: string,
  generation: number
): Promise<string> {
  // Serialize content for wire (Uint8Array fileKey → base64; bigint versionFloor → string)
  const wire = serializeContentForWire(content);
  const contentBytes = new TextEncoder().encode(JSON.stringify(wire));
  const aad = buildNodeAad(nodeId, 0x02 /* file */, generation, 0x03 /* content */);
  const sealed = await sealAesGcmAad(contentBytes, fileNodeReadKey, aad);
  return bytesToBase64(sealed);
}

/**
 * Unseals a file node's content descriptor.
 *
 * Inverse of sealContent. The AAD is rebuilt identically; any mismatch throws.
 *
 * @param sealedBase64    - Base64 sealed blob from sealContent
 * @param fileNodeReadKey - 32-byte AES key of the file node (matches sealing key)
 * @param nodeId          - Hyphenated UUID of the file node
 * @param generation      - Current generation of the file node
 * @returns NodeContent with all Uint8Array fields restored
 */
export async function unsealContent(
  sealedBase64: string,
  fileNodeReadKey: Uint8Array,
  nodeId: string,
  generation: number
): Promise<NodeContent> {
  const aad = buildNodeAad(nodeId, 0x02 /* file */, generation, 0x03 /* content */);
  const sealedBytes = base64ToBytes(sealedBase64);
  const contentBytes = await unsealAesGcmAad(sealedBytes, fileNodeReadKey, aad);
  const raw = JSON.parse(new TextDecoder().decode(contentBytes)) as Record<string, unknown>;
  return deserializeContentFromWire(raw);
}
