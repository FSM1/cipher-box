/**
 * @cipherbox/core - Node Read/Write Body Encoder
 *
 * Encodes an in-memory Node to plaintext body bytes (no AEAD).
 * The returned bytes are the plaintext that sealNode (Plan 02) will seal.
 *
 * Wire format: JSON (TextEncoder) with a FIXED field order so the Plan-02
 * body-byte golden vector (D-04) is deterministic across encode calls.
 *
 * Analog: packages/core/src/folder/metadata.ts lines 23-31 + 105-124.
 */

import { CryptoError, bytesToBase64 } from '@cipherbox/crypto';
import type { Node, NodeContent, NodeWriteBody, SealedChildRef } from './types';

// ---------------------------------------------------------------------------
// Content serialization (Uint8Array → base64 string for JSON safety)
// ---------------------------------------------------------------------------

/**
 * Serializes a NodeContent for JSON wire encoding.
 *
 * A raw Uint8Array JSON-serializes to `{ "0": n, "1": n, … }` (an index map),
 * which is not JSON-safe for round-trip and breaks the frozen byte vector (D-04).
 * This function converts `fileKey` and each `VersionEntry.fileKey` to base64 strings
 * so that `JSON.stringify(serializeContentForWire(content))` is losslessly reversible.
 *
 * The returned object has the same shape as NodeContent except that all Uint8Array
 * fields are replaced with base64 strings. deserializeContentFromWire (decode.ts)
 * is the inverse.
 *
 * @param content - NodeContent with raw Uint8Array key fields
 * @returns JSON-safe representation
 */
export function serializeContentForWire(content: NodeContent): Record<string, unknown> {
  return {
    cid: content.cid,
    fileIv: content.fileIv,
    size: content.size,
    mimeType: content.mimeType,
    encryptionMode: content.encryptionMode,
    // Convert raw 32-byte AES key to base64 (reversible; not ECIES hex — D-07/NODE-02)
    fileKey: bytesToBase64(content.fileKey),
    versions: content.versions.map((v) => ({
      versionId: v.versionId,
      cid: v.cid,
      fileIv: v.fileIv,
      size: v.size,
      createdAt: v.createdAt,
      encryptionMode: v.encryptionMode,
      // Each version's raw 32-byte AES key also base64-encoded
      fileKey: bytesToBase64(v.fileKey),
    })),
  };
}

// ---------------------------------------------------------------------------
// SealedChildRef serialization (bigint versionFloor → string for JSON)
// ---------------------------------------------------------------------------

/**
 * Serializes a SealedChildRef for JSON wire encoding.
 *
 * `versionFloor` is a bigint; JSON.stringify throws on bigint values.
 * We serialize it as a decimal string and reverse in decode.ts.
 */
function serializeChildRefForWire(ref: SealedChildRef): Record<string, unknown> {
  return {
    name: ref.name,
    ipnsName: ref.ipnsName,
    generation: ref.generation,
    versionFloor: ref.versionFloor.toString(),
    readKeySealed: ref.readKeySealed,
  };
}

// ---------------------------------------------------------------------------
// Public encode functions
// ---------------------------------------------------------------------------

/**
 * Encodes the read-body of a Node to JSON bytes.
 *
 * Field order is FIXED (schema, kind, kind-specific fields, createdAt, modifiedAt)
 * so the encoded bytes are deterministic for the Plan-02 golden vector (D-04).
 *
 * Does NOT apply AEAD — the caller (sealNode, Plan 02) wraps these bytes.
 * Does NOT zero any buffer — caller is the terminal owner of key material (D-09).
 *
 * @param node - In-memory Node to encode
 * @returns UTF-8 JSON bytes of the read-body
 */
export function encodeReadBody(node: Node): Uint8Array {
  // Build read-body with a fixed field order for byte-level determinism (D-04).
  // Kind-specific fields come between 'kind' and 'createdAt'.
  let readBody: Record<string, unknown>;

  if (node.kind === 'file') {
    if (!node.content) {
      throw new CryptoError('File node missing content', 'INVALID_AAD_INPUT');
    }
    readBody = {
      schema: node.schema,
      kind: node.kind,
      id: node.id,
      generation: node.generation,
      content: serializeContentForWire(node.content),
      createdAt: node.createdAt,
      modifiedAt: node.modifiedAt,
    };
  } else {
    // folder or root
    readBody = {
      schema: node.schema,
      kind: node.kind,
      id: node.id,
      generation: node.generation,
      children: (node.children ?? []).map(serializeChildRefForWire),
      createdAt: node.createdAt,
      modifiedAt: node.modifiedAt,
    };
  }

  // D-03: JSON wire format — mirrors encryptFolderMetadata exactly
  return new TextEncoder().encode(JSON.stringify(readBody));
}

/**
 * Encodes the write-body of a Node to JSON bytes.
 *
 * The write-body contains the Ed25519 signing seed (`ipnsPrivateKey`) and the
 * write chain to child nodes (`writeChildren`). It is sealed under a SEPARATE
 * writeKey (Plan 02), never exposed in a read grant.
 *
 * Throws CryptoError if called on a node with no writeBody.
 *
 * @param node - In-memory Node whose writeBody to encode
 * @returns UTF-8 JSON bytes of the write-body
 */
export function encodeWriteBody(node: Node): Uint8Array {
  if (!node.writeBody) {
    throw new CryptoError('Node has no writeBody — cannot encode write-body', 'INVALID_AAD_INPUT');
  }

  const wb: NodeWriteBody = node.writeBody;
  // FIXED field order (ipnsPrivateKey, writeChildren, then recipientPins) so the
  // JSON bytes are byte-identical to the Rust serde field order (D-03b). The
  // recipientPins key is emitted ONLY when the list is present and non-empty —
  // mirroring the Rust `skip_serializing_if = "Vec::is_empty"` so the frozen
  // empty-pin KAT (seal_vectors[0]) is preserved byte-for-byte (Pitfall 1).
  const wireBody: {
    ipnsPrivateKey: string;
    writeChildren: { childId: string; writeKeySealed: string }[];
    recipientPins?: string[];
  } = {
    ipnsPrivateKey: bytesToBase64(wb.ipnsPrivateKey),
    writeChildren: wb.writeChildren.map((wc) => ({
      childId: wc.childId,
      writeKeySealed: wc.writeKeySealed,
    })),
  };

  if (wb.recipientPins && wb.recipientPins.length > 0) {
    wireBody.recipientPins = wb.recipientPins;
  }

  return new TextEncoder().encode(JSON.stringify(wireBody));
}
