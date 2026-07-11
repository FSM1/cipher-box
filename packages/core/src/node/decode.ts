/**
 * @cipherbox/core - Node Read/Write Body Decoder
 *
 * Decodes plaintext body bytes back to an in-memory Node.
 * Mirrors validateFolderMetadata's fail-closed CryptoError pattern.
 *
 * Generation range guard is copied verbatim from packages/crypto/src/aes/seal.ts
 * buildNodeAad (lines 93-95) so that decode and AAD-binding use identical predicates
 * (D-08, NODE-04).
 *
 * Does NOT apply AEAD — sealNode/unsealNode (Plan 02) handles that layer.
 * Does NOT zero any caller-supplied buffer — caller is terminal owner (D-09).
 * Does NOT log key material (T-62-03).
 *
 * Analog: packages/core/src/folder/metadata.ts lines 38-96 + 135-150.
 */

import { CryptoError, base64ToBytes } from '@cipherbox/crypto';
import type { Node, NodeContent, NodeWriteBody, SealedChildRef, VersionEntry } from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Decodes a base64 string to a Uint8Array.
 * Asserts decoded length if `expectedLength` is provided.
 *
 * Thin wrapper over the shared @cipherbox/crypto base64ToBytes helper —
 * preserves the decode-specific expectedLength length-check (superset signature).
 */
function base64ToUint8Array(b64: string, expectedLength?: number): Uint8Array {
  const bytes = base64ToBytes(b64);
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new CryptoError(
      `Invalid node format: expected ${expectedLength}-byte key, got ${bytes.length}`,
      'DECRYPTION_FAILED'
    );
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Content deserialization (base64 string → Uint8Array)
// ---------------------------------------------------------------------------

/**
 * Reverse of serializeContentForWire (encode.ts).
 *
 * Converts base64 fileKey fields back to raw 32-byte Uint8Array.
 * Asserts exactly 32 bytes on each key (NODE-02).
 *
 * @param raw - JSON-parsed content object (unknown field types)
 * @returns NodeContent with all fileKey fields as Uint8Array
 * @throws CryptoError on invalid structure or bad key length
 */
export function deserializeContentFromWire(raw: Record<string, unknown>): NodeContent {
  if (typeof raw.cid !== 'string') {
    throw new CryptoError('Invalid node format: content.cid must be a string', 'DECRYPTION_FAILED');
  }
  if (typeof raw.fileIv !== 'string') {
    throw new CryptoError(
      'Invalid node format: content.fileIv must be a string',
      'DECRYPTION_FAILED'
    );
  }
  if (typeof raw.size !== 'number') {
    throw new CryptoError(
      'Invalid node format: content.size must be a number',
      'DECRYPTION_FAILED'
    );
  }
  if (typeof raw.mimeType !== 'string') {
    throw new CryptoError(
      'Invalid node format: content.mimeType must be a string',
      'DECRYPTION_FAILED'
    );
  }
  if (raw.encryptionMode !== 'GCM' && raw.encryptionMode !== 'CTR') {
    throw new CryptoError(
      'Invalid node format: content.encryptionMode must be GCM or CTR',
      'DECRYPTION_FAILED'
    );
  }
  if (typeof raw.fileKey !== 'string') {
    throw new CryptoError(
      'Invalid node format: content.fileKey must be a base64 string on wire',
      'DECRYPTION_FAILED'
    );
  }
  if (!Array.isArray(raw.versions)) {
    throw new CryptoError(
      'Invalid node format: content.versions must be an array',
      'DECRYPTION_FAILED'
    );
  }

  // Decode the 32-byte AES key from base64 (NODE-02; assert 32 bytes)
  const fileKey = base64ToUint8Array(raw.fileKey as string, 32);

  const versions: VersionEntry[] = (raw.versions as unknown[]).map((v, idx) => {
    if (typeof v !== 'object' || v === null) {
      throw new CryptoError(
        `Invalid node format: versions[${idx}] is not an object`,
        'DECRYPTION_FAILED'
      );
    }
    const ve = v as Record<string, unknown>;
    if (ve.encryptionMode !== 'GCM' && ve.encryptionMode !== 'CTR') {
      throw new CryptoError(
        `Invalid node format: versions[${idx}].encryptionMode must be GCM or CTR`,
        'DECRYPTION_FAILED'
      );
    }
    if (typeof ve.fileKey !== 'string') {
      throw new CryptoError(
        `Invalid node format: versions[${idx}].fileKey must be a base64 string on wire`,
        'DECRYPTION_FAILED'
      );
    }
    return {
      versionId: String(ve.versionId ?? ''),
      cid: String(ve.cid ?? ''),
      fileIv: String(ve.fileIv ?? ''),
      size: Number(ve.size ?? 0),
      createdAt: Number(ve.createdAt ?? 0),
      encryptionMode: ve.encryptionMode,
      fileKey: base64ToUint8Array(ve.fileKey as string, 32),
    } satisfies VersionEntry;
  });

  return {
    cid: raw.cid,
    fileIv: raw.fileIv,
    size: raw.size,
    mimeType: raw.mimeType,
    encryptionMode: raw.encryptionMode,
    fileKey,
    versions,
  };
}

// ---------------------------------------------------------------------------
// SealedChildRef deserialization (string versionFloor → bigint)
// ---------------------------------------------------------------------------

/**
 * Deserializes a SealedChildRef from its wire representation.
 * `versionFloor` is stored as a decimal string on the wire (bigint is not JSON-safe).
 */
function deserializeChildRefFromWire(raw: Record<string, unknown>, idx: number): SealedChildRef {
  if (typeof raw.name !== 'string') {
    throw new CryptoError(
      `Invalid node format: children[${idx}].name must be a string`,
      'DECRYPTION_FAILED'
    );
  }
  if (typeof raw.ipnsName !== 'string') {
    throw new CryptoError(
      `Invalid node format: children[${idx}].ipnsName must be a string`,
      'DECRYPTION_FAILED'
    );
  }
  if (typeof raw.generation !== 'number') {
    throw new CryptoError(
      `Invalid node format: children[${idx}].generation must be a number`,
      'DECRYPTION_FAILED'
    );
  }
  if (typeof raw.readKeySealed !== 'string') {
    throw new CryptoError(
      `Invalid node format: children[${idx}].readKeySealed must be a string`,
      'DECRYPTION_FAILED'
    );
  }
  // versionFloor is serialized as a decimal string to survive JSON round-trip
  if (typeof raw.versionFloor !== 'string' && typeof raw.versionFloor !== 'bigint') {
    throw new CryptoError(
      `Invalid node format: children[${idx}].versionFloor must be a string or bigint`,
      'DECRYPTION_FAILED'
    );
  }

  return {
    name: raw.name,
    ipnsName: raw.ipnsName,
    generation: raw.generation,
    versionFloor: BigInt(String(raw.versionFloor)),
    readKeySealed: raw.readKeySealed,
  };
}

// ---------------------------------------------------------------------------
// Public validation + decode functions
// ---------------------------------------------------------------------------

/**
 * Validates raw parsed JSON as a Node and reconstructs runtime types.
 *
 * Mirrors validateFolderMetadata's fail-closed structure:
 *   - throws CryptoError('...', 'DECRYPTION_FAILED') on any structural failure
 *
 * Generation range guard is copied verbatim from buildNodeAad (seal.ts lines 93-95)
 * so that the two predicates stay in sync (D-08, NODE-04):
 *   `Number.isInteger(generation) && generation >= 0 && generation <= 0xffffffff`
 *
 * @param data - JSON.parse result from wire bytes
 * @returns Validated Node with all Uint8Array and bigint fields reconstructed
 * @throws CryptoError('...', 'DECRYPTION_FAILED') on validation failure
 */
export function validateNode(data: unknown): Node {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid node format: not an object', 'DECRYPTION_FAILED');
  }

  const obj = data as Record<string, unknown>;

  if (obj.schema !== 'node/v3') {
    throw new CryptoError('Invalid node format: unsupported schema', 'DECRYPTION_FAILED');
  }

  if (obj.kind !== 'folder' && obj.kind !== 'file' && obj.kind !== 'root') {
    throw new CryptoError('Invalid node format: unknown kind', 'DECRYPTION_FAILED');
  }

  if (typeof obj.id !== 'string') {
    throw new CryptoError('Invalid node format: missing id', 'DECRYPTION_FAILED');
  }

  // D-08 / NODE-04: generation range guard — COPIED VERBATIM from buildNodeAad (seal.ts:93-95)
  // to ensure the two predicates are byte-for-byte identical.
  if (
    typeof obj.generation !== 'number' ||
    !Number.isInteger(obj.generation) ||
    obj.generation < 0 ||
    obj.generation > 0xffffffff
  ) {
    throw new CryptoError('Invalid generation for AAD', 'DECRYPTION_FAILED');
  }

  const kind = obj.kind as 'folder' | 'file' | 'root';
  const generation = obj.generation as number;

  // Kind-specific field validation and runtime-type reconstruction
  if (kind === 'file') {
    if (typeof obj.content !== 'object' || obj.content === null) {
      throw new CryptoError(
        'Invalid node format: file node must have content',
        'DECRYPTION_FAILED'
      );
    }
    const content = deserializeContentFromWire(obj.content as Record<string, unknown>);
    return {
      schema: 'node/v3',
      kind,
      id: obj.id as string,
      generation,
      createdAt: Number(obj.createdAt ?? 0),
      modifiedAt: Number(obj.modifiedAt ?? 0),
      content,
    };
  } else {
    // folder or root
    if (!Array.isArray(obj.children)) {
      throw new CryptoError(
        'Invalid node format: folder/root node must have children array',
        'DECRYPTION_FAILED'
      );
    }
    const children: SealedChildRef[] = (obj.children as unknown[]).map((c, idx) => {
      if (typeof c !== 'object' || c === null) {
        throw new CryptoError(
          `Invalid node format: children[${idx}] is not an object`,
          'DECRYPTION_FAILED'
        );
      }
      return deserializeChildRefFromWire(c as Record<string, unknown>, idx);
    });
    return {
      schema: 'node/v3',
      kind,
      id: obj.id as string,
      generation,
      createdAt: Number(obj.createdAt ?? 0),
      modifiedAt: Number(obj.modifiedAt ?? 0),
      children,
    };
  }
}

/**
 * Decodes a Node's read-body from its plaintext wire bytes.
 *
 * Mirrors decryptFolderMetadata lines 148-149:
 *   JSON.parse(new TextDecoder().decode(bytes)) → validateNode(parsed)
 *
 * @param bytes - UTF-8 JSON bytes (output of encodeReadBody)
 * @returns Decoded Node with all Uint8Array and bigint fields reconstructed
 * @throws CryptoError on any structural or range validation failure
 */
export function decodeReadBody(bytes: Uint8Array): Node {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
  return validateNode(parsed);
}

/**
 * Decodes a Node's write-body from its plaintext wire bytes.
 *
 * The write-body carries the Ed25519 signing seed and write chain to children.
 * The ipnsPrivateKey is stored as base64 on the wire; this function restores
 * it to a raw Uint8Array.
 *
 * @param bytes - UTF-8 JSON bytes (output of encodeWriteBody)
 * @returns Decoded NodeWriteBody with ipnsPrivateKey as Uint8Array
 * @throws CryptoError on invalid structure
 */
export function decodeWriteBody(bytes: Uint8Array): NodeWriteBody {
  const raw = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;

  if (typeof raw.ipnsPrivateKey !== 'string') {
    throw new CryptoError(
      'Invalid write-body format: ipnsPrivateKey must be a base64 string',
      'DECRYPTION_FAILED'
    );
  }
  if (!Array.isArray(raw.writeChildren)) {
    throw new CryptoError(
      'Invalid write-body format: writeChildren must be an array',
      'DECRYPTION_FAILED'
    );
  }

  // ipnsPrivateKey is a raw Ed25519 seed (32 bytes for most implementations, but we
  // do NOT assert a fixed length here since the wire might carry an extended seed)
  const ipnsPrivateKey = base64ToUint8Array(raw.ipnsPrivateKey as string);

  const writeChildren = (raw.writeChildren as unknown[]).map((wc, idx) => {
    if (typeof wc !== 'object' || wc === null) {
      throw new CryptoError(
        `Invalid write-body format: writeChildren[${idx}] is not an object`,
        'DECRYPTION_FAILED'
      );
    }
    const wcObj = wc as Record<string, unknown>;
    if (typeof wcObj.childId !== 'string') {
      throw new CryptoError(
        `Invalid write-body format: writeChildren[${idx}].childId must be a string`,
        'DECRYPTION_FAILED'
      );
    }
    if (typeof wcObj.writeKeySealed !== 'string') {
      throw new CryptoError(
        `Invalid write-body format: writeChildren[${idx}].writeKeySealed must be a string`,
        'DECRYPTION_FAILED'
      );
    }
    return {
      childId: wcObj.childId as string,
      writeKeySealed: wcObj.writeKeySealed as string,
    };
  });

  return { ipnsPrivateKey, writeChildren };
}
