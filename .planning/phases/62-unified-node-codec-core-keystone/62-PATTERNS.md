# Phase 62: Unified Node Codec (Core Keystone) - Pattern Map

**Mapped:** 2026-06-28
**Files analyzed:** 14 new/modified files
**Analogs found:** 12 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `packages/core/src/node/types.ts` | model | — | `packages/core/src/vault/types.ts` | role-match |
| `packages/core/src/node/encode.ts` | utility | transform | `packages/core/src/folder/metadata.ts` (`encryptFolderMetadata`) | exact |
| `packages/core/src/node/decode.ts` | utility | transform | `packages/core/src/folder/metadata.ts` (`validateFolderMetadata` + `decryptFolderMetadata`) | exact |
| `packages/core/src/node/seal.ts` | utility | transform | `packages/crypto/src/aes/seal.ts` (`sealAesGcmAad`/`unsealAesGcmAad`) + `packages/core/src/folder/metadata.ts` | exact |
| `packages/core/src/node/index.ts` | config | — | `packages/core/src/vault/index.ts` | role-match |
| `packages/core/src/vault/blob.ts` | utility | transform | itself (v2 → v3 rewrite) | exact |
| `packages/core/src/vault/types.ts` | model | — | itself (modify) | exact |
| `packages/core/src/vault/init.ts` | service | CRUD | itself (modify) | exact |
| `packages/core/src/bin/types.ts` | model | — | itself (modify, retire `FilePointer`/`FolderEntry` imports) | exact |
| `packages/core/src/registry/schema.ts` | utility | transform | itself (may need import adaptation) | exact |
| `packages/core/src/index.ts` | config | — | itself (barrel update) | exact |
| `tests/vectors/node-codec.json` | test | — | `tests/vectors/crypto/node-aad.json` | role-match |
| `packages/core/src/__tests__/node-codec-vectors.test.ts` | test | — | `packages/core/src/__tests__/vault-blob-vectors.test.ts` | exact |
| `packages/core/src/__tests__/vault-blob-vectors.test.ts` | test | — | itself (modify) | exact |

---

## Pattern Assignments

### `packages/core/src/node/types.ts` (model)

**Analog:** `packages/core/src/vault/types.ts`

**Type definition pattern** (lines 1-21 of vault/types.ts):
```typescript
// Minimal imports; use `type` keyword; Uint8Array for all key material
import type { Ed25519Keypair } from '@cipherbox/crypto';

export type VaultInit = {
  rootFolderKey: Uint8Array;
  rootIpnsKeypair: Ed25519Keypair;
};
```

**Node types to define** (derived from CONTEXT.md D-03/D-06/D-08):
```typescript
// node/types.ts — string literals, not enums (project convention)
export type NodeKind = 'folder' | 'file' | 'root';
export type EncryptionMode = 'GCM' | 'CTR';

export type VersionEntry = {
  versionId: string;
  cid: string;
  size: number;
  createdAt: number;
  encryptionMode: EncryptionMode;
  fileKey: Uint8Array;      // raw 32B inside sealed body; NOT ECIES hex (D-07/NODE-02)
};

export type NodeContent = {
  cid: string;
  size: number;
  mimeType: string;
  encryptionMode: EncryptionMode;
  fileKey: Uint8Array;      // raw 32B AES key; semantic type change from legacy fileKeyEncrypted
  versions: VersionEntry[];
};

export type SealedChildRef = {
  // read-only chain link — no writeKeySealed field (NODE-03)
  name: string;
  ipnsName: string;
  generation: number;       // mirror; staleness witness only (D-07 invariant 1)
  versionFloor: bigint;     // bigint: matches IPNS sequenceNumber convention (D-08)
  readKeySealed: string;    // base64; sealed with role 0x02 child-readkey
};

export type Node = {
  schema: 'node/v3';
  kind: NodeKind;
  id: string;               // hyphenated UUID
  generation: number;       // u32-safe number; [0, 2^32-1] (D-08)
  createdAt: number;
  modifiedAt: number;
  // folder + root only:
  children?: SealedChildRef[];
  // file only:
  content?: NodeContent;
  // write-body children (in write-body, not in SealedChildRef):
  writeChildren?: WriteChildRef[];
};

export type WriteChildRef = {
  name: string;
  ipnsName: string;
  generation: number;
  writeKeySealed: string;   // base64; sealed with role 0x04 child-writekey
};

export type PublishedNode = {
  schema: 'node/v3';
  kind: NodeKind;
  id: string;
  generation: number;       // plaintext + AAD-bound in both sealed bodies (NODE-04)
  aeadVersion: 1;
  readSealed: string;       // base64 of IV ‖ ciphertext ‖ tag
  writeSealed?: string;     // base64; absent for file nodes with no write chain
};
```

---

### `packages/core/src/node/encode.ts` (utility, transform)

**Analog:** `packages/core/src/folder/metadata.ts` lines 23-31 + 105-124

**uint8ArrayToBase64 helper** (metadata.ts lines 23-31 — copy verbatim):
```typescript
// [SECURITY: MEDIUM-08] Chunk-based base64 encoding to avoid call stack issues
function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}
```

**Imports pattern** (metadata.ts lines 8-17 adapted for node/encode.ts):
```typescript
import type { Node } from './types';
// No @cipherbox/crypto needed in encode.ts — pure JSON + TextEncoder
```

**Core encode pattern** (metadata.ts lines 113 adapted):
```typescript
// node/encode.ts — encodeReadBody: Node → Uint8Array (no AEAD; IV-independent)
export function encodeReadBody(node: Node): Uint8Array {
  const readBody = {
    schema: 'node/v3',
    kind: node.kind,
    ...(node.kind !== 'file' ? { children: node.children ?? [] } : {}),
    ...(node.kind === 'file' ? { content: serializeContentForWire(node.content!) } : {}),
    createdAt: node.createdAt,
    modifiedAt: node.modifiedAt,
  };
  // D-03: JSON wire format — mirrors encryptFolderMetadata exactly
  return new TextEncoder().encode(JSON.stringify(readBody));
}
```

**content.fileKey serialization note:** Inside `serializeContentForWire`, `content.fileKey` (Uint8Array) must be serialized as `number[]` or base64 — never as a raw `Uint8Array` (not JSON-safe). The decode step reverses this.

---

### `packages/core/src/node/decode.ts` (utility, transform)

**Analog:** `packages/core/src/folder/metadata.ts` lines 38-96 (`validateFolderMetadata`), plus `packages/core/src/registry/schema.ts` lines 34-49 (validation skeleton)

**Validation pattern** (metadata.ts lines 38-50 + registry/schema.ts lines 34-48):
```typescript
// node/decode.ts — validateNode: unknown → Node
import { CryptoError } from '@cipherbox/crypto';
import type { Node } from './types';

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

  // D-08: generation range validation (mirrors buildNodeAad guard exactly)
  if (
    typeof obj.generation !== 'number' ||
    !Number.isInteger(obj.generation) ||
    obj.generation < 0 ||
    obj.generation > 0xffffffff
  ) {
    throw new CryptoError('Invalid node format: generation out of range', 'DECRYPTION_FAILED');
  }

  // kind-specific field validation omitted here — expand per NODE-01..NODE-03
  return data as Node;
}

// Decode entry point: bytes → Node
export function decodeReadBody(bytes: Uint8Array): Node {
  // D-03: JSON → TextDecoder (mirrors decryptFolderMetadata lines 148-149)
  const parsed = JSON.parse(new TextDecoder().decode(bytes));
  return validateNode(parsed);
}
```

**Generation range guard** (seal.ts lines 93-95 — copy exact guard):
```typescript
// From packages/crypto/src/aes/seal.ts buildNodeAad:
if (!Number.isInteger(generation) || generation < 0 || generation > 0xffffffff) {
  throw new CryptoError('Invalid generation for AAD', 'INVALID_AAD_INPUT');
}
```

---

### `packages/core/src/node/seal.ts` (utility, transform)

**Analog:** `packages/crypto/src/aes/seal.ts` + `packages/core/src/folder/metadata.ts`

**Imports pattern**:
```typescript
import { sealAesGcmAad, unsealAesGcmAad, buildNodeAad, CryptoError } from '@cipherbox/crypto';
import { encodeReadBody, encodeWriteBody } from './encode';
import { decodeReadBody } from './decode';
import type { Node, PublishedNode } from './types';
```

**sealAesGcmAad call pattern** (seal.ts lines 132-150 — use as-is):
```typescript
// packages/crypto/src/aes/seal.ts lines 132-150
export async function sealAesGcmAad(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array>
// Returns: IV (12 bytes) ‖ ciphertext ‖ auth tag (16 bytes)
// Mints a fresh random IV automatically — never reuse an IV (D-00a)
```

**buildNodeAad call pattern** (seal.ts lines 80-112):
```typescript
// Kind bytes: 0x01 folder, 0x02 file, 0x03 root
// Role bytes: 0x01 body, 0x02 child-readkey, 0x03 content, 0x04 child-writekey
const aad = buildNodeAad(node.id, kindByte, node.generation, 0x01 /* body */);
```

**Core seal pattern** (mirrors metadata.ts encryptFolderMetadata lines 105-124):
```typescript
// node/seal.ts — sealNode
export async function sealNode(
  node: Node,
  readKey: Uint8Array,
  writeKey: Uint8Array,
): Promise<PublishedNode> {
  const kindByte = node.kind === 'folder' ? 0x01 : node.kind === 'file' ? 0x02 : 0x03;

  // Seal read-body (role 0x01)
  const readBodyBytes = encodeReadBody(node);
  const readAad = buildNodeAad(node.id, kindByte, node.generation, 0x01);
  const readSealed = await sealAesGcmAad(readBodyBytes, readKey, readAad);

  // Seal write-body (role 0x01 — same role byte, different key)
  const writeBodyBytes = encodeWriteBody(node);
  const writeAad = buildNodeAad(node.id, kindByte, node.generation, 0x01);
  const writeSealed = await sealAesGcmAad(writeBodyBytes, writeKey, writeAad);

  return {
    schema: 'node/v3',
    kind: node.kind,
    id: node.id,
    generation: node.generation,
    aeadVersion: 1,
    readSealed: uint8ArrayToBase64(readSealed),
    writeSealed: uint8ArrayToBase64(writeSealed),
  };
}
```

**D-09 zeroization contract:** Seal functions receive caller-owned key material (`readKey`, `writeKey`, `childReadKey`). The codec MUST NOT zero these after use — the caller is the terminal owner. Only zero keys the codec itself generates from scratch (if any).

**Child-readkey seal (role 0x02)**:
```typescript
// For SealedChildRef.readKeySealed — child's readKey wrapped under parent readKey
const aad = buildNodeAad(childId, childKindByte, childGeneration, 0x02);
const sealed = await sealAesGcmAad(childReadKey, parentReadKey, aad); // do NOT zero childReadKey (D-09)
```

**Content self-seal (role 0x03, file nodes only)**:
```typescript
// content.fileKey is raw 32B AES key inside sealed body — NOT ECIES hex (NODE-02, D-07)
const aad = buildNodeAad(node.id, 0x02 /* file */, node.generation, 0x03);
const sealed = await sealAesGcmAad(contentBytes, fileNodeReadKey, aad);
```

**unsealAesGcmAad call pattern** (seal.ts lines 165-188):
```typescript
// Must rebuild AAD identically to sealing; any mismatch throws CryptoError
const aad = buildNodeAad(published.id, kindByte, published.generation, 0x01);
const plaintext = await unsealAesGcmAad(sealedBytes, readKey, aad);
```

---

### `packages/core/src/vault/blob.ts` (utility, transform — v3 hard-cut)

**Analog:** itself (v2) — `packages/core/src/vault/blob.ts` lines 48-100

**v2 serialize pattern** (blob.ts lines 48-67 — extend to two keys):
```typescript
// From blob.ts serializeVaultBlobV2 — exact byte manipulation pattern
export const BLOB_V2_VERSION = 0x02;

export function serializeVaultBlobV2(encryptedRootFolderKey: Uint8Array): Uint8Array {
  const keyLen = encryptedRootFolderKey.length;
  const result = new Uint8Array(3 + keyLen);
  result[0] = BLOB_V2_VERSION;
  result[1] = (keyLen >> 8) & 0xff;
  result[2] = keyLen & 0xff;
  result.set(encryptedRootFolderKey, 3);
  return result;
}
```

**v3 pattern** (D-05 — two-key extension, DELETE the v2 functions and `detectBlobVersion`):
```typescript
// DELETE: detectBlobVersion, serializeVaultBlobV2, deserializeVaultBlobV2, BLOB_V2_VERSION
// REPLACE WITH:
export const BLOB_V3_VERSION = 0x03;

export function serializeVaultBlobV3(
  encryptedRootReadKey: Uint8Array,   // ECIES(rootReadKey) ~129 bytes
  encryptedRootWriteKey: Uint8Array,  // ECIES(rootWriteKey) ~129 bytes
): Uint8Array {
  const readLen = encryptedRootReadKey.length;
  const writeLen = encryptedRootWriteKey.length;
  // Layout: 0x03 | u16_BE(readLen) | ecies(readKey) | u16_BE(writeLen) | ecies(writeKey)
  const result = new Uint8Array(1 + 2 + readLen + 2 + writeLen);
  result[0] = BLOB_V3_VERSION;
  result[1] = (readLen >> 8) & 0xff;
  result[2] = readLen & 0xff;
  result.set(encryptedRootReadKey, 3);
  const writeOffset = 3 + readLen;
  result[writeOffset] = (writeLen >> 8) & 0xff;
  result[writeOffset + 1] = writeLen & 0xff;
  result.set(encryptedRootWriteKey, writeOffset + 2);
  return result;
}

export function deserializeVaultBlobV3(blob: Uint8Array): {
  encryptedRootReadKey: Uint8Array;
  encryptedRootWriteKey: Uint8Array;
} {
  if (blob.length < 5) throw new Error('Vault blob too short for v3 header (need at least 5 bytes)');
  if (blob[0] !== BLOB_V3_VERSION) throw new Error('Not a v3 vault blob');
  const readLen = (blob[1] << 8) | blob[2];
  if (readLen === 0) throw new Error('Invalid v3 blob: read key length must be > 0');
  if (blob.length < 3 + readLen + 2) throw new Error('Vault blob truncated (missing write key header)');
  const encryptedRootReadKey = blob.subarray(3, 3 + readLen);
  const writeOffset = 3 + readLen;
  const writeLen = (blob[writeOffset] << 8) | blob[writeOffset + 1];
  if (writeLen === 0) throw new Error('Invalid v3 blob: write key length must be > 0');
  if (blob.length < writeOffset + 2 + writeLen) throw new Error('Vault blob truncated (write key)');
  const encryptedRootWriteKey = blob.subarray(writeOffset + 2, writeOffset + 2 + writeLen);
  return { encryptedRootReadKey, encryptedRootWriteKey };
}
```

---

### `packages/core/src/vault/types.ts` (model — modify)

**Analog:** itself lines 1-37

**Fields to change** (remove `encryptedRootFolderKey`, add two-key fields):
```typescript
// VaultInit: rename rootFolderKey → rootReadKey, add rootWriteKey
export type VaultInit = {
  rootReadKey: Uint8Array;       // was rootFolderKey
  rootWriteKey: Uint8Array;      // new: independent random 32B AES key
  rootIpnsKeypair: Ed25519Keypair; // unchanged
};

// EncryptedVaultKeys: remove encryptedRootFolderKey, add two encrypted keys
export type EncryptedVaultKeys = {
  encryptedRootReadKey: Uint8Array;   // was encryptedRootFolderKey
  encryptedRootWriteKey: Uint8Array;  // new
  encryptedIpnsPrivateKey: Uint8Array; // unchanged
};
```

---

### `packages/core/src/vault/init.ts` (service, CRUD — modify)

**Analog:** itself lines 37-129

**Three-point adaptation** (mirrors existing `encryptVaultKeys`/`decryptVaultKeys` lines 71-129):
```typescript
// initializeVault: add rootWriteKey = generateFileKey() alongside rootReadKey
const rootReadKey = generateFileKey();    // was rootFolderKey
const rootWriteKey = generateFileKey();   // new; independent random 32B

// encryptVaultKeys: wrap both read and write keys
const encryptedRootReadKey = await wrapKey(vault.rootReadKey, userPublicKey);
const encryptedRootWriteKey = await wrapKey(vault.rootWriteKey, userPublicKey);

// decryptVaultKeys: unwrap both
const rootReadKey = await unwrapKey(encrypted.encryptedRootReadKey, userPrivateKey);
const rootWriteKey = await unwrapKey(encrypted.encryptedRootWriteKey, userPrivateKey);
```

`wrapKey`/`unwrapKey` from `@cipherbox/crypto` — same functions, same signature (init.ts line 14).

---

### `packages/core/src/bin/types.ts` (model — adapt imports)

**Analog:** itself lines 1-10

**Import swap** (lines 9-10 of bin/types.ts):
```typescript
// OLD:
import type { FilePointer } from '../file/types';
import type { FolderEntry } from '../folder/types';

// NEW (D-06 — both retired types replaced; behavior stubbed per D-01):
import type { Node } from '../node/types';

// BinEntry fields filePointer?/folderEntry? both become:
nodeRef?: Node; // or separate typed fields if needed for Phase 65 bin restore
// Use Node as the compile target (RESEARCH.md Open Question 1 recommendation)
```

Also remove `originalFolderKeyEncrypted?: string` (field referenced the legacy `folderKey` concept; stub with `// TODO(phase 65)`).

---

### `tests/vectors/node-codec.json` (test fixture — new)

**Analog:** `tests/vectors/crypto/node-aad.json` lines 1-45

**JSON structure pattern** (node-aad.json lines 1-13):
```json
{
  "seal_vectors": [
    {
      "description": "encryptAesGcmAad fixed key/iv, kind=folder role=body generation=42 (D-01b full-seal KAT)",
      "node_id": "550e8400-e29b-41d4-a716-446655440000",
      "kind": 1,
      "generation": 42,
      "role": 1,
      "key": "0123456789abcdef...",
      "iv": "000102030405060708090a0b",
      "plaintext": "...",
      "ciphertext": "..."
    }
  ],
  "aad_vectors": [...]
}
```

**Node codec fixture structure** (D-04 — two locks + vault v3):
```json
{
  "body_vectors": [
    {
      "description": "folder node read-body bytes PRIMARY LOCK (IV-independent)",
      "node": { "schema": "node/v3", "kind": "folder", "id": "550e8400-e29b-41d4-a716-446655440000", "generation": 0, ... },
      "expected_read_body_hex": "<hex of TextEncoder(JSON.stringify(readBody))>"
    },
    {
      "description": "file node read-body bytes with GCM VersionEntry",
      ...
    },
    {
      "description": "file node read-body bytes with CTR VersionEntry",
      ...
    },
    {
      "description": "root node read-body bytes",
      ...
    }
  ],
  "seal_vectors": [
    {
      "description": "folder node FULL-SEAL LOCK (fixed key + fixed IV)",
      "node_id": "550e8400-e29b-41d4-a716-446655440000",
      "kind": 1,
      "generation": 0,
      "read_key": "0101010101010101010101010101010101010101010101010101010101010101",
      "write_key": "0202020202020202020202020202020202020202020202020202020202020202",
      "fixed_iv": "000102030405060708090a0b",
      "expected_published_node": { ... }
    }
  ],
  "vault_v3_vectors": [
    {
      "description": "vault blob v3 two-key serialize",
      "ecies_read_key_hex": "aa000102...",
      "ecies_write_key_hex": "bb000102...",
      "expected_blob_hex": "03 0081 <readKey> 0081 <writeKey>"
    }
  ]
}
```

---

### `packages/core/src/__tests__/node-codec-vectors.test.ts` (test — new)

**Analog:** `packages/core/src/__tests__/vault-blob-vectors.test.ts` lines 1-97

**Test file skeleton** (vault-blob-vectors.test.ts lines 1-15, 58-97):
```typescript
import { describe, it, expect } from 'vitest';
// Same toHex/fromHex helpers (vault-blob-vectors.test.ts lines 44-56 — copy verbatim)
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}

import VECTORS from '../../../../tests/vectors/node-codec.json';
import { encodeReadBody } from '../node/encode';
import { sealNode, unsealNode } from '../node/seal';

describe('Node Codec — Body Bytes PRIMARY LOCK (D-04)', () => {
  it('folder node read-body hex matches vector', () => {
    const bytes = encodeReadBody(VECTORS.body_vectors[0].node);
    expect(toHex(bytes)).toBe(VECTORS.body_vectors[0].expected_read_body_hex);
  });
  // repeat for file/GCM, file/CTR, root
});

describe('Node Codec — FULL-SEAL LOCK (D-04, fixed key/IV)', () => {
  // Requires a test-only sealNodeWithFixedIv helper that injects the IV
  it('folder node full-seal hex matches vector', async () => {
    // ...
  });
});

describe('Node Codec — Round-Trip', () => {
  it('seal then unseal recovers identical Node', async () => {
    const readKey = new Uint8Array(32).fill(0x01);
    const writeKey = new Uint8Array(32).fill(0x02);
    // ...
    const recovered = await unsealNode(published, readKey, writeKey);
    expect(recovered).toEqual(node);
  });
});
```

**Generation range test** (mirrors buildNodeAad guard):
```typescript
it('encodeReadBody throws on generation > 0xffffffff', () => {
  expect(() => encodeReadBody({ ...node, generation: 0x100000000 })).toThrow();
});
```

---

### `packages/core/src/__tests__/vault-blob-vectors.test.ts` (test — modify)

**Analog:** itself — replace v2 imports/functions with v3 equivalents

**Import change** (line 10):
```typescript
// OLD:
import { serializeVaultBlobV2, deserializeVaultBlobV2, BLOB_V2_VERSION } from '../vault/blob';
// NEW:
import { serializeVaultBlobV3, deserializeVaultBlobV3, BLOB_V3_VERSION } from '../vault/blob';
```

**Vector layout change** (lines 24-42 — adapt to two-key format):
```typescript
// v3 needs TWO 129-byte keys; test `describe` block name changes to 'Vault Key Blob v3 Test Vectors'
const TEST_READ_KEY_129 = new Uint8Array(129); TEST_READ_KEY_129[0] = 0xaa; /* ... */
const TEST_WRITE_KEY_129 = new Uint8Array(129); TEST_WRITE_KEY_129[0] = 0xbb; /* ... */

const EXPECTED_HEX =
  '03' +       // version byte
  '0081' +     // readLen = 129
  'aa...' +    // read key bytes
  '0081' +     // writeLen = 129
  'bb...';     // write key bytes
```

---

## Shared Patterns

### JSON Encode → Seal (D-03)
**Source:** `packages/core/src/folder/metadata.ts` lines 113-123
**Apply to:** `node/encode.ts`, `node/seal.ts`
```typescript
// Step 1: JSON serialize to bytes (encode.ts)
const plaintext = new TextEncoder().encode(JSON.stringify(body));
// Step 2: seal with AAD (seal.ts) — replaces encryptAesGcm with sealAesGcmAad
const sealed = await sealAesGcmAad(plaintext, key, aad);
return uint8ArrayToBase64(sealed); // [SECURITY: MEDIUM-08] chunked base64
```

### JSON Unseal → Validate (D-03)
**Source:** `packages/core/src/folder/metadata.ts` lines 135-150
**Apply to:** `node/decode.ts`
```typescript
// Step 1: unseal
const plaintext = await unsealAesGcmAad(sealedBytes, key, aad);
// Step 2: JSON parse + validate (mirrors decryptFolderMetadata lines 148-149)
const parsed = JSON.parse(new TextDecoder().decode(plaintext));
return validateNode(parsed); // throws CryptoError('...', 'DECRYPTION_FAILED') on failure
```

### Runtime Validation Pattern
**Source:** `packages/core/src/folder/metadata.ts` lines 38-96 + `packages/core/src/registry/schema.ts` lines 34-105
**Apply to:** `node/decode.ts` (`validateNode`)
```typescript
// Pattern: unknown → typed; CryptoError('...', 'DECRYPTION_FAILED') on any failure
export function validateNode(data: unknown): Node {
  if (typeof data !== 'object' || data === null) {
    throw new CryptoError('Invalid node format: not an object', 'DECRYPTION_FAILED');
  }
  // field-by-field checks; use VALID_KINDS array for discriminated union
}
```

### Consumer Stub Pattern (D-01/D-02)
**Source:** RESEARCH.md Code Examples
**Apply to:** All `packages/sdk-core/src/`, `packages/sdk/src/`, `apps/web/src/` call sites requiring real new behavior
```typescript
// Stub behavioral call sites:
export async function loadFolder(/* ... */): Promise<Node> {
  throw new Error('not implemented — phase 63 (read-chain navigation)');
}

// Quarantine broken tests (D-02):
describe.skip('loadFolder — TODO(phase 63)', () => {
  // original test body preserved as spec
});
```

### `toHex`/`fromHex` Test Helpers
**Source:** `packages/core/src/__tests__/vault-blob-vectors.test.ts` lines 44-56
**Apply to:** `node-codec-vectors.test.ts` (copy verbatim)
```typescript
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `packages/core/src/node/index.ts` | config | — | Re-export barrel only; no analog needed, pattern is trivial |

---

## Metadata

**Analog search scope:** `packages/core/src/`, `packages/crypto/src/`, `tests/vectors/`
**Files scanned:** 8 source files, 1 JSON fixture
**Pattern extraction date:** 2026-06-28
