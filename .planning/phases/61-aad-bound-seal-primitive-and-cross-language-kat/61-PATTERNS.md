# Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT - Pattern Map

**Mapped:** 2026-06-28
**Files analyzed:** 11 new/modified files
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `packages/crypto/src/aes/seal.ts` (extend) | utility/crypto | transform | `packages/crypto/src/aes/seal.ts` (existing funcs) | exact |
| `packages/crypto/src/utils/encoding.ts` (extend) | utility | transform | same file (`hexToBytes`) | exact |
| `packages/crypto/src/__tests__/build-node-aad.test.ts` | test | request-response | `packages/crypto/src/__tests__/aes.test.ts` | exact |
| `crates/crypto/src/aes.rs` (extend) | utility/crypto | transform | same file (`seal_aes_gcm`) | exact |
| `crates/crypto/tests/cross_language.rs` (extend) | test | batch | same file (`aes_gcm_cross_language`) | exact |
| `crates/crypto/Cargo.toml` (extend) | config | — | `crates/crypto/Cargo.toml` (existing deps) | exact |
| `Cargo.toml` (extend workspace deps) | config | — | `Cargo.toml` `[workspace.dependencies]` | exact |
| `tests/vectors/crypto/node-aad.json` | config/fixture | — | `tests/vectors/crypto/aes-gcm.json` | exact |
| `scripts/check-vector-parity.sh` (extend) | config | — | same file (`EXPECTED_VECTORS` array) | exact |
| `docs/adr/0003-aad-bound-node-seal-encoding.md` | doc | — | `docs/adr/0001-write-revocation-full-ed25519-rotation.md` | exact |
| `docs/METADATA_SCHEMAS.md`, `docs/METADATA_EVOLUTION_PROTOCOL.md`, `docs/FILESYSTEM_SPECIFICATION.md` (extend) | doc | — | existing doc sections | role-match |

## Pattern Assignments

### `packages/crypto/src/aes/seal.ts` — extend with AAD variants + `buildNodeAad`

**Analog:** same file, existing `sealAesGcm`/`unsealAesGcm`

**Imports pattern** (lines 1-15 of seal.ts):
```typescript
import { CryptoError } from '../types';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_TAG_SIZE } from '../constants';
import { generateIv } from '../utils/random';
import { concatBytes } from '../utils/encoding';
import { encryptAesGcm } from './encrypt';
import { decryptAesGcm } from './decrypt';
```
Add to imports: `hexToBytes` from `'../utils/encoding'` (for `uuidToBytes`). No new package imports needed on TS side.

**Core seal pattern** (lines 35-49 of seal.ts — copy exactly, add `aad` parameter):
```typescript
export async function sealAesGcm(plaintext: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Encryption failed', 'INVALID_KEY_SIZE');
  }
  const iv = generateIv();
  const ciphertext = await encryptAesGcm(plaintext, key, iv);
  return concatBytes(iv, ciphertext);
}
```
New `sealAesGcmAad` mirrors this exactly, replacing `encryptAesGcm` with `encryptAesGcmAad(plaintext, key, iv, aad)`.

**Unseal pattern** (lines 63-82 of seal.ts — copy MIN_SEALED_SIZE guard + IV slice pattern):
```typescript
const MIN_SEALED_SIZE = AES_IV_SIZE + AES_TAG_SIZE;

export async function unsealAesGcm(sealed: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  if (key.length !== AES_KEY_SIZE) {
    throw new CryptoError('Decryption failed', 'INVALID_KEY_SIZE');
  }
  if (sealed.length < MIN_SEALED_SIZE) {
    throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
  }
  const iv = sealed.slice(0, AES_IV_SIZE);
  const ciphertext = sealed.slice(AES_IV_SIZE);
  return decryptAesGcm(ciphertext, key, iv);
}
```
`unsealAesGcmAad` mirrors identically, passing `aad` through to `decryptAesGcmAad`.

**`encryptAesGcmAad` pattern** (analog: `packages/crypto/src/aes/encrypt.ts` lines 23-65):
```typescript
// existing: { name: AES_GCM_ALGORITHM, iv: ivBuffer }
// new: add additionalData to the AesGcmParams object
const ciphertext = await crypto.subtle.encrypt(
  { name: AES_GCM_ALGORITHM, iv: ivBuffer, additionalData: aadBuffer },
  cryptoKey,
  plaintextBuffer
);
```
Copy the full `encryptAesGcm` body verbatim, adding `const aadBuffer = new Uint8Array(aad).buffer as ArrayBuffer;` alongside the other buffer copies, and adding `additionalData: aadBuffer` to the params object. Pattern is from `encrypt.ts` lines 40-58.

**`buildNodeAad` domain-separator pattern** (frozen encoding from CONTEXT.md D-00):
```typescript
const DOMAIN = new TextEncoder().encode('cipherbox/node-seal/v1');
const NULL_SEP = new Uint8Array([0x00]);

export function buildNodeAad(
  nodeId: string,
  kind: number,
  generation: number,
  role: number,
): Uint8Array {
  // D-03 fail-closed validation
  if (![0x01, 0x02, 0x03].includes(kind))
    throw new CryptoError('Invalid kind', 'INVALID_AAD_INPUT');
  if (![0x01, 0x02, 0x03, 0x04].includes(role))
    throw new CryptoError('Invalid role', 'INVALID_AAD_INPUT');
  if (!Number.isInteger(generation) || generation < 0 || generation > 0xffffffff)
    throw new CryptoError('Invalid generation', 'INVALID_AAD_INPUT');
  const nodeIdBytes = uuidToBytes(nodeId); // throws on malformed UUID
  const genBytes = new Uint8Array(4);
  new DataView(genBytes.buffer).setUint32(0, generation, false); // big-endian
  return concatBytes(DOMAIN, NULL_SEP, nodeIdBytes, new Uint8Array([kind]), genBytes, new Uint8Array([role]));
}
```
`concatBytes` pattern is from `packages/crypto/src/utils/encoding.ts` lines 51-62.

---

### `packages/crypto/src/utils/encoding.ts` — add `uuidToBytes`

**Analog:** existing `hexToBytes` in same file (lines 14-31)

```typescript
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error('Invalid hex string: non-hex character');
    }
    bytes[i] = byte;
  }
  return bytes;
}
```
New `uuidToBytes` strips hyphens then delegates to `hexToBytes`. NEVER uses `TextEncoder` (PITFALLS Pitfall 1 — produces 36 UTF-8 bytes, not 16 raw bytes):
```typescript
export function uuidToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');
  if (clean.length !== 32) throw new CryptoError('Malformed UUID', 'INVALID_AAD_INPUT');
  return hexToBytes(clean);
}
```

---

### `packages/crypto/src/__tests__/build-node-aad.test.ts` — new TS KAT + transplant suite

**Analog:** `packages/crypto/src/__tests__/aes.test.ts`

**Imports/describe pattern** (lines 1-11 of aes.test.ts):
```typescript
import { describe, it, expect } from 'vitest';
import { encryptAesGcm, decryptAesGcm, sealAesGcm, unsealAesGcm } from '../aes';
import { generateFileKey, generateIv } from '../utils';
import { AES_KEY_SIZE, AES_IV_SIZE, AES_TAG_SIZE } from '../constants';
```
New test imports `buildNodeAad`, `sealAesGcmAad`, `unsealAesGcmAad`, `encryptAesGcmAad` from `'../aes'`; `hexToBytes`, `bytesToHex` from `'../utils/encoding'`; and loads vectors from `'../../../../tests/vectors/crypto/node-aad.json'` (use `fs` or inline the frozen values).

**KAT assertion pattern** — load JSON vectors then assert byte equality:
```typescript
it('matches committed aad_vectors for all four role bytes', async () => {
  for (const v of vectors.aad_vectors) {
    const aad = buildNodeAad(v.node_id, v.kind, v.generation, v.role);
    expect(bytesToHex(aad)).toBe(v.expected_aad);
  }
});
```

**Transplant resistance pattern** — copy `decrypt_corrupted_ciphertext_fails` style from aes.test.ts (see Rust unit tests at `crates/crypto/src/aes.rs` lines 129-139):
```typescript
it('fails to unseal when nodeId differs', async () => {
  const key = generateFileKey();
  const aad = buildNodeAad(nodeId, 0x01, 0, 0x01);
  const sealed = await sealAesGcmAad(plaintext, key, aad);
  const wrongAad = buildNodeAad(differentNodeId, 0x01, 0, 0x01);
  await expect(unsealAesGcmAad(sealed, key, wrongAad)).rejects.toThrow();
});
```

---

### `crates/crypto/src/aes.rs` — extend with AAD variants + `build_node_aad`

**Analog:** same file, existing `seal_aes_gcm`/`unseal_aes_gcm` (lines 62-87)

**Imports extension** (lines 6-9 of aes.rs — add `Payload`):
```rust
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use uuid::Uuid;
```

**`encrypt_aes_gcm_aad` pattern** (mirrors `encrypt_aes_gcm` lines 29-40, add `Payload`):
```rust
pub fn encrypt_aes_gcm_aad(
    plaintext: &[u8],
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesEncryptionFailed)?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::AesEncryptionFailed)
}
```

**`seal_aes_gcm_aad` pattern** (mirrors `seal_aes_gcm` lines 62-71 exactly):
```rust
pub fn seal_aes_gcm_aad(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let iv = generate_iv();
    let ciphertext = encrypt_aes_gcm_aad(plaintext, key, &iv, aad)?;
    let mut sealed = Vec::with_capacity(AES_IV_SIZE + ciphertext.len());
    sealed.extend_from_slice(&iv);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}
```

**`unseal_aes_gcm_aad` pattern** (mirrors `unseal_aes_gcm` lines 76-87 — same MIN_SEALED_SIZE guard + IV slice):
```rust
pub fn unseal_aes_gcm_aad(sealed: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < MIN_SEALED_SIZE {
        return Err(CryptoError::AesDecryptionFailed);
    }
    let iv: [u8; 12] = sealed[..AES_IV_SIZE]
        .try_into()
        .map_err(|_| CryptoError::AesDecryptionFailed)?;
    let ciphertext = &sealed[AES_IV_SIZE..];
    decrypt_aes_gcm_aad(ciphertext, key, &iv, aad)
}
```

**`build_node_aad` domain-separator pattern** (mirrors `crates/crypto/src/hkdf.rs` lines 24-28 frozen byte literal style):
```rust
// hkdf.rs precedent:
const HKDF_SALT: &[u8] = b"CipherBox-v1";
const VAULT_HKDF_INFO: &[u8] = b"cipherbox-vault-ipns-v1";

// New constant in aes.rs:
const NODE_SEAL_DOMAIN: &[u8] = b"cipherbox/node-seal/v1";

pub fn build_node_aad(
    node_id: &str,
    kind: u8,
    generation: u32,
    role: u8,
) -> Result<Vec<u8>, CryptoError> {
    if !matches!(kind, 0x01..=0x03) { return Err(CryptoError::InvalidAadInput); }
    if !matches!(role, 0x01..=0x04) { return Err(CryptoError::InvalidAadInput); }
    let uuid = Uuid::parse_str(node_id).map_err(|_| CryptoError::InvalidAadInput)?;
    let id_bytes = uuid.as_bytes(); // &[u8; 16] RFC-4122 field order
    let mut aad = Vec::with_capacity(NODE_SEAL_DOMAIN.len() + 1 + 16 + 1 + 4 + 1);
    aad.extend_from_slice(NODE_SEAL_DOMAIN);
    aad.push(0x00);
    aad.extend_from_slice(id_bytes);
    aad.push(kind);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.push(role);
    Ok(aad)
}
```
Note: `CryptoError::InvalidAadInput` is a new variant to add to `crates/crypto/src/error.rs`.

---

### `crates/crypto/tests/cross_language.rs` — extend with node-AAD test

**Analog:** same file, `aes_gcm_cross_language` test (lines 31-73)

**Struct + test pattern** (copy exactly from lines 31-43 and 42-73):
```rust
#[derive(Deserialize)]
struct NodeAadVector {
    #[allow(dead_code)]
    description: String,
    node_id: String,
    kind: u8,
    generation: u32,
    role: u8,
    expected_aad: String,
}

#[derive(Deserialize)]
struct NodeSealVector {
    #[allow(dead_code)]
    description: String,
    key: String,
    iv: String,
    plaintext: String,
    aad_node_id: String,
    aad_kind: u8,
    aad_generation: u32,
    aad_role: u8,
    ciphertext: String,
}

#[test]
fn node_aad_cross_language() {
    // node-aad.json has top-level object with "aad_vectors" and "seal_vectors" arrays
    // use serde_json::Value to parse both arrays from one file
    let path = vectors_path("crypto/node-aad.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    let root: serde_json::Value = serde_json::from_str(&data).unwrap();

    let aad_vectors: Vec<NodeAadVector> =
        serde_json::from_value(root["aad_vectors"].clone()).unwrap();
    assert!(!aad_vectors.is_empty(), "No AAD vectors loaded");
    for v in &aad_vectors {
        let aad = cipherbox_crypto::build_node_aad(&v.node_id, v.kind, v.generation, v.role)
            .unwrap();
        assert_eq!(hex::encode(&aad), v.expected_aad,
            "AAD mismatch: {}", v.description);
    }

    let seal_vectors: Vec<NodeSealVector> =
        serde_json::from_value(root["seal_vectors"].clone()).unwrap();
    assert!(!seal_vectors.is_empty(), "No seal vectors loaded");
    for v in &seal_vectors {
        let key: [u8; 32] = hex::decode(&v.key).unwrap().try_into().unwrap();
        let iv: [u8; 12] = hex::decode(&v.iv).unwrap().try_into().unwrap();
        let plaintext = hex::decode(&v.plaintext).unwrap();
        let aad = cipherbox_crypto::build_node_aad(
            &v.aad_node_id, v.aad_kind, v.aad_generation, v.aad_role
        ).unwrap();
        let encrypted = cipherbox_crypto::encrypt_aes_gcm_aad(&plaintext, &key, &iv, &aad)
            .unwrap();
        assert_eq!(hex::encode(&encrypted), v.ciphertext,
            "Seal mismatch: {}", v.description);
    }
}
```
Note: `load_vectors` (line 20-25) only handles flat arrays; the node-aad file uses a top-level object with two arrays, so parse via `serde_json::Value` directly as shown above.

---

### `tests/vectors/crypto/node-aad.json` — new KAT fixture

**Analog:** `tests/vectors/crypto/aes-gcm.json` (exact JSON shape, no `0x` prefixes, all hex lowercase)

```json
{
  "aad_vectors": [
    {
      "description": "buildNodeAad kind=folder role=body generation=42",
      "node_id": "550e8400-e29b-41d4-a716-446655440000",
      "kind": 1,
      "generation": 42,
      "role": 1,
      "expected_aad": "<hex>"
    },
    { "description": "role=child-readkey", "role": 2, ... },
    { "description": "role=content", "role": 3, ... },
    { "description": "role=child-writekey", "role": 4, ... }
  ],
  "seal_vectors": [
    {
      "description": "encryptAesGcmAad fixed IV round-trip",
      "key": "<32B hex>",
      "iv": "<12B hex>",
      "plaintext": "<hex>",
      "aad_node_id": "550e8400-e29b-41d4-a716-446655440000",
      "aad_kind": 1,
      "aad_generation": 42,
      "aad_role": 1,
      "ciphertext": "<hex>"
    }
  ]
}
```
The `expected_aad` and `ciphertext` hex values must be computed from the TS implementation and committed as the frozen ground truth. The KAT tests assert Rust produces identical bytes. Note: test the fixed-IV `encryptAesGcmAad` (not `sealAesGcmAad`, which mints a random IV and can't produce a fixed vector — see RESEARCH.md Anti-Patterns).

---

### `scripts/check-vector-parity.sh` — extend EXPECTED_VECTORS

**Analog:** same file lines 14-24

```bash
EXPECTED_VECTORS=(
  "tests/vectors/crypto/aes-gcm.json"
  "tests/vectors/crypto/ed25519.json"
  "tests/vectors/crypto/ecies.json"
  "tests/vectors/crypto/hkdf.json"
  "tests/vectors/crypto/ipns-name.json"
  "tests/vectors/crypto/node-aad.json"    # ADD THIS LINE
  "tests/vectors/core/vault-blob.json"
  ...
)
```

---

### `crates/crypto/Cargo.toml` + root `Cargo.toml` — add `uuid` workspace dep

**Analog:** existing dependency pattern in `crates/crypto/Cargo.toml` lines 1-20

In root `Cargo.toml` `[workspace.dependencies]`:
```toml
uuid = { version = "1", features = ["std"] }
```

In `crates/crypto/Cargo.toml` `[dependencies]` (after existing `hex` line):
```toml
uuid = { workspace = true }
```

---

### `docs/adr/0003-aad-bound-node-seal-encoding.md` — new ADR

**Analog:** `docs/adr/0001-write-revocation-full-ed25519-rotation.md` (frontmatter pattern, lines 1-4):
```markdown
---
status: accepted
date: 2026-06-28
---

# [Title]

[Body]
```
ADR 0003 body: frozen encoding table (from CONTEXT.md D-00), role-byte table, AEAD parameters (AES-256-GCM, 12-byte IV, 16-byte tag, `[IV][ct+tag]` layout), rule "every new role byte must extend the KAT," and cross-language KAT discipline.

---

## Shared Patterns

### Error type convention (apply to all new validation code)

**Source:** `packages/crypto/src/aes/seal.ts` lines 37-39, `crates/crypto/src/aes.rs` (existing `CryptoError::AesEncryptionFailed` / `AesDecryptionFailed`)

TS: `throw new CryptoError('message', 'ERROR_CODE_STRING')` — add new code `'INVALID_AAD_INPUT'`

Rust: add `InvalidAadInput` variant to `crates/crypto/src/error.rs` following same PascalCase pattern as existing variants.

### Minimum-size guard (apply to all unseal functions)

**Source:** `packages/crypto/src/aes/seal.ts` lines 70-72; `crates/crypto/src/aes.rs` lines 77-79

```typescript
if (sealed.length < MIN_SEALED_SIZE) {
  throw new CryptoError('Decryption failed', 'DECRYPTION_FAILED');
}
```

```rust
if sealed.len() < MIN_SEALED_SIZE {
    return Err(CryptoError::AesDecryptionFailed);
}
```

### IV minting — never accept caller-supplied IV in production seal

**Source:** `packages/crypto/src/aes/seal.ts` line 42; `crates/crypto/src/aes.rs` line 63

```typescript
const iv = generateIv(); // always fresh in sealAesGcm*
```
```rust
let iv = generate_iv(); // always fresh in seal_aes_gcm*
```
The fixed-IV KAT uses `encryptAesGcmAad`/`encrypt_aes_gcm_aad` directly — NOT the `seal_*` wrappers.

### Public API export (barrel)

**Source:** `packages/crypto/src/index.ts` (barrel re-exports existing `sealAesGcm` etc.)

New functions `sealAesGcmAad`, `unsealAesGcmAad`, `buildNodeAad`, `encryptAesGcmAad`, `decryptAesGcmAad` must be re-exported from the barrel. Implementations stay in named files (`src/aes/seal.ts`, `src/utils/encoding.ts`) per C-02. The barrel itself is excluded from vitest coverage.

### Domain separator as frozen byte literal

**Source:** `crates/crypto/src/hkdf.rs` lines 24-30

```rust
const HKDF_SALT: &[u8] = b"CipherBox-v1";
const VAULT_HKDF_INFO: &[u8] = b"cipherbox-vault-ipns-v1";
```
New pattern: `const NODE_SEAL_DOMAIN: &[u8] = b"cipherbox/node-seal/v1";` in `crates/crypto/src/aes.rs`.

TS side: module-level `const DOMAIN = new TextEncoder().encode('cipherbox/node-seal/v1');` — evaluated once at module load, not inside the function body.

## No Analog Found

None — all files have a direct analog or extend an existing file in-place.

## Metadata

**Analog search scope:** `packages/crypto/src/`, `crates/crypto/src/`, `crates/crypto/tests/`, `tests/vectors/crypto/`, `scripts/`, `docs/adr/`
**Files scanned:** 12
**Pattern extraction date:** 2026-06-28
