# Phase 51: Crypto-Signature & Secret-Leak Hardening - Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 12
**Analogs found:** 12 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `apps/api/src/ipns/ipns.service.ts` | service | request-response | self (lines 222-234 anti-rollback block) | exact |
| `apps/api/src/ipns/ipns.service.spec.ts` | test | request-response | self (lines 384-463 upsertFolderIpns describe block) | exact |
| `apps/web/src/services/ipns.service.ts` | service | request-response | `packages/sdk-core/src/ipns/index.ts:182-239` | exact |
| `apps/web/src/services/__tests__/ipns.service.test.ts` | test | request-response | `packages/sdk-core/src/__tests__/ipns.test.ts` | role-match |
| `packages/sdk-core/src/ipns/index.ts` | service | request-response | `packages/sdk-core/src/file/index.ts:369-373` | role-match |
| `packages/sdk-core/src/vault/index.ts` | service | request-response | `packages/sdk-core/src/file/index.ts:369-373` | role-match |
| `packages/sdk-core/src/folder/index.ts` | service | request-response | `packages/sdk-core/src/file/index.ts:369-373` | exact |
| `packages/sdk-core/src/__tests__/ipns.test.ts` | test | request-response | self (existing describe blocks) | exact |
| `crates/api-client/src/types.rs` | model | request-response | self (lines 130-137 IpnsResolveResponse) | exact |
| `crates/api-client/src/ipns.rs` | service | request-response | `crates/core/src/ipns.rs:272-316` (#[cfg(test)]) + `crates/crypto/src/ecies.rs:49-80` (#[cfg(test)]) | role-match |
| `crates/crypto/src/ecies.rs` | utility | transform | `crates/fuse/src/inode.rs` (Zeroizing<Vec<u8>> pattern) | role-match |
| `crates/fuse/src/lib.rs` | service | request-response | `crates/fuse/src/inode.rs` (Zeroizing fields) | role-match |

---

## Pattern Assignments

### `apps/api/src/ipns/ipns.service.ts` (service, request-response) — S1

**Analog:** self — `apps/api/src/ipns/ipns.service.ts:222-248`

**Imports pattern** (lines 1-24):
```typescript
import {
  BadRequestException,
  ConflictException,
  // ...other NestJS imports
} from '@nestjs/common';
import { deriveIpnsName, parseIpnsRecord, verifyIpnsRecordSignature } from '@cipherbox/crypto';
```

**Existing anti-rollback anchor** (lines 222-234) — S1 validation inserts AFTER this block:
```typescript
if (existing?.signedRecord) {
  const [incoming, stored] = await Promise.all([
    parseIpnsRecord(signedRecord),        // ← reuse `incoming` for S1 checks
    parseIpnsRecord(existing.signedRecord),
  ]);
  if (incoming.sequence < stored.sequence) {
    throw new ConflictException({
      statusCode: 409,
      message: 'IPNS record sequence regression rejected (rollback/replay)',
      currentSequenceNumber: existing.sequenceNumber,
    });
  }
  // INSERT S1 embedded-vs-DTO checks here using `incoming`
}
// For first publish (no existing): call parseIpnsRecord(signedRecord) once for S1 only
```

**S1 CID check pattern** — insert after anti-rollback, before metadataCid save:
```typescript
// S1: embedded-vs-DTO CID check (strict)
const incomingParsed = existing?.signedRecord ? incoming : await parseIpnsRecord(signedRecord);
const embeddedCidMatch = incomingParsed.value.match(/\/ipfs\/([a-zA-Z0-9]+)/);
const embeddedCid = embeddedCidMatch?.[1];
if (embeddedCid !== metadataCid) {
  throw new BadRequestException(
    `signedRecord embedded CID does not match metadataCid: ` +
    `embedded=${embeddedCid}, dto=${metadataCid}`
  );
}
```

**S1 offset-aware sequence check pattern** — follows CID check:
```typescript
// S1: embedded-vs-DTO sequence check (offset-aware for first-publish convention)
if (expectedSequenceNumber !== undefined) {
  const expectedSeqBigInt = BigInt(expectedSequenceNumber);
  const isFirstPublish = !existing;
  if (isFirstPublish) {
    // First publish: client signs seq 0n or 1n; accept both
    const diff = incomingParsed.sequence - expectedSeqBigInt;
    if (diff !== 0n && diff !== 1n) {
      throw new BadRequestException(
        `signedRecord sequence does not match expectedSequenceNumber on first publish: ` +
        `embedded=${incomingParsed.sequence}, expected=${expectedSequenceNumber}`
      );
    }
  } else {
    // Subsequent publish: client signs (expectedSequenceNumber + 1)
    const expectedEmbedded = expectedSeqBigInt + 1n;
    if (incomingParsed.sequence !== expectedEmbedded) {
      throw new BadRequestException(
        `signedRecord sequence does not match expectedSequenceNumber: ` +
        `embedded=${incomingParsed.sequence}, expected=${expectedEmbedded}`
      );
    }
  }
}
```

**Error class pattern:** Use `BadRequestException` for embedded-vs-DTO mismatch (400), keep existing `ConflictException` for anti-rollback (409).

---

### `apps/api/src/ipns/ipns.service.spec.ts` (test) — S1 extension

**Analog:** self — existing `describe('upsertFolderIpns (tested through publishRecord)')` at line 384.

**Test structure pattern** (lines 384-485):
```typescript
describe('upsertFolderIpns (tested through publishRecord)', () => {
  it('should create new folder with correct fields', async () => { ... });
  it('should increment sequence number for existing folder', async () => { ... });
  // ADD:
  it('should throw 400 when embedded CID does not match metadataCid', async () => { ... });
  it('should throw 400 when embedded seq mismatches expectedSequenceNumber on update', async () => { ... });
  it('should accept embedded seq 0n or 1n on first publish', async () => { ... });
  it('should pass through when embedded CID and seq match DTO', async () => { ... });
});
```

**Mock pattern for parseIpnsRecord** — the existing `parseIpnsRecord` import is real from `@cipherbox/crypto`; tests must mock it via `jest.mock('@cipherbox/crypto', ...)` or provide a real signed record bytes fixture.

---

### `apps/web/src/services/ipns.service.ts` (service, request-response) — S2

**Analog:** `packages/sdk-core/src/ipns/index.ts:182-239` — the canonical fail-closed behavior web must mirror.

**Current buggy pattern** (lines 177-219 — to be replaced):
```typescript
// BEFORE: swallows verification errors
if (response.signatureV2 && response.data && response.pubKey) {
  try {
    const valid = await verifyIpnsSignature(...);
    if (!valid) {
      logger.warn('[IPNS] Signature verification failed for', ipnsName); // SWALLOWED
    } else {
      // name-binding check also swallowed on error
      signatureVerified = true;
    }
  } catch (verifyError) {
    logger.warn('[IPNS] Signature verification error for', ipnsName, ...); // SWALLOWED
  }
} else {
  logger.warn('[IPNS] IPNS resolve returned without signature data, skipping verification');
}
```

**Target pattern** (mirrors sdk-core lines 196-219):
```typescript
// AFTER (S2 fix): fail-closed on present-but-invalid, allow-on-absent (D-02/D-03)
let signatureVerified = false;
if (response.signatureV2 && response.data && response.pubKey) {
  // D-02: present-but-invalid → throw (no swallowing)
  const valid = await verifyIpnsSignature(
    response.signatureV2,
    response.data,
    response.pubKey
  );
  if (!valid) {
    throw new Error('IPNS signature verification failed - record may be tampered');
  }
  const pubKeyBytes = Uint8Array.from(atob(response.pubKey), (c) => c.charCodeAt(0));
  const derivedName = await deriveIpnsName(pubKeyBytes);
  if (derivedName !== ipnsName) {
    throw new Error('IPNS public key does not match requested name - possible key substitution');
  }
  signatureVerified = true;
} else {
  // D-03: absent fields → allow + flag (signatureVerified stays false)
  logger.warn('[IPNS] IPNS resolve returned without signature data, skipping verification');
}
```

**Outer 404 catch — keep narrow** (lines 212-219 — do not modify):
```typescript
} catch (error) {
  // 404 means IPNS name not found - return null
  // Other errors (including verification) must propagate
  if (error instanceof Error && (error as Error & { status?: number }).status === 404) {
    return null;
  }
  throw error;
}
```

---

### `apps/web/src/services/__tests__/ipns.service.test.ts` (test, NEW) — S2 web

**Analog:** `packages/sdk-core/src/__tests__/ipns.test.ts` — identical mock structure with `vi.mock('@cipherbox/api-client', ...)`, `vi.mock('@cipherbox/core', ...)`, `vi.mock('@cipherbox/crypto', ...)`.

**Mock boilerplate** (from sdk-core ipns.test.ts lines 1-35):
```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolveIpnsRecord } from '../ipns.service';

vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerResolveRecord: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  verifyEd25519: vi.fn(),
  deriveIpnsName: vi.fn(),
  concatBytes: vi.fn((...args: Uint8Array[]) => {
    const total = args.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of args) { result.set(arr, offset); offset += arr.length; }
    return result;
  }),
}));
```

**Required test cases** (the Wave 0 gaps per RESEARCH.md):
```typescript
describe('resolveIpnsRecord', () => {
  it('throws when signature fields present but invalid (D-02)', async () => {
    // Mock: verifyIpnsSignature returns false → expect throw
  });
  it('returns signatureVerified=false when signature fields absent (D-03)', async () => {
    // Mock: response without signatureV2/data/pubKey → expect { signatureVerified: false }
  });
  it('returns null on 404', async () => {
    // Mock: error with status=404 → expect null
  });
  it('propagates non-404 errors (not 404 catch leak)', async () => {
    // Verify verification errors are not silently swallowed
  });
});
```

**File location:** `apps/web/src/services/__tests__/ipns.service.test.ts` (`.test.ts` suffix required — web vitest only includes `*.test.ts`, not `*.spec.ts`).

---

### `packages/sdk-core/src/ipns/index.ts` (service, request-response) — S3

**Analog:** `packages/sdk-core/src/file/index.ts:369-373` — T-47-01 reference implementation.

**T-47-01 reference** (file/index.ts lines 369-373):
```typescript
  } finally {
    // Zeroize the private key on all exit paths (T-47-01 / T-44-12). publishWithCas
    // never zeroes keys; the caller (this function) owns zeroing.
    params.fileIpnsPrivateKey.fill(0);
  }
```

**Apply to `createAndPublishIpnsRecord`** (currently lines 50-98, no try/finally):
```typescript
export async function createAndPublishIpnsRecord(params: { ipnsPrivateKey: Uint8Array; ... }) {
  return withPerf('ipns:publish', async () => {
    try {
      const record = await createIpnsRecord(params.ipnsPrivateKey, ...);
      // ... rest of publish logic ...
    } finally {
      // T-47-01: caller-owns-key convention — zeroize before returning on all exit paths
      params.ipnsPrivateKey.fill(0);
    }
  });
}
```

---

### `packages/sdk-core/src/vault/index.ts` (service, request-response) — S3

**Analog:** `packages/sdk-core/src/file/index.ts:369-373` — same T-47-01 pattern.

**Apply to `publishVaultKeyBlob`** — `vaultKeyKeypair.privateKey` is derived inside the function (buffer-owning boundary), so this function is the terminal consumer:
```typescript
export async function publishVaultKeyBlob(params: { ... }) {
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(params.userPrivateKey);
  try {
    // ... existing publish logic ...
  } finally {
    vaultKeyKeypair.privateKey.fill(0); // T-47-01
  }
}
```

---

### `packages/sdk-core/src/folder/index.ts` (service, request-response) — S3

**Analog:** `packages/sdk-core/src/file/index.ts:369-373` (sibling `updateFileMetadata` DOES zero; `updateFolderMetadataAndPublish` does not — Phase-44 contradiction).

**Prerequisite before adding `fill(0)`:** Audit `packages/sdk/src/client.ts` call sites of `updateFolderMetadataAndPublish`. If the key is not reused after the call returns, add the `finally` block. If reused, document a comment and skip.

**Pattern to apply (if confirmed terminal)**:
```typescript
export async function updateFolderMetadataAndPublish(params: {
  ipnsPrivateKey: Uint8Array;
  folderKey: Uint8Array;
  // ...
}) {
  try {
    // ... existing CAS + publish logic ...
  } finally {
    // T-47-01: zeroize on all exit paths (mirrors updateFileMetadata sibling)
    params.ipnsPrivateKey.fill(0);
    params.folderKey.fill(0);
  }
}
```

---

### `packages/sdk-core/src/__tests__/ipns.test.ts` (test) — S2/S3 extension

**Analog:** self — existing `describe('IPNS operations')` structure.

**Existing mock setup** (lines 1-35) is already correct — extend with new `it()` blocks:
```typescript
// S2 regression — sdk-core already throws (confirm behavior is preserved):
it('throws on present-but-invalid signature (regression guard)', async () => { ... });

// S3 — zeroization:
it('zeroes ipnsPrivateKey after createAndPublishIpnsRecord returns', async () => {
  const key = new Uint8Array(32).fill(5);
  await createAndPublishIpnsRecord({ ipnsPrivateKey: key, ... });
  expect(key.every(b => b === 0)).toBe(true); // T-47-01 guard
});
```

---

### `crates/api-client/src/types.rs` (model, request-response) — S2/D-04

**Analog:** self — `IpnsResolveResponse` at lines 127-137.

**Current struct** (lines 127-137):
```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveResponse {
    pub success: bool,
    pub cid: String,
    pub sequence_number: String,
}
```

**S2 addition — add three optional fields** (camelCase mapping via `rename_all`):
```rust
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpnsResolveResponse {
    pub success: bool,
    pub cid: String,
    pub sequence_number: String,
    // S2: IPNS signature fields (optional — absent for legacy records, D-03)
    pub signature_v2: Option<String>,  // base64 Ed25519 signature (JSON: "signatureV2")
    pub data: Option<String>,           // base64 CBOR data         (JSON: "data")
    pub pub_key: Option<String>,        // base64 raw 32-byte Ed25519 public key (JSON: "pubKey")
}
```

**Serde pitfall:** `rename_all = "camelCase"` maps `signature_v2` → `signatureV2` and `pub_key` → `pubKey`, which matches the API JSON. Verify with a `#[cfg(test)]` deserialization test.

---

### `crates/api-client/src/ipns.rs` (service + test module, request-response) — S2/D-04

**Analog for function structure:** `crates/api-client/src/ipns.rs:14-54` (existing `resolve_ipns` fn) — new `verify_ipns_resolve_signature` follows the same error propagation pattern using `ApiError::DeserializationFailed`.

**Analog for `#[cfg(test)]` module:** `crates/crypto/src/ecies.rs:49-80` and `crates/core/src/ipns.rs:272-316`.

**Core pattern** (from `crates/core/src/ipns.rs:272-316`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_crypto::ed25519::{generate_ed25519_keypair, verify_ed25519};

    #[test]
    fn test_name() {
        // arrange
        // act
        // assert
    }
}
```

**New function to add** (after `publish_ipns`):
```rust
/// Verify the Ed25519 signature on an IPNS resolve response.
///
/// D-02: present-but-invalid → returns Ok(Some(false)); caller must treat as error.
/// D-03: absent fields → returns Ok(None); allow + flag, not fail.
pub fn verify_ipns_resolve_signature(
    resp: &IpnsResolveResponse,
    ipns_name: &str,
) -> Result<Option<bool>, crate::error::ApiError> {
    let (Some(sig_b64), Some(data_b64), Some(pk_b64)) =
        (&resp.signature_v2, &resp.data, &resp.pub_key)
    else {
        return Ok(None); // D-03: absent fields — allow + flag
    };

    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| ApiError::DeserializationFailed("signatureV2 base64 decode failed".into()))?;
    let cbor_data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|_| ApiError::DeserializationFailed("data base64 decode failed".into()))?;
    let pub_key = base64::engine::general_purpose::STANDARD
        .decode(pk_b64)
        .map_err(|_| ApiError::DeserializationFailed("pubKey base64 decode failed".into()))?;

    // Per IPFS IPNS spec: signature covers "ipns-signature:" + cbor_data
    let mut signed_data = Vec::with_capacity(b"ipns-signature:".len() + cbor_data.len());
    signed_data.extend_from_slice(b"ipns-signature:");
    signed_data.extend_from_slice(&cbor_data);

    let valid = cipherbox_crypto::verify_ed25519(&signed_data, &sig, &pub_key);
    if !valid {
        return Ok(Some(false));
    }

    // Verify pubKey derives to the requested ipnsName (key substitution check)
    let derived_name = cipherbox_crypto::derive_ipns_name(&pub_key)
        .map_err(|e| ApiError::DeserializationFailed(format!("IPNS name derivation: {}", e)))?;
    Ok(Some(derived_name == ipns_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IpnsResolveResponse;

    fn make_response(sig: Option<&str>, data: Option<&str>, pk: Option<&str>) -> IpnsResolveResponse {
        IpnsResolveResponse {
            success: true,
            cid: "QmTest".into(),
            sequence_number: "1".into(),
            signature_v2: sig.map(String::from),
            data: data.map(String::from),
            pub_key: pk.map(String::from),
        }
    }

    #[test]
    fn absent_fields_returns_none() {
        let resp = make_response(None, None, None);
        assert!(verify_ipns_resolve_signature(&resp, "k51test").unwrap().is_none());
    }

    #[test]
    fn invalid_signature_returns_some_false() { ... }

    #[test]
    fn valid_signature_returns_some_true() { ... }

    #[test]
    fn deserialize_sig_fields_from_json() {
        // Wave 0 gap: verify camelCase serde mapping works
        let json = r#"{"success":true,"cid":"Qm","sequenceNumber":"1","signatureV2":"abc","data":"def","pubKey":"ghi"}"#;
        let resp: IpnsResolveResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.signature_v2.as_deref(), Some("abc"));
        assert_eq!(resp.pub_key.as_deref(), Some("ghi"));
    }
}
```

**Dependency check:** Confirm `crates/api-client/Cargo.toml` already depends on `cipherbox-crypto`. If not, add `cipherbox-crypto = { workspace = true }` (per research assumption A1).

---

### `crates/crypto/src/ecies.rs` (utility, transform) — S3

**Analog:** `crates/fuse/src/inode.rs:14,105-123` — `Zeroizing<Vec<u8>>` wrapper pattern.

**Current `unwrap_key` return** (line 35-47):
```rust
pub fn unwrap_key(wrapped: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // ...
    ecies::decrypt(private_key, wrapped).map_err(|_| CryptoError::EciesUnwrappingFailed)
}
```

**S3 fix — wrap return value**:
```rust
use zeroize::Zeroizing;

pub fn unwrap_key(wrapped: &[u8], private_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if private_key.len() != SECP256K1_PRIVATE_KEY_SIZE {
        return Err(CryptoError::InvalidPrivateKey);
    }
    if wrapped.len() < ECIES_MIN_CIPHERTEXT_SIZE {
        return Err(CryptoError::EciesUnwrappingFailed);
    }
    ecies::decrypt(private_key, wrapped)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::EciesUnwrappingFailed)
}
```

**Caller audit required:** Changing `unwrap_key` return type affects all call sites in `crates/fuse/src/lib.rs`. `Zeroizing<Vec<u8>>` deref-coerces to `&[u8]` so most slice callers work unchanged. Watch for `let key: Vec<u8> = unwrap_key(...)?.into()` patterns — those require explicit `.into()`.

---

### `crates/fuse/src/lib.rs` (service, request-response) — S2 + S3

**Analog for Zeroizing pattern:** `crates/fuse/src/inode.rs:14,105-123,413-428` — existing `Zeroizing<Vec<u8>>` field declarations and wrapping.

**S3 — `get_folder_key` fix** (lines 933-941):
```rust
// BEFORE
pub fn get_folder_key(&self, folder_ino: u64) -> Option<Vec<u8>> {
    self.inodes.get(folder_ino).and_then(|inode| match &inode.kind {
        inode::InodeKind::Root { .. } => Some(self.root_folder_key.to_vec()),
        inode::InodeKind::Folder { folder_key, .. } => Some(folder_key.to_vec()),
        _ => None,
    })
}

// AFTER
pub fn get_folder_key(&self, folder_ino: u64) -> Option<Zeroizing<Vec<u8>>> {
    self.inodes.get(folder_ino).and_then(|inode| match &inode.kind {
        inode::InodeKind::Root { .. } => Some(Zeroizing::new(self.root_folder_key.to_vec())),
        inode::InodeKind::Folder { folder_key, .. } => Some(Zeroizing::new(folder_key.to_vec())),
        _ => None,
    })
}
```

**S3 — `resolve_folder_key` BFS queue fix** (lines 1612-1652):
```rust
// BEFORE
let mut queue: std::collections::VecDeque<(String, Vec<u8>)> = std::collections::VecDeque::new();
queue.push_back((root_ipns_name.to_string(), root_folder_key.to_vec()));
// ...
let child_folder_key = cipherbox_crypto::ecies::unwrap_key(&enc_key_bytes, private_key)?;
queue.push_back((f.ipns_name.clone(), child_folder_key));

// AFTER
use zeroize::Zeroizing;
let mut queue: std::collections::VecDeque<(String, Zeroizing<Vec<u8>>)> =
    std::collections::VecDeque::new();
queue.push_back((root_ipns_name.to_string(), Zeroizing::new(root_folder_key.to_vec())));
// unwrap_key already returns Zeroizing<Vec<u8>> after ecies.rs fix
// queue.push_back((f.ipns_name.clone(), child_folder_key)); // same, no change needed
```

**S3 — `spawn_file_meta_reencrypt` fix** (line 745-747) — audit for raw Vec<u8> derived from `get_folder_key`; wrap in `Zeroizing::new(...)` if `get_folder_key` return type not yet updated.

**S2 — FUSE callers of `resolve_ipns`** — after adding `verify_ipns_resolve_signature`, callers in `resolve_folder_key` (line 1627) and any other `resolve_ipns` call site must check the returned `sig_verified` flag. Pattern:
```rust
let resolve = cipherbox_api_client::ipns::resolve_ipns(api, &current_ipns).await
    .map_err(|e| format!("resolve IPNS {}: {}", current_ipns, e))?;

// S2: check signature (D-03 absent-fields path is Ok(None) — warn only)
match cipherbox_api_client::ipns::verify_ipns_resolve_signature(&resolve, &current_ipns) {
    Ok(None) => tracing::warn!("IPNS {} resolved without signature data", current_ipns),
    Ok(Some(false)) => return Err(format!("IPNS {} signature verification failed", current_ipns)),
    Ok(Some(true)) => {} // verified
    Err(e) => return Err(format!("IPNS {} signature verify error: {}", current_ipns, e)),
}
```

---

## Shared Patterns

### T-47-01 Key Zeroization (TypeScript)

**Source:** `packages/sdk-core/src/file/index.ts:369-373`
**Apply to:** `sdk-core/src/ipns/index.ts` (`createAndPublishIpnsRecord`), `sdk-core/src/vault/index.ts` (`publishVaultKeyBlob`), `sdk-core/src/folder/index.ts` (`updateFolderMetadataAndPublish` — if confirmed terminal).
```typescript
} finally {
  // T-47-01: caller-owns-key convention — zeroize before returning on all exit paths
  params.ipnsPrivateKey.fill(0);
}
```

### Fail-Closed IPNS Verification (TypeScript)

**Source:** `packages/sdk-core/src/ipns/index.ts:196-219`
**Apply to:** `apps/web/src/services/ipns.service.ts` (S2 — replace swallowing try/catch with rethrow; keep outer 404-only catch).

Canonical behavior: throw on `!valid`, throw on name mismatch, `logger.warn` on absent fields, return `signatureVerified: false` on absent.

### Rust Zeroizing<Vec<u8>> Pattern

**Source:** `crates/fuse/src/inode.rs:14,105-123,413-428`
**Apply to:** `crates/crypto/src/ecies.rs` (`unwrap_key` return), `crates/fuse/src/lib.rs` (`get_folder_key` return, BFS queue type, `spawn_file_meta_reencrypt` key handling).
```rust
use zeroize::Zeroizing;
// Wrap allocations: Zeroizing::new(vec.to_vec()) or Zeroizing::new(some_vec)
// Fields: folder_key: Zeroizing<Vec<u8>>
```

### Rust #[cfg(test)] Module Structure

**Source:** `crates/crypto/src/ecies.rs:49-80` and `crates/core/src/ipns.rs:272-316`
**Apply to:** inline `#[cfg(test)] mod tests { ... }` in `crates/api-client/src/ipns.rs`.
```rust
#[cfg(test)]
mod tests {
    use super::*;
    // import test-only crypto helpers if needed
    #[test]
    fn test_case_name() { /* arrange / act / assert */ }
}
```

### NestJS BadRequestException Pattern

**Source:** `apps/api/src/ipns/ipns.service.ts:4-5` (import) + existing uses in `publishRecord`.
**Apply to:** S1 embedded-vs-DTO checks in `upsertFolderIpns`.
```typescript
import { BadRequestException } from '@nestjs/common';
throw new BadRequestException('descriptive message with embedded vs dto values');
```

---

## No Analog Found

All files have close analogs in the codebase. No entries.

---

## Metadata

**Analog search scope:** `apps/api/src/ipns/`, `apps/web/src/services/`, `packages/sdk-core/src/`, `crates/api-client/src/`, `crates/crypto/src/`, `crates/fuse/src/`, `crates/core/src/`
**Files scanned:** ~15
**Pattern extraction date:** 2026-06-19
