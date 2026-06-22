# Phase 58: IPNS Signature-Verify Coverage - Pattern Map

**Mapped:** 2026-06-22
**Files analyzed:** 12 new/modified files
**Analogs found:** 11 / 12

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `crates/core/src/ipns.rs` (modify) | utility | transform | self (`build_cbor_data` in same file) | exact |
| `crates/fuse/src/verify.rs` (NEW) | service | request-response | `crates/fuse/src/replay.rs` lines 333-364 | role-match |
| `crates/fuse/src/events.rs` (modify) | service | request-response | `crates/fuse/src/replay.rs` lines 333-364 | role-match |
| `crates/fuse/src/fs.rs` (modify) | service | request-response | `crates/fuse/src/replay.rs` lines 333-364 | role-match |
| `crates/fuse/src/publish.rs` (modify) | service | request-response | `crates/fuse/src/replay.rs` lines 333-364 | role-match |
| `crates/fuse/src/metadata.rs` (modify) | service | request-response | `crates/fuse/src/replay.rs` lines 333-364 | role-match |
| `crates/fuse/src/replay.rs` (modify) | service | request-response | self (parent-IPNS merge reroute) | exact |
| `packages/sdk-core/src/ipns/index.ts` (modify) | service | request-response | self (`resolveIpnsRecord` extension) | exact |
| `apps/web/src/services/ipns.service.ts` (modify) | service | request-response | `packages/sdk-core/src/ipns/index.ts` lines 195-261 | exact |
| `apps/api/src/ipns/ipns.service.ts` (modify) | service | CRUD | self (`upsertFolderIpns` lines 258-297) | exact |
| `apps/api/src/ipns/ipns.service.spec.ts` (modify) | test | CRUD | self (existing test file) | exact |
| `tests/vectors/ipns/verify.json` (NEW) | config | transform | `tests/vectors/crypto/aes-gcm.json` + `cross_language.rs` convention | role-match |
| `crates/crypto/tests/cross_language.rs` (modify) | test | transform | self (existing test fns in same file) | exact |
| `packages/sdk-core/src/__tests__/ipns.test.ts` (modify) | test | request-response | self (existing test file lines 1-80) | exact |

## Pattern Assignments

### `crates/core/src/ipns.rs` — `decode_ipns_cbor_data` helper (modify)

**Analog:** `crates/core/src/ipns.rs` `build_cbor_data` (lines 68-104)

**Imports pattern** (lines 1-17 — already present, no new imports needed):

```rust
use ciborium::Value as CborValue;
use thiserror::Error;
```

**Core CBOR encode pattern to mirror** (lines 72-104):

```rust
fn build_cbor_data(value: &str, validity: &str, sequence: u64, ttl: u64)
    -> Result<Vec<u8>, IpnsError>
{
    let cbor_map = CborValue::Map(vec![
        (CborValue::Text("TTL".to_string()),      CborValue::Integer(ttl.into())),
        (CborValue::Text("Value".to_string()),     CborValue::Bytes(value.as_bytes().to_vec())),
        (CborValue::Text("Sequence".to_string()),  CborValue::Integer(sequence.into())),
        (CborValue::Text("Validity".to_string()),  CborValue::Bytes(validity.as_bytes().to_vec())),
        (CborValue::Text("ValidityType".to_string()), CborValue::Integer(0.into())),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cbor_map, &mut buf).map_err(|_| IpnsError::CborEncodingFailed)?;
    Ok(buf)
}
```

**Decode pattern (new `decode_ipns_cbor_data` — mirror with inverse operations):**

- Use `ciborium::from_reader(data)` → `CborValue` (inverse of `ciborium::into_writer`).
- Match `CborValue::Map(m)`, iterate entries.
- `"Value"` key → `CborValue::Bytes(b)` (NOT `CborValue::Text` — confirmed from build side line 85).
- `"Sequence"` key → `CborValue::Integer(i)`: extract via `let raw: i128 = i.into(); u64::try_from(raw)`.
- Missing fields → `IpnsError::CborEncodingFailed` (same error variant used throughout this file).

**Error type** (lines 30-43 — reuse existing):

```rust
pub enum IpnsError {
    #[error("CBOR encoding failed")]
    CborEncodingFailed,
    // ... other existing variants
}
```

---

### `crates/fuse/src/verify.rs` — `resolve_ipns_verified` chokepoint (NEW file)

**Analog:** `crates/fuse/src/replay.rs` lines 333-364 (`resolve_folder_key` verify block)

**Imports pattern** (mirror from replay.rs usage):

```rust
use cipherbox_api_client::client::ApiClient;
use cipherbox_api_client::error::ApiError;
use cipherbox_api_client::ipns::{resolve_ipns, verify_ipns_resolve_signature};
use cipherbox_core::ipns::decode_ipns_cbor_data;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
```

**Core pattern — the verify match block to replicate** (`crates/fuse/src/replay.rs` lines 333-364):

```rust
let resolve = cipherbox_api_client::ipns::resolve_ipns(api, &current_ipns)
    .await
    .map_err(|e| format!("resolve IPNS {}: {}", current_ipns, e))?;

match cipherbox_api_client::ipns::verify_ipns_resolve_signature(&resolve, &current_ipns) {
    Ok(None) => {
        log::warn!(
            "resolve_folder_key: IPNS {} resolved without signature fields — \
             proceeding (D-03, DB CID authoritative)",
            current_ipns
        );
    }
    Ok(Some(true)) => {
        // Signature valid and IPNS name matches — proceed.
    }
    Ok(Some(false)) => {
        return Err(format!(
            "IPNS {} signature verification failed — refusing to use CID (D-02)",
            current_ipns
        ));
    }
    Err(e) => {
        return Err(format!(
            "IPNS {} signature verification error: {} — refusing to use CID",
            current_ipns, e
        ));
    }
}
```

**New wrapper — extend this pattern with CBOR binding after `Ok(Some(true))`:**

- After `Ok(Some(true))`: decode `resp.data` from base64 (`STANDARD.decode`) → call `decode_ipns_cbor_data` → compare `embedded_value == format!("/ipfs/{}", resp.cid)` and `embedded_seq == resp.sequence_number.parse::<u64>()`.
- On mismatch: map to `VerifyError::Invalid(...)` — same handling as `Ok(Some(false))`.
- `Ok(None)` → `VerifyError::Legacy` — callers warn + proceed with `resp.cid` (D-04).
- `ApiError` from `resolve_ipns` → `VerifyError::Api(e)` — propagate.

**Error enum (new, in `verify.rs`):**

```rust
pub enum VerifyError {
    Api(ApiError),
    Legacy,           // all-absent fields (D-04); callers warn + proceed
    Invalid(String),  // invalid/partial sig or CborMismatch — callers fail-closed (D-02)
}

pub struct VerifiedResolve {
    pub cid: String,            // from signed CBOR data (D-08 authoritative)
    pub sequence_number: u64,   // from signed CBOR data (D-08 authoritative)
    pub signature_verified: bool,
}
```

---

### `crates/fuse/src/{events,fs,publish,metadata,replay}.rs` — call-site routing (modify)

**Analog:** `crates/fuse/src/replay.rs` lines 333-364 (the resolved site that already calls `verify_ipns_resolve_signature`).

**Pattern for each of the 8 unverified sites:** Replace the bare `resolve_ipns(api, name).await?` call with `resolve_ipns_verified(api, name).await` and handle the `VerifyError` variants:

```rust
// Before (bare, unverified — pattern at e.g. events.rs:89, fs.rs:490, etc.):
let resolve = cipherbox_api_client::ipns::resolve_ipns(api, ipns_name).await?;
// ... use resolve.cid directly

// After:
use crate::verify::{resolve_ipns_verified, VerifyError};
let verified = match resolve_ipns_verified(api, ipns_name).await {
    Ok(v) => v,
    Err(VerifyError::Legacy) => {
        log::warn!("IPNS {} resolved without signature — using DB CID (D-04)", ipns_name);
        // construct a VerifiedResolve-equivalent from the raw resp for Legacy path
        // (or re-call resolve_ipns to get the cid — see Pitfall 5 in RESEARCH.md)
        return <appropriate per-operation error or stale-state result>;
    }
    Err(VerifyError::Invalid(msg)) => {
        log::warn!("IPNS {} verify failed: {} — failing operation (D-02)", ipns_name, msg);
        return <appropriate per-operation error>;
    }
    Err(VerifyError::Api(e)) => return Err(e.into()),
};
// use verified.cid (not the raw resolve.cid)
```

**D-03 exception — `replay.rs` `resolve_folder_key` (lines 341-364):** This site keeps its current verbatim match arms, only substituting the `resolve_ipns_verified` wrapper call in place of the two-step `resolve_ipns` + `verify_ipns_resolve_signature`. The existing `Ok(None)` warn-and-continue arm is D-03 compliant and must not become hard fail-closed.

---

### `packages/sdk-core/src/ipns/index.ts` — CBOR binding extension (modify)

**Analog:** self (lines 195-261 — the existing `resolveIpnsRecord` function).

**Existing verify block to extend** (lines 217-238):

```typescript
if (hasSignatureV2 || hasData || hasPubKey) {
  if (!hasSignatureV2 || !hasData || !hasPubKey || !signatureV2 || !data || !pubKey) {
    throw new Error('IPNS resolve returned incomplete signature data - record cannot be verified');
  }

  const valid = await verifyIpnsSignature(signatureV2, data, pubKey);
  if (!valid) {
    throw new Error('IPNS signature verification failed - record may be tampered');
  }

  const pubKeyBytes = Uint8Array.from(atob(pubKey), (c) => c.charCodeAt(0));
  const derivedName = await deriveIpnsName(pubKeyBytes);
  if (derivedName !== ipnsName) {
    throw new Error('IPNS public key does not match requested name - possible key substitution');
  }

  signatureVerified = true;
  // D-08: INSERT CBOR binding check HERE, after signatureVerified = true
}
```

**CBOR binding addition** (insert after `signatureVerified = true`, before closing `}`):

```typescript
// D-07/D-08: decode CBOR data and bind embedded cid/sequence to response fields
// Import: import { decode as cborDecode } from 'cborg'  (fallback; see RESEARCH.md Pitfall 3)
const dataBytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
// parseCborData from 'ipns/dist/src/utils.js' OR cborDecode from 'cborg'
const cborData = parseCborData(dataBytes); // returns { Value: Uint8Array, Sequence: bigint, ... }
const embeddedValue = new TextDecoder().decode(cborData.Value).trim();
const embeddedSeq = cborData.Sequence; // bigint
const expectedValue = `/ipfs/${response.cid}`;
if (embeddedValue !== expectedValue) {
  throw new Error(
    `IPNS cid binding mismatch: embedded=${embeddedValue}, response cid=${response.cid}`
  );
}
if (embeddedSeq !== BigInt(response.sequenceNumber)) {
  throw new Error(
    `IPNS sequence binding mismatch: embedded=${embeddedSeq}, response seq=${response.sequenceNumber}`
  );
}
```

**Error handling pattern** (lines 248-259 — unchanged; both binding errors propagate through the existing `catch` block):

```typescript
} catch (error) {
  if (error instanceof Error) {
    const anyError = error as Error & { status?: number; response?: { status?: number } };
    const status = anyError.status ?? anyError.response?.status;
    if (status === 404) { return null; }
  }
  throw error;
}
```

**`withPerf` wrapper** (lines 199): the sdk-core version already wraps in `withPerf('ipns:resolve', ...)`. The web version (analog below) also uses this wrapper — keep both.

---

### `apps/web/src/services/ipns.service.ts` — dedup (D-13) (modify)

**Analog:** `packages/sdk-core/src/ipns/index.ts` lines 195-261 (the function being imported).

**Current web pattern to DELETE** (`apps/web/src/services/ipns.service.ts` lines 139-231):

- `verifyIpnsSignature` function (lines 139-151): delete entirely.
- `resolveIpnsRecord` function (lines 163-230): delete the function body, replace with an import.

**Seam to PRESERVE** (web `resolveIpnsRecord` lines 163-167 and 163, the `withPerf` wrapper):

```typescript
// web ipns.service.ts currently (lines 163-165, wrapper absent — verify against live source):
export async function resolveIpnsRecord(
  ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
```

The web version does NOT currently have `withPerf` around its `resolveIpnsRecord` (the sdk-core version does). Confirm before deleting. The `ctx.axiosInstance` injection seam: sdk-core `resolveIpnsRecord` already accepts `ctx?: SdkContext` (line 197) — the web caller must pass its axios instance via that arg.

**Replacement import pattern:**

```typescript
import { resolveIpnsRecord } from '@cipherbox/sdk-core';
// Then call with ctx:
const result = await withPerf('ipns:resolve', () =>
  resolveIpnsRecord(ipnsName, { axiosInstance: ctx.axiosInstance })
);
```

---

### `apps/api/src/ipns/ipns.service.ts` — D-09 non-CAS gate (modify)

**Analog:** self (lines 258-297 — the block being replaced).

**Current gated block** (lines 274-297):

```typescript
// S1 sequence check — CURRENTLY only when expectedSequenceNumber given (line 277):
if (expectedSequenceNumber !== undefined) {
  const expectedSeqBigInt = BigInt(expectedSequenceNumber);
  const isFirstPublish = !existing;
  if (isFirstPublish) {
    const diff = incomingParsed.sequence - expectedSeqBigInt;
    if (diff !== 0n && diff !== 1n) {
      throw new BadRequestException(`signedRecord sequence does not match...`);
    }
  } else {
    const expectedEmbedded = expectedSeqBigInt + 1n;
    if (incomingParsed.sequence !== expectedEmbedded) {
      throw new BadRequestException(`signedRecord sequence does not match...`);
    }
  }
}
```

**DB update block to also modify** (lines 299-306 — must skip sequence increment when idempotent):

```typescript
if (existing) {
  // ...
  existing.latestCid = metadataCid;
  existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString(); // ← must be conditional
  existing.signedRecord = Buffer.from(signedRecord);
```

**D-09 replacement (replace lines 277-297, introduce `isIdempotentRepublish`):**

```typescript
// D-09: unconditional embedded-sequence gate (replaces the CAS-gated block)
const embeddedSeq = incomingParsed.sequence; // bigint from parseIpnsRecord
let isIdempotentRepublish = false;
if (!existing) {
  // First publish: allow 0n or 1n only
  if (embeddedSeq !== 0n && embeddedSeq !== 1n) {
    throw new BadRequestException(
      `First publish: embedded sequence must be 0 or 1, got ${embeddedSeq}`
    );
  }
} else {
  const dbSeq = BigInt(existing.sequenceNumber);
  if (embeddedSeq === dbSeq) {
    isIdempotentRepublish = true; // TEE re-sign path — do NOT increment DB (Pitfall 4)
  } else if (embeddedSeq === dbSeq + 1n) {
    // Normal forward publish — increment allowed
  } else if (embeddedSeq < dbSeq) {
    throw new BadRequestException(
      `Rollback rejected: embedded sequence ${embeddedSeq} < stored ${dbSeq}`
    );
  } else {
    throw new BadRequestException(
      `Sequence jump rejected: embedded ${embeddedSeq}, expected ${dbSeq + 1n}`
    );
  }
}
```

**Idempotent no-increment** (modify line 306 within the `existing` update block):

```typescript
// Skip increment when idempotent (TEE re-sign path):
if (!isIdempotentRepublish) {
  existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString();
}
// latestCid and signedRecord still updated (Pitfall 4 — must not skip these):
existing.latestCid = metadataCid;
existing.signedRecord = Buffer.from(signedRecord);
```

---

### `apps/api/src/ipns/ipns.service.spec.ts` — D-09 tests (modify)

**Analog:** existing test file (mock-based jest + NestJS `BadRequestException` pattern — mirror existing describe blocks in same file).

**Test structure pattern** (from existing spec convention in the api suite):

```typescript
describe('upsertFolderIpns D-09 embedded-sequence gate', () => {
  it('rejects first publish with embedded sequence > 1', async () => { ... });
  it('allows first publish with embedded sequence 0', async () => { ... });
  it('allows first publish with embedded sequence 1', async () => { ... });
  it('allows idempotent republish (embedded = DB seq) without incrementing', async () => { ... });
  it('allows forward publish (embedded = DB seq + 1)', async () => { ... });
  it('rejects rollback (embedded < DB seq)', async () => { ... });
  it('rejects wild jump (embedded > DB seq + 1)', async () => { ... });
});
```

---

### `tests/vectors/ipns/verify.json` (NEW)

**Analog:** `tests/vectors/crypto/aes-gcm.json` (same directory convention; JSON array of objects).

**Consumption analog:** `crates/crypto/tests/cross_language.rs` lines 20-25:

```rust
fn load_vectors<T: serde::de::DeserializeOwned>(filename: &str) -> Vec<T> {
    let path = vectors_path(filename);  // resolves to ../../tests/vectors/<filename>
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap()
}
// Call: load_vectors("ipns/verify.json")
```

**Required fields per vector entry** (matches `IpnsResolveResponse` fields in api-client):

```json
{
  "description": "valid — signature, name, cid, and sequence all match",
  "ipns_name": "k51...",
  "public_key": "<hex 32 bytes>",
  "private_key": "<hex 32 bytes>",
  "cid": "bafy...",
  "sequence_number": "5",
  "signature_v2": "<base64 64 bytes>",
  "data": "<base64 CBOR bytes>",
  "pub_key": "<base64 32 bytes>",
  "expected_result": "valid"
}
```

**Seven required cases (D-11):** `valid`, `tampered-sig`, `name-mismatch`, `cid-swapped`, `seq-mismatch`, `partial-fields`, `legacy-absent`.

---

### `crates/crypto/tests/cross_language.rs` — `ipns_verify_cross_language` test (modify)

**Analog:** `ed25519_cross_language` test in same file (lines 89-125).

**Pattern to mirror exactly:**

```rust
#[derive(Deserialize)]
struct Ed25519Vector {
    #[allow(dead_code)]
    description: String,
    private_key: String,
    // ... fields
}

#[test]
fn ed25519_cross_language() {
    let vectors: Vec<Ed25519Vector> = load_vectors("crypto/ed25519.json");
    assert!(!vectors.is_empty(), "No Ed25519 vectors loaded");
    for v in &vectors {
        // ... assertions with v.description in failure messages
        assert_eq!(result, expected, "mismatch for: {}", v.description);
    }
}
```

**New test function (same file, new section):**

```rust
#[derive(Deserialize)]
struct IpnsVerifyVector {
    #[allow(dead_code)]
    description: String,
    ipns_name: String,
    cid: String,
    sequence_number: String,
    signature_v2: Option<String>,
    data: Option<String>,
    pub_key: Option<String>,
    expected_result: String, // "valid" | "invalid" | "legacy"
}

#[test]
fn ipns_verify_cross_language() {
    let vectors: Vec<IpnsVerifyVector> = load_vectors("ipns/verify.json");
    assert!(!vectors.is_empty(), "No IPNS verify vectors loaded");
    // Build mock IpnsResolveResponse, call verify_ipns_resolve_signature
    // + decode_ipns_cbor_data, assert expected_result
}
```

---

### `packages/sdk-core/src/__tests__/ipns.test.ts` — CBOR binding tests (modify)

**Analog:** self (lines 1-80 — existing mock-based vitest structure).

**Mock pattern to extend** (lines 1-33):

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolveIpnsRecord } from '../ipns';

vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerResolveRecord: vi.fn(),
}));
vi.mock('@cipherbox/crypto', () => ({
  verifyEd25519: vi.fn().mockResolvedValue(true),
  deriveIpnsName: vi.fn().mockResolvedValue('k51resolve'),
  concatBytes: vi.fn(/* ... real impl */),
}));
```

**New test cases (append to existing `describe('IPNS operations')`):**

```typescript
describe('resolveIpnsRecord CBOR binding', () => {
  it('throws on cid-swapped record (D-07)', async () => {
    // mock response: valid sig but data CBOR encodes /ipfs/bafy_DIFFERENT
    // expect: throw matching 'IPNS cid binding mismatch'
  });
  it('throws on seq-mismatch record (D-07)', async () => {
    // mock response: valid sig, cid matches, but CBOR Sequence != response.sequenceNumber
    // expect: throw matching 'IPNS sequence binding mismatch'
  });
  it('accepts valid record after binding check (D-08)', async () => { ... });
});
```

**Vector-driven test (load shared JSON):**

```typescript
import vectors from '../../../tests/vectors/ipns/verify.json';
// For each vector: construct mock response, call resolveIpnsRecord, assert result
```

---

## Shared Patterns

### Rust: `resolve_ipns` + `verify_ipns_resolve_signature` call sequence

**Source:** `crates/fuse/src/replay.rs` lines 333-364 and `crates/api-client/src/ipns.rs` lines 14-51 + 66-125

**Apply to:** `crates/fuse/src/verify.rs` (new chokepoint) and all 8 unverified FUSE call sites routed through it.

```rust
// resolve_ipns signature (api-client/src/ipns.rs:14-17):
pub async fn resolve_ipns(client: &ApiClient, ipns_name: &str) -> Result<IpnsResolveResponse, ApiError>

// verify_ipns_resolve_signature signature (api-client/src/ipns.rs:66-69):
pub fn verify_ipns_resolve_signature(
    resp: &IpnsResolveResponse,
    ipns_name: &str,
) -> Result<Option<bool>, ApiError>
// Returns: Ok(None) = legacy, Ok(Some(true)) = valid, Ok(Some(false)) = invalid, Err = decode error
```

### TypeScript: base64 decode pattern

**Source:** `packages/sdk-core/src/ipns/index.ts` lines 176-178 and `apps/web/src/services/ipns.service.ts` lines 144-146

**Apply to:** CBOR binding decode in both `resolveIpnsRecord` (sdk-core) and any test mock constructing CBOR bytes.

```typescript
// Consistent base64 decode idiom used everywhere in IPNS code:
const bytes = Uint8Array.from(atob(base64String), (c) => c.charCodeAt(0));
```

### TypeScript: 404 vs error propagation in `resolveIpnsRecord`

**Source:** `packages/sdk-core/src/ipns/index.ts` lines 248-259

**Apply to:** Keep this block unchanged in both sdk-core and web versions — D-07/D-08 binding errors must NOT be swallowed as 404.

```typescript
} catch (error) {
  if (error instanceof Error) {
    const anyError = error as Error & { status?: number; response?: { status?: number } };
    const status = anyError.status ?? anyError.response?.status;
    if (status === 404) { return null; }
  }
  throw error; // signature/binding errors propagate (D-02 scoped fail-closed)
}
```

### TypeScript: `incomingParsed` single-parse guard

**Source:** `apps/api/src/ipns/ipns.service.ts` lines 261-263

**Apply to:** D-09 gate in `upsertFolderIpns` — do NOT call `parseIpnsRecord` a second time; reuse the `incomingParsed` already set by the S1 CID check.

```typescript
if (incomingParsed === null) {
  incomingParsed = await parseIpnsRecord(signedRecord);
}
```

### Rust: `load_vectors` + `#[derive(Deserialize)]` struct per domain

**Source:** `crates/crypto/tests/cross_language.rs` lines 12-25 and 31-39

**Apply to:** New `IpnsVerifyVector` struct and `ipns_verify_cross_language` test in same file.

```rust
fn load_vectors<T: serde::de::DeserializeOwned>(filename: &str) -> Vec<T> {
    let path = vectors_path(filename); // CARGO_MANIFEST_DIR/../../tests/vectors/<filename>
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap()
}
// Usage: load_vectors("ipns/verify.json")
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
| --- | --- | --- | --- |
| `tests/vectors/ipns/verify.json` (content) | config | transform | Vector content must be generated offline (Node.js script using `@cipherbox/core createIpnsRecord` + `marshalIpnsRecord`); no existing analog for the signed IPNS byte values themselves |

## Critical Pitfalls (from RESEARCH.md — planner must embed in task actions)

1. **CBOR `Value` field is `CborValue::Bytes`, not `CborValue::Text`** — confirmed from `build_cbor_data` line 85. Match arm must be `CborValue::Bytes(b)`.
2. **`ciborium::Integer` → u64 is two-step:** `let raw: i128 = i.into(); u64::try_from(raw)?`.
3. **`parseCborData` not re-exported from `ipns` index** — import from `'ipns/dist/src/utils.js'` directly or use `import { decode } from 'cborg'`. Wave-0 probe required: `node --input-type=module -e "import { parseCborData } from 'ipns'; console.log(typeof parseCborData)"`.
4. **D-09 idempotent path must still update `latestCid`** — only `sequenceNumber` increment is skipped; `latestCid` and `signedRecord` still written.
5. **`IpnsResolveResponse.data` is not returned from `verify_ipns_resolve_signature`** — `resolve_ipns_verified` must base64-decode `resp.data` itself before calling `decode_ipns_cbor_data` (Option B from RESEARCH.md).
6. **`sequence_number` is a `String` in `IpnsResolveResponse`** — parse via `resp.sequence_number.parse::<u64>()` for comparison.

## Metadata

**Analog search scope:** `crates/`, `packages/sdk-core/src/`, `apps/api/src/`, `apps/web/src/`, `tests/vectors/`, `crates/crypto/tests/`
**Files scanned:** 10 source files read directly
**Pattern extraction date:** 2026-06-22

---

## PATTERN MAPPING COMPLETE
