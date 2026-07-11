# Phase 75: Cross-Language IPNS and Node-Codec Verification Parity - Pattern Map

**Mapped:** 2026-07-11
**Files analyzed:** 11
**Analogs found:** 11 / 11 (all are in-place edits to files that already contain the pattern to mirror — this is a parity phase, not a greenfield phase)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `packages/sdk-core/src/ipns/index.ts` (strict RFC3339 parser) | utility (verifier) | transform (parse+validate) | `crates/api-client/src/ipns.rs::parse_rfc3339_to_unix_secs` (lines ~190-261) | exact — line-by-line port target |
| `crates/core/src/ipns.rs::decode_ipns_cbor_validity` | utility (CBOR decoder) | transform | itself, lines 136-165 (extend return type in place) | exact — self-analog, extend signature |
| `packages/sdk-core/src/ipns/index.ts` (Validity/ValidityType read) | service (verifier) | request-response | `crates/api-client/src/ipns.rs::bind_verified` lines 66-140+ (ValidityType gate to add mirrors the Validity-bytes gate already there) | role-match |
| `crates/api-client/src/ipns.rs::bind_verified` (add ValidityType gate) | service (verifier) | request-response | itself — extend in place using the same `Ok`/`Err(VerifyError::Invalid(...))` idiom already used for cid/seq binding | exact — self-analog |
| `crates/fuse/tests/ipns_verify_vectors.rs::classify_vector` | test (KAT consumer) | batch (vector-driven) | `crates/api-client/src/ipns.rs::bind_verified` (the function it hand-duplicates) | exact — dedup target |
| `scripts/gen-ipns-verify-vectors.ts` (new vector cases) | utility (vector generator) | batch | itself — existing 8-case generator, `buildCborData` at lines ~126-134 | exact — self-analog |
| `tests/vectors/ipns/verify.json` (new entries) | config (test fixture) | batch | itself — vector `[0]` (see excerpt below) | exact — self-analog shape |
| `tests/vectors/node-codec.json` (`fileIv` samples) | config (test fixture) | batch | itself — existing `body_vectors[*].node.content.fileIv` / `versions[].fileIv` entries | exact — self-analog shape |
| `crates/core/tests/node_codec_vectors.rs` (new decode-assert) | test (KAT consumer) | batch | itself — `node_codec_round_trips_and_byte_matches_kat` (lines 39-84) | exact — self-analog, add a new assertion block |
| `packages/core/src/__tests__/node-codec-vectors.test.ts` (new decode-assert) | test (KAT consumer) | batch | itself — the "PRIMARY LOCK" `describe` block (lines ~106-130) | exact — self-analog, add a new assertion block |
| `packages/crypto/src/utils/encoding.ts::uuidToBytes` | utility (primitive parser) | transform | `crates/crypto/src/aes.rs` UUID parse at line ~172 (`Uuid::parse_str`) | cross-language twin — tighten both together |
| `crates/crypto/src/aes.rs::build_node_aad` (UUID parse) | service (AEAD AAD builder) | transform | `packages/crypto/src/utils/encoding.ts::uuidToBytes` | cross-language twin |

## Pattern Assignments

### 1. `packages/sdk-core/src/ipns/index.ts` — strict RFC3339 parser (replaces `new Date(...)`)

**Analog:** `crates/api-client/src/ipns.rs::parse_rfc3339_to_unix_secs` (lines 190-261)

**Current Rust parser to port (the parity target):**
```rust
// crates/api-client/src/ipns.rs:190-245 (current, verified)
fn parse_rfc3339_to_unix_secs(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date_part, time_part) = s.split_once('T')?;

    let mut date_parts = date_part.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() { return None; } // reject trailing date components

    let mut dot = time_part.splitn(2, '.');
    let time_no_nanos = dot.next()?;
    if let Some(frac) = dot.next() {
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) { return None; }
    }
    let mut time_parts = time_no_nanos.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let minute: u64 = time_parts.next()?.parse().ok()?;
    let second: u64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() { return None; } // reject trailing time components

    if month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 { return None; }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap { 29 } else { 28 },
        _ => return None,
    };
    if day > days_in_month { return None; }
    // ... Hinnant civil_from_days conversion to unix seconds ...
}
```

**Current TS code to replace:**
```typescript
// packages/sdk-core/src/ipns/index.ts:307-319 (current)
const validityBytes = cborFields['Validity'];
if (!(validityBytes instanceof Uint8Array)) {
  throw new Error('IPNS record has no Validity field — fail closed');
}
const validityStr = new TextDecoder().decode(validityBytes);
const expiryMs = new Date(validityStr).getTime();   // <-- replace this line + surrounding parse
if (isNaN(expiryMs)) {
  throw new Error(`IPNS record has unparseable Validity field: ${validityStr}`);
}
const skewBufferMs = 5 * 60 * 1000; // 5 minutes
if (expiryMs < Date.now() - skewBufferMs) {
  throw new Error(`IPNS record expired: validity=${validityStr}`);
}
```

**Port instructions:** write a `parseRfc3339ToUnixSecs(s: string): number | null` in TS that mirrors every rejection branch above exactly (strip `Z` suffix — reject if absent; split on first `T`; reject >3 dash-separated date parts; reject empty or non-digit fractional seconds; reject >3 colon-separated time parts; validate month/day/hour/minute/second ranges including leap-year day-of-month). Keep the 5-minute skew-buffer comparison logic unchanged, just swap the `new Date(...)` call for this function's output (convert to ms only at the comparison site, matching Rust's whole-seconds internal unit).

---

### 2. `ValidityType == 0` binding — both sides currently ignore it

**Analog for the Rust return-type extension:** `crates/core/src/ipns.rs::decode_ipns_cbor_validity` (lines 136-165, current — extend in place, same file):
```rust
// crates/core/src/ipns.rs:136-165 (current)
pub fn decode_ipns_cbor_validity(data: &[u8]) -> Result<Option<Vec<u8>>, IpnsError> {
    let map: CborValue = ciborium::from_reader(data).map_err(|_| IpnsError::CborEncodingFailed)?;
    let entries = match map {
        CborValue::Map(m) => m,
        _ => return Err(IpnsError::CborEncodingFailed),
    };
    let mut validity_bytes: Option<Vec<u8>> = None;
    for (k, v) in entries {
        let key = match k {
            CborValue::Text(s) => s,
            _ => continue,
        };
        if key == "Validity" {
            if validity_bytes.is_some() {
                return Err(IpnsError::CborEncodingFailed);
            }
            validity_bytes = match v {
                CborValue::Bytes(b) => Some(b),
                _ => return Err(IpnsError::CborEncodingFailed),
            };
        }
    }
    Ok(validity_bytes)
}
```
**Pattern to mirror when adding `ValidityType`:** same loop-and-match idiom, add a parallel `validity_type: Option<i64>` accumulator keyed on `key == "ValidityType"` with the same duplicate-key rejection (`Err(IpnsError::CborEncodingFailed)` if seen twice), matched as `CborValue::Integer(n) => Some(n)`. Change the return type to `Result<(Option<Vec<u8>>, Option<i64>), IpnsError>` (or a small struct) and thread through its one call site.

**Analog for the gate itself (where to add `ValidityType == 0` check):** `crates/api-client/src/ipns.rs::bind_verified`, the existing Validity-bytes gate this new check sits beside:
```rust
// crates/api-client/src/ipns.rs (current bind_verified, Validity extraction block)
let validity_bytes =
    cipherbox_core::ipns::decode_ipns_cbor_validity(&data_bytes)
        .map_err(|e| VerifyError::Invalid(format!("CBOR Validity decode failed: {}", e)))?
        .ok_or_else(|| VerifyError::Invalid("IPNS record has no Validity field — fail closed".to_string()))?;

let validity_str = std::str::from_utf8(&validity_bytes)
    .map_err(|_| VerifyError::Invalid("IPNS Validity is not valid UTF-8".to_string()))?;

let expiry_secs = parse_rfc3339_to_unix_secs(validity_str)
    .ok_or_else(|| VerifyError::Invalid(format!("IPNS Validity parse failed: {}", validity_str)))?;
```
Add the `ValidityType == 0` check as a new `Err(VerifyError::Invalid(format!(...)))` guard in this exact same style, placed before or after the Validity-bytes extraction (both fields come from the same `decode_ipns_cbor_validity` call once its signature is widened).

**TS side — analog is the same file's existing Validity-bytes extraction** (`packages/sdk-core/src/ipns/index.ts:307-319`, shown above in Pattern 1) — add a parallel `cborFields['ValidityType']` read and `=== 0` check using the same `throw new Error(...)` fail-closed idiom already used for the missing-Validity case.

**CBOR field layout both sides already agree on (from the generator, confirming ValidityType is always emitted as 0 today):**
```typescript
// scripts/gen-ipns-verify-vectors.ts:126-134 (buildCborData — current)
return cborEncode({
  TTL: 300000000000,
  Value: new TextEncoder().encode(`/ipfs/${cid}`),
  Sequence: sequenceNumber,
  Validity: new TextEncoder().encode('2099-01-01T00:00:00.000000000Z'),
  ValidityType: 0,
});
```

---

### 3. Vector classifier dedup — `classify_vector` vs `bind_verified`

**Problem file:** `crates/fuse/tests/ipns_verify_vectors.rs::classify_vector` (lines ~64-142) hand-duplicates `crates/api-client/src/ipns.rs::bind_verified`'s binding logic (cid match, seq match — will also need the new ValidityType gate). Its own doc comment admits: *"This is equivalent to `bind_verified(&resp, verdict)` but spelled out explicitly."*

**Visibility blocker to fix first:**
```rust
// crates/api-client/src/ipns.rs (current — must become `pub`)
pub(crate) fn bind_verified(
    resp: &IpnsResolveResponse,
    sig_verdict: Option<bool>,
) -> Result<VerifiedResolve, VerifyError> {
```
Change `pub(crate)` → `pub`. `VerifyError` and `VerifiedResolve` are already `pub`.

**Recommended replacement** — once `pub`, `classify_vector` should become a thin wrapper:
```rust
fn classify_vector(v: &IpnsVerifyVector) -> String {
    let resp = cipherbox_api_client::types::IpnsResolveResponse { /* ...same as today... */ };
    let verdict = match cipherbox_api_client::ipns::verify_ipns_resolve_signature(&resp, &v.ipns_name) {
        Err(_) => return "invalid".to_string(),
        Ok(v) => v,
    };
    match cipherbox_api_client::ipns::bind_verified(&resp, verdict) {
        Ok(_) => "valid".to_string(),
        Err(_) => "invalid".to_string(),
    }
}
```
This deletes the hand-duplicated cid/seq/(new ValidityType) matching block entirely — the exact fix for gap #9 (drift between `bind_verified` and its test-only twin).

---

### 4. New IPNS vectors — `verify.json` shape + generator

**Analog:** existing vector `[0]` in `tests/vectors/ipns/verify.json` (real Ed25519-signed CBOR, do not hand-edit):
```json
{
  "description": "valid — signature, name, cid, and sequence all match",
  "ipns_name": "k51qzi5uqu5djmw2yvf8kk5cdjc1ddc00o4d5sjwi6f79xzcay9j3gkddw5uu4",
  "cid": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "sequence_number": "5",
  "signature_v2": "Mrfkvxcc2SwD1uxzPEzbGiYqZMS9qhh0MCe5sOviTXRddqz46qdaj4WwJkKSvY9VWkK7I2c8k46MhMomGng+AQ==",
  "data": "pWNUVEwbAAAARdlkuABlVmFsdWVYQS9pcGZzL2JhZnliZWlnZHlyenQ1c2ZwN3VkbTdodTc2dWg3eTI2bmYzZWZ1eWxxYWJmM29jbGd0cXk1NWZiemRpaFNlcXVlbmNlBWhWYWxpZGl0eVgeMjA5OS0wMS0wMVQwMDowMDowMC4wMDAwMDAwMDBabFZhbGlkaXR5VHlwZQA=",
  "pub_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
  "expected_result": "valid"
}
```
New cases (`expired`, `wrong-validity-type`, malformed-RFC3339 variants) must be added by extending `scripts/gen-ipns-verify-vectors.ts`'s `buildCborData`-driven generation and re-running `npx tsx scripts/gen-ipns-verify-vectors.ts` — never hand-crafted (signature bytes are real Ed25519 sigs over the exact CBOR bytes).

**Non-vacuous count guards that MUST be updated together** (currently `8`, both must move to the new count in the same commit):
```rust
// crates/fuse/tests/ipns_verify_vectors.rs:165 (current)
assert_eq!(vectors.len(), 8, "Expected exactly 8 IPNS verify vectors");
```
```typescript
// packages/sdk-core/src/__tests__/ipns.test.ts:527 (current)
expect(vectors.length).toBe(8);
```

---

### 5. node-codec KAT `fileIv` decode-and-assert (new assertion, not just a new sample)

**Analog (Rust) — existing hex-round-trip assertion pattern to mirror the style of, in the SAME test function:**
```rust
// crates/core/tests/node_codec_vectors.rs:39-84 (current, node_codec_round_trips_and_byte_matches_kat)
#[test]
fn node_codec_round_trips_and_byte_matches_kat() {
    let vectors = load_vectors();
    assert!(!vectors.body_vectors.is_empty(), "node-codec.json body_vectors must not be empty");
    for v in &vectors.body_vectors {
        let expected_bytes = hex::decode(&v.expected_read_body_hex)
            .unwrap_or_else(|e| panic!("bad hex in {}: {}", v.description, e));
        let decoded = decode_node(&expected_bytes)
            .unwrap_or_else(|e| panic!("decode_node failed for {}: {:?}", v.description, e));
        // ...kind check, re-encode byte-match check...
    }
}
```
**New block to add (mirrors the same `panic!`-with-description idiom, uses `base64::engine::general_purpose::STANDARD` already imported by `ipns_verify_vectors.rs` in this same crate):**
```rust
// pattern to add — decode fileIv as bytes and pin length, not just carry the string
let file_iv_b64 = /* extract v.node.content.fileIv or versions[].fileIv from serde_json::Value */;
let file_iv_bytes = STANDARD.decode(file_iv_b64)
    .unwrap_or_else(|e| panic!("fileIv base64 decode failed for {}: {}", v.description, e));
assert_eq!(file_iv_bytes.len(), v.expected_file_iv_len_bytes, "fileIv byte length mismatch for {}", v.description);
```

**Analog (TS) — existing "PRIMARY LOCK" describe block to add a sibling `it()` inside:**
```typescript
// packages/core/src/__tests__/node-codec-vectors.test.ts:106-130 (current)
describe('Node Codec — Body Bytes PRIMARY LOCK (D-04, NODE-05)', () => {
  it('folder node read-body hex matches frozen vector [0]', () => {
    const vector = VECTORS.body_vectors[0];
    const node = nodeFromFixture(vector.node as Record<string, unknown>);
    expect(toHex(encodeReadBody(node))).toBe(vector.expected_read_body_hex);
  });
  // ...
});
```
**New `it()` to add in the same style, using the project's existing `base64ToBytes` helper (same one used in production at `apps/web/src/services/download.service.ts:128` / `packages/sdk-core/src/file/index.ts:414`):**
```typescript
it('fileIv decodes to the expected byte length (base64, not hex) for vector [N]', () => {
  const vector = VECTORS.body_vectors[N];
  const fileIvB64 = (vector.node as any).content.fileIv as string;
  const decoded = base64ToBytes(fileIvB64);
  expect(decoded.length).toBe(vector.expected_file_iv_len_bytes);
});
```

**Current `fileIv` sample values to replace (encoding-ambiguous today — valid as BOTH hex and base64):**
```
tests/vectors/node-codec.json:25   "fileIv": "000102030405060708090a0b"
tests/vectors/node-codec.json:34   "fileIv": "0a0b0c0d0e0f101112131415"
tests/vectors/node-codec.json:56   "fileIv": "111213141516171819202122"
tests/vectors/node-codec.json:65   "fileIv": "1c1d1e1f20212223242526272829"
```
Per RESEARCH.md Pattern 3, pick GCM samples (12 bytes) whose base64 encoding contains at least one non-hex character (verify programmatically, don't hand-derive), and CTR samples (16 bytes, naturally `==`-padded and thus already hex-invalid). Add a new `expected_file_iv_len_bytes` field per vector (12 for GCM, 16 for CTR) alongside `expected_read_body_hex`.

**Scope note:** do NOT touch `tests/vectors/crypto/node-aad.json`'s `seal_vectors[0].iv` or `node-codec.json`'s `seal_vectors[0].fixed_iv` (both `"000102030405060708090a0b"`) — those are decoded exclusively via `fromHex()`/`hex::decode()` in `node-codec-vectors.test.ts:145` and `build-node-aad.test.ts:357-358`, no base64 path exists for them, per RESEARCH.md Pattern 3.

---

### 6. UUID canonical-form tightening (Option A) — cross-language twin

**Current TS (too loose — accepts simple-32-hex):**
```typescript
// packages/crypto/src/utils/encoding.ts:58-64 (current)
export function uuidToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');          // strips ALL hyphens regardless of position
  if (!/^[0-9a-fA-F]{32}$/.test(clean)) {
    throw new CryptoError('Malformed UUID', 'INVALID_AAD_INPUT');
  }
  return hexToBytes(clean);
}
```
**Recommended tightened form** (canonical-form regex checked BEFORE hyphen-stripping, so loose-hyphen and no-hyphen forms are rejected):
```typescript
export function uuidToBytes(uuid: string): Uint8Array {
  if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(uuid)) {
    throw new CryptoError('Malformed UUID', 'INVALID_AAD_INPUT');
  }
  return hexToBytes(uuid.replace(/-/g, ''));
}
```

**Current Rust (too loose in the other direction — accepts braced/urn/simple via the `uuid` crate):**
```rust
// crates/crypto/src/aes.rs:172 (current)
let uuid = Uuid::parse_str(node_id).map_err(|_| CryptoError::InvalidAadInput)?;
```
**Recommended tightened form** — add an explicit canonical-form pre-check (same regex shape as TS) before delegating to `Uuid::parse_str`:
```rust
static CANONICAL_UUID_RE: once_cell::sync::Lazy<regex::Regex> = /* or inline byte-position check */
    once_cell::sync::Lazy::new(|| regex::Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ).unwrap());
if !CANONICAL_UUID_RE.is_match(node_id) {
    return Err(CryptoError::InvalidAadInput);
}
let uuid = Uuid::parse_str(node_id).map_err(|_| CryptoError::InvalidAadInput)?;
```
(Check `Cargo.toml`/`Cargo.lock` for whether `regex`/`once_cell` are already workspace deps before adding one; a hand-rolled byte-position check avoids a new dependency if they are not — RESEARCH.md's "Don't Hand-Roll" table does not flag either as pre-approved, so prefer the dependency-free version unless `regex` is already present in `crates/crypto`.)

**Verified safe:** no production call site or existing test in this repo passes a non-canonical form (`crypto.randomUUID()` / `generate_uuid_v4()` always produce canonical lowercase-hyphenated output) — see RESEARCH.md Pattern 4.

---

## Shared Patterns

### Shared JSON vector as the parity oracle
**Source:** `crates/fuse/tests/ipns_verify_vectors.rs` (loader helper `load_vectors`, lines 20-38) / `crates/core/tests/node_codec_vectors.rs` (loader, lines 15-37)
**Apply to:** every new/extended vector file in this phase (`ipns/verify.json`, `node-codec.json`, and any new `uuid-acceptance.json`/extended `node-aad.json`)
```rust
fn vectors_path(subpath: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/vectors");
    p.push(subpath);
    p
}
fn load_vectors<T: serde::de::DeserializeOwned>(filename: &str) -> Vec<T> {
    let path = vectors_path(filename);
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap()
}
```

### Fail-closed error idiom (Rust)
**Source:** `crates/api-client/src/ipns.rs::bind_verified` — every rejection path returns `Err(VerifyError::Invalid(format!("...: {}", detail)))` with a description string that names the specific mismatch (cid/seq/validity). Apply this exact style to the new ValidityType and UUID-canonical-form rejections.

### Fail-closed error idiom (TS)
**Source:** `packages/sdk-core/src/ipns/index.ts` — every rejection path `throw new Error('...: fail closed')` or with an interpolated detail. Apply the same style to the new ValidityType gate and strict-RFC3339 rejection.

### Non-vacuous vector-count guard
**Source:** `crates/fuse/tests/ipns_verify_vectors.rs:165` (`assert_eq!(vectors.len(), 8, ...)`) / `crates/core/tests/node_codec_vectors.rs:44-48` ("Non-vacuous vector-count guard" comment) / `packages/sdk-core/src/__tests__/ipns.test.ts:527` (`expect(vectors.length).toBe(8)`)
**Apply to:** any file where new vectors are added — update the hard-coded count in the SAME commit as the generator extension, on both language sides.

## No Analog Found

None — every file in this phase's manifest already contains the code to extend or a directly cross-referenced twin in the other language. This is expected for a parity-hardening phase (no new architecture, only tightening existing logic to match its counterpart).

## Metadata

**Analog search scope:** `crates/core/src/ipns.rs`, `crates/api-client/src/ipns.rs`, `crates/fuse/tests/ipns_verify_vectors.rs`, `crates/core/tests/node_codec_vectors.rs`, `crates/crypto/src/aes.rs`, `packages/sdk-core/src/ipns/index.ts`, `packages/core/src/__tests__/node-codec-vectors.test.ts`, `packages/crypto/src/utils/encoding.ts`, `scripts/gen-ipns-verify-vectors.ts`, `tests/vectors/ipns/verify.json`, `tests/vectors/node-codec.json`
**Files scanned:** 11 (all read directly this session; RESEARCH.md's prior session reads supplied the remaining excerpts reused verbatim below where line ranges matched)
**Pattern extraction date:** 2026-07-11
