# Phase 60: IPNS Verification Cross-Layer Closeout — Pattern Map

**Mapped:** 2026-06-24
**Files analyzed:** 14 change sites across 6 pattern groups
**Analogs found:** 6 / 6

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/api-client/src/ipns.rs` (new verified-resolve section) | utility/middleware | request-response | `crates/fuse/src/verify.rs` (entire file being relocated) | exact |
| `crates/fuse/src/verify.rs` (deleted / thin re-export) | utility | request-response | self (source file being moved) | exact |
| `crates/fuse/tests/ipns_verify_vectors.rs` (update classifier) | test | transform | self (existing classifier at lines 88-90, 134) | exact |
| `packages/sdk-core/src/ipns/index.ts` (remove legacy-else + skew disjunct + add expiry) | utility | request-response | self (existing gate at lines 218-239 is the strict pattern to extend) | exact |
| `packages/crypto/src/ipns/verify-record.ts` (EOL already present; resolve path must call it) | utility | request-response | self (validate() call at line 48 is the EOL-aware pattern to reuse) | exact |
| `apps/api/src/ipns/ipns-record.codec.ts` (null-signed-record + seq-override) | service | CRUD | self (parseCachedRecord lines 53-83; strict fallthrough is the pattern) | exact |
| `apps/api/src/ipns/ipns.service.ts` (first-publish gate + enrich removal) | service | CRUD | self (anchor at lines 87-89; gate at lines 279-285) | exact |
| 9 embed-0 → embed-1 producer sites | utility/config | CRUD | `crates/fuse/src/replay.rs:628` (already embeds 1) | exact |

## Pattern Assignments

### 1. Verified-Resolve Wrapper — Move from `crates/fuse/src/verify.rs` to `crates/api-client/src/ipns.rs`

**Analog:** `crates/fuse/src/verify.rs` (entire file — this is the source to relocate)

**What moves:** `VerifyError` enum, `VerifiedResolve` struct, `bind_verified()`, `resolve_ipns_verified()`, and the `#[cfg(test)]` block.

**What changes on move (D-04):**
- Remove `VerifyError::Legacy` variant (lines 21-24) and its `Display` arm (lines 34-37)
- In `bind_verified()`, the `None =>` arm (line 69-72) becomes `None => Err(VerifyError::Invalid("all signature fields absent".to_string()))`
- In `bind_verified()`, the skew disjunct on line 124 becomes strict equality: `let seq_ok = embedded_seq == resp_seq;`
- Add expiry check after CBOR decode (D-07 — see EOL pattern below)
- `verify_ipns_resolve_signature()` on line 78-79: remove the `Ok(None)` all-absent branch so absent fields fall through to `Ok(Some(false))`

**Struct/enum definitions to keep (lines 17-50):**
```rust
pub enum VerifyError {
    Api(cipherbox_api_client::error::ApiError),
    // Legacy variant REMOVED — was: Legacy { cid: String, sequence_number: String }
    Invalid(String),
}

pub struct VerifiedResolve {
    pub cid: String,
    pub sequence_number: u64,
}
```

**bind_verified core (lines 64-148 — the pattern, with Phase 60 changes noted):**
```rust
pub(crate) fn bind_verified(
    resp: &crate::types::IpnsResolveResponse,
    sig_verdict: Option<bool>,
) -> Result<VerifiedResolve, VerifyError> {
    match sig_verdict {
        // D-04: None was VerifyError::Legacy — REPLACE with Invalid:
        None => Err(VerifyError::Invalid("all signature fields absent — fail closed".to_string())),
        Some(false) => Err(VerifyError::Invalid("signature verification failed".to_string())),
        Some(true) => {
            // ... CBOR decode (unchanged) ...
            // D-04: drop skew disjunct — was: embedded_seq == resp_seq || (resp_seq == 1 && embedded_seq == 0)
            let seq_ok = embedded_seq == resp_seq;  // STRICT
            // D-07: add expiry check here (see EOL pattern)
            Ok(VerifiedResolve { cid, sequence_number: resp_seq })
        }
    }
}
```

**resolve_ipns_verified (lines 163-175 — unchanged structure):**
```rust
pub async fn resolve_ipns_verified(
    api: &crate::client::ApiClient,
    ipns_name: &str,
) -> Result<VerifiedResolve, VerifyError> {
    let resp = crate::ipns::resolve_ipns(api, ipns_name)
        .await
        .map_err(VerifyError::Api)?;
    let verdict = crate::ipns::verify_ipns_resolve_signature(&resp, ipns_name)
        .map_err(|e| VerifyError::Invalid(format!("signature verification error: {}", e)))?;
    bind_verified(&resp, verdict)
}
```

**Cargo.toml addition needed:** `crates/api-client/Cargo.toml` must add `cipherbox-core = { workspace = true }` (needed for `decode_ipns_cbor_data`).

**FUSE callers (9 arms to update after Legacy removal):**
Each arm in `events.rs:92`, `metadata.rs:326/477/645`, `publish.rs:105/173`, `fs.rs:496`, `replay.rs:338/467` currently matches on `VerifyError::Legacy { .. }` and warns+proceeds. After D-04, collapse these to the existing `VerifyError::Invalid` arm (fail the operation). The compiler enforces exhaustiveness — compile errors locate all 9 sites.

---

### 2. Unit Test Pattern — Strict `bind_verified` Tests

**Analog:** `crates/fuse/src/verify.rs` lines 177-305 (the `#[cfg(test)]` block)

**Tests to KEEP / update (move to `crates/api-client/src/ipns.rs` test module):**

```rust
// This harness pattern (unchanged) — make_cbor_data + make_resp_with_cbor helpers:
fn make_cbor_data(value: &str, seq: u64) -> Vec<u8> { /* ciborium map with Value/Sequence/Validity/ValidityType/TTL */ }
fn make_resp_with_cbor(cid: &str, seq: u64, resp_cid: &str, resp_seq: u64) -> IpnsResolveResponse { /* ... */ }

// Tests to keep (no change):
//   bind_verified_valid_returns_ok_with_embedded_cid  (line 212)
//   bind_verified_cid_swap_returns_invalid            (line 222)
//   bind_verified_seq_mismatch_returns_invalid        (line 233)
//   bind_verified_seq_skew_only_applies_to_first_publish (line 256)  ← now covers the ONLY allowed case disappearing
//   bind_verified_invalid_sig_returns_invalid         (line 288)
```

**Tests to REPLACE / ADD (D-04):**
```rust
// REPLACE bind_verified_first_publish_seq_skew_returns_ok (line 244):
// After D-04 strict equality, embedded=0/resp=1 is now Invalid, not Ok.
#[test]
fn bind_verified_first_publish_seq_skew_now_invalid() {
    let resp = make_resp_with_cbor("bafyFIRST", 0, "bafyFIRST", 1);
    let err = bind_verified(&resp, Some(true)).unwrap_err();
    assert!(matches!(err, VerifyError::Invalid(_)));
}

// REPLACE bind_verified_legacy_returns_legacy (line 268):
// After D-04, None verdict → Invalid, not Legacy.
#[test]
fn bind_verified_absent_fields_returns_invalid() {
    let resp = IpnsResolveResponse { success: true, cid: "x".into(), sequence_number: "1".into(),
        signature_v2: None, data: None, pub_key: None };
    let err = bind_verified(&resp, None).unwrap_err();
    assert!(matches!(err, VerifyError::Invalid(_)));
}

// ADD (D-07):
#[test]
fn bind_verified_expired_record_returns_invalid() {
    // make_cbor_data with past Validity timestamp
    // Assert VerifyError::Invalid containing "expired"
}
```

**Cross-language vector test — classifier update (`crates/fuse/tests/ipns_verify_vectors.rs`):**

```rust
// Line 88-90 BEFORE (analog — current code):
match verdict {
    None => "legacy".to_string(),     // ← CHANGE to "invalid"
    Some(false) => "invalid".to_string(),

// Line 134 BEFORE (skew disjunct):
let seq_ok = embedded_seq == resp_seq || (resp_seq == 1 && embedded_seq == 0);
// AFTER (strict):
let seq_ok = embedded_seq == resp_seq;
```

In `scripts/gen-ipns-verify-vectors.ts`, reclassify vector cases:
- `legacy-absent` → `expected_result: "invalid"` (was `"legacy"`)
- `first-publish-skew` → `expected_result: "invalid"` (was `"valid"`)
Then regenerate: `npx tsx scripts/gen-ipns-verify-vectors.ts`

---

### 3. TS Resolve Throw-Path — `packages/sdk-core/src/ipns/index.ts`

**Analog:** The existing strict gate at lines 218-239 (the `if (hasSignatureV2 || hasData || hasPubKey)` block — already throws on partial fields).

**The legacy-else branch to DELETE (lines 293-295):**
```typescript
} else {
    console.warn('IPNS resolve returned without signature data, skipping verification');
}
// DELETE the entire else branch — no fields → throw, not warn+proceed
```

**After D-05 (strict equality), the skew disjunct to REPLACE (lines 285-292):**
```typescript
// BEFORE (current — lines 285-287):
const seqOk =
  embeddedSeqBigInt === responseSeqBigInt ||
  (responseSeqBigInt === 1n && embeddedSeqBigInt === 0n);

// AFTER (strict D-05):
const seqOk = embeddedSeqBigInt === responseSeqBigInt;
```

**The entire `if (hasSignatureV2 || hasData || hasPubKey) { ... } else { ... }` block after D-05 must become unconditional:** When all three are absent, the code must throw (not fall through). The simplest approach — after the existing partial-fields check — add:
```typescript
if (!hasSignatureV2 && !hasData && !hasPubKey) {
  throw new Error('IPNS resolve returned without signature fields — fail closed');
}
```

**Blast-radius:** After this change, `resolveIpnsRecord` no longer returns `{ signatureVerified: false }` for unsigned records — it throws. Audit pattern before Wave 1 merge:
```bash
grep -rn "signatureVerified\|resolveIpnsRecord" packages/ apps/web/src/
```
Each call site must be in a try/catch that handles generic `Error` throws, not just 404.

---

### 4. EOL/Expiry Enforcement Pattern

**TS analog — `packages/crypto/src/ipns/verify-record.ts` line 48:**
```typescript
// The publish path already uses validate() which throws RecordExpiredError on expiry:
await validate(peerId.publicKey, marshalledRecord);  // line 48 — EOL-aware
```

The resolve path currently uses the inline `verifyIpnsSignature` (lines 172-184) which does NOT call `validate()`. D-07 requires adding expiry to the resolve path.

**Recommended inline addition (Option B from RESEARCH.md) in `resolveIpnsRecord` after CBOR decode:**
```typescript
// After cborFields is populated from data field (after line 247):
const validityBytes = cborFields['Validity'];
if (validityBytes instanceof Uint8Array) {
  const validityStr = new TextDecoder().decode(validityBytes);
  const expiryMs = new Date(validityStr).getTime();
  const nowMs = Date.now();
  if (expiryMs < nowMs) {
    throw new Error(`IPNS record expired: validity=${validityStr}`);
  }
}
```

**Rust analog — `crates/core/src/ipns.rs` `build_cbor_data` includes `"Validity"` as bytes:**
The `decode_ipns_cbor_data` function (lines 81-121) returns `(Value, Sequence)` today. Extend it to also return `Validity` bytes, then check in `bind_verified`:
```rust
// In bind_verified, after CBOR decode succeeds:
// decode_ipns_cbor_data returns (embedded_value, embedded_seq, validity_bytes) after extension
if let Some(validity_bytes) = validity_bytes {
    let validity_str = std::str::from_utf8(&validity_bytes)
        .map_err(|_| VerifyError::Invalid("Validity field is not valid UTF-8".to_string()))?;
    // Parse RFC3339; format is "2026-01-01T00:00:00.000000000Z"
    // Use chrono or manual parse (format is predictable)
    // Apply 5-minute clock skew buffer: reject if expiry < now - 5min
}
```

---

### 5. API Codec/Service Strict Edits

**Anchor pattern (publish-side verify, already strict — `ipns.service.ts` lines 87-89):**
```typescript
// This is the model for fail-closed behavior — DO NOT modify:
if (!(await verifyIpnsRecordSignature(dto.ipnsName, recordBytes))) {
  throw new BadRequestException('IPNS record signature verification failed');
}
```

**D-06 — `parseCachedRecord` null-signedRecord fix (`ipns-record.codec.ts` lines 53-83):**

Current behavior (line 82): falls through to `return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber }` when `signedRecord` is null.

```typescript
// CURRENT (analog showing the fall-through to fix):
if (cached.signedRecord) {
  // ... parse ...
}
return { cid: cached.latestCid, sequenceNumber: cached.sequenceNumber }; // line 82 — legacy tolerance

// AFTER D-06 (strict: null signedRecord → null → 404):
if (!cached.signedRecord) {
  return null;  // caller returns 404 to client
}
// ... parse signedRecord ...
return { ...parsed, cid: cached.latestCid, sequenceNumber: cached.sequenceNumber };
```

**D-03 — first-publish gate tighten (`ipns.service.ts` lines 279-285):**

```typescript
// BEFORE (current — allows 0n OR 1n):
if (embeddedSeq !== 0n && embeddedSeq !== 1n) {
  throw new BadRequestException(`First publish: embedded sequence must be 0 or 1, got ${embeddedSeq}`);
}

// AFTER D-03 (strict — require 1n only):
if (embeddedSeq !== 1n) {
  throw new BadRequestException(`First publish: embedded sequence must be 1, got ${embeddedSeq}`);
}
```

**D-06 — resolve enrichment removal (`ipns.service.ts` lines 494-519):**
Remove the `withCachedPublicKey(result, cached.publicKey)` call and the equal-seq `signatureV2` enrich block. After D-06, `parseCachedRecord` already returns null for null-signedRecord rows, so these enrich branches are unreachable for legacy rows and unnecessary for fresh rows (pubKey is already in signedRecord).

---

### 6. Embed-1 Producer Pattern (9 sites)

**Canonical correct pattern (analog — `crates/fuse/src/replay.rs:628`, already embeds 1):**
```rust
let record = cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, 1, 86_400_000)
```

**Sites to change from `0` to `1` (one-line each):**

| Site | Current call |
|---|---|
| `crates/fuse/src/write_ops/implementation/mkdir.rs:173` | `create_ipns_record(&ipns_key_arr, &value, 0, 86_400_000)` |
| `crates/fuse/src/platform/windows/write_ops.rs:201` | `create_ipns_record(..., 0, ...)` (Windows — winfsp CI gate required) |
| `crates/fuse/src/metadata.rs:557` | `make_bin_record(0)` → `make_bin_record(1)` |
| `apps/desktop/src-tauri/src/commands/vault.rs:109` | `create_ipns_record(..., 0, ...)` |
| `apps/desktop/src-tauri/src/commands/vault.rs:154` | `create_ipns_record(..., 0, ...)` |

Confirmed at `mkdir.rs:173` (read above shows the exact call shape).

**TS sites (`packages/sdk-core/src/vault/index.ts:44`, `apps/web/src/hooks/useAuth.ts:191/208`, `apps/web/src/services/vault-settings.service.ts:131`):** Change the sequence argument in `createIpnsRecord(...)` calls from `0` to `1`. Pattern: search for `createIpnsRecord` + `sequence: 0` or positional `0` in these files.

---

## Shared Patterns

### SDK/Desktop Call Shape Being Replaced (D-08/D-09)

**Source (unverified bypasses to replace):**
- `crates/sdk/src/registry.rs:170`: `cipherbox_api_client::ipns::resolve_ipns(api, ipns_name)`
- `crates/sdk/src/sync.rs:201`: `cipherbox_api_client::ipns::resolve_ipns(&self.state.api, &root_ipns_name)`
- `apps/desktop/src-tauri/src/fuse/prepopulate.rs:43,110,177,236`: `resolve_ipns(...)` (raw)
- `apps/desktop/src-tauri/src/commands/vault.rs:21,250`: `resolve_ipns(...)` (raw)

**Replacement pattern (after D-08 wrapper moves to api-client):**
```rust
// Replace every raw resolve_ipns call with:
cipherbox_api_client::ipns::resolve_ipns_verified(api, ipns_name).await
// Returns Result<VerifiedResolve, VerifyError>
// Callers extract: result.cid, result.sequence_number
```

### Error Handling for VerifyError at Call Sites

**Apply to:** All 8 raw `resolve_ipns` sites above, plus the existing 9 FUSE callers updating their Legacy arms.

```rust
match resolve_ipns_verified(&self.api, &ipns_name).await {
    Ok(verified) => { /* use verified.cid, verified.sequence_number */ }
    Err(VerifyError::Api(e)) => return Err(e.into()),
    // After D-04: Legacy arm is gone — only Invalid remains
    Err(VerifyError::Invalid(msg)) => {
        tracing::error!("IPNS verification failed for {}: {}", ipns_name, msg);
        return Err(/* ENOENT or appropriate error */);
    }
}
```

### D-11 — DB-Authoritative Short-Circuit (API publish path)

**Context:** The publish anchor at `ipns.service.ts:87-89` calls `verifyIpnsRecordSignature` on every publish including TEE idempotent republishes. The safe optimization is to add `skipSigVerify` gated on the internal republish code path.

**Pattern:** Add an optional boolean to `upsertFolderIpns` signature:
```typescript
private async upsertFolderIpns(
  // ... existing params ...
  options?: { skipSigVerify?: boolean }
): Promise<FolderIpns>

// In publishRecord, before calling verifyIpnsRecordSignature:
const shouldVerify = !options?.skipSigVerify || !isIdempotentRepublish;
if (shouldVerify && !(await verifyIpnsRecordSignature(dto.ipnsName, recordBytes))) {
  throw new BadRequestException('IPNS record signature verification failed');
}
```

Only pass `skipSigVerify: true` from the internal TEE republish code path (after confirming `RepublishService` calls `publishRecord` — verify by reading `apps/api/src/ipns/republish.service.ts`).

## No Analog Found

None. All change sites have direct analogs in the existing codebase.

## Metadata

**Analog search scope:** `crates/fuse/src/`, `crates/api-client/src/`, `crates/core/src/`, `packages/sdk-core/src/ipns/`, `packages/crypto/src/ipns/`, `apps/api/src/ipns/`, `apps/desktop/src-tauri/src/`
**Files read:** 10 source files
**Pattern extraction date:** 2026-06-24
