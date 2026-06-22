# Phase 58: IPNS Signature-Verify Coverage - Research

**Researched:** 2026-06-22
**Domain:** Rust FUSE + TypeScript sdk-core/api — IPNS signed-record CBOR binding, verify chokepoint, non-CAS sequence validation, cross-language test vectors
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** `resolve_ipns_verified` wrapper — all ~9 Rust resolve sites routed through it; JS `resolveIpnsRecord` chokepoint already single — keep it.
- **D-02:** Fail-closed, scoped per-operation — verify failure refuses CID but fails only that operation; IPNS poll loop is not wedged.
- **D-03:** replay.rs `resolve_folder_key` (T-51-07) keeps hard fail-closed.
- **D-04:** All-absent legacy records still allowed and flagged `signatureVerified=false`.
- **D-05:** Rust and JS both fail closed on invalid/partial — unified posture.
- **D-06:** Verification-failure metric may be emitted, but is not the primary handling.
- **D-07:** CBOR-embedded cid/sequence mismatch == verification failure (same D-02 handling).
- **D-08:** Signed/embedded cid/sequence is authoritative; response field trusted only when it matches. Binding applied symmetrically in Rust and JS.
- **D-09:** Exact non-CAS sequence rule: first-publish allows 0 or 1; existing row: embedded=N → idempotent no-increment; embedded=N+1 → allow increment; embedded<N → reject; embedded>N+1 → reject.
- **D-10:** Hard reject now, gated on non-CAS path enumeration + full SDK E2E.
- **D-11:** One shared JSON fixture with cases: valid, tampered-sig, name-mismatch, cid-swapped, seq-mismatch, partial-fields, legacy-absent.
- **D-12:** Vectors consumed by existing `cargo test` + sdk-core vitest — no new CI gate.
- **D-13:** `apps/web/src/services/ipns.service.ts` imports `resolveIpnsRecord` from `@cipherbox/sdk-core`, deletes local duplicates; preserves `withPerf` wrapper + `ctx.axiosInstance` injection.

### Claude's Discretion

- Exact `resolve_ipns_verified` API shape / return type and how callers thread the verdict.
- CBOR decode approach/library on Rust and JS sides.
- Per-operation "stale vs error" UX surface for a D-02 scoped failure.
- Fixture file path/format details.
- Telemetry/metric plumbing for D-06 (optional; do not block on it).

### Deferred Ideas (OUT OF SCOPE)

None.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                                           | Research Support                                                                                               |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| HARD-09 | IPNS signature-verify coverage: CBOR cid/seq binding + Rust chokepoint, non-CAS sequence validation, web/sdk-core dedup, shared vectors | All four plans below map directly; CBOR decode recipe, API shape, non-CAS enumeration, and vector format documented here |

</phase_requirements>

## Summary

Phase 58 finishes the IPNS signed-record verification story deferred from Phase 51 / PR #529. Four gaps remain. First, neither Rust nor JS decodes the CBOR `data` field to bind the signed embedded cid/sequence back to the response fields — a valid signature can be presented alongside a swapped CID and both sides accept it. Second, only one of ~9 Rust `resolve_ipns` call sites actually calls `verify_ipns_resolve_signature` (replay.rs `resolve_folder_key`); the other eight trust the CID unconditionally. Third, the server's S1 embedded-sequence check is gated on `expectedSequenceNumber !== undefined`, so non-CAS publishes accept any embedded sequence including the wedge-poison case. Fourth, `apps/web/src/services/ipns.service.ts` carries a near-identical duplicate of the sdk-core `resolveIpnsRecord` path, maintained in lockstep by hand.

The CBOR decode path on the Rust side uses the `ciborium` crate (already in `cipherbox-core`; not in `api-client`), so CBOR decode logic must either live in `cipherbox-core` (new `decode_ipns_cbor_data` helper) or be performed in the FUSE wrapper after the raw verify call. On the JS side the `ipns` package exposes `parseCborData(buf: Uint8Array): IPNSRecordData` which returns `{Value, Validity, ValidityType, Sequence, TTL}` using the `cborg` library — this is already accessible through `@cipherbox/core` and `@cipherbox/crypto`. The `resolve_ipns_verified` wrapper lives cleanest in `crates/fuse/src/` (which depends on both `cipherbox-api-client` and `cipherbox-core`), calling `verify_ipns_resolve_signature` from api-client for the signature check and `decode_ipns_cbor_data` from core for the CBOR binding.

**Primary recommendation:** Place `decode_ipns_cbor_data(cbor_bytes: &[u8]) -> Result<(String, u64), IpnsError>` in `crates/core/src/ipns.rs`, expose it from `cipherbox-core`, then call it from the new `resolve_ipns_verified` wrapper in `crates/fuse/src/verify.rs`. Route all 8 unverified FUSE call sites through the wrapper. For the JS side, extend `resolveIpnsRecord` in `packages/sdk-core/src/ipns/index.ts` to call `parseCborData` on `record.data` after signature verification and compare `Value`/`Sequence` to the response.

## Architectural Responsibility Map

| Capability                                | Primary Tier          | Secondary Tier        | Rationale                                                                                    |
| ----------------------------------------- | --------------------- | --------------------- | -------------------------------------------------------------------------------------------- |
| IPNS signature + name verification        | API-client crate      | FUSE wrapper          | Already lives in `verify_ipns_resolve_signature`; wrapper calls it                          |
| CBOR cid/sequence decode (Rust)           | cipherbox-core crate  | FUSE wrapper (caller) | `ciborium` dep already in core; api-client lacks it; decode is domain logic not transport   |
| CBOR cid/sequence decode (JS)             | @cipherbox/sdk-core   | (none)                | `ipns.parseCborData` already transitive dep; sdk-core is the single chokepoint              |
| Resolve chokepoint (Rust)                 | crates/fuse src       | (none)                | 8 call sites are all in fuse; wrapper in fuse/verify.rs wraps api-client fn                 |
| Resolve chokepoint (JS)                   | packages/sdk-core     | (none)                | Single `resolveIpnsRecord` fn already the chokepoint                                        |
| Non-CAS sequence validation               | apps/api ipns.service | (none)                | Server-side gate; runs unconditionally on `upsertFolderIpns`                                |
| Web/sdk-core dedup                        | apps/web ipns.service | @cipherbox/sdk-core   | Web imports sdk-core fn; no new logic                                                       |
| Cross-language verify vectors             | tests/vectors/        | cargo test + vitest   | Follows existing `cross_language.rs` convention in `crates/crypto/tests/`                  |

## Standard Stack

### Core (all already in workspace — no new installs)

| Library                      | Version    | Purpose                                     | Why Standard                                          |
| ---------------------------- | ---------- | ------------------------------------------- | ----------------------------------------------------- |
| `ciborium` (Rust)            | 0.2        | CBOR encode/decode for IPNS data field      | Already in workspace; used by `cipherbox-core/src/ipns.rs` |
| `ipns` (JS)                  | ^10.1.3    | IPNS record creation, unmarshal, parseCborData | Already in `@cipherbox/core` dependency tree        |
| `cborg` (JS, transitive)     | ^4.5.8     | CBOR decode (used internally by `ipns`)     | Transitive via `ipns`; `parseCborData` hides it       |
| `cipherbox-core` (Rust crate) | workspace | IPNS record creation + decode helper site  | Has `ciborium`; FUSE depends on it already            |

### No new packages needed

This phase adds no new external dependencies. All decode libraries are already available; the work is wiring them together.

## Package Legitimacy Audit

No new packages are installed in this phase. All required libraries (`ciborium`, `ipns`, `cborg`) are already workspace dependencies. Package legitimacy gate: SKIPPED (no new installs).

## Architecture Patterns

### System Architecture Diagram

```
Rust FUSE resolve call sites (8 unverified + 1 verified)
  │
  ▼
crates/fuse/src/verify.rs::resolve_ipns_verified(api, ipns_name)
  ├── calls cipherbox_api_client::ipns::resolve_ipns()     → IpnsResolveResponse
  ├── calls verify_ipns_resolve_signature()                → Ok(None|Some(bool))|Err
  │     [unchanged; stays in api-client]
  └── if Ok(Some(true)):
        calls cipherbox_core::ipns::decode_ipns_cbor_data(resp.data_bytes)
          → (embedded_value: String, embedded_seq: u64)
        compare embedded_value == "/ipfs/{resp.cid}"
        compare embedded_seq == resp.sequence_number.parse()
        → VerifiedRecord { cid, sequence } | VerifyError::Mismatch

replay.rs resolve_folder_key (D-03 hard fail-closed)
  │
  └── calls resolve_ipns_verified() — same wrapper, returns Err on any verify fail
      (existing match arms kept verbatim, now just call the wrapper instead of inline)

JS resolveIpnsRecord (sdk-core single chokepoint)
  ├── [existing] verify Ed25519 signature
  ├── [existing] verify pubKey derives to ipnsName
  └── [NEW] parseCborData(base64-decode(response.data))
        → { Value: Uint8Array, Sequence: bigint, ... }
        normalizeByteValue(Value) == "/ipfs/" + response.cid  → ok or throw
        Sequence == BigInt(response.sequenceNumber)           → ok or throw
        (both mismatches: throw same error class as invalid sig → D-07)

apps/api upsertFolderIpns (D-09 non-CAS gate)
  existing signedRecord = await parseIpnsRecord(...)
  [CURRENTLY] if (expectedSequenceNumber !== undefined) { ... seq check ... }
  [NEW]       always run seq check using DB row as baseline per D-09 rule
```

### Recommended Project Structure

```
crates/core/src/ipns.rs           # add decode_ipns_cbor_data() helper
crates/fuse/src/verify.rs         # NEW — resolve_ipns_verified() chokepoint
crates/fuse/src/events.rs         # route spawn_metadata_refresh to wrapper
crates/fuse/src/fs.rs             # route FilePointer resolve to wrapper
crates/fuse/src/publish.rs        # route resolve_sequence / resolve_sequence_strict to wrapper
crates/fuse/src/metadata.rs       # route remote_merge / bin IPNS / file-metadata IPNS to wrapper
crates/fuse/src/replay.rs         # route parent-IPNS merge to wrapper; fold-key descent unchanged
packages/sdk-core/src/ipns/index.ts  # add CBOR binding to resolveIpnsRecord
apps/web/src/services/ipns.service.ts  # import resolveIpnsRecord from sdk-core, delete local copies
apps/api/src/ipns/ipns.service.ts      # unconditional non-CAS D-09 sequence gate in upsertFolderIpns
apps/api/src/ipns/ipns.service.spec.ts # non-CAS D-09 test coverage
tests/vectors/ipns/verify.json         # NEW — shared cross-language verify vectors
crates/crypto/tests/cross_language.rs  # add ipns_verify_cross_language test fn
packages/sdk-core/src/__tests__/ipns.test.ts  # add CBOR binding + vector-driven tests
```

### Pattern 1: `decode_ipns_cbor_data` in crates/core/src/ipns.rs

**What:** New public function in `cipherbox-core` that decodes the CBOR `data` bytes from a signed IPNS record and extracts `Value` (bytes → UTF-8 string) and `Sequence` (integer → u64).

**When to use:** Called by `resolve_ipns_verified` in `crates/fuse` after `verify_ipns_resolve_signature` returns `Ok(Some(true))`.

The CBOR map keys and types in `build_cbor_data` (already in this file) show the exact layout:

```rust
// Source: crates/core/src/ipns.rs build_cbor_data — CborValue::Map with keys:
// "TTL" → Integer, "Value" → Bytes, "Sequence" → Integer, "Validity" → Bytes, "ValidityType" → Integer
pub fn decode_ipns_cbor_data(data: &[u8]) -> Result<(String, u64), IpnsError> {
    use ciborium::Value as CborValue;
    let map: CborValue = ciborium::from_reader(data)
        .map_err(|_| IpnsError::CborEncodingFailed)?;
    let entries = match map {
        CborValue::Map(m) => m,
        _ => return Err(IpnsError::CborEncodingFailed),
    };
    let mut value_bytes: Option<Vec<u8>> = None;
    let mut sequence: Option<u64> = None;
    for (k, v) in entries {
        match (&k, v) {
            (CborValue::Text(s), CborValue::Bytes(b)) if s == "Value" => {
                value_bytes = Some(b);
            }
            (CborValue::Text(s), CborValue::Integer(i)) if s == "Sequence" => {
                let raw: i128 = i.into();
                sequence = u64::try_from(raw).ok();
            }
            _ => {}
        }
    }
    let value = String::from_utf8(value_bytes.ok_or(IpnsError::CborEncodingFailed)?)
        .map_err(|_| IpnsError::CborEncodingFailed)?;
    let seq = sequence.ok_or(IpnsError::CborEncodingFailed)?;
    Ok((value, seq))
}
```

### Pattern 2: `resolve_ipns_verified` in crates/fuse/src/verify.rs

**What:** New FUSE-layer async fn that calls `resolve_ipns`, then `verify_ipns_resolve_signature`, then (on `Some(true)`) `decode_ipns_cbor_data` and compares embedded fields to response fields.

**Return type:** `Result<VerifiedResolveResponse, VerifyError>` where:

- `VerifiedResolveResponse` wraps `cid: String` and `sequence_number: u64` (the authoritative signed values, D-08).
- `VerifyError` is an enum: `Api(ApiError)`, `SignatureInvalid(String)`, `CborMismatch(String)`, `Legacy` (Ok(None) path, which callers handle per D-04).

**Caller contract:**

- `Legacy` variant → log warning + proceed with `resp.cid` (D-04), set `signatureVerified=false`.
- `SignatureInvalid` / `CborMismatch` → fail the operation (D-02), return `Err` from the enclosing async fn.
- `Api` → propagate as-is.
- `replay.rs resolve_folder_key` (D-03): hard fail on ALL error variants including `Legacy` is NOT needed — D-03 says keep existing hard fail-closed, meaning keep the current `Ok(None) → warn + continue` behavior unchanged. The wrapper just replaces the inline `verify_ipns_resolve_signature` call.

```rust
// Source: crates/fuse/src/verify.rs (new file)
// [ASSUMED] exact error type names; planner can finalize
pub enum VerifyError {
    Api(cipherbox_api_client::error::ApiError),
    Legacy,        // all-absent fields (D-04); callers warn + proceed
    Invalid(String), // invalid/partial sig or CborMismatch — callers fail-closed
}

pub struct VerifiedResolve {
    pub cid: String,             // authoritative from signed data (D-08)
    pub sequence_number: u64,    // authoritative from signed data (D-08)
    pub signature_verified: bool, // true for full verify; false for Legacy
}

pub async fn resolve_ipns_verified(
    api: &cipherbox_api_client::ApiClient,
    ipns_name: &str,
) -> Result<VerifiedResolve, VerifyError> { ... }
```

**D-08 in practice:** When binding succeeds, the `VerifiedResolve.cid` is `embedded_value.strip_prefix("/ipfs/")`, not `resp.cid`. Callers use `VerifiedResolve.cid` to fetch IPFS content. When Legacy, callers use `resp.cid` directly (DB-authoritative path, D-04).

### Pattern 3: JS CBOR binding in resolveIpnsRecord (sdk-core)

**What:** After the existing Ed25519 verify + name-binding check, decode `response.data` with `parseCborData` from the `ipns` package and compare `Value`/`Sequence`.

**Library path:** `import { parseCborData } from 'ipns'` — this is an internal util function. Confirm it is exported. If not exported directly, use `unmarshalIPNSRecord` on the marshalled record bytes (which the response does NOT have) — in that case decode directly with `cborg.decode`.

**Verified export check:** `parseCborData` IS exported from `ipns/dist/src/utils.d.ts` (confirmed in source inspection). Import path is `import { parseCborData } from 'ipns'` — verify it re-exports from `ipns/src/index.ts`. Fallback: import from `'ipns/dist/src/utils.js'` directly.

**Decode recipe:**

```typescript
// Source: ipns package utils.js parseCborData — field layout confirmed
import { parseCborData } from 'ipns';
// response.data is the base64 CBOR bytes from the resolve API response
const dataBytes = Uint8Array.from(atob(response.data!), (c) => c.charCodeAt(0));
const cborData = parseCborData(dataBytes);
// cborData.Value is Uint8Array (UTF-8 bytes of "/ipfs/<cid>")
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

Both mismatches throw (D-07), which is caught by the existing `catch (error)` block in `resolveIpnsRecord` — non-404 errors propagate up, implementing D-02 scoped fail-closed.

**NOTE on `parseCborData` export:** The `ipns` package re-exports it from `index.d.ts` only via utils — verify `import { parseCborData } from 'ipns'` works at runtime. If it does not re-export from index, use `import { parseCborData } from 'ipns/dist/src/utils.js'` or decode inline with `cborg.decode` (also a transitive dep). The planner should add a Wave-0 verification step.

### Pattern 4: D-09 gate in apps/api upsertFolderIpns

**What:** Move the S1 sequence check out of the `if (expectedSequenceNumber !== undefined)` branch so it runs unconditionally using the DB row's sequence as the baseline.

**Current code location:** `apps/api/src/ipns/ipns.service.ts:277` — `if (expectedSequenceNumber !== undefined) {`.

**D-09 rule precisely:**

```typescript
// After: incomingParsed = await parseIpnsRecord(signedRecord);
const embeddedSeq = incomingParsed.sequence; // bigint from parsed record
if (!existing) {
  // First publish: allow 0n or 1n only (wedge-poison prevention)
  if (embeddedSeq !== 0n && embeddedSeq !== 1n) {
    throw new BadRequestException(
      `First publish: embedded sequence must be 0 or 1, got ${embeddedSeq}`
    );
  }
} else {
  const dbSeq = BigInt(existing.sequenceNumber);
  if (embeddedSeq === dbSeq) {
    // Idempotent republish (TEE re-sign path) — allow, do NOT increment DB
    // Set flag so the update branch below skips the increment
    isIdempotentRepublish = true;
  } else if (embeddedSeq === dbSeq + 1n) {
    // Normal forward publish — allow, DB increments normally
  } else if (embeddedSeq < dbSeq) {
    throw new BadRequestException(
      `Rollback rejected: embedded sequence ${embeddedSeq} < stored ${dbSeq}`
    );
  } else {
    // embeddedSeq > dbSeq + 1n — wild jump
    throw new BadRequestException(
      `Sequence jump rejected: embedded ${embeddedSeq}, expected ${dbSeq + 1n}`
    );
  }
}
```

**Idempotent-republish NO-INCREMENT path:** When `isIdempotentRepublish = true`, the update branch that does `existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString()` must be skipped. The existing record is updated (new `latestCid`, `signedRecord`) but `sequenceNumber` stays unchanged. This is the TEE 6-hour re-sign path.

**Critical: the existing `if (expectedSequenceNumber !== undefined)` block (lines ~277-297) must be REPLACED, not duplicated.** The CAS check (line ~244-255) that raises 409 stays in place; only the S1 sequence check moves.

### Pattern 5: Shared vector format (tests/vectors/ipns/verify.json)

Following the existing convention in `crates/crypto/tests/cross_language.rs` (which loads from `tests/vectors/crypto/*.json`), the new fixture lives at `tests/vectors/ipns/verify.json`.

Each vector requires pre-computed signed bytes — generate them offline via a one-shot Node.js script (uses `@cipherbox/core createIpnsRecord` + `marshalIpnsRecord`) and hard-code the hex/base64 outputs in the fixture.

**Vector schema (one entry per case):**

```json
[
  {
    "description": "valid — signature, name, cid, and sequence all match",
    "ipns_name": "k51...",
    "public_key": "<hex 32 bytes>",
    "private_key": "<hex 32 bytes>",
    "cid": "bafy...",
    "sequence_number": "5",
    "signature_v2": "<base64>",
    "data": "<base64 CBOR bytes>",
    "expected_result": "valid"
  },
  {
    "description": "tampered-sig — flip one byte of signatureV2",
    "...",
    "expected_result": "invalid"
  },
  {
    "description": "name-mismatch — sig valid but pubKey derives to different name",
    "...",
    "expected_result": "invalid"
  },
  {
    "description": "cid-swapped — sig valid, embedded cid differs from response cid field",
    "cid": "bafy_response_cid",
    "data": "<CBOR encoding /ipfs/bafy_DIFFERENT_cid + same seq>",
    "expected_result": "invalid"
  },
  {
    "description": "seq-mismatch — sig valid, embedded seq differs from response sequenceNumber",
    "sequence_number": "5",
    "data": "<CBOR encoding correct cid + seq=99>",
    "expected_result": "invalid"
  },
  {
    "description": "partial-fields (downgrade vector) — only signatureV2 present",
    "signature_v2": "<base64>",
    "data": null,
    "pub_key": null,
    "expected_result": "invalid"
  },
  {
    "description": "legacy-absent — all three fields absent",
    "signature_v2": null,
    "data": null,
    "pub_key": null,
    "expected_result": "legacy"
  }
]
```

**Vector generation approach:** The `cid-swapped` and `seq-mismatch` vectors need a record whose CBOR `data` field was hand-constructed to embed the wrong cid or seq, while the `signatureV2` covers that exact `data` (so the Ed25519 check passes but the binding check fails). Generate them by calling `build_cbor_data` / `cipherbox_core::build_cbor_data_for_test` with the tampered values, then signing.

**Rust test fn in cross_language.rs:**

```rust
// Source: crates/crypto/tests/cross_language.rs convention
#[derive(Deserialize)]
struct IpnsVerifyVector {
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
    assert!(!vectors.is_empty());
    // Build a mock IpnsResolveResponse from vector fields and call
    // verify_ipns_resolve_signature + decode_ipns_cbor_data
    // Assert result matches expected_result
}
```

### Anti-Patterns to Avoid

- **Putting CBOR decode in `crates/api-client`:** api-client has no `ciborium` dep. Adding it creates a circular concern; domain decoding belongs in core.
- **Using `resp.cid` after binding succeeds:** D-08 says signed value is authoritative. Always use `VerifiedResolve.cid` (from decoded CBOR), not `resp.cid`.
- **Moving the CAS 409 check after the D-09 check:** The existing order is correct — CAS 409 must fire before D-09 400 so concurrent-modification gets the right error code.
- **Zeroing the `incomingParsed` buffer between CAS and D-09 checks:** `upsertFolderIpns` already guards reuse; don't call `parseIpnsRecord` twice.
- **Making the `Legacy` arm fail-closed everywhere:** Only D-03 (`resolve_folder_key`) is hard fail-closed on legacy. All other sites warn + continue (D-04).

## Non-CAS Publish Path Enumeration

These are ALL publish calls with `expected_sequence_number: None` (Rust) or omitted `expectedSequenceNumber` (JS) confirmed by source inspection. Each must sign a sequence that D-09's new gate accepts.

### Rust FUSE / SDK crates

| File | Function / Context | Sequence signed | D-09 verdict |
| ---- | ------------------ | --------------- | ------------ |
| `crates/fuse/src/content_ops.rs:180` | Per-file IPNS first publish | `seq 1n` (from `create_file_ipns_record`, line 147 signs `1n`) | OK — first-publish allows 0 or 1 |
| `crates/fuse/src/metadata.rs:529` | Bin IPNS first publish | `seq 0` (line 522 calls `make_bin_record(0)`) | OK — first-publish allows 0 |
| `crates/fuse/src/replay.rs:632` | replay child-folder init | `seq 0` (caller context: fresh subfolder initial publish) | OK — first-publish allows 0 |
| `crates/fuse/src/write_ops/implementation/mkdir.rs:190` | mkdir new folder first publish | `seq 0` (comment: "sequence 0, no conflict check") | OK — first-publish allows 0 |
| `crates/fuse/src/platform/windows/write_ops.rs:216` | Windows mkdir new folder first publish | `seq 0` | OK — first-publish allows 0 |
| `crates/sdk/src/registry.rs:145` | Device registry publish | Caller must be verified before shipping D-10 (see below) |

**Device registry path (`crates/sdk/src/registry.rs:145`):** The device registry uses a separate IPNS namespace (comment confirms). The D-09 rule applies to ALL IPNS names via `upsertFolderIpns`. Registry publishes need verification that they sign the correct sequence. The comment says "Device registry publishes do not use conflict detection" and "serialized by the caller" — but D-09 still fires server-side. **Flag for enumeration task in 58-02:** check what sequence the registry signs on each update and confirm it is always DB+1 or 0 for first.

### TypeScript SDK / web

| File | Function | Sequence signed | D-09 verdict |
| ---- | -------- | --------------- | ------------ |
| `packages/sdk-core/src/vault/index.ts:44` | `publishVaultKeyBlob` (vault init) | `0n` | OK — first-publish allows 0 |
| `packages/sdk/src/bin/index.ts` via `publishWithVerify` | bin publish (add/restore/delete/empty) | `loaded.sequenceNumber + 1` from `BinState` (line ~306-310) | OK — signs DB_current+1 |

**Bin publish detail:** `addToBin`, `restoreToBin`, etc. each call `publishWithVerify` with `sequenceNumber: params.binState.sequenceNumber + 1`. `binState.sequenceNumber` comes from `loadBin` → `loadBinMetadataInternal` → `resolveIpnsRecord` → `response.sequenceNumber`. But the API's `sequenceNumber` in the resolve response is the **DB-stored** sequence (which tracks the last accepted publish). So bin publishes sign `DB_sequence + 1` which matches D-09's `embedded = N+1` rule. If `loadBin` returns the in-memory empty state (`sequenceNumber: 0`), the first bin publish signs `0 + 1 = 1n` which matches the first-publish allow set. **No regression expected.**

**TEE republish path:** TEE re-signs the same record without bumping sequence — it calls the publish endpoint with the same `sequenceNumber` as the stored record. This is the `embedded = N` idempotent path in D-09 that must NOT increment the DB. This path is not in the SDK code (it runs in the TEE worker); the SDK E2E suite exercises it indirectly.

## Don't Hand-Roll

| Problem                 | Don't Build                         | Use Instead                                      | Why                                              |
| ----------------------- | ----------------------------------- | ------------------------------------------------ | ------------------------------------------------ |
| CBOR decode (Rust)      | Custom CBOR parser                  | `ciborium::from_reader` (already in core)        | `build_cbor_data` uses same library; byte-for-byte compat guaranteed |
| CBOR decode (JS)        | Custom byte parser                  | `parseCborData` from `ipns` package              | Library that created the encoding owns the decoding |
| IPNS record unmarshal   | Custom protobuf decoder             | `unmarshalIPNSRecord` from `ipns` (already used in `@cipherbox/crypto` `parse-record.ts`) | Protobuf format is complex; library is already there |
| Sequence integer decode | Manual CBOR integer extraction      | `ciborium::Value::Integer::into::<i128>()` then `u64::try_from` | ciborium's `Integer` wraps an i128 with known conversion |

## Common Pitfalls

### Pitfall 1: CBOR `Value` field is `Bytes`, not `Text`

**What goes wrong:** The CBOR map key `"Value"` stores the IPFS path as `CborValue::Bytes` (raw UTF-8 bytes), not `CborValue::Text`. Matching against `CborValue::Text` misses it.

**Why it happens:** Confirmed in `build_cbor_data` in `crates/core/src/ipns.rs:85`: `CborValue::Bytes(value.as_bytes().to_vec())`. The JS side likewise: `parseCborData` returns `Value` as `Uint8Array` (bytes), not a string.

**How to avoid:** In Rust match arm: `CborValue::Bytes(b)`. In JS: `new TextDecoder().decode(cborData.Value).trim()` (the `trim()` is a safety measure matching the ipns package's `normalizeByteValue`).

### Pitfall 2: `ciborium::Integer` to u64 requires two-step conversion

**What goes wrong:** `ciborium::Value::Integer` does not implement `From<u64>` directly; it wraps an `i128`. Calling `.as_u64()` does not exist on the type.

**Why it happens:** `ciborium::Integer` is a newtype over `i128`.

**How to avoid:** `let raw: i128 = i.into(); u64::try_from(raw).map_err(|_| IpnsError::CborEncodingFailed)?`

### Pitfall 3: `parseCborData` import path from `ipns`

**What goes wrong:** `import { parseCborData } from 'ipns'` may fail at runtime if the function is not re-exported from the package's main entry point.

**Why it happens:** `ipns/dist/src/index.d.ts` does NOT re-export `parseCborData` from utils. It is defined in `utils.js` and used internally.

**How to avoid:** Import from `'ipns/dist/src/utils.js'` directly, or use `cborg` directly: `import { decode } from 'cborg'` then interpret the decoded map. `cborg` IS a direct dependency of the `ipns` package (confirmed at version 4.5.8). Add `cborg` as an explicit dev-dep in `packages/sdk-core/package.json` to avoid relying on a transitive. Confirm the correct import in Wave-0 test run.

**FLAGGED RISK:** If `parseCborData` is not importable, the fallback is `import { decode as cborDecode } from 'cborg'` which decodes the map directly. The `cborg` map returns plain JS objects with keys matching the CBOR text keys ("Value", "Sequence", etc.). This is a straightforward alternative that does not require the `ipns` package internal.

### Pitfall 4: D-09 idempotent path skips DB increment but must still update latestCid

**What goes wrong:** When `embedded = N` (TEE re-sign), the code flow falls into the "idempotent republish" branch. If the update block is skipped entirely, `latestCid` is not updated — the DB row still points to the old CID even if the re-published record points to a new CID.

**Why it happens:** TEE re-signs the same sequence but may be publishing to a new CID (after the operator manually pushed new content). Skipping the DB update entirely loses that CID.

**How to avoid:** The idempotent branch updates `latestCid` and `signedRecord` but does NOT increment `sequenceNumber`. Only the `sequenceNumber` increment is skipped.

### Pitfall 5: IpnsResolveResponse does not include raw `data` bytes in the current Rust type

**What goes wrong:** `verify_ipns_resolve_signature` receives `IpnsResolveResponse` which has `data: Option<String>` (base64). After decode, `cbor_data: Vec<u8>` is local to the function. To call `decode_ipns_cbor_data` in `resolve_ipns_verified`, we need access to those decoded bytes.

**How to avoid (two options):**
- Option A: Extend `verify_ipns_resolve_signature` to also return the decoded `cbor_data` bytes alongside the bool verdict (change return type to `Ok((Option<bool>, Option<Vec<u8>>))`). Simple but changes the existing function signature.
- Option B: `resolve_ipns_verified` in fuse/verify.rs decodes `resp.data` independently (base64 → bytes) before calling `decode_ipns_cbor_data`. The base64 decode is trivial and duplicating it is acceptable since the verify fn already does it internally.

**Recommendation:** Option B — `resolve_ipns_verified` decodes `resp.data` from base64 itself. This avoids changing the api-client's `verify_ipns_resolve_signature` signature, which would require cascading updates to the existing test in replay.rs.

### Pitfall 6: Sequence number string vs integer type at API boundary

**What goes wrong:** `IpnsResolveResponse.sequence_number` is a `String` in Rust (serde_json: string). `decode_ipns_cbor_data` returns `u64`. Comparison must parse the string: `resp.sequence_number.parse::<u64>()`.

**How to avoid:** In `resolve_ipns_verified`, after a successful binding check, set `VerifiedResolve.sequence_number = embedded_seq_u64` (the signed value, D-08). Parse `resp.sequence_number` for comparison only.

## Runtime State Inventory

> Omitted — this is a code/test hardening phase with no rename, rebrand, or data migration.

## Validation Architecture

> nyquist_validation is `true` in `.planning/config.json` — section required.

### Test Framework

| Property           | Value                                           |
| ------------------ | ----------------------------------------------- |
| Rust framework     | `cargo test` (workspace-level)                  |
| JS framework       | `vitest` (sdk-core), `jest` (apps/api)          |
| Rust run command   | `cargo test -p cipherbox-fuse -p cipherbox-core -p cipherbox-api-client` |
| JS run (sdk-core)  | `pnpm --filter @cipherbox/sdk-core test`        |
| JS run (api)       | `pnpm --filter @cipherbox/api test`             |
| SDK E2E gate       | `tests/sdk-e2e` (local; prereqs: redis 6380, local API stack) |

### Phase Requirements to Test Map

| Req ID  | Behavior                                                | Test Type         | Automated Command                                                              | File |
| ------- | ------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------ | ---- |
| HARD-09 | CBOR cid binding: mismatch → verify failure             | unit (Rust)       | `cargo test -p cipherbox-api-client ipns_verify` + cross-lang                 | `crates/crypto/tests/cross_language.rs` |
| HARD-09 | CBOR seq binding: mismatch → verify failure             | unit (Rust)       | cross-lang vector `seq-mismatch`                                               | `tests/vectors/ipns/verify.json` |
| HARD-09 | `resolve_ipns_verified`: legacy → warn + return Legacy  | unit (Rust)       | `cargo test -p cipherbox-fuse ipns_verify`                                    | `crates/fuse/src/verify.rs` |
| HARD-09 | `resolve_ipns_verified`: invalid sig → Err              | unit (Rust)       | `cargo test -p cipherbox-fuse`                                                 | `crates/fuse/src/verify.rs` |
| HARD-09 | `resolve_ipns_verified`: cid swap → Err                 | unit (Rust)       | `cargo test -p cipherbox-fuse`                                                 | `crates/fuse/src/verify.rs` |
| HARD-09 | All 8 FUSE call sites route through wrapper             | integration (Rust)| `cargo test -p cipherbox-fuse`                                                | call-site grep in CI |
| HARD-09 | JS CBOR cid binding: mismatch → throw                   | unit (vitest)     | `pnpm --filter @cipherbox/sdk-core test ipns`                                  | `packages/sdk-core/src/__tests__/ipns.test.ts` |
| HARD-09 | JS CBOR seq binding: mismatch → throw                   | unit (vitest)     | `pnpm --filter @cipherbox/sdk-core test ipns`                                  | `packages/sdk-core/src/__tests__/ipns.test.ts` |
| HARD-09 | D-09 first-publish: seq 0 and seq 1 allowed; seq 2 rejected | unit (jest)  | `pnpm --filter @cipherbox/api test ipns.service`                               | `apps/api/src/ipns/ipns.service.spec.ts` |
| HARD-09 | D-09 existing: embedded=N → idempotent no-increment     | unit (jest)       | `pnpm --filter @cipherbox/api test ipns.service`                               | `apps/api/src/ipns/ipns.service.spec.ts` |
| HARD-09 | D-09 existing: embedded=N+1 → increment allowed         | unit (jest)       | `pnpm --filter @cipherbox/api test ipns.service`                               | `apps/api/src/ipns/ipns.service.spec.ts` |
| HARD-09 | D-09 existing: embedded<N → reject 400                  | unit (jest)       | `pnpm --filter @cipherbox/api test ipns.service`                               | `apps/api/src/ipns/ipns.service.spec.ts` |
| HARD-09 | D-09 existing: embedded>N+1 → reject 400                | unit (jest)       | `pnpm --filter @cipherbox/api test ipns.service`                               | `apps/api/src/ipns/ipns.service.spec.ts` |
| HARD-09 | Non-CAS bin/vault/file first publishes pass D-09         | SDK E2E           | `tests/sdk-e2e` (local)                                                        | existing e2e suite |
| HARD-09 | TEE re-sign path (embedded=N) does not increment DB     | unit (jest)       | `pnpm --filter @cipherbox/api test ipns.service`                               | `apps/api/src/ipns/ipns.service.spec.ts` |
| HARD-09 | Web uses sdk-core resolveIpnsRecord (no local copy)     | type-check        | `pnpm --filter @cipherbox/web typecheck`                                       | `apps/web/src/services/ipns.service.ts` |
| HARD-09 | Shared vectors: valid case passes on both sides         | cross-lang        | `cargo test ipns_verify_cross_language` + `pnpm --filter @cipherbox/sdk-core test` | `crates/crypto/tests/cross_language.rs` + `ipns.test.ts` |
| HARD-09 | Shared vectors: cid-swapped fails on both sides         | cross-lang        | same                                                                            | same |
| HARD-09 | Shared vectors: partial-fields downgrade fails          | cross-lang        | same                                                                            | same |
| HARD-09 | replay.rs resolve_folder_key still hard fail-closed     | regression (Rust) | `cargo test -p cipherbox-fuse`                                                 | existing test in replay.rs |

### TDD RED/GREEN Contracts per Decision

**D-07/D-08 (CBOR binding, Rust):**

- RED: call `resolve_ipns_verified` with a response where `cid` in `resp` is swapped but `data` CBOR contains the real cid → expect `Err(VerifyError::Invalid("cid binding mismatch"))`.
- GREEN: implement `decode_ipns_cbor_data` + binding check in `resolve_ipns_verified`.

**D-07/D-08 (CBOR binding, JS):**

- RED: call `resolveIpnsRecord` with a mock response where `response.cid = "bafy_different"` but `data` CBOR encodes `"/ipfs/bafy_real"` with valid signature → expect throw `"IPNS cid binding mismatch"`.
- GREEN: add `parseCborData` call + comparison inside `resolveIpnsRecord`.

**D-09 (non-CAS gate, API):**

- RED: call `publishRecord` without `expectedSequenceNumber`, first publish with embedded `seq=999n` → expect 400.
- GREEN: add unconditional D-09 check.
- RED: call with existing row at seq=5, embedded=5 (idempotent) → expect success and DB seq stays at 5.
- GREEN: add `isIdempotentRepublish` branch.

**D-13 (web dedup):**

- RED: `apps/web/src/services/ipns.service.ts` references a local `verifyIpnsSignature` or `resolveIpnsRecord` → TypeScript error after import changes.
- GREEN: import from `@cipherbox/sdk-core`, delete local copies.

### Sampling Rate

- Per task commit: `cargo test -p cipherbox-core && pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/api test`
- Per wave merge: full `cargo test` + sdk-core vitest + api jest
- Phase gate: full SDK E2E suite (local, redis 6380) + `cargo test` green before `/gsd-verify-work`

### Wave 0 Gaps (tasks that must exist before TDD tasks run)

- `tests/vectors/ipns/` directory + `verify.json` fixture (the vector-generation script must run before the Rust/JS consumer tests)
- `crates/fuse/src/verify.rs` new file (skeleton with error types before call-site routing)
- Verify `parseCborData` import path from `ipns` at runtime (Wave-0 probe: `node -e "import('ipns').then(m => console.log(typeof m.parseCborData))"` in packages/sdk-core context)

## Security Domain

### Applicable ASVS Categories

| ASVS Category                    | Applies | Standard Control                                                            |
| -------------------------------- | ------- | --------------------------------------------------------------------------- |
| V2 Authentication                | no      | N/A                                                                         |
| V3 Session Management            | no      | N/A                                                                         |
| V4 Access Control                | partial | Server-side D-09 gate prevents sequence-wedge attack                       |
| V5 Input Validation              | yes     | D-09 validates embedded sequence bounds; D-07 validates CBOR field binding |
| V6 Cryptography                  | yes     | Ed25519 verify stays in `cipherbox-crypto`; CBOR decode is separate concern |
| V7 Error Handling (data leakage) | partial | Verify failures must not log signature bytes; error messages are opaque     |

### Known Threat Patterns for This Stack

| Pattern                                    | STRIDE     | Standard Mitigation                                           |
| ------------------------------------------ | ---------- | ------------------------------------------------------------- |
| CID swap (replace cid field post-signature)| Tampering  | D-07/D-08 CBOR binding check                                  |
| Sequence wedge (first-publish high seq)    | DoS        | D-09 first-publish gate (allow 0 or 1 only)                   |
| Rollback replay (old valid record)         | Repudiation| D-09 `embedded < N` reject + existing anti-rollback check     |
| Partial-fields downgrade                   | Tampering  | Already shipped in PR #529; D-11 vector pins the regression guard |
| Legacy-absent downgrade                    | Tampering  | D-04 all-absent still allowed (not addressable without breaking compat) |
| CBOR null / type confusion                 | Tampering  | `ciborium` type matching with explicit match arms; missing field → IpnsError::CborEncodingFailed → Invalid |

## Environment Availability

> This phase is code-only (Rust + TypeScript). No new external services.

| Dependency          | Required By           | Available | Version | Fallback           |
| ------------------- | --------------------- | --------- | ------- | ------------------ |
| `ciborium` (Rust)   | decode_ipns_cbor_data | ✓         | 0.2     | —                  |
| `ipns` npm package  | parseCborData (JS)    | ✓         | ^10.1.3 | `cborg` direct     |
| `cborg` npm         | CBOR decode fallback  | ✓         | ^4.5.8  | —                  |
| Redis 6380          | SDK E2E suite         | confirm at runtime | — | —           |
| Local API stack     | SDK E2E suite         | confirm at runtime | — | —           |

## State of the Art

| Old Approach                                  | Current Approach                               | Changed       | Impact                                                |
| --------------------------------------------- | ---------------------------------------------- | ------------- | ----------------------------------------------------- |
| IPNS verify only at replay.rs (1 site)        | `resolve_ipns_verified` wrapper (all 9 sites)  | Phase 58-01   | All FUSE resolves safe-by-default                     |
| No CBOR cid/seq binding                       | Decode + compare on both Rust and JS           | Phase 58-01   | Closes CID-swap gap                                   |
| Non-CAS sequence: any embedded accepted       | D-09 unconditional gate in upsertFolderIpns    | Phase 58-02   | Closes sequence-wedge first-publish poison            |
| Web duplicates sdk-core verify logic          | Web imports sdk-core resolveIpnsRecord         | Phase 58-03   | Single verify path eliminates lockstep divergence risk |
| No shared cross-language IPNS verify vectors  | `tests/vectors/ipns/verify.json` consumed by both | Phase 58-04 | Drift between Rust/JS byte-construction caught in CI  |

## Assumptions Log

| #  | Claim                                                                                        | Section                      | Risk if Wrong                                                |
| -- | -------------------------------------------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------ |
| A1 | `parseCborData` from `ipns` package is importable as `import { parseCborData } from 'ipns'` | Pattern 3 + Pitfall 3        | Must fall back to `import { decode } from 'cborg'`; low implementation risk |
| A2 | Device registry (`crates/sdk/src/registry.rs`) always signs a valid sequence per D-09        | Non-CAS enumeration          | May need additional investigation during 58-02 task; flag for enumeration step |
| A3 | TEE republish path always sends `embedded = DB_stored_seq` (not DB+1)                       | D-09 idempotent path         | If TEE sends DB+1, the idempotent branch is never triggered; no regression but the branch is dead code |
| A4 | `VerifyError::Legacy` variant for all-absent records is the right modeling choice            | Pattern 2 (API shape)        | Planner may prefer a different return shape; adjust in planning without security impact |

## Open Questions (RESOLVED)

All three questions have a concrete in-plan resolution path; none block execution.

1. **`parseCborData` direct import from `ipns` package**
   - What we know: `parseCborData` is in `ipns/dist/src/utils.js` and used internally.
   - What's unclear: Whether it is re-exported from `ipns/dist/src/index.js`.
   - RESOLVED: Deferred to a Wave-0 runtime probe in 58-01 (`node --input-type=module -e "import { parseCborData } from 'ipns'; console.log(typeof parseCborData)"`). If undefined, fall back to `cborg.decode` directly. Low-risk — both paths decode the same bytes.

2. **Device registry sequence on update (registry.rs:145)**
   - What we know: Current code publishes with `expected_sequence_number: None`. Comment says "serialized by caller."
   - What's unclear: On a registry update (not first publish), what sequence does it sign? Is it always first-publish (seq 0)?
   - RESOLVED: Deferred to the 58-02 enumeration task (Task 1), which inspects `crates/sdk/src/registry.rs` and confirms it signs `DB+1` (or only ever publishes seq 0). The enumeration is a BLOCKER-if-unresolved gate before D-09 enforcement, so this cannot silently regress.

3. **IpnsResolveResponse.data field availability**
   - What we know: `IpnsResolveResponse` has `data: Option<String>` (base64 CBOR). The CBOR `data` is included in the resolve response when the delegated routing provider returns it.
   - What's unclear: Is `data` always populated when `signatureV2` is present? (Expected yes — all three fields come from the same IPNS record protobuf field 9.)
   - RESOLVED: Treat absent `data` when `signatureV2` is present as partial-fields (fail closed, D-05) — identical to existing logic. No special case needed.

## Sources

### Primary (HIGH confidence — source code verified)

- `crates/api-client/src/ipns.rs` — `verify_ipns_resolve_signature` implementation; confirms `"ipns-signature:" || cbor_data` as signed bytes construction.
- `crates/core/src/ipns.rs` — `build_cbor_data` CBOR map layout: keys TTL/Value/Bytes/Sequence/Validity/ValidityType; uses `ciborium`. Confirms `Value` is `CborValue::Bytes`.
- `packages/sdk-core/src/ipns/index.ts` — `resolveIpnsRecord` current implementation; single JS chokepoint; no CBOR binding today.
- `apps/web/src/services/ipns.service.ts:139-231` — web duplicate; no `ctx` arg on `resolveIpnsRecord` (D-13 migration seam confirmed: sdk-core version already accepts `ctx?`).
- `apps/api/src/ipns/ipns.service.ts:277` — S1 sequence gate gated on `expectedSequenceNumber !== undefined`; D-09 gap confirmed.
- `crates/fuse/src/replay.rs:333-364` — sole verified Rust call site; confirms match arm structure to replicate in wrapper.
- `packages/crypto/src/ipns/parse-record.ts` — `parseIpnsRecord` via `unmarshalIPNSRecord`; returns `{value, sequence, signatureV2, data, pubKey}`.
- `node_modules/.pnpm/ipns@10.1.3/node_modules/ipns/dist/src/utils.d.ts` — `parseCborData(buf: Uint8Array): IPNSRecordData` type confirmed.
- `node_modules/.pnpm/ipns@10.1.3/node_modules/ipns/dist/src/utils.js:155-172` — `parseCborData` implementation; uses `cborg.decode`; `Sequence` coerced to `bigint`.
- `crates/crypto/tests/cross_language.rs` — existing vector convention: `load_vectors("crypto/aes-gcm.json")`, `#[derive(Deserialize)]` struct, one test fn per domain.

### Secondary (MEDIUM confidence)

- `node_modules/.pnpm/ipns@10.1.3/node_modules/ipns/dist/src/index.d.ts` — confirms `IPNSRecord`, `IPNSRecordData` types; `parseCborData` not re-exported from index (only from utils).
- `Cargo.toml` workspace — `ciborium = "0.2"` confirmed as workspace dep.

## Metadata

**Confidence breakdown:**

- CBOR decode recipe (Rust): HIGH — source-verified from `build_cbor_data` and `ciborium` API
- CBOR decode recipe (JS): HIGH — source-verified from `parseCborData` in ipns utils.js, with one low-risk import-path assumption (A1)
- `resolve_ipns_verified` API shape: MEDIUM — recommended shape is design, not verified against final Rust code
- Non-CAS path enumeration: HIGH for all Rust/JS paths found; MEDIUM for device registry (A2 — needs 58-02 task verification)
- Vector format: HIGH — mirrors verified cross_language.rs convention exactly
- D-09 implementation recipe: HIGH — derived directly from current upsertFolderIpns code

**Research date:** 2026-06-22
**Valid until:** 2026-07-22 (stable domain; no upstream IPNS spec changes expected)

---

## RESEARCH COMPLETE
