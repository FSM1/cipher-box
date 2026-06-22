---
phase: 58-ipns-signature-verify-coverage
reviewed: 2026-06-22T00:00:00Z
depth: deep
files_reviewed: 13
files_reviewed_list:
  - crates/core/src/ipns.rs
  - crates/fuse/src/verify.rs
  - crates/fuse/src/events.rs
  - crates/fuse/src/fs.rs
  - crates/fuse/src/publish.rs
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/replay.rs
  - crates/fuse/tests/ipns_verify_vectors.rs
  - packages/sdk-core/src/ipns/index.ts
  - apps/api/src/ipns/ipns.service.ts
  - apps/web/src/services/ipns.service.ts
  - scripts/gen-ipns-verify-vectors.mjs
  - tests/vectors/ipns/verify.json
findings:
  critical: 0
  warning: 2
  info: 2
  total: 4
status: issues
---

# Phase 58: Code Review Report

**Reviewed:** 2026-06-22
**Depth:** deep
**Files Reviewed:** 13
**Status:** issues_found

## Summary

Phase 58 adds IPNS signature verification coverage across the full stack: a Rust `resolve_ipns_verified` chokepoint in `crates/fuse/src/verify.rs`, CBOR cid/sequence binding in `crates/core/src/ipns.rs` (`decode_ipns_cbor_data`) and its JS counterpart in `packages/sdk-core/src/ipns/index.ts` (`resolveIpnsRecord`), a non-CAS embedded-sequence gate in the API (`D-09`), and cross-language test vectors in `tests/vectors/ipns/verify.json`.

The core design is sound. The `resolve_ipns_verified` chokepoint is correctly wired at all 9 resolve sites (events, fs, publish×2, metadata×3, replay×2). The D-03 exception (hard fail-closed in `resolve_folder_key`) is confirmed. Legacy records (D-04) are handled consistently across all sites with warn-and-proceed posture. The CBOR binding logic is byte-for-byte consistent between Rust (`build_cbor_data`/`decode_ipns_cbor_data`) and JS (cborg + `IPNS_SIGNATURE_PREFIX`). The D-09 sequence gate is logically correct for all four cases (first-publish, forward, idempotent-TEE-resign, rollback, and jump/wedge). No hardcoded secrets or key material leaks in logs.

Two quality issues were found: an unchecked integer addition in `replay.rs` that is inconsistent with every other arithmetic operation in this module, and an unsafe JS type cast in the CBOR sequence comparison that would silently truncate a BigInt sequence value if cborg ever returns one.

---

## Warnings

### WR-01: Unchecked `seq + 1` in `fetch_merge_publish_parent` will wrap in release builds

**File:** `crates/fuse/src/replay.rs:540`

**Issue:** `let new_seq = seq + 1;` uses unchecked u64 arithmetic. In Rust debug builds this panics on overflow; in release builds it wraps to 0. Every other `seq + 1` operation in this crate uses `checked_add` with an explicit error return (see `metadata.rs:899,914`, `publish.rs:115,160`, `metadata.rs:292,374`). At u64::MAX overflow the wrapped value (0) would be submitted as `expected_sequence_number=u64::MAX` with an embedded seq=0. The API's D-09 gate would reject it (`0 < stored_seq` → 400), so this does not produce a security bypass or data loss, but it converts an extreme-state replay into a confusing 400 error rather than a clean `"IPNS sequence number overflow"` and could panic the thread in debug.

**Fix:**

```rust
let new_seq = seq
    .checked_add(1)
    .ok_or_else(|| "IPNS sequence number overflow".to_string())?;
```

---

### WR-02: Unsafe `BigInt(embeddedSeq as number)` cast silently truncates if cborg returns a BigInt

**File:** `packages/sdk-core/src/ipns/index.ts:263`

**Issue:** `cborDecode(dataBytes)` is typed as `Record<string, unknown>`. The `cborg` library returns a JavaScript `number` for CBOR integers within the safe range, but may return a `bigint` for values exceeding `Number.MAX_SAFE_INTEGER` (2^53−1). The current code casts `embeddedSeq as number` before passing to `BigInt(...)`. If `embeddedSeq` is already a `bigint`, the intermediate `as number` coercion via TypeScript's type assertion does not actually convert the runtime value — `BigInt(bigintValue)` still works correctly. However, if cborg returns a native `bigint` and the JS runtime coerces it to `number` before passing to `BigInt()` (which does not happen in practice with strict JS semantics, but the typed cast encourages future breakage), sequences above 2^53 would compare incorrectly, producing a false `"sequence binding mismatch"` error that throws for a valid record.

More practically: the `as number` cast removes type safety. If this line is ever refactored and the `BigInt()` wrapper is dropped, the plain `as number` would silently truncate. Use a safe coercion that handles both types:

**Fix:**

```typescript
const embeddedSeq = cborFields['Sequence'];
const embeddedSeqBigInt =
  typeof embeddedSeq === 'bigint' ? embeddedSeq : BigInt(embeddedSeq as number);
if (embeddedSeqBigInt !== BigInt(response.sequenceNumber)) {
  throw new Error(
    `IPNS sequence binding mismatch: embedded=${embeddedSeq}, response sequenceNumber=${response.sequenceNumber}`
  );
}
```

---

## Info

### IN-01: Dead-code `unwrap_or("")` on `resp.data` in `bind_verified`

**File:** `crates/fuse/src/verify.rs:72`

**Issue:** `let data_b64 = resp.data.as_deref().unwrap_or("");` is executed only when `sig_verdict` is `Some(true)`. By contract, `verify_ipns_resolve_signature` returns `Some(true)` only when all three signature fields are present AND the signature is valid — meaning `resp.data` cannot be `None` on this path. The `unwrap_or("")` is dead code. It is fail-closed (an empty string produces an empty byte slice, `decode_ipns_cbor_data` returns `Err(CborEncodingFailed)`, the arm returns `VerifyError::Invalid`), so there is no correctness risk. But the defensive fallback obscures the invariant and would silently turn a future contract violation into a misleading CBOR-decode error rather than a panic or explicit `unreachable!`.

**Fix:** Replace with an explicit `expect` or `ok_or_else` to document the invariant:

```rust
let data_b64 = resp
    .data
    .as_deref()
    .ok_or_else(|| VerifyError::Invalid(
        "sig_verdict=Some(true) but resp.data is None — contract violation".to_string()
    ))?;
```

---

### IN-02: `.trim()` on CBOR `Value` decode is unnecessary and misleading

**File:** `packages/sdk-core/src/ipns/index.ts:252`

**Issue:** `new TextDecoder().decode(cborFields['Value']).trim()` strips whitespace from the CBOR-embedded IPFS path before comparing to `response.cid`. The CBOR `Value` field is a byte-string produced by the signing library from an `/ipfs/<CID>` string; it never contains leading/trailing whitespace. The `.trim()` call (a) does nothing in practice, (b) would silently cause a false-positive match if an attacker could craft a value like `/ipfs/REAL_CID  ` (trailing spaces) — though this is not exploitable since the signature covers the value, (c) is inconsistent with the Rust `bind_verified` which compares without trimming.

**Fix:** Remove `.trim()`:

```typescript
const embeddedValue =
  cborFields['Value'] instanceof Uint8Array
    ? new TextDecoder().decode(cborFields['Value'])
    : null;
```

---

## Verdict

Phase 58 is a well-executed crypto-correctness hardening pass. The chokepoint architecture, CBOR binding logic, D-09 sequence gate, and cross-language vector suite are all correct and consistent. No security vulnerabilities, data-loss risks, or authentication bypasses were found. The two warnings are mechanical quality issues: an unchecked integer addition in `replay.rs` that is inconsistent with every other overflow-safe arithmetic call in the crate (fix is a one-liner), and a type-unsafe BigInt coercion path in the JS CBOR binding check that works correctly today but is fragile under refactoring. Both should be fixed before merge; neither blocks the core security intent of the phase.

---

_Reviewed: 2026-06-22_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
