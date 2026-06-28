---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
plan: "04"
subsystem: crypto
tags: [crypto, aad, aes-gcm, seal, kat, cross-language, rust, transplant-resistance]
requires: [61-02, 61-03]
provides: [AAD-seal-unit-tests, seal_vectors-KAT, CRYPTO-02, CRYPTO-03, TEST-02]
affects: [crates/crypto]
tech-stack:
  added: []
  patterns: [Rust TDD unit tests for seal variants, NodeSealVector deserialization, seal_vectors full-seal KAT assertion]
key-files:
  created: []
  modified:
    - crates/crypto/src/aes.rs
    - crates/crypto/tests/cross_language.rs
decisions:
  - "seal_vectors assertion uses serde_json::Value pull (same as aad_vectors) — NodeSealVector struct deserializes per entry"
  - "!seal_vectors.is_empty() guard before KAT loop prevents vacuous pass if array is ever emptied"
  - "AAD seal unit tests added as tests on pre-existing implementations (plan 02 already delivered the four functions)"
metrics:
  duration: "~8 minutes"
  completed: "2026-06-28"
  tasks_completed: 2
  files_changed: 2
status: complete
---

# Phase 61 Plan 04: Rust Full-Seal KAT and AAD Seal Unit Tests Summary

Rust AAD seal unit tests (round-trip, transplant rejection, truncation rejection, fresh-IV proof) plus the full-seal cross-language KAT extending `node_aad_cross_language` to assert `seal_vectors` — proving `encrypt_aes_gcm_aad` reproduces the exact ciphertext TS committed byte-for-byte (CRYPTO-02, TEST-02, CRYPTO-03 symmetry).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | AAD seal unit tests in aes.rs | 8399bd78a | crates/crypto/src/aes.rs |
| 2 | seal_vectors full-seal KAT in cross_language.rs | 3cc374e20 | crates/crypto/tests/cross_language.rs |

## What Was Built

### AAD Seal Unit Tests — `crates/crypto/src/aes.rs`

Six new tests added to the existing `#[cfg(test)]` module, covering the four AEAD-with-AAD functions delivered in plan 02:

- **`encrypt_decrypt_aad_round_trip`**: fixed key/iv/aad, verifies plaintext round-trips through `encrypt_aes_gcm_aad` → `decrypt_aes_gcm_aad`.
- **`decrypt_aad_wrong_aad_fails`**: proves wrong AAD on decrypt returns `Err` (GCM auth-tag covers AAD — T-61-12).
- **`seal_unseal_aad_round_trip`**: verifies `unseal_aes_gcm_aad(seal_aes_gcm_aad(pt, key, aad), key, aad) == pt` and asserts `sealed.len() == AES_IV_SIZE + plaintext.len() + AES_TAG_SIZE` (12 + len + 16).
- **`seal_aad_two_calls_differ`**: identical inputs to `seal_aes_gcm_aad` produce different blobs — proves fresh `generate_iv()` is called each time (D-00a, T-61-13).
- **`unseal_aad_transplant_fails`**: blob sealed under `aad_a` rejected when `unseal_aes_gcm_aad` is given `aad_b` — CRYPTO-03 symmetry.
- **`unseal_aad_truncated_blob_fails`**: blob of `AES_IV_SIZE + AES_TAG_SIZE - 1` bytes (27 bytes) returns `Err` before decryption is attempted — `MIN_SEALED_SIZE` guard.

Total: 30 unit tests pass (up from 24).

### Full-Seal Cross-Language KAT — `crates/crypto/tests/cross_language.rs`

Extended `node_aad_cross_language` with:

1. **`NodeSealVector` struct**: `#[derive(Deserialize)]` struct with `description`, `node_id`, `kind`, `generation`, `role`, `key`, `iv`, `plaintext`, `ciphertext` fields.

2. **`seal_vectors` assertion loop** (after the existing `aad_vectors` loop):
   - Pulls `root["seal_vectors"]` via `serde_json::Value`
   - Asserts `!seal_vectors.is_empty()` (vacuous-pass guard — mirrors TS `expect(sealVectors.length).toBeGreaterThanOrEqual(1)`)
   - For each entry: hex-decodes key/iv/plaintext, rebuilds AAD via `cipherbox_crypto::build_node_aad`, calls `cipherbox_crypto::encrypt_aes_gcm_aad`, asserts `hex::encode(result) == v.ciphertext`

The one committed vector (`cf6bfe784b825669294884ec63a59327c004cc03571e1227`) proves:
- TS `additionalData` in `AesGcmParams` ≡ Rust `Payload { msg, aad }` in `aes-gcm 0.10` — same bytes in, same bytes out (T-61-11, CRYPTO-02)
- The full AEAD-with-AAD path is now pinned byte-for-byte TS↔Rust (TEST-02), not merely AAD construction (which plan 02 already pinned)

## Verification Results

- `cargo test -p cipherbox-crypto --lib aes --no-default-features`: **30 tests passed** (6 new AAD seal tests)
- `cargo test -p cipherbox-crypto --test cross_language --no-default-features`: **6 tests passed** (`node_aad_cross_language` now covers both `aad_vectors` and `seal_vectors`)

## Deviations from Plan

### Implementation Already Present (Idempotent Adjustment)

**[Rule 0 - Idempotent] Plan 02 pre-delivered the four AEAD-with-AAD functions**

- **Found during:** Initial file read (critical constraint check)
- **Issue:** `encrypt_aes_gcm_aad`, `decrypt_aes_gcm_aad`, `seal_aes_gcm_aad`, `unseal_aes_gcm_aad` and their crate-root re-exports in `lib.rs` were all present from plan 02. The plan 04 `tdd="true"` task 1 was intended for the full implementation cycle; the implementations pre-existed.
- **Adjustment:** Wrote only the unit tests (RED+GREEN in one pass since implementation already compiled). The functions are correctly implemented; tests go GREEN immediately. Plan objective is fully met.
- **No files incorrectly duplicated.**

No other deviations. Plan executed as written.

## Known Stubs

None. All functions are fully implemented and verified by KAT.

## Threat Flags

None. All threats from the plan threat model are mitigated:

| Threat | Mitigation |
|--------|------------|
| T-61-11 TS/Rust AEAD-with-AAD output divergence | Full-seal KAT asserts exact ciphertext byte-for-byte; passes |
| T-61-12 Rust AAD transplant / truncation | `unseal_aad_transplant_fails` + `unseal_aad_truncated_blob_fails` unit tests; both pass |
| T-61-13 IV reuse under fixed key | `seal_aad_two_calls_differ` unit test; passes |

## Self-Check: PASSED

- `crates/crypto/src/aes.rs`: 6 new tests present, 30 total pass
- `crates/crypto/tests/cross_language.rs`: `NodeSealVector` struct present, `seal_vectors` assertion loop present
- Commits 8399bd78a and 3cc374e20 confirmed in git log
- Both test commands green
