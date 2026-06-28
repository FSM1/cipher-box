---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
plan: "02"
subsystem: crypto
tags: [crypto, aad, aes-gcm, kat, cross-language, rust, uuid]
requires: [61-01]
provides: [build_node_aad, encrypt_aes_gcm_aad, decrypt_aes_gcm_aad, seal_aes_gcm_aad, unseal_aes_gcm_aad, InvalidAadInput, node_aad_cross_language]
affects: [crates/crypto, Cargo.toml]
tech-stack:
  added: [uuid = { version = "1", features = ["std"] }]
  patterns: [frozen domain-separator byte literal, fail-closed validation, Payload API for AAD, RFC-4122 Uuid::parse_str().as_bytes()]
key-files:
  created: []
  modified:
    - Cargo.toml
    - crates/crypto/Cargo.toml
    - crates/crypto/src/error.rs
    - crates/crypto/src/aes.rs
    - crates/crypto/src/lib.rs
    - crates/crypto/tests/cross_language.rs
decisions:
  - "D-04 UUID parity: Uuid::parse_str(s)?.as_bytes() gives 16 raw RFC-4122 bytes, never uuid.to_string() (36 UTF-8)"
  - "NODE_SEAL_DOMAIN frozen byte literal in aes.rs mirrors hkdf.rs domain-separator precedent"
  - "node_aad_cross_language parses node-aad.json via serde_json::Value (top-level object) not load_vectors (flat-array helper)"
  - "assert_eq!(aad_vectors.len(), 4) guards four-role coverage cannot silently erode"
metrics:
  duration: "~12 minutes"
  completed: "2026-06-28"
  tasks_completed: 2
  files_changed: 6
status: complete
---

# Phase 61 Plan 02: Rust AAD Builder and Cross-Language KAT Summary

Rust twin `build_node_aad` producing byte-identical 45-byte AAD to the TS implementation, backed by `uuid` crate RFC-4122 parsing, plus the `node_aad_cross_language` Rust KAT asserting all four committed `aad_vectors` — C-01 merge gate closed on both sides.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | uuid dep + InvalidAadInput + build_node_aad + AAD seal variants | bc091aa46 | Cargo.toml, crates/crypto/Cargo.toml, error.rs, aes.rs, lib.rs |
| 2 | node_aad_cross_language Rust KAT | 86cb7be20 | crates/crypto/tests/cross_language.rs |

## What Was Built

### uuid workspace dependency

Added `uuid = { version = "1", features = ["std"] }` to `[workspace.dependencies]` in the root `Cargo.toml` and `uuid = { workspace = true }` to `crates/crypto/Cargo.toml`. This is the D-04 silent-mismatch prevention: `Uuid::parse_str(s)?.as_bytes()` produces the canonical 16-byte RFC-4122 field-order representation.

### `CryptoError::InvalidAadInput` — `crates/crypto/src/error.rs`

New variant following the existing PascalCase + thiserror pattern. Returned by `build_node_aad` for all invalid inputs (D-03 fail-closed).

### `build_node_aad` — `crates/crypto/src/aes.rs`

Produces the frozen 45-byte AAD per D-00:

```
"cipherbox/node-seal/v1" (22B, frozen byte literal) ‖ 0x00 ‖ nodeId (16B Uuid::as_bytes()) ‖ kind (1B) ‖ generation (4B BE u32) ‖ role (1B)
```

Fail-closed (D-03): rejects `kind` outside `0x01..=0x03`, `role` outside `0x01..=0x04`, and malformed UUID (via `Uuid::parse_str` returning `Err`). `generation` is a `u32` so range is enforced by type. Unit tests cover canonical layout byte-by-byte, generation=0/MAX boundary, and all three error paths.

### AAD seal variants — `crates/crypto/src/aes.rs`

`encrypt_aes_gcm_aad` / `decrypt_aes_gcm_aad` use `aes-gcm 0.10`'s `Payload { msg, aad }` API (no new dependency). `seal_aes_gcm_aad` / `unseal_aes_gcm_aad` mirror `seal_aes_gcm` / `unseal_aes_gcm` exactly, threading AAD through. All four are re-exported from the crate root in `lib.rs`.

### Rust cross-language KAT — `crates/crypto/tests/cross_language.rs`

`node_aad_cross_language` parses `node-aad.json` via `serde_json::Value` (top-level object with `aad_vectors` array, not a flat array). Asserts `aad_vectors.len() == 4` (four-role invariant guard), then for each entry:

```
hex::encode(build_node_aad(&v.node_id, v.kind, v.generation, v.role).unwrap()) == v.expected_aad
```

All four committed hex strings match — C-01 merge gate is now closed on both TS (plan 01) and Rust sides against the same `node-aad.json`.

## Verification Results

- `cargo test -p cipherbox-crypto --lib aes --no-default-features`: **24 tests passed** (7 new build_node_aad tests)
- `cargo test -p cipherbox-crypto --test cross_language --no-default-features`: **6 tests passed** (includes new `node_aad_cross_language`)

## Deviations from Plan

### Auto-fixed Issues

None. Plan executed exactly as written.

### TDD Note

Tests and implementation were written in the same editing session (not as separate RED/GREEN commits). Since Rust requires the function to exist before tests compile, the RED state would have been a compile error rather than a test failure. The implementation was straightforward from the frozen spec, so a single `feat` commit captures both.

## Known Stubs

None. `build_node_aad` is fully implemented and byte-identical to the TS builder for all four role bytes (proven by KAT).

## Threat Flags

None. All threat mitigations from the plan threat model are implemented:

- T-61-05 (uuid.to_string() vs as_bytes()): `Uuid::parse_str(s)?.as_bytes()` used; KAT pins exact bytes against TS ground truth
- T-61-06 (wrong-length AAD): fail-closed `Err` on all invalid inputs; 45-byte assertion in unit tests and KAT
- T-61-SC (uuid supply chain): pre-approved in RESEARCH Package Legitimacy Audit; uuid 1.20.0 resolved

## Self-Check: PASSED

- `crates/crypto/src/aes.rs`: `build_node_aad` exists with `NODE_SEAL_DOMAIN` constant and 7 unit tests
- `crates/crypto/src/error.rs`: `InvalidAadInput` variant present
- `crates/crypto/src/lib.rs`: `build_node_aad` and AAD variants re-exported
- `crates/crypto/tests/cross_language.rs`: `node_aad_cross_language` test present and passing
- Commits bc091aa46 and 86cb7be20 confirmed in git log
- Both test commands green
