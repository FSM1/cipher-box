---
phase: 51-crypto-signature-secret-leak-hardening
plan: "03"
subsystem: rust-client-crypto
tags:
  - ipns-signature-verification
  - zeroizing
  - ecies
  - fuse
  - s2
  - s3
dependency_graph:
  requires:
    - 51-01 (S1 server-side embed-vs-DTO validation)
    - 51-02 (S2 web/sdk-core fail-closed)
  provides:
    - verify_ipns_resolve_signature in cipherbox-api-client
    - S2 Rust client signature verification parity with web and sdk-core
    - Zeroizing<Vec<u8>> from unwrap_key (S3/D-05 Rust half)
  affects:
    - crates/crypto/src/ecies.rs (return type change)
    - crates/fuse/src/lib.rs (BFS queue, get_folder_key, verify gate)
    - crates/api-client/src/ipns.rs (new verify fn)
    - crates/api-client/src/types.rs (3 optional sig fields)
tech_stack:
  added:
    - cipherbox-crypto workspace dep in crates/api-client
  patterns:
    - TDD (RED commit 3fb891a21, GREEN commit 03e46d271)
    - Zeroizing<Vec<u8>> via zeroize crate (existing pattern, extended)
    - let-else for absent-field early return in verify fn
key_files:
  created: []
  modified:
    - crates/api-client/Cargo.toml
    - crates/api-client/src/types.rs
    - crates/api-client/src/ipns.rs
    - crates/crypto/src/ecies.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/inode.rs
    - crates/fuse/src/operations.rs
    - crates/fuse/src/journal_helpers.rs
    - crates/fuse/src/write_ops.rs
    - crates/fuse/src/platform/windows/operations.rs
    - crates/fuse/src/platform/windows/write_ops.rs
    - crates/crypto/tests/cross_language.rs
decisions:
  - "Keep resolve_folder_key_cached cache as HashMap<String, Vec<u8>> (not Zeroizing) — cache is short-lived, scoped to replay_for_vault call, cleared on drop"
  - "Verify gate applied only in resolve_folder_key BFS (key-descent path), not in fetch_merge_publish_parent (merge-publish replay) or resolve_ipns_for_replay per plan scope fence"
  - "Missing sig fields → warn+continue (D-03), not fail-closed, for backward-compat with legacy records"
metrics:
  duration: "~45 minutes"
  completed: "2026-06-19"
  tasks_completed: 4
  files_modified: 12
---

# Phase 51 Plan 03: Rust S2 Verify + S3 Zeroizing Summary

Closed S2/D-04 (Rust IPNS signature verification parity) and S3/D-05 Rust half (Zeroizing key handling across ecies + fuse).

## What Was Built

Rust signature verification for IPNS resolve responses with Zeroizing key handling throughout the FUSE key-descent path and ECIES unwrap path.

## Tasks Completed

### Task 1 (RED): IpnsResolveResponse sig fields + failing tests

- Added `cipherbox-crypto = { workspace = true }` to `crates/api-client/Cargo.toml`
- Added `signature_v2`, `data`, `pub_key` as `Option<String>` fields to `IpnsResolveResponse` with `#[serde(rename_all = "camelCase")]` mapping to `signatureV2`/`data`/`pubKey`
- Added `#[cfg(test)] mod tests` with 5 failing tests referencing unimplemented stub
- Commit: `3fb891a21` — 4 tests panicked (RED confirmed)

### Task 2 (GREEN): Implement verify_ipns_resolve_signature

- Implements D-03: `Ok(None)` when any of the 3 sig fields is absent (let-else early return)
- Implements D-02: `Ok(Some(false))` on invalid Ed25519 signature
- Implements D-04: `Ok(Some(true))` on valid signature with derived IPNS name match
- Wrong-length pubKey → `Ok(Some(false))` (fail-safe, not hard error)
- No key material in error messages
- Commit: `03e46d271` — 6 tests pass (GREEN confirmed)

### Task 3: Zeroizing unwrap_key + FUSE BFS queue + get_folder_key + caller audit

- `crates/crypto/src/ecies.rs`: `unwrap_key` returns `Result<Zeroizing<Vec<u8>>, CryptoError>`
- `crates/fuse/src/lib.rs`: BFS queue is `VecDeque<(String, Zeroizing<Vec<u8>>)>`; `get_folder_key` returns `Option<Zeroizing<Vec<u8>>>`; `spawn_file_meta_reencrypt` params are `Zeroizing<Vec<u8>>`
- Fixed all `unwrap_key` call sites removing redundant `Zeroizing::new()` wrappers: `inode.rs`, `operations.rs`, `platform/windows/operations.rs`, `lib.rs` (3 sites)
- Updated type annotations: `write_ops.rs`, `platform/windows/write_ops.rs`
- Updated `journal_helpers.rs` struct field to `Option<Zeroizing<Vec<u8>>>`
- Fixed `cross_language.rs` and ecies unit tests for new return type
- Commit: `8d7fe0d7b`

### Task 4: FUSE resolve callers honor verify_ipns_resolve_signature

- Added 4-arm match after each `resolve_ipns` call in `resolve_folder_key` BFS loop:
  - `Ok(None)` → `log::warn!` + continue (D-03, absent fields backward-compat)
  - `Ok(Some(true))` → proceed
  - `Ok(Some(false))` → `return Err(...)` fail-closed (D-02)
  - `Err(e)` → `return Err(...)` surface verify failure
- Applied at the folder-key descent site only (not fetch_merge_publish_parent per scope fence)
- Commit: `c253b5cc7`

## Test Results

- `cargo test -p cipherbox-api-client`: 6 passed, 0 failed
- `cargo test -p cipherbox-fuse`: 60 passed, 0 failed
- `cargo test -p cipherbox-crypto` (cross-language): 5 passed, 0 failed
- `cargo build -p cipherbox-crypto -p cipherbox-fuse`: exits 0

## Deviations from Plan

### Auto-fixed Issues (Rule 3 — Blocking Issues)

**1. [Rule 3 - Cascade] Fixed all unwrap_key call sites outside files_modified**

- **Found during:** Task 3 — changing `unwrap_key` return type to `Zeroizing<Vec<u8>>`
- **Issue:** 10+ call sites in `inode.rs`, `operations.rs`, `platform/windows/operations.rs`, `write_ops.rs`, `platform/windows/write_ops.rs`, `journal_helpers.rs`, `cross_language.rs` would not compile with the new return type
- **Fix:** Removed redundant `Zeroizing::new()` wrappers; updated type annotations; updated struct field types; updated assert comparisons in tests
- **Files modified:** crates/fuse/src/inode.rs, crates/fuse/src/operations.rs, crates/fuse/src/journal_helpers.rs, crates/fuse/src/write_ops.rs, crates/fuse/src/platform/windows/operations.rs, crates/fuse/src/platform/windows/write_ops.rs, crates/crypto/tests/cross_language.rs
- **Commit:** 8d7fe0d7b

**2. [Rule 3 - Scope] resolve_folder_key_cached cache left as Vec<u8>**

- **Decision:** The plan specified BFS queue and `get_folder_key` return as `Zeroizing`, but didn't mention the memoizing cache. The cache is cleared at the end of `replay_for_vault` and is short-lived. Changed only the BFS-queue, `get_folder_key`, and `spawn_file_meta_reencrypt` params per plan spec.

## Known Stubs

None — all functionality fully implemented.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced. All changes are internal type-hardening and signature verification.

## TDD Gate Compliance

- RED gate: commit `3fb891a21` (`test 51-03: add failing verify_ipns_resolve_signature tests`)
- GREEN gate: commit `03e46d271` (`feat 51-03: implement verify_ipns_resolve_signature`)
- REFACTOR: not needed (clean first implementation)

## Self-Check: PASSED

Files confirmed present:

- crates/api-client/Cargo.toml contains `cipherbox-crypto`: FOUND
- crates/api-client/src/types.rs contains `signature_v2`: FOUND
- crates/api-client/src/ipns.rs exports `verify_ipns_resolve_signature` with `#[cfg(test)]` module: FOUND
- crates/crypto/src/ecies.rs `unwrap_key` returns `Zeroizing`: FOUND
- crates/fuse/src/lib.rs contains `verify_ipns_resolve_signature` and `VecDeque<(String, Zeroizing<Vec<u8>>)>`: FOUND

Commits confirmed:

- 3fb891a21: test 51-03 RED
- 03e46d271: feat 51-03 GREEN
- 8d7fe0d7b: feat 51-03 S3 Zeroizing
- c253b5cc7: feat 51-03 FUSE verify gate
