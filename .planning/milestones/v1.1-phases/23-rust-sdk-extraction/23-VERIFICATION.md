---
phase: 23-rust-sdk-extraction
verified: 2026-03-24T12:30:00Z
status: passed
score: 5/5 success criteria verified (re-verified 2026-06-18 — both gaps closed)
re_verification:
  previous_status: gaps_found
  previous_score: 4/5
  reverified: 2026-06-18
  gaps_closed:
    - 'Orphaned legacy FUSE files deleted — apps/desktop/src-tauri/src/fuse/ now contains only mod.rs + windows/mod.rs (inode/cache/operations/read_ops/write_ops/dir_ops/file_handle/helpers/constants all gone)'
    - 'WinFsp operations relocated to crates/fuse/src/platform/windows/ (read_ops/dir_ops/write_ops/operations/mod.rs) exactly as Plan 04 specified'
    - 'Cargo workspace check/test human-verification gate satisfied by .github/workflows/ci.yml — cargo check + cargo test --workspace on Windows (winfsp), macOS (fuse), Linux (fuse), continuously green'
  gaps_remaining: []
  regressions: []
# Historical gaps below were the original 2026-03-24 finding; all closed by subsequent FUSE refactors (see re_verification above).
gaps:
  - truth: 'Desktop app is a thin Tauri shell (~1,500 LOC) with all logic delegated to workspace crates'
    status: partial
    reason: >
      The desktop app compiles with ~5,064 LOC of active code (non-orphaned files), plus 2,824 LOC
      of Windows WinFsp operations that still reside in apps/desktop/src-tauri/src/fuse/windows/
      instead of being moved to crates/fuse/src/platform/windows/ as Plan 04 specified.
      Additionally, 3,767 LOC of orphaned legacy FUSE files (inode.rs, cache.rs, operations.rs,
      read_ops.rs, write_ops.rs, dir_ops.rs, file_handle.rs, helpers.rs, constants.rs) remain
      on disk in apps/desktop/src-tauri/src/fuse/ though they are not compiled. Plan 04 acceptance
      criteria explicitly required these files to NOT exist.
    artifacts:
      - path: 'apps/desktop/src-tauri/src/fuse/windows/'
        issue: '2,824 LOC of WinFsp operations remain in desktop instead of crates/fuse/src/platform/windows/'
      - path: 'apps/desktop/src-tauri/src/fuse/inode.rs'
        issue: 'Orphaned file (936 LOC) — not declared as module, not compiled, but still on disk'
      - path: 'apps/desktop/src-tauri/src/fuse/cache.rs'
        issue: 'Orphaned file (285 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/operations.rs'
        issue: 'Orphaned file (558 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/read_ops.rs'
        issue: 'Orphaned file (770 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/write_ops.rs'
        issue: 'Orphaned file (976 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/dir_ops.rs'
        issue: 'Orphaned file (242 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/file_handle.rs'
        issue: 'Orphaned file (353 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/helpers.rs'
        issue: 'Orphaned file (108 LOC) — not declared as module, not compiled'
      - path: 'apps/desktop/src-tauri/src/fuse/constants.rs'
        issue: 'Orphaned file (22 LOC) — not declared as module, not compiled'
    missing:
      - 'Delete orphaned FUSE files from apps/desktop/src-tauri/src/fuse/ (inode.rs, cache.rs, operations.rs, read_ops.rs, write_ops.rs, dir_ops.rs, file_handle.rs, helpers.rs, constants.rs)'
      - 'Move windows/ WinFsp operations to crates/fuse/src/platform/windows/ behind winfsp feature (or document intentional deviation from Plan 04)'
      - 'Create crates/fuse/src/platform/windows/ with the 5 files currently in desktop/fuse/windows/'
human_verification:
  - test: 'Run cargo test --workspace --no-default-features --features fuse'
    expected: 'All workspace tests pass with zero errors'
    why_human: 'Cannot run cargo test in this environment — agent cannot execute long-running Rust compilation'
  - test: 'Run cargo check --workspace --no-default-features --features fuse'
    expected: 'Zero compilation errors; acceptable warnings only in vendored fuser'
    why_human: 'Cannot run cargo compile in this environment'
---

# Phase 23: Rust SDK Extraction Verification Report

**Phase Goal:** Extract five Rust crates (cipherbox-crypto, cipherbox-core, cipherbox-api-client, cipherbox-fuse, cipherbox-sdk) mirroring the TypeScript SDK hierarchy, replace duplicated logic in desktop FUSE code, enable unit testing at same granularity as TypeScript. Desktop app becomes a thin Tauri shell.
**Verified:** 2026-03-24T12:30:00Z
**Status:** passed (re-verified 2026-06-18 — both gaps closed)
**Re-verification:** Yes — closed 2026-06-18 (original: 2026-03-24, gaps_found 4/5)

## Goal Achievement

### Observable Truths (from ROADMAP.md Success Criteria)

| #   | Truth                                                                                                | Status   | Evidence                                                                                                                                                                                                                                                                      |
| --- | ---------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Five Rust crates compile independently under a Cargo workspace with centralized dependency versions  | VERIFIED | Root Cargo.toml has `[workspace]` with all 5 members; each crate has its own Cargo.toml with `workspace = true` dependencies                                                                                                                                                  |
| 2   | Desktop app is a thin Tauri shell (~1,500 LOC) with all logic delegated to workspace crates          | PARTIAL  | ~5,064 LOC active (3.4x target); Windows WinFsp operations (2,824 LOC) still in desktop instead of crates/fuse; 9 orphaned legacy files (3,767 LOC) remain on disk but are not compiled                                                                                       |
| 3   | Cross-language test vectors in `tests/vectors/` produce identical output in both Rust and TypeScript | VERIFIED | 9 JSON vector files in tests/vectors/; cross_language.rs has 4 test functions (aes_gcm_cross_language, ed25519_cross_language, hkdf_cross_language, ipns_name_cross_language) loading shared vectors                                                                          |
| 4   | CI runs workspace-level builds on macOS, Linux, and Windows with cross-language parity gate          | VERIFIED | ci.yml uses `cargo check/test --workspace` on all 3 platforms; `vector-parity` CI job added; cache keys reference root Cargo.lock; path filter includes crates/\*\*                                                                                                           |
| 5   | No duplicated crypto, domain, or API logic remains in the desktop app                                | PARTIAL  | No duplicated crypto/domain/API logic — those directories deleted. However Windows WinFsp operations (2,824 LOC compiled) remain in desktop/fuse/windows/ and orphaned FUSE files (3,767 LOC) remain on disk. Plan 04 acceptance criteria explicitly required their deletion. |

**Score:** 3/5 truths fully verified (2 partial, blocking one requirement)

### Required Artifacts

| Artifact                                   | Expected                                 | Status   | Details                                                                                                                                                 |
| ------------------------------------------ | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Cargo.toml`                               | Workspace root with centralized deps     | VERIFIED | Contains `[workspace]`, `resolver = "2"`, 5 members, `[workspace.dependencies]`, `[patch.crates-io]` for vendored fuser                                 |
| `crates/crypto/Cargo.toml`                 | cipherbox-crypto manifest                | VERIFIED | `name = "cipherbox-crypto"`, all deps use `workspace = true`                                                                                            |
| `crates/crypto/src/lib.rs`                 | Crypto crate public API re-exports       | VERIFIED | 8 modules declared, all primary functions re-exported via `pub use`                                                                                     |
| `crates/crypto/src/error.rs`               | CryptoError enum                         | VERIFIED | `pub enum CryptoError` with 15 variants                                                                                                                 |
| `crates/core/Cargo.toml`                   | cipherbox-core manifest                  | VERIFIED | `name = "cipherbox-core"`, depends on `cipherbox-crypto`                                                                                                |
| `crates/core/src/lib.rs`                   | Core crate public API                    | VERIFIED | `pub mod folder`, `pub mod ipns`, `pub mod vault_blob`, `pub mod bin`, `pub mod registry`, `pub mod decrypt`                                            |
| `crates/core/src/error.rs`                 | CoreError with #[from] CryptoError       | VERIFIED | `pub enum CoreError` with `Crypto(#[from] cipherbox_crypto::CryptoError)`                                                                               |
| `crates/core/src/ipns.rs`                  | IPNS record creation                     | VERIFIED | `pub fn create_ipns_record` present, imports `cipherbox_crypto::`                                                                                       |
| `crates/api-client/Cargo.toml`             | API client manifest                      | VERIFIED | `name = "cipherbox-api-client"`, no `tauri` or `cipherbox-crypto` deps                                                                                  |
| `crates/api-client/src/lib.rs`             | API client public API                    | VERIFIED | `pub mod client`, `pub mod auth`, `pub mod ipfs`, `pub mod ipns`, `pub mod types`                                                                       |
| `crates/fuse/Cargo.toml`                   | FUSE crate manifest with feature flags   | VERIFIED | `name = "cipherbox-fuse"`, features `fuse` and `winfsp` defined                                                                                         |
| `crates/fuse/src/lib.rs`                   | FUSE crate public API                    | VERIFIED | `pub mod inode`, `pub mod cache`, `pub mod file_handle`, `pub mod platform`; ops behind `#[cfg(feature = "fuse")]`                                      |
| `crates/fuse/src/inode.rs`                 | Platform-agnostic InodeTable             | VERIFIED | `pub struct InodeTable` present; imports `cipherbox_core::folder::FolderMetadata`                                                                       |
| `crates/fuse/src/platform/mod.rs`          | Platform dispatch with feature gates     | VERIFIED | `#[cfg(feature = "winfsp")] pub mod windows;` — but `windows/` directory does not exist                                                                 |
| `crates/sdk/Cargo.toml`                    | SDK manifest                             | VERIFIED | `name = "cipherbox-sdk"`, depends on crypto/core/api-client; NO `tauri`                                                                                 |
| `crates/sdk/src/lib.rs`                    | SDK public API                           | VERIFIED | `pub mod sync`, `pub mod queue`, `pub mod state`, `pub mod registry`                                                                                    |
| `crates/sdk/src/sync.rs`                   | SyncDaemon without Tauri                 | VERIFIED | `pub struct SyncDaemon` with `status_callback: Arc<dyn Fn(SyncStatus) + Send + Sync>`; no Tauri imports                                                 |
| `crates/sdk/src/state.rs`                  | KeyState                                 | VERIFIED | `pub struct KeyState` with all key material fields; no Tauri dependency                                                                                 |
| `tests/vectors/crypto/aes-gcm.json`        | AES-GCM cross-language test vectors      | VERIFIED | 1 vector with keys: description, key, iv, plaintext, ciphertext                                                                                         |
| `tests/vectors/crypto/hkdf.json`           | HKDF vectors                             | VERIFIED | 5 vectors covering vault, vault-key, file, registry, bin IPNS keypair derivations                                                                       |
| `crates/crypto/tests/cross_language.rs`    | Rust cross-language parity tests         | VERIFIED | Functions: aes_gcm_cross_language, ed25519_cross_language, hkdf_cross_language, ipns_name_cross_language; loads from `tests/vectors/crypto/`            |
| `.github/workflows/ci.yml`                 | CI with workspace builds and parity gate | VERIFIED | All 3 platform jobs use `cargo check/test --workspace`; `vector-parity` job added; cache keys use root `Cargo.lock`                                     |
| `scripts/check-vector-parity.sh`           | Parity verification script               | VERIFIED | Executable; validates all 9 vector files; checks Rust tests reference vectors                                                                           |
| `release-please-config.json`               | Release Please with Rust crate entries   | VERIFIED | 5 entries with `"release-type": "rust"` and `"include-component-in-tag": true`                                                                          |
| `apps/desktop/src-tauri/src/fuse/inode.rs` | Should NOT exist (moved to crate)        | FAILED   | File exists (936 LOC, orphaned — not declared as module)                                                                                                |
| `apps/desktop/src-tauri/src/fuse/windows/` | Should NOT exist (moved to crate)        | FAILED   | Directory exists with 2,824 LOC of active WinFsp code; plan/windows/ stub declared in crates/fuse/src/platform/mod.rs but directory missing from crates |

### Key Link Verification

| From                                     | To                                  | Via                                          | Status   | Details                                                                                                                |
| ---------------------------------------- | ----------------------------------- | -------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------- |
| `apps/desktop/src-tauri/Cargo.toml`      | all crates                          | workspace dependencies                       | VERIFIED | `cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`, `cipherbox-fuse`, `cipherbox-sdk` all `workspace = true` |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | `crates/fuse/src/lib.rs`            | `pub use cipherbox_fuse::*` re-exports       | VERIFIED | mod.rs imports `CipherBoxFS`, `inode`, `file_handle`, `helpers`, `constants` from cipherbox_fuse                       |
| `apps/desktop/src-tauri/src/state.rs`    | `crates/sdk/src/state.rs`           | `use cipherbox_sdk::KeyState`                | VERIFIED | `AppState.sdk: Arc<KeyState>`; delegates key zeroization to `KeyState.clear()`                                         |
| `apps/desktop/src-tauri/src/sync/mod.rs` | `crates/sdk/src/sync.rs`            | `pub use cipherbox_sdk::SyncDaemon`          | VERIFIED | Thin bridge creates SyncDaemon with Tauri tray status callback                                                         |
| `crates/fuse/src/inode.rs`               | `crates/core/src/folder.rs`         | `cipherbox_core::folder::FolderMetadata`     | VERIFIED | inode.rs uses `cipherbox_core::folder::{FolderChild, FolderMetadata}`                                                  |
| `crates/core/src/ipns.rs`                | `crates/crypto/src/ed25519.rs`      | `cipherbox_crypto::sign_ed25519`             | VERIFIED | ipns.rs imports from `cipherbox_crypto::` (not `super::ed25519`)                                                       |
| `crates/sdk/src/sync.rs`                 | `crates/api-client/src/client.rs`   | ApiClient for IPNS polling                   | VERIFIED | SyncDaemon uses KeyState.api (Arc<ApiClient>)                                                                          |
| `crates/crypto/tests/cross_language.rs`  | `tests/vectors/crypto/aes-gcm.json` | serde_json load via CARGO_MANIFEST_DIR       | VERIFIED | Pattern `tests/vectors/crypto` present; vectors_path() resolves relative to workspace                                  |
| `crates/fuse/src/platform/mod.rs`        | `crates/fuse/src/platform/windows/` | `#[cfg(feature = "winfsp")] pub mod windows` | BROKEN   | Module declaration exists but `windows/` directory does not exist in crates/fuse/src/platform/                         |
| `.github/workflows/ci.yml`               | `Cargo.toml`                        | workspace-level cargo commands               | VERIFIED | All platform jobs use `cargo --workspace`                                                                              |
| `scripts/check-vector-parity.sh`         | `tests/vectors/`                    | test vector JSON files                       | VERIFIED | Script validates all 9 expected vector files                                                                           |

### Requirements Coverage

| Requirement | Source Plan | Description                                                                                             | Status    | Evidence                                                                                                                                                                                                    |
| ----------- | ----------- | ------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RSDK-01     | 23-01       | Cargo workspace at repo root with centralized `[workspace.dependencies]`                                | SATISFIED | Root Cargo.toml with `[workspace]`, `[workspace.dependencies]`, all 5 crates as members                                                                                                                     |
| RSDK-02     | 23-01       | `cipherbox-crypto` contains pure crypto primitives with no domain knowledge                             | SATISFIED | 8 modules (aes, aes_ctr, ecies, ed25519, hkdf, ipns_name, utils, error); no cipherbox-core dependency                                                                                                       |
| RSDK-03     | 23-03       | Shared JSON test vectors loaded by both Rust and TypeScript                                             | SATISFIED | 9 JSON files in tests/vectors/; Rust cross_language.rs loads 5+ vector files; both test suites share the same vectors                                                                                       |
| RSDK-04     | 23-02       | `cipherbox-core` contains domain types, metadata encrypt/decrypt, vault blob v2, IPNS records           | SATISFIED | 8 modules (folder, file, registry, bin, vault_blob, ipns, decrypt, error); all domain types present                                                                                                         |
| RSDK-05     | 23-03       | `cipherbox-api-client` provides typed HTTP client for all CipherBox API endpoints                       | SATISFIED | Crate with ApiClient, auth, ipfs, ipns, types modules; no Tauri/cipherbox-crypto deps                                                                                                                       |
| RSDK-06     | 23-04       | `cipherbox-fuse` with platform-agnostic abstractions and platform-specific modules behind feature flags | PARTIAL   | Platform-agnostic modules present and correct; macOS/Linux platform modules present; Windows WinFsp platform module declared but `platform/windows/` directory missing from crate (code remains in desktop) |
| RSDK-07     | 23-05       | `cipherbox-sdk` contains stateful orchestration with no Tauri dependency                                | SATISFIED | SyncDaemon uses generic callback; KeyState has no Tauri fields; SDK Cargo.toml has no tauri dep                                                                                                             |
| RSDK-08     | 23-06       | Desktop app is a thin Tauri shell (commands/, tray/, main.rs) with all logic delegated                  | PARTIAL   | crypto/ and api/ directories deleted; state/sync/registry delegated to SDK; but 9 orphaned FUSE files on disk (not compiled) + Windows WinFsp operations (2,824 LOC, compiled) still in desktop             |
| RSDK-09     | 23-07       | CI uses workspace-level cargo commands, caches root Cargo.lock, includes cross-language parity gate     | SATISFIED | All 3 platform CI jobs use `cargo --workspace`; cache keys use `hashFiles('Cargo.lock')`; `vector-parity` job added                                                                                         |
| RSDK-10     | 23-07       | Release Please configured for independent versioning of all five Rust crates                            | SATISFIED | All 5 entries in release-please-config.json with `release-type: rust`; .release-please-manifest.json has `0.1.0` versions                                                                                   |

### Anti-Patterns Found

| File                                                   | Line    | Pattern                                                             | Severity | Impact                                                                                                                       |
| ------------------------------------------------------ | ------- | ------------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `crates/fuse/src/write_ops.rs`                         | 584     | `TODO: Add full re-fetch+merge+retry for parent mkdir publish (v2)` | Warning  | Incomplete write conflict handling for mkdir — known limitation                                                              |
| `apps/desktop/src-tauri/src/fuse/windows/write_ops.rs` | 194     | `TODO: Add full re-fetch+merge+retry for parent mkdir publish (v2)` | Warning  | Same TODO in Windows copy — both are the same known gap, not blocking                                                        |
| `apps/desktop/src-tauri/src/fuse/inode.rs`             | 290     | `placeholder` (comment text in documentation)                       | Info     | Word "placeholder" in a doc comment describing FilePointer behavior — not a code stub                                        |
| `crates/fuse/src/operations.rs`                        | various | `#[allow(dead_code)]` on extracted functions                        | Warning  | Functions in crate marked dead_code because desktop still uses its own local copies; noted as "future task" in 23-06-SUMMARY |

### Human Verification Required

**1. Workspace compile check**

**Test:** From repo root: `cargo check --workspace --no-default-features --features fuse`
**Expected:** Zero errors; acceptable warnings only in vendored fuser
**Why human:** Cannot run Rust compilation in this verification environment

**2. Workspace test suite**

**Test:** From repo root: `cargo test --workspace --no-default-features --features fuse`
**Expected:** All 55+ tests pass including the 4 cross_language tests loading shared vectors
**Why human:** Cannot execute long-running Rust test compilation

**3. Cross-language vector parity script**

**Test:** `bash scripts/check-vector-parity.sh`
**Expected:** Prints "=== Parity check passed ===" with OK for all 9 vector files
**Why human:** Script checks for files that exist, but cannot independently verify Rust/TS output parity without running both test suites

## Gaps Summary

**✅ Re-verified & closed 2026-06-18 (maintainer).** Both gaps below are resolved on current `main`: (1) the 9 orphaned legacy FUSE files no longer exist — `apps/desktop/src-tauri/src/fuse/` contains only `mod.rs` + `windows/mod.rs`; (2) the WinFsp operations now live in `crates/fuse/src/platform/windows/` (`read_ops`/`dir_ops`/`write_ops`/`operations`/`mod.rs`), exactly as Plan 04 specified. The cargo workspace check/test human-verification gate is satisfied by `.github/workflows/ci.yml` (`cargo check` + `cargo test --workspace` on Windows/macOS/Linux, continuously green). The original findings below are retained as the historical record. Status set to `passed`.

---

**[HISTORICAL — 2026-03-24] Two gaps blocked full goal achievement. Both related to the cipherbox-fuse Windows extraction:**

**Gap 1: Orphaned FUSE files still on disk in desktop/fuse/**

Plan 04 acceptance criteria explicitly stated that `apps/desktop/src-tauri/src/fuse/inode.rs`, `cache.rs`, `operations.rs`, and similar files should NOT exist after extraction. These 9 files (3,767 LOC total) remain on disk but are NOT declared as Rust modules anywhere, so they are not compiled. They are dead code on the filesystem. The 23-06-SUMMARY documented this as "Left extracted functions in cipherbox-fuse with #[allow(dead_code)] since desktop still uses its own local copies" — however this description appears inaccurate: the local copies are not actually used (no `mod` declarations). These files should be deleted to avoid confusion and maintain clean repository state.

**Gap 2: Windows WinFsp operations still in desktop, not in crates/fuse**

Plan 04 specified that `apps/desktop/src-tauri/src/fuse/windows/` (2,824 LOC) should be moved to `crates/fuse/src/platform/windows/`. The platform/mod.rs in the crate declares `#[cfg(feature = "winfsp")] pub mod windows;` but the `windows/` directory does not exist in crates/fuse/src/platform/. The Windows WinFsp code remains in the desktop app where it IS actively compiled (the windows/ submodules are declared in desktop/fuse/windows/mod.rs). This means the WinFsp platform logic was never extracted to the crate as intended, leaving duplicated logic in the desktop for the Windows case.

**Impact on Success Criteria:**

- Success Criterion 2 ("Desktop app is a thin Tauri shell ~1,500 LOC"): PARTIAL — 5,064 LOC active (3.4x target), ~7,888 LOC total on disk
- Success Criterion 5 ("No duplicated crypto, domain, or API logic remains"): PARTIAL — no duplicated crypto/domain/API, but Windows FUSE operations remain in desktop rather than the crate

**Non-blocking notes:**

- The single TODO in crates/fuse/src/write_ops.rs and desktop/fuse/windows/write_ops.rs (mkdir publish retry) is a known future enhancement, not a gap in the extraction goals
- The `#[allow(dead_code)]` attributes on crate functions are a code quality warning but do not affect functionality
- The crates/fuse/src/platform/mod.rs declaring `pub mod windows` without a backing directory will cause a compile error if `--features winfsp` is used with the workspace. This is a latent compilation bug.

---

_Verified: 2026-03-24T12:30:00Z_
_Verifier: Claude (gsd-verifier)_
