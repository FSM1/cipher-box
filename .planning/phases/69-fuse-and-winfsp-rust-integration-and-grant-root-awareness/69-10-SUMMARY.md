---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 10
subsystem: infra
tags: [rust, crates-core, fuse, node-model, legacy-retirement, d-04]

# Dependency graph
requires:
  - phase: 69-09
    provides: FUSE read/write/replay/delete/rename path moved onto the Node model
  - phase: 69-19
    provides: recycle-bin BinEntry reshaped to node/v3 (bin.rs no longer names FilePointer/FolderEntry)
  - phase: 69-20
    provides: vault-creation emits an empty node/v3 Root (vault.rs no longer names FolderMetadata)
provides:
  - Legacy folder-model types deleted from crates/core (FolderMetadata/FolderChild/FolderEntry/FilePointer/FileMetadata + encrypt/decrypt helpers)
  - Dead decrypt.rs IPFS helpers removed; module dropped from lib.rs
  - Legacy fuse consumers removed (merge_folder_children, encrypt_metadata_to_json, publish_file_metadata) + their tests/re-exports
  - crates/core::folder::VersionEntry retained as the single intentionally-kept legacy type (helpers.rs consumer)
  - Single Node model in crates/core with no legacy<->Node bridge (D-04 clean cutover)
affects: [69-14]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-04 single-codec doctrine: no From<FolderMetadata>/From<FileMetadata>/to_node bridge left behind"
    - "default=[\"fuse\"] feature gate defers winfsp-tree breakage to 69-14 without blocking the default build"

key-files:
  created: []
  modified:
    - crates/core/src/folder.rs
    - crates/core/src/file.rs
    - crates/core/src/lib.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/content_ops.rs
    - crates/fuse/src/lib.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
  deleted:
    - crates/core/src/decrypt.rs

key-decisions:
  - "Deleted crates/core/src/decrypt.rs entirely (both helpers dead, no non-def callers) rather than leaving an empty module"
  - "Reduced folder.rs to hold only VersionEntry; kept pub mod folder + re-exported VersionEntry once from folder in lib.rs"
  - "Dropped now-unused FolderError/aes/zeroize imports from folder.rs since VersionEntry needs only serde derives"
  - "publish_file_node is now the single per-file publish path; its doc comment was rewritten to remove FileMetadata/publish_file_metadata references"
  - "winfsp build left RED by design (deferred to 69-14); on macOS it fails at the windows-* dependency crates (CI-only)"

patterns-established:
  - "Pattern 1: rustfmt on a crate-root (lib.rs) recursively reformats the whole module tree — format module files individually and git checkout -- any out-of-scope reformat"

requirements-completed: [SC-04]

coverage:
  - id: D1
    description: "Legacy folder-model types (FolderMetadata/FolderChild/FolderEntry/FilePointer/FileMetadata + encrypt/decrypt helpers) deleted from crates/core; VersionEntry retained"
    requirement: SC-04
    verification:
      - kind: unit
        ref: "cargo test -p cipherbox-core (1 passed, 0 failed)"
        status: pass
      - kind: other
        ref: "grep -rnE '\\b(FolderMetadata|FolderChild|FolderEntry|FilePointer|FileMetadata)\\b' crates/core/src — no type references (only unrelated InvalidFolderMetadata error variant + doc comment)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Default fuse build green on the single Node model; legacy fuse/desktop consumers removed (merge_folder_children, encrypt_metadata_to_json, publish_file_metadata)"
    requirement: SC-04
    verification:
      - kind: integration
        ref: "cargo check --workspace + cargo test --workspace --no-default-features --features fuse (all suites pass, 0 failed)"
        status: pass
    human_judgment: false

# Metrics
duration: 10min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 10: Delete Legacy Folder-Model Types (P4c / D-04) Summary

**Deleted the legacy `FolderMetadata`/`FolderChild`/`FolderEntry`/`FilePointer`/`FileMetadata` types + their encrypt/decrypt helpers from crates/core (retaining only `VersionEntry`) and removed every remaining default-build consumer — the D-04 clean core cutover to the single Node model, with the winfsp tree deferred to 69-14.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-07-06T20:17:00Z
- **Completed:** 2026-07-06T20:26:41Z
- **Tasks:** 2
- **Files modified:** 7 (+1 deleted)

## Accomplishments
- Reduced `crates/core/src/folder.rs` to hold only `VersionEntry`; deleted `FolderMetadata`/`FolderChild`/`FolderEntry`/`FilePointer`/`FileMetadata`, `encrypt_folder_metadata`/`decrypt_folder_metadata`, `encrypt_file_metadata`/`decrypt_file_metadata`, `default_encryption_mode`, and their `#[cfg(test)]` tests.
- Deleted `crates/core/src/decrypt.rs` (both dead IPFS helpers) and dropped `pub mod decrypt;` + its re-export from `lib.rs`.
- Reduced `file.rs` to `pub use crate::folder::VersionEntry;` and re-exported `VersionEntry` once from `folder` in `lib.rs`.
- Removed the default-build fuse consumers: `merge_folder_children` + `encrypt_metadata_to_json` (metadata.rs) and the legacy `publish_file_metadata` (content_ops.rs), plus their tests and lib.rs re-exports.
- Removed the `encrypt_metadata_to_json` import + the merge-test block from the desktop `fuse/mod.rs` (keeping the unrelated `default_journal_dir` test).
- `cargo check --workspace` and `cargo test --workspace --no-default-features --features fuse` both green; no legacy<->Node bridge introduced.

## Task Commits

Each task was committed atomically:

1. **Task 1: Delete legacy types from crates/core (retain VersionEntry); drop dead decrypt helpers** - `a4af46256` (refactor)
2. **Task 2: Remove remaining default-build consumers (fuse metadata/content_ops + desktop tests)** - `edcfddabf` (refactor)

## Files Created/Modified
- `crates/core/src/folder.rs` - Reduced to the `VersionEntry` struct only; all legacy folder/file metadata types + helpers removed.
- `crates/core/src/file.rs` - Re-export reduced to `pub use crate::folder::VersionEntry;`.
- `crates/core/src/decrypt.rs` - **Deleted** (both `decrypt_metadata_from_ipfs_public` / `decrypt_file_metadata_from_ipfs_public` were dead).
- `crates/core/src/lib.rs` - Dropped `pub mod decrypt;` and the deleted re-exports; `pub use folder::VersionEntry;` retained.
- `crates/fuse/src/metadata.rs` - Deleted `encrypt_metadata_to_json` + `merge_folder_children` and their `#[cfg(test)]` merge tests.
- `crates/fuse/src/content_ops.rs` - Deleted legacy `publish_file_metadata`; rewrote the `publish_file_node` doc comment to drop `FileMetadata`/`publish_file_metadata` references.
- `crates/fuse/src/lib.rs` - Dropped `encrypt_metadata_to_json`/`merge_folder_children` from the metadata re-export; refreshed a stale comment.
- `apps/desktop/src-tauri/src/fuse/mod.rs` - Removed the `encrypt_metadata_to_json` import + the merge-test block.

## Green Boundary (verified in this worktree)

| Check | Result | Evidence |
|-------|--------|----------|
| `cargo check --workspace` (default fuse) | GREEN | Finished dev profile; all crates compiled |
| `cargo test --workspace --no-default-features --features fuse` | GREEN | Every suite `test result: ok` — 0 failed (core 1, fuse/api-client/sdk/crypto suites all pass) |
| Residual grep (deleted types/fns, excl winfsp trees + comments) | CLEAN | Only substring/prose hits remain: `PendingFilePointer` (a distinct live type), `InvalidFolderMetadata` (unrelated error variant), CHANGELOG/CLAUDE.md docs, and `FilePointer` inside `log::debug!`/`log::warn!` string literals in 69-09-owned files — no live deleted-type/fn usage |
| `--features winfsp` | RED (EXPECTED) | Deferred to 69-14. On macOS fails at the `windows-future`/`windows_core::imp::IMarshal` dependency crates (winfsp is CI-only here); on the Windows runner the still-present `publish_file_metadata` callers (`platform/windows/operations.rs:272`, `write_ops.rs:18,983`) + the deleted types break — closed out by 69-14 |

### Survivors confirmed
- `crates/core::folder::VersionEntry` retained (`pub struct VersionEntry` present, `pub mod folder` present) — consumed by `crates/fuse/src/helpers.rs` (`apply_versioning`/`versions_to_bin_entries`).
- node/v3 types (`crates/core/src/node/*`) untouched.
- `publish_file_node` (the live node/v3 per-file publish) retained and is now the single per-file publish path.
- No `From<FolderMetadata>`/`From<FileMetadata>`/`to_node`/`from_legacy`/`into_node` adapter exists (grep empty) — D-04 single-codec doctrine enforced.

## Decisions Made
- Deleted `decrypt.rs` outright (both helpers dead) rather than leaving an empty module — cleaner than a stub file.
- Dropped `FolderError`/`aes`/`zeroize` imports from `folder.rs`: `VersionEntry` needs only serde derives, so the crypto imports became unused.
- Left benign prose references intact (log-string `FilePointer` messages in 69-09-owned `fs.rs`/`read_ops.rs`/`prepopulate.rs`, `apps/desktop/CLAUDE.md` doc, `crates/fuse/CHANGELOG.md`) — these are not code references to the deleted type and are out of this plan's scope.

## Deviations from Plan

None functional — plan executed as written. Two mechanical scope-guard actions worth noting:

**1. [Scope guard] Reverted rustfmt collateral on out-of-scope files**
- **Found during:** Both tasks (after `rustfmt ... lib.rs`).
- **Issue:** Passing a crate-root `lib.rs` to `rustfmt` recursively reformats the entire module tree, touching out-of-scope files (crates/core: `ipns.rs`, `node/decode.rs`, `vault_blob.rs`; crates/fuse: `file_handle.rs`, `helpers.rs`, `platform/macos.rs`, `platform/windows/*`, `write_ops/mod.rs`).
- **Fix:** `git checkout --` on every out-of-scope reformatted file; kept only the 8 in-scope files. Verified the committed tree touches only `files_modified`.
- **Verification:** `git status --short` shows only the in-scope files before each commit.

## Issues Encountered
- Initial Task 1 `git add` aborted because `decrypt.rs` was already staged via `git rm` (pathspec no longer matched), so only the deletion landed in the first commit attempt. Resolved by `git commit --amend` after staging the remaining core files. Final Task 1 commit `a4af46256` contains all 4 core changes.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SC-04 satisfied: the legacy folder-model types are gone from crates/core; the default `fuse` build (core + sdk + Unix fuse + desktop) is on the single Node model.
- **This completes the phase's non-Windows legacy-retirement work.** The only remaining legacy-type surface is the `#[cfg(feature="winfsp")]` Windows tree (`crates/fuse/src/platform/windows/*`, `apps/desktop/src-tauri/src/fuse/windows/*`), which still names the deleted types + `publish_file_metadata` and is closed out by **69-14** (the plan that exercises `--features winfsp` on the Windows CI job).

## Self-Check: PASSED

All modified files present; `crates/core/src/decrypt.rs` confirmed deleted; both task commits (`a4af46256`, `edcfddabf`) present in git history.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*
