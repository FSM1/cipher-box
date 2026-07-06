---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 07
subsystem: infra
tags: [rust, fuse, winfsp, ipns, grant-root, rotation, shares]

# Dependency graph
requires:
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
    provides: "cipherbox_sdk::rotation::scope::has_covering_grant / CoverageParams / LocalGrantRecord (69-05)"
  - phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
    provides: "cipherbox_api_client::shares::collect_sent_shares / list_sent_shares (69-03)"
provides:
  - "crates/fuse/src/write_ops/grant_scope.rs — ancestor_ipns_chain (O(depth), zero-network inode-tree walk), build_coverage_params, grant_root_for, SentSharesCache, refresh_sent_shares"
  - "CipherBoxFS.sent_shares local cache + CipherBoxFS::refresh_sent_shares() method"
  - "write_ops module widened to any(fuse, winfsp) so Windows write handlers (69-14) can reach the same grant_scope module as Unix (69-11)"
affects: [69-11, 69-14]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Ancestor walk over the already-mounted InodeTable (parent_ino chaining to ROOT_INO) as the local, zero-network source of a mutated node's IPNS-name ancestry"
    - "grant_root_for wraps has_covering_grant per-candidate-ancestor instead of reimplementing the coverage predicate"
    - "Local cache (refreshed out-of-band, read synchronously) as the client-side source for both the relay completeness-aid set and the anti-malicious-relay local_grant_record cross-check, mirroring apps/web/src/services/rotation-driver.service.ts's getActiveGrantRootIpnsNames/getLocalGrantRecord over the same sentShares store"

key-files:
  created:
    - crates/fuse/src/write_ops/grant_scope.rs
  modified:
    - crates/fuse/src/write_ops/mod.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/test_support.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs

key-decisions:
  - "ancestor_ipns_chain takes &InodeTable (not the full CipherBoxFS) — decouples the walk from the heavyweight FS struct (tokio Handle, open file handles, etc.) so it is trivially unit-testable over a synthetic table"
  - "grant_root_for wraps has_covering_grant by constructing a single-ancestor CoverageParams per candidate and delegating the boolean check, rather than reimplementing the relay-set/local-record membership logic inline (Pitfall 1)"
  - "build_coverage_params derives BOTH active_grant_root_ipns_names (the full cached set) and local_grant_record (the first/closest matching ancestor) from the SAME SentSharesCache — this client currently has one grant-set source (list_sent_shares), so both CoverageParams inputs are cache-derived, mirroring the shipped web pattern where getActiveGrantRootIpnsNames and getLocalGrantRecord both read the same sentShares store"
  - "sent_shares field added to CipherBoxFS in crates/fuse/src/fs.rs, not lib.rs — the plan's read_first pointed at lib.rs, but the struct itself moved to fs.rs in an earlier lib.rs decomposition (lib.rs now only re-exports it); documented as a deviation below"
  - "refresh_sent_shares is exposed as a callable async method on CipherBoxFS (manual/on-demand hook) but is NOT wired into the mount-init call path or a periodic timer in this plan — that wiring belongs to the write-handler rewiring plans (69-11/69-14) per this plan's explicitly additive, non-rewiring scope"

patterns-established:
  - "Shared, platform-agnostic write_ops submodules live at write_ops::<name> under #[cfg(any(feature = \"fuse\", feature = \"winfsp\"))], sibling to the fuse-only write_ops::implementation submodule tree"

requirements-completed: [SC-03]

coverage:
  - id: D1
    description: "ancestor_ipns_chain computes a mutated inode's leaf-first IPNS-name ancestry by walking parent_ino up to ROOT_INO over the already-mounted InodeTable, with zero network calls"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs#ancestor_ipns_chain_is_leaf_first_over_a_synthetic_tree"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs#ancestor_ipns_chain_from_a_folder_starts_with_that_folder"
        status: pass
    human_judgment: false
  - id: D2
    description: "grant_root_for selects the closest (leaf-first) ancestor covered by a grant root by wrapping cipherbox_sdk::rotation::scope::has_covering_grant, never reimplementing the predicate"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs#grant_root_for_selects_the_closest_ancestor_that_is_a_grant_root"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs#grant_root_for_returns_none_when_no_ancestor_is_covered"
        status: pass
    human_judgment: false
  - id: D3
    description: "SentSharesCache is populated from collect_sent_shares (69-03) and build_coverage_params reads it synchronously to build CoverageParams for has_covering_grant, with zero per-mutation network calls"
    requirement: "SC-03"
    verification:
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs#build_coverage_params_populates_local_grant_record_from_the_cache"
        status: pass
      - kind: other
        ref: "cargo check --workspace (default features)"
        status: pass
    human_judgment: false
  - id: D4
    description: "grant_scope is a single shared module reachable by both the Unix (fuse) and Windows (winfsp) feature sets, never duplicated per platform"
    requirement: "SC-03"
    verification:
      - kind: other
        ref: "grep -rn 'has_covering_grant|ancestor' crates/fuse/src shows one grant_scope module referenced, not reimplemented, from write_ops/mod.rs (any(fuse,winfsp)) and lib.rs"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-06
status: complete
---

# Phase 69 Plan 07: Grant-Root Scope Module Summary

**Net-new `crates/fuse::write_ops::grant_scope` module: a zero-network leaf-first ancestor walk over the mounted inode tree, wrapping `cipherbox_sdk::rotation::scope::has_covering_grant`, backed by a local sent-shares cache on `CipherBoxFS` — shared verbatim by both the future Unix and Windows write handlers.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-06T03:09:00Z
- **Completed:** 2026-07-06T03:34:00Z
- **Tasks:** 2
- **Files modified:** 7 (1 created, 6 modified)

## Accomplishments

- `ancestor_ipns_chain(&InodeTable, start_ino) -> Vec<String>` walks `parent_ino` from the mutated node up to `ROOT_INO`, collecting `Folder`/`Root` `ipns_name` and resolved-`File` `file_meta_ipns_name`, leaf-first (node itself first, vault root last), O(depth), purely in-memory
- `build_coverage_params` and `grant_root_for` wrap `cipherbox_sdk::rotation::scope::has_covering_grant` (69-05) instead of reimplementing the relay-set / local-record coverage predicate
- `SentSharesCache` + `refresh_sent_shares` (free async fn) source the grant-root set from `cipherbox_api_client::shares::collect_sent_shares` (69-03) — a local, out-of-band-refreshed cache, never queried inline on the delete/rename hot path
- `CipherBoxFS` gained a `sent_shares: RwLock<SentSharesCache>` field and a `refresh_sent_shares(&self)` method, wired into both the Unix and Windows mount-glue construction sites and the fuse-only test harness
- `write_ops` module gating widened from `feature = "fuse"` to `any(feature = "fuse", feature = "winfsp")` (both in `lib.rs`'s module declaration and via a new sibling `pub mod grant_scope;` in `write_ops/mod.rs`) so the Windows write handlers (69-14) can consume the identical module the Unix handlers (69-11) will use — never a per-platform copy

## Task Commits

Each task was committed atomically:

1. **Task 1: ancestor-walk + coverage-params builder over the mounted inode tree** - `a1405dc38` (feat)
2. **Task 2: sent-shares local cache on FS state + refresh from list_sent_shares** - `bb8333a90` (feat)

_Note: no TDD tasks in this plan; both are plain `type="auto"` tasks._

## Files Created/Modified

- `crates/fuse/src/write_ops/grant_scope.rs` - New module: `ancestor_ipns_chain`, `SentSharesCache`, `refresh_sent_shares`, `build_coverage_params`, `grant_root_for`, plus 6 unit tests
- `crates/fuse/src/write_ops/mod.rs` - Added `#[cfg(any(feature = "fuse", feature = "winfsp"))] pub mod grant_scope;` as a sibling to the fuse-only `implementation` submodule tree
- `crates/fuse/src/lib.rs` - Widened `pub mod write_ops;`'s cfg gate from `feature = "fuse"` to `any(feature = "fuse", feature = "winfsp")`
- `crates/fuse/src/fs.rs` - Added `sent_shares` field to `CipherBoxFS` + `refresh_sent_shares(&self)` inherent method
- `crates/fuse/src/test_support.rs` - Wired `sent_shares: RwLock::new(SentSharesCache::empty())` into the `make_test_fs_with_keypair` test harness constructor
- `apps/desktop/src-tauri/src/fuse/mod.rs` - Wired the new field into the Unix `CipherBoxFS` mount-glue construction site
- `apps/desktop/src-tauri/src/fuse/windows/mod.rs` - Wired the new field into the Windows `CipherBoxFS` mount-glue construction site

## Decisions Made

- `ancestor_ipns_chain` takes `&InodeTable` rather than `&CipherBoxFS`, decoupling the walk from the heavyweight FS struct (no `tokio::runtime::Handle`, no open file handles needed) so unit tests build only a synthetic `InodeTable`.
- `grant_root_for` wraps `has_covering_grant` per-candidate-ancestor (constructing a single-element `CoverageParams` per candidate) instead of hand-rolling the same membership/cross-check logic — satisfies "does NOT reimplement the predicate" literally, not just by import.
- `build_coverage_params` derives BOTH `active_grant_root_ipns_names` (the cache's full root set) and `local_grant_record` (the closest matching ancestor) from the SAME `SentSharesCache`. This client currently has one grant-set source (`list_sent_shares`), so both `CoverageParams` inputs are cache-derived — mirroring the shipped web pattern (`rotation-driver.service.ts`'s `getActiveGrantRootIpnsNames`/`getLocalGrantRecord`, both reading the same `sentShares` store).
- `refresh_sent_shares` is exposed as a callable method (the "manual/periodic refresh hook" the plan calls for) but this plan does NOT wire it into the mount-init call path or a periodic timer — that belongs to 69-11/69-14, which will actually consume the module for delete/rename. This plan is additive only, per its own scope note.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `sent_shares` field added to `crates/fuse/src/fs.rs`, not `lib.rs`**
- **Found during:** Task 2
- **Issue:** The plan's `files_modified` frontmatter and Task 2's `<read_first>` point at `crates/fuse/src/lib.rs` as "the `CipherBoxFS` state struct — where api/rt live." A prior (already-merged) lib.rs decomposition moved the actual `pub struct CipherBoxFS { ... }` definition and its inherent `impl` block into `crates/fuse/src/fs.rs`; `lib.rs` now only contains `#[cfg(any(feature = "fuse", feature = "winfsp"))] pub mod fs;` and a re-export (`pub use fs::{CipherBoxFS, mount_point};`). Adding the field to `lib.rs` as written would not compile — there is no struct definition there to modify.
- **Fix:** Added the `sent_shares` field and `refresh_sent_shares` method to `crates/fuse/src/fs.rs` (the actual struct/impl site). `lib.rs` was still modified in this plan, but for the correct purpose: widening the `write_ops` module's cfg gate (Task 1), which genuinely lives in `lib.rs`.
- **Files modified:** `crates/fuse/src/fs.rs` (in place of the plan's stated `lib.rs` target for this specific field)
- **Verification:** `cargo check --workspace` green; `cargo test -p cipherbox-fuse` — 112/112 passed (0 regressions)
- **Committed in:** `bb8333a90` (Task 2 commit)

**2. [Rule 3 - Blocking] Wired the new struct field into all `CipherBoxFS` construction sites outside the plan's stated file list**
- **Found during:** Task 2
- **Issue:** `CipherBoxFS` has no `Default` impl and is constructed via three explicit field-list literals: the fuse-only test harness (`crates/fuse/src/test_support.rs`) and the two desktop app mount-glue sites (`apps/desktop/src-tauri/src/fuse/mod.rs` for Unix, `apps/desktop/src-tauri/src/fuse/windows/mod.rs` for Windows/WinFsp). None of these three files were in the plan's `files_modified` list, but adding a new non-`Option`/non-`Default` field to the struct without updating every construction site is a compile-breaking omission (E0063 missing field), not an optional nicety.
- **Fix:** Added `sent_shares: RwLock::new(SentSharesCache::empty())` (or the crate-qualified equivalent) to all three construction sites.
- **Files modified:** `crates/fuse/src/test_support.rs`, `apps/desktop/src-tauri/src/fuse/mod.rs`, `apps/desktop/src-tauri/src/fuse/windows/mod.rs`
- **Verification:** `cargo check --workspace` compiles cleanly (including `cipherbox-desktop`); `cargo test -p cipherbox-fuse` green
- **Committed in:** `bb8333a90` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 3 - blocking compile issues caused by a stale file reference in the plan's read_first / files_modified list)
**Impact on plan:** Both auto-fixes were required for the workspace to compile at all; no scope creep beyond wiring the same new field through its unavoidable call sites. No architectural changes — the module boundaries and public API match the plan's `<artifacts_this_phase_produces>` exactly.

## Issues Encountered

None beyond the two deviations documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `crates/fuse::write_ops::grant_scope` is ready to be consumed by 69-11 (Unix delete/rename rewiring) and 69-14 (Windows write handlers) via the exact same call site: `ancestor_ipns_chain(&fs.inodes, ino)` → `build_coverage_params(&ancestors, &fs.sent_shares.read().unwrap())` → `grant_root_for` / `has_covering_grant`.
- `CipherBoxFS::refresh_sent_shares()` exists and compiles but is not yet called anywhere (no mount-init or periodic-timer wiring) — 69-11/69-14 (or a dedicated follow-up) must call it at least once after mount before the cache is non-empty, otherwise `has_covering_grant` will correctly-but-uselessly report no coverage until the first refresh.
- No blockers for 69-11/69-14.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-06*
