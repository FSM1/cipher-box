---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 14
subsystem: infra
tags: [winfsp, fuse, rust, node-v3, grant-scope, rotation, ipns, ecies, ci]

# Dependency graph
requires:
  - phase: 69-09
    provides: node/v3 Unix read migration (content_ops symmetric unseal, gated list_folder_owned, 8-arg spawn_metadata_refresh)
  - phase: 69-10
    provides: D-04 legacy-type (FilePointer/FolderEntry/FolderMetadata) deletion from the core node model
  - phase: 69-13
    provides: Unix write-path grant gate (delete.rs/rename.rs run_scope_exit_gate), SC#2 re-encrypt-on-move deletion, SC#2 CI gate (with platform/windows carve-out)
  - phase: 69-06
    provides: crates/sdk::listing::list_folder / list_shared_folder gated entrypoints
  - phase: 69-07
    provides: crates/fuse::write_ops::grant_scope shared module (ancestor_ipns_chain, has_covering_grant wrap, run_scope_exit_gate, SentSharesCache)
  - phase: 69-08
    provides: crates/sdk::rotation::engine::rotate_read_from_node
provides:
  - node/v3- and grant-root-conformant Windows/WinFsp platform layer that compiles under `--features winfsp`
  - Windows read path symmetric file-key unseal (SC#1) + gated listing consumption (SC#6)
  - Windows write path shared grant-root delete/rename/set_delete gate with D-07 dual-keying (SC#3)
  - spawn_file_meta_reencrypt deleted whole-tree; SC#2 grep gate promoted to whole-tree (SC#2)
  - winfsp-gated desktop glue (apps/desktop/src-tauri/src/fuse/windows/mod.rs) repointed to the reshaped platform signatures
affects: [69-verify, desktop-e2e, winfsp, secure-phase]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Windows platform layer mirrors the Unix path 1:1 (read_ops/dir_ops/operations/write_ops) rather than maintaining a divergent implementation"
    - "Both platforms CONSUME the single crates/fuse::write_ops::grant_scope predicate — no per-platform grant-scope copy (Pitfall 1 / research landmine 10)"
    - "Feature-gated normalize_name unit tests: NFC-composition asserted under feature=fuse, case-insensitive lowercasing under feature=winfsp"

key-files:
  created: []
  modified:
    - crates/fuse/src/platform/windows/operations.rs
    - crates/fuse/src/platform/windows/content_fetch.rs
    - crates/fuse/src/platform/windows/read_ops.rs
    - crates/fuse/src/platform/windows/dir_ops.rs
    - crates/fuse/src/platform/windows/write_ops.rs
    - crates/fuse/src/inode.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
    - .github/workflows/ci.yml

key-decisions:
  - "Windows fetch_and_decrypt_file_content resignatured to (fs, ipns_name, read_key) — mirrors the macOS operations.rs sync wrapper; the node-to-node ECIES file-content-key unwrap is gone (SC#1)"
  - "publish_file_metadata (deleted 69-13) replaced by publish_file_node on the Windows cleanup flush path — the single per-file node/v3 publish path on both platforms"
  - "Windows handle_set_delete and handle_rename cross-folder move both call the SHARED run_scope_exit_gate (69-07); the unconditional revoke_shares_blocking and the ECIES re-encrypt-on-move (spawn_file_meta_reencrypt) are both REPLACED, not augmented"
  - "childId for D-07 dual-keying sourced from the inode's STORED node_id (its real published.id), consistent with the Unix delete.rs — never uuid_from_ino(local_ino)"
  - "test_find_child_nfc_normalizes_unicode gated to feature=fuse (Rule 1): the test's NFC assumption only holds under fuse; winfsp's normalize_name lowercases. Added a winfsp-only case-insensitivity counterpart."
  - "apps/desktop/src-tauri/src/fuse/windows/mod.rs needed only the removal of the now-unused UploadComplete import (research landmine 8 was already handled in 69-09/22/24; the CipherBoxFS construction site was already node/v3)"

patterns-established:
  - "Platform parity: the WinFsp read/write handlers are literal mirrors of the fuser read_ops/dir_ops/write_ops handlers, sharing content_ops, journal_helpers, grant_scope, and fs::build_folder_metadata"
  - "Whole-tree CI grep gates (SC#2/SC#6) with no platform carve-out now that the winfsp build compiles and is CI-exercised"

requirements-completed: [TEST-03]

coverage:
  - id: D1
    description: "Windows read path recovers file content keys by symmetric unseal of the file node's own sealed read-body (SC#1) — no node-to-node ECIES unwrap remains in platform/windows/operations.rs"
    requirement: "TEST-03"
    verification:
      - kind: other
        ref: "grep -n 'ecies::unwrap_key' crates/fuse/src/platform/windows/operations.rs | grep -v '^\\s*//' (empty)"
        status: pass
      - kind: unit
        ref: "cargo check/test --workspace --no-default-features --features winfsp (compiles + 69/69 fuse-crate tests pass)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Windows read path (open/read/readdir/metadata-refresh + FilePointer poll) consumes the gated listing (list_folder_owned / fetch_node_gated) — SC#6; CI grep gate covers platform/windows with no carve-out and returns zero raw-resolve hits"
    requirement: "TEST-03"
    verification:
      - kind: other
        ref: "grep -rnE 'resolve_ipns_verified\\(|resolve_published_node\\(' crates/fuse/src/platform/windows (empty)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Windows write handlers (handle_set_delete, cross-folder handle_rename) CONSUME the shared crate::write_ops::grant_scope::run_scope_exit_gate (SC#3) — private delete = zero rotation, shared-scope exit = exactly one rotate_read_from_node; no per-platform grant predicate"
    requirement: "TEST-03"
    verification:
      - kind: other
        ref: "grep -rn 'fn ancestor_ipns_chain|fn has_covering_grant|fn grant_root_for' crates/fuse/src/platform/windows (empty)"
        status: pass
      - kind: unit
        ref: "crates/fuse/src/write_ops/grant_scope.rs gate_scope_exit spy tests (private/shared/multi-root/rotate-error) pass under winfsp"
        status: pass
    human_judgment: false
  - id: D4
    description: "D-07 dual-keying threaded through the Windows delete/rename/cleanup: WriteChildRef.child_id (UUID) vs SealedChildRef.ipns_name (k51) never conflated; platform/windows/write_ops.rs FLAGGED for security review"
    requirement: "TEST-03"
    verification:
      - kind: manual_procedural
        ref: "gsd-security-auditor review of crates/fuse/src/platform/windows/write_ops.rs D-07 call sites"
        status: unknown
    human_judgment: true
    rationale: "D-07 read/write-plane non-conflation is a cryptographic-correctness invariant (T-69-14-02, high severity). The compile + grep gates prove the shared predicate is consumed and the fields are distinct, but confirming no live conflation across the reshaped Windows write path requires a security reviewer's judgment (the SECURITY.md author, not the executor)."
  - id: D5
    description: "spawn_file_meta_reencrypt caller deleted (SC#2 whole-tree) and the SC#2 CI grep gate promoted to whole-tree (69-13's platform/windows carve-out removed)"
    requirement: "TEST-03"
    verification:
      - kind: other
        ref: "grep -rn 'spawn_file_meta_reencrypt' crates/fuse/src | grep -vE ':[0-9]+:[[:space:]]*//' (empty); ci.yml has no \"grep -v 'platform/windows'\""
        status: pass
    human_judgment: false
  - id: D6
    description: "SC#5 / TEST-03 objective sign-off: the cargo-windows CI job (--features winfsp) is green AND the dispatched Desktop E2E Tests workflow is green"
    verification:
      - kind: e2e
        ref: "GitHub Actions: cargo-windows job (must have RUN, not path-filter-skipped) + `gh workflow run \"Desktop E2E Tests\"`"
        status: unknown
    human_judgment: true
    rationale: "D-06: WinFsp iteration and CI dispatch are the USER's on their Windows box / GitHub; the executor iterated the winfsp build green LOCALLY (cargo check 0 errors, cargo test all green, all four grep gates clean) but the CI job + dispatched Desktop E2E are the objective SC-05 authority and are a human-verify checkpoint (Task 3)."

# Metrics
duration: 50min
completed: 2026-07-07
status: complete
---

# Phase 69 Plan 14: WinFsp / Windows Platform Node-v3 + Grant-Root Conformance Summary

**The Windows/WinFsp platform layer (`crates/fuse/src/platform/windows/*`) migrated 1:1 off the pre-69-09 legacy InodeKind shape onto node/v3: symmetric file-key unseal (SC#1), gated listing consumption (SC#6), the shared grant-root delete/rename/set_delete gate with D-07 dual-keying (SC#3), and the `spawn_file_meta_reencrypt` caller deleted with the SC#2 CI gate promoted whole-tree — `cargo check/test --workspace --no-default-features --features winfsp` is GREEN locally.**

## Performance

- **Duration:** ~50 min active work (wall-clock spanned longer due to a 1Password SSH-signing auth gate on the Task 2 commit, resolved by user approval)
- **Started:** 2026-07-07 (Task 1 commit 03:17 local)
- **Completed:** 2026-07-07 (Task 2 commit 12:52 local)
- **Tasks:** 2 of 3 (Task 3 is a human-verify checkpoint — pending)
- **Files modified:** 8

## Accomplishments
- **SC#1 (Windows):** `operations.rs::fetch_and_decrypt_file_content` re-signatured to `(fs, ipns_name, read_key)` and routed through `content_ops::fetch_node_and_decrypt_content` (gated `fetch_node_gated` → symmetric `unseal_node`). The node-to-node `ecies::unwrap_key` file-content-key hop is GONE; the now-dead `zeroizing_32_from_slice` helper was removed. `content_fetch.rs`, `read_ops.rs` (open/read + FilePointer poll), and `dir_ops.rs` (readdir prefetch) all repointed to the node/v3 `InodeKind::File { ipns_name, read_key }` fields.
- **SC#6 (Windows):** the Windows metadata-refresh path now calls the 8-arg `spawn_metadata_refresh` (`read_key` + `write_key` + `high_water`) which drives the gated `list_folder_owned`; no raw IPNS resolve remains in `platform/windows`.
- **SC#3 + D-07 (Windows):** `handle_set_delete` and the cross-folder branch of `handle_rename` now CONSUME the shared `crate::write_ops::grant_scope::run_scope_exit_gate` (69-07) — the unconditional `revoke_shares_blocking` and the ECIES re-encrypt-on-move are both replaced. `handle_create` (mkdir + file) and `handle_cleanup` seal via the node/v3 symmetric keys (`build_mkdir_journal_entry`, `publish_file_node`), and the bin-capture path in `handle_cleanup` (already node/v3 from a prior wave) keeps its D-07 `build_child_refs` dual ref.
- **SC#2 (whole-tree):** the `spawn_file_meta_reencrypt` caller at `handle_rename` is deleted; the ci.yml SC#2 grep gate lost its `grep -v 'platform/windows'` carve-out and now scans the whole `crates/fuse/src` tree.
- **winfsp build green locally:** `cargo check --workspace --no-default-features --features winfsp` → **0 errors** (down from 58 baseline errors, all previously confined to `platform/windows/*`); `cargo test --workspace --no-default-features --features winfsp` → **all green** (fuse crate 69/69, desktop 22/22, sdk/core/crypto/api-client suites all pass).

## Task Commits

Each task was committed atomically:

1. **Task 1: SC#1 + SC#6 Windows READ path** — `6c76c71ae` (feat)
2. **Task 2: SC#3 + D-07 + SC#2 Windows WRITE path** — `4bf0c81f0` (feat)
3. **Task 3: SC#5 / TEST-03 CI + E2E sign-off** — `checkpoint:human-verify` (PENDING — the user dispatches Desktop E2E and confirms the cargo-windows CI job per D-06; NOT self-approved)

## Files Created/Modified
- `crates/fuse/src/platform/windows/operations.rs` — SC#1 symmetric `fetch_and_decrypt_file_content`; re-export `fetch_node_and_decrypt_content` + `publish_file_node`; dropped dead ECIES unwrap + `zeroizing_32_from_slice`
- `crates/fuse/src/platform/windows/content_fetch.rs` — `spawn_content_prefetch(ipns_name, read_key)` via the gated fetch (SC#6)
- `crates/fuse/src/platform/windows/read_ops.rs` — open/read/stale-refresh/FilePointer-poll repointed to node/v3 `InodeKind::File` fields + 8-arg `spawn_metadata_refresh`
- `crates/fuse/src/platform/windows/dir_ops.rs` — readdir stale-check + proactive prefetch repointed to node/v3 + the gated fetch; removed a dead `drop(&InodeData)` no-op
- `crates/fuse/src/platform/windows/write_ops.rs` — mkdir/file create mint node/v3 keys; cleanup flush uses `publish_file_node` + in-place descriptor update; rename cross-folder + set_delete consume the shared grant-scope gate; `spawn_file_meta_reencrypt` caller deleted. **FLAGGED FOR SECURITY REVIEW (D-07 dual-keying).**
- `crates/fuse/src/inode.rs` — feature-gated the NFC-normalize unit test to `fuse` and added a `winfsp`-only case-insensitivity counterpart (Rule 1 latent-test-bug fix)
- `apps/desktop/src-tauri/src/fuse/windows/mod.rs` — removed the now-unused `UploadComplete` import (the CipherBoxFS construction site was already node/v3)
- `.github/workflows/ci.yml` — SC#2 grep gate promoted to whole-tree (no `platform/windows` carve-out)

## Decisions Made
See `key-decisions` in the frontmatter. Highlights:
- Mirrored the Unix path 1:1 rather than diverging; the Windows handlers reference the shared `content_ops` / `journal_helpers` / `grant_scope` / `build_folder_metadata` seams the fuser handlers use.
- childId for D-07 dual-keying is the inode's stored `node_id` (its real `published.id`), matching the Unix delete.rs — never `uuid_from_ino(local_ino)`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Feature-gated the NFC-normalize inode unit test**
- **Found during:** Task 2 (first-ever `cargo test --features winfsp`)
- **Issue:** `inode::tests::test_find_child_nfc_normalizes_unicode` asserts NFC composition (`café` ↔ `cafe` + combining acute). `normalize_name` NFC-composes only under `feature = "fuse"`; under `feature = "winfsp"` (no `fuse`) it lowercases instead (WinFsp owns case-insensitive lookup). The test failed under winfsp. This assumption was latent — the winfsp build never compiled before this plan, so the test never ran there.
- **Fix:** Gated the NFC test to `#[cfg(feature = "fuse")]` and added a `#[cfg(all(feature = "winfsp", not(feature = "fuse")))]` case-insensitivity counterpart (`Documents`/`documents`/`DOCUMENTS`).
- **Files modified:** `crates/fuse/src/inode.rs`
- **Verification:** `cargo test --workspace --no-default-features --features winfsp` → all green
- **Committed in:** `4bf0c81f0` (Task 2 commit)

**2. [Rule 1 - Bug] Removed a dead `drop(&InodeData)` no-op**
- **Found during:** Task 1 (first-ever `cargo check --features winfsp`)
- **Issue:** `dir_ops.rs` called `drop(inode)` on a `&InodeData` reference — a no-op that triggers `dropping_references` (a `-D warnings` failure in the strict lane).
- **Fix:** Replaced with `let _ = inode;` to end the NLL borrow explicitly.
- **Files modified:** `crates/fuse/src/platform/windows/dir_ops.rs`
- **Verification:** `cargo check --features winfsp` warning cleared
- **Committed in:** `4bf0c81f0` (Task 2 commit)

**3. [Rule 3 - Blocking] Removed the now-unused `UploadComplete` import**
- **Found during:** Task 2
- **Issue:** `apps/desktop/src-tauri/src/fuse/windows/mod.rs` imported `UploadComplete` which is unused after the reshaped platform signatures (`unused_imports` warning → `-D warnings` failure).
- **Fix:** Dropped the import.
- **Files modified:** `apps/desktop/src-tauri/src/fuse/windows/mod.rs`
- **Verification:** `cargo check --features winfsp` warning cleared
- **Committed in:** `4bf0c81f0` (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (2 Rule 1 bugs, 1 Rule 3 blocking).
**Impact on plan:** All three are compile/test-correctness fixes surfaced by the FIRST-EVER winfsp compile of these files (69-10 could not compile-verify `platform/windows`); no scope creep. Pre-existing out-of-scope warnings (`poll.rs::PollResult` dead-code under winfsp; `fuse/mod.rs` unused imports) were left untouched (SCOPE BOUNDARY) — neither is in this plan's `files_modified`.

## Issues Encountered
- **1Password SSH-signing auth gate:** the Task 2 commit was blocked for an extended window by a 1Password `op-ssh-sign` approval prompt (`error: 1Password: failed to fill whole buffer` on fast-fail; hung on direct invocation). Resolved when the user approved the prompt at their PC; the commit (`4bf0c81f0`) then landed signed. This was an environment/auth gate, not a code issue — no changes were lost (the 5 staged files remained staged throughout).

## Security Review Flag

**`crates/fuse/src/platform/windows/write_ops.rs` is FLAGGED FOR EXPLICIT SECURITY REVIEW (D-07 dual-keying).** The Windows delete/rename/cleanup call sites thread BOTH `WriteChildRef.child_id` (a UUID, write plane) AND `SealedChildRef.ipns_name` (a k51, read plane) through the shared grant-scope gate and the bin-capture `build_child_refs`. Conflating the two key spaces silently breaks `rotateWriteFromNode` (project invariant / T-69-14-02, high severity). The grep gate proves no per-platform predicate copy exists and the fields are structurally distinct, but confirming no live conflation across the reshaped Windows write path is a security-reviewer judgment (the SECURITY.md author, not the executor). The `// SECURITY-REVIEW: D-07 dual-keying` markers are present on the bin-capture call sites (inherited from the prior wave's node/v3 cleanup path).

## User Setup Required
None new. Per D-06 / `user_setup` in the plan, the USER's Windows box needs WinFsp v2.1+ installed for local `--features winfsp` iteration and an authenticated `gh` CLI (prefix `env -u GITHUB_TOKEN`) to dispatch the Desktop E2E workflow — both already satisfied on this box (local winfsp iteration was performed here).

## Next Phase Readiness
- **Task 3 (human-verify checkpoint) is the remaining gate.** The winfsp build is green LOCALLY (cargo check 0 errors, cargo test all green, all four grep gates clean), but the objective SC#5 / TEST-03 authority is the CI `cargo-windows` job + the dispatched `Desktop E2E Tests` workflow. Per D-06 the USER dispatches and confirms these; the executor does NOT self-approve or run `gh workflow run`.
- To resume: confirm the `Cargo Check & Test (Windows)` job actually RAN (not path-filter-skipped — this plan touches `platform/windows/*` so `desktop == 'true'` should hold) and is green on both `cargo check` and `cargo test` steps, then `env -u GITHUB_TOKEN gh workflow run "Desktop E2E Tests" --ref <branch>` (verify the name via `gh workflow list` — ROADMAP wording "CI E2E Tests" does not match the live `name:`) and wait for green.

## Self-Check: PASSED
- All 8 modified source files exist on disk (verified via `[ -f ]`).
- Both task commits exist in git history: `6c76c71ae` (Task 1), `4bf0c81f0` (Task 2).
- `cargo check --workspace --no-default-features --features winfsp`: 0 errors.
- `cargo test --workspace --no-default-features --features winfsp`: all green.
- SC#1 / SC#2 (whole-tree) / SC#6 (no raw resolve in platform/windows) / no-per-platform-predicate grep gates: all clean.

---
*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Completed: 2026-07-07*
