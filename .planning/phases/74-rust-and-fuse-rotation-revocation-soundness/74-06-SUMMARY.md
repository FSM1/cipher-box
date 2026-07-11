---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 06
subsystem: fuse
tags: [rust, winfsp, fuse, rotation, revocation, scope-exit-gate, rename]

# Dependency graph
requires:
  - phase: 70.1
    provides: run_scope_exit_gate primitive (grant_scope.rs, platform-agnostic) and the D-16 fuser rename.rs D-15d reference ordering
provides:
  - WinFsp handle_rename reordered to the fuser D-15d pipeline (validate -> source-gate -> dest-gate -> mutate)
  - New destination scope-exit gate on WinFsp overwrite-rename (closes T-74-09)
  - Two WinFsp unit tests mirroring the fuser D-15d twins
  - crate::test_support harness widened to be reachable from feature = "winfsp" test builds (not just "fuse")
affects: [74-07, any future WinFsp write-op work needing the shared test_support harness]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-15d ordering (validate destination-replacement -> source scope-exit gate -> dest scope-exit gate -> mutate) now implemented identically on both fuser and WinFsp"
    - "test_support.rs split: feature-agnostic CipherBoxFS builder (make_test_fs/make_test_fs_with_keypair) reachable under any(fuse, winfsp); fuser-specific CaptureSender/reply_error_code stay fuse-gated"

key-files:
  created: []
  modified:
    - crates/fuse/src/platform/windows/write_ops.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/test_support.rs

key-decisions:
  - "Widened crate::test_support's cfg gate from `all(test, feature=\"fuse\")` to `all(test, any(feature=\"fuse\", feature=\"winfsp\"))` so WinFsp's own #[cfg(test)] module could reuse make_test_fs_with_keypair — the plan's read_first assumed an existing WinFsp test module/harness that did not actually exist in the file; this was the minimal fix to make Task 1 possible at all (Rule 3, blocking)."
  - "Kept CaptureSender/reply_error_code (fuser::ReplySender-based) gated to feature=\"fuse\" only inside test_support.rs, since fuser is an optional dependency gated to that feature."
  - "WinFsp test harness constructs its own ctx_on_runtime()/insert_*/seed_sent_share() helpers directly in write_ops.rs's new test module (mirroring, not importing, the fuser rename.rs test helpers) since handle_rename's WinFsp signature takes &WinFspContext, not &mut CipherBoxFS directly."
  - "Did not add self-replace (dest_ino==source_ino) or kind-mismatch (ENOTDIR/EISDIR) validation to WinFsp handle_rename — RESEARCH.md Pitfall 4/point 4 explicitly scoped these as an optional stretch item outside this phase's Success Criteria; only the ENOTEMPTY-equivalent check was reordered, matching the plan's acceptance criteria exactly."

requirements-completed: [SC3]

coverage:
  - id: D1
    description: "WinFsp handle_rename reordered to fuser D-15d pipeline (validate -> source-gate -> dest-gate -> mutate) with a new destination scope-exit gate before fs.inodes.remove(dest_ino)"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "crates/fuse/src/platform/windows/write_ops.rs#rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt"
        status: unknown
      - kind: unit
        ref: "crates/fuse/src/platform/windows/write_ops.rs#rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit"
        status: unknown
      - kind: other
        ref: "static ordering-parity inspection vs crates/fuse/src/write_ops/implementation/rename.rs lines 93-163 (documented below)"
        status: pass
    human_judgment: true
    rationale: "crates/fuse/src/platform/windows/write_ops.rs is #[cfg(feature = \"winfsp\")]-only and does not build on macOS/Linux (no WinFsp SDK/linker locally). The two new unit tests cannot be compiled or executed on this dev machine — they were authored test-first, verified only by static/manual inspection, and require the dispatched `Cargo Check & Test (Windows)` CI job to actually run and report pass/fail. This is a documented, expected infra limitation (project memory `project-winfsp-build-ci-only-macos`), not a gap in this plan's work."

# Metrics
duration: 45min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 06: WinFsp rename D-15d dest-gate + ordering parity Summary

**Reordered WinFsp's overwrite-rename to the fuser D-15d pipeline and added the missing destination scope-exit gate, closing a Windows-only revocation bypass on overwrite-rename (T-74-09).**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-07-11T03:XX:XXZ
- **Completed:** 2026-07-11T04:02:49Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- `crates/fuse/src/platform/windows/write_ops.rs::handle_rename` now runs the exact fuser D-15d sequence: (1) the unconditional `replace_if_exists==false` collision check, unchanged, still first; (2) the `STATUS_DIRECTORY_NOT_EMPTY`-equivalent destination-replacement validation, moved to run BEFORE the source scope-exit gate; (3) the existing source `run_scope_exit_gate`, unchanged; (4) a NEW destination `run_scope_exit_gate(&mut fs, dest_ino)` immediately after it, returning `status_access_denied()` on failure, before the previously-ungated `fs.inodes.remove(dest_ino)`.
- Two new `#[cfg(all(test, feature = "winfsp"))]` unit tests mirror the fuser `rename.rs` D-15d twins byte-for-byte in intent: `rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt` (a covered source must never attempt rotation on a doomed rename) and `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit` (overwriting a covered destination must gate its own scope-exit before removal). Each asserts (a) the correct NTSTATUS rejection code and (b) the relevant inode is still present post-rejection.
- Widened `crate::test_support`'s cfg gate (`lib.rs`) so its feature-agnostic `make_test_fs_with_keypair` builder is reachable from WinFsp's own test module, while keeping the `fuser`-specific `CaptureSender`/`reply_error_code` gated to `feature = "fuse"` only (the plan's `read_first` claimed an existing WinFsp `#[cfg(test)]` module/harness that did not actually exist — this widening was the minimal fix needed to make Task 1 possible).

## Task Commits

Each task was committed atomically:

1. **Task 1: Author WinFsp dest-gate unit tests mirroring the fuser D-15d tests** - `f51ab8a9c` (test)
2. **Task 2: Reorder handle_rename + add the destination scope-exit gate** - `92eef837a` (fix)

_Note: Task 1's commit intentionally lands the two new tests against the STILL-UNFIXED `handle_rename` (harness widening + test module only, no reorder) so the tests are demonstrably exercising the not-yet-added dest gate before Task 2's fix lands — verified by round-tripping the diff (`git apply -R`/`git apply` on the reorder hunk) rather than a live `cargo test --features winfsp` run, which is not possible on this host._

## Files Created/Modified

- `crates/fuse/src/platform/windows/write_ops.rs` - `handle_rename` reordered (D-15d) + new dest scope-exit gate + two new unit tests
- `crates/fuse/src/lib.rs` - `test_support` module cfg widened to `any(feature = "fuse", feature = "winfsp")`
- `crates/fuse/src/test_support.rs` - split `CaptureSender`/`reply_error_code` (fuser-specific) behind `#[cfg(feature = "fuse")]`, keeping `make_test_fs`/`make_test_fs_with_keypair`/`make_isolated_journal_dir` feature-agnostic

## Ordering Parity Proof (fuser rename.rs vs WinFsp handle_rename)

Static line-by-line inspection against `crates/fuse/src/write_ops/implementation/rename.rs` (the D-15d correctness baseline):

| Stage | fuser `rename.rs` | WinFsp `write_ops.rs` (post-fix) | Parity |
|---|---|---|---|
| 1. Collision check | N/A (POSIX `rename(2)` has no `replace_if_exists` flag) | `replace_if_exists == false` -> `status_object_name_collision()`, unconditional, first, **unmoved** | N/A on fuser side; WinFsp-only precondition correctly left untouched (RESEARCH Pitfall 4) |
| 2. Destination-replacement POSIX validation | lines 93-133: self-replace no-op, kind-mismatch (ENOTDIR/EISDIR), then ENOTEMPTY | `STATUS_DIRECTORY_NOT_EMPTY`-equivalent check only (self-replace/kind-mismatch explicitly out of scope per RESEARCH todo 3 point 4) — now runs BEFORE the source gate | Match on the in-scope check (ENOTEMPTY); self-replace/kind-mismatch intentionally deferred, not required by this plan's acceptance criteria |
| 3. Source scope-exit gate | lines 145-150: `if parent != newparent && run_scope_exit_gate(fs, source_ino).is_err() => EIO` | lines: `if old_parent_ino != new_parent_ino && run_scope_exit_gate(&mut fs, source_ino).is_err() => status_io_device_error()` | Exact structural match — same condition, same shared `run_scope_exit_gate` function, unchanged from before this plan |
| 4. Dest scope-exit gate (NEW) | lines 158-163: `if let Some(dest_ino) = dest_ino { if run_scope_exit_gate(fs, dest_ino).is_err() => EIO }` | `if let Some(dest_ino) = dest_ino { if run_scope_exit_gate(&mut fs, dest_ino).is_err() => status_access_denied() }` | Exact structural match — same shared function, same plain (non-coalesced) gate, added in this plan |
| 5. Mutation (dest removal, then source relink) | lines 171-244 | lines (post-gate block) through end of function | Order preserved: mutation only after both gates pass |

**Coalescing:** neither the fuser reference nor the WinFsp fix uses `run_scope_exit_gate_coalesced` for rename (grep-confirmed: `run_scope_exit_gate_coalesced` appears exactly once in `write_ops.rs`, inside `handle_set_delete`, not `handle_rename`) — matches RESEARCH's explicit "don't invent coalescing for rename" guidance.

## Local Verification Performed

Static/structural verification only, per the plan's `autonomous: false` designation — `platform/windows/write_ops.rs` is `#[cfg(feature = "winfsp")]`-only and the `winfsp`/`winfsp-sys` crates require Windows-only APIs (`windows_registry::LOCAL_MACHINE`, COM marshaling) that do not build on macOS. Confirmed via a direct attempt:

```
$ cargo check -p cipherbox-fuse --no-default-features --features winfsp
error[E0432]: unresolved import `windows_registry::LOCAL_MACHINE` (winfsp-sys build.rs)
error[E0412]: cannot find type `IMarshal` in module `windows_core::imp` (windows-future)
```
This confirms the constraint is a genuine host/toolchain limitation (documented, expected — project memory `project-winfsp-build-ci-only-macos`), not a defect in this plan's code. The `x86_64-pc-windows-msvc` Rust target is also not installed locally (`rustup target list --installed` returns empty for Windows targets) — per the checkpoint policy, noted and not installed (no toolchain installation attempted).

What WAS verified locally:
- `rustfmt --edition 2021` successfully parsed and formatted the modified files with zero syntax errors (rustfmt requires valid Rust syntax to run; a parse failure would have surfaced here even though `winfsp` itself can't compile).
- `grep -n 'run_scope_exit_gate(&mut fs, dest_ino)'` and `run_scope_exit_gate(&mut fs, source_ino)'` both resolve inside `handle_rename` (line 1157, 1142) — dest gate present, source gate unchanged.
- `grep -n 'run_scope_exit_gate_coalesced'` resolves only inside `handle_set_delete` (line 1310) — confirms no coalescing was added to `handle_rename`.
- `cargo test -p cipherbox-fuse --lib` (default `feature = "fuse"` build, 111 tests) passes with zero regressions both before and after the `write_ops.rs`/`lib.rs`/`test_support.rs` changes — proves the `test_support` cfg-widening did not break the macOS/Linux fuser build or its own test suite (the WinFsp test module is invisible to this build; `#[cfg(all(test, feature = "winfsp"))]` never activates under `feature = "fuse"`).
- Manual line-by-line ordering-parity inspection against the fuser reference (table above).

## Deferred to Windows CI (infra-gated, not locally verifiable on macOS)

The following can ONLY be verified by the `Cargo Check & Test (Windows)` GitHub Actions job (dispatched separately from this plan's execution, per the plan's `autonomous: false` / checkpoint-policy directive):

- **Compilation:** `crates/fuse` with `--features winfsp` actually compiles on Windows (winfsp-sys/windows-rs build correctly there; the errors seen locally are macOS-specific and do not occur on the Windows CI runner).
- **The two new unit tests pass:** `rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt` and `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit`, asserting the exact NTSTATUS codes (`STATUS_DIRECTORY_NOT_EMPTY` = `0xC0000101`, `STATUS_ACCESS_DENIED` = `0xC0000022`) and post-rejection inode presence.
- **Pitfall 4 regression guard:** the pre-existing `replace_if_exists == false` -> `status_object_name_collision()` behavior is unregressed by the reorder (no dedicated new test was added for this — it is an unchanged code path, covered implicitly by any existing WinFsp integration/desktop-e2e coverage that exercises overwrite-rename-without-replace).
- **Type/borrow-check correctness of the new test harness** (`ctx_on_runtime`, `insert_empty_folder`/`insert_non_empty_folder`/`insert_file`, `seed_sent_share`, `winfsp_path`, `assert_ntstatus`) — verified by careful manual cross-reference against every struct/function signature used (`WinFspContext { inner: Arc<Mutex<CipherBoxFS>>, rt: tokio::runtime::Handle }`, `InodeData`/`InodeKind`/`FileAttrs` field shapes, `SentShareResponse` field shapes, `FspError::NTSTATUS(i32)` non-exhaustive enum with `Debug` but no `PartialEq`, `widestring::U16CString::from_str`/`as_ucstr`), but the Rust compiler itself has not type-checked this code.

**Recommended dispatch command** (to run before phase 74 close-out, mirroring the plan's own `<verify><human-check>` instruction):
```
gh workflow run "Cargo Check & Test (Windows)" --ref feat/rust-and-fuse-rotation-revocation-soundness
```

## Decisions Made

- Widened `crate::test_support`'s module-level `cfg` gate rather than duplicating a second, WinFsp-only test harness — the underlying `make_test_fs_with_keypair` builder has zero `fuser` dependency, so gating it to `any(feature = "fuse", feature = "winfsp")` is the minimal, non-duplicative fix (Rule 3 — this was a blocking issue: the plan's own `read_first` incorrectly assumed an existing WinFsp `#[cfg(test)]` module/harness).
- Split `test_support.rs` at the `fuser`-usage boundary: `CaptureSender`/`reply_error_code` (which wrap `fuser::ReplySender`) stay `#[cfg(feature = "fuse")]`-gated since `fuser` is an optional dependency only pulled in by that feature; everything else (`make_isolated_journal_dir`, `make_test_fs`, `make_test_fs_with_keypair`) is feature-agnostic.
- WinFsp's new tests build their own local `ctx_on_runtime`/`insert_*`/`seed_sent_share` helpers in `write_ops.rs`'s test module rather than trying to reuse the fuser `rename.rs` test module's private helpers directly — `handle_rename`'s two platform signatures differ (`&mut CipherBoxFS` for fuser vs `&WinFspContext` for WinFsp), so the harness had to be adapted, not imported.
- Did not add self-replace (`dest_ino == source_ino`) or kind-mismatch (`ENOTDIR`/`EISDIR`) validation to WinFsp `handle_rename`, even though the fuser reference has both — RESEARCH.md's Todo 3 point 4 explicitly scopes these as an optional stretch item outside this phase's Success Criteria (SC3 is about the scope-exit gate, not POSIX-parity completeness). Only the in-scope `STATUS_DIRECTORY_NOT_EMPTY` check was reordered.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `crate::test_support` harness was unreachable from WinFsp test builds; the plan's `read_first` incorrectly assumed an existing WinFsp `#[cfg(test)]` module**
- **Found during:** Task 1 (authoring the WinFsp dest-gate unit tests)
- **Issue:** The plan's `read_first` for Task 1 said to consult "the existing `#[cfg(test)]` module" in `platform/windows/write_ops.rs` — no such module existed (grep confirmed zero `mod tests`/`#[test]` occurrences in the file or anywhere under `platform/windows/`). Additionally, `crate::test_support` (which holds `make_test_fs_with_keypair`, the harness the plan explicitly says to reuse) was gated `#[cfg(all(test, feature = "fuse"))]` in `lib.rs` — entirely invisible to a `feature = "winfsp"` test build, since `fuse`/`winfsp` are mutually-exclusive-in-practice platform features.
- **Fix:** Widened the `test_support` module gate to `#[cfg(all(test, any(feature = "fuse", feature = "winfsp")))]` in `lib.rs`, and split `test_support.rs` internally so only the genuinely `fuser`-dependent items (`CaptureSender`, `reply_error_code`, their `std::io::IoSlice`/`std::sync::Mutex` imports) stay `#[cfg(feature = "fuse")]`-gated. `make_test_fs`/`make_test_fs_with_keypair`/`make_isolated_journal_dir` have zero `fuser` dependency and are now reachable from both platforms' test builds.
- **Files modified:** `crates/fuse/src/lib.rs`, `crates/fuse/src/test_support.rs`
- **Verification:** `cargo test -p cipherbox-fuse --lib` (default `feature = "fuse"` build) — 111 tests, all passing, zero regressions, both before and after the split.
- **Committed in:** `f51ab8a9c` (Task 1 commit)

**2. [Rule 1 - Bug] Accidental crate-wide `rustfmt` scope creep reverted**
- **Found during:** Local formatting verification after authoring the tests
- **Issue:** Running `rustfmt --edition 2021` directly on `lib.rs` (a crate-root file with `mod` declarations) caused rustfmt to recursively reformat the ENTIRE module tree it discovered from `lib.rs` (8 unrelated files: `file_handle.rs`, `fs.rs`, `helpers.rs`, `platform/macos.rs`, `platform/windows/{dir_ops,mod,read_ops}.rs`, `write_ops/mod.rs`), producing large, out-of-scope formatting-only diffs unrelated to this plan.
- **Fix:** Reverted the 8 unrelated files via targeted `git checkout -- <file>` (not a blanket reset), keeping only the intentional formatting fixes to the 3 files this plan actually touched (`write_ops.rs`, `test_support.rs`; `lib.rs` itself needed no reformatting).
- **Files modified:** (reverted, not committed) `crates/fuse/src/file_handle.rs`, `crates/fuse/src/fs.rs`, `crates/fuse/src/helpers.rs`, `crates/fuse/src/platform/macos.rs`, `crates/fuse/src/platform/windows/dir_ops.rs`, `crates/fuse/src/platform/windows/mod.rs`, `crates/fuse/src/platform/windows/read_ops.rs`, `crates/fuse/src/write_ops/mod.rs`
- **Verification:** `git status --short` post-revert showed only the 3 intended files modified; `cargo test -p cipherbox-fuse --lib` still green.
- **Committed in:** N/A (reverted before any commit — no trace in git history)

---

**Total deviations:** 2 (1 blocking-issue fix, 1 self-caught scope-creep revert)
**Impact on plan:** Both were necessary corrections with zero net scope expansion beyond what Task 1 required. No unrelated files were committed.

## Issues Encountered

- Could not run `cargo test -p cipherbox-fuse --features winfsp` or `cargo check -p cipherbox-fuse --target x86_64-pc-windows-msvc` on this host — see "Deferred to Windows CI" above. This is the documented, expected constraint stated in the plan's own `autonomous: false` rationale, not a new issue.
- No live desktop-e2e run was attempted for this plan — RESEARCH.md's Component Responsibilities table flags a WinFsp-specific rename-overwrite-with-covering-grant desktop-e2e leg as a possible future addition (Assumption A3, low-risk), but this plan's scope (per its own `<tasks>`) was the unit-test + code-reorder pair only, verified via `Cargo Check & Test (Windows)` CI, not a new desktop-e2e script.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- SC3 (WinFsp overwrite-rename scope-exit gate parity) is code-complete and locally statically verified to the maximum extent possible on macOS; **dispatch the `Cargo Check & Test (Windows)` CI job before considering SC3 fully closed** — the two new tests and the winfsp compilation itself are unverified pending that CI run.
- No blockers for `74-07` or any other phase-74 plan; this plan's changes are isolated to `crates/fuse/src/platform/windows/write_ops.rs` (a leaf file, no downstream consumers within this phase) plus the shared `test_support`/`lib.rs` harness widening (backward-compatible, additive).
- The `.planning/todos/pending/2026-07-08-winfsp-d15d-gate-ordering-parity.md` source todo's rename half is now closed by this plan (the delete half shipped earlier in 70.1-13a, per the plan's own objective statement).

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: crates/fuse/src/platform/windows/write_ops.rs
- FOUND: crates/fuse/src/lib.rs
- FOUND: crates/fuse/src/test_support.rs
- FOUND: .planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-06-SUMMARY.md
- FOUND commit: f51ab8a9c (test(74-06): add WinFsp rename D-15d dest-gate tests)
- FOUND commit: 92eef837a (fix(74-06): dest-gate WinFsp overwrite-rename with fuser D-15d ordering)
