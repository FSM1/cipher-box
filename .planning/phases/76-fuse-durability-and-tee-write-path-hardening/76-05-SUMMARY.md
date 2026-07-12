---
phase: 76-fuse-durability-and-tee-write-path-hardening
plan: 05
subsystem: desktop-fuse
tags: [fuse, windows, winfsp, d-07, write-plane, node-id, hardening]
status: complete-pending-ci-verify
requires:
  - Unix D-07 write-plane keying fix (delete.rs:180/:419, commit c4d30e598)
  - InodeData.node_id persisted field + build_child_refs dual-ref seal
provides:
  - Windows cleanup() bin-capture child_id keyed by persisted node_id (D-07 parity)
  - ported D-07 restore-sufficiency regression test in the winfsp-gated tests module
affects:
  - crates/fuse/src/platform/windows
tech-stack:
  added: []
  patterns:
    - write-plane child_id sourced from inode.node_id (not uuid_from_ino) — materialized-node correctness
    - winfsp-gated pure build_child_refs round-trip as the reachable D-07 proof
key-files:
  created: []
  modified:
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - "Mirrored delete.rs:180 exactly: child_id = inode.node_id.clone() (inode is already bound in the Some(inode) arm), rather than a redundant fs.inodes.get(ino) re-fetch — the fallback is unnecessary inside the materialized branch and node_id is seeded to uuid_from_ino(ino) at creation for the fresh case"
  - "Updated the two inline SECURITY-REVIEW comments off the stale 'via uuid_from_ino' wording to 'the stored node_id'"
  - "Ported test uses a materialized node_id ('remote-creator-node-uuid') distinct from uuid_from_ino(local_ino) and asserts write_child_ref.child_id equals the stored node_id and NOT uuid_from_ino — a direct regression guard"
open_checkpoints:
  - "Task 2 (checkpoint:human-verify, blocking) — Windows CI must be GREEN before merge: 'Cargo Check & Test (Windows)' + 'Desktop E2E (windows-latest)'. NOT verifiable on this macOS worktree (winfsp feature does not compile/link locally). Executed in BACKGROUND with no human — checkpoint deferred to the PR CI round-trip."
metrics:
  duration: 20min
  completed: 2026-07-12
  tasks: 2
  files: 1
---

# Phase 76 Plan 05: Windows D-07 Write-Plane node_id Keying Summary

One-liner: brought the Windows/WinFsp `cleanup()` delete/bin-capture path to parity with the shipped Unix D-07 fix — `WriteChildRef.child_id` now derives from the inode's persisted `node_id` (`inode.node_id.clone()`) instead of `uuid_from_ino(ino)`, so a materialized-then-removed node keys its bin entry by its creator-assigned id and pairs correctly on restore, with a ported regression test in the winfsp-gated module. The blocking human-verify checkpoint (Windows CI green) is deferred to the PR CI round-trip because this module cannot compile on the macOS execution worktree.

## What Was Built

### Task 1 — node_id-keyed child_id + ported regression test (write_ops.rs)

- In `cleanup()`'s `bin_capture` match (`Some(inode) => ...`), replaced `let child_id = crate::fs::uuid_from_ino(ino);` with `let child_id = inode.node_id.clone();`, mirroring the Unix `delete.rs:180`/`:419` sites exactly (the `inode` is already bound by the match arm).
- Added the `SECURITY-REVIEW: D-07 dual-keying` block comment (childId is the STORED node_id, its real published.id, not `uuid_from_ino(ino)`; a materialized-then-deleted node keeps its creator's id; a never-materialized node has `node_id == uuid_from_ino(ino)` from creation so the fresh case is unchanged).
- Updated the two inner `build_child_refs` SECURITY-REVIEW comments off the now-inaccurate "via uuid_from_ino" wording to "the stored node_id".
- Ported the Unix D-07 restore-sufficiency test (`bin_dual_refs_are_restore_sufficient_and_d07_distinct`) into the winfsp-gated `mod tests` as `bin_child_id_keys_by_stored_node_id_not_local_ino_d07`. It keys by a materialized `node_id` distinct from `uuid_from_ino(local_ino)` and asserts: (a) D-07 distinctness (`child_id` UUID != `ipns_name` k51), (b) the write plane is keyed by the stored `node_id`, (c) the regression guard `child_id != uuid_from_ino(local_ino)`, and (d) read+write plane restore-sufficiency via a `seal_published_node` → `unseal_node` round-trip.

### Task 2 — Blocking Windows-CI checkpoint (DEFERRED, not blocked on)

- This is a `checkpoint:human-verify` (blocking) gate: the fix is verifiable ONLY via the `Cargo Check & Test (Windows)` job and the `Desktop E2E (windows-latest)` matrix leg — the winfsp platform module does not compile/link on macOS (no WinFsp SDK), so no local cargo command can prove it.
- This resume ran in BACKGROUND with no human present, so the checkpoint was NOT self-approved and NOT blocked on. The code is landed; the required CI confirmation is recorded as a pending item in `.planning/STATE.md` and below. Per plan prohibitions, no local macOS cargo verification of this fix was attempted.

## Deviations from Plan

### 1. Direct inode.node_id.clone() instead of the fs.rs re-fetch fallback pattern

- **Plan action:** suggested the `fs.inodes.get(ino).map(|i| i.node_id.clone()).unwrap_or_else(|| uuid_from_ino(ino))` fallback pattern (as used at fs.rs:947-955).
- **What was done:** used `inode.node_id.clone()` directly — the exact structure of the shipped Unix fix at delete.rs:180 (which must_have truth #1 names as the mirror target). Inside the `Some(inode)` arm the inode is already borrowed, so the re-fetch + fallback would be dead code; `node_id` is seeded to `uuid_from_ino(ino)` at creation, so the never-materialized case resolves identically without an explicit fallback. Net behavior is identical to the fs.rs pattern's intent, with a tighter mirror of the Unix site.

## Threat Model Mitigations Applied

- **T-76-13 (Tampering, Windows write_ops cleanup child_id):** child_id keyed by persisted node_id (mirror of c4d30e598) so a materialized-then-removed node pairs correctly on bin-restore. Mitigation LANDED in code; final proof is gated on the Windows CI legs (see pending checkpoint).

## Verification

- CANNOT be verified locally — `crates/fuse/src/platform/windows/*` is behind `feature = "winfsp"` (confirmed in `platform/mod.rs:12` and `platform/windows/mod.rs`), which does not build on macOS/Linux. Per the plan prohibition, no local macOS cargo run was attempted.
- Rust files are not covered by lint-staged (only `*.{ts,tsx,js,jsx,mjs,cjs,mts,cts}` / `*.{json,yml,yaml}` / `*.md`), so the commit ran no local Rust check.
- PENDING (blocking, merge gate): `Cargo Check & Test (Windows)` GREEN + `Desktop E2E (windows-latest)` GREEN on the phase PR. The E2E leg exercises the materialized-node delete/bin round-trip end-to-end.

## Commits

- 36b8d24f5: fix(fuse): key Windows delete bin-capture child_id by stored node_id for D-07 parity

## Follow-ups / Notes

- Before merging Plan 76-05: confirm both Windows CI jobs are green on the PR. If either is red (e.g. a compile error in the ported test that cannot surface locally), a fix iteration is required — do NOT merge on a red Windows leg.

## Self-Check: PASSED (code) / PENDING (CI checkpoint)

- SUMMARY file present on disk.
- Commit 36b8d24f5 present in git history.
- Code parity landed; the blocking Windows-CI human-verify checkpoint is recorded as pending in STATE.md (background run, no human, CI-gated).
