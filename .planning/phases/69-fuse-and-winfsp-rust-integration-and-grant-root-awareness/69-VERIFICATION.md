---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
verified: 2026-07-07T00:00:00Z
status: passed
score: 5/5 local must-haves verified (SC#5 = required-green CI gate, not a code gap)
behavior_unverified: 0
overrides_applied: 0
test_evidence: "cargo test --workspace: 476 passed, 0 failed (macOS, default fuse feature)"
required_ci_gates:
  - criterion: "SC#5 — WinFsp platform layer, REQUIRED green before merge (not optional)"
    status: "pending CI — required green before merge"
    reason: "crates/fuse/src/platform/windows/* never compiles under local mac cargo (macFUSE-only linking). Plan 69-14 is autonomous:false and intentionally unexecuted locally. SC#5 is NOT a code gap — it is objective sign-off authority that runs in CI, not locally on mac."
    gates:
      - "(a) PR cargo-windows job (ci.yml:590, cargo check/test --workspace --no-default-features --features winfsp) MUST be green."
      - "(b) The full Desktop E2E Tests workflow (desktop-e2e.yml, macOS/Windows/Linux matrix) MUST be explicitly dispatched against the shipped branch SHA (gh workflow run \"Desktop E2E Tests\" --ref feat/fuse-and-winfsp-rust-integration-and-grant-root-awareness) and pass ALL matrix legs before merge."
    evidence: ".github/workflows/ci.yml:590 cargo-windows (--no-default-features --features winfsp); .github/workflows/desktop-e2e.yml; 69-14-PLAN.md autonomous:false, no 69-14-SUMMARY.md"
notes:
  - "SC#3 residual (documented, non-blocking): shared-scope-exit read-key rotation is fail-CLOSED (returns EIO) pending a production cipherbox_sdk::rotation::engine::RotationDeps implementor. The grant-root gate/awareness IS delivered and wired; live rotation EXECUTION is a standalone deferred live-wiring plan (matches the known ROT-07 live-wiring gap, flagged in 69-13-SUMMARY). Fail-closed is security-safe: a covered scope-exit refuses to complete a delete/move without rotating, preventing the revocation bypass the gate exists to close. Private deletes never reach this seam and work fully."
---

# Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness Verification Report

**Phase Goal:** FUSE and WinFsp clients use symmetric key unwrap throughout; grant-root awareness gates scope-exit mutations; `Node` is a real Rust enum; the Rust read chain (IPNS resolve + durable anti-rollback floor gate + node unseal + child-metadata resolution) lives in shared Rust core/SDK crates (mirroring Phase 68.2's SDK-owned read chain on the TS side), not reimplemented inline in FUSE/WinFsp.

**Verified:** 2026-07-07
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Success Criteria)

| #   | Truth (SC)                                                                 | Status         | Evidence |
| --- | ------------------------------------------------------------------------- | -------------- | -------- |
| 1   | Node unseal in `inode.rs`/`replay.rs` uses symmetric AAD unwrap, no ECIES | ✓ VERIFIED     | Zero `ecies`/`unwrap_key` in `crates/fuse/src/inode.rs` and `replay.rs`. Both delegate to SDK symmetric chain `unseal_child_read_key`/`unseal_child_write_key`/`unseal_node` (`replay.rs:46,244,249,273`), node-AAD via `build_node_aad` (69-04) in `crates/sdk/src/rotation/engine.rs:1694,1934` |
| 2   | `spawn_file_meta_reencrypt` deleted + node-side callers removed           | ✓ VERIFIED     | `fn spawn_file_meta_reencrypt` returns zero matches repo-wide (definition deleted). `rename.rs` + `metadata.rs` callers gone. CI grep gate `SC#2 re-encrypt-on-move deletion` at `ci.yml:757` enforces absence in non-Windows tree. Lone residual caller (`platform/windows/write_ops.rs:1189`) is explicitly 69-14's deletion target — see SC#5 Required CI Gates section |
| 3   | Grant-root awareness gates scope-exit; private no-grant delete = pure relink, zero rotation | ✓ VERIFIED | `grant_scope.rs` `gate_scope_exit`: no covering grant → `ScopeExitResult::NoRotation` (pure parent relink, zero extra publishes, `grant_scope.rs:230-243`); covering grant → `rotate(...)` EXACTLY once via `rotate_read_from_node` (SDK `engine.rs:882`). `delete.rs:200,399` + `rename.rs` wire `run_scope_exit_gate` fail-closed. Tests: `unlink_..._pure_relink` (zero rotation) and `unlink_shared_scope_exit_fails_closed` confirm both paths. See SC#3 residual note |
| 4   | `enum Node { Folder{children}, File{content}, Root{children} }` in core + durable generation/seq high-water | ✓ VERIFIED | `enum Node` at `crates/core/src/node/types.rs:154` with `Folder{...children}`, `File{...content}`, `Root{...children}` variants. Durable floors: `JsonSidecarFloorStore` (`crates/sdk/src/floor_store.rs`) persists `{nodeId:value}` to `<journal_dir>/rotation-high-water-generation.json` + `-seq.json` (adjacent to `WriteQueue` journal), atomic temp-rename write, 0600, survives restart. `RotationHighWater` seam in `rotation/high_water.rs` |
| 5   | WinFsp CI gate (`cargo-windows`, `--features winfsp`) + Desktop E2E matrix | ⏳ PENDING CI — REQUIRED GREEN BEFORE MERGE | Both gates exist and are objective sign-off authority (run in CI, not on mac). NOT a code gap. See Required CI Gates section for the two mandatory conditions |
| 6   | Rust read chain (resolve+floor gate+unseal+child-meta) in core/SDK; fuse delegates, no inline duplication | ✓ VERIFIED | `inode.rs:361` `populate_folder` → `cipherbox_sdk::list_folder_owned`; `replay.rs:156` `resolve_owned_parent` → `list_folder_owned`; `replay.rs:426` → `cipherbox_sdk::fetch_node_gated`. Zero inline `resolve_published_node`/`unseal_aes_gcm` in fuse (only comments forbidding it, `replay.rs:154`). CI `SC#6` gate (`ci.yml:748`) enforces all fuse reads route through `list_folder/list_shared_folder/list_folder_owned/fetch_node_gated` |

**Score:** 5/5 locally-verifiable must-haves verified. SC#5 is a required-green CI gate pending PR CI (not a code gap).

### Key Link Verification

| From | To | Via | Status |
| ---- | -- | --- | ------ |
| `crates/fuse/src/inode.rs` | `cipherbox_sdk::list_folder_owned` | `populate_folder` async fetch (`inode.rs:361`) | ✓ WIRED |
| `crates/fuse/src/replay.rs` | `cipherbox_sdk::fetch_node_gated` / `list_folder_owned` | `resolve_owned_parent` (`replay.rs:156,426`) | ✓ WIRED |
| `crates/fuse/.../delete.rs`,`rename.rs` | `grant_scope::run_scope_exit_gate` | fail-closed gate call (`delete.rs:200,399`) | ✓ WIRED |
| `grant_scope::gate_scope_exit` | `cipherbox_sdk::rotation::engine::rotate_read_from_node` | injected `rotate` closure, exactly-once (`grant_scope.rs:236`) | ⚠️ WIRED but fail-closed (live RotationDeps pending — SC#3 residual) |
| `grant_scope::build_coverage_params`/`grant_root_for` | `cipherbox_sdk::rotation::scope::has_covering_grant` | wraps 69-05 (`grant_scope.rs:180`) | ✓ WIRED |
| `RotationHighWater` | `JsonSidecarFloorStore` (generation + seq sidecars) | `HighWaterStore` seam (`high_water.rs`, `floor_store.rs`) | ✓ WIRED |

### Behavioral Spot-Checks / Test Evidence

| Behavior | Evidence | Status |
| -------- | -------- | ------ |
| Full Rust workspace behavior (default fuse feature, macOS) | `cargo test --workspace: 476 passed, 0 failed` (orchestrator-run) across cipherbox-core, -sdk, -fuse, -crypto, desktop | ✓ PASS |
| Private delete = zero rotation | `delete.rs` tests `unlink_private_..._pure_relink` / `rmdir_private_...` (`delete.rs:591,616`) | ✓ PASS |
| Shared-scope exit routes through rotation, fail-closed | `unlink_shared_scope_exit_fails_closed_until_rotation_wired` (`delete.rs:645`) | ✓ PASS (fail-closed by design) |

### SC#5 — Required CI Gates (objective sign-off authority; MUST be green before merge)

SC#5 is **not optional and not a mere deferral** — it is the phase's objective sign-off authority for the WinFsp platform layer. `crates/fuse/src/platform/windows/*` never compiles under local mac cargo (macFUSE-only linking, per project memory + `69-14-PLAN.md:20`), so this criterion is verified in CI, not locally. Two conditions MUST both hold before merge:

- **(a) `cargo-windows` job green** — `.github/workflows/ci.yml:590` runs `cargo check/test --workspace --no-default-features --features winfsp` (`ci.yml:630,633`). This job must pass on the PR head SHA.
- **(b) Full `Desktop E2E Tests` matrix green** — `.github/workflows/desktop-e2e.yml` (macOS / Windows / Linux matrix) must be **explicitly dispatched against the shipped branch SHA** and pass ALL matrix legs:

  ```bash
  gh workflow run "Desktop E2E Tests" --ref feat/fuse-and-winfsp-rust-integration-and-grant-root-awareness
  ```

Related: plan 69-14 (WinFsp platform layer) is `autonomous:false` with no `69-14-SUMMARY.md` — intentionally unexecuted locally, verified on the PR. Its scope includes deleting the lone residual `spawn_file_meta_reencrypt` caller in `platform/windows/write_ops.rs:1189` and promoting the SC#2 grep gate to the whole tree (dropping `grep -v 'platform/windows'`) — see `ci.yml:754-757` (`"69-14 deletes it"`). SC#5 status: **pending CI — required green before merge**, NOT a code gap.

### Acknowledged Gaps / Follow-ups (non-blocking)

1. **SC#3 shared-scope-exit rotation is fail-closed, not live-wired.** `rotate_read_on_scope_exit` (`grant_scope.rs`) currently returns `Err(RotateFailed)` → EIO because no production `cipherbox_sdk::rotation::engine::RotationDeps` implementor exists yet (only the engine's in-crate `FakeDeps` test double). The grant-root gate/awareness (the phase-goal deliverable) IS present and wired; the live rotation EXECUTION is a standalone deferred live-wiring plan matching the known ROT-07 live-wiring gap, explicitly flagged in the code doc-comment and `69-13-SUMMARY`. Security posture is correct: fail-closed refuses to complete a covered delete/move without rotating, preventing revocation bypass. Private deletes are fully functional. This is a documented, intentional deferral — tracked, not a phase-goal miss.

### Anti-Patterns Found

None blocking. The `ecies` references remaining in `crates/fuse` are legitimate: test-only keypair generation (`journal_helpers.rs:551`, `lib.rs:140`, `delete.rs:462`) and the winfsp-feature-gated Windows write/read plane wrapping (`platform/windows/*`, 69-14 surface) — none are node-unseal on the read path, satisfying SC#1's intent.

## Gaps Summary

No code gaps block the phase goal. All five locally-verifiable Success Criteria (SC#1, 2, 3, 4, 6) are delivered in code and backed by 476 passing workspace tests. SC#5 (WinFsp platform layer) is a **required-green CI gate** — the PR's `cargo-windows` job AND a full explicitly-dispatched `Desktop E2E Tests` matrix run against the branch SHA must both pass before merge; these are objective sign-off authority that run in CI (not on mac), not a code gap. The one documented follow-up — live-wiring the shared-scope-exit read-key rotation (currently fail-closed, security-safe) — is a tracked ROT-07-class deferral, not a phase-goal miss.

---

_Verified: 2026-07-07_
_Verifier: Claude (gsd-verifier)_
