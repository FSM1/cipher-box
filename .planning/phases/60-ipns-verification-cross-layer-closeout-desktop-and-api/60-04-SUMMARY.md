---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: 04
subsystem: infra
tags: [ipns, rust, cryptography, verify, fuse, sdk, desktop, d-04, d-08, d-09]

requires:
  - phase: 60-01
    provides: resolve_ipns_verified chokepoint in cipherbox_api_client::ipns + all 9 FUSE Legacy arms pre-folded to Invalid
  - phase: 60-02
    provides: vault.rs embed sites already edited (avoids file-conflict)

provides:
  - Zero raw/unverified resolve_ipns calls in sdk or desktop resolve paths (D-08, D-09)
  - verify.rs deleted — single chokepoint exclusively in cipherbox-api-client (D-08)
  - All 9 FUSE crate::verify:: imports re-pointed to cipherbox_api_client::ipns:: (D-04)

affects:
  - 60-05 and beyond (downstream plans can rely on full Rust verify coverage being closed)

tech-stack:
  added: []
  patterns:
    - Scoped fail-closed posture (D-09): per-operation failure on Invalid; no whole-app abort
    - Inline path-qualified imports (cipherbox_api_client::ipns::VerifyError) instead of use-imports at call sites

key-files:
  created: []
  modified:
    - crates/fuse/src/events.rs
    - crates/fuse/src/metadata.rs
    - crates/fuse/src/publish.rs
    - crates/fuse/src/fs.rs
    - crates/fuse/src/replay.rs
    - crates/fuse/src/lib.rs
    - crates/sdk/src/registry.rs
    - crates/sdk/src/sync.rs
    - apps/desktop/src-tauri/src/fuse/prepopulate.rs
    - apps/desktop/src-tauri/src/commands/vault.rs
  deleted:
    - crates/fuse/src/verify.rs

decisions:
  - 'All 9 FUSE Legacy arms already folded by 60-01; Task 1 only re-pointed imports and deleted verify.rs'
  - 'sync.rs poll(): Invalid verify failure returns Err (skip poll cycle) rather than warn-and-proceed'
  - 'registry.rs: VerifyError::Invalid maps to SdkError::RegistryError (fail-closed, callers log and continue login)'
  - 'prepopulate.rs: per-operation fail-closed (root/subfolder failures return early but do not crash mount)'
  - 'vault.rs resolve sites: fail-closed Err string propagated to Tauri command error handler'
  - 'Used log:: (not tracing::) throughout to match existing logging style in each crate'

metrics:
  duration: 15min
  completed: 2026-06-24T00:54:26Z
  tasks: 2
  commits: 2
  files_modified: 10
  files_deleted: 1
---

# Phase 60 Plan 04: FUSE Import Re-Point, SDK and Desktop Resolve Closeout Summary

**verify.rs deleted, all 9 FUSE crate::verify imports re-pointed, 2 SDK bypasses and 6 desktop Tauri resolve sites routed through resolve_ipns_verified — zero raw resolves remain in Rust resolve paths**

## Performance

- **Duration:** 15 min
- **Started:** 2026-06-24T00:40:00Z
- **Completed:** 2026-06-24T00:54:26Z
- **Tasks:** 2
- **Files modified:** 10
- **Files deleted:** 1

## Accomplishments

- Re-pointed all 9 `crate::verify::*` call sites in FUSE (events.rs ×1, metadata.rs ×3, publish.rs ×2, fs.rs ×1, replay.rs ×2) to `cipherbox_api_client::ipns::*`
- Removed `pub mod verify;` from `crates/fuse/src/lib.rs` and deleted `crates/fuse/src/verify.rs` — the thin re-export shim is gone; single chokepoint in api-client
- Routed `crates/sdk/src/registry.rs` `fetch_and_decrypt_registry` through `resolve_ipns_verified` — `VerifyError::Invalid` maps to `SdkError::RegistryError` (D-08)
- Routed `crates/sdk/src/sync.rs` `poll()` through `resolve_ipns_verified` — `Invalid` returns `Err` to skip the poll cycle with a logged error (D-08)
- Routed all 4 `apps/desktop/src-tauri/src/fuse/prepopulate.rs` sites (root, root-file-pointer, subfolder, subfolder-file-pointer) through `resolve_ipns_verified` with scoped fail-closed posture (D-09)
- Routed 2 `apps/desktop/src-tauri/src/commands/vault.rs` resolve sites (`load_vault_settings`, `fetch_and_decrypt_vault`) through `resolve_ipns_verified` with fail-closed `Err` return (D-09)
- `cargo check -p cipherbox-fuse`, `cargo check -p cipherbox-sdk`, and `cargo check -p cipherbox-desktop` all clean

## Task Commits

1. `86a878b29` — refactor(60-04): re-point FUSE crate::verify imports to api-client and delete verify.rs
2. `9a4540c0c` — feat(60-04): route sdk and desktop resolve paths through resolve_ipns_verified

## Files Modified

- `crates/fuse/src/events.rs` — 1 call site re-pointed
- `crates/fuse/src/metadata.rs` — 3 call sites re-pointed
- `crates/fuse/src/publish.rs` — 2 call sites re-pointed
- `crates/fuse/src/fs.rs` — 1 call site re-pointed
- `crates/fuse/src/replay.rs` — 2 call sites re-pointed
- `crates/fuse/src/lib.rs` — removed `pub mod verify;` block
- `crates/fuse/src/verify.rs` — DELETED (thin re-export shim)
- `crates/sdk/src/registry.rs` — 1 raw resolve replaced with verified
- `crates/sdk/src/sync.rs` — 1 raw resolve replaced with verified
- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` — 4 raw resolves replaced with verified
- `apps/desktop/src-tauri/src/commands/vault.rs` — 2 raw resolves replaced with verified

## Deviations from Plan

### Reconciliation with 60-01 Pre-Work

**1. [Pre-folded — no action needed] All 9 FUSE Legacy arms already folded by 60-01**

- **Expected by plan:** Task 1 would fold 9 FUSE `VerifyError::Legacy` arms into `Invalid`
- **Actual state found:** 60-01 was forced to fold all 9 arms immediately when it removed the `Legacy` variant (compiler-enforced exhaustive match). All 9 sites were already fail-closed `Invalid` handling.
- **What Task 1 actually did:** Confirmed the 9 sites were already fail-closed, then re-pointed the `crate::verify::*` import paths to `cipherbox_api_client::ipns::*` (the plan's secondary objective) and deleted `verify.rs`.
- **Impact:** No semantic change to FUSE behavior; purely a namespace/import cleanup. The plan's primary security goal (D-04 fail-closed) was already satisfied.
- **Documentation:** Recorded as an intended deviation from the plan's stated work, not a regression.

None beyond the 60-01 pre-work reconciliation above.

## Issues Encountered

- `tracing::error!` used initially in `registry.rs` was corrected to `log::error!` to match the crate's existing logging style (`log` workspace dep, no `tracing` dep in sdk Cargo.toml)

## Security Surface (Threat Register Closure)

| Threat ID | Status | Notes |
| --------- | ------ | ----- |
| T-60-12 | CLOSED | sdk registry.rs + sync.rs now route through resolve_ipns_verified (D-08) |
| T-60-13 | CLOSED | All 6 desktop resolve sites route through resolve_ipns_verified, scoped fail-closed (D-09) |
| T-60-14 | CLOSED (60-01) | All 9 FUSE Legacy arms already folded to Invalid fail-closed in 60-01 |
| T-60-15 | CLOSED | verify.rs deleted; single chokepoint in api-client (D-08) |

## Next Phase Readiness

- All Rust resolve paths verified through the single `cipherbox_api_client::ipns::resolve_ipns_verified` chokepoint
- Zero raw `resolve_ipns` calls remain in `crates/sdk` or `apps/desktop` resolve paths
- Windows winfsp paths (`crates/fuse/src/platform/windows/`) contain no `crate::verify::` or raw `resolve_ipns` calls — confirmed by grep (those paths use the same api-client symbols already)
- Desktop E2E (dispatch-gated) and Windows CI gate are authoritative for runtime coverage

## Known Stubs

None — all resolve sites are wired to the verified chokepoint with real fail-closed logic.

## Self-Check: PASSED

- `crates/fuse/src/verify.rs`: DELETED (confirmed)
- `crate::verify::` references in fuse/src: NONE (grep clean)
- `resolve_ipns_verified` in registry.rs: FOUND
- `resolve_ipns_verified` in sync.rs: FOUND
- `resolve_ipns_verified` in prepopulate.rs (×4): FOUND
- `resolve_ipns_verified` in vault.rs (×2): FOUND
- `cargo check -p cipherbox-fuse`: PASSED
- `cargo check -p cipherbox-sdk`: PASSED
- `cargo check -p cipherbox-desktop`: PASSED
- Task commit `86a878b29`: VERIFIED in git log
- Task commit `9a4540c0c`: VERIFIED in git log
