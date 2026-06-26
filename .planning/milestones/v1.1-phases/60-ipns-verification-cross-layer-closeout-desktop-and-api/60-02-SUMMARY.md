---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: "02"
subsystem: ipns-producers
tags: [ipns, fuse, desktop, sdk-core, web, sequence, d-02]
dependency_graph:
  requires: [60-01]
  provides: [unified-first-publish-seq-1]
  affects: [60-03, 60-04, 60-05]
tech_stack:
  added: []
  patterns:
    - "First-publish IPNS record always embeds sequence 1 (D-02) across all producers"
key_files:
  created: []
  modified:
    - crates/fuse/src/write_ops/implementation/mkdir.rs
    - crates/fuse/src/platform/windows/write_ops.rs
    - crates/fuse/src/metadata.rs
    - apps/desktop/src-tauri/src/commands/vault.rs
    - packages/sdk-core/src/vault/index.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/services/vault-settings.service.ts
decisions:
  - "D-02: all 9 first-publish producers embed sequence 1; coordinator.record_publish updated to match the actual embedded value"
  - "vault-settings.service.ts forward-publish path (BigInt(resolved.sequenceNumber ?? 0) + 1n) left untouched; only the fallback initializer changed"
  - "Windows winfsp site changed by code analysis; authoritative gate is Cargo Check & Test (Windows) CI job"
metrics:
  duration: "~4 min"
  completed: "2026-06-24"
  tasks_completed: 2
  files_changed: 7
---

# Phase 60 Plan 02: Unify First-Publish Producers to Sequence 1 Summary

All nine IPNS first-publish producer sites have been changed from embedding sequence `0`/`0n` to sequence `1`/`1n` (D-02). This satisfies the precondition for the D-12 lockstep invariant: no embedded-0 record will be produced once strict verify ships in Wave 2.

## Tasks Completed

### Task 1: Unify 5 Rust first-publish producers to embed sequence 1

Five Rust first-publish call sites changed:

| File | Site | Change |
| ---- | ---- | ------ |
| `crates/fuse/src/write_ops/implementation/mkdir.rs` | New-folder create | `create_ipns_record(..., 0, ...)` -> `1`; `record_publish(..., 0)` -> `1` |
| `crates/fuse/src/platform/windows/write_ops.rs` | Windows new-folder create | `create_ipns_record(..., 0, ...)` -> `1`; `record_publish(..., 0)` -> `1` |
| `crates/fuse/src/metadata.rs` | Bin first publish | `make_bin_record(0)` -> `make_bin_record(1)`; `record_publish(&bin_ipns_name, 0)` -> `1` |
| `apps/desktop/src-tauri/src/commands/vault.rs` | Vault-key blob | `create_ipns_record(..., 0, ...)` -> `1` |
| `apps/desktop/src-tauri/src/commands/vault.rs` | Root-folder metadata | `create_ipns_record(..., 0, ...)` -> `1` |

`cargo check -p cipherbox-fuse` passes (non-Windows sites). Windows winfsp site verified by code analysis; the `Cargo Check & Test (Windows)` CI gate is authoritative.

Commit: `ffbcd47fd`

### Task 2: Unify 4 TypeScript first-publish producers to embed 1n

Four TS first-publish call sites changed:

| File | Site | Change |
| ---- | ---- | ------ |
| `packages/sdk-core/src/vault/index.ts` | Vault-key blob | `sequenceNumber: 0n` -> `1n` |
| `apps/web/src/hooks/useAuth.ts` | Vault-key blob | `sequenceNumber: 0n` -> `1n` |
| `apps/web/src/hooks/useAuth.ts` | Root-folder metadata | `sequenceNumber: 0n` -> `1n` |
| `apps/web/src/services/vault-settings.service.ts` | First-publish fallback | `let sequenceNumber = 0n` -> `1n` |

Forward-publish path (`BigInt(resolved.sequenceNumber ?? 0) + 1n`) in vault-settings.service.ts left unchanged.

`pnpm --filter @cipherbox/sdk-core build` and `tsc --noEmit` for web both pass.

Commit: `ca803dc52`

## Verification

### Acceptance greps

All clear — no embedded-0 first-publish literal remains at any of the 9 sites:

- `grep -n "create_ipns_record(.*, 0," mkdir.rs|windows/write_ops.rs|vault.rs` → no matches
- `grep -n "make_bin_record(0)" metadata.rs` → no matches
- `grep -n "sequenceNumber: 0n" sdk-core/vault/index.ts useAuth.ts` → no matches
- `grep -n "let sequenceNumber = 0n" vault-settings.service.ts` → no matches

### Build checks

- `cargo check -p cipherbox-fuse` → Finished (non-Windows)
- `pnpm --filter @cipherbox/sdk-core build` → ESM/CJS build success
- `tsc --noEmit` (apps/web) → clean (0 errors)

## Deviations from Plan

### Auto-applied improvements

**1. [Rule 2 - Missing correctness] Updated coordinator.record_publish to match embedded sequence**

- Found during: Task 1
- Issue: `coordinator.record_publish(&ipns_name_clone, 0)` in mkdir.rs and windows/write_ops.rs, and `coordinator.record_publish(&bin_ipns_name, 0)` in metadata.rs would have recorded stale sequence 0 in the PublishCoordinator cache after embedding seq 1. The cache drives forward-publish CAS increments; recording a stale value would cause a monotonic-sequence regression on the next publish from the same coordinator instance.
- Fix: Updated all three `record_publish` calls to pass `1` matching the embedded value.
- Files modified: Same files as plan (no additional files)

**2. Updated log messages referencing "sequence 0"** in vault.rs conflict arms to say "sequence 1" for accuracy. Cosmetic only.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced. All edits are in-place literal changes to existing producer call sites.

## Self-Check: PASSED

- Files created: N/A (no new files)
- Commits exist: `ffbcd47fd`, `ca803dc52` — confirmed via git log
- All 9 first-publish sites embed sequence 1
- No embedded-0 literal remains at any producer
