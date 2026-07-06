---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 22
subsystem: sdk
tags: [keystate, zeroization, node-v3, root-keys, recovery]
requires: ["69-21"]
provides:
  - KeyState.root_read_key
  - KeyState.root_write_key
affects:
  - crates/sdk/src/state.rs
tech-stack:
  added: []
  patterns:
    - RwLock<Option<zeroize::Zeroizing<Vec<u8>>>> field idiom (mirrors root_folder_key)
    - clear() terminal-owner zeroization block per sensitive field
key-files:
  created: []
  modified:
    - crates/sdk/src/state.rs
decisions:
  - Two independent node/v3 root keys (read + write) added ALONGSIDE the retained root_folder_key; root_folder_key stays transitional until 69-24 flips the mount
  - AppState (apps/desktop/src-tauri/src/state.rs) left untouched — it wraps Arc<KeyState> and clear_keys() already delegates to KeyState::clear()
metrics:
  duration: ~6m
  completed: 2026-07-07
status: complete
---

# Phase 69 Plan 22: KeyState node/v3 root read/write key slots Summary

Added `root_read_key` and `root_write_key` (`RwLock<Option<zeroize::Zeroizing<Vec<u8>>>>`) to the SDK `KeyState` as the in-memory landing slots for the two independent random 32-byte node/v3 root keys, zeroized on `clear()`, mirroring the retained `root_folder_key` idiom — purely additive, workspace-green, no new dependency.

## What Was Built

- **`KeyState.root_read_key`** and **`KeyState.root_write_key`** fields (`crates/sdk/src/state.rs`), typed identically to `root_folder_key` so the mount's `[u8;32]` copy idiom is reused in 69-24. Documented as the two independent random node/v3 root keys (research §Q1) — never derived from each other or from `root_folder_key`.
- **`new()` init**: both initialized to `RwLock::new(None)` alongside `root_folder_key`.
- **`clear()` zeroization**: two new blocks (adjacent to the `root_folder_key` block) acquire the write lock, `k.zeroize()` the stored bytes, then set `*key = None`. `clear()` is the terminal owner wiping its OWN stored keys (correct per project zeroization rule — not a callee borrowing).
- **Extended the three existing unit tests**:
  - `new_creates_state_with_none_fields` — asserts both new fields default to `None`.
  - `fields_are_writable_and_readable` — writes/reads `Some(Zeroizing::new(...))` to each independently.
  - `clear_zeros_all_sensitive_byte_fields` — populates both with non-zero bytes, calls `clear()`, asserts both `None`.

## Green Boundary (verified in worktree)

- `cargo check --workspace` — GREEN (`Finished dev profile in 35.08s`).
- `cargo test -p cipherbox-sdk state` — GREEN: 6 passed; 0 failed (incl. new/writable/clear covering both new fields).
- `root_folder_key` accessor + tests retained unchanged: `grep -c root_folder_key crates/sdk/src/state.rs` = 10; diff is additive-only (48 insertions, 0 deletions).
- `grep '0xA5' crates/sdk/src/state.rs` — empty (no XOR bridge introduced).
- `apps/desktop/src-tauri/src/state.rs` — untouched (git status shows only `crates/sdk/src/state.rs` modified); AppState delegates via `self.sdk.clear()`.
- `git diff crates/sdk/Cargo.toml` — empty (no new dependency).

## Exact Fields/Accessors Added

In struct **`KeyState`** (`crates/sdk/src/state.rs`):

```rust
pub root_read_key: RwLock<Option<zeroize::Zeroizing<Vec<u8>>>>,
pub root_write_key: RwLock<Option<zeroize::Zeroizing<Vec<u8>>>>,
```

Access is via the public `RwLock` fields directly (same pattern as `root_folder_key`) — the desktop reaches them as `state.sdk.root_read_key` / `state.sdk.root_write_key`. No separate getter/setter methods exist on `KeyState` (the struct exposes fields directly); `clear()` is the only method extended.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Reverted out-of-scope rustfmt drift on pre-existing lines**
- **Found during:** Task 1 (post-`rustfmt --edition 2021`)
- **Issue:** `rustfmt` reformatted three pre-existing lines I did not functionally change (two `vault_settings` `assert_eq!` calls and the `root_ipns_name`/`root_ipns_private_key` asserts in `fields_are_writable_and_readable`) because the base tree is not fmt-clean.
- **Fix:** Restored those lines to their original single-line form so the commit diff is purely additive (per plan constraint: `git checkout --`/revert out-of-scope reformats). My newly-added `root_read_key`/`root_write_key` multi-line asserts remain rustfmt-correct.
- **Files modified:** crates/sdk/src/state.rs
- **Commit:** b8abd36d7

## Known Stubs

None. These fields are intentional landing slots populated by 69-23 (recovery) and read by 69-24 (mount); they are `None` by design until then, which is the correct additive state, not a stub blocking this plan's goal.

## Self-Check: PASSED

- FOUND: crates/sdk/src/state.rs (modified, root_read_key/root_write_key present)
- FOUND: commit b8abd36d7 in git log
- root_folder_key retained (10 refs); apps/desktop state.rs untouched; no 0xA5; Cargo.toml unchanged
