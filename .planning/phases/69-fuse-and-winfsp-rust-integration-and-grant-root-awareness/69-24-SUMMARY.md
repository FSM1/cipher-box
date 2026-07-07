---
phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
plan: 24
subsystem: desktop-fuse
tags: [fuse, winfsp, node-v3, root-keys, mount, keystate]
requires:
  - "69-22: KeyState carries root_read_key/root_write_key fields"
  - "69-23: vault init/recovery populates root_read_key/root_write_key at login"
provides:
  - "desktop mount consumes the REAL node/v3 root read/write keys from KeyState"
  - "the 0xA5 placeholder bridge is deleted from both desktop mount fns"
affects:
  - apps/desktop/src-tauri/src/fuse/mod.rs
  - apps/desktop/src-tauri/src/commands/auth.rs
  - apps/desktop/src-tauri/src/fuse/windows/mod.rs
tech-stack:
  added: []
  patterns:
    - "narrow Zeroizing<Vec<u8>> state keys into fixed Zeroizing<[u8;32]> locals (no derivation)"
    - "terminal-owner zeroization (D-09): mount borrows/copies caller-owned state keys, never zeroes them"
key-files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/commands/auth.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
decisions:
  - "Shadow the passed root_read_key/root_write_key Vec params with the [u8;32] locals (same idiom as the deleted bridge, sourced from the params not from root_folder_key)"
  - "Keep root_folder_key threaded into CipherBoxFS — its removal is out-of-scope crates/fuse cleanup"
metrics:
  duration: ~10m
  completed: 2026-07-07
  tasks: 2
  files: 3
status: complete
---

# Phase 69 Plan 24: Wire Real node/v3 Root Keys into the FUSE Mount Summary

The desktop mount now consumes the REAL node/v3 root read/write keys recovered into KeyState (69-22 fields, populated by 69-23), and the `^0xA5` placeholder bridge is deleted from both the macOS/Linux (`fuse/mod.rs`) and Windows (`fuse/windows/mod.rs`) mount paths.

## What Changed

### Task 1 — fuse/mod.rs + auth.rs (commit 6d4810b32)

- **`mount_filesystem` (macOS/Linux)** signature gains `root_read_key: Zeroizing<Vec<u8>>` and `root_write_key: Zeroizing<Vec<u8>>`, placed adjacent to the retained `root_folder_key`.
- The inline `^0xA5` bridge (old mod.rs:179-205 — `root_read_key = root_folder_key[..32]`, `root_write_key = read_key ^ 0xA5`) is **DELETED**. The two `Zeroizing<[u8;32]>` locals are now built by narrowing the passed 32-byte state keys — no derivation, no XOR.
- The locals feed `InodeKind::Root`, `prepopulate_filesystem`, and the replay copies + `replay_for_vault` exactly as before (all already accept the two keys).
- **`post_auth_finalize` (auth.rs)** reads `state.sdk.root_read_key` and `state.sdk.root_write_key` (erroring if absent, like `root_folder_key`) and passes both into the single cfg-agnostic `mount_filesystem` call in the new argument position.
- `CipherBoxFS.root_folder_key` is still populated (crates/fuse legacy field, fs.rs:112 consumer); `crates/fuse` is untouched.

### Task 2 — fuse/windows/mod.rs (commit 4ebce5cf3)

- The `cfg(winfsp)` `mount_filesystem` gains the identical `root_read_key`/`root_write_key` params (param-for-param match with `fuse/mod.rs`) so the shared auth.rs call site type-checks under both cfgs.
- Its own `^0xA5` bridge (old windows/mod.rs:86-96) is **DELETED**; the real keys feed `InodeKind::Root`, `prepopulate`, and replay for parity.
- This file is NOT compiled by the default build (cfg(winfsp)); correctness is owned by the `Cargo Check & Test (Windows)` CI gate + the user's Windows box (D-06). The deeper WinFsp write-path work is 69-14.

## How the Mount Now Sources the Real Root Keys

`KeyState.root_read_key` / `KeyState.root_write_key` (`RwLock<Option<Zeroizing<Vec<u8>>>>`, 69-22, populated at recovery by 69-23) → `post_auth_finalize` reads + clones them → passed to `mount_filesystem` → narrowed into `Zeroizing<[u8;32]>` → `InodeKind::Root { read_key, write_key }` + `prepopulate_filesystem` + `replay_for_vault`. No key is fabricated from `root_folder_key` anywhere in the mount path.

## Green-Boundary Checks (verified in worktree)

- `cargo check --workspace` (default fuse feature): **GREEN** (Finished, cipherbox-desktop checks clean).
- `cargo test -p cipherbox-desktop --features fuse`: **GREEN** (22 passed; 0 failed) — includes `init_recover_v3_round_trips` and `build_empty_root_published_node_round_trips`.
- `grep -rn '0xA5\|derive_root_node_keys' apps/desktop/src-tauri/src/fuse/`: **EMPTY** (bridge gone from both mod.rs and windows/mod.rs).
- Mount pulls the real keys: `grep 'root_read_key\|root_write_key' auth.rs` confirms both are read from `state.sdk` and passed to `mount_filesystem`.
- `crates/fuse` untouched: `git diff <base> HEAD --name-only -- crates/fuse/` is empty; `CipherBoxFS` still constructed with `root_folder_key` in both mount fns.
- `--features winfsp`: **EXPECTED-RED** — fails at the `winfsp-sys v0.12.1` dependency `build.rs` (`windows_registry::LOCAL_MACHINE` unresolved) and windows-crates `IMarshal`/`marshaler` errors; these are macOS-can't-build-windows-crates failures, so our `windows/mod.rs` never even reaches compilation locally. Windows CI gate + 69-14 own this.

## Deviations from Plan

None — plan executed exactly as written. `rustfmt --edition 2021` on the three changed files produced no out-of-scope drift (`git status` showed only the three intended files).

## Residual E2E Risks (validation honesty)

This plan is the flip that makes desktop-e2e meaningful, but the reachable gate here is only workspace-green + desktop unit tests + the 0xA5-gone grep. Live mount-and-read correctness of a real node/v3 vault is validated by the orchestrator's **desktop-e2e run after 69-25** (necessary, not sufficient here). Specifically unverified locally:

- Whether the recovered `root_read_key`/`root_write_key` byte values actually resolve/decrypt the persisted root node at runtime (69-23 recovery correctness × this wiring).
- The `--features winfsp` compile of the parity edits — deferred to the Windows CI gate + 69-14.
- Read/write plane separation under the real keys at the FUSE callback level (only unit-covered here).

## Self-Check: PASSED

- Commit 6d4810b32: FOUND
- Commit 4ebce5cf3: FOUND
- All three modified files present in worktree and in the diff vs base.
