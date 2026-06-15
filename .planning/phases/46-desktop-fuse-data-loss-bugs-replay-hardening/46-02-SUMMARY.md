---
phase: 46-desktop-fuse-data-loss-bugs-replay-hardening
plan: 02
subsystem: desktop-fuse
tags: [fuse, linux, mount, recovery, mountinfo, eexist]
requires: [46-01]
provides:
  - recover_stale_mount Linux stale/disconnected mount auto-recovery (REQ-3)
  - mountinfo_contains_mountpoint pure /proc/self/mountinfo parser
  - should_recover_then_retry EEXIST decision helper
  - mount_filesystem Linux-gated recovery call + EEXIST recover-then-retry-once
affects:
  - crates/fuse/src/platform/linux.rs
  - apps/desktop/src-tauri/src/fuse/mod.rs
tech-stack:
  added: []
  patterns:
    - mountinfo field-index parse (field 4 mount point) with octal escape un-escaping
    - fusermount3 -u with lazy -z fallback layered on the existing unmount cascade
    - Linux-only cfg gating keeps macOS/Windows mount paths byte-identical
key-files:
  created:
    - .planning/phases/46-desktop-fuse-data-loss-bugs-replay-hardening/46-02-SUMMARY.md
  modified:
    - crates/fuse/src/platform/linux.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
decisions:
  - Authoritative stale detection via /proc/self/mountinfo, never path.exists() (lies with ENOTCONN)
  - Lazy fusermount3 -z fallback added because the existing unmount cascade lacks it
  - recover_stale_mount is best-effort and returns unit so the caller always proceeds to the clean-stale path
  - platform module was already pub; no visibility widening needed
metrics:
  duration: ~12m
  completed: 2026-06-15
---

# Phase 46 Plan 02: Linux Stale-Mount Auto-Recovery Summary

REQ-3: a crash that leaves `~/CipherBox` as a disconnected FUSE mount made
`stat()` return ENOTCONN, so `mount_path.exists()` returned false, the code took
the `create_dir_all` branch, and the leftover dirent produced EEXIST (os error
17) surfaced as a user-facing "Failed to create mount point" error that blocked
remount. This plan adds Linux-only auto-recovery so the vault remounts cleanly.

## What Was Built

### crates/fuse/src/platform/linux.rs

- `mountinfo_contains_mountpoint(mountinfo: &str, mount_path: &Path) -> bool` — a
  pure helper that scans each `/proc/self/mountinfo` line, takes the mount-point
  field (space-separated index 4), un-escapes octal escapes (`\040` to space and
  general `\NNN`), and compares to the target path. Pure over a `&str`, so it
  unit-tests without `/proc` or root.
- `recover_stale_mount(mount_path: &Path)` — reads `/proc/self/mountinfo` (on read
  error logs and returns, never blocking the mount); if the path is a current
  mount point, runs `fusermount3 -u <path>`, and on non-success falls back to the
  lazy `fusermount3 -z -u <path>`. Best-effort: returns unit so the caller always
  proceeds to its normal clean-stale path.
- `should_recover_then_retry(err_kind) -> bool` — pure decision helper returning
  true only for `ErrorKind::AlreadyExists`.

### apps/desktop/src-tauri/src/fuse/mod.rs

- Inserted `#[cfg(target_os = "linux")] cipherbox_fuse::platform::linux::recover_stale_mount(&mount_path);`
  immediately after the `is_symlink` guard and before the `exists()`/`create_dir_all`
  decision, mirroring the existing `unmount_filesystem` crate path.
- Made `create_dir_all` EEXIST-tolerant on Linux: when the error kind is
  `AlreadyExists`, it calls `recover_stale_mount` again and retries `create_dir_all`
  once before mapping to the user-facing error. Non-EEXIST errors map unchanged.
  The macOS `.metadata_never_index` block, the clean-stale `else` branch, and all
  mount-option cfg arms are untouched.

## Test Results

The named tests live in `platform::linux`, which compiles only on
`target_os = "linux"`. On the macOS dev host they filter out; the logic was
validated by extracting byte-identical function bodies and running them under
`rustc --test`:

```text
test eexist_triggers_recovery ... ok
test mountinfo_detects_stale ... ok
test mountinfo_detects_stale_with_spaced_path ... ok
test result: ok. 3 passed; 0 failed
```

`cargo check -p cipherbox-desktop --features fuse` finished clean. The in-crate
`cargo test` filters run natively on the CI `cargo-linux` job (ubuntu-22.04 with
libfuse3-dev).

## Manual Verification Required

Task 3 is a blocking human-verify gate: the real disconnected-mount remount
cannot be unit-tested. On a Linux host, SIGKILL the desktop app mid-session to
leave a stale mount, then relaunch and confirm the vault remounts cleanly with no
"Failed to create mount point" notification. See 46-02-PLAN.md Task 3 for the
full recipe.

## Threat Model Compliance

- T-46-03 (DoS): stale mount detected via mountinfo (not the lying `exists()`),
  unmounted with `-u` then lazy `-z`, with a single EEXIST retry — restores mount
  availability after a crash.
- T-46-05 (Tampering): `recover_stale_mount` shells `fusermount3` with a fixed
  argv and the app-derived `mount_point()` path; no user-controlled command
  string.
