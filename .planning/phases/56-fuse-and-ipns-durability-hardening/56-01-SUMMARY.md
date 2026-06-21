---
phase: 56-fuse-and-ipns-durability-hardening
plan: "01"
subsystem: crates/fuse
tags: [rust, fuse, winfsp, write-path, safety-guards, ipns, sequence, arithmetic]
dependency_graph:
  requires: [55-fuse-refactor]
  provides: [D-05-offset-guard, D-06-eexist-guard, D-07-sequence-overflow-guard]
  affects: [crates/fuse/src/write_ops, crates/fuse/src/publish.rs, crates/fuse/src/platform/windows/write_ops.rs]
tech_stack:
  added: []
  patterns: [checked_add overflow guard, find_child existence check, libc errno returns before mutation, winfsp status constants]
key_files:
  created: []
  modified:
    - crates/fuse/src/publish.rs
    - crates/fuse/src/write_ops/implementation/file_data.rs
    - crates/fuse/src/write_ops/implementation/mkdir.rs
    - crates/fuse/src/platform/windows/write_ops.rs
decisions:
  - D-07 uses checked_add returning Err("IPNS sequence number overflow") — existing return type Result<u64, String> unchanged
  - D-06 mkdir guard placed before closure (not inside) to return genuine EEXIST not EIO, since the outer match maps all closure Err to libc::EIO
  - D-06 winfsp guard placed before is_dir branch to cover both file and directory creates in a single check point
  - winfsp handle_write has no offset<0 check because actual_offset is u64 (cannot be negative)
metrics:
  duration: "~30min"
  completed_date: "2026-06-22"
  tasks_completed: 3
  files_modified: 4
---

# Phase 56 Plan 01: Rust FUSE Write-Path Safety Guards Summary

Closed D-05, D-06, and D-07 from the Phase 56 hardening scope: reject malformed FUSE write parameters, prevent duplicate-name inode pollution, and guard IPNS sequence arithmetic against u64 overflow. macOS and winfsp paths updated in lockstep (D-15).

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | D-07: publish.rs overflow guard (TDD RED then GREEN) | c2182009f | crates/fuse/src/publish.rs |
| 2 | D-05 + D-06: file_data.rs + mkdir.rs macOS guards + new test module | 2da670ee0 | crates/fuse/src/write_ops/implementation/file_data.rs, mkdir.rs |
| 3 | D-05 + D-06 winfsp lockstep (D-15) | 080675f8e | crates/fuse/src/platform/windows/write_ops.rs |

## What Was Built

### Task 1: D-07 sequence overflow guard (publish.rs)

Replaced `current_sequence.map(|seq| seq + 1)` with:

```rust
current_sequence
    .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
    .and_then(|seq| {
        seq.checked_add(1)
            .ok_or_else(|| "IPNS sequence number overflow".to_string())
    })
```

TDD RED: added `next_file_publish_sequence_overflow_returns_err` test (panicked on unchecked add at u64::MAX in debug mode). TDD GREEN: checked_add guard makes the test pass. Existing missing-sequence error string is byte-identical.

New tests added to `publish::tests`:

- `next_file_publish_sequence_normal_increment_unchanged` — Some(5) → Ok(6)
- `next_file_publish_sequence_overflow_returns_err` — Some(u64::MAX) → Err containing "overflow"
- `next_file_publish_sequence_missing_sequence_error_preserved` — None → Err containing "Missing current sequence"

### Task 2: D-05 + D-06 macOS guards (file_data.rs + mkdir.rs)

**file_data.rs `handle_write` (D-05):** Guards inserted before `write_at`, before open_files lookup:

```rust
if offset < 0 { reply.error(libc::EINVAL); return; }
let offset_u64 = offset as u64;
let new_end = match offset_u64.checked_add(data.len() as u64) {
    Some(end) => end,
    None => { reply.error(libc::EFBIG); return; }
};
```

`new_end` replaces the old unchecked `offset as u64 + data.len() as u64` in the Ok arm.

**file_data.rs `handle_create` (D-06):** Guard after parent_exists check, before `allocate_ino`:

```rust
if fs.inodes.find_child(parent, name_str).is_some() {
    reply.error(libc::EEXIST); return;
}
```

**mkdir.rs `handle_mkdir` (D-06):** Guard before the closure (not inside it), so the return is EEXIST not EIO:

```rust
if fs.inodes.find_child(parent, name_str).is_some() {
    reply.error(libc::EEXIST); return;
}
```

**New test module** `#[cfg(all(test, feature = "fuse"))] mod tests` in file_data.rs (first test module under `write_ops/`):

- `d05_offset_overflow_predicate_at_boundary` — u64::MAX + 1 overflows (checked_add returns None)
- `d05_offset_no_overflow_within_range` — 100 + 200 = Some(300)
- `d06_find_child_detects_duplicate` — seeds a parent+child in InodeTable, asserts find_child returns Some
- `handle_write_rejects_negative_offset` — end-to-end: handle_write with offset=-1 captures EINVAL

### Task 3: winfsp lockstep guards (write_ops.rs)

**D-05 winfsp handle_write:** Overflow guard before `write_at`. No `< 0` check because `actual_offset` is `u64`:

```rust
let new_end = match actual_offset.checked_add(buffer.len() as u64) {
    Some(end) => end,
    None => return Err(status_io_device_error()),
};
```

**D-06 winfsp handle_create:** Single guard before the `is_dir` branch covers both file and directory creates:

```rust
if fs.inodes.find_child(parent_ino, name).is_some() {
    return Err(status_object_name_collision());
}
```

D-04 constraint respected: `MkdirConflict` event-channel re-arm in the background thread is untouched.

`cargo check -p cipherbox-fuse --features fuse` compiles clean on macOS. winfsp code compiles only under `#[cfg(feature = "winfsp")]` — authoritative gate is `Cargo Check & Test (Windows)` CI.

## Deviations from Plan

### Auto-adjustments (Rule 1/2)

**1. [Rule 1 - Bug] D-06 mkdir guard placement: before closure, not inside**

- **Found during:** Task 2
- **Issue:** The plan's action note mentioned placing the guard inside the closure and returning `Err(format!("EEXIST: ..."))`, but the outer `match result` maps ALL `Err` to `reply.error(libc::EIO)`. Placing the guard inside the closure would return EIO, not EEXIST — violating the acceptance criterion.
- **Fix:** Placed the guard BEFORE the closure using `reply.error(libc::EEXIST); return;`, producing a genuine EEXIST reply (consistent with the plan's stated intent: "the guard path yields a genuine EEXIST reply, NOT EIO").
- **Files modified:** crates/fuse/src/write_ops/implementation/mkdir.rs
- **Commit:** 2da670ee0

**2. [Rule 1 - Bug] fuser::ReplyWrite::new requires use of Reply trait**

- **Found during:** Task 2 test compilation
- **Issue:** `fuser::ReplyWrite::new(...)` produced `no function or associated item named 'new'` — requires `use fuser::Reply`.
- **Fix:** Changed test to use `<fuser::ReplyWrite as Reply>::new(1, sender)` (same pattern as `lib.rs:260`).
- **Files modified:** crates/fuse/src/write_ops/implementation/file_data.rs
- **Commit:** 2da670ee0

**3. [Rule 2 - Critical] D-06 winfsp: single guard covers both file and directory creates**

- **Found during:** Task 3
- **Issue:** Plan's action described adding the mkdir guard "in the mkdir branch" separately from the file create branch. However, both share the same `handle_create` function and the same `parent_ino`/`name` variables. Placing a single guard before the `is_dir` branch covers both cases with one check, cleaner than two separate guards.
- **Fix:** Single `find_child` guard before `is_dir` branch covers file AND directory creates.
- **Files modified:** crates/fuse/src/platform/windows/write_ops.rs
- **Commit:** 080675f8e

## Verification Results

- `cargo test -p cipherbox-fuse --features fuse -- publish::tests write_ops`: 11 passed, 0 failed
- `cargo check -p cipherbox-fuse --features fuse`: clean compile
- `grep -n "checked_add" crates/fuse/src/publish.rs` → line 24 in `next_file_publish_sequence`
- `grep -n "seq + 1" crates/fuse/src/publish.rs` → no matches (unchecked add removed)
- `grep -n "libc::EINVAL" crates/fuse/src/write_ops/implementation/file_data.rs` → line 107 (inside handle_write before write_at)
- `grep -n "libc::EFBIG" crates/fuse/src/write_ops/implementation/file_data.rs` → line 115 (overflow guard)
- `grep -n "libc::EEXIST" crates/fuse/src/write_ops/implementation/file_data.rs` → line 180 (after parent_exists, before allocate_ino)
- `grep -n "find_child" crates/fuse/src/write_ops/implementation/mkdir.rs` → line 41 (before closure)
- `grep -n "status_io_device_error" crates/fuse/src/platform/windows/write_ops.rs` → line 429 (in handle_write, before write_at)
- `grep -n "status_object_name_collision" crates/fuse/src/platform/windows/write_ops.rs` → line 73 (handle_create, before is_dir branch)
- `grep -n "MkdirConflict" crates/fuse/src/platform/windows/write_ops.rs` → line 274 (unchanged — D-04 preserved)
- **winfsp authoritative gate:** `Cargo Check & Test (Windows)` CI — required before phase sign-off

## Known Stubs

None — all guards are wired to real errno/status returns with no placeholder paths.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. This plan closes existing threat register entries:

| Threat ID | Status |
| --------- | ------ |
| T-56-02 (handle_write offset/overflow) | Mitigated (D-05) |
| T-56-04 (handle_create/mkdir EEXIST) | Mitigated (D-06) |
| T-56-02 (sequence overflow) | Mitigated (D-07) |

## Self-Check

Verified commits exist in git log.
