---
phase: 52-desktop-fuse-durability-at-rest-safety
plan: 01
subsystem: fuse/sdk
tags: [security, at-rest-safety, error-handling, journal, rust, s1]
dependency_graph:
  requires: []
  provides: [D-05-path-scrub, D-06-removal-logging]
  affects:
    - crates/sdk/src/sync.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/write_ops.rs
tech_stack:
  added: []
  patterns: [hand-rolled-char-scan-scrub, if-let-err-warn-logging]
key_files:
  created: []
  modified:
    - crates/sdk/src/sync.rs
    - crates/fuse/src/lib.rs
    - crates/fuse/src/write_ops.rs
decisions:
  - "D-05 keeps the existing hand-rolled char_indices scan; no regex crate added"
  - "Windows drive-letter branch matches any ASCII uppercase letter + ':\\Users\\'"
  - "D-06 test decoupled from JournalEntry struct shape (writes a raw .json) so it survives the 52-02 field rename"
metrics:
  completed: "2026-06-20T00:00:00Z"
  tasks_completed: 3
  files_modified: 3
---

# Phase 52 Plan 01: At-Rest-Safety Path Scrub and Removal Logging

One-liner: Extended `sanitize_error`'s path scrub to `/var`, `/tmp`, `/private`, and Windows drive-letter `X:\Users\` (D-05), and replaced the three swallowed `let _ = journal.remove(...)` sites with `if let Err(e) { log::warn!(...) }` so a failed removal can no longer silently cause a later double-replay/double-publish (D-06).

## What Was Built

### D-05 — extended `regex_replace_paths` scrub (crates/sdk/src/sync.rs)

- Added `/var/`, `/tmp/`, `/private/` to the existing `if c == '/' && (...)` prefix list.
- Added a new `else if c.is_ascii_uppercase() && i + 2 < input.len() && input[i + 1..].starts_with(":\\Users\\")` branch for Windows drive-letter paths (e.g. `C:\Users\...`, `D:\Users\...`), reusing the same skip-until-whitespace/quote loop.
- New `#[cfg(test)] mod tests` with `sanitize_error_extended_paths` covering all five Unix prefixes, two Windows drive letters, an unchanged no-path string, and a multi-path boundary case.

### D-06 — log `journal.remove` failures (crates/fuse/src/lib.rs, write_ops.rs)

Three sites converted from `let _ = ...remove(...)` to `if let Err(e) { log::warn!(...) }`, each naming the op + entry id and stating "entry may replay again on next mount":

1. `crates/fuse/src/lib.rs` MkdirPublish replay-success arm.
2. `crates/fuse/src/lib.rs` UploadFile replay-success arm.
3. `crates/fuse/src/write_ops.rs` mkdir parent-publish success arm (the existing `log::info!("Parent metadata published after mkdir")` is preserved).

New `remove_failure_is_logged` test in lib.rs proves a genuine removal error is an `Err` (on Unix, by setting the journal dir to `0o500` so unlinking the child `.json` fails), confirming the `if let Err` branch is reachable — not dead code. The test writes a raw `.json` rather than constructing a `JournalEntry`, so it is decoupled from the upcoming 52-02 field rename.

## Phase 51 Reconciliation

D-06 line numbers in the plan (`:1494`/`:1558`) were stale relative to the merged tree — Phase 51's zeroization/Zeroizing edits shifted them to `:1503`/`:1567`. Located the actual sites by grep before editing. No Phase 51 hardening was reverted; these edits only swap the swallowed-error idiom for logging and do not touch any key-handling code.

## Test Results

- `sanitize_error_extended_paths` (cipherbox-sdk): pass.
- `remove_failure_is_logged` (cipherbox-fuse): pass.
- Grep gate: 0 remaining `let _ = journal.remove` / `let _ = journal_for_mkdir.remove` in the three files.
- Full suites: cipherbox-fuse 61/61, cipherbox-sdk 49/49 — no regressions (baseline was 60/48).

## Deviations from Plan

None functionally. The only adjustment: the `let _ = cipherbox_api_client::ipfs::unpin_content(...)` at write_ops.rs (adjacent to the journal removal) is intentionally left fire-and-forget — it is out of D-06 scope, which targets journal-entry removals only.

## Known Stubs

None.

## Self-Check: PASSED

- `crates/sdk/src/sync.rs` contains `/var/`, `/tmp/`, `/private/`, and the `:\\Users\\` branch.
- `crates/fuse/src/lib.rs` and `crates/fuse/src/write_ops.rs` contain `if let Err` removal logging at all three sites.
- Both new tests pass; grep gate is 0; no regressions.
