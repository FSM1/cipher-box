---
created: 2026-06-14T12:37:25.820Z
title: Extract shared journal-dir and max-retries helper
area: desktop-fuse
files:
  - apps/desktop/src-tauri/src/fuse/mod.rs
  - apps/desktop/src-tauri/src/fuse/windows/mod.rs
  - apps/desktop/src-tauri/src/commands/sync.rs
  - crates/sdk/src/queue.rs
---

## Problem

The journal directory path (`<data_local_dir>/cipherbox/cb-journal`, with a temp_dir
fallback) plus the magic retry count `5` are triplicated across three production sites:
`apps/desktop/src-tauri/src/fuse/mod.rs`, `apps/desktop/src-tauri/src/fuse/windows/mod.rs`,
and `apps/desktop/src-tauri/src/commands/sync.rs`. The code comments openly concede it
("same path the FUSE mount uses (CR-07)", "mirroring ... mod.rs").

This is a CR-07 footgun: the sync daemon and the FUSE mount MUST point at the same
directory or parked-write notifications silently break. The invariant is enforced by
three hand-copied path builders that must stay byte-identical; the moment one changes
(per-vault subdir, XDG override, different retry budget) they diverge with no error.

Surfaced by the phase-43 `/simplify` altitude reviewer; deferred from commit a1ec69f1b
because the clean fix needs a new dependency.

## Solution

Add one constructor/helper that encodes the invariant once — e.g. a
`pub fn default_journal_dir() -> PathBuf` and `pub const DEFAULT_MAX_RETRIES: u32 = 5`
in `crates/sdk/src/queue.rs` — and call it from all three sites. The clean version
needs a `dirs` dependency in `crates/sdk` (the SDK currently has none); alternatively a
partial helper `journal_dir_in(base: PathBuf)` keeps `dirs` in the desktop crate while
still centralizing the `.join("cipherbox").join("cb-journal")` convention and the retry
constant. Note: `WriteQueue::default()` was intentionally removed in 43-05 to force an
explicit dir — the replacement should be this single resolver, not three open-coded copies.
