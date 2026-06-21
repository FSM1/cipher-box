---
created: 2026-06-18T00:00:00.000Z
title: FUSE write-journal unbounded growth + ciphertext-in-JSON, and replay has no network timeout
area: bug
severity: high
source: .planning/phases/43-fuse-write-durability/43-REVIEW.md warnings (criticals fixed 2026-06-14; warnings re-verified against live code 2026-06-18, post phases 45/46)
files:
  - crates/sdk/src/queue.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/lib.rs
  - crates/sdk/src/sync.rs
  - apps/desktop/src-tauri/src/fuse/mod.rs
---

## Problem

All 8 critical findings (CR-01..CR-08) in `43-REVIEW.md` were verified FIXED on 2026-06-14, and
phases 45/46 resolved most warnings (replay ordering, BFS folder-key resolution, atomic 0600 +
parent-dir fsync, mkdir rollback, conflict entry-id threading, empty-name guard, `Default` removed).
Re-verified 2026-06-18 — these remain **open**:

- **WR-06 (high)** — Each `UploadFile` journal entry embeds the **entire file ciphertext as base64
  inside the JSON document**. A 2 GB file → ~2.7 GB allocation in `serde_json::to_vec`, then a
  multi-GB write + `F_FULLFSYNC` executed **on the single FUSE callback thread** (macOS) / while
  holding the global WinFsp mutex (Windows) — blocking the whole filesystem for the duration and
  capable of OOM. There is no size cap, no GC of parked `Failed` entries, and entries from other
  vaults persist forever after account switch (the journal dir is shared, only ever filtered).
  (`crates/sdk/src/queue.rs:36`)
- **WR-07 (med)** — `replay_for_vault` awaits raw `resolve_ipns`/`fetch_content`/`upload_content`
  per entry with none of the `NETWORK_TIMEOUT` discipline used elsewhere. A hung connection stalls
  `mount_filesystem` indefinitely; many entries on a slow link delay mount by minutes.
  (`apps/desktop/src-tauri/src/fuse/mod.rs:278`)
- **IN-03 (low)** — plaintext `filename`/`name` persisted in journal JSON (new local at-rest
  disclosure of vault item names; 0600, local-only). (`crates/sdk/src/queue.rs:62`)
- **IN-04 (low)** — `sanitize_error` only scrubs `/Users/` and `/home/`; `C:\Users\…`, `/var`,
  `/tmp`, `/private` leak into tray/notification copy. (`crates/sdk/src/sync.rs:271`)
- **IN-05 (low)** — `let _ = journal.remove(...)` swallows removal errors → silent later replay /
  double-publish risk. (`crates/fuse/src/lib.rs:1494`, `:1558`; `write_ops.rs:679`)

## Fix

- **WR-06:** store ciphertext in a sidecar `<id>.bin` streamed to disk; JSON holds only path/hash.
  Cap journaled payload size. Add GC for parked entries (age/size budget) and an explicit purge on
  logout / account deletion.
- **WR-07:** wrap each entry's replay in `tokio::time::timeout(NETWORK_TIMEOUT * k, ...)` and/or run
  replay concurrently with (not before) mount.
- **IN-03/04/05:** document/encrypt journaled names; extend the path-scrub prefix list + drive-letter
  pattern; `log::warn!` on removal errors.

## Acceptance

Large-file write no longer blocks the FS thread (sidecar ciphertext); journal has a bounded
growth/GC story and a logout purge; replay cannot hang the mount.
