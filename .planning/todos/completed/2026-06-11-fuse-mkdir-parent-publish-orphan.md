---
created: 2026-06-11
title: FUSE mkdir orphans the new folder when parent publish conflicts
area: desktop-fuse
severity: high
files:
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/write_ops.rs
---

## Problem

In `handle_mkdir` the child folder's IPNS record publishes first (seq 0), then the
parent folder metadata CAS-publishes. On a parent-publish conflict the code only
warns, claiming "debounced publish will retry" — but `handle_mkdir` never calls
`queue_publish` / adds the parent to `mutated_folders` (`write_ops.rs:601-610`), so
nothing actually retries. This is the existing TODO at
`crates/fuse/src/platform/windows/write_ops.rs:194` (agent reports an identical
macOS path around `write_ops.rs:584`).

Consequence: the child IPNS record exists remotely as an orphan, but its IPNS
private key and folder key live only in the parent metadata that was never
published. After restart the new folder is irrecoverable. A crash before the
spawned thread runs loses the directory entirely.

Severity: data loss / orphaned remote state.

## Solution

TBD — key considerations:

- On parent-publish conflict, actually enqueue the parent for retry
  (`queue_publish` / `mutated_folders`) instead of only logging.
- Make mkdir atomic or replayable so the child is never published without its
  parent reference committing — ties into the FUSE persisted-journal gap
  (`2026-06-11-fuse-release-data-loss-before-remote-commit.md`).
- Verify the macOS path line number by grep before fixing; confirm both platforms.
