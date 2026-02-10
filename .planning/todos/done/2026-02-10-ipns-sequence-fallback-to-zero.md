---
created: 2026-02-10T12:00
title: Fix IPNS sequence number fallback to 0 on resolve failure
area: desktop
files:
  - apps/desktop/src-tauri/src/fuse/operations.rs:1141-1147
---

## Problem

When IPNS resolve fails in the desktop client FUSE layer, the sequence number falls back to 0. Publishing with seq=1 when the actual current sequence is seq=100 could cause metadata rollback to a stale state. Concurrent publishes can also race on the same sequence number.

Despite being categorized as LOW severity in the security review, this has HIGH data integrity impact — it can cause silent data loss through overwrites and metadata rollback.

Identified by Phase 9 Desktop Security Review (REVIEW-2026-02-08-phase9-desktop.md, L-6). Also tracked in LOW-SEVERITY-BACKLOG.md item 18.

## Solution

1. Cache last-known sequence number locally per IPNS name (monotonic counter)
2. Never allow sequence to go below the last-known value
3. Return error if unable to resolve current sequence and no cached value exists
4. Serialize publishes with per-folder mutex to prevent concurrent publish races
