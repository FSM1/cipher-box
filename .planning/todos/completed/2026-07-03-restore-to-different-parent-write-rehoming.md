---
created: 2026-07-03T00:00:00Z
title: Restore-to-different-parent must re-home the WriteChildRef
area: sdk
files:
  - packages/sdk/src/client.ts:3273
  - packages/sdk/src/client.ts:1669
source: 68.1-VERIFICATION.md follow-ups (same defect class as 68.1-31 move fix)
---

## Problem

Phase 68.1-31 fixed `moveItem` to re-home the write link on cross-folder moves
(unseal `WriteChildRef` under the source folder's writeKey → drop from source →
reseal under the destination writeKey, keyed by the child node UUID with the dest
entry's generation). `restoreFromBin` (`client.ts:3273`) has the same latent defect
when restoring to a parent different from the original: the WriteChildRef is not
re-homed, so a restored file would be read-only in its new parent ("not
write-capable (no WriteChildRef)"). Not currently a shipped flow (web UI restores
to the original parent only), so it was documented rather than fixed in 68.1.

## Solution

Before shipping any restore-to-chosen-folder UX, apply the 68.1-31 re-homing
pattern to the restore path: reseal the WriteChildRef under the target folder's
writeKey (dest-before-source publish ordering), keyed by node UUID + dest
generation. Add a regression spec mirroring `move-restore-content` test 2b for the
restore direction.
