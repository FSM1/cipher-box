---
created: 2026-07-09T00:33:19.530Z
title: macOS FUSE-T read-side sync invalidation gap soft-skips cross-client Tests 5 & 7
area: desktop-fuse
severity: medium
source: Phase 70.1 D-16 desktop-e2e work; flagged 2026-07-09
files:
  - tests/desktop-e2e/scripts/test-cross-client-sync.sh
  - tests/desktop-e2e/scripts/test-cross-client-sync.ps1
  - crates/fuse/src
---

## Problem

Two desktop-e2e cross-client-sync legs are permanently soft-skipped on macOS:

- **Test 5** — content sync: the FUSE mount must pick up a remote SDK edit
  (`test-cross-client-sync.sh` ~lines 168-215).
- **Test 7** — folder rename sync: the mount must pick up a remote folder
  rename (`test-cross-client-sync.sh` ~lines 262-301).

On macOS both time out and `pass` with an "optional on macOS -- timed out"
warning instead of hard-asserting. Root cause (verified experimentally, #560
stopgap): our code re-resolves the FilePointer/folder IPNS record correctly in
~5s, but **FUSE-T's SMB client cache serves STALE content/attributes because
FUSE-T ignores the `inval_inode` reverse-notification**. So the reader never
sees the re-resolved change within the poll budget.

This is a READ / cache-invalidation-side limitation and is DISTINCT from the
Phase 70.1 write-side publish-queue-drain pump (commit 313ebf178), which drives
the local publish queue on an idle mount and does NOT touch the SMB read cache
for an already-cached file — it does not fix these two tests.

The soft-skip masks real macOS cross-client sync latency and, because the legs
pass-with-warning, they cannot catch a regression in that path.

## Solution

Find a working FUSE-T notification/invalidation path (or shorten the SMB client
cache TTL) so a re-resolved remote change is actually served to the reader
within a few seconds. Then flip Test 5 and Test 7 from soft-skip
(pass-with-warning) to hard assertions on macOS. Investigate whether FUSE-T
exposes any honored invalidation primitive (vs the ignored `inval_inode`), or
whether the SMB attribute/content cache TTL can be tuned at mount time
(`MountOption::CUSTOM`). TBD which lever is viable — spike first.

## Acceptance

On macOS: a remote SDK content edit (Test 5) and a remote folder rename
(Test 7) are visible through the FUSE mount within the normal poll budget, and
both tests hard-assert (no "optional on macOS -- timed out" skip). Linux/Windows
behavior unchanged.
