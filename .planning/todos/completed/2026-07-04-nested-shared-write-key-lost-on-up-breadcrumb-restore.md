---
created: 2026-07-04T00:00:00Z
title: Nested write-share loses write capability on navigate-up / breadcrumb restore
area: web
files:
  - apps/web/src/hooks/useSharedNavigationActions.ts:565
  - apps/web/src/hooks/useSharedNavigationActions.ts:660
source: PR #588 Greptile re-review (P-level, valid — deferred with PR note)
---

## Problem

In a nested write-share, navigating root → A → B and then going UP to A (or
clicking A's breadcrumb) restores A with NO write key. `navigateUp`
(useSharedNavigationActions.ts:565-571) only re-derives the writeKey when
`isRootDepth` (`parent.ipnsName === share.ipnsName`); for a deeper subfolder it
passes `writeKey: null → undefined` to `seedActiveSharedFolder`, so the restored
level keeps the zero-buffer writeKey default. `navigateToBreadcrumb` (~:660) has
the identical gap. The folder renders, but the next rename/upload/delete from the
restored subfolder fails at write-body unseal ("not write-capable"). The code
comment documents this as an intentional current limitation.

Not data loss or a security hole (the write throws; content is untouched), and it
has a workaround (re-navigate from the share root down into the subfolder, which
re-derives each depth's writeKey via 68.1-30's `resolveSharedSubfolderWriteKey`).
The descent path is correct; only the up/breadcrumb RESTORE path is missing the
per-depth writeKey. The writable-shares e2e covers descend-then-write, not
up-navigate-then-write, so it passed while this gap exists.

## Solution

Give the restore paths the per-depth writeKey. Preferred: when descending via
`navigateToSubfolder`, store a CLONE of that depth's derived writeKey in the
navStack entry (alongside folderKey), reuse it on navigateUp/navigateToBreadcrumb
restore, and zero it when the stack entry is discarded (mirror the folderKey
zeroing at :531/:616-618 — D-09 terminal-owner discipline; seedActiveSharedFolder
already clones internally). Alternative: re-walk the write chain from the share
root down to the restored depth via `resolveSharedSubfolderWriteKey` on restore.
MUST add a writable-shares web-e2e: descend two levels, navigate up one, then
rename/upload from the restored level and assert it succeeds. Relates to
[[shared-nav-stack-stale-children-snapshot]] and
[[remove-dead-getsharekeys-folder-ipns-path]].
