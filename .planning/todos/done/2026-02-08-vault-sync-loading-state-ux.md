---
created: 2026-02-08T21:20
title: Show loading state while vault syncs on login
area: ui
files:
  - apps/web/src/pages/FilesPage.tsx
  - apps/web/src/stores/vault.store.ts
---

## Problem

When a user logs in to an existing vault, they see an empty directory with only a small "Sync" spinner in the toolbar while IPNS resolves and metadata loads. This takes 10-30 seconds depending on delegated routing latency. The user may think their files are gone.

The empty directory placeholder ("// EMPTY DIRECTORY — drag files here or use --upload") is misleading during initial sync because it implies there are no files, when in reality they just haven't loaded yet.

Discovered during e2e persistence testing on 2026-02-08.

## Solution

Replace the empty directory view with an explicit loading/syncing state when the vault is still performing its initial sync:

1. Track `initialSyncComplete` in the vault store (false until first IPNS resolve + metadata fetch completes)
2. While `initialSyncComplete === false`, show a distinct loading UI instead of the empty directory placeholder — e.g. "Syncing vault..." with a terminal-style animation consistent with the app's aesthetic
3. Once sync completes, if the vault is truly empty show the normal empty state; if files exist, show the file list
4. If sync fails (IPNS not found, network error), show an error state with retry option rather than silently showing empty

**Considerations:**

- The "Synced" status indicator in the toolbar is too subtle — users don't notice it
- Should distinguish between "never synced yet" and "synced but empty vault" states
- For returning users, could optimistically show a skeleton/shimmer of the last-known file count while syncing
