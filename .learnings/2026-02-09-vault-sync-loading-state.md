# Vault Sync Loading State — Stale Closure & Initial Sync Bugs

**Date:** 2026-02-09

## Original Prompt

> Show loading state while vault syncs on login — users see misleading "EMPTY DIRECTORY" for 10-30s while IPNS resolves.

## What I Learned

- **Stale closure was the root cause, not IPNS latency.** `handleSync` captured `folders` from React's render cycle via `useFolderStore()` hook. On initial load, the root folder is added to the Zustand store in a `useEffect` (from `useFolderNavigation`), but the sync callback's closure still has the pre-effect value (`{}`). So `folders['root']` was undefined and sync returned early doing nothing. Fix: use `useFolderStore.getState().folders['root']` inside async callbacks.

- **`useInterval` doesn't fire immediately.** The sync polling hook used `setInterval` which waits a full interval (30s) before the first tick. Need a separate `useEffect` to fire sync immediately on mount.

- **Backend IPNS resolve has a DB cache fallback.** `IpnsService.resolveRecord()` falls back to `folder_ipns.latestCid` when delegated routing returns 404. So `resolveIpnsRecord()` almost never returns null for existing vaults — it returns the DB-cached CID. The "IPNS not resolved" throw path is a safety net for truly new IPNS names that haven't been published yet.

- **Sequence number comparison silently succeeds on stale closure.** When `rootFolder` was undefined (stale closure), the `if (!rootFolder) return` early exit caused `doSync` to call `syncSuccess()` — marking the sync as "Synced" even though nothing was fetched. This is why users saw "Synced" status + empty directory simultaneously.

- **New vault vs returning vault distinction matters.** A brand new vault has no IPNS records at all. Need `isNewVault` flag to skip the syncing loading state for first-time users (their vault IS empty).

- **Playwright browser context persists across page close/reopen.** Closing a tab and navigating again reuses the same context (cookies, Web3Auth IndexedDB). Need explicit logout or context clearing to test clean sessions.

## What Would Have Helped

- Reading `useFolderNavigation` initialization flow first to understand when root folder enters the store
- Checking `IpnsService.resolveRecord()` backend fallback behavior earlier — assumed IPNS null meant "not propagated" when it actually meant "DB cache miss too"
- Adding `console.log` in `handleSync` from the start to trace the exact code path taken during initial sync

## Key Files

- `apps/web/src/components/file-browser/FileBrowser.tsx` — sync callback, display logic
- `apps/web/src/hooks/useSyncPolling.ts` — polling orchestration, initial sync trigger
- `apps/web/src/hooks/useFolderNavigation.ts` — root folder initialization timing
- `apps/web/src/stores/sync.store.ts` — `initialSyncComplete` tracking
- `apps/web/src/stores/vault.store.ts` — `isNewVault` flag
- `apps/api/src/ipns/ipns.service.ts:260` — DB cache fallback in `resolveRecord()`
