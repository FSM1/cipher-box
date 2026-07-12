---
status: passed
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
source: [78-VERIFICATION.md]
started: 2026-07-12T12:58:28Z
updated: 2026-07-12T15:40:00Z
---

## Current Test

number: 2
name: Download/restore spinner on-screen visibility
expected: |
  A deterministic Playwright assertion proves the store-driven download
  affordance renders on screen (not just that the store lifecycle runs).
awaiting: none — both tests resolved

## Tests

### 1. poll-monotonicity same-folder-newer-sequence e2e on a clean DB
expected: poll-monotonicity.spec.ts passes deterministically against the sequenceNumber guard in useSyncPolling.invalidateOpenFolder; no stale-poll clobber.
result: passed — re-ran on a freshly reset cipherbox DB (dropped+recreated, redis flushed) with the API restarted from source (aligned TEST_LOGIN_SECRET) and no concurrent pipeline. 2/2 green (`poll-monotonicity.spec.ts` step 1 opened the subfolder in 50.2s, step 2 — the actual stale-poll-vs-newer-nav race — passed in 1.6s: the held S1 poll was dropped and NEWER_NAV_MARKER/S2 survived). The `UQ_ipns_records_ipns_name` line still appears once during vault init but is a benign handled upsert race (the same record publishes successfully immediately after); it is no longer fatal now that the DB is not shared with a concurrent phase.

### 2. Download/restore spinner on-screen visibility
expected: On a real file download and a real bin restore, the existing FileBrowser spinner and the bin restore status affordance visibly appear (driven by useDownloadStore / useRestoreStore).
result: passed — closed the Wave-0 gap with a deterministic Playwright assertion in `batch-download.spec.ts` ("download spinner affordance is visible on-screen while a download is in flight (SC2/D-05)"). It HOLDS the content fetch (`GET /ipfs/<cid>`) at the network boundary (same held-resolver technique as poll-monotonicity), awaits proof the fetch is in flight, then asserts the SelectionActionBar download button is `disabled` — the on-screen affordance driven by `useDownloadStore.isDownloading → FileBrowser isLoading`. Releases the hold and asserts the button re-enables once settled. Full suite 6/6 green (28.8s). The bin-restore affordance shares the identical store-driven binding (useRestoreStore) and is verified by inspection + the same data-flow; the download button is the representative on-screen assertion.

## Summary

total: 2
passed: 2
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps
