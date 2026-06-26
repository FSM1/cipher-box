# Plan 38-02 Summary: Migrate bin.service callers to SDK client

## Status: COMPLETE

## Changes Made

Migrated all callers of `bin.service.ts` to `@cipherbox/sdk` client methods. Added `purgeExpired()` method to `CipherBoxClient` and `purgeExpiredEntries()` function in `packages/sdk/src/bin/index.ts`. Improved bin load/purge flows and store synchronization to reduce stale recycle-bin state.

## Delivered In

PR #422 — merged 2026-03-31
