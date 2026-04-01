# Plan 38-01 Summary: Migrate folder.service callers to SDK imports

## Status: COMPLETE

## Changes Made

Migrated all callers of `folder.service.ts` to `@cipherbox/sdk` / `@cipherbox/sdk-core` imports. Extracted `addFileToFolder`, `addFilesToFolder`, `replaceFileInFolder` into `@cipherbox/sdk-core`. Web hooks now import SDK functions directly and pass store-extracted state as explicit params, following the established pattern from `useSharedWriteOps.ts`.

## Delivered In

PR #422 — merged 2026-03-31
