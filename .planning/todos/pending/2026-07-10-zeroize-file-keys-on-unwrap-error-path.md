---
created: 2026-07-10
title: Zero file read/write keys when a later unwrap throws in updateSharedSingleFile
area: crypto
files:
  - packages/sdk/src/client.ts
---

## Problem

In `SdkClient.updateSharedSingleFile` (packages/sdk/src/client.ts ~5312-5319), both
`fileReadKey` and `fileWriteKey` are produced by `unwrapKey(...)` BEFORE the `try` block
that owns the `finally { fileReadKey?.fill(0); fileWriteKey?.fill(0); }` cleanup. If the
SECOND `unwrapKey` (fileWriteKey) throws, the already-unwrapped `fileReadKey` never reaches
the `finally` and lingers un-zeroed in the heap until GC.

Pre-existing (the try-block structure is unchanged by Phase 71; only the field name on the
adjacent `hexToBytes(args.encryptedReadKey)` line was renamed). Flagged by CodeRabbit on the
Phase 71 diff. Low severity (hygiene, not a direct exploit) — deferred to keep the Phase 71
PR scoped to the share-plane rename + security/data-integrity work.

## Solution

Initialize `fileReadKey`/`fileWriteKey` to `null` before the `try`, and move BOTH `unwrapKey`
calls inside the `try` so any failure reaches the existing `finally` cleanup:

```ts
let fileReadKey: Uint8Array | null = null;
let fileWriteKey: Uint8Array | null = null;
let currentFileNode: CoreNode | null = null;
try {
  fileReadKey = await unwrapKey(hexToBytes(args.encryptedReadKey), args.recipientPrivateKey);
  fileWriteKey = await unwrapKey(hexToBytes(args.encryptedWriteKey), args.recipientPrivateKey);
  ...
```

Validate with `packages/sdk/src/__tests__/update-shared-single-file.test.ts`.
