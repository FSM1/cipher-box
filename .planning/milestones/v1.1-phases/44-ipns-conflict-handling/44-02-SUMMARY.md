---
phase: 44-ipns-conflict-handling
plan: "02"
subsystem: sdk-core
tags:
  - conflict-handling
  - retry-loop
  - merge-and-republish
  - ipns-409
dependency_graph:
  requires:
    - ConflictError class (44-01)
    - mergeChildren pure function (44-01)
  provides:
    - 4-attempt merge-and-republish retry loop in updateFolderMetadataAndPublish
    - baseChildren optional param for three-way merge
    - union-fallback warning path
  affects:
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
tech_stack:
  added: []
  patterns:
    - Exponential backoff with jitter (BACKOFF_BASE_MS=100, BACKOFF_CAP_MS=1500)
    - vi.hoisted() for mock references in vitest factories
    - mockFns pattern (shared vi.fn() handles across vi.mock factories)
key_files:
  created: []
  modified:
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
decisions:
  - "Used vi.hoisted() to define mockFns so mock factory references are available when vi.mock() factories are hoisted — avoids ReferenceError on temporal dead zone"
  - "Built @cipherbox/crypto and @cipherbox/core dist artifacts to unblock vitest (they were absent in worktree, causing all folder.test.ts runs to fail — same pre-existing issue as Plan 01)"
  - "Kept mergeChildren import as a named import and re-export rather than re-export-only, so the merge function is available inside updateFolderMetadataAndPublish"
metrics:
  duration: "4m 48s"
  completed: "2026-06-13"
  tasks_completed: 2
  files_created: 0
  files_modified: 2
---

# Phase 44 Plan 02: Merge-and-Republish Retry Loop Summary

4-attempt merge-and-republish loop in updateFolderMetadataAndPublish with three-way merge on 409, exponential backoff+jitter, and ConflictError exhaustion — folder half of the IPNS lost-update fix.

## What Was Built

### Task 1: Merge-and-republish retry loop

`packages/sdk-core/src/folder/index.ts` modified:

- Added `baseChildren?: FolderChild[]` optional param to `updateFolderMetadataAndPublish` (backward compatible — 18 existing callers unaffected)
- Moved encrypt+upload (`encryptFolderMetadata` + `addToIpfs`) INSIDE the loop: each attempt gets a fresh CID (D-03 — never republish a stale CID)
- Loop runs `attempt = 0..3` (4 attempts total, D-04)
- On 409:
  - Re-resolves seq authoritatively via `resolveIpnsRecord` (ignores any seq hint from error body — Pitfall 1+2)
  - Re-fetches + decrypts remote via `fetchAndDecryptMetadata` (same-file, no new import)
  - If `baseChildren` provided: `mergeChildren(baseChildren, currentLocal, remote)` (D-01 three-way)
  - If `baseChildren` absent: `mergeChildren([], currentLocal, remote)` + `console.warn(...)` (D-02 union fallback)
  - On attempt 3: throws `new ConflictError(ipnsName, 4, lastRemoteSeq)` (D-05)
  - Otherwise: awaits `retryDelayMs(attempt)` ms backoff
- Added module constants `BACKOFF_BASE_MS = 100`, `BACKOFF_CAP_MS = 1500` (marked `[ASSUMED]`)
- Added `retryDelayMs(attempt: number): number` helper
- Unreachable fallback after loop also throws `ConflictError` (removed old generic `throw new Error('Publish failed after retry')`)

### Task 2: Conflict handling unit tests

`packages/sdk-core/src/__tests__/folder.test.ts` extended with `describe('updateFolderMetadataAndPublish conflict handling')`:

- "merges remote children on 409 then republishes": asserts second `encryptFolderMetadata` call includes both `local-1` and `remote-1` children — proves no lost update
- "logs union-fallback warning when baseChildren omitted": spies on `console.warn`, asserts it fires with `'baseChildren not provided'`
- "throws ConflictError after 4 failed attempts": asserts `isConflictExhausted(err) === true`, `err.attempts === 4`, `err.ipnsName === 'k51exhaust'`
- "does not throw ConflictError for non-409 errors": asserts a 500 error propagates unchanged

All 14 tests pass (10 original pure-function tests + 4 new conflict tests).

## Deviations from Plan

### Deviation 1: vi.hoisted() required for mock factory references

Using `const mockFns = { ... }` at module scope and referencing it inside `vi.mock()` factories caused a `ReferenceError: Cannot access 'mockFns' before initialization`. The `vi.mock()` calls are hoisted to the top of the file before variable initialization.

Fix: used `const mockFns = vi.hoisted(() => ({ ... }))` so the object is initialized before the hoisted factories execute.

Files modified: `packages/sdk-core/src/__tests__/folder.test.ts`

### Deviation 2: Build @cipherbox/crypto and @cipherbox/core to unblock tests

The worktree had no `dist/` for either package, causing Vite to fail resolving `@cipherbox/crypto` and `@cipherbox/core` even with `vi.mock` factories. This was the same pre-existing issue documented in Plan 01 SUMMARY.

Fix: ran `pnpm --filter @cipherbox/crypto build` and `pnpm --filter @cipherbox/core build`. Both built successfully. Tests then ran and passed.

Note: `dist/` directories are build artifacts — they are not committed. FINAL CLEANUP removes them per instructions.

### Deviation 3: mergeChildren imported as named import for internal use

The original `folder/index.ts` used `export { mergeChildren } from './merge'` (re-export only). Since the merge loop inside `updateFolderMetadataAndPublish` needs to CALL `mergeChildren`, a named import was added alongside the re-export:

```typescript
import { mergeChildren } from './merge';
export { mergeChildren };
```

This is semantically equivalent and ESLint accepted it.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Threat mitigations from plan applied:

| Threat | Status |
| --- | --- |
| T-44-04: stale CID republished on 409 | Mitigated — encrypt+upload inside loop, fresh CID every attempt; unit test proves remote-only child survives |
| T-44-05: unbounded retry livelock | Mitigated — hard cap of 4 attempts with exponential backoff + jitter de-correlates concurrent writers |
| T-44-07: merged children plaintext to IPFS | Mitigated — merged children re-encrypted with params.folderKey via encryptFolderMetadata before upload |
| T-44-08: ConflictError leaks child data | Mitigated — error carries only ipnsName + attempts + lastRemoteSeq (Plan 01 guarantee) |

## Self-Check: PASSED

All modified files verified on disk. Both commits verified in git log.

- `b433553b6` feat 44-02: merge-and-republish 4-attempt retry loop in updateFolderMetadataAndPublish
- `0b826ca65` test 44-02: add conflict handling tests for updateFolderMetadataAndPublish
