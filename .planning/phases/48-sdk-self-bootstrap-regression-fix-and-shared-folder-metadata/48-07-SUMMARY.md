---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: "07"
subsystem: sdk
tags: [sdk, web, shared-folder, projection, polling, ipns, consolidation]

# Dependency graph
requires:
  - phase: 48-03
    provides: SharedFolderState + adoptSharedFolderResult emit shape (sharedFolder:updated)
  - phase: 48-04
    provides: web shared-write hook + sharedFolder:updated projection subscription
provides:
  - SDK-owned shared-folder REFRESH (client.refreshSharedFolder) mirroring the owned loadFolder
  - web 30s poller routed through the SDK; inline IPNS/IPFS/decrypt resolve removed
  - sharedFolder:updated subscription is the sole projection ref writer on BOTH write and poll paths
affects: [shared-folder sync, web-e2e cross-client-sync, 48-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "SDK owns shared-folder refresh (re-resolve + sequence-guard + adopt + emit), not the consumer"
    - "Poll path feeds the same projection event as the write path; refs are write-only-by-event"

key-files:
  created: []
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/client-shared-write.test.ts
    - apps/web/src/hooks/useSharedNavigation.ts
    - apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts

key-decisions:
  - "Reused adoptSharedFolderResult + the #489 sequence-guard verbatim from loadFolder — identical emission shape so the web projection needs no change"
  - "No index.ts change: refreshSharedFolder is a method on the already-exported CipherBoxClient; no new type introduced"
  - "Task 4 fake records refreshSharedFolder via a cast (WithRefresh) rather than widening the SharedFolderClient Pick type, keeping shared-folder-projection.ts out of scope"

patterns-established:
  - "Shared-folder refresh: requireSharedFolder -> sdkCore.loadFolderMetadata -> #489 guard -> adopt or re-emit existing"
  - "Background poll never clobbers fresher in-memory state (sequence-as-clock)"

requirements-completed: [REQ-3]

# Metrics
duration: 18min
completed: 2026-06-16
---

# Phase 48 Plan 07: SDK-Owned Shared-Folder Refresh and Poller Consolidation Summary

**Added `client.refreshSharedFolder(shareId)` — a sequence-guarded IPNS re-resolve that adopts into `sharedFolderTree` and emits `sharedFolder:updated` — then routed the web 30s poller through it and deleted the hook's inline IPNS/IPFS/decrypt path so the projection subscription is the sole ref writer on both write and poll paths.**

## Performance

- **Duration:** 18 min
- **Started:** 2026-06-16T17:01:00Z
- **Completed:** 2026-06-16T17:06:00Z
- **Tasks:** 4 auto/TDD complete (Task 5 UAT deferred to web-e2e)
- **Files modified:** 4

## Accomplishments

- SDK now owns shared-folder REFRESH (background re-resolve), mirroring the owned path's `loadFolder` — not just write.
- `refreshSharedFolder` applies the #489 sequence-guard: a stale/equal IPNS resolve re-emits the existing snapshot instead of clobbering fresher in-memory state.
- The web 30s poller calls `getSdkClient().refreshSharedFolder(currentShareId)`; the inline `refreshFolderContents` (IPNS resolve + IPFS fetch + decrypt + direct ref writes) and its now-unused imports were removed.
- The `sharedFolder:updated` subscription is now the single source-of-truth ref writer on BOTH the write and poll paths — closing the 48-04 poll-then-write desync risk.

## Task Commits

Each task was committed atomically:

1. **Task 1: SDK client.refreshSharedFolder** - `c95dc9840` (feat, TDD RED+GREEN)
2. **Task 2: Export check + rebuild dist** - no commit (no-op on tracked files; `index.ts` unchanged, `dist/` is gitignored)
3. **Task 3: Route web poller through the SDK; delete inline resolve** - `20413f863` (refactor)
4. **Task 4: Web test — poll-through-SDK projection** - `cfdadbd6a` (test)

_Note: Task 1 RED and GREEN were committed together as one atomic task commit (test + impl in the same file set)._

## Files Created/Modified

- `packages/sdk/src/client.ts` - Added `async refreshSharedFolder(shareId)`: `requireSharedFolder` -> `sdkCore.loadFolderMetadata` -> #489 sequence-guard -> `adoptSharedFolderResult` (newer) or re-emit existing (stale/equal); null resolve is a no-op.
- `packages/sdk/src/__tests__/client-shared-write.test.ts` - Added an `@cipherbox/sdk-core` mock for `loadFolderMetadata` and a `refreshSharedFolder` describe block: newer adopt+emit, stale no-clobber+re-emit, null no-op, unloaded throw.
- `apps/web/src/hooks/useSharedNavigation.ts` - Poller calls `getSdkClient().refreshSharedFolder(currentShareId)`; removed `refreshFolderContents` and the `resolveIpnsRecord`/`fetchFromIpfs`/`decryptFolderMetadata`/`EncryptedFolderMetadata` imports.
- `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` - Added `refreshSharedFolder` to the fake client and a poll-path describe block proving refs update only via the subscription and mismatched-shareId events are ignored.

## Build Order

After the Task 1 SDK change, rebuilt the consumed dist BEFORE any web check:

```bash
pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build
```

Both builds succeeded. Verified `packages/sdk/dist/index.d.ts` line 1227 contains `refreshSharedFolder(shareId: string): Promise<void>;`.

## Verification Results

- `cd packages/sdk && pnpm exec vitest run client-shared-write` - 6 passed (2 existing + 4 new).
- `cd packages/sdk && pnpm exec tsc --noEmit -p tsconfig.json` - exit 0.
- `pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build` - both succeeded; `refreshSharedFolder` present in `dist/index.d.ts`.
- `grep resolveIpnsRecord apps/web/src/hooks/useSharedNavigation.ts` - empty (no inline resolve).
- `cd apps/web && pnpm exec tsc -p tsconfig.json --noEmit` - exit 0.
- `cd apps/web && pnpm exec eslint src/hooks/useSharedNavigation.ts` - exit 0.
- `pnpm --filter @cipherbox/web test useSharedWriteOps` - 9 passed (6 existing + 3 new).

## Decisions Made

- Reused `adoptSharedFolderResult` and the #489 sequence-guard verbatim from `loadFolder` so the emission shape is identical to the write path — the web projection subscription needed no changes.
- No `index.ts` change: `refreshSharedFolder` is a public method on the already-exported `CipherBoxClient`, and no new return/arg type was introduced.
- Task 4's fake client records `refreshSharedFolder` via a `WithRefresh` cast rather than widening the `SharedFolderClient` Pick type — the poller calls the full client directly, and this keeps `shared-folder-projection.ts` out of the plan's files-modified scope.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- An eslint `prettier/prettier` reformat was flagged on the poll effect's collapsed dependency array; reformatted to multi-line before the Task 3 commit (caught and fixed within the task's verify loop, not a deviation).

## Known Stubs

None.

## Threat Flags

None - no new security surface. `refreshSharedFolder` reuses the `folderKey` already cloned into `sharedFolderTree` (48-03); no new key material is unwrapped on the poll path (T-48-14 accepted).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The SDK is the single source of truth for shared-folder state on both write and poll paths.
- **Task 5 (shared-folder sync UAT) is DEFERRED to the end-of-phase web-e2e run** per execution instructions — it is a blocking human-verify UAT (recipient sees owner-side changes via the 30s poll; local writes are not regressed by polling). Not executed in this run.

## Self-Check: PASSED

All three task commits (`c95dc9840`, `20413f863`, `cfdadbd6a`) found in git history. All four modified source files and the SUMMARY exist on disk; `refreshSharedFolder` present in both `client.ts` and `useSharedNavigation.ts`.

---

_Phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata_
_Completed: 2026-06-16_
