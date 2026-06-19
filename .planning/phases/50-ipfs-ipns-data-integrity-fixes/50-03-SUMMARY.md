---
phase: 50-ipfs-ipns-data-integrity-fixes
plan: "03"
subsystem: sdk
tags: [ipns, unenroll, on-demand-traversal, tdd, async, d-03]
dependency_graph:
  requires: []
  provides: [collectSubtreeIpnsNamesAsync]
  affects: [deleteItem, permanentDelete, emptyBin, purgeExpired]
tech_stack:
  added: []
  patterns: [on-demand-fetch-and-decrypt, fire-and-forget-async-resolution, per-child-failure-isolation]
key_files:
  created:
    - packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts
  modified:
    - packages/sdk/src/client.ts
decisions:
  - "New async method alongside sync removal: add collectSubtreeIpnsNamesAsync, delete collectSubtreeIpnsNames"
  - "Callers resolve async promise then dispatch: .then(names => fireAndForgetUnenroll(names)) pattern at all 4 sites"
  - "null from loadFolderMetadata is not an error — IPNS record not yet published; skip children silently"
  - "folderTree reads only in collectSubtreeIpnsNamesAsync — zero writes to avoid Zustand/SDK desync"
metrics:
  duration: 10min
  completed: "2026-06-19"
  tasks: 2
  files: 2
---

# Phase 50 Plan 03: D-03 On-Demand Subtree IPNS Collection Summary

One-liner: Async on-demand subtree IPNS collection via `sdkCore.loadFolderMetadata` closes the nested-IPNS-unenroll leak when deleting folders with unloaded subtrees.

## What Was Built

Converted `collectSubtreeIpnsNames` (sync, skips unloaded subtrees) to `collectSubtreeIpnsNamesAsync` (async, fetches persisted child folder metadata on demand from IPNS). This closes HARD-01: deleting a folder whose subtree was never expanded in the current session now unenrolls every descendant IPNS name, not just loaded ones.

## TDD Gate Compliance

### RED — `test(50-03)` commit: `b3984d2e5`

File: `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts`

- Test A: asserts full subtree IPNS names collected when subfolder is NOT in folderTree
- Test B: asserts per-child fetch failure does not abort sibling collection
- Test C: asserts on-demand traversal does not mutate folderTree

All 3 tests FAILED against the sync production code (RED). Tests A and B failed with `expected [...] to include 'k51subfile'` — the sync early-return omitted descendant names.

### GREEN — `fix(50-03)` commit: `e1b4f1a29`

All 3 D-03 tests PASS. Full SDK suite: 238 tests pass, 3 pre-existing integration test failures (live API required, skipped in CI per project memory).

### REFACTOR

No refactor step needed — implementation was clean.

## Commits

| Step   | Hash        | Message |
| ------ | ----------- | ------- |
| RED    | `b3984d2e5` | `test(50-03): add failing regression for unloaded-subtree IPNS collection (D-03)` |
| GREEN  | `e1b4f1a29` | `fix(50-03): collect subtree IPNS names via on-demand fetch+decrypt for unloaded folders` |

## Key Changes in `packages/sdk/src/client.ts`

### Added: `collectSubtreeIpnsNamesAsync`

```
private async collectSubtreeIpnsNamesAsync(
  folderIpnsName: string,
  folderKey: Uint8Array,
  acc: string[] = []
): Promise<string[]>
```

- Pushes `folderIpnsName` to `acc` immediately
- Reads children from `this.folderTree.get()` (in-memory first)
- On miss: calls `sdkCore.loadFolderMetadata({ ipnsName, folderKey, ctx })` to fetch + decrypt from IPNS
- `null` return (IPNS record not published): returns acc without recursing
- Fetch throws: logs warning (no key material) and returns acc
- For each file child: pushes `fileMetaIpnsName`
- For each folder child: independent try/catch — unwraps `folderKeyEncrypted` via `unwrapKey(hexToBytes(...), vaultPrivateKey)` and recurses; on failure pushes child's `ipnsName` and continues siblings
- NEVER writes to `this.folderTree`

### Modified: `collectRemovedItemIpnsNames` (now async)

For folder items: unwraps `entry.folderKeyEncrypted` then calls `collectSubtreeIpnsNamesAsync`. Returns `Promise<string[]>`.

### Modified: `collectBinEntryIpnsNames` (now async)

For folder entries: unwraps `folderEntry.folderKeyEncrypted` then calls `collectSubtreeIpnsNamesAsync`. Returns `Promise<string[]>`.

### Removed: `collectSubtreeIpnsNames` (sync)

Replaced entirely by `collectSubtreeIpnsNamesAsync` — no two code paths.

### Updated: 4 deletion call sites

All resolve the async collection promise before dispatching `fireAndForgetUnenroll`:

- `deleteItem` (~line 856): `.then(names => this.fireAndForgetUnenroll(names))`
- `permanentDelete` (~line 1950): same pattern
- `emptyBin` (~line 1963): `Promise.all(entries.map(...)).then(nameArrays => fireAndForgetUnenroll(nameArrays.flat()))`
- `purgeExpired` (~line 2012): same Promise.all pattern

## Verification

```
grep -n "collectSubtreeIpnsNamesAsync\|loadFolderMetadata" packages/sdk/src/client.ts
# Shows async collector calling on-demand fetch — VERIFIED

grep -n "this\.folderTree" packages/sdk/src/client.ts (within new method body)
# Shows only .get() reads, no assignments — VERIFIED
```

## Deviations from Plan

None — plan executed exactly as written. The test infrastructure approach (copying test file to main repo for running, then removing) was needed because pnpm vitest can't resolve workspace packages from the worktree path; tests run correctly from main repo's SDK directory.

## Threat Surface Scan

No new network endpoints or auth paths introduced. The on-demand fetch uses the existing `sdkCore.loadFolderMetadata` path (same IPNS resolution + AES-256-GCM decrypt used by `ensureFolderLoaded`). No new trust boundaries.

Threat register items T-50-05, T-50-06, T-50-07, T-50-08 all mitigated by this implementation:
- T-50-05: On-demand fetch collects ALL descendant IPNS names for TEE unenrollment
- T-50-06: Per-child failure caught independently; one bad node cannot abort the whole batch
- T-50-07: Traversal keeps no state in `folderTree` — prevents Zustand/SDK desync
- T-50-08: Uses `unwrapKey` from `@cipherbox/crypto` (ECIES) — no hand-rolled crypto

## Self-Check: PASSED

- [x] `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` — FOUND
- [x] `packages/sdk/src/client.ts` contains `collectSubtreeIpnsNamesAsync` — FOUND
- [x] RED commit `b3984d2e5` — FOUND in git log
- [x] GREEN commit `e1b4f1a29` — FOUND in git log
- [x] 3 D-03 tests GREEN, 238 total tests pass, 0 regressions
- [x] TypeCheck (tsc --noEmit) passes cleanly
