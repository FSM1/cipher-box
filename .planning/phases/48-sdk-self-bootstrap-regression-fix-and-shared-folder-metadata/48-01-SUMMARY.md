---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: "01"
subsystem: sdk
tags: [sdk, ipns, folder-state, regression, tdd]
dependency_graph:
  requires: []
  provides: [REQ-1-reconcile-guard]
  affects: [packages/sdk/src/client.ts]
tech_stack:
  added: []
  patterns: [sequence-number-as-version-clock, tdd-red-green]
key_files:
  created:
    - packages/sdk/src/__tests__/client-load-reconcile.test.ts
  modified:
    - packages/sdk/src/client.ts
decisions:
  - "Guard reads existing folderTree entry AFTER IPNS resolve; skips set() when existing.sequenceNumber >= result.sequenceNumber — avoids suppressing the network call itself (only suppresses the write-back)"
  - "Emits folder:loaded with existing children/sequenceNumber on the guard path so event subscribers see correct state"
  - "ensureFolderLoaded short-circuit (:422-423) and DFS per-child get (:454) kept unchanged — guard inside loadFolder makes a redundant child loadFolder safe"
metrics:
  duration: "~5min"
  completed_date: "2026-06-16"
  tasks_completed: 2
  files_changed: 2
status: checkpoint:human-verify (Task 3 pending — awaiting PRE-MERGE web-e2e dispatch)
---

# Phase 48 Plan 01: SDK self-bootstrap regression fix (REQ-1) Summary

One-liner: Sequence-guard in `loadFolder` prevents stale IPNS snapshot from clobbering a fresher in-memory `folderTree` entry; verified with TDD red-green unit tests.

## What Was Built

### Task 1: RED — client-load-reconcile.test.ts

New file `packages/sdk/src/__tests__/client-load-reconcile.test.ts` with three test cases:

- **Test A (keep-fresher):** in-memory entry at `sequenceNumber=5n` must survive an IPNS resolve returning `3n` — confirmed RED against current unconditional `set()`.
- **Test B (absent-loads):** no in-memory entry → must resolve, set, and return (no #498 regression).
- **Test C (older-overwritten):** in-memory at `2n`, resolve returns `7n` → must overwrite with the fresher snapshot.

Commit: `d68368e35`

### Task 2: GREEN — sequence guard in loadFolder

Inserted immediately after `if (!result) return null;` in `loadFolder` (`packages/sdk/src/client.ts:373`):

```typescript
const existing = this.folderTree.get(ipnsName);
if (existing && existing.sequenceNumber >= result.sequenceNumber) {
  this.emitter.emit({
    type: 'folder:loaded', folderId: ipnsName, ipnsName,
    children: existing.children, sequenceNumber: existing.sequenceNumber,
  });
  return existing;
}
```

All three reconcile cases pass GREEN. `ensure-folder-loaded.test.ts` (7 tests) remains green — no #498 regression.

Verification:

- `grep -n "existing.sequenceNumber >= result.sequenceNumber" packages/sdk/src/client.ts` returns exactly one match (line 378).

Commit: `bcb4fc03d`

## TDD Gate Compliance

- RED gate: `test(48-01)` commit `d68368e35` — Test A failing confirmed the bug.
- GREEN gate: `feat(48-01)` commit `bcb4fc03d` — all 3 cases pass.

## Deviations from Plan

None — plan executed exactly as written.

## Task 3: PENDING — PRE-MERGE web-e2e dispatch gate

Task 3 is a `checkpoint:human-verify` (`gate="blocking-human"`). The orchestrator must:

1. Push the feature branch.
2. Dispatch `gh workflow run web-e2e.yml --ref <fix-branch>` (MEMORY: prefix with `env -u GITHUB_TOKEN`).
3. Confirm `bin-restore-after-reload.spec.ts` and `full-workflow.spec.ts:6.6.2` are green.

REQ-1 acceptance is the PRE-MERGE web-e2e run, not the post-merge `ci-e2e.yml` main-push run (the gap #498 missed).

## Known Stubs

None.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

- `packages/sdk/src/__tests__/client-load-reconcile.test.ts` — FOUND
- `packages/sdk/src/client.ts` guard line 378 — FOUND (grep confirmed)
- Commit `d68368e35` (RED) — FOUND
- Commit `bcb4fc03d` (GREEN) — FOUND
