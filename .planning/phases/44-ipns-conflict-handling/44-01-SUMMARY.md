---
phase: 44-ipns-conflict-handling
plan: "01"
subsystem: sdk-core
tags:
  - conflict-handling
  - three-way-merge
  - error-class
  - tdd
dependency_graph:
  requires: []
  provides:
    - ConflictError class with ipnsName/attempts/lastRemoteSeq
    - isConflictExhausted type-guard
    - mergeChildren pure three-way merge function
  affects:
    - packages/sdk-core (barrel exports extended)
tech_stack:
  added: []
  patterns:
    - TDD RED/GREEN with vitest
    - Pure function pattern (no async, no side effects, immutable inputs)
    - Typed error class extending Error (BinNotLoadedError analog)
key_files:
  created:
    - packages/sdk-core/src/errors.ts
    - packages/sdk-core/src/folder/merge.ts
    - packages/sdk-core/src/__tests__/folder-merge.test.ts
  modified:
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/index.ts
decisions:
  - "Wrote both RED test blocks (ConflictError + mergeChildren) in a single commit to satisfy ESLint no-unused-vars (fixture factories used by both describe blocks)"
  - "Pre-existing test failures in download/folder/ipns/upload/vault test files are due to missing @cipherbox/crypto package build artifact - unrelated to this plan, logged as deferred"
metrics:
  duration: "6m 33s"
  completed: "2026-06-13"
  tasks_completed: 2
  files_created: 3
  files_modified: 2
---

# Phase 44 Plan 01: ConflictError and mergeChildren Summary

Pure building blocks for the IPNS lost-update fix: typed `ConflictError` and three-way folder merge function, both tested with a permutation matrix.

## What Was Built

### Task 1: ConflictError + isConflictExhausted

`packages/sdk-core/src/errors.ts` exports:

- `class ConflictError extends Error` with `readonly ipnsName: string`, `readonly attempts: number`, `readonly lastRemoteSeq: bigint`
- Constructor calls `super(...)` with a message containing only ipnsName, attempts, and remote seq (no plaintext child data — T-44-01 mitigated)
- `this.name = 'ConflictError'` set explicitly for `instanceof`-safe pattern matching
- `function isConflictExhausted(error: unknown): error is ConflictError` type-guard

Both re-exported from `packages/sdk-core/src/index.ts`.

### Task 2: mergeChildren three-way merge

`packages/sdk-core/src/folder/merge.ts` exports:

- `function mergeChildren(base, local, remote): FolderChild[]`
- Keyed by `child.id` (UUID, stable identity — never by name or ipnsName)
- Implements all D-01 branches: local-add, remote-add, added-by-both, local-delete-dropped, edit-beats-delete, remote-delete-local-wins, modified-in-both
- Implements D-02 union fallback (empty base = no deletions detectable, union of both sides)
- Treats undefined `modifiedAt` as 0 (T-44-03 DoS mitigated — function is total, never throws on malformed input)
- Does not mutate input arrays
- Re-exported from `packages/sdk-core/src/folder/index.ts` and `packages/sdk-core/src/index.ts`

### Tests

`packages/sdk-core/src/__tests__/folder-merge.test.ts` contains 18 passing tests:

- 7 ConflictError tests (field carriage, message content, type-guard branches)
- 11 mergeChildren tests (all D-01 permutations, D-02 union fallback, missing-modifiedAt, no-mutation)

## TDD Gate Compliance

RED gate commit: `c34c8e604` — `test(44-01): add failing tests for ConflictError and mergeChildren`

GREEN gate commit: `3219aae61` — `feat(44-01): implement ConflictError, isConflictExhausted, and mergeChildren`

Both gates present in order.

## Deviations from Plan

### Adjusted TDD Strategy

Both RED test blocks (ConflictError and mergeChildren) were written in a single commit rather than two separate RED commits. ESLint's `no-unused-vars` rule would have rejected a test file with only ConflictError tests since the fixture factories `makeFolder`/`makeFile` (needed for mergeChildren tests) would be flagged as unused.

Fix: wrote the full test matrix for both tasks in the single RED commit, matching the "one test file for this plan" instruction in the task spec.

Files modified: `packages/sdk-core/src/__tests__/folder-merge.test.ts`

### Known Pre-existing Test Failures (out of scope)

5 test files in `packages/sdk-core` fail with `"Failed to resolve entry for package '@cipherbox/crypto'"` — the package's built artifacts are absent in the worktree. These failures existed before this plan and are unrelated to the changes made here. Logged to deferred-items.

Affected files (not modified by this plan): `download.test.ts`, `folder.test.ts`, `ipns.test.ts`, `upload.test.ts`, `vault.test.ts`

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Threat mitigations from plan applied:

| Threat | Status |
| --- | --- |
| T-44-01: ConflictError message leaks child data | Mitigated — message contains only ipnsName + attempts + lastRemoteSeq; asserted by test |
| T-44-02: mergeChildren silently drops children | Mitigated — permutation matrix proves all survival branches (edit-beats-delete, union fallback, both-add) |
| T-44-03: mergeChildren throws on malformed input | Mitigated — undefined modifiedAt defaults to 0, function is total |

## Self-Check: PASSED

All created files verified on disk. Both commits (RED + GREEN) verified in git log.
