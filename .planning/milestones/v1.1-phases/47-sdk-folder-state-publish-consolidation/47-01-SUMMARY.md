---
phase: 47-sdk-folder-state-publish-consolidation
plan: "01"
subsystem: sdk-core
tags: [sdk-core, cas, ipns, refactor, tdd]
dependency_graph:
  requires: []
  provides: [publishWithCas, REQ-2-cas-unification, REQ-3-sdk-core-base-snapshot]
  affects:
    - packages/sdk-core/src/cas.ts
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/file/index.ts
tech_stack:
  added: []
  patterns: [generic-cas-retry-helper, sequence-number-as-version-clock, tdd-red-green, key-zeroing-in-caller-finally]
key_files:
  created:
    - packages/sdk-core/src/__tests__/cas.test.ts
  modified:
    - packages/sdk-core/src/cas.ts
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/file/index.ts
    - packages/sdk-core/src/index.ts
decisions:
  - "One publishWithCas<TData> engine owns the resolve to encrypt to upload to CAS to 409 to merge to retry skeleton for both file and folder paths (D-1)"
  - "Both paths reconciled UP to maxAttempts 4 + backoff (file path was accidentally 2 attempts / no backoff before) — locked decision 1"
  - "publishWithCas NEVER zeroes key material; fileIpnsPrivateKey.fill(0) stays in updateFileMetadata's finally on all exit paths (T-47-01)"
  - "Dropped the concurrent pre-resolve+upload optimization from updateFileMetadata — it depended on the hand-unrolled loop structure"
  - "baseChildren snapshot ceremony encapsulated inside updateFolderMetadataAndPublish; union-fallback warn preserved when baseChildren omitted (REQ-3 sdk-core half)"
  - "Public signatures of updateFolderMetadataAndPublish and updateFileMetadata unchanged — mock surface preserved, existing suites stay green"
metrics:
  duration: "backfilled"
  completed_date: "2026-06-15"
  tasks_completed: 2
  files_changed: 5
status: complete (backfilled 2026-06-17 — plan shipped via PR #494, summary reconstructed retroactively)
---

# Phase 47 Plan 01: publishWithCas unification in sdk-core Summary

One-liner: A single generic `publishWithCas<TData>` helper in sdk-core now owns the 409-CAS-retry skeleton for both the file and folder publish paths, with key zeroing left to the callers and the folder base-snapshot ceremony encapsulated.

## What Was Built

### Task 1: publishWithCas generic helper (TDD)

- New `packages/sdk-core/src/cas.ts` exports `publishWithCas<TData>` (verified at `cas.ts:38`), implementing the resolve to encrypt to upload to CAS to 409 to merge to retry loop generically over `TData`.
- `retryDelayMs` plus `BACKOFF_BASE_MS`/`BACKOFF_CAP_MS` relocated from `folder/index.ts` into `cas.ts` as module-private symbols (`cas.ts:17-22`).
- Re-exported from `packages/sdk-core/src/index.ts:5`.
- New `packages/sdk-core/src/__tests__/cas.test.ts` covers the six behaviors: success-first-attempt, 409 merge retry, ConflictError exhaustion (attempts === 4), prunedCids passthrough (deduped union), non-409 immediate rethrow, and the backoff toggle.
- Security invariant documented in the file header: publishWithCas never zeroes key material — callers own that lifecycle.

### Task 2: Delegate folder + file paths

- `updateFolderMetadataAndPublish` (`folder/index.ts:205`) is now a thin wrapper over `publishWithCas<FolderChild[]>` with maxAttempts 4 + backoff; it captures the base snapshot internally and maps `publishedData` to `publishedChildren`. Public signature unchanged.
- `updateFileMetadata` (`file/index.ts:288`) delegates to `publishWithCas<FileMetadata>` with maxAttempts 4 + backoff (unified up from the accidental 2/no-backoff). The CR-02 prunedCids reference-filter is preserved through the merge callback.
- `fileIpnsPrivateKey.fill(0)` remains in the `finally` block (`file/index.ts:369-370`) on all exit paths — success, conflict-exhausted throw, and non-409 throw. The concurrent pre-resolve+upload optimization was dropped per locked decision 1.

## Verification

Shipped and merged via PR #494 (commit d17d42e5f). Phase 47 VERIFICATION.md (score 5/5, status human_needed) covers goal achievement. This summary was backfilled on 2026-06-17 to close a bookkeeping gap (plans had no matching summaries on disk).
