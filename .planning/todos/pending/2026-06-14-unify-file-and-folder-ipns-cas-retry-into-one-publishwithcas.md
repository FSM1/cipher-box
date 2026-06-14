---
created: 2026-06-14T01:32:39.825Z
title: Unify file and folder IPNS CAS-retry into one publishWithCas helper
area: sdk-core
severity: low
files:
  - packages/sdk-core/src/folder/index.ts
  - packages/sdk-core/src/file/index.ts
---

## Problem

Phase 44 added two independent 409-conflict retry engines that duplicate the same
skeleton (resolve -> encrypt+upload -> CAS publish -> detect 409 -> re-resolve ->
re-fetch+decrypt remote -> domain merge -> retry/backoff -> ConflictError):

- `updateFolderMetadataAndPublish` (folder/index.ts): a 4-attempt `for` loop with
  exponential backoff + jitter, merging via `mergeChildren`.
- `updateFileMetadata` (file/index.ts): a hand-unrolled 2-attempt try/catch with
  no backoff, merging via `mergeVersions` + loser-as-version.

They have already drifted (4 vs 2 attempts; backoff vs none). A future change to
retry count, backoff, or sequence handling must be made twice and is easy to apply
to only one path.

Surfaced by `/simplify` (2026-06-14). The smaller duplications it found were already
fixed in that pass: the inline 409 predicate was deduped into `is409`, and the
file-side fetch+decode+decrypt into `fetchAndDecryptFileMetadata`. This larger
unification was deferred as out of scope for a quality-only pass.

## Solution

TBD — key considerations:

- Extract a generic `publishWithCas` in sdk-core that owns the
  resolve -> encrypt -> upload -> CAS -> 409-classify -> re-resolve -> re-fetch ->
  retry skeleton and throws `ConflictError` on exhaustion.
- Folder supplies `mergeChildren`; file supplies `mergeVersions` + loser-as-version
  as the domain merge callback.
- Reconcile the attempt-count/backoff divergence intentionally (pick the right
  values for both) rather than preserving the accidental difference.
- Keep the CR-02 `prunedCids` reference-filter behavior for the file path.
