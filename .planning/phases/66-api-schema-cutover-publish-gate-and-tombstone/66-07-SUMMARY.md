---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "07"
subsystem: sdk-core
tags: [ipns, generation, tee, publish-gate]
dependency_graph:
  requires: ["66-06"]
  provides: ["66-09"]
  affects: ["packages/sdk-core"]
tech_stack:
  added: []
  patterns: [optional-param-forwarding, caller-owns-key]
key_files:
  created: []
  modified:
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/cas.ts
decisions:
  - "generation param is optional (string = bigint-as-string) so existing callers compile unchanged"
  - "generation is forwarded on every CAS retry attempt inside publishWithCas"
  - "no durable client-side generation high-water added; ROT-07 persistence is Phase 68"
metrics:
  duration: "~8 minutes"
  completed: "2026-06-30"
status: complete
---

# Phase 66 Plan 07: sdk-core generation param Summary

Thread an optional `generation` argument through sdk-core publish primitives so the TEE-07 server-side forward-only generation gate is exercisable through the real client path in sdk-e2e (66-09).

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Add optional generation param to createAndPublishIpnsRecord + publishWithCas | f074d432e | packages/sdk-core/src/ipns/index.ts, packages/sdk-core/src/cas.ts |

## What Was Built

- `createAndPublishIpnsRecord` now accepts an optional `generation?: string` (bigint-as-string) param and forwards it inside the `ipnsControllerPublishRecord` request body.
- `publishWithCas` now accepts an optional `generation?: string` param and threads it through to `createAndPublishIpnsRecord` on every CAS attempt (including retries after 409 conflicts).
- Both changes are additive: omitting `generation` preserves existing behavior exactly (the server treats an absent `generation` as a no-op gate per 66-02).
- `pnpm --filter @cipherbox/sdk-core build` passes clean.

## Deviations from Plan

None - plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. The `generation` field was already present in the regenerated api-client DTOs (`PublishIpnsEntryDto`, `PublishIpnsDto`) from prior plans in this phase.

## Self-Check

- [x] `packages/sdk-core/src/ipns/index.ts` modified
- [x] `packages/sdk-core/src/cas.ts` modified
- [x] Commit f074d432e exists
- [x] `grep -c "generation" packages/sdk-core/src/ipns/index.ts` = 3 (>= 1)
- [x] `grep -c "generation" packages/sdk-core/src/cas.ts` = 3 (>= 1)
- [x] No IndexedDB/highWater references in modified files
- [x] `generation: params.generation` present in `ipnsControllerPublishRecord` call

## Self-Check: PASSED
