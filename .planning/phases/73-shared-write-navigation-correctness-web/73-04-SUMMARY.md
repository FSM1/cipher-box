---
phase: 73-shared-write-navigation-correctness-web
plan: 04
subsystem: api
tags: [sdk, ipns, rot-07, anti-rollback, gatedResolveChild, resolveNodeIdentity, resolveFileMetadata, downloadFromIpns]

requires:
  - phase: 68.2-sdk-owned-read-chain-and-resolved-folder-listings
    provides: gatedResolveChild (ROT-07 anti-rollback floor) and resolveChildIdentity as the proven pattern this plan reuses
provides:
  - resolveFileMetadata and downloadFromIpns now resolve through gatedResolveChild instead of raw resolvePublishedNode
  - resolveNodeIdentity takes a SealedChildRef (breaking signature change) and routes through gatedResolveChild
  - useSharedWriteOps resolveChildNodeId updated to pass the full SealedChildRef
affects: [73-08 (useSharedWriteOps runWithFailureUx wiring touches the same file), any future SC3/ROT-07 audit of read facades]

tech-stack:
  added: []
  patterns:
    - "Non-listing read facades reuse gatedResolveChild rather than introducing new gate logic (V4 access-control-adjacent, no new attack surface)"

key-files:
  created:
    - packages/sdk/src/__tests__/file-metadata-facade.test.ts
  modified:
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/resolve-node-identity.test.ts
    - apps/web/src/hooks/useSharedWriteOps.ts

key-decisions:
  - "resolveFileMetadata/downloadFromIpns keep their public signature (SealedChildRef, folderKey) unchanged -- only the internal resolve call swaps from resolvePublishedNode to gatedResolveChild"
  - "resolveNodeIdentity's public signature changes from (ipnsName: string) to (childRef: SealedChildRef) -- a breaking change with exactly one production caller (useSharedWriteOps.resolveChildNodeId), updated atomically in the same commit"
  - "Test fixtures pass rotationHighWater in createTestConfig() to enter gatedResolveChild's signatureVerified fail-closed branch (that branch is itself gated on this.config.rotationHighWater being set) -- mirrors folder-listing-gate.test.ts's fakeRotationHighWater pattern"

patterns-established:
  - "New non-listing SDK read facade fail-closed test files mock sdk-core's resolveIpnsRecord/fetchFromIpfs at the package-export boundary AND any sdk-core-internal facade the client method further delegates to (e.g. sdk-core's own resolveFileMetadata), since tsup bundles sdk-core into a single file where internal calls bypass the exported-binding mock"

requirements-completed: [SC3]

coverage:
  - id: D1
    description: "resolveFileMetadata and downloadFromIpns route through gatedResolveChild and fail closed on signatureVerified:false"
    requirement: SC3
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/file-metadata-facade.test.ts"
        status: pass
    human_judgment: false
  - id: D2
    description: "resolveNodeIdentity(childRef: SealedChildRef) routes through gatedResolveChild and fails closed on signatureVerified:false; its one production call site (useSharedWriteOps.resolveChildNodeId) passes the full ref"
    requirement: SC3
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/resolve-node-identity.test.ts"
        status: pass
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk run typecheck (proves useSharedWriteOps.ts compiles against the new signature)"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-10
status: complete
---

# Phase 73 Plan 04: Floor-gate the three non-listing read facades Summary

**Routed resolveFileMetadata, downloadFromIpns, and resolveNodeIdentity through the existing gatedResolveChild ROT-07 anti-rollback floor, closing the last three read facades that bypassed it via raw resolvePublishedNode.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-10T21:21:00Z
- **Completed:** 2026-07-10T21:26:30Z
- **Tasks:** 3
- **Files modified:** 4 (1 new test file, 3 modified)

## Accomplishments

- `resolveFileMetadata` and `downloadFromIpns` (packages/sdk/src/client.ts) now resolve the file's `PublishedNode` via `gatedResolveChild` instead of a raw `resolvePublishedNode`, so a `signatureVerified:false`/rolled-back record fails closed for both.
- `resolveNodeIdentity` changed from `resolveNodeIdentity(ipnsName: string)` to `resolveNodeIdentity(childRef: SealedChildRef)`, routed through `gatedResolveChild`; its one production caller (`useSharedWriteOps.ts`'s `resolveChildNodeId`) and its test file were updated atomically in the same commit.
- New `file-metadata-facade.test.ts` and rewritten `resolve-node-identity.test.ts` prove fail-closed behavior via Vitest for all three facades.

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): new file-metadata-facade fail-closed test** - `489e184c4` (test)
2. **Task 2 (GREEN): route resolveFileMetadata + downloadFromIpns through gatedResolveChild** - `ef32cab7a` (feat)
3. **Task 3: resolveNodeIdentity(SealedChildRef) + gate + update test + one call site** - `0c3fa020a` (feat)

_TDD plan: Task 1 is the RED test commit; Task 2 is the GREEN implementation commit for the file-metadata facades; Task 3 combines the resolveNodeIdentity signature change, its gate, its test rewrite, and its one call site into a single atomic commit (the breaking-signature blast radius is fully contained to that one commit, per the plan's acceptance criteria)._

## Files Created/Modified

- `packages/sdk/src/__tests__/file-metadata-facade.test.ts` - NEW: fail-closed Vitest cases for `resolveFileMetadata` and `downloadFromIpns` (signatureVerified:false and null-resolve)
- `packages/sdk/src/client.ts` - `resolveFileMetadata`, `downloadFromIpns` resolve swapped to `gatedResolveChild`; `resolveNodeIdentity` signature changed to `(childRef: SealedChildRef)` and routed through `gatedResolveChild`
- `packages/sdk/src/__tests__/resolve-node-identity.test.ts` - rewritten to build a `SealedChildRef` fixture (mirroring `resolve-child-identity.test.ts`), pass it instead of a bare string, and add a `signatureVerified:false` fail-closed case
- `apps/web/src/hooks/useSharedWriteOps.ts` - `resolveChildNodeId(ipnsName: string)` changed to `resolveChildNodeId(item: SealedChildRef)`; `deleteItemHandler`'s call site updated to pass `item` directly

## Decisions Made

- Kept `resolveFileMetadata`/`downloadFromIpns` public signatures unchanged (already receive a full `SealedChildRef`) -- only the internal resolve mechanism changed, per the plan's trivial-swap framing.
- `resolveNodeIdentity`'s breaking signature change was scoped tightly to its one production call site (`useSharedWriteOps.resolveChildNodeId`) and its one test file, verified via `grep -rn "resolveNodeIdentity"` across the repo before making the change.
- Test fixtures needed `rotationHighWater` set in `createTestConfig()` for the `signatureVerified:false` fail-closed branch to actually fire, since `gatedResolveChild` guards that branch behind `this.config.rotationHighWater` being configured (mirrors the existing `folder-listing-gate.test.ts` pattern) -- documented directly in the new/rewritten test files' comments.

## Deviations from Plan

**1. [Rule 1 - Bug in test authoring, self-caught during RED] Added extra mocks to avoid a live network call in the RED test**

- **Found during:** Task 1 (writing `file-metadata-facade.test.ts`)
- **Issue:** The plan's fixture pattern only mocks `sdk-core`'s exported `resolveIpnsRecord`/`fetchFromIpfs` bindings. But `resolveFileMetadata`/`downloadFromIpns` in `client.ts` ALSO call sdk-core's own `resolveFileMetadata`/`downloadFileContent` internally. Since `sdk-core` is bundled by `tsup` into a single file, `resolveFileMetadata`'s internal call to `resolveIpnsRecord` is a direct in-module reference, not a call through the package's exported-binding mock -- so in the pre-fix (RED) state, that internal call bypassed the `vi.mock` and hit a real (unauthenticated) network request, surfacing as `Request failed with status code 401` instead of a clean assertion failure.
- **Fix:** Added `resolveFileMetadata: vi.fn()` and `downloadFileContent: vi.fn()` to the `vi.mock('@cipherbox/sdk-core', ...)` block and stubbed their resolved values in the two `signatureVerified:false` test cases, so the RED failure is "promise resolved instead of rejecting" (a clean, deterministic RED) rather than a network-dependent error.
- **Files modified:** `packages/sdk/src/__tests__/file-metadata-facade.test.ts`
- **Verification:** Re-ran the test after the fix -- RED failures now report `AssertionError: promise resolved ... instead of rejecting` for both cases; after Task 2's GREEN change, both pass cleanly with no network I/O.
- **Committed in:** `489e184c4` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (test-authoring correctness fix, Rule 1)
**Impact on plan:** No scope creep -- the deviation only tightened the new test file's own mocking so the suite stays hermetic (no live network calls), which is itself a project-wide test-quality bar. No production code or behavior was affected.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SC3 fully satisfied: all three non-listing read facades (`resolveFileMetadata`, `downloadFromIpns`, `resolveNodeIdentity`) now fail closed on an unverified/rolled-back IPNS resolve via the existing, proven `gatedResolveChild` gate.
- `grep -n "resolvePublishedNode" packages/sdk/src/client.ts` confirms no remaining hit inside any of the three facades' bodies (only doc-comment references to the old term remain).
- Full `pnpm --filter @cipherbox/sdk test` (420 passed, 3 skipped) and `pnpm --filter @cipherbox/sdk run typecheck` are green; `apps/web`'s `tsc -b` is also green against the new `resolveNodeIdentity` signature.
- Plan 73-08 (which wires `runWithFailureUx` into `useSharedWriteOps.ts`) touches the same file -- no conflict expected since this plan only changed `resolveChildNodeId`'s signature and `deleteItemHandler`'s one call site, not the `runWithFailureUx`/error-handling wiring itself.

---
*Phase: 73-shared-write-navigation-correctness-web*
*Completed: 2026-07-10*
