# Phase 73: Shared Write/Navigation Correctness (Web) - Context

**Gathered:** 2026-07-10
**Status:** Ready for planning
**Source:** Orchestrator-captured decisions (roadmap-scoped, no full discuss-phase)

<domain>
## Phase Boundary

Web-side correctness for shared-folder navigation and write capability. All five original success criteria plus two folded-in tangential cleanups that live in the same subsystem (`useSharedNavigationActions.ts`). Scope is the web app's shared-navigation/write path and the SDK seams it consumes — NOT new SDK write-plane primitives (Phase 72), NOT the SDK-owned read chain itself (Phase 68.2), NOT API changes beyond surfacing an already-emitted tombstone signal.

In scope:

- navStack write-key retention across navigate-up / breadcrumb restore
- nav-stack stale-child-snapshot invalidation on `sharedFolder:updated`
- floor-gating the three non-listing read facades (`resolveFileMetadata`, `downloadFromIpns`, `resolveNodeIdentity`) through the ROT-07 anti-rollback floor
- WRITE-03 refresh-access live production trigger (wire end-to-end)
- `SharedFolderRow` drag-payload kind from the resolved listing
- (folded-in) dedup of duplicated shared-navigation logic in `useSharedNavigationActions`
- (folded-in) removal of the dead `resolveFolderIpnsPrivateKey` / `getShareKeys` folder-IPNS write-share key path

Out of scope: the three "adjacent-but-separate" todos deliberately left in the backlog — shared-write base-aware merge parity (SDK), dead SDK share-scaffolding retirement, and the D-07 boundary ESLint rule.

</domain>

<decisions>
## Implementation Decisions

### SC4 — WRITE-03 refresh-access (LOCKED: wire end-to-end)

Chosen direction (user-confirmed): **wire the co-writer stale-write trigger end-to-end**, do NOT trim the branch.

- `packages/sdk/src/client.ts#buildSharedWriteContextFromState` — `publishNodeFn` must surface the API's tombstone signal as `{tombstoned: true}` so `CannotWriteUntilRefetchError` has a live throw site (today it is a Phase-66 mock seam that never returns tombstoned).
- The shared-write hooks must pass a real `refreshWriteAccess` supplier into `useMutationFailureUx`'s D-01/WRITE-03 branch (`refreshWriteAccess` / `retryAfterRefresh` / `dispatchWriteDescriptorStale`) — today no production call site supplies one.
- Upgrade the rotation-ux e2e case from direct toast injection to a genuine classifier-driven flow (exercise the classifier, not a hand-injected toast).
- Acceptance: at least one live production supplier exists; the classifier path is reachable from real shared-write publish failures.

### SC1 — nested write-key retention

navStack entries must carry the derived `writeKey`, not only `folderKey`. A write into a deep shared subfolder must succeed after navigate-up / breadcrumb restore. This is the sole write-key source after the SC7 dead-path removal.

### SC2 — stale-child-snapshot invalidation

On `sharedFolder:updated`, the nav-stack must invalidate or re-resolve stale child snapshots — no children pushed/restored by reference without re-resolve.

### SC3 — floor-gate the non-listing read facades

`resolveFileMetadata`, `downloadFromIpns`, and `resolveNodeIdentity` route through the ROT-07 anti-rollback floor gate, not raw `resolvePublishedNode`.

### SC5 — drag-payload kind from resolved listing

`SharedFolderRow` drag-payload kind derived from the resolved listing (`isFileRefResolved` / `resolvedByIpnsName`), not `isFileRef` on a bare `SealedChildRef` (which is always false post-kind-cache-removal).

### SC6 (folded-in) — consolidate duplicated shared-navigation logic

Dedup the navigateUp / navigateToBreadcrumb restore + resolve-kinds-before-project logic in `useSharedNavigationActions` to a single source of truth, so the SC1/SC2 fixes live in one place rather than copy-pasted across nav entrypoints. Do the dedup in a way that the writeKey/snapshot fixes are applied once.

### SC7 (folded-in) — remove dead getShareKeys/folder-IPNS write-share key path

Remove the dead `resolveFolderIpnsPrivateKey` / `getShareKeys` folder-IPNS write-share key path from `useSharedNavigationActions.ts` (no remaining references), leaving the SC1 derived-writeKey path as the sole write-key source. Sequence this with SC6 so removal and dedup do not conflict.

### Claude's Discretion

Exact task decomposition, wave ordering, test file placement (web logic lives in packages/sdk per repo convention — see project rules), and whether SC6 dedup lands before or after SC1/SC2 as long as the fixes end up single-sourced.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Source todos (problem + solution + file lists)

- `.planning/todos/pending/2026-07-04-nested-shared-write-key-lost-on-up-breadcrumb-restore.md` — SC1
- `.planning/todos/pending/2026-07-04-shared-nav-stack-stale-children-snapshot.md` — SC2
- `.planning/todos/pending/2026-07-06-gate-non-listing-read-facades.md` — SC3
- `.planning/todos/pending/2026-07-02-write03-refresh-access-path-has-no-live-trigger.md` — SC4
- `.planning/todos/pending/2026-07-06-sharedfolderrow-drag-kind-classification.md` — SC5
- `.planning/todos/pending/2026-07-03-consolidate-web-shared-navigation-dup.md` — SC6 (folded-in)
- `.planning/todos/pending/2026-07-04-remove-dead-getsharekeys-folder-ipns-path.md` — SC7 (folded-in)
- `.planning/todos/pending/2026-07-06-68.2-coderabbit-hardening-backlog.md` — web-scoped items only (item 4 refreshSharedFolder stale write envelope, item 9 shared-nav seed race)

### Dependencies (prior-phase artifacts to maintain consistency with)

- Phase 68.1 (`.planning/phases/68.1-web-client-runtime-integration/`) — web client runtime integration
- Phase 68.2 (`.planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/`) — SDK-owned read chain, resolved listings (`isFileRefResolved`, `resolvedByIpnsName`)
- Phase 72 (`.planning/phases/72-sdk-write-plane-durability-and-correctness/`) — write-plane primitives the web nav consumes

### Specs

- `docs/FILESYSTEM_SPECIFICATION.md` — ROT-07 anti-rollback floor, read-chain navigation
- `.planning/ROADMAP.md` (Phase 73 section) — the 7 success criteria (source of truth)

</canonical_refs>

<specifics>
## Specific Ideas

- Primary web file: `apps/web/src/hooks/useSharedNavigationActions.ts` (SC1, SC2, SC6, SC7 all touch it — sequence to avoid churn/conflicts).
- WRITE-03 files: `apps/web/src/hooks/useMutationFailureUx.ts`, `packages/sdk/src/client.ts` (`buildSharedWriteContextFromState`, `publishNodeFn`).
- Per repo convention, web UI is not unit-tested — hoist testable logic into `packages/sdk` (Vitest) and cover UI behavior via Playwright web-e2e. Do not add apps/web unit tests.
- `isFileRef(bareSealedChildRef)` is always `false` since kind-cache removal — SC5 must use `isFileRefResolved` against the resolved listing.

</specifics>

<deferred>
## Deferred Ideas

Left in the backlog (adjacent but separate concerns, NOT this phase):

- `2026-07-10-shared-write-base-aware-merge-parity.md` — SDK CAS-409 merge resurrection
- `2026-07-02-retire-dead-sdk-share-scaffolding.md` — SDK ShareCallbacks public-API retirement
- `2026-07-06-d07-boundary-eslint-rule.md` — web↔SDK import-boundary ESLint/CI rule

</deferred>

---

*Phase: 73-shared-write-navigation-correctness-web*
*Context captured: 2026-07-10 by orchestrator (roadmap-scoped)*
