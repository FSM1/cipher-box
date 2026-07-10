---
phase: 73
phase_name: "Shared Write/Navigation Correctness (Web)"
project: "CipherBox"
generated: "2026-07-11"
counts:
  decisions: 6
  lessons: 6
  patterns: 6
  surprises: 6
missing_artifacts:
  - "UAT.md"
---

# Phase 73 Learnings — Shared Write/Navigation Correctness (Web)

## Decisions

### SC4 was wired end-to-end across four stacked gaps, not trimmed

The LOCKED direction (user-confirmed in 73-CONTEXT.md) was to make the WRITE-03 refresh-access path reachable from real production, not delete the dead branch. RESEARCH found this was NOT "just add a supplier" — four independent gaps stacked: (a) `createAndPublishIpnsRecord` let a real API 410 propagate as a raw `AxiosError`; (b) `publishNodeFn` never produced `{tombstoned:true}`; (c) `useSharedWriteOps.ts` called `runWithFailureUx` in ZERO of its write paths; (d) the `refreshWriteAccess` supplier did not exist. All four had to close for the "at least one live production supplier" bar. They were split across plans 73-02 (a), 73-05 (b), 73-07 (supplier `refreshCurrentDepthWriteKey`), and 73-08 (c + wiring).

**Rationale:** The source todo's wording read as if `runWithFailureUx` was already called and merely missing one option; it was not called at all for shared writes (RESEARCH Pitfall 1).

**Source:** 73-02/05/07/08-SUMMARY.md, 73-RESEARCH.md SC4

### Push the 410-detection into sdk-core, not sdk; map ONLY 410

The 410 catch went into `packages/sdk-core/src/ipns/index.ts`'s `createAndPublishIpnsRecord`, reusing the exact `anyError.status ?? anyError.response?.status` idiom already used by `resolveIpnsRecord`'s 404 handling. `packages/sdk` does not declare `axios`; detecting the 410 in `client.ts`'s `publishNodeFn` would have added a new cross-package dependency for no benefit. Only `status === 410` maps to `{success:false, sequenceNumber:0n, tombstoned:true}`; every other status/error rethrows unchanged. The return type was extended additively (`tombstoned?: boolean`) so no existing caller breaks.

**Rationale:** The axios call lives two layers below `publishNodeFn` inside sdk-core; mapping there keeps `publishNodeFn` a pure field read (RESEARCH Pitfall 2). Mapping any non-410 would silently swallow real publish failures (threat T-73-02-01).

**Source:** 73-02-SUMMARY.md, 73-05-SUMMARY.md

### `resolveNodeIdentity` takes the full `SealedChildRef`, a breaking signature change

To route through `gatedResolveChild` (the ROT-07 floor), `resolveNodeIdentity(ipnsName: string)` became `resolveNodeIdentity(childRef: SealedChildRef)` — the gate sources its `generation`/`versionFloor` from the parent mirror, which a bare `ipnsName` cannot supply. `resolveFileMetadata`/`downloadFromIpns` kept their public signatures (they already receive a full `SealedChildRef`); only the internal resolve swapped. The breaking change was scoped to exactly one production caller (`useSharedWriteOps.resolveChildNodeId`, verified via repo-wide grep) and its one test file, all updated atomically in the same commit.

**Rationale:** `gatedResolveChild` cannot gate on an `ipnsName` alone; mirroring `resolveChildIdentity`'s ref-taking shape is the minimal correct fix (RESEARCH SC3, Pitfall 4).

**Source:** 73-04-SUMMARY.md

### SC7 dead path removed by inlining the zero-buffer it always produced

`resolveFolderIpnsPrivateKey` always fell through to `return new Uint8Array(32)` (its `fetchShareKeys` producer is a stub that returns `[]`). Rather than dropping the `ipnsPrivateKey` field from the SDK's `SeedSharedFolderArgs` contract, each of the 4 call sites was replaced with a direct inline `new Uint8Array(32)` — byte-identical behavior, smaller and safer diff. `fetchShareKeys` itself was deliberately left live (still the `file-ipns` fallback for `resolveFileIpnsKey`).

**Rationale:** Touching the SDK seed contract to remove a web-inert field is a larger blast radius than preserving it with a zero buffer; the real write signing key comes from the SDK write-body, never this path (RESEARCH SC7 landmine).

**Source:** 73-06-SUMMARY.md

### Sequence SC7 delete → SC6 consolidate → SC1/SC2 inside the single helper

All four criteria touch the same ~400-line block (`navigateToSubfolder`/`navigateUp`/`navigateToBreadcrumb`). RESEARCH prescribed the order: delete the dead path first (pure subtraction, shrinks the file), extract one `restoreToBreadcrumbIndex(crumbIndex)` helper second (`navigateUp` delegates with `stack.length - 1`), then land SC1 (writeKey-in-stack) and SC2 (refresh-after-restore) as edits INSIDE that one helper — not as separate passes over two copies.

**Rationale:** Landing SC1/SC2 in one consolidated function eliminates the copy-paste risk (fixing `navigateUp` but forgetting `navigateToBreadcrumb`) that SC6 exists to remove.

**Source:** 73-06-SUMMARY.md, 73-07-SUMMARY.md, 73-09-SUMMARY.md, 73-RESEARCH.md sequencing

### `NavStackEntry` carries `publishedNode` too, not just `writeKey`

SC1's task list literally specified only a `writeKey` field, but restore also had to carry the depth's live `publishedNode`. Shared write ops (`buildSharedWriteContextFromState`) trust `SharedFolderState.publishedNode` directly with NO network re-resolve (unlike `updateSharedFile`), so a restore that seeded the all-zero `PLACEHOLDER_PUBLISHED_NODE` made the first write-after-restore fail to unseal even with a correct writeKey.

**Rationale:** SC1's own acceptance criterion ("a write into a deep shared subfolder succeeds after restore") could not hold with a placeholder envelope; the field was a load-bearing pre-existing gap that only surfaces on write-immediately-after-restore.

**Source:** 73-07-SUMMARY.md (Deviation 1)

## Lessons

### A throw→return-value contract change must sweep ALL tests asserting the old shape

SC4 changed `createAndPublishIpnsRecord` to map an API 410 to a catchable `{success:false, tombstoned:true}` return instead of throwing a raw `AxiosError`. Adding the new sdk-core unit test was not enough — a pre-existing sdk-e2e assertion (WRITE-04 Test 20 in `ipns-publish-gate.test.ts`) still asserted the old throw contract on the publish half and had to be updated to the new return-value contract (the resolve half still throws 410 unchanged).

**Context:** The change surfaced post-execution (commit `7ecec1422`) when the sdk-e2e suite ran; a green sdk-core unit suite did not cover the cross-package e2e assertion.

**Source:** commit `7ecec1422`, 73-02-SUMMARY.md

### A retry supplier that reseeds from cache without re-resolving can never recover

`refreshCurrentDepthWriteKey` (the SC4 `refreshWriteAccess` supplier) initially reseeded the current depth from cached SDK state without re-resolving IPNS, so a co-writer whose write failed on a stale-but-not-revoked `publishedNode` reused the same stale envelope on retry and could never recover. Fixed by mirroring `restoreToBreadcrumbIndex`'s additive `refreshSharedFolder` re-check after reseeding — guarded by the SDK monotonicity no-op and try/catch-ignored so a genuinely tombstoned name still escalates to the terminal toast.

**Context:** Found post-execution (commit `7e0026862`); the "refresh" path must actually re-fetch, not replay the same cached state that caused the failure.

**Source:** commit `7e0026862`

### tsup bundles sdk-core into one file, so internal facade calls bypass exported-binding mocks

The RED `file-metadata-facade.test.ts` mocked sdk-core's exported `resolveIpnsRecord`/`fetchFromIpfs`, but `client.ts`'s `resolveFileMetadata` ALSO calls sdk-core's own internal `resolveFileMetadata`/`downloadFileContent`, whose in-module `resolveIpnsRecord` reference is a direct call, not a call through the mocked export — so the RED hit a real 401 network request instead of a clean assertion. The fix: also mock the sdk-core-internal delegates so the RED fails as "resolved instead of rejecting."

**Context:** Same tsup-bundle boundary as Phase 72's `vi.spyOn`-on-re-export finding, seen from the other direction (a mock that must reach a bundled-internal call, not intercept one).

**Source:** 73-04-SUMMARY.md (Deviation 1)

### Adding a required param breaks test call sites the plan's file list omits

Adding a required `refreshWriteAccess` to `SharedWriteOpsParams` broke the 4 pre-existing `useSharedWriteOps({...})` call sites in `useSharedWriteOps.test.ts` against the type, failing the plan's own `pnpm typecheck` gate. Each had to gain `refreshWriteAccess: vi.fn(() => Promise.resolve())` in the same task despite the test file not being in the plan's declared targets.

**Context:** The same "signature change must sweep every caller including tests" lesson as Phase 72's `getShareKeysFn` removal; the typed build, not the test run, is what catches it.

**Source:** 73-08-SUMMARY.md (Deviation 1)

### A long-lived key buffer in a nav ref needs a fresh zero-on-every-exit audit

Before SC1 the derived `writeKey` was zeroed almost immediately after seeding; after SC1 it persists in `navStackRef` for the lifetime of the stack entry, increasing the number of live key buffers the web owns. Every new storage site needed a matching zero: `navigateToShare` (new-share entry), `restoreToBreadcrumbIndex` (active-abandon + discarded-deeper entries), `navigateToRoot` (full sweep), and unmount cleanup — documented in a file-header zeroization audit comment.

**Context:** RESEARCH Landmine 5 / threat T-73-07-01; get it wrong and it is a key-material-in-memory-longer-than-necessary regression, not a functional bug.

**Source:** 73-07-SUMMARY.md, 73-SECURITY.md T-73-07-01

### Whole-file grep acceptance criteria match doc-comment prose, not just code

SC7's "grep returns 0 across `apps/web/src`, code AND comments" bar failed on first check because `useSharedWriteOps.ts`'s `resolveFileIpnsKey` doc comment named the deleted `resolveFolderIpnsPrivateKey` as a cross-reference. The comment had to be reworded (describing the function as "the last live consumer of the `share_keys` fan-out") without touching any logic.

**Context:** Same class as Phase 72's `describe.skip`/`.fill(0)` grep-match-in-prose self-corrections; a wording fix, not a behavior change.

**Source:** 73-06-SUMMARY.md (Deviation 1)

## Patterns

### Single-owner writeKey buffer discipline across the nav stack

Exactly one of `NavStackEntry.writeKey` (a suspended depth) or `currentWriteKeyRef` (the active depth) ever owns a given writeKey buffer, never both. On descent the buffer transfers (clone-on-transfer, no zero at the source); on restore the stored entry's buffer transfers to the active ref; the terminal owner zeroes on every exit path. `resolveSharedSubfolderWriteKey`/`resolveSharedRootWriteKey` implementations are never touched — only where their output is stored or discarded.

**When to use:** Any web-side long-lived storage of a derived key buffer across navigation; the same use-after-free / double-zero class as the Phase 51 zeroization break.

**Source:** 73-07-SUMMARY.md, 73-SECURITY.md T-73-07-01/02

### Single restore helper as the landing spot for coordinated fixes

`restoreToBreadcrumbIndex(crumbIndex)` — a `useCallback` so `navigateUp`/`navigateToBreadcrumb` can list it as a stable dependency — is the one place both entrypoints delegate to. SC1 (writeKey/publishedNode transfer) and SC2 (`refreshSharedFolder` re-check) each land ONCE inside it rather than being copy-pasted across two near-verbatim ~55-line blocks.

**When to use:** When several coordinated correctness fixes must all touch the same duplicated navigation/restore logic; consolidate first, then fix once.

**Source:** 73-06-SUMMARY.md, 73-07-SUMMARY.md, 73-09-SUMMARY.md

### Non-listing read facades reuse the existing gate, introduce no new gate logic

`resolveFileMetadata`, `downloadFromIpns`, and `resolveNodeIdentity` route through the already-proven `gatedResolveChild` (fail-closed on `!signatureVerified`, overflow guard, `RotationHighWater.enforceResolved`), the same gate used by `resolveChildIdentity`/`resolveListingChildren`. No new anti-rollback logic was written — the phase only closed the last three facades that bypassed the floor via raw `resolvePublishedNode`.

**When to use:** Closing an access-control gap where a proven gate already exists; re-route the un-gated caller rather than duplicating the control (V4, no new attack surface).

**Source:** 73-04-SUMMARY.md, 73-SECURITY.md T-73-04-01

### Additive freshness re-check relying on the existing monotonicity guard

SC2's fix inserts `refreshSharedFolder(shareId)` AFTER the existing `seedActiveSharedFolder` restore, as a purely additive re-check — no new invalidation data structure. It relies on `refreshSharedFolder`'s own `state.sequenceNumber >= result.sequenceNumber` monotonicity guard (client.ts:5624) to no-op cheaply when nothing changed, and the already-wired `sharedFolder:updated` projection subscription to apply a fresher listing. Placed inside the helper's existing try/catch so a refresh failure never undoes the committed restore.

**When to use:** Correcting a stale-snapshot symptom where re-resolve plumbing and a monotonicity clock already exist; add a re-check step, never bypass the guard with a "just re-fetch and overwrite."

**Source:** 73-09-SUMMARY.md, 73-05-SUMMARY.md, 73-RESEARCH.md Pitfall 5

### `withRevocationGuard(outer) -> runWithFailureUx(inner)` composition for shared writes

Every `useSharedWriteOps` mutation nests `runWithFailureUx` INSIDE `withRevocationGuard`: `withRevocationGuard(() => runWithFailureUx(() => op(shareId), { refreshWriteAccess }))`. A 403 revocation is a harder, non-recoverable failure than a stale writeKey a refresh might fix, so the revocation guard stays outermost — matching the owned-path analogs (`useFolderMutations.ts`).

**When to use:** Composing a recoverable refresh-and-retry classifier with a terminal-failure guard; the terminal guard wraps the retryable one.

**Source:** 73-08-SUMMARY.md

### Transport-boundary status → typed-field mapping

Catch a specific HTTP status crossing the SDK→API trust boundary and translate it into a typed result field rather than letting the raw transport error leak: `createAndPublishIpnsRecord` maps a 410 to `tombstoned:true`, checked BEFORE the generic `!pubResult.success` throw since a tombstone is a specific retryable-after-refetch signal, not a generic failure. Every other status rethrows unchanged.

**When to use:** When one specific transport status carries domain meaning that a downstream classifier must branch on; map only that status, rethrow the rest.

**Source:** 73-02-SUMMARY.md, 73-05-SUMMARY.md

## Surprises

### SC4 was three independent stacked gaps, not "wire a supplier"

The source todo read as if `runWithFailureUx` was already called and merely missing a `refreshWriteAccess` option. In fact `useSharedWriteOps.ts` called `runWithFailureUx` in ZERO of its write paths (confirmed by a repo-wide grep), `publishNodeFn` never emitted `{tombstoned:true}`, and a real 410 would have surfaced as a raw uncaught `AxiosError` before either check. Even a correctly-thrown `CannotWriteUntilRefetchError` would have hit the generic `setError` catch, never the classifier.

**Impact:** SC4 became a four-plan effort spanning sdk-core, sdk, and two web hooks — materially larger than the todo's one-line framing.

**Source:** 73-RESEARCH.md SC4 / Pitfall 1, 73-08-SUMMARY.md

### writeKey-only restore silently failed to decrypt; the gap was invisible to every prior test

Landing the writeKey-in-navStack fix alone left the SC1 e2e failing with `// ERROR: Decryption failed`: write ops trust the cached `publishedNode` with no re-resolve, and restore seeded the all-zero placeholder envelope. The bug was invisible before this phase because no prior test performed a write IMMEDIATELY after a restore — every earlier test either read-only after restore or wrote only after a fresh re-descent (which always supplies a real `publishedNode`).

**Impact:** `NavStackEntry` had to carry `publishedNode` alongside `writeKey`; the new 8.4b e2e case (descend-2 / up-1 / write) is exactly the previously-uncovered gap.

**Source:** 73-07-SUMMARY.md (Deviation 1)

### The SC4 supplier shipped incompletely wired twice, both caught after execution

`refreshCurrentDepthWriteKey` needed two post-execution fixes to the same reseed call: `d3c39c06e` (verification 6/7→7/7) added the live `publishedNode` to its `seedActiveSharedFolder` call so the retried write read a valid envelope instead of the placeholder; `7e0026862` then added the `refreshSharedFolder` IPNS re-check so a stale-not-revoked co-writer could actually recover on retry. Both were omissions the plan-level typecheck and unit gates passed over.

**Impact:** The "refresh access" retry path only became genuinely recoverable after two follow-up fixes; the supplier is subtle enough that "compiles and reseeds" did not mean "recovers."

**Source:** commits `d3c39c06e`, `7e0026862`, 73-VERIFICATION.md

### `tee_key_state empty` on the sdk-e2e run was a host-port collision, not a phase regression

Running the WRITE-04 sdk-e2e assertion surfaced `tee_key_state is empty`-style failures that looked like a Phase 73 regression but were an environment issue: the API's default `TEE_WORKER_URL` (`:3001`) collides with mock-ipns-routing, while the real worker runs on host `:3002`, compounded by a mismatched auth secret. Not a code defect introduced by this phase.

**Impact:** Avoided mis-attributing a docker/port/secret alignment gap to the SC4 tombstone changes; the WRITE-04 assertion update (`7ecec1422`) is the only real e2e change.

**Source:** commit `7ecec1422`; consistent with `project-tee-republish-e2e-stack-recipe` memory

### The WRITE-03 live e2e never ran on-branch due to worktree port contention

Plan 73-08 could not run its rewritten classifier-driven `rotation-ux.spec.ts` WRITE-03 case live: it executed as a parallel worktree agent alongside plan 73-09, both sharing the default local ports (API `:3000`, web `:5173`), and starting a second dev stack risked disrupting the sibling's verification. Static verification only (`playwright --list` confirms active-not-fixme, `tsc -b` clean); the live run was deferred to CI / a dedicated stack.

**Impact:** SC4 is code-complete and statically traced, but the end-to-end retry-after-refresh round trip has one CI/manual confirmation outstanding — flagged in VERIFICATION as non-blocking, not a code gap.

**Source:** 73-08-SUMMARY.md, 73-VERIFICATION.md Human Verification

### Verification caught the SC4 gap on the first pass; re-verification closed it cleanly

The initial verification scored 6/7 — SC4's `refreshCurrentDepthWriteKey` omitted `publishedNode` on reseed, so the WRITE-03 retry would throw an unclassified GCM/unseal error instead of reaching the `CannotWriteUntilRefetch` classifier. Fix commit `d3c39c06e` brought the call site in line with the other three `seedActiveSharedFolder` sites in the same file, and re-verification confirmed 7/7 with zero regressions.

**Impact:** The goal-backward verifier caught a real reachability gap that all nine plans' own self-checks passed over — the same-file consistency check ("this call site differs from its three siblings") was the tell.

**Source:** 73-VERIFICATION.md (re-verification block)
