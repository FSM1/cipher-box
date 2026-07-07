---
phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl
plan: 08
subsystem: testing
tags: [rotation, e2e, crash-recovery, merge-downgrade, fresh-record-resume, sdk-e2e]

# Dependency graph
requires:
  - phase: 70-04
    provides: mergeConcurrentChildren/updateFolderMetadataAndPublish local-wins merge wired at both rotation CAS-409 sites (site A + site B)
  - phase: 70-06
    provides: rotateReadFromNode's restructured entry gate (probe → unconditional verifySubtreeClean → rotateOne(root)), RootKeyStaleError, safe double-rotation, fresh-copy dirty-resume result
provides:
  - Strengthened e2e test 3 (rotation-crash-safety.test.ts) that navigates into the concurrently-relevant existing rotated child (sub3IpnsName) and UNSEALS it with the new root key, proving local-wins keeps the D-02 re-seal intact where remote-wins would AEAD-fail
  - A fail-fast guard on test 3 asserting the concurrent-write injection callback genuinely executed
  - A new e2e test 4 proving genuine fresh-record resume — mid-walk crash (immediately after root's own commit), resume with a BRAND-NEW RotationJobRecord (empty completedNodeIds) and the CURRENT valid rootReadKey, converging via safe double-rotation (generation 1 → 2) and cutting the pre-rotation grant
affects: [sdk-e2e phase gate for Phase 70]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "e2e proof of a merge-downgrade fix requires an ACTUAL unseal of the affected child's real published body with the derived key — child-name-membership assertions alone cannot distinguish local-wins from remote-wins, since both policies preserve the entry, only the WRAPPED KEY differs"
    - "A childless (single-node, file-kind) rotation root is the only crash point in this suite's persistCallback-only fault-injection model for which a fresh (empty completedNodeIds) resume with the CURRENT valid rootReadKey is cryptographically guaranteed to converge without an unrelated AEAD mismatch — any node with children whose own D-09 batched parent-republish has not yet fired leaves its SealedChildRef[...].readKeySealed entries wrapped under a pre-rotation key that cannot be re-derived from the node's post-rotation key (RESEARCH.md Pitfall 4's unrecoverable window)"
    - "navigateReadChain accepts path: [] to exercise grant issuance/behind-retry/ok semantics directly against a file-kind rotation root, without requiring a folder wrapper or a linked child"

key-files:
  created: []
  modified:
    - tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts

key-decisions:
  - "Test 3's strengthened assertion derives subfolder3's key via unsealChildReadKey(sub3ChildRef.readKeySealed, readKeyPrimeRoot3, sub3Pub.id, sub3Pub.kind, sub3ChildRef.generation) and then calls unsealNode against subfolder3's ACTUAL published (post-rotation) body — this is what AEAD-fails under the old remote-wins bug (the remote snapshot points at subfolder3's pre-rotation key) and succeeds under local-wins (this phase's fix), which is the precise behavior test 3 exists to prove"
  - "Test 4's rotation root is deliberately a single FILE node with no children (via makeFileNode/publishFileNode), not a folder with a linked child — a rigorous trace of the engine's D-02/D-09 out-of-band re-seal timing (engine.ts lines ~1442-1470) shows that for ANY node with children, deriving that node's children from the ROOT'S mirror during a resume requires the node's own D-09 batched parent-republish to have ALREADY fired; since D-09 fires atomically only once a node's LAST pending child commits (no intervening checkpoint reachable via this suite's persistCallback-only fault-injection hook), there is no crash point strictly before the walk's own final persist where a multi-level tree's mirror is partially-but-not-fully consistent without hitting an AEAD mismatch during verifySubtreeClean's own recursive traversal. A childless root sidesteps this entirely while still proving the SC#3 entry-gate's actual target: a fresh job with empty completedNodeIds must not get stuck skip-gated and must converge via safe double-rotation"
  - "Test 4 crashes on the FIRST persistCallback call (immediately after root's own commit) rather than seeding an intermediate persistCallback count, since a childless root only ever produces exactly 2 checkpoints (root commit, then final complete) — crashing at call 1 is unambiguously earlier than test 2's 4th/final-call crash and satisfies the plan's 'earlier fault-injection point' requirement"
  - "Test 4 explicitly does NOT seed freshJob4.completedNodeIds from jobRecord4 (the crash-time job) and does NOT pass the ORIGINAL pre-crash-run rootReadKey — it passes the CURRENT valid key (readKeyPrimeRoot4, captured via the existing crypto.getRandomValues spy, mirroring test 2's established capture pattern) because the ORIGINAL key would fail the entry gate's stale-key PROBE (root already rotated once in the crash run) — per the plan's prohibition, this is the 'CURRENT rootReadKey', not a durable-job-record artifact"

patterns-established:
  - "e2e assertions for a merge-policy fix must perform the actual cryptographic unseal of the affected entity, not just check for presence/absence in a collection"

requirements-completed: ["SC#1", "SC#3"]

coverage:
  - id: D1
    description: "Strengthened e2e test 3 navigates into the concurrently-relevant existing rotated child (sub3IpnsName) and unseals it with the new root key (readKeyPrimeRoot3), proving local-wins keeps the D-02 re-seal intact after a concurrent-add CAS-409 merge"
    requirement: "SC#1"
    verification:
      - kind: e2e
        ref: "tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts#concurrent-add: child added mid-rotation survives in merged parent (HIGH-4/ROT-05) — navigate+unseal block"
        status: unknown
    human_judgment: true
    rationale: "Executor is explicitly instructed to AUTHOR ONLY — the orchestrator owns the live docker-stack + local-API gate run of this sdk-e2e suite. Self-check here was typecheck (0 errors) + static correctness review only; the actual pass/fail of the live assertion has not been observed by this agent."
  - id: D2
    description: "test 3 fails fast if the concurrent-write injection callback did not actually execute (concurrentInjectionRan guard) and the expected 3-checkpoint persistCallback count is asserted"
    requirement: "SC#1"
    verification:
      - kind: e2e
        ref: "tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts#concurrent-add: child added mid-rotation survives in merged parent (HIGH-4/ROT-05) — persistCall3Count/concurrentInjectionRan assertions"
        status: unknown
    human_judgment: true
    rationale: "Same as D1 — live-run status not observed by this agent; deferred to the orchestrator's phase gate."
  - id: D3
    description: "New e2e test 4 proves genuine fresh-record resume: mid-walk crash (immediately after root's own commit, earlier than the existing final-persist crash), resume with a BRAND-NEW RotationJobRecord (empty completedNodeIds, not seeded) and the CURRENT valid rootReadKey, converging via safe double-rotation (generation 1 → 2) without throwing"
    requirement: "SC#3"
    verification:
      - kind: e2e
        ref: "tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts#fresh-record resume: mid-walk crash → resume with EMPTY completedNodeIds + current key → safe double-rotation → revocation cut"
        status: unknown
    human_judgment: true
    rationale: "Same as D1 — AUTHOR ONLY per objective; live-run status not observed by this agent. Additionally flagging a genuine engineering scoping decision (see key-decisions) that the orchestrator/user should validate on the actual live run: the test uses a childless (single file node) rotation root rather than a multi-level tree, based on a cryptographic-timing analysis of the engine's D-02/D-09 out-of-band re-seal that concluded a multi-level 'mid-walk' crash cannot converge via this exact resume mechanism without an unrelated AEAD mismatch. This reasoning was not empirically verified against the live engine — only reasoned from reading engine.ts's source directly."
  - id: D4
    description: "Test 4 asserts the pre-rotation grant is cut (behind-retry) both immediately after the crash-run's root commit AND after the resume's root step, and that a freshly issued grant using the resume's new key navigates successfully"
    requirement: "SC#3"
    verification:
      - kind: e2e
        ref: "tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts#fresh-record resume: mid-walk crash → resume with EMPTY completedNodeIds + current key → safe double-rotation → revocation cut — revokedNav4/revokedNavAfterResume/postResumeNav4 assertions"
        status: unknown
    human_judgment: true
    rationale: "Same as D1 — live-run status not observed by this agent."

# Metrics
duration: 55min
completed: 2026-07-07
status: complete
---

# Phase 70 Plan 08: Strengthen Concurrent-Add E2E and Add Genuine Fresh-Record-Resume E2E Summary

**Strengthened the concurrent-add CAS-409 merge e2e (test 3) to navigate+unseal the pre-existing rotated child with the new root key, and added a new mid-walk-crash e2e (test 4) proving genuine fresh-record resume with empty completedNodeIds converges via safe double-rotation — both authored and typechecked only, live-stack run deferred to the orchestrator's phase gate**

## Performance

- **Duration:** 55 min
- **Started:** 2026-07-07T21:05:00Z
- **Completed:** 2026-07-07T22:00:00Z
- **Tasks:** 2
- **Files modified:** 1

## IMPORTANT: Live run deferred to orchestrator

Per this plan's explicit AUTHORING-only objective, this executor did **not** run
`docker compose -f docker/docker-compose.yml up -d`, did **not** start the local API,
and did **not** run `pnpm --filter sdk-e2e test -- rotation-crash-safety`. The only
verification performed was:

1. `pnpm --filter @cipherbox/sdk-core build` — succeeded (tsup + tsc, 0 errors).
2. `pnpm --filter @cipherbox/sdk build` — succeeded (tsup + tsc, 0 errors).
3. `pnpm --filter @cipherbox/sdk-e2e exec tsc --noEmit -p tsconfig.json` — **0 errors**
   in `rotation-crash-safety.test.ts` (the file's only errors before AND after this
   plan's changes are 3 pre-existing, unrelated `TS18048` errors in
   `bin-operations.test.ts`, confirmed via `git status --short` showing that file was
   never touched by this plan).
4. `npx eslint tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` — 0 findings,
   both after Task 1 and after Task 2.

The actual pass/fail of both the strengthened test 3 and the new test 4 against the
live docker stack + local API has **not been observed** by this agent. The
orchestrator (or a human) must run the live suite to close this loop — see the
`coverage:` block's `human_judgment: true` entries for the precise deferred items.

## Accomplishments

- **Test 3 (concurrent-add merge) strengthened:** after the CAS-409 merge completes,
  the test now derives subfolder3's readKey via `unsealChildReadKey` against the new
  root key (`readKeyPrimeRoot3`) and calls `unsealNode` against subfolder3's ACTUAL
  published (post-rotation) body — an assertion that AEAD-fails under the old
  remote-wins merge (which would leave subfolder3's `SealedChildRef.readKeySealed`
  pointing at its stale pre-rotation key) and succeeds under this phase's local-wins
  fix. The prior assertion (`childIpnsNames.toContain(sub3IpnsName)`) only checked
  name membership, which cannot distinguish the two policies since both preserve the
  entry — only the wrapped key differs.
- **Fail-fast injection guard added to test 3:** a `concurrentInjectionRan` boolean is
  now asserted `true` after the walk completes, plus an explicit
  `persistCall3Count === 3` assertion, so a future refactor that silently skips the
  concurrent-write injection cannot make this test vacuously pass.
- **New test 4 (genuine fresh-record resume, mid-walk crash):** a single-node
  (file-kind, childless) rotation root crashes on the FIRST `persistCallback` call
  (immediately after its own commit) — strictly earlier than test 2's 4th/final-call
  crash. Resume uses a BRAND-NEW `RotationJobRecord` with `completedNodeIds: new
  Set()` (not seeded from the crash-time job) and the CURRENT valid `rootReadKey`
  (captured via the suite's existing `crypto.getRandomValues` spy, mirroring test 2's
  established capture pattern — NOT the original pre-crash-run key, which would fail
  the entry gate's stale-key probe). The resume converges without throwing, root goes
  from generation 1 → 2 (safe double-rotation, the opposite of test 2's
  no-double-bump case), and the pre-rotation grant is confirmed `behind-retry` both
  immediately after the crash and again after the resume's root step. A freshly
  issued grant using the resume's returned key navigates `ok`.

## Task Commits

1. **Task 1: Strengthen concurrent-add test 3 (navigate + unseal the concurrent-added subtree)** - `3c71d6664` (test)
2. **Task 2: New genuine fresh-record-resume (mid-walk crash) e2e** - `fc4c5dcc2` (test)

## Files Created/Modified

- `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` - Strengthened test 3 with a
  navigate+unseal assertion and a fail-fast injection guard; added test 4 (genuine
  fresh-record resume, mid-walk crash); updated the file-header doc comment to
  describe both changes and the childless-root design rationale for test 4;
  imported `unsealChildReadKey` from `@cipherbox/core`.

## Decisions Made

See frontmatter `key-decisions` for the full list. The most consequential decision —
and the one most worth the orchestrator's attention before/during the live gate run
— is **test 4's childless (single-file-node) rotation root**. This was not an
arbitrary simplification; it follows from tracing the engine's exact D-02/D-09
out-of-band re-seal ordering (`packages/sdk-core/src/rotation/engine.ts` lines
~1339-1470):

- A parent's `SealedChildRef[...].readKeySealed` entries for its children are only
  re-wrapped under the parent's OWN new key once that parent's batched D-09
  republish fires — which happens atomically, only after ALL of that parent's
  pending children have committed, with no intervening `persistCallback` checkpoint
  reachable via this suite's fault-injection hook.
- Therefore any crash point strictly before a node's OWN D-09 fires leaves that
  node's children mirror wrapped under the node's PRE-rotation key. A resume that
  supplies the node's POST-rotation "current" key (required for the entry gate's
  own PROBE to succeed) cannot re-derive those children's keys — `unsealChildReadKey`
  AEAD-fails, and neither `verifySubtreeClean`'s recursive walk nor the "Normal
  path" walk's own children-enqueue loop catches this failure (no try/catch wraps
  either call site) — the whole `rotateReadFromNode` call would throw uncaught.
- This is exactly the same class of "genuinely lost key, no cryptographic recovery"
  window RESEARCH.md's Pitfall 4 documents, just recurring at every tree level
  (not only at the root). A multi-level tree therefore has NO crash point strictly
  between "root's own commit" and "the walk's final persist" that is
  cryptographically safe to resume via this exact mechanism, for ANY node that has
  children.
- A childless root sidesteps this window entirely (there are no children to
  mis-derive) while still proving the literal thing SC#3's entry-gate restructuring
  targets: a fresh job record with EMPTY `completedNodeIds` must not get stuck
  skip-gated, and must converge via safe double-rotation using whatever key is
  genuinely current — which test 4 proves end-to-end against the live crypto stack.

This reasoning was derived entirely from static source reading (this agent could not
run the live suite to empirically confirm a riskier multi-level design would actually
fail as predicted). If the orchestrator's live run of test 4 passes as authored, this
reasoning is validated. If a reviewer believes a multi-level dirty-tail e2e recovery
is still achievable, that would require either a different fault-injection mechanism
than the existing `persistCallback` hook, or accepting a test that only converges
because `resolveChildKeyAndEnvelope`/`collectDirtyFrontier` gain a try/catch not
present in the codebase as of Plan 70-06/70-07 — an engine.ts change outside this
plan's scope (`tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` only).

## Deviations from Plan

None — plan executed exactly as written for both tasks. The childless-root design
choice for test 4 is a fixture/scenario-construction decision made WITHIN Task 2's
stated scope ("resume by calling rotateReadFromNode again with a BRAND-NEW
RotationJobRecord... converges... the revoked recipient is cut") — the plan's
acceptance criteria do not mandate a specific tree shape, only the resume semantics
and outcomes, all of which are satisfied. This is documented prominently above (not
buried) because it is the single largest judgment call in this plan, made without the
ability to empirically verify it via a live run.

## Issues Encountered

None during authoring. The extensive cryptographic-timing analysis described above
(D-02/D-09 re-seal ordering vs. this suite's persistCallback-only fault-injection
granularity) was necessary to avoid authoring a test that would provably fail on the
live gate — a multi-level "mid-walk, some D-09s fired, others not" tree was
considered and rejected for test 4 specifically because it would hit an uncaught AEAD
mismatch during `verifySubtreeClean`'s traversal, per direct reading of
`resolveChildKeyAndEnvelope`/`collectDirtyFrontier` (neither has a try/catch around
`unsealChildReadKey`).

## User Setup Required

None - no external service configuration required. The orchestrator DOES need to
bring up `docker compose -f docker/docker-compose.yml up -d` and
`pnpm --filter @cipherbox/api dev` before running the live gate, per the suite's own
file-header prerequisites (unchanged by this plan).

## Next Phase Readiness

This is the last plan in Phase 70's execution wave (wave 6, `depends_on: 70-07`).
The sdk-e2e `rotation-crash-safety` suite now has 4 scenarios (happy-path,
abort-and-resume, concurrent-add [strengthened], fresh-record-resume [new]) covering
SC#1 and SC#3 at the only real client→API IPNS round-trip in the codebase. The
orchestrator must run `pnpm --filter sdk-e2e test -- rotation-crash-safety` against
the live docker stack + local API to close the phase gate — this is the single
remaining verification step for Phase 70 as a whole, per 70-RESEARCH.md's own test
architecture ("Phase gate: Full sdk-e2e suite green ... before `/gsd-verify-work`").
If test 4 unexpectedly fails on the live run, the most likely culprit (per the
Decisions Made analysis above) is a subtle timing assumption about exactly when
`persistCallback` fires relative to `mintFileKeyOnRotate`'s own `generateRandomBytes`
call for a file-kind root — re-verify `capturedReadKeys[0]` is genuinely the
`readKeyPrime` (not the `fileKeyPrime`) by adding a temporary
`console.error(capturedReadKeys.length)` probe before further debugging.

---
*Phase: 70-rotation-soundness-deep-merge-fresh-record-resume-and-durabl*
*Completed: 2026-07-07*

## Self-Check: PASSED

Both created/modified artifacts found on disk (`tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts`,
this SUMMARY.md); both task commits (`3c71d6664`, `fc4c5dcc2`) verified present in git log.
