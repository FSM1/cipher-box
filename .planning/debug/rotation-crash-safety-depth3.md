---
status: investigating
trigger: "DATA_START\nDiagnose two failing sdk-e2e tests in Phase 70.1 rotation crash-safety:\nTest 5 'depth-3 fan-out>=2 mid-walk crash at a DEEP child resumes and converges (D-10 anti-vacuous gate)' fails at rotation-crash-safety.test.ts:1298 (expect(resumeError5).toBeUndefined()) with CryptoError: Decryption failed thrown by resume rotateReadFromNode.\nTest 6 'multi-dirty-edge: 2 siblings published while parent batch still open resumes via a single batched repair' fails at line ~1549 with the same error.\nThe 4 pre-existing depth-2 tests pass; only the 2 new depth-3 fixtures (plan 70.1-10) fail.\nDATA_END"
created: 2026-07-08T20:00:00Z
updated: 2026-07-08T20:15:00Z
---

<!-- VERDICT: PRODUCT BUG, root cause confirmed with live instrumentation. No fix applied
     per task instructions (stop and report; orchestrator decides). No commits made.
     Working tree restored to the pre-investigation state (git diff empty). -->

## Current Focus

hypothesis: CONFIRMED. collectDirtyFrontier (engine.ts) decrypts a child's SealedChildRef.readKeySealed via resolveChildKeyAndEnvelope BEFORE checking dirtiness (childPub.generation > childRef.generation). For a genuinely dirty edge whose IMMEDIATE PARENT has ALSO rotated in the same walk (parent's own key changed) but whose OWN batched re-seal of that child's ref has not fired yet, the child ref ciphertext is still wrapped under the parent's OLD key while collectDirtyFrontier calls unsealChildReadKey with the parent's NEW (current) key -> AEAD decrypt genuinely fails. This is a PRODUCT bug in the dirty-frontier detection order of operations, not a fixture bug.
test: DONE — temporary fingerprint-only console diagnostics added to resolveChildKeyAndEnvelope in engine.ts, sdk-core+sdk dist rebuilt, both failing tests re-run, instrumentation captured, then REVERTED (git diff clean) and dist rebuilt back to matching committed source.
expecting: N/A — confirmed.
next_action: NONE — this is a PRODUCT bug. Per task instructions, do not modify product code or the test to force a pass. Report to orchestrator for a decision on the recommended fix below.

## Verdict: PRODUCT BUG (not a fixture bug)

Confirmed via live instrumentation (see Evidence below) — the dirty-frontier
detection logic in `packages/sdk-core/src/rotation/engine.ts` has a genuine
order-of-operations bug: it attempts to DECRYPT a child's `SealedChildRef`
before checking whether that edge is dirty, but a genuinely-dirty edge is BY
DEFINITION not decryptable with the parent's post-rotation key when the
parent's own key changed in the same walk (which is the normal case for a
full-subtree rotation). The unit-test suite for this code masked the bug
because it mocks `unsealChildReadKey` to unconditionally succeed regardless
of which key is passed in (see Evidence entry below) — so this class of bug
was structurally unreachable by any unit test, and the depth-3/multi-dirty-edge
sdk-e2e fixtures (Plan 70.1-10, real crypto, real IPFS/IPNS) are the first
test in the whole repo to exercise it.

## Symptoms

expected: Test 5 and Test 6 resume (`rotateReadFromNode` on a fresh job record seeded with crash-time completedNodeIds) should converge without throwing, mirroring the deferred D-09 batch and consuming the ECIES key checkpoint for the dirty node(s).
actual: Resume throws `CryptoError: Decryption failed` (code DECRYPTION_FAILED) before any repair happens — caught by the test's try/catch, surfaced via `expect(resumeError5).toBeUndefined()` failing.
errors: "CryptoError: Decryption failed" { code: 'DECRYPTION_FAILED' } — thrown during the `rotateReadFromNode` resume call.
reproduction: cd tests/sdk-e2e; set -a; . ./.env; set +a; npx vitest run --no-coverage rotation-crash-safety -t "depth-3 fan-out" (also -t "multi-dirty-edge" for test 6). Live docker stack + API required.
started: introduced by Plan 70.1-10's two new depth-3/multi-dirty-edge fixtures; the 4 pre-existing depth-2 tests in the same suite pass.

## Eliminated

(none yet — first hypothesis pending confirmation via instrumentation)

## Evidence

- timestamp: 2026-07-08T20:05:00Z
  checked: Read full rotation-crash-safety.test.ts (tests 1-6) and packages/sdk-core/src/rotation/engine.ts (rotateOne, rotateReadFromNode BFS, verifySubtreeClean, collectDirtyFrontier, resolveChildKeyAndEnvelope, repairDirtyNode).
  found: Test 5 tree: root5 -> [subA5, subB5] (fan-out 2), subA5 -> [fileA5] (depth 3). Crash at persistCallback call 4 = right after fileA5's own commit, BEFORE subA5's own D-09 batch (which would re-seal fileA5's ref in subA5's children mirror and republish subA5). At crash time: root5's OWN batch (mirroring subA5+subB5) ALREADY fired (call 3, when both direct children finished) — so root5->subA5 edge is CLEAN (root5's mirror of subA5 is up to date, sealed under root5's NEW key). But subA5's OWN mirror of fileA5 is STALE — still sealed under subA5's OLD (pre-rotation) key, since subA5's own batched republish never fired.
  implication: verifySubtreeClean(root5IpnsName, readKeyPrimeRoot5) recurses: root5->subA5 edge decrypts fine (clean, root5's mirror up to date) yielding subA5's CURRENT (post-rotation) readKey. Recursing into subA5's children, collectDirtyFrontier calls resolveChildKeyAndEnvelope(fileA5ref, subA5's CURRENT/NEW readKey) — but fileA5ref.readKeySealed is still wrapped under subA5's OLD (pre-rotation) key. AEAD key mismatch -> unsealChildReadKey throws Decryption failed BEFORE the childPub.generation > childRef.generation dirtiness check ever runs.

- timestamp: 2026-07-08T20:06:00Z
  checked: Test 6 tree/crash-timing: root6 -> [c1_6, c2_6] (fan-out 2, both files, depth 2). Crash at persistCallback call 3 = right after c2_6's own commit, BEFORE root6's own D-09 batch (which only fires once BOTH children finish — c1_6 finished at call 2 but did not trigger republish since pendingChildCount was still 1; c2_6 finishing at call 3 would have triggered it, but the crash fires before that decrement/republish runs).
  found: At crash time, root6's OWN published body (from its own rotateOne commit at call 1) still has children=[c1_6ref, c2_6ref] BOTH sealed under root6's OLD (pre-rotation) key — root6's D-09 batch never ran for either child.
  implication: Same root cause as test 5, but manifesting one level shallower: verifySubtreeClean(root6IpnsName, readKeyPrimeRoot6) itself (the TOP level of the walk) tries resolveChildKeyAndEnvelope(c1_6ref, root6's CURRENT/NEW key) — but c1_6ref is sealed under root6's OLD key. Same AEAD mismatch, same throw site (collectDirtyFrontier's first-level loop this time, not a recursive call).

- timestamp: 2026-07-08T20:07:00Z
  checked: Unit test packages/sdk-core/src/__tests__/rotation/engine.test.ts "verifySubtreeClean — full-subtree recursion (Plan 70-05 SC#2)" Test 1 (depth-2 dirty grandchild) and Test 3 (clean multi-level).
  found: `mockFns.unsealChildReadKey.mockImplementation(async (sealed) => { if (sealed === 'subfoldersealed==') return ...; if (sealed === 'grandchildsealed==') return ...; throw ... })` — the mock ignores the `parentReadKey` argument entirely and unconditionally "succeeds" based only on the ciphertext string, regardless of which key is passed in.
  implication: The existing (passing) unit-test suite for verifySubtreeClean/collectDirtyFrontier can never catch a genuine AEAD key-mismatch on a dirty edge, because its crypto is mocked to always succeed. This explains why the depth>=2 "parent-also-rotated + own child-mirror stale" scenario was never caught before the live e2e fixtures (Plan 70.1-10) exercised REAL crypto. Confirms this is a previously-undetected product gap, not a fixture-only issue.

- timestamp: 2026-07-08T20:08:00Z
  checked: Ran `npx vitest run --no-coverage rotation-crash-safety -t "depth-3 fan-out"` against the live stack.
  found: Reproduced: `CryptoError: Decryption failed { code: 'DECRYPTION_FAILED' }` at test.ts:1298 exactly as reported. 4 pre-existing tests pass, test 5 fails as described.
  implication: Confirmed reproduction; matches task description exactly.

- timestamp: 2026-07-08T20:12:00Z
  checked: Instrumented `resolveChildKeyAndEnvelope` in engine.ts with fingerprint-only (SHA-256, first 4 bytes) console diagnostics around the `unsealChildReadKey` call; rebuilt sdk-core+sdk dist; re-ran test 5 and test 6 individually against the live stack.
  found: |
    Test 5 final two log lines before the throw:
      `OK ipnsName=...cij3y childId=829035cd... childPubGen=1 childRefGen=1 parentKeyFp=07375fc3` (subA5, resolved from root5's mirror — CLEAN: root5's mirror generation matches subA5's actual published generation, decrypts fine with root5's current/resume key)
      `FAIL ipnsName=...b0zb childId=4701aa2d... childPubGen=1 childRefGen=0 parentKeyFp=7c06b760 err=Decryption failed` (fileA5, resolved from subA5's mirror — childPubGen=1 [fileA5 actually published/rotated] vs childRefGen=0 [subA5's OWN mirror of fileA5 is STALE, still generation 0] — this IS the dirty edge, and the decrypt attempt against it, using subA5's CURRENT/NEW readKey [fp 7c06b760], throws BEFORE any generation comparison runs)
    Test 6 (single-level, root6 is itself the top of the walk): `FAIL ipnsName=...x85f childId=2c6e114d... childPubGen=1 childRefGen=0 parentKeyFp=9e5260a2 err=Decryption failed` — same signature, occurring in collectDirtyFrontier's very first loop over root6's own children (c1_6), since root6 itself already rotated and its own D-09 batch never fired for either child.
  implication: Directly confirms the hypothesis — in both tests, the throw occurs while attempting to unseal a SealedChildRef whose childRefGen is STALE (behind the child's actual published generation), i.e. exactly the case `collectDirtyFrontier` is supposed to detect as "dirty" via a plaintext generation comparison, but the code attempts an AEAD decrypt using the intermediate/root parent's CURRENT (post-rotation) key first — which cannot succeed against a ref still sealed under that parent's OLD (pre-rotation) key. No fallback/try-catch exists around this decrypt attempt in `collectDirtyFrontier`.
  code_path: |
    packages/sdk-core/src/rotation/engine.ts
      - `resolveChildKeyAndEnvelope` (~line 664): calls `unsealChildReadKey(childRef.readKeySealed, parentReadKey, ...)` unconditionally, with no try/catch, before any caller has compared `childPub.generation` vs `childRef.generation`. `childPub.generation` is available from `resolveAndFetchNode` alone (plaintext AAD field, no decryption needed) — the dirtiness check does NOT require decrypting the ref at all.
      - `collectDirtyFrontier` (~line 815-871): calls `resolveChildKeyAndEnvelope` as its FIRST step for every child, then only AFTER it returns does it check `childPub.generation > childRef.generation` (~line 828) to decide dirty vs clean. By the time that check would run, the throw has already propagated.
  instrumentation_reverted: true — `git diff --stat packages/sdk-core/src/rotation/engine.ts` is empty; sdk-core + sdk dist rebuilt from clean source after reverting.

## Resolution

root_cause: |
  `collectDirtyFrontier` (packages/sdk-core/src/rotation/engine.ts, ~line 815) determines whether a child edge is dirty by comparing `childPub.generation` (the child's actual published generation, fetched in plaintext via `resolveAndFetchNode` — no decryption needed) against `childRef.generation` (the parent's mirrored generation). But it derives BOTH values via a single `resolveChildKeyAndEnvelope` call (~line 664) that ALSO unconditionally attempts to decrypt `childRef.readKeySealed` with the parent's CURRENT readKey via `unsealChildReadKey`, with no try/catch, BEFORE the generation comparison ever runs.
  A genuinely dirty edge is, by construction, one whose `SealedChildRef.readKeySealed` has NOT yet been re-sealed to reflect the child's rotation — i.e. it is still AEAD-sealed under whatever the PARENT's readKey was when that ref was last written, not necessarily the parent's key AS OF THIS VERIFY CALL. When the parent has ALSO rotated in the same walk (the normal case for a full-subtree `rotateReadFromNode` — every node in the subtree rotates, including every intermediate parent), the parent's CURRENT key differs from the OLD key the stale ref is still sealed under. Decrypting with the current key genuinely, cryptographically fails — this is not a logic bug in the crypto, it is a bug in the ORDER of operations: the code must check plaintext dirtiness FIRST (no decrypt needed) and only attempt the decrypt on a CONFIRMED-clean edge.
  This exact class of bug (parent-also-rotated + parent's-own-child-mirror-stale) was never caught by the sdk-core unit-test suite for `verifySubtreeClean`/`collectDirtyFrontier` (Plan 70-05, `__tests__/rotation/engine.test.ts`) because those tests mock `unsealChildReadKey` to unconditionally succeed regardless of which key argument is passed in — masking exactly the AEAD-key-mismatch scenario that is fatal with real crypto. The Plan 70.1-10 depth-3/multi-dirty-edge sdk-e2e fixtures are the first tests in the repo to exercise `collectDirtyFrontier` against REAL crypto with a genuinely-dirty, parent-also-rotated edge — which is exactly why Phase 70's crash-safety gate previously "passed vacuously" (per this suite's own file-header comment) and why this bug surfaced only now.
fix: |
  NOT APPLIED (product bug — per task instructions, stopping here for orchestrator decision rather than hacking product code).
  Recommended fix direction: restructure `collectDirtyFrontier` (and its use of `resolveChildKeyAndEnvelope`) to check dirtiness BEFORE attempting decryption:
    1. Fetch `childPub` via the existing `resolveAndFetchNode(childRef.ipnsName, ctx)` alone (no decrypt) — already have everything needed (`childPub.generation`) to compare against `childRef.generation`.
    2. If `childPub.generation > childRef.generation` (dirty): push a `DirtyFrontierItem` WITHOUT calling `unsealChildReadKey` at all (it is not guaranteed to succeed, and is not needed — `repairDirtyNode`, the consumer of dirty items when `keyCheckpointCallbacks` is wired, already recovers the correct key via the ECIES checkpoint plane keyed by `childPub.id`, never via `item.nodeReadKey`). `DirtyFrontierItem.nodeReadKey` would need to become optional (or use an explicit zero-filled placeholder, mirroring `enqueueDirtyFrontierItem`'s existing `readKeySealed: ''` placeholder pattern) for this path.
    3. Only if CLEAN, call `unsealChildReadKey` (expected to succeed, since a clean edge's ref is by definition sealed under the parent's current key) and recurse into folder children as today.
  This preserves the legacy (no-`keyCheckpointCallbacks`) fallback contract note (RESEARCH.md Pitfall 4 — a dirty edge whose immediate parent has also rotated is genuinely unrecoverable WITHOUT the checkpoint plane) while making the scenario RECOVERABLE when `keyCheckpointCallbacks` IS wired (this phase's whole point) — currently the bug prevents the checkpoint-repair path (`repairDirtyNode`) from ever being reached at all, because `verifySubtreeClean` throws before `rotateReadFromNode` gets a chance to route to it.
  Secondary consideration: `findParentNodeByIpnsName` (~line 702) also calls `resolveChildKeyAndEnvelope` while walking down from root to find an arbitrary dirty item's real parent, skipping non-folder children — it should be safe today since it only descends via provably-clean edges reachable from a `DirtyFrontierItem`'s parent chain, but should be re-audited once `collectDirtyFrontier` is fixed, in case a tree with MULTIPLE independent dirty edges at different depths causes it to walk through a folder that itself has an unrelated dirty child.
verification: NOT APPLICABLE — no fix applied; both tests still fail (as designed, since no product change was made). Confirmed via re-run after reverting instrumentation that source/dist are clean and match the pre-investigation committed state (git diff of engine.ts is empty).
files_changed: []
