---
phase: 70
extracted: 2026-07-08
---

# Phase 70 — Learnings

## Surprises

- **The sdk-e2e gate caught a real over-reach that all unit tests + typecheck missed.** Plan 70-04 spec'd "enqueue the concurrently-added child onto the BFS frontier for its own `rotateOne` pass." That shipped GREEN-only (unit tests mocked the boundary), and 70-08 was author-only. The FIRST real execution — the live `rotation-crash-safety` round-trip — threw `rotateOne: no valid IPNS private key`, revealing the child needed a write key the rotating party structurally may not hold, plus an orphaned parent pointer. **Lesson:** for cross-writer / key-lifecycle behavior, the live sdk-e2e round-trip is the only gate that counts; a GREEN-only plan + author-only e2e is an unverified path, not a proven one.

## Decisions

- **Merge-and-re-seal, not rotate, for concurrent adds.** The authoritative spec (ROT-05 "never dropped", design §4.5 "picked up, full re-key is a follow-on") says a concurrently-added child's `SealedChildRef` is re-sealed under the parent's new readKey — which needs only the parent's old+new readKeys, NOT the child's write key. Rotating the child's own node in-walk was the over-reach. Fix: `createConcurrentAddResealingMerge`.
- **Hard-guard vs accept for same-seq/CID equivocation is decidable only by tracing the TEE contract** (carried over to Phase 71 D-09): once Phase 67 made the TEE a lease-renewer that structurally cannot repoint a CID, same-seq+different-CID became provably anomaly-only → hard-guard is safe. Pattern: resolve "reject vs accept" ambiguities by proving what the trusted component can/can't emit, not by guessing.

## Patterns

- **Local-wins `createConcurrentAddResealingMerge` must be the ONLY merge at rotation republish sites** (`engine.ts` `decrementPendingAndMaybeRepublish`). A remote-wins fallback there re-opens the revocation bypass (a concurrent writer re-adopts the pre-rotation seal → revoked reader stays navigable). Security-load-bearing invariant — re-audit on any change to the republish merge wiring.
- **Terminal-owner zeroization ownership must be traced, not assumed.** The dirty-frontier fix required proving that an *adopted* frontier item shares its `nodeReadKey` reference with the queued item (zeroed once by the BFS `finally`), while a *dropped/deduped* item owns its buffer and must be zeroed on the early return. Wrong-side zeroing has broken 48/89 E2E historically.

## Process

- **On Claude Code, run manager plan/execute inline, not backgrounded.** A backgrounded plan agent switched the shared checkout's branch mid-flight, stranding a parallel phase's artifacts. Sequential (no-worktree) executor dispatch was chosen over parallel worktrees for reliability — the only parallelism lost was one 3-plan wave, versus the worktree merge/cleanup corruption surface.
- **A childless-root e2e fixture that "sidesteps" a failure mode is a smell.** 70-08's author-only executor made Test 4's root childless to avoid an uncaught AEAD failure it reasoned about but couldn't run. The live gate later proved the multi-level path via Test 3 once the engine was fixed — but the childless workaround would have masked the real bug if Test 3 hadn't also been strengthened.
