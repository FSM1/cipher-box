---
phase: 70
slug: rotation-soundness-deep-merge-fresh-record-resume-and-durable-floor-concurrency
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-07
---

# Phase 70 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from 70-RESEARCH.md "Validation Architecture". This phase is todo-driven (phase_req_ids is null); the six Success Criteria (SC#1–SC#6) function as the requirement set. Task IDs are assigned by the planner — rows below are keyed by SC and inherit the plan/task that covers them.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (TS unit)** | Vitest — `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts` (coverage excludes `src/**/index.ts`; keep `engine.ts` out of any barrel) |
| **Framework (Rust unit)** | `cargo test` / `#[tokio::test]` — extend `#[cfg(test)]` blocks in `crates/sdk/src/rotation/high_water.rs` and `crates/sdk/src/floor_store.rs` |
| **Framework (e2e)** | Vitest live-stack — `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk-core test -- rotation` + `cargo test -p cipherbox-sdk rotation` |
| **Full suite command** | full `sdk-core`/`sdk` vitest + `cargo test -p cipherbox-sdk` + `pnpm --filter sdk-e2e test -- rotation-crash-safety` |
| **Estimated runtime** | ~30s TS unit + ~15s Rust unit; sdk-e2e requires docker stack (multi-minute) |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test -- rotation` + `cargo test -p cipherbox-sdk rotation`
- **After every plan wave:** Run full `sdk-core`/`sdk` vitest + full `cargo test -p cipherbox-sdk` + sdk-e2e rotation-crash-safety (docker stack up)
- **Before `/gsd-verify-work`:** Full sdk-e2e suite green (all 3 existing scenarios + the new genuine-fresh-resume scenario)
- **Max feedback latency:** ~45 seconds for the unit tier; sdk-e2e is a per-wave/phase-gate cost

---

## Per-Task Verification Map

| SC | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|----|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| SC#1 | 1 | Local-wins rotation merge preserves rotated child readKeySealed | T-70 EoP (merge downgrade) | Revoked reader cannot regain access via merge downgrade; authorized reader stays navigable | unit | `pnpm --filter @cipherbox/sdk-core test -- rotation/merge` | ❌ W0 (new `rotation/merge.test.ts`) | ⬜ pending |
| SC#1 | 2 | e2e: navigate into concurrent-added subtree, unseal with new root key | T-70 EoP | Existing rotated child still navigable after concurrent-add CAS-409 merge | e2e | `pnpm --filter sdk-e2e test -- rotation-crash-safety` (test 3, strengthened) | ✅ extend | ⬜ pending |
| SC#2 | 1 | `verifySubtreeClean` recurses full subtree; missing root ⇒ dirty | — | Resume never treats an unresolved/missing root as clean | unit | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` | ✅ extend | ⬜ pending |
| SC#3 | 1 | `rotateOne` returns merged (incl. remote-added) children | — | Concurrent adds get enqueued into the BFS, not just preserved | unit | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` | ✅ extend | ⬜ pending |
| SC#3 | 2 | Genuine fresh-record resume (empty completedNodeIds, no pre-seeded keys) | — | Fresh record + current rootReadKey converges via safe double-rotation | e2e | `pnpm --filter sdk-e2e test -- rotation-crash-safety` (new mid-walk-crash test) | ❌ W0 (new test) | ⬜ pending |
| SC#3 | 1 | Missing job record does not desync `pendingChildCount` | V5 Input Validation | Missing IPNS/envelope record is fail-closed / accounted, not silently skipped | unit | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` | ❌ W0 (new test) | ⬜ pending |
| SC#4 | 1 | `grantCallbacks` reaches `reMintGrantsRootedAt` via public `rotateReadFromNode` | V4 Access Control | Inner-grant re-mint fires in the real walk, not just direct-injection tests | unit | `pnpm --filter @cipherbox/sdk-core test -- rotation/engine` | ❌ W0 (new test) | ⬜ pending |
| SC#5 | 1 | Rust: concurrent bump/put same+different node_id preserve monotonic-max, no lost updates | T-70 Tampering (rollback) | Atomic compare-and-set; no lost update under async concurrency | Rust `#[tokio::test]` | `cargo test -p cipherbox-sdk floor_store` | ❌ W0 (new test) | ⬜ pending |
| SC#5 | 1 | Rust: `JsonSidecarFloorStore` no blocking I/O on async executor | — | fs work in `spawn_blocking`; lock held only around load-modify-write | Rust static review | manual (`spawn_blocking` presence) | N/A | ⬜ pending |
| SC#5 | 1 | Corrupt sidecar fails closed (not `unwrap_or_default`) | T-70 Tampering | Unparseable sidecar rejects rather than silently cold-starting | Rust unit | `cargo test -p cipherbox-sdk floor_store` | ❌ W0 (new test) | ⬜ pending |
| SC#5 | 1 | TS parity: `idbPut` already max-preserving atomic; TS `bumpFloor` cross-store race addressed | — | TS and Rust behaviorally equivalent | doc/manual + unit if code changes | `pnpm --filter @cipherbox/sdk test -- rotation-high-water` | ✅ (extend if changed) | ⬜ pending |
| SC#6 | 1 | `rotationResult.readKey` zeroed by terminal owner after defensive copy | T-70 self-DoS (callee-zeroes-shared-buffer) | Terminal-owner zeroization; caller-owned buffers untouched | unit | `pnpm --filter @cipherbox/sdk test -- rotation` | ✅ locate+extend | ⬜ pending |
| SC#6 | 1 | `activeRootNodeId` → per-root `Set`; badge resets only when set drains | — | Concurrent multi-root rotations do not misclassify each other | web-e2e / extracted-logic unit | `pnpm --filter web test:e2e -- rotation` (existing 68-10 spec, extend) | ✅ locate+extend | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/__tests__/rotation/merge.test.ts` — new tests for `mergeRotatedChildren` (local-wins / remote-only-add / base-only-drop)
- [ ] `engine.test.ts` — new cases: merged-children return threading (SC#1↔SC#3), full-recursion `verifySubtreeClean` with a multi-level fixture (SC#2), `grantCallbacks` reachability via `rotateReadFromNode` (SC#4), `pendingChildCount` accounting on a missing-record path (SC#3)
- [ ] `rotation-crash-safety.test.ts` — new e2e for genuine fresh-record resume (crash mid-walk, earlier fault-injection than the existing 4th-persistCallback crash) + strengthen test 3 to navigate+unseal the concurrent-added subtree
- [ ] `crates/sdk/src/floor_store.rs` `#[cfg(test)]` — concurrent same-node_id put, concurrent different-node_id put, corrupt-sidecar fail-closed
- [ ] Locate during planning (grep): the client-side rotation test file (SC#6 zeroization) and the 68-10 web-e2e rotation-ux spec (SC#6 badge)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Rust `spawn_blocking` keeps the tokio executor non-blocking | SC#5 | No cheap automated perf assertion for "does not block executor" | Static review: confirm all sync fs `read`/`write`/`rename`/`fsync` in `JsonSidecarFloorStore` run inside `tokio::task::spawn_blocking`, and the `tokio::sync::Mutex` is held only around load-modify-write |
| Genuinely-lost-root-key crash window surfaces `RootKeyStaleError` (documented residual, not full recovery) | SC#3 (narrowed scope, Open Q1) | The unrecoverable window has no client-side cryptographic recovery; verified by fault-injection + error-type assertion, but the top-down re-nav fallback completeness (Open Q2) needs a manual code trace | Assert the resume probe surfaces a distinct `RootKeyStaleError` (not a generic AEAD failure) when `rootReadKey` is stale; document the top-down re-nav fallback residual per Open Q2 |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s (unit tier)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
