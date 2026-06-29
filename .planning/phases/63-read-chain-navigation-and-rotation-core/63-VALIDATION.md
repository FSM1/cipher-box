---
phase: 63
slug: read-chain-navigation-and-rotation-core
status: ready
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-29
---

# Phase 63 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest |
| **Config file** | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, `tests/sdk-e2e/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk-core test` |
| **Full suite command** | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test` |
| **Estimated runtime** | ~60 seconds (unit); sdk-e2e round-trip requires the live local stack |

---

## Sampling Rate

- **After every task commit:** Run the task's `<automated>` command (mostly `pnpm --filter @cipherbox/sdk-core test --run <file>`)
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full unit suite must be green; the one sdk-e2e round-trip green against the live local stack
- **Max feedback latency:** 60 seconds (unit)

Note: every Wave-1 task and the first task of each later wave runs `pnpm --filter @cipherbox/core build` first to guard against Phase-62 codec dist staleness before sdk-core typecheck/test.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Secure Behavior | Test Type | Automated Command |
|---------|------|------|-------------|-----------------|-----------|-------------------|
| 63-01-01 | 01 | 1 | READ-02 | AAD-bound unseal fails closed on stale/replayed generation | tdd | `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts` |
| 63-01-02 | 01 | 1 | READ-02 | navigate returns typed `ok`/`behind-retry`/`revoked` (no ambiguous null) | tdd | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/share/navigate.test.ts` |
| 63-02-01 | 02 | 1 | READ-01, READ-05 | grant = one ECIES wrap of share-root readKey; zero node touches | tdd | `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core test --run src/__tests__/share/grant.test.ts` |
| 63-02-02 | 02 | 1 | READ-01, READ-05 | invite re-wrap: unwrap with ephemeral priv, re-wrap to claimer pub | tdd | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/share/grant.test.ts` |
| 63-03-01 | 03 | 1 | ROT-01 | rotateOne commits per-node via CAS before advancing frontier; zeroize minted readKey' only | tdd | `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` |
| 63-03-02 | 03 | 1 | ROT-01 | 4 Phase-64 seams throw (not silently no-op); clean path never trips them | tdd | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` |
| 63-04-01 | 04 | 2 | READ-03, READ-04 | add-item seals child readKey under parent readKey, no per-recipient fan-out | tdd | `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts` |
| 63-04-02 | 04 | 2 | READ-03, READ-04 | move within scope = link rewrites only, zero re-encryption | tdd | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts && pnpm --filter @cipherbox/sdk test --run src/__tests__/client-extended.test.ts` |
| 63-05-01 | 05 | 2 | ROT-02, READ-04 | scope-exit zero-rotation invariant: private delete → 0 rotateReadFromNode + 0 extra IPNS publishes (publish-call spy) | tdd | `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/scope.test.ts` |
| 63-05-02 | 05 | 2 | ROT-02, READ-04 | barrels export-only; engine.ts/scope.ts named files counted by coverage | execute | `pnpm --filter @cipherbox/sdk-core typecheck && pnpm --filter @cipherbox/sdk-core build` |
| 63-06-01 | 06 | 3 | READ-03 | `reWrapForRecipients` deleted; sdk add-item rewired to parent-key sealing | execute | `pnpm --filter @cipherbox/sdk typecheck 2>&1 \| tail -40` |
| 63-06-02 | 06 | 3 | READ-03 | `addShareKeys` callback type preserved (web wiring is Phase 68) | execute | `pnpm --filter @cipherbox/sdk typecheck && pnpm --filter @cipherbox/sdk test --run src/__tests__/enumerate-shared-subtree.test.ts` |
| 63-07-01 | 07 | 4 | READ-01, READ-02, ROT-01, ROT-02 | revoked grant cannot navigate after root-step rotation (live IPNS round-trip) | e2e | `docker compose -f docker/docker-compose.yml up -d && (pnpm --filter @cipherbox/api dev &) && <health-poll> && pnpm --filter @cipherbox/sdk-e2e exec vitest run --no-coverage src/suites/read-chain-navigation.test.ts` |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky — all rows ⬜ pending at plan time.*

---

## Wave 0 Requirements

Existing vitest infrastructure covers all phase requirements — no Wave 0 test-harness install needed. sdk-core and sdk already run vitest; `tests/sdk-e2e` already has a configured harness. The only runtime prerequisite (for the single 63-07 e2e task) is the live local stack: `docker compose -f docker/docker-compose.yml up -d` + `pnpm --filter @cipherbox/api dev` (API on :3000) + redis on 6380. The 63-07 `<automated>` command brings the stack up and health-polls `http://localhost:3000/health` before running.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| sdk-e2e read-chain round-trip | READ-01/02, ROT-01/02 | Requires the live local stack (docker + api dev + redis 6380); not run in PR CI (sdk-e2e is the cross-package publish gate, run locally) | Bring up the stack, then run the 63-07-01 `<automated>` command; assert pre-rotation grant navigates `ok`, post-root-rotation grant is NOT `ok` |

All other phase behaviors have automated unit verification.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (none — existing infra)
- [x] No watch-mode flags (all use `--run` / `vitest run`)
- [x] Feedback latency < 60s (unit)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-29
