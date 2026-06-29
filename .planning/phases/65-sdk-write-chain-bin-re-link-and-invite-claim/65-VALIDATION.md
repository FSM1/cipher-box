---
phase: 65
slug: sdk-write-chain-bin-re-link-and-invite-claim
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-30
---

# Phase 65 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest (sdk-core unit, sdk unit, sdk-e2e integration) |
| **Config file** | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, `tests/sdk-e2e/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/core test run` / `pnpm --filter @cipherbox/sdk-core test run` / `pnpm --filter @cipherbox/sdk test run` |
| **Full suite command** | `pnpm test` |
| **Estimated runtime** | ~seconds for unit; sdk-e2e requires docker stack + API dev server (redis 6380) |

---

## Sampling Rate

- **After every task commit:** Run the relevant package quick run command (`pnpm --filter @cipherbox/<pkg> test run`)
- **After every plan wave:** Run `pnpm test` for the touched packages
- **Before `/gsd-verify-work`:** Full suite must be green; the sdk-e2e write-chain rotation round-trip (D-04 gate) must pass against a live API
- **Max feedback latency:** ~30 seconds for unit feedback (sdk-e2e is gated by stack startup, not run every task)

---

## Per-Task Verification Map

> Filled by the planner / Nyquist auditor once PLAN.md task IDs exist. Anchored to RESEARCH.md `## Validation Architecture`.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 65-XX-XX | XX | 1 | WRITE-01 | — | Read-only holder (only `readDescriptorRef`) cannot unseal the write-body / reach signing material | unit | `pnpm --filter @cipherbox/core test run` | ❌ W0 | ⬜ pending |

Status legend: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky

---

## Wave 0 Requirements

- [ ] `packages/core/src/__tests__/node/seal.test.ts` — add `sealChildWriteKey` / `unsealChildWriteKey` role `0x04` KAT cases
- [ ] `packages/sdk/src/__tests__/shared-write.test.ts` — rewrite for the write-body model (current test targets the pre-v3 mocked API)
- [ ] `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` — unit tests for the write-revocation driver with mocked tombstone/persist callbacks
- [ ] `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` — new D-04 gate: real write-chain rotation round-trip (new k51 per node, parent re-point cascade to share root, tombstone-intent)
- [ ] Un-skip the `addToBin` / `restoreFromBin` Phase-65 `describe.skip` blocks in `packages/sdk/src/__tests__/bin.test.ts` and update fixtures

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Live apps/api tombstone enforcement (publish-gate reject, resolve 410) | WRITE-02 | Out of Phase-65 scope (D-02 holds the Phase-64 line); enforced live in Phase 66 | Mock-tested behind injected callbacks this phase; live verification deferred to Phase 66 |

*All in-scope Phase-65 behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s for unit
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
