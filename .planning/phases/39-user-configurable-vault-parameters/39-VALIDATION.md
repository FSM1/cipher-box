---
phase: 39
slug: user-configurable-vault-parameters
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-31
---

# Phase 39 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------- |
| **Framework**          | vitest (packages), Playwright (web-e2e)                                                     |
| **Config file**        | `packages/core/vitest.config.ts`, `packages/sdk/vitest.config.ts`                           |
| **Quick run command**  | `pnpm --filter @cipherbox/core test -- --run`                                               |
| **Full suite command** | `pnpm --filter @cipherbox/core test -- --run && pnpm --filter @cipherbox/sdk test -- --run` |
| **Estimated runtime**  | ~15 seconds                                                                                 |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/core test -- --run`
- **After every plan wave:** Run full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement          | Test Type   | Automated Command                               | File Exists | Status     |
| -------- | ---- | ---- | -------------------- | ----------- | ----------------------------------------------- | ----------- | ---------- |
| 39-01-01 | 01   | 1    | VaultSettings type   | unit        | `pnpm --filter @cipherbox/core test -- --run`   | ❌ W0       | ⬜ pending |
| 39-01-02 | 01   | 1    | HKDF derivation      | unit        | `pnpm --filter @cipherbox/crypto test -- --run` | ❌ W0       | ⬜ pending |
| 39-02-01 | 02   | 1    | Settings store       | unit        | `pnpm --filter @cipherbox/core test -- --run`   | ❌ W0       | ⬜ pending |
| 39-03-01 | 03   | 2    | Settings load        | unit        | `pnpm --filter @cipherbox/sdk test -- --run`    | ❌ W0       | ⬜ pending |
| 39-04-01 | 04   | 2    | Consumer integration | integration | `pnpm --filter web test -- --run`               | ❌ W0       | ⬜ pending |
| 39-05-01 | 05   | 3    | Settings UI          | visual      | Playwright MCP verification                     | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/core/src/__tests__/vault-settings.test.ts` — type validation, defaults, range clamping
- [ ] `packages/crypto/src/__tests__/vault-settings-derive.test.ts` — HKDF derivation produces stable keypair

_Existing infrastructure (vitest, IPNS test helpers) covers framework needs._

---

## Manual-Only Verifications

| Behavior                  | Requirement     | Why Manual     | Test Instructions                                    |
| ------------------------- | --------------- | -------------- | ---------------------------------------------------- |
| Settings UI visual layout | UI correctness  | Visual check   | Navigate to Settings > Vault tab, verify form layout |
| Cross-session persistence | IPNS round-trip | Requires login | Save settings, logout, login, verify settings loaded |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
