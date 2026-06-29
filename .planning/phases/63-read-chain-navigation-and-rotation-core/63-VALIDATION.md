---
phase: 63
slug: read-chain-navigation-and-rotation-core
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-29
---

# Phase 63 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest |
| **Config file** | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk-core test` |
| **Full suite command** | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test` |
| **Estimated runtime** | ~60 seconds (unit); sdk-e2e round-trip requires live local stack |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test`
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| (populated during planning) | — | — | — | — | — | — | — | — | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

*Populated during planning — likely "Existing vitest infrastructure covers all phase requirements" since sdk-core/sdk already run vitest. sdk-e2e round-trip needs docker stack + `pnpm --filter @cipherbox/api dev` + redis on 6380.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| (populated during planning) | — | — | — |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
