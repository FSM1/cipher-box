---
phase: 64
slug: rotation-soundness-revocation-guarantees
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-29
---

# Phase 64 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (sdk-core unit) + sdk-e2e (live API round-trip) |
| **Config file** | `packages/sdk-core/vitest.config.ts`; `tests/sdk-e2e/` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk-core test` |
| **Full suite command** | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter sdk-e2e test` |
| **Estimated runtime** | ~60–180 seconds (unit); sdk-e2e adds live-stack round-trip time |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test`
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full suite (incl. sdk-e2e) must be green
- **Max feedback latency:** ~180 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | TBD | ROT-03/04/05/06, TEST-01 | — | old readKey/fileKey holder cannot decrypt next published version | unit + e2e | `pnpm --filter @cipherbox/sdk-core test` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

*The planner populates concrete per-task rows; the Nyquist auditor fills coverage gaps during execution. See `64-RESEARCH.md` `## Validation Architecture` for the per-success-criterion validation mapping.*

---

## Wave 0 Requirements

- [ ] sdk-e2e crash-safety suite scaffold (TEST-01) — depth ≥2 manual-node tree with known keypairs
- [ ] vitest mocks for `reMintGrantsRootedAt` (mocked `shares` query + mocked persist callback)

*Existing vitest + sdk-e2e infrastructure covers the unit and round-trip requirements; no new framework install.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| sdk-e2e live round-trip | TEST-01 | Needs the live local API stack (docker compose + `pnpm --filter @cipherbox/api dev`, redis on 6380) | Bring up the stack, run `pnpm --filter sdk-e2e test` |

*Live-stack sdk-e2e is automated but gated on operator-provisioned infrastructure.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 180s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
