---
phase: 21
slug: byo-ipfs-node-support
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-24
---

# Phase 21 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                             |
| ---------------------- | --------------------------------------------------------------------------------- |
| **Framework**          | jest 29.x (API), vitest (SDK/web)                                                 |
| **Config file**        | apps/api/jest.config.ts, packages/sdk-core/vitest.config.ts                       |
| **Quick run command**  | `pnpm --filter api test -- --testPathPattern=byo`                                 |
| **Full suite command** | `pnpm --filter api test && pnpm --filter sdk-core test && pnpm --filter web test` |
| **Estimated runtime**  | ~45 seconds                                                                       |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter api test -- --testPathPattern=byo`
- **After every plan wave:** Run full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command                                                  | File Exists | Status     |
| -------- | ---- | ---- | ----------- | ----------- | ------------------------------------------------------------------ | ----------- | ---------- |
| 21-01-01 | 01   | 1    | BYO-01      | unit        | `pnpm --filter sdk-core test -- --testPathPattern=psa-provider`    | ❌ W0       | ⬜ pending |
| 21-01-02 | 01   | 1    | BYO-01      | unit        | `pnpm --filter sdk-core test -- --testPathPattern=kubo-provider`   | ❌ W0       | ⬜ pending |
| 21-02-01 | 02   | 1    | BYO-02      | unit        | `pnpm --filter sdk-core test -- --testPathPattern=dual-pin`        | ❌ W0       | ⬜ pending |
| 21-03-01 | 03   | 1    | BYO-03      | unit        | `pnpm --filter api test -- --testPathPattern=byo-config`           | ❌ W0       | ⬜ pending |
| 21-04-01 | 04   | 2    | BYO-04      | integration | `pnpm --filter web test -- --testPathPattern=StorageTab`           | ❌ W0       | ⬜ pending |
| 21-05-01 | 05   | 2    | BYO-05      | unit        | `pnpm --filter sdk-core test -- --testPathPattern=connection-test` | ❌ W0       | ⬜ pending |
| 21-06-01 | 06   | 2    | BYO-06      | unit        | `pnpm --filter sdk-core test -- --testPathPattern=ipns-routing`    | ❌ W0       | ⬜ pending |
| 21-07-01 | 07   | 3    | BYO-07      | integration | `pnpm --filter web test -- --testPathPattern=quota`                | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/__tests__/byo/` — test directory and stubs for PSA/Kubo providers, dual-pin, connection test
- [ ] `apps/api/src/__tests__/byo/` — test stubs for CID registration, config endpoints
- [ ] `apps/web/src/__tests__/StorageTab.test.tsx` — component test stub

_Existing jest/vitest infrastructure covers framework needs._

---

## Manual-Only Verifications

| Behavior                   | Requirement | Why Manual                | Test Instructions                                            |
| -------------------------- | ----------- | ------------------------- | ------------------------------------------------------------ |
| CORS validation in browser | BYO-05      | Requires live browser     | Open Settings > Storage, enter external endpoint, run test   |
| TEE migration progress UI  | BYO-03      | Requires TEE infra        | Trigger migration, verify progress bar updates in Settings   |
| BYO-only upload failure UX | BYO-01      | Requires unreachable node | Configure offline endpoint, attempt upload, verify error msg |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
