---
phase: 21
slug: byo-ipfs-node-support
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-03-24
---

# Phase 21 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                             |
| ---------------------- | --------------------------------------------------------------------------------- |
| **Framework**          | jest 29.x (API), vitest (SDK/web)                                                 |
| **Config file**        | apps/api/jest.config.ts, packages/sdk-core/vitest.config.ts                       |
| **Quick run command**  | `pnpm --filter api test -- --testPathPattern=migration`                           |
| **Full suite command** | `pnpm --filter api test && pnpm --filter sdk-core test && pnpm --filter web test` |
| **Estimated runtime**  | ~45 seconds                                                                       |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter api test -- --testPathPattern=migration`
- **After every plan wave:** Run full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command                                                                      | File Exists | Status  |
| -------- | ---- | ---- | ----------- | ----------- | -------------------------------------------------------------------------------------- | ----------- | ------- |
| 21-01-01 | 01   | 1    | BYO-01      | unit        | `pnpm --filter sdk-core test -- --run src/__tests__/pinning/kubo-provider.test.ts`     | W0 (Plan01) | pending |
| 21-01-02 | 01   | 1    | BYO-05      | unit        | `pnpm --filter sdk-core test -- --run src/__tests__/pinning/connection-test.test.ts`   | W0 (Plan01) | pending |
| 21-02-01 | 02   | 1    | BYO-07      | unit        | `pnpm --filter api test -- --testPathPattern="(ipfs.controller\|vault.service)"`       | W0 (Plan02) | pending |
| 21-03-01 | 03   | 2    | BYO-02      | unit        | `pnpm --filter sdk-core test -- --run src/__tests__/pinning/dual-pin-provider.test.ts` | W0 (Plan03) | pending |
| 21-03-02 | 03   | 2    | BYO-06      | unit        | `pnpm --filter sdk test -- --run src/__tests__/client-pinning.test.ts`                 | W0 (Plan03) | pending |
| 21-04-01 | 04   | 3    | BYO-04      | manual      | Playwright MCP / human verification                                                    | N/A         | pending |
| 21-05-01 | 05   | 3    | BYO-03      | unit        | `pnpm --filter api test -- --testPathPattern="migration.service"`                      | W0 (Plan05) | pending |
| 21-05-02 | 05   | 3    | BYO-03      | compilation | `cd tee-worker && npx tsc --noEmit`                                                    | N/A         | pending |
| 21-06-01 | 06   | 4    | BYO-04      | compilation | `pnpm --filter web exec tsc --noEmit`                                                  | N/A         | pending |
| 21-06-02 | 06   | 4    | BYO-04      | manual      | End-to-end human verification                                                          | N/A         | pending |

_Status: pending / green / red / flaky_

---

## Requirement Coverage

| Requirement | Plans            | Verification                                |
| ----------- | ---------------- | ------------------------------------------- |
| BYO-01      | Plan 01          | KuboProvider + PsaProvider unit tests       |
| BYO-02      | Plan 03          | DualPinProvider + client pinning tests      |
| BYO-03      | Plan 03, Plan 05 | Vault config type + migration service tests |
| BYO-04      | Plan 04, Plan 06 | Manual UI verification                      |
| BYO-05      | Plan 01          | Connection test unit tests                  |
| BYO-06      | Plan 03          | Client pinning tests (IPNS unchanged)       |
| BYO-07      | Plan 02          | Advisory quota unit tests                   |

---

## Nyquist Sampling Continuity

Wave 3 (Plans 04 + 05) now includes functional `migration.service.spec.ts` tests in Plan 05 Task 1. This breaks the consecutive TSC-only verification window:

- Plan 04 Task 1: TSC compile
- Plan 04 Task 2: TSC compile
- Plan 04 Task 3: Human verify (checkpoint)
- **Plan 05 Task 1: TSC compile + `migration.service.spec.ts` functional tests** (breaks window)
- Plan 05 Task 2: TSC compile

Maximum consecutive TSC-only tasks: 2 (within Nyquist limit of 3).

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/__tests__/pinning/` -- test directory for KuboProvider, PsaProvider, connection test, DualPinProvider (created in Plan 01 Task 2 and Plan 03 Task 3)
- [ ] `apps/api/src/migration/migration.service.spec.ts` -- migration service unit tests (created in Plan 05 Task 1)
- [ ] `apps/api/src/ipfs/ipfs.controller.spec.ts` -- registerCid endpoint tests (created/extended in Plan 02 Task 2)
- [ ] `apps/api/src/vault/vault.service.spec.ts` -- advisory quota mode tests (extended in Plan 02 Task 2)

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

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 45s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
