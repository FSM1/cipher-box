---
phase: 44
slug: ipns-conflict-handling
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-13
---

# Phase 44 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                  |
| ---------------------- | ---------------------------------------------------------------------- |
| **Framework**          | vitest (confirmed in `packages/sdk-core/vitest.config.ts`)             |
| **Config file**        | `packages/sdk-core/vitest.config.ts`                                   |
| **Quick run command**  | `pnpm --filter @cipherbox/sdk-core test src/__tests__/folder-merge.test.ts` |
| **Full suite command** | `pnpm --filter @cipherbox/sdk-core test`                               |
| **Estimated runtime**  | ~30 seconds                                                            |

---

## Sampling Rate

- **After every task commit:** Run the touched test file via `pnpm --filter @cipherbox/sdk-core test src/__tests__/<file>.test.ts`
- **After every plan wave:** Run `pnpm --filter @cipherbox/sdk-core test`
- **Before `/gsd-verify-work`:** sdk-core suite green + `pnpm --filter @cipherbox/web exec vitest run --reporter=basic <touched specs>` for swept web callers
- **Max feedback latency:** 60 seconds

RAM constraint: single-package vitest runs only — never root `pnpm test`, never concurrent suites. pnpm/jest gotcha: use `pnpm --filter <pkg> exec vitest run ...` or the package's `test` script directly; never `pnpm --filter <pkg> test -- --flag` (pnpm inserts `--` and the flag becomes a positional).

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                                  | Test Type | Automated Command                                                          | File Exists | Status     |
| ------- | ---- | ---- | ----------- | ---------- | ----------------------------------------------------------------- | --------- | --------------------------------------------------------------------------- | ----------- | ---------- |
| TBD     | 01   | 1    | D-01        | —          | Three-way merge permutations (local/remote add/delete, edit-beats-delete) | unit      | `pnpm --filter @cipherbox/sdk-core test src/__tests__/folder-merge.test.ts` | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | D-02        | —          | Union merge fallback when baseChildren absent                      | unit      | same file                                                                   | ❌ W0       | ⬜ pending |
| TBD     | 01   | 1    | D-05        | —          | Typed ConflictError thrown after 4 failed attempts                 | unit      | `pnpm --filter @cipherbox/sdk-core test src/__tests__/folder.test.ts`       | expansion   | ⬜ pending |
| TBD     | 02   | 2    | D-06        | —          | File publish includes expectedSequenceNumber (CAS)                 | unit      | `pnpm --filter @cipherbox/sdk-core test src/__tests__/file.test.ts`         | ❌ W0       | ⬜ pending |
| TBD     | 02   | 2    | D-07        | —          | File conflict loser content preserved in versions[]                | unit      | same file                                                                   | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

(Planner: replace TBD task IDs and extend rows for the caller-sweep plan.)

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/__tests__/folder-merge.test.ts` — D-01/D-02 merge permutation matrix
- [ ] `packages/sdk-core/src/__tests__/file.test.ts` — D-06/D-07 file CAS + conflict semantics
- [ ] No framework install needed — vitest already configured in sdk-core

---

## Manual-Only Verifications

| Behavior                                              | Requirement | Why Manual                                              | Test Instructions                                                                  |
| ------------------------------------------------------ | ----------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Two-client concurrent edit converges without lost child | D-01..D-05  | Needs two live sessions racing real IPNS publishes        | Open vault in two browsers, add different files to the same folder simultaneously, verify both children persist after sync |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
