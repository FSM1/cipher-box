---
phase: 38
slug: retire-deprecated-web-services
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-31
---

# Phase 38 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                    |
| ---------------------- | -------------------------------------------------------- |
| **Framework**          | vitest + TypeScript typecheck                            |
| **Config file**        | packages/crypto/vitest.config.ts                         |
| **Quick run command**  | `pnpm typecheck`                                         |
| **Full suite command** | `pnpm typecheck && pnpm --filter @cipherbox/crypto test` |
| **Estimated runtime**  | ~30 seconds                                              |

---

## Sampling Rate

- **After every task commit:** Run `pnpm typecheck`
- **After every plan wave:** Run `pnpm typecheck && pnpm --filter @cipherbox/crypto test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                                     | File Exists | Status     |
| -------- | ---- | ---- | ----------- | --------- | ----------------------------------------------------- | ----------- | ---------- |
| 38-01-01 | 01   | 1    | N/A         | typecheck | `pnpm typecheck`                                      | ✅          | ⬜ pending |
| 38-01-02 | 01   | 1    | N/A         | typecheck | `pnpm typecheck`                                      | ✅          | ⬜ pending |
| 38-02-01 | 02   | 1    | N/A         | typecheck | `pnpm typecheck`                                      | ✅          | ⬜ pending |
| 38-02-02 | 02   | 1    | N/A         | typecheck | `pnpm typecheck`                                      | ✅          | ⬜ pending |
| 38-03-01 | 03   | 2    | N/A         | unit      | `pnpm --filter @cipherbox/crypto test`                | ✅          | ⬜ pending |
| 38-03-02 | 03   | 2    | N/A         | build     | `pnpm typecheck`                                      | ✅          | ⬜ pending |
| 38-04-01 | 04   | 2    | N/A         | typecheck | `pnpm typecheck`                                      | ✅          | ⬜ pending |
| 38-04-02 | 04   | 2    | N/A         | grep      | `grep -r "folder.service\|bin.service" apps/web/src/` | N/A         | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. This phase is a refactoring/cleanup — no new test stubs needed. The vault-ipns test exists and will be modified (not created from scratch).

---

## Manual-Only Verifications

| Behavior                          | Requirement | Why Manual                       | Test Instructions                                         |
| --------------------------------- | ----------- | -------------------------------- | --------------------------------------------------------- |
| Upload file flow works end-to-end | N/A         | Full E2E requires browser + IPFS | Upload a file in the web app, verify it appears in folder |
| Bin load/purge works              | N/A         | Requires full auth flow          | Login, delete a file, check bin loads correctly           |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
