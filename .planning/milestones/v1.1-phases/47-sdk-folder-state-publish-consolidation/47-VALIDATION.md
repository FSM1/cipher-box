---
phase: 47
slug: sdk-folder-state-publish-consolidation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-15
---

# Phase 47 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property                | Value                                                       |
| ----------------------- | ----------------------------------------------------------- |
| **Framework**           | vitest (all three packages)                                 |
| **Config file**         | per-package `vitest.config.ts`                              |
| **Quick run command**   | `pnpm --filter @cipherbox/sdk-core test`                    |
| **Full suite command**  | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test && pnpm --filter @cipherbox/web test` |
| **Estimated runtime**   | ~60 seconds (three suites)                                  |

Web vitest `include` is `src/**/*.test.ts` — name every new web test `*.test.ts`, NOT `*.spec.ts`.

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test` (plus `@cipherbox/sdk` if the task touched sdk)
- **After every plan wave:** Run the full suite command
- **Before phase verification:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                          | Test Type  | Automated Command                          | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | -------------------------------------------------------- | ---------- | ------------------------------------------ | ----------- | ---------- |
| 47-01-xx  | 01   | 1    | REQ-2       | —          | N/A                                                      | unit       | `pnpm --filter @cipherbox/sdk-core test`   | ❌ W0       | ⬜ pending |
| 47-02-xx  | 02   | 2    | REQ-3       | —          | N/A                                                      | unit/compile | `pnpm --filter @cipherbox/sdk build && test` | ✅          | ⬜ pending |
| 47-03-xx  | 03   | 2    | REQ-4       | T-47-04    | recipient unpin gated by Phase-42 server guard           | unit       | `pnpm --filter @cipherbox/sdk test`        | ❌ W0       | ⬜ pending |
| 47-04-xx  | 04   | 3    | REQ-1       | T-47-01    | `fileIpnsPrivateKey.fill(0)` preserved in finally        | unit       | `pnpm --filter @cipherbox/sdk test`        | ❌ W0       | ⬜ pending |
| 47-05-xx  | 05   | 3    | REQ-1       | —          | N/A                                                      | unit       | `pnpm --filter @cipherbox/web test`        | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

(Exact task IDs assigned by the planner; this map enumerates the requirement-to-test coverage that every plan must satisfy.)

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/__tests__/cas.test.ts` — `publishWithCas` unit tests (4-attempt retry, backoff, 409 merge callback, ConflictError on exhaustion, prunedCids passthrough) — REQ-2
- [ ] `packages/sdk/src/__tests__/client-file-ops.test.ts` — `replaceFile` / `restoreFileVersion` / `deleteFileVersion` emit `folder:updated` with correct children + sequenceNumber — REQ-1
- [ ] `packages/sdk/src/share/__tests__/shared-write.test.ts` (extend or create) — `updateSharedFile` unpins each `prunedCid`, tolerates unpin failure — REQ-4
- [ ] `apps/web/src/stores/__tests__/folder.store.test.ts` — `subscribeToSdk` writes children + sequenceNumber only on `folder:updated` — REQ-1

_Existing folder/file/client suites cover regression for the delegating refactors (REQ-2/REQ-3)._

---

## Manual-Only Verifications

| Behavior                                                  | Requirement | Why Manual                                                  | Test Instructions                                                                          |
| -------------------------------------------------------- | ----------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Recycle-bin TC08: replace then soft-delete no resurrect  | REQ-1       | Full IPNS round-trip + 409 merge needs the web e2e harness | Run web e2e recycle-bin suite (or headless desktop UAT): replace a file, soft-delete it, confirm it stays deleted (no stale-sequence 409 resurrection) |

_All other phase behaviors have automated verification._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
