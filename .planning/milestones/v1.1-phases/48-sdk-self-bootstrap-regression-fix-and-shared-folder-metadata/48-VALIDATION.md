---
phase: 48
slug: sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-16
validated: 2026-06-16
---

# Phase 48 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| **Framework**          | vitest (`packages/sdk`, `packages/sdk-core`, `packages/crypto`, `apps/web`) · jest (`apps/api`) · Playwright (`tests/web-e2e`) |
| **Config file**        | per-package `vitest.config.ts` · `apps/api/jest.config.js` (`testRegex` `.*\.spec\.ts$`) · `tests/web-e2e/playwright.config.ts` |
| **Quick run command**  | `pnpm --filter @cipherbox/sdk test`                                                           |
| **Full suite command** | `pnpm --filter @cipherbox/sdk test && pnpm --filter @cipherbox/api test`                      |
| **Estimated runtime**  | ~60–120 seconds (unit) · web-e2e ~13 min via dispatch                                         |

> Do NOT run all workspace suites concurrently (RAM). REQ-1/2/3/4 integration acceptance is the web-e2e gate, dispatched not run locally.

---

## Sampling Rate

- **After every task commit:** Run the relevant package's quick command (`pnpm --filter <pkg> test`)
- **After every plan wave:** Run the full suite command above
- **Before completion:** Unit suites green AND the full-phase web-e2e dispatch green
- **Max feedback latency:** 120 seconds (unit) — e2e gate is async via dispatch

---

## Per-Task Verification Map

| Requirement | Sub-behavior | Test Type | Automated Command | Status |
| ----------- | ------------ | --------- | ----------------- | ------ |
| REQ-1 | `loadFolder` sequence-guard (keep fresher in-memory vs stale resolve; absent loads; older overwritten) | unit | `pnpm --filter @cipherbox/sdk exec vitest run client-load-reconcile` | ✅ green |
| REQ-1 | bin durability (null resolve → empty, never publish; transient null retry no-clobber) | unit | `pnpm --filter @cipherbox/sdk exec vitest run bin` | ✅ green |
| REQ-1 | bin-restore-after-reload + version-restore cold-reload | e2e | `gh workflow run web-e2e.yml --ref <branch>` | ✅ green |
| REQ-2 | remove web folder-seeding (self-bootstrap covers cold-reload) | static + e2e | typecheck + lint + grep zero `ensureFolderRegistered`; web-e2e cold-reload | ✅ green |
| REQ-3 | `sharedFolderTree` per-share isolation + key-zeroing | unit | `pnpm --filter @cipherbox/sdk exec vitest run shared-folder-tree` | ✅ green |
| REQ-3 | client shared-write + `refreshSharedFolder` (adopt/no-clobber/null/unloaded) | unit | `pnpm --filter @cipherbox/sdk exec vitest run client-shared-write` | ✅ green |
| REQ-3 | web projection + poll-through-SDK (refs written only by `sharedFolder:updated`; per-share filter) | unit | `pnpm --filter @cipherbox/web test useSharedWriteOps` | ✅ green |
| REQ-3 | writable-shares (recipient open + edit + save) | e2e | web-e2e `writable-shares.spec.ts` | ✅ green |
| REQ-4 | ECIES wrap/unwrap of UTF-8 itemName primitive | unit | `pnpm --filter @cipherbox/crypto exec vitest run ecies` | ✅ green |
| REQ-4 | web `decryptItemName` + `shouldBackfill` decision logic | unit | `pnpm --filter @cipherbox/web test share-item-name` | ✅ green |
| REQ-4 | API `createShare` ciphertext-as-Buffer passthrough + legacy-null | unit | `cd apps/api && pnpm exec jest src/shares/shares.service.spec.ts` | ✅ green |
| REQ-4 | API invite-create + claim ciphertext persistence | unit | `cd apps/api && pnpm exec jest src/shares/share-invite.service.spec.ts` | ✅ green |
| REQ-4 | invite-link create end-to-end | e2e | web-e2e `invite-link-workflow.spec.ts` | ✅ green |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky._

---

## Wave 0 Requirements

- [x] REQ-1: SDK unit test for the `loadFolder` sequence-guard (`client-load-reconcile.test.ts`) + bin durability (`bin.test.ts`)
- [x] REQ-3: SDK unit tests for `sharedFolderTree` reconcile + `sharedFolder:updated` emission (`shared-folder-tree.test.ts`, `client-shared-write.test.ts`, `useSharedWriteOps.test.ts`)
- [x] REQ-4: unit tests for `itemName` ECIES wrap/unwrap (`ecies.test.ts`) and the lazy-backfill decision (`share-item-name.test.ts`) + API ciphertext persistence (`shares.service.spec.ts`, `share-invite.service.spec.ts`)

_Otherwise existing infrastructure covers phase requirements._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| Shared-folder sync UAT (owner change polls in; local write not regressed) | REQ-3 | Two-account browser/IPNS runtime | Covered transitively by the green web-e2e writable-shares gate; full UAT deferred per 48-07 Task 5 |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 120s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-16

---

## Validation Audit 2026-06-16

| Metric     | Count |
| ---------- | ----- |
| Gaps found | 1     |
| Resolved   | 1     |
| Escalated  | 0     |

The single gap — REQ-4 invite/claim ciphertext persistence in `share-invite.service.ts` (create + claim) had no unit assertion (only the web-e2e invite-link gate) — was closed by adding 3 tests to `apps/api/src/shares/share-invite.service.spec.ts` (commit `e8a3a2fe0`). All REQ-1..4 sub-behaviors now have green automated coverage.
