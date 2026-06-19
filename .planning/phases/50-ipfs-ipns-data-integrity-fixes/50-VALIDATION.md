---
phase: 50
slug: ipfs-ipns-data-integrity-fixes
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-06-19
---

# Phase 50 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| **Framework**          | jest 29.x (API plans 50-01, 50-02, 50-04, 50-05 — `apps/api`) + vitest 3.x (SDK plan 50-03 — `packages/sdk`) |
| **Config file**        | `apps/api/jest.config.js` (jest) · `packages/sdk/vitest.config.ts` (vitest)              |
| **Quick run command**  | API: `pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec\|pending-unpin.processor.spec\|ipfs.controller.spec"` · SDK: `pnpm --filter @cipherbox/sdk test` |
| **Full suite command** | `pnpm --filter @cipherbox/api test` · `pnpm --filter @cipherbox/sdk test`                |
| **Estimated runtime**  | API unit specs ~tens of seconds (~20–40s) · SDK unit ~seconds (~2–10s)                    |

Two frameworks are in play: the four API plans (50-01, 50-02, 50-04, 50-05) run under **jest** because they touch `apps/api`; plan 50-03 runs under **vitest** because it touches `packages/sdk`. The SDK vitest `include` glob matches only `src/**/*.test.ts`, so the new D-03 spec uses the `.test.ts` suffix.

---

## Sampling Rate

- **After every task commit:** Run the quick command for that task's file — API: `pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec|pending-unpin.processor.spec|ipfs.controller.spec"` · SDK: `pnpm --filter @cipherbox/sdk test`
- **After every plan wave:** Run the full suites — `pnpm --filter @cipherbox/api test` and `pnpm --filter @cipherbox/sdk test`
- **Before `/gsd-verify-work`:** Both full suites must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                                                                   | Test Type | Automated Command                                                                                                                                                                  | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | ------------------------------------------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ---------- |
| 50-01-01  | 01   | 1    | HARD-01     | T-50-01    | RED: advisory-lock SQL must not use `abs(int4)` form, so the INT_MIN-hash CID stays deletable     | unit      | `pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec" -t "WR-01" 2>&1 \| grep -Eiq "1 failed\|✕\|FAIL" && echo RED_OK`                                       | ✅          | ⬜ pending |
| 50-01-02  | 01   | 1    | HARD-01     | T-50-01    | GREEN: `pg_advisory_xact_lock(hashtext($1)::bigint)` (no `abs()`); INT_MIN sign-extends safely    | unit      | `pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec" -t "WR-01" 2>&1 \| grep -Eiq "1 passed\|PASS\|✓" && echo GREEN_OK`                                     | ✅          | ⬜ pending |
| 50-02-01  | 02   | 1    | HARD-01     | T-50-03    | RED: re-pinned CID (count > 0) is not unpinned during drain but its stale outbox row is deleted   | unit      | `pnpm --filter @cipherbox/api test -- --testPathPattern="pending-unpin.processor.spec" -t "WR-03" 2>&1 \| grep -Eiq "1 failed\|✕\|FAIL" && echo RED_OK`                             | ✅          | ⬜ pending |
| 50-02-02  | 02   | 1    | HARD-01     | T-50-03    | GREEN: drain re-checks `pinnedCidRepository.count` and skips physical unpin when refcount > 0      | unit      | `pnpm --filter @cipherbox/api test -- --testPathPattern="pending-unpin.processor.spec" 2>&1 \| grep -Eiq "Tests:.*passed\|PASS" && echo GREEN_OK`                                   | ✅          | ⬜ pending |
| 50-03-01  | 03   | 1    | HARD-01     | T-50-05    | RED: full-subtree IPNS names collected for an unloaded subfolder; one bad child doesn't abort siblings; folderTree not mutated | unit      | `pnpm --filter @cipherbox/sdk test -- collect-subtree-ipns-names 2>&1 \| grep -Eiq "fail\|✕\|FAIL" && echo RED_OK`                                                                   | ❌ W0       | ⬜ pending |
| 50-03-02  | 03   | 1    | HARD-01     | T-50-05    | GREEN: async on-demand `collectSubtreeIpnsNamesAsync` fetches+decrypts persisted metadata, no folderTree mutation | unit      | `pnpm --filter @cipherbox/sdk test -- collect-subtree-ipns-names 2>&1 \| grep -Eiq "pass\|✓\|PASS" && echo GREEN_OK`                                                                 | ❌ W0       | ⬜ pending |
| 50-04-01  | 04   | 2    | HARD-01     | T-50-10    | IN-01/IN-06/IN-03: `shouldAttemptPhysicalUnpin` rename, `fileUnpins` guarded on real row deletion, `recordUnpin` removed | unit      | `grep -q "shouldAttemptPhysicalUnpin" apps/api/src/vault/vault.service.ts && ! grep -q "outboxRowInserted" apps/api/src/vault/vault.service.ts && ! grep -qE "^\s*async recordUnpin\(" apps/api/src/vault/vault.service.ts && pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec" 2>&1 \| grep -Eiq "Tests:.*passed\|PASS" && echo DISPOSITION_OK` | ✅          | ⬜ pending |
| 50-04-02  | 04   | 2    | HARD-01     | T-50-09    | WR-07/WR-04/IN-05 dispositions: BYO-blocks-unpin accept-comment + CAPACITY.md retention note; drift set consistency | unit      | `grep -Eq "WR-04" apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts && grep -Eq "WR-07" apps/api/src/vault/vault.service.ts && grep -Eq "IN-05" apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts && pnpm --filter @cipherbox/api test -- --testPathPattern="pending-unpin.processor.spec" 2>&1 \| grep -Eiq "Tests:.*passed\|PASS" && echo DISPOSITION_OK` | ✅          | ⬜ pending |
| 50-05-01  | 05   | 1    | HARD-01     | T-50-13    | WR-02: upload-compensation no-row path physically unpins the leaked CID without firing the cross-user alert | unit      | `grep -q "WR-02" apps/api/src/ipfs/ipfs.controller.ts && pnpm --filter @cipherbox/api test -- --testPathPattern="ipfs.controller.spec" 2>&1 \| grep -Eiq "Tests:.*passed\|PASS" && echo WR02_OK`                                                | ✅          | ⬜ pending |
| 50-05-02  | 05   | 1    | HARD-01     | T-50-12    | IN-02: `UnpinDto.cid` validated via `@Matches` CID regex + `@MaxLength(255)`; api-client regenerated/committed | unit      | `grep -q "MaxLength" apps/api/src/ipfs/dto/unpin.dto.ts && grep -q "Matches" apps/api/src/ipfs/dto/unpin.dto.ts && bash scripts/check-api-client.sh 2>&1 \| grep -Eiv "error\|drift" >/dev/null; git diff --name-only \| grep -q "packages/api-client" && echo "WARN: unstaged api-client diff" \|\| echo IN02_OK`                                          | ✅          | ⬜ pending |
| 50-05-03  | 05   | 1    | HARD-01     | T-50-14    | WR-05/WR-06/IN-04: backfill age cutoff excludes in-flight uploads, real `is_byo_user` projection, IN-04 module disposition | unit      | `grep -q "v.is_byo_user   AS \"isByoUser\"" scripts/backfill-pinned-cids.ts \|\| grep -q "v.is_byo_user AS \"isByoUser\"" scripts/backfill-pinned-cids.ts; grep -q "INTERVAL '1 hour'" scripts/backfill-pinned-cids.ts && grep -lq "IN-04" apps/api/src/ipfs/ipfs.module.ts apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts apps/api/src/vault/vault.module.ts && echo BACKFILL_IN04_OK` | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

Threat Ref maps each task to the most specific STRIDE entry in its plan's `<threat_model>` (50-01 → T-50-01; 50-02 → T-50-03; 50-03 → T-50-05; 50-04 task 1 → T-50-10 IN-01, task 2 → T-50-09 WR-07; 50-05 task 1 → T-50-13 WR-02, task 2 → T-50-12 IN-02, task 3 → T-50-14 WR-05).

---

## Wave 0 Requirements

- [ ] `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` — NEW vitest file created by 50-03 Task 1 (`.test.ts` suffix mandatory; SDK vitest `include` matches only `src/**/*.test.ts`). Covers D-03 on-demand traversal (Tests A/B/C).
- [ ] `mockPinnedCidRepository.count` added to the existing `pending-unpin.processor.spec.ts` mock definition — additive within an existing file (50-02 Task 1), not a new file.

All other tasks reuse existing specs: `vault.service.spec.ts`, `pending-unpin.processor.spec.ts`, and `ipfs.controller.spec.ts` already exist; the API plans add `it()` blocks / dispositions to them rather than creating new test files. The 50-04 and 50-05 disposition tasks verify via `grep` + the existing API suites.

---

## Manual-Only Verifications

All phase behaviors have automated verification.

Every task carries a `<verify><automated>` command (jest/vitest spec runs for RED/GREEN tasks, and grep-gated source assertions plus the existing API suites for the D-04 disposition tasks). No behavior requires manual verification.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (the new SDK `collect-subtree-ipns-names.test.ts` and the `mockPinnedCidRepository.count` addition)
- [x] No watch-mode flags (all commands use `vitest run` via the `test` script and `jest` non-watch)
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-06-19
