---
phase: 42
slug: api-unpin-integrity
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-12
---

# Phase 42 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                              |
| ---------------------- | ------------------------------------------------------------------ |
| **Framework**          | jest (apps/api NestJS specs) / vitest (packages, web)              |
| **Config file**        | apps/api/jest config in package.json                               |
| **Quick run command**  | `pnpm --filter @cipherbox/api test -- --testPathPattern='(ipfs\|vault)'` |
| **Full suite command** | `pnpm --filter @cipherbox/api test`                                |
| **Estimated runtime**  | ~60 seconds                                                        |

---

## Sampling Rate

- **After every task commit:** Run the quick run command
- **After every plan wave:** Run the full suite command
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

| Task ID                                | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status     |
| -------------------------------------- | ---- | ---- | ----------- | ---------- | --------------- | --------- | ----------------- | ----------- | ---------- |
| (filled by planner — one row per task) |      |      |             |            |                 |           |                   |             | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `apps/api/src/ipfs/ipfs.controller.spec.ts` — extend with guarded-unpin cases (no-row no-op, cross-user audit, refcount-skip)
- [ ] `apps/api/src/vault/vault.service.spec.ts` — extend with guardedUnpin transaction/refcount cases

_Existing jest infrastructure covers all phase requirements — no new framework install._

---

## Manual-Only Verifications

| Behavior                                       | Requirement | Why Manual                       | Test Instructions                                                                                  |
| ---------------------------------------------- | ----------- | -------------------------------- | -------------------------------------------------------------------------------------------------- |
| Kubo `pin/rm` "not pinned" error shape (v0.40) | both todos  | Requires live Kubo node          | Run `ipfs pin rm <unpinned-cid>` against docker Kubo; assert error string matched by provider code |
| One-shot backfill against staging data         | quota todo  | Requires staging DB + Kubo state | Run backfill script in dry-run mode first; compare reported stale rows against `pin ls` diff       |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
