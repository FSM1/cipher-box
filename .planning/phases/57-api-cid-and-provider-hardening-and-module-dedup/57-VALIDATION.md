---
phase: 57
slug: api-cid-and-provider-hardening-and-module-dedup
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-22
---

# Phase 57 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                         |
| ---------------------- | ------------------------------------------------------------- |
| **Framework**          | Jest 29 + ts-jest                                             |
| **Config file**        | `apps/api/jest.config.js`                                     |
| **Quick run command**  | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipfs` |
| **Full suite command** | `pnpm --filter @cipherbox/api test`                          |
| **Estimated runtime**  | ~60 seconds (full api suite)                                  |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/api test -- --testPathPattern=<changed-module> --passWithNoTests`
- **After every plan wave:** Run `pnpm --filter @cipherbox/api test`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

> Filled by the planner from PLAN.md tasks. Seed rows from RESEARCH.md Validation Architecture below; planner refines task IDs to match final plan structure.

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior                                            | Test Type  | Automated Command                                                              | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ---------- | ---------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------- | ----------- | ---------- |
| 57-01-\*  | 01   | 1    | HARD-08     | —          | `RegisterCidDto` rejects CIDv0 `{44,}` > 46 chars         | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=register-cid`         | ❌ W0       | ⬜ pending |
| 57-01-\*  | 01   | 1    | HARD-08     | —          | `RegisterCidDto` rejects strings > 255 chars               | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=register-cid`         | ❌ W0       | ⬜ pending |
| 57-01-\*  | 01   | 1    | HARD-08     | —          | `RegisterCidDto` accepts valid CIDv1 `bafk...`             | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=register-cid`         | ❌ W0       | ⬜ pending |
| 57-01-\*  | 01   | 1    | HARD-08     | —          | `LocalProvider.unpinFile` uses `arg=` query param safely   | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=local.provider`       | ✅          | ⬜ pending |
| 57-01-\*  | 01   | 1    | HARD-08     | —          | `LocalProvider.getFile` uses `arg=` query param safely     | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=local.provider`       | ✅          | ⬜ pending |
| 57-02-\*  | 02   | 1    | HARD-08     | —          | `withCidLock` executes `pg_advisory_xact_lock` SQL         | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=unpin-helpers`        | ❌ W0       | ⬜ pending |
| 57-02-\*  | 02   | 1    | HARD-08     | —          | `refcountAndMaybeUnpin` skips unpin when refs > 0          | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=unpin-helpers`        | ❌ W0       | ⬜ pending |
| 57-02-\*  | 02   | 1    | HARD-08     | —          | `IpfsProviderModule` provides + exports `IPFS_PROVIDER`    | unit       | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipfs-provider.module` | ❌ W0       | ⬜ pending |
| 57-\*\*   | both | 1    | HARD-08     | —          | Full api suite green (regression)                          | regression | `pnpm --filter @cipherbox/api test`                                           | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `apps/api/src/ipfs/dto/register-cid.dto.spec.ts` — stubs for HARD-08 (D-01 regex tightening + `@MaxLength(255)`, D-02 CIDv1 acceptance)
- [ ] `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` — stubs for `withCidLock` SQL and `refcountAndMaybeUnpin` refcount branching (D-07)
- [ ] `apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts` — stubs for `IpfsProviderModule` provides/exports `IPFS_PROVIDER` (D-05)
- [ ] `local.provider` existing spec extended with URL-encoding assertions for pin/rm + cat (D-04)

_Jest framework already installed; no new framework install needed._

---

## Manual-Only Verifications

| Behavior                                                    | Requirement | Why Manual                                       | Test Instructions                                                                 |
| ---------------------------------------------------------- | ----------- | ------------------------------------------------ | --------------------------------------------------------------------------------- |
| `pnpm api:generate` regenerated client matches DTO change   | HARD-08     | Cross-package codegen; pre-commit hook enforces  | Run `pnpm api:generate`; confirm `openapi.json` gains `maxLength: 255` on RegisterCidDto.cid; stage regenerated `@cipherbox/api-client` (D-08) |

_All in-code phase behaviors have automated verification._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
