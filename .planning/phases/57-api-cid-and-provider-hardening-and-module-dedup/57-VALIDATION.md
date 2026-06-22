---
phase: 57
slug: api-cid-and-provider-hardening-and-module-dedup
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-22
audited: 2026-06-22
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

---

## Retroactive Compliance Audit

> Performed 2026-06-22 (static analysis only — full jest suite already green: 903/903 tests, 47/47 suites). Each must-have requirement from `57-VERIFICATION.md` is mapped to a validating test or a deterministic source assertion below.

### Audit Result

- **Nyquist compliant:** yes
- **Must-have requirements:** 12
- **Requirements with validating coverage:** 12
- **Nyquist gaps:** 0

### Requirement to Test Mapping

| #   | Requirement                                                                                | Validating Coverage                                                                                                  | Verdict |
| --- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ------- |
| 1   | `RegisterCidDto` rejects CIDv0 `{44,}` overflow (47 chars after `Qm`)                       | `register-cid.dto.spec.ts` — "rejects a CIDv0 with {44,} overflow" asserts `cidErrors.length >= 1`                    | covered |
| 2   | `RegisterCidDto` rejects strings > 255 chars                                                | `register-cid.dto.spec.ts` — "rejects a cid string longer than 255 chars" (300-char input)                            | covered |
| 3   | `RegisterCidDto` accepts a valid CIDv1                                                      | `register-cid.dto.spec.ts` — "accepts a valid CIDv1" asserts `errors.length === 0`                                    | covered |
| 4   | `RegisterCidDto` + `UnpinDto` share a single `CID_REGEX`                                    | grep: `cid.constants.ts` exports `CID_REGEX`; both `register-cid.dto.ts` and `unpin.dto.ts` import it                 | covered |
| 5   | `LocalProvider` URL-encodes the CID in pin/rm and cat                                       | `local.provider.spec.ts` — "percent-encode ... in pin/rm URL" + "... in cat URL" assert `bafk%26evil%3D1`             | covered |
| 6   | `openapi.json` gains `maxLength: 255` and regenerated client is committed                   | node assertion: `packages/api-client/openapi.json` RegisterCidDto.cid = `{pattern, maxLength:255}` (committed)         | covered |
| 7   | A single leaf `IpfsProviderModule` owns the `IPFS_PROVIDER` factory                         | `ipfs-provider.module.spec.ts` (provides + exports as `LocalProvider`) + grep: only `ipfs-provider.module.ts` has `provide: IPFS_PROVIDER` | covered |
| 8   | `IpfsModule` / `VaultModule` / `PendingUnpinModule` import `IpfsProviderModule`             | grep: `ipfs.module.ts`, `vault.module.ts`, `pending-unpin.module.ts` all import `IpfsProviderModule`                  | covered |
| 9   | IN-04 accepted-circular-dependency comments removed                                         | grep: no `forwardRef` / "circular dependency" comments remain in `ipfs/` or `vault/`                                  | covered |
| 10  | `withCidLock` runs verbatim `pg_advisory_xact_lock(hashtext($1)::bigint)`, no `abs()`       | `unpin-helpers.spec.ts` — lock-SQL test asserts exact SQL + `[cid]`; source confirms no `abs()`                       | covered |
| 11  | All 3 unpin sites route through shared helpers; `drainRow` uses `refcountAndMaybeUnpin`, vault.service post-commit does not | `unpin-helpers.spec.ts` (refs>0 skip, refs===0 unpin) + grep: `drainRow` = `withCidLock(... refcountAndMaybeUnpin)`; vault.service post-commit calls `ipfsProvider.unpinFile` directly | covered |
| 12  | Post-commit `unpinFile` is OUTSIDE the inner transaction (D-03)                             | `vault.service.ts` inspection: transaction block (L260-309) closes before `unpinFile` at L314; comment + structure confirm | covered |

### Notes

- Requirements 1-3, 5, 7, 10, 11 are sampled by executed unit tests (part of the green 903/903 run).
- Requirements 4, 8, 9 are structural invariants verified by source grep — no behavioral surface to assert beyond import wiring.
- Requirement 6 is verified by a deterministic assertion against the committed `openapi.json` (located in `packages/api-client/openapi.json`, not `apps/api/`).
- Requirement 12 is an ordering invariant verified by source inspection; the post-commit Kubo call provably sits outside the `dataSource.transaction` callback.

_No Nyquist gaps. All must-have requirements have validating coverage._
