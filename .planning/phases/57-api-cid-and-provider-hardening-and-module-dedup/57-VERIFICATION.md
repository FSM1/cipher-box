---
phase: 57-api-cid-and-provider-hardening-and-module-dedup
verified: 2026-06-22T02:10:00Z
status: passed
score: 12/12 must-haves verified
overrides_applied: 0
---

# Phase 57: API CID and Provider Hardening + Module Dedup — Verification Report

**Phase Goal:** Close CID-validation divergence (HARD-08), URL-encode CID in Kubo query strings, deduplicate the IPFS_PROVIDER factory and advisory-lock SQL across the module graph.
**Verified:** 2026-06-22T02:10:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | RegisterCidDto rejects CIDv0 Qm... longer than 46 chars ({44,} overflow) | VERIFIED | register-cid.dto.spec.ts test 2 passes; `{44}` exact branch in cid.constants.ts; no `{44,}` in register-cid.dto.ts |
| 2 | RegisterCidDto rejects any cid longer than 255 chars | VERIFIED | `@MaxLength(255)` on cid field in register-cid.dto.ts; test 3 in spec passes; 903/903 tests green |
| 3 | RegisterCidDto accepts a valid CIDv1 bafk... string | VERIFIED | register-cid.dto.spec.ts test 1 passes; CIDv1 branch `b[a-z2-7]{58,}` kept in CID_REGEX |
| 4 | RegisterCidDto and UnpinDto validate CID via the single shared CID_REGEX constant | VERIFIED | Both import `{ CID_REGEX } from './cid.constants'`; no inline regex in either DTO; no `const CID_REGEX` in unpin.dto.ts |
| 5 | LocalProvider URL-encodes the CID in pin/rm and cat Kubo query strings | VERIFIED | `URLSearchParams` count=2; lines 87-88 (pin/rm) and 128+ (cat) confirmed; no raw `?arg=${cid}` interpolation |
| 6 | openapi.json carries maxLength:255 on RegisterCidDto.cid and regenerated api-client is committed | VERIFIED | `node -e` assertion exits 0; `maxLength: 255` confirmed in openapi.json |
| 7 | Single leaf IpfsProviderModule owns the IPFS_PROVIDER factory; three duplicated factories deleted | VERIFIED | `grep -rl "provide: IPFS_PROVIDER" apps/api/src --include="*.ts"` (non-spec) returns ONLY `ipfs-provider.module.ts` |
| 8 | IpfsModule, VaultModule, PendingUnpinModule import IpfsProviderModule instead of self-providing | VERIFIED | Each module imports IpfsProviderModule; factory block deleted from all three |
| 9 | Misleading IN-04 accepted-circular-dependency comments removed | VERIFIED | `grep -rn "IN-04 (accepted)" apps/api/src` returns nothing |
| 10 | withCidLock runs verbatim pg_advisory_xact_lock(hashtext($1)::bigint) SQL with no abs() | VERIFIED | SQL string confirmed verbatim in unpin-helpers.ts; `grep -F "abs(" apps/api/src/ipfs/pending-unpin/unpin-helpers.ts` returns nothing (doc comment only, not in SQL) |
| 11 | All three advisory-lock unpin sites route through shared helpers; drainRow uses refcountAndMaybeUnpin; vault.service post-commit does NOT | VERIFIED | processor.ts uses withCidLock+refcountAndMaybeUnpin; vault.service.ts has 0 uses of refcountAndMaybeUnpin; both use withCidLock |
| 12 | Post-commit ipfsProvider.unpinFile(cid) stays OUTSIDE the inner transaction in guardedUnpin | VERIFIED | vault.service.ts lines 316-335: `unpinFile` call precedes the `dataSource.transaction` block for outbox delete; withCidLock only wraps the outbox delete |

**Score:** 12/12 truths verified

---

### Required Artifacts

| Artifact | Status | Evidence |
|----------|--------|----------|
| `apps/api/src/ipfs/dto/cid.constants.ts` | VERIFIED | Exists; exports `CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}\|b[a-z2-7]{58,})$/` with IN-02 comment |
| `apps/api/src/ipfs/dto/register-cid.dto.spec.ts` | VERIFIED | Exists; 4 tests (CIDv1 accept, CIDv0 overflow reject, 255+ char reject, canonical CIDv0 accept); all pass |
| `apps/api/src/ipfs/dto/register-cid.dto.ts` | VERIFIED | Contains `@MaxLength(255)`, imports CID_REGEX from cid.constants; no inline `{44,}` regex |
| `apps/api/src/ipfs/providers/local.provider.ts` | VERIFIED | Contains `URLSearchParams` in 2 locations (pin/rm + cat); pin/add unchanged |
| `apps/api/src/ipfs/providers/ipfs-provider.module.ts` | VERIFIED | Exists; leaf @Module importing only ConfigModule; exports `[IPFS_PROVIDER]`; exports `class IpfsProviderModule` |
| `apps/api/src/ipfs/pending-unpin/unpin-helpers.ts` | VERIFIED | Exists; exports `withCidLock` and `refcountAndMaybeUnpin`; verbatim SQL; no abs() |
| `apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts` | VERIFIED | Exists; contains `IpfsProviderModule` |
| `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` | VERIFIED | Exists; contains `withCidLock`; 3 tests: lock SQL, refs>0 skip-unpin, refs===0 unpin |

---

### Key Link Verification

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `register-cid.dto.ts` | `cid.constants.ts` | `import { CID_REGEX }` | WIRED | Line 3 confirmed |
| `unpin.dto.ts` | `cid.constants.ts` | `import { CID_REGEX }` | WIRED | Line 3 confirmed |
| `ipfs.module.ts` | `ipfs-provider.module.ts` | `imports: [..., IpfsProviderModule]` | WIRED | `exports: [IPFS_PROVIDER]` confirmed at line 16 |
| `vault.service.ts` | `unpin-helpers.ts` | `import { withCidLock }` | WIRED | Line 17 confirmed; used at lines 267, 324 |
| `pending-unpin.processor.ts` | `unpin-helpers.ts` | `import { withCidLock, refcountAndMaybeUnpin }` | WIRED | Line 10 confirmed; drainRow uses both at line 81 |

---

### Grep Gate Results

| Gate | Command Result | Status |
|------|---------------|--------|
| Single `provide: IPFS_PROVIDER` source (non-spec) | 1 file: `ipfs-provider.module.ts` | PASS |
| No `IN-04 (accepted)` comments | 0 matches | PASS |
| No inline `pg_advisory_xact_lock` SQL at 3 sites | vault.service.ts + processor.ts: 0 executable SQL calls (comments only) | PASS |
| No `abs(` in unpin-helpers.ts SQL | 0 matches in code (doc comment explains prohibition) | PASS |
| No `{44,}` in register-cid.dto.ts | 0 matches | PASS |
| No `const CID_REGEX` in unpin.dto.ts | 0 matches | PASS |
| `URLSearchParams` count in local.provider.ts | 2 | PASS |
| No raw `pin/rm?arg=${cid}` or `cat?arg=${cid}` | 0 matches | PASS |
| `refcountAndMaybeUnpin` in vault.service.ts | 0 uses | PASS |
| `refcountAndMaybeUnpin` in pending-unpin.processor.ts | 3 matches (import + usage) | PASS |
| `exports: [IPFS_PROVIDER]` in ipfs.module.ts | Line 16 confirmed | PASS |
| `providers/index.ts` re-exports IpfsProviderModule | `export * from './ipfs-provider.module'` | PASS |

---

### Test Suite Results

| Suite | Command | Result |
|-------|---------|--------|
| Full apps/api jest | `npx jest` in apps/api | **903 tests, 47 suites — ALL PASSING** |
| tsc --noEmit (phase-57-touched files) | `npx tsc --noEmit 2>&1 \| grep -E "ipfs/\|vault/"` | **0 errors** |
| tsc --noEmit (known pre-existing) | 3 errors in `metrics/http-metrics.interceptor.spec.ts`, `shares/share-invite.service.spec.ts`, `shares/shares.controller.spec.ts` | Pre-existing at fork base; not introduced by phase 57 |

---

### D-03 Ordering Verification (Critical Safety Check)

Post-commit `ipfsProvider.unpinFile(cid)` placement in `guardedUnpin` (vault.service.ts ~line 316):

- `await this.ipfsProvider.unpinFile(cid)` is called FIRST, OUTSIDE any transaction
- The `dataSource.transaction(async (manager) => { await withCidLock(...delete PendingUnpin...) })` runs AFTER
- Kubo network call is never held inside the advisory-lock transaction — D-03 ordering maintained

**Status: VERIFIED**

---

### Anti-Patterns Found

None. No TBD/FIXME/XXX markers found in phase-57-touched files. No stub implementations. No hardcoded empty returns in functional paths.

---

### Human Verification Required

None. All must-haves are verifiable programmatically. The openapi.json maxLength assertion was confirmed by direct `node -e` execution.

---

## Gaps Summary

No gaps. All 12 must-have truths verified against actual source code and test execution.

---

_Verified: 2026-06-22T02:10:00Z_
_Verifier: Claude (gsd-verifier)_
