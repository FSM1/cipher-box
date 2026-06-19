---
phase: 50-ipfs-ipns-data-integrity-fixes
plan: "05"
subsystem: api
tags: [security, ipfs, unpin, backfill, validation]
dependency_graph:
  requires: []
  provides: [WR-02-fix, IN-02-fix, WR-05-fix, WR-06-fix, IN-04-accepted]
  affects:
    - apps/api/src/ipfs/ipfs.controller.ts
    - apps/api/src/ipfs/ipfs.controller.spec.ts
    - apps/api/src/ipfs/dto/unpin.dto.ts
    - scripts/backfill-pinned-cids.ts
    - apps/api/src/ipfs/ipfs.module.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
    - apps/api/src/vault/vault.module.ts
    - packages/api-client/openapi.json
tech_stack:
  added: []
  patterns:
    - direct ipfsProvider.unpinFile on no-row compensation path (WR-02)
    - class-validator @Matches + @MaxLength on CID input (IN-02)
    - backfill age cutoff for TOCTOU exclusion (WR-05)
    - real column projection replacing hardcoded boolean (WR-06)
    - accept-with-comment disposition for module cycle (IN-04)
key_files:
  created: []
  modified:
    - apps/api/src/ipfs/ipfs.controller.ts
    - apps/api/src/ipfs/ipfs.controller.spec.ts
    - apps/api/src/ipfs/dto/unpin.dto.ts
    - scripts/backfill-pinned-cids.ts
    - apps/api/src/ipfs/ipfs.module.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
    - apps/api/src/vault/vault.module.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated (all files)
    - packages/api-client/src/models (all files)
decisions:
  - "IN-04 accepted with comment: IPFS_PROVIDER useFactory duplication across three modules retained to avoid import cycle restructuring; explicit cycle-reason comment added to each module"
  - "WR-02 fix: replaced guardedUnpin on no-row compensation path with direct ipfsProvider.unpinFile; guardedUnpin checks DB first and would return early with no Kubo call if no row exists"
metrics:
  duration: "~15min"
  completed_date: "2026-06-19"
  tasks: 3
  files: 10
---

# Phase 50 Plan 05: D-04 Unpin Integrity Fixes Summary

Disposes five D-04 findings across the IPFS controller, UnpinDto, backfill script, and provider module factories: WR-02 (upload-compensation no-row path leaked the Kubo pin), IN-02 (UnpinDto.cid lacked CID format and length validation — DoS gap), WR-05 (backfill TOCTOU could delete in-flight upload rows), WR-06 (backfill hardcoded `false::boolean AS "isByoUser"` defeating the defensive re-assert), and IN-04 (triplicated provider factory accepted with cycle-reason comment).

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | WR-02: physical unpin on no-row compensation path | ded892a57 | ipfs.controller.ts, ipfs.controller.spec.ts |
| 2 | IN-02: CID format/length validation + api-client regen | ace5fe2d3 | unpin.dto.ts, packages/api-client/* (132 files) |
| 3 | WR-05/WR-06 backfill fixes + IN-04 disposition | 2b6213244 | backfill-pinned-cids.ts, 3 module files |

## Changes by Finding

### WR-02: Upload-compensation no-row path leaks the Kubo pin

Root cause: `guardedUnpin` looks up the `pinned_cids` DB row first. When `recordPin` fails, no row was written, so `guardedUnpin.findOne()` returns null and returns early — never calling Kubo. The just-created physical pin leaks.

Fix: Replaced `guardedUnpin` on the `recordPin` catch path with a direct `this.ipfsProvider.unpinFile(result.cid).catch(() => undefined)` call. This physically removes the Kubo pin regardless of DB state. The cross-user audit path is never reached (guardedUnpin is bypassed entirely), so no false cross-user security signal is emitted.

Tests: Updated test 4 in `ipfs.controller.spec.ts` to assert `ipfsProvider.unpinFile` is called (not `guardedUnpin`) on the no-row compensation path. Updated test 5 to reflect that `unpinFile` rejection (not `guardedUnpin` rejection) is swallowed. All 20 controller tests pass.

### IN-02: UnpinDto.cid lacks CID format and length validation

Fix: Added `@MaxLength(255)` and `@Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/)` to `UnpinDto.cid`, importing `MaxLength` and `Matches` from `class-validator`. Covers CIDv0 (`Qm...` base58) and CIDv1 (`b...` base32). Updated `@ApiProperty` with `pattern` and `maxLength` fields for OpenAPI documentation.

api-client regenerated: `pnpm api:generate` run from main repo with modified DTO. `packages/api-client/openapi.json` now includes `"pattern"` and `"maxLength": 255` on the `UnpinDto.cid` schema. All 132 generated files committed alongside the DTO change. Pre-commit hook (`check-api-client.sh`) satisfied.

### WR-05: Backfill TOCTOU — in-flight uploads selected as phantoms

Fix: Added `AND pc.pinned_at < NOW() - INTERVAL '1 hour'` to the candidate query WHERE clause. Rows less than 1 hour old are excluded, covering the race window between a Kubo pin being created and the pin list being refreshed.

### WR-06: Backfill hardcodes `false::boolean AS "isByoUser"`

Fix: Changed projection from `false::boolean AS "isByoUser"` to `v.is_byo_user AS "isByoUser"`. The query-level `WHERE v.is_byo_user = false` guard is retained. The projection fix makes the `!row.isByoUser` re-assert in `selectRowsToDelete` (backfill-helpers.ts) meaningful — it now sees the actual vault value, not a constant.

### IN-04: Triplicated IPFS_PROVIDER useFactory

Disposition: ACCEPT with comment — The `IPFS_PROVIDER` `useFactory` is duplicated across `IpfsModule`, `PendingUnpinModule`, and `VaultModule`. Each module self-provides to break the NestJS circular import created by the `IpfsModule -> VaultModule` dependency. Extraction into a shared `IpfsProviderCoreModule` would require restructuring the import graph. A cycle-reason comment citing IN-04 has been added to each of the three module files.

## Deviations from Plan

None — plan executed exactly as written. IN-04 disposition defaulted to accept-with-comment as specified.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. All changes are within existing boundaries (controller compensation path, DTO validation, SQL query, module comments).

## Known Stubs

None.

## Self-Check: PASSED

All task files confirmed on disk. All commits verified in git log.

| Item | Status |
|------|--------|
| SUMMARY.md | FOUND |
| apps/api/src/ipfs/ipfs.controller.ts | FOUND |
| apps/api/src/ipfs/dto/unpin.dto.ts | FOUND |
| scripts/backfill-pinned-cids.ts | FOUND |
| ded892a57 (WR-02) | FOUND |
| ace5fe2d3 (IN-02) | FOUND |
| 2b6213244 (WR-05/WR-06/IN-04) | FOUND |
