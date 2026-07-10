---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 01
subsystem: api
tags: [typeorm, nestjs, api-client, orval, share-plane-rename, migration]

# Dependency graph
requires: []
provides:
  - "Renamed shares/share_invites cutover columns (encrypted_read_key/encrypted_write_key/share_root_ipns_name) edited in place"
  - "D-04 claim_count CHECK folded into the share_invites CREATE TABLE + entity @Check"
  - "Renamed Share/ShareInvite entity fields and all apps/api/src/shares DTOs/services/controllers"
  - "Regenerated @cipherbox/api-client exposing the new field names"
affects: [71-02, 71-03, 71-04, 71-05, 71-06, 71-07, 71-08, 71-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Greenfield in-place cutover edit (v2.0 unreleased) instead of a forward rename migration"
    - "D-10 canonical rename map applied module-wide within apps/api/src/shares, scoped away from vault/ipns/folder-tree rootIpnsName"

key-files:
  created: []
  modified:
    - apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts
    - apps/api/src/shares/entities/share.entity.ts
    - apps/api/src/shares/entities/share-invite.entity.ts
    - apps/api/src/shares/dto/create-share.dto.ts
    - apps/api/src/shares/dto/create-invite.dto.ts
    - apps/api/src/shares/dto/claim-invite.dto.ts
    - apps/api/src/shares/dto/update-grant.dto.ts
    - apps/api/src/shares/dto/share-response.dto.ts
    - apps/api/src/shares/dto/invite-response.dto.ts
    - apps/api/src/shares/dto/get-invites-for-item-query.dto.ts
    - apps/api/src/shares/share-invite.service.ts
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/shares.controller.ts
    - apps/api/src/shares/invites.controller.ts
    - apps/api/src/shares/share-invites.controller.ts
    - apps/api/src/shares/share-invite.service.spec.ts
    - apps/api/src/shares/shares.service.spec.ts
    - apps/api/src/shares/shares.controller.spec.ts
    - apps/api/src/shares/invites.controller.spec.ts
    - apps/api/src/shares/share-invites.controller.spec.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/invites/invites.ts
    - packages/api-client/src/generated/shares/shares.ts
    - packages/api-client/src/models/claimInviteDto.ts
    - packages/api-client/src/models/createInviteDto.ts
    - packages/api-client/src/models/createShareDto.ts
    - packages/api-client/src/models/createShareResponseDto.ts
    - packages/api-client/src/models/inviteDataResponseDto.ts
    - packages/api-client/src/models/inviteResponseDto.ts
    - packages/api-client/src/models/receivedShareResponseDto.ts
    - packages/api-client/src/models/sentShareResponseDto.ts
    - packages/api-client/src/models/shareInvitesControllerListInvitesParams.ts
    - packages/api-client/src/models/updateGrantDto.ts

key-decisions:
  - "D-10 rename map applied verbatim: read_descriptor_ref/write_descriptor_ref -> encrypted_read_key/encrypted_write_key, root_ipns_name -> share_root_ipns_name (shares + share_invites only), share_invites.encrypted_key -> encrypted_read_key"
  - "D-04 CHECK folded directly into the share_invites CREATE TABLE + entity @Check, no separate forward migration (greenfield, cutover unreleased)"
  - "rootIpnsName renamed module-wide within apps/api/src/shares only (share-domain), vault/ipns/folder-tree rootIpnsName elsewhere in apps/api left untouched"
  - "share-invites.controller.ts updated even though not explicitly listed in plan files_modified -- compile-blocking consumer of the renamed ShareInvite entity fields, in-scope directory"

patterns-established:
  - "Descriptor-ref terminology fully purged from apps/api/src/shares in favor of encrypted-key wording (fields, SQL literals, @ApiProperty descriptions, validator messages, comments)"

requirements-completed: [D-10, D-04, "SC#3"]

coverage:
  - id: D1
    description: "shares/share_invites cutover columns renamed in place (encrypted_read_key/encrypted_write_key/share_root_ipns_name) with D-04 claim_count CHECK folded inline"
    requirement: D-10
    verification:
      - kind: unit
        ref: "grep -n encrypted_read_key|encrypted_write_key|share_root_ipns_name apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts"
        status: pass
      - kind: unit
        ref: "grep -n CHK_share_invites_claim_count apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts apps/api/src/shares/entities/share-invite.entity.ts"
        status: pass
    human_judgment: false
  - id: D2
    description: "Share/ShareInvite entities and all apps/api/src/shares DTOs/services/controllers renamed to encryptedReadKey/encryptedWriteKey/shareRootIpnsName/clearEncryptedWriteKey; descriptor term purged"
    requirement: D-10
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/api test (49 suites, 879 tests)"
        status: pass
      - kind: other
        ref: "grep -rin descriptor apps/api/src/shares (zero hits)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Regenerated @cipherbox/api-client exposes the new field names and builds cleanly"
    requirement: D-10
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/api-client build"
        status: pass
      - kind: other
        ref: "grep -rn DescriptorRef packages/api-client/src (zero hits)"
        status: pass
    human_judgment: false
  - id: D4
    description: "D-04 backstop: raw UPDATE share_invites SET claim_count = -1 rejected with SQLSTATE 23514 on real Postgres"
    requirement: D-04
    verification: []
    human_judgment: true
    rationale: "apps/api Jest mocks the DataSource -- no live Postgres in this test run. Documented manual verification below; explicitly non-blocking per plan (SC#3 backstop, not a gate)."

duration: 62min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 01: Share-Plane Encrypted-Key Rename + D-04 CHECK Fold Summary

**Renamed the shares/share_invites schema and TS surface from "descriptor-ref" to "encrypted-key" terminology in place (greenfield cutover edit), folded the D-04 claim_count CHECK into the same CREATE TABLE, and regenerated @cipherbox/api-client to match.**

## Performance

- **Duration:** 62 min
- **Started:** 2026-07-09T20:27:00Z
- **Completed:** 2026-07-09T21:29:11Z
- **Tasks:** 3
- **Files modified:** 32

## Accomplishments
- Edited `1750000000000-ApiSchemaCutover.ts` in place: `read_descriptor_ref`/`write_descriptor_ref` -> `encrypted_read_key`/`encrypted_write_key`, `root_ipns_name` -> `share_root_ipns_name` on both `shares` and `share_invites`, `share_invites.encrypted_key` -> `encrypted_read_key`, plus an inline `CONSTRAINT CHK_share_invites_claim_count CHECK (claim_count >= 0 AND claim_count <= max_claims)`
- `vaults.root_ipns_name`/`root_node_id`/`root_generation`/`item_name_encrypted` left completely untouched
- `Share`/`ShareInvite` entities renamed to `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName`, with a matching `@Check('CHK_share_invites_claim_count', ...)` on `ShareInvite`
- All `apps/api/src/shares` DTOs, services, controllers, and specs renamed to the new field names; `clearWriteDescriptor` -> `clearEncryptedWriteKey`; raw SQL literal `root_ipns_name` -> `share_root_ipns_name` in `SharesService.revokeForItems`
- "descriptor" term fully purged from `apps/api/src/shares` (zero grep hits across code, comments, and `@ApiProperty` descriptions)
- `pnpm api:generate` regenerated `@cipherbox/api-client` (openapi.json + generated functions + models) with the new field names; client builds cleanly

## Task Commits

Each task was committed atomically:

1. **Task 1: Rename cutover columns (in place) + fold D-04 CHECK + entities** - `347b068` (feat)
2. **Task 2: Rename DTOs + services + controllers + apps/api specs** - `881eaff` (feat)
3. **Task 3: Regenerate + commit the API client** - `0e4a9d3` (feat)

_Note: no test-only or refactor-only commits were needed -- each task's verification (tsc/test/build) passed on first application of the rename._

## Files Created/Modified

**Migration + entities:**
- `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` - shares/share_invites CREATE TABLE columns renamed in place, D-04 CHECK added inline
- `apps/api/src/shares/entities/share.entity.ts` - `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName`
- `apps/api/src/shares/entities/share-invite.entity.ts` - same rename + `@Check` for D-04

**DTOs, services, controllers, specs (apps/api/src/shares):**
- `dto/create-share.dto.ts`, `dto/create-invite.dto.ts`, `dto/claim-invite.dto.ts`, `dto/update-grant.dto.ts`, `dto/share-response.dto.ts`, `dto/invite-response.dto.ts`, `dto/get-invites-for-item-query.dto.ts` - field renames + description/message rewrites
- `share-invite.service.ts`, `shares.service.ts` - field renames, raw SQL literal fix
- `shares.controller.ts`, `invites.controller.ts`, `share-invites.controller.ts` - field renames (the last one was a Rule 3 addition, see Deviations)
- `share-invite.service.spec.ts`, `shares.service.spec.ts`, `shares.controller.spec.ts`, `invites.controller.spec.ts`, `share-invites.controller.spec.ts` - fixture renames

**API client:**
- `packages/api-client/openapi.json`, `src/generated/invites/invites.ts`, `src/generated/shares/shares.ts`, and the 10 affected model files - regenerated by `pnpm api:generate`

## Decisions Made
- Applied the D-10 canonical rename map exactly as specified in 71-CONTEXT.md; no naming deviations
- `rootIpnsName` renamed module-wide within `apps/api/src/shares` only (all occurrences in that directory are share-domain), leaving the ~74 other `rootIpnsName` occurrences elsewhere in `apps/api` (vault/ipns/folder-tree) untouched per the plan's explicit scope boundary
- D-04's CHECK constraint folded directly into the cutover's `share_invites` CREATE TABLE rather than a separate forward migration, per the greenfield-unreleased amendment in 71-CONTEXT.md

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated share-invites.controller.ts (not in plan's files_modified list)**
- **Found during:** Task 2 (rename DTOs/services/controllers/specs)
- **Issue:** `share-invites.controller.ts` (the `/shares/invites` management controller, distinct from `invites.controller.ts` at the public `/invites` prefix) reads `ShareInvite.rootIpnsName` in `createInvite`/`listInvites`. After the entity rename in Task 1, this file failed to compile (`Property 'rootIpnsName' does not exist on type 'ShareInvite'`). It was not listed in the plan's `files_modified` for Task 2, but is squarely within the `apps/api/src/shares` scope the task's action text targets ("every DTO, service, controller, and spec").
- **Fix:** Renamed `rootIpnsName` -> `shareRootIpnsName` in `share-invites.controller.ts` (both the response mapping and the `@ApiQuery` name, which already matched `GetInvitesForItemQueryDto.shareRootIpnsName`).
- **Files modified:** `apps/api/src/shares/share-invites.controller.ts`
- **Verification:** `pnpm --filter @cipherbox/api exec tsc --noEmit` shows zero errors in this file; `pnpm --filter @cipherbox/api test` includes `share-invites.controller.spec.ts` passing.
- **Committed in:** `881eaff` (Task 2 commit)

**2. [Rule 3 - Blocking] Built @cipherbox/crypto before typechecking apps/api**
- **Found during:** Task 1 verification (`tsc --noEmit`)
- **Issue:** `apps/api` imports `@cipherbox/crypto`, but the worktree's fresh `pnpm install` left `packages/crypto/dist/` unbuilt (`Cannot find module '@cipherbox/crypto'`), a pre-existing cross-package dist-staleness condition unrelated to this plan's edits.
- **Fix:** Ran `pnpm --filter @cipherbox/crypto build` once before typechecking. No source changes.
- **Files modified:** none (build artifact only, gitignored)
- **Verification:** Subsequent `tsc --noEmit -p apps/api/tsconfig.json` only reported the 2 pre-existing, out-of-scope errors (`ipns-verify-cache.spec.ts`, `http-metrics.interceptor.spec.ts`) plus the expected Task-2-scope consumer errors, confirming the crypto-module error was resolved.
- **Committed in:** n/a (no code change; documented for reproducibility)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both auto-fixes were required to complete verification as specified; no scope creep beyond the plan's own `apps/api/src/shares` boundary.

## Issues Encountered
None beyond the two auto-fixed blocking issues above.

**D-04 backstop (documented, non-blocking per plan):** The plan's `must_haves.truths` flags a backstop that "needs live Postgres: a raw `UPDATE share_invites SET claim_count = -1` is rejected with SQLSTATE 23514." `apps/api` Jest mocks the DataSource, so this cannot be exercised in this plan's test run. Manual verification recipe for a future live-Postgres pass:
```sql
-- after migrations run
UPDATE share_invites SET claim_count = -1 WHERE id = '<any existing row>';
-- expected: ERROR: new row for relation "share_invites" violates check constraint "CHK_share_invites_claim_count" (SQLSTATE 23514)
```
This is explicitly NOT a blocking gate per the plan and 71-CONTEXT.md D-04.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The apps/api share plane and the regenerated `@cipherbox/api-client` now expose `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName`/`clearEncryptedWriteKey` end-to-end -- this is the compiler-guided foundation 71-02 (sdk/web consumer rename) builds on.
- `pnpm --filter @cipherbox/api test` (49 suites, 879 tests) and `pnpm --filter @cipherbox/api-client build` both pass cleanly on top of this plan's changes.
- No blockers for downstream plans in this phase's wave.

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*

## Self-Check: PASSED

- FOUND: apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts
- FOUND: apps/api/src/shares/entities/share.entity.ts
- FOUND: apps/api/src/shares/entities/share-invite.entity.ts
- FOUND: packages/api-client/openapi.json
- FOUND: .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-01-SUMMARY.md
- FOUND commit: 347b068 (Task 1)
- FOUND commit: 881eaff (Task 2)
- FOUND commit: 0e4a9d3 (Task 3)
- FOUND commit: f9e8ab2 (docs: summary)
