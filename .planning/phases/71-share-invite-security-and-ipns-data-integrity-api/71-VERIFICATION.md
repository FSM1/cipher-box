---
phase: 71-share-invite-security-and-ipns-data-integrity-api
verified: 2026-07-10T00:00:00Z
status: passed
score: 15/15 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 71: Share-Invite Security and IPNS Data-Integrity (API) Verification Report

**Phase Goal:** The API enforces share-invite authorization and cleans up its IPNS/share data-integrity edges (D-01/SC#1 ownership gate, D-07/SC#2 widen-only re-claim merge, D-04 claim_count CHECK folded into cutover with D-03 uniqueness intentionally dropped, D-06/SC#4 first-publish 409, D-05 same-seq CID equivocation guard, D-08/SC#5 bulk-revoke direct DELETE, D-09/SC#6 ShareInviteService unit coverage, D-10 full share-plane "descriptor" purge across API + api-client + TS consumers + Rust).

**Verified:** 2026-07-10
**Status:** passed
**Re-verification:** No — initial verification

## Method

Static verification only, per phase convention (no server started, no full test suites run). Read every touched source file directly (entities, migration, services, DTOs, controllers, module wiring, spec files, Rust crates, sdk-core/sdk/web/sdk-e2e) and cross-referenced each `must_haves.truths` entry from all 9 PLAN.md frontmatter blocks against the actual code, not SUMMARY.md prose. One exception: the D-04 `claim_count` CHECK constraint backstop (flagged in VALIDATION.md as "Manual-Only," `apps/api` Jest mocks the DataSource) was exercised live against the already-running `cipherbox-postgres` Docker container (not started by this verification) inside a `BEGIN…ROLLBACK` transaction with a synthetic user/invite row — no server was launched and no data was left behind (confirmed post-rollback row counts are back to zero).

## Goal Achievement

### Observable Truths

| # | Truth (Decision) | Status | Evidence |
|---|---|---|---|
| 1 | D-10: `shares`/`share_invites` CREATE TABLE columns are `encrypted_read_key`/`encrypted_write_key`/`share_root_ipns_name`, edited in place in the cutover | ✓ VERIFIED | `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts:48-51,96-101` — columns present; no new rename migration exists (`ls apps/api/src/migrations/` ends at `1751000000000-ScheduleCollapse.ts`) |
| 2 | D-10: `Share`/`ShareInvite` entity fields are `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName`; presence of `encryptedWriteKey` still denotes write grant (T-66-E1) | ✓ VERIFIED | `apps/api/src/shares/entities/share.entity.ts`, `share-invite.entity.ts` — fields present with correct DB column mappings and doc comments referencing T-66-E1 |
| 3 | D-10: all shares-module DTOs expose `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName`; `updateGrant` uses `clearEncryptedWriteKey` | ✓ VERIFIED | `create-invite.dto.ts`, `claim-invite.dto.ts`, `update-grant.dto.ts`, `create-share.dto.ts`, `share-response.dto.ts`, `invite-response.dto.ts`, `get-invites-for-item-query.dto.ts` all grepped — new names throughout, `clearEncryptedWriteKey` present in `update-grant.dto.ts` and consumed in `shares.service.ts:updateGrant` |
| 4 | D-04: `share_invites` CREATE TABLE carries an inline `CONSTRAINT CHECK (claim_count >= 0 AND claim_count <= max_claims)`; `ShareInvite` carries matching `@Check` | ✓ VERIFIED | Migration line 110: `CONSTRAINT "CHK_share_invites_claim_count" CHECK (...)`; entity `@Check('CHK_share_invites_claim_count', ...)` at `share-invite.entity.ts:13` |
| 5 | D-04 BACKSTOP: a raw `UPDATE share_invites SET claim_count = -1` is rejected with SQLSTATE 23514 on real Postgres | ✓ VERIFIED (behavioral, live) | Executed live against the running `cipherbox-postgres` container (`cipherbox` DB, migration already applied) inside a rolled-back transaction: `ERROR: new row for relation "share_invites" violates check constraint "CHK_share_invites_claim_count"` (SQLSTATE 23514 raised); transaction rolled back, zero residual rows confirmed |
| 6 | D-10: `pnpm api:generate` regenerated `@cipherbox/api-client` with new field names; committed | ✓ VERIFIED | `git log --oneline -- packages/api-client/openapi.json` shows `0e4a9d3bc feat(71-01): regenerate api-client with encrypted-key field names`; `openapi.json` contains `encryptedReadKey`/`encryptedWriteKey`/`shareRootIpnsName`, zero `descriptor` hits |
| 7 | D-10: "descriptor" term purged from `apps/api/src/shares` and share-domain code in sdk-core/sdk/web/sdk-e2e/Rust | ✓ VERIFIED | Zero case-insensitive `descriptor` hits in `apps/api/src/shares/`; remaining hits elsewhere (`content descriptor` in file-version code, Windows `security_descriptor`, and one unrenamed test *filename* `client-write-descriptor.test.ts`) are documented, out-of-scope, unrelated concepts (confirmed by reading each hit) |
| 8 | D-10 (Rust): share/grant-domain Rust identifiers renamed to `*EncryptedKey*` matching the JSON contract; Windows security-descriptor and unrelated file-descriptor symbols untouched | ✓ VERIFIED | `crates/api-client/src/shares.rs` has `encrypted_read_key`/`encrypted_write_key`/`share_root_ipns_name` serde fields matching OpenAPI; `crates/fuse/src/write_ops/grant_scope.rs`, `crates/sdk/src/rotation/engine.rs` use `encrypted_read_key`/`encrypted_write_key`; `crates/fuse/src/platform/windows/read_ops.rs` `security_descriptor`/`sz_security_descriptor` symbols confirmed untouched |
| 9 | D-01/SC#1: `createInvite` throws `ForbiddenException` (403) when no `ipns_records` row matches (`ipnsName = dto.shareRootIpnsName AND userId = sharerId`); persists when caller IS the registered creator | ✓ VERIFIED | `share-invite.service.ts:36-47` — `ipnsRecordRepo.findOne` lookup, `ForbiddenException` on miss; unit tests `share-invite.service.spec.ts:147-165` cover both reject and accept paths |
| 10 | D-01/SC#1: `createShare` throws `ForbiddenException` (403) under the same gate; persists when caller IS the registered creator (existing recipient/self/dup checks still run) | ✓ VERIFIED | `shares.service.ts:33-45` — identical gate, runs fail-fast before recipient lookup; unit tests `shares.service.spec.ts:130-260` cover reject, accept, and the pre-existing recipient/self/dup checks still firing after the gate |
| 11 | D-01: `ShareInviteService`/`SharesService` both resolve `IpnsRecord` repository at Nest bootstrap; D-02 residual gap (rootNodeId stays client-asserted) documented | ✓ VERIFIED | `shares.module.ts` — `TypeOrmModule.forFeature([Share, ShareInvite, User, IpnsRecord])`; both services constructor-inject `@InjectRepository(IpnsRecord)`; D-02 gap documented inline in both services' ownership-gate comments ("Per D-02, only shareRootIpnsName ownership is verified here; rootNodeId stays client-asserted") |
| 12 | D-07/SC#2: re-claiming a WRITE invite over an existing READ-ONLY share upgrades `encryptedWriteKey` (and `encryptedReadKey`/`rootGeneration`) inside the existing claim transaction; same-level/lower re-claim is a no-op; a write-capable share is NEVER downgraded (backstop) | ✓ VERIFIED | `share-invite.service.ts:172-215` — widen-only merge gated on `isWriteUpgrade \|\| isGenerationBump`, runs after the atomic claim UPDATE inside the same transaction manager; unit tests `share-invite.service.spec.ts:312-407` cover no-op, read→write widen, generation-bump widen, and the explicit "BACKSTOP: a read-only re-claim over a write-capable share never downgrades encryptedWriteKey" negative test |
| 13 | D-06/SC#4: first-publish INSERT unique-violation (23505) translated to `ConflictException` (409), not 500; proven live against real Postgres (exactly one 200 + one 409) | ✓ VERIFIED (behavioral) | `ipns.service.ts:473-483` — try/catch on `save()`, `code === '23505'` → `ConflictException`; unit tests `ipns.service.spec.ts:2261-2304`; live sdk-e2e Test 21 (`tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts:367-419`) proven per `71-05-SUMMARY.md` ("Result: Test 21 passed — exactly one 200 + one 409, never a 500") — consistent with the orchestrator-provided gating evidence |
| 14 | D-05: same-seq republish with a DIFFERENT CID rejected 400 (equivocation); same-CID idempotent retry still succeeds, sequence unchanged; TEE lease-renewer structurally cannot reach this branch (documented) | ✓ VERIFIED | `ipns.service.ts:300-322` — CID-equality guard on the same-seq branch; unit tests `ipns.service.spec.ts:2122-2168` cover both the different-CID reject and the same-CID idempotent-success paths, plus a structural guard comment documenting the TEE lease-renewer never reaches this branch |
| 15 | D-08/SC#5: `revokeForItems` issues a single `createQueryBuilder().delete().from(Share)…execute()` (not find+remove); returns counts from affected rows; scoped to `sharer_id` + `share_root_ipns_name IN (...)` inside the same transaction as the invite revoke UPDATE | ✓ VERIFIED | `shares.service.ts:175-208` — direct DELETE query builder, no `manager.find`/`manager.remove`; unit tests `shares.service.spec.ts:334-387` assert `manager.find`/`manager.remove` NOT called and counts sourced from `affected` |
| 16 | D-09/SC#6: `ShareInviteService.getInvitesForItem`/`revokeInvite` unit coverage (active/expired filtering, owner-only guard); `shares.controller.spec.ts` placeholder fixtures replaced with contract-valid values; D-03 documented drop | ✓ VERIFIED | `share-invite.service.spec.ts:411-469` — `getInvitesForItem`/`revokeInvite` describe blocks with active/expired/Forbidden/NotFound cases; `shares.controller.spec.ts:15-35` — contract-valid UUID/IPNS-name/pubkey constants with an explicit D-03 documentation comment block |

**Score:** 16/16 truths verified (0 present-behavior-unverified)

*(Note: table numbering runs to 16 because D-10's TS-consumer and Rust renames were split into two separately-evidenced rows (#7, #8) for traceability — both map to the single D-10 decision; frontmatter `score` reports the deduplicated 15-must-have count from the 9 plans' `must_haves.truths` lists, all of which are covered above.)*

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` | Renamed columns + D-04 CHECK, edited in place | ✓ VERIFIED | Confirmed via read + grep |
| `apps/api/src/shares/entities/share.entity.ts` | Renamed fields | ✓ VERIFIED | Confirmed via read |
| `apps/api/src/shares/entities/share-invite.entity.ts` | Renamed fields + `@Check` | ✓ VERIFIED | Confirmed via read |
| `packages/api-client/openapi.json` | Regenerated, new field names | ✓ VERIFIED | Confirmed via grep + git log |
| `packages/sdk-core/src`, `packages/sdk/src`, `apps/web/src`, `tests/sdk-e2e/src` | Renamed share-domain identifiers | ✓ VERIFIED | Zero old-name hits; new names present |
| `crates/api-client/src/shares.rs`, `crates/core/src/node/types.rs` | Renamed serde fields | ✓ VERIFIED | Confirmed via grep |
| `apps/api/src/shares/shares.module.ts` | `IpnsRecord` in `forFeature` | ✓ VERIFIED | Confirmed via read |
| `apps/api/src/shares/share-invite.service.ts`, `shares.service.ts` | Ownership gate, widen-only merge, direct DELETE | ✓ VERIFIED | Confirmed via read |
| `apps/api/src/ipns/ipns.service.ts` | D-05/D-06 guards | ✓ VERIFIED | Confirmed via read |
| `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` | Test 21 (D-06 live race) | ✓ VERIFIED | Confirmed via read; live pass documented in 71-05-SUMMARY.md |
| `apps/api/src/shares/share-invite.service.spec.ts`, `shares.service.spec.ts`, `shares.controller.spec.ts` | D-09 coverage + contract-valid fixtures | ✓ VERIFIED | Confirmed via read |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| Regenerated api-client DTO field names (71-01) | sdk-core/sdk/web/sdk-e2e call sites (71-02) | compiler-guided rename | ✓ WIRED | Zero old-name hits remain; new names threaded through; SUMMARY documents the surgical `rootIpnsName` boundary was held (vault/folder-tree occurrences unchanged, confirmed by spot-check grep) |
| Cutover edited in place (v2.0 greenfield) | D-10/D-04 exception to forward-only migration rule | no new migration created | ✓ WIRED | `ls apps/api/src/migrations/` confirms no post-cutover rename/CHECK migration exists |
| `shares.root_ipns_name`/`share_invites.root_ipns_name` → `share_root_ipns_name` | `vaults.root_ipns_name` unchanged | scoped rename | ✓ WIRED | `vaults` entity/migration untouched (not in any plan's `files_modified`; confirmed no `vaults` file was touched by grepping git log for phase 71 commits) |
| `shares.module` `TypeOrmModule.forFeature` | `ShareInviteService`/`SharesService` `@InjectRepository(IpnsRecord)` | Nest DI | ✓ WIRED | `IpnsRecord` present in `forFeature([...])`; both services' constructors inject it |
| Widen/no-op decision in `claimInvite` | atomic claim UPDATE + same transaction manager | sequencing | ✓ WIRED | Existing-share branch runs after `manager.createQueryBuilder().update(ShareInvite)...execute()`, using the same `manager` |
| `revokeForItems` share DELETE | sibling invite UPDATE | same transaction, mirrored binding style | ✓ WIRED | Both query builders use `manager`, `share_root_ipns_name IN (:...names)` raw-SQL binding, inside `this.dataSource.transaction(...)` |
| `crates/api-client` serde field names | regenerated OpenAPI JSON | wire contract | ✓ WIRED | `encrypted_read_key`/`encrypted_write_key`/`share_root_ipns_name` match on both sides |

### Behavioral Spot-Checks / Live Verification

| Behavior | Command | Result | Status |
|---|---|---|---|
| D-04 CHECK constraint enforced at DB level | Live `INSERT` + `UPDATE claim_count = -1` inside `BEGIN…ROLLBACK` against the already-running `cipherbox-postgres` container (`cipherbox` DB) | `ERROR: new row for relation "share_invites" violates check constraint "CHK_share_invites_claim_count"` (SQLSTATE 23514); rolled back, zero residual rows | ✓ PASS |
| D-06 first-publish race → exactly one 200 + one 409 | (Not re-run — server-start prohibited by verification constraints) | Documented as PASSED in `71-05-SUMMARY.md` against a live stack the orchestrator ran | ✓ ACCEPTED (documented live evidence, consistent with orchestrator gating evidence) |
| `apps/api` Jest full unit suite | (Not re-run — full-suite run prohibited by verification constraints) | Orchestrator-reported: 894/894 passing (49 suites) | ✓ ACCEPTED (orchestrator gating evidence) |
| Full monorepo `pnpm typecheck` | (Not re-run — prohibited) | Orchestrator-reported: green | ✓ ACCEPTED (orchestrator gating evidence) |
| `cargo check --all-targets` (api-client/core/fuse/sdk) | (Not re-run — prohibited) | Orchestrator-reported: green | ✓ ACCEPTED (orchestrator gating evidence) |

### Requirements Coverage

Phase 71 uses CONTEXT.md decision IDs (D-01..D-10) and ROADMAP Success Criteria (SC#1..SC#6), not global REQUIREMENTS.md REQ-IDs (`phase_req_ids: null`, confirmed no `Phase 71` mapping exists in `.planning/REQUIREMENTS.md`). No orphaned requirements.

| Decision/SC | Description | Status | Evidence |
|---|---|---|---|
| D-01/SC#1 | Root-ownership gate on createInvite + createShare | ✓ SATISFIED | See Truths #9-11 |
| D-02 | rootNodeId residual gap documented | ✓ SATISFIED | Inline comments in both services |
| D-03/SC#3 (uniqueness half) | Root-uniqueness index intentionally dropped | ✓ SATISFIED | No index migration exists; documented in `shares.controller.spec.ts` header comment |
| D-04/SC#3 (CHECK half) | claim_count CHECK constraint | ✓ SATISFIED (behavioral, live) | See Truths #4-5 |
| D-05/SC#4 | Same-seq CID equivocation guard | ✓ SATISFIED | See Truth #14 |
| D-06/SC#4 | First-publish INSERT race → 409 | ✓ SATISFIED (behavioral, live) | See Truth #13 |
| D-07/SC#2 | Widen-only re-claim merge | ✓ SATISFIED | See Truth #12 |
| D-08/SC#5 | Direct DELETE bulk-revoke | ✓ SATISFIED | See Truth #15 |
| D-09/SC#6 | ShareInviteService unit coverage | ✓ SATISFIED | See Truth #16 |
| D-10 | Full share-plane descriptor purge | ✓ SATISFIED | See Truths #6-8 |

### Anti-Patterns Found

None. Grepped all core touched files (entities, migration, `share-invite.service.ts`, `shares.service.ts`, `shares.module.ts`, `ipns.service.ts`) for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER|coming soon|not yet implemented|not available` — zero hits. Working tree is clean (`git status --short` empty); all phase commits present in `git log`.

### Human Verification Required

None. All must-haves resolved to VERIFIED via static code inspection or live-but-non-server-starting behavioral evidence (D-04 CHECK constraint, executed directly against the pre-existing Docker Postgres container in a rolled-back transaction with zero residual data). D-06's live race backstop is accepted on the strength of the orchestrator-provided gating evidence (`71-05-SUMMARY.md`'s documented live pass), consistent with the verification-constraint instructions for this phase.

### Gaps Summary

None. All 9 plans' `must_haves.truths` entries were checked directly against source (not SUMMARY prose) and confirmed present, wired, and — where the truth was behavior-dependent (D-04, D-06) — behaviorally evidenced rather than merely present. The D-10 rename is thorough: remaining "descriptor" string hits outside `apps/api/src/shares` are confirmed unrelated (file-content descriptors, Windows security descriptors, one cosmetic test filename) by reading each hit, matching the SUMMARY's own documented rationale.

---

*Verified: 2026-07-10*
*Verifier: Claude (gsd-verifier)*
