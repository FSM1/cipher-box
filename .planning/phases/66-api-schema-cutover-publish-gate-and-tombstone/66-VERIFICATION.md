---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
verified: 2026-06-30T00:00:00Z
status: passed
score: 6/6 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification: false
---

# Phase 66: API Schema Cutover, Publish Gate, and Tombstone — Verification Report

**Phase Goal:** The database reflects the `node/v3` model: `share_keys` deleted, `shares` slimmed to descriptor refs, `folder_ipns` renamed to `ipns_records` with `public_key` dropped, atomic CAS publish, tombstone state machine, and case-split resolve hardening.
**Verified:** 2026-06-30T00:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths (from ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| SC1 | `share_keys` table/entity deleted; `shares` carries descriptor-ref + root-identity columns; legacy `readKeyEcies`/`ShareGrant` shape gone from all entity, DTO, and service files | VERIFIED | `share-key.entity.ts` absent; `share.entity.ts` has `read_descriptor_ref`, `write_descriptor_ref`, `root_node_id`, `root_ipns_name`, `root_generation` + `@Unique(['sharerId','recipientId','rootNodeId'])`; `shares.service.ts` has 0 lines referencing ShareKey/shareKeyRepo/revokedAt/addShareKeys/getShareKeys/etc.; no `readKeyEcies`/`ShareGrant` in any shares source |
| SC2 | `folder_ipns` renamed to `ipns_records` (entity `IpnsRecord`); `public_key` column dropped; pubkey recovered exclusively via `publicKeyFromIpnsName`; Test 15 seqFloor path covers the null-shared-folder row | VERIFIED | `folder-ipns.entity.ts` absent; `ipns-record.entity.ts` has `@Entity('ipns_records')` class `IpnsRecord`; no `publicKey` field in entity; `ipns-record.codec.ts` has `publicKeyFromIpnsName` as sole pubkey recovery (comment: "D-03: public_key column dropped"); orchestrator confirmed Test 15 PASS (5/5) |
| SC3 | Publish is an atomic conditional UPDATE (`WHERE ipns_name = :ipnsName AND sequence_number = :expected AND generation <= :incoming AND tombstoned_at IS NULL`); two concurrent publishes at same expected seq → exactly one 409, zero lost updates | VERIFIED | `ipns.service.ts` L370: single `.update(IpnsRecord)` with 4-predicate WHERE; L379: `if (updateResult.affected === 0)` drives 0-row disambiguation; no in-memory CAS gate precedes the write; orchestrator confirmed Tests 16 + 17 PASS (5/5) |
| SC4 | `parseCachedRecord` null-case-split explicit: null-`signedRecord` shared-folder row returns `{ seqFloor }` discriminant; `resolveRecord` gates network record via `BigInt(networkSeq) >= BigInt(seqFloor)`; CID-mismatch fails closed | VERIFIED | `ipns-record.codec.ts` L90: `return { seqFloor: cached.sequenceNumber }` on null-signedRecord; `ipns.service.ts` L622-643: `isSeqFloor` type-narrow, floor comparison, fail-closed branch; orchestrator confirmed Test 15 PASS (5/5) |
| SC5 | Tombstoned row rejected at publish (410 IPNS_TOMBSTONED) and at resolve (410); EOL renewal also blocked via `tombstoned_at IS NULL` in CAS WHERE; server-side `generation` gate enforces forward-only | VERIFIED | `ipns.service.ts`: 2+ `HttpStatus.GONE` throws for tombstone cases (publish disambiguation L387 + resolve guard L607); `tombstoneRecord` method at L516 with `user_id = :userId` authz + `republishService.unenrollIpns`; `publish.dto.ts` has optional `generation` field; sdk-core `cas.ts` and `ipns/index.ts` forward `generation` to `ipnsControllerPublishRecord`; orchestrator confirmed Test 20 (tombstone) + TEE-07 (generation regression) PASS (5/5) |
| SC6 | `pnpm api:generate` run; regenerated `@cipherbox/api-client` committed; tombstone op + generation field + 410 marker in openapi.json; deleted share operations absent; `check-api-client.sh` passes | VERIFIED | `openapi.json` has `/ipns/tombstone` path with `IpnsController_tombstoneRecord`, generation field in publish schema (L2737), 410 responses on publish+resolve; generated `shares/shares.ts` has 0 references to GetShareKeys/AddShareKeys/GetPendingRotations/CompleteRotation/UpdatePermission/UpdateShareEncryptedKey; orchestrator confirmed API build + typecheck green |

**Score:** 6/6 truths verified

---

### Required Artifacts

| Artifact | Status | Evidence |
|----------|--------|----------|
| `apps/api/src/ipns/entities/ipns-record.entity.ts` | VERIFIED | Exists; class `IpnsRecord`; `@Entity('ipns_records')`; `tombstoned_at` + `generation` columns; no `publicKey` field |
| `apps/api/src/ipns/ipns.service.ts` (atomic CAS + tombstone) | VERIFIED | Single `.update(IpnsRecord)` with 4-predicate WHERE; `tombstoneRecord` method; 2+ IPNS_TOMBSTONED throws; `ipnsRecordRepository: Repository<IpnsRecord>` |
| `apps/api/src/ipns/ipns-record.codec.ts` (seqFloor discriminant) | VERIFIED | `SeqFloor` type at L25; `return { seqFloor: cached.sequenceNumber }` on null signedRecord; `publicKeyFromIpnsName` as sole pubkey path |
| `apps/api/src/ipns/ipns.controller.ts` (tombstone endpoint + 410 responses) | VERIFIED | `@Post('tombstone')` at L239; `@ApiResponse({ status: 410 })` on publish (L72) and resolve (L200) |
| `apps/api/src/ipns/dto/tombstone-ipns.dto.ts` | VERIFIED | Exists; single `ipnsName` field with k51 pattern validation |
| `apps/api/src/ipns/dto/publish.dto.ts` (generation field) | VERIFIED | Optional `generation?: string` at L117 with `@Matches(/^\d+$/)` |
| `apps/api/src/shares/entities/share.entity.ts` (descriptor refs) | VERIFIED | `read_descriptor_ref`, `write_descriptor_ref`, `root_node_id`, `root_ipns_name`, `root_generation`; `@Unique(['sharerId','recipientId','rootNodeId'])`; no `revokedAt`/`permission`/`OneToMany` |
| `apps/api/src/shares/shares.service.ts` (hard-delete revoke; descriptor-ref createShare) | VERIFIED | `revokeShare` calls `this.shareRepo.remove(share)`; `revokeForItems` matches `rootIpnsName: In(uniqueNames)` and `manager.remove(shares)`; `createShare` sets `readDescriptorRef`; 0 ShareKey/revokedAt references |
| `apps/api/src/shares/share-invite.service.ts` (single-readKey claim) | VERIFIED | `claimInvite` mints one `Share` with `readDescriptorRef` + `invite.rootNodeId`/`rootIpnsName`/`rootGeneration`; 0 ShareKey/childKeys references |
| `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` | VERIFIED | `DROP TABLE share_keys`; `CREATE TABLE ipns_records` with `tombstoned_at`+`generation`, no `public_key`; `CREATE TABLE shares` with `read_descriptor_ref` + `UNIQUE(sharer_id,recipient_id,root_node_id)`; `down()` throws |
| `packages/api-client/openapi.json` (regenerated) | VERIFIED | Tombstone endpoint, generation field, IPNS_TOMBSTONED 410 marker; deleted share ops absent |
| `packages/sdk-core/src/ipns/index.ts` (generation param) | VERIFIED | Optional `generation?: string` forwarded to `ipnsControllerPublishRecord` |
| `packages/sdk-core/src/cas.ts` (generation param) | VERIFIED | Optional `generation?: string` forwarded to `createAndPublishIpnsRecord` |
| `apps/web/src/services/share.service.ts` (compile-gate stubs) | VERIFIED | 5+ `throw new Error('deferred to Phase 68...')` stubs; 0 references to deleted endpoint functions; no Phase-68 rotation logic (rotateReadFromNode/IndexedDB absent) |
| `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` | VERIFIED | Exists; covers Tests 15/16/17/20 + TEE-07 generation regression; orchestrator confirmed 5/5 PASS |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| `ipns.module.ts` | `IpnsRecord` entity | `TypeOrmModule.forFeature([IpnsRecord])` | WIRED |
| `republish.module.ts` | `IpnsRecord` entity | `TypeOrmModule.forFeature([IpnsRepublishSchedule, IpnsRecord])` | WIRED |
| `vault.module.ts` | `IpnsRecord` entity | `TypeOrmModule.forFeature([Vault, PinnedCid, IpnsRecord, User, PendingUnpin])` | WIRED |
| `ipns.service.ts` publish path | atomic CAS UPDATE | `.update(IpnsRecord).where('...AND tombstoned_at IS NULL')` | WIRED |
| `ipns.service.ts` tombstone path | 410 IPNS_TOMBSTONED | `HttpException({error:'IPNS_TOMBSTONED'}, HttpStatus.GONE)` at publish (L387) + resolve (L607) | WIRED |
| `ipns-record.codec.ts` | `publicKeyFromIpnsName` | D-03 sole pubkey recovery path; `cached.publicKey` removed | WIRED |
| `shares.service.ts` revoke | hard-DELETE | `this.shareRepo.remove(share)` / `manager.remove(shares)` | WIRED |
| `sdk-core cas.ts` | API generation field | `generation: params.generation` in `ipnsControllerPublishRecord` call | WIRED |
| `openapi.json` | deleted share ops | GetShareKeys/AddShareKeys/etc. absent from generated `shares/shares.ts` | WIRED (absence confirmed) |

### Behavioral Spot-Checks

Behavioral evidence provided by orchestrator (authoritative per orchestrator context — sdk-e2e must NOT be re-run by verifier per D-08/[[feedback-gsd-subagents-no-test-runs]]):

| Behavior | Test | Result |
|----------|------|--------|
| TEE-04: concurrent forward publishes → one 200 + one 409, seq=2 | Test 16 (sdk-e2e ipns-publish-gate) | PASS (orchestrator) |
| TEE-04: renewal at stale expected → 409 (not 410), latestCid stays | Test 17 (sdk-e2e ipns-publish-gate) | PASS (orchestrator) |
| TEE-07: generation regression → 409, generation never regresses | TEE-07 case (sdk-e2e ipns-publish-gate) | PASS (orchestrator) |
| WRITE-04: tombstone → publish 410 IPNS_TOMBSTONED + resolve 410 | Test 20 (sdk-e2e ipns-publish-gate) | PASS (orchestrator) |
| TEE-05: seqFloor — at/above floor serves; below-floor fails closed | Test 15 (sdk-e2e ipns-publish-gate) | PASS (orchestrator) |

Full SDK-e2e suite: 5/5 PASS.

### Requirements Coverage

| Requirement | Description | Plans | Status | Evidence |
|-------------|-------------|-------|--------|----------|
| DATA-01 | `share_keys` table and entity deleted outright | 66-03, 66-04, 66-05, 66-09 | SATISFIED | `share-key.entity.ts`/`share-key.dto.ts` absent; migration drops `share_keys CASCADE`; shares.service has 0 ShareKey references |
| DATA-02 | `shares` slimmed to one grant row per recipient with `readDescriptorRef`/`writeDescriptorRef` | 66-03, 66-04, 66-05, 66-06, 66-08, 66-09 | SATISFIED | `share.entity.ts` has descriptor-ref columns; createShare sets readDescriptorRef; claimInvite mints single Share; legacy shape gone from entity/DTO/service |
| DATA-03 | `folder_ipns` renamed to `ipns_records`; `public_key` dropped; pubkey recovered via `publicKeyFromIpnsName` | 66-01, 66-05, 66-09 | SATISFIED | Entity renamed, column dropped, migration recreates table without `public_key`, sole pubkey recovery is `publicKeyFromIpnsName` |
| DATA-04 | Schema ready for shared-delete grant re-mint/revoke; hard-delete on revoke; `revokeForItems` by `rootIpnsName` | 66-03, 66-04, 66-09 | SATISFIED | `revokeShare` hard-deletes; `revokeForItems` matches `rootIpnsName: In(names)` and hard-removes; `rootGeneration` on Share and ShareInvite for caller in Phase 68 |
| TEE-04 | Publish is atomic CAS (`WHERE sequence_number = :expected`; 0 rows → 409); EOL renewal gated identically | 66-02, 66-09 | SATISFIED | Single `.update(IpnsRecord)` with 4-predicate WHERE including `tombstoned_at IS NULL`; Tests 16/17 PASS |
| TEE-05 | Resolve case-split fail-closed: null-signedRecord applies seq floor; CID mismatch fails closed | 66-02, 66-09 | SATISFIED | `parseCachedRecord` returns `{ seqFloor }` discriminant; `resolveRecord` gates on `networkSeq >= floorSeq`; Test 15 PASS |
| TEE-07 | Publish gate enforces forward-only `generation` per node server-side | 66-02, 66-07, 66-09 | SATISFIED | `generation <= CAST(:incoming AS bigint)` in CAS WHERE; optional `generation` param in sdk-core publish primitives; TEE-07 test PASS |

All 7 requirement IDs from PLAN frontmatter are accounted for and satisfied.

### Anti-Patterns Found

None. Scan of all modified production files (ipns.service.ts, ipns-record.codec.ts, shares.service.ts, share-invite.service.ts, ipns-record.entity.ts, share.entity.ts, migration, sdk-core, web share.service.ts, sdk-e2e test) returned 0 TBD/FIXME/XXX markers. Phase-68 deferrals in web share.service.ts use `throw new Error('deferred to Phase 68...')` — these are intentional, loud, and correctly scoped.

The `update-encrypted-key.dto.ts` file remains in `apps/api/src/shares/dto/` (not referenced by any current controller or service); this is an orphan but not a blocker — no route or service calls it.

### Human Verification Required

None. All truths are mechanically verifiable from the codebase and the orchestrator-confirmed sdk-e2e run.

---

## Gaps Summary

No gaps. All 6 success criteria are verified against the codebase:

1. `share_keys` deleted; descriptor-ref `shares` schema in place — code + migration confirmed.
2. `folder_ipns` renamed, `public_key` dropped, sole pubkey path is `publicKeyFromIpnsName` — code confirmed; Test 15 exercises the shared-folder null-signedRecord path.
3. Atomic CAS publish with 4-predicate WHERE and `result.affected` outcome — code confirmed; Tests 16/17 PASS (orchestrator).
4. `parseCachedRecord` 3-way union with explicit seqFloor discriminant and fail-closed CID-mismatch branch — code confirmed; Test 15 PASS (orchestrator).
5. Tombstone 410 on publish + resolve; generation forward-only gate; EOL renewal blocked by same `tombstoned_at IS NULL` WHERE — code confirmed; Test 20 + TEE-07 PASS (orchestrator).
6. Regenerated api-client committed with tombstone op, generation field, 410 marker, deleted share ops absent — confirmed in openapi.json and generated files.

---

_Verified: 2026-06-30T00:00:00Z_
_Verifier: Claude (gsd-verifier)_
