# Phase 66: API Schema Cutover, Publish Gate, and Tombstone - Research

**Researched:** 2026-06-30
**Domain:** NestJS/TypeORM schema cutover, atomic CAS publish gate, tombstone state machine, IPNS resolve hardening
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01** — Migration = destructive drop-recreate. FK-map research runs first. `down()` may be minimal/throw. Reversibility discipline waived under greenfield.
- **D-02** — Add only `tombstoned_at timestamptz NULL` + `generation bigint NOT NULL DEFAULT 0` to `ipns_records`. No richer status enum yet.
- **D-03** — Publish gate = ONE atomic conditional UPDATE. 0 rows → follow-up read to distinguish 409 vs 410.
- **D-04** — DATA-04 = schema + endpoints + proof here; live rotation→grant caller defers to Phase 68/69.
- **D-05** — Keep + slim `share_invites`. Drop `encrypted_child_keys`. `encrypted_key` = single ephemeral-wrapped root `readKey`.
- **D-06** — `UNIQUE (sharer_id, recipient_id, root_node_id)` (plain, not partial). Retain `sharer_id` for multi-sharer semantics.
- **D-07** — Resolve-410 = `{ error: 'IPNS_TOMBSTONED', ipnsName }` body flowing through `api:generate` into `@cipherbox/api-client`.
- **D-08** — ALL proof runs through `tests/sdk-e2e`. Checker subagents stay static-analysis only. Orchestrator/human gate = e2e run.
- **D-09** — Drop `permission` column; derive write-vs-read from `writeDescriptorRef IS NOT NULL`.
- **D-10** — `ipns_records` TEE/resolve columns carry over unchanged (`encrypted_ipns_private_key`, `key_epoch`, `signed_record`). TEE signing-input reshape is Phase 67.
- **D-11** — Revoke = hard DELETE the `shares` row. No `revoked_at`. Scope-exit scope-exit re-mint = UPDATE of active row (distinct action).

### Claude's Discretion

- Exact 409-vs-410 disambiguation after 0-row CAS (single follow-up read preferred).
- Whether `generation`/`root_generation` are `bigint` (string in TypeORM) or `int` — match seq convention (`bigint`).
- Internal migration factoring (one file vs small ordered set, all forward) and FK drop/recreate ordering — recreate must be atomic and re-wire every referencing table.
- Precise typed shape of 410 marker body and NestJS wiring, as long as it flows through `api:generate`.
- How `tests/sdk-e2e` forces the concurrent-CAS race deterministically.

### Deferred Ideas (OUT OF SCOPE)

- `ipns_republish_schedule` duplicated-column collapse → Phase 67 (TEE-03).
- TEE lease-renewer contract + enclave bindings → Phase 67 (TEE-01/02/06).
- Durable client-side `{nodeId→highestGeneration/Seq}` high-water → Phase 68 (ROT-07).
- Live rotation→grant re-mint/revoke caller flow → Phase 68 (web) / 69 (FUSE).
- Richer `ipns_records` status enum → Phase 67 if needed.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DATA-01 | Delete `share_keys` table + entity + `addShareKeys` endpoint/service/controller | Section: share_keys map; shares.controller.ts ~L267 POST `:shareId/keys` + shares.service.ts ~L207 |
| DATA-02 | Slim `shares` to one grant row per recipient with `readDescriptorRef`/`writeDescriptorRef` | Section: shares reshape; current columns enumerated; target constraint defined |
| DATA-03 | Rename `folder_ipns` → `ipns_records`, drop `public_key` | Section: FK map confirms no external FKs; publicKeyFromIpnsName confirmed in @cipherbox/crypto |
| DATA-04 | `shares` schema + endpoints ready for shared-delete grant re-mint/revoke; live caller defers | Section: shares service methods; endpoint inventory |
| TEE-04 | Atomic CAS publish (`UPDATE … WHERE ipnsName AND sequenceNumber = :expected`; 0 rows → 409) | Section: current upsertFolderIpns TOCTOU gap documented; atomic UPDATE pattern |
| TEE-05 | Resolve anti-rollback case-split: DB-canonical + `generation` authority; fail-closed fall-through | Section: parseCachedRecord current behavior; case-split target |
| TEE-07 | Server-side forward-only `generation` per node (publish-gate defence-in-depth) | Section: atomic UPDATE WHERE clause includes `generation <= :incoming` |
</phase_requirements>

---

## Summary

Phase 66 delivers the `node/v3` DB schema and the publish/resolve integrity plane for `apps/api`. The work falls into four coordinated streams: (1) destructive drop-recreate migration, (2) atomic CAS publish gate + tombstone state machine on `ipns_records`, (3) `shares` descriptor-ref reshape + `share_keys` deletion, and (4) proof suite in `tests/sdk-e2e`.

The FK map investigation reveals the migration is simpler than CONTEXT.md implied: **no table has a SQL foreign key referencing `folder_ipns(id)`**. The `ipnsName` column in `shares`, `vaults`, and `ipns_republish_schedule` is a plain varchar — not a FK constraint. The rename is therefore a pure drop-recreate with no cascade ordering required beyond the within-`shares`-ecosystem `share_keys → shares` FK.

The current `publishRecord` / `upsertFolderIpns` path is a non-atomic `findOne → gate → save` sequence with a confirmed TOCTOU gap. The atomic replacement must be a single `UPDATE ipns_records SET … WHERE ipns_name = :n AND sequence_number = :expected AND generation <= :incoming AND tombstoned_at IS NULL`; 0 rows triggers a follow-up read to distinguish 409 from 410.

**Primary recommendation:** Execute streams in order: migration file → entity/repository rename → shares reshape → atomic CAS service rewrite → 410 endpoint wiring → `pnpm api:generate` → sdk-e2e proofs.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| IPNS publish CAS gate | API / Backend | — | DB serialization point; relay writes DB synchronously before DHT push |
| `ipns_records` tombstone state | API / Backend | — | Publish gate + resolve both read DB row |
| `shares` grant rows | API / Backend | — | Server stores grant descriptor refs; zero-knowledge wrapping happens client-side |
| `public_key` column removal | API / Backend | — | Function `publicKeyFromIpnsName` recovers from the k51 name; column was null for shared rows |
| 410 tombstone marker | API / Backend | `@cipherbox/api-client` | NestJS exception → OpenAPI spec → generated client SDK |
| E2E proof suite | `tests/sdk-e2e` | — | Only real client→API round-trip; all §7.3 proofs run here per D-08 |

---

## FK Map (D-01 Sub-Phase Research)

**Result: `folder_ipns` has zero SQL foreign key dependents from other tables.** [VERIFIED: reading migration files + entity files]

The CONTEXT.md phrase "FKs on `ipns_republish_schedule`/`shares`/`vaults` re-established" referred to verifying those tables — not to FK constraints pointing at `folder_ipns`. All three reference `ipnsName` as a plain `varchar(255)` column:

| Table | Column | Type | FK to `folder_ipns`? |
|-------|--------|------|----------------------|
| `ipns_republish_schedule` | `ipns_name` | `varchar(255)` | No — only FK is to `users(id)` |
| `shares` | `ipns_name` | `varchar(255)` | No — FKs are to `users(id)` only |
| `vaults` | `root_ipns_name` | `varchar(255)` | No — only FK is to `users(id)` |

**Current `folder_ipns` constraints (verified from migrations):** [VERIFIED: reading 1700000000000-FullSchema.ts + incremental migrations]

| Constraint name | Type | Columns / Target |
|----------------|------|-----------------|
| `PK_folder_ipns` | PRIMARY KEY | `id` |
| `UQ_folder_ipns_ipns_name` | UNIQUE | `ipns_name` (from migration 1749300000000) |
| `FK_folder_ipns_user` | FOREIGN KEY | `user_id` → `users(id)` ON DELETE CASCADE |
| `IDX_folder_ipns_user_id` | INDEX | `user_id` |

**Current `share_keys` constraints:**

| Constraint name | Type | Columns / Target |
|----------------|------|-----------------|
| `PK_share_keys` | PRIMARY KEY | `id` |
| `UQ_share_keys_share_type_item` | UNIQUE | `(share_id, key_type, item_id)` |
| `FK_share_keys_share` | FOREIGN KEY | `share_id` → `shares(id)` ON DELETE CASCADE |
| `IDX_share_keys_share_id` | INDEX | `share_id` |
| `IDX_share_keys_item_id` | INDEX | `item_id` |

**Current `shares` constraints:**

| Constraint name | Type | Columns / Target |
|----------------|------|-----------------|
| `PK_shares` | PRIMARY KEY | `id` |
| `UQ_shares_active_triple` | UNIQUE (partial, `WHERE revoked_at IS NULL`) | `(sharer_id, recipient_id, ipns_name)` |
| `FK_shares_sharer` | FOREIGN KEY | `sharer_id` → `users(id)` ON DELETE CASCADE |
| `FK_shares_recipient` | FOREIGN KEY | `recipient_id` → `users(id)` ON DELETE CASCADE |
| `IDX_shares_sharer_id` | INDEX | `sharer_id` |
| `IDX_shares_recipient_id` | INDEX | `recipient_id` |
| `IDX_shares_ipns_name` | INDEX | `ipns_name` |

**Migration drop/recreate ordering:**

1. `DROP TABLE share_keys CASCADE` (removes `FK_share_keys_share`; safe because `shares` is not yet dropped)
2. `DROP TABLE shares CASCADE` (removes sharer/recipient FKs; safe because `users` persists)
3. `CREATE TABLE shares` with new schema (D-06/D-09/D-11)
4. `DROP TABLE folder_ipns CASCADE` (no dependents; safe)
5. `CREATE TABLE ipns_records` with new schema (D-02/D-10)

`share_invites` `encrypted_child_keys` column can be dropped with `ALTER TABLE … DROP COLUMN IF EXISTS`.

**TypeORM migration class pattern (newest migration 1749400000000-DropFolderIpnsRecordType.ts):**

```typescript
import { MigrationInterface, QueryRunner } from 'typeorm';

export class ApiSchemaCutover1750000000000 implements MigrationInterface {
  name = 'ApiSchemaCutover1750000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // raw queryRunner.query() calls with SQL strings
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // minimal / throw — greenfield waiver (D-01)
  }
}
```

New migration timestamp: `1750000000000` (next after `1749400000000`).

---

## Standard Stack

### Core (all existing, no new dependencies)

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| TypeORM | (existing) | ORM + migration runner | `MigrationInterface`, `QueryRunner`, `Repository` |
| NestJS | ^11.0.0 | HTTP framework | `GoneException`, `HttpException`, `HttpStatus.GONE` = 410 confirmed |
| `@cipherbox/crypto` | (workspace) | `publicKeyFromIpnsName` | Exported from `packages/crypto/src/index.ts` L77; dist type at `packages/crypto/dist/index.d.ts` L46 |
| Vitest | ^3.0.5 | E2E test runner | `tests/sdk-e2e/vitest.config.ts`; `sequence: { concurrent: false }` |

**No new packages needed.** [VERIFIED: reading entity files, package.json, and node_modules]

---

## Package Legitimacy Audit

> No new external packages required for this phase. All dependencies are existing workspace packages or already-installed NestJS/TypeORM dependencies.

**Packages removed due to SLOP verdict:** none
**Packages flagged as suspicious SUS:** none

---

## Architecture Patterns

### System Architecture Diagram

```
Client (sdk-core)
   │ POST /ipns/publish { record, ipnsName, metadataCid, expectedSequenceNumber, ... }
   ▼
IpnsController.publishRecord
   │
   ▼
IpnsService.publishRecord
   ├─ verify Ed25519 signature (existing, unchanged)
   ├─ parse embedded seq
   │
   └─ ATOMIC UPDATE ipns_records
      WHERE ipns_name = :n
        AND sequence_number = :expected      ← CAS
        AND generation <= :incoming          ← forward-only gate (TEE-07)
        AND tombstoned_at IS NULL            ← tombstone gate
      ── 0 rows ─► follow-up findOne ──► tombstoned_at IS NOT NULL → 410 IPNS_TOMBSTONED
      │                                  └► seq mismatch / gen regression → 409 Conflict
      └─ 1 row ─► fire-and-forget DHT push → 200

GET /ipns/resolve?ipnsName=k51...
   ▼
IpnsService.resolveRecord
   ├─ try delegatedRouting.resolve (network) → parseIpnsRecordBytes
   ├─ findOne({ where: { ipnsName } }) → check tombstoned_at
   │     ├─ tombstoned_at IS NOT NULL → throw 410 IPNS_TOMBSTONED (D-07)
   │     └─ parseCachedRecord case-split:
   │          ├─ signedRecord null (shared-folder row) → apply seq floor, serve with network gate
   │          └─ signedRecord CID ≠ latestCid → fail closed (null → 404)
   └─ prefer DB when dbSeq >= networkSeq (existing logic)

Tombstone write path (WRITE-04):
   Client rotateWriteFromNode → calls teeUnenrollFn callback
   ─► POST /ipns/tombstone { ipnsName }  (new endpoint)
       ▼
   IpnsService.tombstoneRecord(ipnsName)
       ├─ UPDATE ipns_records SET tombstoned_at = NOW() WHERE ipns_name = :n AND tombstoned_at IS NULL
       └─ republishService.unenrollIpns(userId, ipnsName)  (deletes schedule row)
```

### Recommended Project Structure

No new directories required. Files to create/modify within existing structure:

```
apps/api/src/
├── migrations/
│   └── 1750000000000-ApiSchemaCutover.ts       # new migration
├── ipns/
│   ├── entities/
│   │   └── folder-ipns.entity.ts → ipns-record.entity.ts  # rename + reshape
│   ├── ipns.service.ts                          # atomic CAS + tombstone
│   ├── ipns-record.codec.ts                     # parseCachedRecord case-split
│   ├── ipns.controller.ts                       # 410 response + tombstone endpoint
│   └── ipns.module.ts                           # update entity registration
└── shares/
    ├── entities/
    │   ├── share.entity.ts                      # reshape
    │   ├── share-key.entity.ts                  # DELETE
    │   └── share-invite.entity.ts               # drop encrypted_child_keys
    ├── shares.service.ts                        # delete addShareKeys, update methods
    ├── shares.controller.ts                     # delete /keys routes
    └── shares.module.ts                         # remove ShareKey registration

tests/sdk-e2e/src/suites/
└── ipns-publish-gate.test.ts                   # new: tests 15, 16, 17, 20
```

### Pattern 1: Atomic CAS UPDATE via TypeORM QueryBuilder

The current `upsertFolderIpns` uses `findOne → save`. Replace with `createQueryBuilder().update()`:

```typescript
// Source: TypeORM docs — createQueryBuilder update with WHERE + affected check
// ASSUMED based on TypeORM API knowledge; verify against TypeORM docs for exact syntax

const result = await this.ipnsRecordRepository
  .createQueryBuilder()
  .update(IpnsRecord)
  .set({
    latestCid: metadataCid,
    sequenceNumber: () => `sequence_number + 1`,
    signedRecord: Buffer.from(signedRecord),
    updatedAt: new Date(),
    // encryptedIpnsPrivateKey + keyEpoch updated only if provided and userId matches
  })
  .where(
    'ipns_name = :ipnsName AND sequence_number = :expected AND generation <= :incoming AND tombstoned_at IS NULL',
    { ipnsName, expected: expectedSequenceNumber, incoming: incomingGeneration }
  )
  .execute();

if (result.affected === 0) {
  // Disambiguate: follow-up read
  const row = await this.ipnsRecordRepository.findOne({ where: { ipnsName } });
  if (!row) throw new NotFoundException(...);
  if (row.tombstonedAt) throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE);
  throw new ConflictException({ statusCode: 409, message: '...', currentSequenceNumber: row.sequenceNumber });
}
```

Note: TypeORM `createQueryBuilder().update()` returns `UpdateResult` with `affected: number | undefined`. PostgreSQL always returns the affected row count.

### Pattern 2: NestJS 410 Gone Response

```typescript
// Source: @nestjs/common exports — GoneException confirmed available (NestJS ^11.0.0)
import { HttpException, HttpStatus } from '@nestjs/common';

// In service (for typed body flowing through api:generate):
throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE);

// In controller @ApiResponse decorator:
@ApiResponse({
  status: 410,
  description: 'Gone — IPNS name has been tombstoned (rotated out; no longer publishable)',
  schema: {
    type: 'object',
    properties: {
      error: { type: 'string', example: 'IPNS_TOMBSTONED' },
      ipnsName: { type: 'string' },
    },
  },
})
```

`GoneException` from NestJS is a shorthand for `new HttpException(message, 410)` but does not accept a structured body object directly; use `HttpException` with `HttpStatus.GONE` to emit a typed JSON body that Swagger/api:generate picks up.

### Pattern 3: Deterministic CAS Race Forcing (sdk-e2e Tests 16/17)

The existing concurrent-add test (rotation-crash-safety.test.ts ~L628) uses a `persistCallback` hook injection to interpose a publish between rotation steps. The same callback-injection pattern applies for Tests 16 and 17.

For **Test 16 (concurrent forward publishes)**:
1. Publish IPNS record to seq 1 (baseline).
2. Both clients read the same `expectedSequenceNumber = '1'`.
3. `Promise.allSettled([ publishA(expected=1), publishB(expected=1) ])` — two simultaneous POSTs.
4. Assert exactly one `fulfilled` (200) and one `rejected` (409 ConflictException).
5. Resolve and assert `sequenceNumber = '2'` (only one increment, no lost update).

For **Test 17 (lease-renewal racing a forward publish)**:
1. Publish IPNS record to seq 1 (baseline, `idempotentRepublish = true` path).
2. Forward client publishes (seq 1→2).
3. Simulated renewal publishes the SAME signed record bytes (seq=1) with `expectedSequenceNumber = '1'` (the renewal reads the old seq).
4. With atomic CAS, the renewal sees `sequence_number = 2 ≠ 1` → 0 rows → disambiguation → 409 (not 410).
5. Assert `latestCid` in DB still reflects the forward publish CID (not the stale renewal CID).

The E2E harness (`tests/sdk-e2e/src/fixtures/test-harness.ts`) creates accounts via `/auth/test-login` and exposes `createAndPublishIpnsRecord` + `publishWithCas` from `@cipherbox/sdk-core`.

Runtime contract (D-08): docker compose (redis on 6380, kubo, postgres) + `pnpm --filter @cipherbox/api dev` on :3000. Run: `pnpm --filter tests-sdk-e2e test` from repo root.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| 410 HTTP response with typed body | Custom exception filter | `HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE)` | NestJS built-in flows through Swagger/api:generate |
| Atomic conditional update | Optimistic lock + retry loop | TypeORM `createQueryBuilder().update().where().execute()` checking `result.affected` | PostgreSQL UPDATE is atomic; JS retry loops add TOCTOU |
| Ed25519 pubkey from k51 name | Re-derive from column | `publicKeyFromIpnsName(ipnsName)` from `@cipherbox/crypto` | Column is being dropped; function already exists |
| Partial unique index on `shares` | Application-level duplicate check | Plain `UNIQUE (sharer_id, recipient_id, root_node_id)` — no WHERE clause | Hard-delete means no revoked rows to coexist with |

---

## Runtime State Inventory

> This is a backend schema-only cutover in a greenfield (no prod data; staging wiped on deploy). Minimal runtime state.

| Category | Items Found | Action Required |
|----------|-------------|-----------------|
| Stored data | `folder_ipns` table rows, `share_keys` rows, `shares.revoked_at`/`permission`/`encrypted_key` columns | Dropped by migration (greenfield; no migration of existing rows) |
| Live service config | `ipns_republish_schedule` keeps its FK to `users(id)`; no FK to `folder_ipns`/`ipns_records` exists, so no schedule rows are orphaned by the rename | No live config change needed |
| OS-registered state | None — no systemd/launchd/pm2 processes reference the table name | None |
| Secrets/env vars | None — DB schema names are not in secrets | None |
| Build artifacts | `packages/api-client/src/generated/` — must regenerate after API surface changes | `pnpm api:generate` + commit as part of phase |

---

## Common Pitfalls

### Pitfall 1: Assuming `folder_ipns` Has FK Dependents

**What goes wrong:** Migration drops `folder_ipns` and tries to DROP FK constraints from `shares`/`vaults`/`ipns_republish_schedule` that do not exist → migration fails.
**Why it happens:** CONTEXT.md's language "FKs on ipns_republish_schedule/shares/vaults re-established" implies FK constraints to `folder_ipns`.
**How to avoid:** Read confirmed: those columns are plain varchar, not FK constraints. The migration only needs to DROP TABLE `folder_ipns` (no dependent FK drops required) and CREATE TABLE `ipns_records`. The `shares` table must be re-created for the schema change, but for its own FK constraints (to `users`), not for any FK to `folder_ipns`.

### Pitfall 2: TOCTOU in `result.affected` — Raw SQL vs QueryBuilder

**What goes wrong:** TypeORM `queryRunner.query(UPDATE...)` returns `[rows, affected]` (array), but `createQueryBuilder().update().execute()` returns `UpdateResult { affected: number | undefined }`. Mixing these breaks the 0-rows check.
**Why it happens:** TypeORM has two SQL-execution APIs with different return shapes.
**How to avoid:** Use `createQueryBuilder().update()...execute()` everywhere for the CAS UPDATE; check `result.affected === 0` (or `=== 1`).

### Pitfall 3: First-Publish CAS (expectedSequenceNumber undefined)

**What goes wrong:** The atomic UPDATE `WHERE sequence_number = :expected` fails for first-publish because the row does not exist yet — 0 rows returned, triggers 409 disambiguation read, finds no row, throws NotFoundException.
**Why it happens:** First-publish must INSERT (not UPDATE). The CAS gate only applies when an existing row exists.
**How to avoid:** Keep the first-publish path as an INSERT (with `ON CONFLICT DO NOTHING` or separate `findOne` check). The atomic CAS UPDATE applies only to forward-publishes where `expectedSequenceNumber` is provided and the row exists.

### Pitfall 4: Forgetting `pnpm api:generate` Before Commit

**What goes wrong:** `scripts/check-api-client.sh` pre-commit hook detects changed DTOs/controllers/entities but no updated `packages/api-client/openapi.json` → commit blocked.
**Why it happens:** The hook checks for staged API files without matching generated files.
**How to avoid:** After all API changes, run `pnpm api:generate` at repo root. This runs `openapi:generate` → `api-client generate` → `api-client build` → `lint:fix`. Stage `packages/api-client/src/generated/` + `packages/api-client/openapi.json` with API changes.

### Pitfall 5: `generation` Type — bigint vs string

**What goes wrong:** TypeORM `bigint` columns are returned as `string` in Node.js (precision). Comparing `row.generation <= incoming` where `incoming` is a `bigint` JS type and `row.generation` is a `string` gives NaN comparisons.
**Why it happens:** TypeORM bigint behavior.
**How to avoid:** Use the same pattern as `sequenceNumber`: declare `generation!: string` in the entity; cast to `BigInt()` before comparisons; use raw SQL literal in the WHERE clause (e.g., `generation <= :incoming::bigint`).

### Pitfall 6: Entity File Rename vs Import Updates

**What goes wrong:** Renaming `folder-ipns.entity.ts` → `ipns-record.entity.ts` leaves stale imports in `ipns.service.ts`, `ipns-record.codec.ts`, `republish.service.ts`, `vault.service.ts`, `ipns.module.ts` (and wherever `FolderIpns` is imported).
**Why it happens:** TypeScript only errors at compile time; the server still starts if the old file is kept alongside.
**How to avoid:** Grep all imports of `FolderIpns` / `folder-ipns.entity` after rename.

Confirmed import sites: [VERIFIED: reading source files]
- `apps/api/src/ipns/ipns.service.ts` L13 — `import { FolderIpns } from './entities/folder-ipns.entity'`
- `apps/api/src/ipns/ipns-record.codec.ts` L3 — `import type { FolderIpns } from './entities/folder-ipns.entity'`
- `apps/api/src/ipns/ipns.module.ts` L6 — `import { FolderIpns } from './entities/folder-ipns.entity'`
- `apps/api/src/republish/republish.service.ts` L5 — `import { FolderIpns } from '../ipns/entities/folder-ipns.entity'`

### Pitfall 7: `parseCachedRecord` Null Case — Shared-Folder Rows vs Corruption

**What goes wrong:** The current code returns `null` for `!cached.signedRecord`. After Phase 66, this case has two distinct meanings (§6.5): expected null (shared-folder row — apply seq floor) vs not expected null (corruption — fail closed). Treating both as "return null" leaves the silently-fall-through-to-network gap.
**Why it happens:** The current code (L64) handles both with a single `if (!cached.signedRecord) return null`.
**How to avoid:** Add an optional `applyFloor` flag or check whether `signedRecord` being null is expected given the row's state. The DB `sequenceNumber` column is always populated; when `signedRecord` is null, apply `seq ≥ storedSeq` against the network record rather than returning null unconditionally.

---

## Detailed Implementation Site Map

### `folder_ipns` Entity → `IpnsRecord`

**File:** `apps/api/src/ipns/entities/folder-ipns.entity.ts` (rename to `ipns-record.entity.ts`)

Current columns: `id`, `userId`, `ipnsName`, `latestCid`, `sequenceNumber: string`, `signedRecord: Buffer | null`, `publicKey: Buffer | null`, `encryptedIpnsPrivateKey`, `keyEpoch`, `isRoot`, `createdAt`, `updatedAt`

Target (D-02/D-10):
- **Drop:** `publicKey` (nullable, derivable from k51 name via `publicKeyFromIpnsName`, null for shared rows — the footgun behind two Phase-60 regressions)
- **Add:** `tombstonedAt: Date | null` (`@Column({ type: 'timestamptz', name: 'tombstoned_at', nullable: true })`)
- **Add:** `generation: string` (`@Column({ type: 'bigint', name: 'generation', default: 0 })`) — TypeORM bigint = string
- **Keep unchanged:** all other columns

### `shares` Entity Reshape

**File:** `apps/api/src/shares/entities/share.entity.ts`

Current columns: `id`, `sharerId`, `recipientId`, `itemType`, `ipnsName`, `itemName`, `itemNameEncrypted`, `encryptedKey`, `permission`, `encryptedIpnsKey`, `hiddenByRecipient`, `revokedAt`, `shareKeys` (relation), `createdAt`, `updatedAt`

Target (D-06/D-09/D-11):
- **Drop:** `itemType`, `ipnsName`, `itemName`, `encryptedKey`, `permission`, `encryptedIpnsKey`, `revokedAt`, `shareKeys` relation
- **Keep:** `id`, `sharerId`, `recipientId`, `itemNameEncrypted`, `hiddenByRecipient`, `createdAt`, `updatedAt`
- **Add:** `readDescriptorRef: Buffer` (`@Column({ type: 'bytea', name: 'read_descriptor_ref' })`), `writeDescriptorRef: Buffer | null` (`@Column({ type: 'bytea', name: 'write_descriptor_ref', nullable: true })`), `rootNodeId: string` (`@Column({ type: 'uuid', name: 'root_node_id' })`), `rootIpnsName: string` (`@Column({ type: 'varchar', length: 255, name: 'root_ipns_name' })`), `rootGeneration: string` (`@Column({ type: 'bigint', name: 'root_generation', default: 0 })`)
- **Unique:** `@Unique(['sharerId', 'recipientId', 'rootNodeId'])` (plain, no partial index — D-06/D-11)

### `share_keys` Entity → DELETE

**File:** `apps/api/src/shares/entities/share-key.entity.ts` — delete entirely.

Dependency chain (all to clean up):
- `apps/api/src/shares/entities/index.ts` — remove `ShareKey` export
- `apps/api/src/shares/shares.module.ts` L12 — `TypeOrmModule.forFeature([Share, ShareKey, ShareInvite, User])` → remove `ShareKey`
- `apps/api/src/shares/shares.service.ts` — remove `@InjectRepository(ShareKey)` injection; delete `addShareKeys`, `getShareKeys`, `completeRotation`, `updatePermission` methods (or refactor where needed)
- `apps/api/src/shares/shares.controller.ts` — delete `GET :shareId/keys` (~L240) and `POST :shareId/keys` (~L267) routes
- `apps/api/src/shares/dto/share-key.dto.ts` — delete `AddShareKeysDto`
- `apps/api/src/shares/dto/share-response.dto.ts` — delete `ShareKeyResponseDto`
- `apps/api/src/shares/dto/create-share.dto.ts` — drop `childKeys` field (was for fanning out to `share_keys`)
- `apps/api/src/shares/types.ts` — check if `ShareKeyType` / `ChildKeyType` types are used elsewhere

### `share_invites` Entity Slim

**File:** `apps/api/src/shares/entities/share-invite.entity.ts`

- **Drop:** `encryptedChildKeys: Array<{...}> | null` (D-05)
- `encryptedKey` stays but semantics change: single ephemeral-wrapped root `readKey` only

### `ipns.service.ts` Changes

**File:** `apps/api/src/ipns/ipns.service.ts`

Changes required:
1. Replace `private readonly folderIpnsRepository: Repository<FolderIpns>` → `private readonly ipnsRecordRepository: Repository<IpnsRecord>` throughout.
2. Replace `upsertFolderIpns` (the non-atomic `findOne → gate → save`) with an atomic `UPDATE ipns_records SET … WHERE ipns_name = :n AND sequence_number = :expected AND generation <= :incoming AND tombstoned_at IS NULL`. When `result.affected === 0`: do a follow-up `findOne`; if `tombstonedAt IS NOT NULL` → `throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE)`; else → `throw new ConflictException(...)`.
3. Add `tombstoneRecord(ipnsName: string): Promise<void>` method: `UPDATE ipns_records SET tombstoned_at = NOW() WHERE ipns_name = :n AND tombstoned_at IS NULL`, then call `republishService.unenrollIpns(userId, ipnsName)`.
4. Update `resolveRecord` to check `tombstonedAt` on the DB row before calling `parseCachedRecord`. If tombstoned: throw 410 (matches D-07).
5. Update all `folderIpnsRepository` references to `ipnsRecordRepository`.

### `ipns-record.codec.ts` Changes

**File:** `apps/api/src/ipns/ipns-record.codec.ts`

Change type import: `import type { IpnsRecord } from './entities/ipns-record.entity'`.

Update `parseCachedRecord(cached: IpnsRecord | null, ...)`:
- Remove `public_key` column fallback (column is dropped). Fallback path stays: `publicKeyFromIpnsName(cached.ipnsName)` (already implemented at L96).
- Implement the §6.5 case-split for null `signedRecord`:
  - **Currently:** `if (!cached.signedRecord) return null;` (undifferentiated fail closed)
  - **Target:** when `!cached.signedRecord`, return an object indicating "apply seq floor" (the caller in `resolveRecord` applies `seq ≥ cached.sequenceNumber` against the network record) rather than unconditionally returning null → 404.

### `republish.service.ts` Changes

**File:** `apps/api/src/republish/republish.service.ts`

- Update `@InjectRepository(FolderIpns)` → `@InjectRepository(IpnsRecord)`.
- Update all `folderIpnsRepository` → `ipnsRecordRepository` references.
- `unenrollIpns` at L257 is already correct behavior (deletes schedule row). Tombstone also needs a separate `UPDATE ipns_records SET tombstoned_at = NOW()` — this is done in `IpnsService.tombstoneRecord`.

### `ipns.controller.ts` Changes

- Add `@ApiResponse({ status: 410, description: 'Gone — name tombstoned', schema: ... })` to `publishRecord` and `resolveRecord`.
- Add new `POST /ipns/tombstone` endpoint wired to `ipnsService.tombstoneRecord(ipnsName)`.

### `ipns.module.ts` Changes

- `TypeOrmModule.forFeature([FolderIpns])` → `TypeOrmModule.forFeature([IpnsRecord])`.

---

## `ipns.service.ts` Current vs Target — Publish Path

### Current (non-atomic, TOCTOU gap)

`publishRecord` → `upsertFolderIpns`:
1. L228: `this.folderIpnsRepository.findOne({ where: { ipnsName } })` — read existing row
2. L243: parse `signedRecord` for anti-rollback
3. L258: CAS check `expectedSequenceNumber !== current` (in-memory, not DB-locked)
4. L274: S1 embedded-seq integrity check
5. L329: `existing.sequenceNumber = (BigInt(existing.sequenceNumber) + 1n).toString()`
6. L344: `this.folderIpnsRepository.save(existing)` — **non-atomic write**

**TOCTOU gap:** Two concurrent writers both at `dbSeq = N` both pass step 3 (comparing against the same in-memory value), and the second `save` clobbers the first — a `200`'d write silently lost.

**Generation check:** Not present in current code. Phase 66 adds the `generation <= :incoming` gate.

**Tombstone check:** Not present in current code. Phase 66 adds `tombstoned_at IS NULL` to the CAS WHERE clause.

### Target (atomic)

```
publishRecord → atomicCasPublish:
  1. Verify Ed25519 signature (unchanged)
  2. Parse embedded seq (incomingParsed)
  3. First-publish path (no expectedSequenceNumber):
     INSERT INTO ipns_records (..., sequence_number=1, generation=0, tombstoned_at=NULL) ON CONFLICT DO NOTHING
     → 0 rows: conflict → disambiguate (existing row? → 409)
  4. Forward-publish path (expectedSequenceNumber provided):
     UPDATE ipns_records
       SET latest_cid=:cid, sequence_number=sequence_number+1,
           signed_record=:bytes, generation=:gen, updated_at=NOW()
     WHERE ipns_name=:n
       AND sequence_number=:expected
       AND generation<=:incoming
       AND tombstoned_at IS NULL
     → 0 rows: follow-up findOne → tombstoned_at? → 410 : 409
     → 1 row: success
  5. Fire-and-forget TEE enrollment + DHT push (unchanged)
```

---

## `parseCachedRecord` Case-Split (Test 15)

**Current behavior** (`ipns-record.codec.ts` L57–L113):

```
parseCachedRecord(cached):
  if (!cached?.latestCid) → return null (→ 404)
  if (!cached.signedRecord) → return null (→ 404)   ← undifferentiated fall-through
  parse signedRecord → if CID mismatch → return null (→ 404, fail closed)
  recover pubKey: parsed.pubKey ?? cached.publicKey.base64 ?? publicKeyFromIpnsName(ipnsName)
  return { cid, sequenceNumber: cached.sequenceNumber, pubKey }
```

**Target (§6.5 case-split):**

```
parseCachedRecord(cached):
  if (!cached?.latestCid) → return null
  if (!cached.signedRecord):
    // Expected null — shared-folder row (never had a signedRecord)
    // Return a floor descriptor: { seqFloor: cached.sequenceNumber }
    // resolveRecord applies: networkSeq >= seqFloor? serve : fail closed
    → return { seqFloor: cached.sequenceNumber }  (new case)
  parse signedRecord
  if CID mismatch → return null (fail closed, unchanged)
  recover pubKey via publicKeyFromIpnsName only (column dropped)
  return { cid, sequenceNumber, pubKey }
```

The `resolveRecord` caller then handles the `seqFloor` discriminant: if the network record's seq ≥ floor, serve it; otherwise fail closed.

---

## Tombstone Flow (§5.5 / WRITE-04)

The tombstone is the **server-side enforcement** of write-revocation. After `rotateWriteFromNode` runs client-side:

1. `teeUnenrollFn` callback fires (per write-chain-rotation.test.ts ~L325 — currently a `vi.fn()` mock).
2. Phase 66 wires this callback to a live `POST /ipns/tombstone { ipnsName }` call.
3. Server: `UPDATE ipns_records SET tombstoned_at = NOW() WHERE ipns_name = :n AND tombstoned_at IS NULL`.
4. Server: `DELETE FROM ipns_republish_schedule WHERE ipns_name = :n AND user_id = :userId` (via `unenrollIpns`).
5. Any subsequent publish to the tombstoned name → atomic CAS UPDATE finds 0 rows (tombstoned_at IS NOT NULL) → follow-up read → 410.
6. Any resolve of the tombstoned name → `tombstonedAt IS NOT NULL` → 410 `{ error: 'IPNS_TOMBSTONED', ipnsName }`.

**Key constraint (§5.5):** The tombstone check must also block the EOL-only renewal CAS. Since the renewal uses the same `UPDATE … WHERE tombstoned_at IS NULL`, it is automatically blocked — the gate is unified.

---

## Validation Architecture

Nyquist validation is **enabled** (`workflow.nyquist_validation: true` in `.planning/config.json`).

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest 3.0.5 |
| Config file | `tests/sdk-e2e/vitest.config.ts` |
| Quick run command | `pnpm --filter tests-sdk-e2e test:single -- ipns-publish-gate` |
| Full suite command | `pnpm --filter tests-sdk-e2e test` |
| Timeout per test | 120,000 ms (vitest.config.ts) |
| Concurrency | `sequence: { concurrent: false }`, `fileParallelism: false` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | File | Automated? |
|--------|----------|-----------|------|-----------|
| TEE-04 | Concurrent forward publishes → exactly one 409, zero lost updates | E2E (sdk-e2e) | `ipns-publish-gate.test.ts` test 16 | Yes — `pnpm --filter tests-sdk-e2e test` |
| TEE-04 | Lease-renewal racing a forward publish → renewal never regresses CID | E2E (sdk-e2e) | `ipns-publish-gate.test.ts` test 17 | Yes |
| TEE-05 | `parseCachedRecord`-null case-split → seq floor applied, no ungated network fallthrough | E2E (sdk-e2e) | `ipns-publish-gate.test.ts` test 15 | Yes |
| TEE-07 | Forward-only generation gate — generation regression rejected at publish | E2E (sdk-e2e) | `ipns-publish-gate.test.ts` (can be combined with test 16) | Yes |
| WRITE-04 | Tombstoned name rejected at publish; resolve returns 410 | E2E (sdk-e2e) | `ipns-publish-gate.test.ts` test 20 | Yes |
| DATA-01 | `share_keys` table gone; `POST :shareId/keys` returns 404 | Static analysis (TypeScript build) + E2E | TypeScript compiler | Yes (tsc) |
| DATA-02/DATA-03 | Schema migration runs clean on fresh DB | Migration smoke | Manual / Docker startup | Manual gate |
| DATA-04 | `shares` API CRUD with descriptor ref fields | E2E (sdk-e2e) | Can extend `share-operations.test.ts` | Yes |

### Sampling Rate

- **Per task commit:** `pnpm typecheck` (static-analysis only per D-08 / [[feedback-gsd-subagents-no-test-runs]])
- **Per wave merge:** `pnpm typecheck && pnpm --filter tests-sdk-e2e test`
- **Phase gate:** Full sdk-e2e suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` — covers tests 15, 16, 17, 20 (TEE-04, TEE-05, TEE-07, WRITE-04)
- [ ] Tombstone endpoint (new `POST /ipns/tombstone`) needs corresponding DTO/response types before api:generate

*(Existing `write-chain-rotation.test.ts` covers the `teeUnenrollFn` mock call — Phase 66 replaces that mock with a live endpoint.)*

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No (existing JWT guard unchanged) | JWT guard |
| V3 Session Management | No | — |
| V4 Access Control | Yes — tombstone endpoint must only be callable by the record owner or the write-rotation actor | Check `userId` against `ipns_records.user_id` before tombstoning |
| V5 Input Validation | Yes — `ipnsName` pattern validation on all new endpoints | `@Matches(/^k[a-z0-9]+$/)` existing pattern |
| V6 Cryptography | Yes (critical) — `publicKeyFromIpnsName` used for pubKey recovery; never hand-roll | `@cipherbox/crypto` |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Replay of old lower-seq signed record to roll back `latestCid` | Tampering | Atomic CAS `WHERE sequence_number = :expected` rejects old seq |
| Concurrent writes — both clients at same seq → silent overwrite | Tampering | Atomic UPDATE; `affected === 0` → 409 |
| Tombstoned name re-publication (revoked writer replays cached key) | Tampering | `WHERE tombstoned_at IS NULL` in CAS; tombstoned_at persists for audit |
| Generation regression (serving stale generation content) | Tampering | `WHERE generation <= :incoming`; reject regression |
| Null `signedRecord` shared-folder row serving ungated network content | Information Disclosure | case-split `parseCachedRecord`; apply seq floor; never fall-through unconditionally |
| `public_key` column null for shared rows (footgun) | Elevation of Privilege | Dropped; `publicKeyFromIpnsName` always recovers from k51 name |
| Stale `encryptedKey` / ECIES material in revoked `shares` rows | Information Disclosure | Hard-delete on revoke (D-11); no residue |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `generation` should be declared `bigint` in TypeORM entity (returned as string, matching `sequenceNumber` pattern) | Standard Stack / ipns_records entity target | If `int4` is used instead, JS number precision is fine for reasonable generation counts but breaks bigint comparison operators |
| A2 | TypeORM `createQueryBuilder().update().execute().affected` works reliably on PostgreSQL for detecting 0-row CAS | Publish gate pattern | If `affected` is undefined, the 0-row detection fails silently; workaround: use raw `queryRunner.query` with `pg` result |
| A3 | The `seqFloor` discriminant approach for `parseCachedRecord` is a breaking change for callers expecting `IpnsRecordFields | null` | parseCachedRecord case-split | If callers are not updated, null checks remain incorrect; the planner must update `resolveRecord` to handle the new discriminant |

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| PostgreSQL | Migration + api dev | ✓ (via Docker) | 15+ | None — required |
| Redis | API session / rate-limit | ✓ (port 6380 per D-08) | Any | None — required for E2E |
| `pnpm` | `api:generate` | ✓ | (workspace) | None |
| `@cipherbox/crypto` dist | `publicKeyFromIpnsName` | ✓ | workspace | None — already built |

---

## Sources

### Primary (HIGH confidence)

- `apps/api/src/migrations/1700000000000-FullSchema.ts` — authoritative SQL for `folder_ipns`, `shares`, `share_keys`, `ipns_republish_schedule` table creation; FK constraints confirmed
- `apps/api/src/migrations/1740250000000-AddSharesTables.ts`, `1740300000000-SharesPartialUniqueIndex.ts`, `1743000000000-AddWritableShares.ts` — incremental `shares` changes
- `apps/api/src/migrations/1749300000000-IpnsCacheKeyedByName.ts` — current `UQ_folder_ipns_ipns_name` unique constraint
- `apps/api/src/ipns/ipns.service.ts` — full non-atomic `publishRecord`/`upsertFolderIpns` implementation (L214–L406)
- `apps/api/src/ipns/ipns-record.codec.ts` — `parseCachedRecord` current behavior (L53–L113)
- `apps/api/src/republish/republish.service.ts` — `unenrollIpns` at L256–L267
- `apps/api/src/shares/entities/share.entity.ts`, `share-key.entity.ts`, `share-invite.entity.ts` — current column shapes
- `apps/api/src/shares/shares.service.ts` — `addShareKeys` at L207; `revokeShare` at L258
- `apps/api/src/shares/shares.controller.ts` — `POST :shareId/keys` at L267
- `packages/crypto/src/index.ts` L77 — `publicKeyFromIpnsName` export confirmed
- `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` — `persistCallback` forcing pattern at L628
- `tests/sdk-e2e/vitest.config.ts` — runtime contract (sequential, 120s timeout)
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §5.5, §6.5, §6.6, §7.3 — design authority
- Verified NestJS `GoneException` / `HttpStatus.GONE = 410` via node module introspection

### Secondary (MEDIUM confidence)

- `apps/api/src/ipns/ipns.controller.ts` — Swagger `@ApiResponse` patterns to follow for 410
- `apps/api/src/ipns/republish-schedule.entity.ts` — confirms no FK from `ipns_republish_schedule` to `folder_ipns`

---

## Metadata

**Confidence breakdown:**
- FK map: HIGH — verified by reading all migration SQL and entity files
- Current publish path: HIGH — read full `ipns.service.ts`
- Atomic CAS pattern: MEDIUM — TypeORM `createQueryBuilder().update()` API is well-known; `result.affected` behavior on PostgreSQL is reliable
- 410 NestJS wiring: HIGH — verified `GoneException`/`HttpStatus.GONE = 410` in installed NestJS ^11.0.0
- Test forcing mechanism: HIGH — `persistCallback` pattern directly observed in `rotation-crash-safety.test.ts`
- Shares reshape: HIGH — current entity columns verified directly

**Research date:** 2026-06-30
**Valid until:** 2026-07-30 (stable TypeORM/NestJS; changes only if API evolves)
