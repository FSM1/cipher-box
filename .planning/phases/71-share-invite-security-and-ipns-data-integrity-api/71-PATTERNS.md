# Phase 71: Share-Invite Security and IPNS Data-Integrity (API) - Pattern Map

**Mapped:** 2026-07-09
**Files analyzed:** 7 modified + 1 new migration
**Analogs found:** 8 / 8

This phase modifies existing NestJS services/entities and adds one migration — no new
controller/component files. RESEARCH.md already embeds most excerpts verbatim from live code;
this file extends it with exact line numbers, the module-wiring gap for D-01, and the
idempotent-DDL analog requested for D-04.

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match Quality |
|----------------|------|-----------|-----------------|---------------|
| `apps/api/src/shares/share-invite.service.ts` (`createInvite`) | service | CRUD (write, authz-gated) | `apps/api/src/vault/vault.service.ts:90-115` (ownership-scoped lookup before write) | role-match |
| `apps/api/src/shares/share-invite.service.ts` (`claimInvite` existing-share branch) | service | CRUD (transactional read-modify-write) | itself (`share-invite.service.ts:139-203`, extend existing transaction) | exact (self-extend) |
| `apps/api/src/shares/entities/share-invite.entity.ts` | model | CRUD (schema) | `apps/api/src/shares/entities/share.entity.ts` (sibling entity, same module) | exact |
| `apps/api/src/migrations/{new}-ClaimCountCheckConstraint.ts` | migration | batch (DDL) | `apps/api/src/migrations/1740300000000-SharesPartialUniqueIndex.ts` (idempotent guarded ALTER) + `1751000000000-ScheduleCollapse.ts` (down()-throws precedent) | role-match |
| `apps/api/src/ipns/ipns.service.ts` (`upsertIpnsRecord` same-seq branch, D-05) | service | CRUD (CAS write-gate) | itself, existing rollback-guard branch `ipns.service.ts:264-278` | exact (self-extend) |
| `apps/api/src/ipns/ipns.service.ts` (first-publish insert, D-06) | service | CRUD (insert + race translation) | `apps/api/src/shares/shares.service.ts:74-89` (`createShare` 23505→409 idiom) | exact |
| `apps/api/src/shares/shares.service.ts` (`revokeForItems`, D-08) | service | CRUD (bulk delete) | itself, sibling `createQueryBuilder().update()` block in same method (`shares.service.ts:179-186`) | exact (self-extend, mirror the adjacent query-builder style already in the same method) |
| `apps/api/src/shares/share-invite.service.spec.ts` (D-09 new describes) | test | request-response (unit, mocked repo/DataSource) | itself — existing `describe` blocks + `makeInvite()` fixture builder (lines 29-124) | exact (extend same file) |
| `apps/api/src/shares/shares.module.ts` (wiring, D-01 prerequisite) | config/provider wiring | — | itself — `TypeOrmModule.forFeature([Share, ShareInvite, User])` | exact — **must add `Vault`** |

## Pattern Assignments

### `apps/api/src/shares/share-invite.service.ts` — `createInvite` (D-01/D-02)

**Analog:** `apps/api/src/vault/vault.service.ts:90-115` (ownership/uniqueness-checked write) and
the `Vault` entity itself.

**Current code to modify** (`share-invite.service.ts:33-57`, no ownership check today):
```typescript
async createInvite(sharerId: string, dto: CreateInviteDto): Promise<ShareInvite> {
  const token = randomBytes(16).toString('base64url');
  const expiresAt = new Date(Date.now() + INVITE_EXPIRY_MS);

  const invite = this.inviteRepo.create({
    token,
    sharerId,
    rootIpnsName: dto.rootIpnsName,
    rootNodeId: dto.rootNodeId,
    // ...verbatim DTO copy, zero server-side verification
  });

  return this.inviteRepo.save(invite);
}
```

**Vault entity shape to query against** (`apps/api/src/vault/entities/vault.entity.ts:12-20`):
```typescript
@Entity('vaults')
export class Vault {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'uuid', name: 'owner_id' })
  ownerId!: string;
  // ...root_ipns_name column follows
}
```

**Pattern to apply** — constructor DI + `ForbiddenException` gate before the existing `save`,
mirroring RESEARCH.md Pattern 1 exactly:
```typescript
constructor(
  @InjectRepository(ShareInvite) private readonly inviteRepo: Repository<ShareInvite>,
  @InjectRepository(Vault) private readonly vaultRepo: Repository<Vault>, // NEW
  private readonly dataSource: DataSource
) {}

async createInvite(sharerId: string, dto: CreateInviteDto): Promise<ShareInvite> {
  const owned = await this.vaultRepo.findOne({
    where: { ownerId: sharerId, rootIpnsName: dto.rootIpnsName },
  });
  if (!owned) {
    throw new ForbiddenException('You do not own this root');
  }
  // ...existing token/expiresAt/invite.create/save unchanged
}
```

**CRITICAL — module wiring gap found (not yet in RESEARCH.md as a confirmed blocker):**
`apps/api/src/shares/shares.module.ts` currently only registers
`TypeOrmModule.forFeature([Share, ShareInvite, User])` — **`Vault` is absent**. The
`@InjectRepository(Vault)` constructor injection will fail to resolve at Nest bootstrap unless
`Vault` is added to this array (and imported from `../vault/entities/vault.entity`). This is a
required companion edit to D-01, not optional:
```typescript
// apps/api/src/shares/shares.module.ts — add Vault import + forFeature entry
import { Vault } from '../vault/entities/vault.entity';
// ...
imports: [TypeOrmModule.forFeature([Share, ShareInvite, User, Vault])],
```

---

### `apps/api/src/shares/share-invite.service.ts` — `claimInvite` existing-share branch (D-07)

**Analog:** itself — the existing-share branch at lines 169-174, inside the already-open
transaction (lines 139-203). No external analog needed; extend in place per RESEARCH.md Pattern 2.

**Current code** (`share-invite.service.ts:169-174`):
```typescript
if (existingShare) {
  this.logger.warn(
    `Invite claim for ${invite.rootIpnsName}: share already exists between ${invite.sharerId} and ${claimerId}`
  );
  return { shareId: existingShare.id };
}
```
Replace per RESEARCH.md's widen-only gate (`isWriteUpgrade`/`isGenerationBump`), preserving the
`manager.save`/`manager` transaction context already in scope. Mirror the invariant-comment style
already used at lines 176-183 (T-66-E1 write-authority is presence-derived) when documenting the
widen guard.

---

### `apps/api/src/shares/entities/share-invite.entity.ts` (D-04 entity mirror)

**Analog:** `apps/api/src/shares/entities/share.entity.ts` (sibling entity in the same directory —
read it for decorator/import conventions before adding `@Check`).

**Pattern:**
```typescript
import { Check } from 'typeorm';

@Entity('share_invites')
@Check('CHK_share_invites_claim_count', '"claim_count" >= 0 AND "claim_count" <= "max_claims"')
export class ShareInvite {
  // ...unchanged fields
}
```

---

### `apps/api/src/migrations/{new}-ClaimCountCheckConstraint.ts` (D-04)

**Analog 1 — idempotent-guard shape:** `apps/api/src/migrations/1740300000000-SharesPartialUniqueIndex.ts`
(full file read). Its `up()` wraps a conditional drop in a `DO $$ ... END $$;` block before creating
the new index — this is the project's established idiom for "don't blow up if the old constraint
name is unknown/varies." For an `ADD CONSTRAINT` (which has no native `IF NOT EXISTS`), mirror this
`DO $$ BEGIN ... EXCEPTION WHEN duplicate_object THEN NULL; END $$;` shape:
```typescript
// Source: apps/api/src/migrations/1740300000000-SharesPartialUniqueIndex.ts:11-30 (DO $$ idiom)
public async up(queryRunner: QueryRunner): Promise<void> {
  await queryRunner.query(`
    DO $$
    BEGIN
      ALTER TABLE "share_invites"
        ADD CONSTRAINT "CHK_share_invites_claim_count"
        CHECK ("claim_count" >= 0 AND "claim_count" <= "max_claims");
    EXCEPTION
      WHEN duplicate_object THEN NULL;
    END $$;
  `);
}
```

**Analog 2 — greenfield `down()`-throws precedent:** `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts`
(full file read, per RESEARCH.md Code Examples — mirror its `down()` throwing pattern verbatim,
same wording style: "down() not implemented... Staging DB is wiped on each deploy").

**Timestamp rule:** must be strictly greater than `1751000000000` (use `Date.now()`, current date
2026-07-09 satisfies this automatically). Never edit `1750000000000-ApiSchemaCutover.ts` or
`1751000000000-ScheduleCollapse.ts` in place.

---

### `apps/api/src/ipns/ipns.service.ts` — same-seq branch (D-05)

**Analog:** itself. The file already has an established "rollback/equivocation → reject" idiom two
branches above the target — mirror its `ConflictException`/`BadRequestException` shape exactly.

**Rollback-guard analog** (`ipns.service.ts:264-278`, existing, read-only reuse of style):
```typescript
if (incoming.sequence < stored.sequence) {
  throw new ConflictException({
    statusCode: 409,
    message: 'IPNS record sequence regression rejected (rollback/replay)',
    currentSequenceNumber: existing.sequenceNumber,
  });
}
```

**Exact target to modify** (`ipns.service.ts:310-315`, current — no CID check):
```typescript
const dbSeq = BigInt(existing.sequenceNumber);
if (embeddedSeq === dbSeq) {
  // Idempotent republish — TEE 6-hour re-sign path (D-09 / Pitfall 4).
  // Do NOT increment the DB sequence, but still update latestCid/signedRecord below.
  isIdempotentRepublish = true;
} else if (embeddedSeq === dbSeq + 1n) {
```
Apply RESEARCH.md Pattern 4's guard here — gate on `metadataCid !== existing.latestCid`, using
`BadRequestException` (matching the sibling `BadRequestException` throws at lines 294-297,
306-309, 319-321, 324-326 in the same method — all four use the same flat single-arg string-message
shape, not the object shape used by the two `ConflictException` sites). Also rewrite the stale
comment inline at line 313 (see D-05 cleanup note in CONTEXT.md/RESEARCH.md).

---

### `apps/api/src/ipns/ipns.service.ts` — first-publish insert (D-06)

**Analog:** `apps/api/src/shares/shares.service.ts:74-89` (`createShare`'s established 23505→409
idiom — the exact pattern to mirror, per RESEARCH.md Pattern 3 and CONTEXT.md D-06).

**Analog excerpt** (`shares.service.ts:74-89`):
```typescript
try {
  return await this.shareRepo.save(share);
} catch (err: unknown) {
  // Handle race condition: concurrent createShare for the same triple.
  // Detect Postgres unique-violation (SQLSTATE 23505) on the error code,
  // not a brittle message substring.
  const code = (err as { code?: string; driverError?: { code?: string } }).code;
  const driverCode = (err as { driverError?: { code?: string } }).driverError?.code;
  if (code === '23505' || driverCode === '23505') {
    throw new ConflictException('Share already exists for this item and recipient');
  }
  throw err;
}
```
A third occurrence of the identical idiom exists at `apps/api/src/vault/vault.service.ts:101-103`
(single-field `.code` check, no `driverError` fallback — the shares.service.ts version is the more
complete template since it checks both).

**Exact target to wrap** (`ipns.service.ts:436-453`, current — no try/catch):
```typescript
const folder = this.ipnsRecordRepository.create({
  userId,
  ipnsName,
  latestCid: metadataCid,
  sequenceNumber: '1',
  // ...unchanged fields
  isRoot: false, // Root folder is tracked in Vault entity
});

const saved = await this.ipnsRecordRepository.save(folder);
```
Wrap the `save(folder)` call in the shares.service.ts try/catch shape, using
`ConflictException({ statusCode: 409, message: 'IPNS record already exists' })` (object form, to
match the sibling `ConflictException` object-shape calls already in this same file at lines
271-275 and 404-408 — this file's house style for `ConflictException` is the object form, unlike
`shares.service.ts`'s string form; prefer file-local consistency over cross-file consistency here).

---

### `apps/api/src/shares/shares.service.ts` — `revokeForItems` (D-08)

**Analog:** itself — the adjacent invite-revocation query-builder block in the same method
(`shares.service.ts:179-186`), already using the exact `createQueryBuilder()` delete/update idiom
this decision needs for the shares half too.

**Current code to replace** (`shares.service.ts:170-176`):
```typescript
const shares = await manager.find(Share, {
  where: { sharerId, rootIpnsName: In(uniqueNames) },
});
if (shares.length > 0) {
  await manager.remove(shares);
}
```

**Pattern to mirror** (the immediately-following invite-update block, same method, same
transaction manager — `shares.service.ts:179-186`, unchanged, use as the query-builder-shape
template):
```typescript
const inviteResult = await manager
  .createQueryBuilder()
  .update(ShareInvite)
  .set({ status: 'revoked' })
  .where('sharer_id = :sharerId', { sharerId })
  .andWhere('root_ipns_name IN (:...names)', { names: uniqueNames })
  .andWhere('status = :status', { status: 'active' })
  .execute();
```
Replace the `find`+`remove` block with a sibling `.createQueryBuilder().delete().from(Share)...`
call (see RESEARCH.md Code Examples D-08 for the exact shape) — same manager, same transaction,
same `.where()`/`.andWhere()` binding style already established two lines below it in this file.
**Note:** if `In` becomes unused elsewhere in the file after this change, remove the now-dead
import.

---

### `apps/api/src/shares/share-invite.service.spec.ts` (D-09)

**Analog:** itself — extend the existing file, do not create a new spec file.

**Fixture builder to reuse** (`share-invite.service.spec.ts:29-49`):
```typescript
function makeInvite(overrides: Partial<ShareInvite> = {}): ShareInvite {
  return {
    id: 'invite-id-1',
    token,
    sharerId,
    sharer: {} as never,
    rootNodeId,
    rootIpnsName,
    rootGeneration,
    itemNameEncrypted: null,
    encryptedKey: Buffer.from('cc'.repeat(64), 'hex'),
    writeDescriptorRef: null,
    status: 'active',
    maxClaims: 1,
    claimCount: 0,
    claimedBy: null,
    expiresAt: futureDate,
    createdAt: new Date('2026-06-01T00:00:00Z'),
    ...overrides,
  } as ShareInvite;
}
```
Constants at top of file (`sharerId`, `claimerId`, `rootNodeId`, `rootIpnsName`,
`READ_HEX`/`WRITE_HEX` full-length hex, real UUID-shaped IDs) are the contract-valid fixture style
D-09 explicitly wants replicated into `shares.controller.spec.ts` too (whose current fixtures use
placeholder strings like `'share-uuid-1'`, `'k51qzi5uqu5full'`, `'04sharerkey'` — non-contract-valid
per CodeRabbit NIT3).

**Mock scaffolding to reuse for new `createInvite`/`getInvitesForItem`/`revokeInvite` describes**
(`share-invite.service.spec.ts:77-124`): the `mockInviteRepo`/`mockDataSource`/`mockManager`/`mockQb`
object shapes and the `Test.createTestingModule` provider wiring (`getRepositoryToken(ShareInvite)`,
`DataSource` mock) are the exact scaffolding to extend — for D-01's new `createInvite` tests, add a
`mockVaultRepo: { findOne: jest.Mock }` following the same shape and register it via
`{ provide: getRepositoryToken(Vault), useValue: mockVaultRepo }`.

**Existing test needing a rename/split per D-07** ("idempotent re-claim", lines 253-269): keep as
"same-level re-claim is a no-op" and add sibling read→write widen + generation-bump widen cases
(RESEARCH.md Pattern 2 test-impact note).

## Shared Patterns

### 23505 → HTTP error translation
**Source:** `apps/api/src/shares/shares.service.ts:74-89` (primary template, checks both `.code`
and `.driverError.code`); secondary occurrence `apps/api/src/vault/vault.service.ts:101-103`.
**Apply to:** `apps/api/src/ipns/ipns.service.ts` first-publish insert (D-06). Use the exact
`(err as { code?: string; driverError?: { code?: string } })` cast idiom — do NOT introduce a
`QueryFailedError instanceof` check anywhere in this phase (established anti-pattern per
RESEARCH.md "Don't Hand-Roll").

### Transactional atomic-UPDATE + branch-inside-transaction
**Source:** `apps/api/src/shares/share-invite.service.ts:139-203` (`claimInvite`'s
`dataSource.transaction(async (manager) => {...})` wrapping an atomic `createQueryBuilder().update()`
followed by a conditional branch, all sharing one `manager`).
**Apply to:** D-07's widen-merge logic — must execute inside this same transaction/manager, not a
new transaction.

### `createQueryBuilder()` bulk delete/update inside a transaction manager
**Source:** `apps/api/src/shares/shares.service.ts:179-186` (`revokeForItems`'s existing invite
`.update()` half).
**Apply to:** D-08's new `Share` delete half — same manager, same `.where()`/`.andWhere()` binding
conventions (named params, snake_case column refs in raw SQL fragments).

### Migration idempotency (`DO $$ ... EXCEPTION ... END $$;`)
**Source:** `apps/api/src/migrations/1740300000000-SharesPartialUniqueIndex.ts:11-30`.
**Apply to:** D-04's `ADD CONSTRAINT` — Postgres has no `IF NOT EXISTS` for named constraints;
this is the project's only precedent for guarding conditional DDL and should be reused rather than
inventing an `information_schema` existence-check variant.

### Greenfield migration `down()` waiver
**Source:** `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts` (down() throws with the
"Staging DB is wiped on each deploy — no rollback target" rationale).
**Apply to:** D-04's new migration `down()`.

## No Analog Found

None — all 8 folded decisions have a direct in-repo analog (several are self-referential:
extending the same file/method that already contains the target branch).

## Metadata

**Analog search scope:** `apps/api/src/shares/`, `apps/api/src/ipns/`, `apps/api/src/vault/`,
`apps/api/src/migrations/`
**Files scanned:** `share-invite.service.ts`, `share-invite.service.spec.ts`, `shares.service.ts`,
`shares.module.ts`, `ipns.service.ts`, `vault.service.ts`, `vault.entity.ts`,
`1740300000000-SharesPartialUniqueIndex.ts`, `1751000000000-ScheduleCollapse.ts`
**Pattern extraction date:** 2026-07-09

## PATTERN MAPPING COMPLETE

**Phase:** 71 - share-invite-security-and-ipns-data-integrity-api
**Files classified:** 9 (7 modified service/entity/test files + 1 new migration + 1 module-wiring edit)
**Analogs found:** 8 / 8

### Coverage
- Files with exact analog: 6 (self-extend in place, or sibling-block-in-same-file)
- Files with role-match analog: 2 (vault.service.ts for D-01 ownership lookup; SharesPartialUniqueIndex for D-04 idempotent DDL shape)
- Files with no analog: 0

### Key Findings / Key Patterns Identified
- All `ConflictException` throws in `ipns.service.ts` use the **object** payload shape
  (`{statusCode, message, ...}`); `shares.service.ts`/`vault.service.ts` use the **string** shape.
  D-06's new throw should match `ipns.service.ts`'s local object-shape convention, not
  `shares.service.ts`'s string-shape (file-local consistency wins over cross-file consistency).
- **Blocking prerequisite for D-01 not previously flagged as confirmed:** `Vault` is NOT registered
  in `apps/api/src/shares/shares.module.ts`'s `TypeOrmModule.forFeature([...])` array today —
  injecting `@InjectRepository(Vault)` into `ShareInviteService` will fail Nest DI resolution unless
  this module-wiring edit lands alongside D-01's service change.
- D-04's idempotent-DDL open question (RESEARCH.md Open Question 2) is now resolved: the project's
  only comparable precedent (`1740300000000-SharesPartialUniqueIndex.ts`) uses a `DO $$ ... END $$;`
  guarded block — reuse that shape (`EXCEPTION WHEN duplicate_object THEN NULL;`) for the new
  `ADD CONSTRAINT`, not an `information_schema` pre-check.
- D-08's cleanest implementation mirrors the sibling query-builder block already present two lines
  below the target code, in the same method, same transaction manager — no new abstraction needed.

### File Created
`.planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-PATTERNS.md`

### Ready for Planning
Pattern mapping complete. Planner can now reference analog patterns in PLAN.md files.
