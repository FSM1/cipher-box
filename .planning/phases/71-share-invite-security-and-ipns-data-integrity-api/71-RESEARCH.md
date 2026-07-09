# Phase 71: Share-Invite Security and IPNS Data-Integrity (API) - Research

**Researched:** 2026-07-09
**Domain:** NestJS/TypeORM/Postgres authorization + DB-integrity hardening (apps/api)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01 — Root-ownership source (SC#1):** Validate root ownership by looking up the **`vaults`
entity**, not `ipns_records`: `SELECT 1 FROM vaults WHERE owner_id = :req.user.id AND
root_ipns_name = :dto.rootIpnsName`. `vaults.owner_id` is a real FK to `users` and is
`@Index({ unique: true })` (one vault per user) — `apps/api/src/vault/entities/vault.entity.ts:19-38`.
Rejected Flow A (check `ipns_records.is_root` + `user_id`) — trusts the non-authoritative creator
marker. Rejected Flow B (elevate `ipns_records.user_id` to authoritative) — invasive, redundant with
the vault, fights the documented design. Cost: one indexed lookup added to `createInvite` before
persist.

**D-02 — rootNodeId validation (SC#1):** Validate `rootIpnsName` ownership only. `rootNodeId` stays
client-asserted for this phase. No server store records a root's nodeId today. Rejected persisting
`root_node_id` on `vaults` (larger blast radius than this phase warrants). Known gap to document:
SC#1's "owns the `(rootIpnsName, rootNodeId)` pair" is only half-enforced server-side.

**D-03 — SC#3 root-uniqueness index: SKIP.** Do NOT add the `ipns_records(user_id) WHERE is_root`
partial unique index. `vaults.owner_id` is already unique → one-root-per-user is already enforced at
the vault layer. SC#3 is flagged for revision: its `claim_count` CHECK-constraint half still applies
(D-04); its root-uniqueness-index half is dropped as already-covered.

**D-04 — claim_count CHECK constraint (SC#3, mechanical):** Add a forward migration + entity
`@Check`: `CHECK (claim_count >= 0 AND claim_count <= max_claims)` on `share_invites`. Target:
`share-invite.entity.ts`.

**D-05 — Same-seq CID equivocation → HARD-GUARD 400 (SC#4 / D-09):** When a republish arrives with
`embeddedSeq === dbSeq` and the incoming metadata CID differs from the stored `latestCid`, reject
with `BadRequestException` (400). Evidence this is anomaly-only: the TEE lease-renewer (post-Phase
67) structurally cannot repoint the CID (`renewIpnsRecord` re-signs value+sequence parsed from the
existing record; the request body has no `metadataCid` field); it also uses a separate EOL-only
write path that never reaches the `upsertIpnsRecord` same-seq branch. Client publish always bumps
the sequence on any content change. Guard precision: reject ONLY when incoming CID ≠ stored
`latestCid` — idempotent same-CID retries MUST still succeed (no blanket same-seq reject). Cleanup
required: rewrite the stale "Pitfall 4" test (`ipns.service.spec.ts:2111-2137`) and the misleading
comment (`ipns.service.ts:313`).

**D-06 — First-publish INSERT race → 409 (SC#4, mechanical):** Wrap the first-publish `save`
(`ipns.service.ts` ~436-451), catch TypeORM `QueryFailedError` unique-violation (Postgres `23505`)
and translate to `ConflictException` (409) instead of a 500. Add an e2e case. Detect via error code
`23505` (constraint-name detection is a fallback).

**D-07 — Re-claim later-grant → UPGRADE-MERGE, widen-only (SC#2):** In `claimInvite`, when a share
to the recipient already exists, apply the later invite's grant only if it widens authority (e.g.
read → write); otherwise no-op. Never downgrade write → read. Write authority is presence-derived:
`invite.writeDescriptorRef !== null` (invariant T-66-E1). Only widen. Ordering: the existing-share
branch currently runs after the atomic claim UPDATE has already incremented `claim_count` — the
merge/no-op decision must be resolved without wasting/burning the invite improperly. Rejected
Reject-on-conflict (409) — worse UX.

**D-08 — Bulk-revoke direct DELETE (SC#5, mechanical):** Swap `find` + `remove` for a single
`DELETE ... execute()`. Naming correction: there is no `bulkRevoke` on `ShareInviteService`; the
bulk share+invite revoke lives in `SharesService.revokeForItems`. `Share` has no
hooks/cascades/subscribers, so direct DELETE is behavior-preserving. Spec mock churn only.

**D-09 — Restore ShareInviteService unit coverage (SC#6, mechanical):** Extend
`share-invite.service.spec.ts` for `createInvite`, `getInvitesForItem`, `revokeInvite` with realistic
UUID/key fixtures (not placeholder strings). Also fix placeholder fixtures in
`shares.controller.spec.ts` (contract-valid UUIDs/keys).

**Migration ordering (cross-cutting):** New forward migrations (D-04 CHECK constraint, plus any
needed for D-07) land in `apps/api/src/migrations/` with timestamps after the latest existing
`1751000000000-ScheduleCollapse.ts`. NEVER edit the shipped `1750000000000-ApiSchemaCutover.ts` in
place.

**Ownership ceiling (applies across SC#1/SC#3):** No store proves *key possession* —
`vaults.root_ipns_name` was itself client-asserted at `/vault/init`, and the whole model bottoms out
at "first authenticated user to claim the globally-`@Unique` ipnsName wins." This phase raises
ownership from *nothing* to *"the authenticated user who registered this root."* A cryptographic
key-possession challenge is explicitly out of scope (own phase).

### Claude's Discretion

None called out separately in CONTEXT.md — all 9 decisions above are fully locked (mechanical or
design-decided). The only discretionary latitude is HOW to implement each locked decision (exact
merge-field-write ordering for D-07, exact idempotent-migration SQL shape for D-04), which this
RESEARCH.md's Architecture Patterns / Open Questions sections address.

### Deferred Ideas (OUT OF SCOPE)

- **Cryptographic key-possession proof of root ownership** (signature challenge at
  `createInvite`/`/vault/init`) — the real fix for the "first-claimer-wins" ceiling. Out of scope;
  own phase. This phase only raises ownership to "authenticated registrant."
- **Persisting `root_node_id` on `vaults`** to enable full `(rootIpnsName, rootNodeId)` pair
  validation (D-02 gap) — deferred; touches vault-init write path.

**Reviewed Todos (not folded):** None — all 8 source todos folded (one, root-uniqueness-index,
folded then dropped as already-covered per D-03).
</user_constraints>

## Summary

This phase closes 7 diagnosed authorization/data-integrity edges plus 1 test-coverage gap in
`apps/api`'s share-invite and IPNS modules. All 9 decisions (D-01…D-09) are locked in
`71-CONTEXT.md`; this research verifies the locked decisions against the live codebase, confirms
the D-05 TEE-contract evidence is NOT stale, and — most importantly for the plan-checker — maps
each decision to a concrete, runnable verification strategy.

Every file this phase touches was read in full. Two decisions (D-05, D-06) implement guards that
**do not exist yet** in the current code — verified by direct inspection: `upsertIpnsRecord`'s
same-seq branch (`ipns.service.ts:310-315`) unconditionally sets `isIdempotentRepublish = true`
with no CID-equality check, and the first-publish INSERT (`ipns.service.ts:436-453`) has no
try/catch around `save()`. D-01/D-02 (ownership check) is also absent — `createInvite` copies
`dto.rootIpnsName`/`dto.rootNodeId` verbatim with zero server-side verification
(`share-invite.service.ts:37-46`). D-07's existing-share branch (`share-invite.service.ts:169-174`)
literally returns the stale `existingShare.id` with a `logger.warn` and no merge logic — confirmed
this is the exact target for the widen-only upgrade. D-08's `revokeForItems`
(`shares.service.ts:171-176`) still does `find` + `remove`, not a direct DELETE. All are exactly as
CONTEXT.md describes — no drift between the diagnosis and the current tree.

The TEE-contract evidence for D-05 checked out: `renewIpnsRecord` (`ipns-signer.ts:33-46`) derives
`value` and `sequence` exclusively from `parseIpnsRecord(marshaledExistingRecord)` — there is no CID
or sequence parameter it could accept. The TEE worker's `/republish` route (`republish.ts`) never
sends a `metadataCid` in its request/response shape. Separately, the API's own EOL-only renewal path
(`republish.service.ts:459-478`, `renewIpnsRecordEol`) is a **standalone** direct `UPDATE ... WHERE
sequence_number = :expected` that never calls `upsertIpnsRecord` at all — so the TEE renewal flow
cannot reach the same-seq branch this phase is hardening. The evidence is current, not stale.

**Primary recommendation:** Implement all 9 decisions as scoped, mechanical edits to 3 service
files + 1 entity + 1 new migration, following the exact existing 23505-detection idiom already used
twice in this codebase (`shares.service.ts:81-85`, `vault.service.ts:103`) rather than a
`QueryFailedError` instanceof check (the todo's suggestion) — this keeps D-06 consistent with
established project style. No new npm packages are required for any decision.

## Project Constraints (from CLAUDE.md)

Directives from the root `CLAUDE.md` that apply to this phase's implementation:

- **Terminology standards:** Use `folderKey`, `fileKey`, `keyEpoch`, `ipnsName`/`ipnsRecord`
  consistently — not applicable to most of this phase's edits (no key-material fields are
  introduced or renamed by D-01…D-09), but any new code touching `rootIpnsName`/`rootNodeId` must
  keep the existing correct terminology (already used correctly in all touched files).
- **Critical security rules:** Never suggest storing `privateKey` in localStorage/sessionStorage;
  never log sensitive keys; never send unencrypted keys to server; server NEVER has access to
  plaintext or unencrypted keys. This phase touches zero key material — all 9 decisions are
  DB-integrity/authorization logic (ownership lookups, CHECK constraints, error-code translation,
  grant-merge semantics). No decision requires touching ECIES wrapping, AES-256-GCM encryption, or
  any crypto primitive. Confirmed zero-knowledge posture is unaffected.
- **API Development Workflow:** "After modifying API endpoints, DTOs, or controllers, regenerate the
  API client... Always run `pnpm api:generate` before completing a feature that touches the API."
  **Applicability check per decision:**
  - D-01/D-02: `createInvite`'s DTO (`CreateInviteDto`) and response shape (`InviteResponseDto`) are
    UNCHANGED — the ownership check only adds an internal lookup before persist; no new/changed DTO
    fields, no new HTTP status code beyond the standard `403 Forbidden` (NestJS's built-in
    `ForbiddenException` — already a documented status in Swagger for other endpoints in this
    controller). **`pnpm api:generate` likely NOT required** for D-01/D-02 unless the planner adds a
    NEW documented error response to the OpenAPI spec (e.g., an explicit `@ApiResponse({status: 403,
    ...})` decorator addition) — if that decorator is added, `api:generate` must run since the
    OpenAPI spec output changes even without a DTO/field change.
  - D-04: entity-only change (`@Check` decorator) + migration — no controller/DTO surface change.
    **`pnpm api:generate` NOT required.**
  - D-05/D-06: internal `IpnsService` logic changes only, no DTO/controller signature change (the
    `BadRequestException`/`ConflictException` responses these produce are the SAME exception types
    already thrown by neighboring branches in the same method, already documented in the existing
    OpenAPI spec for this endpoint). **`pnpm api:generate` NOT required** — mirrors the precedent
    noted in STATE.md for Phase 60-05: "api:generate NOT required; changes are internal
    service/codec logic with no OpenAPI surface change."
  - D-07: `claimInvite`'s DTO/response shape unchanged — the merge logic is entirely internal to
    the transaction. **`pnpm api:generate` NOT required.**
  - D-08: `revokeForItems`'s signature and response shape (`{revokedShares, revokedInvites}`)
    unchanged — internal implementation swap only. **`pnpm api:generate` NOT required.**
  - D-09: test-only changes. **`pnpm api:generate` NOT required.**
  - **Net assessment: this entire phase is unlikely to require `pnpm api:generate`** since no
    decision changes a DTO field, a response shape, or adds a NEW documented `@ApiResponse` status
    code beyond what's already in the existing OpenAPI spec for these endpoints. The planner should
    still verify this at execution time by running `pnpm api:generate` as a final check (per the
    "Always run before completing a feature that touches the API" directive) — if the generated
    diff is empty, no commit of `packages/api-client/` is needed; the pre-commit hook
    (`scripts/check-api-client.sh`) will only fail if API changes were staged without a
    corresponding client update, which won't apply here if the OpenAPI surface is genuinely
    unchanged.
- **Terminology/commit conventions:** Conventional Commits format, no parenthesized text in commit
  subjects — applies to this phase's commits as it does to all commits in this repo (workflow-level,
  not phase-specific, noted here for completeness).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Root-ownership check (D-01/D-02) | API / Backend | Database (indexed lookup on `vaults`) | Authorization must be server-enforced; client cannot be trusted to self-report ownership |
| Claim-count bound (D-04) | Database | API / Backend | App layer already enforces it; DB CHECK is defense-in-depth, must live at the DB tier to be unconditional |
| Same-seq CID equivocation guard (D-05) | API / Backend | — | Publish-gate logic lives entirely in `IpnsService`; no DB constraint can express "conditional on incoming vs. stored value" as cleanly as an app-layer branch |
| First-publish race → 409 (D-06) | API / Backend | Database (`@Unique(['ipnsName'])` constraint is the actual race-breaker) | The DB unique constraint already prevents duplicate rows; this decision only fixes the HTTP status translation in the API tier |
| Re-claim upgrade-merge (D-07) | API / Backend | Database (transaction boundary) | Business logic (widen-only semantics) belongs in the service; the atomic UPDATE + merge must share one DB transaction |
| Bulk-revoke DELETE (D-08) | Database | API / Backend | Direct DELETE pushes the deletion into the DB tier instead of round-tripping rows through the app |
| Unit test coverage (D-09) | Test / API | — | N/A — coverage lives alongside the service it tests |

## Standard Stack

No new packages. This phase is scoped entirely to `apps/api`'s existing dependency set.

### Core (already installed, verified)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `typeorm` | 0.3.28 (`npm view typeorm version` confirms `1.0.0` is NOT the installed version — pinned via pnpm-lock; `package.json` specifies `^0.3.28`) | ORM, migrations, `@Check` decorator, `QueryFailedError` | Already the project's ORM; `Check` decorator confirmed exported from `typeorm/decorator/Check` in the installed 0.3.28 tree |
| `@nestjs/common` | ^11.0.0 (`ConflictException`, `BadRequestException`, `ForbiddenException`) | HTTP error mapping | Already used identically in `ipns.service.ts` and `shares.service.ts` |
| `@nestjs/typeorm` | ^11.0.0 | Repository injection | Existing pattern, no change |

**Installation:** None required — no `pnpm add` for this phase.

**Version verification:** `npm view typeorm version` returned `1.0.0` (the registry's *latest* tag), but the project pins `typeorm@^0.3.28` in `apps/api/package.json` and the installed tree under `node_modules/.pnpm/typeorm@0.3.28.../typeorm/index.d.ts` confirms `Check` is exported at that version `[VERIFIED: local node_modules inspection]`. Do not upgrade typeorm as part of this phase — out of scope, and `^0.3.28` already satisfies every decision's needs.

## Package Legitimacy Audit

**Not applicable — this phase installs zero new external packages.** All 9 decisions use libraries
already present in `apps/api`'s dependency tree (`typeorm`, `@nestjs/common`). No `package-legitimacy
check` run was needed.

**Packages removed due to [SLOP] verdict:** none (N/A — no new packages)
**Packages flagged as suspicious [SUS]:** none (N/A — no new packages)

## Architecture Patterns

### System Architecture Diagram

```
createInvite request (rootIpnsName, rootNodeId, ...)
        │
        ▼
┌───────────────────────────┐
│ ShareInviteService        │  D-01/D-02: NEW — vaultRepo.findOne({owner_id, root_ipns_name})
│ .createInvite()           │──────► reject 403/404 if no matching Vault row
└───────────────────────────┘        (rootNodeId stays client-asserted — documented gap)
        │ (ownership OK)
        ▼
   inviteRepo.save()  ──► share_invites row (unchanged shape)


claimInvite request (token, claimerId, dto)
        │
        ▼
┌───────────────────────────┐
│ dataSource.transaction()  │
│  1. atomic claim UPDATE   │  (existing :141 — unchanged)
│     claim_count+1         │
│  2. existing-share lookup │  (existing :161 — unchanged query)
│  3. D-07 NEW: if existing,│──────► widen-only merge (read→write / gen bump)
│     compare + merge grant │        else: mint new Share (existing :185 — unchanged)
└───────────────────────────┘


IPNS publish (ipns.service.ts upsertIpnsRecord)
        │
        ▼
   existing row? ──NO──► D-06 NEW: try/catch around save()
        │                 23505 → ConflictException(409)  [mirrors shares.service.ts:81-85]
       YES
        │
        ▼
   embeddedSeq === dbSeq? ──YES──► D-05 NEW: incoming CID !== stored latestCid?
        │                            │ YES → BadRequestException(400)
        │                            │ NO  → idempotent no-op (existing behavior, unchanged)
       NO (forward/rollback/jump — existing branches unchanged)


revokeForItems (shares.service.ts)
        │
        ▼
   D-08: find+remove ──► REPLACE WITH ──► single DELETE ... WHERE sharer_id AND root_ipns_name IN (...)
```

### Recommended Project Structure

No new files/folders — all edits land in existing files:

```
apps/api/src/
├── shares/
│   ├── share-invite.service.ts       # D-01, D-02, D-07
│   ├── shares.service.ts             # D-08
│   ├── entities/share-invite.entity.ts  # D-04 (@Check decorator)
│   └── share-invite.service.spec.ts  # D-09 (extend)
├── ipns/
│   ├── ipns.service.ts               # D-05, D-06
│   └── ipns.service.spec.ts          # D-05 (rewrite Pitfall-4 test), D-06 (add test)
├── vault/
│   └── entities/vault.entity.ts      # D-01 (read-only — reuse, no change)
└── migrations/
    └── {new-timestamp}-ClaimCountCheckConstraint.ts  # D-04
```

### Pattern 1: Vault-backed ownership lookup (D-01)
**What:** A single indexed `findOne` against the `vaults` repository before persisting an invite.
**When to use:** Any time a "does this user own this root" check is needed — this is now the
canonical pattern (superseding any temptation to trust `ipns_records.user_id`, which the entity
comment explicitly calls a "denormalized creator marker").
**Example:**
```typescript
// Source: apps/api/src/vault/entities/vault.entity.ts:18-38 (existing entity, read-only reuse)
@Injectable()
export class ShareInviteService {
  constructor(
    @InjectRepository(ShareInvite) private readonly inviteRepo: Repository<ShareInvite>,
    @InjectRepository(Vault) private readonly vaultRepo: Repository<Vault>, // NEW injection
    private readonly dataSource: DataSource
  ) {}

  async createInvite(sharerId: string, dto: CreateInviteDto): Promise<ShareInvite> {
    const owned = await this.vaultRepo.findOne({
      where: { ownerId: sharerId, rootIpnsName: dto.rootIpnsName },
    });
    if (!owned) {
      throw new ForbiddenException('You do not own this root');
    }
    // ...existing invite creation unchanged
  }
}
```
`ShareInviteModule` must import `TypeOrmModule.forFeature([Vault])` if `Vault` is not already
registered in that module — **verify this at plan time** (grep
`apps/api/src/shares/shares.module.ts` for existing `TypeOrmModule.forFeature` entries).

### Pattern 2: Widen-only grant merge sequenced around the atomic claim (D-07)
**What:** When `claimInvite`'s existing-share branch fires, compare the new invite's grant to the
existing share's and apply only if it widens (read → write, or a higher `rootGeneration`); never
downgrade.
**When to use:** Exactly the `existingShare` branch at `share-invite.service.ts:169-174` inside the
already-open transaction.
**Sequencing analysis (the exact question CONTEXT.md flags as needing research):** The atomic claim
UPDATE at `:141` (`claim_count + 1`, `status = 'claimed'`) has ALREADY run and committed inside the
same transaction manager by the time the existing-share branch executes at `:161`. This is
correct and must NOT change — the invite is validly consumed regardless of whether the resulting
grant needs a merge or is a true no-op, because:
  - A legitimate widen (recipient previously claimed read-only, now claims a write invite) MUST
    consume the invite (claim_count increments) — otherwise the same write invite could be
    re-claimed indefinitely.
  - A redundant re-claim (same access level) is safe to consume too — `maxClaims` defaults to 1,
    so the invite is single-use by design regardless of merge outcome.
  So: **do the merge/no-op decision AFTER the atomic UPDATE, still inside the same transaction,
  before the function returns** — no reordering needed, just add logic to the existing branch:

```typescript
// Source: apps/api/src/shares/share-invite.service.ts:169-174 (existing branch, extend)
if (existingShare) {
  const inviteGrantsWrite = invite.writeDescriptorRef !== null;
  const existingHasWrite = existingShare.writeDescriptorRef !== null;
  const isGenerationBump = BigInt(invite.rootGeneration) > BigInt(existingShare.rootGeneration);
  const isWriteUpgrade = inviteGrantsWrite && !existingHasWrite;

  if (isWriteUpgrade || isGenerationBump) {
    existingShare.readDescriptorRef = Buffer.from(dto.readDescriptorRef, 'hex');
    if (isWriteUpgrade && dto.writeDescriptorRef) {
      existingShare.writeDescriptorRef = Buffer.from(dto.writeDescriptorRef, 'hex');
    }
    if (isGenerationBump) {
      existingShare.rootGeneration = invite.rootGeneration;
    }
    await manager.save(existingShare);
  }
  // else: existing grant already >= invite's grant — true no-op, matches current behavior
  return { shareId: existingShare.id };
}
```
Never downgrade: if `existingHasWrite && !inviteGrantsWrite`, skip the write-field write entirely
(the `isWriteUpgrade` guard already prevents this — `existingHasWrite` being true makes
`isWriteUpgrade` false).

**Test impact:** the current `share-invite.service.spec.ts` "idempotent re-claim" test (line 254-269)
asserts `manager.save` is never called and only checks `manager.create` was not called — this test's
name and assertions describe the OLD silent-drop behavior. It needs to be either (a) kept as a
same-level-grant no-op case (still valid — no widen means no save), or (b) split into a same-level
no-op case (unchanged assertions) PLUS new widen-merge cases. Recommend (b): keep the existing test
renamed to "same-level re-claim is a no-op" and add two new test cases for read→write widen and
generation-bump widen.

### Pattern 3: 23505-to-409 translation (D-06) — reuse the established idiom
**What:** Wrap `save()`, inspect the caught error's `.code` / `.driverError.code` for `'23505'`.
**When to use:** D-06's first-publish INSERT race.
**Do NOT** introduce a `QueryFailedError` instanceof check (the todo file's suggestion) — the
codebase has an established, simpler idiom used twice already:
```typescript
// Source: apps/api/src/shares/shares.service.ts:75-88 (existing pattern — mirror exactly)
try {
  const saved = await this.ipnsRecordRepository.save(folder);
  // ...existing enrollment side-effect unchanged
  return saved;
} catch (err: unknown) {
  const code = (err as { code?: string; driverError?: { code?: string } }).code;
  const driverCode = (err as { driverError?: { code?: string } }).driverError?.code;
  if (code === '23505' || driverCode === '23505') {
    throw new ConflictException({
      statusCode: 409,
      message: 'IPNS record already exists',
    });
  }
  throw err;
}
```
This exact shape is also used in `vault.service.ts:103`. Following it keeps error-detection style
uniform across the codebase (three call sites now use the identical idiom) rather than introducing
a fourth, different pattern.

### Pattern 4: Same-seq CID-equality guard (D-05)
**What:** Add one condition inside the existing `embeddedSeq === dbSeq` branch.
**Example:**
```typescript
// Source: apps/api/src/ipns/ipns.service.ts:311-315 (existing branch — add one check)
} else {
  const dbSeq = BigInt(existing.sequenceNumber);
  if (embeddedSeq === dbSeq) {
    // D-05: reject only when the incoming CID diverges from the stored latestCid.
    // Idempotent same-CID retries (the TEE lease-renewer path, and legitimate client
    // retries) MUST still succeed — this is NOT a blanket same-seq reject.
    if (metadataCid !== existing.latestCid) {
      throw new BadRequestException(
        `Same-sequence republish with a different CID is rejected: ` +
          `embedded seq ${embeddedSeq} already committed to ${existing.latestCid}, ` +
          `got ${metadataCid}`
      );
    }
    isIdempotentRepublish = true;
  } else if (embeddedSeq === dbSeq + 1n) {
    // unchanged
  }
  // ...rest unchanged
}
```
**Cleanup required alongside this (explicitly called out in D-05):**
- Rewrite the stale comment at `ipns.service.ts:313` ("Idempotent republish — TEE 6-hour re-sign
  path... Do NOT increment the DB sequence, but still update latestCid/signedRecord below.") — the
  "still update latestCid" half is no longer universally true; it only holds for same-CID retries
  now.
- Rewrite the "Pitfall 4" test at `ipns.service.spec.ts:2111-2137` — it currently asserts
  `setArgs.latestCid` equals a DIFFERENT CID (`newCid`) at the same sequence, which is now the
  REJECTED case. Change the test to either (a) assert `BadRequestException` is thrown for a
  different-CID same-seq publish (the new negative case), and (b) add a new positive case asserting
  a same-CID same-seq publish still succeeds without incrementing `sequence_number` (the true
  idempotent-retry case this decision preserves).

### Anti-Patterns to Avoid
- **Trusting `ipns_records.user_id` for authorization (D-01/D-03):** The entity's own doc comment
  calls it a non-authoritative "denormalized creator marker." Any future authorization check in
  this module must go through `vaults.owner_id`, never `ipns_records.user_id`.
- **Editing the shipped `1750000000000-ApiSchemaCutover.ts` or `1751000000000-ScheduleCollapse.ts`
  in place (D-04):** Both are immutable per the DB Evolution Protocol. The claim_count CHECK must
  be a brand-new migration timestamped after `1751000000000`.
- **Blanket same-seq rejection (D-05):** Rejecting ALL same-sequence republishes (not just
  divergent-CID ones) would break the legitimate TEE-style same-CID idempotent retry path and the
  existing "allows idempotent republish" test's happy-path semantics — the guard must be
  CID-equality-conditional, not sequence-conditional alone.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Postgres unique-violation detection | A custom SQL error parser or regex on `err.message` | The existing `err.code === '23505' \|\| err.driverError?.code === '23505'` idiom | Already proven correct in this codebase at 2 call sites; message-substring matching is brittle across driver/Postgres versions |
| DB-level bound enforcement | Application-only bounds checking as the sole defense | A `@Check` constraint (D-04) | Postgres CHECK constraints are unconditional — they hold even if a future code path bypasses the service layer (raw SQL, admin tooling, a bug) |
| Root ownership proof | A new cryptographic challenge/signature scheme | The existing `vaults.owner_id` unique FK (D-01) | CONTEXT.md explicitly defers true key-possession proof to a future phase; this phase only needs to raise the ceiling from "nothing" to "authenticated registrant," which the existing FK already encodes |

**Key insight:** Every one of this phase's 9 decisions is a bounded, mechanical fix layered on
existing infrastructure (`vaults`, TypeORM `@Check`, the established 23505 idiom, the existing
transaction boundary in `claimInvite`). None require new abstractions, new tables, or new
dependencies — the risk in this phase is entirely in getting the edge-case sequencing right (D-05's
CID-equality precision, D-07's widen-only merge ordering), not in architecture.

## Common Pitfalls

### Pitfall 1: D-05 guard placed too broadly (rejects legitimate same-CID retries)
**What goes wrong:** If the guard rejects on `embeddedSeq === dbSeq` alone (without the CID check),
every legitimate idempotent retry (client retry after a dropped response, TEE-adjacent re-publish
with unchanged content) starts failing with 400.
**Why it happens:** Conflating "same-seq is anomalous" with "same-seq + different-CID is
anomalous" — CONTEXT.md is explicit that only the latter is illegitimate.
**How to avoid:** The guard condition MUST be `embeddedSeq === dbSeq && metadataCid !==
existing.latestCid`, never `embeddedSeq === dbSeq` alone.
**Warning signs:** The rewritten Pitfall-4 test's "same CID, same seq" case starts failing.

### Pitfall 2: D-07 merge downgrades write → read or regresses generation
**What goes wrong:** A read-only re-invite claimed after an existing write share silently clears
the recipient's write access.
**Why it happens:** Implementing the merge as an unconditional overwrite of
`existingShare.writeDescriptorRef` from the invite, instead of gating on `isWriteUpgrade` (which
requires `inviteGrantsWrite && !existingHasWrite`).
**How to avoid:** Every field write in the merge branch must be individually gated — never a blanket
`Object.assign`. Mirror the existing T-66-E1 invariant test style (assert the specific field, not
the whole object).
**Warning signs:** A test claiming a read-only invite after an existing write share still shows
`writeDescriptorRef !== null` afterward — this must NOT happen (regression).

### Pitfall 3: D-01 blocks legitimate shared-folder re-invites
**What goes wrong:** If the ownership check is scoped too narrowly (e.g., requiring
`rootIpnsName` to equal the user's OWN vault root exactly), a sharer trying to re-invite for a
**sub-folder** they own (not the vault root itself) gets incorrectly rejected — but per D-02, only
`rootIpnsName` ownership is checked this phase, and CONTEXT.md's SC#1 language is about "the root of
the shared subtree," which for invites of arbitrary subfolders is NOT necessarily the user's vault
root.
**Why it happens:** Misreading "root" in `rootIpnsName`/`rootNodeId` (the invite's root — the top of
the SHARED subtree) as synonymous with "vault root" (the user's OWN vault root).
**How to avoid:** Re-read D-01/D-02 carefully: **confirm with the actual createInvite call sites in
the web/SDK client** whether `dto.rootIpnsName` is always the caller's OWN vault root, or can be an
arbitrary owned subfolder's IPNS name. If it can be a subfolder, the `vaults` table (one row per
user, storing only the TOP-level `root_ipns_name`) cannot validate ownership of an arbitrary
subfolder — this would be a genuine gap requiring escalation back to the user/CONTEXT before
planning proceeds naively.
**Warning signs:** e2e test for "owner invites a subfolder they own (not the vault root)" fails
after D-01 lands.
**Recommendation:** This is flagged as an **Open Question** below — the planner MUST verify actual
invite call sites (`apps/web/src` share/invite creation flow) before finalizing D-01's task, since
CONTEXT.md's own text says "Root folder is tracked in Vault entity" implying `createInvite`'s
`rootIpnsName` is expected to always be a VAULT root name (i.e., invites are only issued at
subtree-root granularity that happens to align with a user's single vault root) — but this needs a
one-grep confirmation, not an assumption.

### Pitfall 4: Migration ordering violation (D-04)
**What goes wrong:** A new migration timestamped before `1751000000000-ScheduleCollapse.ts` would
run out of order or before its dependency exists.
**Why it happens:** Copy-pasting an old timestamp instead of using `Date.now()`.
**How to avoid:** New migration must use a timestamp strictly greater than `1751000000000`. Current
date is 2026-07-09, so any `Date.now()`-based timestamp naturally satisfies this — just don't
hardcode an old constant.
**Warning signs:** `pnpm --filter api build` / migration runner errors about ordering, or the CHECK
constraint migration silently no-ops because `ALTER TABLE` ran against a table that hadn't been
created yet (not applicable here since `share_invites` was created in
`1740400000000-AddShareInvites.ts`, long before either boundary migration — just confirm the new
timestamp sorts after `1751000000000`).

## Code Examples

### D-04: claim_count CHECK constraint migration
```typescript
// Source: apps/api/src/migrations/1751000000000-ScheduleCollapse.ts (style template)
import { MigrationInterface, QueryRunner } from 'typeorm';

export class ClaimCountCheckConstraint{TIMESTAMP} implements MigrationInterface {
  name = 'ClaimCountCheckConstraint{TIMESTAMP}';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "share_invites"
        ADD CONSTRAINT "CHK_share_invites_claim_count"
        CHECK ("claim_count" >= 0 AND "claim_count" <= "max_claims")
    `);
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    throw new Error(
      'down() not implemented: greenfield migration under D-01 waiver (Phase-66 precedent). ' +
        'Staging DB is wiped on each deploy — no rollback target.'
    );
  }
}
```
Entity mirror (documentation only — Postgres enforces the real constraint):
```typescript
// Source: apps/api/src/shares/entities/share-invite.entity.ts (add @Check to @Entity decorator)
import { Check } from 'typeorm';

@Entity('share_invites')
@Check('CHK_share_invites_claim_count', '"claim_count" >= 0 AND "claim_count" <= "max_claims"')
export class ShareInvite {
  // ...unchanged
}
```
**Idempotency note:** unlike `CREATE TABLE`/`CREATE INDEX`, `ADD CONSTRAINT` has no built-in
`IF NOT EXISTS` in Postgres < 9.6-compatible syntax for constraints by name in one statement;
wrap in a `DO $$ ... EXCEPTION WHEN duplicate_object THEN NULL; END $$;` block OR precede with a
`information_schema.table_constraints` existence check if idempotent re-run safety across
partial-failure redeploys is required — **verify project convention**: grep other migrations for
constraint-add idempotency patterns (e.g., `1740300000000-SharesPartialUniqueIndex.ts`) before
finalizing the exact SQL.

### D-08: Direct DELETE for bulk revoke
```typescript
// Source: apps/api/src/shares/shares.service.ts:170-193 (existing method, replace find+remove)
async revokeForItems(
  sharerId: string,
  ipnsNames: string[]
): Promise<{ revokedShares: number; revokedInvites: number }> {
  const uniqueNames = [...new Set(ipnsNames)];
  if (uniqueNames.length === 0) {
    return { revokedShares: 0, revokedInvites: 0 };
  }

  return this.dataSource.transaction(async (manager) => {
    const shareResult = await manager
      .createQueryBuilder()
      .delete()
      .from(Share)
      .where('sharer_id = :sharerId', { sharerId })
      .andWhere('root_ipns_name IN (:...names)', { names: uniqueNames })
      .execute();

    const inviteResult = await manager
      .createQueryBuilder()
      .update(ShareInvite)
      .set({ status: 'revoked' })
      .where('sharer_id = :sharerId', { sharerId })
      .andWhere('root_ipns_name IN (:...names)', { names: uniqueNames })
      .andWhere('status = :status', { status: 'active' })
      .execute();

    return {
      revokedShares: shareResult.affected ?? 0,
      revokedInvites: inviteResult.affected ?? 0,
    };
  });
}
```
If `In` becomes unused elsewhere in the file after this change, remove the now-dead import
(the todo explicitly calls this out).

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `find()` + `remove()` for bulk delete | Direct `DELETE ... WHERE` query builder | This phase (D-08) | Avoids loading `bytea` descriptor columns into memory for large subtree revokes |
| Verbatim DTO trust for root identity at invite-issuance | Server-side `vaults` ownership lookup | This phase (D-01) | Closes CodeRabbit-flagged "Heavy lift" finding from Phase 66 |
| Same-seq republish always overwrites `latestCid` | Same-seq republish overwrites `latestCid` ONLY if CID unchanged | This phase (D-05) | Closes CodeRabbit-flagged equivocation concern from Phase 66; TEE lease-renewer (Phase 67) already made the "legitimate CID repoint at same seq" case structurally impossible, which is WHY this hard-guard is now safe to add (it would have been unsafe pre-Phase-67 if the TEE could repoint CIDs) |

**Deprecated/outdated:**
- The "ipns_records root-uniqueness partial index" idea (original SC#3 half) — superseded by D-03's
  finding that `vaults.owner_id` unique FK already enforces one-root-per-user. Do not implement the
  partial index; SC#3 is amended per CONTEXT.md.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `createInvite`'s `dto.rootIpnsName` is always the caller's own vault root (never an arbitrary owned subfolder) — needed for D-01's `vaults` lookup to be sufficient | Common Pitfalls #3, Pattern 1 | If false, D-01 as specified would reject legitimate subfolder-only invites; planner must grep `apps/web/src` invite-creation call sites and the `SC#1`/`SC#2` original design doc (`docs/design/2026-06-26-sharing-read-keychaining-design.md`, referenced in REQUIREMENTS.md) to confirm invite semantics before finalizing D-01's task boundary |
| A2 | The `@Check` constraint SQL does not need `IF NOT EXISTS`-equivalent idempotency wrapping because this codebase's constraint-migrations don't establish that convention | Code Examples (D-04) | If wrong (i.e., the project DOES require idempotent constraint-adds for redeploy safety), a re-run against a DB where the constraint already exists will throw `duplicate_object` and fail the migration step; low risk since migrations run once per environment via `migrationsRun: true`, but should be verified against `1740300000000-SharesPartialUniqueIndex.ts`'s actual pattern at plan time |

**If this table is empty:** N/A — 2 assumptions above need a one-time grep-verification at plan
time; both are LOW risk (mechanical, quickly falsifiable) but are flagged rather than silently
assumed as fact.

## Open Questions

1. **Does `rootIpnsName` in invite creation ever refer to a non-vault-root subfolder?**
   - What we know: `vaults.root_ipns_name` stores exactly one root per user (`owner_id` unique FK).
     `share-invite.entity.ts`'s `rootIpnsName`/`rootNodeId` fields are named generically ("root of
     the shared node"), which in sharing terminology typically means "the top of the shared
     subtree," NOT necessarily the user's vault root.
   - What's unclear: Whether the web/SDK client only ever calls `createInvite` with the user's OWN
     vault root (in which case D-01's `vaults` lookup is exactly sufficient), or whether users can
     invite access to an arbitrary owned subfolder (in which case D-01 as scoped would break that
     flow).
   - Recommendation: Planner should grep `apps/web/src` and `packages/sdk`/`packages/sdk-core` for
     the actual `createInvite`/invite-flow call site and confirm what `rootIpnsName` is set to in
     practice, before writing the D-01 task's acceptance criteria. If subfolder invites ARE
     supported, D-01 needs a broader lookup (e.g., confirming the invoking user owns SOME vault
     whose subtree contains this node) — likely still out of scope for this phase (would need the
     deferred `root_node_id` on `vaults`, per D-02's explicit deferral) and should be flagged back to
     CONTEXT.md as a scope note rather than silently narrowed.

2. **Idempotent migration SQL convention for `ADD CONSTRAINT`.**
   - What we know: The DB Evolution Protocol mandates idempotent DDL (`IF NOT EXISTS` for
     tables/indexes, `IF EXISTS` for drops).
   - What's unclear: Postgres `ALTER TABLE ... ADD CONSTRAINT` has no native `IF NOT EXISTS`
     clause; the project's only comparable precedent (`1740300000000-SharesPartialUniqueIndex.ts`)
     handles an INDEX, not a CHECK constraint, so its exact idiom (`CREATE INDEX IF NOT EXISTS`)
     doesn't directly transfer.
   - Recommendation: Planner reads `1740300000000-SharesPartialUniqueIndex.ts` in full before
     writing the D-04 migration task, and either (a) wraps the `ADD CONSTRAINT` in a
     `DO $$ BEGIN ... EXCEPTION WHEN duplicate_object THEN NULL; END $$;` block, or (b) precedes it
     with an `information_schema.table_constraints` existence guard — whichever matches the
     project's established idiom most closely once that file is read.

## Environment Availability

Skipped — this phase has no new external tool/service/runtime dependencies. Postgres, Node, pnpm,
and the existing test runners (Jest for `apps/api`, Vitest for `tests/sdk-e2e`) are all already
verified present and in active use by this same codebase (confirmed via `apps/api/package.json`
scripts and `tests/sdk-e2e/package.json` scripts read during this research session).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Jest (via `ts-jest`) for `apps/api` unit tests; Vitest for `tests/sdk-e2e` integration tests |
| Config file | `apps/api/jest.config.js` (rootDir `src`, testRegex `.*\.spec\.ts$`, coverage thresholds: global 85% lines/statements/functions, 78% branches); `tests/sdk-e2e/vitest.config.ts` |
| Quick run command | `pnpm --filter @cipherbox/api test -- --testPathPattern="share-invite\|shares\.service\|ipns\.service"` (targeted; runs in seconds) |
| Full suite command | `pnpm --filter @cipherbox/api test` (unit, no live services needed — all repos/DataSource mocked); `pnpm --filter sdk-e2e test` (REQUIRES live stack: `docker compose -f docker/docker-compose.yml up -d` + `pnpm --filter @cipherbox/api dev` + `pnpm --filter @cipherbox/api migration:run`, per the header comment convention in `ipns-publish-gate.test.ts`) |

Note: `apps/api`'s Jest coverage thresholds apply globally (85% lines) but have NO per-file
threshold on `share-invite.service.ts` today (confirmed absent from `jest.config.js`'s per-file
override list) — D-09's coverage improvement is a completeness goal, not a CI-gating one, though
adding tests will help the file's contribution to the global threshold.

### Phase Requirements → Test Map

No REQ-IDs are mapped to this phase (todo-driven, `phase_req_ids: null` per ROADMAP). Coverage is
anchored to the 6 Success Criteria (SC#1-SC#6, amended per D-03) and decisions D-01…D-09.

| SC / Decision | Behavior | Test Type | Automated Command | File Exists? |
|------|----------|-----------|-------------------|-------------|
| SC#1 / D-01 | `createInvite` rejects when sharer does not own `rootIpnsName` | unit | `pnpm --filter @cipherbox/api test -- --testPathPattern=share-invite.service` | ❌ Wave 0 (new `describe('createInvite')` block) |
| SC#1 / D-01 | `createInvite` succeeds when sharer owns the root (positive case) | unit | same as above | ❌ Wave 0 |
| SC#2 / D-07 | Re-claim with a write invite over an existing read-only share upgrades `writeDescriptorRef` | unit | same as above | ❌ Wave 0 (new case in existing "idempotent re-claim" describe block, or new sibling describe) |
| SC#2 / D-07 | Re-claim with a lower/equal-generation invite over an existing higher-generation share is a no-op (never downgrades) | unit | same as above | ❌ Wave 0 |
| SC#2 / D-07 | **Backstop (non-inferable):** a write-capable existing share is NEVER downgraded by a subsequent read-only re-claim | unit (property-style: assert `writeDescriptorRef` unchanged across ALL non-widening invite shapes fed into the merge branch) | same as above | ❌ Wave 0 — this is the anomaly-only edge; a single positive-widen test is not sufficient, needs an explicit negative-downgrade assertion |
| SC#3 / D-04 | INSERT/UPDATE violating `claim_count` bounds is rejected at the DB level even if application code is bypassed | integration (migration + raw SQL against a real Postgres, OR a targeted TypeORM repository test hitting a real test DB) | `pnpm --filter @cipherbox/api migration:run` against a scratch DB, then a raw `UPDATE share_invites SET claim_count = -1` expected to throw `23514` (check_violation) | ❌ Wave 0 — apps/api unit tests mock the DataSource, so this constraint can ONLY be proven by an integration test against a real Postgres instance; flag as backstop needing either a dedicated integration spec or manual verification documented in VERIFICATION.md |
| SC#4 / D-05 | Same-seq + different-CID republish → 400 | unit | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipns.service` | ❌ Wave 0 (rewrite Pitfall-4 test) |
| SC#4 / D-05 | Same-seq + SAME-CID republish still succeeds, `sequence_number` unchanged (preserves legitimate idempotent retry) | unit | same as above | ❌ Wave 0 (new positive case alongside the rewritten negative case) |
| SC#4 / D-05 | **Backstop (non-inferable):** TEE lease-renewer path (`renewIpnsRecordEol`) never reaches `upsertIpnsRecord`'s same-seq branch at all | Already proven by code-structure inspection this session (`republish.service.ts:459-478` is a standalone query, never calls `upsertIpnsRecord`) — no NEW test needed, but the planner should add a one-line assertion/comment in `ipns.service.spec.ts` documenting this structural guarantee so a future refactor that accidentally routes TEE renewal through `upsertIpnsRecord` gets caught | — | documented in this RESEARCH.md; no test file gap |
| SC#4 / D-06 | Concurrent first-publish of the same brand-new `ipnsName` → exactly one 200 + one 409 | unit (mocked 23505 catch) AND sdk-e2e (real concurrency against live Postgres) | unit: `pnpm --filter @cipherbox/api test -- --testPathPattern=ipns.service`; e2e: `pnpm --filter sdk-e2e test -- ipns-publish-gate` | ❌ Wave 0 for both — unit test needs a new case mocking `save()` rejecting with `{code: '23505'}`; e2e needs a new "Test 21" case in `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` (the file's existing Tests 16/17/20 cover forward-publish and tombstone races, NOT first-publish races — confirmed by reading the file's own header comment) |
| SC#5 / D-08 | `revokeForItems` issues one DELETE (not find+remove) and returns correct affected counts | unit | `pnpm --filter @cipherbox/api test -- --testPathPattern=shares.service` | ❌ Wave 0 (existing `shares.service.spec.ts` `revokeForItems` tests must be rewritten per the todo's own "Spec impact" note — sequencing `execute` mocks instead of `find`/`remove` mocks) |
| SC#6 / D-09 | `createInvite`, `getInvitesForItem`, `revokeInvite` have unit coverage with realistic UUID/key fixtures | unit | `pnpm --filter @cipherbox/api test -- --testPathPattern=share-invite.service --coverage` | ❌ Wave 0 — 3 new `describe` blocks in `share-invite.service.spec.ts` |
| — | `shares.controller.spec.ts` fixtures use contract-valid UUIDs/keys (CodeRabbit NIT3, folded into D-09) | unit | `pnpm --filter @cipherbox/api test -- --testPathPattern=shares.controller` | ✅ exists, needs fixture edits only (not new test cases) |

### Sampling Rate
- **Per task commit:** `pnpm --filter @cipherbox/api test -- --testPathPattern=<touched-file-basename>`
- **Per wave merge:** `pnpm --filter @cipherbox/api test` (full unit suite, ~seconds, no live services)
- **Phase gate:** Full `apps/api` unit suite green (this is the primary gate — sdk-e2e's
  ipns-publish-gate live-stack case for D-06 is HIGH-value but requires manual `docker compose up`
  + API dev-server bootstrap per the file's own header comment; treat it as a checkpoint:human-verify
  item if the executor cannot start the live stack autonomously) before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `share-invite.service.spec.ts` — add `describe('createInvite')` (D-01 ownership reject +
      accept), `describe('getInvitesForItem')`, `describe('revokeInvite')` (D-09); extend the
      existing "idempotent re-claim" describe block with D-07 widen-merge positive/negative cases
- [ ] `ipns.service.spec.ts` — rewrite the "Pitfall 4" test block (lines 2111-2137) into a
      same-CID-succeeds case + a different-CID-rejects case (D-05); add a first-publish-race 23505→409
      case (D-06)
- [ ] `shares.service.spec.ts` — rewrite `revokeForItems` tests from `find`/`remove` mocks to
      sequenced `execute` mocks per the D-08 todo's own documented "Spec impact" section
- [ ] `shares.controller.spec.ts` — swap placeholder fixtures (`'share-uuid-1'`,
      `'k51qzi5uqu5full'`, `'04sharerkey'`) for contract-valid UUIDs / full IPNS names / full-length
      hex public keys (D-09, CodeRabbit NIT3)
- [ ] `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` — add a first-publish concurrent-race
      case (D-06); this is the ONLY test type that can prove the real Postgres unique-constraint race
      (unit tests mock the repository and cannot exercise genuine DB-level concurrency)
- [ ] A new integration/manual check for D-04's DB CHECK constraint — apps/api's Jest suite mocks
      the DataSource entirely, so the CHECK constraint's actual enforcement cannot be unit-tested;
      recommend either a small integration spec against a real test Postgres (if the project has one
      wired — check for a `docker-compose.test.yml` or similar) or a documented manual verification
      step (`psql` against a migrated dev DB, attempt `UPDATE share_invites SET claim_count = -1`,
      confirm `23514` error) captured in VERIFICATION.md

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | No | Unchanged — JwtAuthGuard already gates all touched endpoints |
| V3 Session Management | No | Unchanged |
| V4 Access Control | **Yes** | D-01 adds server-side ownership verification (ceiling: "authenticated registrant," not cryptographic key-possession — documented limitation, deferred); D-07 preserves the existing write-authority invariant (T-66-E1: presence-derived from the invite, never claimer input) |
| V5 Input Validation | Yes (unchanged) | `class-validator` DTOs already in place (`CreateInviteDto`, `ClaimInviteDto`) — no new DTO fields needed for any of D-01…D-09 |
| V6 Cryptography | No | This phase touches zero crypto/key material — it is pure DB-integrity/authorization logic. Server never sees plaintext keys throughout (unchanged) |
| V9 Communication (N/A) | No | — |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Spoofed invite root (sharer claims ownership of a root they don't own) | Spoofing / Elevation of Privilege | D-01: server-side `vaults` ownership lookup before persist |
| Silent grant-drop on re-claim (functional bug, not exploit, but a data-integrity edge) | Tampering (data-integrity, not confidentiality) | D-07: widen-only merge, never downgrade |
| Claim-count bypass via a future non-transactional code path or admin tool | Tampering | D-04: DB-level CHECK constraint as defense-in-depth beyond the app-layer atomic UPDATE |
| Concurrent-request race producing an inconsistent duplicate row / ambiguous 500 | Denial of Service (poor error UX) / Repudiation (unclear failure mode) | D-06: translate the DB's own unique-constraint enforcement into a clean, idempotent-retriable 409 |
| Same-seq CID equivocation (a validly-signed record repointing the served CID without advancing the sequence) | Tampering | D-05: hard-guard reject when incoming CID diverges from stored `latestCid` at the same sequence — proven safe post-Phase-67 because the TEE lease-renewer structurally cannot produce this combination |

## Sources

### Primary (HIGH confidence — direct codebase inspection this session)
- `apps/api/src/shares/share-invite.service.ts` (full file read) — confirms D-01/D-02/D-07 gaps as
  described, confirms existing transaction/branch structure
- `apps/api/src/shares/shares.service.ts` (full file read) — confirms D-08 gap, confirms the
  established 23505-detection idiom at `createShare` (lines 75-88) to mirror for D-06
- `apps/api/src/ipns/ipns.service.ts` (full file read) — confirms D-05/D-06 gaps precisely at the
  cited line numbers
- `apps/api/src/vault/entities/vault.entity.ts`, `apps/api/src/shares/entities/share-invite.entity.ts`
  (full files read) — confirm D-01's FK/unique-index basis and D-04's `@Check` target shape
- `apps/tee-worker/src/services/ipns-signer.ts`, `apps/tee-worker/src/routes/republish.ts`,
  `apps/api/src/republish/republish.service.ts` (lines 180-210, 455-490 read) — confirm D-05's
  TEE-contract evidence is current, not stale; confirm the EOL-renewal path never touches
  `upsertIpnsRecord`
- `packages/sdk-core/src/cas.ts` (lines 70-110 read) — confirms client always bumps sequence on
  content change (D-05 evidence)
- `apps/api/src/shares/share-invite.service.spec.ts`, `apps/api/src/shares/shares.controller.spec.ts`
  (full files read) — confirm D-09's exact coverage gap (zero `createInvite`/`getInvitesForItem`/
  `revokeInvite` tests) and the exact placeholder-fixture shapes needing hardening
- `apps/api/src/ipns/ipns.service.spec.ts` (lines 2080-2150 read) — confirms the exact Pitfall-4
  test assertions that must be rewritten for D-05
- `apps/api/jest.config.js` (read) — confirms test framework, coverage thresholds, and the absence
  of a per-file threshold on `share-invite.service.ts`
- `docs/DATABASE_EVOLUTION_PROTOCOL.md` (sections 1-5 read) — confirms migration idempotency and
  timestamp-ordering rules governing D-04
- `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts` (full file read) — confirms the
  greenfield-`down()`-throws precedent to mirror for the new D-04 migration
- All 8 source todo files under `.planning/todos/pending/2026-06-30-*.md` (read in full) — each
  decision's original CodeRabbit-flagged problem statement and proposed fix, cross-checked against
  CONTEXT.md's locked decisions (no drift found)
- Local `node_modules` inspection confirming `typeorm@0.3.28`'s `Check` decorator export
  `[VERIFIED: local node_modules inspection]`

### Secondary (MEDIUM confidence)
- `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` (header comment + structure, lines 1-50 read)
  — confirms existing e2e coverage is forward-publish/tombstone-race only, NOT first-publish-race,
  confirming D-06's e2e gap
- `tests/sdk-e2e/src/suites/invite-link.test.ts` (existence + line count only) — likely landing spot
  for D-01/D-07 e2e cases if the planner chooses to add any; not read in full this session

### Tertiary (LOW confidence)
- None — every claim in this research was verified against the actual codebase this session; no
  claims rest on WebSearch or training-data-only knowledge (this phase's domain is 100% internal
  codebase state, not an external library/framework question)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — zero new dependencies, all existing library usage confirmed via direct
  `node_modules` inspection and existing call-site greps
- Architecture: HIGH — every decision's target code was read in full this session; all 9 gaps
  confirmed to exist exactly as CONTEXT.md describes, no drift
- Pitfalls: HIGH for D-04/D-05/D-06/D-08 (mechanical, low ambiguity); MEDIUM for D-01/D-07 (the
  ownership-scope and merge-sequencing questions are correctly resolved by CONTEXT.md's decisions,
  but Open Question 1 flags a real residual ambiguity about invite semantics that should be
  confirmed with a one-grep check at plan time, not assumed)

**Research date:** 2026-07-09
**Valid until:** 2026-08-08 (30 days — stable internal-codebase research, no fast-moving external
dependency)

## RESEARCH COMPLETE

**Phase:** 71 - share-invite-security-and-ipns-data-integrity-api
**Confidence:** HIGH

### Key Findings
- All 9 locked decisions (D-01…D-09) verified against live code: every diagnosed gap exists exactly
  as CONTEXT.md describes (no drift since context-gathering).
- D-05's TEE-contract evidence is CURRENT, not stale: `renewIpnsRecord` structurally cannot repoint
  a CID (no CID parameter), and the API's separate EOL-only renewal path
  (`republish.service.ts:459`) never calls `upsertIpnsRecord` — so the same-seq guard cannot
  conflict with any legitimate TEE flow.
- D-07's merge must be sequenced AFTER the existing atomic claim UPDATE (already the case) but
  BEFORE return, inside the same transaction — no reordering needed, only new widen-gated field
  writes added to the existing existing-share branch.
- D-06 should follow the codebase's OWN established 23505-detection idiom (`shares.service.ts:81-85`,
  `vault.service.ts:103`) rather than the todo's suggested `QueryFailedError` instanceof check, for
  stylistic consistency.
- D-04's DB CHECK constraint cannot be unit-tested (Jest mocks the DataSource entirely) — flagged as
  a backstop requiring either a real-Postgres integration spec or a documented manual verification
  step.
- One real open question (not a blocker, but must be resolved at plan time): does `createInvite`'s
  `rootIpnsName` ever refer to a subfolder the user owns but doesn't correspond 1:1 to their single
  `vaults` row? A one-grep check of the actual web/SDK invite-creation call site resolves this before
  D-01's task is finalized.

### File Created
`/Users/myankelev/Code/random/cipher-box/.planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-RESEARCH.md`

### Confidence Assessment
| Area | Level | Reason |
|------|-------|--------|
| Standard Stack | HIGH | Zero new packages; all library usage verified in installed `node_modules` |
| Architecture | HIGH | Every touched file read in full; all 9 gaps confirmed present exactly as diagnosed |
| Pitfalls | HIGH/MEDIUM | Mechanical decisions (D-04/05/06/08) HIGH; D-01/D-07 MEDIUM pending the one open-question grep |

### Open Questions
1. Does `createInvite`'s `rootIpnsName` ever refer to an owned subfolder rather than always the
   caller's single vault root? (Recommend: grep `apps/web/src`/`packages/sdk` invite-creation call
   sites at plan time — low-cost, resolves before D-01's task is written.)
2. What is this project's established idiom for idempotent `ALTER TABLE ... ADD CONSTRAINT` in
   migrations? (Recommend: read `1740300000000-SharesPartialUniqueIndex.ts` in full at plan time —
   not read this session beyond its existence being noted.)

### Ready for Planning
Research complete. Planner can now create PLAN.md files for Phase 71.
