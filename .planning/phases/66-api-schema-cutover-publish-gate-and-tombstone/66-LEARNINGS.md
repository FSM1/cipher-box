---
phase: 66
phase_name: "api-schema-cutover-publish-gate-and-tombstone"
project: "CipherBox"
generated: "2026-06-30"
counts:
  decisions: 17
  lessons: 13
  patterns: 15
  surprises: 7
missing_artifacts:
  - "UAT.md"
---

# Phase 66 Learnings: API schema cutover, IPNS publish gate, and tombstone

## Decisions

### Publish is a single atomic conditional UPDATE (CAS), no in-memory gate

Replaced the non-atomic `findOne -> in-memory-gate -> save` publish path with one `createQueryBuilder().update(IpnsRecord)` whose WHERE fuses four predicates: `ipns_name = :ipnsName AND sequence_number = :expected AND generation <= CAST(:incoming AS bigint) AND tombstoned_at IS NULL`. `updateResult.affected === 0` drives a single follow-up read that disambiguates 404 vs 409 vs 410.

**Rationale:** Removes the TOCTOU window and serializes concurrent publishes at the DB row — exactly one 200 + one 409 with zero lost updates (TEE-04) — while folding the forward-only generation gate (TEE-07) and tombstone gate (D-03) into the same write.
**Source:** 66-02-PLAN.md, 66-VERIFICATION.md

---

### First publish stays an INSERT, not routed through the CAS

First publish (no existing row) remains a `create() + save` INSERT with `sequence_number = 1`, `generation = 0`; the conditional UPDATE applies only when a row already exists.

**Rationale:** A conditional UPDATE would affect 0 rows on first publish (Pitfall 3). The existing strict embedded-`seq == 1` gate still guards the first publish.
**Source:** 66-02-PLAN.md

---

### Drop the public_key column; recover the pubkey solely via publicKeyFromIpnsName

Removed the nullable `public_key` (bytea) column from the IPNS record entity; `publicKeyFromIpnsName(ipnsName)` in `ipns-record.codec.ts` is the only recovery path, and the `cached.publicKey` precedence branch in `parseCachedRecord` was deleted.

**Rationale:** The nullable column was the footgun behind two Phase-60 regressions and was null for shared rows — a high-severity elevation surface (T-66-EP1). Deriving from the k51 name is always available (D-03 / DATA-03) and removes the stored-column trust dependency.
**Source:** 66-01-PLAN.md, 66-05-SUMMARY.md, 66-SECURITY.md

---

### Rename FolderIpns to IpnsRecord / ipns_records and add tombstone + generation columns

Renamed class `FolderIpns` to `IpnsRecord` over table `ipns_records` (keeping `@Unique(['ipnsName'])`) and added `tombstonedAt` (timestamptz null) and `generation` (bigint default 0, typed as string) columns.

**Rationale:** Establishes the minimal type foundation for the tombstone state machine and forward-only generation gate (D-02/D-03/D-10); `generation` typed as string follows the TypeORM bigint-as-string convention mirroring `sequenceNumber`.
**Source:** 66-01-PLAN.md

---

### Tombstone: owner-scoped 410 at publish and resolve, unconditional unenroll

`tombstoneRecord(userId, ipnsName)` sets `tombstoned_at = NOW()` with `WHERE tombstoned_at IS NULL AND user_id = :userId`, throws 410 `IPNS_TOMBSTONED` on both the publish disambiguation path and the resolve guard, blocks EOL renewal via the same `tombstoned_at IS NULL` CAS predicate, and always calls `republishService.unenrollIpns` afterward.

**Rationale:** Makes a tombstoned name terminally dead across every write/renew/read entry point (resolves open question 3 with `user_id = req.user.id` authz, T-66-A1) and stops the republisher resurrecting it; the unconditional unenroll is idempotent and avoids orphaned republish-schedule rows.
**Source:** 66-02-PLAN.md, 66-VERIFICATION.md

---

### parseCachedRecord returns a 3-way discriminated union with a SeqFloor discriminant

`parseCachedRecord` now returns `IpnsRecordFields | SeqFloor | null`; the null-signedRecord (shared-folder) branch returns `{ seqFloor: cached.sequenceNumber }` instead of `null`, and `resolveRecord` gates the network record — serve iff `networkSeq >= seqFloor`, else fail closed to 404.

**Rationale:** Closes the gap where a null-signedRecord shared row could serve an ungated network CID (TEE-05 / T-66-I1). A `SeqFloor` interface (not a string discriminant) gives clean TS narrowing via `'seqFloor' in r`.
**Source:** 66-02-PLAN.md, 66-VERIFICATION.md

---

### Use CAST(:incoming AS bigint), not the ::bigint shorthand

The atomic CAS WHERE casts the generation parameter with `CAST(:incoming AS bigint)` rather than `:incoming::bigint`.

**Rationale:** The `::name` cast shorthand can be misread by the TypeORM parameter parser as a named parameter.
**Source:** 66-02-SUMMARY.md

---

### Backward-compat defaults for an omitted expected sequence / generation

When `expectedSequenceNumber` or `dto.generation` is undefined (legacy unconditional publish), the effective values default to the stored row's `sequenceNumber` / `generation`.

**Rationale:** A SQL NULL bound into a CAS WHERE makes the predicate always false (0 rows affected), which would wrongly fail every legacy publish. The stored-value fallback keeps the atomic CAS valid for callers that omit the conditional fields.
**Source:** 66-02-SUMMARY.md

---

### Reshape shares to the descriptor-ref grant model; delete share_keys

Deleted the `ShareKey` entity, `AddShareKeysDto`, `ShareKeyResponseDto`, `UpdatePermissionDto`, and `PendingRotationResponseDto`. `Share` now carries `readDescriptorRef` / `writeDescriptorRef` (nullable) / `rootNodeId` / `rootIpnsName` / `rootGeneration`; `ShareInvite` is slimmed to root identity + a single ephemeral-wrapped readKey.

**Rationale:** Moves to the node/v3 descriptor-ref grant model where the wrapped readKey is the only DB residue (DATA-01/02/04, D-05).
**Source:** 66-03-PLAN.md, 66-04-PLAN.md

---

### writeDescriptorRef presence is the sole write-vs-read signal

Dropped the `permission` column/enum; the presence (vs null) of `writeDescriptorRef` alone distinguishes a write grant from a read grant.

**Rationale:** D-09 — no separate permission enum is needed when the descriptor ref's existence encodes the capability.
**Source:** 66-03-SUMMARY.md, 66-04-PLAN.md

---

### Claim-time write authority is presence-derived from the invite, not the claimer DTO

Write authority is computed from `invite.writeDescriptorRef !== null` (the server-trusted invite row), never from the claimer-supplied `dto.writeDescriptorRef`.

**Rationale:** Otherwise a recipient of a read-only invite could mint a write grant by supplying their own ref (T-66-E1, high elevation-of-privilege). This was found OPEN by the first security audit and remediated at ship time.
**Source:** 66-SECURITY.md, 66-04-PLAN.md

---

### claimInvite copies root identity from the invite row and mints exactly one Share

On claim, `rootNodeId` / `rootIpnsName` / `rootGeneration` come from the looked-up invite row; only the descriptor refs come from the claimer DTO. Self-claim is rejected. The ShareKey creation and childKeys fan-out were removed — exactly one descriptor-ref Share is minted.

**Rationale:** Anchoring scope to server-side invite data prevents a claimer minting a grant they were not invited to (T-66-S1 spoofing); D-05 replaces the per-key-type fan-out with one re-wrapped readKey grant.
**Source:** 66-04-SUMMARY.md, 66-04-PLAN.md

---

### Revoke is a hard DELETE (no revoked_at); plain UNIQUE(sharer, recipient, rootNode)

`revokeShare`/`revokeForItems` hard-delete matched rows; there is no `revoked_at` column. Uniqueness is a plain `@Unique(['sharerId','recipientId','rootNodeId'])`.

**Rationale:** D-11 — a soft-revoked row is consumer-less residue retaining stale ECIES-wrapped key material (T-66-I2 info disclosure). Hard delete leaves nothing decryptable behind, so no `revoked_at` discriminator is needed in the unique key.
**Source:** 66-04-SUMMARY.md, 66-03-PLAN.md, 66-SECURITY.md

---

### Drop-recreate migration with a non-reversible down()

A single forward migration (`ApiSchemaCutover1750000000000`) drop-recreates `shares` / `share_invites` / `folder_ipns` rather than altering columns; `down()` throws.

**Rationale:** D-01 greenfield waiver — staging is wiped on each deploy and there is no production data, so reversibility is deliberately waived (AR-66-2); drop-recreate wins on schema consistency and simplicity.
**Source:** 66-05-SUMMARY.md, 66-SECURITY.md

---

### The phase behavioral gate is sdk-e2e, not the api jest suite

Five shares/invite jest specs were deleted (they asserted share_keys / permission / soft-revoke / childKeys flows that no longer exist); descriptor-ref CRUD + shared-delete revoke is proven by the sdk-e2e suite in 66-09.

**Rationale:** D-08 — the real client to API round-trip is the authoritative proof for this cutover; unit specs asserting the old model are noise.
**Source:** 66-04-PLAN.md

---

### Optional generation param forwarded on every CAS retry; durable client floor deferred

Added an optional `generation?: string` to `createAndPublishIpnsRecord` / `publishWithCas`, threaded through every attempt including post-409 retries. No IndexedDB/journal client-side generation high-water was added.

**Rationale:** Optional so existing callers compile unchanged and omitting it preserves behavior (server treats absent generation as a no-op gate). The durable client floor is ROT-07 / Phase 68; this phase only needs the server gate exercisable through the real client path (D-08).
**Source:** 66-07-SUMMARY.md

---

### Phase-68 deferrals shipped as loud throw-stubs

Web `share.service.ts` (9), `invite.service.ts` (2), and a `ShareDialog` effect were stubbed with `throw new Error('deferred to Phase 68 ...')`, keeping exported signatures so component callers still typecheck; surviving-but-unused api-client imports were removed for `noUnusedLocals`.

**Rationale:** Keeps the monorepo `tsc -b` gate green without implementing Phase-68 rotation/grant behavior; the app is intentionally non-runnable mid-milestone and fails loudly rather than silently (matches the 62-08/63-65 compile-gate-stub precedent; Phase 68 wires the real path before any web ship, T-66-T7).
**Source:** 66-08-SUMMARY.md, 66-VERIFICATION.md

---

## Lessons

### A fresh worktree needs pnpm install + @cipherbox/crypto built before the API build

`nest build` failed with `Cannot find module @cipherbox/crypto` (TS2307) in `src/ipns/` — `pnpm install` brought the package source but not its built `dist/`, so the api tsconfig resolved to a missing `dist/index.d.ts`. Fix: run `pnpm install` (also needed for git hooks) then `pnpm --filter @cipherbox/crypto build` before the api build.

**Context:** Recurred across 66-01 and 66-04 worktree pre-build checks; a build-artifact-only setup step, no code change.
**Source:** 66-01-SUMMARY.md, 66-04-SUMMARY.md

---

### TypeScript can't narrow a `let` across an async null-fill assignment

Reading `incomingParsed` after `if (x === null) { x = await ... }` still tripped TS18047 (possibly null). Fixed by assigning to a non-null `const` (`resolvedParsed`) after the null-fill block.

**Context:** Building the atomic CAS publish path (66-02 Task 1).
**Source:** 66-02-SUMMARY.md

---

### A TypeORM .set() built with a dynamic raw-SQL callback object resists typing

A dynamically-built SET object that includes a callback for the `sequence_number` raw SQL literal caused TS2352/TS2559 against the `Parameters<ReturnType<...>>` cast; resolved with an `as any` cast + an eslint-disable, since the runtime QueryBuilder shape is correct.

**Context:** Building the atomic conditional UPDATE (66-02 Task 1).
**Source:** 66-02-SUMMARY.md

---

### Schema/type-layer plans intentionally leave the build red

The 66-03 type reshape removes columns and the ShareKey entity still referenced by `shares.service`/`share-invite.service`, so the api build does not pass until the dependent logic plan (66-04) wires the services. Verification for such plans is structural (grep + file existence), not a green build; the build-green gate is deferred to the dependent plan.

**Context:** 66-02's ipns build was clean but reported ~102 pre-existing errors, all in `src/shares` (sibling 66-04 scope).
**Source:** 66-03-SUMMARY.md, 66-05-SUMMARY.md

---

### Cross-wave cleanup misses surface only when the dependent step runs

`pnpm openapi:generate` failed with TS2307 on `../src/shares/entities/share-key.entity` because `apps/api/scripts/generate-openapi.ts` still imported `ShareKey` and registered a mock repository even though the entity was deleted in an earlier wave. Fix removed the import, the const, and its providers-array entry.

**Context:** Found in 66-06 (api-client regeneration) — a Wave-1 deletion's stale reference only failed when the generation step ran.
**Source:** 66-06-SUMMARY.md

---

### DTO reshaping that drops legacy fields forces broader stubbing than the deleted endpoints

`SentShareResponseDto`/`ReceivedShareResponseDto`/`InviteResponseDto` dropped `itemType`/`ipnsName`/`itemName`/`encryptedKey`/`permission`/etc., so functions beyond the six deleted endpoints (`fetchReceivedShares`, `fetchSentShares`, `createShare`, `claimInvite`, `fetchInvitesForItem`, the ShareDialog effect) also had to be stubbed — accessing a removed field is a compile error.

**Context:** Making `@cipherbox/web` typecheck against the regenerated client (66-08).
**Source:** 66-08-SUMMARY.md

---

### A duplicate migrations row makes TypeORM falsely report "no pending migrations"

A duplicate `WidenShareKeyType1743100000000` row made TypeORM 0.3.28 count 22 DB rows vs 22 code migrations and conclude all were applied, so `ApiSchemaCutover1750000000000` silently never ran despite being absent from the table.

**Context:** Discovered when `migration:run` reported "No migrations are pending" but the schema lacked the new columns (66-09 Task 1).
**Source:** 66-09-SUMMARY.md

---

### Build and typecheck pass without the live migration applied

Types come from the entities, not the live DB, so build/typecheck stay green even when the schema migration has not run. The schema push must be sequenced as an explicit [BLOCKING] step after schema-file edits and before the e2e proof.

**Context:** Documented as the rationale for the [BLOCKING] `migration:run` in plan 66-09.
**Source:** 66-09-PLAN.md

---

### No public API path creates null-signedRecord ipns_records rows

The shared-folder seqFloor scenario (stored `sequenceNumber` but null `signed_record`) cannot be produced through the public API, so the test had to seed it via direct DB writes. (Post-phase, this gate's pure decision logic was migrated from the e2e seed to unit tests.)

**Context:** Setting up Test 15 (TEE-05 resolve case-split).
**Source:** 66-09-SUMMARY.md

---

### The cutover deleted the shares unit suite, including security-critical claim coverage

The schema cutover removed 5 shares specs; only the claim path was restored during the ship review (9 tests in `share-invite.service.spec.ts`). The broader `SharesService` grant/revoke/listing coverage was left as a deferred todo — best written against the Phase-68 finalized flow rather than the mid-cutover model.

**Context:** Surfaced by the retroactive Nyquist validation audit.
**Source:** 66-VALIDATION.md

---

### The first security audit found a high-severity EoP open; SECURED only after a ship-time remediation

The first auditor pass closed 16/17 threats but left T-66-E1 OPEN (high): a read-only invite could yield a write grant. It was remediated during the ship review (presence-derived write authority), moving the register to 17/17 closed.

**Context:** The threat register was authored at plan time and verified in verify-mitigations mode; SECURED status required a ship-time commit.
**Source:** 66-SECURITY.md

---

### An orphan DTO survived the cutover

`apps/api/src/shares/dto/update-encrypted-key.dto.ts` remains in the tree but is referenced by no controller or service.

**Context:** Found in the verification anti-pattern scan; classified non-blocking since no route or service calls it.
**Source:** 66-VERIFICATION.md

---

### Test 15 was narrowed to an unparseable-signedRecord case

Test 15 Part B exercises garbage `signed_record` bytes (parseCachedRecord throws -> null, no network fallback) rather than the exact CID-mismatch (404) case the plan specified; the seqFloor below/at-floor split (Part A) is fully tested.

**Context:** Documented as a Known Stub deviation from the plan's behavior spec.
**Source:** 66-09-SUMMARY.md

---

## Patterns

### TypeORM atomic conditional UPDATE as CAS

Express a compare-and-swap as a single `createQueryBuilder().update(Entity).set({...}).where(<fused predicates>)` (including a raw SQL literal such as `sequence_number + 1`), then branch on `result.affected`: `=== 1` success, `=== 0` do exactly one follow-up read to disambiguate the failure reason. No in-memory pre-check.

**When to use:** When multiple clients race to publish/mutate the same row and you need exactly-one-winner semantics with no lost updates, folding several guards (sequence CAS, forward-only generation, tombstone null-check) into one statement.
**Source:** 66-02-SUMMARY.md, 66-09-SUMMARY.md, 66-VERIFICATION.md

---

### Discriminated-union cache record with an explicit-absence floor

Model a parsed cached record as `Fields | { seqFloor } | null`; the partially-populated case carries an explicit `{ seqFloor }` discriminant. Callers narrow via `'seqFloor' in r` and apply a forward-only floor comparison, failing closed on a below-floor or mismatched record.

**When to use:** When a cached/derived row may legitimately lack the full signed payload but must still gate downstream serving safely instead of silently serving ungated data.
**Source:** 66-02-SUMMARY.md, 66-VERIFICATION.md

---

### Stored-value fallback for optional CAS parameters

Compute `effective = providedValue ?? storedRow.value` (per field) so an omitted optional parameter does not bind SQL NULL into a WHERE predicate (always false), keeping the atomic CAS valid for legacy unconditional callers.

**When to use:** When adding a conditional UPDATE behind an API that still has callers who omit the conditional fields.
**Source:** 66-02-SUMMARY.md

---

### Typed 410 via HttpException(GONE) as an OpenAPI marker

Throw `HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE)` and add `@ApiResponse({ status: 410, schema })` on both the publish and resolve handlers so the typed marker body flows through `api:generate` into the SDK.

**When to use:** When a terminal state (e.g. tombstone) must be a distinct, machine-readable status separate from a transient 409 conflict.
**Source:** 66-02-SUMMARY.md

---

### Derivable-value recovery instead of a nullable persisted column

Drop a nullable persisted value that has become a correctness footgun and recover it deterministically on demand (here: the Ed25519 key from the k51 IPNS name via `publicKeyFromIpnsName`) as the single recovery path.

**When to use:** When a derivable value is stored nullable and the nullable column causes correctness/security bugs (e.g. null for shared rows).
**Source:** 66-01-SUMMARY.md

---

### Descriptor-ref grant with capability-by-presence

Persist a grant as `readDescriptorRef` (required) + optional `writeDescriptorRef` (presence encodes write capability) + root identity, with a plain `UNIQUE(sharer, recipient, root)` and hard-delete on revoke — no permission enum, no `revoked_at`, no per-key-type fan-out rows.

**When to use:** When replacing per-key/per-permission grant rows with a single zero-knowledge wrapped-key residue where revocation is a hard delete.
**Source:** 66-03-SUMMARY.md, 66-04-SUMMARY.md, 66-SECURITY.md

---

### Presence-derived authority from a server-trusted record

Derive a capability (e.g. write access) from a field on the server-side invite/grant the user cannot forge — never from the request DTO the claimer supplies.

**When to use:** In claim/redeem/grant-minting flows where the caller could otherwise self-escalate by populating a privilege field in their request body.
**Source:** 66-SECURITY.md

---

### Atomic single-claim invite mint

Inside the atomic-claim transaction, after the single-claim UPDATE succeeds, mint exactly one `Share` via `manager.create(Share, {...})` copying the root identity from the invite row.

**When to use:** When an invite must produce exactly one grant and the operation must be race-safe against concurrent claims.
**Source:** 66-04-PLAN.md

---

### Drop-recreate TypeORM migration with greenfield waiver

Use `MigrationInterface` with raw `queryRunner.query` DDL: `DROP TABLE ... CASCADE` then `CREATE TABLE` in dependency order, issue FK and index statements separately after each CREATE, and make `down()` throw when there is no rollback target.

**When to use:** Greenfield/staging-only schema cutovers where reversibility is waived and column sets are authored directly from reshaped entities.
**Source:** 66-05-SUMMARY.md

---

### Regenerated-client staging gate

Run `pnpm api:generate` inside the worktree, stage `openapi.json` + `src/generated/` + `src/models/` together, and rely on `scripts/check-api-client.sh` (pre-commit) to require the regenerated files staged alongside API changes.

**When to use:** Any API surface change in this monorepo, to stop a stale generated client masking a contract change (T-66-T6) and to keep the regen from leaking into the orchestrator tree.
**Source:** 66-06-PLAN.md, 66-SECURITY.md

---

### compile-gate-stub (deferral throw)

Replace a not-yet-implemented function body with `throw new Error('deferred to Phase N ...')` while keeping the exported signature so downstream consumers still typecheck; delete dead imports of removed dependencies to satisfy `noUnusedLocals`.

**When to use:** After a breaking api-client/schema regeneration when the real consumer rework is deferred to a later phase but the monorepo typecheck gate must stay green and fail loudly at runtime.
**Source:** 66-08-SUMMARY.md, 66-VERIFICATION.md

---

### Optional-param forwarding

Add a new optional parameter and thread it through every call layer (including retry attempts), defaulting to prior behavior when the param is absent.

**When to use:** Extending a primitive to support a new server-side feature (e.g. a generation gate) without breaking or recompiling existing callers.
**Source:** 66-07-SUMMARY.md

---

### Promise.allSettled concurrent-CAS race forcing (e2e)

Capture a single `expectedSequenceNumber` and fire two concurrent publishes with it via `Promise.allSettled`, asserting exactly one fulfilled (200) and one rejected (409) with zero lost updates.

**When to use:** Deterministically forcing a concurrent-publish race through the real client to API path to prove atomic CAS behavior.
**Source:** 66-09-SUMMARY.md

---

### psql/execSync e2e precondition seeding

Seed DB state that no public API can create (e.g. null-signedRecord seqFloor rows) using `execSync`-driven psql against temp SQL files. Reserve this for genuine internal/edge-case preconditions — pure decision logic is better moved to unit tests (as the seqFloor gate later was).

**When to use:** Live-stack e2e tests that need internal rows as preconditions that the API itself will not produce.
**Source:** 66-09-SUMMARY.md

---

### Caller-owns-key zeroization contract

The publish primitive must not zero the caller-supplied `ipnsPrivateKey`; key lifecycle and zeroization are owned by the caller.

**When to use:** Designing crypto primitives where the key material is provided and managed by the caller rather than the primitive (zero only at the terminal owner).
**Source:** 66-07-PLAN.md

---

## Surprises

### A class-name substring grep also matched semantically-distinct method names

The acceptance criterion grepped for `FolderIpns` across non-spec source, which also matched `getFolderIpns`/`getAllFolderIpns` and `upsertFolderIpns`/`syncFolderIpnsSequence` — all had to be renamed (`getIpnsRecord`, `getAllIpnsRecords`, ...) along with their spec mocks and `describe()` blocks.

**Impact:** Expanded a mechanical class/path rename into a public-API method rename touching `ipns.service.spec.ts`, `ipns.integration.spec.ts`, and `ipns.security.spec.ts`.
**Source:** 66-01-SUMMARY.md

---

### A SQL NULL comparison silently breaks a CAS WHERE clause

When `expectedSequenceNumber` was undefined (legacy unconditional publish), binding NULL into `sequence_number = :expected` made the predicate always false, so the atomic UPDATE affected 0 rows and wrongly failed every such publish.

**Impact:** Required the `effectiveExpected = expectedSequenceNumber ?? existing.sequenceNumber` fallback (and the same for generation) to preserve backward-compatible publishes.
**Source:** 66-02-SUMMARY.md

---

### Zero SQL foreign keys reference folder_ipns

Research found no table holds a SQL FK to `folder_ipns`; `ipns_republish_schedule`, `vaults`, and `shares` reference the IPNS name only as a plain varchar column.

**Impact:** The rename-by-drop-recreate to `ipns_records` required no dependent-FK drops and left those tables untouched, simplifying the migration.
**Source:** 66-05-PLAN.md

---

### One api:generate run changed 109 files in a single commit

The single `api:generate` run for plan 66-06 produced 109 changed files in one commit, including three new models (`tombstoneIpnsDto`, `ipnsControllerPublishRecord410`, `ipnsControllerResolveRecord410`).

**Impact:** A large generated diff lands as one commit; reviewers must trust the generator and the `check-api-client.sh` gate rather than reviewing each file.
**Source:** 66-06-SUMMARY.md

---

### migration:run still reported a no-op even after deleting the duplicate row

After removing the duplicate migrations row, `migration:run` continued to report no pending migrations (suspected TypeORM caching or a separate matching quirk).

**Impact:** Forced applying the cutover DDL directly via psql in a `BEGIN ... COMMIT` transaction and manually inserting `INSERT INTO migrations VALUES (1750000000000, 'ApiSchemaCutover1750000000000')` to cut the live schema over and unblock the sdk-e2e proof.
**Source:** 66-09-SUMMARY.md

---

### The generation field was already present in the regenerated client DTOs

`PublishIpnsEntryDto` and `PublishIpnsDto` already carried the `generation` field from prior plans in the phase, so the sdk-core change required no schema change of its own.

**Impact:** The client-side change was purely additive param-forwarding — no new endpoints, auth paths, or schema changes.
**Source:** 66-07-SUMMARY.md

---

### A stale-expected renewal returns 409, not 410, and preserves latestCid

A renewal at a stale expected sequence yields a 409 (conflict) rather than a 410 (tombstone), and the latest CID stays intact (sdk-e2e Test 17).

**Impact:** Confirms the publish gate cleanly separates concurrent-conflict semantics from terminal-tombstone semantics, so a benign stale renewal never destroys or masquerades as a dead record.
**Source:** 66-VERIFICATION.md
