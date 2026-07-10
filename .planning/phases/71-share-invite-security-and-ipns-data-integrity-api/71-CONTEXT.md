# Phase 71: Share-Invite Security and IPNS Data-Integrity (API) - Context

**Gathered:** 2026-07-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Server-side (`apps/api`) authorization and DB-integrity hardening for share-invites and IPNS records. The phase closes seven diagnosed API edges plus a test-coverage gap; it does **not** change client crypto, the read/write chains, or the TEE contract.

Fixed scope = ROADMAP.md Phase 71 six Success Criteria:

1. `createInvite` rejects when the caller does not own the root (server-side ownership lookup, not verbatim DTO copy).
2. `claimInvite` against an already-existing share applies the later invite's grant instead of silently dropping it.
3. DB-level defense for `share_invites.claim_count` bounds and root uniqueness.
4. First-publish INSERT race → clean 409; same-seq CID equivocation decided (D-09).
5. `bulkRevoke` (the invite+share bulk path) issues a single DELETE.
6. `ShareInviteService` gains real unit coverage.

**Ownership ceiling (applies across SC#1/SC#3):** No store proves *key possession* — `vaults.root_ipns_name` was itself client-asserted at `/vault/init`, and the whole model bottoms out at "first authenticated user to claim the globally-`@Unique` ipnsName wins." This phase raises ownership from *nothing* to *"the authenticated user who registered this root."* A cryptographic key-possession challenge is explicitly out of scope (own phase).

</domain>

<decisions>
## Implementation Decisions

**Decision index** — full detail in the sections below; this bullet list is the machine-readable decision record:

- **D-01:** Root-ownership source (SC#1, AMENDED) — verify the sharer registered the shared node via `ipns_records` (ipnsName + userId), NOT `vaults`; applied to `createInvite` + `createShare`.
- **D-02:** rootNodeId validation (SC#1) — validate `shareRootIpnsName` ownership only; `rootNodeId` stays client-asserted (documented gap).
- **D-03:** SC#3 root-uniqueness index — SKIP (already covered by `vaults.owner_id` uniqueness); documented drop.
- **D-04:** `claim_count` CHECK (SC#3, AMENDED) — fold the CHECK into the greenfield cutover `CREATE TABLE` in place + entity `@Check`; no separate forward migration.
- **D-05:** Same-seq CID equivocation (SC#4) — HARD-GUARD 400 when incoming CID differs at equal sequence; same-CID idempotent retries still pass; rewrite the Pitfall-4 test.
- **D-06:** First-publish INSERT race (SC#4) — translate the `23505` unique-violation to a 409; unit + sdk-e2e concurrent-race backstop.
- **D-07:** Re-claim later-grant (SC#2) — widen-only merge (read→write), never downgrade; preserve invariant T-66-E1.
- **D-08:** Bulk-revoke (SC#5) — `revokeForItems` issues a single `createQueryBuilder().delete()` instead of find+remove.
- **D-09:** ShareInviteService coverage (SC#6) — real unit tests for `createInvite`/`getInvitesForItem`/`revokeInvite` + contract-valid controller fixtures.
- **D-10:** Full share-plane rename (NEW) — purge "descriptor" end-to-end (columns + TS fields/methods/types + Rust + api-client); greenfield edit-in-place; surgical `rootIpnsName→shareRootIpnsName` (share-domain only); `root_generation` untouched.

### D-01 — Root-ownership source (SC#1) — AMENDED 2026-07-09

**Verify the sharer registered the shared node by looking up `ipns_records`, keyed by the shared node's own IPNS name:**

```sql
SELECT 1 FROM ipns_records WHERE ipns_name = :dto.rootIpnsName AND user_id = :req.user.id
```

Reject with `ForbiddenException` (403) if no row. Apply to **BOTH** `createInvite` (`share-invite.service.ts:40`) and `createShare` (`shares.service.ts:69`) — identical verbatim-DTO-copy vulnerability.

**Why this REVERSES the original vaults-based decision (Flow C):** The original D-01 (query `vaults`) rested on a **false assumption** — that `dto.rootIpnsName` is the caller's *vault root*. Verified false against live code (2026-07-09):

- Sharing is a **children-only** action: the web share/invite flow is a context-menu action on a listing item (`ContextMenu.tsx:366`), and `dto.rootIpnsName = params.item.ipnsName` (`invite.service.ts:172`, `ShareDialog.tsx:216`) is always a **child** node's IPNS name — never the vault root.
- `vaults` holds exactly **one** row per user, the top-level vault root only (inserted once at `/vault/init`; children publish with `isRoot:false` and never touch `vaults`).
- Therefore `vaults WHERE root_ipns_name = dto.rootIpnsName` **never matches a real (child) share**: the literal whitelist would 403 every share (regressing shipped subfolder/file sharing), and a "conflict-only" variant would be a **no-op** that protects nothing. `vaults` is structurally incapable of verifying child-share ownership.

**The only server-side child-ownership signal is `ipns_records.user_id`** — the creator marker set at first publish (`ipns.service.ts:437`, `userId, ipnsName, isRoot:false`). This is the former **Flow A**, originally rejected as "non-authoritative"; that rejection is void because it assumed `vaults` could do the job. With `vaults` out, the real choice was "`ipns_records` creator marker (weak but works) vs. nothing," and we chose the check.

**Ownership ceiling (unchanged posture, documented):** `ipns_records.user_id` is a denormalized creator marker; the record's Ed25519 signature is the true update-authority (`ipns-record.entity.ts:15-19`). This check is **defense-in-depth** layered atop the real cryptographic access boundary — a sharer can only wrap keys they hold into the descriptor refs (`resolveShareWriteDescriptor` requires the parent folder's keys via the SDK client), so a forged share/invite for content the caller lacks keys to is **cryptographically inert**. D-01 raises server-side ownership from *nothing* to *"the authenticated user who registered this node."* A cryptographic key-possession challenge remains the real fix (deferred — see Deferred Ideas).

- Rejected **Flow B** (elevate `ipns_records.user_id` to authoritative / add a global uniqueness authority) — invasive, fights the signature-based design. We only *read* the creator marker for a cheap anti-spoof gate; we do not elevate it to authority.
- **Wiring note (supersedes the PATTERNS.md `Vault` forFeature finding):** the DI dependency is now an `ipns_records` repository, not `Vault`. `ShareInviteService`/`SharesService` must be able to query `ipns_records` (inject the repo via `@InjectRepository(IpnsRecord)` and register `IpnsRecord` in `shares.module.ts`'s `TypeOrmModule.forFeature([...])`, OR depend on an existing IPNS read path). Planner to resolve the exact wiring; the `Vault`-forFeature task from PATTERNS.md is NO LONGER needed.
- Cost: one indexed lookup (`ipns_name` is `@Unique`-indexed, `user_id` is `@Index`) before persist, on both create paths.

### D-02 — rootNodeId validation (SC#1)
**Validate `rootIpnsName` ownership only.** `rootNodeId` stays client-asserted for this phase.

- No server store records a *root's* nodeId today — `vaults` has `root_ipns_name` but no `root_node_id`; `rootNodeId` lives only on `shares`/`share_invites`.
- Rejected persisting `root_node_id` on `vaults` (would add a migration + a `/vault/init` write-path change — larger blast radius than this phase warrants).
- **Known gap to document:** SC#1's "owns the `(rootIpnsName, rootNodeId)` pair" is only half-enforced server-side. The nodeId half remains client-trusted. Note this explicitly in the ADR/CONTEXT so it isn't mistaken for a full pair-ownership check.

### D-03 — SC#3 root-uniqueness index: SKIP
**Do NOT add the `ipns_records(user_id) WHERE is_root` partial unique index.** SC#3's root-uniqueness sub-goal is already satisfied.

- `vaults.owner_id` is already `unique` → one-root-per-user is **already enforced** at the vault layer.
- The proposed ipns index would guard `ipns_records.user_id`, the column the entity model says is *not* authoritative — redundant and semantically wrong-layer.
- **SC#3 is flagged for revision:** its `claim_count` CHECK-constraint half still applies (D-04); its root-uniqueness-index half is dropped as already-covered. Planner should record this SC amendment.

### D-04 — claim_count CHECK constraint (SC#3) — AMENDED 2026-07-09 (greenfield → fold into cutover)
Add the entity `@Check` on `share-invite.entity.ts`: `CHECK (claim_count >= 0 AND claim_count <= max_claims)`.

**Migration:** apply the `CONSTRAINT ... CHECK (...)` **directly inside the `share_invites` CREATE TABLE in the shipped cutover** `1750000000000-ApiSchemaCutover.ts` (edit in place). **NO separate forward migration, NO `[BLOCKING]` `migration:run` gate.** Rationale: the v2.0 schema is **greenfield/unreleased** (user-confirmed 2026-07-09) — a forward migration to constrain a column defined in the same unreleased cutover is pointless indirection. This supersedes the original "forward migration + never edit cutover" instruction below and retires the planned `1752100000000-ClaimCountCheckConstraint` migration and its blocking run task. The DB-level `23514 check_violation` backstop verification (real-Postgres or documented manual) still applies.

### D-05 — Same-seq CID equivocation → HARD-GUARD 400 (SC#4 / D-09)
When a republish arrives with `embeddedSeq === dbSeq` **and the incoming metadata CID differs from the stored `latestCid`**, reject with `BadRequestException` (400).

- **Evidence this is anomaly-only:** No legitimate flow produces same-seq + different-CID.
  - TEE lease-renewer (post-Phase 67) structurally cannot repoint the CID — `renewIpnsRecord` re-signs value+sequence parsed from the existing record; the request body has no `metadataCid` field (`apps/tee-worker/src/services/ipns-signer.ts:37-51`, `apps/tee-worker/src/routes/republish.ts:29`). It also uses a separate EOL-only write path (`republish.service.ts:469`) that never reaches the `upsertIpnsRecord` same-seq branch.
  - Client publish always bumps the sequence on any content change (`packages/sdk-core/src/cas.ts:88-100`); a same-seq retry re-sends the identical CID.
- **Guard precision:** reject **only when incoming CID ≠ stored `latestCid`**. Idempotent same-CID retries MUST still succeed (no blanket same-seq reject).
- **Cleanup required:** rewrite the stale "Pitfall 4" test (`apps/api/src/ipns/ipns.service.spec.ts:2111-2137`, assertions ~2124/2131) and the misleading comment (`apps/api/src/ipns/ipns.service.ts:313`) — they encode a TEE re-sign-with-new-CID behavior that Phase 67 made impossible.

### D-06 — First-publish INSERT race → 409 (SC#4, mechanical)
Wrap the first-publish `save` (`ipns.service.ts` ~436-451), catch TypeORM `QueryFailedError` unique-violation (Postgres `23505`) and translate to `ConflictException` (409) instead of a 500. Add an e2e case. Detect via error code `23505` (constraint-name detection is a fallback).

### D-07 — Re-claim later-grant → UPGRADE-MERGE, widen-only (SC#2)
In `claimInvite`, when a share to the recipient already exists, apply the later invite's grant **only if it widens authority** (e.g. read → write); otherwise no-op. Never downgrade write → read.

- Write authority is presence-derived: `invite.writeDescriptorRef !== null` (`share-invite.service.ts:187`, invariant T-66-E1). Only widen.
- **Ordering:** the existing-share branch (`share-invite.service.ts:160`) currently runs *after* the atomic claim UPDATE at `:141` has already incremented `claim_count`. The merge/no-op decision must be resolved without wasting/burning the invite improperly — planner to sequence the existing-share detection and grant-merge relative to the atomic claim so a legitimate widen consumes the invite and a redundant re-claim does not silently drop the grant.
- Rejected **Reject-on-conflict (409)** — worse UX (re-inviting with write wouldn't upgrade; would force revoke-then-reinvite).

### D-08 — Bulk-revoke direct DELETE (SC#5, mechanical)
Swap `find` + `remove` for a single `DELETE ... execute()`. **Note the naming correction:** there is no `bulkRevoke` on `ShareInviteService`; the bulk share+invite revoke lives in `SharesService.revokeForItems` (`shares.service.ts:161`). Todo already verified `Share` has no hooks/cascades/subscribers, so direct DELETE is behavior-preserving. Spec mock churn only.

### D-09 — Restore ShareInviteService unit coverage (SC#6, mechanical)
Extend `share-invite.service.spec.ts` for `createInvite`, `getInvitesForItem`, `revokeInvite` with realistic UUID/key fixtures (not placeholder strings). Also fix placeholder fixtures in `shares.controller.spec.ts` (contract-valid UUIDs/keys).

### D-10 — Full share-plane rename, purge "descriptor" (NEW 2026-07-09)

The `shares`/`share_invites` naming is renamed **end-to-end** (columns + TS fields/DTOs + methods/types + api-client + Rust crates), purging the "descriptor" term from the share context. **Greenfield edit-in-place** — no rename migration; edit the CREATE TABLE column names directly in the cutover `1750000000000-ApiSchemaCutover.ts` (user-confirmed v2.0 schema is unreleased).

**Canonical rename map (apply everywhere the identifier is share/invite-grant-scoped):**

| Old | New | Scope note |
|-----|-----|-----------|
| col `read_descriptor_ref` (shares) | `encrypted_read_key` | cutover CREATE TABLE, in place |
| col `write_descriptor_ref` (shares, share_invites) | `encrypted_write_key` | both tables, cutover in place |
| col `root_ipns_name` (shares, share_invites) | `share_root_ipns_name` | both tables, cutover in place |
| col `encrypted_key` (share_invites read key) | `encrypted_read_key` | cross-table parallelism with shares |
| field `readDescriptorRef` | `encryptedReadKey` | entities, DTOs, sdk-core/sdk, web, api-client |
| field `writeDescriptorRef` | `encryptedWriteKey` | " (presence still = write grant, T-66-E1 / D-07) |
| field/DTO `rootIpnsName` **(share-grant domain ONLY)** | `shareRootIpnsName` | **SURGICAL** — the ~21 share/invite/grant-domain files, NOT the vault/ipns/folder-tree `rootIpnsName` (95 total; the vault-root/folder-tree ones stay `rootIpnsName`) |
| field `encryptedKey` (invite read key) | `encryptedReadKey` | parallelism |
| method `resolveShareWriteDescriptor` | `resolveShareEncryptedWriteKey` (planner may pick a cleaner name) | sdk client + call sites + tests |
| `clearWriteDescriptor`, `dispatchWriteDescriptor`, `claimerReadDescriptorRef` | `clearEncryptedWriteKey`, `dispatchEncryptedWriteKey`, `claimerEncryptedReadKey` | sdk/web |
| `*DescriptorRef` TS types | `*EncryptedKeyRef` (or inline) | purge the type name |
| Rust `*Descriptor*` symbols (`crates/fuse`, `crates/sdk`) | matching `*EncryptedKey*` | full e2e |

**Blast radius (measured):** field-level ~40–95 files/220–538 hits per identifier; crosses TS + Rust + api-client. `readDescriptorRef` field ONLY unwraps to a single ECIES-wrapped key (no packed metadata — verified: builder `wrapKey(itemWriteKey, pub)` at `client.ts:3771`, consumer `unwrapKey(...) → key → unsealNode` at `client.ts:5314`), so `encrypted_read_key`/`encryptedReadKey` is the accurate name. The grant's logical metadata (`rootNodeId`, `share_root_ipns_name`, `root_generation`) stays in separate columns.

**Regenerate:** run `pnpm api:generate` after the DTO field renames and commit the regenerated `@cipherbox/api-client` (pre-commit hook enforces it). Greenfield → no client back-compat concern.

**Sequencing:** the rename is a **foundation** step — it must land BEFORE (or be threaded through) the D-01/D-07/D-08/D-09 logic changes, since they touch the same files/fields. All subsequent plans use the NEW names.

**Explicitly NOT renamed:** `root_generation`/`rootGeneration` (load-bearing anti-rollback staleness witness — seeds the recipient's durable generation floor, `shares.service.ts:275`; not derivable from live metadata; out of scope), `root_node_id`/`rootNodeId`, `item_name_encrypted`/`itemNameEncrypted`, and the vault/ipns/folder-tree `rootIpnsName`.

### Migration ordering (cross-cutting) — AMENDED 2026-07-09 (greenfield)
The v2.0 schema is **greenfield/unreleased**, so for this phase the `shares`/`share_invites` schema changes (D-10 renames + D-04 CHECK) are applied **directly in the cutover `1750000000000-ApiSchemaCutover.ts` in place** — NO new forward migration. (The general forward-only / immutable-shipped-migration rule resumes once v2.0 ships; it does not apply to this unreleased cutover.) D-05/D-06 are runtime-logic changes with no schema component.

### Folded Todos
All 8 ROADMAP source todos are folded into this phase's scope (they define it):

- `share-invite-validate-root-ownership` → D-01, D-02
- `share-invite-reclaim-apply-later-grant` → D-07
- `share-invites-claim-count-check-constraint` → D-04
- `ipns-records-root-uniqueness-index` → D-03 (dropped — already covered by vault uniqueness; SC#3 amended)
- `ipns-first-publish-insert-race` → D-06
- `ipns-idempotent-same-seq-cid-equivocation` → D-05
- `shares-bulk-revoke-direct-delete` → D-08
- `restore-shares-module-unit-coverage` → D-09

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Source todos (the phase definition)
- `.planning/todos/pending/2026-06-30-share-invite-validate-root-ownership.md`
- `.planning/todos/pending/2026-06-30-share-invite-reclaim-apply-later-grant.md`
- `.planning/todos/pending/2026-06-30-share-invites-claim-count-check-constraint.md`
- `.planning/todos/pending/2026-06-30-ipns-records-root-uniqueness-index.md`
- `.planning/todos/pending/2026-06-30-ipns-first-publish-insert-race.md`
- `.planning/todos/pending/2026-06-30-ipns-idempotent-same-seq-cid-equivocation.md`
- `.planning/todos/pending/2026-06-30-shares-bulk-revoke-direct-delete.md`
- `.planning/todos/pending/2026-06-30-restore-shares-module-unit-coverage.md`

### Ownership / share-invite (SC#1, SC#2, SC#5)
- `apps/api/src/shares/share-invite.service.ts` — `createInvite`:33 (verbatim DTO copy :40-41, no ownership check today), `claimInvite`:108 (existing-share branch :160, atomic claim UPDATE :141, mint :183, write-authority invariant :187)
- `apps/api/src/shares/shares.service.ts` — `revokeForItems`:161 (bulk share+invite revoke — the real "bulkRevoke")
- `apps/api/src/shares/dto/create-invite.dto.ts` — `rootIpnsName`:39-46 (format-only validation), `rootNodeId`:51-52 (`@IsUUID` only)
- `apps/api/src/shares/share-invites.controller.ts:52-56` — principal injection (`req.user.id → sharerId`)
- `apps/api/src/vault/entities/vault.entity.ts:19-38` — authoritative user→root binding (`owner_id` unique FK, `root_ipns_name`)
- `apps/api/src/vault/vault.service.ts:66-122` — `/vault/init`; is_root setter (:98, :110)
- `apps/api/src/shares/entities/share-invite.entity.ts` — `@Check` target for D-04

### IPNS data-integrity (SC#3, SC#4)
- `apps/api/src/ipns/ipns.service.ts` — `upsertIpnsRecord`:231, same-seq branch :300-360 (idempotent overwrite :315/:358-360), stale comment :313, first-publish insert :436-451 (`isRoot:false`), CAS ConflictException path ~404
- `apps/api/src/ipns/entities/ipns-record.entity.ts:15-30` — denormalization comment + `@Unique(['ipnsName'])` + `user_id` FK; `is_root` :78
- `apps/api/src/migrations/` — shipped cutover `1750000000000-ApiSchemaCutover.ts`; latest `1751000000000-ScheduleCollapse.ts` (new migrations sort after)

### TEE contract (evidence for D-05 — read-only, do not modify)
- `apps/tee-worker/src/services/ipns-signer.ts:37-51` — `renewIpnsRecord` (same value+seq, no CID input)
- `apps/tee-worker/src/routes/republish.ts:15-31,52-58` — republish contract (no `metadataCid`/`sequenceNumber` in body)
- `apps/api/src/republish/republish.service.ts:190-196,469` — EOL-only CAS update (separate from `upsertIpnsRecord`)
- `packages/sdk-core/src/cas.ts:86-100` — client always bumps sequence on content change

### Test targets
- `apps/api/src/ipns/ipns.service.spec.ts:2111-2137` — Pitfall-4 test to rewrite (D-05)
- `apps/api/src/shares/share-invite.service.spec.ts` — extend (D-09)
- `apps/api/src/shares/shares.service.spec.ts`, `apps/api/src/shares/shares.controller.spec.ts` — mock/fixture updates (D-08, D-09)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ipns_records` (`IpnsRecord` entity) — D-01 (AMENDED) reads its `user_id` creator marker via a single indexed `findOne({ where: { ipnsName, userId } })` rather than any new schema. (`vaults`/`VaultService` is NOT usable for D-01 — it records only the vault root, never the shared child nodes.)
- Existing CAS `ConflictException` path in `ipns.service.ts` (~404) — the 409 translation pattern for D-06 mirrors this.
- `share-invite.service.spec.ts` scaffolding — extend, don't rebuild (D-09).

### Established Patterns
- Migrations are forward-only, timestamp-ordered; shipped ones are immutable (see project DB Evolution Protocol). D-04 and any D-07 schema follow this.
- Authority for IPNS records is signature-based by design; `user_id` is a creator marker. D-01/D-03 deliberately avoid leaning on `ipns_records.user_id` for authorization.
- Write-authority is presence-derived (`writeDescriptorRef !== null`), invariant T-66-E1 — D-07 must preserve widen-only semantics.

### Integration Points
- `createInvite` AND `createShare` gain an `ipns_records` creator-marker lookup (`ipnsName` + `userId`) before persist (D-01, AMENDED — see decision for why `vaults` cannot serve this).
- `claimInvite` existing-share branch gains grant-merge logic sequenced around the atomic claim UPDATE (D-07).
- `upsertIpnsRecord` same-seq branch gains a CID-equality guard (D-05); first-publish insert gains 23505→409 (D-06).

</code_context>

<specifics>
## Specific Ideas

- User explicitly wanted the root-ownership flows laid out before deciding — chose the vault-backed check (D-01) once the FK-backed `vaults` entity and the `ipns_records` denormalization tension were surfaced.
- User confirmed Hard-guard (D-05) only after the TEE lease-renewer contract was traced and proven to make same-seq CID-repoint impossible.

</specifics>

<deferred>
## Deferred Ideas

- **Cryptographic key-possession proof of root ownership** (signature challenge at `createInvite`/`/vault/init`) — the real fix for the "first-claimer-wins" ceiling. Out of scope; own phase. This phase only raises ownership to "authenticated registrant."
- **Persisting `root_node_id` on `vaults`** to enable full `(rootIpnsName, rootNodeId)` pair validation (D-02 gap) — deferred; touches vault-init write path.

### Reviewed Todos (not folded)
None — all 8 source todos folded (one, root-uniqueness-index, folded then dropped as already-covered per D-03).

</deferred>

---

*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Context gathered: 2026-07-07*
