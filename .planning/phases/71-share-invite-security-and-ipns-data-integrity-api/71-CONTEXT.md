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

### D-01 — Root-ownership source (SC#1)
Validate root ownership by looking up the **`vaults` entity**, not `ipns_records`:

```sql
SELECT 1 FROM vaults WHERE owner_id = :req.user.id AND root_ipns_name = :dto.rootIpnsName
```

- `vaults.owner_id` is a real FK to `users` and is `@Index({ unique: true })` (one vault per user) — `apps/api/src/vault/entities/vault.entity.ts:19-38`.
- This is the purpose-built binding ("Root folder is tracked in Vault entity"); it does not fight the `ipns_records` model, which deliberately makes authority signature-based and calls `user_id` a mere "denormalized creator marker" (`ipns-record.entity.ts:15-19`).
- Rejected **Flow A** (check `ipns_records.is_root` + `user_id`) — trusts the non-authoritative creator marker. Rejected **Flow B** (elevate `ipns_records.user_id` to authoritative) — invasive, redundant with the vault, fights the documented design.
- Cost: one indexed lookup added to `createInvite` before persist.

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

### D-04 — claim_count CHECK constraint (SC#3, mechanical)
Add a forward migration + entity `@Check`: `CHECK (claim_count >= 0 AND claim_count <= max_claims)` on `share_invites`. Target: `share-invite.entity.ts`.

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

### Migration ordering (cross-cutting)
New forward migrations (D-04 CHECK constraint, plus any needed for D-07) land in `apps/api/src/migrations/` with timestamps **after** the latest existing `1751000000000-ScheduleCollapse.ts`. NEVER edit the shipped `1750000000000-ApiSchemaCutover.ts` in place.

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
- `Vault` entity + `VaultService` — already the authoritative user→root binding; D-01 reuses it via a single `vaultRepo` lookup rather than any new schema.
- Existing CAS `ConflictException` path in `ipns.service.ts` (~404) — the 409 translation pattern for D-06 mirrors this.
- `share-invite.service.spec.ts` scaffolding — extend, don't rebuild (D-09).

### Established Patterns
- Migrations are forward-only, timestamp-ordered; shipped ones are immutable (see project DB Evolution Protocol). D-04 and any D-07 schema follow this.
- Authority for IPNS records is signature-based by design; `user_id` is a creator marker. D-01/D-03 deliberately avoid leaning on `ipns_records.user_id` for authorization.
- Write-authority is presence-derived (`writeDescriptorRef !== null`), invariant T-66-E1 — D-07 must preserve widen-only semantics.

### Integration Points
- `createInvite` gains a `vaults` ownership lookup before `inviteRepo.save` (D-01).
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
