# Phase 66: API Schema Cutover, Publish Gate, and Tombstone - Context

**Gathered:** 2026-06-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 66 is the **apps/api cutover** that Phases 62–65 deliberately mock-deferred (65 D-02). The Postgres/TypeORM schema becomes the `node/v3` model and the publish/resolve plane becomes integrity-authoritative. Seven requirements (DATA-01..04, TEE-04, TEE-05, TEE-07):

**In scope:**

- **DATA-01 — delete `share_keys`** outright (table + entity + `addShareKeys` endpoint/service/controller); no dual-codec, no `version` discriminator.
- **DATA-02 — slim `shares`** to one grant row per recipient carrying `readDescriptorRef`/`writeDescriptorRef` (+ `rootNodeId`/`rootIpnsName`/`rootGeneration`); retire `readKeyEcies`/`ShareGrant`/`encrypted_key`/`encrypted_ipns_key`.
- **DATA-03 — rename `folder_ipns` → `ipns_records`** (entity `IpnsRecord`, repository) and **drop `public_key`**; strict-verify recovers the Ed25519 pubkey exclusively via `publicKeyFromIpnsName`.
- **DATA-04 (API surface) — `BinEntry` re-link + shared-delete grant-revoke schema.** The SDK bin re-link/restore already shipped in Phase 65; Phase 66 delivers the `shares` schema + endpoints that the shared-delete grant re-mint/revoke (the inverted HIGH-3 `reMintGrantsRootedAt` seam) writes against. The **live caller** flow defers to 68/69 (D-04).
- **TEE-04 — atomic publish CAS** (conditional `UPDATE … WHERE ipnsName AND sequenceNumber = :expected`; 0 rows ⇒ 409); the EOL-only renewal is guarded identically.
- **TEE-05 — resolve anti-rollback case-split**: DB-canonical with `generation` as authority + a per-node seq floor; explicit fail-closed fall-through (expected-null shared-folder row ⇒ apply seq floor; `signedRecord`-CID ≠ `latestCid` ⇒ fail closed).
- **TEE-07 — server-side forward-only `generation` per node** (publish-gate defence-in-depth mirroring the seq CAS).
- **Tombstone state machine** (design §5.5): tombstoned `ipns_records` row rejected at the publish gate (incl. the EOL renewal) and resolve returns a `410` marker; the name is removed from the TEE republish batch.
- **`pnpm api:generate`** + commit the regenerated `packages/api-client/src/generated/` (pre-commit `check-api-client.sh`).

**Out of scope (hard boundary — owned by later phases):**

- **`ipns_republish_schedule` duplicated-column collapse** (latestCid/sequenceNumber/encryptedIpnsKey/keyEpoch → sole source `ipns_records`) → **Phase 67** (TEE-03). Phase 66 keeps the schedule table; the rename only re-points its FK.
- **TEE lease-renewer contract + enclave bindings** (verify marshaled record, no-increment republish, internal epoch derivation, name↔key binding) → **Phase 67** (TEE-01/02/06).
- **Durable *client-side* `{nodeId→highestGeneration/Seq}` high-water** → **Phase 68** (ROT-07). Phase 66 provides the server-side `generation` column + gate; the durable client floor is the web/FUSE side.
- **Live rotation→`shares` grant re-mint/revoke caller** (`executeLazyRotation` → `rotateReadFromNode`, `folderTree` reconcile, web mutation paths) → **Phase 68** (web) / **Phase 69** (FUSE). `reWrapForRecipients` + `addShareKeysFn` type deletion → Phase 68.

The app stays **intentionally non-runnable mid-milestone** (greenfield, single cutover). Do not pull later-phase apps/web or crates/fuse deletions forward.

</domain>

<decisions>
## Implementation Decisions

### Migration & table reshape

- **D-01 — Migration = destructive drop-recreate** (user overrode the reversible-rename recommendation). Exploit greenfield (staging wiped on deploy, no prod data): drop and recreate the affected tables fresh rather than the rename/ALTER dance. Still delivered as a **forward TypeORM migration** (it is the deploy mechanism, success criterion 6 still requires `api:generate` + committed client), but it drops dependent FK constraints, recreates `ipns_records` clean, and re-establishes every referencing FK (`ipns_republish_schedule`, `shares`, `vaults`). `down()` may be minimal/throw given there is no rollback target. **Tradeoff accepted:** this sets aside the reversibility discipline in `DATABASE_EVOLUTION_PROTOCOL.md` — justified solely by greenfield. **The sub-phase FK-map research flag still runs first** so the recreate re-wires every referencing table correctly.
- **D-10 — `ipns_records` TEE/resolve columns carry over unchanged; rename only.** `encrypted_ipns_private_key`, `key_epoch`, `signed_record` are preserved as-is in the recreate (`signed_record` stays — DB-cached resolve needs the canonical signed bytes). Add **only** `tombstoned_at` + `generation` (see D-02). The TEE signing-input reshape (schedule collapse TEE-03, enclave bindings TEE-06) is **explicitly Phase 67** — do not pull it forward.

### `shares` grant model

- **D-06 — Keep the `(sharer_id, recipient_id, root_node_id)` partial-unique triple.** One grant row per recipient per share-root, but **retain `sharer_id` in the unique key** (`UNIQUE (sharer_id, recipient_id, root_node_id)` — see D-11 on the `WHERE` clause) to preserve **multi-sharer semantics required for Q3/D-01**: the owner AND a write-recipient can independently grant the same node. `readDescriptorRef` + `writeDescriptorRef` both **nullable** on the row; add `root_node_id`/`root_ipns_name`/`root_generation` columns (the latter feeds the reconcile enumeration + the M1 generation floor). Recipient stays a **userId FK** (existing pattern).
- **D-09 — Drop the `permission` column; derive write-vs-read from `writeDescriptorRef IS NOT NULL`.** Single source of truth, matches the design's "authority is key possession" principle (a row holding the wrapped writeKey IS a write grant). A Phase-68 downgrade-to-read-only just nulls `writeDescriptorRef`. Removes a field that can drift from the actual key state.
- **D-11 — Live grant-revoke = HARD-DELETE the `shares` row; drop `revoked_at` entirely.** (Recommendation flipped after the user's data-minimization point.) Revoke = `DELETE` the grant; the partial-unique `WHERE revoked_at IS NULL` becomes a **plain `UNIQUE (sharer_id, recipient_id, root_node_id)`** (re-share after revoke inserts cleanly because the row is gone). **Rationale:** the revoked row holds **stale ECIES key material with no consumer** — it wraps a now-superseded readKey to a recipient who already held it (ADR 0002, forward-only revocation), so retaining it adds at-rest surface for **zero** security or audit value, against the zero-DB-crypto / vault-blob-v2 ethos and GDPR. The real security boundary is **rotation**, not the row. The two write paths stay distinct: **scope-exit re-mint is an UPDATE** of the active row (new root/generation); **revoke is a DELETE** — so this does not touch `reMintGrantsRootedAt`. See [[feedback-minimize-db-crypto-prefer-hard-delete]]. **Note:** the *active* grant's wrapped key is load-bearing, not residue — design §2.8 calls the read-root grant "the only DB residue," and the row doubles as the recipient's discovery mechanism (`shares WHERE recipient_id = me`); that stays.

### `share_invites`

- **D-05 — Keep + slim `share_invites`** (distinct ephemeral/unclaimed lifecycle, do not fold into `shares`). Drop the `encrypted_child_keys` jsonb fan-out column; `encrypted_key` becomes the **single ephemeral-wrapped root `readKey`** (+ an optional write ref for writable invites). Keep `token`/`status`/`max_claims`/`claim_count`/`expires_at`/`item_name_encrypted` lifecycle. Claim re-wraps the root `readKey` to the claimer and **inserts a standard `shares` grant** (the SDK invite-claim re-wrap logic already shipped in Phase 65).

### Publish gate, CAS, generation, tombstone

- **D-02 — Minimal columns on `ipns_records`:** `tombstoned_at timestamptz NULL` (gate/resolve check `IS NULL`, keeps an audit timestamp) + `generation bigint NOT NULL DEFAULT 0`. No premature lifecycle modeling — Phase 67 can introduce a richer status enum when it folds the schedule's status column in.
- **D-03 — Publish gate is ONE atomic conditional UPDATE; 410 on tombstoned publish.** A single statement enforces seq CAS + forward-only generation + tombstone together: `UPDATE ipns_records SET … WHERE ipnsName = :n AND sequenceNumber = :expected AND generation <= :incoming AND tombstoned_at IS NULL`. 0 rows ⇒ follow-up read to distinguish **409** (seq conflict / generation regression) from **410** (tombstoned — symmetric with resolve). The EOL-only renewal is guarded identically (`WHERE sequenceNumber = :loaded …`) so it can never regress `latestCid`/`sequenceNumber` and a tombstoned name's renewal CAS is rejected (design §5.5/§6.6). No TOCTOU.
- **D-07 — Resolve-410 marker = structured body, SDK-parsed.** HTTP `410` + a typed body (e.g. `{ error: 'IPNS_TOMBSTONED', ipnsName }`) flowing through `api:generate` into `@cipherbox/api-client`, so sdk-core/web can surface an explicit "moved/revoked" signal (design §5.5 intent) rather than a generic Gone error.

### Scope & proof

- **D-04 — DATA-04 = schema + endpoints + proof here; live caller defers.** Phase 66 reshapes `shares` + endpoints (descriptor refs, `rootNodeId`/`rootIpnsName`/`rootGeneration` to support the reconcile enumeration) and proves CAS/tombstone/resolve/case-split. The **live** rotation→grant re-mint/revoke caller flow (the inverted HIGH-3 seam wired into real mutation paths) rides Phase 68 (web) / 69 (FUSE), where the mutation paths live. Keeps Phase 66 scoped to the API plane.
- **D-08 — Test proof: EVERYTHING through `tests/sdk-e2e`** (user overrode the supertest-for-DB-behaviors recommendation). All §7.3 proofs run via the real client→API round-trip: **test 15** (`parseCachedRecord`-null case-split), **test 16** (concurrent forward publishes → exactly one 409, zero lost updates), **test 17** (lease-renewal racing a forward publish), **test 20** (tombstoned name rejected at publish + resolve-410). **Planner must own:** a deterministic forcing mechanism for the concurrent-CAS race through the real client path (barrier / temp axios interceptor à la Phase 64/65), honoring docker + `pnpm --filter @cipherbox/api dev` + redis on **6380**. Checker subagents stay **static-analysis only** (no concurrent vitest) per [[feedback-gsd-subagents-no-test-runs]]; the e2e run is the orchestrator/human gate. The existing `apps/api/test/*.e2e-spec.ts` supertest harness may still be used opportunistically but is not the primary gate.

### Claude's Discretion

- The exact 409-vs-410 disambiguation after a 0-row CAS (single follow-up read vs `RETURNING`/affected-rows + a separate tombstone probe) — keep it a single round-trip if possible.
- Whether `generation`/`root_generation` are `bigint` (string in TypeORM) or `int` — match the seq convention (`bigint`) unless there's a reason not to.
- Internal factoring of the migration (one migration file vs a small ordered set, all forward) and the FK drop/recreate ordering — as long as the recreate is atomic and re-wires every referencing table.
- The precise typed shape of the 410 marker body and its NestJS exception filter wiring, as long as it flows through `api:generate`.
- How `tests/sdk-e2e` forces the concurrent-CAS race deterministically (D-08).

### Folded Todos

None folded — the `todo.match-phase 66` hits were keyword noise (UI/auth/crypto/search) with no schema-cutover overlap. The one partially-relevant item (rotation grant-threading) is reviewed below.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design source of truth (read first)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — single source of truth for v2.0. Phase-66 sections:
  - **§2.8** the read-root grant is "the only DB residue" (`readDescriptorRef`/`writeDescriptorRef`) — the active grant's wrapped key is load-bearing (D-11 distinction).
  - **§5.5** tombstone-and-keep: publish gate rejects all writes (incl. the EOL renewal CAS), resolve returns `410`, name removed from the republish batch.
  - **§6.1** resolve precedence — `generation` is the anti-rollback authority; DB is canonical (relay writes DB synchronously before the someguy push).
  - **§6.2** sequence advances iff the CID changes; republish never increments (the increment fix itself is Phase 67, but the gate must not regress on equal-seq renewal).
  - **§6.5** the resolve case-split (TEE-05): durable seq high-water (client = Phase 68) + `versionFloor`; **the relay must never silently fall through to an ungated network record** — expected-null `signedRecord` shared-folder row ⇒ apply `seq ≥ storedSeq` floor; `signedRecord`-CID ≠ `latestCid` ⇒ **fail closed**.
  - **§6.6** atomic publish CAS (TEE-04) — the exact `UPDATE … WHERE ipnsName AND sequenceNumber = :expected` shape; idempotent/renewal guarded identically.
  - **§7.1** blast radius — the apps/api row (rename `folder_ipns`→`ipns_records`, drop `public_key`, slim `shares`, delete `share_keys`, atomic CAS, tombstone); **`public_key` is the raw 32-byte Ed25519 IPNS pubkey, NOT the user secp256k1 `publicKey`** — derivable from the k51 name, null for shared rows (the null-row footgun behind two Phase-60 regressions).
  - **§7.2 step 5** the buildable cutover order for apps/api; **§7.3 tests 15/16/17/20** the must-pass proofs (D-08).

### ADRs (authoritative freezes)

- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation = (c) full Ed25519 rotation; the rotated-out name tombstone is the apps/api enforcement of this.
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — forward-only revocation; the honesty caveat that makes the revoked `shares` row residue (D-11).
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — frozen seal/AAD encoding (context; not modified here).

### Requirements, roadmap, prior context

- `.planning/REQUIREMENTS.md` — **DATA-01, DATA-02, DATA-03, DATA-04, TEE-04, TEE-05, TEE-07** (this phase); TEE-01/02/03/06 (Phase 67), ROT-07 (Phase 68), TEST-03 (Phase 69) are the boundary.
- `.planning/ROADMAP.md` — Phase 66 goal + 6 success criteria + sub-phase research flag (live FK map for the rename); Phase 67/68/69 boundaries (what defers).
- `.planning/phases/65-sdk-write-chain-bin-re-link-and-invite-claim/65-CONTEXT.md` — **D-02** (the 65→66 transport boundary: every DB/transport symbol was mock-tested in 65 and goes live here; lists the exact deletion targets that defer to 66 vs 68); **D-01** (Q3 split-authority → the `shares WHERE rootNodeId ∈ subtree` enumeration that D-06 keeps `sharer_id` for).
- `CONTEXT.md` (repo root) — pinned glossary: the **three counters** (`generation` / `keyEpoch` / `sequenceNumber` — never conflate), descriptor refs. **Cite, do not redefine.**

### Schema & protocol references

- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — TypeORM migration discipline (D-01 sets the reversibility rule aside under greenfield — read to know what is being waived and why).
- `docs/METADATA_SCHEMAS.md` — static `node/v3` schema (descriptor refs, `BinEntry.nodeRef`).
- `CLAUDE.md` — API Development Workflow: `pnpm api:generate` + commit `packages/api-client/src/generated/` + `scripts/check-api-client.sh` pre-commit hook (success criterion 6).

### Parity / pitfalls

- `.planning/research/PITFALLS.md` — IPNS resolve / first-publish-seq pitfalls.
- `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/STRUCTURE.md` — apps/api package boundaries.

### Implementation sites — apps/api

- `apps/api/src/ipns/entities/folder-ipns.entity.ts` → rename to `ipns_records` (entity `IpnsRecord`); drop `public_key`; add `tombstoned_at` + `generation` (D-02/D-10).
- `apps/api/src/shares/entities/share.entity.ts` → slim to descriptor refs; drop `permission`/`encrypted_key`/`encrypted_ipns_key`/`revoked_at`; add `root_node_id`/`root_ipns_name`/`root_generation`; plain `UNIQUE (sharer_id, recipient_id, root_node_id)` (D-06/D-09/D-11).
- `apps/api/src/shares/entities/share-key.entity.ts` + `shares.service.ts` (`addShareKeys`, ~L207) + `shares.controller.ts` (~L277) → **delete** (DATA-01).
- `apps/api/src/shares/entities/share-invite.entity.ts` + dto/service → drop `encrypted_child_keys`; `encrypted_key` = single ephemeral-wrapped root readKey (D-05).
- `apps/api/src/ipns/ipns.service.ts` → `publishRecord` (non-atomic findOne→gate→save today, §6.6) becomes the atomic CAS (D-03); `resolveRecord`/`parseCachedRecord` fail-closed case-split (D-07/§6.5); strict-verify recovers pubkey via `publicKeyFromIpnsName` ([[project-ipns-resolve-ed25519-pubkey-from-name]]).
- `apps/api/src/ipns/.../republish.service.ts` (`unenrollIpns`, ~L257) → tombstone removes the name from the republish batch (§5.5); keep the schedule table (collapse is Phase 67).
- `apps/api/src/**/migrations/` → new forward migration(s), drop-recreate (D-01); FKs on `ipns_republish_schedule`/`shares`/`vaults` re-established.
- `packages/api-client/src/generated/` → regenerate + commit (`api:generate`); the 410 marker contract surfaces here.
- `tests/sdk-e2e/` → the proof suite (D-08, §7.3 tests 15/16/17/20); `apps/api/test/*.e2e-spec.ts` (supertest) available but not the primary gate.

</code_context>

<specifics>
## Specific Ideas

- The user **took the recommended option on 9 of 11 decisions**, overriding twice — both toward **simplicity / minimization**: D-01 (destructive drop-recreate over a reversible rename, exploiting greenfield) and D-08 (everything through sdk-e2e over a split supertest+e2e harness).
- **Data-minimization is a first-class value** here (surfaced in the D-11 exchange): the user pushed back on retaining a revoked `shares` row, flagging that it parks ECIES key material in the DB for no consumer. This flipped the revoke decision from soft to hard-delete and is captured as a standing preference ([[feedback-minimize-db-crypto-prefer-hard-delete]]). Apply the same lens to any future "keep an audit row?" choice in this codebase.
- **`generation` is the through-line of this phase's hardening:** a server-side column + forward-only gate (TEE-07) here; the durable *client* high-water (ROT-07) is Phase 68. Don't conflate the server gate with the client floor — both are needed, in different phases.

</specifics>

<deferred>
## Deferred Ideas

- **`ipns_republish_schedule` duplicated-column collapse** (latestCid/sequenceNumber/encryptedIpnsKey/keyEpoch → `ipns_records` sole source) → **Phase 67** (TEE-03). Phase 66 keeps the table; rename re-points its FK only.
- **TEE lease-renewer contract + enclave bindings** (verify marshaled record, no-increment republish, internal epoch self-derivation, name↔key binding, migration durability) → **Phase 67** (TEE-01/02/06).
- **Durable client-side `{nodeId→highestGeneration/Seq}` high-water** (IndexedDB / FUSE journal-adjacent) → **Phase 68** (ROT-07, web) / **Phase 69** (FUSE). Phase 66 ships the server `generation` column + gate only.
- **Live rotation→grant caller flow** — `executeLazyRotation` → `rotateReadFromNode`, per-mutation fan-out removal, `folderTree` reconcile, `reWrapForRecipients` + `addShareKeysFn` type deletion → **Phase 68** (web); FUSE grant-root awareness → **Phase 69**.
- **Richer `ipns_records` status enum** (paused/migrating beyond active/tombstoned) → revisit in Phase 67 if the schedule fold needs it (D-02 keeps it minimal for now).

### Reviewed Todos (not folded)

- `2026-06-29-rotation-coderabbit-followups-deferred.md` — its **grant-threading** sub-item (`reMintGrantsRootedAt` unreachable in the real walk) touches Phase 66's `shares` schema, but the *live wiring* is the Phase-68 caller per D-04; merge re-enqueue (RR-01) + `verifySubtreeClean` depth (RR-02) are Phase 68. Not folded — Phase 66 only delivers the schema/enumeration support it needs.
- All other `todo.match-phase 66` hits (async search index, permanent-delete dialog, ERC-1271, CRDT inbox, base64 dedup, upload-batch mock drift, etc.) are generic keyword matches with no schema-cutover overlap.

</deferred>

---

*Phase: 66-api-schema-cutover-publish-gate-and-tombstone*
*Context gathered: 2026-06-30*
