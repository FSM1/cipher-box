# Phase 67: TEE Lease-Renewer Contract Rewrite - Context

**Gathered:** 2026-07-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 67 rewrites the TEE worker from a **record originator** into a **record-lease-renewer** (design §6.4). Today the worker does the exact opposite of the target contract: it mints a fresh IPNS record from relay-supplied scalars — `newSequenceNumber = BigInt(entry.sequenceNumber) + 1n` and signs `entry.latestCid` (`apps/tee-worker/src/routes/republish.ts:79-80`) — sourced from the `ipns_republish_schedule` snapshot, trusts a relay-supplied `currentEpoch`, asserts **no** name↔key binding, performs **no** tombstone/revoked-CID check, and stamps a hardcoded 48h EOL. Four requirements (TEE-01, TEE-02, TEE-03, TEE-06):

**In scope:**

- **TEE-01/02 — Lease-renewer contract (§7.3 test 12).** Remove the `+ 1n`; the renewer re-emits the **same CID + same `sequenceNumber`** with only a **later EOL**. The sequence-increment policy stays in the relay (§6.2). A revoked/rotated-out CID is never re-signed forward.
- **TEE-03 — `ipns_records` is the sole signing-input source.** Collapse the four duplicated columns on `ipns_republish_schedule` (`encrypted_ipns_key`, `key_epoch`, `latest_cid`, `sequence_number`); the schedule becomes pure scheduling metadata.
- **TEE-06 — Hardened enclave bindings (§6.7).** Internal epoch self-derivation (TEE clock, never the relay's scalars); name↔key binding asserted before emit; migration durability via a TEE-side stale-key guard + re-enroll signal.
- **EOL-only renewal uses the same atomic CAS** guard as the Phase-66 publish path (§6.6 / TEE-04), not the current weaker forward-only write-back.
- **Local docker + sdk-e2e round-trip** proving the new contract end-to-end (success criterion 4).
- **`pnpm api:generate`** + commit the regenerated client if the relay↔TEE request/response or the `ipns_records`/schedule API surface changes.

**Out of scope (hard boundary — owned by later phases):**

- **Client-side re-enroll / re-wrap recovery path** (the consumer of the TEE's "re-enroll required" signal) → **Phase 68** (web) / **Phase 69** (FUSE). Phase 67 ships the TEE-side guard + signal only (D-03, mirrors Phase 66 D-04).
- **Durable client `{nodeId → highestGeneration/Seq}` high-water** → **Phase 68** (ROT-07).
- **Cross-layer `ValidityType` verify hardening** beyond the renewer's emit path (`crates/core/src/ipns.rs` `decode_ipns_cbor_validity`, the TS verifier, `tests/vectors/ipns/verify.json` lockstep) → may exceed Phase 67's TEE-worker scope; planner scopes (see folded todo 3).

The app stays **intentionally non-runnable mid-milestone** (greenfield, staging wiped on deploy). Do not pull later-phase client work forward.

</domain>

<decisions>
## Implementation Decisions

### Renewer contract

- **D-01 — Verify-in-enclave lease renewer (design §6.4).** The relay sends the **marshaled existing `signedRecord`** (sourced from the canonical `ipns_records.signed_record`) plus the encrypted IPNS key (`ipns_records.encrypted_ipns_private_key`). The TEE: (1) parses the marshaled IPNS record → value (CID), `sequenceNumber`, pubkey, validity; (2) **verifies the record's Ed25519 signature** against `publicKeyFromIpnsName(ipnsName)`; (3) decrypts the IPNS private key and asserts the name↔key binding `publicKeyFromIpnsName(ipnsName) == pubkey(decryptedKey) == record.pubkey` (§6.7-2); (4) **re-signs the SAME CID + SAME `sequenceNumber` with only a later EOL** (extends the lease). This requires bundling the `@cipherbox/core` IPNS record parse + Ed25519 verify into the worker (§7.1 lists `packages/core/src/ipns` in the enclave-contract blast radius). **Rationale:** chosen over re-signing from the relay-read canonical row because only verify-in-enclave holds if the relay is compromised — the TEE physically cannot re-sign a `(name, CID, seq)` tuple it did not cryptographically validate. **Note:** extending the EOL mutates the record's `Validity` field, so the TEE still re-signs (needs the decrypted Ed25519 private key) — verify-incoming-sig + name↔key binding together guarantee it can only extend the lease of a record the legitimate key already signed, with a key that derives to the name. Replaces `republish.ts:79-80`; removes the `+ 1n` (TEE-02).

### Schedule collapse (TEE-03)

- **D-02 — Pure scheduler (the first of the two options §6.3 offers).** Drop the four duplicated columns from `ipns_republish_schedule` (`encrypted_ipns_key`, `key_epoch`, `latest_cid`, `sequence_number`). The table keeps only `{ipnsName, nextRepublishAt, lastRepublishAt, consecutiveFailures, status, lastError}` — pure "when to republish." All signing inputs come **solely** from the canonical `ipns_records` row via a JOIN (TEE-03). **Rationale:** chosen over §6.3's alternative (fold scheduling columns into `ipns_records`, drop the table) to keep churn-y retry/failure/status state **off** the integrity-authoritative, CAS-guarded `ipns_records` row. Consistent with the D-11 data-minimization ethos: the only crypto-bearing duplicate (`encrypted_ipns_key`) is exactly what gets dropped; the surviving columns are operational, not residue. Migration follows Phase-66 **D-01** (forward TypeORM migration, greenfield drop-recreate; FKs re-established).

### Migration durability (TEE-06, §6.7-item-3)

- **D-03 — TEE-side guard + signal; defer the client re-enroll consumer to 68/69.** Phase 67 ships: **(a) Internal epoch self-derivation** — the TEE derives `currentEpoch`/`previousEpoch` from its **own clock + epoch schedule**, never the relay's `entry.currentEpoch`/`entry.previousEpoch` scalars (which are removed from the request body); re-wrap targets restricted to an enclave-enumerated set (§6.7-1, §7.3 test 19). Changes `reEncryptForEpoch` to target the TEE-internal `currentEpoch`. **(b) Refuse-to-renew-stale guard** — the TEE refuses to renew a key older than `currentEpoch − 1` (the existing current→previous fallback window becomes a hard floor) and emits a structured **"re-enroll required"** signal. The actual **client re-wrap-on-activity recovery** (the signal's consumer) rides Phase 68 (web) / 69 (FUSE). **Rationale:** keeps Phase 67 scoped to the enclave; safe because the 4-week × 2 epoch grace + greenfield means no key ages past `currentEpoch − 1` within a milestone cycle (§6.7 explicitly offers both this and the client-recovery path as alternatives).

### Proof strategy (success criterion 4)

- **D-04 — Local docker + sdk-e2e round-trip; test owns its own scheduling.** Add the tee-worker (`TEE_MODE=simulator`, no Phala dependency) to `docker/docker-compose.yml` (today only `docker-compose.staging.yml` runs it) and wire the relay's `TEE_WORKER_URL` to it. A new `tests/sdk-e2e` suite publishes a record (seq N, CID X), forces one republish, and asserts the republished record has **equal seq (no increment), equal CID, a later EOL**, and that a tombstoned/revoked name is **never re-signed forward**. The test enforces scheduling **deterministically — it never waits on the 6h cron**: (1) a direct DB write sets the schedule row's `nextRepublishAt` to the past (make-due, à la `tests/desktop-e2e/scripts/bump-ipns-sequence.ts`), then (2) enqueue **one** job into the real `republish` BullMQ queue (redis 6380) so `processRepublishBatch()` runs a single pass against the real (docker, simulator) worker. The production 6h cron is just a periodic enqueuer of that same job. Checker subagents stay **static-analysis only** ([[feedback-gsd-subagents-no-test-runs]]); the e2e run is the orchestrator/human gate (Phase-66 D-08 carryover; sdk-e2e is the only real client→API IPNS round-trip — [[project-sdk-e2e-only-cross-package-publish-gate]]).
- **Research flag (planner):** confirm the exact enqueue/trigger surface in `apps/api/src/republish/republish.module.ts` (is there a `@Cron`/repeatable BullMQ job; trigger via `queue.add(...)` vs a dev-guarded endpoint vs direct `processRepublishBatch()`), the local-compose `TEE_WORKER_URL` wiring, and that the relay can source `signed_record`/`encrypted_ipns_private_key` from `ipns_records` for the new marshaled-record request body.

### Claude's Discretion

- **Pre-publish tombstone/revoked gate (defense-in-depth) — REQUIRED, factoring is discretion.** Verified nuance: today's only tombstone guard (`syncIpnsRecordSequence` `tombstonedAt: IsNull()`, `republish.service.ts:390`) runs **after** publish, so it blocks DB sequence resurrection but **not** the TEE signing or the delegated-routing publish. Phase 67 must reject a tombstoned name **before** signing/publishing — both (a) at batch selection (`getDueEntries` JOIN `ipns_records.tombstoned_at IS NULL`, so tombstoned names never enter the batch — §5.5 "remove from the republish batch") **and** (b) at the renewal write CAS. Both layers; exact factoring is discretion.
- Whether the EOL-only renewal write reuses `upsertIpnsRecord`'s idempotent (equal-sequence) branch (`apps/api/src/ipns/ipns.service.ts:311-317`) or a dedicated renewal CAS — as long as it is guarded by the **same equality CAS** (`WHERE sequence_number = :loaded …`), replacing the current weaker forward-only `LessThanOrEqual` write-back (`republish.service.ts:386-397`). §6.6 / TEE-04.
- The structured shape of the "re-enroll required" signal (error code / response field) the client phases consume.
- Whether the marshaled record sent to the TEE is the raw `ipns_records.signed_record` bytes or a re-marshaled form — as long as the TEE parses + verifies it.
- Internal migration factoring (drop the four schedule columns; re-wire the signing-input JOIN) — forward TypeORM migration, greenfield drop-recreate per Phase-66 D-01.

### Folded Todos

- **`2026-06-30-ipns-idempotent-same-seq-cid-equivocation.md`** — *Decide whether a same-sequence republish may change the CID.* The §6.4 lease-renewer contract resolves this for the renewal path **by construction**: the TEE re-signs the verified record's own value, only extending the EOL, so it can no longer change `latestCid` at an equal sequence. **Reconciliation flag for the planner:** the *client* publish path's idempotent branch still updates `latestCid` on an equal-seq re-sign (`ipns.service.ts:311-317`; the test `ipns.service.spec.ts ~2022` asserts "latestCid must be updated even on idempotent re-sign (Pitfall 4)"). The design intends sequence advances iff the CID changes (§6.2), so an equal-seq CID change is an equivocation the gate should arguably reject — decide whether to tighten the client path here or leave it (it is pre-existing Phase-58 behavior, out of the strict TEE-worker scope).
- **`2026-06-29-createsubfolder-tee-republish-wiring.md`** (`resolves_phase: 67`) — `createSubfolder` (`packages/sdk-core/src/folder/registration.ts`) accepts `teeKeys` but never wires `encryptedIpnsPrivateKey`/`keyEpoch` into the published record, so a new subfolder is not republish-enrolled (silent: its IPNS record eventually expires). Fold: wire `encryptedIpnsPrivateKey` + `keyEpoch` into the published `ipns_records` row (now the sole signing source) so subfolders enroll in the TEE renewal — or fail-closed if the wiring is incomplete.
- **`2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md`** — Fold the **renewer-emit** part: the renewer extends the EOL → it must emit `ValidityType == 0` (EOL) and the new EOL must parse identically in the TS and Rust strict verifiers. The **broader** cross-layer verify hardening (`crates/core/src/ipns.rs` `decode_ipns_cbor_validity` reading `ValidityType`, `packages/sdk-core/src/ipns/index.ts`, the `tests/vectors/ipns/verify.json` lockstep) may exceed Phase 67's TEE-worker scope — flagged to the planner as possibly broader (see Deferred).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.** All line references below were adversarially verified against the live tree on 2026-07-01.

### Design source of truth (read first)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — single source of truth for v2.0. Phase-67 sections:
  - **§6.2** (L507-511) — sequence advances iff the CID changes; republish never increments; names `apps/tee-worker/src/routes/republish.ts:79`'s `+ 1n` as the offender (increment policy moves to the relay).
  - **§6.3** (L513-517) — collapse the dual-source state; `ipns_records` is the **sole** signing-input source; reduce the schedule to scheduling metadata **or** fold + drop (D-02 takes the first option).
  - **§6.4** (L519-527) — **the TEE is a record-lease-renewer**: relay sends the marshaled `signedRecord`; TEE parses + verifies the signature + re-emits same CID + same sequence, later EOL only; cannot originate or repoint a CID (D-01).
  - **§6.6** (L541-551) — atomic publish CAS; the idempotent/renewal write is guarded identically (`WHERE sequenceNumber = :loaded`) so an EOL-only renewal can never regress `latestCid`/`sequenceNumber`.
  - **§6.7** (L553-559) — three enclave bindings: (1) internal epoch derivation (own clock; re-wrap to an enclave-enumerated set); (2) name↔key binding; (3) migration durability — **client re-enroll path OR refuse keys older than `currentEpoch − 1`** (D-03 takes the refuse-guard + signal, defers the client path).
  - **§5.5** — tombstone-and-keep: TEE-unenroll = **remove from the republish batch** (schedule-row delete alone is "not sufficient"); the EOL-only renewal CAS must also reject tombstoned names.
  - **§7.1** (L575/L578/L581) — blast radius: `apps/tee-worker` + `packages/core/src/ipns` = the enclave-contract rewrite (High); `apps/api` collapses the schedule's duplicated columns.
  - **§7.2 step 6** (L590) — cutover order: lease-renewer contract + internal epoch derivation + name↔key binding + round-trip the TEE/republish E2E.
  - **§7.3 test 12** (L609, verbatim): *"Republisher stale-CID. Republisher re-signs mid-rotation → assert the revoked CID is never re-signed and never served; assert republish does not increment the sequence."* Also TEE-adjacent: **test 17** (L614, lease-renewal racing a forward publish), **test 18** (L615, name↔key binding), **test 19** (L616, epoch self-derivation), **test 20** (L617, tombstoned name).

### ADRs (authoritative freezes)

- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation = full Ed25519 rotation; the rotated-out IPNS name is tombstoned (the revoked CID the renewer must never re-sign forward).
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — forward-only revocation.
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — frozen seal/AAD encoding (context; not modified here).

### Requirements, roadmap, prior context

- `.planning/REQUIREMENTS.md` — **TEE-01, TEE-02, TEE-03, TEE-06** (this phase); TEE-04/05/07 shipped in Phase 66; ROT-07 (Phase 68), TEST-03 (Phase 69) are the boundary.
- `.planning/ROADMAP.md` — Phase 67 goal + 4 success criteria; Phase 68/69 boundaries (what defers).
- `.planning/phases/66-api-schema-cutover-publish-gate-and-tombstone/66-CONTEXT.md` — **D-01** (destructive drop-recreate migration discipline this phase inherits), **D-02/D-03** (the `ipns_records` `tombstoned_at`/`generation` columns + the atomic publish CAS the renewal write must match), **D-08** (everything through `tests/sdk-e2e`), **D-11** (data-minimization), and the explicit statement that the schedule collapse + enclave bindings are "explicitly Phase 67."
- `CONTEXT.md` (repo root) — pinned glossary: the **three counters** (`generation` / `keyEpoch` / `sequenceNumber` — never conflate). **Cite, do not redefine.**

### Schema, protocol & infra references

- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — TypeORM migration discipline (Phase-66 D-01 waives reversibility under greenfield).
- `docs/METADATA_SCHEMAS.md` — `node/v3` schema; IPNS record / EOL / `ValidityType` conventions.
- `CLAUDE.md` — TEE Republishing architecture (Phala CVM prod, local Docker simulator); API Development Workflow (`pnpm api:generate` + commit `packages/api-client/src/generated/` + `scripts/check-api-client.sh` pre-commit hook).
- `.planning/research/PITFALLS.md` — IPNS resolve / first-publish-seq / Validity pitfalls.

### Implementation sites (verified file:line)

- `apps/tee-worker/src/routes/republish.ts` — `:79` `+ 1n` (remove), `:80` signs `entry.latestCid` (→ re-sign verified marshaled record), `:25-32` `RepublishEntry` request shape (add marshaled `signedRecord`; remove `currentEpoch`/`previousEpoch`), `:71-93` decrypt→sign→re-encrypt→zero path (insert parse+verify+name↔key binding before sign).
- `apps/tee-worker/src/services/ipns-signer.ts` — `:12` `TEE_RECORD_LIFETIME_MS = 48h`, `:30-35` `createIpnsRecord(...)` (today create-only; add the parse + verify + EOL-extend-re-sign path here or in a new helper); emit `ValidityType == 0` (folded todo 3).
- `apps/tee-worker/src/services/key-manager.ts` — `:53-67` `decryptWithFallback` (current→previous epoch), `:88-89` `reEncryptForEpoch` (retarget to TEE-internal `currentEpoch`; add the `currentEpoch − 1` refuse guard).
- `apps/tee-worker/src/services/tee-keys.ts` — `:30-85` `getKeypair(epoch)` (HKDF simulator / dstack CVM); add enclave-internal epoch derivation from own clock (no enclave current-epoch state today).
- `apps/api/src/republish/republish.service.ts` — `:43-52` `getDueEntries` (add `ipns_records.tombstoned_at IS NULL` join + source signing inputs from `ipns_records`), `:97-105` `teeEntries` map (rebuild from `ipns_records`, send marshaled record), `:133-163` success branch, `:386-397` `syncIpnsRecordSequence` (weak `LessThanOrEqual` write-back → equality CAS).
- `apps/api/src/republish/republish-schedule.entity.ts` — `:39-60` the four duplicated columns to drop (`encrypted_ipns_key`, `key_epoch`, `latest_cid`, `sequence_number`).
- `apps/api/src/republish/republish.processor.ts` / `republish.module.ts` — BullMQ `'republish'` queue; `process()` → `processRepublishBatch()` (the e2e trigger surface).
- `apps/api/src/ipns/ipns.service.ts` — `:231` `upsertIpnsRecord`, `:384-391` the fused equality CAS (`sequence_number = :expected AND generation <= CAST(:incoming AS bigint) AND tombstoned_at IS NULL`), `:311-317` idempotent equal-seq branch (folded todo 1), `:394-406` 409/410 disambiguation.
- `apps/api/src/ipns/entities/ipns-record.entity.ts` — `:14` `@Entity('ipns_records')`, `:56-57` `signed_record`, `:64-65` `encrypted_ipns_private_key`, `:72-73` `key_epoch`, `:86-87` `tombstoned_at`, `:94-95` `generation`; no `public_key` (Phase-66 rename done).
- `packages/core/src/ipns` — the IPNS record parse + Ed25519 verify primitives to bundle into the worker (D-01); `publicKeyFromIpnsName` for the name↔key binding ([[project-ipns-resolve-ed25519-pubkey-from-name]]).
- `packages/sdk-core/src/folder/registration.ts` — `createSubfolder` `teeKeys` wiring (folded todo 2).
- `docker/docker-compose.yml` — add the `tee-worker` service (`TEE_MODE=simulator`) + relay `TEE_WORKER_URL` (D-04); `docker/docker-compose.staging.yml:96-115` is the existing simulator reference.
- `tests/sdk-e2e/` — the new TEE round-trip suite (D-04); redis 6380; `apps/tee-worker/src/__tests__/republish.test.ts` mocks the signer (unmock-fallback reference).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`@cipherbox/core` IPNS primitives** (`packages/core/src/ipns`): the record parse + Ed25519 verify + `publicKeyFromIpnsName` the worker must bundle for D-01's verify-in-enclave. The tee-worker unit tests already note "IPNS record creation is tested in @cipherbox/core" — the marshaling lives there.
- **`key-manager.ts` decrypt/re-wrap** (`decryptWithFallback`, `reEncryptForEpoch`) and **`tee-keys.ts` `getKeypair(epoch)`** (HKDF simulator / dstack CVM) — extend rather than replace for internal epoch derivation.
- **Phase-66 fused CAS** (`upsertIpnsRecord`, `ipns.service.ts:384-391`) — the equality-CAS shape the renewal write must adopt; its idempotent equal-seq branch (`:311-317`) is a candidate host for the EOL-only renewal.
- **BullMQ `'republish'` queue** + `getDueEntries`/`processRepublishBatch` — the deterministic e2e trigger; `tests/desktop-e2e/scripts/bump-ipns-sequence.ts` is the make-due DB-poke pattern.
- **`docker/docker-compose.staging.yml` tee-worker block** — copy into `docker-compose.yml` for the local stack.

### Established Patterns

- **TEE never sees plaintext content** (§4.7) — it only renews record leases (write plane). The verify-in-enclave change keeps that boundary; it adds Ed25519 verify, not content decryption.
- **Greenfield destructive migration** (Phase-66 D-01) — drop the four schedule columns and re-wire FKs in a forward TypeORM migration; `down()` may throw.
- **sdk-e2e is the only real client→API IPNS round-trip** ([[project-sdk-e2e-only-cross-package-publish-gate]]) — redis on 6380; deterministic forcing via barrier/DB-poke (Phase 64/65 pattern), not timers.

### Integration Points

- Relay→TEE request body (`RepublishEntry`) reshapes: **add** the marshaled `signedRecord` (from `ipns_records.signed_record`), **remove** `currentEpoch`/`previousEpoch` (TEE self-derives), source `encryptedIpnsKey`/`latestCid`/`sequenceNumber` from `ipns_records` not the schedule.
- Renewal write moves from `syncIpnsRecordSequence`'s `LessThanOrEqual` UPDATE onto the equality CAS (shared with `upsertIpnsRecord`).
- The "re-enroll required" signal is a new relay→client surface consumed in Phase 68/69 (flows through `api:generate` if it touches the API).

</code_context>

<specifics>
## Specific Ideas

- The user took **all four recommendations** (verify-in-enclave, pure scheduler, TEE-guard + deferred client re-enroll, local-docker sdk-e2e) — a security-first + scope-tight pattern consistent with Phase 66 (9/11 recommendations, overrides toward minimization).
- On the e2e decision the user raised a real **testability concern** — "will the test enforce its own scheduling on the relay to make the IPNS refresh fire at the right time?" — and locked it only after confirming the mechanism: the test makes the schedule row due (DB write to `nextRepublishAt`) and fires **one** `republish` BullMQ job, so determinism comes from the test, not the 6h cron. The planner must honor this — **no timer waits** in the e2e.
- **Verify-in-enclave was the explicit security driver:** the contract "cannot originate or repoint a CID" is only true if the TEE validates the incoming signature itself; re-signing a relay-read row would relocate trust to the relay. Bundling `packages/core/src/ipns` into the worker is therefore load-bearing, not incidental.

</specifics>

<deferred>
## Deferred Ideas

- **Client re-enroll / re-wrap recovery path** (the consumer of the TEE "re-enroll required" signal) → **Phase 68** (web) / **Phase 69** (FUSE). Phase 67 ships the TEE-side guard + signal only (D-03).
- **Broader cross-layer `ValidityType == 0` verify hardening** — `crates/core/src/ipns.rs` `decode_ipns_cbor_validity` reading `ValidityType`, the TS verifier, and the `tests/vectors/ipns/verify.json` TS↔Rust lockstep (from todo `2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md`). Phase 67 folds only the renewer **emit** side; the full verify-stack binding is planner-scoped, may defer.
- **Client publish-path equal-seq CID equivocation** (`ipns.service.ts:311-317` "Pitfall 4" behavior) — if the planner decides to tighten the client path to reject equal-seq CID changes (per §6.2), it may exceed the TEE-worker scope; otherwise leave as pre-existing Phase-58 behavior (folded todo 1).
- **Richer `ipns_records` status enum** (paused/migrating beyond active/tombstoned) — Phase 66 kept it minimal (D-02); revisit only if the schedule collapse needs it.

### Reviewed Todos (not folded)

- All other `todo.match-phase 67` hits (async search index, permanent-delete dialog, ERC-1271, MFA factors, web logger redaction, base64 dedups, rotation/shares follow-ups, web-e2e flake, etc.) are generic keyword matches with no TEE-lease-renewer overlap — not folded.

</deferred>

---

*Phase: 67-tee-lease-renewer-contract-rewrite*
*Context gathered: 2026-07-01*
