# Phase 66: API Schema Cutover, Publish Gate, and Tombstone - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-30
**Phase:** 66-api-schema-cutover-publish-gate-and-tombstone
**Areas discussed:** Migration shape, Tombstone + generation columns, Publish-gate shape, DATA-04 live wiring, share_invites fate, shares uniqueness, resolve-410 marker, test proof, permission column, ipns_records TEE columns, live grant-revoke

---

## Migration shape

| Option | Description | Selected |
|--------|-------------|----------|
| Reversible forward migration | One timestamped TypeORM migration: RENAME folder_ipns→ipns_records (preserves FKs atomically), DROP share_keys, ALTER shares, ADD cols, real down(); honors the migration chain + DATABASE_EVOLUTION_PROTOCOL | |
| Destructive drop-recreate | Exploit greenfield: drop/recreate tables fresh, no rename dance, minimal/throw down() | ✓ |

**User's choice:** Destructive drop-recreate (overrode the recommendation).
**Notes:** Staging is wiped on deploy, no prod data — greenfield justifies setting aside the reversibility discipline. Still delivered as a forward TypeORM migration; the sub-phase FK-map research still runs so the recreate re-wires `ipns_republish_schedule`/`shares`/`vaults`.

---

## Tombstone + generation columns

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal: tombstoned_at + generation | `tombstoned_at timestamptz NULL` + `generation bigint NOT NULL DEFAULT 0` | ✓ |
| Unified status enum now | `status` enum (active/tombstoned…) anticipating Phase 67's schedule fold | |

**User's choice:** Minimal: tombstoned_at + generation (recommended).
**Notes:** Phase 67 can introduce a richer status enum when it folds the schedule's status column in.

---

## Publish-gate shape

| Option | Description | Selected |
|--------|-------------|----------|
| One CAS UPDATE, 410 on publish | Single conditional UPDATE enforces seq + generation + tombstone; 409 conflict vs 410 gone; tombstoned publish → 410 (symmetric with resolve) | ✓ |
| One CAS UPDATE, 403 on publish | Same atomicity; 403 Forbidden for tombstoned publish | |
| Separate generation/tombstone guard | Seq CAS as UPDATE; generation/tombstone as a pre-check findOne (TOCTOU window) | |

**User's choice:** One CAS UPDATE, 410 on publish (recommended).
**Notes:** Single atomic statement, no TOCTOU; EOL renewal guarded identically so it can never regress latestCid/sequenceNumber.

---

## DATA-04 live wiring

| Option | Description | Selected |
|--------|-------------|----------|
| Schema + endpoints + sdk-e2e proof; defer caller | Reshape shares + endpoints + prove CAS/tombstone/resolve here; live rotation→grant caller flow rides 68/69 | ✓ |
| Wire live grant re-mint/revoke now | Extend sdk-e2e with a full rotation→shares grant re-mint+revoke round-trip in Phase 66 | |

**User's choice:** Schema + endpoints + sdk-e2e proof; defer caller (recommended).
**Notes:** The live caller (web mutation paths / FUSE) is where the rotation→grant flow belongs — Phases 68/69.

---

## share_invites fate

| Option | Description | Selected |
|--------|-------------|----------|
| Keep + slim share_invites | Drop encrypted_child_keys jsonb; encrypted_key = single ephemeral-wrapped root readKey; keep token/status/maxClaims/expiresAt; claim inserts a shares grant | ✓ |
| Fold invites into shares (pending state) | One table with status=pending/claimed | |

**User's choice:** Keep + slim share_invites (recommended).
**Notes:** Distinct ephemeral/unclaimed lifecycle stays separate from claimed grants.

---

## shares uniqueness + recipient keying

| Option | Description | Selected |
|--------|-------------|----------|
| Keep the (sharer, recipient, root) triple | UNIQUE (sharer_id, recipient_id, root_node_id); preserves multi-sharer semantics for Q3/D-01; both descriptor refs nullable; recipient = userId FK | ✓ |
| Drop sharer from the key | UNIQUE (recipient_id, root_node_id); collapses owner-vs-delegate grants of the same node | |

**User's choice:** Keep the (sharer, recipient, root) triple (recommended).
**Notes:** Owner AND a write-recipient can independently grant the same node — keeping sharer_id preserves the Q3 split-authority distinction.

---

## Resolve-410 marker shape

| Option | Description | Selected |
|--------|-------------|----------|
| Structured 410 body, SDK-parsed | HTTP 410 + typed body ({ error: 'IPNS_TOMBSTONED', ipnsName }) through api:generate into @cipherbox/api-client | ✓ |
| Bare 410 status | 410 with the standard error envelope; clients infer from status code | |

**User's choice:** Structured 410 body, SDK-parsed (recommended).
**Notes:** Lets sdk-core/web surface an explicit "moved/revoked" signal (design §5.5 intent).

---

## Test proof

| Option | Description | Selected |
|--------|-------------|----------|
| supertest for DB/gate, sdk-e2e for 1 round-trip | Existing apps/api supertest harness for tests 15/16/17/20; sdk-e2e for one descriptor-ref reshape round-trip | |
| Everything through sdk-e2e | All proofs via the real client→API round-trip (docker + api dev + redis 6380) | ✓ |

**User's choice:** Everything through sdk-e2e (overrode the recommendation).
**Notes:** Maximal end-to-end fidelity. Planner must design a deterministic forcing mechanism for the concurrent-CAS race through the real client path (barrier / temp axios interceptor). Checker subagents stay static-only.

---

## permission column

| Option | Description | Selected |
|--------|-------------|----------|
| Drop; derive from writeDescriptorRef | write-vs-read = writeDescriptorRef IS NOT NULL; single source of truth | ✓ |
| Keep permission explicit | Retain permission varchar for cheap listing; redundant, can drift | |

**User's choice:** Drop; derive from writeDescriptorRef (recommended).
**Notes:** Matches the "authority is key possession" principle; downgrade-to-read-only just nulls writeDescriptorRef.

---

## ipns_records TEE/resolve columns

| Option | Description | Selected |
|--------|-------------|----------|
| Keep as-is; rename only | Carry encrypted_ipns_private_key/key_epoch/signed_record unchanged; add only tombstoned_at + generation | ✓ |
| Reshape TEE columns now | Start collapsing TEE signing-input columns during this cutover | |

**User's choice:** Keep as-is; rename only (recommended).
**Notes:** TEE-input reshape (TEE-03 schedule collapse / TEE-06 enclave bindings) is explicitly Phase 67 — not pulled forward. signed_record stays (DB-cached resolve needs it).

---

## Live grant-revoke

| Option | Description | Selected |
|--------|-------------|----------|
| Hard-delete the shares row | Revoke = DELETE; drop revoked_at; partial-unique becomes plain UNIQUE (sharer_id, recipient_id, root_node_id) | ✓ |
| Soft revoke via revoked_at | Keep soft-delete + audit trail | |

**User's choice:** Hard-delete the shares row (recommendation flipped after discussion).
**Notes:** User questioned the value of retaining a revoked row that parks stale ECIES key material with no consumer. Confirmed: rotation is the security boundary (not the row); the wrapped key wraps a now-superseded readKey the recipient already held (ADR 0002 forward-only), so retention is zero-value residue against the zero-DB-crypto / GDPR posture. Scope-exit re-mint stays an UPDATE of the active row (distinct from revoke=DELETE), so reMintGrantsRootedAt is unaffected. The *active* grant's wrapped key is load-bearing (design §2.8 "only DB residue") and stays. Saved as a standing preference.

---

## Claude's Discretion

- 409-vs-410 disambiguation mechanism after a 0-row CAS (follow-up read vs RETURNING/affected-rows).
- `generation`/`root_generation` column type (`bigint` to match seq convention, vs `int`).
- Migration file count/ordering (one vs a small ordered forward set) and FK drop/recreate sequencing — as long as the recreate is atomic and re-wires every referencing table.
- The precise typed shape of the 410 marker body + NestJS exception-filter wiring (must flow through api:generate).
- How tests/sdk-e2e forces the concurrent-CAS race deterministically.

## Deferred Ideas

- `ipns_republish_schedule` duplicated-column collapse → Phase 67 (TEE-03).
- TEE lease-renewer contract + enclave bindings → Phase 67 (TEE-01/02/06).
- Durable client-side generation/seq high-water → Phase 68 (ROT-07, web) / Phase 69 (FUSE).
- Live rotation→grant caller flow (executeLazyRotation → rotateReadFromNode, folderTree reconcile, reWrapForRecipients/addShareKeysFn deletion) → Phase 68 (web) / Phase 69 (FUSE).
- Richer ipns_records status enum (paused/migrating) → revisit in Phase 67 if needed.
