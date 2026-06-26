# Phase 42: API unpin integrity - Context

**Gathered:** 2026-06-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the unpin-path gaps in `apps/api`: verify the caller owns a `pinned_cids(userId, cid)` row before unpinning, reference-count CIDs across users before issuing global Kubo `pin/rm`, delete the caller's row, and decrement quota via `recordUnpin` so deletes stop leaking quota. The upload-compensation path (`ipfs.controller.ts:122`) goes through the same guarded logic. One small `apps/web` touch is in scope (quota reconcile after delete — the source todo lists `delete.service.ts`). Everything else client-side is out of scope.

**Threat model (established during discussion, must hold in the implementation):** `POST /ipfs/unpin` is reachable by any authenticated user (open signup), and CIDs are public identifiers — the Kubo swarm port (4001) is public with the `server` profile so the DHT advertises provider records for every pinned CID; IPNS records resolve publicly to metadata CIDs; share recipients learn content CIDs and keep them after revocation. Knowledge of a CID must never confer deletion authority.

</domain>

<decisions>
## Implementation Decisions

### Non-owned unpin response

- **D-01:** When the caller has no `pinned_cids` row for the CID: return silent 2XX `{success: true}`, touch nothing. Uniform response for ALL no-row calls — never distinguish "CID unknown" from "CID owned by another user" in the response (no existence oracle).
- **D-02:** Emit audit telemetry in the no-row case: warn log + Prometheus metric when the CID exists under another user's row (abuse visibility). Benign races (CID unknown entirely) may be logged at lower severity or counted separately.

### Ordering & reconciliation

- **D-03:** Row first, Kubo best-effort: transactionally delete the caller's `pinned_cids` row + compute refcount, commit, then attempt Kubo `pin/rm`. Worst failure mode = tracked orphan pin; never billed-but-destroyed content.
- **D-04:** Close the concurrent-delete refcount race with a per-CID lock around the delete+refcount decision (Postgres advisory xact lock on `hash(cid)`). Without it, two concurrent deleters of the same CID can each see the other's row and neither unpins.
- **D-05:** Outbox pattern: when refcount hits zero, insert the CID into a `pending_unpins` table in the SAME transaction as the row delete. After commit, attempt `pin/rm`; on success delete the outbox row. A periodic BullMQ retry job (reuse the Phase 21 `pin-migration` queue pattern) drains failures. Kubo "not pinned" responses count as success everywhere (endpoint and worker).
- **D-06:** Drift report: a read-only periodic job diffs Kubo `pin ls` against `pinned_cids` ∪ `pending_unpins` and REPORTS unaccounted pins (metric + log). It never deletes — auto-GC of unknown pins is forbidden (pins predating quota tracking or created by ops would be destroyed).

### BYO / refcount semantics

- **D-07:** All `pinned_cids` rows count equally in the refcount — no `origin` column, no migration. BYO advisory rows (from `register-cid`) may delay physical `pin/rm` on dedup-overlapped CIDs; that over-retention is accepted and self-heals when the BYO user deletes. Note: a BYO user registering another user's CID can only BLOCK physical unpin (disk-level over-retention), never force one — the design must preserve this property.
- **D-08:** External-only BYO deletes work for free under the new semantics: row delete + quota decrement succeed, the Kubo "not pinned" error is swallowed. `/ipfs/unpin` becomes the row-removal path for advisory rows (there is no unregister endpoint).

### Historical backfill

- **D-09:** One-shot backfill in scope: a maintenance script diffs non-BYO users' `pinned_cids` rows against Kubo `pin ls` and deletes rows whose CID is no longer pinned (restores honest quota). BYO users are excluded entirely — their advisory rows reference CIDs never on our Kubo and their quota is unenforced.

### Rate limiting

- **D-10:** No dedicated `@Throttle` on unpin — the global `BypassableThrottlerGuard` (~10/s) stays as the only limit, avoiding false positives on bulk folder deletes and bin purges (sequential per-file unpin clients). Instead, add a Grafana alert on the cross-user-attempt audit metric (Phase 26 alerting patterns).

### Response DTO

- **D-11:** `UnpinResponseDto` stays opaque `{success: true}` — identical for owned-deleted, no-op, and refcount-skip cases. No debug fields (`refsRemaining` would leak that another user references the CID). No DTO change means no api-client churn beyond the regeneration check.

### Web quota refresh

- **D-12:** `apps/web/src/services/delete.service.ts`: keep the instant local `removeUsage()` decrement, then fire `fetchQuota()` to reconcile with the now-authoritative server number (pattern already used after file saves).

### Upload/unpin race

- **D-13:** Accepted + documented, not closed: an uploader can be left with a row-but-no-pin if a concurrent deleter of the same deduped CID refcounts to zero between the uploader's `pin` and `recordPin`. Requires identical ciphertext across users (cryptographically negligible with random per-file keys) in a sub-second window; closing it would add a Kubo verify to the hot upload path Phase 19.2 optimized. The drift report provides detection if it ever occurs. Document the window in code comments at the compensation path.

### Claude's Discretion

- Exact metric names/labels for audit telemetry and drift report (follow existing `cipherbox_*` Prometheus conventions, Phase 18 patterns).
- `pending_unpins` table schema and BullMQ job naming/scheduling details.
- Backfill script vehicle (standalone script vs admin maintenance command) and batch sizing.
- Lower-severity handling of "CID unknown entirely" no-row calls vs the cross-user audit case.

### Folded Todos

- `2026-06-11-ipfs-unpin-missing-ownership-check.md` — IPFS unpin has no ownership check; any authenticated user can delete any CID (cross-tenant data destruction). This phase IS the fix: ownership check (D-01), refcount (D-07), compensation-path guard.
- `2026-06-11-server-quota-never-decremented-on-unpin.md` — `recordUnpin` has zero callers; quota only grows until lockout. This phase wires it in transactionally (D-03) with ordering/reconciliation decided (D-05) and historical repair (D-09).

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Source requirements (the audit todos)

- `.planning/todos/pending/2026-06-11-ipfs-unpin-missing-ownership-check.md` — ownership-check requirement, attack surface, files involved
- `.planning/todos/pending/2026-06-11-server-quota-never-decremented-on-unpin.md` — quota-decrement requirement, ordering/reconciliation considerations

### Project rules that bind this phase

- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — migration discipline for the new `pending_unpins` table (TypeORM rules)
- `CLAUDE.md` §API Development Workflow — run `pnpm api:generate` after touching API endpoints/DTOs/controllers and commit the regenerated client (pre-commit hook enforces staging)
- `docs/CAPACITY.md` — storage limits and quota context (500 MiB free tier)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `VaultService.recordUnpin()` (`apps/api/src/vault/vault.service.ts:225`) — exists, idempotent delete, zero callers today; becomes the row-removal primitive
- `VaultService.recordPin()` upsert with `orIgnore` (`vault.service.ts:207`) — idempotency pattern to mirror
- BullMQ queue pattern from Phase 21 (`pin-migration` queue) — template for the `pending_unpins` retry job
- `MetricsService` counters/histograms (`fileUnpins` already exists) — extend with audit/drift metrics per `cipherbox_*` conventions
- `@Throttle` usage example on `register-cid` (`ipfs.controller.ts:151`) — reference only; D-10 says don't add one to unpin

### Established Patterns

- `pinned_cids` has `@Unique(['userId', 'cid'])` with an index on `userId` only — the refcount query (`WHERE cid = ?`) and backfill need an index on `cid` (new migration alongside `pending_unpins`)
- All legitimate Kubo pins flow through `POST /ipfs/upload` → `recordPin` — the IPNS publish path pins nothing server-side; vault/metadata blobs ride the same relay (`packages/sdk-core/src/vault/index.ts:37`)
- Every unpin caller is fire-and-forget: web `.catch(logger.warn)`, FUSE `let _ =` — response-semantics change breaks nothing
- snake_case DB columns / camelCase API fields; `Uint8Array` for binary data

### Integration Points

- `IpfsController.unpin()` (`apps/api/src/ipfs/ipfs.controller.ts:144`) — currently ignores `req.user`; gains the guarded flow
- Upload compensation (`ipfs.controller.ts:122`) — must call the same guarded unpin service method instead of raw `unpinFile`
- `apps/web/src/services/delete.service.ts:17-21` — add `fetchQuota()` reconcile (D-12)
- Grafana/Prometheus stack from Phases 18/26 — alert on cross-user-attempt metric

</code_context>

<specifics>
## Specific Ideas

- The endpoint's semantic becomes "delete my reference; physically unpin from CipherBox only if I was the last reference and it's actually pinned" — keep the public contract opaque while the service layer does the real work.
- Kubo "not pinned" must be treated as success in BOTH the inline attempt and the outbox worker, or external-only BYO rows poison the retry queue forever.

</specifics>

<deferred>
## Deferred Ideas

- **Wire `provider.unpin` into BYO client delete flows** — external-only BYO deletes never unpin from the user's own node (`DualPinProvider.unpin` has zero app callers); user hardware accumulates pins forever. Client-side (`apps/web` / `packages/sdk`), belongs in a future BYO phase or todo.
- **Writable-share version-prune leak** — shared-file saves drop `prunedCids` without unpinning (`packages/sdk/src/share/shared-write.ts:450`); pruned version CIDs of shared files stay pinned and billed to whoever uploaded them. Pre-existing, untouched by this phase.
- **Upload/unpin race hardening** (per-CID lock + pin verify in the upload path) — revisit only if the drift report ever shows row-but-no-pin occurrences (D-13).

### Reviewed Todos (not folded)

- `2026-03-23-investigate-removal-of-mock-ipns-routing-layer.md` — api-area keyword match only; unrelated to the unpin path.
- `2026-02-14-erc-1271-contract-wallet-authentication.md`, `2026-02-26-alternative-mfa-factor-types.md`, `2026-03-30-check-remaining-github-actions-for-node-24-updates.md`, `2026-02-24-async-incremental-search-index.md`, `2026-02-22-crdt-ipns-inbox-sharing.md` — keyword-matcher noise; no relevance to unpin integrity.

</deferred>

---

_Phase: 42-api-unpin-integrity_
_Context gathered: 2026-06-12_
