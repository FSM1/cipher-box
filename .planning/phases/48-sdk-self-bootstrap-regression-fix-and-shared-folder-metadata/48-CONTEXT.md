# Phase 48: SDK self-bootstrap regression fix and shared-folder/metadata consolidation - Context

**Gathered:** 2026-06-16
**Status:** Ready for planning
**Source:** plan-phase (no discuss-phase; research-driven + two user policy decisions)

<domain>

## Phase Boundary

Fix the PR #498 self-bootstrap regression (P0 — main web-e2e is RED), then finish the SDK-as-single-owner work for shared folders, remove the now-redundant web folder-seeding, and close the Phase-14 M1 plaintext-`itemName` leak. The CRDT-IPNS-inbox share-discovery research (#2) is OUT of scope.

</domain>

<decisions>

## Implementation Decisions (LOCKED)

### REQ-1 — self-bootstrap reconcile (P0)

- Add a sequence-guard before `loadFolder`'s `folderTree.set()` (`packages/sdk/src/client.ts` ~385): if an entry already exists and `existing.sequenceNumber >= resolved.sequenceNumber`, keep the existing (fresher) in-memory state — never blindly overwrite with a stale IPNS-resolved snapshot. `ensureFolderLoaded`'s existing short-circuit on already-present folders stays.
- Both failing specs (`bin-restore-after-reload.spec.ts`, `full-workflow.spec.ts:6.6.2`) route through `requireFolder`, so the single guard fixes both. Must NOT re-introduce the original "Folder not loaded" gap #498 closed.
- Acceptance is a PRE-MERGE web-e2e dispatch — `gh workflow run web-e2e.yml --ref <branch>` (web-e2e.yml is `workflow_dispatch`-enabled, checks out `inputs.ref || github.sha`) — not the post-merge `ci-e2e.yml` main-push run.

### REQ-3 — shared-folder state ownership

- Add a sibling `sharedFolderTree` keyed by `shareId` (NOT extend `folderTree`): shared folders carry a distinct `SharedWriteContext` (owner+recipient pubkeys, shareId, addShareKeys) and can collide on `ipnsName`.
- New client methods own publish + sequence bookkeeping + a `sharedFolder:updated` emission; route `useSharedWriteOps` (`uploadToSharedFolder`/`createSharedSubfolder`/`renameInSharedFolder`/`updateSharedFile`/`deleteFromSharedFolder`) through them.
- `useSharedNavigation`'s `folderChildrenRef`/`sequenceNumberRef` become event-fed projections — never written from the write hook directly (mirrors REQ-1's ownership model).

### REQ-4 — encrypt share itemName at rest (M1 security fix)

- ECIES-wrap `itemName` with the recipient pubkey, mirroring the existing `encryptedKey` flow in the same share-create path. Migrate via an ADDITIVE, NULLABLE ciphertext column; store only ciphertext server-side (`shares.service.ts:96`); decrypt client-side for display.
- **Legacy plaintext rows (decision A2): LAZY CLIENT BACKFILL.** New shares write ciphertext; a key-holding client re-encrypts each legacy plaintext row on next load. No big-bang server migration (server is zero-knowledge). Closes M1 over time. Keep the plaintext column readable only until backfilled, then stop persisting plaintext for new/updated rows.
- **Invite / share-creation flow (decision A3): INCLUDE.** Encrypt `itemName` on the invite/notification path too (`share.service.ts:117` sends the raw name today) — no plaintext path remains.

### Ordering / waves

- REQ-1 = Wave 1 (gates everything; pre-merge dispatch acceptance).
- REQ-2 gated on REQ-1 proven green.
- REQ-3 and REQ-4 are independent of each other and of REQ-2.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase spec + research

- `.planning/phases/48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata/48-RESEARCH.md` — full technical research (HIGH confidence)
- `.planning/ROADMAP.md` — Phase 48 Goal + REQ-1..REQ-4

### SDK / web

- `packages/sdk/src/client.ts` — `loadFolder`, `ensureFolderLoaded`, `requireFolder`, `deleteToBin`, `restoreFromBin`, version-restore, `publishWithCas`, `folder:updated`
- `packages/sdk/src/share/` — shared-write functions + `SharedWriteContext`
- `apps/web/src/hooks/useSharedWriteOps.ts`, `useSharedNavigation.ts`, `useFolderNavigation.ts`, `apps/web/src/lib/sdk-provider.ts`

### API / crypto / migration

- `apps/api/src/shares/entities/share.entity.ts`, `apps/api/src/shares/shares.service.ts`, `apps/web/src/services/share.service.ts`
- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — TypeORM migration discipline
- `CLAUDE.md` — security rules (ECIES key wrapping, AES-256-GCM, server zero-knowledge), the `pnpm api:generate` requirement after API entity/DTO changes, terminology table

</canonical_refs>

<specifics>

## Specific Ideas

- REQ-4 changes the shares entity/DTO → MUST run `pnpm api:generate` and commit the regenerated `@cipherbox/api-client` files (pre-commit hook verifies).
- Migration command: `pnpm --filter @cipherbox/api migration:run` (TypeORM, `-d src/data-source.ts`); new migration file under `apps/api/src/migrations/` following the existing timestamp-prefixed naming.
- TDD mode ON: unit-test the REQ-1 reconcile guard, the ECIES wrap/unwrap, and the lazy-backfill decision logic; the bin/version web-e2e specs are the integration gate.

</specifics>

<deferred>

## Deferred Ideas

- CRDT-IPNS-inbox serverless share discovery (#2) — would subsume REQ-4 but is long-horizon research; NOT in this phase.

</deferred>

---

Phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata. Context gathered 2026-06-16 via plan-phase (research + user policy decisions A2=lazy-backfill, A3=include-invite-flow).
