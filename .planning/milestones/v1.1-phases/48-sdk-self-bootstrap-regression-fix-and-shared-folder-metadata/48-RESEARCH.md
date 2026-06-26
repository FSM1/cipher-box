# Phase 48: SDK self-bootstrap regression fix and shared-folder/metadata consolidation - Research

**Researched:** 2026-06-16
**Domain:** TypeScript SDK state management (IPNS sequence reconciliation), monorepo web-hook cleanup, NestJS/TypeORM share-metadata encryption + migration
**Confidence:** HIGH (all findings grounded in current source; no external packages introduced)

## Summary

This is an internal-refactor + correctness/security phase across `packages/sdk`, `packages/sdk-core`, `apps/web`, and `apps/api`. No new dependencies are added — every primitive needed (ECIES `wrapKey`/`unwrapKey`, the `publishWithCas` CAS engine, the `folderTree` + `folder:updated` event model, the `FolderState.sequenceNumber` clock) already exists in the codebase from Phases 44/47/489. The work is to (1) fix a P0 regression PR #498 introduced, (2) delete the web seeders that fix made redundant, (3) extend the SDK's single-ownership state model to shared folders, and (4) encrypt the last plaintext share-metadata field.

The P0 regression is precisely understood and verified against current source: `loadFolder` (`client.ts:385`) calls `this.folderTree.set(ipnsName, state)` **unconditionally**. When `requireFolder → ensureFolderLoaded` self-bootstraps a folder that is missing from `folderTree` (post-reload / never-navigated), it walks from root via IPNS and `loadFolder`s each folder — but IPNS reads lag a just-written sequence, so a fresher in-memory entry gets clobbered by a stale snapshot. The fix is a sequence-guarded `loadFolder` plus an `ensureFolderLoaded` short-circuit, mirroring the sequence-as-version-clock pattern from PR #489.

**Primary recommendation:** Make `loadFolder` reconcile on `sequenceNumber` (never overwrite a newer in-memory entry), keep `ensureFolderLoaded`'s existing top-level short-circuit, and add the same guard inside the DFS so an already-loaded subfolder is never re-resolved. For REQ-3, **add a sibling `sharedFolderTree` keyed by share** (not extend `folderTree`) — rationale below. For REQ-4, accept that the server (zero-knowledge) cannot re-encrypt existing plaintext names, so the migration must add a nullable ciphertext column and a **lazy client-side backfill**, not a server-side data migration.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
| ---------- | ------------ | -------------- | --------- |
| Folder-state reconciliation (REQ-1) | SDK (`packages/sdk` client) | — | folderTree is SDK-internal; web is a projection (Phase 47) |
| Web seed removal (REQ-2) | Frontend (`apps/web` hooks) | SDK chokepoint | seeders are web glue; SDK `requireFolder` now self-heals |
| Shared-folder state ownership (REQ-3) | SDK (`packages/sdk` client) | Frontend (event-fed projection) | mirror REQ-1 single-ownership for the share path |
| share `itemName` encryption (REQ-4) | Client (encrypt/decrypt, browser) | API (stores ciphertext only) | zero-knowledge: server never sees plaintext; ECIES wrap is client-side |
| Plaintext→ciphertext column migration (REQ-4) | Database (TypeORM migration) | Client (lazy backfill) | server cannot encrypt (no recipient privkey); schema add is additive |

## Standard Stack

No new libraries. All work uses existing in-repo modules.

### Core (existing — reuse, do not reinstall)

| Module | Location | Purpose | Why reuse |
| ------ | -------- | ------- | --------- |
| `publishWithCas<TData>` | `packages/sdk-core/src/cas.ts:38` | Generic 409-CAS retry/merge/backoff engine | The one retry engine (Phase 47); shared-folder publishes must route through it |
| `FolderTree` | `packages/sdk/src/state/folder-tree.ts:20` | SDK-internal folder state map (key-zeroing on clear/delete) | The single owner of folder state; `sharedFolderTree` should be a second instance |
| `FolderState` | `packages/sdk/src/types.ts:110` | `{ ipnsName, folderKey, ipnsKeypair, sequenceNumber, children, metadata, lastLoadedAt }` | Carries the `sequenceNumber` clock the reconcile compares on |
| `wrapKey`/`unwrapKey` | `packages/crypto/src/ecies/{encrypt,decrypt}.ts` | ECIES (eciesjs) over arbitrary bytes | `itemName` encryption mirrors the existing `encryptedKey` flow exactly |
| `SdkEventEmitter` / `folder:updated` | `packages/sdk/src/events.ts` | Event bus the web store projects from | shared path needs an analogous emission |

### Test framework

| Package | Framework | Command |
| ------- | --------- | ------- |
| `packages/sdk`, `packages/sdk-core` | Vitest 3.x [VERIFIED: package.json] | `pnpm --filter @cipherbox/sdk test` |
| `apps/api` | Jest 29 [VERIFIED: package.json] | `pnpm --filter @cipherbox/api test` |
| web-e2e | Playwright (`tests/web-e2e/`) | `gh workflow run web-e2e.yml --ref <branch>` (workflow_dispatch) |

## Package Legitimacy Audit

> Not applicable — this phase installs **zero** external packages. All primitives are existing in-repo modules. No registry verification required.

## Architecture Patterns

### System Architecture Diagram

```
REQ-1 (P0 reconcile):
  mutation (deleteToBin / restoreFromBin / restoreFileVersion)
        │
        ▼
  requireFolder(ipnsName)  ── present in folderTree? ──► return in-memory (fresh)
        │ (missing)
        ▼
  ensureFolderLoaded ── DFS from root ── loadFolder(child)
        │                                       │
        │                              ┌────────▼─────────┐
        │                              │ RECONCILE GATE   │  ← NEW
        │                              │ existing.seq ≥    │
        │                              │ resolved.seq ?    │
        │                              └──┬───────────┬───┘
        │                          keep in-mem    set from IPNS
        ▼                          (no clobber)   (was absent)
  publish on freshest snapshot ──► IPNS CAS (publishWithCas)

REQ-3 (shared single-ownership):
  useSharedWriteOps.<op>()
        │
        ▼
  client.uploadToSharedFolder(shareId, ...) ── owns publish + seq bookkeeping
        │                                          via sharedFolderTree.get(shareId)
        ▼
  publishWithCas ──► emit 'sharedFolder:updated' {shareId, children, sequenceNumber}
        │
        ▼
  useSharedNavigation projection: folderChildrenRef/sequenceNumberRef set FROM event only

REQ-4 (itemName at rest):
  ShareDialog → wrapKey(utf8(itemName), recipientPubKey) → hex
        │
        ▼  POST /shares { itemNameEncrypted: <hex>, encryptedKey: <hex>, ... }
  API stores ciphertext only (bytea) ── never sees plaintext
        │
        ▼  recipient GET /shares → decrypt client-side (unwrapKey) → display
```

### Pattern 1: Sequence-guarded loadFolder (REQ-1 — the minimal fix)

**What:** Before `folderTree.set`, compare the resolved IPNS `sequenceNumber` against any existing in-memory entry; keep the fresher one.
**When to use:** Every `loadFolder` call (it is the only writer the self-bootstrap path uses).
**Minimal diff (conceptual):**

```typescript
// packages/sdk/src/client.ts loadFolder(), replacing the unconditional set at ~385
const existing = this.folderTree.get(ipnsName);
if (existing && existing.sequenceNumber >= result.sequenceNumber) {
  // In-memory entry is at least as fresh as the IPNS snapshot — do NOT clobber.
  // (IPNS reads lag a just-written sequence; #489 sequence-as-clock invariant.)
  this.emitter.emit({ type: 'folder:loaded', folderId: ipnsName, ipnsName,
    children: existing.children, sequenceNumber: existing.sequenceNumber });
  return existing;
}
const state: FolderState = { ipnsName, folderKey, ipnsKeypair,
  sequenceNumber: result.sequenceNumber, children: result.metadata.children,
  metadata: result.metadata, lastLoadedAt: Date.now() };
this.folderTree.set(ipnsName, state);
// ...existing emit + return
```

**Why this also fixes both specs:** `deleteToBin`/`restoreFromBin` (`client.ts:1675,1718`) and `restoreFileVersion` (`client.ts:1392`) all call `requireFolder` first. With the guard, a folder already advanced in-memory by a prior write in the same session is never reset to a stale IPNS snapshot, so the parent republish and version-restore compose on top of the freshest local children/sequence.

**`ensureFolderLoaded` companion change:** The top-level short-circuit (`client.ts:422-423` — `if (existing) return existing`) already exists and is correct; keep it. The DFS loop (`client.ts:454-455`) already checks `folderTree.get(child.ipnsName)` before loading — but because the guard now lives **inside** `loadFolder`, even a redundant `loadFolder` on an already-fresh child is safe. No structural change to the DFS is required beyond the `loadFolder` guard; optionally add an explicit `if (this.folderTree.has(child.ipnsName)) { push existing; continue; }` for clarity/perf.

### Pattern 2: sharedFolderTree as a sibling map (REQ-3 — DECISION)

**Decision: add a separate `sharedFolderTree`, keyed by `shareId`, NOT extend the existing `folderTree`.**

**Rationale (firm):**

1. **Distinct key/context model.** Owned folders carry one keypair the user fully controls. Shared folders carry `SharedWriteContext` (`shared-write.ts:58`): an `ownerPublicKey` (keys wrap for owner), a separate `recipientPublicKey` (share_keys wrap for recipient), a `shareId`, and an `addShareKeysFn` callback. `FolderState` has no slot for these. Cramming them into `folderTree` would either widen `FolderState` with share-only optional fields (polluting the owned path) or require a discriminated union — more churn than a sibling map.
2. **Keying.** Shared folders are addressed by `shareId` in the web (`useSharedWriteOps` resolves `sharedItems.find(s => s.share.shareId === currentShareId)`), and the same physical `ipnsName` can be reached both as an owned folder and via a share — so an `ipnsName`-keyed map would collide. Keying by `shareId` (or `shareId:ipnsName` for subfolder navigation within a share) avoids this.
3. **Mirror, don't merge.** The win the brief wants is the *same single-ownership discipline*, not literal map reuse. A `SharedFolderTree` class can mirror `FolderTree` (it can even be the same class with a `SharedFolderState` value type) and emit a parallel `sharedFolder:updated` event. This keeps the owned-path guarantees from REQ-1 untouched while giving the share path identical event-fed projection semantics.

**New client methods (design):** `uploadToSharedFolder`, `createSharedSubfolder`, `renameInSharedFolder`, `updateSharedFile`, `deleteFromSharedFolder` move onto the client. Each:

- reads `{ children, sequenceNumber }` from `sharedFolderTree.get(shareId)` (not from a web ref),
- delegates the actual write to the existing `packages/sdk/src/share/shared-write.ts` functions (which already return `{ publishedChildren, newSequenceNumber }`),
- writes the returned `publishedChildren`/`newSequenceNumber` back into `sharedFolderTree`,
- emits `sharedFolder:updated { shareId, ipnsName, children, sequenceNumber }`.

**Web projection:** `useSharedNavigation`'s `folderChildrenRef`/`sequenceNumberRef` (`useSharedWriteOps.ts:40-41,143-146`) stop being written by the write hook; instead a subscription to `sharedFolder:updated` writes them. The write hook calls `client.uploadToSharedFolder(shareId, ...)` and reads nothing back. This is the exact transform Phase 47 applied to `useFileOperations`/`useFileVersions` for the owned path.

### Pattern 3: ECIES itemName at rest (REQ-4)

**What:** `itemName` is wrapped with the recipient's secp256k1 public key (the same key already used for `encryptedKey`) before leaving the browser.
**Where encrypt happens:** `apps/web/src/components/file-browser/ShareDialog.tsx:338,351` (the two `itemName: item.name` sites) → wrap with `recipientPublicKey` → pass hex to `createShare`. Same site already has the recipient pubkey (it wraps `encryptedKey` there).
**Where decrypt happens:** wherever `share.itemName` is read for display — `SharedListRow.tsx:48`, `useSharedNavigationActions.ts:134,163` (breadcrumbs), `SharedFileBrowser.tsx:339` (`isTextFile(share.itemName)`), the share store (`share.store.ts:12,31`). Decrypt with the user's vault private key on load and project the plaintext into the store so display sites stay unchanged.
**Invite path also affected:** `create-invite.dto.ts:65` carries `itemName` too — REQ-4 scope must include the invite flow (`invite.service.ts:189`) or explicitly defer it (recommend include; it is the same wrap).

### Anti-Patterns to Avoid

- **Server-side itemName backfill.** The server has no recipient private key — it physically cannot encrypt existing plaintext names. Do NOT write a TypeORM `UPDATE` that encrypts. Use a nullable ciphertext column + lazy client backfill (see Pitfall 3).
- **Extending `folderTree` for shared state.** Couples the owned-path REQ-1 invariant to share concerns (see Pattern 2 rationale).
- **Reading `folderChildrenRef`/`sequenceNumberRef` back into the SDK.** Refs become write-only-by-event projections; the SDK is the source of truth.
- **Blindly `folderTree.set()` anywhere on the bootstrap path.** That is the regression. Every set on a possibly-loaded folder must be sequence-guarded.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| ------- | ----------- | ----------- | --- |
| 409 conflict retry/merge for shared publishes | A second retry loop in client share methods | `publishWithCas` (`cas.ts:38`) via the existing `shared-write.ts` functions | One retry engine (Phase 47 consolidated this) |
| Sequence reconciliation | A timestamp/`lastLoadedAt` comparison | `sequenceNumber` (bigint) comparison | IPNS sequence is the canonical monotonic clock (#489) |
| ECIES over itemName | New AES wrapper | `wrapKey`/`unwrapKey` (eciesjs) | Identical to the audited `encryptedKey` path |
| Key-zeroing folder state | Manual `.fill(0)` in new map | `FolderTree`/`SharedFolderTree` class | clear()/delete() already zero key material (CLAUDE.md rule) |

**Key insight:** Phase 47 already built the single-ownership + single-CAS-engine machinery for the owned path. REQ-1 and REQ-3 are *applications* of that machinery, not new infrastructure.

## Runtime State Inventory

> This phase is partly a refactor (REQ-2 deletes code) and partly a schema migration (REQ-4). The owned-folder paths touch no external datastore. REQ-4 touches the DB.

| Category | Items Found | Action Required |
| -------- | ----------- | --------------- |
| Stored data | `shares.item_name` column (varchar 255, plaintext) in Postgres holds plaintext display names for all existing shares (`share.entity.ts:49-50`). | Schema: add nullable `item_name_encrypted bytea`. Data: **cannot** be server-migrated (zero-knowledge) — lazy client backfill on next owner access, or leave legacy plaintext readable until re-share. |
| Live service config | None — no UI/DB-resident config references the renamed/changed code paths. | None — verified: REQ-1/2/3 are in-process SDK/web state only. |
| OS-registered state | None — no OS-level registration involved. | None. |
| Secrets/env vars | None — no secret key names change. ECIES uses existing vault keypair. | None. |
| Build artifacts | `packages/sdk` and `packages/sdk-core` `dist/` must be rebuilt after SDK public-API changes (new client methods) before web typecheck (cross-package dist staleness — see MEMORY). `packages/api-client` regenerates via `pnpm api:generate` after the share DTO change (REQ-4). | `pnpm build` on sdk-core→sdk before web typecheck; `pnpm api:generate` after share DTO/entity change. |

**Canonical question — after all files are updated, what runtime systems still hold the old string?** Only the Postgres `shares.item_name` plaintext column (REQ-4). There is no cached/registered copy of the SDK state to migrate (it is rebuilt on each client init).

## Common Pitfalls

### Pitfall 1: Reconcile gate that breaks the #498 fix it is patching

**What goes wrong:** Over-correcting so `ensureFolderLoaded` refuses to load a genuinely-absent folder, re-introducing the original "Folder not loaded" failure #498 fixed.
**Why it happens:** Conflating "already loaded, keep it" with "never loaded, must resolve."
**How to avoid:** The guard only suppresses the **set** when an entry already exists AND is `>=` the resolved sequence. A missing entry still loads normally. Keep `ensureFolderLoaded`'s `if (existing) return existing` and the DFS's `folderTree.get(child)` check intact.
**Warning signs:** `ensure-folder-loaded.test.ts` (existing) goes red, or the cold-reload-then-mutate-into-never-navigated-subfolder manual check throws "Folder not loaded".

### Pitfall 2: `cross-package dist staleness` on the new client methods

**What goes wrong:** Web typecheck passes against a stale `packages/sdk/dist`, missing new `uploadToSharedFolder` etc.; CI fails.
**Why it happens:** sdk/web typecheck the built `dist`, not source (MEMORY: cross-package-dist-staleness).
**How to avoid:** Rebuild `@cipherbox/sdk-core` then `@cipherbox/sdk` dist before running web typecheck/E2E.

### Pitfall 3: Trying to migrate plaintext itemName server-side

**What goes wrong:** A migration `UPDATE shares SET item_name_encrypted = encrypt(item_name)` is impossible — the server has no recipient private key (zero-knowledge), violating CLAUDE.md rule 6.
**Why it happens:** Treating REQ-4 like a normal column-type migration.
**How to avoid:** Migration is **additive only** (`ADD COLUMN IF NOT EXISTS item_name_encrypted bytea` nullable). New shares write ciphertext + NULL plaintext. Existing rows keep plaintext until re-shared or lazily backfilled client-side by the owner (who can re-wrap with the stored recipient pubkey). Decide in planning: (a) lazy backfill on owner's next share-list load, or (b) accept legacy plaintext until natural re-share. Recommend (a) for the security finding to be fully closed, but it requires the owner to have the recipient pubkey (it is in the share row).

### Pitfall 4: Forgetting `pnpm api:generate` after the share DTO change

**What goes wrong:** `packages/api-client` and `apps/web` drift from the API; pre-commit `check-api-client.sh` blocks the commit.
**How to avoid:** After editing `create-share.dto.ts` / `share-response.dto.ts` / entity, run `pnpm api:generate` and stage `packages/api-client/src/generated/`, `packages/api-client/src/models/`, `packages/api-client/openapi.json` (CLAUDE.md API workflow).

### Pitfall 5: web vitest only runs `*.test.ts`

**What goes wrong:** A `*.spec.ts` SDK-style test in `apps/web` is silently skipped (MEMORY: web-vitest-include-test-only). SDK package tests are `*.test.ts` already — keep that convention.

## Code Examples

### REQ-1 reconcile (verified shape from current source)

```typescript
// Source: packages/sdk/src/client.ts:361-396 (loadFolder) + types.ts:110 (FolderState.sequenceNumber: bigint)
// Guard inserted before this.folderTree.set(ipnsName, state) at :385
const existing = this.folderTree.get(ipnsName);
if (existing && existing.sequenceNumber >= result.sequenceNumber) return existing;
```

### REQ-4 migration (mirror of AddWritableShares template)

```typescript
// Source pattern: apps/api/src/migrations/1743000000000-AddWritableShares.ts (bytea additive column)
// New file: apps/api/src/migrations/<ts>-EncryptShareItemName.ts
public async up(q: QueryRunner) {
  await q.query(`ALTER TABLE "shares" ADD COLUMN IF NOT EXISTS "item_name_encrypted" bytea`);
  // NO data UPDATE — server cannot encrypt (zero-knowledge). Lazy client backfill.
}
public async down(q: QueryRunner) {
  await q.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "item_name_encrypted"`);
}
```

### REQ-4 ECIES (existing primitive, arbitrary bytes)

```typescript
// Source: packages/crypto/src/ecies/encrypt.ts:26-54 (wrapKey → eciesjs encrypt)
import { wrapKey, unwrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
const itemNameEncrypted = bytesToHex(await wrapKey(new TextEncoder().encode(itemName), recipientPublicKey));
// recipient display:
const itemName = new TextDecoder().decode(await unwrapKey(hexToBytes(row.itemNameEncrypted), vaultPrivateKey));
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| ------------ | ---------------- | ------------ | ------ |
| Web pre-seeds folderTree via `ensureFolderRegistered` before every mutation | SDK `requireFolder` self-bootstraps from root IPNS key | PR #498 (this regressed; REQ-1 fixes, REQ-2 removes seeders) | ~16 seed sites + 1 web key-unwrap become dead |
| Web owns shared-folder children/seq in refs | SDK `sharedFolderTree` owns it, web projects from events | REQ-3 (this phase) | `useSharedNavigation` refs become event-fed |
| Separate file/folder CAS loops | One `publishWithCas` engine | Phase 47 / PR #494 | shared methods reuse it |
| Plaintext `shares.item_name` | ECIES ciphertext at rest | REQ-4 (this phase) | closes Phase-14 finding M1 |

**Deprecated/outdated after this phase:**

- `apps/web/src/lib/sdk-provider.ts:96` `ensureFolderRegistered` and all ~16 callers (REQ-2).
- `apps/web/src/hooks/useFolderNavigation.ts:233-240` duplicate web-side key-unwrap (REQ-2).

## Phase Requirements

| ID | Description | Research Support |
| -- | ----------- | ---------------- |
| REQ-1 | P0: non-clobbering self-bootstrap; reconcile on sequenceNumber; both web-e2e specs green; PRE-MERGE dispatch | Pattern 1 + Code Example; exact guard at `client.ts:385`; `FolderState.sequenceNumber` clock confirmed; bin paths `client.ts:1669-1741`, version-restore `client.ts:1374-1433` |
| REQ-2 | Delete ~16 `ensureFolderRegistered` seeders + `useFolderNavigation` unwrap | Call-site inventory (5 files, 16 sites) + definition `sdk-provider.ts:96`; `useBin` confirmed never had it; gated on REQ-1 proven green |
| REQ-3 | SDK owns shared-folder state; route `useSharedWriteOps` through client; refs become projections | Pattern 2 DECISION (sibling `sharedFolderTree` keyed by shareId); `SharedWriteContext` shape `shared-write.ts:58`; existing return `{publishedChildren,newSequenceNumber}`; web write-back sites `useSharedWriteOps.ts:143-146` |
| REQ-4 | ECIES-encrypt `itemName` at rest; migrate column; client decrypt-for-display; api:generate | Pattern 3 + migration template + ECIES primitive; entity `share.entity.ts:49`, service `shares.service.ts:96`, web `share.service.ts:117`, DTO `create-share.dto.ts:78`, display sites enumerated; **zero-knowledge migration constraint surfaced** |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| - | ----- | ------- | ------------- |
| A1 | `sequenceNumber` is reliably monotonic per folder and the in-memory entry always reflects the latest local write (so `>=` is a safe keep-condition) | Pattern 1 | If a local write fails to advance `sequenceNumber`, the guard could keep stale local state; mitigated by #489 establishing this invariant — verify against `publishWithCas` newSequenceNumber bookkeeping during planning |
| A2 | Lazy client-side backfill is acceptable for legacy plaintext `itemName` (vs. forcing immediate re-share) | Pitfall 3 / REQ-4 | If product wants zero plaintext immediately, legacy rows need a forced owner-side re-encryption pass — larger scope. Needs a product/security decision (no CONTEXT.md exists for this phase). |
| A3 | The invite flow (`create-invite.dto.ts:65`, `invite.service.ts:189`) is in scope for itemName encryption | Pattern 3 | If deferred, an invite still leaks plaintext itemName — partial closure of M1. Recommend include. |
| A4 | Keying `sharedFolderTree` by `shareId` (not ipnsName) avoids owned/shared collision | Pattern 2 | If subfolder navigation within a share needs per-ipns entries, key becomes `shareId:ipnsName` — minor design adjustment |

## Open Questions

1. **Legacy plaintext itemName disposition (REQ-4).**
   - What we know: server cannot re-encrypt; migration is additive-nullable.
   - What's unclear: whether to lazily backfill (owner re-wraps with stored recipient pubkey on next share-list load) or accept plaintext until natural re-share.
   - Recommendation: lazy backfill to fully close M1; gate on a planning decision since no CONTEXT.md exists. Either way the **schema migration and new-share encryption are unconditional**.

2. **Invite-flow scope (REQ-4).**
   - Recommendation: include `create-invite` itemName encryption in the same wave; it is the identical wrap and otherwise leaves a plaintext leak.

3. **`sharedFolder:updated` event vs. reuse `folder:updated`.**
   - Recommendation: a distinct event type carrying `shareId`, so the owned-path projection and shared-path projection stay decoupled. Low risk; confirm event union shape in `events.ts` during planning.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
| ---------- | ----------- | --------- | ------- | -------- |
| Vitest | SDK unit tests (REQ-1/3) | ✓ | 3.x | — |
| Jest | API tests (REQ-4 migration/service) | ✓ | 29 | — |
| Playwright web-e2e | REQ-1 pre-merge gate | ✓ (CI workflow_dispatch) | — | none — gate is mandatory |
| `gh` CLI | dispatch web-e2e.yml | ✓ | — | prefix `env -u GITHUB_TOKEN` (MEMORY) |
| Postgres | REQ-4 migration apply | ✓ (local dev stack) | 15 | — |

**Missing dependencies with no fallback:** none — all tooling present.

## Validation Architecture

### Test Framework

| Property | Value |
| -------- | ----- |
| Framework | Vitest 3.x (`packages/sdk`, `packages/sdk-core`); Jest 29 (`apps/api`); Playwright (`tests/web-e2e`) |
| Config file | `packages/sdk/vitest.config.ts`, `apps/api` jest config in package.json, Playwright `tests/web-e2e/playwright.config.ts` |
| Quick run command | `pnpm --filter @cipherbox/sdk test` |
| Full suite command | `pnpm --filter @cipherbox/sdk test && pnpm --filter @cipherbox/api test` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
| ------ | -------- | --------- | ----------------- | ------------ |
| REQ-1 | loadFolder keeps fresher in-memory entry over stale IPNS snapshot | unit | `pnpm --filter @cipherbox/sdk test loadFolder` | ❌ Wave 0 (new `client-load-reconcile.test.ts`) |
| REQ-1 | ensureFolderLoaded still loads genuinely-absent folder (no regression of #498) | unit | `pnpm --filter @cipherbox/sdk test ensure-folder-loaded` | ✅ `ensure-folder-loaded.test.ts` |
| REQ-1 | bin-restore-after-reload green | e2e | `gh workflow run web-e2e.yml --ref <branch>` | ✅ `bin-restore-after-reload.spec.ts` |
| REQ-1 | version-restore (6.6.2) green | e2e | (same dispatch) | ✅ `full-workflow.spec.ts` |
| REQ-3 | client.uploadToSharedFolder owns publish + emits sharedFolder:updated | unit | `pnpm --filter @cipherbox/sdk test shared` | ⚠️ extend `shared-write.test.ts` |
| REQ-3 | shared write hook reads nothing back from result (projection-only) | unit (web) | `pnpm --filter @cipherbox/web test` | ❌ Wave 0 |
| REQ-4 | wrapKey(itemName)/unwrapKey round-trips | unit | `pnpm --filter @cipherbox/crypto test` | ⚠️ extend `ecies.test.ts` |
| REQ-4 | migration adds nullable bytea, no data loss | integration (api) | `pnpm --filter @cipherbox/api test` | ❌ Wave 0 |
| REQ-4 | service stores ciphertext only (no plaintext persisted) | unit (api) | `pnpm --filter @cipherbox/api test shares` | ⚠️ extend shares.service spec |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/sdk test` (and the touched package's test).
- **Per wave merge:** full SDK + API suites; rebuild sdk-core→sdk dist before web typecheck.
- **Phase gate (REQ-1):** **PRE-MERGE** `gh workflow run web-e2e.yml --ref <fix-branch>` must be green before REQ-2 starts and before merge — this is the explicit gate that #498's post-merge-only run missed.

### Wave 0 Gaps

- [ ] `packages/sdk/src/__tests__/client-load-reconcile.test.ts` — REQ-1 sequence-guard unit (TDD; write red first)
- [ ] API migration test + shares.service ciphertext-only assertion — REQ-4
- [ ] web shared-write projection test — REQ-3
- [ ] Extend `ecies.test.ts` for itemName round-trip — REQ-4

### TDD applicability (TDD mode ENABLED)

| Work | Unit-testable (TDD red-first) | Integration/E2E |
| ---- | ----------------------------- | --------------- |
| REQ-1 reconcile logic | ✅ pure sequence comparison in `loadFolder`/`ensureFolderLoaded` | bin/version specs (web-e2e, post-implementation gate) |
| REQ-3 client shared methods | ✅ publish + event emission with mocked sdk-core | web projection wiring (web vitest + manual) |
| REQ-4 ECIES wrap/unwrap | ✅ crypto round-trip | — |
| REQ-4 migration | ✅ schema assertion (jest) | apply-on-startup verify |
| REQ-2 seeder deletion | — (deletion; covered by REQ-1 e2e green) | cold-reload manual check per former call site |

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
| ------------- | ------- | ---------------- |
| V2 Authentication | no | unchanged |
| V3 Session Management | no | unchanged |
| V4 Access Control | yes | share authorization unchanged; itemName ciphertext readable only by recipient/owner |
| V5 Input Validation | yes | DTO `@Matches(/^[0-9a-fA-F]+$/)` hex validation on `itemNameEncrypted` (mirror `encryptedKey`) |
| V6 Cryptography | yes | ECIES via existing `wrapKey` (eciesjs) — never hand-roll; AES-256-GCM unchanged |
| V9/V8 Data Protection | yes | zero-knowledge: server stores only ciphertext; **server cannot migrate plaintext** |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
| ------- | ------ | ------------------- |
| Server learns display names (info disclosure) | Information Disclosure | ECIES-wrap itemName client-side; store bytea ciphertext only (REQ-4) |
| Stale-state overwrite resurrects deleted items / wrong version | Tampering | sequence-guarded loadFolder (REQ-1) — never clobber newer in-memory state |
| Plaintext hex injection in itemNameEncrypted DTO | Tampering | hex-only `@Matches` validation mirroring `encryptedKey` |
| Key material left in memory | Information Disclosure | `FolderTree`/`SharedFolderTree` clear()/delete() zero keys (CLAUDE.md rule 9) |

## Project Constraints (from CLAUDE.md)

- **Terminology:** use `publicKey`/`privateKey`/`folderKey`/`ipnsName`/`sequenceNumber`/`encryptedIpnsPrivateKey` exactly (table in CLAUDE.md). Prefer string-literal unions over TS enums.
- **Security:** never store/log `privateKey`; always ECIES key-wrapping (`wrapKey`); AES-256-GCM for content; server is zero-knowledge (rule 6) — **this directly constrains REQ-4 migration** (no server-side encrypt). Clear sensitive `Uint8Array` after use.
- **Binary data:** `Uint8Array`, Web Crypto; `camelCase` API fields, `snake_case` DB columns (so `item_name_encrypted` column ↔ `itemNameEncrypted` field).
- **API workflow:** run `pnpm api:generate` after the share DTO/entity/controller change and commit `packages/api-client/src/generated/`, `models/`, `openapi.json` (pre-commit `check-api-client.sh` enforces).
- **DB protocol:** `synchronize` off; migration must be idempotent (`IF NOT EXISTS`/`IF EXISTS`); create-before-modify timestamp ordering; no data loss — additive nullable column satisfies this.
- **Git:** feature branch (`feat/{slug}`), never push to main; conventional commits, no parens in subject; `env -u GITHUB_TOKEN` for `gh`.
- **markdownlint** on commit: headings not bold-as-heading, blank lines around code/lists.

## Sources

### Primary (HIGH confidence)

- `packages/sdk/src/client.ts` (loadFolder :361-396, ensureFolderLoaded :421-491, requireFolder :504-508, deleteToBin/restoreFromBin :1669-1741, restoreFileVersion :1374-1433, registerFolder :304-324) — exact regression + fix sites
- `packages/sdk/src/state/folder-tree.ts`, `packages/sdk/src/types.ts:110` — FolderTree + FolderState.sequenceNumber clock
- `packages/sdk-core/src/cas.ts:38` — publishWithCas engine
- `packages/sdk/src/share/shared-write.ts:58,105+` — SharedWriteContext + return shapes
- `apps/web/src/hooks/useSharedWriteOps.ts:40-146` — current ref write-back pattern (REQ-3 transform target)
- `apps/web/src/lib/sdk-provider.ts:96` + 16 callers — REQ-2 inventory
- `apps/api/src/shares/{entities/share.entity.ts:49,shares.service.ts:96,dto/create-share.dto.ts:78}`, `apps/web/src/services/share.service.ts:105` — REQ-4 sites
- `apps/api/src/migrations/1743000000000-AddWritableShares.ts`, `1740500000000-BackfillIpnsSequenceNumbers.ts` — migration templates
- `packages/crypto/src/ecies/encrypt.ts:26` — wrapKey over arbitrary bytes
- `.github/workflows/web-e2e.yml:3-9,59` — workflow_dispatch `inputs.ref || github.sha`
- `docs/DATABASE_EVOLUTION_PROTOCOL.md` §2 — migration discipline

### Secondary (MEDIUM confidence)

- Project MEMORY: cross-package dist staleness, web-vitest-test-only, web/SDK folder-state desync (#489), gh GITHUB_TOKEN

### Tertiary (LOW confidence)

- None — all claims grounded in current source.

## Metadata

**Confidence breakdown:**

- REQ-1 fix design: HIGH — exact source lines + existing test + verified sequence-clock invariant
- REQ-2 inventory: HIGH — grep-verified all call sites
- REQ-3 decision: HIGH — grounded in SharedWriteContext shape + existing return contract; sibling-map is the lower-churn mirror
- REQ-4: HIGH on mechanism, MEDIUM on legacy-data policy (A2 — needs product decision)

**Research date:** 2026-06-16
**Valid until:** 2026-07-16 (stable internal code; re-verify line numbers if `client.ts`/share files change before planning)
