# Phase 48: SDK self-bootstrap regression fix and shared-folder/metadata consolidation - Pattern Map

**Mapped:** 2026-06-16
**Files analyzed:** 12 (modified) + 4 (created)
**Analogs found:** 16 / 16

This phase adds zero new dependencies. Every new file/method mirrors an existing in-repo analog (Phase 47 single-ownership model, the `encryptedKey` ECIES wrap, the `AddWritableShares` migration shape). Line numbers below are verified against current source on 2026-06-16.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| ----------------- | ---- | --------- | -------------- | ------------- |
| `packages/sdk/src/client.ts` (REQ-1 guard in `loadFolder`) | service (SDK client) | state-reconcile / event-driven | self (`loadFolder`/`ensureFolderLoaded` :361-491) | exact (in-place) |
| `packages/sdk/src/__tests__/client-load-reconcile.test.ts` (NEW) | test | unit | `packages/sdk/src/__tests__/ensure-folder-loaded.test.ts` | role-match |
| `packages/sdk/src/client.ts` (REQ-3 new shared methods) | service (SDK client) | request-response → publish + event | owned methods `replaceFile`/`restoreFileVersion`/`deleteToBin` + `folder:updated` emit | exact |
| `packages/sdk/src/state/shared-folder-tree.ts` (NEW, optional) | store | in-memory map | `packages/sdk/src/state/folder-tree.ts` (`FolderTree`) | exact |
| `packages/sdk/src/events.ts` (REQ-3 `sharedFolder:updated`) | config (event union) | event-driven | `folder:updated` member :29-35 | exact |
| `apps/web/src/hooks/useSharedWriteOps.ts` (REQ-3 transform) | hook | request-response → event projection | Phase 47 transform of `useFileOperations`/`useFileVersions` | role-match |
| `apps/web/src/hooks/useSharedNavigation.ts` (REQ-3 refs → event-fed) | hook | event-driven projection | `useFolderNavigation` event subscription | role-match |
| `apps/web/src/lib/sdk-provider.ts` + ~16 callers (REQ-2 deletion) | utility | n/a (deletion) | — (removal; gated on REQ-1 green) | n/a |
| `apps/web/src/hooks/useFolderNavigation.ts` :233-240 (REQ-2 unwrap removal) | hook | n/a (deletion) | — | n/a |
| `apps/api/src/migrations/<ts>-EncryptShareItemName.ts` (NEW) | migration | DDL (additive) | `1743000000000-AddWritableShares.ts` | exact |
| `apps/api/src/shares/entities/share.entity.ts` (REQ-4 column) | model | CRUD | `encryptedKey`/`encryptedIpnsKey` bytea columns :57,72 | exact |
| `apps/api/src/shares/shares.service.ts` :96 (REQ-4 store ciphertext) | service | CRUD | existing `encryptedKey` persist path | exact |
| `apps/api/src/shares/dto/create-share.dto.ts` :78 (REQ-4 field) | model (DTO) | request-response | `encryptedKey` hex `@Matches` field | exact |
| `apps/web/src/services/share.service.ts` :117 (REQ-4 wrap) | service | transform | `encryptedKey` wrap on same `createShare` path | exact |
| `apps/web/src/components/file-browser/ShareDialog.tsx` :338,351 (REQ-4 encrypt) | component | transform | adjacent `encryptedKey` wrap site | exact |
| `packages/crypto/src/__tests__/ecies.test.ts` (REQ-4 extend) | test | unit | existing wrapKey/unwrapKey round-trip | exact |

## Pattern Assignments

### REQ-1: `packages/sdk/src/client.ts` `loadFolder` reconcile guard (service, state-reconcile)

**Analog:** self — the unconditional `folderTree.set` at `client.ts:385`.

**Current core (lines 375-396):**
```typescript
const state: FolderState = {
  ipnsName, folderKey, ipnsKeypair,
  sequenceNumber: result.sequenceNumber,
  children: result.metadata.children,
  metadata: result.metadata,
  lastLoadedAt: Date.now(),
};
this.folderTree.set(ipnsName, state);   // <- unconditional clobber (the regression)
this.emitter.emit({ type: 'folder:loaded', folderId: ipnsName, ipnsName,
  children: result.metadata.children, sequenceNumber: result.sequenceNumber });
return state;
```

**Guard to insert immediately after `if (!result) return null;` (:373), before building `state`:**
```typescript
// IPNS reads lag a just-written sequence (#489 sequence-as-clock invariant).
// Never overwrite a fresher in-memory entry with a stale IPNS snapshot.
const existing = this.folderTree.get(ipnsName);
if (existing && existing.sequenceNumber >= result.sequenceNumber) {
  this.emitter.emit({
    type: 'folder:loaded', folderId: ipnsName, ipnsName,
    children: existing.children, sequenceNumber: existing.sequenceNumber,
  });
  return existing;
}
```

**`ensureFolderLoaded` companion (KEEP as-is — do NOT remove):**
- Top-level short-circuit `client.ts:422-423` (`const existing = this.folderTree.get(targetIpnsName); if (existing) return existing;`) — keep.
- DFS per-child check `client.ts:454` (`this.folderTree.get(child.ipnsName) ?? null`) — keep.
- No structural DFS change needed; the guard inside `loadFolder` makes a redundant child `loadFolder` safe. Optional clarity/perf: explicit `if (this.folderTree.has(child.ipnsName)) { stack.push(existing); continue; }`.

**Anti-pattern (Pitfall 1):** Do not suppress the *load* of a genuinely-absent folder — only suppress the `set` when `existing && existing.sequenceNumber >= result.sequenceNumber`. A missing entry must still resolve, or #498's "Folder not loaded" fix regresses.

**`FolderState.sequenceNumber` is `bigint`** (`packages/sdk/src/types.ts:110`) — `>=` is a native bigint compare.

**Mutation entry points that route through `requireFolder` (proves the single guard fixes both specs):** `deleteToBin`/`restoreFromBin` (`client.ts:1669-1741`), `restoreFileVersion` (`client.ts:1374-1433`).

---

### REQ-1 test: `client-load-reconcile.test.ts` (NEW, TDD red-first)

**Analog:** `packages/sdk/src/__tests__/ensure-folder-loaded.test.ts` (same dir, same `*.test.ts` convention, mocks `sdkCore.loadFolderMetadata`). Copy its mock-client setup. Assert: (a) when an in-memory entry has `sequenceNumber >= resolved`, `loadFolder` returns the existing entry and does NOT call `folderTree.set`; (b) when absent, it loads and sets normally (no #498 regression).

---

### REQ-3: new shared-folder client methods in `client.ts` (service, request-response → publish + event)

**Analog 1 (ownership + event):** owned-folder methods that read from `folderTree.get`, delegate to a sdk-core write, write the returned `{children, sequenceNumber}` back into `folderTree`, and emit `folder:updated`. The canonical emit shape (`events.ts:29-35`):
```typescript
this.emitter.emit({ type: 'folder:updated', folderId, ipnsName, children, sequenceNumber });
```

**Analog 2 (the write delegate + return contract):** `packages/sdk/src/share/shared-write.ts` functions already return `{ publishedChildren, newSequenceNumber }` and route through `publishWithCas` (`packages/sdk-core/src/cas.ts:38`). New client methods MUST delegate to these — do NOT add a second retry loop (Don't-Hand-Roll).

**Analog 3 (context shape):** `SharedWriteContext` is built by `buildSharedWriteContext` (`packages/sdk/src/share/context.ts:40`) from `SharedWriteContextParams` (`context.ts:15-29`): `{ ctx, folderKey, ipnsPrivateKey, ipnsName, sequenceNumber, children, ownerPublicKey, recipientPublicKey, shareId, addShareKeysFn }`. This is exactly why a sibling `sharedFolderTree` keyed by `shareId` is needed — `FolderState` has no slot for owner/recipient pubkeys + shareId + callback, and the same `ipnsName` can be reached both as owned and shared.

**New method shape (each of `uploadToSharedFolder`/`createSharedSubfolder`/`renameInSharedFolder`/`updateSharedFile`/`deleteFromSharedFolder`):**
```typescript
async uploadToSharedFolder(shareId: string, args: {...}) {
  const state = this.sharedFolderTree.get(shareId);   // source of truth, not a web ref
  if (!state) throw new Error('Shared folder not loaded');
  const result = await uploadToSharedFolder(buildSharedWriteContext({ ...state, children: state.children, sequenceNumber: state.sequenceNumber }), args);
  this.sharedFolderTree.set(shareId, { ...state, children: result.publishedChildren, sequenceNumber: result.newSequenceNumber });
  this.emitter.emit({ type: 'sharedFolder:updated', shareId, ipnsName: state.ipnsName,
    children: result.publishedChildren, sequenceNumber: result.newSequenceNumber });
}
```

**Web transform of `useSharedWriteOps.ts` (current write-back to remove):** lines 143-146 currently do:
```typescript
p.sequenceNumberRef.current = result.newSequenceNumber;
p.folderChildrenRef.current = result.publishedChildren;
p.setCurrentSequenceNumber(result.newSequenceNumber);
p.setFolderChildren(result.publishedChildren);
```
After REQ-3 the hook calls `client.uploadToSharedFolder(shareId, ...)` and reads NOTHING back; `folderChildrenRef`/`sequenceNumberRef` (`useSharedWriteOps.ts:40-41`) become written ONLY by a `sharedFolder:updated` subscription in `useSharedNavigation`. This is the exact Phase 47 transform applied to the owned path. The `withConflictRetry`/`resyncSharedFolder` wrapper (`:131,148-150`) is subsumed by `publishWithCas` inside the client method — drop it from the hook.

---

### REQ-3: `events.ts` `sharedFolder:updated` (config, event-driven)

**Analog:** `folder:updated` union member (`events.ts:29-35`). Add a distinct member carrying `shareId` so owned/shared projections stay decoupled (Open Question 3 recommendation):
```typescript
| {
    type: 'sharedFolder:updated';
    shareId: string;
    ipnsName: string;
    children: FolderChild[];
    sequenceNumber: bigint;
  }
```
Insert into the `SdkEvent` union (`events.ts:21-51`). Use a string-literal type (CLAUDE.md: prefer string-literal unions over enums).

---

### REQ-3: `state/shared-folder-tree.ts` (store, optional NEW)

**Analog:** `packages/sdk/src/state/folder-tree.ts` (`FolderTree` class, key-zeroing on `clear()`/`delete()` per CLAUDE.md rule 9). Either instantiate a second `FolderTree` with a `SharedFolderState` value type, or subclass. Keyed by `shareId` (not `ipnsName`) to avoid owned/shared collision (REQ-3 decision, A4). `SharedFolderState` = `FolderState` fields + the share-context fields (`ownerPublicKey`, `recipientPublicKey`, `shareId`, `addShareKeysFn`).

---

### REQ-4: `<ts>-EncryptShareItemName.ts` migration (migration, additive DDL)

**Analog:** `apps/api/src/migrations/1743000000000-AddWritableShares.ts` (verified full file). Mirror its exact shape — `name` field, `ADD COLUMN IF NOT EXISTS ... bytea` up / `DROP COLUMN IF EXISTS` down. NO data UPDATE (server is zero-knowledge, cannot encrypt — Pitfall 3).
```typescript
import { MigrationInterface, QueryRunner } from 'typeorm';

export class EncryptShareItemName<TS> implements MigrationInterface {
  name = 'EncryptShareItemName<TS>';
  public async up(q: QueryRunner): Promise<void> {
    await q.query(`ALTER TABLE "shares" ADD COLUMN IF NOT EXISTS "item_name_encrypted" bytea`);
  }
  public async down(q: QueryRunner): Promise<void> {
    await q.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "item_name_encrypted"`);
  }
}
```
Timestamp-prefixed name, newer than `1743300000000` (latest existing). Run: `pnpm --filter @cipherbox/api migration:run`.

---

### REQ-4: `share.entity.ts` column (model, CRUD)

**Analog:** `encryptedKey` (`:53-58`) and `encryptedIpnsKey` (`:67-73`) — both `@Column({ type: 'bytea', ... })`, the latter `nullable: true`. Add the nullable mirror (camelCase field ↔ snake_case column per CLAUDE.md):
```typescript
/**
 * ECIES-wrapped display name (itemName) — recipient secp256k1 pubkey.
 * Nullable: legacy rows hold plaintext in item_name until lazily backfilled.
 * Server never sees plaintext (zero-knowledge).
 */
@Column({ type: 'bytea', name: 'item_name_encrypted', nullable: true })
itemNameEncrypted!: Buffer | null;
```
Keep the existing plaintext `itemName` column (`:49-50`) readable until backfill completes (decision A2).

---

### REQ-4: ECIES wrap on share-create path (service, transform)

**Analog:** the existing `encryptedKey` flow on the SAME `createShare` path. Web `share.service.ts:105-127` already passes `encryptedKey` hex; add `itemNameEncrypted` alongside it (same shape). The actual wrap happens at the call site `ShareDialog.tsx:338,351` (the two `itemName: item.name` sites), which already holds `recipientPublicKey` for the `encryptedKey` wrap:
```typescript
import { wrapKey, unwrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
const itemNameEncrypted = bytesToHex(await wrapKey(new TextEncoder().encode(itemName), recipientPublicKey));
// recipient display: new TextDecoder().decode(await unwrapKey(hexToBytes(row.itemNameEncrypted), vaultPrivateKey))
```
DTO `create-share.dto.ts:78`: add `itemNameEncrypted` with hex `@Matches(/^[0-9a-fA-F]+$/)` mirroring `encryptedKey` (ASVS V5). Service `shares.service.ts:96`: store ciphertext only.

**Invite path (decision A3 — INCLUDE):** `apps/api/src/.../create-invite.dto.ts:65` + `invite.service.ts:189` carry raw `itemName` today — apply the identical wrap so no plaintext path remains.

**After DTO/entity change:** run `pnpm api:generate`, stage `packages/api-client/src/generated/`, `models/`, `openapi.json` (Pitfall 4, pre-commit `check-api-client.sh`).

**Lazy backfill (decision A2):** key-holding client re-wraps each legacy plaintext row on next share-list load (owner has recipient pubkey in the share row), stops persisting plaintext for new/updated rows.

## Shared Patterns

### ECIES key wrapping

**Source:** `packages/crypto/src/ecies/encrypt.ts:26` (`wrapKey` over arbitrary bytes), `decrypt.ts` (`unwrapKey`).
**Apply to:** REQ-4 itemName encrypt/decrypt and the invite path. Never hand-roll AES (CLAUDE.md rule 4 / V6). Identical to the audited `encryptedKey` path.

### IPNS sequence as the version clock

**Source:** `FolderState.sequenceNumber: bigint` (`packages/sdk/src/types.ts:110`); `publishWithCas` returns `newSequenceNumber`.
**Apply to:** REQ-1 reconcile guard AND REQ-3 shared bookkeeping. Compare on `sequenceNumber`, never `lastLoadedAt`.

### Single CAS retry engine

**Source:** `publishWithCas` (`packages/sdk-core/src/cas.ts:38`), reached via `packages/sdk/src/share/shared-write.ts`.
**Apply to:** all REQ-3 shared publishes. Do NOT add a second retry loop in client methods or keep `withConflictRetry` in the web hook.

### Event-fed web projection (Phase 47 model)

**Source:** owned path — web store/refs written only from `folder:updated`/`folder:loaded` subscriptions.
**Apply to:** REQ-3 — `useSharedNavigation` refs become write-only-by-`sharedFolder:updated`. SDK is the source of truth; never read refs back into the SDK.

### Key-zeroing state map

**Source:** `FolderTree.clear()`/`delete()` zero key material (`packages/sdk/src/state/folder-tree.ts`).
**Apply to:** REQ-3 `sharedFolderTree` (reuse/subclass `FolderTree`, CLAUDE.md rule 9).

## No Analog Found

None. Every file maps to an existing analog (Phase 47 single-ownership, `encryptedKey` ECIES, `AddWritableShares` migration).

## Metadata

**Analog search scope:** `packages/sdk/src/{client.ts,events.ts,state,share,types.ts,__tests__}`, `apps/web/src/{hooks,services,lib,components/file-browser}`, `apps/api/src/{shares,migrations}`, `packages/crypto/src/ecies`.
**Files scanned:** ~14 (all read directly; research line numbers verified accurate).
**Pattern extraction date:** 2026-06-16
