# Phase 68: Web Integration — Rotation UX and Durable Client State - Pattern Map

**Mapped:** 2026-07-01
**Files analyzed:** 11 new/modified
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `apps/web/src/services/rotation-state.service.ts` (NEW) | service | file-I/O (IndexedDB) | `apps/web/src/lib/device/identity.ts` | exact |
| `packages/sdk/src/client.ts` (`renameItem`/`moveItem`/`deleteItem`/`deleteToBin`, MODIFY) | service | CRUD + event-driven | same file's `loadFolder` anti-clobber block (L369-381) | exact (self-analog) |
| `apps/web/src/services/ipns.service.ts` (`resolveIpnsRecord`, MODIFY) | service | request-response | same file (existing passthrough, L141-149) | exact (self-analog) |
| `apps/web/src/components/NotificationToast.tsx` (MODIFY) | component | event-driven | same file (existing `[x]` dismiss button, L91-106) | exact (self-analog) |
| `apps/web/src/stores/notification.store.ts` (MODIFY) | store | event-driven | same file (existing `Notification` type + actions) | exact (self-analog) |
| `apps/web/src/stores/rotation.store.ts` (NEW) | store | event-driven | `apps/web/src/stores/notification.store.ts` | role-match |
| `apps/web/src/components/layout/RotationStatusBadge.tsx` (NEW) | component | event-driven | `apps/web/src/components/layout/AppHeader.tsx` (`.header-search-btn`) | role-match |
| `apps/web/src/components/layout/AppHeader.tsx` (MODIFY, mount badge) | component | request-response | same file (existing `.header-right` slot) | exact (self-analog) |
| `apps/api/src/shares/shares.controller.ts` (add `PATCH :shareId` route, MODIFY) | controller | CRUD | same file's `updateShareItemName` (`PATCH :shareId/item-name`, L229-248) | exact (self-analog) |
| `apps/api/src/shares/dto/update-grant.dto.ts` (NEW) | model (DTO) | request-response | `apps/api/src/shares/dto/update-item-name.dto.ts` | exact |
| `apps/web/src/services/share.service.ts` (`fetchReceivedShares`/`fetchSentShares`, MODIFY) | service | request-response | `apps/web/src/services/ipns.service.ts` (existing typed api-client wrapper pattern) | role-match |
| `packages/sdk/src/__tests__/client-rotation.test.ts` (NEW) | test | request-response | `packages/sdk-core/src/rotation/scope.ts` (`ScopeExitDeps` injection contract — no existing `scope.test.ts` file found in repo; write against this contract) | partial (no existing test file to copy, but the injection seam is concrete) |
| `apps/web/src/services/rotation-state.test.ts` (NEW) | test | file-I/O | no existing IndexedDB-backed `.test.ts` found in `apps/web` — see "No Analog Found" | none |

## Pattern Assignments

### `apps/web/src/services/rotation-state.service.ts` (NEW service, file-I/O)

**Analog:** `apps/web/src/lib/device/identity.ts` (full file read) and `apps/web/src/services/search-index.service.ts` (L63-91)

**IndexedDB open/upgrade pattern** (identity.ts L24-43):
```typescript
const DB_NAME = 'cipherbox-device';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
```
Apply directly for the new store: `DB_NAME = 'cipherbox-rotation-state'` (or similar — name is Claude's discretion per D-07), with **two** object stores (`generation-high-water`, `seq-high-water`) created in the same `onupgradeneeded`, keyed by `nodeId` (no `keyPath`, key passed explicitly to `put`/`get`).

**Monotonic-max write pattern** (adapt from identity.ts's `saveDeviceKeypair` transaction shape, L143-173):
```typescript
async function saveDeviceKeypair(...): Promise<void> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  const store = tx.objectStore(STORE_NAME);
  store.put({ /* ... */ }, KEYPAIR_KEY);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
```
For D-07, read-then-compare-then-put inside one `readwrite` transaction (do the `get` and conditional `put` before awaiting `tx.oncomplete`, per the module docstring's committed pattern in `search-index.service.ts`/`identity.ts`).

**Payload validation before use (V5 / D-08 fail-closed)** (identity.ts L95-108):
```typescript
// Validate payload shape before touching crypto
const publicKeyArr = Array.isArray(val?.publicKey) ? (val.publicKey as number[]) : null;
if (!publicKeyArr || publicKeyArr.length !== 32) return null;
if (val?.version !== STORAGE_VERSION) return null;
```
Apply the same posture: a stored high-water value that isn't a valid non-negative integer/bigint-serializable string must be treated as absent (fail-closed to the D-08 first-contact path), never coerced.

**Call-site-level try/catch for graceful degradation (D-08)** (identity.ts L283-296, `resolvePersistedIdentity`):
```typescript
try {
  await saveDeviceKeypair({ publicKey: keypair.publicKey, privateKey: keypair.privateKey }, vaultPrivateKey);
} catch {
  // IndexedDB unavailable or write failed; keep identity stable for this session.
  sessionFallback = { keypair, vaultKeyHash };
}
```
Wrap the *caller* of the DB helpers in try/catch (not the helpers themselves) — mirrors D-08's "in-memory session floor" fallback exactly. Module-scoped fallback map (like `sessionFallback`) holds the in-memory high-water when IndexedDB is unavailable/cleared, plus a one-time-warning flag (`let warnedOnce = false`).

**Error handling:** No throw from the store layer on read; only the fail-closed *comparison* (in `ipns.service.ts`) throws a distinguishable error type.

---

### `packages/sdk/src/client.ts` — `renameItem`/`moveItem`/`deleteItem`/`deleteToBin` (MODIFY, CRUD + event-driven)

**Analog:** the file's own `loadFolder` anti-clobber guard (verified L355-404) and the `hasCoveringGrant`/`maybeRotateOnScopeExit` injection contract (`packages/sdk-core/src/rotation/scope.ts`, full file read).

**Anti-clobber / reconcile-before-publish pattern** (`client.ts` L369-381):
```typescript
// IPNS reads lag a just-written sequence (#489 sequence-as-clock invariant).
// Never overwrite a fresher in-memory entry with a stale IPNS snapshot.
const existing = this.folderTree.get(ipnsName);
if (existing && existing.sequenceNumber >= result.sequenceNumber) {
  this.emitter.emit({
    type: 'folder:loaded',
    folderId: ipnsName,
    ipnsName,
    children: existing.children,
    sequenceNumber: existing.sequenceNumber,
  });
  return existing;
}
```
For D-04 (SC#3), invert the polarity per RESEARCH.md Pattern 2: before firing a rotation publish, re-resolve the target folder's `sequenceNumber` and compare against `this.folderTree.get(ipnsName)?.sequenceNumber`; **any** mismatch (either direction) must defer, not just the "stale IPNS lags memory" direction this existing guard covers.

**Scope-exit gating composition** (`scope.ts` L145-159, verified signature):
```typescript
export type ScopeExitDeps = { rotate: () => Promise<void> };

export async function maybeRotateOnScopeExit(
  params: CoverageParams,
  deps: ScopeExitDeps
): Promise<ScopeExitResult> {
  if (!hasCoveringGrant(params)) {
    return 'no-rotation';
  }
  await deps.rotate();
  return 'rotated';
}
```
Wire this into each of `renameItem` (L495), `moveItem` (L554), `deleteItem` (L689), `deleteToBin` (L1451) at their scope-exit point, with `deps.rotate` wrapping `sdkCore.rotateReadFromNode(...)`. `CoverageParams.nodeAncestorIpnsNames` must be built leaf-first from the existing `FolderTree` ancestry, not re-derived ad hoc.

**Error handling:** Existing methods are already wrapped by `withOperation()` (see `loadFolder`'s `return this.withOperation('loadFolder', async () => { ... })` at L360) — the new reconcile-defer and rotation calls stay inside that same wrapper so start/end/error events fire consistently; a defer should throw a distinguishable error subtype (e.g. `ReconcileStaleError`) that the web toast layer can catch via `instanceof`.

---

### `apps/web/src/services/ipns.service.ts` — `resolveIpnsRecord` (MODIFY, request-response)

**Analog:** same file, existing passthrough (verified L141-149):
```typescript
export async function resolveIpnsRecord(
  ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  return resolveIpnsRecordCore(ipnsName, {
    apiUrl,
    getAccessToken: async () => useAuthStore.getState().accessToken || '',
    axiosInstance: apiAxios,
  });
}
```
**Core pattern to add (SC#4/D-05):** wrap the return value — look up `nodeId`'s stored `highestSeq`/`highestGeneration` from `rotation-state.service.ts`, compare, throw a fail-closed error on regression (never silently accept), else bump the high-water (monotonic-max) via the new service before returning. Do not conflate this seq/generation check with `unsealChildReadKey`'s AAD `generation` parameter (Pitfall 5 in RESEARCH.md) — keep it a pre-unseal gate only.

**Error handling:** Mirror the existing top-level function shape (single async function, no internal try/catch — errors propagate to caller); the *new* fail-closed throw should be a named error class (e.g. `SequenceRegressionError`) so `NotificationToast`/toast-dispatch code can pattern-match it to the D-05 "stale data from server rejected" copy.

---

### `apps/web/src/stores/notification.store.ts` + `NotificationToast.tsx` (MODIFY, event-driven)

**Analog:** same files (full reads).

**Store shape to extend** (`notification.store.ts` L3-8, full file):
```typescript
export type Notification = {
  id: string;
  type: 'info' | 'warning' | 'error';
  message: string;
  createdAt: number;
};
```
Add an optional `action?: { label: string; onClick: () => void }` field (D-01 "Refresh access", D-06 "Retry") — keep `type` as the existing string-literal union (no enum, per project convention), do not add a new `type` variant for actionable notifications.

**Toast render pattern to extend** (`NotificationToast.tsx` L89-107):
```tsx
<span style={{ color: typeColors[n.type], flexShrink: 0 }}>{labels[n.type]}</span>
<span style={{ flex: 1 }}>{n.message}</span>
<button
  onClick={() => dismissNotification(n.id)}
  style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', padding: 0, fontFamily: 'var(--font-family-mono)', fontSize: 'var(--font-size-sm)', flexShrink: 0 }}
  aria-label="Dismiss notification"
>
  [x]
</button>
```
Insert a second `<button>` for `n.action` (rendered only when `n.action` is present) between the message `<span>` and the dismiss `[x]` button, styled consistently (same `font-family`/`font-size` vars, but using `--color-green-primary` to read as an affordance rather than muted dismiss). Per `apps/web/CLAUDE.md`: any `//`-style decorative text must be wrapped in `{'...'}`; add `:focus-visible` styles if the action button gets custom hover styling.

**Error handling / auto-dismiss interaction:** `NotificationToast.tsx` L23-42 already manages a `timersRef` auto-dismiss loop (`AUTO_DISMISS_MS = 8000`) — actionable notifications (fail-closed/defer states) likely should suppress or extend auto-dismiss; confirm against the (deferred) UI-SPEC copy but default to leaving auto-dismiss as-is unless the badge/toast is a *terminal* error (D-06 exhaustion), which should not auto-dismiss.

---

### `apps/web/src/stores/rotation.store.ts` (NEW store, event-driven)

**Analog:** `apps/web/src/stores/notification.store.ts` (full file, Zustand `create<T>()` pattern):
```typescript
import { create } from 'zustand';

export type Notification = { id: string; type: 'info' | 'warning' | 'error'; message: string; createdAt: number };

type NotificationState = {
  notifications: Notification[];
  addNotification: (type: Notification['type'], message: string) => void;
  dismissNotification: (id: string) => void;
  clearNotifications: () => void;
};

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],
  addNotification: (type, message) =>
    set((state) => ({ notifications: [...state.notifications, { id: crypto.randomUUID(), type, message, createdAt: Date.now() }] })),
  dismissNotification: (id) => set((state) => ({ notifications: state.notifications.filter((n) => n.id !== id) })),
  clearNotifications: () => set({ notifications: [] }),
}));
```
Follow this exact shape for `rotation.store.ts`: a string-literal-union `status` field (`'idle' | 'root-cut' | 'tail-walk' | 'resuming'` — D-02/D-03), plain `set()` mutators, no middleware. Persist-across-reload for the "Resuming revocation…" state should read from the durable `rotation-state.service.ts` job-record checkpoint on store initialization, not from `localStorage` directly.

---

### `apps/web/src/components/layout/RotationStatusBadge.tsx` (NEW component) + `AppHeader.tsx` (MODIFY)

**Analog:** `apps/web/src/components/layout/AppHeader.tsx` (full file):
```tsx
<div className="header-right">
  {onSearchClick && (
    <button
      className="header-search-btn"
      onClick={onSearchClick}
      aria-label={`Search files (${shortcutLabel})`}
      title={`Search (${shortcutLabel})`}
      type="button"
    >
      {'>_'} <kbd>{shortcutLabel}</kbd>
    </button>
  )}
  <UserMenu />
</div>
```
Mount `<RotationStatusBadge />` inside `.header-right`, before `<UserMenu />`, following the same conditional-render-when-active pattern as `onSearchClick &&`. The badge itself should render nothing (`return null`) when `status === 'idle'`, matching `NotificationToast`'s `if (notifications.length === 0) return null;` early-return idiom. Use `aria-live="polite"`, non-interactive markup (per RESEARCH.md's Security Domain note — no per-item subtree detail exposed to a revoked reader observing timing).

---

### `apps/api/src/shares/shares.controller.ts` — new PATCH grant-update route (MODIFY)

**Analog:** same file's `updateShareItemName` route (verified L229-248):
```typescript
@Patch(':shareId/item-name')
@HttpCode(HttpStatus.NO_CONTENT)
@ApiOperation({
  summary: 'Backfill share encrypted item name',
  description: 'Persist the at-rest itemNameEncrypted ciphertext on a share. ' +
    'Only the sharer can update it; the server never encrypts and stores ' +
    'the client-supplied ciphertext as-is.',
})
@ApiResponse({ status: 204, description: 'Item name updated' })
@ApiResponse({ status: 401, description: 'Unauthorized' })
@ApiResponse({ status: 403, description: 'Only the sharer can update' })
@ApiResponse({ status: 404, description: 'Share not found' })
async updateShareItemName(
  @Request() req: RequestWithUser,
  @Param('shareId', ParseUUIDPipe) shareId: string,
  @Body() dto: UpdateItemNameDto
): Promise<void> {
  await this.sharesService.updateShareItemName(shareId, req.user.id, dto.itemNameEncrypted);
}
```
Per RESEARCH.md's Open Question #1 recommendation, extend `PATCH :shareId` (not `:shareId/item-name`) with optional `readDescriptorRef`/`rootGeneration` fields, following this exact `@Patch` + `@HttpCode(204)` + `@ApiOperation`/`@ApiResponse` decorator shape and the `Only the sharer can update` auth-check idiom (mirrors `updateShareItemName`'s ownership check, not `hideShare`'s recipient check — the owner drives D-10/D-11 reconcile).

**Service method analog** (`shares.service.ts` L234-249, `updateShareItemName`):
```typescript
async updateShareItemName(shareId: string, sharerId: string, itemNameEncrypted: string): Promise<void> {
  const share = await this.shareRepo.findOne({ where: { id: shareId } });
  if (!share) {
    throw new NotFoundException('Share not found');
  }
  if (share.sharerId !== sharerId) {
    throw new ForbiddenException('Only the sharer can update the item name');
  }
  share.itemNameEncrypted = Buffer.from(itemNameEncrypted, 'hex');
  // ... await this.shareRepo.save(share);
}
```
Follow this exact find→ownership-check→mutate→save shape for the new `updateGrant` service method (`NotFoundException`/`ForbiddenException` from `@nestjs/common`, same as existing methods).

**DTO analog** (`apps/api/src/shares/dto/update-item-name.dto.ts`, full file):
```typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsString, Matches, MaxLength } from 'class-validator';

export class UpdateItemNameDto {
  @ApiProperty({ description: '...' })
  @IsString()
  @Matches(/^(?:[0-9a-fA-F]{2})+$/, { message: '...' })
  @MaxLength(2500)
  itemNameEncrypted!: string;
}
```
New `update-grant.dto.ts` should follow this `class-validator` decorator style: `@IsOptional() @IsString()` for `readDescriptorRef` (hex-validated like the above), `@IsOptional() @IsNumberString()` or similar for `rootGeneration` (transported as a string per the existing `receivedShareResponseDto.ts`'s `rootGeneration: string` convention — RESEARCH.md confirms API DTOs already use string-typed generation).

**IMPORTANT — cross-cutting requirement:** after this change, run `pnpm api:generate` and commit the regenerated `packages/api-client/src/generated/`, `packages/api-client/src/models/`, and `packages/api-client/openapi.json` per `CLAUDE.md`'s API Development Workflow — the pre-commit hook `scripts/check-api-client.sh` will block otherwise.

---

### `apps/web/src/services/share.service.ts` — `fetchReceivedShares`/`fetchSentShares` rewire (MODIFY)

**Analog:** `apps/web/src/services/ipns.service.ts`'s typed api-client wrapper shape (`createAndPublishIpnsRecord`, L34-83) — a thin function that calls a generated `@cipherbox/api-client` function and reshapes the response into the service's own return type.

**Core pattern:** replace the `throw new Error('deferred to Phase 68 ...')` stub bodies with calls to `sharesControllerGetReceivedShares`/`sharesControllerGetSentShares` (already generated in `packages/api-client/src/generated/shares/shares.ts`, confirmed present by RESEARCH.md), then map the DTO shape (`readDescriptorRef`, `rootGeneration: string`, `rootNodeId`) onto extended `ReceivedShare`/`SentShare` types in `apps/web/src/stores/share.store.ts` — do not keep the legacy `encryptedKey`/`encryptedIpnsKey` fields as the primary shape; add the new fields alongside or replace per the planner's migration call.

---

### Test files (NEW, `.test.ts` only — SC#5 hard constraint)

**Analog for `packages/sdk/src/__tests__/client-rotation.test.ts`:** no existing `scope.test.ts` file was found in the repo (RESEARCH.md's claim of a "proven pattern" refers to the *injection contract* in `scope.ts`, not an existing test file — verify this at plan time). Write against `ScopeExitDeps.rotate: () => Promise<void>` using `vi.fn()`:
```typescript
const rotateSpy = vi.fn().mockResolvedValue(undefined);
const result = await maybeRotateOnScopeExit(
  { nodeAncestorIpnsNames: [...], activeGrantRootIpnsNames: new Set([...]), localGrantRecord: null },
  { rotate: rotateSpy }
);
expect(result).toBe('rotated');
expect(rotateSpy).toHaveBeenCalledTimes(1);
```
Locate existing `packages/sdk/src/__tests__/*.test.ts` files for the surrounding `describe`/`vi.mock` conventions used to test `CipherBoxClient` methods (not read in this pass — grep at plan time for `renameItem` or `deleteItem` in existing sdk test files).

**Analog for `apps/web/src/services/rotation-state.test.ts`:** **No analog found** — see below. `apps/web/vitest.config.ts` sets `environment: 'node'` (confirmed by RESEARCH.md); native `indexedDB` is unavailable there. This test needs either a `fake-indexeddb` devDependency (not currently in the monorepo per RESEARCH.md's Wave 0 Gaps) or a per-file `// @vitest-environment jsdom` pragma if `jsdom`/`happy-dom` is already a devDependency — verify at plan time.

## Shared Patterns

### IndexedDB (hand-rolled, no `idb` package)
**Source:** `apps/web/src/lib/device/identity.ts` (openDB, L34-43), `apps/web/src/services/search-index.service.ts` (openSearchDB, L82-91)
**Apply to:** `rotation-state.service.ts` — same `indexedDB.open(name, version)` + `onupgradeneeded: () => createObjectStore()` shape. Do NOT introduce the `idb` npm package (explicit anti-pattern in RESEARCH.md).

### Fail-closed error surfacing
**Source:** RESEARCH.md's ipns.service.ts wiring sketch + `packages/sdk-core/src/rotation/scope.ts`'s `@security` docblocks
**Apply to:** `ipns.service.ts` regression check, `client.ts` reconcile-defer, `share.service.ts` rewire. Every ambiguous state throws a named, distinguishable error subtype rather than returning `null`/silently swallowing — mirrors the project's existing `BinNotLoadedError` pattern in `client.ts` (L52-56: `export class BinNotLoadedError extends Error { constructor() { super('Bin not loaded'); this.name = 'BinNotLoadedError'; } }`).

### String-literal unions, never TypeScript enums
**Source:** `packages/sdk-core/src/rotation/scope.ts` L28-29 explicit comment: "Types — string-literal unions, never TypeScript enums (project convention)"; `apps/web/src/stores/notification.store.ts`'s `Notification['type']`
**Apply to:** every new `type`/`status` field in this phase (`ScopeExitResult`, rotation store `status`, notification `action` discriminant, if any).

### Zeroization terminal-owner rule
**Source:** `packages/sdk-core/src/rotation/engine.ts` `@security` docblocks (per RESEARCH.md Pitfall 4) + project memory (`project-zeroization-callee-must-not-zero-reused-buffer.md`)
**Apply to:** any new wrapper code in `client.ts` or the rotation-progress driver that touches `rootReadKey`/`Uint8Array` key material passed into `rotateReadFromNode` — never add a `.fill(0)` on a buffer not freshly allocated by that same function.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `apps/web/src/services/rotation-state.test.ts` | test | file-I/O | No existing `apps/web` test exercises `indexedDB` in the current `environment: 'node'` vitest config; needs a Wave-0 infra decision (fake-indexeddb vs. per-file jsdom pragma) before this test file can be written — flag to planner as an explicit prerequisite task, not silently assumed |
| Multi-tab leader election (`navigator.locks`, D-09) | utility | event-driven | RESEARCH.md confirms this is the **first use** of the Web Locks API in this codebase — no existing analog to copy from; implement directly against the MDN-documented `navigator.locks.request()` API |

## Metadata

**Analog search scope:** `apps/web/src/{lib/device,services,stores,components}`, `packages/sdk/src/`, `packages/sdk-core/src/rotation/`, `apps/api/src/shares/`
**Files scanned:** identity.ts, search-index.service.ts, NotificationToast.tsx, notification.store.ts, AppHeader.tsx, ipns.service.ts, client.ts (partial, ~150 lines across targeted ranges), scope.ts (full), shares.controller.ts (partial), shares.service.ts (partial), update-item-name.dto.ts (full)
**Pattern extraction date:** 2026-07-01
