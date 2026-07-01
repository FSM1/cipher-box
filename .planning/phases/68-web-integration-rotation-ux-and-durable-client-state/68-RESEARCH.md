# Phase 68: Web Integration — Rotation UX and Durable Client State - Research

**Researched:** 2026-07-01
**Domain:** Client-side crypto-state integration (rotation engine wiring, durable IndexedDB anti-rollback state, Zustand/SDK folder-state reconcile) in a TypeScript web app
**Confidence:** HIGH (code surface verified directly against the live repo); MEDIUM on the grant/API wiring gap (design-doc-cited, not yet built)

## Summary

Phase 68 is not a UI phase in disguise — it is a **security-integration phase** with a narrow, well-defined UI surface (5 notification/status states, per the approved UI-SPEC). The real work is threading `rotateReadFromNode` (already built and unit-tested in `packages/sdk-core/src/rotation/engine.ts`) into the **`packages/sdk`** `CipherBoxClient` mutation methods (`renameItem`, `moveItem`, `deleteItem`, `deleteToBin`) — NOT directly into the web app's React hooks. The web hooks (`useFolderMutations`, `useFileBrowserActions`) are thin UI wrappers that already call `client.renameItem()` / `client.moveItem()` / `client.deleteItem()` / `client.deleteToBin()`; none of these SDK methods currently call rotation, `hasCoveringGrant`, or any share/grant logic at all. This is the correct, single integration point for D-04 (folderTree reconcile) and the scope-exit rotation trigger (SC#2).

Three deliverables, in order of build risk:

1. **Scope-exit rotation wiring (SC#2).** `packages/sdk/src/client.ts`'s `renameItem`/`moveItem`/`deleteItem`/`deleteToBin` must each call `maybeRotateOnScopeExit` (from `packages/sdk-core/src/rotation/scope.ts`) with the mutated node's ancestry, then `rotateReadFromNode` when covered. `apps/web/src/services/share.service.ts`'s `executeLazyRotation` is dead legacy code with **zero callers** (confirmed by repo-wide grep) — deleting it is nearly free. `addShareKeys`/`reWrapForRecipients` in that same file DO have callers (`useAuth.ts`, `useSharedNavigation.ts`, and `reWrapForRecipients` itself calls `addShareKeys`) that must be removed or rerouted as part of this cutover.

2. **Durable IndexedDB high-water (ROT-07 / D-07/D-08).** No `idb` npm package exists in this repo — the established pattern (`apps/web/src/lib/device/identity.ts`, `apps/web/src/services/search-index.service.ts`) is **hand-rolled raw `indexedDB` API** wrapped in Promises, one object store per DB, `onupgradeneeded` → `createObjectStore`. Follow this pattern exactly for the new `{nodeId → highestGeneration}` / `{nodeId → highestSeq}` store — do not introduce a new dependency.

3. **`folderTree` reconcile before rotation publish (SC#3 / D-04).** `packages/sdk`'s internal `FolderTree` (`packages/sdk/src/state/folder-tree.ts`) already carries `sequenceNumber` per folder and already has an anti-clobber guard pattern in `loadFolder` ("never overwrite a fresher in-memory entry with a stale IPNS snapshot" — `packages/sdk/src/client.ts:369-381`). The reconcile-before-rotate logic for SC#3 should follow that exact pattern: re-resolve the mutation's target folder's current `sequenceNumber` immediately before triggering `rotateReadFromNode`, and defer (never publish) if the resolved sequence disagrees with the in-memory `FolderTree` entry.

**Critical scope gap discovered (not in CONTEXT.md's code_context, must be surfaced to the planner):** `apps/web/src/services/share.service.ts` is almost entirely **stub functions that unconditionally `throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired')`** (`fetchReceivedShares`, `fetchSentShares`, `createShare`, `updateSharePermission`, `fetchShareKeys`, `addShareKeys`, `fetchPendingRotations`, `updateShareKey`, `completeShareRotation`). The web app's local `ReceivedShare`/`SentShare` types (`apps/web/src/stores/share.store.ts`) are still the **legacy v1 shape** (`encryptedKey`, `encryptedIpnsKey`) — they do NOT carry `readDescriptorRef`/`rootGeneration`/`rootNodeId`, even though the **API and generated client already do** (`packages/api-client/src/models/receivedShareResponseDto.ts` has `readDescriptorRef`, `rootGeneration: string`, `rootNodeId`, and `sharesControllerGetReceivedShares`/`sharesControllerGetSentShares` exist and are unused by the web app today). D-07 requires seeding the durable generation floor "from the grant's `rootGeneration`" — that data literally cannot reach the web client today without at minimum rewriting `fetchReceivedShares`/`fetchSentShares` to call the real (already-generated) API functions and updating the local share types. **This is real Phase 68 work, not optional polish** — flag it to the planner as an in-scope prerequisite subtask, sized modestly (rewire 2 fetch functions + extend 2 types), not a rabbit hole.

**Second scope gap (owner reconcile, D-10/D-11):** `reMintGrantsRootedAt`'s `GrantRemintCallbacks.updateGrantFn(shareId, readDescriptorRef, newGeneration)` has **no backing API endpoint**. `apps/api/src/shares/shares.controller.ts` has `POST /shares`, `GET /shares/received`, `GET /shares/sent`, `DELETE /shares/:shareId` (hard `remove()`, confirmed suitable for `deleteGrantFn`), `PATCH /shares/:shareId/hide`, `PATCH /shares/:shareId/item-name` — but **no PATCH that updates `readDescriptorRef`/`rootGeneration` on an existing grant row**. The design doc's cutover-order step 5 (`apps/api`) was supposed to include "rotation bookkeeping" but the controller shows no such route was added. Wiring D-10 (owner reconcile re-minting grants after a write-recipient's independent unlink+bin) requires a **new `apps/api` endpoint** — this is cross-cutting into `apps/api`, not pure "web" work, and per CLAUDE.md's API workflow rule, any DTO/controller change requires `pnpm api:generate` + committing the regenerated client. Flag this to the planner explicitly; it changes the plan's blast radius beyond `apps/web`.

**Primary recommendation:** Wire rotation into `packages/sdk/src/client.ts` mutation methods (not the web hooks), reuse the hand-rolled raw-`indexedDB` pattern from `identity.ts`/`search-index.service.ts` for the new durable store, budget an explicit subtask to rewire `share.service.ts`'s fetch functions onto the already-generated `sharesControllerGetReceivedShares`/`GetSentShares` API calls, and treat the missing grant-update API endpoint as a small but real cross-package (`apps/api` + `packages/api-client`) addition inside this phase's scope for D-10/D-11.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Scope-exit rotation trigger (delete/move/rename) | API/Backend-adjacent client SDK (`packages/sdk`) | — | `CipherBoxClient` methods are the single chokepoint every UI (web today, FUSE-equivalent later) calls through; rotation must be triggered here, not duplicated per-UI-framework |
| Rotation walk execution (`rotateReadFromNode`) | Host-agnostic core library (`packages/sdk-core`) | — | Already built, pure/host-agnostic per Phase 63 D-02; web is a caller, not an implementer |
| Rotation progress UX (badge, toasts) | Browser/Client (React) | — | Pure presentation; reads advisory job-record state, never drives crypto |
| Durable generation/seq high-water | Browser/Client (IndexedDB) | — | Per M1/§6.5, must be signed-signal-independent client state; cannot live server-side (defeats the anti-colluding-relay purpose) |
| `folderTree` reconcile | Client SDK (`packages/sdk` `FolderTree`) | Browser/Client (Zustand `folder.store.ts`) | `packages/sdk`'s `FolderTree.sequenceNumber` is the authoritative in-memory clock the SDK checks before mutating; the Zustand store is a read-projection for React and must not be the reconcile source of truth (avoids the documented `#489`/`#494` desync class) |
| Grant fetch/persist (`readDescriptorRef`, `rootGeneration`) | API/Backend (`apps/api` `shares` module) | Client SDK (fetch + cache) | Server is the durable store of grant rows; web fetches and projects, never invents grant state |
| Grant re-mint after rotation (`reMintGrantsRootedAt` callbacks) | API/Backend (needs new endpoint) | Client SDK (drives the callback) | Persisting a re-minted `readDescriptorRef` is a DB write; must go through a real API mutation, not be inferred client-side |
| Multi-tab coordination (`navigator.locks`) | Browser/Client | — | Purely a same-origin, same-browser coordination primitive; no server involvement |

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ROT-07 | (M1) A durable client-side `{nodeId → highestGeneration}` high-water (survives restart, seeded from the grant `rootGeneration`) fails closed on generation regression | §4.3 of the design doc (cited below) + the `identity.ts`/`search-index.service.ts` IndexedDB pattern (verified in this repo) give the exact shape and precedent; the grant-fetch gap (share.service.ts stubs) is the concrete prerequisite subtask this requirement surfaces |

## Standard Stack

No new external packages are required for this phase. Every mechanism (`indexedDB`, `navigator.locks`, `crypto.subtle`) is a browser built-in already used elsewhere in this codebase.

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Browser `indexedDB` (native) | n/a (Web API) | Durable per-nodeId generation/seq high-water store | Already the established pattern in this repo (`identity.ts`, `search-index.service.ts`); no wrapper library in use |
| Browser `navigator.locks` (Web Locks API) | n/a (Web API) | D-09 multi-tab leader election for the tail-walk driver | [MDN: Web Locks API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API) `[CITED]` — secure-context (HTTPS) only, available in workers; no existing precedent in this codebase (first use) |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `@cipherbox/sdk-core` (workspace) | current | `rotateReadFromNode`, `rotateOne`, `hasCoveringGrant`, `maybeRotateOnScopeExit`, `resolveIpnsRecord` | Already imported by `apps/web/src/services/ipns.service.ts` and `packages/sdk/src/client.ts` |
| `@cipherbox/api-client` (workspace, generated) | current (openapi 0.44.1 at time of research) | `sharesControllerGetReceivedShares`, `sharesControllerGetSentShares` — already generated, currently unused by web | Required to unblock D-07's `rootGeneration` seeding |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled raw `indexedDB` | `idb` (npm, Jake Archibald's Promise wrapper) | Not in this repo's dependency tree today; introducing it for one new store breaks the established local convention and adds a dependency-legitimacy review for zero real benefit — reject, follow `identity.ts` pattern |
| `navigator.locks` | A Zustand-store-based `BroadcastChannel` leader-election | `navigator.locks` is purpose-built, has no message-passing races, and D-09 explicitly names it — use it, with the documented double-run-safe fallback (idempotent walk + CAS-409 re-merge) when unavailable |

**Installation:** None — no new dependencies.

## Package Legitimacy Audit

Not applicable — no external packages are introduced by this phase. All new mechanisms are native browser Web APIs (`indexedDB`, `navigator.locks`) and existing workspace packages (`@cipherbox/sdk-core`, `@cipherbox/sdk`, `@cipherbox/api-client`).

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
 React UI (apps/web hooks: useFolderMutations, useFileBrowserActions)
        │  calls client.deleteItem() / moveItem() / renameItem() / deleteToBin()
        ▼
 CipherBoxClient (packages/sdk/src/client.ts)  ◄── SINGLE CHOKEPOINT
        │
        ├─ 1. requireFolder() / FolderTree lookup (packages/sdk/src/state/folder-tree.ts)
        │     │
        │     ▼
        │  [NEW] reconcile: re-resolve current sequenceNumber via ipns.service.ts
        │        → resolveIpnsRecord() → sdk-core resolveIpnsRecordCore()
        │        mismatch vs in-memory FolderTree.sequenceNumber?
        │        ├─ yes → defer (throw a distinguishable "stale, retry" error) — D-04
        │        └─ no  → proceed
        │
        ├─ 2. sdkCore.deleteFromFolder / renameInFolder / moveItem (pure metadata ops)
        │
        ├─ 3. [NEW] maybeRotateOnScopeExit (packages/sdk-core/src/rotation/scope.ts)
        │        hasCoveringGrant(ancestry, activeGrantRootIpnsNames, localGrantRecord)
        │        ├─ false → 'no-rotation' (zero extra publishes) — SC#4 invariant
        │        └─ true  → deps.rotate() → rotateReadFromNode() (packages/sdk-core/src/rotation/engine.ts)
        │                     │
        │                     ├─ rotates scope-root FIRST (sync, fast cut)
        │                     ├─ BFS tail walk (background, resumable)
        │                     ├─ [NEW] durable IndexedDB high-water checkpoint per node commit
        │                     │        (persistCallback on RotationJobRecord)
        │                     └─ [NEW] reMintGrantsRootedAt callbacks → apps/api (NEW endpoint needed)
        │
        ├─ 4. sdkCore.updateFolderMetadataAndPublish (existing) → apps/api IPNS publish (CAS)
        │
        └─ 5. emitter.emit('folder:updated') → apps/web store subscription → Zustand folder.store.ts
                                                    (React re-render; badge/toast driven by
                                                     [NEW] rotation-status store, not folder.store)

 Resolve chokepoint (every read, not just rotation):
 apps/web/src/services/ipns.service.ts:resolveIpnsRecord()
        └─ delegates 100% to @cipherbox/sdk-core resolveIpnsRecordCore()
              [NEW] wrap this call: check + update the durable
              {nodeId → highestSeq} / {nodeId → highestGeneration} store here — SC#1/#4/D-05
              regression → hard fail-closed toast, mutation/read aborts
```

### Recommended Project Structure

```
apps/web/src/
├── services/
│   ├── ipns.service.ts              # existing — wrap resolveIpnsRecord with high-water check (SC#4)
│   └── rotation-state.service.ts    # NEW — IndexedDB open/read/write for {nodeId→highestGeneration}, {nodeId→highestSeq}
├── stores/
│   ├── rotation.store.ts            # NEW — Zustand store backing the D-02/D-03 status badge (root-cut / tail-walk / resuming)
│   └── notification.store.ts        # existing — extend Notification type with optional `action` (D-01/D-06)
├── components/layout/
│   ├── AppHeader.tsx                # existing — mount RotationStatusBadge in .header-right, before UserMenu
│   └── RotationStatusBadge.tsx      # NEW
└── components/
    └── NotificationToast.tsx        # existing — extend to render n.action as a text button before [x]

packages/sdk/src/
├── client.ts                        # existing — wire maybeRotateOnScopeExit + reconcile into renameItem/moveItem/deleteItem/deleteToBin
├── share.ts + share/                # existing — extend ShareOperationContext or add rotation grant-callback wiring for D-10/D-11
└── state/folder-tree.ts             # existing — reconcile source of truth (sequenceNumber)

apps/api/src/shares/
├── shares.controller.ts             # existing — ADD PATCH endpoint for grant re-mint (readDescriptorRef + rootGeneration)
└── shares.service.ts                # existing — ADD updateGrant-equivalent service method
```

### Pattern 1: Hand-rolled Promise-wrapped IndexedDB (established in this repo)

**What:** A single-object-store IndexedDB database opened via `indexedDB.open(name, version)`, with `onupgradeneeded` creating the store, and every read/write wrapped in a `new Promise` resolving on `onsuccess`/`oncomplete`.

**When to use:** Any new durable client-side store in this codebase (D-07's high-water store).

**Example (verified pattern from `apps/web/src/services/search-index.service.ts:82-91` and `apps/web/src/lib/device/identity.ts:34-43`):**
```typescript
// Source: apps/web/src/lib/device/identity.ts (verified in-repo, adapt for D-07)
const DB_NAME = 'cipherbox-rotation-state'; // D-07: name is Claude's discretion
const DB_VERSION = 1;
const STORE_NAME = 'high-water';

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME); // keyPath: none, key = nodeId
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Monotonic-max write (D-07):
async function bumpHighWater(nodeId: string, candidate: number): Promise<void> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, 'readwrite');
  const store = tx.objectStore(STORE_NAME);
  const current = await new Promise<number | undefined>((resolve, reject) => {
    const req = store.get(nodeId);
    req.onsuccess = () => resolve(req.result as number | undefined);
    req.onerror = () => reject(req.error);
  });
  if (current === undefined || candidate > current) {
    store.put(candidate, nodeId);
  }
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
```
Note: `identity.ts` and `search-index.service.ts` both wrap the whole call in `try { ... } catch { return null/fallback }` at the call site (not inside the DB helper) to implement the D-08 graceful-degradation contract — follow that same call-site-level try/catch, not an internal swallow.

### Pattern 2: Anti-clobber sequence guard (established in `packages/sdk/src/client.ts:369-381`)

**What:** Before adopting a freshly-resolved IPNS snapshot into in-memory state, compare its `sequenceNumber` against the existing in-memory entry; only adopt if strictly newer.

**When to use:** The exact shape SC#3's `folderTree` reconcile-before-rotation-publish should follow (D-04's "defer, never skip").

**Example:**
```typescript
// Source: packages/sdk/src/client.ts loadFolder() — verified in-repo
const existing = this.folderTree.get(ipnsName);
if (existing && existing.sequenceNumber >= result.sequenceNumber) {
  // IPNS reads lag a just-written sequence (#489 sequence-as-clock invariant).
  // Never overwrite a fresher in-memory entry with a stale IPNS snapshot.
  return existing; // or, for D-04: defer the mutation instead of silently keeping stale
}
```
For D-04, invert the polarity: reconcile means checking the *current network* sequence is not *ahead* of what the in-memory `FolderTree` thinks before firing a rotation publish — i.e., detect the case where the local state is stale relative to the network, not (only) the reverse. Both directions of mismatch must defer per D-04 ("if `folderTree` reconcile against the current `sequenceNumber` fails, the mutation defers").

### Pattern 3: Transport-decoupled callback injection (established across Phase 63–65)

**What:** Crypto/rotation logic never imports API clients directly; production callers inject real API-backed callback functions, tests inject `vi.fn()` mocks.

**When to use:** Wiring `GrantRemintCallbacks` (D-10/D-11 owner reconcile) and the rotation job's `persistCallback` (D-07 durable checkpoint).

**Example:**
```typescript
// Source: packages/sdk-core/src/rotation/engine.ts — GrantRemintCallbacks type (verified)
export type GrantRemintCallbacks = {
  queryGrantsFn: (nodeId: string) => Promise<ReadonlyArray<{
    shareId: string; recipientPublicKey: Uint8Array; isRevoked: boolean;
  }>>;
  updateGrantFn: (shareId: string, readDescriptorRef: string, newGeneration: number) => Promise<void>;
  deleteGrantFn: (shareId: string) => Promise<void>;
};
// Production wiring belongs in packages/sdk/src/client.ts or share.ts, calling into
// @cipherbox/api-client. deleteGrantFn → sharesControllerRevokeShare (hard DELETE, verified
// in apps/api/src/shares/shares.service.ts:145 `this.shareRepo.remove(share)`).
// updateGrantFn → NO EXISTING ENDPOINT (gap — see Common Pitfalls / Open Questions).
```

### Anti-Patterns to Avoid

- **Wiring rotation into the web React hooks directly:** `useFolderMutations`/`useFileBrowserActions` are UI-concern wrappers; the mutation logic (and thus the rotation trigger) belongs in `packages/sdk/src/client.ts` so a future non-web host reuses the same chokepoint. Do not duplicate `hasCoveringGrant` calls in web code.
- **Reintroducing per-mutation fan-out:** `reWrapForRecipients`/`addShareKeys` (both in `share.service.ts`) are the exact `O(recipients)` pattern ROT-03/READ-03 replaced. Deleting them and NOT reintroducing an equivalent inline loop is the point of SC#2 — do not "port" their logic into the new rotation call sites.
- **Trusting `activeGrantRootIpnsNames` alone:** `hasCoveringGrant` is explicitly designed to cross-check the relay-supplied set against `localGrantRecord` (T-63-17, anti-malicious-relay). A web implementation that only queries the relay and skips the local cross-check reintroduces the suppressed-rotation vulnerability the pure predicate was built to close.
- **Introducing an `idb` npm dependency:** breaks local convention for zero benefit (see Alternatives Considered).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Scope-exit coverage detection | A new "is this node shared" check in web/hooks | `hasCoveringGrant` (`packages/sdk-core/src/rotation/scope.ts`) | Already a pure, unit-tested, anti-malicious-relay predicate; re-deriving it in web risks missing the local-record cross-check |
| Rotation walk / BFS / CAS-409 merge | A web-specific rotation loop | `rotateReadFromNode` (`packages/sdk-core/src/rotation/engine.ts`) | Host-agnostic by design (Phase 63 D-02); already handles crash-resume, convergence guard, batched parent republish |
| Key wrapping for grant re-mint | Hand-rolled ECIES call | `wrapKey` from `@cipherbox/crypto` (already used inside `reMintGrantsRootedAt`) | Standard primitive, cross-language KAT-verified |
| IndexedDB promise plumbing | A generic `idb`-style abstraction layer | The `identity.ts`/`search-index.service.ts` inline pattern | Consistency with existing 2 call sites; a 3rd hand-rolled variant is acceptable, a *different abstraction* is not |
| Multi-tab leader election | Custom `localStorage` polling / `BroadcastChannel` election protocol | `navigator.locks.request()` | Purpose-built Web API; D-09 names it explicitly; avoid races a hand-rolled election would reintroduce |

**Key insight:** Every crypto/coverage/rotation primitive this phase needs already exists and is unit-tested in `packages/sdk-core`. The actual net-new logic in this phase is thin: (1) call the right functions from the right chokepoint (`client.ts`), (2) persist two small maps to IndexedDB, (3) render 5 UI states. The bulk of the *risk* is in the two gaps above (grant-fetch stubs, missing update-grant endpoint), not in re-deriving crypto.

## Common Pitfalls

### Pitfall 1: Wiring rotation into web hooks instead of `packages/sdk/src/client.ts`

**What goes wrong:** A plan that patches `useFolderMutations.ts`/`useFileBrowserActions.ts` to call `hasCoveringGrant`/`rotateReadFromNode` directly bypasses the SDK's `FolderTree`, `requireFolder`, and existing `withOperation` wrapper — losing the self-heal/self-bootstrap guarantees those already provide, and diverging from the single-chokepoint design the desktop/FUSE Rust client will need to mirror later (Phase 69).
**Why it happens:** CONTEXT.md's `code_context` section lists the web hooks as "Integration Points," which reads as "patch these files," but the hooks are thin — the actual mutation bodies live in `packages/sdk/src/client.ts`.
**How to avoid:** Wire `maybeRotateOnScopeExit` calls inside `CipherBoxClient.renameItem`/`moveItem`/`deleteItem`/`deleteToBin` (verified line ranges: 495, 554, 689, 1451 of `packages/sdk/src/client.ts`).
**Warning signs:** A plan task that only touches files under `apps/web/src/hooks/` for the SC#2 rotation trigger, with no corresponding change to `packages/sdk/src/client.ts`.

### Pitfall 2: D-07's `rootGeneration` seeding has no data path today

**What goes wrong:** `fetchReceivedShares`/`fetchSentShares` in `apps/web/src/services/share.service.ts` unconditionally throw (`'deferred to Phase 68...'`). A plan that writes the durable-store seeding logic assuming grant data is already available will fail at runtime with no received/sent shares ever loading.
**Why it happens:** Prior phases (63–67) deliberately stubbed these functions with a Phase-68 TODO comment; this phase is where the debt comes due.
**How to avoid:** Add an explicit task rewiring `fetchReceivedShares`/`fetchSentShares` to call `sharesControllerGetReceivedShares`/`sharesControllerGetSentShares` (already generated in `packages/api-client/src/generated/shares/shares.ts`), and extend `ReceivedShare`/`SentShare` (`apps/web/src/stores/share.store.ts`) to carry `readDescriptorRef`, `rootGeneration` (parse the numeric string to `number`), and `rootNodeId`.
**Warning signs:** Any plan task referencing "the grant's `rootGeneration`" without a preceding task that makes grant data reachable in the web app.

### Pitfall 3: `reMintGrantsRootedAt`'s `updateGrantFn` has no backing API route

**What goes wrong:** D-10/D-11's owner reconcile calls `GrantRemintCallbacks.updateGrantFn(shareId, readDescriptorRef, newGeneration)` — but `apps/api/src/shares/shares.controller.ts` has no PATCH/PUT route that accepts a new `readDescriptorRef`/`rootGeneration` for an existing share row. A plan that treats D-10/D-11 as "just wire the callback" will discover this gap mid-execution.
**Why it happens:** The design doc's cutover-order step 5 bundled "rotation bookkeeping" into the `apps/api` phase (Phase 66), but the controller (verified: only `POST /shares`, `GET /received`, `GET /sent`, `DELETE /:shareId`, `PATCH /:shareId/hide`, `PATCH /:shareId/item-name`) shows this specific route was not added.
**How to avoid:** Size a small `apps/api` task (new DTO + controller route + service method, e.g. `PATCH /shares/:shareId/rotate`) into this phase's plan for D-10/D-11, run `pnpm api:generate`, and commit the regenerated `packages/api-client` files per CLAUDE.md's API workflow rule and the pre-commit `check-api-client.sh` hook.
**Warning signs:** A plan with D-10/D-11 tasks scoped only to `apps/web`/`packages/sdk`, no `apps/api` file touched, no `pnpm api:generate` step.

### Pitfall 4: Zeroization discipline — `rotateOne`/`rotateReadFromNode` are strict about caller-owned vs. engine-owned buffers

**What goes wrong:** A prior incident (documented in `engine.ts`'s own header comment and in project memory) caused 48/89 sdk-e2e failures from a callee zeroing a reused session buffer. Any new code wrapping `rotateReadFromNode` (e.g., the D-02/D-03 progress-badge driver, or the D-07 persistence callback) must NOT zero `rootReadKey` or any parent-supplied key — only the engine's own minted `readKeyPrime` is engine-owned.
**Why it happens:** The temptation to "clean up" key material defensively in new wrapper code around an existing security-sensitive function.
**How to avoid:** Read and follow the `@security` docblocks on `rotateOne`/`rotateReadFromNode` verbatim; the terminal-owner rule is: the mint site zeros on failure, the caller never zeros what it passed in.
**Warning signs:** Any `.fill(0)` call added inside new Phase-68 code that touches a `Uint8Array` not freshly allocated by that same function.

### Pitfall 5: `SealedChildRef.generation` mirror vs. the node's own envelope `generation` — never conflate as unseal key material

**What goes wrong:** Per design §2.6, the reader's expected AAD `generation` for unsealing a child comes from the **parent's mirror** (`SealedChildRef.generation`), never from the child's own envelope. The M1 durable high-water check (ROT-07) is a *separate* concern that DOES use the child's own envelope `generation`. A plan or implementation that uses the durable high-water value as unseal-AAD input (or vice versa) breaks the AAD binding.
**Why it happens:** Both are called "generation" and both gate access, inviting conflation.
**How to avoid:** Keep the M1 high-water check (fail-closed comparison against `{nodeId → highestGeneration}`) strictly a *pre-unseal gate*, separate from the AAD-input generation sourced from the parent mirror — do not let the durable-store lookup replace or feed the AAD parameter passed to `unsealChildReadKey`.
**Warning signs:** Any code path that reads from the new IndexedDB store and passes that value directly into `unsealChildReadKey`'s `generation` parameter.

### Pitfall 6: `.spec.ts` silently skipped by apps/web vitest

**What goes wrong:** New test files named `*.spec.ts` are silently excluded — CI shows green with zero new tests run.
**Why it happens:** `apps/web/vitest.config.ts` `include: ['src/**/*.test.ts']` only (verified in-repo) — no `.spec.ts` glob.
**How to avoid:** Every new test file created by this phase MUST use `.test.ts`. Verify at plan-checkpoint time with `find apps/web/src -name "*.spec.ts"` returning empty (this is literally SC#5).
**Warning signs:** Any generated test filename ending in `.spec.ts`.

## Code Examples

### Scope-exit gating composition (verified signature, `packages/sdk-core/src/rotation/scope.ts`)
```typescript
// Source: packages/sdk-core/src/rotation/scope.ts (verified in-repo)
export async function maybeRotateOnScopeExit(
  params: CoverageParams,   // { nodeAncestorIpnsNames, activeGrantRootIpnsNames, localGrantRecord }
  deps: ScopeExitDeps       // { rotate: () => Promise<void> }
): Promise<ScopeExitResult>; // 'no-rotation' | 'rotated'

// Wiring sketch for packages/sdk/src/client.ts deleteItem() (illustrative, not verified against
// a merged implementation — this exact call site does not exist yet):
const result = await maybeRotateOnScopeExit(
  {
    nodeAncestorIpnsNames: ancestryOf(folderIpnsName), // NEW helper, leaf-first per scope.ts docs
    activeGrantRootIpnsNames: await this.getActiveGrantRootIpnsNames(), // NEW, relay-supplied
    localGrantRecord: this.getLocalGrantRecordFor(folderIpnsName),      // NEW, client-authoritative
  },
  { rotate: () => sdkCore.rotateReadFromNode({ /* … */ }) }
);
```

### `rotateReadFromNode` call shape (verified signature, `packages/sdk-core/src/rotation/engine.ts:753`)
```typescript
// Source: packages/sdk-core/src/rotation/engine.ts (verified in-repo)
export async function rotateReadFromNode(params: {
  rootNodeId: string;
  rootNodeIpnsName: string;
  rootReadKey: Uint8Array;              // NOT zeroed by the engine — caller-owned
  rootIpnsPrivateKey?: Uint8Array;
  rootIpnsPublicKey?: Uint8Array;
  jobRecord: RotationJobRecord;         // .persistCallback hooks D-07 durable checkpointing
  ctx: SdkContext;
  nodeKeySource?: (ipnsName: string) => { privateKey: Uint8Array; publicKey: Uint8Array; writeKey?: Uint8Array } | undefined;
}): Promise<void>;

// RotationJobRecord.persistCallback is the exact seam for D-07's durable checkpoint:
type RotationJobRecord = {
  rootNodeId: string;
  status: 'pending' | 'in-progress' | 'complete' | 'failed';
  completedNodeIds: Set<string>;
  frontier: Array<{ nodeIpnsName: string; parentReadKey: Uint8Array; /* … */ }>;
  persistCallback?: (job: RotationJobRecord) => void | Promise<void>; // NEW: write to IndexedDB here
};
```

### The web resolve chokepoint to wrap for SC#4/D-05 (verified, `apps/web/src/services/ipns.service.ts:141-149`)
```typescript
// Source: apps/web/src/services/ipns.service.ts (verified in-repo, current implementation —
// this function currently performs NO seq/generation high-water check at all)
export async function resolveIpnsRecord(
  ipnsName: string
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  return resolveIpnsRecordCore(ipnsName, {
    apiUrl,
    getAccessToken: async () => useAuthStore.getState().accessToken || '',
    axiosInstance: apiAxios,
  });
}
// SC#4/D-05 wiring: wrap the return value here — look up nodeId's highestSeq/highestGeneration
// from the new IndexedDB store, compare, fail closed on regression (throw a distinguishable
// error type so the toast layer can render "Stale data from server rejected."), else bump
// the high-water (monotonic-max) and return normally.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `executeLazyRotation` (per-share re-wrap loop in `share.service.ts`) | `rotateReadFromNode` (BFS walk, engine.ts) | Design doc §4.8, ratified this milestone | `executeLazyRotation` has zero callers in the current tree — it is dead code as of this research, not a live path that needs a careful cutover; deletion is safe and mechanical |
| `share_keys` table / per-child ECIES fan-out (`addShareKeys`, `reWrapForRecipients`) | Single `shares` grant row (`readDescriptorRef`/`writeDescriptorRef`), `O(1)` issuance | Phase 66 (DATA-01/02, complete) | Web's `share.service.ts` and `share.store.ts` have NOT been updated to the new shape yet — this phase must do that catch-up alongside the rotation wiring |
| Sequence-only IPNS anti-rollback (`resolve_sequence_strict`, in-memory, lost on restart per design §4.3) | Durable `{nodeId → highestGeneration}` + `{nodeId → highestSeq}` (M1 + §6.5) | This phase (ROT-07) | Closes the "colluding relay drops the rotation publish" residual; web currently has NEITHER check (verified: `resolveIpnsRecord` is a pure passthrough) |

**Deprecated/outdated:**
- `executeLazyRotation`, `addShareKeys`, `reWrapForRecipients` (all in `apps/web/src/services/share.service.ts`) — explicitly slated for deletion by D-12/SC#2.
- The legacy `ReceivedShare`/`SentShare` shapes in `apps/web/src/stores/share.store.ts` (`encryptedKey`, `encryptedIpnsKey`) — superseded by the API's `readDescriptorRef`/`writeDescriptorRef`/`rootGeneration` shape; not formally deprecated in a decision doc, but factually stale relative to the DTOs the API already returns.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `navigator.locks` is safe to adopt with no polyfill, given D-09's explicit double-run-safe fallback covers unsupported browsers | Standard Stack / Pattern D-09 | Low — D-09 already designs for the API being unavailable; worst case is the fallback path runs unconditionally on an unsupported browser, which is still correct, just less efficient |
| A2 | The recommended new API route for D-10/D-11 (`PATCH /shares/:shareId/rotate` or similar) is the right shape vs. reusing/extending an existing route | Common Pitfalls #3 | Medium — the exact route design (single-grant PATCH vs. a batch endpoint accepting the rotated set) is an implementation choice the planner/executor should confirm against the design doc's exact cutover intent before building; sizing could shift if a batch endpoint is preferred for the `O(rotated-nodes)` re-mint fan-out |
| A3 | Fetching all sent shares via `GET /shares/sent` and filtering client-side by `rootNodeId` is an acceptable v1 implementation of `GrantRemintCallbacks.queryGrantsFn` (no dedicated indexed-by-rootNodeId endpoint exists) | Common Pitfalls #3 / Don't Hand-Roll | Low-Medium — functionally correct at today's scale (mirrors the existing `findCoveringShares` client-side-filter pattern in `share.service.ts`), but not the "indexed query on `shares.rootNodeId`" the design doc §4.4 recommends for scale; acceptable for this milestone, flag as a future optimization if grant counts grow large |

**If this table is empty:** N/A — see rows above.

## Open Questions (RESOLVED)

> Both questions resolved during planning (2026-07-01). Q1 → plan 68-03 implements the recommended `PATCH :shareId/grant` route. Q2 → no plan touches `ensureFolderLoaded`/`createFolder`, matching the recommendation to leave the pre-existing stub out of Phase-68 scope (executor sanity-checks via the phase's own tests).

1. **Exact API route shape for D-10/D-11's grant re-mint persistence.** — RESOLVED (68-03)
   - What we know: `GrantRemintCallbacks.updateGrantFn(shareId, readDescriptorRef, newGeneration)` needs a backing mutation; `deleteGrantFn` already maps cleanly to the existing `DELETE /shares/:shareId`.
   - What's unclear: whether to add a single-grant `PATCH /shares/:shareId` (extend the existing hide/item-name PATCH family) or a purpose-built route; also whether `queryGrantsFn` should get a new `GET /shares/sent?rootNodeId=` filter param rather than client-side filtering of the full sent-shares list.
   - Recommendation: default to extending `PATCH /shares/:shareId` with optional `readDescriptorRef`/`rootGeneration` fields (smallest DTO/controller delta, consistent with the existing hide/item-name PATCH pattern) and defer the `rootNodeId` query-param filter unless the planner judges the O(all sent shares) client-side filter unacceptable for this milestone.

2. **Whether `packages/sdk`'s `ensureFolderLoaded`/`createFolder` stub-throws (`'not implemented — phase 63'`) block any Phase-68 mutation path.** — RESOLVED (out of scope; executor sanity-check)
   - What we know: `moveItem` explicitly does NOT call `ensureFolderLoaded` ("moveItem does not auto-load" per its own comment) and requires both folders pre-loaded via direct `FolderTree.get()`; `renameItem`/`deleteItem`/`deleteToBin` DO call `requireFolder`, which falls back to the throwing `ensureFolderLoaded` only when the folder isn't already in `FolderTree`.
   - What's unclear: whether the web app's existing navigation flow always pre-populates `FolderTree` before a rename/delete is possible (likely yes, since the file browser must have loaded the folder to show the delete button) — if so this stub-throw is a latent-but-unreachable path for Phase 68's flows and out of scope; if there is a reachable path (e.g., search-result delete without prior navigation) it could throw unrelated to rotation.
   - Recommendation: the planner should NOT scope fixing `ensureFolderLoaded`/`createFolder` into Phase 68 (out of the stated boundary and requirements) but should have the executor verify via a quick manual/E2E check that the phase's own new test coverage doesn't trip this pre-existing stub.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Browser `indexedDB` | D-07 durable high-water store | Runtime-dependent (unavailable in private/incognito on some browsers) | n/a | D-08: degrade to §4.3 first-contact path, one-time warning notice, in-memory session floor |
| Browser `navigator.locks` (Web Locks API) | D-09 multi-tab leader election | Runtime-dependent (secure-context/HTTPS only; some older browsers lack support) `[CITED: MDN]` | n/a | D-09: both tabs run idempotently — safe via the idempotent walk + CAS-409 re-merge |
| `apps/api` `PATCH` grant-update route | D-10/D-11 owner reconcile persistence | Not yet built (verified absent from `shares.controller.ts`) | n/a | None — this is new work required by this phase, not an environment gap with a runtime fallback |

**Missing dependencies with no fallback:**
- The `apps/api` grant-update endpoint for D-10/D-11 — must be built as part of this phase (see Common Pitfalls #3 and Open Question #1).

**Missing dependencies with fallback:**
- `indexedDB` unavailability — D-08 fallback path already specified by CONTEXT.md decisions.
- `navigator.locks` unavailability — D-09 fallback path already specified by CONTEXT.md decisions.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest (`apps/web/vitest.config.ts`, verified: `environment: 'node'`, `globals: true`) |
| Config file | `apps/web/vitest.config.ts` |
| Quick run command | `pnpm --filter @cipherbox/web test -- <file-glob>` |
| Full suite command | `pnpm --filter @cipherbox/web test` |

Rotation-engine-level tests (crash-safety, resume, content-key rotation, HIGH-3/HIGH-4) already live in `packages/sdk-core/src/__tests__` and `tests/sdk-e2e` — Phase 68 does not need to re-prove engine correctness, only that the web wiring correctly invokes it and correctly persists/enforces the durable high-water.

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ROT-07 / SC#1 | `{nodeId→highestGeneration}` persists across a simulated page reload; a downgrade is rejected fail-closed after restart | unit (fake-indexeddb or real IDB in jsdom/happy-dom test env) | `pnpm --filter @cipherbox/web test -- rotation-state.test.ts` | ❌ Wave 0 — needs a test-env IndexedDB shim since current `environment: 'node'` has no native IDB |
| SC#2 | `executeLazyRotation` deleted; delete/move/rename-on-scope-exit call `rotateReadFromNode`; `addShareKeys`/`reWrapForRecipients` removed from fan-out | unit (spy on `deps.rotate`, mirroring `scope.test.ts`'s existing pattern in sdk-core) | `pnpm --filter @cipherbox/sdk test -- client.test.ts` (or new `client-rotation.test.ts`) | ❌ Wave 0 |
| SC#3 | `folderTree` reconciled against current `sequenceNumber` before rotation publish; reconcile failure defers | unit (mock resolve returning a mismatched sequence, assert rotation NOT published + defer-notice emitted) | `pnpm --filter @cipherbox/sdk test -- client.test.ts` | ❌ Wave 0 |
| SC#4 | Durable seq high-water wired into `resolveIpnsRecord`; regression → fail-closed error | unit (mock resolve returning a lower seq than the stored high-water; assert throw, not silent accept) | `pnpm --filter @cipherbox/web test -- ipns.service.test.ts` | ❌ Wave 0 (no existing `ipns.service.test.ts` found in this research pass — verify at plan time) |
| SC#5 | No `.spec.ts` files under `apps/web/src` | static check | `find apps/web/src -name "*.spec.ts"` (must return empty) | n/a — shell check, not a test file |
| §7.3 test 5 (design doc) | M1 generation downgrade survives restart | unit / integration | Same as ROT-07/SC#1 row above | ❌ Wave 0 |
| §7.3 test 13 | Within-generation seq rollback rejected via seq high-water | unit | Same as SC#4 row above | ❌ Wave 0 |
| §7.3 test 14 | First-contact/cold-device rollback rejected via `SealedChildRef.versionFloor` | unit (fresh client, no local high-water, below-floor seq from relay → rejected) | New test file, e.g. `rotation-state.test.ts` or `ipns.service.test.ts` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** targeted `vitest run <file>` for the touched service/store/client method.
- **Per wave merge:** `pnpm --filter @cipherbox/web test` and `pnpm --filter @cipherbox/sdk test` full suites.
- **Phase gate:** Full suite green (both packages) + `find apps/web/src -name "*.spec.ts"` empty, before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `apps/web/src/services/rotation-state.test.ts` — covers SC#1/ROT-07 durable high-water persistence + monotonic-max + regression rejection
- [ ] A test-environment IndexedDB shim — `apps/web/vitest.config.ts` currently sets `environment: 'node'` (no native `indexedDB`); confirm whether `fake-indexeddb` (or switching this one test file's environment to `jsdom`/`happy-dom`) is needed. **This is a real Wave 0 infra gap, not a nitpick** — verify at plan time whether `fake-indexeddb` is already a devDependency anywhere in the monorepo (not found in this research pass) or needs adding.
- [ ] `packages/sdk/src/__tests__/client-rotation.test.ts` (or extend `client.test.ts`) — covers SC#2/SC#3 scope-exit wiring + reconcile-defer, using the existing `vi.fn()` injection pattern already proven in `scope.test.ts`
- [ ] `apps/web/src/services/ipns.service.test.ts` — no such file was found in this research pass; confirm at plan time whether `ipns.service.ts` has any existing test coverage before assuming this is greenfield

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | No | Out of scope — this phase does not touch login/session |
| V3 Session Management | No | Out of scope |
| V4 Access Control | Yes | This phase's entire purpose is access-control soundness (read-key rotation on scope exit) — the control is `hasCoveringGrant` + `rotateReadFromNode`, already built; this phase must not weaken the "either source covering ⇒ rotate" invariant |
| V5 Input Validation | Yes | The new IndexedDB high-water values must be validated on read (reject non-numeric/negative/malformed stored values as if the store were absent — same posture as `identity.ts`'s "validate payload shape before touching crypto" pattern) before use in a fail-closed comparison |
| V6 Cryptography | Yes (indirectly) | No new crypto primitives are introduced — this phase only *invokes* existing AEAD/ECIES primitives (`wrapKey`, `sealChildReadKey`) inside already-built engine code; never hand-roll comparison logic that substitutes for AAD binding (see Pitfall 5) |

### Known Threat Patterns for this phase

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Colluding relay withholds/replays a stale signed IPNS record post-revocation (design §4.3 M1) | Spoofing / Tampering | Durable client-side `{nodeId→highestGeneration}` high-water, fail-closed on regression (ROT-07 — this phase's core deliverable) |
| Colluding relay serves a within-generation stale-sequence record (design §6.5) | Tampering | Durable `{nodeId→highestSeq}` high-water, fail-closed on regression |
| Relay omits a grant root from `activeGrantRootIpnsNames` to suppress rotation (T-63-17) | Repudiation / Elevation of privilege | `hasCoveringGrant` cross-checks `localGrantRecord` independently — this phase must actually populate `localGrantRecord` from real client-held grant state (tie-in to the share.service.ts fetch-stub gap, Pitfall 2) or the cross-check is vacuously always-relay-trusting |
| Stale `folderTree` causes a rotation publish on top of already-superseded state, silently missing a revocation (the `#489`/`#494` desync class) | Tampering / DoS-of-security-guarantee | Reconcile-before-publish (D-04), defer never skip |
| A revoked reader observes the rotation-progress badge/toast timing to infer subtree size or in-progress state | Information disclosure (low severity) | UI-SPEC already scopes the badge to `aria-live="polite"`, non-interactive, no per-item detail exposed — no new work needed, just don't regress this in implementation |

## Sources

### Primary (HIGH confidence — verified directly against the live repository this session)
- `packages/sdk-core/src/rotation/engine.ts` — `rotateReadFromNode`, `rotateOne`, `RotationJobRecord`, `GrantRemintCallbacks`, `reMintGrantsRootedAt` (full signatures and security docblocks read in full)
- `packages/sdk-core/src/rotation/scope.ts` — `hasCoveringGrant`, `maybeRotateOnScopeExit`, `CoverageParams`, `ScopeExitDeps` (full file read)
- `apps/web/src/services/share.service.ts` — confirmed stub-throw functions and dead `executeLazyRotation`/live `addShareKeys`/`reWrapForRecipients` (full file read)
- `packages/sdk/src/client.ts` — `renameItem` (L495), `moveItem` (L554), `deleteItem` (L689), `deleteToBin` (L1451), `loadFolder` anti-clobber pattern (L369-381), `ensureFolderLoaded`/`createFolder` stub-throws (L438, L477) (partial read, ~760 lines + L1406-1506)
- `packages/sdk/src/state/folder-tree.ts` — full `FolderTree` class read
- `apps/web/src/services/ipns.service.ts` — full file read, confirms `resolveIpnsRecord` is a pure passthrough with no high-water logic today
- `apps/web/src/lib/device/identity.ts` — full file read, IndexedDB pattern source
- `apps/web/src/services/search-index.service.ts` — partial read (IndexedDB open pattern, lines 1-150)
- `apps/web/src/stores/share.store.ts`, `apps/web/src/hooks/useFolderMutations.ts`, `apps/web/src/components/file-browser/useFileBrowserActions.ts` — full reads
- `apps/web/src/stores/notification.store.ts`, `apps/web/src/components/NotificationToast.tsx`, `apps/web/src/components/layout/AppHeader.tsx` — full/partial reads confirming UI-SPEC extension points
- `apps/web/vitest.config.ts` — confirms `include: ['src/**/*.test.ts']` only
- `packages/api-client/src/generated/shares/shares.ts`, `packages/api-client/src/models/receivedShareResponseDto.ts` — confirms `sharesControllerGetReceivedShares`/`GetSentShares` exist with `readDescriptorRef`/`rootGeneration`/`rootNodeId` already generated
- `apps/api/src/shares/shares.controller.ts`, `apps/api/src/shares/shares.service.ts` — confirms no grant-update PATCH route exists; confirms `revokeShare` is a hard `remove()`
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §2.6, §4.2–§4.8, §5, §6.1–§6.8, §7.1–§7.3 — full read of all cited sections

### Secondary (MEDIUM confidence)
- [MDN: Web Locks API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API) `[CITED]` — general API shape and secure-context requirement; exact per-browser version support not independently re-verified beyond the search summary

### Tertiary (LOW confidence)
- None — no unverified-only claims were included; all `[ASSUMED]`-risk items are captured in the Assumptions Log with explicit risk notes rather than stated as fact.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new packages, native Web APIs only, verified via direct repo inspection
- Architecture: HIGH — every chokepoint (client.ts methods, ipns.service.ts, folder-tree.ts) was read directly; the two scope gaps (share fetch stubs, missing grant-update endpoint) were confirmed by grep/read, not inferred
- Pitfalls: HIGH — sourced from explicit `@security` docblocks in the engine code, verified vitest config, and verified controller routes (not speculative)

**Research date:** 2026-07-01
**Valid until:** 14 days (this is an actively-changing greenfield milestone at 78% completion — file line numbers and stub states will drift quickly; re-verify line references before executing any plan derived from this research if more than ~2 weeks elapse)
