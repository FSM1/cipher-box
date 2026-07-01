# Phase 68: Web Integration — Rotation UX and Durable Client State - Context

**Gathered:** 2026-07-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Cut the **web app** over to the v2.0 read key-chaining rotation model. Three deliverables (ROT-07 + ROADMAP SC 1–5):

1. All revocation-triggering mutations (delete, move, rename-on-scope-exit) call `rotateReadFromNode`; `executeLazyRotation` is deleted and `addShareKeys` / `reWrapForRecipients` are removed from per-mutation fan-out.
2. A **durable IndexedDB** anti-rollback floor — `{nodeId → highestGeneration}` (M1) and `{nodeId → highestSeq}` (§6.5) — that survives page reload and fails closed on regression.
3. `folderTree` is reconciled against the current `sequenceNumber` **before** any rotation publish; reconcile failure defers (never publishes rotation on stale state).

This is the **web-side integration** of engine/crypto already built in Phases 62–67. No new crypto primitives, no schema changes. UI hint: **yes** (rotation progress + offline/fail-closed messaging → follow-up `/gsd-ui-phase 68`).

**Not this phase:** FUSE/WinFsp/Rust integration and the Q3 FUSE-side authority mirror → **Phase 69**. The rotation engine internals (already sound as of Phase 64). Server-side generation gate (Phase 66, shipped).

</domain>

<decisions>
## Implementation Decisions

### Rotation UX — co-writer offline (Q1) & progress
- **D-01 (Q1 — offline co-writer):** Explicit **fail-closed error + one-tap "Refresh access"**. A stale/rotated-out co-writer's write fails closed with a clear message and a "Refresh access" action that re-resolves the write descriptor. If they were rotated out, the message escalates to "write access revoked." No silent grace window — honors the explicit WRITE-03 / ADR 0001 model.
- **D-02 (progress):** **Synchronous fast root cut + background badge for the tail walk.** The root cut (the actual revocation for the revoked reader) completes synchronously with a spinner; the `O(items)` tail runs as a background, resumable walk with a persistent "Finishing revocation…" indicator that survives reload. Matches the Phase 63 Q2 decision (web = first-class best-effort host; long multi-session web rotation for large revokes is an accepted documented limitation).
- **D-03 (badge placement):** **Global app-header/status badge**, visible across folder navigation (the walk spans a subtree, not one folder), with a "Resuming revocation…" state after reload. Exact copy and visual spec **deferred to `/gsd-ui-phase 68`**.

### Reconcile & fail-closed behavior
- **D-04 (reconcile failure — SC#3):** **Defer, never skip.** If `folderTree` reconcile against the current `sequenceNumber` fails, the mutation **defers** (does not publish a rotation on stale state) with an auto-retrying "Syncing latest state…" notice. The `#489`/`#494` desync class must not produce a silent missed revocation.
- **D-05 (regression detected — SC#1/#4):** **Hard fail-closed.** A generation or seq regression from the relay raises a hard fail-closed error toast ("stale data from server rejected") — never silent acceptance. Surfaced as a **per-mutation toast**, not a global page block.
- **D-06 (deferred-mutation terminal behavior):** **Bounded backoff → terminal error + manual retry; nothing queued.** Auto-retry the defer path with backoff for a bounded window (target ~5 attempts / ~30s — exact numbers are Claude's discretion); on exhaustion surface a terminal "couldn't complete securely — retry" with a manual retry action. The mutation is **not** applied (fail-closed, SC#3). **No durable retry queue** (that would be scope creep).

### Durable client state (ROT-07 / M1 + §6.5)
- **D-07 (storage):** Persist both high-water maps (`{nodeId → highestGeneration}`, `{nodeId → highestSeq}`) in a **dedicated IndexedDB object store**, reusing the existing `idb` wrapper pattern (`search-index.service.ts`, `lib/device/identity.ts`), keyed by `nodeId`, **monotonic-max** on write. The generation floor is **seeded from the grant's `rootGeneration`** (owner-vouched) on first contact. Store name/version/eviction = Claude's discretion.
- **D-08 (IndexedDB unavailable/cleared):** **Degrade to the design §4.3 first-contact path, warn once.** When the durable store is unavailable (private mode) or was cleared, fall back: seed from grant `rootGeneration` and cross-check the envelope `generation` against the parent `SealedChildRef.generation` mirror + `versionFloor`; hold an in-memory session floor. Reads continue and anti-rollback is still held by the signed parent chain. Show a **one-time** "secure cache unavailable" notice. (The colluding-relay self-consistent-old-snapshot residual is already an accepted irreducible per §4.3.)
- **D-09 (multi-tab coordination):** **`navigator.locks` leader + monotonic-max high-water.** One tab is elected to drive the tail walk; other tabs observe. High-water writes are monotonic-max (last-write-wins is safe). If Web Locks is unavailable, **both tabs run idempotently** — still safe via the idempotent walk + CAS-409 re-merge (Phase 64 D-07: double-rotation only strengthens revocation).

### Q3 — write-recipient-vs-owner sub-share authority (web mirror)
- **D-10 (authority — mirrors Phase 65 D-01):** Crypto is locked upstream: write-recipient **C** unlinks + bins with **no cross-principal revoke attempt and no new schema**. The **owner's** reconcile+rotation pass re-derives dangling grants from the existing `shares WHERE rootNodeId ∈ destroyed/binned-subtree` enumeration (the inverted HIGH-3 `reMintGrantsRootedAt` seam). Phase 68 wires this owner reconcile **live on web** (Phase 65 built the mock-tested seam; Phase 66 cut over the `shares` schema).
- **D-11 (owner reconcile cadence):** **Eager — on login/app-open + opportunistically after the owner's own mutations.** Minimizes the dangling-grant window with no new schema. **C receives no advisory**; the exposure window is already documented (ADR 0002 — read-revoke protects future content/navigation only).

### Cutover scope (from ROADMAP success criteria)
- **D-12 (delete list — SC#2):** Delete `executeLazyRotation` from `apps/web/src/services/share.service.ts`; remove `addShareKeys` and `reWrapForRecipients` from per-mutation fan-out paths. All revocation-triggering mutations route through `rotateReadFromNode`. Fold in the Phase 64 OUT-tagged `sdk-client-move-publish-durability` work (dest-before-source publish ordering + unreadable-descendant enumeration) since it ties into `folderTree`/sequence reconcile.
- **D-13 (test extension — SC#5):** All new web test files use `.test.ts` (never `.spec.ts`). apps/web vitest `include` is `*.test.ts` only — `.spec.ts` files are silently skipped in CI. `find apps/web/src -name "*.spec.ts"` must return empty.

### Claude's Discretion
- Exact retry counts / backoff curve for D-06.
- IndexedDB store name, schema version, and eviction policy for D-07.
- Badge copy, visual treatment, and per-state text (D-03) → resolved at `/gsd-ui-phase 68`.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design source of truth (read first)
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — the read key-chaining design. Sections directly governing this phase:
  - §4.3 — M1 durable client generation floor (seed from grant `rootGeneration`; first-contact cross-check vs parent `SealedChildRef.generation` mirror; fail-closed on regression). Backs D-07/D-08.
  - §6.5 — durable per-node `{nodeId → highestSeq}` seq high-water; reject `seq < high-water` regardless of source. Backs D-05/D-07.
  - §2.6 — `versionFloor` on `SealedChildRef` (owner-vouched cold/first-contact floor). Backs D-08.
  - §4.6 / §4.7 — concurrency, CAS-409 re-merge, batched parent-publish, forward-only-generation invariant. Backs D-09.
  - §7.3 — test strategy: test 5 (M1 generation downgrade, durable high-water survives restart), test 13 (within-generation seq rollback), test 14 (first-contact/cold-device rollback via `versionFloor`).
  - table L577 / step L591 — the `apps/web` cutover checklist (`executeLazyRotation` → `rotateReadFromNode`; drop per-mutation fan-out; reconcile `folderTree`; durable M1 + seq high-water).

### ADRs
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation = full Ed25519 rotation; the explicit "offline co-writer cannot write until re-fetch" model (backs D-01).
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — honesty caveat bounding the Q3 exposure window and the "no advisory to C" call (backs D-10/D-11).
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — frozen 45-byte AAD encoding for `buildNodeAad` (needed by the resolve/unseal path the web wires into).

### Glossary & schema (cite, do not redefine)
- `CONTEXT.md` (repo root) — pinned glossary: the three counters (`generation` / `keyEpoch` / `sequenceNumber` — never conflate), `readKey`/`writeKey`, `readDescriptorRef`/`writeDescriptorRef`.
- `docs/METADATA_SCHEMAS.md` — the static `node/v3` schema + the `generation`-single-source-of-truth invariant (per-node authoritative on the child's own envelope; every mirror is a staleness witness).

### Requirements
- `.planning/REQUIREMENTS.md` — **ROT-07** (durable `{nodeId → highestGeneration}` high-water, seeded from grant `rootGeneration`, fails closed on regression), **WRITE-03** (offline co-writer explicit), ROADMAP SC 1–5.

### Prior phase context (carry-forward locks)
- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-CONTEXT.md` — **D-02 / Q2**: web = first-class best-effort rotation host; host-agnostic engine; long chunked multi-session web rotation accepted as documented limitation; durable resume-across-reload is this phase.
- `.planning/phases/64-rotation-soundness-revocation-guarantees/64-CONTEXT.md` — **D-06** node-identity/`generation` preservation on `updateFolderMetadataAndPublish`; crash-resume idempotency (`verifySubtreeClean`); the OUT→Phase-68 `sdk-client-move-publish-durability` item (folded via D-12).
- `.planning/phases/65-sdk-write-chain-bin-re-link-and-invite-claim/65-CONTEXT.md` — **D-01 / Q3**: write-recipient unlink+bin, no cross-principal revoke, no new schema; owner reconcile re-derives dangling grants from the inverted HIGH-3 seam (backs D-10/D-11).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `packages/sdk-core/src/rotation/engine.ts` — `rotateReadFromNode` (L753), `rotateOne` (L530), `reMintGrantsRootedAt` (L379). The web replaces `executeLazyRotation` with `rotateReadFromNode`; the owner reconcile (D-10) drives `reMintGrantsRootedAt`.
- `packages/sdk-core/src/rotation/scope.ts` — `hasCoveringGrant` (L98), the scope-exit predicate that decides rotate-vs-pure-relink.
- `apps/web/src/services/search-index.service.ts` + `apps/web/src/lib/device/identity.ts` — existing IndexedDB (`idb` wrapper) usage; reuse this pattern for the durable high-water store (D-07).

### Established Patterns
- **Web/SDK folder-state desync:** state lives in BOTH the Zustand store (`apps/web/src/stores/folder.store.ts`) and the SDK `folderTree`; reconcile `folderTree` before sdk-core mutations — IPNS `sequenceNumber` is the clock (backs D-04).
- **Transport-decoupled share callbacks:** grant issuance/persistence goes through injected callbacks (Phase 63 D-05 / Phase 64 D-04) — the owner reconcile (D-10) wires the real `shares` persistence (schema cut over in Phase 66) behind that seam.
- **Fail-closed IPNS resolve:** the verified-resolver chokepoint (v1.1 HARD block) is where the seq high-water hooks in (D-05).

### Integration Points
- `apps/web/src/services/share.service.ts` — delete `executeLazyRotation` (L501); remove `addShareKeys` (L251) / `reWrapForRecipients` (L377) from per-mutation fan-out (D-12).
- `apps/web/src/services/ipns.service.ts` — `resolveIpnsRecord` web resolve path; wire the durable `{nodeId → highestSeq}` high-water check here (SC#4 / D-05).
- `apps/web/src/stores/folder.store.ts` — `folderTree` / `sequenceNumber` reconcile-before-publish (D-04).
- Mutation call sites (delete/move/rename) in `apps/web/src/hooks/` (`useFolderMutations`, `useFileOperations`, `useFileBrowserActions`) route to `rotateReadFromNode` on scope exit.

</code_context>

<specifics>
## Specific Ideas

- The user took the **recommended option on all eight decisions across two discussion rounds** — terse/decisive, consistent with the Phase 63/64/65 "recommended on all" pattern. Treat the recommendations as firm locks, not tentative defaults.
- Fail-closed is the through-line: every ambiguous state (reconcile fail, regression, missing durable store, offline co-writer) resolves toward **surface-and-block**, never silent acceptance — this is a security phase wearing a UX hat.

</specifics>

<deferred>
## Deferred Ideas

- **Q3 option (c) — owner-signed revocation-request queue** (C enqueues, owner/desktop/TEE-agent executes on next online). A real feature; deferred (Phase 65 already parked it). Revisit only if the eager owner-reconcile window (D-11) proves insufficient.
- **Durable cross-reload retry queue** for deferred mutations (rejected in D-06 as scope creep) — revisit if transient-relay defers prove common in practice.
- **Q3 FUSE-side authority mirror** and all FUSE/WinFsp/Rust rotation integration → **Phase 69**.
- **Badge copy / visual / state text** → `/gsd-ui-phase 68` (D-03).

</deferred>

---

*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Context gathered: 2026-07-01*
