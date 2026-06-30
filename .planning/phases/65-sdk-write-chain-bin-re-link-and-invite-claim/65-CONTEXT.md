# Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim - Context

**Gathered:** 2026-06-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 65 builds the **write plane** in `packages/sdk-core` + `packages/sdk`, on top of the Phase-62 `node/v3` codec and the Phase-63/64 read-chain rotation engine. Four deliverables (WRITE-01..04, ADR 0001):

**In scope (WRITE-01, WRITE-02, WRITE-03, WRITE-04):**

- **WRITE-01 — structured recursive write chain.** Implement the stubbed `packages/sdk/src/share/shared-write.ts` (every export currently throws `"not implemented — phase 65 (write-chain)"`). Each node's write-body holds its Ed25519 signing material; each **parent write-body** seals the child `writeKey` (`writeChildren[].writeKeySealed = AES-GCM(child.writeKey, key=parent.writeKey, role=0x04 child-writekey)`). The write link lives in the parent **write-body**, never in `SealedChildRef` (which stays read-only, one sealed field `readKeySealed`). A read-only holder (only `readKey`/`readDescriptorRef`) can never reach signing material — verified by attempting a write-body unseal with only the `readKey`.
- **WRITE-02 — write-revocation = (c) full Ed25519 rotation** (ADR 0001). New Ed25519 keypair + k51 name **per node**, cascading parent re-points **upward** to the share root, re-pointing surviving co-grants and owner devices. This is a **distinct, heavier** operation than read-rotation (design §5.3: "not a strict subset of the read-rotation machinery").
- **WRITE-03 — surviving co-writer re-key.** Rotated Ed25519 key re-wrapped into each surviving co-writer's `writeDescriptorRef`; an offline co-writer gets an explicit "cannot write until re-fetch" error on next attempt.
- **WRITE-04 — tombstone the rotated-out IPNS name** (intent + client-side removal from the TEE republish batch via the unenroll callback). The **live** publish-gate rejection + resolve-410 enforcement is mock-tested here, cut over for real in Phase 66 (see D-02).
- **Bin restore = pure re-link** (`BinEntry` re-sealed under destination `readKey`, identical to a move); delete `originalFolderKeyEncrypted` + its re-encrypt-on-restore path from `packages/sdk/src/bin/index.ts` (the `node/v3` `BinEntry` already carries `nodeRef`, not the legacy fields — Phase 62 [62-05]).
- **Invite claim = re-wrap a single root `readKey`.** On claim, unwrap `readKey` with the URL-fragment ephemeral private key, re-wrap to the claimer's public key → a standard `shares` grant. Delete the `encryptedChildKeys[]` fan-out path from the invite-claim **logic** (sdk-core/sdk). Revoke = rotate the `readKey` (cuts the link and all claimers at once).
- **Wire the real `writeKey`** into the rotation engine's Phase-64 `nodeKeySource` seam (folds `rotateone-placeholder-writekey-phase65`).
- **TEST-01-style gate:** a real `tests/sdk-e2e` write-chain rotation round-trip (D-04).

**Out of scope (hard boundary — owned by later phases):**

- **All apps/api surface** — live `shares` schema (`readDescriptorRef`/`writeDescriptorRef` columns), `share_keys`/`addShareKeys` deletion, `encryptedChildKeys` column drop, tombstone state machine + publish-gate enforcement + resolve-410, atomic publish CAS, `folder_ipns` → `ipns_records` rename → **Phase 66**. Phase 65 exercises these behind injected callback seams (D-02 / Phase-64 D-04 discipline).
- **All apps/web surface** — `reWrapForRecipients` (now only in `apps/web/src/services/share.service.ts`), the `addShareKeysFn` callback type, `executeLazyRotation` → `rotateReadFromNode`, co-writer offline grace/notification UX (open question Q1), durable M1/seq high-water → **Phase 68**.
- **TEE lease-renewer contract** + `createSubfolder` TEE republish wiring → **Phase 67**.
- **`crates/fuse`** write plane, Q3 FUSE-side authority mirror → **Phase 69**.
- **The rotation-soundness follow-ups** (RR-01 merge re-enqueue, RR-02 `verifySubtreeClean` depth, grant-threading) → Phases 66/68 (see Deferred).

The app stays **intentionally non-runnable mid-milestone** (greenfield, single cutover). Do not pull later-phase apps/* deletions or migrations forward to make it runnable.

</domain>

<decisions>
## Implementation Decisions

### Q3 — write-recipient-vs-owner sub-share authority (D-01)

- **D-01:** **Model (a) — reconcile on owner sync; the exposure window is a documented residual.** (ROADMAP-mandated decision for this phase; mirrors to Phases 68/69.)
  - When a write-recipient **C** deletes / moves-out / overwrites a node inside a shared folder that the **owner** independently sub-shared to a third party **D**, C unlinks immediately (C holds the folder write keys and signs the folder publish) but **cannot** cryptographically revoke D — only the owner holds that node's rotation keys and authority over the `shares` rows. The unlink (C) and the revocation (owner) are split across two principals.
  - **Phase 65 behavior:** C's destroy/move path **unlinks + bins** with **no cross-principal revoke attempt** and **no new schema**. The owner's reconcile+rotation pass re-derives the dangling grants from the existing **`shares WHERE rootNodeId IN (destroyed/binned subtree)` enumeration** (the HIGH-3 `reMintGrantsRootedAt` seam, inverted) — it is wired **live in Phase 66/68**, needs **no new marker** here.
  - **Exposure window:** D retains read access to the now-binned snapshot until the owner's next online reconcile. **Accepted as a documented residual**, bounded by the owner's next online session. Per ADR 0002 the binned content is **already irreducibly readable** via IPFS, so the marginal exposure is the navigation/future-write window, which closes on the owner's reconcile-rotation.
  - **Rejected:** (b) block C's destructive op — requires the relay to tell C "this node has active owner grants," **leaking share existence to a delegate**. (c) owner-signed revocation request queue — real feature, but new signed-request plumbing; **deferred** as a noted idea, not Phase-65 scope.

### Phase 65/66 transport boundary — and what "delete X" means per layer (D-02)

- **D-02:** **Hold the Phase-64 line (D-04 discipline): Phase 65 is `sdk-core`/`sdk` crypto + behavior only; everything DB/transport is mock-tested behind injected callbacks and cut over live in Phase 66.**
  - **Tombstone enforcement** — Phase 65 produces the tombstone **intent** (mark the rotated-out name, remove it from the TEE republish batch via the unenroll callback) and **mock-tests** the publish-gate rejection + resolve-410. The **live** apps/api publish-gate reject / resolve-410 / tombstone state machine is **Phase 66**.
  - **`writeDescriptorRef` co-writer persistence** — re-wrap crypto runs behind a **mocked `shares` query + mocked persist callback** (exactly as Phase-64 D-04 did for HIGH-3 read-grant re-mint). Live `shares` columns are **Phase 66**.
  - **What the ROADMAP's "delete `addShareKeys`/`reWrapForRecipients`/`encryptedChildKeys`" means given the layer split** (a deliberate refinement — the physical deletions live in apps/* which are later phases):
    - `reWrapForRecipients` — **already deleted from the sdk layer in Phase 63**. The only remaining copy is `apps/web/src/services/share.service.ts:469` → **Phase 68**. Nothing for Phase 65.
    - `addShareKeys` — the apps/api endpoint/service (`shares.service.ts:207`, `shares.controller.ts:277`) → **Phase 66** (schema cutover); the `client.ts` `addShareKeysFn` callback **type** stays quarantined → **Phase 68** (per Phase 63). Phase 65 rewires the sdk add-item / invite-claim **logic** so it no longer depends on the fan-out.
    - `encryptedChildKeys` — the apps/api invite **column/DTO/service** drop → **Phase 66**; Phase 65 deletes the **invite-claim fan-out logic** in sdk-core/sdk and replaces it with the single-`readKey` re-wrap.
  - Net: Phase 65 makes these symbols **dead from the client's perspective** (mock-tested); the physical apps/api + apps/web removals ride Phases 66 and 68. This keeps Phase 65 unblocked by the DB and preserves the single-cutover, non-runnable-greenfield discipline.

### Co-writer offline handling (D-03)

- **D-03:** **Explicit SDK error only this phase.** A co-writer offline during write-key rotation gets a clear `"cannot write until re-fetch"` SDK error; on next attempt the surviving co-writer re-fetches the re-wrapped `writeDescriptorRef` and proceeds. WRITE-03 itself says "explicit." **No** grace-period / notification / pending-rekey marker — that is **open question Q1, already assigned to Phase 68** (web UX). Do not pull it forward into the SDK layer. The exact error type/shape is Claude's discretion.

### Write-revocation E2E proof (D-04)

- **D-04:** **Real `tests/sdk-e2e` write-chain rotation round-trip is the phase gate** (mirrors Phase-64 TEST-01). Extend the suite with a live round-trip that exercises: a node carrying a `writeBody`, write-revocation minting a **new k51 name per node**, the **parent re-point cascade to the share root**, surviving co-writer re-wrap, and tombstone-**intent** on the rotated-out names. Reuse the Phase-63/64 **manual-node build pattern** (`sealNode` + `addToIpfs` + `createAndPublishIpnsRecord` with known keypairs) — now with **real write-bodies** since the codec supports them. Honor SDK-E2E prereqs (docker stack + `pnpm --filter @cipherbox/api dev`; redis on **6380**; temp axios interceptor for real 400s). Unit-only was rejected — the heaviest operation in the system must be proven end-to-end against a real API.

### Write-chain implementation discipline — call the Phase-62 codec; wire the real writeKey (D-05)

- **D-05:** **The `node/v3` write-body codec is Phase-62-complete — Phase 65 CALLS it, never reimplements it** (the "fill seams, don't re-architect" discipline from Phases 62/63/64). `packages/core/src/node/seal.ts` already implements: `sealNode(node, readKey, writeKey)` (seals `writeBody` → `writeSealed` under `writeKey`, role `0x01`, only when `node.writeBody` is set), `unsealNode(published, readKey, writeKey?)` (unseals `writeBody` only when `writeKey` supplied), `encodeWriteBody`/`decodeWriteBody`, and role `0x04 child-writekey` for the write link (ADR 0003, KAT-frozen).
  - Phase 65 work is **wiring + the write-revocation driver**: implement `shared-write.ts` to use the codec's write-body; build the write-revocation cascade (separate from / composed with `rotateReadFromNode`, planner's discretion per design §5.3); and wire the **real `writeKey`** into the rotation engine's Phase-64 `nodeKeySource` seam (`packages/sdk-core/src/rotation/engine.ts` ~L382/L399/L512-523 + the Phase-65 comments at L92/L157/L213/L227), removing the placeholder. The Phase-64 fail-closed guard (rejects all-zero/malformed/wrong-length IPNS keys) stays.

### Bin re-link + invite claim re-wrap (locked by design — D-06)

- **D-06:** **Locked by design §3.10 / §3.11 — restated for implementation.** Bin restore re-seals the node's own `readKey` under the destination parent `readKey` (pure re-link, no content re-encrypt); delete `originalFolderKeyEncrypted` + the re-encrypt-on-restore path (`packages/sdk/src/bin/index.ts`). Invite claim unwraps the share-root `readKey` with the URL-fragment ephemeral key and re-wraps to the claimer (one standard `shares` grant per claimer of the same `readKey`); delete the `encryptedChildKeys[]` fan-out logic. Read/write keys are **independent** — a write-revoke rotates only the write plane and does **not** touch the read chain (ADR 0001 consequences; design §2.2). "Revoke write but keep read" composition (downgrade-to-read-only vs full revoke) is a **caller/product** concern (Phase 68), not the SDK primitive.

### Claude's Discretion

- The write-revocation driver shape — a distinct `rotateWriteFromNode` vs an extension of `rotateReadFromNode` (design §5.3 frames write-revoke as structurally heavier: mints new k51 names, cascades **upward**). Planner decides; keep the read chain invariant.
- Whether Phase 65 un-stubs `createFileMetadata`/`createSubfolder` to emit real write-bodies, or continues the manual-node-build pattern for the e2e. Prefer the minimum that proves WRITE-01..04.
- The exact co-writer "cannot write until re-fetch" error type/shape (D-03).
- Internal factoring of `shared-write.ts`, the write-chain walk, and how the mocked `shares`/persist + unenroll callbacks are structured (extend the Phase-64 seams).
- How the e2e injects/verifies the parent re-point cascade and tombstone-intent.

### Folded Todos

- `2026-06-29-rotateone-placeholder-writekey-phase65.md` (area `sdk-core`, `resolves_phase: 65`) — `rotateOne` passes an all-zeros placeholder `writeKey` to `sealNode`. Folded per D-05: wire the **real** `writeKey` from the write-body into the rotation engine and add a test covering rotation of a node that **has** a `writeBody`. (FLAG-63-U1.)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design source of truth (read first)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — single source of truth for v2.0. Phase-65 sections:
  - **§1.3 / §5.2** the two gaps + ground truth — `shared-write.ts:138-141,311` ECIES-wraps the raw Ed25519 key (cryptographically inert delete); publish auth is key-possession only (`ipns.service.ts:226`).
  - **§2.2** two sealed bodies + the **resolved write-body shape** (structured recursive write chain; write link in the parent write-body; role `0x04`).
  - **§2.3 / §2.4** Node schema + published envelope (`writeBody.writeChildren[]`, `writeSealed`, omitted on read-only nodes).
  - **§2.5** AAD-bound seal, roles `{0x01 body, 0x02 child-readkey, 0x03 content, 0x04 child-writekey}`; topology enforced by parent-key possession, not AAD.
  - **§2.6 / §2.8** `SealedChildRef` is read-only (one sealed field); the read-root grant (`readDescriptorRef`/`writeDescriptorRef`).
  - **§3.4** add-item deletes `reWrapForRecipients`/`addShareKeys` fan-out; **§3.10** bin re-link (delete `originalFolderKeyEncrypted`); **§3.11** invite claim re-wrap (delete `encryptedChildKeys[]`).
  - **§5** write-revocation ratified as (c) full Ed25519 rotation — §5.1 comparison, §5.3 honest cost + co-writer re-key (review **m1**), §5.4 flip conditions, **§5.5 tombstone-and-keep** (publish gate rejects incl. EOL renewal; resolve 410; remove from republish batch).
  - **§6.4 / §6.6** TEE lease-renewer + atomic publish CAS — **context for tombstone**, but the live apps/api/TEE work is Phases 66/67.
  - **§7.2** buildable cutover order (step 4 = this phase: `shared-write.ts` rewrite, delete fan-out, `bin/*` re-link, invite claim re-wrap); **§7.3** test strategy (tests 10 bin-restore, 11 invite-claim, 12 republisher stale-CID, 20 tombstoned name — Phase-65-relevant; test 1 crash-safety is the gate scaffold).
  - **§9.2.3** Q3 (the D-01 decision); §9.2.1 Q1 (co-writer offline → Phase 68); §9.2.2 Q2 (rotation host → Phase 63/68).

### ADRs (authoritative freezes)

- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — **(c) full Ed25519 rotation**, ratified; the honest cost + co-writer-offline consequence; flip-to-(a) conditions. The read chain is invariant.
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — frozen seal/AAD byte encoding incl. role `0x04 child-writekey`; the write chain **calls** this primitive, never reimplements it.
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — the honesty caveat that bounds the Q3 exposure window (binned content already irreducibly readable).

### Requirements, roadmap, prior context

- `.planning/REQUIREMENTS.md` — **WRITE-01, WRITE-02, WRITE-03, WRITE-04** (this phase).
- `.planning/ROADMAP.md` — Phase 65 goal + 4 success criteria + the Q3 open question; Phase 66/67/68/69 boundaries (what defers).
- `.planning/phases/64-rotation-soundness-revocation-guarantees/64-CONTEXT.md` — carried-forward: **D-01** (the 64→65 seam: test-supplied keymap + fail-closed engine; Phase 65 supplies the real write-body key), **D-04** (transport-decoupled mock-tested crypto — mirrored here as D-02), **D-02** (out-of-band re-seal + batched parent-publish).
- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-CONTEXT.md` + `63-SECURITY.md` (FLAG-63-U1).
- `CONTEXT.md` (repo root) — pinned glossary: the **three counters** (`generation` / `keyEpoch` / `sequenceNumber` — never conflate), `readKey` / `writeKey`, descriptor refs. **Cite, do not redefine.**

### Schema reference (do not modify this phase)

- `docs/METADATA_SCHEMAS.md` — static `node/v3` schema (read-body, write-body, `SealedChildRef`, `BinEntry.nodeRef`).

### Parity / pitfalls

- `.planning/research/PITFALLS.md` — AAD byte-encoding drift = silent total decryption failure; the coverage-barrel pitfall (`shared-write.ts`, `engine.ts` stay named files, never `index.ts` barrels — coverage excludes barrels).
- `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/STRUCTURE.md` — package boundaries (where sdk-core / sdk / core sit).

### Implementation sites — TypeScript

- `packages/sdk/src/share/shared-write.ts` — **implement** the stubbed write-chain exports (all currently throw `"not implemented — phase 65 (write-chain)"`). Core WRITE-01/02/03.
- `packages/core/src/node/seal.ts` (+ `encode.ts`/`decode.ts`/`types.ts`) — **call, never reimplement**: `sealNode`/`unsealNode` (write-body params), `encodeWriteBody`/`decodeWriteBody`, role `0x04`.
- `packages/sdk-core/src/rotation/engine.ts` — wire the real `writeKey` into the `nodeKeySource` seam (~L382/L399/L512-523; remove placeholder per D-05/the folded todo); the write-revocation cascade driver.
- `packages/sdk/src/bin/index.ts` — bin restore pure re-link; delete `originalFolderKeyEncrypted` + re-encrypt-on-restore (`packages/sdk/src/__tests__/bin.test.ts` adjusts).
- Invite-claim logic in `packages/sdk-core`/`packages/sdk` (claim re-wrap; delete `encryptedChildKeys[]` build/consume) — `packages/sdk-core/src/__tests__/share/grant.test.ts` references `encryptedChildKeys` today.
- `packages/sdk-core/src/cas.ts` (`publishWithCas`) + `packages/sdk-core/src/ipns/index.ts` (`createAndPublishIpnsRecord`) — CAS-publish infra; first-publish-seq-1 convention.
- `tests/sdk-e2e/` — the **new write-chain rotation round-trip** (D-04); the Phase-63/64 manual-node + crash-safety scaffolds.
- **Mock seams (do not hit live apps/api):** the injected `shares` query / persist callback (`writeDescriptorRef` re-wrap) and the TEE unenroll callback (tombstone-intent), extending the Phase-64 D-04 pattern.

### Deletion targets that DEFER (do NOT delete in Phase 65 — see D-02)

- `apps/api/src/shares/shares.service.ts:207` `addShareKeys` (+ controller) → **Phase 66**.
- `apps/api/src/shares/share-invite.service.ts` + `entities/share-invite.entity.ts` + `dto/*` `encryptedChildKeys` column → **Phase 66**.
- `apps/web/src/services/share.service.ts:469` `reWrapForRecipients` + `client.ts` `addShareKeysFn` type → **Phase 68**.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **Phase-62 write-body codec is complete and callable** (`packages/core/src/node/seal.ts`) — `sealNode(node, readKey, writeKey)` seals `writeBody`→`writeSealed` (role 0x01) only when `node.writeBody` is set; `unsealNode(…, writeKey?)` returns `writeBody` only when a `writeKey` is supplied; role `0x04 child-writekey` for the parent→child write link. **Never reimplement** (D-05).
- **`shared-write.ts` stub scaffold** (`packages/sdk/src/share/shared-write.ts`) — exports already named and typed (taking `ipnsPrivateKey: Uint8Array`), all throwing the Phase-65 marker. Phase 65 fills the bodies + reshapes to the write-body model.
- **Rotation engine + `nodeKeySource` seam** (`packages/sdk-core/src/rotation/engine.ts`) — Phase-64 threads per-node IPNS keys via `nodeKeySource`; explicit "Phase 65 derives from write-body" comments at the seam. Fail-closed guard (reject all-zero/malformed/wrong-length keys) already in place.
- **sdk-e2e manual-node pattern** — Phase 63/64 build nodes by hand (`sealNode` + `addToIpfs` + `createAndPublishIpnsRecord`) with known keypairs; now extend with **real write-bodies** for the write-chain round-trip (D-04).
- **Transport-decoupled callback seam** (STATE.md: "Share module accepts callback functions for API calls"; Phase-63 D-05 / Phase-64 D-04) — the mock boundary for `writeDescriptorRef` re-wrap + tombstone unenroll (D-02).
- **`BinEntry.nodeRef`** (Phase 62 [62-05]) — already replaced `filePointer`/`folderEntry`/`originalFolderKeyEncrypted` in the `node/v3` `BinEntry`; Phase 65 owns the **re-link behavior**.

### Established Patterns

- **Coverage excludes `src/**/index.ts` barrels** ([[project-sdk-core-coverage-excludes-index-barrels]]) — `shared-write.ts` / `engine.ts` stay named files.
- **Zeroization — terminal-owner only** ([[project-zeroization-callee-must-not-zero-reused-buffer]]) — mint-and-own `writeKey'`/Ed25519 seeds zero on own failure paths; never zero caller-supplied keys. Flag the write-chain files in every security review.
- **Every first IPNS publish embeds sequence 1** ([[project-ipns-first-publish-embed-seq-1]]) — new k51 names minted on write-revocation are first publishes (`createAndPublishIpnsRecord` embeds `1n`).
- **Strict IPNS resolve recovers the Ed25519 pubkey from the k51 name** ([[project-ipns-resolve-ed25519-pubkey-from-name]]) — relevant to the new-name cascade + tombstone resolve.
- **Fail-closed over placeholders (Phase-64 D-01)** — no record published with an all-zeros/placeholder key.
- **Greenfield delete-outright** — no dual-codec / no migration; the app stays non-runnable mid-milestone.

### Integration Points

- **`packages/core` `dist/` rebuild required** before sdk-core/sdk typecheck after codec touches ([[project-cross-package-dist-staleness]]).
- **sdk-e2e is the only real client→API IPNS round-trip** ([[project-sdk-e2e-only-cross-package-publish-gate]]) — the WRITE phase gate (D-04); docker stack + `pnpm --filter @cipherbox/api dev`; redis on 6380.
- **SDK runtime partially quarantined** ([[project-sdk-runtime-not-fully-quarantined]]) — `client.ts` consumer re-wire is Phase 68; some `packages/sdk` unit tests are active and gate the Test CI job (grep for non-skipped tests before deferring any finding).
- **Checker subagents: static analysis only** ([[feedback-gsd-subagents-no-test-runs]]) — no concurrent vitest (RAM); design §7.3 echoes this.

</code_context>

<specifics>
## Specific Ideas

- The user took the **recommended option on all five questions** (Q3 authority, Q3 exposure window, 65/66 boundary, co-writer offline, e2e scope) — terse/decisive, consistent with the Phase-63/64 "recommended on all" pattern.
- **Scope refinement surfaced during discussion (D-02):** the ROADMAP's "delete `addShareKeys`/`reWrapForRecipients`/`encryptedChildKeys`" is a **per-layer split** — the sdk-layer fan-out is already gone (Phase 63), Phase 65 rewires the consumers, and the physical apps/api / apps/web symbol deletions ride Phases 66 / 68. This was confirmed by code scout (`reWrapForRecipients` lives only in apps/web; `addShareKeys`/`encryptedChildKeys` live in apps/api).
- **Wiring discipline (D-05):** the Phase-62 codec already provides the entire write-body primitive surface — Phase 65 is a wiring + driver phase, not a primitive-build phase. This keeps the heavy crypto out of scope creep.
- **Q3 needs no new schema** — the owner's reconcile re-derives dangling grants from the existing `shares WHERE rootNodeId ∈ destroyed-subtree` enumeration (the inverted HIGH-3 seam), wired live in Phase 66/68.

</specifics>

<deferred>
## Deferred Ideas

- **Q3 option (c) — owner-signed revocation-request queue** (C enqueues, owner/desktop/TEE-agent executes on next online). Real feature; deferred, not Phase-65 scope. Revisit if the dangling-window proves insufficient.
- **Co-writer offline grace/notification UX** (open question Q1) → **Phase 68** (web). Phase 65 ships only the explicit SDK error (D-03).
- **Live apps/api cutover** — tombstone state machine + publish-gate rejection + resolve-410, atomic publish CAS, `share_keys`/`addShareKeys` deletion, `encryptedChildKeys` column drop, `shares` slim (`readDescriptorRef`/`writeDescriptorRef`), `folder_ipns` → `ipns_records` → **Phase 66**.
- **Live apps/web cutover** — `reWrapForRecipients` deletion, `addShareKeysFn` type removal, `executeLazyRotation` → `rotateReadFromNode`, durable M1 generation + seq high-water, Q3 web-side authority mirror → **Phase 68**.
- **TEE lease-renewer contract** + `createSubfolder` TEE republish wiring (`createsubfolder-tee-republish-wiring`, `resolves_phase: 67`) → **Phase 67**.
- **`crates/fuse` write plane** + Q3 FUSE-side authority mirror → **Phase 69**.

### Reviewed Todos (not folded)

- `2026-06-29-createsubfolder-tee-republish-wiring.md` (`resolves_phase: 67`) — TEE republish wiring; Phase 67, not the write-chain. A cheap fail-closed guard could land earlier if any caller starts passing `teeKeys`, but no Phase-65 dependency.
- `2026-06-29-rotation-coderabbit-followups-deferred.md` (`resolves_phase: 68`) — merge re-enqueue (RR-01) + `verifySubtreeClean` depth (RR-02) → Phase 68; **grant-threading** (`reMintGrantsRootedAt` unreachable in the real walk) → Phase 66 (live `shares` transport). None block the write-chain.
- `2026-06-29-rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md` (RR-01) / `2026-06-29-rotation-fresh-record-resume-and-sc4-double-bump.md` (RR-02) → Phase 68 durable-floor + resume rework.
- `2026-06-29-sdk-client-move-publish-durability.md` (area `sdk`) → Phase 68 (folderTree reconcile; user-decided at Phase 64).
- The remaining `todo.match-phase 65` hits (ERC-1271 wallet auth, async search index, alt MFA, permanent-delete dialog, base64 helper dedup, upload-batch mock drift, CRDT inbox, etc.) are generic keyword matches with no write-chain overlap.

</deferred>

---

*Phase: 65-sdk-write-chain-bin-re-link-and-invite-claim*
*Context gathered: 2026-06-29*
