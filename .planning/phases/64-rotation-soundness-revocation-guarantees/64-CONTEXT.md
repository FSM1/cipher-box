# Phase 64: Rotation Soundness — Revocation Guarantees - Context

**Gathered:** 2026-06-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 64 makes the Phase-63 rotation engine (`rotateReadFromNode` / `rotateOne` in `packages/sdk-core/src/rotation/engine.ts`) **cryptographically sound** by filling the four named seams Phase 63 stubbed and hardening the multi-node BFS walk, then proving it against a live local API stack.

**In scope (ROT-03, ROT-04, ROT-05, ROT-06, TEST-01):**

- **CRIT-1 / ROT-03 — content-key rotation** (`mintFileKeyOnRotate`): rotating a file node mints a fresh `fileKey'` and sets `contentRekeyPending` (lazy, applied on next content write per ADR 0002). A holder of the old `readKey`/`fileKey` cannot decrypt the **next published** version.
- **HIGH-3 / ROT-04 — inner-grant re-mint** (`reMintGrantsRootedAt`): rotation enumerates `shares WHERE rootNodeId IN (rotated set)` and re-mints `readDescriptorRef` for every non-revoked recipient (including inner grants rooted at subtree nodes); the revoked recipient's row is deleted. No orphaned inner grant.
- **HIGH-4 / ROT-05 — concurrent-add merge** (`mergeConcurrentChildren`): on a CAS-409, `rotateOne` re-fetches the current parent node, re-decodes the read-body, and merges concurrently-added `SealedChildRef`s before re-sealing — a concurrent add is never silently dropped.
- **ROT-06 — crash-resume convergence** (`verifySubtreeClean` + the resumable walk): a crash mid-walk is recovered by re-running `rotateReadFromNode`; `verifySubtreeClean` rebuilds the frontier from published IPNS records, the re-run converges without double-bumping any node's `generation`, and the revoked recipient is cut from the root after the root step.
- **The multi-level BFS walk correctness fix** (the Phase-63 CRITICAL deferred finding): re-seal each rotated child's link under the **parent's NEW `readKey'`**, write it back onto the parent's `SealedChildRef`, and publish the parent — so non-root nodes survive later `unsealChildReadKey`.
- **TEST-01** — a new `tests/sdk-e2e` abort-and-resume (crash-safety) suite against the live local API stack. SDK E2E must pass before phase sign-off (the only real client→API IPNS publish/resolve round-trip).

**Out of scope (hard boundary — owned by later phases):**

- **M1 durable client floor** — `{nodeId → highestGeneration}` IndexedDB persistence that survives page reload (ROT-07 / §7.3 test 5) → **Phase 68**. Phase 64's job record stays advisory/in-memory; resume rebuilds from published IPNS truth.
- **Server-side `generation` gate** (defence-in-depth, §4.3) → **Phase 66** (publish gate / schema cutover).
- **Full write-body signing material** — per-node Ed25519 keys sourced from the write-body, real write-revocation → **Phase 65**. Phase 64 takes per-node IPNS keys via a test-supplied key source (D-01) and **fails closed** when a real key is absent (no placeholder publish).
- **Live `shares` schema** (`readDescriptorRef`/`writeDescriptorRef` columns, `share_keys` drop) → **Phase 66**. HIGH-3 re-mint runs behind a transport-decoupled mock seam (D-04).
- **`client.ts` move dest-before-source ordering durability** + `folderTree` reconcile → **Phase 68** (decided this discussion — not folded here).
- Web/FUSE host integration, Rust `Node` enum, TEE lease-renewer → **Phases 67–69**.

The app stays **intentionally non-runnable mid-milestone** (greenfield). Do not pull later-phase behavior forward to make it runnable.

</domain>

<decisions>
## Implementation Decisions

### Per-node signing keys — the 64→65 seam (D-01)

- **D-01:** **Test-supplied keymap + fail-closed engine.** Delete the `PLACEHOLDER_WRITE_KEY` publish fallback in `rotateOne` (engine.ts ~L346-349/L357): the engine **requires a real `ipnsPrivateKey` per frontier node** and throws if absent (closes the deferred "never publish with a placeholder" finding). The crash-safety `sdk-e2e` builds a **multi-level tree with known keypairs** using the established "bypass `createFileMetadata`, manually build nodes (`sealNode` + `addToIpfs` + `createAndPublishIpnsRecord`)" pattern Phase 63's e2e used (STATE.md decision), and threads the per-node keypairs into the rotation params via a test-provided key source. Production write-body→key wiring is **Phase 65** — not pulled forward. This satisfies ROT-06/TEST-01's real multi-level publish without the write-chain.

### Engine re-seal correctness + batched parent-publish (D-02)

- **D-02:** **Out-of-band re-seal in the BFS caller + adopt the D-09 batched parent-publish now.** `rotateOne` already returns the child's freshly minted `childReadKey`. The walk caller (`rotateReadFromNode`) — which holds the **parent's new `readKey'`** from the parent's own `rotateOne` result — re-seals `childReadKey` under `parentNewReadKey'` via `sealChildReadKey`, writes the result onto the parent's `SealedChildRef[child].readKeySealed` + `.generation` mirror, and **publishes the parent once after all its children rotate** (interior nodes child-first per §4.2/§4.6; batched parent-link rewrite per §4.7 "the main constant-factor win at scale").
  - Fixes the Phase-63 **CRITICAL** bug: `newReadKeySealed` was sealed under the child's own old key, not the parent's new key, and was never written back to the parent → every non-root node would AEAD-fail on later `unsealChildReadKey`.
  - Keeps `rotateOne` focused on "rotate this node"; parent-link knowledge stays in the walk that owns the parent/child relationship. Strengthen `engine.test.ts` to assert the parent ref is updated AND republished (not merely that `sealChildReadKey` was called).
  - The `parentReadKey` param remains a legacy misnomer (it carries the node's OWN pre-rotation key); planner may rename for clarity at discretion.

### Crash-safety E2E — fault injection + resume model (D-03)

- **D-03:** **Throw-after-N + fresh-resume via `verifySubtreeClean`.**
  - **Tree:** depth ≥ 2 (root → folder → file) so the walk has a real frontier/tail to crash in — Phase 63's e2e was single root-step only.
  - **Crash injection:** throw from an injected hook after N committed nodes; **resume by calling `rotateReadFromNode` again with a FRESH job record** — `verifySubtreeClean` rebuilds the frontier from the published IPNS records (the source of truth, D-10), the re-run converges with **no double-bump** of any node's `generation`. **No durable job-record persistence** (that is Phase 68). Proves D-10's "a reload restarts the idempotent walk."
  - **Concurrent-add injection:** a second SDK client uploads a child mid-rotation (between the root commit and that parent's rotation); assert the HIGH-4 merge picks it up and the new child is present in the completed parent (§7.3 test 4).
  - Honor SDK-E2E prereqs: `docker compose -f docker/docker-compose.yml up -d` + `pnpm --filter @cipherbox/api dev`; redis on **6380**; capture real 400s via a temporary axios interceptor.

### HIGH-3 inner-grant re-mint — transport boundary (D-04)

- **D-04:** **Follow Phase-63 D-05 — transport-decoupled, mock-tested.** `reMintGrantsRootedAt` enumerates grants via an injected callback (the established "Share module accepts callback functions for API calls" seam) and re-mints `readDescriptorRef` crypto behind the same boundary. Unit-test against a **mocked `shares` query + mocked persist callback** (a leaf-level inner grant: assert its descriptor is re-minted under the new key/generation and the revoked recipient's row is deleted). **Live `shares` persistence is Phase 66** (the schema cutover to `readDescriptorRef`/`writeDescriptorRef`). Keeps Phase 64 entirely in `sdk-core`/`sdk`, unblocked by the DB.

### CRIT-1 content-key rotation shape (D-05)

- **D-05:** **Locked by design §4.1 / ADR 0002 — restated for the seam fill.** `mintFileKeyOnRotate` mints `fileKey' = random32` and sets a per-node `contentRekeyPending` marker on the file node; the re-key is **lazy** (applied on the next content write). A cold file never rewritten keeps its old `fileKey` valid and its still-pinned CID decryptable — read-revocation protects **future** writes/navigation/filenames, **not** already-distributed content or prior versions (ADR 0002 caveat carried on every revoke flow). Keep `fileKey` rotation coupled to `readKey` rotation coupled to the `generation` bump. The §7.3-test-2 assertion: a holder of the old `readKey`/`fileKey` cannot decrypt the **next published version**.

### Folded correctness todos (D-06)

- **D-06:** Two adjacent binding-stability bugs **fold into Phase 64** (preconditions for rotation to be testable/sound end-to-end); the move-ordering durability bug **does not**.
  - **IN** — `move-within-scope-reseal-child-readkey` (FLAG-63-U2): `moveItem` must re-seal the moved child's `readKey` under the **destination** parent's `readKey` (compute `newReadKeySealed = sealChildReadKey(childReadKey, destParentReadKey, …)`), else dest-path navigation AEAD-fails. The node keeps its own `readKey`/`generation` (no content re-encryption). Add a dest-path-navigation-after-move unit test. Distinct from the scope-exit rotation gate (`hasCoveringGrant` in `rotation/scope.ts`) — both wired.
  - **IN** — `update-folder-metadata-preserve-node-identity` (CRITICAL): make `nodeId`/`nodeGeneration` **required** on `updateFolderMetadataAndPublish` (drop `?? crypto.randomUUID()` / `?? 0`), thread the stable `id` + current `generation` through all six `client.ts` call sites. `generation` is the rotation counter / convergence witness — resetting it to 0 corrupts the staleness signal the read path and rotation engine rely on, and a fresh UUID breaks the parent's sealed-child AAD binding.
  - **OUT (→ Phase 68)** — `sdk-client-move-publish-durability`: the dest-before-source publish-ordering reorder and the unreadable-descendant enumeration fix tie into Phase-68 `folderTree`/sequence reconcile; not folded here.

### Job-record / walk ordering hardening — part of ROT-06 (D-07)

- **D-07:** The Phase-63 CodeRabbit walk-soundness findings (`rotation-engine-walk-soundness-phase64` todo) are **core ROT-06 work**, fixed alongside the resumable walk:
  - Move `jobRecord.completedNodeIds.add(nodeId)` to **after** the node is fully processed (after `reMintGrantsRootedAt`), so a failed re-mint isn't skipped on resume.
  - Fix the resume fast-path guard so an already-complete `rootNodeId` does **not** mark the whole walk complete and bypass `verifySubtreeClean` / the frontier.
  - Persist terminal `jobRecord.status` via the host-injected callback on successful finish (in-engine ordering; durable storage is Phase 68).
  - Zero engine-derived child read keys in the BFS queue once their children are derived/enqueued (terminal-owner — safe to zero). Keep the D-09 zeroization invariant: **never** zero caller-supplied `rootReadKey`/`parentReadKey`; zero only minted `readKeyPrime`/`fileKeyPrime` on failure paths.
- **Convergence test (in-engine, Phase 64):** N is done iff `parent.SealedChildRef[N].generation == N.envelope.generation` and that generation exceeds the baseline observed when N was enqueued. Crash recovery = a fresh full `rotateOne(N)` (double-rotation only strengthens revocation); publish-child-then-parent guarantees the worst a crash leaves is a child ahead of its parent.

### Claude's Discretion

- Seam-function internal factoring and signatures, provided the four seams keep their names and the engine's seam structure is **filled, not re-architected** (Phase 63 D-01).
- Whether to rename the `parentReadKey` misnomer; helper extraction for the batched parent-publish.
- Exact `verifySubtreeClean` return shape and how the resume frontier is rebuilt.
- How the mocked-API unit tests and the test key source are structured.
- How fault injection is wired into the engine for the e2e (injected hook vs test-only seam) — keep it test-only, not a production code path.

### Folded Todos

- `2026-06-29-rotation-engine-walk-soundness-phase64.md` — CodeRabbit/greptile rotation-walk soundness findings (the CRITICAL re-seal bug, job-record ordering, resume guard, queue-key zeroization). Folded as the core of ROT-06 + D-02/D-07.
- `2026-06-29-move-within-scope-reseal-child-readkey.md` — FLAG-63-U2 move re-seal. Folded per D-06.
- `2026-06-29-update-folder-metadata-preserve-node-identity.md` — CRITICAL node-identity/generation preservation. Folded per D-06.
- `2026-06-29-rotateone-placeholder-writekey-phase65.md` — the *write-body* placeholder is Phase 65; but the **publish-path** placeholder guard (fail closed) is folded here per D-01.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design source of truth (read first)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — the single source of truth for v2.0. Phase-64 sections:
  - **§4.1** CRIT-1 content-key rotation (ROT-03 / D-05) — lazy `fileKey'` + `contentRekeyPending`, ADR 0002 honesty.
  - **§4.2** ordering scope-root-first; the atomic root step (re-mint `readDescriptorRef`, delete revoked row).
  - **§4.3** M1 durable client floor + server-side generation gate — **out of scope here** (Phase 68 / 66); read for the convergence-invariant context only.
  - **§4.4** HIGH-3 multi-rooted grant re-mint (ROT-04 / D-04) — `shares WHERE rootNodeId ∈ rotated set`.
  - **§4.5** per-node commit / the `rotateOne` 9-step algorithm / convergence test / crash recovery / `verifySubtreeClean` (ROT-06 / D-03 / D-07).
  - **§4.6** concurrency, CAS-409 re-merge (ROT-05 / HIGH-4), corrected forward-only-generation invariant, soft-behind-vs-hard-revoked liveness.
  - **§4.7** exposure window + batched parent-link publish (D-02 / D-09 adoption).
  - **§4.8** eager is committed; lazy walk deferred.
  - **§3.5** move within scope (the re-seal — D-06); **§3.6** scope-exit rotation; **§3.7** add-during-rotation (HIGH-4).
  - **§7.3** test strategy — Phase-64-relevant: test 2 (CRIT-1 content), test 3 (HIGH-3 inner grant), test 4 (HIGH-4 concurrent-add), test 1 (happy-resume), plus the crash-safety abort/resume cases.
- `.planning/design/2026-06-26-sharing-flows-walkthrough.md` — FS-permutation walkthrough.

### ADRs (authoritative freezes)

- `docs/adr/0002-read-revocation-protects-future-content-only.md` — the honest threat-model stance every revoke flow carries (protects future writes/navigation/filenames, **not** already-distributed content or prior versions). Anchors CRIT-1's "lazy is correct."
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — the frozen seal/AAD byte encoding (roles `0x01 body / 0x02 child-readkey / 0x03 content / 0x04 child-writekey`); rotation **calls** this primitive, never reimplements it.
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-body context (Phase 65; the read chain is invariant).

### Requirements, roadmap, prior context

- `.planning/REQUIREMENTS.md` — **ROT-03, ROT-04, ROT-05, ROT-06, TEST-01** (this phase). Note ROT-07 (M1 durable floor) → Phase 68.
- `.planning/ROADMAP.md` — Phase 64 goal + the 5 success criteria (CRIT-1 §7.3 test 2, HIGH-3 §7.3 test 3, HIGH-4 §7.3 test 4, crash-resume convergence, TEST-01 sdk-e2e gate).
- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-CONTEXT.md` — carried-forward: **D-01** (the 63→64 seam line — fill, don't re-architect), **D-02** (web first-class best-effort host), **D-05** (transport-decoupled mock-tested crypto — mirrored here as D-04), **D-09** (batched parent-publish — adopted here in D-02), **D-10** (advisory job record, published records are source of truth).
- `CONTEXT.md` (repo root) — pinned glossary: the **three counters** (`generation` / `keyEpoch` / `sequenceNumber` — never conflate), `readKey`/`writeKey`, descriptor refs. **Cite, do not redefine.**

### Schema reference (do not modify this phase)

- `docs/METADATA_SCHEMAS.md` — the static `node/v3` schema + the **`generation`-single-source-of-truth invariant** (per-node authoritative on the child's own envelope; every mirror is a staleness witness). Directly relevant to the convergence test (D-07) and node-identity preservation (D-06).

### Parity / pitfalls

- `.planning/research/PITFALLS.md` — AAD byte-encoding drift = silent total decryption failure; the coverage-barrel pitfall (engine stays in `engine.ts`, never an `index.ts` barrel — SC#5 coverage).

### Implementation sites — TypeScript

- `packages/sdk-core/src/rotation/engine.ts` — **fill** the four seams (`mintFileKeyOnRotate`, `reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean`); the re-seal/batched-publish rework (D-02); job-record ordering + zeroization (D-07); delete the placeholder publish fallback (D-01). Named file, **not** a barrel.
- `packages/sdk-core/src/rotation/scope.ts` — `hasCoveringGrant` scope-exit predicate (present; gates move-out — interacts with D-06 move re-seal).
- `packages/sdk-core/src/folder/metadata-ops.ts` — `moveItem` re-seal under destination parent `readKey` (D-06 / FLAG-63-U2).
- `packages/sdk-core/src/folder/registration.ts` — `updateFolderMetadataAndPublish` node-identity/generation preservation (D-06, ~L174-175).
- `packages/sdk/src/client.ts` — six `updateFolderMetadataAndPublish` call sites (L493, L558, L581, L629, L747, L1006) must thread stable `id` + current `generation` (D-06).
- `packages/core/src/node/` — Phase-62 codec to **call, never reimplement**: `sealNode`/`unsealNode`, `sealChildReadKey`/`unsealChildReadKey`, `sealContent`/`unsealContent`, `encodeReadBody`/`decodeReadBody`, types.
- `packages/crypto/src/aes/seal.ts` — `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`; ECIES `wrapKey`/`unwrapKey` for `readDescriptorRef` re-mint (D-04).
- `packages/sdk-core/src/cas.ts:38` (`publishWithCas`) + `packages/sdk-core/src/ipns/index.ts:39` (`createAndPublishIpnsRecord`) — CAS-publish infra to reuse; CAS-409 is the HIGH-4 re-merge trigger. Mind the first-publish seq-1 convention.
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — strengthen (parent-ref-update + republish assertion, resume test, failure-path zeroization test).
- `tests/sdk-e2e/` — the **new abort-and-resume crash-safety suite** (TEST-01 / D-03); the Phase-63 happy-path round-trip lives here as the scaffold.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **Phase-63 engine is the scaffold** (`rotation/engine.ts`) — the four seams already exist as named, individually-throwing functions with the exact requirement IDs in their throw messages; Phase 64 replaces each body without re-architecting (Phase 62/63 D-01 discipline). The BFS frontier walk, `rotateOne` 9-step skeleton, and the `RotationJobRecord` type are in place.
- **Phase-62 codec complete and callable** (`packages/core/src/node/`) — never reimplement seal/encode/decode.
- **Seal primitive (Phase 61)** — `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`, roles `0x01–0x04` KAT-frozen. AAD uses the **child's** id/kind/generation, so re-pointing a parent or replaying a stale generation fails the unwrap closed — exactly what makes the cut genuine and what the convergence test depends on.
- **CAS publish infra** — `publishWithCas` (`cas.ts:38`) + `createAndPublishIpnsRecord` (`ipns/index.ts:39`, `expectedSequenceNumber` pre-increment CAS guard). HIGH-4 re-merge plugs into the `merge` callback (currently throws the Phase-64 stub).
- **Transport-decoupled share/callback pattern** (STATE.md) — the seam for D-04 (mock-testable HIGH-3 re-mint).
- **sdk-e2e manual-node pattern** — Phase 63 e2e bypassed `createFileMetadata` (Phase 65) by hand-building file nodes (`sealNode` + `addToIpfs` + `createAndPublishIpnsRecord`) with known keypairs; D-01's test key source extends this to a multi-level tree.

### Established Patterns

- **Coverage excludes `src/**/index.ts` barrels** ([[project-sdk-core-coverage-excludes-index-barrels]]) — engine stays in `engine.ts` (SC#5).
- **Every first IPNS publish embeds sequence 1** ([[project-ipns-first-publish-embed-seq-1]]) — new-node creation in the e2e tree is a first publish: `createAndPublishIpnsRecord` embeds the arg verbatim (`1n`); `publishWithCas` embeds base+1 (`0n`). Post-Phase-60 strict gate rejects first publish with embedded seq ≠ 1 (400).
- **Zeroization — terminal-owner only** ([[project-zeroization-callee-must-not-zero-reused-buffer]]) — mint-and-own `readKey'`/`fileKey'` (zero on own failure paths); never zero caller-supplied/reused keys (D-07). Flag the engine file in every security review.
- **Strict IPNS resolve recovers the Ed25519 pubkey from the k51 name** ([[project-ipns-resolve-ed25519-pubkey-from-name]]) — relevant wherever the walk resolves a node.
- **Greenfield delete-outright** — no dual-codec / no migration.

### Integration Points

- **`packages/core` `dist/` rebuild required** before sdk-core typecheck ([[project-cross-package-dist-staleness]]).
- **sdk-e2e is the only real client→API IPNS round-trip** ([[project-sdk-e2e-only-cross-package-publish-gate]]) — TEST-01 gate; docker stack + `pnpm --filter @cipherbox/api dev`; redis on **6380**.
- **Checker subagents: static analysis only** ([[feedback-gsd-subagents-no-test-runs]]) — no concurrent vitest (RAM starvation); design §7.3 echoes this.
- **Web/SDK folder-state desync** ([[project-web-sdk-folder-state-desync]]) — the engine must not assume a reconciled tree; `folderTree` reconcile-before-rotate is a Phase-68 caller responsibility (D-06 OUT item).

</code_context>

<specifics>
## Specific Ideas

- The user took the **recommended option on all four discussed areas** (terse/decisive, consistent with the Phase-63 "recommended default on all 10" pattern).
- **Net scope cut, user-decided:** the `client.ts` move dest-before-source publish-ordering durability fix is **explicitly NOT folded** into Phase 64 — it goes to Phase 68 with the `folderTree` reconcile. Only the two binding-stability bugs (move re-seal, node-identity preservation) fold in.
- **Engine discipline:** fill the four seams in place; do not re-architect the seam structure (the same "name the deferred behavior after its owning phase" pattern Phase 62/63 used). The CRITICAL re-seal fix (D-02) is the one place the walk is genuinely reworked, and it is done in the caller, not by reshaping `rotateOne`'s contract.
- **Fail-closed over placeholders:** no IPNS record is ever published with an all-zeros placeholder key — require a real per-node key or throw (D-01).

</specifics>

<deferred>
## Deferred Ideas

- **M1 durable client floor** — `{nodeId → highestGeneration}` IndexedDB persistence surviving page reload (ROT-07 / §7.3 test 5), `executeLazyRotation` deletion, `folderTree` reconcile-before-rotate → **Phase 68**.
- **Server-side `generation` gate** (forward-only per node, mirroring the sequence CAS) → **Phase 66**.
- **Full write-body signing material** — per-node Ed25519 keys from the write-body, full write-revocation, `rotateOne` placeholder write-key (the *write-body* one, `rotateone-placeholder-writekey-phase65` todo) → **Phase 65**.
- **Live `shares` schema** for HIGH-3 persistence (`readDescriptorRef`/`writeDescriptorRef` columns) → **Phase 66**.
- **`client.ts` move dest-before-source ordering + unreadable-descendant enumeration fix** (`sdk-client-move-publish-durability` todo) → **Phase 68** (folderTree reconcile context). User-decided this discussion.

### Reviewed Todos (not folded)

- `2026-06-29-sdk-client-move-publish-durability.md` (area `sdk`) — move-ordering durability; deferred to Phase 68 per D-06 (user decision).
- `2026-06-29-rotateone-placeholder-writekey-phase65.md` (area `sdk-core`) — the *write-body* placeholder is Phase 65; only the publish-path guard is folded (D-01).
- `2026-06-29-createsubfolder-tee-republish-wiring.md` (area `sdk-core`) — TEE republish wiring for `createSubfolder`; TEE contract is Phase 67, not rotation soundness.
- `2026-06-29-dedup-base64-helpers-sdk-core-share.md` / `2026-06-29-node-codec-base64-helper-dedup.md` — pure cleanup, not soundness; defer.
- `2026-06-28-harden-uuid-acceptance-parity-aad-builder.md` / `2026-06-28-zeroize-local-key-plaintext-copies-in-aes-helpers.md` (area `crypto`) — Phase-61 `packages/crypto` follow-ups, not the `sdk-core` rotation engine.
- `2026-06-29-upload-batch-test-mock-type-drift.md` — test mock type-drift to `SealedChildRef`; tidy alongside if touched, not a scope item.
- The remaining `todo.match-phase 64` hits (recovery.html v3, permanent-delete dialog, ERC-1271, CRDT inbox, web logger, search index, staging GC, etc.) are generic keyword matches with no rotation-soundness overlap.

</deferred>

---

*Phase: 64-rotation-soundness-revocation-guarantees*
*Context gathered: 2026-06-29*
