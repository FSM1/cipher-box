# Phase 63: Read-Chain Navigation and Rotation Core - Context

**Gathered:** 2026-06-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 63 implements, in `packages/sdk-core`, the **behavior** the Phase-62 codec made possible. It is the first consumer phase to un-stub the keystone:

**In scope (READ-01…05, ROT-01, ROT-02):**

- **Read key-chain navigation walk** — one ECIES unwrap of the grant `readDescriptorRef`, then `O(depth)` symmetric `unsealAesGcmAad` down `SealedChildRef[].readKeySealed`, recovering content key / CID / `encryptionMode` at a file node (READ-02). The read path distinguishes "soft behind, retry" from "hard revoked".
- **Read-grant issuance** — ECIES-wrap the share-root `readKey` into one grant (`readDescriptorRef`), zero node touches, zero republishes; single-file grant is structurally identical to a deep-folder grant (READ-01).
- **Add-item child sealing** — seal the new child `readKey` under the parent `readKey` with **no per-recipient fan-out** (READ-03).
- **Move-within-scope** — link rewrites only, zero re-encryption; the `hasCoveringGrant` scope-exit predicate gates delete/move/rename (READ-04, ROT-02).
- **Invite claim re-wrap primitive** — unwrap the share-root `readKey` with the URL-fragment ephemeral private key, re-wrap to the claimer's public key (READ-05, crypto primitive only — see D-07).
- **Rotation engine** — `rotateReadFromNode` / `rotateOne` in a **named file** (`src/rotation/engine.ts`, not an `index.ts` barrel, so vitest coverage counts it); per-node commit via CAS before advancing the walk frontier (ROT-01); rotation fires **iff** a node leaves a grantee's reachable scope — a node with no covering grant is a pure relink, zero rotations (ROT-02).

**Out of scope (hard boundary — owned by later phases):**

- **Rotation soundness** — CRIT-1 content-key rotation (ROT-03), HIGH-3 inner-grant re-mint (ROT-04), HIGH-4 concurrent-add merge (ROT-05), crash-resume convergence + `verifySubtreeClean` (ROT-06), and the `tests/sdk-e2e` crash-safety suite (TEST-01) → **Phase 64**. Phase 63 ships these as **named, individually-testable seam functions** (see D-01).
- Write-chain / full Ed25519 write-revocation / bin re-link / full invite-service wiring → **Phase 65**.
- `shares`/`share_keys` schema cutover, `readDescriptorRef`/`writeDescriptorRef` columns, `encryptedChildKeys` JSONB drop, atomic CAS publish gate, tombstone, server-side `generation` gate → **Phase 66**.
- TEE lease-renewer contract → **Phase 67**.
- Web rotation UX, `executeLazyRotation` deletion, durable IndexedDB `{nodeId → generation}` + seq high-water (ROT-07 / M1), `folderTree` reconcile-before-rotate, `addShareKeys` web-callback removal → **Phase 68**.
- FUSE/WinFsp symmetric unwrap, Rust `Node` enum, Rust grant-root awareness, durable client floors → **Phase 69**.

The app stays **intentionally non-runnable mid-milestone** (greenfield, no prod instance) — do not pull later-phase behavior forward to make it runnable. This continues the Phase-62 keystone discipline.

</domain>

<decisions>
## Implementation Decisions

### Rotation engine — the 63→64 line (D-01)

- **D-01:** `rotateOne` ships the **structural walk skeleton**: resolve N → unseal N's read-body (key chained from parent) → mint `readKey'` + `generation' = generation + 1` → re-seal N's read-body under `readKey'` (AAD bound to `generation'`) → rewrite parent's `SealedChildRef[N].readKeySealed` + `.generation` mirror → **publish child-then-parent with CAS** on `expectedSequenceNumber` → advance the walk frontier with `readKey'`. The happy path — a read-revoke of a **clean, single-rooted, no-concurrent-add** subtree — works end-to-end and is unit-tested; coverage counts the named engine file.
  - The four **soundness concerns are present as named, individually-testable seam functions** deferred to Phase 64 (filled there without re-architecting the engine):
    - `mintFileKeyOnRotate` — CRIT-1 / ROT-03 (lazy `contentRekeyPending` fresh `fileKey` on file-node rotate).
    - `reMintGrantsRootedAt` — HIGH-3 / ROT-04 (re-mint `readDescriptorRef` for every non-revoked grant whose `rootNodeId` ∈ rotated set).
    - `mergeConcurrentChildren` — HIGH-4 / ROT-05 (re-fetch + re-merge `SealedChildRef`s on CAS-409 instead of re-sealing from a stale child list).
    - `verifySubtreeClean` + crash-resume convergence — ROT-06 (the published-IPNS-truth resume rebuild; see D-10).
  - Mirrors Phase 62 D-01 ("fully implement the core seam, name the deferred behavior after its owning phase").

### Rotation host — ROADMAP open question Q2 (D-02) — ANSWERED HERE

- **D-02:** **Web is a first-class but best-effort rotation host.** The rotation engine is **host-agnostic pure logic** — no FUSE/Tauri dependency. The root step (the actual cut for the revoked reader) completes fast; the `O(items)` tail runs as a resumable background walk. A long, chunked, multi-session web rotation for a large web-only revoke is **accepted as a documented limitation**. Durable resume-across-page-reload is **Phase 68 (ROT-07)**, so in Phase 63 a web reload simply restarts the **idempotent** walk from `verifySubtreeClean` (Phase-64 logic). No desktop dependency is introduced. This closes ROADMAP Q2.

### Legacy fan-out deletion boundary (D-03)

- **D-03:** Phase 63 deletes `reWrapForRecipients` (`packages/sdk/src/share/index.ts:88`) and its sdk add-item fan-out call path (`packages/sdk/src/client.ts:164,1602`), and **rewires the add-item path** to seal the child `readKey` under the parent `readKey` (READ-03 — no per-recipient fan-out). The `addShareKeys` **callback type** (`packages/sdk/src/types.ts:32`) and its **web wiring** removal land in **Phase 68**. Layering invariant: **sdk-core/sdk = Phase 63, apps/web = Phase 68.** (`SC#3`'s "deleted from the codebase" is satisfied for the SDK layer at 63; the web caller was already stubbed in Phase 62 and is finalized at 68.)

### Phase 63 test gate (D-04)

- **D-04:** **Vitest unit bulk + ONE happy-path sdk-e2e round-trip.**
  - Vitest: navigation walk to depth-`d`; `O(1)` grant issuance; **scope-exit zero-rotation invariant** via a publish-call spy asserting a private delete/move (no covering grant) triggers **zero** `rotateReadFromNode` invocations and zero IPNS publishes beyond the parent relink (ROADMAP SC#4); coverage on the named engine file (ROADMAP SC#5); revive the Phase-62-quarantined `folder.test.ts` / `client-extended.test.ts` suites marked `TODO(phase 63)`.
  - One `tests/sdk-e2e` round-trip: **issue grant → navigate to file → root-step rotate → revoked grant can't navigate** — against the live local API, proving the engine survives real IPNS publish/resolve.
  - The full fault-injection / crash-safety matrix is **Phase 64 (TEST-01)**. Honor the SDK-E2E prereqs (docker stack + `pnpm --filter @cipherbox/api dev`, redis on 6380) — see `<code_context>`.

### Schema dependency — landing READ-01 before the Phase-66 cutover (D-05)

- **D-05:** **Transport-decoupled crypto, mock-tested.** Grant issuance + `readDescriptorRef` ECIES crypto live behind the existing **callback / transport-decoupled seam** (the established "Share module accepts callback functions for API calls" pattern). Unit-test against a **mocked API**. The happy-path sdk-e2e (D-04) exercises only **node navigation + rotation over IPNS** — schema-agnostic, because the API stores opaque published-record bytes and does not parse node internals — **not** live `shares` persistence. Real `shares` persistence + the live grant round-trip wait for **Phase 66** (the `shares` schema cutover to `readDescriptorRef`/`writeDescriptorRef`). This keeps Phase 63 entirely in `sdk-core`/`sdk`, unblocked by the DB.

### Navigation read-result shape (D-06)

- **D-06:** Navigation surfaces a **typed discriminated result**: `'ok' | 'behind-retry' | 'revoked'` (READ-02 / §4.6).
  - `behind-retry` — a re-minted grant is present but the envelope `generation` is ahead of the client's expected value ⇒ the caller retries (honest-reader liveness after a rotation).
  - `revoked` — the grant row is absent ⇒ hard fail.
  - A typed union the Phase-69 (FUSE) and Phase-68 (web) callers branch on — **no ambiguous boolean/null**. Mirrors the documented `#489`/`#494` desync handling.

### Invite slice (D-07)

- **D-07:** **Crypto primitive only in Phase 63.** Implement the claim re-wrap crypto in `sdk-core`/`sdk`: unwrap the share-root `readKey` with the URL-fragment ephemeral private key → re-wrap to the claimer's public key → produce a standard grant's `readDescriptorRef`; and **stop USING** `encryptedChildKeys` in the SDK claim path. The full invite create/claim **service wiring** + `encryptedChildKeys` removal from the service is **Phase 65**; the `encryptedChildKeys` **JSONB column drop** is **Phase 66** schema. Phase 63 = the re-wrap primitive + its unit test (READ-05).

### Scope-exit predicate inputs (D-08)

- **D-08:** `hasCoveringGrant` is a **pure `sdk-core` function** taking `(mutated-node ancestry chain, activeGrantRoots set, localGrantRecord) → coverage`. The **host** (web Phase 68 / FUSE Phase 69) supplies the active grant-root set (from the API `shares` query) **and** the client's own local grant record for the **anti-malicious-relay cross-check** (§3.9 — treat the relay set as a completeness aid, never an authority). `sdk-core` does **not** fetch grants or hold durable state. The "defer rather than skip when the tree cannot be reconciled" policy is enforced by the **caller** (a wrong "don't rotate" is a silent missed revoke). Gates every delete/move/rename (ROADMAP SC#4).

### Batched parent-link publish (D-09)

- **D-09:** **Deferred to Phase 64.** Phase 63's `rotateOne` does the straightforward **per-node** parent-link publish (correct, simpler). The batched-parent-publish optimization (step 8 in §4.5; "the main constant-factor win at scale", §4.7) is folded into Phase 64's `O(items)` scale-hardening. Noted as a seam in the engine so 64 picks it up.

### Job-record / resume ownership (D-10)

- **D-10:** Phase 63 defines the **job-record type** + the **resumable in-memory frontier loop**, with an **optional host-injected persistence callback** (no-op by default). The published IPNS records are the source of truth; the job record is advisory (§4.5). `verifySubtreeClean` (the published-IPNS-truth resume rebuild) is a **Phase-64 seam** per D-01. Durable storage (IndexedDB/sqlite) is **Phase 68 (web) / 69 (FUSE)**. Consistent with D-02 (web reload restarts the idempotent walk).

### Claude's Discretion

- `sdk-core` module layout **beyond** the locked `src/rotation/engine.ts` (e.g., placement of the navigation walk, grant/share helpers, the `hasCoveringGrant` predicate, the invite re-wrap primitive).
- Exact result/error type names and the `'ok' | 'behind-retry' | 'revoked'` representation (string-literal union per project convention).
- Seam-function signatures and helper factoring — provided each deferred seam is **explicit and names its owning phase**.
- How the mocked-API unit tests are structured.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Design source of truth (read first)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — the single source of truth for v2.0. Phase-63 sections:
  - **§2.6** `SealedChildRef` + the 4-step unwrap walk (the navigation algorithm) and the generation-source rule (parent mirror is the reader's AAD source, never the child's own envelope).
  - **§2.8** the read-root grant (`readDescriptorRef`/`writeDescriptorRef`, `rootGeneration` witness).
  - **§2.9** file content self-seals under its own `readKey` (single-file-share enabler).
  - **§3.2–3.11** flows: issue grant (3.2), navigate (3.3), add item (3.4), move within scope (3.5 — per-grant scope), **delete/move-out/rename rotate iff scope-exit (3.6)**, add-during-rotation (3.7), the one-rule-four-call-sites unification (3.8), **client-side scope computation + FUSE blind spot (3.9)**, bin (3.10), invites (3.11).
  - **§4** read-side resumable rotation: 4.1 CRIT-1 (Phase 64), 4.2 **ordering scope-root-first**, 4.3 M1 (Phase 68), 4.4 HIGH-3 (Phase 64), **4.5 per-node commit / the `rotateOne` 9-step algorithm / convergence test / crash recovery / `verifySubtreeClean`**, 4.6 concurrency + **soft-behind-vs-hard-revoked** (D-06), 4.7 exposure window + **host** (D-02), 4.8 eager is committed / lazy-walk deferred.
  - **§7.3** test strategy (Phase-63-relevant: tests 1 happy-resume scaffold, 6 AAD transplant, 8 CTR content, 9 scope-exit-only, 10 bin restore, 11 invite claim).
  - **§9.2** open questions (Q2 answered in D-02; Q3 deferred to Phase 65/68/69).
- `.planning/design/2026-06-26-sharing-flows-walkthrough.md` — FS-permutation walkthrough (context behind Q3; flows are 63–69).

### ADRs (authoritative freezes)

- `docs/adr/0002-read-revocation-protects-future-content-only.md` — the honest threat-model stance rotation serves (read-revocation protects future writes/navigation/filenames, **not** already-distributed content or prior versions). Every revoke flow carries this caveat.
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — the frozen seal/AAD byte encoding (roles `0x01 body / 0x02 child-readkey / 0x03 content / 0x04 child-writekey`); navigation/rotation **call** this primitive, never reimplement it.
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-body context (Phase 65; the read chain is invariant across write candidates).

### Requirements, roadmap, prior context

- `.planning/REQUIREMENTS.md` — **READ-01…05, ROT-01, ROT-02** (this phase) + the `## Out of Scope` table (no migration / no dual-codec). Note ROT-03…06 → Phase 64, ROT-07 → Phase 68.
- `.planning/ROADMAP.md` — Phase 63 goal + 5 success criteria; the **Q2 open-question note** ("decision captured in the phase context file" — see D-02); the v2.0 sequence (62 keystone → 63–69 consumers).
- `.planning/phases/62-unified-node-codec-core-keystone/62-CONTEXT.md` — carried-forward codec decisions: D-01 keystone/stub discipline, D-03 JSON wire format, D-09 zeroization ownership, the coverage-barrel rule, dist-staleness.
- `CONTEXT.md` (repo root) — pinned glossary: `readKey`/`writeKey`, the **three counters** (`generation` / `keyEpoch` / `sequenceNumber` — never conflate), descriptor refs. **Cite, do not redefine.**

### Schema reference (do not modify this phase)

- `docs/METADATA_SCHEMAS.md` — the static `node/v3` schema (Phase-62 rewrite) + the **`generation`-single-source-of-truth invariant** navigation/rotation must respect (per-node authoritative only on the child's own envelope; every mirror is a staleness witness).

### Parity / pitfalls

- `.planning/research/PITFALLS.md` — AAD byte-encoding drift = silent total decryption failure; the coverage-barrel pitfall (drives the named `engine.ts`).
- `.planning/research/ARCHITECTURE.md` — envelope + AAD byte encoding + TS↔Rust parity surface (Rust consumes this in Phase 69).

### Implementation sites — TypeScript

- `packages/sdk-core/src/folder/load.ts` — **un-stub** `fetchAndDecryptMetadata` (L32) + `loadFolderMetadata` (L54); the read-chain navigation home.
- `packages/sdk-core/src/folder/metadata-ops.ts` — **un-stub** `renameInFolder` (L27), `deleteFromFolder` (L37), `addFilePointerToFolder` (L54), `moveItem` (L69); add/move/scope-exit mutation home.
- `packages/sdk-core/src/folder/registration.ts` — **un-stub** `createSubfolder` (L37), `updateFolderMetadataAndPublish` (L59).
- `packages/sdk-core/src/rotation/engine.ts` — **NEW** (D-01): `rotateReadFromNode` / `rotateOne` + the 4 named seams; the `hasCoveringGrant` predicate (D-08, file placement at discretion). **Named file, not a barrel** (ROADMAP SC#5).
- `packages/sdk-core/src/cas.ts:38` (`publishWithCas`) + `packages/sdk-core/src/ipns/index.ts:39` (`createAndPublishIpnsRecord`) — existing CAS-publish infra; **reuse**. Mind the first-publish seq convention (see `<code_context>`).
- `packages/core/src/node/` — Phase-62 codec surface to **call, never reimplement**: `sealNode`/`unsealNode`, `sealChildReadKey`/`unsealChildReadKey`, `sealContent`/`unsealContent`, `encodeReadBody`/`decodeReadBody`, `validateNode`, types (`Node`/`SealedChildRef`/`PublishedNode`/`NodeContent`/`VersionEntry`).
- `packages/crypto/src/aes/seal.ts` — `sealAesGcmAad(plaintext,key,aad)` / `unsealAesGcmAad(sealed,key,aad)` / `buildNodeAad(nodeId,kind,generation,role)`; ECIES `wrapKey`/`unwrapKey` for `readDescriptorRef` (grant issue + invite claim).
- `packages/sdk/src/share/index.ts:88` (`reWrapForRecipients`) — **DELETE** (D-03); callers `packages/sdk/src/client.ts:164,1602` — **rewire** to parent-key sealing. `packages/sdk/src/types.ts:32` (`addShareKeys` callback) — **leave for Phase 68**.
- `packages/sdk/src/reencrypt.ts` — `executeLazyRotation` stub → superseded by `rotateReadFromNode`; web wiring is Phase 68.
- Quarantined suites to revive (`TODO(phase 63)`): `packages/sdk-core/src/__tests__/folder.test.ts` (L105/248/445/491/515/563), `packages/sdk/src/__tests__/client-extended.test.ts` (moveItem), `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts`.
- `tests/sdk-e2e/` — the **one happy-path round-trip** home (D-04); the crash-safety suite is Phase 64.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **Phase-62 codec is complete and callable** (`packages/core/src/node/`) — navigation/rotation compose `unsealChildReadKey` → fetch by `ipnsName` → `unsealNode`/`unsealContent`; sealing composes `sealChildReadKey` / `sealNode`. Never reimplement the seal/encode/decode.
- **Seal primitive (Phase 61)** in `@cipherbox/crypto`: `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`, roles `0x01–0x04` KAT-frozen. AAD uses the **child's** id/kind/generation, so re-pointing a parent or replaying a stale generation fails the unwrap closed — this is what makes delete/move/rename-over genuinely cut off.
- **CAS publish infra** exists and is functional: `publishWithCas` (`cas.ts:38`, takes `encodeAndUpload`/`decodeRemote`/`merge` + `sequenceNumber`) and `createAndPublishIpnsRecord` (`ipns/index.ts:39`, `expectedSequenceNumber` pre-increment CAS guard). The rotation `rotateOne` CAS step builds on these.
- **Transport-decoupled share pattern** — the established "Share/Bin operations take explicit context objects + accept callback functions for API calls" convention (STATE.md) is the seam for D-05 (mock-testable grant issuance).

### Established Patterns

- **Coverage excludes `src/**/index.ts` barrels** ([[project-sdk-core-coverage-excludes-index-barrels]]) — `rotateReadFromNode`/`rotateOne` MUST live in a named file (`engine.ts`), or SC#5 coverage misses them.
- **Every first IPNS publish embeds sequence 1** ([[project-ipns-first-publish-embed-seq-1]]) — new-node creation (add-item, subfolder, file node) is a first publish: `createAndPublishIpnsRecord` embeds the arg verbatim (pass `1n`); `publishWithCas` embeds base+1 (pass `0n`). The post-Phase-60 strict gate rejects first publish with embedded seq ≠ 1 (400).
- **Zeroization — terminal-owner only** ([[project-zeroization-callee-must-not-zero-reused-buffer]]) — rotation **mints** `readKey'`/`fileKey'` (it owns those; zero on its own failure paths), but must NOT zero caller-supplied parent keys or reused session keys. Carried from Phase 62 D-09; flag for the security-reviewer.
- **Strict IPNS resolve recovers the Ed25519 pubkey from the k51 name, not a DB column** ([[project-ipns-resolve-ed25519-pubkey-from-name]]) — relevant wherever navigation resolves a node.
- **Greenfield delete-outright** — no dual-codec / no migration; `node/v3` is the sole codec.

### Integration Points

- **`packages/core` `dist/` rebuild required** before sdk-core typecheck ([[project-cross-package-dist-staleness]]) — rebuild core dist before judging the typecheck gate.
- **sdk-e2e is the only real client→API IPNS round-trip** ([[project-sdk-e2e-only-cross-package-publish-gate]]) — for the D-04 happy-path: spin up `docker compose -f docker/docker-compose.yml up -d` + `pnpm --filter @cipherbox/api dev`; redis is on **6380**; capture real 400s via a temporary axios interceptor.
- **Web/SDK folder-state desync** ([[project-web-sdk-folder-state-desync]]) — treat IPNS `sequenceNumber` as the version clock; the `folderTree` reconcile-before-rotate discipline is a **Phase-68** caller responsibility (D-08), but the engine must not assume a reconciled tree.
- **Checker subagents: static analysis only** ([[feedback-gsd-subagents-no-test-runs]]) — design §7.3 echoes this (no concurrent vitest — RAM starvation).

</code_context>

<specifics>
## Specific Ideas

- The user took the **recommended default on all 10 decisions** (terse/decisive), and explored gray areas thoroughly before committing — D-01…D-10 are all the recommended options.
- **Strong scope discipline:** keep Phase 63 to the `sdk-core` read-chain + rotation **skeleton**. Do NOT pull Phase-64 soundness, Phase-65 write-chain/invite-service, Phase-66 schema, or Phase-68/69 host/durable-state work forward. The app being non-runnable mid-milestone is explicitly acceptable.
- **Freeze-the-shape discipline:** the four named seams (`mintFileKeyOnRotate`, `reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean`) must exist and be individually testable so Phase 64 fills them **without re-architecting** the engine — the same "name the deferred behavior after its owning phase" pattern Phase 62 used.
- **ROADMAP Q2 is answered in this file** (D-02: web first-class best-effort, host-agnostic engine).

</specifics>

<deferred>
## Deferred Ideas

- **Rotation soundness** — CRIT-1 content-key rotation (ROT-03), HIGH-3 inner-grant re-mint (ROT-04), HIGH-4 concurrent-add merge (ROT-05), crash-resume convergence + `verifySubtreeClean` (ROT-06), the `tests/sdk-e2e` crash-safety suite (TEST-01), and **batched parent-link publish** (D-09) → **Phase 64**.
- **Write-chain, full Ed25519 write-revocation, bin re-link, full invite create/claim service wiring + `encryptedChildKeys` service removal** → **Phase 65**.
- **`shares`/`share_keys` schema cutover, `readDescriptorRef`/`writeDescriptorRef` columns, `encryptedChildKeys` JSONB drop, atomic CAS publish gate, tombstone, server-side `generation` gate** → **Phase 66**.
- **TEE lease-renewer contract** → **Phase 67**.
- **Web rotation UX, `executeLazyRotation` deletion, durable IndexedDB `{nodeId → generation}` + seq high-water (ROT-07 / M1), `folderTree` reconcile-before-rotate, `addShareKeys` web-callback removal** → **Phase 68**.
- **FUSE/WinFsp symmetric unwrap, Rust `Node` enum, Rust grant-root awareness, durable client floors** → **Phase 69**.
- **Q3** (write-recipient deletions vs owner-held sub-shares — authority model + exposure window) → resolved in **Phase 65 / 68 / 69**.

### Reviewed Todos (not folded)

The `todo.match-phase 63` hits are generic keyword matches with no genuine read-chain/rotation `sdk-core` scope overlap:

- `2026-06-29-node-codec-base64-helper-dedup.md` (area `core`) — a `packages/core` Phase-62 **codec** cleanup, not Phase-63 `sdk-core` behavior.
- `2026-06-24-ts-resolve-strict-rfc3339-validity-parity.md` (area `sdk-core`) — IPNS **Validity** timestamp parsing (phases 66/67), not the read chain. Also reviewed-not-folded in Phase 62.
- `2026-06-26-vault-init-publish-ordering-preflight.md` (area `desktop`) — desktop vault-init ordering, not Phase 63.
- `2026-06-27-add-permanent-delete-confirmation-dialog-in-web-app.md` (area `ui`) — web UX, not `sdk-core`.
- `2026-06-29-recovery-html-vault-v3-migration.md` (area `web`) — web recovery page, Phase-68-ish.
- `2026-02-24-async-incremental-search-index.md` (area `ui`) — client search index, unrelated.

</deferred>

---

*Phase: 63-read-chain-navigation-and-rotation-core*
*Context gathered: 2026-06-29*
