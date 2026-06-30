# Roadmap: CipherBox

## Milestones

- ✅ **v1.1 IPFS Infrastructure** — Phases 18–60 (shipped 2026-06-27) — full detail: `milestones/v1.1-ROADMAP.md`
- 📋 **v2.0 Metadata and Sharing Refactor** — Phases 61–69 (active)

## Phases

<details>
<summary>✅ v1.1 IPFS Infrastructure (Phases 18–60) — SHIPPED 2026-06-27</summary>

- [x] Phase 18: Performance Instrumentation
- [x] Phase 19: IPNS Resolution Improvement
- [x] Phase 19.1: Extract core crypto SDK as shared package (INSERTED)
- [x] Phase 19.2: IPFS Upload Performance Optimization (INSERTED)
- [x] Phase 20: Vault Migration
- [x] Phase 21: BYO-IPFS Node Support
- [x] Phase 22: Performance Baselines Completion
- [x] Phase 23: Rust SDK Extraction
- [x] Phase 24: Bug Fixes & Test Infrastructure
- [x] Phase 25: Desktop Enhancements
- [x] Phase 26: Observability & UX Tuning
- [x] Phase 27: Writable Shares (PoC)
- [x] Phase 28: Code Hygiene & Logging
- [x] Phase 29: Infrastructure Hardening
- [x] Phase 30: Web App Observability
- [x] Phase 31: Structural Decomposition
- [x] Phase 32: FUSE Async FilePointer Resolution
- [x] Phase 33: Windows Async FilePointer Resolution
- [x] Phase 34: E2E Test Expansion & Staging Baselines
- [x] Phase 35: Phala Testnet TEE Migration
- [x] Phase 36: Inline upload progress
- [x] Phase 37: Parallel batch upload pipeline
- [x] Phase 38: Retire deprecated web services
- [x] Phase 39: User-configurable vault parameters
- [x] Phase 40: Desktop vault settings integration
- [x] Phase 41: package and app versioning and release cycles
- [x] Phase 42: API unpin integrity
- [x] Phase 43: FUSE write durability
- [x] Phase 44: IPNS conflict handling
- [x] Phase 45: Desktop FUSE write-durability cleanup
- [x] Phase 46: Desktop FUSE data-loss bugs + replay hardening
- [x] Phase 47: SDK folder-state and publish-path consolidation
- [x] Phase 48: SDK self-bootstrap regression fix and shared-folder/metadata consolidation
- [x] Phase 49: Shared-folder move (intra-share) and useFolderNavigation unwrap consolidation
- [x] Phase 50: IPFS/IPNS Data-Integrity Fixes
- [x] Phase 51: Crypto-Signature & Secret-Leak Hardening
- [x] Phase 52: Desktop FUSE Durability & At-Rest Safety
- [x] Phase 53: Release & Supply-Chain Engineering
- [x] Phase 54: E2E Test-Infra Typing
- [x] Phase 55: Large Source-File Refactor
- [x] Phase 56: FUSE and IPNS Durability Hardening
- [x] Phase 57: API CID and Provider Hardening and Module Dedup
- [x] Phase 58: IPNS Signature-Verify Coverage
- [x] Phase 59: FUSE IPNS Verify/Publish Hardening and Cleanup
- [x] Phase 60: IPNS Verification Cross-Layer Closeout: Desktop and API

</details>

### v2.0 Metadata and Sharing Refactor (Phases 61–69)

- [x] **Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT** — Additive AES-GCM+AAD seal in `packages/crypto` and `crates/crypto` with a committed TS↔Rust known-answer test (completed 2026-06-28)
- [x] **Phase 62: Unified Node Codec (Core Keystone)** — `Node`/`SealedChildRef`/`PublishedNode` types replacing all legacy metadata types; nothing downstream typechecks until this lands (completed 2026-06-28)
- [x] **Phase 63: Read-Chain Navigation and Rotation Core** — Read key-chain walk, `rotateReadFromNode`/`rotateOne` engine, scope-exit predicate, and invite re-wrap in `packages/sdk-core` (completed 2026-06-29)
- [x] **Phase 64: Rotation Soundness — Revocation Guarantees** — CRIT-1 content-key rotation, HIGH-3 inner grant re-mint, HIGH-4 concurrent-add merge, crash-safe resume, and the `tests/sdk-e2e` crash-safety suite (completed 2026-06-29)
- [x] **Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim** — Structured write-body, (c) full Ed25519 write-revocation, bin restore as pure re-link, invite claim re-wrap; delete `addShareKeys`/`reWrapForRecipients`/`encryptedChildKeys` (completed 2026-06-30)
- [x] **Phase 66: API Schema Cutover, Publish Gate, and Tombstone** — Delete `share_keys`, slim `shares`, rename `folder_ipns` → `ipns_records`, drop `public_key`, atomic CAS publish, tombstone state, resolve case-split, server-side generation gate; run `pnpm api:generate` (completed 2026-06-30)
- [ ] **Phase 67: TEE Lease-Renewer Contract Rewrite** — TEE becomes a record-lease-renewer (no CID origination, no sequence increment), internal epoch derivation, name↔key binding, tombstone guard
- [ ] **Phase 68: Web Integration — Rotation UX and Durable Client State** — Replace `executeLazyRotation` with `rotateReadFromNode`, durable IndexedDB generation + seq high-water (M1 defense, survives restart), `folderTree` reconcile-before-rotate
- [ ] **Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness** — Symmetric child-key unwrap, `spawn_file_meta_reencrypt` deletion from both callers, grant-root scope computation, durable client floors, `Node` Rust enum, Windows CI gate

## Phase Details

### Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT

**Goal**: The canonical AES-GCM+AAD seal primitive and its frozen byte encoding exist in both TypeScript and Rust with a committed known-answer test proving byte-identical output.

**Depends on**: Phase 60 (v1.1 complete)

**Requirements**: CRYPTO-01, CRYPTO-02, CRYPTO-03, TEST-02

**Success Criteria** (what must be TRUE):

1. `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad` are exported from `packages/crypto` with each seal minting a fresh random IV
2. A byte-identical Rust twin exists in `crates/crypto` with the same AAD encoding (domain separator, raw UUID bytes, 4-byte BE generation, role bytes 0x01–0x04)
3. The cross-language KAT fixture — a single hardcoded vector covering all four role bytes — is asserted by both `packages/crypto/__tests__/build-node-aad.test.ts` AND a Rust `#[test]` in `crates/crypto/tests/cross_language.rs`; both pass in CI
4. A sealed blob replayed under a different `childId`, `role`, or `generation` fails to unseal (AAD transplant resistance test passes)

**Plans**: 5/5 plans complete

Plans:
**Wave 1**

- [x] 61-01-PLAN.md — TS AAD builder (`buildNodeAad`/`uuidToBytes`) + frozen `node-aad.json` (aad_vectors, all 4 roles) + TS KAT + parity-script registration [merge gate]

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 61-02-PLAN.md — Rust AAD builder (`build_node_aad` + `uuid` dep + `InvalidAadInput`) + cross-language AAD KAT [closes merge gate]

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 61-03-PLAN.md — TS AEAD-with-AAD seal variants + full-seal vector (D-01b) + extended transplant/negative suite (D-02, CRYPTO-03)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 61-04-PLAN.md — Rust AEAD-with-AAD seal variants + Rust full-seal cross-language KAT
- [x] 61-05-PLAN.md — Docs: ADR 0003 freeze + METADATA_SCHEMAS / METADATA_EVOLUTION_PROTOCOL / FILESYSTEM_SPECIFICATION pointers (D-05)

---

### Phase 62: Unified Node Codec (Core Keystone)

**Goal**: The unified `Node`/`SealedChildRef`/`PublishedNode` types and codecs exist in `packages/core`, replacing all `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` types; all downstream packages typecheck after `dist/` rebuild.

**Depends on**: Phase 61

**Requirements**: NODE-01, NODE-02, NODE-03, NODE-04, NODE-05, NODE-06

**Success Criteria** (what must be TRUE):

1. A single `Node` discriminated by `kind` (folder/file/root) carries two independently sealed bodies — `readSealed` under `readKey` and `writeSealed` under `writeKey` — and the published envelope exposes `generation` plaintext as the AAD epoch and anti-rollback witness
2. A file node's `content` (including `content.fileKey` and each `VersionEntry`'s inline `fileKey` + mandatory `encryptionMode`) self-seals under the file node's own `readKey`, not the parent's key
3. `SealedChildRef` contains name, `ipnsName`, `generation` mirror, `versionFloor`, and `readKeySealed` only — the write link is in the parent write-body exclusively
4. Vault recovery blob carries `ECIES(rootReadKey)` + `ECIES(rootWriteKey)` (two keys, one blob); old `encryptedRootFolderKey` field is removed
5. `packages/sdk-core`, `packages/sdk`, and `apps/web` typecheck cleanly after `packages/core` `dist/` is rebuilt — zero references to retired `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry`
6. `METADATA_SCHEMAS.md` is updated to document the `generation`-as-convergence-witness invariant and the `fileKey`-inside-sealed-read-body semantic change

**Plans**: 9/9 plans complete

Plans:
**Wave 1**

- [x] 62-01-PLAN.md — Node type model + JSON encode/decode codec (folder/file/root round-trip, generation range, fileKey-as-Uint8Array)
- [x] 62-03-PLAN.md — Vault recovery blob v3 hard-cut (two ECIES keys, delete v2/v1 + encryptedRootFolderKey, two-key init)

**Wave 2** *(blocked on 62-01)*

- [x] 62-02-PLAN.md — AAD-bound sealNode/unsealNode + node/index barrel + frozen golden vectors (body-bytes + full-seal lock)

**Wave 3** *(blocked on 62-02, 62-03)*

- [x] 62-04-PLAN.md — Docs: METADATA_SCHEMAS node/v3 rewrite + two SC#6 invariants + evolution/filesystem pointers
- [x] 62-05-PLAN.md — Core barrel cutover, delete folder/+file/, bin→Node adaptation, legacy-test cleanup

**Wave 4** *(blocked on 62-05)*

- [x] 62-06-PLAN.md — sdk-core compile-gate (core dist rebuild, stub behavioral paths, quarantine suites)

**Wave 5** *(blocked on 62-06)*

- [x] 62-07-PLAN.md — sdk compile-gate (write-chain/share/bin/invite stubs, quarantine suites)

**Wave 6** *(blocked on 62-07)*

- [x] 62-08a-PLAN.md — web logic-layer compile-gate (stores/hooks/services/lib/utils to Node + stubs, shared display projection)

**Wave 7** *(blocked on 62-08a)*

- [x] 62-08b-PLAN.md — web component-layer compile-gate (file-browser to Node, discover + quarantine all retired-type suites, full `pnpm typecheck` gate)

---

### Phase 63: Read-Chain Navigation and Rotation Core

**Goal**: The read key-chain navigation and rotation walk exist in `packages/sdk-core` as named implementation files; read grants require one ECIES unwrap then O(depth) symmetric AES; the scope-exit predicate gates every delete/move/rename.

**Depends on**: Phase 62

**Requirements**: READ-01, READ-02, READ-03, READ-04, READ-05, ROT-01, ROT-02

**Open question (Q2)**: Document whether a large eager rotation in a browser-only (no desktop) session is acceptable — the rotation host question for pure-web users. Decision captured in the phase context file.

**Success Criteria** (what must be TRUE):

1. A read grant is issued by ECIES-wrapping the share-root `readKey` into one `shares` row (`readDescriptorRef`) with zero node touches and zero republishes; granting a single file is structurally identical to granting a deep folder
2. A grantee navigates to a depth-`d` child via one ECIES unwrap then `d` symmetric `unsealAesGcmAad` calls, recovering the content key and CID at a file node; the read path distinguishes "soft behind, retry" from "hard revoked" without ambiguity
3. Adding an item seals the child `readKey` under the parent `readKey` with no per-recipient fan-out; `reWrapForRecipients` and `addShareKeys` are deleted from the codebase
4. A move within a grantee's scope produces link rewrites only (zero re-encryption); the scope-exit predicate `hasCoveringGrant` is present and gates every delete/move/rename — a private delete with no active grants triggers zero `rotateReadFromNode` invocations and zero IPNS publishes beyond the parent relink (test verifies zero publish calls)
5. `rotateReadFromNode` is implemented in a named file (`src/rotation/engine.ts` or equivalent, not `index.ts` barrel) so vitest coverage counts it; `rotateOne` commits per-node atomically via CAS before advancing the walk frontier

**Plans**: 7/7 plans complete

Plans:
**Wave 1**

- [x] 63-01-PLAN.md — Read-chain navigation: un-stub `folder/load.ts` + new `share/navigate.ts` (`navigateReadChain` + `NavigateResult` ok/behind-retry/revoked) [READ-02, D-06]
- [x] 63-02-PLAN.md — Grant issuance + invite claim re-wrap: `share/grant.ts` (`issueReadGrant`, `claimInviteReadKey`) mock-tested [READ-01, READ-05, D-05, D-07]
- [x] 63-03-PLAN.md — Rotation engine core: `rotation/engine.ts` (`rotateOne`, `rotateReadFromNode`, 4 named Phase-64 seams, `RotationJobRecord`) [ROT-01, D-01, D-02, D-09, D-10]

**Wave 2** *(blocked on Wave 1)*

- [x] 63-04-PLAN.md — Folder mutations: un-stub `metadata-ops.ts` (add seals child readKey under parent, move = link rewrites only) + `registration.ts` [READ-03, READ-04]
- [x] 63-05-PLAN.md — Scope-exit predicate `hasCoveringGrant` + gating + zero-rotation invariant test + sdk-core barrel wiring [ROT-02, READ-04, D-08]

**Wave 3** *(blocked on 63-04)*

- [x] 63-06-PLAN.md — Delete `reWrapForRecipients` from sdk layer + rewire `client.ts` add-item off the fan-out (addShareKeys type stays for Phase 68) [READ-03, D-03]

**Wave 4** *(blocked on Waves 1-3)*

- [x] 63-07-PLAN.md — One happy-path sdk-e2e round-trip: issue grant → navigate → root-step rotate → revoked grant can't navigate [D-04]

---

### Phase 64: Rotation Soundness — Revocation Guarantees

**Goal**: Rotation correctly closes all three cryptographic revocation gaps — content-key rotation (CRIT-1), inner-grant re-mint (HIGH-3), concurrent-add merge (HIGH-4) — and survives a crash mid-walk; the `tests/sdk-e2e` crash-safety suite gates the phase.

**Depends on**: Phase 63

**Requirements**: ROT-03, ROT-04, ROT-05, ROT-06, TEST-01

**Success Criteria** (what must be TRUE):

1. (CRIT-1 / §7.3 test 2) Rotating a file node mints a new `fileKey'` and sets `contentRekeyPending`; a test asserts a holder of the old `readKey`/`fileKey` cannot decrypt the next published version of the file
2. (HIGH-3 / §7.3 test 3) Rotation queries `shares WHERE rootNodeId IN (rotated_node_ids)` and re-mints `readDescriptorRef` for every non-revoked recipient including inner grants rooted at subtree nodes; a test with a leaf-level share asserts the inner grantee's descriptor is re-minted and the revoked recipient's row is deleted
3. (HIGH-4 / §7.3 test 4) On a CAS-409, `rotateOne` re-fetches the current parent node, re-decodes the read-body, and merges concurrently-added `SealedChildRef`s before re-sealing; a test injects a concurrent upload mid-rotation and asserts the new child is present in the completed parent
4. A crash mid-walk is recovered by re-running `rotateReadFromNode`; `verifySubtreeClean` rebuilds the frontier from published IPNS records, re-run converges without double-bumping any node's `generation`, and the revoked recipient is cut from the root after the root step
5. (TEST-01) The `tests/sdk-e2e` abort-and-resume suite covering crash-safety passes against a live local API stack; SDK E2E must pass before phase sign-off (it is the only real client→API IPNS publish/resolve round-trip)

**Plans**: 8/8 plans complete

Plans:
**Wave 1**

- [x] 64-01-PLAN.md — D-06 binding-stability: node-identity/generation preservation + moveItem dest re-seal
- [x] 64-02-PLAN.md — mergeChildren three-way merge (ROT-05 domain logic)
- [x] 64-03-PLAN.md — mintFileKeyOnRotate content-key rotation (ROT-03/CRIT-1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 64-04-PLAN.md — D-01 fail-closed publish + D-02 re-seal + batched parent-publish

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 64-05-PLAN.md — reMintGrantsRootedAt inner-grant re-mint (ROT-04/HIGH-3)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 64-06-PLAN.md — mergeConcurrentChildren CAS-409 merge (ROT-05/HIGH-4)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 64-07-PLAN.md — verifySubtreeClean + resume guard + D-07 ordering (ROT-06)

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 64-08-PLAN.md — sdk-e2e abort-and-resume crash-safety suite (TEST-01)

---

### Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim

**Goal**: The write-body carries Ed25519 signing material sealed under a separate `writeKey`; write-revocation performs full Ed25519 rotation per ADR 0001; bin restore is a pure re-link; invite claim re-wraps a single root `readKey`.

**Depends on**: Phase 64

**Requirements**: WRITE-01, WRITE-02, WRITE-03, WRITE-04

**Open question (Q3)**: When a write-recipient deletes or moves a node the owner independently sub-shared, the unlink and the revocation split across two principals. Decide the authority model and the acceptable exposure window; document the decision in the phase context file.

**Success Criteria** (what must be TRUE):

1. The write-body holds the node's Ed25519 signing material sealed under `writeKey` with role `0x04` (`child-writekey`); a read-only holder who holds only `readDescriptorRef` can never reach signing material — verified by attempting to unseal the write-body with only the `readKey`
2. Write-revocation generates a new Ed25519 keypair and k51 name per node, cascading parent re-points to the share root; old names are tombstoned (publish gate rejects, resolve returns 410) and removed from the TEE republish batch
3. Surviving co-writers receive the rotated Ed25519 key re-wrapped into their `writeDescriptorRef`; an offline co-writer receives a clear "cannot write until re-fetch" error on next attempt
4. `bin` restore is a pure re-link (`BinEntry` re-sealed under destination `readKey`); `originalFolderKeyEncrypted` and its re-encrypt-on-restore path are deleted from `packages/core/src/bin/types.ts` and `packages/sdk/src/bin/index.ts`; `encryptedChildKeys` JSONB fan-out is deleted from invite claim

**Plans**: 7/7 plans complete

Plans:
**Wave 1**

- [x] 65-01-PLAN.md — core role-0x04 write-chain seal primitives (sealChildWriteKey / unsealChildWriteKey) [wave 1]
- [x] 65-02-PLAN.md — bin restore pure re-link + delete legacy re-encrypt path (BinEntry.nodeReadKey) [wave 1]
- [x] 65-03-PLAN.md — invite-claim service wiring (single readKey re-wrap; no encryptedChildKeys fan-out) [wave 1]

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 65-04-PLAN.md — shared-write on the write-body model + co-writer "cannot write until re-fetch" error [wave 2]
- [x] 65-05-PLAN.md — rotation engine real-writeKey wiring; remove PLACEHOLDER_WRITE_KEY (folds FLAG-63-U1) [wave 2]

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 65-06-PLAN.md — write-revocation driver rotateWriteFromNode (full Ed25519 rotation, child-first cascade, tombstone-intent, co-writer re-wrap) [wave 3]

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 65-07-PLAN.md — sdk-e2e write-chain rotation round-trip gate (D-04) [wave 4]

---

### Phase 66: API Schema Cutover, Publish Gate, and Tombstone

**Goal**: The database reflects the `node/v3` model: `share_keys` deleted, `shares` slimmed to descriptor refs, `folder_ipns` renamed to `ipns_records` with `public_key` dropped, atomic CAS publish, tombstone state machine, and case-split resolve hardening.

**Depends on**: Phase 65

**Requirements**: DATA-01, DATA-02, DATA-03, DATA-04, TEE-04, TEE-05, TEE-07

**Sub-phase research flag**: Before writing the TypeORM migration, inspect the live FK constraint map for `folder_ipns` → `ipns_records` rename against staging DB schema; all referencing tables (`ipns_republish_schedule`, `shares`, `vaults`) must migrate atomically.

**Success Criteria** (what must be TRUE):

1. `share_keys` table and entity are deleted; `shares` carries `readDescriptorRef`/`writeDescriptorRef`/`rootNodeId`/`rootIpnsName`/`rootGeneration`; the legacy `readKeyEcies`/`ShareGrant` shape is gone from all entity, DTO, and service files
2. `folder_ipns` is renamed to `ipns_records` (entity class `IpnsRecord`); the `public_key` column is dropped; strict-verify recovers the Ed25519 pubkey exclusively via `publicKeyFromIpnsName`; a test with a null-`public_key` shared-folder row asserts strict-verify works correctly
3. Publish is an atomic conditional UPDATE (`WHERE ipnsName = :n AND sequenceNumber = :expected`; zero rows ⇒ 409); (§7.3 test 16) two concurrent publishes at the same `dbSeq` produce exactly one 409 and zero lost updates
4. (§7.3 test 15) The `parseCachedRecord`-null case-split is explicit: a legitimate null-`signedRecord` shared-folder row applies the `seq ≥ storedSeq` floor; a `signedRecord`-CID mismatch fails closed — neither falls through ungated
5. A tombstoned `ipns_records` row is rejected at the publish gate (403/410) and at the EOL-only renewal; resolve returns a 410 marker for tombstoned names; server-side `generation` gate enforces forward-only per node, mirroring the sequence CAS
6. `pnpm api:generate` is run and the regenerated `packages/api-client/src/generated/` is committed alongside the migration; the `check-api-client.sh` pre-commit hook passes

**Plans**: 9/9 plans complete

Plans:
**Wave 1**

- [x] 66-01-PLAN.md — IPNS entity rename (`folder_ipns`→`ipns_records`, drop `public_key`, +`tombstoned_at`/`generation`) + import-site propagation [DATA-03]
- [x] 66-03-PLAN.md — Shares entities + DTOs reshape (descriptor refs; delete `share_keys`; slim `share_invites`) [DATA-01, DATA-02, DATA-04]

**Wave 2** *(blocked on Wave 1)*

- [x] 66-02-PLAN.md — IPNS atomic CAS publish + generation gate + tombstone + resolve case-split + 410 marker [TEE-04, TEE-05, TEE-07]
- [x] 66-04-PLAN.md — Shares service/controller + invite-claim rewrite (hard-delete revoke; single-`readKey` grant) [DATA-01, DATA-02, DATA-04]
- [x] 66-05-PLAN.md — Forward drop-recreate migration `1750000000000-ApiSchemaCutover` [DATA-01, DATA-02, DATA-03]

**Wave 3** *(blocked on Wave 2)*

- [x] 66-06-PLAN.md — `pnpm api:generate` + commit regenerated `@cipherbox/api-client` (success criterion 6)

**Wave 4** *(blocked on Wave 3)*

- [x] 66-07-PLAN.md — sdk-core `generation` param threading (publish primitives) [TEE-07]
- [x] 66-08-PLAN.md — web compile-gate stubs for deleted/reshaped share+invite endpoints (real rework defers to Phase 68)

**Wave 5** *(blocked on Wave 4)*

- [x] 66-09-PLAN.md — [BLOCKING] `migration:run` + sdk-e2e `ipns-publish-gate` proof suite (tests 15/16/17/20 + TEE-07) [TEE-04, TEE-05, TEE-07, DATA-01..04]

---

### Phase 67: TEE Lease-Renewer Contract Rewrite

**Goal**: The TEE worker is a record-lease-renewer — it receives a marshaled `signedRecord`, verifies its signature, and re-emits the same CID and sequence with only a later EOL; it cannot originate or repoint a CID.

**Depends on**: Phase 66

**Requirements**: TEE-01, TEE-02, TEE-03, TEE-06

**Success Criteria** (what must be TRUE):

1. (§7.3 test 12) The `+ 1n` sequence increment is removed from `apps/tee-worker/src/routes/republish.ts`; republish re-signs with the same `sequenceNumber` and same `value` (CID), only a later EOL; a test asserts the re-signed record has equal `sequenceNumber` to the input and that a revoked CID is never re-signed forward
2. The TEE derives `currentEpoch` from its own clock (never from relay-supplied scalars); it asserts `publicKeyFromIpnsName(ipnsName) == pubkey(decryptedKey) == record.pubkey` before emitting any re-signed record; a tombstoned name presented to the renewer is rejected at the publish gate
3. The canonical `ipns_records` row is the sole source of the TEE's signing inputs; `ipns_republish_schedule`'s duplicated `latestCid`/`sequenceNumber`/`encryptedIpnsKey`/`keyEpoch` columns are collapsed; no signing inputs are sourced from the schedule snapshot
4. The EOL-only renewal uses the same atomic CAS guard (`WHERE sequenceNumber = :loaded`), so it can never regress `latestCid`/`sequenceNumber`; a TEE republish E2E round-trip (staging or local stack) confirms the new contract end-to-end

**Plans**: TBD

---

### Phase 68: Web Integration — Rotation UX and Durable Client State

**Goal**: The web app uses `rotateReadFromNode` for all revocation-triggering mutations, persists a durable IndexedDB generation + seq high-water that survives page reload, and reconciles `folderTree` before any rotation publish.

**Depends on**: Phase 67

**Requirements**: ROT-07

**Open question (Q1)**: A co-writer offline during write-key rotation cannot write until re-fetch. Accept as explicit with a clear error message, or add a grace period/notification? Decision documented in the phase context file.

**Open question (Q3 — web side)**: When a write-recipient deletes/moves a node the owner independently sub-shared, decide the authority model for the web mutation path (mirrors Phase 65 Q3 decision).

**Success Criteria** (what must be TRUE):

1. (M1 / §7.3 test 5) The `{nodeId → highestGeneration}` map persists to IndexedDB; a test simulates a page reload mid-session and asserts generation regression is rejected fail-closed after restart — in-memory-only storage is rejected at review
2. `executeLazyRotation` is deleted from `apps/web/src/services/share.service.ts`; all revocation-triggering paths (delete, move, rename when scope exit) call `rotateReadFromNode`; `addShareKeys` and `reWrapForRecipients` are deleted from per-mutation fan-out paths
3. `folderTree` is reconciled against the current `sequenceNumber` before any rotation publish; if reconciliation fails the mutation defers rather than skipping rotation — the `#489`/`#494` desync class cannot produce a silent missed revocation
4. A durable per-node `{nodeId → highestSeq}` seq high-water is wired into `resolveIpnsRecord` in the web resolve path; a generation or seq regression from the relay causes a fail-closed error, not silent acceptance
5. All new web test files use the `.test.ts` extension (not `.spec.ts`); `find apps/web/src -name "*.spec.ts"` returns empty

**Plans**: TBD

**UI hint**: yes

---

### Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness

**Goal**: The FUSE and WinFsp clients use symmetric key unwrap throughout, grant-root awareness gates scope-exit mutations, `Node` is a real Rust enum, and the Windows CI gate passes.

**Depends on**: Phase 68

**Requirements**: TEST-03

**Sub-phase research flag**: The grant-root scope computation algorithm in `crates/fuse/src/write_ops/` is net-new and under-specified in the design; a plan-time design pass is required before implementation.

**Open question (Q3 — FUSE side)**: When a write-recipient deletes/moves a node the owner independently sub-shared, decide the authority model for the FUSE delete path (mirrors Phase 65 Q3 decision).

**Success Criteria** (what must be TRUE):

1. All `cipherbox_crypto::ecies::unwrap_key` calls in `crates/fuse/src/inode.rs` (lines 434, 452, 658, 716) and `crates/fuse/src/replay.rs` (line 365) are replaced by `cipherbox_crypto::aes::unseal_aes_gcm_aad` symmetric unwrap with correct `buildNodeAad` AAD
2. `spawn_file_meta_reencrypt` is deleted from `crates/fuse/src/metadata.rs` AND from both callers: `crates/fuse/src/write_ops/implementation/rename.rs` (line 248) and `crates/fuse/src/platform/windows/write_ops.rs` (line 1183) — Windows path verified in CI, not locally
3. Grant-root awareness is implemented in `delete`/`rename`/`move` FUSE paths: a shared-scope exit triggers `rotateReadFromNode`; a private delete with no active grants is a pure relink with zero rotation publishes
4. `enum Node { Folder { children: Vec<SealedChildRef> }, File { content: SealedContent }, Root { children: Vec<SealedChildRef> } }` exists in `crates/core/src/`; durable generation + seq high-water is persisted adjacent to the write journal (survives FUSE daemon restart)
5. (TEST-03 / §7.3 test 21) `Cargo Check & Test (Windows)` CI gate passes; the dispatch-gated desktop E2E is triggered explicitly via `gh workflow run "CI E2E Tests" --ref <branch>` and passes before phase sign-off

**Plans**: TBD

---

## Progress

| Phase | Name | Plans Complete | Status | Completed |
| --- | --- | --- | --- | --- |
| 61 | AAD-Bound Seal Primitive and Cross-Language KAT | 5/5 | Complete    | 2026-06-28 |
| 62 | Unified Node Codec (Core Keystone) | 9/9 | Complete    | 2026-06-28 |
| 63 | Read-Chain Navigation and Rotation Core | 7/7 | Complete    | 2026-06-29 |
| 64 | Rotation Soundness — Revocation Guarantees | 8/8 | Complete   | 2026-06-29 |
| 65 | SDK Write-Chain, Bin Re-link, and Invite Claim | 7/7 | Complete    | 2026-06-30 |
| 66 | API Schema Cutover, Publish Gate, and Tombstone | 9/9 | Complete    | 2026-06-30 |
| 67 | TEE Lease-Renewer Contract Rewrite | 0/? | Not started | - |
| 68 | Web Integration — Rotation UX and Durable Client State | 0/? | Not started | - |
| 69 | FUSE and WinFsp — Rust Integration and Grant-Root Awareness | 0/? | Not started | - |

v1.1 history: 45 phases complete (198 plans). See `milestones/v1.1-ROADMAP.md` for full detail.
