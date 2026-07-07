# Roadmap: CipherBox

## Milestones

- ✅ **v1.1 IPFS Infrastructure** — Phases 18–60 (shipped 2026-06-27) — full detail: `milestones/v1.1-ROADMAP.md`
- 📋 **v2.0 Metadata and Sharing Refactor** — Phases 61–73 (active)

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

### v2.0 Metadata and Sharing Refactor (Phases 61–73)

- [x] **Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT** — Additive AES-GCM+AAD seal in `packages/crypto` and `crates/crypto` with a committed TS↔Rust known-answer test (completed 2026-06-28)
- [x] **Phase 62: Unified Node Codec (Core Keystone)** — `Node`/`SealedChildRef`/`PublishedNode` types replacing all legacy metadata types; nothing downstream typechecks until this lands (completed 2026-06-28)
- [x] **Phase 63: Read-Chain Navigation and Rotation Core** — Read key-chain walk, `rotateReadFromNode`/`rotateOne` engine, scope-exit predicate, and invite re-wrap in `packages/sdk-core` (completed 2026-06-29)
- [x] **Phase 64: Rotation Soundness — Revocation Guarantees** — CRIT-1 content-key rotation, HIGH-3 inner grant re-mint, HIGH-4 concurrent-add merge, crash-safe resume, and the `tests/sdk-e2e` crash-safety suite (completed 2026-06-29)
- [x] **Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim** — Structured write-body, (c) full Ed25519 write-revocation, bin restore as pure re-link, invite claim re-wrap; delete `addShareKeys`/`reWrapForRecipients`/`encryptedChildKeys` (completed 2026-06-30)
- [x] **Phase 66: API Schema Cutover, Publish Gate, and Tombstone** — Delete `share_keys`, slim `shares`, rename `folder_ipns` → `ipns_records`, drop `public_key`, atomic CAS publish, tombstone state, resolve case-split, server-side generation gate; run `pnpm api:generate` (completed 2026-06-30)
- [x] **Phase 67: TEE Lease-Renewer Contract Rewrite** — TEE becomes a record-lease-renewer (no CID origination, no sequence increment), internal epoch derivation, name↔key binding, tombstone guard (completed 2026-07-01)
- [x] **Phase 68: Web Integration — Rotation UX and Durable Client State** — Replace `executeLazyRotation` with `rotateReadFromNode`, durable IndexedDB generation + seq high-water (M1 defense, survives restart), `folderTree` reconcile-before-rotate (all 12 plans executed 2026-07-01; verification passed 14/14 after 68-11/68-12 gap closure, see 68-VERIFICATION.md) (completed 2026-07-01)
- [x] **Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness** — Symmetric child-key unwrap, `spawn_file_meta_reencrypt` deletion from both callers, grant-root scope computation, durable client floors, `Node` Rust enum, Rust SDK-owned read chain (Phase 68.2 parity), Windows CI gate (completed 2026-07-06)
- [ ] **Phase 70: Rotation Soundness — Deep Merge, Fresh-Record Resume, and Durable Floor Concurrency** — Local-wins merge for rotated child keys, deep `verifySubtreeClean`, true fresh-record crash-resume, grant-callback threading through the real walk, and an atomic/async-safe anti-rollback floor store (5 deferred CodeRabbit/PR-review todos)
- [ ] **Phase 71: Share-Invite Security and IPNS Data-Integrity (API)** — Validate sharer root ownership, apply-or-reject later invite grants, `claim_count` CHECK constraint, partial unique index on `ipns_records(user_id) WHERE is_root`, first-publish INSERT-race 409, same-seq CID equivocation decision, direct bulk-revoke DELETE, and `ShareInviteService` lifecycle unit coverage (8 todos)
- [ ] **Phase 72: SDK Write-Plane Durability and Correctness** — Delete drops the removed child's `WriteChildRef`, fail-closed `getWriteBodyParams` on transient resolve miss, restore-to-different-parent re-homing, `SealedChildRef` size/modifiedAt mirror refresh, legacy `moveInSharedFolder` branch removal, write-plane helper dedup, and two write-chain test-fidelity fixes (8 todos)
- [ ] **Phase 73: Shared Write/Navigation Correctness (Web)** — Preserve nested write capability across navigate-up/breadcrumb restore, invalidate stale nav-stack child snapshots, gate the non-listing read facades with the ROT-07 floor, give WRITE-03 refresh-access a live production trigger, and route drag-payload kind through the resolved listing (5 todos)

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

**Plans**: 8/8 plans complete

Plans:

**Wave 1**

- [x] 67-01-PLAN.md — Schedule collapse: drop 4 signing-input columns from the entity + forward migration [TEE-03]
- [x] 67-02-PLAN.md — TEE internal epoch self-derivation + refuse-stale guard + ReEnrollRequiredError [TEE-06]
- [x] 67-03-PLAN.md — TEE renewIpnsRecord lease transform (same CID + same seq + later EOL) [TEE-01, TEE-02]
- [x] 67-04-PLAN.md — createSubfolder teeKeys wiring (ECIES-wrap + enroll new subfolders) [TEE-03]
- [x] 67-05-PLAN.md — Local docker tee-worker service + API env + sdk-e2e bullmq/pg deps [TEE-01]

**Wave 2** *(blocked on Wave 1)*

- [x] 67-06-PLAN.md — TEE route verify-in-enclave rewrite: verify→name↔key binding→no-increment re-sign [TEE-01, TEE-02, TEE-06]
- [x] 67-07-PLAN.md — Relay reshape: ipns_records JOIN + marshaled-record contract + renewIpnsRecordEol equality CAS + 2-arg enrollFolder [TEE-03, TEE-06]

**Wave 3** *(blocked on Wave 2)*

- [x] 67-08-PLAN.md — [BLOCKING] migration:run + sdk-e2e TEE round-trip suite + human-verify gate [TEE-01, TEE-02, TEE-03, TEE-06]

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
5. Per docs/TESTING.md, this phase adds ZERO `apps/web` test files: core logic is hoisted to the SDK and unit-tested with Vitest, and the UI + durability are covered by Web E2E (Playwright, `tests/web-e2e/`); `find apps/web/src -name "*.spec.ts"` returns empty

**Plans**: 12/12 plans complete

Plans:
**Wave 1**

- [x] 68-01-PLAN.md — SDK durable high-water state machine + resolve enforcement over an injected HighWaterStore seam, Vitest (ROT-07/SC#1/SC#4/D-05)
- [x] 68-02-PLAN.md — share.service modernization: real grant fetch + type extension + delete legacy fan-out (SC#2/D-12)
- [x] 68-03-PLAN.md — apps/api PATCH :shareId/grant + DTO + service + api:generate, Jest (D-10 endpoint gap)
- [x] 68-04-PLAN.md — rotation UI primitives: notification action, toast, rotation.store, header badge (D-02/D-03)
- [x] 68-05-PLAN.md — client.ts rotation integration: scope-exit rotate + reconcile-defer + move-durability, Vitest (SC#2/SC#3/D-04/D-12)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 68-06-PLAN.md — thin web IndexedDB HighWaterStore adapter + resolveIpnsRecord enforcement wiring (ROT-07/SC#1/SC#4/D-05/D-07/D-08)
- [x] 68-07-PLAN.md — owner reconcile: SDK driver (Vitest) + thin web api-client transport wrapper, eager on login (D-10/D-11)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 68-08-PLAN.md — rotation tail-walk driver + navigator.locks multi-tab + badge lifecycle (D-02/D-03/D-09)
- [x] 68-09-PLAN.md — mutation-failure UX: defer-retry backoff + fail-closed toasts + co-writer refresh-access (D-01/D-05/D-06/WRITE-03)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 68-10-PLAN.md — Web E2E Playwright specs: rotation-durability (real-reload IndexedDB + fail-closed toast, SC#1/SC#4) + rotation-ux (badge lifecycle + failure UX, D-01/D-02/D-03/D-06/WRITE-03)

**Gap closure** *(from 68-VERIFICATION.md — closes the 2 failed truths; client.ts shared-file serialized across two waves)*

- [x] 68-11-PLAN.md — Gap 1 (BLOCKER): make the fail-closed anti-rollback gate live — inject RotationHighWater into CipherBoxClient, gate reconcileFolderSequence via enforceResolved, thread ResolveRotationContext into handleSync, UI-driven durability spec (ROT-07/SC#4) [wave 1]
- [x] 68-12-PLAN.md — Gap 2: refresh folderTree after scope-exit rotation — rotateReadFromNode returns the root's rotated key/generation/seq, performScopeExitRotation writes it back so a same-session retry self-heals without reload (ROT-07/SC#3) [wave 2, depends on 68-11]

**UI hint**: yes

---

### Phase 68.1: Web Client Runtime Integration

**Goal**: The v2.0 web app runs end-to-end on the `node/v3` read+write chain — login initializes/loads the root Node, folders navigate, files upload/download/preview/stream, versions and bin work, and sharing (grant/invite/shared-folder ops) functions — replacing all 46 `not implemented — phase 63/65` runtime stubs by wiring the web app + `CipherBoxClient` to the existing `packages/sdk-core` primitives. The full `tests/web-e2e` Playwright suite passes, finally validating Phases 62–68 at runtime.

**Depends on**: Phase 63 (read-chain sdk-core), Phase 65 (write-chain sdk-core), Phase 66 (API/DB cutover), Phase 68 (rotation UX)

**Requirements**: WEB-01, WEB-02, WEB-03, WEB-04

**Context**: web-e2e has not run green since the start of Milestone 4 — the sdk-core read/write chains shipped (Phases 63/65) but the web + `client.ts` wiring was deferred as `not implemented — phase 63/65` stubs. This phase is the deferred integration, gated by the web-e2e suite. Scope is runtime wiring to existing primitives only; two small new sdk-core helpers are permitted (empty-root-Node publish; raw-`fileKey` download). No new crypto/codec design.

**Success Criteria** (what must be TRUE):

1. No `not implemented — phase 63` or `not implemented — phase 65` throw remains reachable from any live web/`client.ts` runtime path (`grep -rn "not implemented — phase 6" packages/sdk/src apps/web/src` returns only test/commented references, if any)
2. A new user logs in, an empty root Node is published via the Node codec, and the app reaches `/files`; an existing user's root loads — the login→vault flow completes without throwing
3. Owned flows work end-to-end in the browser: folder navigate/create, file upload/create, download, preview, AES-CTR streaming, replace/update/save, versions (restore/delete/download), delete→bin re-link, and move
4. Shared flows work end-to-end: shared-folder read navigation + shared-file download (`navigateReadChain`), shared-folder write ops (rename/delete/move/batch, shared file update), share creation, permission upgrade, and invite create+claim
5. The full `tests/web-e2e` Playwright suite passes locally against the standard stack (all specs, not a subset); `find apps/web/src -name "*.spec.ts"` stays empty (logic in SDK, UI via web-e2e — SC#5 doctrine)

**Plans**: 22/22 plans complete

Plans:
**Wave 1**

- [x] 68.1-01-PLAN.md — Owned write-body foundation: sdk-core publishEmptyRootNode + write-body in updateFolderMetadataAndPublish + client ensureFolderLoaded recovery + FolderState/config keys (resolves D-03) [wave 1]

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 68.1-02-PLAN.md — client createFolder (owned subfolder + write-body) + bin subtree-collectors + delete obsolete reencrypt.ts (D-05) [wave 2]
- [x] 68.1-03-PLAN.md — Login root-Node init wiring: new-user publishes empty root Node + registers vault; existing-user unchanged (SC#2) [wave 2]
- [x] 68.1-05-PLAN.md — Shared read navigation (navigateToShare/subfolder/up/breadcrumb/downloadSharedFile) via navigateReadChain [wave 2]
- [x] 68.1-07-PLAN.md — [TDD] sdk-core owned file-Node chain (createFileMetadata/resolveFileMetadata/updateFileMetadata + raw-fileKey helper + registration wrappers) — the one genuine build [wave 2]

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 68.1-04-PLAN.md — Owned file read services (resolveFileMetadata + raw-fileKey download) + D-02 kind-cache discrimination [wave 3]
- [x] 68.1-08-PLAN.md — client shared-write wrappers: updateSharedFile + moveInSharedFolder (primitives already exist) [wave 3]

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 68.1-06-PLAN.md — Owned read UI wiring: preview + AES-CTR streaming + DetailsDialog [wave 4]
- [x] 68.1-09-PLAN.md — client owned file write: uploadFile rewire + replaceFile + restore/deleteFileVersion + downloadFromIpns [wave 4]
- [x] 68.1-10-PLAN.md — Shared-folder write ops web wiring: rename/update/delete/move/batch (useSharedWriteOps) [wave 4]
- [x] 68.1-11-PLAN.md — Sharing create + invite: collectChildKeys + ShareDialog share/upgrade + createInviteLink/claimInvite [wave 4]
- [x] 68.1-14-PLAN.md — D-02 kind-cache population: call resolveKinds on owned (useFolderNavigation + folder.store) and shared (useSharedNavigationActions + useSharedNavigation) folder-load/nav render paths so files render as file rows [wave 4]

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 68.1-12-PLAN.md — Owned file write + versions web wiring: service transforms + editor save + versions + download UI [wave 5]

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 68.1-13-PLAN.md — web-e2e enablement + triage: SC#1/SC#5 assertions hold; 5 real bugs fixed (createFolder retry+folder-store desync, details-dialog fields, batch-download UI, FileListItem/ContextMenu kind-cache wiring). **Full Playwright suite NOT re-confirmed green** — GAP-1 (resolveFileMetadata AEAD failure) and GAP-2 (cold-reload IPNS DFS timeout) surfaced; WEB-04 left unchecked pending a follow-up session. See 68.1-13-SUMMARY.md Known Gaps. [wave 6]

**Gap closure** *(verification returned 2/5 SCs — plans address SC#3/GAP-1, SC#4, the durable-registration addendum, SHARE-WRITE-KEY/GAP-3, GAP-4, GAP-5, and the SC#5 exit gate)*

- [x] 68.1-15-PLAN.md — SC#4 shared-browse UI: wire SharedFolderRow + SharedFileBrowser to the D-02 kind cache (isFileRef); in-folder Download + kind-gated double-click [wave 1]
- [x] 68.1-16-PLAN.md — Durable child IPNS registration: createFolder TEE enrollment (addendum i, TDD) + confirm per-file mint enrolls + bin-restore hardening (addendum ii) [wave 1]
- [x] 68.1-21-PLAN.md — Triage: GAP-4 D-05 stale-data toast (role=alert) + GAP-5 share-itemname-backfill legacy-seed 400 (DTO drift) [wave 1]
- [x] 68.1-17-PLAN.md — SC#3/GAP-1: diagnose + fix resolveFileMetadata AEAD decrypt failure (CTR/streaming video + post-upload batch-download) [wave 2]
- [x] 68.1-18-PLAN.md — SHARE-WRITE-KEY foundation: SDK resolveShareWriteDescriptor (owned write-chain, TDD) + owner-side WRITE share/invite create [wave 3]
- [x] 68.1-19-PLAN.md — Write upgrade/downgrade via UpdateGrant + optional writeDescriptorRef API change + api:generate + ShareDialog wiring [wave 4]
- [x] 68.1-20-PLAN.md — fetchShareKeys fail-closed + recipient shared writeKey seeding (writeDescriptorRef) + shared-move dest-key sourcing via write-chain [wave 4]
- [x] 68.1-22-PLAN.md — WEB-04 exit gate: fresh FULL tests/web-e2e run (supersede stale .last-run.json) + GAP-2 re-triage; human sign-off (autonomous: false) [wave 5]

**Gap closure — round 2** *(from 68.1-VERIFICATION.md Round-2 Addendum: write-plane cold-load clobber, breadcrumb-up regression, rotation SC-4, GAP-6 item-name cutover, GAP-7 shared-move picker, test-infra flake, and the fresh exit gate)*

- [ ] 68.1-23-PLAN.md — Write-plane cold-load clobber fix: cold-load writeKey recovery + refreshFolderStateFromNetwork preserves the write-body mirror (conflict-detection 219 / writable-shares 3.2 / sharing-workflow 7.3) [wave 1]
- [ ] 68.1-24-PLAN.md — GAP-6 item-name encrypted cutover: remove dead plaintext backfill + updateItemName endpoint + api:generate; encrypted end-to-end spec [wave 1]
- [ ] 68.1-25-PLAN.md — Test-infra hardening: wallet-login Core Kit retry/backoff + createTestAccount root-Node publish (D-06 nodeId) [wave 1]
- [ ] 68.1-26-PLAN.md — Breadcrumb-up regression (full-workflow 3.9): restore synchronous cached-children render on navigate-up [wave 2, depends 68.1-23]
- [ ] 68.1-27-PLAN.md — GAP-7 enumerateSharedSubtree read/write-chain rewrite (off deleted share_keys) + SharedMoveDialog picker [wave 2, depends 68.1-23]
- [ ] 68.1-28-PLAN.md — rotation-durability SC-4: classify the reconcile/regression error to the D-05 stale-data toast on the stale-replay rename [wave 2, depends 68.1-23]
- [ ] 68.1-29-PLAN.md — WEB-04 exit gate: fresh FULL 208-spec tests/web-e2e run + corroborated artifact + human sign-off (autonomous: false) [wave 3, depends 68.1-23..28]

**Gap closure — round 3** *(from 68.1-29-SUMMARY.md new gap: deep shared writes — root-depth-only shared writeKey seeding blocks writes inside nested subfolders of a write-shared tree, writable-shares 8.2)*

- [ ] 68.1-30-PLAN.md — Deep shared-write seeding: SDK resolveSharedSubfolderWriteKey (one-hop write-chain, TDD) + navigateToSubfolder seeds the recovered subfolder writeKey; single-file writable-shares.spec.ts live re-run (WEB-03) [wave 1]

---

### Phase 68.2: SDK-Owned Read Chain and Resolved Folder Listings (INSERTED)

**Goal**: The gated read chain — IPNS resolve, the ROT-07 durable anti-rollback gate, IPFS fetch, and node unseal — and per-child metadata resolution live entirely inside `packages/sdk`. The SDK exposes **resolved folder listings** (a `ResolvedChild` carrying `ipnsName`, `name`, `kind`, `size?`, `modifiedAt`, `sequence`) and owns the resolve + cache + invalidation, becoming the single source of truth for folder state. The web app's parallel read path and duplicate state are collapsed to thin projections driven by SDK output/events, closing the Web/SDK folder-state desync bug class.

**Depends on**: Phase 68.1 (web runtime integration — the parallel web-layer read path this consolidates was wired there)

**Requirements**: SDK-READ-01, SDK-READ-02, SDK-READ-03, SDK-READ-04 (new — register in REQUIREMENTS.md during planning/discuss)

**Context**: Phase 68.1 wired the web file browser onto a web-layer read chain — `apps/web/src/services/ipns.service.ts` (which owns the security-critical ROT-07 durable anti-rollback gate the raw sdk-core resolve does not apply), `apps/web/src/services/file-metadata.service.ts`, `apps/web/src/lib/kind-cache.ts`, and `apps/web/src/hooks/useFileSize.ts` — that duplicates `packages/sdk`'s own read chain (`client.ts` `ensureFolderLoaded`/`dfsFindFolder`, `sdk-core` `resolveFileMetadata`) and maintains a second source of truth (`apps/web/src/stores/folder.store.ts`) alongside the SDK's `folderTree`. This dual read path + dual state is the root of the "Web/SDK folder-state desync" bug class surfaced during 68.1 smoke testing (an owner not seeing a grantee's upload into a shared folder until they themselves write; file size/modifiedAt display gaps). Project doctrine is logic in `packages/sdk`, UI as a thin layer validated via web-e2e — so security-critical read verification must not live in a React service. This phase moves the gated read chain + listing resolution into the SDK behind an injected `DurableFloorStore` adapter (the browser supplies persistence; the SDK owns the anti-rollback gating logic), exposes resolved listings, and reduces the web to rendering a projection. It subsumes and supersedes the interim `SealedChildRef.size`/`modifiedAt` mirror added under 68.1 (commit ba3e0229a): size/kind/modifiedAt become fields on `ResolvedChild`, resolved once per folder load and cached inside the SDK — no parent-node write amplification and no per-open web-side resolve.

**Success Criteria** (what must be TRUE):

1. The ROT-07 durable anti-rollback gate and the file/folder read-chain resolve live in `packages/sdk`/`packages/sdk-core`, not in `apps/web/src/services`: `ipns.service.ts` and `file-metadata.service.ts` are deleted or reduced to thin re-exports, and `apps/web` no longer imports `unsealNode`/`unsealChildReadKey` or calls a web-side `resolveIpnsRecord` on the read path (`grep` in `apps/web/src` returns only rendering/projection usage).
2. The SDK exposes a folder-listing API returning resolved children (`kind`, `size?`, `modifiedAt`, `sequence` per child); the web file list, shared browser, and details dialogs render from it with no web-side per-child resolve or cache — `apps/web/src/lib/kind-cache.ts` and `apps/web/src/hooks/useFileSize.ts` are deleted.
3. `apps/web/src/stores/folder.store.ts` is a projection of SDK state/events, not an independent source of truth; there is exactly one folder-state owner (the SDK `folderTree`).
4. The interim mirror is reverted: `SealedChildRef` is back to its frozen five-field set (NODE-03), and size/modifiedAt are sourced from the resolved listing (the codec/encode/decode/`metadata-ops` mirror changes from ba3e0229a are removed).
5. Regression coverage closes the desync bug class: a `tests/web-e2e` proves an owner (or a second client) sees a grantee's upload into a shared folder without the owner first writing, and that file size/modified-date render from the resolved listing; the full web-e2e suite stays green.

**Plans**: 14/14 plans complete

Plans:
**Wave 1**

- [x] 68.2-01-PLAN.md — Wave 1: SDK-internal gated read resolve (ROT-07 enforceResolved on resolvePublishedNode/dfsFindFolder, before any deletion) [TDD]

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 68.2-02-PLAN.md — Wave 2: ResolvedChild type + listFolder/listSharedFolder listing API + folder:updated ResolvedChild[] event [TDD]

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 68.2-03-PLAN.md — Wave 3: SDK write-path + IPFS-transport facade + pure-util re-exports (D-07 write scope)
- [x] 68.2-05-PLAN.md — Wave 3: Author the shared-folder desync regression e2e (SC#5)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 68.2-04-PLAN.md — Wave 4: SDK vault-bootstrap + device-registry + BYO-pinning facade (off-path pockets)
- [x] 68.2-06-PLAN.md — Wave 4: Web owned read rewire + relocate version-transforms + render kind/size/modifiedAt from ResolvedChild
- [x] 68.2-07-PLAN.md — Wave 4: Web owned file I/O rewire onto the SDK IPFS-transport facade (progress preserved)
- [x] 68.2-08-PLAN.md — Wave 4: Web shared-folder navigation/write rewire onto listSharedFolder
- [x] 68.2-09-PLAN.md — Wave 4: Collapse folder.store to a ResolvedChild projection + nav re-resolve + poll invalidation (SC#3/#5)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 68.2-10-PLAN.md — Wave 5: Web off-path pockets (BYO/auth/device-registry) + pure-util call sites onto the facade

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 68.2-11-PLAN.md — Wave 6: Delete ipns.service/file-metadata.service/kind-cache/useFileSize + allowlist-free D-07 grep gate + unit/typecheck

**Wave 7** *(blocked on Wave 6 completion)*

- [x] 68.2-12-PLAN.md — Wave 7: Revert the SealedChildRef size/modifiedAt mirror LAST (restore NODE-03) + full web-e2e phase gate

**Wave 8** *(gap closure — SDK-READ-03 / SC#5, verification 2026-07-06)*

- [x] 68.2-13-PLAN.md — Wave 8: Gated live-resolve-on-navigation for already-loaded folders (forceResolve option, fixes the self-referential cache clock) [TDD]

**Wave 9** *(blocked on Wave 8 completion)*

- [x] 68.2-14-PLAN.md — Wave 9: Thread { forceResolve: true } into the web nav/poll freshness legs + prove shared-folder-desync e2e + full-suite re-triage

### Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness

**Goal**: The FUSE and WinFsp clients use symmetric key unwrap throughout, grant-root awareness gates scope-exit mutations, `Node` is a real Rust enum, and the Windows CI gate passes. The Rust read chain (IPNS resolve + durable anti-rollback floor gate + node unseal + child-metadata resolution) lives in the shared Rust core/SDK crates — not reimplemented inline in the FUSE/WinFsp layer — mirroring the Phase 68.2 SDK-owned read chain on the TypeScript side.

**Depends on**: Phase 68, Phase 68.2 (mirrors its SDK-owned read-chain design on the Rust side)

**Requirements**: TEST-03

**Sub-phase research flag**: The grant-root scope computation algorithm in `crates/fuse/src/write_ops/` is net-new and under-specified in the design; a plan-time design pass is required before implementation.

**Open question (Q3 — FUSE side)**: When a write-recipient deletes/moves a node the owner independently sub-shared, decide the authority model for the FUSE delete path (mirrors Phase 65 Q3 decision).

**Added scope (Phase 68.2 parity — Rust SDK ownership)**: Mirror the Phase 68.2 consolidation on the Rust side. The read-chain resolve, the durable anti-rollback generation/sequence high-water gate, node unseal, and per-child metadata resolution must live in the shared Rust crates (`crates/core`, and a dedicated Rust SDK crate if warranted), with the FUSE and WinFsp layers consuming a resolved child-listing API rather than reimplementing resolve/unseal/gating inline in `crates/fuse/src/inode.rs`, `replay.rs`, and `metadata.rs`. This keeps the desktop client a thin FUSE/WinFsp adapter over an owning Rust SDK — symmetric to `packages/sdk` owning the web read chain — so the duplication/desync class 68.2 removes on the web cannot recur in Rust. The durable floor persistence (SC#4) is the Rust analog of 68.2's injected `DurableFloorStore`.

**Success Criteria** (what must be TRUE):

1. All `cipherbox_crypto::ecies::unwrap_key` calls in `crates/fuse/src/inode.rs` (lines 434, 452, 658, 716) and `crates/fuse/src/replay.rs` (line 365) are replaced by `cipherbox_crypto::aes::unseal_aes_gcm_aad` symmetric unwrap with correct `buildNodeAad` AAD
2. `spawn_file_meta_reencrypt` is deleted from `crates/fuse/src/metadata.rs` AND from both callers: `crates/fuse/src/write_ops/implementation/rename.rs` (line 248) and `crates/fuse/src/platform/windows/write_ops.rs` (line 1183) — Windows path verified in CI, not locally
3. Grant-root awareness is implemented in `delete`/`rename`/`move` FUSE paths: a shared-scope exit triggers `rotateReadFromNode`; a private delete with no active grants is a pure relink with zero rotation publishes
4. `enum Node { Folder { children: Vec<SealedChildRef> }, File { content: SealedContent }, Root { children: Vec<SealedChildRef> } }` exists in `crates/core/src/`; durable generation + seq high-water is persisted adjacent to the write journal (survives FUSE daemon restart)
5. (TEST-03 / §7.3 test 21) `Cargo Check & Test (Windows)` CI gate passes; the dispatch-gated desktop E2E is triggered explicitly via `gh workflow run "CI E2E Tests" --ref <branch>` and passes before phase sign-off
6. (Phase 68.2 parity) The Rust read-chain resolve + durable anti-rollback floor gate + node unseal + child-metadata resolution live in `crates/core` (and/or a dedicated Rust SDK crate); `crates/fuse` and the WinFsp paths consume a resolved child-listing API and contain no duplicated IPNS-resolve/unseal/anti-rollback logic — the read chain exists once in the Rust core, not reimplemented per client

**Plans**: 25/25 plans complete

- [x] 69-21-PLAN.md
- [x] 69-22-PLAN.md
- [x] 69-23-PLAN.md
- [x] 69-24-PLAN.md
- [x] 69-25-PLAN.md

- [x] 69-19-PLAN.md
- [x] 69-20-PLAN.md

- [x] 69-17-PLAN.md
- [x] 69-18-PLAN.md

- [x] 69-15-PLAN.md
- [x] 69-16-PLAN.md

- [x] 69-01-PLAN.md
- [x] 69-02-PLAN.md
- [x] 69-03-PLAN.md
- [x] 69-04-PLAN.md
- [x] 69-05-PLAN.md
- [x] 69-06-PLAN.md
- [x] 69-07-PLAN.md
- [x] 69-08-PLAN.md
- [x] 69-09-PLAN.md
- [x] 69-10-PLAN.md
- [x] 69-11-PLAN.md
- [x] 69-12-PLAN.md
- [x] 69-13-PLAN.md
- [x] 69-14-PLAN.md

---

### Phase 70: Rotation Soundness — Deep Merge, Fresh-Record Resume, and Durable Floor Concurrency

**Goal**: The read-key rotation engine is sound under concurrency and crash-resume: a concurrent-add CAS-409 re-merge no longer downgrades a rotated child's `readKeySealed`, `verifySubtreeClean` walks the full subtree (not just immediate children), fresh-record crash-resume is actually wired, grant callbacks reach the real walk so inner-grant re-mint fires, and the anti-rollback floor store is atomic and non-blocking under async concurrency. This closes the rotation-soundness debt deferred across Phases 64/68/69.

**Depends on**: Phase 64, Phase 68 (durable floor), Phase 69 (Rust floor store)

**Source todos**:

- `.planning/todos/pending/2026-06-29-rotation-concurrent-add-merge-downgrades-rotated-child-readkey.md`
- `.planning/todos/pending/2026-06-29-rotation-fresh-record-resume-and-sc4-double-bump.md`
- `.planning/todos/pending/2026-06-29-rotation-coderabbit-followups-deferred.md`
- `.planning/todos/pending/2026-07-02-rotation-hardening-followups-from-pr-review.md`
- `.planning/todos/pending/2026-07-07-sdk-floor-store-concurrency-atomicity.md`

**Success Criteria** (what must be TRUE):

1. A concurrent-add CAS-409 re-merge preserves a locally-rotated child's `readKeySealed` (a `localWins`/generation-aware merge in `packages/sdk-core/src/rotation/merge.ts`), verified by an sdk-e2e test where remote-wins would break navigation
2. `verifySubtreeClean` recurses the full subtree and treats a missing root record as unclean (not clean); resume gating no longer depends on a non-empty `completedNodeIds`
3. Fresh-record crash-resume is wired (no docstring "not yet wired — needs Phase-68 durable floor"); `rotateOne` returns the merged children, not the pre-merge snapshot, and a missing job record does not silently desync `pendingChildCount`
4. `RotationParams` threads `grantCallbacks` into the real walk so the inner-grant reMint gate is reachable outside tests
5. The anti-rollback floor store performs an atomic compare-and-set (Rust `bump_floor` guarded; `JsonSidecarFloorStore::put` no blocking RMW on the async executor; corrupt sidecar fails closed, not `unwrap_or_default`); `bumpFloor` on the TS side no longer runs sequentially where it can race
6. Rotation readKey source buffers are zeroed after use; no module-global `activeRootNodeId` leaks across roots

**Plans**: TBD (run `/gsd-plan-phase 70`)

---

### Phase 71: Share-Invite Security and IPNS Data-Integrity (API)

**Goal**: The API enforces share-invite authorization and cleans up its IPNS/share data-integrity edges: the sharer must own the root before an invite is issued, a later invite's grant is applied-or-explicitly-rejected when a share already exists, DB constraints defend `claim_count` and root uniqueness, the first-publish INSERT race returns a clean 409, the same-seq CID equivocation question is decided, bulk-revoke is a direct DELETE, and `ShareInviteService` gains lifecycle unit coverage.

**Depends on**: Phase 66 (schema cutover), Phase 65 (invite claim)

**Source todos**:

- `.planning/todos/pending/2026-06-30-share-invite-validate-root-ownership.md`
- `.planning/todos/pending/2026-06-30-share-invite-reclaim-apply-later-grant.md`
- `.planning/todos/pending/2026-06-30-share-invites-claim-count-check-constraint.md`
- `.planning/todos/pending/2026-06-30-ipns-records-root-uniqueness-index.md`
- `.planning/todos/pending/2026-06-30-ipns-first-publish-insert-race.md`
- `.planning/todos/pending/2026-06-30-ipns-idempotent-same-seq-cid-equivocation.md`
- `.planning/todos/pending/2026-06-30-shares-bulk-revoke-direct-delete.md`
- `.planning/todos/pending/2026-06-30-restore-shares-module-unit-coverage.md`

**Success Criteria** (what must be TRUE):

1. `createInvite` rejects when the caller does not own `rootIpnsName`/`rootNodeId` (ownership lookup, not verbatim copy from the DTO)
2. `claimInvite` against an already-existing share applies the later invite's grant or explicitly rejects it (no silent `return { shareId }` that drops the grant)
3. A DB CHECK constraint keeps `share_invites.claim_count` within `[0, max_claims]`, and a partial unique index on `ipns_records(user_id) WHERE is_root` exists (both via migration)
4. The IPNS first-publish INSERT race translates the unique-violation into a 409 (not a 500), and the same-seq idempotent-republish path either guards CID equality or documents the accepted equivocation (D-09 decision recorded)
5. `bulkRevoke` issues a single DELETE (not `find` + `remove`)
6. `ShareInviteService` has unit coverage for `createInvite`, `getInvitesForItem`, and `revokeInvite` with realistic fixtures (not placeholder strings)

**Plans**: TBD (run `/gsd-plan-phase 71`)

---

### Phase 72: SDK Write-Plane Durability and Correctness

**Goal**: The SDK write plane no longer grows or corrupts the write-chain on delete/move/restore/replace, fails closed on a transient resolve miss instead of sealing an empty write-body, keeps the display mirror fresh after in-place edits, and drops a latent wrong-key branch — with the duplicated write-plane helper sequences consolidated and two write-chain tests hardened.

**Depends on**: Phase 65 (write-chain), Phase 68.1 (write-link ownership)

**Source todos**:

- `.planning/todos/pending/2026-07-04-delete-should-drop-writechildref-not-just-retain.md`
- `.planning/todos/pending/2026-07-04-getwritebodyparams-transient-resolve-miss-drops-write-chain.md`
- `.planning/todos/pending/2026-07-04-child-ref-size-modifiedat-mirror-stale-after-inplace-edit.md`
- `.planning/todos/pending/2026-07-03-remove-legacy-moveinsharedfolder-sharekeys-branch.md`
- `.planning/todos/pending/2026-07-03-restore-to-different-parent-write-rehoming.md`
- `.planning/todos/pending/2026-07-03-dedupe-sdk-write-plane-helpers.md`
- `.planning/todos/pending/2026-06-30-write-chain-e2e-seed-index-stability.md`
- `.planning/todos/pending/2026-06-29-upload-batch-test-mock-type-drift.md`

**Success Criteria** (what must be TRUE):

1. `deleteItem` drops the removed child's `WriteChildRef` (no unbounded write-chain growth); regression test asserts the chain length shrinks
2. `getWriteBodyParams` (both `client.ts` and `bin/index.ts`) fails closed on a null resolve when a real writeKey is present — it never seals `writeChildren: []` and silently discards the chain
3. `restoreFromBin` to a different parent re-homes the `WriteChildRef` under the destination write scope (not only re-seals the readKey)
4. `replaceFile`/`restoreFileVersion` refresh the parent `SealedChildRef` `size`/`modifiedAt` mirror after an in-place edit
5. The unreachable `moveInSharedFolder` `shareKeys.length > 0` branch (and its `getShareKeysFn` param) is removed, eliminating the latent wrong-key bug
6. The near-identical write-plane helpers (`client.ts` ↔ `bin/index.ts` `getWriteBodyParams`, `replaceFile`/`restoreFileVersion`) share one primitive; `write-chain-rotation.test.ts` identifies rotated seeds by provenance (not fixed `capturedKeys` offsets); `upload-batch.test.ts` mocks use the current `SealedChildRef` shape

**Plans**: TBD (run `/gsd-plan-phase 72`)

---

### Phase 73: Shared Write/Navigation Correctness (Web)

**Goal**: The web app preserves write capability and fresh listings when navigating shared folders — nested write-shares keep their writeKey across navigate-up/breadcrumb restore, the nav-stack no longer serves stale child snapshots, the non-listing read facades are floor-gated, WRITE-03 refresh-access has a real production trigger, and drag-payload kind comes from the resolved listing.

**Depends on**: Phase 68.1, Phase 68.2 (SDK-owned read chain), Phase 72 (write-plane primitives)

**Source todos**:

- `.planning/todos/pending/2026-07-04-nested-shared-write-key-lost-on-up-breadcrumb-restore.md`
- `.planning/todos/pending/2026-07-04-shared-nav-stack-stale-children-snapshot.md`
- `.planning/todos/pending/2026-07-06-gate-non-listing-read-facades.md`
- `.planning/todos/pending/2026-07-02-write03-refresh-access-path-has-no-live-trigger.md`
- `.planning/todos/pending/2026-07-06-sharedfolderrow-drag-kind-classification.md`

**Success Criteria** (what must be TRUE):

1. Navigating up / restoring a breadcrumb into a nested write-share retains the derived writeKey (navStack entries carry the writeKey, not only `folderKey`); a write into a deep shared subfolder succeeds after breadcrumb restore
2. The nav-stack invalidates or re-resolves stale child snapshots on `sharedFolder:updated` (no children pushed/restored by reference without re-resolve)
3. `resolveFileMetadata`, `downloadFromIpns`, and `resolveNodeIdentity` route through the ROT-07 anti-rollback floor gate (not raw `resolvePublishedNode`)
4. WRITE-03 `refreshWriteAccess` / `CannotWriteUntilRefetchError` has at least one live production supplier (`publishNodeFn` can surface a tombstone), not test-only
5. `SharedFolderRow` drag-payload kind is derived from the resolved listing (`isFileRefResolved`/`resolvedByIpnsName`), not `isFileRef` on a bare `SealedChildRef`

**Plans**: TBD (run `/gsd-plan-phase 73`)

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
| 67 | TEE Lease-Renewer Contract Rewrite | 8/8 | Complete    | 2026-07-01 |
| 68 | Web Integration — Rotation UX and Durable Client State | 12/12 | Complete    | 2026-07-01 |
| 69 | FUSE and WinFsp — Rust Integration and Grant-Root Awareness | 25/25 | Complete   | 2026-07-07 |

v1.1 history: 45 phases complete (198 plans). See `milestones/v1.1-ROADMAP.md` for full detail.
