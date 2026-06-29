# Requirements: CipherBox v2.0 Metadata and Sharing Refactor

**Defined:** 2026-06-27
**Core Value:** Zero-knowledge privacy — files encrypted client-side; the server is cryptographically unable to access user data.
**Source of truth:** `.planning/design/2026-06-26-sharing-read-keychaining-design.md` + ADR 0001 (write-revocation = full Ed25519 rotation) + ADR 0002 (read-revoke protects future content only) + `CONTEXT.md` glossary.
**Scope:** Tier 1 (read chain + resumable rotation) + Tier 2 (write-revocation + resolve/republish/TEE contract). Tier 3 out. Greenfield — `node/v3` is the sole codec, no migration.

## v1 Requirements (this milestone)

Requirements for v2.0. Each maps to exactly one roadmap phase. Categories: CRYPTO, NODE, READ, ROT, WRITE, TEE, DATA, TEST.

### CRYPTO — AAD-bound seal primitive

- [x] **CRYPTO-01**: `packages/crypto` exposes `sealAesGcmAad`/`unsealAesGcmAad` + a canonical `buildNodeAad(domain‖nodeId‖kind‖generation‖role)` builder, each seal minting a fresh random IV
- [x] **CRYPTO-02**: A byte-identical Rust twin lives in `cipherbox_crypto`, with a committed cross-language KAT (frozen byte encoding; `kind` 0x01/0x02/0x03, raw 16-byte uuid, 4-byte BE generation, role ∈ {0x01 body, 0x02 child-readkey, 0x03 content, 0x04 child-writekey}) asserted by both TS and Rust
- [x] **CRYPTO-03**: A sealed blob replayed under a different `childId`/`role`/`generation` fails to unseal (AAD transplant resistance)

### NODE — unified metadata model and codecs

- [x] **NODE-01**: A single `Node` model (folder/file/root via `kind`) with two independently sealed bodies — read-body under `readKey`, write-body under a separate `writeKey` — replaces `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry`
- [x] **NODE-02**: A file node's `content` (incl. `content.fileKey`, and each `VersionEntry`'s inline `fileKey` + mandatory `encryptionMode` GCM/CTR) self-seals under the file node's own `readKey`
- [x] **NODE-03**: `SealedChildRef` is the read-only chain link (`name`, `ipnsName`, `generation` mirror, `versionFloor`, `readKeySealed`); the write link lives in the parent write-body, never in `SealedChildRef`
- [x] **NODE-04**: The published object is a plaintext envelope (`kind`/`id`/`generation`/`aeadVersion` + `readSealed`/`writeSealed`) with `generation` folded into AAD and tamper-evident
- [x] **NODE-05**: In Rust crates, `Node` is a real enum (`Folder { children } / File { content } / Root { children }`), not an `Option`-bag — impossible states unrepresentable
- [x] **NODE-06**: The vault recovery blob carries two keys — `ECIES(rootReadKey)` + `ECIES(rootWriteKey)` — re-designed (not migrated) for the root node's read + write bodies

### READ — read key-chaining navigation and sharing

- [x] **READ-01**: A user can issue a read grant with one ECIES wrap of the share-root `readKey` + one `shares` row (0 node touches, 0 republishes); granting a single file is identical to granting a deep folder
- [x] **READ-02**: A grantee can navigate to a depth-`d` child via one ECIES unwrap then `O(depth)` symmetric AES, recovering content key/CID/mode at a file node; the read path distinguishes "soft behind, retry" from "hard revoked"
- [x] **READ-03**: Adding an item seals the child `readKey` under the parent `readKey` with no per-recipient fan-out; `reWrapForRecipients`/`addShareKeys` are deleted
- [x] **READ-04**: A move within a grantee's scope is link rewrites only (no re-encrypt), computing exact per-grant scope so benign within-scope moves do not over-rotate
- [x] **READ-05**: An invite wraps the single share-root `readKey` to an ephemeral key (private half in the URL fragment); claim re-wraps it to the claimer's key and stores a standard grant; the `encryptedChildKeys[]` fan-out is deleted

### ROT — resumable read-rotation and revocation soundness

- [x] **ROT-01**: `rotateReadFromNode` is a resumable, per-node-commit, idempotent walk backing read-revoke and every scope-exit mutation; published IPNS records are the source of truth (job record advisory)
- [x] **ROT-02**: Rotation fires iff a node leaves a grantee's reachable scope; a node with no covering grant is a pure relink (zero rotations) — enforced as a hard test across delete/move/rename
- [x] **ROT-03**: (CRIT-1) Rotating a file node mints a new `fileKey` (lazy `contentRekeyPending`); a holder of the old `readKey`/`fileKey` cannot decrypt the next published version
- [x] **ROT-04**: (HIGH-3) Rotation re-mints `readDescriptorRef` for every non-revoked grant whose `rootNodeId` is in the rotated set — no orphaned inner grant
- [x] **ROT-05**: (HIGH-4) On a CAS-409 the walk re-fetches and re-merges `SealedChildRef`s rather than re-sealing from a stale child list — a concurrent add is never silently dropped
- [x] **ROT-06**: A crash mid-walk is recoverable — `verifySubtreeClean` rebuilds the frontier, re-run converges, no incorrect double-bump, and the revoked recipient is cut from the root after the root step
- [ ] **ROT-07**: (M1) A durable client-side `{nodeId → highestGeneration}` high-water (survives restart, seeded from the grant `rootGeneration`) fails closed on generation regression

### WRITE — write-revocation (Tier 2, ADR 0001)

- [ ] **WRITE-01**: The write-body holds the node's Ed25519 signing material sealed under a separate `writeKey` as a structured recursive write chain (parent seals child `writeKey`, role `0x04`); a read-only holder can never reach signing material
- [ ] **WRITE-02**: Write-revocation performs (c) full Ed25519 rotation — new keypair + k51 name per node, cascading parent re-points to the share root, re-pointing co-grants and owner devices
- [ ] **WRITE-03**: Surviving co-writers receive the rotated Ed25519 key re-wrapped into their `writeDescriptorRef`; an offline co-writer cannot write until re-fetch (explicit)
- [ ] **WRITE-04**: A rotated-out IPNS name is tombstoned (row kept) — the publish gate rejects all writes to it including the EOL-only renewal, resolve returns a tombstone/410, and the name is removed from the TEE republish batch

### TEE — resolve, republish, and the TEE signing contract (Tier 2)

- [ ] **TEE-01**: The TEE is a record-lease-renewer — it receives the marshaled `signedRecord`, verifies its signature, and re-emits the same CID and same sequence with only a later EOL; it cannot originate or repoint a CID
- [ ] **TEE-02**: Republish never increments the sequence (the `+ 1n` republisher path is unified to no-increment); sequence-increment policy lives in the relay
- [ ] **TEE-03**: The canonical `ipns_records` row is the sole source of the TEE's signing inputs; `ipns_republish_schedule`'s duplicated `latestCid`/`sequenceNumber`/`encryptedIpnsKey`/`keyEpoch` columns are collapsed
- [ ] **TEE-04**: Publish is an atomic compare-and-set (`UPDATE … WHERE ipnsName = :n AND sequenceNumber = :expected`; 0 rows ⇒ 409); the EOL-only renewal is guarded identically so it can never regress `latestCid`/`sequenceNumber`
- [ ] **TEE-05**: Resolve anti-rollback uses `generation` as the authority plus a durable per-node seq high-water and `versionFloor`; DB is canonical with a case-split fail-closed fall-through (expected-null shared-folder rows apply the seq floor; signedRecord-CID ≠ latestCid fails closed)
- [ ] **TEE-06**: Enclave bindings are hardened — internal epoch self-derivation (never the relay's scalars), name↔key binding asserted before emit, and migration durability via a client recovery path
- [ ] **TEE-07**: The publish gate enforces forward-only `generation` per node server-side (defence-in-depth, mirroring the sequence anti-rollback)

### DATA — schema/DB cutover and bin

- [ ] **DATA-01**: The `share_keys` table and entity are deleted outright (no dual-codec, no `version`-discriminator bridge)
- [ ] **DATA-02**: `shares` is slimmed to one grant row per recipient carrying `readDescriptorRef`/`writeDescriptorRef` (legacy `readKeyEcies`/`ShareGrant` retired)
- [ ] **DATA-03**: `folder_ipns` is renamed to `ipns_records` (entity `IpnsRecord`) and `folder_ipns.public_key` is dropped — the Ed25519 pubkey is always recovered from the k51 name via `publicKeyFromIpnsName`
- [ ] **DATA-04**: A `BinEntry` is a `readKey`-sealed re-link; restore is a pure re-link (the `originalFolderKeyEncrypted` re-encrypt-on-restore path is deleted), a private delete is unlink + `BinEntry` (no rotation), and a shared delete rotates the departing subtree + revokes the grant rows

### TEST — cross-cutting verification infrastructure

- [ ] **TEST-01**: A rotation crash-safety/resume suite (the must-exist-before-merge suite) extends `tests/sdk-e2e` — the only real client→API IPNS publish/resolve round-trip — with abort-and-resume cases
- [x] **TEST-02**: The TS↔Rust AAD KAT is a single committed fixture asserted by both `packages/crypto/__tests__` and a Rust `#[test]` (a byte mismatch is silent total decryption failure)
- [ ] **TEST-03**: The winfsp read-path is validated via `Cargo Check & Test (Windows)` (authoritative) and the dispatch-gated desktop E2E is triggered explicitly

## Future Requirements (deferred)

### Capability layer (Tier 3)

- **CAP-01**: Write-plane time-boxing / op-count caps (`ttl`/`opCap`/`capabilityId` on the grant row) — only meaningful on the write path, only if a mediated mechanism is ever chosen; read-side TTL is cryptographically unenforceable. Do NOT add to `Node`/`SealedChildRef`.
- **CAP-02**: Per-file "re-encrypt now" + `O(versions)` "purge history" for high-sensitivity content rotation
- **CAP-03**: Lazy rotation *walk* (rotate-on-next-write across a subtree) — the `rotateOne` primitive is amortizable later if the eager cost proves painful

### Infra

- **INFRA-01**: SEED-001 Phala TEE on-demand cost cycling (stop/start the CVM around the republish window)

## Out of Scope

Explicitly excluded; documented to prevent scope creep.

| Feature | Reason |
| --- | --- |
| Data migration / dual-codec bridge | Greenfield — no prod data, staging wiped; `node/v3` is the sole codec |
| Mediated write signing (`POST /ipns/sign`, approach a/d) | Runner-up only; (c) full Ed25519 rotation is ratified (ADR 0001); turns the untrusted relay into a signing oracle |
| Read-side TTL / op-caps | Cryptographically unenforceable — once a reader holds key + CID, IPFS serves it forever |
| Retroactive content protection | Read-revoke protects future content/navigation only; already-distributed CIDs + prior versions stay readable (ADR 0002) |
| Lazy rotation walk | Eager walk is the committed model this milestone |
| Network-first resolve repoint | Stays a post-v2.0 v2 move; near-term DB-canonical with generation + seq-floor authority |
| SEED-001 TEE cost cycling | Separable infra-cost optimization; deferred to a future infra milestone |
| Encrypted Productivity Suite | Deferred to a post-v2.0 milestone |

## Traceability

Which phases cover which requirements. Populated during roadmap creation.

| Requirement | Phase | Status |
| --- | --- | --- |
| CRYPTO-01 | Phase 61 | Complete |
| CRYPTO-02 | Phase 61 | Complete |
| CRYPTO-03 | Phase 61 | Complete |
| TEST-02 | Phase 61 | Complete |
| NODE-01 | Phase 62 | Complete |
| NODE-02 | Phase 62 | Complete |
| NODE-03 | Phase 62 | Complete |
| NODE-04 | Phase 62 | Complete |
| NODE-05 | Phase 62 | Complete |
| NODE-06 | Phase 62 | Complete |
| READ-01 | Phase 63 | Complete |
| READ-02 | Phase 63 | Complete |
| READ-03 | Phase 63 | Complete |
| READ-04 | Phase 63 | Complete |
| READ-05 | Phase 63 | Complete |
| ROT-01 | Phase 63 | Complete |
| ROT-02 | Phase 63 | Complete |
| ROT-03 | Phase 64 | Complete |
| ROT-04 | Phase 64 | Complete |
| ROT-05 | Phase 64 | Complete |
| ROT-06 | Phase 64 | Complete |
| TEST-01 | Phase 64 | Pending |
| WRITE-01 | Phase 65 | Pending |
| WRITE-02 | Phase 65 | Pending |
| WRITE-03 | Phase 65 | Pending |
| WRITE-04 | Phase 65 | Pending |
| DATA-01 | Phase 66 | Pending |
| DATA-02 | Phase 66 | Pending |
| DATA-03 | Phase 66 | Pending |
| DATA-04 | Phase 66 | Pending |
| TEE-04 | Phase 66 | Pending |
| TEE-05 | Phase 66 | Pending |
| TEE-07 | Phase 66 | Pending |
| TEE-01 | Phase 67 | Pending |
| TEE-02 | Phase 67 | Pending |
| TEE-03 | Phase 67 | Pending |
| TEE-06 | Phase 67 | Pending |
| ROT-07 | Phase 68 | Pending |
| TEST-03 | Phase 69 | Pending |

**Coverage:**

- v1 requirements: 39 total (CRYPTO ×3, NODE ×6, READ ×5, ROT ×7, WRITE ×4, TEE ×7, DATA ×4, TEST ×3)
- Mapped to phases: 39
- Unmapped: 0 ✓

---

_Requirements defined: 2026-06-27_
_Last updated: 2026-06-27 — traceability table populated, coverage 39/39_
