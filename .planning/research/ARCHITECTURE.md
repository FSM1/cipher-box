# Architecture: v2.0 Metadata and Sharing Refactor (node/v3 Integration)

**Domain:** Brownfield integration of ratified node/v3 read key-chaining design into an existing 8-layer monorepo
**Researched:** 2026-06-27
**Confidence:** HIGH — design is implementation-ready; all cited symbols verified against live code

## 1. Design Source of Truth (not relitigated here)

The design is complete and ratified. Sources:

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — canonical implementation spec
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation mechanism ratified as (c)
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — read-revoke scope ratified
- `CONTEXT.md` — pinned terminology (`readKey`/`writeKey`, `generation`/`keyEpoch`/`sequenceNumber`, `grant`, `scope exit`)

## 2. Existing System Architecture (verified)

The live system has 8 layers:

| Layer | Path | Role |
| ----- | ---- | ---- |
| crypto primitives (TS) | `packages/crypto/src/` | AES-GCM/CTR, ECIES, Ed25519, HKDF |
| core domain (TS) | `packages/core/src/` | Metadata schemas + codecs, IPNS record construction |
| sdk-core (TS) | `packages/sdk-core/src/` | Stateless upload/download/CRUD/IPNS |
| sdk (TS) | `packages/sdk/src/` | Stateful client: sharing, bin, invite |
| api (NestJS) | `apps/api/src/` | Untrusted relay: publish gate, share bookkeeping |
| tee-worker | `apps/tee-worker/src/` | Phala enclave: 6h IPNS republish batch signer |
| web | `apps/web/src/` | React 18 SPA, Zustand stores, Web Worker crypto |
| fuse/desktop (Rust) | `crates/fuse/src/`, `apps/desktop/` | FUSE/WinFsp virtual filesystem, Tauri shell |

Rust mirrors of layers 1–3 live in `crates/crypto/`, `crates/core/`, `crates/sdk/`, `crates/api-client/`.

## 3. What the Design Replaces vs Extends

### 3.1 Deleted (confirmed symbols verified in codebase)

| Symbol | Path | Reason |
| ------ | ---- | ------ |
| `FolderMetadata`, `FolderEntry`, `FolderChild`, `EncryptedFolderMetadata` | `packages/core/src/folder/types.ts:15-53` | Replaced by unified `Node` |
| `FileMetadata`, `FilePointer`, `VersionEntry` (current form), `EncryptedFileMetadata` | `packages/core/src/file/` | Replaced by unified `Node` with content self-seal |
| `ShareKey` entity, `share_keys` DB table | `apps/api/src/shares/entities/share-key.entity.ts:14` | Entire per-item key fan-out model deleted |
| `addShareKeys()` (line 337), `reWrapForRecipients()` (line 469) | `apps/web/src/services/share.service.ts` | Fan-out replaced by single `readDescriptorRef` |
| `executeLazyRotation()` | `apps/web/src/services/share.service.ts:602` | Replaced by `rotateReadFromNode()` |
| `spawn_file_meta_reencrypt()` | `crates/fuse/src/metadata.rs:777` | Content self-seal makes move-reencrypt unnecessary |
| `originalFolderKeyEncrypted` field + restore re-encrypt path | `packages/core/src/bin/types.ts:69`, `packages/sdk/src/bin/index.ts:497,688` | Bin restore becomes a pure re-link |
| `encryptedChildKeys` JSONB column on `share_invites` | `apps/api/src/shares/entities/share-invite.entity.ts:59` | Single root-key wrap replaces per-child fan-out |
| `folder_ipns.public_key` column | `apps/api/src/ipns/entities/folder-ipns.entity.ts:63-64` (nullable `Buffer \| null`) | Derivable from k51 name via `publicKeyFromIpnsName`; null for shared-folder rows caused two Phase-60 regressions |
| Dual-source columns on `ipns_republish_schedule` | `apps/api/src/republish/entities/republish-schedule.entity.ts:40-60` (`latestCid`, `sequenceNumber`, `encryptedIpnsKey`, `keyEpoch`) | Collapsed into `ipns_records` as sole source |

Caller note on `spawn_file_meta_reencrypt` deletion: both call sites must be removed — `crates/fuse/src/write_ops/implementation/rename.rs:248` and `crates/fuse/src/platform/windows/write_ops.rs:1183`. The Windows path cannot compile on macOS; `Cargo Check & Test (Windows)` CI gate is authoritative.

### 3.2 Renamed / Schema-Migrated

| Old | New | Where |
| --- | --- | ----- |
| `folder_ipns` table | `ipns_records` table | `apps/api/src/ipns/entities/folder-ipns.entity.ts` entity rename; entity class rename to `IpnsRecord`; all repositories and service imports updated |
| `folderKey` / `fileKey` / `rootFolderKey` | `readKey` | Terminology: retired in all code identifiers per `CONTEXT.md` |
| `ShareGrant` type name | `grant` (concept), no separate type wrapper | `shares` table row is the grant |
| `readKeyEcies` field | `readDescriptorRef` | `shares` entity |
| vault blob: `encryptedRootFolderKey` | `ECIES(rootReadKey)` + `ECIES(rootWriteKey)` | `packages/core/src/vault/blob.ts` — vault blob re-designed to carry two keys |

### 3.3 New Components

| Component | Responsibility | Lives In |
| --------- | -------------- | -------- |
| `sealAesGcmAad` / `unsealAesGcmAad` | AAD-bound AES-256-GCM seal/unseal | `packages/crypto/src/aes/seal.ts` (additive) |
| `buildNodeAad()` | Canonical AAD builder — frozen byte encoding | `packages/crypto/src/aes/seal.ts` (TS); `crates/crypto/` (Rust twin) |
| Cross-language KAT fixture | Byte-identical vector asserted by both TS and Rust | `crates/crypto/tests/cross_language.rs` + `packages/crypto/__tests__/` |
| `Node` / `SealedChildRef` / `PublishedNode` types + codecs | Unified metadata model with two sealed bodies | `packages/core/src/node/` (new subdirectory) |
| `rotateReadFromNode()` | Resumable read-rotation engine with crash-safe frontier | `packages/sdk-core/src/` (named files, not barrel) |
| Durable generation high-water map (`{nodeId → highestGeneration}`) | M1 downgrade defense — fail-closed on generation regression | IndexedDB (web), sqlite-adjacent journal (FUSE/desktop) |
| Durable seq high-water map (`{nodeId → highestSeq}`) | Within-generation rollback defense | IndexedDB (web), FUSE journal adjacent |
| Rotation job record | Crash-safe frontier for `rotateReadFromNode` | IndexedDB (web), FUSE durable state |
| `verifySubtreeClean()` | O(items) read pass flagging dirty edges; resume entry point | `packages/sdk-core/src/` |
| Atomic publish CAS | `UPDATE ipns_records SET … WHERE sequenceNumber = :expected` | `apps/api/src/ipns/ipns.service.ts` (replace non-atomic `findOne → save`) |
| Tombstone state machine | `tombstoned` flag on `ipns_records`; publish-gate rejection; `410` resolve | `apps/api/src/ipns/` |
| TEE lease-renewer contract | Receive marshaled `signedRecord`, verify signature, extend EOL only; no CID origination, no seq increment | `apps/tee-worker/src/routes/republish.ts` (rewrite) |
| Server-side generation gate | Forward-only `generation` per node, mirrors sequence anti-rollback | `apps/api/src/ipns/ipns.service.ts` |
| Grant-root awareness in FUSE | Per-grant scope computation for `delete`/`rename`/`move` paths | `crates/fuse/src/write_ops/` |
| `Node` as Rust enum | `enum Node { Folder { children }, File { content }, Root { children } }` | `crates/core/src/` |

### 3.4 Modified (Extended) — Key Paths

| Component | What Changes |
| --------- | ------------ |
| `packages/crypto/src/aes/seal.ts` | Add `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`; `sealAesGcm` stays for non-node uses |
| `packages/core/src/ipns/create-record.ts` | Clients still self-sign; no change to signing mechanics — only the vault init path changes keys |
| `apps/api/src/ipns/ipns.service.ts` | Atomic CAS publish; generation forward-only gate; tombstone check; `parseCachedRecord`-null fall-through made case-dependent |
| `apps/api/src/ipns/ipns.service.ts:226` | Key-possession-only check unchanged structurally; tombstone check added before it |
| `apps/api/src/shares/share-invite.service.ts` | Invite wraps single root `readKey`; claim re-wraps to claimer; delete `encryptedChildKeys` fan-out |
| `apps/api/src/republish/republish.service.ts:257` | `unenrollIpns` must also tombstone the `ipns_records` row, not only delete the schedule row |
| `crates/fuse/src/inode.rs:434,452,658,716` | ECIES unwrap of `folderKeyEncrypted`/`ipnsPrivateKey` per child → symmetric `unsealAesGcmAad` of `readKeySealed`/`writeKeySealed` |
| `crates/fuse/src/replay.rs:365` | Journal replay ECIES unwrap → symmetric chain unwrap |
| `crates/fuse/src/publish.rs:140` | `resolve_sequence_strict` extended with generation high-water check |
| `apps/web/src/services/share.service.ts` | `executeLazyRotation` → `rotateReadFromNode`; folderTree reconcile before publish |

## 4. Data Flow Under node/v3

### 4.1 Node Publish Envelope (on IPFS)

```text
PublishedNode {
  schema: "node/v3"
  kind:  folder | file | root    -- PLAINTEXT, AAD input
  id:    uuid                    -- PLAINTEXT, AAD input
  generation: u32                -- PLAINTEXT, AAD input; anti-rollback witness
  aeadVersion: 1                 -- PLAINTEXT, primitive tag

  readSealed:  base64            -- AES-256-GCM(read-body,  key=readKey,  aad=buildNodeAad(id,kind,gen,body))
  writeSealed: base64 | null     -- AES-256-GCM(write-body, key=writeKey, aad=buildNodeAad(id,kind,gen,body))
}
```

`buildNodeAad` encodes: `"cipherbox/node-seal/v1" ‖ 0x00 ‖ nodeId(16B raw UUID bytes) ‖ kind(1B: 0x01 folder/0x02 file/0x03 root) ‖ generation(4B BE) ‖ role(1B: 0x01 body/0x02 child-readkey/0x03 content/0x04 child-writekey)`. Byte encoding frozen — the KAT pins it.

### 4.2 Key Unwrap Walk (replaces per-child ECIES)

```text
Owner (or grantee) holds:
  share-root readKey  ← ECIES-unwrap(grant.readDescriptorRef, recipientPrivKey)  [1 ECIES once]

To navigate to a depth-d child:
  for each level:
    unseal parent read-body with parent.readKey + buildNodeAad(parentId, kind, gen, body)
    for target child in SealedChildRef[]:
      child.readKey = unsealAesGcmAad(child.readKeySealed, parent.readKey,
                        buildNodeAad(childId, child.kind, child.generation, child-readkey))
    resolve child.ipnsName → child envelope; verify generation ≥ high-water
```

This replaces all `cipherbox_crypto::ecies::unwrap_key` calls in `crates/fuse/src/inode.rs:434,452,658,716` and `crates/fuse/src/replay.rs:365`.

### 4.3 AAD Byte Encoding — Cross-Language Parity Surface

The byte encoding of `buildNodeAad` is the only TS↔Rust parity contract that is silent on failure (a mismatch causes `unsealAesGcmAad` to return `DecryptionError` with no indication of which language produced the wrong AAD). The cross-language KAT — one committed fixture asserted by both `packages/crypto/__tests__/` and `crates/crypto/tests/cross_language.rs` — is the sole guard. It must be the **first deliverable** in the crypto phase and must include role byte `0x04` (child-writekey).

Critical encoding decisions pinned in the design (do not deviate):

- `nodeId` = raw 16 RFC-4122 bytes, not a hash, not hex
- `kind` = `0x01/0x02/0x03` (not a string)
- `generation` = 4-byte big-endian
- `role` bytes = `0x01..0x04`
- Domain separator ends with `0x00` null byte before `nodeId`

### 4.4 Rotation Engine Data Flow

```text
rotateReadFromNode(rootNodeId, reason, revokedRecipient?) →
  1. Root step: new readKey', generation' = gen+1, for files fileKey' (contentRekeyPending)
     Re-seal root read-body under readKey' with buildNodeAad(…, generation')
     Re-mint readDescriptorRef for all remaining recipients (HIGH-3: also re-mint any grants
       rooted at any descendant — indexed query on shares.rootNodeId ∈ rotated set)
     Delete revoked recipient's grant row
     Publish root (CAS); update parent SealedChildRef.generation mirror
  2. Walk: per node, rotateOne(N, parentReadKey):
     Re-fetch child list; merge any concurrent adds (HIGH-4 re-merge on 409)
     New readKey'', generation'' = N.generation+1; for files fileKey''
     Re-seal; publish N (CAS); batch parent-link updates
  3. verifySubtreeClean(root): O(items) read pass; zero dirty edges = done
  4. Job record (IndexedDB/FUSE durable state): frontier+done per-node checkpoint
```

Crash recovery: re-running `rotateOne` on an already-rotated node generates `readKey'''` and a second rotation step. This is safe — an extra rotation only strengthens the cut.

Convergence test: N is done iff `parent.SealedChildRef[N].generation == N.envelope.generation` and that generation exceeds the pre-job baseline.

### 4.5 TEE Contract Change (Section 6 of design)

Current TEE flow (broken — verified at `apps/tee-worker/src/routes/republish.ts:79`): receives `sequenceNumber`, increments to `+ 1n`, builds and signs a new record.

New TEE contract:

```text
API → TEE:  send marshaled signedRecord (existing signed bytes)
TEE:        parse record; verify Ed25519 signature
            assert publicKeyFromIpnsName(ipnsName) == record.pubkey
            derive currentEpoch from own clock (never from relay's scalar)
            emit same record with same value (CID) and same sequence, only later EOL
TEE → API:  re-signed record (no CID, no seq change); optional upgradedEncryptedKey if epoch migrated
API:        UPDATE ipns_records SET signed_record = :new WHERE sequenceNumber = :loaded (idempotent CAS)
```

The idempotent EOL-renewal CAS (`WHERE sequenceNumber = :loaded`) guarantees the renewal can never regress `latestCid`/`sequenceNumber`. The tombstone check must also reject tombstoned names presented to the TEE renewer.

### 4.6 Write-Revocation Cascade (ADR 0001 — Ed25519 rotation)

```text
Per node in revoked-writer's scope:
  generate new Ed25519 keypair → new k51 ipnsName'
  generate new writeKey'
  re-seal write-body (now carrying ed25519'.priv) under writeKey'
  update parent SealedChildRef.ipnsName to ipnsName'
  re-seal parent read-body (same readKey, new ipnsName reference)
  publish new name (seq=1, fresh enroll); tombstone old name
  TEE: unenroll old name, enroll new name
  Update all grant rows: shares.rootIpnsName → new name; re-mint writeDescriptorRef for surviving co-writers
```

This is leaves-to-root (opposite of read-rotation which is root-first).

## 5. Build Order With Dependencies

The design's Section 7.2 build order is verified against the codebase. Dependency rationale follows each step.

### Phase 1 — `packages/crypto`: AAD-Bound Seal Primitive + KAT

**Files changed:** `packages/crypto/src/aes/seal.ts` (add `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`), `packages/crypto/__tests__/` (KAT), `crates/crypto/` (Rust twin + cross-language test in `crates/crypto/tests/cross_language.rs`)

**Why first:** Self-contained; no consumer breaks. The frozen byte encoding must be committed before any consumer seals a `Node` — a retroactive encoding change would require rotating every sealed body. The KAT must exist before the core codec uses the primitives (otherwise byte-mismatch failures are silent decryption errors at FUSE).

**Dependency:** Nothing above this.

### Phase 2 — `packages/core`: Unified `Node` Codec (Keystone)

**Files changed:** Delete `packages/core/src/folder/`, `packages/core/src/file/metadata.ts` (core codec parts — keep IPNS derivation helpers). Add `packages/core/src/node/types.ts`, `packages/core/src/node/codec.ts`. Update `packages/core/src/vault/blob.ts` (two keys in vault blob). Update `packages/core/src/bin/types.ts` (delete `originalFolderKeyEncrypted`). Update `packages/core/src/index.ts` exports.

**Why second:** Nothing below `packages/core` typechecks until `Node`/`SealedChildRef`/`PublishedNode` exist. `packages/sdk-core`, `packages/sdk`, `apps/web`, and all Rust crates import from this package. `dist/` must be rebuilt before any consumer.

**Dependency:** Phase 1 (`sealAesGcmAad`/`buildNodeAad` are the only new crypto calls here).

**Invariant to document in `METADATA_SCHEMAS.md`:** `generation` is authoritative only on the child's own published envelope; `SealedChildRef.generation` and `shares.rootGeneration` are convergence witnesses. `fileKey` is no longer ECIES-wrapped — it lives inside the sealed read-body (semantic type change, not a rename).

### Phase 3 — `packages/sdk-core`: Read-Chain Navigation + Rotation Driver

**Files changed:** New named files (not barrel additions) for read-chain walk (`chainReadKey`, `navigateToNode`), `rotateReadFromNode` + `rotateOne` + `verifySubtreeClean`, durable high-water utilities. Rebuild `dist/` before consumers.

**Why third:** `sdk-core` is stateless; it consumes `packages/core` `Node` types and `packages/crypto` seal primitives. The rotation engine lives here because it is shared between the web (browser) and FUSE (via the Rust `crates/sdk` wrapper). Named files (not fat `index.ts` barrel) because `vitest` coverage excludes barrels — coverage drop would trip the 80% gate.

**Dependency:** Phase 2 (`Node` types), Phase 1 (`sealAesGcmAad`).

### Phase 4 — `packages/sdk`: Write-Chain, Sharing, Bin, Invites

**Files changed:** Rewrite `packages/sdk/src/share/shared-write.ts` (structured write-body, role `0x04` child-writekey). Delete `addShareKeys`/`reWrapForRecipients` from `packages/sdk/src/`. Rewrite `packages/sdk/src/bin/index.ts` (restore as pure re-link; delete re-encrypt path). Rewrite invite claim (`packages/sdk/src/share/invite.ts` or equivalent).

**Why fourth:** `packages/sdk` wraps `sdk-core` and adds state + sharing semantics. The share + bin + invite rewrites all depend on `Node` types (Phase 2) and the rotation driver (Phase 3).

**Dependency:** Phase 3.

### Phase 5 — `apps/api`: Schema + Publish Gate + Tombstone + Atomic CAS

**Files changed:**

- **TypeORM migration:** Delete `share_keys` table + entity (`apps/api/src/shares/entities/share-key.entity.ts`). Slim `shares` entity: add `readDescriptorRef`/`writeDescriptorRef`/`rootNodeId`/`rootIpnsName`/`rootGeneration`, remove old per-item key columns. Rename `folder_ipns` → `ipns_records` (entity class, table name, all repository references). Drop `folder_ipns.public_key` column. Collapse `ipns_republish_schedule` duplicated columns into `ipns_records` (or fold the schedule table).
- **`apps/api/src/ipns/ipns.service.ts`:** Atomic publish CAS (`UPDATE … WHERE sequenceNumber = :expected`); server-side generation forward-only gate; tombstone state check before key-possession gate at line 226; `parseCachedRecord`-null case-split (shared-folder null is expected → apply seq floor; `signedRecord` CID≠`latestCid` mismatch → fail closed). Fix TEE republish to use `ipns_records` as sole source (not schedule snapshot).
- **`apps/api/src/republish/republish.service.ts:257`:** `unenrollIpns` must tombstone `ipns_records` row, not only delete the schedule row.
- **`apps/api/src/shares/entities/share-invite.entity.ts`:** Remove `encryptedChildKeys` JSONB column; add `readDescriptorRef` for the single root-key wrap.
- **Run `pnpm api:generate`** and commit the regenerated `packages/api-client/src/generated/` alongside these changes (pre-commit `scripts/check-api-client.sh` enforces this).

**Why fifth:** API schema changes unblock TEE worker (which references `ipns_records`) and web/FUSE (which call the new API shape). The atomic CAS must land before any rotation work exercises the publish path. The `check-api-client.sh` pre-commit hook will reject a commit that changes API endpoints without also regenerating the client.

**Dependency:** Phase 2 (entity types reference `Node` schema shape conceptually; the migration itself is independent but must not reference deleted types).

### Phase 6 — `apps/tee-worker`: Lease-Renewer Contract Rewrite

**Files changed:** `apps/tee-worker/src/routes/republish.ts` — replace line 79 `+ 1n` increment with re-sign-same-sequence logic; add signature verification of incoming marshaled record; add internal epoch derivation (remove relay-supplied epoch scalar trust); add name↔key binding assertion (`publicKeyFromIpnsName(ipnsName) == pubkey(decryptedKey)`); add tombstone check (reject renewal of tombstoned name).

**Why sixth:** Depends on Phase 5 (`ipns_records` as sole source, tombstone column existing). The TEE republish round-trip E2E (`tests/sdk-e2e` or staging smoke) gates this phase.

**Dependency:** Phase 5 (DB schema; sole-source contract).

### Phase 7 — `apps/web`: Replace Lazy Rotation, Add High-Water, folderTree Reconcile

**Files changed:** `apps/web/src/services/share.service.ts` — replace `executeLazyRotation` (line 602) with `rotateReadFromNode` driver call; delete `addShareKeys` (line 337) and `reWrapForRecipients` (line 469) from per-mutation fan-out paths. Add durable M1 generation high-water to IndexedDB (alongside existing device identity store at `apps/web/src/lib/device/identity.ts`). Add durable seq high-water. Add generation-regression check in IPNS resolve path. Enforce `folderTree` reconcile before rotation publishes (existing reconcile-before-publish discipline at `#489`/`#494`).

**Why seventh:** Web consumes the API (Phase 5) and sdk-core (Phase 3). The generation high-water is web-specific durable state (IndexedDB). The folderTree desync pattern is pre-existing risk — the M1 generation check must compose with the existing `sequenceNumber` reconcile-before-publish discipline, not replace it.

**Dependency:** Phase 3 (rotation driver), Phase 5 (API shape).

### Phase 8 — `crates/fuse`: Rust Integration (FUSE + WinFsp)

**Files changed:**

- Replace all `cipherbox_crypto::ecies::unwrap_key` calls in `crates/fuse/src/inode.rs:434,452,658,716` and `crates/fuse/src/replay.rs:365` with `cipherbox_crypto::aes::unseal_aes_gcm_aad` symmetric unwrap.
- Delete `spawn_file_meta_reencrypt` from `crates/fuse/src/metadata.rs:777` and remove both call sites: `crates/fuse/src/write_ops/implementation/rename.rs:248` and `crates/fuse/src/platform/windows/write_ops.rs:1183`.
- Add grant-root awareness to `delete`/`rename`/`move` paths — FUSE already holds the mounted tree, so ancestry is cheap.
- Add durable generation + seq high-water (adjacent to existing write journal in `crates/fuse/src/cache.rs` or `journal_helpers.rs`).
- Replace `crates/core/src/` Rust types: `Node` as a real Rust enum (`enum Node { Folder { children: Vec<SealedChildRef> }, File { content: SealedContent }, Root { children: Vec<SealedChildRef> } }`), not a struct with `Option` fields.
- Add `crates/crypto/src/aes/` Rust twin of `buildNodeAad` + `sealAesGcmAad`/`unsealAesGcmAad`.
- Add `rotateReadFromNode` to `crates/fuse/src/` rotation paths.
- Strict-verify each rotation republish through the verified chokepoint, recovering Ed25519 pubkey from the k51 name via `publicKeyFromIpnsName` (never from the now-dropped `public_key` column).

**Why eighth:** All prior layers must land first. The FUSE crate is the most complex consumer — it implements both macOS/Linux FUSE and Windows WinFsp, it has the widest ECIES-to-symmetric conversion surface, and it needs grant-root awareness which is net-new logic that builds on the finalized `Node` schema (Phase 2) and the rotation engine (Phase 3).

**Critical:** `crates/fuse/src/platform/windows/write_ops.rs` and anything under `crates/fuse/src/platform/windows/` cannot compile on macOS. The `Cargo Check & Test (Windows)` CI gate is authoritative for this phase. Budget a CI round-trip. The `super::` vs `super::super::` nesting trap (from Phase 55 history) applies in the nested `pub mod implementation` structure; verify path imports in the Windows module explicitly.

**Dependency:** Phases 1–7 (consumes all new types, all new API endpoints, all new crypto primitives).

## 6. Cross-Cutting Integration Concerns

### 6.1 TS↔Rust Parity Surface (AAD bytes)

The `buildNodeAad` byte encoding is the only cross-language contract that fails silently. One KAT fixture — a hardcoded `(nodeId, kind, generation, role) → aad_bytes` vector — must be asserted by:

- `packages/crypto/__tests__/build-node-aad.test.ts`
- `crates/crypto/tests/cross_language.rs` (Rust `#[test]`)

Both must pass before any consumer is written. The fixture must include role `0x04` (child-writekey).

### 6.2 Triplication Surface: web / sdk-core / FUSE+WinFsp

Three independent consumers must implement byte-identical AAD handling:

| Consumer | Language | Durable state location | Rotation host |
| -------- | -------- | ---------------------- | ------------- |
| `apps/web` | TypeScript (Web Crypto) | IndexedDB | Client browser (long-lived tab) |
| `packages/sdk-core` | TypeScript | Caller-provided (web: IndexedDB; FUSE: journal) | Shared library |
| `crates/fuse` | Rust | FUSE write journal / adjacent sqlite-like store | Desktop process (preferred — long-lived, `PublishCoordinator`) |

The `packages/sdk-core` rotation driver (`rotateReadFromNode`) is shared between web and FUSE (the Rust `crates/sdk` wraps `sdk-core`). The durable high-water state is caller-provided; each consumer wires its own storage backend (IndexedDB or Rust journal). The convergence test and frontier representation are identical regardless of host.

### 6.3 folderTree Reconcile-Before-Publish Discipline

Existing project memory: `folderTree` in Zustand `useFolderStore` and the SDK client's `folderTree` can desync (the `#489`/`#494` "Folder not loaded" class). Under v3, this matters more: a wrong "don't rotate" (because the tree appeared to show no covering grant) is a silent missed revocation. The rule is:

> Before any rotation publishes, reconcile `folderTree` against the current `sequenceNumber`. If the tree cannot be reconciled, **defer** the mutation — never skip rotation.

This is an extension of the existing discipline, not a replacement. The web `rotateReadFromNode` call site in `share.service.ts` must check reconciliation status before starting the walk.

### 6.4 Durable Client State: What Persists Where

| State | Web | FUSE/Desktop |
| ----- | --- | ------------ |
| `{nodeId → highestGeneration}` (M1 high-water) | IndexedDB (new store, alongside device identity in `apps/web/src/lib/device/identity.ts`) | FUSE write journal or adjacent key-value file |
| `{nodeId → highestSeq}` (within-generation floor) | IndexedDB | FUSE journal |
| Rotation job record (`jobId`, `rootNodeId`, `frontier[]`, `done[]`, `status`) | IndexedDB | FUSE durable state |

The published IPNS records (not the job record) are the source of truth for convergence. The job record is advisory — it makes resume fast but losing it triggers a `verifySubtreeClean` rescan.

### 6.5 API Client Regeneration Gate

The pre-commit hook `scripts/check-api-client.sh` enforces that `packages/api-client/src/generated/` is staged whenever `apps/api/src/` changes. Phase 5 (api) triggers this. Run `pnpm api:generate` after every API endpoint/DTO/controller change and commit the regenerated files on the same branch. Failing to do so blocks the CI pre-commit.

### 6.6 Sequence Race Residual

The atomic CAS (`UPDATE ipns_records … WHERE sequenceNumber = :expected`) is the primary serialization point. It is not a full distributed lock — two co-writers at different clients can still race. The `PublishCoordinator.get_lock(name)` in `crates/fuse/src/metadata.rs:342` serializes the job against the same client's concurrent writes. The CAS turns a silent clobber into a `409 → refetch → retry` loop. This residual is accepted per the design.

## 7. Symbol Drift Report (Design vs Live Code)

All design-cited symbols verified. No drift found in file paths. Line number accuracy verified for material symbols:

| Design Citation | Verified |
| --------------- | -------- |
| `executeLazyRotation` at `apps/web/src/services/share.service.ts:602` | Line 602 confirmed |
| `revokeShare` keeping `ShareKey` rows "for lazy rotation" at `shares.service.ts:256-269` | Line 256 comment "kept for lazy rotation" confirmed |
| `addShareKeys` at `share.service.ts:337`, `reWrapForRecipients` at `:469` | Lines 337 and 469 confirmed |
| `ipns.service.ts:226` — "no ownership/share check" comment | Confirmed: comment at line 226 |
| `shared-write.ts:138-141,311` ECIES-wraps Ed25519 key | `ipnsPrivateKeyEncrypted` is hex-wrapped at line 137; `ipnsPrivateKey` at 277/303/361/392 — confirmed |
| `spawn_file_meta_reencrypt` at `crates/fuse/src/metadata.rs:777` | Line 777 confirmed |
| Callers: `rename.rs:248` and `platform/windows/write_ops.rs:1183` | Lines 248 and 1183 confirmed |
| `inode.rs:434,452` ECIES unwrap folder key / IPNS key | Lines 434 and 452 confirmed |
| `inode.rs:658,716` additional ECIES unwrap calls | Lines 658 and 716 confirmed |
| `replay.rs:365` ECIES unwrap | Line 365 confirmed |
| `folder_ipns.public_key` nullable `Buffer \| null` at `folder-ipns.entity.ts:63-64` | Confirmed |
| `republish-schedule.entity.ts:39-60` duplicated columns | `encryptedIpnsKey:40`, `keyEpoch:47`, `latestCid:53`, `sequenceNumber:60` confirmed |
| `republish.service.ts:257` `unenrollIpns` only deletes schedule row | Line 257 `scheduleRepository.delete` confirmed — no tombstone |
| `apps/tee-worker/src/routes/republish.ts:79` does `+ 1n` | Line 79 `+ 1n` confirmed |
| `tee.service.ts:110` batch republish | Line 110 `async republish` confirmed |
| `packages/core/src/ipns/create-record.ts` client self-signs | `createIpnsRecord` at line 31 confirmed |
| `publish.rs:140` `resolve_sequence_strict` — sequence only, no generation | Line 140 confirmed; `verified.sequence_number` only, no generation field |
| `share-invite.entity.ts` `encryptedChildKeys` JSONB column | Line 59 confirmed |
| `originalFolderKeyEncrypted` in bin types and re-encrypt path | `packages/core/src/bin/types.ts:69` + `packages/sdk/src/bin/index.ts:497,688` confirmed |

One notation note: the design cites `packages/core/src/file/metadata.ts:232` for `decryptFileMetadata` taking parent `folderKey`. The actual file has `decryptFileMetadata` at approximately line 231 (the comment "32-byte AES key of the parent folder" at line 227 confirms the semantic). Off by one from line 232; not material.

## 8. Phase Seam Recommendations for the Roadmap

The 8-phase build order above maps directly to natural milestone phases. Suggested seaming:

1. **Crypto primitive** (Phase 1) — shippable independently; no consumer breaks; KAT is the merge gate.
2. **Core keystone** (Phase 2) — nothing typechecks below until done; must rebuild `dist/` before proceeding.
3. **sdk-core rotation engine** (Phase 3) — rotation tests (`verifySubtreeClean`, crash-safety suite) gate this phase.
4. **sdk write/bin/invite** (Phase 4) — sdk E2E is the gate; the only real client→API IPNS publish/resolve round-trip.
5. **API schema + publish gate** (Phase 5) — DB migration + atomic CAS + tombstone + `api:generate`. All downstream consumers blocked until this lands.
6. **TEE worker** (Phase 6) — lease-renewer contract; republish E2E or staging smoke gate.
7. **Web** (Phase 7) — rotation UX + M1 high-water + reconcile discipline; Playwright E2E gates.
8. **FUSE + WinFsp** (Phase 8) — widest blast radius; Windows CI round-trip mandatory; grant-root awareness is net-new logic.

Phases that likely need deeper sub-phase research: Phase 8 (FUSE/WinFsp grant-root scope computation is novel; the Windows path can only be CI-verified). Phase 5 (TypeORM migration for `folder_ipns → ipns_records` rename with active FK references from `ipns_republish_schedule`, `shares`, `vaults` tables — verify all FK constraints before the migration).

## 9. Accepted Residuals (Not Fixed By This Refactor)

Per ADR 0002: already-distributed CIDs and prior file versions remain readable by anyone who held the `readKey`. The `contentRekeyPending` marker and optional per-file "re-encrypt now" operation are the high-sensitivity mitigation path.

Per ADR 0001 and design Section 9.2 open question 3: when a write-recipient (C) deletes a node that the owner independently sub-shared to a third party (D), C can unlink immediately but cannot revoke D's grant — the authority is split. Resolution (accept option (a) or (c) from the design) deferred to the implementing phase.

The colluding-relay residual: a malicious relay that drops rotation publishes and serves stale records is bounded by the durable client generation + seq high-water floors (M1 + Section 6.5), not eliminated. This is the explicit systemic residual.

## Sources

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — design source of truth (Sections 2–7)
- `.planning/design/2026-06-26-sharing-flows-walkthrough.md` — flow-by-flow trace (Flows 1–8)
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation rationale
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — read-revocation scope
- `CONTEXT.md` — pinned terminology
- `docs/ARCHITECTURE.md` — existing system overview
- `docs/METADATA_SCHEMAS.md` v1.1 — schemas being replaced
- Live codebase grep verification (all cited symbols confirmed as described above)
