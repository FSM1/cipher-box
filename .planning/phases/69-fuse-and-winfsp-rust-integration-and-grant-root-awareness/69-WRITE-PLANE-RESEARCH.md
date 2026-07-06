# Phase 69: P1a — Node-v3 Write-Plane Emit API + Read Adapter — Research

**Researched:** 2026-07-06
**Domain:** Rust `crates/core`/`crates/sdk` — the ADDITIVE write-plane emit API + real `NodeFetcher` read adapter the FUSE cutover (P1b / 69-09) consumes
**Confidence:** HIGH (every claim grounded in live `Read`/`grep` of the current tree + `git show` of the 68.x web mirror)

## Summary

The 69-FUSE-CUTOVER-RESEARCH design for P1b (the atomic Unix cutover, 69-09) assumes two pieces of
infrastructure already exist that in fact **do not**: (1) a callable Node write-plane **emit/publish API**
the FUSE write path (`mkdir`/`upload`/`delete`/`rename`) can call to mint keys, seal a fresh `Node`, and
publish it; and (2) a **real `NodeFetcher`** bridging `cipherbox_api_client` into `crates/sdk::listing` so
`list_folder` is callable from the daemon. Live grep confirms the gap: `build_node`/`create_node`/
`publish_node` are grep-empty; every `PublishedNode` **producer** is either a listing/rotation **test
fixture** or `rotation/engine.rs`, which only **reseals EXISTING** nodes (`write_sealed: None` at every
producer site). The only `NodeFetcher` impl is the test `FakeFetcher` (`listing.rs:414`). `crates/fuse`
never touches `crates/sdk::listing` — it does raw `resolve_ipns_verified` at ~7 sites.

The good news: the **read+seal LOGIC is complete and green**. `crates/core/src/node/{types,encode,decode,seal}`
ships the `Node` enum, `SealedChildRef`, `NodeContent`, the KAT-conformant read-body codec, and the
symmetric seal/unseal primitives (`seal_node`/`seal_child_read_key`/`seal_child_write_key`). `crates/sdk`
ships `list_folder`/`list_shared_folder` (gate-first), `RotationHighWater<S>`, `JsonSidecarFloorStore`, and
the rotation engine's `RotationDeps` publish-with-CAS seam. What is **missing** is the pure write-body
**emit** (`encode_write_body`, a both-bodies `seal_published_node`) in core, and the **stateful glue** in
sdk (a real `ApiNodeFetcher`, a `create_folder_node`/`create_file_node` emit orchestration, parent-relink
`SealedChildRef`+`WriteChildRef` builders, and a `RotationHighWater` factory).

**Primary recommendation:** Land P1a as **two additive, independently-green plans** — **69-15** (`crates/core`
pure write-body emit primitives) then **69-16** (`crates/sdk` real fetcher adapter + write-emit orchestration).
Both are strictly additive: legacy `crates/core::folder` types stay, `crates/fuse` is not touched, and
`cargo check --workspace` is green at each plan boundary. Then **69-09 (P1b) gains `depends_on: [69-15, 69-16]`**.
Critically, design the core emit so it takes `NodeWriteBody` as an **explicit parameter** rather than adding a
`write_body` field to the `Node` enum — that keeps the blast radius to new functions only (a field-add would
force-recompile every `Node::{Folder,File,Root}` construction across `encode.rs`/`decode.rs`/`engine.rs`/
`listing.rs`, needlessly widening the plan).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|--------------|----------------|-----------|
| Encode write-body (`ipnsPrivateKey` + `writeChildren`) to wire bytes | `crates/core` (pure) | — | Deterministic codec, no IO; twin of `encodeWriteBody` |
| Seal both bodies → `PublishedNode{readSealed, writeSealed}` | `crates/core` (pure) | — | Composes Phase-61 AES-GCM-AAD; no IO; D-02 pure tier |
| Mint readKey/writeKey/Ed25519 keypair for a fresh node | `crates/sdk` (stateful) | `crates/crypto` | Key generation + terminal-owner lifecycle; D-02 stateful tier |
| Upload sealed envelope + publish IPNS (seq=1 / CAS) | `crates/sdk` (stateful) | `crates/api-client` | Network IO; reuses `ipfs::upload_content` + `ipns::publish_ipns` |
| Build parent-relink `SealedChildRef` (read plane, keyed by ipnsName) | `crates/sdk` (stateful) | `crates/core` seal | D-07 read-plane link |
| Build parent-relink `WriteChildRef` (write plane, keyed by childId UUID) | `crates/sdk` (stateful) | `crates/core` seal | D-07 write-plane link |
| Real `NodeFetcher` (resolve+fetch) for `list_folder` | `crates/sdk` (stateful) | `crates/api-client` | Bridges `resolve_ipns_verified`+`fetch_content` into the gated read chain |
| `RotationHighWater<JsonSidecarFloorStore>` construction | `crates/sdk` (stateful) | daemon supplies path | Anti-rollback gate wiring; store injected by FUSE (P1b) |
| FUSE call-site cutover (consume emit + adapter) | `crates/fuse` | — | **DEFERRED to P1b / 69-09** — not in P1a |

## Standard Stack

No external packages are introduced by P1a. Every dependency is already in the workspace and already used
by the crates in scope. Verified via `Cargo.toml` + live `use` sites:

| Crate | Role in P1a | Already present | Evidence |
|-------|-------------|-----------------|----------|
| `cipherbox-crypto` | AES-256-GCM-AAD seal, Ed25519 keygen, `derive_ipns_name`, ECIES (TEE wrap only) | ✓ | `crates/core/src/node/seal.rs:22`, `crates/core/src/ipns.rs:20` |
| `cipherbox-core` | `Node`, `PublishedNode`, `encode_node`, `create_ipns_record`, `marshal_ipns_record` | ✓ | `crates/core/src/node/*`, `crates/core/src/ipns.rs:275` |
| `cipherbox-api-client` | `ipfs::upload_content`, `ipns::publish_ipns`, `ipns::resolve_ipns_verified`, `ipfs::fetch_content` | ✓ (sdk already depends) | `crates/sdk/Cargo.toml:10`, `crates/sdk/src/registry.rs:124,153,177,186` |
| `zeroize` | terminal-owner key lifecycle (`Zeroizing`) | ✓ | `crates/sdk/src/listing.rs:33` |
| `base64`, `serde`, `serde_json`, `thiserror` | wire codec + errors | ✓ | throughout `node/*` |

**Installation:** none — P1a adds functions/modules to existing crates. No `cargo add`.

## Package Legitimacy Audit

**Not applicable — P1a installs no external packages.** All dependencies are first-party workspace crates
already declared in `Cargo.toml`. No registry lookup required.

## Gap Inventory — Missing vs. Present

### Present and reusable (do NOT rebuild)

| Symbol | Location | Notes |
|--------|----------|-------|
| `Node` enum (Folder/File/Root), `NodeKind`, `NodeContent`, `VersionEntry` | `crates/core/src/node/types.rs` | In-memory model. **No `write_body` field** (unlike web `Node.writeBody?`). |
| `SealedChildRef` (frozen NODE-03 5-field), `WriteChildRef`, `NodeWriteBody` | `crates/core/src/node/types.rs:99,121,136` | `WriteChildRef{child_id, write_key_sealed}` and `NodeWriteBody{ipns_private_key, write_children}` **exist** (69-01) but are **never sealed/encoded/emitted** yet. |
| `PublishedNode{schema,kind,id,generation,aead_version,read_sealed, write_sealed: Option}` | `crates/core/src/node/types.rs:215` | `write_sealed` field **exists** but **no producer populates it** (all set `None`). |
| `encode_node` (read-body), `decode_node`, `encode_published_node`, `decode_published_node` | `crates/core/src/node/{encode,decode}.rs` | Read-body codec only. **No `encode_write_body`.** |
| `seal_node`/`unseal_node` (role 0x01, read-body only), `seal_child_read_key`/`unseal_child_read_key` (0x02), `seal_child_write_key`/`unseal_child_write_key` (0x04) | `crates/core/src/node/seal.rs` | Child-writekey seal **exists**. **`seal_node` seals ONLY the read-body** — no write-body seal path (web `sealNode` seals both). |
| `list_folder`/`list_shared_folder`, `resolve_published_node` (pub(crate)), `NodeFetcher` trait, `FetchedRecord`, `ResolvedChild`, `FolderUpdatedEvent` | `crates/sdk/src/listing.rs` | Gated read chain complete. Only `NodeFetcher` impl is test `FakeFetcher` (`:414`). |
| `RotationHighWater<S>::new(gen_store, seq_store)`, `enforce_resolved`, `get_generation_floor`, `HighWaterStore` trait | `crates/sdk/src/rotation/high_water.rs` | Anti-rollback gate. |
| `JsonSidecarFloorStore` | `crates/sdk/src/floor_store.rs` (exported `lib.rs:19`) | Concrete durable store for the daemon. |
| `RotationDeps` (resolve/fetch_node/`publish_with_cas`/persist_job), `seal_and_publish`, `rotate_read_from_node`, `PublishAttempt::{Published,Conflict}` | `crates/sdk/src/rotation/engine.rs` | CAS publish seam + rotation walk. Reseals existing nodes only. |
| `ipfs::upload_content`/`fetch_content`, `ipns::publish_ipns` (Success/Conflict), `ipns::resolve_ipns_verified` (`VerifiedResolve{cid,sequence_number}`), `IpnsPublishRequest` | `crates/api-client/src/{ipfs,ipns,types}.rs` | Raw publish/resolve primitives + first-publish TEE fields. |
| `core::ipns::create_ipns_record` + `marshal_ipns_record` + `derive_ipns_name` | `crates/core/src/ipns.rs:275,321,20` | Signed-record construction (the `record` field of `IpnsPublishRequest`). |
| `registry.rs` publish idiom (upload → build `IpnsPublishRequest` → `publish_ipns`) | `crates/sdk/src/registry.rs:124-158` | Reference for the emit publish path. |

### Missing — `crates/core` (PURE emit; 69-15)

| Missing symbol | Shape | Web twin |
|----------------|-------|----------|
| `encode_write_body(wb: &NodeWriteBody) -> Result<Vec<u8>, NodeError>` | Serialize `{ ipnsPrivateKey(base64), writeChildren:[{childId, writeKeySealed}] }` with FIXED field order | `encode.ts:166 encodeWriteBody` |
| `seal_published_node(node: &Node, read_key: &[u8;32], write_key: &[u8;32], write_body: Option<&NodeWriteBody>) -> Result<PublishedNode, NodeError>` | Compose `encode_node`+`seal_node` (read-body, 0x01/readKey) AND, when `write_body` is `Some`, `encode_write_body`+seal (write-body, 0x01/writeKey) → populate `read_sealed`+`write_sealed` | `seal.ts:96 sealNode(node, readKey, writeKey)` |

> **Design note (blast-radius):** Pass `NodeWriteBody` as an **explicit parameter** — do NOT add a
> `write_body` field to the `Node` enum. A field-add forces recompile of every exhaustive `Node::{Folder,
> File,Root}` construction (`encode.rs:51/66/81`, `decode.rs:69/84/92`, `engine.rs:1331…1944`, `listing.rs:
> 341/470/493`), widening the plan for no read-path benefit (the read chain never needs `write_body`). The
> explicit-param design keeps 69-15 to **new functions only** and leaves the frozen read-body KAT
> (`node-codec.json`) byte-identical (write-body is a separate wire, so read-body output is unchanged).

### Missing — `crates/sdk` (STATEFUL emit + adapter; 69-16)

| Missing symbol | Shape | Web twin |
|----------------|-------|----------|
| `ApiNodeFetcher` (impl `NodeFetcher`) | Wraps `&ApiClient`; `fetch(ipns_name)` = `resolve_ipns_verified` → `fetch_content(cid)` → `FetchedRecord{sequence_number, bytes}` | the production `NodeFetcher` seam (`listing.rs:50` doc) |
| `create_folder_node(...) -> FreshNode` | Mint Ed25519 keypair + readKey + writeKey; `derive_ipns_name`; build empty folder `Node` (gen 0); `seal_published_node(Some(write_body))`; upload; publish IPNS **seq=1** (embed `encryptedIpnsPrivateKey`+`keyEpoch` when TEE-enrolled); return `{node, ipns_name, ipns_private_key(raw), read_key(raw), write_key(raw)}` | `folder/registration.ts:46 createSubfolder` |
| `create_file_node(...) -> FreshFileNode` | Mint keys; build file `Node` with `NodeContent`; seal both bodies; upload; **build (not publish) or publish** the file IPNS record (mirror the batch contract); return keys raw | `file/index.ts createFileMetadata` |
| `build_child_refs(child_read_key, child_write_key, parent_read_key, parent_write_key, child_id, ipns_name, kind, generation, version_floor) -> (SealedChildRef, WriteChildRef)` | D-07 dual link: `SealedChildRef{name, ipns_name, generation, version_floor, read_key_sealed=seal_child_read_key(...)}` AND `WriteChildRef{child_id, write_key_sealed=seal_child_write_key(...)}` | `updateFolderMetadataAndPublish` child assembly |
| `update_folder_and_publish(...)` (or reuse `RotationDeps`) | Reseal parent Node with new `children` (+ write-body `write_children`) and CAS-publish (409 → refetch/merge) | `folder/registration.ts updateFolderMetadataAndPublish` |
| `new_high_water(gen_store, seq_store)` factory / or a `RotationHighWater<JsonSidecarFloorStore>` constructor helper the daemon calls | Thin — likely just document `RotationHighWater::new(JsonSidecarFloorStore::…, …)` for P1b to call | 68.2 `client.ts` `RotationHighWater` wiring |

## Architecture Patterns

### System Architecture Diagram

```
                          P1a additive surface (does NOT touch crates/fuse)
┌──────────────────────────────── crates/core (PURE, 69-15) ────────────────────────────────┐
│  Node ──encode_node──► read-body bytes ──seal_node(0x01,readKey)──┐                         │
│  NodeWriteBody ──encode_write_body──► write-body bytes ──seal(0x01,writeKey)──┐            │
│                                                                    ▼          ▼            │
│                                            seal_published_node ──► PublishedNode{          │
│                                                                     read_sealed,           │
│                                                                     write_sealed }         │
└───────────────────────────────────────────────┬───────────────────────────────────────────┘
                                                 │ (pure, no IO)
┌──────────────────────────── crates/sdk (STATEFUL IO, 69-16) ───────────────────────────────┐
│  WRITE-EMIT:  create_folder_node / create_file_node                                         │
│     mint Ed25519+readKey+writeKey ─► seal_published_node ─► ipfs::upload_content            │
│         ─► core::create_ipns_record(seq=1) ─► ipns::publish_ipns  (embed TEE-wrapped key)   │
│     build_child_refs ─► (SealedChildRef[ipnsName], WriteChildRef[childId])  ── D-07 dual    │
│                                                                                             │
│  READ-ADAPTER:  ApiNodeFetcher(&ApiClient): resolve_ipns_verified ─► ipfs::fetch_content    │
│         ─► FetchedRecord ─► [existing] list_folder(fetcher, RotationHighWater, key)          │
│                                     └─ RotationHighWater<JsonSidecarFloorStore> (gate)       │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                                 │ consumed by
                                                 ▼
                         crates/fuse  ── DEFERRED to P1b / 69-09 (atomic cutover) ──
```

### Pattern 1: Explicit-write-body emit (avoid the Node field-add)

**What:** `seal_published_node` takes `write_body: Option<&NodeWriteBody>` rather than reading it off the
node. **When:** all P1a emit. **Why:** zero blast radius on existing `Node` constructions; read-body KAT
stays byte-identical.

```rust
// Source: mirror of packages/core/src/node/seal.ts sealNode (git show origin/feat/...:packages/core/src/node/seal.ts)
pub fn seal_published_node(
    node: &Node,
    read_key: &[u8; 32],
    write_key: &[u8; 32],
    write_body: Option<&NodeWriteBody>,
) -> Result<PublishedNode, NodeError> {
    let read_body = encode_node(node)?;
    let read_sealed = seal_node(&read_body, read_key, node.id(), node.kind(), node.generation())?;
    let write_sealed = match write_body {
        Some(wb) => {
            let wb_bytes = encode_write_body(wb)?;
            Some(base64(seal_aes_gcm_aad(&wb_bytes, write_key, &body_aad(node))?)) // role 0x01, writeKey
        }
        None => None,
    };
    Ok(PublishedNode { schema: "node/v3".into(), kind: node.kind().as_str().into(),
        id: node.id().into(), generation: node.generation(), aead_version: 1,
        read_sealed: base64(read_sealed), write_sealed })
}
```

### Pattern 2: First-publish embeds sequence 1 + TEE-wrapped key

**What:** `create_*_node` publishes with `sequenceNumber = 1` and, when TEE-enrolled, the ECIES-wrapped
`ipnsPrivateKey` + `keyEpoch`. **Why:** the strict IPNS gate rejects a first publish with seq≠1 (project
memory: *Every first IPNS publish must embed sequence 1*), and TEE republish needs the wrapped key
(CLAUDE.md rule #7).

### Pattern 3: Real fetcher wraps the D-08 verified chokepoint

```rust
// Source: listing.rs:50 doc contract + registry.rs:177-186 idiom
struct ApiNodeFetcher<'a> { api: &'a ApiClient }
impl NodeFetcher for ApiNodeFetcher<'_> {
    async fn fetch(&self, ipns_name: &str) -> Result<FetchedRecord, ListingError> {
        let v = resolve_ipns_verified(self.api, ipns_name).await.map_err(/* -> FetchFailed */)?;
        let bytes = fetch_content(self.api, &v.cid).await.map_err(/* -> FetchFailed */)?;
        Ok(FetchedRecord { sequence_number: v.sequence_number, bytes })
    }
}
```

### Anti-Patterns to Avoid

- **Adding `write_body` to the `Node` enum in P1a.** Widens the plan (recompiles all Node constructions) for
  no read benefit. Use the explicit parameter.
- **Conflating childId and ipnsName** (D-07). The emit API must produce BOTH a `WriteChildRef{child_id: UUID}`
  and a `SealedChildRef{ipns_name}` and never substitute one for the other.
- **Introducing a competing publish trait.** For CAS updates, reuse the rotation engine's
  `RotationDeps::publish_with_cas` seam (or the `registry.rs` direct idiom for a first publish); do not add a
  third publish abstraction.
- **Zeroing minted keys inside the emit fn.** Return `read_key`/`write_key`/`ipns_private_key` RAW; the caller
  is the terminal owner (D-09, mirror `createSubfolder`).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AEAD seal of bodies/keys | new AES-GCM wrapper | `cipherbox_crypto::aes::seal_aes_gcm_aad` + `build_node_aad` (Phase 61) | KAT-tested; ADR-0003 role bytes frozen |
| Signed IPNS record bytes | new protobuf marshaller | `core::ipns::create_ipns_record` + `marshal_ipns_record` | Already libp2p-conformant |
| k51 name derivation | new multihash logic | `cipherbox_crypto::derive_ipns_name` | Shared with resolve path |
| Verified resolve + fetch | new resolve chain in the adapter | `api_client::ipns::resolve_ipns_verified` + `ipfs::fetch_content` | D-08 chokepoint; signature+CBOR binding already enforced |
| CAS publish retry/merge | new conflict loop | `rotation::engine::seal_and_publish` / `RotationDeps::publish_with_cas` | HIGH-4 merge already implemented |
| Durable floor persistence | new sidecar writer | `JsonSidecarFloorStore` | Atomic-write sidecar already shipped |

**Key insight:** P1a is 90% **composition** of already-green primitives. The only genuinely new crypto surface
is `encode_write_body` + the write-body arm of `seal_published_node` — both are thin twins of shipped web code.

## Runtime State Inventory

Not a rename/refactor phase. P1a is **purely additive greenfield code** (new functions/modules). No stored
data, live-service config, OS-registered state, secrets/env, or build artifacts are renamed or migrated.

- **Stored data:** None — no datastore keys change.
- **Live service config:** None.
- **OS-registered state:** None.
- **Secrets/env vars:** None — TEE wrap uses the existing `teePublicKey`/`keyEpoch` inputs unchanged.
- **Build artifacts:** None — no package/crate is renamed.

## Common Pitfalls

### Pitfall 1: Splitting core/sdk such that the field-add straddles both plans
**What goes wrong:** if 69-15 adds a `write_body` field to `Node`, `crates/sdk` (engine.rs/listing.rs
constructions) breaks in the SAME compile unit, so 69-15 can't be `cargo check --workspace` green without also
editing sdk — collapsing the clean core/sdk split.
**How to avoid:** explicit-parameter emit (Pattern 1). Then 69-15 touches only `crates/core/src/node/{seal,
encode,mod}.rs` and is workspace-green in isolation.
**Warning sign:** a planned `Node::Folder { …, write_body }` diff in `types.rs`.

### Pitfall 2: Emit publishes with seq≠1 or omits the TEE-wrapped key
**What goes wrong:** the strict first-publish gate 400s (seq must be 1); or the folder is un-enrollable for
TEE republish (missing `encryptedIpnsPrivateKey`).
**How to avoid:** mirror `createSubfolder` exactly — compute TEE fields BEFORE upload (fail-closed on
malformed `teeKeys`), publish `sequenceNumber = 1`.
**Warning sign:** no `key_epoch`/`encrypted_ipns_private_key` on the `IpnsPublishRequest`.

### Pitfall 3: Read-body KAT drift
**What goes wrong:** touching `encode_node` field order breaks `node-codec.json`.
**How to avoid:** `encode_write_body` is a SEPARATE function/wire; do not modify `encode_node`. Add write-body
golden coverage only if a write-body vector exists (see Open Questions).
**Warning sign:** a diff inside `FolderRootWire`/`FileWire`.

### Pitfall 4: Fetcher swallows the gate
**What goes wrong:** an adapter that decodes/validates bytes itself would bypass the single gated entrypoint.
**How to avoid:** `ApiNodeFetcher::fetch` returns RAW sealed `bytes` + `sequence_number` ONLY; all gating stays
in `resolve_published_node` (`enforce_resolved` runs before decode). Never decode in the fetcher.
**Warning sign:** `decode_published_node` inside the adapter.

### Pitfall 5: Zeroizing returned keys
**What goes wrong:** wiping `read_key`/`write_key`/`ipns_private_key` before returning corrupts the caller's
subsequent parent-relink seal.
**How to avoid:** terminal-owner rule — return raw; zero only intermediates the emit fn is itself the terminal
owner of (D-09; mirror `listing.rs:322` copy-then-wipe idiom for those).

## Code Examples

### Emit a fresh folder node (sdk, 69-16) — mirror of createSubfolder
```rust
// Source: git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:packages/sdk-core/src/folder/registration.ts:46
// 1. mint keys   2. derive ipns_name   3. build empty folder Node (gen 0)
// 4. TEE-wrap ipns_private_key (if teeKeys)  5. seal_published_node(node, rk, wk, Some(write_body))
// 6. ipfs::upload_content(envelope_json)     7. create_ipns_record(seq=1) + publish_ipns
// 8. return { node, ipns_name, ipns_private_key, read_key, write_key } RAW (D-09)
```

### Build the D-07 dual child links (sdk, 69-16)
```rust
// read plane (keyed by ipnsName)
let read_key_sealed = seal_child_read_key(&child_rk, &parent_rk, &child_id, kind, generation)?;
let sealed = SealedChildRef { name, ipns_name, generation, version_floor, read_key_sealed: b64(read_key_sealed) };
// write plane (keyed by childId UUID) — NEVER reuse ipns_name here
let write_key_sealed = seal_child_write_key(&child_wk, &parent_wk, &child_id, kind, generation)?;
let write = WriteChildRef { child_id, write_key_sealed: b64(write_key_sealed) };
```

## State of the Art

| Old (legacy Rust FUSE) | Current (node/v3 target) | Impact |
|------------------------|--------------------------|--------|
| `FolderMetadata`/`FilePointer` + ECIES child-key fan-out | `Node` + symmetric `SealedChildRef`/`WriteChildRef` | P1a supplies the emit side the cutover consumes |
| Write path builds `FolderMetadata` in `journal_helpers.rs:421` and ECIES-wraps keys (`:165`) | `create_folder_node`/`create_file_node` seal both bodies symmetric | replaced in P1b, enabled by P1a |
| Read path 7× raw `resolve_ipns_verified` | single `list_folder(ApiNodeFetcher, RotationHighWater, key)` | adapter (P1a) + call-site cutover (P1b) |

**Deprecated/outdated:** nothing removed in P1a. Legacy `crates/core::folder` deletion is P2 (69-10), post-cutover.

## Proposed P1a Plan Outline

> Two additive plans. New ids **69-15**, **69-16** (do NOT reuse 09–14). Both green at their own boundary;
> `crates/fuse` and legacy `crates/core::folder` types untouched.

### 69-15 — `crates/core` Node write-body emit primitives (PURE)
- **Objective:** Add the pure write-plane codec+seal so a caller can produce a `PublishedNode` carrying BOTH
  `read_sealed` and `write_sealed`. No IO, no `Node`-enum field change.
- **files_modified:** `crates/core/src/node/encode.rs` (add `encode_write_body`), `crates/core/src/node/seal.rs`
  (add `seal_published_node`), `crates/core/src/node/mod.rs` (re-export the two new fns).
- **depends_on:** foundation 69-01 (types), 69-04 (seal). No new deps.
- **green boundary:** `cargo check --workspace` + `cargo test -p cipherbox-core` (round-trip:
  `seal_published_node` → `decode_published_node`/`unseal_node` recovers read-body; write-body encode→decode
  round-trips; `write_sealed` is `None` when `write_body` is `None`; read-body KAT `node-codec.json` unchanged).
- **consumed by:** 69-16.
- **additive proof:** new functions only; existing `seal_node`/`encode_node`/`Node` unchanged; fuse & legacy
  `folder.rs` untouched.

### 69-16 — `crates/sdk` real fetcher adapter + write-emit orchestration (STATEFUL)
- **Objective:** Provide the callable emit API (`create_folder_node`/`create_file_node` + `build_child_refs`
  + a parent CAS-update path) and the real `ApiNodeFetcher`, plus document the
  `RotationHighWater<JsonSidecarFloorStore>` construction the daemon calls.
- **files_modified:** new `crates/sdk/src/fetcher.rs` (`ApiNodeFetcher`), new `crates/sdk/src/emit.rs`
  (`create_folder_node`/`create_file_node`/`build_child_refs`/update-and-publish), `crates/sdk/src/lib.rs`
  (module decls + re-exports). (Optionally fold `ApiNodeFetcher` into `listing.rs` behind the existing seam —
  planner's call.)
- **depends_on:** 69-15, foundation 69-06 (listing), 69-08 (rotation `RotationDeps`/`seal_and_publish`),
  `floor_store`/`high_water`. Reuses `cipherbox-api-client` (already a dep).
- **green boundary:** `cargo check --workspace` + `cargo test -p cipherbox-sdk` (emit→list round-trip via the
  EXISTING `FakeFetcher`: `create_folder_node` output fed back through `list_folder` yields the expected
  `ResolvedChild[]`; `create_file_node` yields a `Some(size)` child; D-07 assertion that `WriteChildRef.child_id`
  ≠ `SealedChildRef.ipns_name`; `ApiNodeFetcher` unit-tested against a mock/`httpmock` or a pure `bind_verified`
  shim — no live IPNS per project memory).
- **consumed by:** 69-09 (P1b).
- **additive proof:** new modules + re-exports only; `crates/fuse` untouched; no legacy type deleted.

### Downstream wiring change (REQUIRED)
- **69-09 (P1b) MUST gain `depends_on: [69-15, 69-16]`** (in addition to its existing foundation deps). Its
  `files_modified` write path (`journal_helpers.rs`, `write_ops/implementation/*`) calls the 69-16 emit API; its
  read path (`inode.rs`/`replay.rs`/`content_ops.rs`) is repointed onto `list_folder` via the 69-16
  `ApiNodeFetcher` + a `RotationHighWater<JsonSidecarFloorStore>`. Update the 69-FUSE-CUTOVER-RESEARCH §2.6 DAG
  so **Wave A (P1)** depends on this new **Wave A-pre (P1a = 69-15 → 69-16)**.

## Landmines

1. **Additive-not-invasive discipline (HARD).** P1a MUST NOT edit any file under `crates/fuse/`, and MUST NOT
   delete or repoint the legacy `crates/core::folder` `FolderMetadata`/`FileMetadata`/`FilePointer`/
   `FolderEntry` (that is P2 / 69-10). If a P1a diff touches fuse or deletes a legacy type, it has exceeded
   scope and will break the `cargo check --workspace` green-at-boundary guarantee (the `JournalOp` weld still
   names `FolderMetadata`).

2. **The `Node`-enum field temptation.** Do NOT add `write_body` to `Node` (Pitfall 1). Explicit-parameter emit
   keeps 69-15 pure-core and workspace-green in isolation.

3. **D-07 dual-keying — write plane keyed by `childId` (UUID), read plane by `ipnsName`.** `build_child_refs`
   must emit BOTH links and never conflate them (conflation silently breaks `rotateWriteFromNode`). The emit
   modules are within the `crates/fuse/src/write_ops/` security-review blast radius conceptually — flag the D-07
   assertion in the 69-16 tests so P1b inherits a proven invariant.

4. **Reuse the rotation publish seam, don't fork it.** For CAS parent updates, reuse
   `RotationDeps::publish_with_cas` / `seal_and_publish` (HIGH-4 merge already correct). For a fresh node's FIRST
   publish, mirror the `registry.rs` direct idiom with `sequenceNumber = 1`. Do not introduce a third publish
   abstraction.

5. **Zeroization terminal-owner rule for minted keys.** `create_folder_node`/`create_file_node` return
   `read_key`/`write_key`/`ipns_private_key` RAW (caller is terminal owner, D-09). Zero only intermediates the
   emit fn itself owns (e.g. a scratch buffer), mirroring `listing.rs:314-324`. A callee receiving caller-owned
   buffers (e.g. `build_child_refs` taking `&child_read_key`) must NOT zero them.

6. **Fetcher must stay dumb.** `ApiNodeFetcher::fetch` returns raw sealed bytes + verified sequence only; all
   gating/decoding stays in `resolve_published_node`. Decoding in the adapter would bypass `enforce_resolved`
   (the ROT-07 anti-rollback gate) — a fail-open regression.

## Validation Architecture

`nyquist_validation: true` — section included.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[cfg(test)]` + `cargo test` (async via `tokio::test`, as in `listing.rs`/`engine.rs`) |
| Config file | none — per-crate `Cargo.toml` `[dev-dependencies]` |
| Quick run command | `cargo test -p cipherbox-core` (69-15) / `cargo test -p cipherbox-sdk` (69-16) |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| Req | Behavior | Test Type | Automated Command | File Exists? |
|-----|----------|-----------|-------------------|-------------|
| P1a-core | `seal_published_node` populates both bodies; `write_sealed=None` when no write-body | unit | `cargo test -p cipherbox-core seal_published_node` | ❌ Wave 0 |
| P1a-core | `encode_write_body` round-trips; read-body KAT unchanged | unit | `cargo test -p cipherbox-core write_body` | ❌ Wave 0 |
| P1a-sdk | emit→list round-trip via `FakeFetcher` yields expected `ResolvedChild` | unit | `cargo test -p cipherbox-sdk emit` | ❌ Wave 0 |
| P1a-sdk | D-07: `WriteChildRef.child_id` ≠ `SealedChildRef.ipns_name` | unit | `cargo test -p cipherbox-sdk dual_key` | ❌ Wave 0 |
| P1a-sdk | `ApiNodeFetcher` maps verified resolve+fetch → `FetchedRecord` (mock/pure) | unit | `cargo test -p cipherbox-sdk fetcher` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** the crate-scoped quick run.
- **Per plan merge:** `cargo check --workspace` + `cargo test -p <crate>`.
- **Phase gate:** `cargo test --workspace` green before P1b starts.

### Wave 0 Gaps
- [ ] `crates/core/src/node/seal.rs` `#[cfg(test)]` — `seal_published_node` both-bodies + None cases.
- [ ] `crates/core/src/node/encode.rs` `#[cfg(test)]` — `encode_write_body` round-trip.
- [ ] `crates/sdk/src/emit.rs` `#[cfg(test)]` — emit→`list_folder` round-trip (reuse `FakeFetcher`), D-07 dual-key.
- [ ] `crates/sdk/src/fetcher.rs` `#[cfg(test)]` — `ApiNodeFetcher` mapping (no live IPNS — mock or `bind_verified` shim; project memory: GSD subagents must not run live integration tests).

## Security Domain

`security_enforcement` absent → treated as enabled. P1a is crypto-bearing (key minting + AEAD seal).

### Applicable ASVS Categories
| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V6 Cryptography | yes | Reuse `cipherbox_crypto` AES-256-GCM-AAD (`seal_aes_gcm_aad`) + Ed25519; **never hand-roll**; ECIES only for the TEE `ipnsPrivateKey` wrap (CLAUDE.md rule #7) |
| V5 Input Validation | yes | 32-byte key-length checks on unseal (already in `listing.rs:314`); fail-closed on malformed `teeKeys` before any upload |
| V2/V3/V4 (auth/session/access) | no | P1a is a client-side codec/emit layer; no new auth surface |

### Known Threat Patterns for the emit/read plane
| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Write-key leakage to disk/log | Information disclosure | Terminal-owner zeroization (D-09); never log key material (T-62-03) |
| childId/ipnsName conflation → write-plane clobber | Tampering | D-07 dual `WriteChildRef`/`SealedChildRef` assertion in tests |
| First-publish seq forgery / rollback | Tampering | seq=1 strict gate on publish; `enforce_resolved` on read (unchanged) |
| Un-enrolled folder (no TEE-wrapped key) | Denial of service (republish) | Fail-closed TEE-field computation before upload (mirror `createSubfolder`) |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `create_file_node` should **build-but-not-publish** the file record (batch-publish contract) rather than publish inline | Gap Inventory (sdk) | If the Rust FUSE path expects inline publish, the seam shape shifts; low risk — planner picks per the P1b call-site (verify against `journal_helpers.rs` batch contract at plan time) |
| A2 | No write-body golden KAT vector exists yet (only `node-codec.json` for read-body) | Pitfall 3 / Open Q | If a `writeSealed` vector exists in `tests/vectors/`, 69-15 should assert against it; grep confirmed only read-body `node-codec.json` present |
| A3 | `ApiNodeFetcher` can live in `crates/sdk` without a new dependency | Standard Stack | Verified: `crates/sdk` already depends on `cipherbox-api-client` (`Cargo.toml:10`) — no risk |

**These three `[ASSUMED]` items need planner/discuss confirmation before they become locked plan decisions.**

## Open Questions

1. **File-node publish timing (inline vs batch).**
   - Known: web `createFileMetadata` builds-but-does-not-publish (caller batch-publishes).
   - Unclear: whether the Rust FUSE `upload` path (P1b) wants inline publish or a batch payload.
   - Recommendation: expose `create_file_node` returning the ready-to-publish record AND a convenience
     inline-publish wrapper; let P1b choose. Confirm against `journal_helpers.rs` `build_upload_journal_entry`.

2. **Write-body KAT coverage.**
   - Known: `node-codec.json` covers the read-body only.
   - Unclear: whether a cross-language write-body/`writeSealed` vector is required for parity.
   - Recommendation: 69-15 asserts read-body KAT unchanged + a Rust-local write-body round-trip; flag a
     cross-language write-body vector as a follow-up if TS has one.

3. **`RotationHighWater` factory home.**
   - Known: `JsonSidecarFloorStore` + `RotationHighWater::new` exist; the daemon supplies the path.
   - Unclear: whether P1a should ship a typed factory or just document the constructor for P1b.
   - Recommendation: document + a thin `pub fn` helper; final wiring (path from journal sidecar dir) lands in
     P1b where the daemon owns the path.

## Sources

### Primary (HIGH confidence — live tree this session)
- `crates/core/src/node/{types,seal,encode,decode,mod}.rs` — Node model, seal roles, read-body codec; `write_sealed` field present but unpopulated.
- `crates/sdk/src/listing.rs` — `NodeFetcher` trait, `FakeFetcher` (only impl, `:414`), gate-first `resolve_published_node`, `list_folder`.
- `crates/sdk/src/rotation/engine.rs` — `RotationDeps`/`seal_and_publish` (reseals existing; `write_sealed: None` at `:668`).
- `crates/sdk/src/{lib.rs,floor_store.rs,rotation/high_water.rs}`, `crates/sdk/src/registry.rs:124-186` (publish idiom).
- `crates/api-client/src/{ipfs.rs,ipns.rs,types.rs}` — `upload_content`/`fetch_content`/`publish_ipns`/`resolve_ipns_verified`/`IpnsPublishRequest`.
- `crates/core/src/ipns.rs:275,321` — `create_ipns_record`/`marshal_ipns_record`.
- grep: `build_node`/`create_node`/`publish_node` empty; `PublishedNode` producers = tests + engine only; fuse has zero `listing`/`NodeFetcher` refs, 7× raw `resolve_ipns_verified`.

### Primary (HIGH confidence — 68.x web mirror via `git show`, D-01 access rule honored)
- `origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:packages/core/src/node/seal.ts` (`sealNode(node, readKey, writeKey)` seals both bodies), `.../encode.ts` (`encodeWriteBody`), `.../types.ts` (`Node.writeBody?`).
- `.../packages/sdk-core/src/folder/registration.ts` (`createSubfolder`, `updateFolderMetadataAndPublish`), `.../file/index.ts` (`createFileMetadata`, build-not-publish contract).

### Context
- `.planning/phases/69-.../69-FUSE-CUTOVER-RESEARCH.md` (the P1b design consuming this), `69-CONTEXT.md` (D-02/D-07/D-09).
- Project memory: first-publish-embeds-seq-1; write-plane keyed by UUID / read-plane by ipnsName; GSD subagents must not run live integration tests.

## Metadata

**Confidence breakdown:**
- Gap inventory (missing vs present): HIGH — direct grep + Read of every symbol.
- Emit API design: HIGH — thin twin of shipped web `createSubfolder`/`sealNode`; primitives all present.
- Read-adapter design: HIGH — `NodeFetcher` seam + verified-resolve chokepoint both exist; adapter is composition.
- Plan split + green boundaries: HIGH — feature/compile boundaries verified (sdk already deps api-client; explicit-param avoids Node blast radius).
- File-node publish timing + write-body KAT: MEDIUM — see Assumptions A1/A2.

**Research date:** 2026-07-06
**Valid until:** 14 days (in-flight milestone; re-verify grep line numbers if execution is delayed).
