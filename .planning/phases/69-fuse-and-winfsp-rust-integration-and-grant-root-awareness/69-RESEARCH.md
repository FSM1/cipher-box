# Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness - Research

**Researched:** 2026-07-06
**Domain:** Rust desktop client (FUSE/WinFsp) port of the TypeScript `node/v3` read chain, rotation engine, and grant-root scope computation
**Confidence:** HIGH for baseline/blast-radius facts (all grounded in live file:line reads + `git show`); MEDIUM for the rotation-engine port scope (large, not yet attempted in Rust); LOW/ASSUMED only where explicitly tagged (mostly Rust-ecosystem conventions, not verified via package registry — this phase installs zero new crates)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (68.2 reference):** Build the Rust read chain now; mirror the Phase 68.2 contract read via `git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:<path>` — **never `git checkout`/`git switch` to that branch** (it is checked out in the main worktree; the switch will fail). `ResolvedChild = { ipnsName, name, kind, size?, modifiedAt, sequence }`; SDK exposes imperative pull (`listFolder`/`listSharedFolder`) + `folder:updated` event push; 68.2 D-04 (`RotationHighWater`/`HighWaterStore` IS the "DurableFloorStore") and D-05 (gated listing is the single read entrypoint; raw resolve is internal-only) are the Rust analogs to build.
- **D-02 (crate placement):** `crates/core` owns pure IPNS-resolve + node-unseal + per-child metadata resolution + the `Node`/`SealedChildRef` codec (mirrors `packages/core`). `crates/sdk` owns the stateful layer — anti-rollback gate (`RotationHighWater` analog), durable floor store, resolved child-listing API (mirrors `packages/sdk`). `crates/fuse`/WinFsp consume the resolved listing from `crates/sdk` — no inline resolve/unseal/gating.
- **D-03 (durable floor persistence):** JSON sidecar file adjacent to the journal dir, behind an injected `HighWaterStore`-analog trait (FUSE daemon supplies path/impl; `crates/sdk` owns gating logic). Atomic write, no new storage dependency. Rejected: sled/redb/sqlite (heavyweight for a handful of monotonic counters + a new runtime dep in the daemon).
- **D-04 (Node enum cutover):** Clean cutover (Phase-62 style). Introduce `enum Node`, **delete** legacy `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` from `crates/core`, migrate every FUSE/`replay`/`metadata` call site this phase, conform to the frozen cross-language KAT (`tests/vectors/node-codec.json`, `tests/vectors/crypto/node-aad.json`). No coexistence/bridge.
- **D-05 (rotation-engine port scope):** Full in-phase port of the TS 63/64 read-rotation engine into `crates/sdk`. Dominant plan-cluster, sequenced AFTER the Node-enum + read-chain foundation lands. Must reach parity on: resumable/crash-safe execution, CRIT-1 content-key rotation, M1 generation-downgrade defense, HIGH-3 multi-rooted grant re-mint, HIGH-4 add-during-rotation merge. **Note:** the grant-root scope-computation algorithm (`crates/fuse/src/write_ops/`) is ROADMAP-flagged net-new and requires a plan-time design pass — this document is that design pass (see Architecture Patterns > Pattern 1 below). Rejected: splitting rotation into a 69.1 follow-up.
- **D-06 (WinFsp/Windows sequencing):** WinFsp is in-phase but isolated as its own plan/plan-cluster against the SAME `crates/sdk` listing/gate API. User executes the WinFsp plan on a Windows machine — planning must NOT assume long CI round-trips for iteration. `Cargo Check & Test (Windows)` CI gate + dispatch-gated desktop E2E remain the sign-off authority (SC#5). Build/verify `crates/core`/`crates/sdk` + macOS/Linux FUSE path FIRST, then the Windows platform layer.
- **D-07 (write-plane dual-keying) — HARD CONSTRAINT:** Every FUSE/WinFsp shared-write delete/move/rename path MUST thread BOTH the write-body `WriteChildRef.childId` (node UUID) AND the read-body `SealedChildRef` (ipnsName). Conflating them silently breaks `rotateWriteFromNode`. `crates/fuse/src/write_ops/` is flagged for explicit security review.
- **D-08 (Q3 write-recipient-vs-owner sub-share authority, carried forward from 65-CONTEXT D-01):** FUSE mirrors Phase 65 Q3 = Model (a), reconcile-on-owner-sync. A write-recipient C deleting/moving-out a node the owner independently sub-shared to D: C's path unlinks+bins with no cross-principal revoke attempt and no new schema; owner's reconcile+rotation pass re-derives dangling grants. D-exposure window until owner's next online reconcile is an accepted documented residual (ADR 0002).

### Claude's Discretion

- Exact Rust type/field naming (`ResolvedChild`, floor-store trait name, `folder:updated`-analog event mechanism) and error shapes — follow existing `crates/sdk` conventions and 68.2 naming where it maps cleanly.
- Whether the read chain warrants a new module split within `crates/core`/`crates/sdk` vs. new files in existing modules — planner's call from the call-site blast radius documented below.

### Deferred Ideas (OUT OF SCOPE)

- None raised that constitute new capabilities — discussion stayed within the phase's Rust-port scope.
- Folded todo `2026-06-24-replay-reuse-verified-parent-sequence.md` — superseded by the SC#6 read-chain consolidation (resolve moves into `crates/sdk`); verify genuinely resolved before retiring at phase close.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| TEST-03 | The winfsp read-path is validated via `Cargo Check & Test (Windows)` (authoritative) and the dispatch-gated desktop E2E is triggered explicitly | See Validation Architecture and `## Common Pitfalls > Pitfall 7 (Windows CI/E2E gating)`. CI job confirmed live: `.github/workflows/ci.yml` job `cargo-windows` (name "Cargo Check & Test (Windows)"), gated on `needs.changes.outputs.desktop == 'true'`, runs `cargo check --workspace --no-default-features --features winfsp` then `cargo test --workspace --no-default-features --features winfsp` on `windows-latest` with WinFsp MSI pre-installed. Desktop E2E is `.github/workflows/desktop-e2e.yml`, `workflow_dispatch`-only, matrix includes a `windows-latest` leg — dispatch via `gh workflow run "CI E2E Tests" --ref <branch>` per CONTEXT.md/ROADMAP SC#5 wording (confirm exact workflow display name at execution time; the file is `desktop-e2e.yml` but SC#5 names it "CI E2E Tests" — verify the `name:` field before scripting the dispatch command). |

</phase_requirements>

## Summary

This phase ports the entire TypeScript `node/v3` read chain, ROT-07 durable anti-rollback gate, and the Phase-63/64 resumable rotation engine into the Rust desktop stack, and makes FUSE/WinFsp grant-root-aware for the first time. It is **not** a crypto swap — `crates/crypto` already ships `seal_aes_gcm_aad`/`unseal_aes_gcm_aad`/`build_node_aad` (Phase 61, fully KAT-tested) — it is a **full architectural port** of code that took TypeScript five phases (62, 63, 64, 65, 68.2) to build, compressed into one Rust phase. Confirmed live: `crates/core` still holds the legacy `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` (`crates/core/src/folder.rs`, 426 lines, full ECIES-fan-out model); there is **zero** `rotate_read`/`grant_root`/`RotationHighWater` code anywhere in Rust; and the FUSE delete/rename paths (`crates/fuse/src/write_ops/implementation/{delete,rename}.rs`) do a **blanket, unconditional** `revoke_shares_blocking` call on every delete regardless of scope — the opposite of the ROT-02/SC#4 "no covering grant ⇒ zero rotation" invariant this phase must implement.

The five exact swap sites for SC#1 were verified at the cited line numbers: `crates/fuse/src/inode.rs:434,452,658,716` and `crates/fuse/src/replay.rs:365` all call `cipherbox_crypto::ecies::unwrap_key` against a `FolderEntry.folder_key_encrypted` or `FilePointer.ipns_private_key_encrypted` hex blob — every one of these is fan-out ECIES-per-recipient unwrap that the `node/v3` model replaces with one symmetric `unseal_aes_gcm_aad`/`build_node_aad` hop per parent→child edge. The SC#2 deletion target `spawn_file_meta_reencrypt` (`crates/fuse/src/metadata.rs:777`) and its two callers (`write_ops/implementation/rename.rs:248`, `platform/windows/write_ops.rs:1183`) exist because a `FileMetadata` is sealed under its **parent's** folder key today (no independent readKey per node) — this whole re-encrypt-on-move dance disappears once each `Node` seals under its own `readKey` and a move becomes a pure `SealedChildRef` relink (design doc §3.5).

The **grant-root scope-computation algorithm** — this phase's single highest-risk, most novel deliverable — has a complete, already-shipped TypeScript reference implementation: `packages/sdk-core/src/rotation/scope.ts` (160 lines, `hasCoveringGrant` + `maybeRotateOnScopeExit`, both pure/testable) plus its composition point `packages/sdk/src/client.ts:1186-1258` (`performScopeExitRotation`). This is a direct, mechanical Rust port (see Architecture Patterns > Pattern 1). One material gap discovered during this research and NOT visible from CONTEXT.md alone: the TypeScript "relay-supplied `activeGrantRootIpnsNames`" is, in the actual shipped web implementation (`apps/web/src/services/rotation-driver.service.ts:199-208`), sourced from a **local cache of the client's own sent-shares** (`useShareStore.getState().sentShares`, populated from `GET /shares/sent`) — not a live per-mutation relay query. `crates/api-client` has **no** wrapper for `GET /shares/sent` today (only `revoke_shares_for_items`/`POST /shares/revoke-for-items` exists in `crates/api-client/src/shares.rs`). The Rust port therefore needs a new `crates/api-client::shares::list_sent_shares` (or equivalent) call plus a local cache the FUSE/WinFsp layer refreshes periodically or on mount — this is additional blast radius beyond the roadmap's literal wording and must be an explicit plan task.

**Primary recommendation:** Sequence the phase in four waves, strictly in this order (each is a hard prerequisite for the next): (1) `crates/core` Node enum + codec + KAT conformance (SC#4, SC#6 foundation) — a pure, no-I/O port with the frozen `tests/vectors/node-codec.json`/`node-aad.json` vectors as the acceptance oracle; (2) `crates/sdk` gated read chain — `RotationHighWater` port (a ~190-line, dependency-free TS module, the single easiest and lowest-risk port target in this phase) + durable JSON-sidecar floor store + `ResolvedChild`/`list_folder`-analog API (SC#6, 68.2 parity); (3) `crates/sdk` rotation engine port (`rotateReadFromNode`/`rotateOne`, SC#3/D-05 — the dominant, highest-effort cluster) + the new `list_sent_shares` api-client call + a local grant-root cache; (4) `crates/fuse` write_ops grant-root wiring (delete/rename/move call `hasCoveringGrant`-equivalent before `revoke_shares_blocking`, SC#3) and the SC#1/SC#2 ECIES→symmetric swap, done LAST once the Node model exists to unwrap against — then the isolated WinFsp plan (D-06) against the same `crates/sdk` API, with the Windows CI gate as sign-off (TEST-03).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Node codec (encode/decode, `build_node_aad` unwrap) | `crates/core` (pure crypto/codec) | `crates/crypto` (AES-GCM-AAD primitive, already shipped) | Mirrors `packages/core`; no I/O, no state — the KAT-conformance layer |
| IPNS resolve + ROT-07 anti-rollback gate + durable floor store | `crates/sdk` (stateful, in-process) | API/Backend boundary (relay routes the actual resolve call) | Mirrors 68.2 D-04/D-05: the gate is a client-side durable floor; `crates/sdk` is the sole in-process owner |
| Resolved child-listing API (`ResolvedChild`, folder-load cache) | `crates/sdk` | `crates/core` (per-child unseal primitive it calls) | Mirrors 68.2 `listFolder`/`listSharedFolder`; FUSE/WinFsp never resolve/unseal inline (D-02) |
| Resumable rotation engine (`rotateReadFromNode`/`rotateOne`) | `crates/sdk` | `crates/api-client` (CAS publish, grant re-mint queries) | Mirrors `packages/sdk-core/src/rotation/engine.ts`; host-agnostic, no FUSE/Tauri import (D-02 parity with TS's own "host-agnostic" doctrine) |
| Grant-root scope computation (`hasCoveringGrant`/`maybeRotateOnScopeExit`) | `crates/fuse` write_ops (mounted-tree ancestry is FUSE-local) OR `crates/sdk` (if hoisted for WinFsp reuse) | `crates/sdk` (owns the actual `rotate` callback) | Design doc §3.9 explicitly says FUSE/desktop computes ancestry because it already holds the mounted tree; **recommend hoisting the pure predicate into `crates/sdk` or a shared module so WinFsp (D-06, separate plan) does not duplicate it** — see Pitfall 1 |
| Active-grant-root set + local grant record (relay completeness aid + anti-malicious-relay cross-check) | `crates/sdk` (cache) | `crates/api-client` (new `GET /shares/sent` wrapper — does not exist yet) | Mirrors `rotation-driver.service.ts`; NOT currently a live per-op relay query even in TS — a periodic/on-mount refresh into a local cache is the correct mirror, not a synchronous call on every delete |
| Write-plane dual-keying (`WriteChildRef.childId` UUID vs `SealedChildRef` ipnsName) | `crates/fuse` write_ops (both keys must be threaded through delete/move/rename) | `crates/sdk` (owns `rotateWriteFromNode` — write-body rotation) | D-07 hard constraint; the write body already exists conceptually in TS (`packages/core/src/node/types.ts` `NodeWriteBody`/`WriteChildRef`) but has NO Rust analog yet — net-new type definitions required in `crates/core` |
| Durable floor persistence (JSON sidecar) | `crates/sdk` (gating logic) | `crates/fuse`/WinFsp (supplies concrete path adjacent to `journal_dir`) | D-03; mirrors 68.2 D-06 injectable-store pattern; reuses the existing `WriteQueue::sidecar_path_for` adjacency point (`crates/sdk/src/queue.rs:267`) |
| WinFsp platform layer | Browser/Client-analog tier (OS filesystem shim) | `crates/sdk` (same listing/gate API as FUSE) | D-06; isolated plan, same consumption contract as macOS/Linux FUSE — no independent read-chain/rotation logic in the Windows platform files |

## Standard Stack

No new external dependencies. This phase ports existing TypeScript logic into existing Rust crates already in the workspace (`crates/core`, `crates/sdk`, `crates/fuse`) using crates already declared in the workspace `Cargo.toml` — no `cargo add` is required for the read-chain/rotation port itself.

### Core (existing, reused — `[VERIFIED: workspace Cargo.toml]`)
| Crate | Version | Purpose | Why reused |
|-------|---------|---------|------------|
| `aes-gcm` | 0.10 | AES-256-GCM(+AAD) primitive | Already backs `seal_aes_gcm_aad`/`unseal_aes_gcm_aad`/`build_node_aad` in `crates/crypto/src/aes.rs` (Phase 61) |
| `ecies` | 0.2 (`pure` feature) | ECIES wrap/unwrap for the vault-key-blob root wrap only | NODE-06 still needs ECIES for `ECIES(rootReadKey)`/`ECIES(rootWriteKey)` in the vault blob — NOT for node-to-node child unwraps (those become symmetric, SC#1) |
| `ed25519-dalek` 2.x | 2 | Node write-body signing key type | Already a workspace dep; the write-body's `ipnsPrivateKey` (raw Ed25519 seed) is new domain data but uses an existing crate |
| `serde`/`serde_json` | 1 | Node codec JSON encode/decode with `camelCase` rename | Existing convention (`#[serde(rename_all = "camelCase")]`) already used by `FolderMetadata` etc.; the Node codec must produce byte-identical JSON to `packages/core/src/node/encode.ts` per `docs/METADATA_SCHEMAS.md` §14 |
| `uuid` | 1 (`std`) | Node `id` field (RFC-4122 hyphenated UUID) | Already used by `build_node_aad`'s `Uuid::parse_str` |
| `zeroize` | 1 (`derive`) | Terminal-owner zeroing of minted read/write keys during rotation | Existing convention throughout `crates/fuse`/`crates/sdk`; the rotation port MUST follow the same "callee zeros only its own mints" rule as the TS engine (see Common Pitfalls > Pitfall 3) |
| `winfsp` | 0.12 (`system` feature) | WinFsp Windows filesystem binding | Already an optional dep behind the `winfsp` feature in `crates/fuse/Cargo.toml`; no version bump needed |

### Supporting (existing, reused)
| Crate | Version | Purpose | When to use |
|-------|---------|---------|-------------|
| `tokio` | 1 (`full`) | Async runtime for the rotation walk's resolve/fetch/publish calls | Rotation engine port is inherently async (IPNS resolve, IPFS fetch, CAS publish) — mirror the existing `resolve_folder_key`/`spawn_file_meta_reencrypt` async patterns in `crates/fuse` |
| `hex`, `base64` | 0.4 / 0.22 | Wire encoding for sealed blobs and hex-encoded keys | `SealedChildRef.readKeySealed` is base64; legacy `folder_key_encrypted` is hex — the Node codec must match `docs/METADATA_SCHEMAS.md` §3 encoding exactly |
| `thiserror` | 2 | Structured error types for the new rotation/gate modules | Existing convention (`CryptoError`, `FolderError`, `ApiError`) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| JSON sidecar for durable floor (D-03, locked) | `sled`/`redb` embedded KV | Rejected in CONTEXT.md D-03: heavyweight for a handful of monotonic counters, adds a new runtime dependency to the daemon. Do not reconsider — this is a locked decision. |
| JSON sidecar for durable floor | SQLite | Same rejection as above (locked D-03) |
| Hand-rolled proptest/property-based rotation tests | `proptest`/`quickcheck` crates | `[ASSUMED]` — neither crate appears in any workspace `Cargo.toml` today; the existing Rust test discipline is 100% hand-written `#[test]`/`#[tokio::test]` cases plus the `tests/vectors/*.json` cross-language KAT pattern (`crates/crypto/tests/cross_language.rs`, `crates/fuse/tests/ipns_verify_vectors.rs`). Recommend continuing that pattern (hand-written BFS/crash-resume test cases mirroring `packages/sdk-core/src/__tests__/rotation/engine.test.ts`) rather than introducing a new test-framework dependency mid-phase — but flag this as a **Claude's Discretion** item for the planner, not a locked decision. |

**Installation:** None required — no new crates.

**Version verification:** `[VERIFIED: workspace Cargo.toml]` — all crates above are already pinned in the root `Cargo.toml` `[workspace.dependencies]` table and in `crates/fuse/Cargo.toml`; confirmed live via `Read`, no `cargo add`/registry lookup needed for this phase.

## Package Legitimacy Audit

**Not applicable** — this phase installs zero new external packages/crates. All work ports existing TypeScript logic into existing Rust crates using dependencies already present in the workspace `Cargo.toml`. No `cargo add`, no `npm install`, no package-legitimacy check required.

## Architecture Patterns

### System Architecture Diagram (target read + rotation flow, Rust side)

```
FUSE/WinFsp mount thread (crates/fuse write_ops, crates/fuse/src/platform/windows)
   |
   |  delete/rename/move syscall handler
   v
crates/fuse::write_ops::implementation::{delete,rename}.rs
   |
   |-- 1. Compute node's ancestor IPNS-name chain from the mounted inode tree
   |        (cheap — already resolved locally, per design doc §3.9)
   v
crates/sdk (or a shared grant-scope module) :: has_covering_grant(ancestors, active_grant_roots, local_grant_record)
   |         <-- PURE predicate, no I/O (mirrors packages/sdk-core/src/rotation/scope.ts)
   |
   +-- false --> pure relink: reseal parent SealedChildRef, republish parent ONLY.
   |             ZERO rotation, ZERO extra publishes (ROT-02 / SC#4 hard invariant).
   |
   +-- true  --> crates/sdk :: rotate_read_from_node(root_node_id, root_ipns_name, root_read_key, ...)
                    |
                    |-- rotate_one(root): mint new readKey'/generation'/fileKey' (files),
                    |     reseal read-body (build_node_aad w/ new generation), CAS-publish
                    v
                 BFS frontier walk over children (crates/core Node.children : Vec<SealedChildRef>)
                    |-- per child: unseal_child_read_key(parent OLD readKey) -> reseal under NEW parent key
                    |-- HIGH-4: re-fetch + re-merge SealedChildRef on CAS-409, never blind re-seal
                    |-- HIGH-3: query shares rooted at each rotated nodeId, re-mint grant descriptors
                    |-- persist advisory JobRecord + durable {nodeId -> generation, seq} floor after
                    |     EVERY per-node commit (crash-safe resume, ROT-06 analog)
                    v
                 crates/api-client :: publish_with_cas / list_sent_shares (NEW) / update_grant (NEW)

--- read path (SC#6 / 68.2 parity) ---

crates/fuse::read_ops / crates/fuse::dir_ops
   v
crates/sdk :: list_folder(ipns_name) -> Vec<ResolvedChild>     <-- SINGLE gated entrypoint
   |
   |-- gate: rotation_high_water.enforce_resolved(node_id, seq, generation, version_floor)
   |          FAIL CLOSED before any floor mutation (mirrors packages/sdk/state/rotation-high-water.ts)
   v
crates/core :: resolve + unseal_node (build_node_aad) -> Node::Folder{children} | Node::File{content}
```

### Recommended Project Structure (net file changes)
```
crates/core/src/
├── node/                      # NEW module (mirrors packages/core/src/node/)
│   ├── mod.rs                 # re-exports; enum Node { Folder{..}, File{..}, Root{..} }
│   ├── types.rs               # Node, SealedChildRef, NodeContent, VersionEntry, NodeWriteBody, WriteChildRef, PublishedNode
│   ├── encode.rs / decode.rs  # JSON codec — MUST byte-match tests/vectors/node-codec.json
│   └── seal.rs                # seal_node/unseal_node/seal_child_read_key/unseal_child_read_key (wraps crates/crypto AAD primitives)
├── folder.rs                  # DELETED per D-04 (FolderMetadata/FolderEntry/FolderChild removed)
├── file.rs                    # DELETED per D-04 (FileMetadata/FilePointer/VersionEntry legacy shape removed)
├── bin.rs                     # MODIFIED — BinEntry.file_pointer/folder_entry fields repoint to Node-shaped refs (mirrors TS bin/* D-06 rework noted in design doc §3.10)
├── decrypt.rs                 # MODIFIED — decrypt_metadata_from_ipfs_public/decrypt_file_metadata_from_ipfs_public repoint to Node codec
└── vault_blob.rs               # MODIFIED — NODE-06 two-key (rootReadKey+rootWriteKey) v3 blob; see tests/vectors/vault-v3-blob.json

crates/sdk/src/
├── rotation/                  # NEW module (mirrors packages/sdk-core/src/rotation/)
│   ├── high_water.rs           # RotationHighWater port — direct, low-risk (mirrors rotation-high-water.ts, 188 lines)
│   ├── scope.rs                # has_covering_grant / maybe_rotate_on_scope_exit — direct port of scope.ts (160 lines)
│   └── engine.rs               # rotate_read_from_node / rotate_one — the dominant-effort port (mirrors engine.ts, 1000+ lines)
├── floor_store.rs              # NEW — injected trait + JSON-sidecar impl (D-03), gated by crates/sdk, path supplied by crates/fuse
└── listing.rs                  # NEW — ResolvedChild + list_folder/list_shared_folder gated resolve (68.2 parity, SC#6)

crates/fuse/src/
├── write_ops/
│   ├── grant_scope.rs          # NEW (or hoisted into crates/sdk, see Pitfall 1) — ancestor-chain computation from the mounted inode tree
│   └── implementation/{delete,rename}.rs  # MODIFIED — call has_covering_grant BEFORE revoke_shares_blocking; thread WriteChildRef.childId (D-07)
├── inode.rs                    # MODIFIED — SC#1 swap sites (lines 434,452,658,716 today) become unseal_node/unseal_child_read_key calls
├── replay.rs                   # MODIFIED — SC#1 swap site (line 365); SC#6 resolve moves into crates/sdk::listing
└── metadata.rs                 # MODIFIED — spawn_file_meta_reencrypt DELETED (SC#2); both callers updated
```

### Pattern 1: Grant-root scope-exit gate — the net-new algorithm (research priority #1)

**What:** A pure, no-I/O predicate that decides, for a mutated node, whether at least one active read grant's root is an ancestor of (or equal to) that node. If yes, rotation must run; if no, the mutation is a pure relink with zero rotation publishes.

**Direct port target — this is not a design-from-scratch problem.** The TypeScript reference implementation is small, pure, and already unit-tested:

```typescript
// Source: packages/sdk-core/src/rotation/scope.ts (full file, 160 lines — verified live read)
export type CoverageParams = {
  nodeAncestorIpnsNames: string[];        // leaf-first: node itself, then ancestors, vault root last
  activeGrantRootIpnsNames: Set<string>;  // relay-supplied completeness aid
  localGrantRecord: { rootIpnsName: string } | null;  // client's own anti-malicious-relay cross-check
};

export function hasCoveringGrant(params: CoverageParams): boolean {
  const { nodeAncestorIpnsNames, activeGrantRootIpnsNames, localGrantRecord } = params;
  for (const ancestor of nodeAncestorIpnsNames) {
    if (activeGrantRootIpnsNames.has(ancestor)) return true;
    if (localGrantRecord !== null && localGrantRecord.rootIpnsName === ancestor) return true;
  }
  return false;
}

export async function maybeRotateOnScopeExit(
  params: CoverageParams,
  deps: { rotate: () => Promise<void> }
): Promise<'no-rotation' | 'rotated'> {
  if (!hasCoveringGrant(params)) return 'no-rotation';   // ROT-02/SC#4: zero rotation, zero publishes
  await deps.rotate();
  return 'rotated';
}
```

**Rust port — recommended signature (mirrors the above 1:1):**
```rust
// crates/sdk/src/rotation/scope.rs (recommended — Claude's Discretion on exact naming)
pub struct CoverageParams {
    pub node_ancestor_ipns_names: Vec<String>,     // leaf-first
    pub active_grant_root_ipns_names: std::collections::HashSet<String>,
    pub local_grant_record: Option<LocalGrantRecord>,
}
pub struct LocalGrantRecord { pub root_ipns_name: String }

pub fn has_covering_grant(params: &CoverageParams) -> bool {
    for ancestor in &params.node_ancestor_ipns_names {
        if params.active_grant_root_ipns_names.contains(ancestor) { return true; }
        if let Some(rec) = &params.local_grant_record {
            if &rec.root_ipns_name == ancestor { return true; }
        }
    }
    false
}

pub enum ScopeExitResult { NoRotation, Rotated }

pub async fn maybe_rotate_on_scope_exit<F, Fut>(
    params: &CoverageParams,
    rotate: F,
) -> Result<ScopeExitResult, String>
where F: FnOnce() -> Fut, Fut: std::future::Future<Output = Result<(), String>> {
    if !has_covering_grant(params) { return Ok(ScopeExitResult::NoRotation); }
    rotate().await?;
    Ok(ScopeExitResult::Rotated)
}
```

**(a) Detecting shared vs private scope:** Walk `parent_ino` chain from the mutated inode up to `ROOT_INO` using the ALREADY-mounted inode table (`fs.inodes`, `crates/fuse/src/inode.rs`) — collect each ancestor's IPNS name (`InodeKind::Folder { ipns_name, .. }` / `InodeKind::Root { ipns_name, .. }`) into a leaf-first `Vec<String>`. This is O(depth), purely local, no network call — exactly the "FUSE already holds the mounted tree" argument in design doc §3.9. **Do not** attempt to resolve ancestry via IPNS network calls; the mounted tree already has it.

**(b) Computing the grant-root to rotate from:** The grant root is whichever ancestor IPNS name first matches `active_grant_root_ipns_names` or `local_grant_record.root_ipns_name` scanning leaf-first — call `rotate_read_from_node` rooted at THAT ancestor's node, not necessarily the mutated node itself (a delete deep inside a shared folder rotates from the shared folder's root, not from the deleted leaf — mirrors `performScopeExitRotation`'s `rootNodeIpnsName`/`rootNodeId`/`rootReadKey` params, `packages/sdk/src/client.ts:1186-1193`).

**(c) Shared-scope-exit vs private-delete decision:** `has_covering_grant(...) == false` → pure relink: reseal the parent's `SealedChildRef` list minus/plus the moved entry, republish the parent ONLY, **zero** rotation invocations, **zero** extra IPNS publishes beyond the parent relink (this is SC#3's literal wording and ROT-02's hard test). `has_covering_grant(...) == true` → call `rotate_read_from_node` rooted at the matched grant-root ancestor exactly once (never once per ancestor match — short-circuit at first match, mirroring `maybeRotateOnScopeExit`'s single `deps.rotate()` call).

**Composition point to mirror:** `packages/sdk/src/client.ts:1186-1258` (`performScopeExitRotation`) shows the full production wiring — fetch `activeGrantRootIpnsNames` from injected callbacks, build `CoverageParams`, call `maybeRotateOnScopeExit`, and on a `'rotated'` result refresh the in-memory folder-tree entry with the rotated root's new `readKey`/`generation`/`sequenceNumber` (zeroing the OLD key copy AFTER the swap, never mid-flight — D-09 terminal-owner rule). Port this composition into `crates/fuse/src/write_ops/implementation/{delete,rename}.rs` replacing today's unconditional `revoke_shares_blocking` call.

### Pattern 2: Gate-first resolve (ROT-07 read-path gate — 68.2 parity, SC#6)

**What:** Every IPNS resolve on the Rust read path passes through the `RotationHighWater`-analog `enforce_resolved` BEFORE its result is trusted, exactly like 68.2's TS-side finding (the write-path-only gate today is the ONLY analog; there is currently zero read-side gate anywhere in Rust — confirmed live: `crates/fuse/src/publish.rs`'s `resolve_sequence_strict` tracks only `sequence`, in-memory, lost on restart, per design doc §4.3's own audit).

**Critical divergence to replicate from 68.2's Pitfall 3 (parent-mirror generation source):** when gating a resolve for a NOT-YET-cached child during a folder-listing walk, the `generation` passed to `enforce_resolved` MUST be the PARENT's `SealedChildRef.generation` mirror — never the child's own envelope generation. Only when reconciling the SAME already-loaded node (a write-path check) does the in-memory node's own generation apply. Getting this backwards silently defeats M1 (generation-downgrade defense, design doc §4.3).

**Example (RotationHighWater — direct, low-risk port target, full TS source read live):**
```typescript
// Source: packages/sdk/src/state/rotation-high-water.ts (188 lines, dependency-free — verified live read)
export interface HighWaterStore {
  get(nodeId: string): Promise<number | undefined>;
  put(nodeId: string, value: number): Promise<void>;
}
export interface EnforceResolvedParams { nodeId: string; seq: number; generation: number; versionFloor: number; }
// enforceResolved: fail-closed on NaN/negative/non-integer inputs (V5), checks generation
// floor first (GenerationRegressionError), then seq floor OR cold-device versionFloor gate
// (SequenceRegressionError), then monotonic-max bumps both floors. See full source for exact logic.
```
This module has NO external dependencies (pure functions + two injected async get/put callbacks) — it is the single lowest-risk, highest-confidence port target in this entire phase. Port `HighWaterStore` to a Rust trait (`async_trait` or a sync trait returning `impl Future`, per existing `crates/sdk` async conventions) and `RotationHighWater`'s five methods verbatim.

### Pattern 3: Resumable rotation engine — port scope and structure (D-05, dominant cluster)

**What:** `rotateReadFromNode`/`rotateOne` (mirrors `packages/sdk-core/src/rotation/engine.ts`, verified live read of ~250 lines of its ~1000+, covering the type/callback surface and the full `rotateReadFromNode` BFS driver). Key structural facts confirmed from live source, NOT training-data assumption:

- **Ordering:** scope-root rotates FIRST (§4.2) — this is the actual revocation cut; the O(items) BFS tail follows.
- **Per-node commit + advisory job record:** `RotationJobRecord { rootNodeId, status, completedNodeIds, frontier, persistCallback }` is persisted after EVERY per-node commit via an injected `persistCallback` — published IPNS records remain the actual source of truth (D-10); the job record is resume-acceleration only.
- **Resume/skip path:** if `rotateOne(root)` returns `{ skipped: true }` (already committed in a prior run), the engine calls a `verifySubtreeClean` analog to rebuild the dirty frontier rather than blindly re-walking everything — this is the crash-safety mechanism (ROT-06).
- **Parent-tracking / out-of-band re-seal (D-02 in engine.ts's own internal numbering, NOT this phase's D-02):** `rotateOne` seals a child's NEW readKey under the CHILD's OWN old readKey — but the PARENT's `SealedChildRef[child].readKeySealed` must be resealed under the PARENT's NEW readKey. This reseal happens in the BFS walk caller (a `parentTracking: Map<parentIpnsName, ParentTrackingState>`), batching one republish per parent regardless of how many children rotated (constant-factor win at scale, §4.7).
- **CRIT-1 (content-key rotation):** a file node's `rotateOne` also mints a fresh `fileKey`, applied lazily (`contentRekeyPending` marker) — do NOT eagerly re-encrypt already-published content (ADR 0002).
- **HIGH-3 (multi-rooted grant re-mint):** after rotating each node, query all `shares` rows rooted at that node's id (`GrantRemintCallbacks.queryGrantsFn`) and re-mint `readDescriptorRef` for every non-revoked recipient — a node independently shared deep inside a rotating subtree must not orphan its own grant.
- **HIGH-4 (add-during-rotation merge):** on every CAS-409 conflict, RE-FETCH and RE-MERGE the current `SealedChildRef[]` list rather than blindly re-sealing from a stale in-memory child list — a concurrent add must never be silently dropped.
- **Zeroization discipline (D-09, security-critical, explicitly flagged in the TS source's own doc comment as a "prior incident" — 48/89 sdk-e2e failures were caused by a callee zeroing a reused caller buffer):** `rotate_one` zeros its own minted `readKeyPrime` ONLY on its own failure paths before re-throwing; it NEVER zeros the caller-supplied `parentReadKey`/any reused session key. Port this rule verbatim into the Rust `rotate_one` — get the ownership direction backwards and you reproduce that exact historical bug class in Rust.

**Rust port structure recommendation:** `crates/sdk/src/rotation/engine.rs` as a single module mirroring `engine.ts`'s shape (types, `GrantRemintCallbacks`-analog trait, `RotationJobRecord`, `rotate_one`, `rotate_read_from_node`). Keep it host-agnostic (no `crates/fuse` import) exactly as the TS version is sdk-core-only with zero web/FUSE import — this is what lets the eventual WinFsp plan (D-06) consume the identical engine with zero duplication.

### Pattern 4: Write-plane dual-keying (D-07 hard constraint)

**What:** Every shared-write delete/move/rename thread BOTH keys — never substitute one for the other.

```typescript
// Source: packages/core/src/node/types.ts:133-141 (verified live read)
export type WriteChildRef = {
  childId: string;         // hyphenated UUID — the WRITE-plane key
  writeKeySealed: string;  // AES-GCM seal of child's writeKey under parent writeKey, AAD role=0x04
};
// SealedChildRef (READ-plane) keys by `ipnsName`, NEVER `childId` — NODE-03 frozen 5-field set,
// no writeKeySealed or any write field ever appears here.
```
**Rust has NO analog of `WriteChildRef`/`NodeWriteBody` today** — this is genuinely net-new type definition work in `crates/core`, not a mechanical port of an existing Rust shape. `crates/fuse/src/write_ops/implementation/{delete,rename,mkdir}.rs` currently key everything by ipnsName only (legacy model has no independent write chain) — every one of these three files needs the `childId` (UUID) threaded through alongside `ipnsName` once the Node write-body exists. **Flag explicitly for security review per D-07's own text.**

### Anti-Patterns to Avoid

- **Rotating on every delete/move/rename regardless of grant coverage.** This is literally what the current Rust code does (`revoke_shares_blocking` fires unconditionally in `handle_unlink`/`handle_rmdir`) — it is the exact anti-pattern ROT-02/SC#4 exists to eliminate. The migration is not additive; it must REPLACE the unconditional call with the gated one.
- **Resolving ancestry via network IPNS calls instead of the mounted inode tree.** FUSE already has the tree in memory (`fs.inodes`); a network round-trip per ancestor on every delete/rename would be a severe performance regression design doc §3.9 explicitly warns against.
- **Treating the relay's `active_grant_root_ipns_names` as authoritative.** T-63-17 in the TS source: a malicious/buggy relay can omit a grant root to suppress rotation. The Rust port MUST cross-check against the client's own `local_grant_record`, exactly as `hasCoveringGrant` does — never trust the relay set alone.
- **Zeroizing a caller-supplied key inside `rotate_one`.** This is THE documented historical bug (48/89 sdk-e2e failures cited in engine.ts's own comments). The Rust rotation engine must encode the identical "callee zeros only its own mints, on its own failure paths" rule from day one.
- **Building a second `DurableFloorStore`/embedded-KV abstraction.** D-03 explicitly locks the JSON-sidecar approach; do not introduce sled/redb/sqlite mid-phase even if it looks cleaner for the generation+seq floor pair.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AES-256-GCM+AAD seal/unseal | A second AEAD wrapper | `cipherbox_crypto::aes::{seal_aes_gcm_aad, unseal_aes_gcm_aad, build_node_aad}` (already shipped, Phase 61, KAT-tested) | This phase's SC#1 is precisely "stop hand-rolling ECIES fan-out, use the primitive that already exists" |
| Durable monotonic-max floor logic | A bespoke ad-hoc "last-seen generation" cache | Direct Rust port of `packages/sdk/src/state/rotation-high-water.ts`'s `bumpFloor`/`readFloor`/`enforceResolved` (188 lines, fully specified, zero deps) | Getting the fail-closed validation (`isValidFloorValue` — reject NaN/negative/non-integer BEFORE comparing) subtly wrong reproduces a real security regression class; the TS logic is already reviewed and battle-tested |
| Grant-root ancestry / scope-exit predicate | A new bespoke "is this shared" heuristic | Direct Rust port of `packages/sdk-core/src/rotation/scope.ts`'s `hasCoveringGrant`/`maybeRotateOnScopeExit` | Pure, 60-line, already-tested reference implementation exists — this is a translation task, not a design task |
| Resumable BFS rotation walk with crash recovery | A simpler "just re-walk everything on restart" approach | Direct port of `rotateReadFromNode`'s per-node-commit + `verifySubtreeClean`-analog resume | The TS design doc (§4.5) explicitly worked through why per-node commit + convergence-test resume is necessary (crash mid-walk must not leave a revoked reader on an un-rotated tail); re-deriving this from scratch in Rust risks reintroducing bugs the TS side already fixed (HIGH-3, HIGH-4, M1, CRIT-1 were all real reviewed defects) |
| Node codec JSON encoding | A hand-rolled ad-hoc JSON shape "close enough" to the TS one | The frozen `tests/vectors/node-codec.json`/`node-aad.json` byte-exact vectors as the conformance oracle | `docs/METADATA_SCHEMAS.md` §14 explicitly requires byte-identical JSON across TS/Rust; any divergence breaks cross-client interop for shared folders |

**Key insight:** Nearly everything "net-new" in this phase already has a complete, working, reviewed TypeScript reference implementation. The engineering risk is **translation fidelity** (getting the zeroization ownership direction, the generation-source rule, and the fail-closed validation order exactly right), not algorithm design — except for the grant-root ancestry-walk mechanics (Pattern 1(a)), which genuinely has no TS analog because TS never had a mounted filesystem tree to walk.

## Runtime State Inventory

> Rename/refactor/migration trigger: D-04's "clean cutover" deletes `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` from `crates/core` — a Rust-side type/schema migration, even though the wire-format schema (`node/v3`) itself is greenfield project-wide (no prod data, staging wiped per `.planning/REQUIREMENTS.md` Out of Scope table).

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data (on-disk journal) | `crates/fuse/src/journal_helpers.rs:97` — `JournalOp::MkdirPublish` embeds `parent_metadata: cipherbox_core::folder::FolderMetadata` directly, serialized to JSON on disk in the FUSE write journal (`<journal_dir>/<id>.json`). A clean D-04 cutover changes this Rust type; any journal entry written by a PRE-cutover desktop build will fail to `serde_json::from_str` against the new `Node`-based `JournalOp` shape. | Code edit (not data migration — no prod journals exist per greenfield policy, but developer/staging desktop installs mid-transition could have stale on-disk entries). Add a fail-closed, log-and-skip (not panic) path in journal replay for an entry that fails to deserialize under the new schema, and document that a developer must clear `~/.cipherbox/journal` (or platform-equivalent) after pulling this phase's build if they see replay errors. |
| Live service config | None found. `shares`/`ipns_records` Postgres rows reference IPNS names and ECIES-wrapped descriptors, not the Rust type shape — no server-side config carries the legacy Rust struct shape. | None. |
| OS-registered state | None found — this phase does not rename any identifier (service name, task name, IPNS key). The WinFsp MSI/service registration is unaffected (crate already installed at v0.12; no version bump). | None. |
| Secrets/env vars | None found — no env var or secret key references `FolderMetadata`/`FilePointer` by name. | None. |
| Build artifacts | `target/` incremental-compilation artifacts for `crates/core`/`crates/fuse`/`apps/desktop/src-tauri` reference the deleted types; a normal `cargo build` after the type deletion will simply recompile (Rust's incremental system handles this natively — NOT a manual-cleanup item like the TS `.egg-info` precedent). | None beyond normal `cargo build` — flagged only for completeness; do not budget a plan task for this. |

**Nothing found in "Live service config", "OS-registered state", "Secrets/env vars" categories** — verified by grep across `crates/`, `apps/api/src/shares`, and `.github/workflows/*.yml` for any Rust-struct-name-shaped identifier leakage outside the Rust codebase itself.

## Common Pitfalls

### Pitfall 1: Grant-scope predicate duplication between FUSE and WinFsp (D-06 boundary risk)
**What goes wrong:** If the ancestor-walk + `has_covering_grant` call is written directly inside `crates/fuse/src/write_ops/`, the isolated WinFsp plan (D-06) either duplicates the identical logic in `crates/fuse/src/platform/windows/write_ops.rs` or — worse — reimplements a subtly different version.
**Why it happens:** WinFsp's write-op handlers are a separate call path (`platform/windows/write_ops.rs`) from the Unix FUSE handlers (`write_ops/implementation/*.rs`); nothing structurally forces them to share the scope predicate.
**How to avoid:** Hoist `has_covering_grant`/the ancestor-walk helper into a module `crates/fuse` exposes to BOTH platform back-ends (e.g., a `crate::write_ops::grant_scope` module used by both `write_ops/implementation/delete.rs` and `platform/windows/write_ops.rs`), or hoist the pure predicate itself into `crates/sdk` (mirrors this phase's own Architectural Responsibility Map recommendation). Either way, write ONE ancestor-walk + one `has_covering_grant` call site consumed by both platforms — never two.
**Warning signs:** A WinFsp plan task that says "port `has_covering_grant`" instead of "wire the existing `has_covering_grant` into the Windows write-op handlers."

### Pitfall 2: The relay-supplied grant-root set is NOT a live per-mutation query even in the reference TS implementation
**What goes wrong:** A naive Rust port might synchronously call a new `crates/api-client::shares::list_sent_shares` on every single delete/rename/move (a network round-trip per file-system mutation) because CONTEXT.md's design-doc language says "relay-supplied."
**Why it happens:** The design doc (§3.9) describes the relay set as "relay-supplied," which reads like a live query. The actual SHIPPED web implementation (`apps/web/src/services/rotation-driver.service.ts:199-208`, verified live read) sources `getActiveGrantRootIpnsNames`/`getLocalGrantRecord` from a **local Zustand cache** (`useShareStore.getState().sentShares`) that is populated once (on load / periodically) from `GET /shares/sent`, not queried synchronously per mutation.
**How to avoid:** Mirror the SHIPPED pattern, not the design-doc prose: maintain a local in-memory cache of sent shares in `crates/sdk` (or `crates/fuse`'s `CipherBoxFS` state), refreshed on mount and periodically (or on-demand before a rotation-eligible mutation), and have `has_covering_grant` read from that cache — not issue a network call inline in the delete/rename hot path. This requires a NEW `crates/api-client::shares::list_sent_shares` (or equivalent `GET /shares/sent` wrapper) since `crates/api-client/src/shares.rs` today contains ONLY `revoke_shares_for_items` — budget this as an explicit plan task, it is not covered by the roadmap's literal SC#1-#6 wording.
**Warning signs:** A plan task that adds a blocking API call inside `handle_unlink`/`handle_rename` for grant-root lookup, or a missing `crates/api-client` task despite `crates/sdk`'s rotation engine needing grant data.

### Pitfall 3: Getting the zeroization ownership direction backwards in `rotate_one` (historical bug class)
**What goes wrong:** A Rust port that zeros the caller-supplied `parent_read_key` (or any reused session key) inside `rotate_one`, rather than only zeroing its own newly-minted `read_key_prime` on its own failure paths.
**Why it happens:** The `zeroize`/`Zeroizing<T>` pattern is pervasive in this codebase (`STATE.md` project memory: "Zeroization: callee must not zero a reused buffer... broke 48/89 E2E"), and it is easy to reflexively wrap every key parameter in `Zeroizing<Vec<u8>>` and let it drop — but a `Zeroizing` wrapper around a CALLER-owned buffer that the callee doesn't actually own will zero it on scope exit regardless of success/failure, corrupting the caller's continued use of that key.
**How to avoid:** Follow the TS `engine.ts` doc comment verbatim: `rotate_one` mints `read_key_prime` and zeros THAT buffer only on its own failure paths before re-throwing — never on success (the BFS walk still needs it for children) — and NEVER zeros `parent_read_key`/any reused session key (caller-owned). Write a unit test asserting a caller-supplied key buffer is unchanged (not zeroed) after a successful `rotate_one` call, mirroring the project's own documented incident.
**Warning signs:** A `rotate_one` signature that takes `parent_read_key: Zeroizing<Vec<u8>>` by value and drops it at function exit instead of `&[u8]`/borrowed-and-explicitly-not-zeroed.

### Pitfall 4: Generation-source confusion during the folder-listing walk (M1 defense integrity)
**What goes wrong:** A gated `list_folder`/`resolve_published_node` implementation that sources `generation` for `enforce_resolved` from the CHILD's own envelope instead of the PARENT's `SealedChildRef.generation` mirror when resolving a not-yet-cached child.
**Why it happens:** It is the more "obvious" data source (the value is right there on the freshly-fetched envelope) and is the exact confusion 68.2's own research flagged as Pitfall 3 on the TypeScript side (`dfsFindFolder`'s explicit comment: "childRef.generation (parent mirror), NEVER childResolved.published.generation").
**How to avoid:** For an ALREADY-loaded node (write-path reconcile case), source `generation` from the in-memory node's own tracked generation. For a COLD child reached during a folder-listing walk, source `generation`/`versionFloor` from the PARENT's `SealedChildRef` entry for that child — exactly mirroring the unseal step's own AAD generation source (which is already correct in the TS reference and must be copied, not re-derived).
**Warning signs:** A `list_folder` implementation with no `SealedChildRef` context threaded into its per-child gate call — if the gate function signature only takes an IPNS name with no parent-mirror generation, it cannot correctly gate a cold child.

### Pitfall 5: `spawn_file_meta_reencrypt` deletion ordering (SC#2) — sequence AFTER the Node model lands, not before
**What goes wrong:** Deleting `spawn_file_meta_reencrypt` and its two callers (SC#2) BEFORE the Node model exists leaves cross-folder file moves with NO re-key mechanism at all during the transition window — a move would silently leave the file's metadata undecryptable under the destination folder's (now-legacy) key, or simply not compile if done out of order against the still-legacy call sites.
**Why it happens:** SC#2 is listed as an independent success criterion in the ROADMAP and could be read as parallelizable with SC#1/SC#4.
**How to avoid:** Sequence SC#2's deletion strictly AFTER the Node model lands (each node self-seals under its own `readKey`, eliminating the parent-folder-key coupling that made re-encryption necessary in the first place) — this phase's own CONTEXT.md domain notes confirm `spawn_file_meta_reencrypt` exists BECAUSE `FileMetadata` is sealed under the parent's folder key today; once that coupling is gone (Node model), the function becomes dead code by construction rather than something to carefully replace.
**Warning signs:** A plan wave that deletes `spawn_file_meta_reencrypt` in the same task/commit as SC#1's ECIES swap, before the Node model + read-body self-sealing exists.

### Pitfall 6: Journal `JournalOp` schema coupling to the legacy `FolderMetadata` type (build-breakage + replay-breakage risk)
**What goes wrong:** `crates/fuse/src/journal_helpers.rs:97` embeds `cipherbox_core::folder::FolderMetadata` directly inside `JournalOp::MkdirPublish`. A D-04 clean cutover that deletes `FolderMetadata` without updating this struct is a compile-time break (good — caught immediately) but ALSO changes the on-disk JSON shape journal entries are serialized under, which is a replay-compatibility break for anything already on disk (see Runtime State Inventory).
**Why it happens:** The journal was built (Phase 43/45/56/59) entirely against the legacy metadata model; nothing about its own design anticipated a codec swap.
**How to avoid:** Update `JournalOp::MkdirPublish.parent_metadata`'s type to the new `Node`/`FolderMetadata`-analog shape as PART of the Node-enum cutover wave (not a follow-up), and add a fail-closed (log + skip, not panic) deserialize-failure path in the journal replay loop so a stale pre-cutover on-disk entry from a developer's own local testing doesn't crash the mount on next launch.
**Warning signs:** A `cargo build` failure in `crates/fuse` for `journal_helpers.rs` that surfaces only after the Node-enum wave is otherwise complete — this is expected and should be fixed in the SAME wave, not deferred.

### Pitfall 7: Windows CI/E2E gating — the "Cargo Check & Test (Windows)" job is path-gated, and desktop E2E is dispatch-only
**What goes wrong:** Assuming the `cargo-windows` CI job runs automatically on every push to the phase branch, or assuming the desktop E2E workflow runs on a normal PR trigger.
**Why it happens:** `.github/workflows/ci.yml`'s `cargo-windows` job (verified live read) is gated `if: needs.changes.outputs.desktop == 'true'` — it only runs when the changes-detection job flags `desktop`-scoped file changes; if this phase's file changes are miscategorized by the path filter (e.g., changes land only under `crates/core`/`crates/sdk` without touching anything the `desktop` path filter watches), the gate may not fire. Separately, `.github/workflows/desktop-e2e.yml` is `workflow_dispatch`-only (verified live read, no `push`/`pull_request` trigger) — it NEVER runs automatically and must be explicitly invoked (`gh workflow run "CI E2E Tests" --ref <branch>` per the ROADMAP/CONTEXT wording — **verify the exact `name:` field in `desktop-e2e.yml` at execution time**, since the file's `name:` was not fully re-confirmed against the literal string "CI E2E Tests" in this research pass).
**How to avoid:** After completing the phase's Rust changes, explicitly check the `changes` job's path-filter output for the PR/branch (or verify `crates/`-path changes are covered by the `desktop` filter category) rather than assuming the Windows gate ran; explicitly run `gh workflow run <exact-workflow-name> --ref <branch>` for the desktop E2E dispatch before phase sign-off, per TEST-03/SC#5.
**Warning signs:** A phase-completion check that only greps CI status for "cargo-windows" without confirming the job actually executed (vs. being skipped by the path filter) or was queued at all.

## Code Examples

### RotationHighWater — full logic to port (lowest-risk, highest-confidence target)
```typescript
// Source: packages/sdk/src/state/rotation-high-water.ts (verified live read, full file)
function isValidFloorValue(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) &&
         Number.isSafeInteger(value) && value >= 0;
}
// enforceResolved: fail-closed on the LIVE inputs first (NaN compares false against everything
// in JS — a malformed generation/seq must be rejected BEFORE the floor comparison, not just on
// write). Then: generationFloor check (throw GenerationRegressionError if regressed), then EITHER
// the cold-device versionFloor gate (no local seq floor yet) OR the seq floor check, then bump
// both floors monotonic-max. This exact ordering (validate live input -> check generation floor
// -> cold-device-or-seq-floor branch -> bump) must be preserved in the Rust port.
```

### hasCoveringGrant / maybeRotateOnScopeExit — full source (direct port target)
```typescript
// Source: packages/sdk-core/src/rotation/scope.ts (verified live read, full 160-line file — see
// Architecture Patterns > Pattern 1 above for the complete reproduction)
```

### Current Rust ECIES swap sites (SC#1) — verified exact locations
```rust
// Source: crates/fuse/src/inode.rs:434 (folder key) and :452 (folder's IPNS private key)
let folder_key = cipherbox_crypto::ecies::unwrap_key(&encrypted_folder_key_bytes, private_key)...;
let ipns_private_key = cipherbox_crypto::ecies::unwrap_key(&encrypted_ipns_key_bytes, private_key)...;
// Source: crates/fuse/src/inode.rs:658 (swapped file's IPNS key) and :716 (fresh FilePointer's IPNS key)
// Source: crates/fuse/src/replay.rs:365 (child folder key during BFS resolve_folder_key walk)
let child_folder_key = cipherbox_crypto::ecies::unwrap_key(&enc_key_bytes, private_key)...;
```
Each of these becomes, post-Node-model, a call chain roughly: `unseal_child_read_key(sealed_child_ref.read_key_sealed, parent_read_key, child_id, child_kind, sealed_child_ref.generation)` → `unseal_node(published_node, child_read_key)`, using `build_node_aad` internally with role `0x02` (child-readkey) — no ECIES involved for any node-to-node hop (ECIES remains ONLY for the vault-blob root-key wrap, NODE-06).

### spawn_file_meta_reencrypt deletion targets (SC#2) — verified exact locations
```
crates/fuse/src/metadata.rs:777      pub fn spawn_file_meta_reencrypt(...)  — DELETE (150 lines, incl. retry/backoff logic)
crates/fuse/src/write_ops/implementation/rename.rs:248   crate::spawn_file_meta_reencrypt(...)  — caller, DELETE call site
crates/fuse/src/platform/windows/write_ops.rs:1183       crate::spawn_file_meta_reencrypt(...)  — caller, DELETE call site (Windows-plan scope)
```

### Journal WriteQueue sidecar adjacency point (D-03 durable floor home)
```rust
// Source: crates/sdk/src/queue.rs:216, :267 (verified live read)
pub fn new(journal_dir: PathBuf, max_retries: u32) -> Self { /* ... */ }
pub fn sidecar_path_for(&self, id: &str) -> PathBuf { /* returns <journal_dir>/<id>.bin */ }
// D-03 recommendation: a sibling file, e.g. <journal_dir>/rotation-high-water.json, written
// atomically (temp-file + rename, matching the existing 0600-permission sidecar convention)
// alongside the per-entry .bin sidecars this struct already manages.
```

### Windows CI gate — exact command sequence (TEST-03 authoritative check)
```yaml
# Source: .github/workflows/ci.yml:590-633 (verified live read, job `cargo-windows`)
# Gated: needs.changes.outputs.desktop == 'true'; runs-on: windows-latest
# Pre-step: installs WinFsp v2.1.25156 MSI (hash-pinned) before any cargo command.
- run: cargo check --workspace --no-default-features --features winfsp
- run: cargo test --workspace --no-default-features --features winfsp
```

## State of the Art

| Old Approach | Current/Target Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| ECIES fan-out per-recipient child-key unwrap (`crates/fuse/src/inode.rs`/`replay.rs`) | Single symmetric `unseal_aes_gcm_aad` hop per parent→child edge, AAD-bound via `build_node_aad` | This phase (SC#1), mirrors TS Phase 62/63 | O(depth) symmetric ops replace O(recipients) ECIES ops per navigation; matches READ-02's already-shipped TS cost model |
| Parent-folder-key-sealed `FileMetadata` requiring re-encrypt-on-move (`spawn_file_meta_reencrypt`) | Each `Node` self-seals its own read-body under its own `readKey`; a move is a pure `SealedChildRef` relink, 0 re-encrypts | This phase (SC#2), mirrors TS design doc §3.5 | Eliminates an entire class of fire-and-forget background re-encrypt jobs with retry/backoff/idempotency logic (150 lines deleted outright) |
| Unconditional `revoke_shares_blocking` on every delete/rmdir | Grant-root-gated rotation: `has_covering_grant` decides zero-rotation (private) vs. `rotate_read_from_node` (shared scope-exit) | This phase (SC#3), mirrors TS ROT-02/design §3.6 | Private deletes (the overwhelming majority of a typical vault) drop from "always call the shares API + revoke" to a pure local relink — matches the TS "no covering grant ⇒ 0 rotation" hard invariant that does NOT exist in Rust today |
| `Option`-bag-style `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` (4 loosely-related structs) | A single `enum Node { Folder{..}, File{..}, Root{..} }` — impossible states unrepresentable | This phase (SC#4/NODE-05), mirrors TS Phase 62 (already shipped) | Matches the already-completed TS-side type-safety improvement; Rust's own type system makes this MORE natural than TS's structural typing, not less |
| In-memory-only, restart-losing `resolve_sequence_strict` (sequence-only, no generation check) | Durable JSON-sidecar `{nodeId -> generation, seq}` floor, survives daemon restart, fails closed on regression | This phase (SC#4/D-03), mirrors TS ROT-07/M1 (Phase 68, already shipped) | Closes the M1 generation-downgrade defense gap design doc §4.3 explicitly flags as "new work, not an extension" — confirmed live: no Rust resolve path enforces a generation check today |

**Deprecated/outdated:**
- ECIES-wrapped per-child keys in `FolderEntry.folder_key_encrypted`/`FilePointer.ipns_private_key_encrypted`: superseded by AES-GCM-AAD symmetric child-key sealing (`SealedChildRef.readKeySealed`), this phase.
- `spawn_file_meta_reencrypt` fire-and-forget re-encrypt-on-move: dead code by construction once nodes self-seal (this phase).
- Blanket `revoke_shares_blocking` on every delete: replaced by grant-root-gated rotation (this phase).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The exact `name:` field in `.github/workflows/desktop-e2e.yml` matches the literal string "CI E2E Tests" that ROADMAP SC#5/CONTEXT.md's dispatch command references | Phase Requirements / Pitfall 7 | Low — if wrong, `gh workflow run "CI E2E Tests"` fails with a not-found error and the executor simply needs to `gh workflow list` to find the correct name before dispatching; does not block planning, only a pre-execution detail to re-verify |
| A2 | No property-based testing crate (`proptest`/`quickcheck`) should be introduced for the rotation-engine port; hand-written test cases mirroring the existing `packages/sdk-core/src/__tests__/rotation/engine.test.ts` shape are the right pattern | Standard Stack > Alternatives Considered | Low-medium — if the planner/executor judges the BFS/crash-resume state space too large for hand-written cases, introducing `proptest` is a reasonable deviation, but it would be a NEW workspace dependency requiring its own justification, not assumed here |
| A3 | Hoisting `has_covering_grant`/the ancestor-walk helper into a shared module (rather than duplicating between Unix FUSE and WinFsp) is the right call, given D-06 explicitly isolates WinFsp as its own plan | Pitfall 1 | Medium — if the planner instead deliberately duplicates for isolation reasons (e.g., WinFsp plan literally cannot depend on new `crates/fuse` internals not yet stabilized when it starts), that's a legitimate call; flagging here only because un-flagged duplication is the likelier failure mode |

**If this table is empty:** N/A — see entries above; all are LOW-MEDIUM risk process/sequencing judgments, not unverified factual claims about the codebase (every factual claim about existing Rust/TS code in this document was verified via live `Read`/`Bash grep` in this research session).

## Open Questions

1. **Does the WinFsp plan (D-06) consume the grant-scope predicate from `crates/sdk` or from a `crates/fuse`-shared module?**
   - What we know: D-06 requires WinFsp to consume "the same `crates/sdk` listing/gate API" as FUSE for the READ side; CONTEXT.md is silent on whether the grant-root SCOPE predicate (a write-path concept) has the same sharing requirement.
   - What's unclear: Whether `has_covering_grant`/the ancestor-walk belongs in `crates/sdk` (available to both platforms uniformly) or in a `crates/fuse`-internal module that WinFsp's `platform/windows/write_ops.rs` also happens to have access to (since `platform/windows` lives inside the `crates/fuse` crate today, behind the `winfsp` feature flag — NOT a separate crate).
   - Recommendation: Since `crates/fuse/Cargo.toml` shows WinFsp code lives INSIDE `crates/fuse` (feature-gated, not a separate crate), a `crates/fuse`-internal shared module (Pitfall 1's recommendation) is sufficient and avoids widening `crates/sdk`'s surface with FUSE-specific ancestor-walk logic. Confirm this reading with the planner before committing to a specific module location.

2. **What is the exact shape of the new `crates/api-client` grant-root query the rotation engine needs?**
   - What we know: `GET /shares/sent` exists server-side (`apps/api/src/shares/shares.controller.ts:134`) and is what the TS web client actually calls to populate its local `sentShares` cache; `crates/api-client/src/shares.rs` has no wrapper for it today.
   - What's unclear: The exact response DTO shape (pagination? filtering by rootIpnsName?) needed to build `active_grant_root_ipns_names: HashSet<String>` efficiently for a potentially large vault with many shares.
   - Recommendation: Read `apps/api/src/shares/shares.controller.ts:134-169` and its DTO (`GetSentSharesDto`/response type) at plan time to size this new `crates/api-client` function precisely; this research pass confirmed the endpoint's EXISTENCE and call pattern but did not fully characterize its response schema.

3. **Should `crates/core`'s Node write-body (`NodeWriteBody`/`WriteChildRef`) be scoped fully in THIS phase, or is a read-only Node sufficient for SC#1/SC#4, deferring write-body support to the rotation-engine wave?**
   - What we know: D-07 is a hard constraint that FUSE/WinFsp thread `WriteChildRef.childId` through delete/move/rename — this requires the write-body type to exist in `crates/core` before `crates/fuse`'s write_ops wave can satisfy D-07.
   - What's unclear: Whether the Node-enum wave (wave 1, per this research's recommended sequencing) should include `NodeWriteBody`/`WriteChildRef` types from the start, or whether they can land in the rotation-engine wave (wave 3) since write-body rotation (`rotateWriteFromNode`) is a separate TS concept from `rotateReadFromNode`.
   - Recommendation: Include `NodeWriteBody`/`WriteChildRef` in the wave-1 Node-enum/codec port (they are pure data types with no behavior dependency on the rotation engine) so wave 4 (FUSE write_ops grant-scope + dual-keying) has the types available without a cross-wave dependency stall.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain (stable) | All crates | ✓ (assumed CI/dev standard; not independently re-verified this session — `[ASSUMED]` based on existing workspace `Cargo.toml` `edition = "2021"` and CI's `rustup default stable`) | stable (per `ci.yml:618`) | — |
| WinFsp (Windows platform layer) | `crates/fuse` `winfsp` feature, D-06 | ✓ (CI-verified: installed via hash-pinned MSI in `cargo-windows` job) | v2.1.25156 (pinned in `ci.yml:605`) | User's local Windows machine must independently install WinFsp v2.1+ for local iteration (D-06 notes user develops WinFsp locally on Windows) — not verified this session whether the user's machine already has it |
| macOS FUSE-T | `crates/fuse` `fuse` feature, macOS local dev | ✓ (CI-verified: `brew install --cask fuse-t` in `cargo-macos` job) | Version pinned via `sudo sed` version-string patch in CI (`2.9.9`) | — |
| `winfsp` Rust crate v0.12 | WinFsp binding | ✓ (already in `crates/fuse/Cargo.toml`) | 0.12, `system` feature | — |
| `fuser` Rust crate v0.16 | Unix FUSE binding | ✓ (already in `crates/fuse/Cargo.toml`) | 0.16, `libfuse` feature | — |
| GitHub CLI (`gh`) | TEST-03 dispatch-gated desktop E2E trigger | `[ASSUMED]` — not verified in this research session; project memory (`feedback_gh_auth.md`) notes `gh` requires `env -u GITHUB_TOKEN` prefix in this environment | — | If `gh` is unavailable, dispatch via the GitHub web UI's "Run workflow" button on `desktop-e2e.yml` as a manual fallback |

**Missing dependencies with no fallback:** None identified as blocking — all core Rust/crate dependencies are already present in the workspace.

**Missing dependencies with fallback:** `gh` CLI availability for the TEST-03 dispatch step has a manual web-UI fallback.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]`/`#[tokio::test]` (no `proptest`/`quickcheck` in any workspace `Cargo.toml` — verified via `grep`); cross-language KAT pattern via `tests/vectors/*.json` fixtures loaded in `crates/crypto/tests/cross_language.rs`-style integration test files |
| Config file | None — standard `cargo test` per-crate; CI invokes `cargo test --workspace --no-default-features --features winfsp` (Windows) and an analogous `--features fuse` (or default-features) invocation for macOS/Linux (confirm exact macOS/Linux cargo-test invocation at plan time — this research verified the Windows job's exact commands but did not re-confirm the macOS job's `cargo test` invocation string) |
| Quick run command | `cargo test -p cipherbox-core node_codec` (once the new `crates/core/src/node/` module + its tests exist) / `cargo test -p cipherbox-sdk rotation` (once `crates/sdk/src/rotation/` exists) |
| Full suite command | `cargo test --workspace --no-default-features --features winfsp` (Windows, exact CI command); `cargo check --workspace && cargo test --workspace` (macOS/Linux, default `fuse` feature) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEST-03 | WinFsp read-path validated via Windows CI gate | integration (CI-gated) | `cargo check --workspace --no-default-features --features winfsp && cargo test --workspace --no-default-features --features winfsp` | ✅ job exists (`ci.yml` `cargo-windows`), ❌ new Rust rotation/read-chain test files needed — Wave 0 |
| SC#1 (ECIES→symmetric swap) | `unseal_node`/`unseal_child_read_key` recover the same keys the legacy ECIES path did | unit | `cargo test -p cipherbox-core node_seal` (new) | ❌ Wave 0 — new test file mirroring `packages/core/src/__tests__/node-codec.test.ts` shape |
| SC#2 (`spawn_file_meta_reencrypt` deletion) | Cross-folder file move requires zero re-encrypt calls; grep-verified absence | static (grep gate) | `grep -rn "spawn_file_meta_reencrypt" crates/fuse/src/` returns empty | ✅ command exists (see Code Examples), not yet wired as a CI gate |
| SC#3 (grant-root awareness) | Private delete = zero rotation; shared-scope-exit delete = exactly one `rotate_read_from_node` call | unit (mock/spy injection, mirrors `scope.test.ts`) | `cargo test -p cipherbox-sdk has_covering_grant` (new) | ❌ Wave 0 — new test file; the injectable `rotate` closure pattern (mirrors TS `deps.rotate: () => Promise<void>` spy) must be ported to enable this assertion |
| SC#4 (Node enum + durable floor) | KAT vectors pass; floor survives simulated daemon restart (drop and recreate the sidecar-store struct, confirm floor persists) | unit + KAT | `cargo test -p cipherbox-core --test node_codec_vectors` (new); `cargo test -p cipherbox-sdk floor_store_restart` (new) | ❌ Wave 0 — both new |
| SC#5 (Windows CI + desktop E2E) | See TEST-03 above | CI + manual dispatch | `gh workflow run <exact-name> --ref <branch>` | ✅ workflow exists, dispatch is a manual executor action |
| SC#6 (68.2 parity — single gated listing entrypoint) | `crates/fuse`/WinFsp never call raw resolve; grep-verified single entrypoint | static (grep gate, mirrors 68.2's own D-07 grep-gate pattern) | New grep command analogous to 68.2's `grep -rnE "resolve_ipns" crates/fuse/src/ | grep -v listing.rs` (exact command TBD at plan time — the 68.2 grep-gate SHAPE is the pattern to reuse, not its literal TS-specific regex) | ❌ Wave 0 — new grep gate, adapt 68.2's two-step type-only-import-aware approach is NOT needed in Rust (no type-only-import ambiguity), so this gate is simpler than 68.2's |

### Sampling Rate
- **Per task commit:** targeted `cargo test -p <crate> <pattern>` for the crate touched (fast — this workspace's existing test suites run in seconds per project memory's velocity table).
- **Per wave merge:** full `cargo check --workspace` + `cargo test --workspace` (default features) locally; defer the Windows-feature build to CI (per D-06, do not assume fast local Windows iteration).
- **Phase gate:** `cargo-windows` CI job green + explicit `gh workflow run` dispatch of the desktop E2E workflow green, per TEST-03 — run as the LAST step before `/gsd-verify-work`, mirroring 68.2's own "grep gate + full e2e as final step" discipline.

### Wave 0 Gaps
- [ ] `crates/core/src/node/` module + a new `crates/core/tests/node_codec_vectors.rs` (or `crates/crypto/tests/cross_language.rs` extension) asserting byte-identical output against `tests/vectors/node-codec.json` and `tests/vectors/crypto/node-aad.json`
- [ ] `crates/sdk/src/rotation/high_water.rs` + unit tests mirroring `packages/sdk/src/__tests__/client-rotation.test.ts`'s floor-regression assertions
- [ ] `crates/sdk/src/rotation/scope.rs` + unit tests mirroring `packages/sdk-core/src/__tests__/rotation/scope.test.ts`'s spy-based zero-rotation assertion (SC#3's signature test)
- [ ] `crates/sdk/src/floor_store.rs` (JSON sidecar) + a restart-survival test (drop the struct, recreate over the same path, confirm the floor value persists)
- [ ] A grep-gate script for SC#6 (single gated read entrypoint), CI-wired or documented as a phase-gate manual check
- [ ] Framework: none to install — existing `cargo test` infrastructure covers this phase's needs

## Security Domain

### Applicable ASVS Categories
| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Unaffected — this phase does not touch Web3Auth/login |
| V3 Session Management | No | Unaffected |
| V4 Access Control | Yes | The grant-root scope-exit gate (`has_covering_grant`) IS an access-control mechanism — it decides whether a revocation-equivalent rotation fires; the ROT-07 durable floor (`enforce_resolved`) is likewise access-control (prevents a rolled-back/stale record from re-granting access) |
| V5 Input Validation | Yes | `enforce_resolved`'s `isValidFloorValue`-equivalent fail-closed check (reject NaN/negative/non-integer generation/seq BEFORE comparison) is exactly a V5 control; the Node codec's `build_node_aad` already fails closed on malformed kind/role/UUID (Phase 61, unaffected by this phase) |
| V6 Cryptography | Yes | AES-GCM-AAD seal/unseal (`unseal_node`/`unseal_child_read_key`) is the frozen primitive (ADR 0003) this phase's call sites migrate TO — must not be reimplemented, only its call sites change (ECIES → symmetric) |

### Known Threat Patterns for this stack
| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious/buggy relay omits a grant-root from the "active grant roots" set to suppress rotation | Tampering / Elevation of Privilege | `has_covering_grant` cross-checks the relay set AGAINST the client's own `local_grant_record` — either source covering an ancestor triggers rotation (T-63-17 mitigation, mirrored from TS) |
| Colluding relay withholds a rotation-publish, keeps serving an old signed record (generation-downgrade) | Tampering | Durable client-side `{nodeId -> generation, seq}` floor (D-03/M1) — fails closed on regression; this is genuinely NEW Rust-side coverage (no resolve path enforces a generation check in Rust today, confirmed live) |
| Zeroizing a reused/caller-owned key buffer inside a rotation callee (data-corruption / functional-security bug, not classic STRIDE but security-relevant per project history) | Tampering (of in-memory key material availability) | D-09 terminal-owner rule: `rotate_one` zeros ONLY its own minted `read_key_prime`, only on its own failure paths — never a caller-supplied buffer (documented historical incident: 48/89 sdk-e2e failures) |
| Write-plane/read-plane key conflation (`WriteChildRef.childId` vs `SealedChildRef.ipnsName`) silently breaking `rotateWriteFromNode` | Tampering / Denial of Service | D-07 hard constraint: both keys threaded through every shared-write delete/move/rename; explicit security review flagged for `crates/fuse/src/write_ops/` |
| Concurrent add during a large rotation walk silently dropped (re-seal from stale child list on CAS-409) | Tampering / Denial of Service (data loss) | HIGH-4: re-fetch + re-merge `SealedChildRef[]` on every CAS-409, never blind re-seal from the in-memory list |
| Orphaned inner grant (deep independently-shared node inside a rotating subtree not re-minted) | Elevation of Privilege (revoked access) / Denial of Service (legitimate grantee locked out) | HIGH-3: query all `shares` rows rooted at every rotated node, re-mint `readDescriptorRef` for non-revoked recipients |
| Revoked reader retains access to already-published content/CIDs after read-revoke | (Accepted residual, not a defect) | ADR 0002: read-revocation protects future navigation/writes only; CRIT-1's lazy `fileKey` rotation (`contentRekeyPending`) is the only content-side mitigation, applied on next write, not retroactively |

## Sources

### Primary (HIGH confidence — live codebase reads + `git show`, this session)
- `git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:.planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/{68.2-CONTEXT,68.2-RESEARCH,68.2-PATTERNS,68.2-VALIDATION}.md` — the 68.2 mirror contract (`ResolvedChild`, `RotationHighWater` reuse, D-04/D-05 gate-first-resolve pattern)
- `crates/fuse/src/{inode,replay,metadata}.rs`, `crates/core/src/folder.rs`, `crates/crypto/src/aes.rs` — current Rust baseline, exact swap-site line numbers, existing AAD primitive
- `crates/fuse/src/write_ops/implementation/{delete,rename}.rs`, `crates/fuse/src/journal_helpers.rs`, `crates/sdk/src/{queue,client,state}.rs` — current write-path/journal/sidecar structure
- `packages/sdk-core/src/rotation/scope.ts` (full file), `packages/sdk-core/src/rotation/engine.ts` (partial, ~250 of 1000+ lines), `packages/sdk/src/state/rotation-high-water.ts` (full file), `packages/sdk/src/client.ts` (lines 1140-1300, the `performScopeExitRotation`/`enumerateMoveDescendants` composition), `packages/core/src/node/types.ts` (full file) — TypeScript reference implementations
- `apps/web/src/services/rotation-driver.service.ts` (lines 180-222) — the actual shipped `activeGrantRootIpnsNames`/`localGrantRecord` source (local cache, not live query — Pitfall 2 finding)
- `crates/api-client/src/shares.rs`, `apps/api/src/shares/shares.controller.ts` — confirmed `GET /shares/sent` exists server-side with no Rust wrapper today
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §3.4-3.11, §4.1-4.8, §5.1-5.3 — the full design rationale for scope computation, rotation ordering, CRIT-1/M1/HIGH-3/HIGH-4
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md`, `docs/adr/0002-read-revocation-protects-future-content-only.md`, `docs/adr/0003-aad-bound-node-seal-encoding.md` — full text read
- `docs/METADATA_SCHEMAS.md` §14 (Cross-Implementation Parity table, explicitly naming Phase 69 as the Rust-twin phase) — confirmed this phase was anticipated at doc-authoring time
- `.github/workflows/ci.yml` (lines 585-660, `cargo-windows`/`cargo-macos` jobs), `.github/workflows/desktop-e2e.yml` (trigger/matrix) — CI gate mechanics for TEST-03
- `tests/vectors/node-codec.json`, `tests/vectors/crypto/node-aad.json` — KAT fixture shapes (partial reads, structure confirmed)
- `crates/fuse/Cargo.toml`, root `Cargo.toml` — dependency/version confirmation, `winfsp` v0.12 already integrated

### Secondary (MEDIUM confidence)
- `packages/sdk-core/src/rotation/engine.ts` lines beyond the ~250 read live in this session (the full 1000+-line file was not read end-to-end; the rotate_one internals, `verifySubtreeClean`, and grant-remint callback wiring beyond the excerpts shown were characterized from the design doc + partial reads, not a full line-by-line read)
- `apps/api/src/shares/shares.controller.ts`'s `GET /shares/sent` exact response DTO shape (endpoint existence confirmed; full DTO not read — Open Question 2)

### Tertiary (LOW confidence / `[ASSUMED]`)
- Rust toolchain version available on the executing agent's own machine (not independently verified this session — inferred from CI's `rustup default stable`)
- `gh` CLI availability for the TEST-03 dispatch step (inferred from project memory, not re-verified live)
- Whether `proptest`/`quickcheck` would be the "right" testing addition for the rotation engine port (a judgment call flagged in Assumptions Log A2, not a verified recommendation)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — zero new dependencies, every crate/version confirmed live against workspace `Cargo.toml`
- Architecture (grant-root algorithm, rotation engine port, gate-first-resolve): HIGH for the TS reference implementation facts (full/near-full live reads of `scope.ts`, `rotation-high-water.ts`, `types.ts`, partial `engine.ts`, `client.ts` composition); MEDIUM for the Rust-side port risk assessment (this exact port has not been attempted before — no prior-phase precedent in Rust to compare against, unlike most other phases in this project's history)
- Pitfalls: HIGH — five of seven pitfalls are direct restatements of explicitly-documented TS-side incidents/design-doc warnings (zeroization ownership, generation-source rule, relay-completeness-aid, per-node-commit crash safety, journal schema coupling); two (WinFsp duplication, Windows CI gating) are inferred from live workflow-file reads

**Research date:** 2026-07-06
**Valid until:** 14 days (this phase touches a fast-moving in-flight milestone — Phase 68.2 on the TS side is still mid-execution on its own branch per the `git show` reads above; re-verify the 68.2 mirror contract facts if this phase's planning/execution is delayed beyond ~2 weeks, since 68.2 could land with a different final shape than its CONTEXT/RESEARCH drafts describe)
