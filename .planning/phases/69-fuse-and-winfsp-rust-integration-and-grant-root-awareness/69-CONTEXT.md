# Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness - Context

**Gathered:** 2026-07-06
**Status:** Ready for planning

<domain>
## Phase Boundary

Port the `node/v3` model to the entire Rust desktop stack and make the FUSE/WinFsp clients grant-root-aware. The Rust core/SDK crates gain the read chain, rotation engine, and durable anti-rollback floors that TypeScript already has; the FUSE/WinFsp layers become thin adapters over an owning Rust SDK.

**Scope anchor (ROADMAP SC#1–#6):**

1. Replace all `cipherbox_crypto::ecies::unwrap_key` child-key unwraps in `crates/fuse/src/inode.rs` (lines 434, 452, 658, 716) and `crates/fuse/src/replay.rs` (line 365) with `cipherbox_crypto::aes::unseal_aes_gcm_aad` symmetric unwrap using the correct `build_node_aad` AAD.
2. Delete `spawn_file_meta_reencrypt` from `crates/fuse/src/metadata.rs` and both callers (`write_ops/implementation/rename.rs:248`, `platform/windows/write_ops.rs:1183`).
3. Grant-root awareness in `delete`/`rename`/`move` FUSE paths: a shared-scope exit triggers the Rust `rotateReadFromNode` analog; a private delete with no active grants is a pure relink with zero rotation publishes.
4. `enum Node { Folder { children }, File { content }, Root { children } }` in `crates/core/src/`; durable generation + seq high-water persisted adjacent to the write journal (survives daemon restart).
5. `Cargo Check & Test (Windows)` CI gate passes; dispatch-gated desktop E2E (`gh workflow run "CI E2E Tests"`) passes before sign-off.
6. (68.2 parity) Read-chain resolve + durable anti-rollback floor gate + node unseal + child-metadata resolution live once in `crates/core`/`crates/sdk`; FUSE and WinFsp consume a resolved child-listing API — no duplicated resolve/unseal/gating inline.

**Current Rust baseline (from scout — this is a large port, not a crypto swap):**
- `crates/core` still holds the **legacy** `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` (`crates/core/src/folder.rs`). The `Node` enum does not exist in Rust yet.
- There is **no** `rotate_read`/`grant_root` anywhere in Rust. The read-rotation engine (TS phases 63/64) has no Rust analog.
- The FUSE read path still does ECIES fan-out unwrap of child folder/IPNS keys — i.e. it is on the pre-v2.0 model.
- `crates/crypto` **already** ships `seal_aes_gcm_aad` / `unseal_aes_gcm_aad` / `build_node_aad` (Phase 61) — SC#1's primitive dependency is met.
- `crates/sdk` already exists (client/sync/state/queue/registry) — the "dedicated Rust SDK crate" the roadmap allows is already present.
- The FUSE journal is an **on-disk sidecar dir** (`journal.sidecar_path_for(...)`) — the natural home for SC#4's durable floors.

</domain>

<decisions>
## Implementation Decisions

### 68.2 reference — build now, mirror the design (D-01)
- **D-01:** Build the Rust read chain **now**; do not block on TS Phase 68.2 shipping. The Rust stack has no `node/v3` read chain today, so 69 builds it fresh regardless — the only question is what it mirrors.
- **The contract comes from the Phase 68.2 planning docs**, already pushed to branch `origin/feat/sdk-owned-read-chain-and-resolved-folder-listings`.
- **ACCESS RULE (hard):** That branch is checked out in the **main worktree**, so `git checkout` / `git switch` to it **will fail** here. Downstream agents MUST read those docs via `git show <ref>:<path>` (e.g. `git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:.planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/68.2-CONTEXT.md`). Never attempt to check the branch out.
- **What to mirror (from 68.2-CONTEXT):**
  - `ResolvedChild` = `{ ipnsName, name, kind, size?, modifiedAt, sequence }` — the single per-child metadata carrier, resolved once per folder load and cached in the SDK. Rust analog: `ResolvedChild { ipns_name, name, kind, size, modified_at, sequence }`.
  - SDK exposes an **imperative pull + event push** model: `listFolder(ipnsName)` / `listSharedFolder(...)` → `ResolvedChild[]`, plus a `folder:updated` event. Rust analog on `crates/sdk`.
  - **68.2 D-04:** the roadmap's "DurableFloorStore" IS the reused `RotationHighWater` + `HighWaterStore` seam (`packages/sdk/src/state/rotation-high-water.ts`); the gated read routes through `RotationHighWater.enforceResolved`. Rust analog: a `RotationHighWater`-equivalent in `crates/sdk` over an injected store trait.
  - **68.2 D-05:** the gated listing path is the **single** read entrypoint and always enforces the floor gate; raw `resolveIpnsRecord` is SDK-internal only. Rust: FUSE/WinFsp never call raw resolve.

### Read-chain crate placement (D-02)
- **D-02:** Mirror the TS `packages/core` vs `packages/sdk` split:
  - `crates/core` owns **pure** IPNS-resolve + node-unseal + per-child metadata resolution + the `Node`/`SealedChildRef` codec.
  - `crates/sdk` owns the **stateful** layer: the anti-rollback gate (`RotationHighWater` analog), the durable floor store, and the resolved child-listing API (`ResolvedChild`).
  - `crates/fuse` and the WinFsp paths **consume the resolved listing from `crates/sdk`** — no inline resolve/unseal/gating.

### Durable floor persistence (D-03)
- **D-03:** Persist the generation + seq high-water as a **JSON sidecar file adjacent to the journal dir**, behind an **injected `HighWaterStore`-analog trait** (the FUSE daemon supplies the concrete path/impl; `crates/sdk` owns the gating logic). This mirrors 68.2's injected store (browser supplies persistence, SDK owns gating) and reuses the journal's existing sidecar pattern. Atomic write, no new storage dependency. Rejected: embedded KV (sled/redb) and sqlite — heavyweight for a handful of monotonic counters and a new runtime dep in the daemon.

### Node enum cutover (D-04)
- **D-04:** **Clean cutover (Phase-62 style).** Introduce `enum Node`, **delete** the legacy `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` from `crates/core`, migrate **every** FUSE/`replay`/`metadata` call site in this phase, and conform to the **frozen cross-language KAT** (`tests/vectors/node-codec.json`, `tests/vectors/crypto/node-aad.json`). No coexistence/bridge — the greenfield single-codec doctrine forbids a dual model.

### Rotation-engine port scope (D-05)
- **D-05:** **Full in-phase port** of the TS 63/64 read-rotation engine into `crates/sdk` (consistent with D-02 — the SDK owns stateful ops). It is the **dominant plan-cluster**, sequenced **after** the Node-enum + read-chain foundation lands. Must reach parity on: resumable/crash-safe execution, **CRIT-1** content-key rotation, **M1** generation-downgrade defense, **HIGH-3** multi-rooted grant re-mint, **HIGH-4** add-during-rotation merge. This fully satisfies SC#3/#6 within Phase 69. (Rejected splitting it into a 69.1 follow-up — that would leave SC#3's rotation trigger fail-closed and require a roadmap change.)
- **Note:** the **grant-root scope-computation algorithm** (`crates/fuse/src/write_ops/`) is ROADMAP-flagged as net-new and **requires a plan-time design pass** before implementation. Route it to research/planning; do not treat it as decided here.

### WinFsp / Windows sequencing (D-06)
- **D-06:** WinFsp is **in-phase** but **isolated as its own plan** (or plan-cluster) built against the **same `crates/sdk` listing/gate API** as FUSE. The **user will execute the WinFsp plan on a Windows machine** — so planning must NOT assume long CI round-trips for WinFsp iteration. The `Cargo Check & Test (Windows)` CI gate + dispatch-gated desktop E2E remain the **sign-off authority** (SC#5), but development/iteration happens on the user's local Windows box. Build + verify the `crates/core`/`crates/sdk` + macOS/Linux FUSE path first, then the Windows platform layer.

### Write-plane dual-keying (D-07) — HARD CONSTRAINT
- **D-07:** Every FUSE/WinFsp shared-write `delete`/`move`/`rename` path MUST thread **both** the write-body `WriteChildRef.childId` (node UUID) **and** the read-body `SealedChildRef` (ipnsName). Conflating the two silently breaks `rotateWriteFromNode` (the write plane is keyed by UUID, the read plane by ipnsName). This is a **locked constraint**, not a suggestion, and the `crates/fuse/src/write_ops/` files are **flagged for explicit security review** to confirm childId/ipnsName are never conflated.

### Q3 — write-recipient-vs-owner sub-share authority (D-08, carried forward)
- **D-08:** FUSE mirrors **Phase 65 Q3 = Model (a)** (reconcile-on-owner-sync). When a write-recipient C deletes/moves-out a node the owner independently sub-shared to D, C's path **unlinks + bins** with **no cross-principal revoke attempt** and **no new schema**; the owner's reconcile+rotation pass re-derives dangling grants. The D-exposure window (until the owner's next online reconcile) is an **accepted documented residual** (ADR 0002: binned content is already irreducibly readable). No re-decision needed — carried from `65-CONTEXT.md` D-01.

### Claude's Discretion
- Exact Rust type/field naming (`ResolvedChild`, the floor-store trait name, the `folder:updated`-analog event mechanism) and error shapes — follow existing `crates/sdk` conventions and 68.2 naming where it maps cleanly.
- Whether the read chain warrants any new module split within `crates/core`/`crates/sdk` vs. new files in existing modules — planner's call from the call-site blast radius.

### Folded Todos
- **`.planning/todos/2026-06-24-replay-reuse-verified-parent-sequence.md`** — "Reuse the verified parent sequence in replay instead of re-resolving" (area: fuse). The SC#6 read-chain consolidation reworks `crates/fuse/src/replay.rs` resolve entirely (resolve moves into `crates/sdk`), so this is **addressed/superseded** by the consolidation. Verify it is genuinely resolved before retiring it at phase close.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### 68.2 mirror — the read-chain contract (READ VIA `git show`, DO NOT CHECK OUT)
Branch: `origin/feat/sdk-owned-read-chain-and-resolved-folder-listings` (live in the main worktree — `checkout` will fail; use `git show <ref>:<path>`).
- `.planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/68.2-CONTEXT.md` — locked decisions: `ResolvedChild` shape, `listFolder`/`listSharedFolder` + `folder:updated`, `RotationHighWater.enforceResolved` = the "DurableFloorStore", single-gated-entrypoint rule (D-04/D-05).
- `.../68.2-RESEARCH.md` — how the SDK-owned gated read chain is implemented on the TS side.
- `.../68.2-PATTERNS.md` — file mapping for the consolidation.
- `.../68.2-VALIDATION.md` and `.../68.2-01..12-PLAN.md` — the concrete task breakdown to mirror on the Rust side.

### Design source of truth
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — read key-chaining + rotation engine; §3.5 (move-within-scope reseal), §5.3 (write-rotation is not a subset of read-rotation).
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation = full Ed25519 rotation (context for the write plane).
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — bounds the Q3/D-08 exposure window.
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — the AAD-bound Node seal encoding (roles `0x01` write-body / `0x04` child-writekey) the Rust codec must match.

### Node codec + KAT (the Node-enum cutover oracle)
- `docs/METADATA_SCHEMAS.md` — `Node`/`SealedChildRef` frozen schema (incl. the NODE-03 five-field set); `ResolvedChild` field definitions.
- `docs/FILESYSTEM_SPECIFICATION.md` — encrypted filesystem / IPNS metadata layout.
- `tests/vectors/node-codec.json`, `tests/vectors/crypto/node-aad.json`, `tests/vectors/crypto/aes-gcm.json` — cross-language golden vectors; the Rust `Node` codec + `build_node_aad` unwrap MUST pass these (D-04).

### Prior-phase decisions to honor
- `.planning/phases/65-sdk-write-chain-bin-re-link-and-invite-claim/65-CONTEXT.md` — Q3 D-01 authority model (mirrored as D-08); write-plane dual-keying background.
- TS reference implementations to mirror: `packages/sdk/src/state/rotation-high-water.ts` (the `RotationHighWater`/`HighWaterStore` gate), `packages/sdk/src/client.ts` `ensureFolderLoaded`/`dfsFindFolder`, `packages/sdk-core/src/file/index.ts` `resolveFileMetadata`, `packages/core/src/node/{types,seal}.ts`.

### Project conventions
- `CLAUDE.md` — terminology standards, crypto rules (AES-256-GCM content, ECIES only for the share-root key wrap), string-literals-over-enums (TS), commit/PR hygiene.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/crypto`: `seal_aes_gcm_aad` / `unseal_aes_gcm_aad` / `build_node_aad` (aes.rs) — the SC#1 symmetric-unwrap primitive is already present and KAT-tested.
- `crates/sdk` (client/sync/state/queue/registry) — the target crate for the gate + floor store + resolved-listing API + rotation engine.
- FUSE journal sidecar (`journal_helpers.rs`, `journal.sidecar_path_for(...)`) — the adjacency point for SC#4's durable floor JSON sidecar.
- `crates/core` (bin/decrypt/file/folder/ipns/registry/vault_blob) — home of the new `Node` enum + pure resolve/unseal.

### Established Patterns
- Zeroization is terminal-owner-only: `unwrap_key` returns `Zeroizing<Vec<u8>>`; a callee receiving caller-owned buffers must NOT zero them. Preserve this when swapping ECIES→symmetric unwrap.
- Greenfield single-codec doctrine: no dual-codec bridge; clean cutover with the cross-language KAT as the conformance gate.

### Integration Points (ECIES → symmetric unwrap swap sites)
- `crates/fuse/src/inode.rs:434,452,658,716` and `crates/fuse/src/replay.rs:365` — SC#1 swap targets.
- `crates/fuse/src/metadata.rs` `spawn_file_meta_reencrypt` + callers `write_ops/implementation/rename.rs:248`, `platform/windows/write_ops.rs:1183` — SC#2 deletions (Windows caller verified in CI/on the user's Windows box).
- `crates/fuse/src/write_ops/` — grant-root scope computation (net-new, plan-time design pass required).

</code_context>

<specifics>
## Specific Ideas

- The Rust side should read like the TS side it mirrors: `crates/core` : `packages/core` :: `crates/sdk` : `packages/sdk`. The desktop client stays a thin FUSE/WinFsp adapter over an owning Rust SDK, so the duplication/desync class 68.2 removes on the web cannot recur in Rust.
- WinFsp iteration is the user's responsibility on a Windows machine — structure that plan so it is self-contained and runnable there, with the Windows CI gate as the objective sign-off.

</specifics>

<deferred>
## Deferred Ideas

- None raised that constitute new capabilities — discussion stayed within the phase's Rust-port scope.

### Reviewed Todos (not folded)
- **`2026-07-04-delete-should-drop-writechildref-not-just-retain.md`** (TS/sdk) — informs the D-07 write-plane dual-keying constraint for the Rust FUSE delete path, but folding it would not fix the TS side. Kept in backlog as a reference.
- **`2026-06-29-move-within-scope-reseal-child-readkey.md`** (TS/sdk-core, design §3.5) — the Rust move/rename path must mirror this reseal semantics; kept as a reference, not retired here.
- ~65 other matcher hits were area/keyword false positives (auth, search-index, web UI, TS-only rotation/share hardening) — not Phase 69 scope.

</deferred>

---

*Phase: 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness*
*Context gathered: 2026-07-06*
