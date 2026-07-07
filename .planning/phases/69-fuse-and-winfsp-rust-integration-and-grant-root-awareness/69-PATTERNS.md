# Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness - Pattern Map

**Mapped:** 2026-07-06
**Files analyzed:** 17 (new + modified, per RESEARCH.md "Recommended Project Structure")
**Analogs found:** 17 / 17 (every file has at least a TS mirror; most also have a Rust idiom analog)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog(s) | Match Quality |
|---|---|---|---|---|
| `crates/core/src/node/mod.rs` | model | transform | TS: `packages/core/src/node/types.ts` (barrel) | exact (TS mirror), no Rust precedent |
| `crates/core/src/node/types.rs` | model | transform | TS: `packages/core/src/node/types.ts` · Rust idiom: `crates/core/src/folder.rs` (struct/enum shape being replaced) | exact (TS) / role-match (Rust) |
| `crates/core/src/node/encode.rs` / `decode.rs` | utility (codec) | transform | TS: `packages/core/src/node/encode.ts` (+ decode) · Rust idiom: `crates/core/src/folder.rs::encrypt_folder_metadata`/`decrypt_folder_metadata` (serde_json + camelCase) | exact (TS) / role-match (Rust) |
| `crates/core/src/node/seal.rs` | service (crypto) | transform | TS: `packages/core/src/node/seal.ts` · Rust idiom: `crates/crypto/src/aes.rs` (`seal_aes_gcm_aad`/`unseal_aes_gcm_aad`/`build_node_aad`) | exact (TS) / exact (Rust primitive already built for this) |
| `crates/core/src/folder.rs` (DELETE) | model | CRUD | n/a — deletion target, D-04 clean cutover | n/a |
| `crates/core/src/bin.rs` (MODIFIED) | model | CRUD | current `crates/core/src/bin.rs` (self, in-place field repoint) | exact |
| `crates/core/src/decrypt.rs` (MODIFIED) | service | request-response | current `crates/core/src/decrypt.rs` (self) | exact |
| `crates/core/src/vault_blob.rs` (MODIFIED) | model | transform | current `crates/core/src/vault_blob.rs` (self); ECIES retained here only (NODE-06) | exact |
| `crates/sdk/src/rotation/high_water.rs` | store/gate | request-response | TS: `packages/sdk/src/state/rotation-high-water.ts` (full 188-line file) · Rust idiom: `crates/sdk/src/queue.rs` (trait-free struct + `Result<_, String>` error convention) | exact (TS) / role-match (Rust) |
| `crates/sdk/src/rotation/scope.rs` | service (pure predicate) | event-driven | TS: `packages/sdk-core/src/rotation/scope.ts` (full 160-line file) | exact |
| `crates/sdk/src/rotation/engine.rs` | service (orchestrator) | batch/event-driven | TS: `packages/sdk-core/src/rotation/engine.ts` (partial read, ~250/1000+ lines) + `packages/sdk/src/client.ts:1186-1258` (`performScopeExitRotation`) | exact (TS), no Rust precedent — dominant-effort cluster |
| `crates/sdk/src/floor_store.rs` | store (persistence trait + JSON sidecar impl) | file-I/O | Rust idiom: `crates/sdk/src/queue.rs` (`sidecar_path_for`, atomic temp-file+rename, 0600 perms, `journal_dir`-adjacent) | exact (Rust adjacency pattern); TS: 68.2 `HighWaterStore` injectable-store shape |
| `crates/sdk/src/listing.rs` | service (resolved child-listing API) | CRUD | TS (68.2, via `git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings`): `packages/sdk/src/client.ts` `listFolder`/`dfsFindFolder`/`ensureFolderLoaded` | exact (TS mirror), no Rust precedent |
| `crates/api-client/src/shares.rs` (MODIFIED — add `list_sent_shares`) | service (HTTP client wrapper) | request-response | current `crates/api-client/src/shares.rs::revoke_shares_for_items` (self, same file — add sibling fn) | exact |
| `crates/fuse/src/write_ops/grant_scope.rs` (or hoisted module) | utility (ancestor-walk + gate call) | event-driven | TS: `packages/sdk/src/client.ts:1186-1258` composition; Rust idiom: `crates/fuse/src/inode.rs` inode-tree walk conventions | role-match |
| `crates/fuse/src/write_ops/implementation/{delete,rename}.rs` (MODIFIED) | controller (syscall handler) | event-driven | current `crates/fuse/src/write_ops/implementation/{delete,rename}.rs` (self — replace `revoke_shares_blocking` call site) | exact |
| `crates/fuse/src/inode.rs` (MODIFIED, lines 434/452/658/716) | controller | request-response | current `crates/fuse/src/inode.rs` (self — swap ECIES call for symmetric unseal) | exact |
| `crates/fuse/src/replay.rs` (MODIFIED, line 365) | controller (BFS resolve walk) | batch | current `crates/fuse/src/replay.rs` (self) | exact |
| `crates/fuse/src/metadata.rs` (MODIFIED — delete `spawn_file_meta_reencrypt`) | service | event-driven | current `crates/fuse/src/metadata.rs` (self — deletion) | exact |
| `crates/fuse/src/journal_helpers.rs` (MODIFIED — `JournalOp::MkdirPublish.parent_metadata` type) | model | file-I/O | current `crates/fuse/src/journal_helpers.rs` + `crates/sdk/src/queue.rs` (`JournalEntry`/sidecar conventions) | exact |

## Pattern Assignments

### `crates/core/src/node/{types,encode,decode,seal}.rs` (model + codec + crypto-service)

**Primary analog — TS reference (mirror target):** `packages/core/src/node/types.ts`, `packages/core/src/node/seal.ts`, `packages/core/src/node/encode.ts`

Key TS type to port verbatim in shape (`crates/core/src/node/types.rs`):
```typescript
// Source: packages/core/src/node/types.ts:133-141 (verified live read)
export type WriteChildRef = {
  childId: string;         // hyphenated UUID — the WRITE-plane key
  writeKeySealed: string;  // AES-GCM seal of child's writeKey under parent writeKey, AAD role=0x04
};
// SealedChildRef (READ-plane) keys by `ipnsName`, NEVER `childId` — NODE-03 frozen 5-field set.
```

**Secondary analog — Rust crypto primitive already shipped** (`crates/crypto/src/aes.rs`, use directly from `seal.rs`, do not reimplement):
```rust
// crates/crypto/src/aes.rs:6-13 (imports)
use aes_gcm::{ /* Aes256Gcm, Nonce, aead traits */ };
use uuid::Uuid;
use crate::error::CryptoError;
use crate::utils::generate_iv;

// crates/crypto/src/aes.rs:128,140,160 (signatures — call these directly, do not re-wrap AEAD)
pub fn seal_aes_gcm_aad(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError>
pub fn unseal_aes_gcm_aad(sealed: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError>
pub fn build_node_aad(node_id: &str, /* kind, role, generation */) -> Result<Vec<u8>, CryptoError>
// build_node_aad is fail-closed: empty/malformed inputs -> Err(CryptoError::InvalidAadInput)
// (verified at aes.rs:167,170,172 — reject BEFORE any crypto op, same discipline node/seal.rs must follow)
```

**Rust codec/error-shape convention to follow** (from the file being deleted, `crates/core/src/folder.rs` — same error-enum + serialize/deserialize pattern, reuse for `node/encode.rs`):
```rust
// crates/core/src/folder.rs:10-20 (imports + error enum shape)
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;
use cipherbox_crypto::aes;
use cipherbox_crypto::error::CryptoError;

#[derive(Debug, Error)]
pub enum FolderError {
    #[error(...)]
    EncryptionFailed(#[from] CryptoError),
    // ...SerializationFailed, DeserializationFailed
}

// folder.rs:100-102, 114-115 — seal/unseal wrapper pattern to mirror in node/seal.rs
// (swap aes::seal_aes_gcm/unseal_aes_gcm for aes::seal_aes_gcm_aad/unseal_aes_gcm_aad + AAD param)
pub fn encrypt_folder_metadata(metadata: &FolderMetadata, folder_key: &[u8; 32]) -> Result<Vec<u8>, FolderError> {
    let json = serde_json::to_vec(metadata).map_err(|_| FolderError::SerializationFailed)?;
    aes::seal_aes_gcm(&json, folder_key).map_err(FolderError::EncryptionFailed)
}
```
Introduce a new `NodeError` enum (do not reuse `FolderError`, which is deleted per D-04) with the same `thiserror`-derive + `#[from] CryptoError` shape.

**Codec fidelity constraint:** JSON output MUST byte-match `tests/vectors/node-codec.json` / `tests/vectors/crypto/node-aad.json` — use `#[serde(rename_all = "camelCase")]` exactly as `FolderMetadata`/`FileMetadata` already do (grep confirms this convention is universal in `crates/core`).

---

### `crates/sdk/src/rotation/high_water.rs` (store/gate, lowest-risk direct port)

**Primary analog — TS reference:** `packages/sdk/src/state/rotation-high-water.ts` (full 188-line file, dependency-free)
```typescript
// Source: packages/sdk/src/state/rotation-high-water.ts (verified live read, full file)
function isValidFloorValue(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) &&
         Number.isSafeInteger(value) && value >= 0;
}
export interface HighWaterStore {
  get(nodeId: string): Promise<number | undefined>;
  put(nodeId: string, value: number): Promise<void>;
}
export interface EnforceResolvedParams { nodeId: string; seq: number; generation: number; versionFloor: number; }
// enforceResolved order (MUST preserve): validate live inputs (fail-closed on NaN/negative/
// non-integer) -> generation-floor check (throw GenerationRegressionError if regressed) ->
// EITHER cold-device versionFloor gate OR seq-floor check (SequenceRegressionError) ->
// bump both floors monotonic-max.
```

**Secondary analog — Rust idiom for error/struct conventions:** `crates/sdk/src/queue.rs`
```rust
// crates/sdk/src/queue.rs:9-13 (imports), :216, :230, :267 (fn signatures + Result<_, String> convention)
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub fn new(journal_dir: PathBuf, max_retries: u32) -> Self { /* ... */ }
pub fn put(&self, entry: &JournalEntry) -> Result<(), String> { /* ... */ }
pub fn sidecar_path_for(&self, id: &str) -> PathBuf { /* <journal_dir>/<id>.bin */ }
```
Follow `queue.rs`'s `Result<_, String>` error convention for `high_water.rs`/`floor_store.rs` unless a `thiserror` enum is clearly warranted (rotation module is new enough to introduce its own `RotationError` if preferred — Claude's Discretion per CONTEXT.md).

---

### `crates/sdk/src/rotation/scope.rs` (pure predicate, direct port)

**Analog — TS reference, full file already reproduced in RESEARCH.md Pattern 1:**
```typescript
// Source: packages/sdk-core/src/rotation/scope.ts (full 160-line file, verified live read)
export type CoverageParams = {
  nodeAncestorIpnsNames: string[];        // leaf-first
  activeGrantRootIpnsNames: Set<string>;
  localGrantRecord: { rootIpnsName: string } | null;
};
export function hasCoveringGrant(params: CoverageParams): boolean {
  for (const ancestor of params.nodeAncestorIpnsNames) {
    if (params.activeGrantRootIpnsNames.has(ancestor)) return true;
    if (params.localGrantRecord !== null && params.localGrantRecord.rootIpnsName === ancestor) return true;
  }
  return false;
}
export async function maybeRotateOnScopeExit(params, deps: { rotate: () => Promise<void> }) {
  if (!hasCoveringGrant(params)) return 'no-rotation';
  await deps.rotate();
  return 'rotated';
}
```

**Rust port target (recommended signature, 1:1 translation):**
```rust
pub struct CoverageParams {
    pub node_ancestor_ipns_names: Vec<String>,
    pub active_grant_root_ipns_names: std::collections::HashSet<String>,
    pub local_grant_record: Option<LocalGrantRecord>,
}
pub struct LocalGrantRecord { pub root_ipns_name: String }
pub fn has_covering_grant(params: &CoverageParams) -> bool { /* leaf-first scan, short-circuit true */ }
pub enum ScopeExitResult { NoRotation, Rotated }
pub async fn maybe_rotate_on_scope_exit<F, Fut>(params: &CoverageParams, rotate: F) -> Result<ScopeExitResult, String>
where F: FnOnce() -> Fut, Fut: std::future::Future<Output = Result<(), String>> { /* ... */ }
```

**No I/O, no external crate deps** — this is the single lowest-risk port target in the phase. Test shape to mirror: `packages/sdk-core/src/__tests__/rotation/scope.test.ts` (spy-based `deps.rotate` assertion — zero-call for private, exactly-one-call for shared-scope-exit).

---

### `crates/sdk/src/rotation/engine.rs` (dominant-effort cluster)

**Analog — TS reference:** `packages/sdk-core/src/rotation/engine.ts` (partial live read, ~250/1000+ lines) + composition point `packages/sdk/src/client.ts:1186-1258` (`performScopeExitRotation`). See RESEARCH.md "Pattern 3" for the full structural breakdown (per-node commit + `RotationJobRecord`, `verifySubtreeClean` resume, parent-tracking reseal batching, CRIT-1 lazy `contentRekeyPending`, HIGH-3 grant re-mint, HIGH-4 CAS-409 re-fetch-merge).

**Zeroization discipline — copy verbatim (security-critical, historical incident):**
```
rotate_one mints read_key_prime and zeros THAT buffer ONLY on its own failure paths
before re-throwing — NEVER on success, NEVER the caller-supplied parent_read_key or
any reused session key. (project memory: 48/89 sdk-e2e failures were caused by a
callee zeroing a reused caller buffer — this is the exact bug class to avoid.)
```
No direct Rust analog exists yet for the engine itself; follow `crates/sdk`'s existing async/`tokio` conventions (see `queue.rs`/`client.rs`) for module shape, and the `zeroize`/`Zeroizing<Vec<u8>>` idiom already used in `crates/core/src/folder.rs` and `crates/fuse/src/inode.rs` (`unwrap_key` returns `Zeroizing<Vec<u8>>` per the comment at `inode.rs:433,450`).

---

### `crates/sdk/src/floor_store.rs` (D-03 durable JSON sidecar)

**Analog — Rust idiom (adjacency + atomic-write pattern to reuse directly):**
```rust
// crates/sdk/src/queue.rs:216, 267 (verified live read)
pub fn new(journal_dir: PathBuf, max_retries: u32) -> Self { /* ... */ }
pub fn sidecar_path_for(&self, id: &str) -> PathBuf { /* <journal_dir>/<id>.bin */ }
```
D-03 recommendation (from RESEARCH.md): a sibling file `<journal_dir>/rotation-high-water.json`, written atomically (temp-file + rename, matching the existing 0600-permission sidecar convention `queue.rs` already uses for its per-entry `.bin` sidecars). Define an injected trait (`HighWaterStore`-analog) so `crates/sdk` owns gating logic while `crates/fuse` supplies the concrete path — mirrors 68.2's injectable-store pattern (browser supplies persistence, SDK owns gating).

**TS analog for the trait contract:** `HighWaterStore { get(nodeId): Promise<number|undefined>; put(nodeId, value): Promise<void> }` (`rotation-high-water.ts`, same file as high_water.rs's primary analog above).

---

### `crates/sdk/src/listing.rs` (ResolvedChild + gated list_folder, SC#6/68.2 parity)

**Analog — TS reference (68.2 branch, read via `git show`, NOT checkout):**
```
git show origin/feat/sdk-owned-read-chain-and-resolved-folder-listings:packages/sdk/src/client.ts
```
Mirror `listFolder`/`listSharedFolder` (imperative pull) + a `folder:updated` event-analog, and `ResolvedChild = { ipnsName, name, kind, size?, modifiedAt, sequence }` → Rust `ResolvedChild { ipns_name, name, kind, size: Option<u64>, modified_at, sequence }`.

**Critical generation-source rule to copy exactly (Pitfall 4):** for a COLD child during a folder-listing walk, source `generation` for `enforce_resolved` from the PARENT's `SealedChildRef.generation` mirror — NEVER the child's own envelope generation. Only an already-loaded node's own tracked generation applies on the write-path reconcile case.

**Single-gated-entrypoint constraint (D-05/SC#6):** raw IPNS resolve must be `crates/sdk`-internal only; `crates/fuse`/WinFsp call `list_folder`/`list_shared_folder` exclusively. Add a grep gate analogous to 68.2's own (see RESEARCH.md Validation Architecture, Req SC#6).

---

### `crates/api-client/src/shares.rs` (add `list_sent_shares`)

**Analog — same file, existing function to copy the shape of exactly** (imports, request struct, error handling, doc-comment style):
```rust
// crates/api-client/src/shares.rs:1-77 (full existing pattern, verified live read)
use serde::Serialize;
use crate::client::ApiClient;
use crate::error::ApiError;

pub async fn revoke_shares_for_items(
    client: &ApiClient,
    ipns_names: &[String],
) -> Result<(), ApiError> {
    if ipns_names.is_empty() { return Ok(()); }
    if ipns_names.len() > REVOKE_FOR_ITEMS_MAX {
        return Err(ApiError::ApiResponse { status: 400, message: format!(...) });
    }
    let request = RevokeForItemsRequest { ipns_names: ipns_names.to_vec() };
    let resp = client.authenticated_post("/shares/revoke-for-items", &request).await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse { status, message: format!("share revocation failed: {}", body) });
    }
    Ok(())
}
```
New `list_sent_shares` should use `client.authenticated_get("/shares/sent")` (mirror the `authenticated_post` call convention above with GET), deserialize into a new response DTO — **read `apps/api/src/shares/shares.controller.ts:134-169`'s DTO at plan time** (RESEARCH.md Open Question 2 flags the exact response shape as unverified). Include the same `#[cfg(test)]` unit-test-with-mock-client pattern shown above (serialization assertions + empty/oversized edge cases where applicable).

**Composition analog (what calls this, TS side):** `apps/web/src/services/rotation-driver.service.ts:199-208` — sources `activeGrantRootIpnsNames`/`localGrantRecord` from a **local cache** (`useShareStore.getState().sentShares`) populated on mount/periodically from `GET /shares/sent`, NOT a live per-mutation query (Pitfall 2). The Rust cache should live in `crates/sdk` or `crates/fuse`'s `CipherBoxFS` state, refreshed on mount/periodic timer, and read synchronously by `has_covering_grant`.

---

### `crates/fuse/src/write_ops/grant_scope.rs` (net-new, no direct analog — design-pass output)

**Analog — TS composition point to mirror:** `packages/sdk/src/client.ts:1186-1258` (`performScopeExitRotation`) — fetch `activeGrantRootIpnsNames` from injected callbacks, build `CoverageParams`, call `maybeRotateOnScopeExit`, on `'rotated'` refresh in-memory folder-tree entry (zero OLD key AFTER swap, never mid-flight).

**Rust idiom for the ancestor-walk half (genuinely novel — no TS analog, TS never had a mounted tree):** walk `parent_ino` in the existing `crates/fuse/src/inode.rs` inode table (`fs.inodes`) up to `ROOT_INO`, collecting `InodeKind::Folder{ipns_name,..}`/`InodeKind::Root{ipns_name,..}` into a leaf-first `Vec<String>` — O(depth), no network call. See RESEARCH.md Pattern 1(a)/(b)/(c) for the full algorithm write-up (this doc already contains the complete design-pass output required for D-05's flagged net-new item).

**Hoisting requirement (Pitfall 1):** write ONE ancestor-walk + one `has_covering_grant` call site, exposed to BOTH `write_ops/implementation/{delete,rename}.rs` and `platform/windows/write_ops.rs` (WinFsp lives inside `crates/fuse`, feature-gated, not a separate crate — confirmed via `crates/fuse/Cargo.toml`). Do not duplicate.

---

### `crates/fuse/src/write_ops/implementation/{delete,rename}.rs` (MODIFIED — replace unconditional revoke)

**Analog — current file (self), the exact anti-pattern being replaced:**
Current behavior (confirmed live): `handle_unlink`/`handle_rmdir` call `revoke_shares_blocking` unconditionally on every delete. Replace with:
```
has_covering_grant(ancestors, ...) == false -> pure relink: reseal parent SealedChildRef list,
    republish parent ONLY, ZERO rotation, ZERO extra publishes (ROT-02/SC#4 hard invariant).
has_covering_grant(...) == true -> call rotate_read_from_node rooted at the matched grant-root
    ancestor EXACTLY ONCE (short-circuit at first match, never once-per-ancestor).
```
Also thread `WriteChildRef.childId` (UUID) alongside `SealedChildRef.ipns_name` per D-07 (hard constraint, explicit security-review flag) — no existing Rust file has this dual-key threading today; mirror `packages/core/src/node/types.ts:133-141`'s `WriteChildRef` shape shown above.

---

### `crates/fuse/src/inode.rs` (MODIFIED, SC#1 swap sites: lines 434, 452, 658, 716)

**Analog — current file (self), exact call sites verified live:**
```rust
// crates/fuse/src/inode.rs:426-458 (verified live read — the swap target)
let encrypted_folder_key_bytes = hex::decode(&folder.folder_key_encrypted)
    .map_err(|_| format!("Invalid folderKeyEncrypted hex for folder '{}'", folder.name))?;
// unwrap_key now returns Zeroizing<Vec<u8>> directly (S3/D-05).
let folder_key = cipherbox_crypto::ecies::unwrap_key(&encrypted_folder_key_bytes, private_key)
    .map_err(|e| format!("Failed to decrypt folder key for '{}': {}", folder.name, e))?;

let encrypted_ipns_key_bytes = hex::decode(&folder.ipns_private_key_encrypted)...;
let ipns_private_key = cipherbox_crypto::ecies::unwrap_key(&encrypted_ipns_key_bytes, private_key)
    .map_err(|e| format!("Failed to decrypt IPNS private key for '{}': {}", folder.name, e))?;
```
Replace each `ecies::unwrap_key(...)` call with a chain roughly:
```rust
unseal_child_read_key(sealed_child_ref.read_key_sealed, parent_read_key, child_id, child_kind, sealed_child_ref.generation)
    -> unseal_node(published_node, child_read_key)
```
using `build_node_aad` internally with role `0x02` (child-readkey) — preserve the same `map_err(|e| format!(...))` error-string convention already used at each site (do not introduce a different error style mid-function). Preserve the `Zeroizing<Vec<u8>>` return-type comment convention (`// unwrap_key now returns Zeroizing<Vec<u8>> directly (S3/D-05).`) — write the equivalent comment for the new symmetric-unwrap call.

---

### `crates/fuse/src/replay.rs` (MODIFIED, line 365)

**Analog — current file (self):** same `ecies::unwrap_key` pattern as `inode.rs` above, inside the BFS `resolve_folder_key` walk. Apply the identical swap; this is the SC#6 read-chain consolidation point where resolve additionally MOVES into `crates/sdk::listing` (folded todo `2026-06-24-replay-reuse-verified-parent-sequence.md` — verify genuinely superseded once this lands).

---

### `crates/fuse/src/metadata.rs` (MODIFIED — delete `spawn_file_meta_reencrypt`)

**Analog — current file (self), deletion target verified at line 777** (150 lines including retry/backoff logic). Callers to update: `write_ops/implementation/rename.rs:248`, `platform/windows/write_ops.rs:1183`. **Sequencing constraint (Pitfall 5):** delete strictly AFTER the Node model lands (each node self-seals under its own `readKey`, eliminating the parent-folder-key coupling) — do not delete in the same commit as the SC#1 ECIES swap.

---

### `crates/fuse/src/journal_helpers.rs` (MODIFIED — `JournalOp::MkdirPublish.parent_metadata`)

**Analog — current file (self) + `crates/sdk/src/queue.rs` (`JournalEntry` sidecar conventions):**
```rust
// crates/fuse/src/journal_helpers.rs:97 (verified live read)
pub struct JournalOp::MkdirPublish { parent_metadata: cipherbox_core::folder::FolderMetadata, /* ... */ }
```
Repoint `parent_metadata`'s type to the new `Node`/`FolderMetadata`-analog shape as PART of the Node-enum cutover wave (not a follow-up, Pitfall 6). Add a fail-closed (log + skip, not panic) deserialize-failure path in the journal replay loop, matching `queue.rs`'s existing `Err(e) if e.kind() == std::io::ErrorKind::NotFound => false` defensive-match style (`queue.rs:368,379`).

## Shared Patterns

### Zeroization: terminal-owner-only
**Source:** project memory + `crates/fuse/src/inode.rs:433,450` comments (`unwrap_key` returns `Zeroizing<Vec<u8>>`), `crates/core/src/folder.rs:12` (`use zeroize::Zeroize;`)
**Apply to:** `node/seal.rs`, `rotation/engine.rs::rotate_one`, `rotation/scope.rs` (no keys touched, N/A), `inode.rs`/`replay.rs` swap sites
```
A callee receiving caller-owned key buffers must NOT zero them. Only the terminal owner
zeros. rotate_one mints its own read_key_prime and zeros ONLY that, ONLY on its own
failure paths — never the caller-supplied parent_read_key. (Historical incident: 48/89
sdk-e2e failures from violating this — do not reproduce in Rust.)
```

### Error handling: `map_err` → formatted `String` (FUSE layer) vs. `thiserror` enum (core/sdk/api-client layer)
**Source:** `crates/fuse/src/inode.rs` (String errors via `format!`), `crates/core/src/folder.rs` (`thiserror`-derived `FolderError`), `crates/api-client/src/shares.rs` (`ApiError` enum)
**Apply to:** all new files — `crates/core/src/node/*` and `crates/sdk/src/rotation/*`/`floor_store.rs`/`listing.rs` should introduce proper `thiserror` enums (`NodeError`, `RotationError`) consistent with `FolderError`/`ApiError`; `crates/fuse` call sites consuming them continue the existing `map_err(|e| format!(...))` convention already used throughout `inode.rs`/`replay.rs`.

### Serde camelCase JSON convention
**Source:** `crates/core/src/folder.rs` (`FolderMetadata`/`FileMetadata`, implicit via existing `#[serde(rename_all = "camelCase")]` usage across `crates/core`), `crates/api-client/src/shares.rs:27` (`#[serde(rename = "ipnsNames")]`)
**Apply to:** `node/types.rs` codec (MUST byte-match `tests/vectors/node-codec.json`), any new DTO in `crates/api-client/src/shares.rs::list_sent_shares`

### Atomic sidecar file persistence (journal-dir-adjacent)
**Source:** `crates/sdk/src/queue.rs:216-267` (`sidecar_path_for`, temp-file+rename, 0600 perms via `OpenOptionsExt`)
**Apply to:** `crates/sdk/src/floor_store.rs` (D-03 durable floor JSON sidecar)

### Grant-scope predicate: single shared call site, no duplication
**Source:** design doc §3.9 + RESEARCH.md Pitfall 1
**Apply to:** `crates/fuse/src/write_ops/grant_scope.rs` consumed identically by `write_ops/implementation/{delete,rename}.rs` (Unix) and `platform/windows/write_ops.rs` (WinFsp) — write once, never duplicate per-platform.

## No Analog Found

None — every file in the phase's blast radius has either a TS reference implementation, an existing Rust idiom to follow, or both (see table above). The two files with the thinnest precedent are:

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `crates/sdk/src/rotation/engine.rs` | service (orchestrator) | batch/event-driven | TS reference exists but was only partially read (~250/1000+ lines) this session; no prior Rust rotation-engine attempt exists to compare against. Read the remaining `engine.ts` lines (`verifySubtreeClean`, full grant-remint callback wiring) at plan/implementation time before finalizing the Rust module's internal structure. |
| `crates/fuse/src/write_ops/grant_scope.rs` | utility (ancestor-walk) | event-driven | The ancestor-walk half is genuinely novel — TS never had a mounted filesystem tree to walk. RESEARCH.md's Pattern 1(a)/(b)/(c) is the design-pass output standing in for a codebase analog. |

## Metadata

**Analog search scope:** `crates/core/src/{folder,decrypt,bin,vault_blob}.rs`, `crates/crypto/src/aes.rs`, `crates/sdk/src/{queue,client,state}.rs`, `crates/api-client/src/shares.rs`, `crates/fuse/src/{inode,replay,metadata,journal_helpers}.rs`, `crates/fuse/src/write_ops/implementation/{delete,rename}.rs`; TS mirrors read via direct `Read`/`git show` against `packages/core/src/node/{types,seal,encode}.ts`, `packages/sdk-core/src/rotation/{scope,engine}.ts`, `packages/sdk/src/{state/rotation-high-water,client}.ts`, `apps/web/src/services/rotation-driver.service.ts`.
**Files scanned:** 12 Rust files (grep + targeted Read), 7 TS reference files (via RESEARCH.md's already-verified live reads + this pass's own grep confirmations).
**Pattern extraction date:** 2026-07-06
