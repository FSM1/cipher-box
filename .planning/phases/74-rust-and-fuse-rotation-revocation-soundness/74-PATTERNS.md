# Phase 74: Rust and FUSE Rotation-Revocation Soundness - Pattern Map

**Mapped:** 2026-07-11
**Files analyzed:** 9 (modified) + 2 (extended tests)
**Analogs found:** 9 / 9 (all in-repo, no external analogs needed — this phase wires existing shipped primitives)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/sdk/src/rotation/engine.rs` (`RotateReadResult` widening) | service (rotation engine) | event-driven/CRUD (BFS walk, per-node commit) | itself — existing `CommittedRotation`/BFS commit branches (same file) | exact (self-extension) |
| `packages/sdk-core/src/rotation/engine.ts` (`RotateReadResult` widening, TS twin) | service (rotation engine) | event-driven/CRUD | `crates/sdk/src/rotation/engine.rs` (Rust twin, cross-language parity pair) | exact (parity twin) |
| `crates/fuse/src/write_ops/grant_scope.rs` (`refresh_grant_root_read_key` → generalized multi-node) | utility (in-memory inode-table mutation) | transform (map over InodeTable) | itself — existing `refresh_grant_root_read_key` (lines 559-582, same file) | exact (self-extension) |
| `crates/fuse/src/write_ops/rotation_deps.rs` (`FuseRotationDeps::query_grants_rooted_at`/`update_grant`/`delete_grant`) | service (adapter impl of `RotationDeps` trait) | request-response (wraps HTTP calls) | `packages/sdk/src/share/owner-reconcile.ts` (`buildGrantRemintCallbacks`) — TS reference impl of the exact same three-callback shape | exact (cross-language reference) |
| `crates/api-client/src/shares.rs` (NEW `update_grant`/`delete_share` wire functions) | service (API-client wire function) | request-response | `revoke_shares_for_items` (same file, lines 48-84) and `list_sent_shares` (lines 137-157) | exact (same-file sibling functions) |
| `crates/fuse/src/platform/windows/write_ops.rs::handle_rename` | controller (WinFsp write-op handler) | request-response | `crates/fuse/src/write_ops/implementation/rename.rs::handle_rename` (fuser twin) | exact (cross-platform twin) |
| `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` (extend: depth≥2 leg + 2nd recipient) | test | event-driven (live-mount e2e) | itself (existing single-recipient shallow leg) | exact (self-extension) |
| `crates/fuse/src/write_ops/rotation_deps.rs` (new unit tests for the 3 new methods) | test | request-response (FakeTransport) | `crates/sdk/src/rotation/engine.rs` `impl RotationDeps for FakeDeps` (lines 2523-2670) and `rotation_deps.rs`'s own existing `FakeTransport`-based tests | exact |
| `crates/fuse/src/platform/windows/write_ops.rs` (new dest-gate unit tests) | test | request-response | `crates/fuse/src/write_ops/implementation/rename.rs` tests `rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt` / `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit` (lines 413-497) | exact (cross-platform twin) |

## Pattern Assignments

### `crates/sdk/src/rotation/engine.rs` — `RotateReadResult` widening (Todo 1)

**Analog:** same file — `CommittedRotation` (lines 312-343), `RotateOneOutcome` (349-357), the two commit branches at 1542 (root) and 1817 (BFS child).

**Current struct to widen** (lines 806-813):
```rust
#[derive(Debug)]
pub struct RotateReadResult {
    pub read_key: Zeroizing<[u8; 32]>,
    pub generation: u32,
    pub sequence_number: u64,
}
```
Widen additively — add e.g. `pub rotated_nodes: HashMap<String, RotatedNodeKey>` keyed by **`ipns_name`** (per RESEARCH Pitfall 1 — `CommittedRotation` only has `node_id`; `ipns_name` must be threaded in at the call site, not added to `CommittedRotation` itself, since the engine is host-agnostic).

**Root commit hook** (lines 1541-1591, the exact insertion point is right where `fresh_root = Some(root_committed)` is set at line 1590):
```rust
match root_outcome {
    RotateOneOutcome::Committed(root_committed) => {
        deps.persist_job(job_record).await;
        deps.delete_wrapped_key(&root_committed.node_id).await?;
        if !root_committed.children.is_empty() {
            parent_tracking.insert(root_ipns_name.to_string(), ParentTrackingState { /* ... */ });
        }
        for child_ref in &root_committed.children {
            enqueue_child(deps, root_ipns_name, root_read_key, child_ref, &mut queue).await?;
        }
        for entry in pre_rotation_frontier {
            enqueue_dirty_frontier_entry(entry, &mut queue);
        }
        fresh_root = Some(root_committed);   // <-- insert root_ipns_name.to_string() + root_committed's
                                              //     read_key_prime/new_generation/new_sequence_number
                                              //     into the new rotated_nodes map HERE
    }
    ...
```

**BFS child commit hook** (lines 1817-1919, inside `while let Some(item) = queue.pop_front()`):
```rust
RotateOneOutcome::Committed(child) => {
    deps.persist_job(job_record).await;
    // ... parent_tracking seed/reseal (D-02) ...
    complete_pending_child(deps, &mut parent_tracking, &item.parent_ipns_name).await?;
    if !child.children.is_empty() {
        parent_tracking.insert(item.child_ref.ipns_name.clone(), ParentTrackingState { /* ... */ });
        // <-- insert item.child_ref.ipns_name.clone() + child's read_key_prime/new_generation/
        //     new_sequence_number into the new rotated_nodes map HERE (child_ref is in scope)
    }
    for grandchild_ref in &child.children {
        enqueue_child(deps, &item.child_ref.ipns_name, node_read_key.as_slice(), grandchild_ref, &mut queue).await?;
    }
}
```

**Open question flagged by RESEARCH (A1):** grep `repair_dirty_node`'s return shape before finalizing — its crash-resume commit path may need the same map population; not blocking, may be a documented follow-up like the D-16 precedent.

**D-09 terminal-owner rule:** do NOT zero any key in the new map from inside the engine — `RotateReadResult` is the terminal owner via `Zeroizing`, exactly as the existing top-level `read_key` field already documents (lines 800-807 doc comment).

---

### `packages/sdk-core/src/rotation/engine.ts` — TS twin (Todo 1, parity)

**Analog:** `crates/sdk/src/rotation/engine.rs` (this is the canonical cross-language parity pair already established for this module — RESEARCH confirms `RotateReadResult` at TS line 337 mirrors Rust line 809). Mirror the exact same additive map field, camelCase-named (e.g. `rotatedNodes: Map<string, RotatedNodeKey>` or a plain object keyed by ipnsName, matching whatever collection convention the surrounding TS file already uses — check `parentTracking`'s own type for the established Map-vs-object idiom before choosing). Populate at the TS structural equivalents of the two Rust commit branches (root branch and the BFS loop's non-skipped `rotateOne` return) inside `rotateReadFromNode`.

**Rust/TS field-name parity requirement (explicit phase requirement):** keep the map's value shape (readKey/generation/sequenceNumber, or read_key/generation/sequence_number) 1:1 field-for-field between the two languages — do not let one side add a field the other lacks.

---

### `crates/fuse/src/write_ops/grant_scope.rs` — generalized multi-node inode refresh (Todo 1)

**Analog:** same file, existing `refresh_grant_root_read_key` (lines 559-582):
```rust
fn refresh_grant_root_read_key(
    inodes: &mut InodeTable,
    grant_root_ipns_name: &str,
    result: &RotateReadResult,
) {
    for inode in inodes.inodes.values_mut() {
        match &mut inode.kind {
            InodeKind::Root { ipns_name, read_key, .. }
            | InodeKind::Folder { ipns_name, read_key, .. }
                if ipns_name.as_str() == grant_root_ipns_name =>
            {
                read_key.copy_from_slice(result.read_key.as_slice());
                return;
            }
            _ => {}
        }
    }
}
```
**Generalize** to loop over `result.rotated_nodes` (the new map from Todo 1's engine widening) and match each entry's `ipns_name` against every inode — same `Root | Folder` arms, but no early `return` (must keep scanning for every rotated node, not stop at the first match). **Extend the match arms to also cover `InodeKind::File { ipns_name, read_key, .. }`** per RESEARCH's explicit recommendation (files are rotated too via `mint_file_key_on_rotate`/CRIT-1 and currently silently skipped — low-cost fix bundled into this same generalization). Rename the function (e.g. `refresh_rotated_inode_read_keys`) since it is no longer grant-root-only.

**Call site to update** (line 530, inside `rotate_read_on_scope_exit`, lines 468-547):
```rust
if let Some(result) = maybe_result {
    refresh_grant_root_read_key(&mut fs.inodes, grant_root_ipns_name, &result);
    // becomes: refresh_rotated_inode_read_keys(&mut fs.inodes, &result);
}
```

---

### `crates/fuse/src/write_ops/rotation_deps.rs` — `FuseRotationDeps` grant-seam impl (Todo 2)

**Analog (cross-language reference, SHIPPED + tested):** `packages/sdk/src/share/owner-reconcile.ts::buildGrantRemintCallbacks` (full file read above) — the exact three-callback shape (`queryGrantsFn`/`updateGrantFn`/`deleteGrantFn`) to port into Rust trait methods.

**Trait to implement** (`crates/sdk/src/rotation/engine.rs` lines 121-199 — `GrantRow` struct + `RotationDeps` trait defaults):
```rust
#[derive(Debug, Clone)]
pub struct GrantRow {
    pub share_id: String,
    pub recipient_public_key: Vec<u8>,   // raw bytes, NOT hex — adapter's job to decode
    pub is_revoked: bool,
}

async fn query_grants_rooted_at(&self, _node_id: &str) -> Result<Vec<GrantRow>, RotationError> {
    Ok(Vec::new())   // <-- default no-op being replaced in FuseRotationDeps
}
async fn update_grant(&self, _share_id: &str, _encrypted_read_key: &str, _new_generation: u32)
    -> Result<(), RotationError> { Ok(()) }
async fn delete_grant(&self, _share_id: &str) -> Result<(), RotationError> { Ok(()) }
```

**Current no-op location to override** (`rotation_deps.rs` lines 171-224, inside `impl<T: RotationTransport> RotationDeps for FuseRotationDeps<T>`):
```rust
// `query_grants_rooted_at`/`update_grant`/`delete_grant` are left at the
// trait's DEFAULT no-op — the ROT-04 desktop-grant-remint deferral this
// plan's <verification> block explicitly sanctions (see 70.1-09-SUMMARY.md).
```
Replace this comment block with real overrides. Follow the `resolve`/`fetch_node`/`publish_with_cas` overrides just above it (lines 174-213) as the structural template for how this impl block wraps `self.transport`/`self.owner_public_key` calls with `RotationError::RotateFailed(format!(...))` error mapping.

**`query_grants_rooted_at` — wire call + filter (analog: `collect_sent_shares`, `crates/api-client/src/shares.rs` lines 176-193):**
```rust
pub async fn collect_sent_shares(client: &ApiClient) -> Result<Vec<SentShareResponse>, ApiError> {
    let mut collected: Vec<SentShareResponse> = Vec::new();
    let mut offset: u32 = 0;
    loop {
        let page = list_sent_shares(client, SENT_SHARES_PAGE_LIMIT, offset).await?;
        let page_len = page.shares.len();
        collected.extend(page.shares);
        if !should_fetch_next_page(page_len, collected.len(), page.total) { break; }
        offset += SENT_SHARES_PAGE_LIMIT;
    }
    Ok(collected)
}
```
`FuseRotationDeps::query_grants_rooted_at(node_id)` should call this (via `self.transport`-reachable `ApiClient`, or add an `api: &ApiClient` handle to `FuseRotationDeps` if not already reachable) then client-side filter: `.filter(|s| s.root_node_id == node_id)`, map to `GrantRow { share_id, recipient_public_key: cipherbox_crypto::hex_to_bytes(&s.recipient_public_key.trim_start_matches("0x"))?, is_revoked: false }`. **`is_revoked` is always `false` from this source** (revoked shares are hard-deleted server-side, confirmed by `SentShareResponse`'s own doc comment, lines 90-94 of `shares.rs`) — do not build a test expecting `true` from this path (RESEARCH Pitfall 2).

**Hex decode helper (resolves RESEARCH Open Question 2 — already exists):**
```rust
// crates/crypto/src/utils.rs:30-32
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}
```
Note: `SentShareResponse.recipient_public_key` is `"0x04..."` — strip the `0x` prefix before calling `hex_to_bytes` (the `04` byte itself is the valid uncompressed-key prefix and must be KEPT, only the `0x` marker is stripped — see `crates/crypto/src/ecies.rs:27-28`'s own `recipient_public_key[0] != 0x04` check for the expected post-decode shape).

**`update_grant` — NEW wire function needed in `crates/api-client/src/shares.rs`** (analog: `revoke_shares_for_items`, same file lines 48-84, and the DTO/controller pair below):
```rust
// Analog shape (revoke_shares_for_items, lines 48-84):
pub async fn revoke_shares_for_items(client: &ApiClient, ipns_names: &[String]) -> Result<(), ApiError> {
    ...
    let resp = client.authenticated_post("/shares/revoke-for-items", &request).await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::ApiResponse { status, message: format!("share revocation failed: {}", body) });
    }
    Ok(())
}
```
New `update_grant` needs a PATCH request (client presumably has `authenticated_patch` — verify; if absent, check `ApiClient`'s method inventory) to `/shares/{shareId}/grant` with body matching `UpdateGrantDto` (`apps/api/src/shares/dto/update-grant.dto.ts`):
```typescript
// apps/api/src/shares/dto/update-grant.dto.ts (server contract to mirror)
export class UpdateGrantDto {
  encryptedReadKey!: string;   // even-length hex string, <=2500 chars
  rootGeneration!: string;     // numeric string, 0..=i64::MAX
  // encryptedWriteKey / clearEncryptedWriteKey: omit both for a read-key-rotation-only call
}
```
Controller (`apps/api/src/shares/shares.controller.ts` lines 231-254): `@Patch(':shareId/grant')`, `@HttpCode(204)` — expect 204 No Content on success, no response body to deserialize.

**`delete_grant` — NEW wire function, `DELETE /shares/{shareId}`** (controller lines 196-212): `@Delete(':shareId')`, `@HttpCode(204)`, hard-delete. Mirror `revoke_shares_for_items`'s POST-then-check-status shape but with `client.authenticated_delete(&path)` (verify method name exists on `ApiClient`; if not, add alongside).

**ECIES wrap — do NOT re-wrap inside `update_grant`:** `re_mint_grants_rooted_at` (the CALLER, already shipped, `engine.rs:613`) does `cipherbox_crypto::wrap_key(new_read_key, &grant.recipient_public_key)` itself BEFORE calling `deps.update_grant(...)` — `FuseRotationDeps::update_grant` receives an already-hex-encoded ciphertext string and just forwards it to the PATCH body.

---

### `crates/api-client/src/shares.rs` — NEW wire functions (Todo 2)

**Analog:** same file, `revoke_shares_for_items` (lines 25-84) for the POST+status-check shape; `list_sent_shares` (lines 131-157) for the GET+JSON-decode shape.

**Imports pattern** (lines 1-16):
```rust
use serde::{Deserialize, Serialize};
use crate::client::ApiClient;
use crate::error::ApiError;
```

**Error handling pattern** (consistent across every function in this file):
```rust
if !resp.status().is_success() {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    return Err(ApiError::ApiResponse { status, message: format!("<op> failed: {}", body) });
}
```

**Request-body DTO pattern** (analog: `RevokeForItemsRequest`, lines 30-34):
```rust
#[derive(Debug, Serialize)]
struct RevokeForItemsRequest {
    #[serde(rename = "ipnsNames")]
    ipns_names: Vec<String>,
}
```
New `UpdateGrantRequest` should follow this exact shape with `#[serde(rename_all = "camelCase")]` or per-field `rename`, matching `UpdateGrantDto`'s `encryptedReadKey`/`rootGeneration` fields (omit `encryptedWriteKey`/`clearEncryptedWriteKey` for this read-key-rotation-only call, per the DTO's own doc comment).

---

### `crates/fuse/src/platform/windows/write_ops.rs::handle_rename` — dest-gate + reorder (Todo 3)

**Analog (the correctness baseline to port verbatim):** `crates/fuse/src/write_ops/implementation/rename.rs::handle_rename` (full file read above, lines 1-170+).

**Current WinFsp order (buggy — confirmed at lines 1081-1149):**
1. Source gate (`run_scope_exit_gate(&mut fs, source_ino)`) — line 1115-1119
2. THEN destination-replacement validation (`status_directory_not_empty` etc.) — lines 1121-1146
3. THEN ungated `fs.inodes.remove(dest_ino)` — line 1148 (no dest gate at all)

**Fuser reference order (D-15d, correct — to replicate):**
1. Destination-replacement POSIX validation FIRST (ENOTDIR/EISDIR/ENOTEMPTY) — `rename.rs` lines 91-131
2. THEN source gate — `rename.rs` lines 143-149
3. THEN dest gate (NEW, currently missing in WinFsp) — `rename.rs` lines 158-163
4. THEN mutation

**Exact dest-gate snippet to port** (`rename.rs` lines 158-163):
```rust
if let Some(dest_ino) = dest_ino {
    if crate::write_ops::grant_scope::run_scope_exit_gate(fs, dest_ino).is_err() {
        reply.error(libc::EIO);
        return;
    }
}
```
WinFsp twin (using already-imported helpers, `status_access_denied` used elsewhere in this same file at `handle_set_delete`):
```rust
if let Some(dest_ino) = fs.inodes.find_child(new_parent_ino, new_name) {
    // ... existing validation stays here, now reordered BEFORE the source gate ...
}
if old_parent_ino != new_parent_ino
    && crate::write_ops::grant_scope::run_scope_exit_gate(&mut fs, source_ino).is_err()
{
    return Err(status_io_device_error());
}
if let Some(dest_ino) = dest_ino {
    if crate::write_ops::grant_scope::run_scope_exit_gate(&mut fs, dest_ino).is_err() {
        return Err(status_access_denied());
    }
}
// THEN fs.inodes.remove(dest_ino) mutation
```

**Pitfall 4 (RESEARCH):** the `replace_if_exists == false` collision check (`status_object_name_collision()`, currently line 1123, ahead of everything) must stay exactly where it is — it is unconditional and does NOT need reordering. Only move the ENOTEMPTY-equivalent (`status_directory_not_empty`) check earlier, ahead of the source gate.

**Coalescing:** do NOT add `run_scope_exit_gate_coalesced` to either gate here — fuser's own `rename.rs` reference uses the PLAIN `run_scope_exit_gate` for both source and dest (confirmed at lines 143 and 159); match this, don't invent new coalescing.

---

### Test analogs (Todo 1/2/3, Wave 0 gaps)

**Todo 1/2 Rust unit tests — analog:** `crates/sdk/src/rotation/engine.rs`'s own `impl RotationDeps for FakeDeps` test harness (lines 2523-2670) and `rotation_deps.rs`'s existing `FakeTransport`-based diagnosis tests (module doc comment references "already prove publish counts deterministically offline, no live network" — seed a 2-level tree via `FakeTransport.seed()`, drive through `FuseRotationDeps`, assert `result.rotated_nodes` contains every level's key).

**Todo 3 WinFsp unit tests — analog (port verbatim, adapted to WinFsp's `FspError`/status-code idiom instead of fuser's `libc::ENOTEMPTY`/`EIO`):**
```rust
// crates/fuse/src/write_ops/implementation/rename.rs:413-448
#[test]
fn rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt() { /* ... */ }

// crates/fuse/src/write_ops/implementation/rename.rs:456-496
#[test]
fn rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit() { /* ... */ }
```
Both assert: (a) the correct rejection status code, (b) the source/dest inode is STILL PRESENT afterward (rejection did not partially mutate state) — mirror this dual-assertion shape for the WinFsp twin tests.

## Shared Patterns

### D-09 terminal-owner zeroization (applies to ALL Todo 1 files)
**Source:** `crates/sdk/src/rotation/engine.rs` lines 800-807 (`RotateReadResult` doc comment) and project memory `project-zeroization-callee-must-not-zero-reused-buffer`.
**Apply to:** `RotateReadResult`'s new `rotated_nodes` map, `RotatedNodeKey.read_key` — never zero from inside the engine or from `refresh_rotated_inode_read_keys`; the receiving inode's `Zeroizing` buffer owns the overwrite-in-place semantics (see `refresh_grant_root_read_key`'s existing `read_key.copy_from_slice(...)` pattern, line 578).

### ECIES wrap/unwrap (applies to Todo 2)
**Source:** `crates/sdk/src/rotation/engine.rs:613` (`re_mint_grants_rooted_at`'s own `wrap_key` call) and `crates/fuse/src/write_ops/rotation_deps.rs` `persist_wrapped_key`/`get_wrapped_key` (lines ~240-275).
**Apply to:** Do NOT wrap/unwrap inside `FuseRotationDeps::update_grant` — the caller (`re_mint_grants_rooted_at`) already does the ECIES wrap before invoking the trait method; `update_grant` just forwards the ciphertext string.

### `RotationError::RotateFailed(format!(...))` error mapping (applies to all new `FuseRotationDeps`/`crates/api-client` code)
**Source:** `crates/fuse/src/write_ops/rotation_deps.rs` `persist_wrapped_key`/`get_wrapped_key` (lines 240-275) and `publish_with_cas` (lines 183-213).
**Apply to:** every new trait-method override and wire function — wrap the underlying `ApiError`/decode error into `RotationError::RotateFailed(format!("<fn>: <what> failed for {id}: {e}"))`, matching the existing message-formatting convention verbatim (function-name-prefixed messages).

### `run_scope_exit_gate` cross-platform primitive (applies to Todo 3)
**Source:** `crates/fuse/src/write_ops/grant_scope.rs` (module-level, `#[cfg(any(feature = "fuse", feature = "winfsp"))]`) — already shared between fuser (`implementation/rename.rs`) and WinFsp (`platform/windows/write_ops.rs::handle_set_delete`, lines 1257 area).
**Apply to:** `handle_rename`'s new dest gate — call the SAME function, do not fork a Windows-specific variant.

## No Analog Found

None — every file in this phase's scope has a strong, concrete, same-repo analog (either a same-file sibling function/branch, or a proven cross-language/cross-platform twin). This is expected: RESEARCH's own framing is "wire an existing, already-correct primitive into a call site that was missed" — no new architecture, so no analog gaps.

## Metadata

**Analog search scope:** `crates/sdk/src/rotation/`, `crates/fuse/src/write_ops/`, `crates/fuse/src/platform/windows/`, `crates/api-client/src/shares.rs`, `packages/sdk/src/share/`, `packages/sdk-core/src/rotation/`, `apps/api/src/shares/`
**Files scanned:** 9 primary source files (all read directly in this worktree, no external search needed — RESEARCH.md already named every analog pair; this pass verified them against live line numbers/symbols)
**Pattern extraction date:** 2026-07-11
