# Phase 74: Rust and FUSE Rotation-Revocation Soundness - Research

**Researched:** 2026-07-11
**Domain:** Rust rotation engine (crates/sdk), FUSE/WinFsp desktop mount (crates/fuse), share-grant API (apps/api, crates/api-client), TS rotation-engine parity (packages/sdk-core)
**Confidence:** HIGH — every claim below is grounded in source read directly from this worktree; no external libraries are involved

## Summary

This phase closes three independently-scoped, already-diagnosed gaps left open by Phase 70.1's D-16 fix (`.planning/debug/scope-exit-part-a-fail.md`). All three gaps are **known, documented, and narrowly bounded** — this is a correctness-completion phase, not exploratory work. No new external dependencies, no new architecture, no new schema.

1. **Deep scope-exit key refresh (Todo 1).** `RotateReadResult` (both `crates/sdk/src/rotation/engine.rs:809` and `packages/sdk-core/src/rotation/engine.ts:337`) carries only the **root** node's post-rotation key. The BFS walk internally computes a `CommittedRotation`/`RotateOneOutcome::Committed` for **every** node it rotates (root and every descendant), but only the root's is surfaced to the caller. `crates/fuse/src/write_ops/grant_scope.rs::refresh_grant_root_read_key` (lines 559-582) can therefore only refresh the grant-root FUSE inode's in-memory `read_key` — any intermediate `Folder` inode below the root keeps its **stale pre-rotation key**, so a subsequent local relink of that intermediate folder reseals it under the old key (the exact Bob-bypass class of bug, one level deeper). This is a **documented, out-of-scope-until-now** limitation explicitly called out in the D-16 Resolution text.

2. **`query_grants_rooted_at` desktop no-op (Todo 2).** The rotation engine's inner-grant re-mint machinery (`re_mint_grants_rooted_at` in Rust / `reMintGrantsRootedAt` in TS) is **already fully wired and unconditionally invoked** after every per-node commit in the walk (both root and BFS children) — this is NOT new engine work. The only gap is that `FuseRotationDeps` (`crates/fuse/src/write_ops/rotation_deps.rs:141-169`) leaves `query_grants_rooted_at`/`update_grant`/`delete_grant` at the trait's default no-op (explicitly sanctioned in Phase 70.1 plan 09 as "ROT-04 deferral"). The TS/web side already has a **shipped, tested reference implementation** of exactly this pattern: `packages/sdk/src/share/owner-reconcile.ts` (`buildGrantRemintCallbacks`) — client-side-filters `GET /shares/sent` by `rootNodeId === nodeId`, and drives `PATCH /shares/:shareId/grant` (update) / `DELETE /shares/:shareId` (revoke). Port this same shape into `FuseRotationDeps`.

3. **WinFsp RENAME dest-gate + ordering (Todo 3).** `crates/fuse/src/platform/windows/write_ops.rs::handle_rename` (~line 1081) gates only the SOURCE scope-exit (`run_scope_exit_gate(&mut fs, source_ino)`) and never gates the overwritten `dest_ino` before removing it — a plain, ungated `fs.inodes.remove(dest_ino)`. The fuser twin, `crates/fuse/src/write_ops/implementation/rename.rs::handle_rename` (line 10), already does this correctly and is the exact template to port: POSIX destination-replacement validation FIRST (ENOTDIR/EISDIR/ENOTEMPTY), THEN the source gate, THEN the dest gate, THEN mutation. WinFsp currently runs its (partial) destination validation AFTER the source gate — reversed order.

**Primary recommendation:** Treat this as three independent, sequential fix-and-test units (they touch disjoint call sites and can be planned/executed as separate waves): (A) widen `RotateReadResult`/`CommittedRotation` surfacing + generalize `refresh_grant_root_read_key` to a multi-node refresh, in Rust AND TS lockstep; (B) implement the three `RotationDeps` grant methods on `FuseRotationDeps` by porting `owner-reconcile.ts`'s pattern; (C) port the fuser `rename.rs` dest-gate-and-ordering shape into WinFsp's `handle_rename`, reusing the exact status-code helpers already imported there. All three are additive/corrective — no removals of existing coalescing (70.1-13a) logic.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Per-node rotated-key surfacing (walk mechanics) | Rotation engine (`crates/sdk`, `packages/sdk-core`) — host-agnostic | — | Engine already computes per-node `CommittedRotation`/`RotateOneOutcome`; surfacing is a return-type widening, not new crypto logic |
| Intermediate FUSE inode key refresh | Desktop / FUSE (`crates/fuse`) | — | `InodeTable` is FUSE-mount-local, in-memory state; only the mount owns it |
| Grant re-mint query/update/delete (desktop) | Desktop / FUSE (`crates/fuse/src/write_ops/rotation_deps.rs`) | API / Backend (`apps/api` `/shares/sent`, `PATCH /shares/:id/grant`, `DELETE /shares/:id`) | Desktop adapter implements the injectable seam; API already exposes the needed endpoints (proven by the TS/web implementation) |
| WinFsp RENAME dest-gate parity | Desktop / FUSE (`crates/fuse/src/platform/windows`) | — | Windows-specific write-op handler; the shared `grant_scope.rs` gate primitive is already platform-agnostic and importable as-is |
| Desktop-e2e retained-vs-revoked / deep-scope-exit assertions | Test harness (`tests/desktop-e2e`) | — | Cross-platform script (`shared-scope-exit-rotation.mts`) already runs on macOS/Linux/Windows CI via `run-all.sh`/`run-all.ps1` |

## Project Constraints (from CLAUDE.md)

- TypeScript: prefer string literals over enums (N/A here — the TS rotation engine already uses plain string/object literal types, no new enums needed for this phase).
- `Uint8Array` for binary data in TS, `Zeroizing<[u8; N]>`/`Zeroizing<Vec<u8>>` for key material in Rust — already the established pattern throughout `crates/sdk`, `crates/fuse`, `packages/sdk-core`. New code (per-node key map, grant callbacks) MUST follow the same terminal-owner zeroization rule (D-09): a callee must never zero a caller-owned buffer (see `project-zeroization-callee-must-not-zero-reused-buffer` memory — this exact bug class caused a historical 48/89 sdk-e2e failure).
- ECIES for key wrapping, never hand-rolled — `cipherbox_crypto::wrap_key`/`unwrap_key` already used throughout `rotation_deps.rs` and MUST be reused for the new `update_grant` wrap step (mirrors `re_mint_grants_rooted_at`'s own `wrap_key` call at `engine.rs:613`).
- Server never sees plaintext keys — `update_grant`'s `encryptedReadKey` is ECIES ciphertext-only, matching `UpdateGrantDto`'s validated hex-string contract (`apps/api/src/shares/dto/update-grant.dto.ts`).
- Conventional commits, no parens in subject line; commits go on a `feat/` branch per CLAUDE.md branch-protection rules.
- Terminology: use `readKey`/`read_key`, `writeKey`/`write_key`, `ipnsName`/`ipns_name` consistently — all existing code in this phase's files already follows this.
- No `pnpm api:generate` needed — this phase touches Rust internals + an already-generated API surface (`PATCH /shares/:id/grant`, `GET /shares/sent`, `DELETE /shares/:id` all already exist and are already consumed by both the TS SDK and (partially) `crates/api-client`).

## Standard Stack

No new external packages. This phase is 100% internal-crate/internal-package work:

| Crate/Package | Role in this phase | Already a dependency |
|---|---|---|
| `cipherbox-sdk` (crates/sdk) | Rotation engine (`RotateReadResult`, `RotationDeps`, `CommittedRotation`) | Yes |
| `cipherbox-fuse` (crates/fuse) | FUSE (`grant_scope.rs`, `rotation_deps.rs`, `implementation/rename.rs`) + WinFsp (`platform/windows/write_ops.rs`) | Yes |
| `cipherbox-api-client` (crates/api-client) | `shares.rs` (`SentShareResponse`, `collect_sent_shares`) — needs a NEW `update_grant`/`revoke_share` wire function | Yes (extend, don't add) |
| `cipherbox-crypto` | `wrap_key`/`unwrap_key` (ECIES) for the grant re-mint | Yes |
| `@cipherbox/sdk-core` (packages/sdk-core) | TS rotation engine twin — `RotateReadResult` widening for parity | Yes |
| `zeroize` (Rust) | `Zeroizing<[u8;32]>` for all new key-bearing types | Yes |

## Package Legitimacy Audit

**Not applicable** — this phase introduces zero new external (npm/crates.io) dependencies. All work is against existing first-party crates/packages already present in the workspace `Cargo.toml`/`package.json` files. No `package-legitimacy check` run was needed.

## Architecture Patterns

### System Architecture Diagram

```
                    Rotation walk (host-agnostic, crates/sdk + packages/sdk-core)
                    ═══════════════════════════════════════════════════════════
   rotate_read_from_node_inner(root)
        │
        ├─► rotate_one_inner(root) ──► CommittedRotation{node_id, read_key_prime, ...}
        │         │                          │
        │         ├─► re_mint_grants_rooted_at(root.node_id) ──► deps.query_grants_rooted_at(root.node_id)
        │         │                                                    │ [TODO 2: FuseRotationDeps default no-op]
        │         │                                              deps.update_grant / deps.delete_grant
        │         │
        │   [TODO 1: only root's CommittedRotation ever reaches the caller as RotateReadResult]
        │
        └─► BFS queue: for each child ─► rotate_one(child) ──► CommittedRotation{child.node_id, read_key_prime, ...}
                  │                            │
                  ├─► re_mint_grants_rooted_at(child.node_id) ──► [SAME seam, per-node — already wired]
                  │
            [TODO 1: child's CommittedRotation is consumed internally (parent reseal)
                      then DISCARDED — never surfaced past the BFS loop]

                    FUSE mount (crates/fuse) — desktop-local, in-memory InodeTable
                    ═══════════════════════════════════════════════════════════
   handle_unlink/handle_rmdir/handle_rename (fuser)          handle_set_delete/handle_rename (WinFsp)
        │                                                          │
        ▼                                                          ▼
   run_scope_exit_gate[_coalesced](fs, ino, ...)  ◄── SHARED gate primitive (grant_scope.rs)
        │
        ├─► detect_scope_exit_grant_root (immutable borrow: ancestor walk + has_covering_grant)
        │
        └─► rotate_read_on_scope_exit(&mut fs, grant_root_ipns, ...)
                  │
                  ├─► FuseRotationDeps::query_grants_rooted_at ──► [TODO 2: wire to GET /shares/sent]
                  │
                  └─► refresh_grant_root_read_key(&mut fs.inodes, grant_root_ipns, result)
                            │
                      [TODO 1: only refreshes the ONE inode matching grant_root_ipns —
                       needs to walk ALL rotated node_ids and refresh each matching inode]

   WinFsp handle_rename (platform/windows/write_ops.rs)
        │
        ├─► run_scope_exit_gate(&mut fs, source_ino)   [source gated — OK today]
        │
        └─► fs.inodes.remove(dest_ino)                  [TODO 3: dest_ino NEVER gated — bypass]
             (validation for ENOTEMPTY runs AFTER the source gate — TODO 3: wrong order vs fuser)
```

### Recommended Approach per Todo

#### Todo 1 — Per-node key surfacing + intermediate inode refresh

**Rust (`crates/sdk/src/rotation/engine.rs`):**
- Widen `RotateReadResult` (line 809) to additionally carry a per-node map, e.g. `pub rotated_nodes: HashMap<String, RotatedNodeKey>` where `RotatedNodeKey { ipns_name: String, read_key: Zeroizing<[u8;32]>, generation: u32, sequence_number: u64 }`. Do NOT remove the existing top-level `read_key`/`generation`/`sequence_number` fields (root convenience accessors) — additive change, avoids churn to the ~27 existing call sites the D-16 note already documents were preserved via delegating wrappers.
- Populate the map at BOTH hook points already proven to fire for every committed node:
  - Root: `rotate_read_from_node_inner`, `RotateOneOutcome::Committed(root_committed) =>` branch (~line 1538, right where `fresh_root = Some(root_committed)` is set).
  - Every BFS child: the `RotateOneOutcome::Committed(child) =>` branch inside the `while let Some(item) = queue.pop_front()` loop (~line 1817, right after `deps.persist_job(job_record).await`).
  - A repaired dirty node: `repair_dirty_node` (used by the crash-safety resume path) also produces committed key material — check whether it needs to feed the same map (it recovers via the ECIES checkpoint, not a `CommittedRotation`, so confirm its shape before wiring; RESEARCH could not find the exact `repair_dirty_node` return type in this pass — **flag as an open question for the planner to resolve during task-writing**, not blocking, since the D-16 known-limitation text scopes the immediate fix to the "normal" committed-node path).
- The map must carry the node's `ipns_name` (not just `node_id`) because `refresh_grant_root_read_key` matches FUSE inodes by `ipns_name`, not `node_id` — `CommittedRotation` today has `node_id` but the child's `ipns_name` is only available via the `QueueItem`/`child_ref` at the call site, not inside `CommittedRotation` itself. Thread it through at the call site, not by widening `CommittedRotation`.

**TS (`packages/sdk-core/src/rotation/engine.ts`):** Mirror the exact same widening at `RotateReadResult` (line 337) and the two matching commit points inside `rotateOne`'s caller loop (mirrors the Rust line numbers structurally — TS `rotateReadFromNode` line 1244 is the parent function; find its own BFS loop's `Committed`-equivalent branch, likely the non-`skipped` branch of `rotateOne`'s return in the walk). **Rust/TS parity is an explicit phase requirement (source todo says "Rust+TS parity")** — do not let the two shapes drift (e.g. same field names in camelCase/snake_case convention, same map keying by ipnsName).

**FUSE (`crates/fuse/src/write_ops/grant_scope.rs`):**
- Generalize `refresh_grant_root_read_key` (lines 559-582) from "find the ONE inode matching `grant_root_ipns_name`" to "for every entry in `result.rotated_nodes`, find the matching inode by `ipns_name` and refresh its `read_key`" — same `InodeKind::Root {..} | InodeKind::Folder {..}` match arms, just looped over the map instead of a single name. Rename to something like `refresh_rotated_inode_read_keys` since it's no longer grant-root-only.
- `rotate_read_on_scope_exit` (line 468) already threads `RotateReadResult` through — only the refresh call site (line 530: `refresh_grant_root_read_key(&mut fs.inodes, grant_root_ipns_name, &result)`) needs updating to the new multi-node call.

**Note on File inodes:** `refresh_grant_root_read_key`'s match arms cover only `InodeKind::Root`/`InodeKind::Folder`, never `InodeKind::File`. Files also carry a `read_key` field and files ARE rotated by the walk (via `mint_file_key_on_rotate`/CRIT-1), so a stale in-memory File inode read_key could cause a subsequent local file READ (not relink) to fail against the new content encryption — a correctness bug, not a security bypass (the file's own `content_rekey_pending` flag signals lazy re-encrypt-on-next-write per ADR 0002). **Recommend the planner scope File inode refresh into the SAME generalized function** (extend the match arm) since the map already has every node's info regardless of kind — low incremental cost, closes a related staleness gap for free.

#### Todo 2 — `query_grants_rooted_at` implementation

**No engine changes needed.** The seam is already generic and already invoked unconditionally for every rotated node (both root and BFS children) via `re_mint_grants_rooted_at`/`reMintGrantsRootedAt`. This is purely a `FuseRotationDeps` (crates/fuse/src/write_ops/rotation_deps.rs) implementation task, following the **already-shipped TS reference pattern** at `packages/sdk/src/share/owner-reconcile.ts`:

```typescript
// Source: packages/sdk/src/share/owner-reconcile.ts (SHIPPED, already tested)
queryGrantsFn: async (nodeId: string) => {
  const grants = await transport.listSentGrants(); // GET /shares/sent, paginated
  return grants
    .filter((grant) => grant.rootNodeId === nodeId)
    .map((grant) => ({
      shareId: grant.shareId,
      recipientPublicKey: grant.recipientPublicKey,
      isRevoked: grant.isRevoked,
    }));
},
updateGrantFn: (shareId, encryptedReadKey, newGeneration) =>
  transport.updateGrant(shareId, encryptedReadKey, newGeneration),
deleteGrantFn: (shareId) => transport.deleteGrant(shareId),
```

Port to Rust as `impl<T: RotationTransport> RotationDeps for FuseRotationDeps<T>` overrides:

- **`query_grants_rooted_at(&self, node_id: &str)`**: call `cipherbox_api_client::shares::collect_sent_shares(self.transport-or-a-new-api-handle)` and client-side-filter by `share.root_node_id == node_id`, mapping each `SentShareResponse` to `GrantRow { share_id, recipient_public_key: <parse "0x04..." hex to raw bytes>, is_revoked: false }`.
  - **CRITICAL FINDING:** `SentShareResponse` (`crates/api-client/src/shares.rs:97`) has **no `revoked`/`is_revoked` field** — its own doc comment explicitly states "revoked shares are hard-deleted server-side... every row returned by this endpoint is, by construction, an active grant" (matches project memory `feedback-minimize-db-crypto-prefer-hard-delete`). This means `GrantRow.is_revoked` will **always be `false`** when populated from this source, and `delete_grant`/`deleteGrantFn` will **never actually fire** through this path in practice (a genuinely-revoked recipient's row is simply absent from the query result, not present-with-a-flag). The TS `owner-reconcile.ts`'s `isRevoked` field is a vestige of a more general `GrantRow` contract that this particular transport also never sets to `true`. **Implement `delete_grant` anyway** (call the existing `DELETE /shares/:shareId`) for engine-contract completeness/parity, but do not expect a desktop-e2e leg to exercise that branch via this particular query path.
- **`update_grant(&self, share_id, encrypted_read_key, new_generation)`**: needs a **NEW** `crates/api-client/src/shares.rs` wire function, `update_grant(client, share_id, encrypted_read_key_hex, root_generation, ...)` → `PATCH /shares/:shareId/grant`, body `UpdateGrantDto { encryptedReadKey, rootGeneration, encryptedWriteKey: None, clearEncryptedWriteKey: None }` (this rotation path never touches the write key — read-key-rotation-only call, per the DTO's own doc comment: "Omit to leave any existing encryptedWriteKey unchanged (e.g. a read-key-rotation-only call)"). This function does not exist yet in `crates/api-client/src/shares.rs` — confirmed absent from the current file (only `revoke_shares_for_items`, `list_sent_shares`, `collect_sent_shares` exist there today).
- **`delete_grant(&self, share_id)`**: also a **NEW** wire function — `DELETE /shares/:shareId` (`shares.controller.ts:196`, `@Delete(':shareId')`, hard-delete, 204 No Content). Does not exist in `crates/api-client` today either.
- **ECIES wrap:** `re_mint_grants_rooted_at` (the CALLER, already shipped) does the `cipherbox_crypto::wrap_key(new_read_key, &grant.recipient_public_key)` call itself (`engine.rs:613`) — `FuseRotationDeps::update_grant` receives an ALREADY-hex-encoded `encrypted_read_key` string, it does NOT need to wrap anything itself. Just forward it to the PATCH call.
- **`recipient_public_key` parsing:** `SentShareResponse.recipient_public_key` is a `String` in `"0x04..."` hex format; `GrantRow.recipient_public_key` (Rust engine type, `engine.rs:120`) wants raw `Vec<u8>`. Need a hex-decode step (strip `0x0` prefix convention — check how the web/TS side parses this exact field; likely an existing `hexToBytes`-equivalent helper already exists in `cipherbox_crypto` or `crates/api-client` for the `0x04` uncompressed-pubkey convention used elsewhere in this codebase, e.g. `lookupUser`'s regex `^0x04[0-9a-fA-F]{128}$`).

#### Todo 3 — WinFsp RENAME dest-gate + ordering parity

Direct port of the ALREADY-PROVEN fuser pattern at `crates/fuse/src/write_ops/implementation/rename.rs::handle_rename` (lines 93-163) into `crates/fuse/src/platform/windows/write_ops.rs::handle_rename` (~line 1081):

1. **Reorder:** move the destination-replacement POSIX-equivalent validation (`status_directory_not_empty` check, currently ~line 1120s, AFTER the source gate at ~line 1105) to run BEFORE the source `run_scope_exit_gate` call. The fuser file's own comment names this **D-15d**: "destination-REPLACEMENT POSIX validation runs BEFORE any scope-exit gate... validate first, gate second, mutate third."
2. **Add the missing dest gate:** immediately after the (now-reordered, already-passing) source gate, and before the `fs.inodes.remove(dest_ino)` mutation, add:
   ```rust
   // Source: crates/fuse/src/write_ops/implementation/rename.rs:158-163 (fuser twin, D-15d)
   if let Some(dest_ino) = dest_ino {
       if crate::write_ops::grant_scope::run_scope_exit_gate(&mut fs, dest_ino).is_err() {
           return Err(status_access_denied()); // WinFsp twin of fuser's libc::EIO
       }
   }
   ```
   All required helpers (`status_access_denied`, `run_scope_exit_gate`, `grant_scope`) are **already imported/in-scope** in `write_ops.rs` (confirmed: `status_access_denied` used at `handle_set_delete`, line ~1257; `run_scope_exit_gate` already called for `source_ino` in the same function).
3. **Coalescing (item 3 in the todo, marked "optional/evaluate"):** the fuser `rename.rs` reference does NOT use `run_scope_exit_gate_coalesced` for either the source or dest gate — it uses the plain (non-coalescing) `run_scope_exit_gate` for both, unlike `delete.rs`'s coalesced gate. **Recommend NOT porting coalescing to rename** — match the fuser reference exactly (a rename is a two-parent relink, not delete's single-authoritative-publish scenario, per the todo's own note). This keeps WinFsp parity with fuser's existing, already-tested rename gating shape rather than inventing new coalescing logic that fuser itself doesn't have.
4. **Known pre-existing WinFsp gap outside this todo's explicit scope:** unlike the fuser path (lines 105-122, ENOTDIR/EISDIR kind-mismatch checks), the current WinFsp `handle_rename` has NO file-vs-folder kind-mismatch validation before replace — only the ENOTEMPTY-equivalent check. This is not called out in the source todo's acceptance criteria and is not required by the phase Success Criteria (which are scoped to the scope-exit gate, not POSIX-parity completeness) — **flag for the planner as an optional stretch item, not a blocking task**, since fixing D-15d ordering does not require adding this check (it only requires moving the EXISTING check earlier).

### Component Responsibilities

| File | Responsibility | Todo |
|---|---|---|
| `crates/sdk/src/rotation/engine.rs` | `RotateReadResult` widening, per-node map population at both commit hook points | 1 |
| `packages/sdk-core/src/rotation/engine.ts` | TS twin of the above (parity) | 1 |
| `crates/fuse/src/write_ops/grant_scope.rs` | `refresh_grant_root_read_key` → generalized multi-node refresh | 1 |
| `crates/fuse/src/write_ops/implementation/delete.rs` | Caller of `rotate_read_on_scope_exit`; no change expected (uses the same result plumbing) | 1 (verify only) |
| `crates/fuse/src/write_ops/rotation_deps.rs` | `FuseRotationDeps` impl of `query_grants_rooted_at`/`update_grant`/`delete_grant` | 2 |
| `crates/api-client/src/shares.rs` | NEW `update_grant`/`delete_share`(revoke) wire functions | 2 |
| `apps/api/src/shares/shares.controller.ts` | Already exposes `PATCH :shareId/grant` and `DELETE :shareId` — no server change expected | 2 (verify only) |
| `crates/fuse/src/platform/windows/write_ops.rs` | `handle_rename` reorder + dest gate | 3 |
| `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` | Extend with a deep (depth>=2) leg + a second recipient (retained-vs-revoked) | 1, 2 |
| `tests/desktop-e2e/scripts/run-all.ps1` / `run-all.sh` | Already invoke `shared-scope-exit-rotation.mts` on all 3 platforms — likely needs a NEW rename-overwrite leg for Todo 3 (WinFsp-specific SC3) | 3 |

### Anti-Patterns to Avoid

- **Don't re-implement `has_covering_grant` or the ancestor-walk logic** — `grant_scope.rs`'s own module doc comment explicitly calls this "Pitfall 1"; always wrap `cipherbox_sdk::rotation::scope::has_covering_grant`.
- **Don't zero a `RotateReadResult`/`CommittedRotation` key buffer from a callee** — D-09 terminal-owner rule; the historical 48/89 sdk-e2e incident (`project-zeroization-callee-must-not-zero-reused-buffer` memory) was caused by exactly this class of bug in this exact subsystem.
- **Don't conflate the read-plane `ipns_name` and write-plane `child_id`/`node_id`** — D-07 dual-keying is enforced throughout `grant_scope.rs` with explicit tests (`d07_read_plane_grant_root_ipns_and_write_plane_child_id_are_distinct`); the new per-node map must key consistently (recommend `ipns_name` as the map key since `refresh_...read_keys` matches inodes by `ipns_name`, not `node_id`).
- **Don't add coalescing to the WinFsp rename dest-gate** — the fuser reference (the correctness baseline) doesn't have it either; matching, not inventing, is the goal.
- **Don't assume `is_revoked` will ever be `true` from `SentShareResponse`-sourced `GrantRow`s** — write tests that don't depend on that branch firing through the live query path (see Todo 2 finding above).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ECIES key wrapping for grant re-mint | Custom wrap/unwrap | `cipherbox_crypto::wrap_key`/`unwrap_key` | Already used identically by `re_mint_grants_rooted_at` and `FuseRotationDeps::persist_wrapped_key`; T-64-04c parity requirement |
| Ancestor-chain / covering-grant detection | New tree-walk logic | `ancestor_ipns_chain` + `has_covering_grant` (existing, tested) | Pitfall 1 (module doc comment); zero new logic needed for any of the 3 todos |
| Grant listing/filtering | A new "grants rooted at X" server endpoint | Client-side filter of `GET /shares/sent` by `rootNodeId` | Proven, shipped pattern in `owner-reconcile.ts`; RESEARCH A3 "acceptable v1" — do not add server-side filtering as new scope |
| WinFsp rename dest-gate | New Windows-specific gating logic | Port `run_scope_exit_gate` verbatim (already platform-agnostic, `#[cfg(any(feature = "fuse", feature = "winfsp"))]`) | The gate primitive was DESIGNED to be shared cross-platform; this is a call-site wiring gap, not a missing primitive |

**Key insight:** All three todos are "wire an existing, already-correct primitive into a call site that was missed or left incomplete" — none require new cryptography, new schema, or new server endpoints. This sharply bounds the risk profile of the phase.

## Runtime State Inventory

Not a rename/refactor/migration phase — this section is omitted per the skip condition. No renamed identifiers, no schema migration, no runtime state relocation.

## Common Pitfalls

### Pitfall 1: Forgetting the map must key by `ipns_name`, not `node_id`
**What goes wrong:** `CommittedRotation` (both root and child) carries `node_id` prominently, but `refresh_grant_root_read_key`/its generalized successor matches FUSE inodes by `ipns_name` (`InodeKind::Folder { ipns_name, .. } if ipns_name.as_str() == grant_root_ipns_name`). If the new per-node map is keyed by `node_id` only, the refresh function needs a second `node_id -> ipns_name` lookup that doesn't cheaply exist inside the engine (host-agnostic, no InodeTable access).
**Why it happens:** The engine's own BFS state (`QueueItem`) already carries `child_ref.ipns_name` right next to the `CommittedRotation`, but that association is easy to drop when refactoring the return type.
**How to avoid:** Thread `ipns_name` into the map's key (or as a field on the map's value) AT THE CALL SITE inside the walk loop, where both `CommittedRotation` and the enclosing `QueueItem`/`child_ref` are simultaneously in scope — not by widening `CommittedRotation` itself (which is host-agnostic and currently has no `ipns_name` field, by design — the engine tracks nodes by id, IPNS naming is a transport-adjacent concern threaded in from outside).
**Warning signs:** A refresh function that silently no-ops for intermediate nodes (compiles fine, tests pass for the shallow/root-only case, deep case still fails) — exactly the class of bug this phase exists to fix, so a regression here would be invisible without a dedicated deep-scope-exit desktop-e2e leg.

### Pitfall 2: Assuming `delete_grant` is reachable via `query_grants_rooted_at`'s current data source
**What goes wrong:** Writing a desktop-e2e assertion expecting a revoked recipient's grant row to be visible-then-deleted via this exact path will never fire, because `SentShareResponse` never returns a revoked row at all (hard-delete-on-revoke, confirmed by the type's own doc comment).
**Why it happens:** The TS `GrantRow.isRevoked` field name implies a boolean-flag model, but the actual server contract is delete-only.
**How to avoid:** Scope the desktop-e2e "retained vs revoked" leg around: (a) a recipient who genuinely has NO grant on the rotated node (never appears in the query — this is what today's happy path already handles correctly via the no-op default), vs (b) a recipient who DOES have a grant on a DIFFERENT node not touched by the delete (retained, tests `update_grant` firing), vs (c) the deleted item's OWN recipient (already cut off by the rotation itself, independent of this seam — this is what the current single-recipient Bob leg already proves). Do not attempt to test the `is_revoked: true` → `delete_grant` branch through this particular query source.
**Warning signs:** A test that seeds a "revoked" `SentShareResponse` fixture with some ad-hoc `is_revoked: true` field that doesn't actually exist on the wire type — a compile error would catch this in Rust, but a hand-rolled TS mock could silently diverge from the real API contract.

### Pitfall 3: Coalescing-mode double-counting in the deep scope-exit case
**What goes wrong:** `run_scope_exit_gate_coalesced` (Todo 1's neighbor, already shipped) only fires the coalesced (empty-child-list, single-publish) path for a SHALLOW scope-exit (`parent_ipns == grant_root_ipns_name`). A DEEP scope-exit (the Todo 1 target case) falls through to `root_children_override = None`, meaning the grant-root publishes twice (Defect 1's "+2" behavior, already accepted/documented as correct-for-a-child-having-root in the D-16 resolution) AND every intermediate parent along the path still performs its own separate relink. The new intermediate-inode-key-refresh fix must be verified to correctly refresh EVERY intermediate node's key BEFORE any of those relinks fire, not just before the LAST one.
**Why it happens:** The coalescing optimization and the intermediate-key-refresh fix are two independent Phase-70.1/74 mechanisms that both touch the same call sequence but were designed to solve different sub-problems (publish-count minimization vs. key-staleness).
**How to avoid:** Structure the deep-scope-exit desktop-e2e leg to assert the SECURITY invariant directly (revoked recipient cannot decrypt ANY node under the grant root, at every depth) rather than an exact publish-count invariant (the D-16 leg's own history shows publish-count assertions are fragile/depth-dependent — the resolution note explicitly recommends "the security-meaningful invariants... plus, if a count is desired, ... (or seed the grant-root empty at rotation time)").
**Warning signs:** A flaky desktop-e2e leg whose pass/fail depends on exact IPNS sequence-number deltas rather than actual decryptability.

### Pitfall 4: WinFsp rename validation reorder breaking an existing passing test
**What goes wrong:** The current WinFsp `handle_rename` order (source-gate-then-validate) means an existing (if any) WinFsp desktop-e2e/unit coverage may implicitly rely on the CURRENT (buggy) order. Reordering without checking could regress the `status_object_name_collision` (`replace_if_exists == false`) early-return path, which today runs BEFORE the source gate already (confirmed — that check is at line ~1112, ahead of the ENOTEMPTY check).
**Why it happens:** WinFsp's `handle_rename` interleaves THREE checks (collision, source gate, ENOTEMPTY) in a different order than fuser's clean 4-stage pipeline (validate-all, source-gate, dest-gate, mutate) — a naive reorder could accidentally move the collision check too.
**How to avoid:** Only move the ENOTEMPTY-equivalent (`status_directory_not_empty`) check earlier, ahead of the source gate; leave the `replace_if_exists`-collision check exactly where it is (it already runs first and doesn't need reordering — it's unconditional and cannot be affected by scope-exit gating either way).
**Warning signs:** A Windows CI failure on the EXISTING `replace_if_exists=false` collision-rejection scenario after this phase's changes land.

## Code Examples

### Existing D-16 fuser test pattern to mirror for the new deep-scope-exit assertion

```rust
// Source: crates/fuse/src/write_ops/rotation_deps.rs — existing FakeTransport-based
// diagnosis test pattern (already proves publish counts deterministically offline,
// no live network). A deep-scope-exit unit test should follow this exact shape:
// seed a 2-level tree (grant-root -> folderB -> fileC) via FakeTransport.seed(),
// drive rotate_read_from_node through FuseRotationDeps, then assert
// result.rotated_nodes contains BOTH folderB's and fileC's post-rotation keys
// (not just the grant-root's).
```

### Existing WinFsp coalesced-gate call-site pattern (Todo 3's structural template, from Todo 1/2's sibling fix)

```rust
// Source: crates/fuse/src/platform/windows/write_ops.rs:1280-1297 (handle_set_delete)
match crate::write_ops::grant_scope::run_scope_exit_gate_coalesced(
    &mut fs, context.ino, parent_ino,
) {
    Ok(true) => { fs.coalesced_scope_exit_relink_suppressed.insert(context.ino); }
    Ok(false) => { fs.coalesced_scope_exit_relink_suppressed.remove(&context.ino); }
    Err(()) => {
        log::error!("set_delete: grant-scope gate failed for ino {} (rejecting delete)", context.ino);
        return Err(status_access_denied());
    }
}
```
For `handle_rename`'s dest gate, use the PLAIN (non-coalesced) `run_scope_exit_gate` — see the fuser `rename.rs` reference at lines 158-163 for the exact non-coalesced shape to port.

### Existing shipped grant-remint callback pattern (Todo 2's template)

```typescript
// Source: packages/sdk/src/share/owner-reconcile.ts (SHIPPED, unit-tested)
export function buildGrantRemintCallbacks(
  transport: OwnerReconcileTransport
): GrantRemintCallbacks {
  return {
    queryGrantsFn: async (nodeId: string) => {
      const grants = await transport.listSentGrants();
      return grants
        .filter((grant) => grant.rootNodeId === nodeId)
        .map((grant) => ({
          shareId: grant.shareId,
          recipientPublicKey: grant.recipientPublicKey,
          isRevoked: grant.isRevoked,
        }));
    },
    updateGrantFn: (shareId, encryptedReadKey, newGeneration) =>
      transport.updateGrant(shareId, encryptedReadKey, newGeneration),
    deleteGrantFn: (shareId) => transport.deleteGrant(shareId),
  };
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Desktop scope-exit rotation refreshes ONLY the grant-root inode's key | (This phase) refreshes every rotated intermediate inode's key | Phase 74 | Closes the deep-scope-exit revocation-bypass class |
| `FuseRotationDeps` grant seams are a hard no-op (all recipients de-authorized on scope-exit) | (This phase) wires real query/update/delete against `/shares/sent` and `/shares/:id/grant` | Phase 74 | Retained recipients keep access; only genuinely-departed items are cut |
| WinFsp rename overwrite bypasses the scope-exit gate for the destination | (This phase) dest-gated with fuser ordering parity | Phase 74 | Closes a Windows-only revocation bypass on overwrite-rename |

**Deprecated/outdated:** None — this phase does not deprecate anything; it completes a fix (D-16 / Phase 70.1) that was intentionally landed with a documented "Known limitation" and two sanctioned deferrals.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `repair_dirty_node` (crash-safety resume path) also needs its committed key surfaced into the same per-node map, but its exact return shape was not located in this research pass | Todo 1 code example | If the resume path also needs wiring and is missed, a crash-recovered deep rotation could still leave some intermediate inodes stale — planner should have the executor grep `repair_dirty_node`'s signature before finalizing task scope |
| A2 | The `0x04...`-hex-to-raw-bytes parsing for `recipient_public_key` has an existing helper somewhere in `cipherbox_crypto`/`crates/api-client` that this phase can reuse rather than hand-roll | Todo 2 | Minor — if no such helper exists, a small (well-tested-elsewhere-pattern) hex decode needs to be added; low risk, not a design decision |
| A3 | No WinFsp-specific desktop-e2e leg currently exercises a rename-overwrite-with-covering-grant scenario (a NEW test script/step is needed for SC3, beyond extending `shared-scope-exit-rotation.mts`) | Component Responsibilities table | If a suitable leg already exists elsewhere under a name RESEARCH didn't search for, the planner may create a redundant test — low risk, easily deduped during planning |

**All three assumptions are LOW-risk / easily resolved during task-writing** — none affect the phase's overall approach or require user confirmation before planning proceeds.

## Open Questions

1. **Does `repair_dirty_node`'s crash-resume commit path need its own per-node key surfaced too (Todo 1)?**
   - What we know: the "normal" (non-crash) commit path for both root and BFS children is fully traced and confirmed as the hook points.
   - What's unclear: whether a node repaired via the ECIES checkpoint after a crash also needs its refreshed key surfaced to the FUSE inode-refresh step, or whether that's already out of scope (the D-16 note's "Known limitation" text only discusses the normal walk).
   - Recommendation: planner should have the executing agent grep `repair_dirty_node`'s return type/call site (`crates/sdk/src/rotation/engine.rs`, search near `enqueue_dirty_frontier_entry`) as the first task-execution step, and fold it into the same map population if its shape allows; otherwise document as a further out-of-scope follow-up mirroring the D-16 precedent.

2. **Exact hex/`0x04` public-key parsing helper location for Todo 2.**
   - What we know: the `0x04` uncompressed-secp256k1 convention is used consistently across this codebase (`lookupUser`'s regex, `SentShareResponse.recipient_public_key`).
   - What's unclear: whether a ready-made `hex_to_bytes`/`parse_public_key` helper already exists in `crates/api-client` or `cipherbox_crypto` that `FuseRotationDeps::query_grants_rooted_at`'s Rust implementation should call, vs. needing a small new local helper.
   - Recommendation: low-stakes — grep `crates/api-client/src` and `crates/crypto` (or wherever `cipherbox_crypto` lives) for an existing hex-decode utility during task execution; write a 3-line local helper if none exists.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain / cargo workspace | All 3 todos | ✓ | Workspace-pinned (existing) | — |
| `cargo test -p cipherbox-sdk` / `-p cipherbox-fuse` | Unit-test verification (Todo 1, 2) | ✓ | — | — |
| WinFsp build environment | Todo 3 verification | ✗ (macOS dev machine) | — | **CI-only** — `Cargo Check & Test (Windows)` GH Actions job is the sole build/verify surface for WinFsp changes (per project memory `project-winfsp-build-ci-only-macos`); budget a CI round-trip, do not attempt local WinFsp compilation |
| Live desktop-e2e headless mount (macOS FUSE-T / Linux fuser) | Extending `shared-scope-exit-rotation.mts` | Available in principle (per D-16 investigation session) but heavy/flaky — prior session notes recommend scoped `cargo test` over live-mount runs where possible | — | Prefer FakeTransport-based unit tests for the Rust-side logic (Todo 1, 2); reserve the live desktop-e2e run for CI, not local iteration |
| `/shares/sent`, `PATCH /shares/:id/grant`, `DELETE /shares/:id` API endpoints | Todo 2 | ✓ (already implemented server-side, already consumed by TS/web) | — | — |

**Missing dependencies with no fallback:**
- None — WinFsp's CI-only constraint has an established fallback (CI verification), not a blocker.

**Missing dependencies with fallback:**
- WinFsp local build → CI-only verification (established project pattern).
- Live desktop-e2e local iteration → scoped `cargo test` with `FakeTransport`/mock-server harnesses for the bulk of Todo 1/2 logic, reserving live-mount runs for final CI-gated verification.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (Rust, workspace crates `cipherbox-sdk`, `cipherbox-fuse`) + Vitest (TS, `packages/sdk-core`) + desktop-e2e `.mts`/`.ps1` scripts (real-mount, CI-only for Windows) |
| Config file | Workspace `Cargo.toml` / `packages/sdk-core/vitest.config.ts` / `tests/desktop-e2e/scripts/run-all.{sh,ps1}` |
| Quick run command | `cargo test -p cipherbox-sdk` / `cargo test -p cipherbox-fuse` (scoped, no live network — matches D-16's own verification discipline) |
| Full suite command | `cargo test --workspace` (Rust) + `pnpm --filter @cipherbox/sdk-core test` (TS) + `tests/desktop-e2e/scripts/run-all.sh` (macOS/Linux) / `run-all.ps1` (Windows, CI-only) |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SC1 | Deep (depth>=2) scope-exit refreshes every retained inode's key; revoked recipient cannot decrypt any node under the grant root | unit (Rust, FakeTransport) + desktop-e2e (real mount) | `cargo test -p cipherbox-sdk rotation::engine::` / `cargo test -p cipherbox-fuse write_ops::rotation_deps::` / extend `shared-scope-exit-rotation.mts` | Unit test scaffold exists (`covered_scope_exit_with_a_child_publishes_the_grant_root_twice` is the closest analog); ❌ new deep (3-level) test + desktop-e2e leg — Wave 0 |
| SC2 | `query_grants_rooted_at` returns live grants; retained recipients keep access post-rotation; desktop-e2e distinguishes retained vs revoked | unit (Rust, FakeTransport for API calls) + desktop-e2e (real mount, 2 recipients) | `cargo test -p cipherbox-fuse write_ops::rotation_deps::` | ❌ new unit tests for `query_grants_rooted_at`/`update_grant`/`delete_grant`; ❌ desktop-e2e second-recipient leg — Wave 0 |
| SC3 | WinFsp overwrite-rename cannot bypass the scope-exit gate; matches fuser behavior | unit (Rust, mirrors `rename.rs`'s existing `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit` pattern) + Windows CI | `cargo test -p cipherbox-fuse --features winfsp` (build-only locally, full test only in CI) / Windows CI `Cargo Check & Test (Windows)` job | ❌ new WinFsp-side unit tests mirroring the two existing fuser `rename.rs` tests — Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-sdk` / `cargo test -p cipherbox-fuse` (scoped, fast, no live network — matches this codebase's established GSD-subagent constraint of never running live/full suites)
- **Per wave merge:** `cargo test --workspace` (excluding `--features winfsp` full test, which is CI-only) + relevant `pnpm --filter @cipherbox/sdk-core test`
- **Phase gate:** Full suite green (Rust workspace + sdk-core) locally; WinFsp-specific verification deferred to a dispatched `Cargo Check & Test (Windows)` CI run before phase close; desktop-e2e (`shared-scope-exit-rotation.mts` extended) run in CI on all 3 platforms before phase close

### Wave 0 Gaps

- [ ] `crates/fuse/src/write_ops/rotation_deps.rs` — new `FakeTransport`-based unit tests for `query_grants_rooted_at`/`update_grant`/`delete_grant` (Todo 2)
- [ ] `crates/sdk/src/rotation/engine.rs` — new unit test proving `RotateReadResult.rotated_nodes` (or equivalent) contains every rotated node's key for a >=2-level tree, not just the root (Todo 1)
- [ ] `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — TS parity test mirroring the above (Todo 1, Rust+TS parity requirement)
- [ ] `crates/fuse/src/platform/windows/write_ops.rs` — new unit tests mirroring `rename.rs`'s `rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt` and `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit` (Todo 3)
- [ ] `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` — extend with a depth>=2 (grant-root -> folder -> file) leg AND a second recipient (Carol, with a grant on an unaffected subtree) to prove retained-vs-revoked distinction (Todo 1 SC1, Todo 2 SC2)
- [ ] A new (or extended existing) desktop-e2e/`.ps1` step exercising a WinFsp overwrite-rename against a covered destination, gated on Windows CI (Todo 3 SC3)
- [ ] `crates/api-client/src/shares.rs` — new `update_grant`/`revoke_share` (or similarly named) wire functions + their own unit tests (mirrors the existing `revoke_shares_for_items`/`list_sent_shares` test shape in the same file) (Todo 2)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Out of scope — this phase does not touch login/session |
| V3 Session Management | No | Out of scope |
| V4 Access Control | Yes | The entire phase IS an access-control (revocation-soundness) fix — the scope-exit gate (`grant_scope.rs`) and grant re-mint machinery ARE the access-control enforcement points |
| V5 Input Validation | Partial | `UpdateGrantDto` already validates hex-string shape server-side (existing, unchanged); new Rust wire functions must not weaken this (pass through validated shapes, do not add client-side bypass) |
| V6 Cryptography | Yes | `cipherbox_crypto::wrap_key`/`unwrap_key` (ECIES) — never hand-roll; already the established pattern for every touch point in this phase |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Stale in-memory key reseal after rotation (the core bug class this phase fixes) | Elevation of Privilege / Information Disclosure | Refresh EVERY rotated node's in-memory key before any subsequent local relink can reseal under a stale key — the exact fix scope of Todo 1 |
| Ungated destructive mutation of a shared node (WinFsp rename-overwrite) | Elevation of Privilege | Gate EVERY destructive removal (delete, rmdir, rename-overwrite-destination) through the shared `run_scope_exit_gate` — Todo 3's exact fix |
| Silent grant-loss on rotation (over-broad revocation) | Denial of Service (availability, not confidentiality) — retained recipients incorrectly cut off | `query_grants_rooted_at`/`update_grant` re-mint retained recipients' keys — Todo 2's exact fix. Note: the INVERSE failure mode (a revoked recipient incorrectly RETAINED) is guarded by the fact that revoked shares are hard-deleted server-side and therefore never appear in the query result to be re-minted in the first place |
| Key material logged or persisted in plaintext | Information Disclosure | Continue the established `Zeroizing` + "public identifiers (ipns_name, node_id, share_id) are safe to log, key bytes never are" convention already enforced throughout `grant_scope.rs`/`rotation_deps.rs` |

## Sources

### Primary (HIGH confidence — direct source reads in this worktree)
- `crates/sdk/src/rotation/engine.rs` (full rotation engine: `RotateReadResult`, `RotationDeps`, `CommittedRotation`, `rotate_one_inner`, `rotate_read_from_node_inner`, `re_mint_grants_rooted_at`)
- `packages/sdk-core/src/rotation/engine.ts` (TS twin, `RotateReadResult`, `reMintGrantsRootedAt`, `rotateOne`)
- `crates/fuse/src/write_ops/grant_scope.rs` (full file — gate primitives, `refresh_grant_root_read_key`, `rotate_read_on_scope_exit`, `run_scope_exit_gate[_coalesced]`, full test suite)
- `crates/fuse/src/write_ops/rotation_deps.rs` (full file — `FuseRotationDeps`, `ApiClientTransport`, `RotationTransport`, all tests including the D-16 diagnosis proofs)
- `crates/fuse/src/write_ops/implementation/rename.rs` (full file — the fuser reference implementation and its D-15d tests, the exact template for Todo 3)
- `crates/fuse/src/platform/windows/write_ops.rs` (`handle_rename`, `handle_set_delete`, `handle_cleanup` — confirmed the missing dest gate and the reordering gap)
- `crates/api-client/src/shares.rs` (full file — `SentShareResponse`, `collect_sent_shares`, confirmed absence of `update_grant`/`delete_share` wire functions)
- `apps/api/src/shares/shares.controller.ts` (confirmed `PATCH :shareId/grant` and `DELETE :shareId` endpoints already exist)
- `apps/api/src/shares/dto/update-grant.dto.ts` (confirmed `UpdateGrantDto` shape)
- `packages/sdk/src/share/owner-reconcile.ts` (the shipped, tested reference pattern for Todo 2)
- `.planning/debug/scope-exit-part-a-fail.md` (full D-16 diagnosis + resolution — the direct provenance of all three todos)
- `.planning/todos/pending/2026-07-09-deep-scope-exit-rotation-refreshes-only-grant-root-inode-key.md`
- `.planning/todos/pending/2026-07-08-desktop-query-grants-rooted-at-remint-noop.md`
- `.planning/todos/pending/2026-07-08-winfsp-d15d-gate-ordering-parity.md`
- `.planning/ROADMAP.md` (Phase 74 section)
- `.planning/STATE.md`
- `.github/workflows/desktop-e2e.yml`, `tests/desktop-e2e/scripts/run-all.ps1` (confirmed cross-platform CI wiring of `shared-scope-exit-rotation.mts`)
- `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` (confirmed current single-recipient, shallow-only leg)

### Secondary (MEDIUM confidence)
- None — no web-search or non-authoritative sources were needed; this phase is entirely internal-codebase archaeology.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no external dependencies, all internal crates already in the workspace
- Architecture: HIGH — every claim traced to a specific file:line in this worktree
- Pitfalls: HIGH — derived directly from the D-16 debug note's own documented failure modes and the codebase's existing test patterns

**Research date:** 2026-07-11
**Valid until:** Should be treated as valid until this phase's code lands (this research is a snapshot of an in-flux subsystem that Phase 74 itself is about to modify) — re-verify file:line references if planning is deferred more than a few days past this research date.
