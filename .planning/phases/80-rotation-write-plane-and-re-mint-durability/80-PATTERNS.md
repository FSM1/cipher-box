# Phase 80: Rotation Write-Plane and Re-Mint Durability - Pattern Map

**Mapped:** 2026-07-12
**Files analyzed:** 10
**Analogs found:** 10 / 10

## Correction to phase brief

The write-body wire format is **plaintext canonical JSON, not CBOR**
(`crates/core/src/node/encode.rs:110-124` `encode_write_body`, mirrored by
`packages/core/src/node/encode.ts:140-155` `encodeWriteBody`). It is then
AEAD-sealed as opaque bytes (`seal_node`/`seal_published_node`, ROLE_BODY
0x01). The "CBOR integer-key dup-key/float" gotcha in
`[[project-cross-language-verification-parity-gotchas]]` applies to a
*different* wire structure (IPNS records), not `NodeWriteBody`. The D-03b
cross-language parity test for the new pin field should mirror the
**existing JSON KAT pattern** below (`node_write_body_vectors.rs` /
`node-codec.json`), not a CBOR contract test. Plan accordingly — don't invent
a CBOR encoder for this field.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `crates/core/src/node/types.rs` (`NodeWriteBody`) | model | transform | itself (add field) | exact |
| `crates/core/src/node/encode.rs` / `decode.rs` | transform | transform | itself (add field, extend KAT) | exact |
| `crates/core/tests/node_write_body_vectors.rs` | test | transform | itself (extend vector) | exact |
| `packages/core/src/node/types.ts` / `encode.ts` / `decode.ts` | model/transform | transform | itself (add field) | exact |
| `tests/vectors/node-codec.json` | fixture | transform | itself (add `pins`/pin-list vector) | exact |
| `crates/fuse/src/write_ops/rotation_deps.rs::ApiClientTransport::publish` | service | request-response | `crates/fuse/src/write_ops/replay.rs` (write-body reconstruct + `seal_node`) | exact |
| `crates/fuse/src/write_ops/rotation_deps.rs::query_grants_rooted_at` | service | CRUD | itself (add caching) | exact |
| `crates/sdk/src/rotation/engine.rs::re_mint_grants_rooted_at` | service | event-driven | itself (add compare) | exact |
| `packages/sdk-core/src/rotation/engine.ts::reMintGrantsRootedAt` | service | event-driven | itself (add compare) | exact |
| `packages/sdk/src/share/owner-reconcile.ts::buildGrantRemintCallbacks` | service | CRUD | itself (add cache wrapper) | exact |
| `apps/web/src/services/owner-reconcile.service.ts` | service | request-response | itself (decode pattern reused) | exact |
| `apps/web/src/components/file-browser/ShareDialog.tsx` (issuance write) | component | request-response | itself (existing share-create call site) | exact |
| `apps/web/recovery-src/walk.ts` | utility | file-I/O | itself — consumes `@cipherbox/core` `unsealNode`, inherits parity automatically | exact |
| `crates/fuse/src/write_ops/grant_scope.rs::refresh_rotated_inode_read_keys` | service | event-driven | itself (D-04 consumer, no change needed — just verify) | exact |

## Pattern Assignments

### `crates/core/src/node/types.rs`, `encode.rs`, `decode.rs` (D-03b schema)

**Analog:** itself — `NodeWriteBody` (`crates/core/src/node/types.rs:131-145`)

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeWriteBody {
    #[serde(with = "base64_key")]
    pub ipns_private_key: Vec<u8>,
    pub write_children: Vec<WriteChildRef>,
}
```

Add the pin list as a new field, e.g. `pub recipient_pins: Vec<Vec<u8>>` (or
hex/base64-encoded `String`s to match `recipient_public_key` handling
elsewhere — see `rotation_deps.rs:270-272` which strips `0x` and hex-decodes
server-supplied keys; store pins in the **same encoding convention** so the
compare in D-03d is a direct byte/hex comparison with no re-encoding step).

Note `SealedChildRef` uses `#[serde(deny_unknown_fields)]`
(`types.rs:100`) but `NodeWriteBody` does **not** — this is intentional and
must be preserved: D-03 depends on `NodeWriteBody` tolerating unknown fields
so `apps/web/recovery-src` (Phase-78, pinned to an older schema) doesn't
fail-closed on the new field. Do not add `deny_unknown_fields` to
`NodeWriteBody`.

**Encode pattern** (`crates/core/src/node/encode.rs:110-124`):

```rust
/// FIXED field order (`ipnsPrivateKey` then `writeChildren`) so the output is
/// deterministic and, once sealed under the writeKey, byte-identical to the
/// frozen cross-language KAT...
pub fn encode_write_body(wb: &NodeWriteBody) -> Result<Vec<u8>, NodeError> {
    serde_json::to_vec(wb).map_err(|_| NodeError::SerializationFailed)
}
```

Appending the new field to the struct changes the FIXED field order the KAT
depends on — the existing `write_body_seal_matches_kat` test
(`crates/core/tests/node_write_body_vectors.rs`) will need its oracle vector
in `tests/vectors/node-codec.json` regenerated/extended (add
`recipientPins` to `seal_vectors[].expected_published_node` or add a new
vector), not silently left stale.

**TS mirror** (`packages/core/src/node/encode.ts:140-155`,
`decode.ts:317-345`, `types.ts:135-140`) — same field, same camelCase name,
same base64/hex convention. `decodeWriteBody` currently manually validates
`ipnsPrivateKey`/`writeChildren` shape (throwing `CryptoError` with code
`DECRYPTION_FAILED` on malformed input) — extend with the same
manual-validation style for the new field, defaulting to `[]` if absent
(never throwing) so older-schema documents (Phase-78 recovery tool consumer,
D-03e "no legacy" only applies to *shares*, not to bytes-on-disk written
before this phase) don't fail-closed on read. Fail-closed only applies at
the D-03d **compare** sites, not at decode.

### Cross-language JSON KAT (D-03b test structure)

**Analog:** `crates/core/tests/node_write_body_vectors.rs` (full file read,
53-123) + `tests/vectors/node-codec.json` `seal_vectors[]`

Pattern to replicate for the new field's parity test:
- Load the same shared oracle `tests/vectors/node-codec.json` (`vectors_path()` helper, lines 17-21).
- Deserialize a `SealVector` struct mirroring the JSON shape (`#[serde(rename = "...")]` for camelCase JSON keys).
- Build a `NodeWriteBody` in Rust with the new field populated from the vector, call `encode_write_body`, seal with `encrypt_aes_gcm_aad` under the vector's `fixed_iv`/`write_key`, and assert byte-identical to `expected_published_node.write_sealed` (lines 97-121).
- Guard `!vectors.seal_vectors.is_empty()` — no vacuous pass (line 76-79).
- TS counterpart: `packages/core/src/__tests__/node-codec-vectors.test.ts` — same oracle file, asserts `encodeWriteBody`/`decodeWriteBody` byte-parity. Read that file's existing `write_sealed`/round-trip assertions before extending (not yet excerpted here — same vectors_path pattern as Rust, adjusted for `import.meta` / repo-root resolution).
- Also add a **round-trip unit test** in the `#[cfg(test)] mod write_body_tests` block already in `encode.rs:126-` (existing example: `write_body_round_trip_populated`, lines 132-139) — extend it to cover the new field non-empty AND empty (mirrors this repo's convention of testing both populated and default-empty variants).

### `crates/fuse/src/write_ops/rotation_deps.rs::ApiClientTransport::publish` (D-01a reconstruct)

**Analog:** same file, `FuseRotationDeps::publish` doc comment
(`rotation_deps.rs:371-378`) documents the `InodeTable` signing-key sourcing
pattern already used by `publish` (lines 417-496) for the **read** plane;
extend the same function for the **write** plane reconstruction.

Fail-closed precedent to copy verbatim (lines 426-431):

```rust
let signing_seed = find_ipns_private_key(self.inodes, ipns_name).ok_or_else(|| {
    RotationError::RotateFailed(format!(
        "publish: no locally-cached IPNS signing key for {ipns_name} \
         (node not materialized in the local inode table)"
    ))
})?;
```

D-01b (fallback to `None` for a non-materialized node) is the **inverse** —
when the node/children aren't locally available, do NOT error; set
`node.write_sealed = None` and proceed (matches current behavior, so this is
an explicit opt-out path, not a new error). Use `InodeKind::Root { .. } |
InodeKind::Folder { .. }`'s `children` map (see `grant_scope.rs:613-628` for
the `InodeKind` match-arm idiom) to rebuild `WriteChildRef`s from child
inodes' write keys.

**Seal call** — use `cipherbox_core::node::seal_node` (`crates/core/src/node/seal.rs:48`, shares `ROLE_BODY = 0x01` AAD with `seal_published_node`'s write arm at `seal.rs:169-192`) at the node's **new generation**, mirroring `publish`'s existing `create_ipns_record`/`upload_content` sequencing (lines 434-463) — reseal happens before `upload_content`, same as the read body.

**D-01c tests** — add unit tests beside the existing `ApiClientTransport` tests in this module (check bottom of `rotation_deps.rs` for existing `#[cfg(test)]`) for: (1) reconstruct round-trip (unseal under write key at new generation recovers the write body/children), (2) `None` fallback for a non-materialized node.

### `query_grants_rooted_at` caching (D-02) + TS `queryGrantsFn` (D-02a)

**Analog:** `rotation_deps.rs:264-286` (current per-call fetch) — add a
`OnceCell`/`tokio::sync::OnceCell` or a plain `Option<Vec<SentShareResponse>>`
field on `ApiClientTransport` (constructed once per rotation job — check the
job-scoped constructor, likely near `ApiClientTransport::new`/struct
definition ~line 379) so `collect_sent_shares()` (line 498-506) is called at
most once per job and `query_grants_rooted_at` filters the cached list by
`root_node_id` (existing filter logic at line 268 is unchanged — just swap
the fresh fetch for a cache read/populate).

Preserve the existing per-share error handling exactly (lines 270-278: `0x`
strip, hex-decode, per-share `RotateFailed` on bad key) — do not change
error semantics, only add caching.

**TS mirror:** `packages/sdk/src/share/owner-reconcile.ts::buildGrantRemintCallbacks` (lines 66-84) — `queryGrantsFn` currently calls `transport.listSentGrants()` fresh every invocation (line 71). Cache the `listSentGrants()` promise/result for the lifetime of the `runOwnerReconcile` call (function at lines 94-104) — e.g. lazily populate a closure-scoped variable in `buildGrantRemintCallbacks` shared across repeated `queryGrantsFn` calls within one reconcile pass. Same filter-by-`rootNodeId` logic stays (line 73).

### Fail-closed pubkey pin compare (D-03d) — three consumers

**Rust site 1 — `crates/sdk/src/rotation/engine.rs::re_mint_grants_rooted_at`** (lines 597-620):

```rust
async fn re_mint_grants_rooted_at<D: RotationDeps>(...) {
    ...
    let wrapped = cipherbox_crypto::wrap_key(new_read_key, &grant.recipient_public_key)
        .map_err(|e| RotationError::RotateFailed(format!(
            "re_mint_grants_rooted_at: wrap_key failed for share {}: {e}", ...
        )))?;
```

Insert the pin compare immediately before this `wrap_key` call: fetch the
root node's `NodeWriteBody.recipient_pins` (already unsealed as part of the
rotation walk — thread it through the same way `deps` already carries other
node state) and `RotateFailed` (same error type/format style) on mismatch or
absent-pin (D-03e: absent = hard fail, not TOFU).

**Rust site 2 — `rotation_deps.rs::query_grants_rooted_at`** doesn't wrap
keys itself (that's the engine's job) — no compare needed there; the compare
belongs in the engine per D-03d ("all three round-trip consumers" = the
three **wrap** call sites, not the query call site).

**TS site — `packages/sdk-core/src/rotation/engine.ts::reMintGrantsRootedAt`**
(lines 563-590, wrap call at line 587):

```typescript
const wrappedBytes = await wrapKey(newReadKey, grant.recipientPublicKey);
```

Same insertion point — compare against the pin list before this call, throw
(mirror this file's existing `Error` construction style, e.g. line 2764's
`throw new Error('rotateWriteFromNode: wrapKey for co-writer failed', { cause: err })` pattern) on mismatch/absent.

**Web site — `apps/web/src/components/file-browser/ShareDialog.tsx`**
(wrap calls at lines 184, 205) and **`owner-reconcile.service.ts`** (decode
at lines 57-69) — these are thin wrappers over the sdk-core/sdk functions
above; the compare should live in sdk-core/sdk (D-03d's "three consumers"),
not duplicated in the web layer, UNLESS the web ShareDialog upgrade/downgrade
path calls `wrapKey` directly without routing through `reMintGrantsRootedAt`
— confirm at the plan stage which of ShareDialog's two `wrapKey` call sites
(184, 205) are issuance-time (trusted, no pin exists yet) vs
reconcile/upgrade-time (must compare). Issuance-time calls are exempt (the
pin doesn't exist until this call writes it — D-03c).

### Issuance write (D-03c) — where to write the pin

**Site:** `apps/web/src/components/file-browser/ShareDialog.tsx` around the
existing share-create call (near line 184-222, where `recipientPublicKey`
is ECIES-wrapped and the share row is POSTed). Add a client-side step here
that updates the shared **root node's** `NodeWriteBody.recipient_pins`
(append this recipient's raw pubkey), then re-seals and re-publishes that
node's write body — reuse whatever "update this node's write body and
republish" helper `packages/sdk-core/src/folder/registration.ts` already
exposes for write-chain mutation (it already threads `WriteChildRef[]`
updates through a merge+republish flow, e.g. `registration.ts:379-397`
`mergedMap`/`byChildId` merge pattern) rather than hand-rolling a new
publish path.

### D-04 — TS `rotatedNodes` defensive copy

**Analog:** the fix is already spec'd exactly by CONTEXT.md D-04, and the
Rust side to mirror is `crates/sdk/src/rotation/engine.rs`'s
`Zeroizing<[u8;32]>` clone-per-node pattern (search `rotated_nodes` insert
sites in that file — same function family as `re_mint_grants_rooted_at`).

**Current TS (to fix)** — `packages/sdk-core/src/rotation/engine.ts:2056-2059` (root):

```typescript
rotatedNodes.set(rootNodeIpnsName, {
  ipnsName: rootNodeIpnsName,
  readKey: rootResult.childReadKey,
  ...
});
```

and the child-branch equivalent at `:2227-2231` (`result.childReadKey`
directly). Fix per D-04: `readKey: new Uint8Array(rootResult.childReadKey)`
/ `new Uint8Array(result.childReadKey)`. The file already has the exact
"defensive copy, not zeroed here" idiom to copy at line ~2068-2070
(`parentOldReadKey: new Uint8Array(rootReadKey)` with the comment "a
defensive copy of the caller-owned rootReadKey... owned by this tracking
state so it can be safely zeroed on teardown below without touching the
caller's buffer") — replicate that exact comment style for the `rotatedNodes`
fix.

**Regression test:** add near existing rotation-engine tests asserting
`rotatedNodes` values are non-aliased with `parentNewReadKey`, non-zero, and
equal to the node's expected post-rotation key (per D-04's spec).

**Consumer — `crates/fuse/src/write_ops/grant_scope.rs::refresh_rotated_inode_read_keys`**
(lines 613-628) is the Rust consumer of the *Rust* `rotated_nodes` map
(already independently cloned via `Zeroizing`, no bug there) — this file
needs no change for D-04 itself; it's cited in scope only as the FUSE
consumer that a *future* TS-side zero-on-drop tightening would have broken.
Confirm no Rust changes needed here beyond an optional comment/test noting
the parity guarantee.

## Shared Patterns

### Fail-closed error style

**Source:** `rotation_deps.rs:426-431`, `re_mint_grants_rooted_at` (engine.rs:610-615)

All new fail-closed compares should use the same `RotateFailed(format!("<fn>: <what> for <id>: <detail>"))` message convention (Rust) and `throw new Error('<fn>: <what>', { cause })` (TS) already used throughout these two engines — do not introduce a new error type.

### 0x-strip / hex-decode convention for recipient keys

**Source:** `rotation_deps.rs:270-272`, `owner-reconcile.service.ts:57-59`, `ShareDialog.tsx:297-299`

```typescript
const bareHex = share.recipientPublicKey.startsWith('0x')
  ? share.recipientPublicKey.slice(2)
  : share.recipientPublicKey;
```

Reuse this exact idiom (already duplicated 3x in TS, once in Rust) if the pin list is stored/compared as hex — apply consistently so the D-03d compare is a straight equality check with no encoding mismatch.

## No Analog Found

None — all 10 files have a strong same-file or same-role exact match (this phase is entirely modifications to existing rotation/write-plane machinery, no genuinely new subsystem).

## Metadata

**Analog search scope:** `crates/core/src/node/`, `crates/core/tests/`, `crates/fuse/src/write_ops/`, `crates/sdk/src/rotation/`, `packages/core/src/node/`, `packages/sdk-core/src/rotation/`, `packages/sdk/src/share/`, `apps/web/src/services/`, `apps/web/src/components/file-browser/`, `apps/web/recovery-src/`
**Files scanned:** ~20 (targeted reads/greps, no full-repo scan)
**Pattern extraction date:** 2026-07-12
