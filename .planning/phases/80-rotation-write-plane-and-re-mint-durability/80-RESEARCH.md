# Phase 80: Rotation Write-Plane and Re-Mint Durability - Research

**Researched:** 2026-07-12
**Domain:** Rust/TS cross-language sharing-crypto — NodeWriteBody re-sealing, ECIES re-mint, CBOR/JSON wire parity
**Confidence:** HIGH (all code sites read directly; no framework-selection ambiguity — this is a closed-codebase surgical phase)

## Summary

This phase touches four narrow, already-located code sites (D-01 through D-04) inside an
existing, well-tested `node/v3` codec and rotation-engine architecture. Three of the four
(D-01, D-02, D-04) are mechanical fixes to functions that already exist and already have
test scaffolding to extend. D-03 (the recipient-pubkey pin) is the one genuine net-new
design surface: it requires (a) a new optional field on `NodeWriteBody` with matching
Rust/TS wire-tolerance, (b) a **new SDK write path** to mutate-and-republish a shared
node's own write-body pin list at share-issuance time (no such mutation path currently
exists — `resolveShareEncryptedWriteKey` only *derives* the item's writeKey, it never
writes back to the write-body), and (c) three independent fail-closed comparison sites
threaded with access to that pin list.

**Primary recommendation:** Sequence the four items D-01 → D-02 → D-04 → D-03, in that
order. D-01/D-02/D-04 are additive, low-risk, and unblock the D-03 cross-language vector
work (D-03's schema change is easiest to reason about once the write-body reconstruction
path (D-01) is already flowing real write-body content through `rotation_deps.rs`). D-03
is the only item requiring new cross-language KAT vectors and a net-new SDK method
(`addRecipientPubkeyPin` or equivalent) — budget it as its own plan/wave.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Write-body reconstruction on rotation republish (D-01) | API/Backend (FUSE transport adapter, in-process) | — | `ApiClientTransport::publish` is the FUSE-mount-local write-plane assembly point; no server involvement |
| Sent-shares fetch caching (D-02) | API/Backend (SDK/rotation-engine callers) | — | Both Rust `FuseRotationDeps` and TS `owner-reconcile.ts` are the two callers issuing the redundant `GET /shares/sent` |
| Recipient-pubkey pin storage (D-03a) | Database/Storage (IPFS-sealed `NodeWriteBody`) | — | Owner-sealed, IPNS-published — server-opaque by construction, not a DB column |
| Recipient-pubkey pin enforcement (D-03d) | API/Backend (3 independent consumers: Rust FUSE, TS SDK, web service) | Browser/Client (ShareDialog upgrade/downgrade UI) | Each consumer independently re-wraps a key to a server-returned pubkey; each must independently verify against the pin before wrapping |
| TS `rotatedNodes` defensive copy (D-04) | API/Backend (`packages/sdk-core` rotation engine, pure in-memory) | — | No I/O; a buffer-aliasing correctness fix inside the TS rotation walk |

## Standard Stack

No new dependencies. This phase is 100% internal crypto/codec/engine surgery inside the
existing `node/v3` stack (`packages/core`, `crates/core`, `packages/sdk-core`,
`crates/sdk`, `crates/fuse`). No package installs, so `## Package Legitimacy Audit` is
not applicable — skipped.

**Existing primitives this phase composes (verified in this session):**

| Primitive | Location | Purpose |
|-----------|----------|---------|
| `seal_node` / `unseal_node` | `crates/core/src/node/seal.rs:48-74` | AES-256-GCM + AAD role `0x01` body seal, used by D-01's re-seal |
| `seal_published_node` | `crates/core/src/node/seal.rs:169-209` | Seals BOTH read+write bodies into a `PublishedNode`; explicit `write_body: Option<&NodeWriteBody>` param (never a `Node` field — Landmine 2 in the module doc, deliberate to avoid a D-02/D-07 core/sdk split) |
| `sealNode` / `unsealNode` (TS twin) | `packages/core/src/node/seal.ts:78-150` (approx; `unsealNode` at :121) | Same role, `writeKey` param is **optional** (line 124: `writeKey?: Uint8Array`) — write-body unseal is skipped entirely when omitted |
| `encodeWriteBody`/`decodeWriteBody` | `packages/core/src/node/encode.ts:140-155`, `packages/core/src/node/decode.ts:317-364` | Manual (non-schema-validated) JSON encode/decode of `NodeWriteBody` |
| `encode_write_body`/`decode_write_body` (Rust twin) | `crates/core/src/node/encode.rs:110-124`, `crates/core/src/node/decode.rs:113-118` | `serde_json::to_vec`/`from_slice` directly on the `NodeWriteBody` struct (no `deny_unknown_fields`) |
| `wrap_key`/`unwrap_key` (ECIES) | `cipherbox_crypto` (Rust), `@cipherbox/crypto` (TS) | The re-mint/re-wrap primitive at every D-03 enforcement site — never hand-roll |

## Package Legitimacy Audit

Not applicable — no external packages are added by this phase.

## Architecture Patterns

### System Architecture Diagram

```text
                     ┌─────────────────────────────────────────┐
                     │   Scope-exit read-key rotation walk       │
                     │   (crates/sdk/rotation/engine.rs /         │
                     │    packages/sdk-core/rotation/engine.ts)   │
                     └───────────────┬─────────────────────────┘
                                     │ per-node commit
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │ rotate_one / rotateOne: mint readKey', reseal SealedChildRef│
        └───────────────┬──────────────────────┬───────────────┘
                         │                      │
     (D-01) publish path │       (D-02/D-03) re_mint_grants_rooted_at
                         ▼                      ▼
    ┌────────────────────────────┐   ┌──────────────────────────────┐
    │ ApiClientTransport::publish │   │ query_grants_rooted_at()      │
    │ (rotation_deps.rs)          │   │  -> collect_sent_shares()     │
    │                              │   │     GET /shares/sent          │
    │ if write_sealed==None:      │   │  (D-02: cache once per job,   │
    │  reconstruct NodeWriteBody  │   │   filter by root_node_id)     │
    │  from InodeTable, re-seal   │   │                                │
    │  via seal_node at NEW gen   │   │ for each non-revoked grant:   │
    │  (ROLE_BODY=0x01 AAD)       │   │  (D-03) verify grant.recipient │
    │  fail-open->None if node    │   │  _public_key against the pin  │
    │  not locally materialized   │   │  list read from THIS node's   │
    └──────────────┬───────────────┘   │  own NodeWriteBody, THEN      │
                   │                   │  wrap_key(new_read_key, pk)   │
                   ▼                   └──────────────────────────────┘
    ┌────────────────────────────┐
    │ PublishedNode.write_sealed  │
    │ (now populated)             │
    └──────────────┬───────────────┘
                   ▼
    ┌────────────────────────────────────────┐
    │ replay.rs::recover_signing_seed()        │
    │ unseals write_sealed -> ipns_private_key │
    │ (D-01 durability consumer — the fix      │
    │  closes the "cannot recover signing seed"│
    │  fail path)                              │
    └────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │ D-04 (TS-only, in-memory, no I/O):                          │
    │ rotateReadFromNode's rotatedNodes.set(ipnsName, {            │
    │   readKey: <SAME Uint8Array ref as parentNewReadKey> })      │
    │ engine.ts:2057 (root) / :2228 (child) — aliasing bug         │
    │ Fix: wrap in `new Uint8Array(...)` at the .set() call only   │
    └────────────────────────────────────────────────────────────┘

    ┌────────────────────────────────────────────────────────────┐
    │ D-03 issuance write (NEW — no existing code path):           │
    │ ShareDialog.tsx::handleShare() (apps/web) pastes recipient   │
    │ pubkey -> MUST also write it into the shared root NODE's own │
    │ write-body pin list (a new SDK mutate+republish call,        │
    │ sibling to the existing resolveShareEncryptedWriteKey which  │
    │ only DERIVES, never WRITES, to a write-body)                 │
    └────────────────────────────────────────────────────────────┘
```

### Recommended Project Structure

No new files/folders — every change is inside existing modules:

```text
crates/core/src/node/
├── types.rs      # D-03b: add recipient_pubkey_pins field to NodeWriteBody (Option<Vec<Vec<u8>>>, #[serde(default)])
├── encode.rs      # D-03b: encode_write_body — conditionally emit pin field
├── decode.rs      # D-03b: decode_write_body — tolerate absent field (already tolerant: no deny_unknown_fields)
├── seal.rs        # unchanged — seal_published_node already takes write_body: Option<&NodeWriteBody>

crates/fuse/src/write_ops/
├── rotation_deps.rs  # D-01 fix (ApiClientTransport::publish), D-02 fix (cache collect_sent_shares), D-03 enforcement (query_grants_rooted_at)
├── grant_scope.rs    # D-04 downstream consumer (refresh_rotated_inode_read_keys) — READ ONLY, Rust side already correct (Zeroizing clone)

crates/fuse/src/replay.rs  # D-01 durability consumer (recover_signing_seed) — no code change, just a regression test target

crates/sdk/src/rotation/engine.rs  # D-02/D-03 fix (re_mint_grants_rooted_at, query_grants_rooted_at trait default)

packages/core/src/node/
├── types.ts       # D-03b: add recipientPubkeyPins?: string[] (or Uint8Array[]) to NodeWriteBody
├── encode.ts       # D-03b: encodeWriteBody — conditionally emit pin field
├── decode.ts       # D-03b: decodeWriteBody — tolerate absent field (already manual/tolerant)

packages/sdk-core/src/rotation/engine.ts  # D-02 fix (queryGrantsFn caching contract), D-03 enforcement (reMintGrantsRootedAt), D-04 fix (rotatedNodes.set defensive copy at :2057/:2228)

packages/sdk/src/share/owner-reconcile.ts     # D-02 mirror (buildGrantRemintCallbacks caching), D-03 enforcement
packages/sdk/src/client.ts                    # D-03c: NEW method to write the pin into a node's own write-body (sibling to resolveShareEncryptedWriteKey ~:3839)

apps/web/src/services/owner-reconcile.service.ts  # D-03 enforcement (3rd consumer)
apps/web/src/components/file-browser/ShareDialog.tsx  # D-03c issuance write (handleShare ~:162) + D-03d enforcement (upgrade path ~:286-327)

tests/vectors/node-codec.json   # D-03b: NEW seal_vector entry with a non-empty pin list (lockstep discipline)
docs/METADATA_SCHEMAS.md         # D-03b: document the new NodeWriteBody field, bump version-history table
```

### Pattern 1: Fail-open reconstruction with an explicit "not materialized" boundary (D-01)

**What:** `ApiClientTransport::publish` must reconstruct `NodeWriteBody` only from data the
FUSE mount already has plaintext access to in-memory (`InodeTable`), and return `None` for
`write_sealed` rather than erroring when the node isn't locally materialized.

**When to use:** Any time a republish needs write-plane data the current transport layer
wasn't designed to carry, and a graceful degradation (not a hard failure) is the existing
project convention for "node not in local cache" (see `find_ipns_private_key`,
`crates/fuse/src/write_ops/rotation_deps.rs:555-576`, which already returns `Option` for
exactly this reason).

**Example — the existing sibling helper to mirror for reconstruction:**
```rust
// Source: crates/fuse/src/write_ops/rotation_deps.rs:552-576
fn find_ipns_private_key(inodes: &InodeTable, ipns_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    inodes.inodes.values().find_map(|inode| {
        let (candidate_name, key) = match &inode.kind {
            InodeKind::Root { ipns_name, ipns_private_key, .. } => (ipns_name, ipns_private_key),
            InodeKind::Folder { ipns_name, ipns_private_key, .. } => (ipns_name, ipns_private_key),
            InodeKind::File { ipns_name, ipns_private_key, .. } => (ipns_name, ipns_private_key),
        };
        (candidate_name == ipns_name && !key.is_empty()).then(|| Zeroizing::new(key.to_vec()))
    })
}
```
D-01's reconstruction helper should follow the identical `inodes.inodes.values().find_map`
shape, additionally pulling the node's own **stable write key** and rebuilding each child's
`WriteChildRef` from the child inodes' cached write keys (documented as
"read-key-rotation-independent" in CONTEXT D-01a). The `InodeKind::{Root,Folder,File}`
variants already carry `ipns_private_key`; confirm during planning whether they also cache
a `write_key` field and child write-key material — if not, this is the actual scope
boundary of D-01a (grep `InodeKind` definition in `crates/fuse/src/inode.rs` before
planning the exact reconstruction fields).

### Pattern 2: Single-fetch-per-job caching via an owned cache field, not a static/global (D-02)

**What:** `collect_sent_shares()` (a full `GET /shares/sent`) is currently called once
**per rotated node** from both `query_grants_rooted_at` (Rust, `rotation_deps.rs:264-286`)
and `queryGrantsFn` (TS, `owner-reconcile.ts:66-84` calling `transport.listSentGrants()`
fresh every invocation). Both call sites are simple pass-throughs with no caching layer.

**When to use:** Any per-job (not per-request) invariant data set that a walk re-fetches on
every per-node callback.

**Fix shape:** Add a cache field to `FuseRotationDeps<T>` (Rust) — e.g. an
`Arc<tokio::sync::OnceCell<Vec<SentShareResponse>>>` or a simple `RefCell<Option<Vec<...>>>`
scoped to the lifetime of a single `rotate_read_from_node` call — populated on first
`query_grants_rooted_at` call, reused thereafter, filtered by `root_node_id` per call. For
TS, `buildGrantRemintCallbacks` (owner-reconcile.ts:66) needs the equivalent: the returned
`queryGrantsFn` closure should memoize `transport.listSentGrants()`'s promise on first
call (a simple `let cached: Promise<GrantRow[]> | undefined` closed over by the returned
function object satisfies this — no new dependency needed).

**Landmine:** `FuseRotationDeps` is constructed once per rotation call site in the current
test suite (`FuseRotationDeps::new(transport, owner_pub, owner_priv, floor_store)`,
`rotation_deps.rs:177-191`) — confirm whether a single `FuseRotationDeps` instance is reused
across an ENTIRE rotation job (good — cache lives for the job) or reconstructed per-node
(bad — cache would reset every node, defeating D-02). Grep the call site in
`crates/fuse/src/write_ops/` that constructs `FuseRotationDeps` before assuming instance
lifetime; if it's per-call, the cache must be threaded through the injected `deps` at a
higher scope or invalidated per rotation-job-id, not per-instance.

### Pattern 3: Fail-closed pin comparison at three independent consumer sites (D-03d)

**What:** Every site currently does `wrapKey(newReadKey, grant.recipientPublicKey)` (or the
Rust `wrap_key(new_read_key, &grant.recipient_public_key)`) with NO verification that
`recipientPublicKey` is the one the owner actually issued the share to. D-03 requires
inserting a pin comparison immediately before each wrap, using the pin list read from the
node's OWN `NodeWriteBody` (not from the server response).

**Confirmed exact wrap call sites (verified this session):**

| # | Location | Line | Trust boundary crossed |
|---|----------|------|------------------------|
| 1 | `crates/sdk/src/rotation/engine.rs` `re_mint_grants_rooted_at` | :610 | `cipherbox_crypto::wrap_key(new_read_key, &grant.recipient_public_key)` |
| 2 | `packages/sdk-core/src/rotation/engine.ts` `reMintGrantsRootedAt` | :587 | `await wrapKey(newReadKey, grant.recipientPublicKey)` |
| 3 | `apps/web/src/components/file-browser/ShareDialog.tsx` upgrade path | :306 | `wrapKey(rootWriteKey??..., recipientPublicKey)` — recipientPublicKey decoded straight from `share.recipientPublicKey` (server-fed store, line 297-300) with **no pin check** |

**Also relevant (write-plane co-writer re-wrap, same trust pattern, different function):**
`crates/sdk/src/rotation/engine.rs:2762` (`rotateWriteFromNode`'s co-writer re-wrap) —
confirm during planning whether D-03's scope includes this write-revocation co-writer
re-wrap or is strictly the read-rotation re-mint path; CONTEXT's three named consumers
(rotation_deps.rs/engine.rs Rust, owner-reconcile.ts/sdk-core engine.ts TS, web
owner-reconcile.service.ts + ShareDialog.tsx) do not explicitly name this write-plane
site — flag as an Open Question below.

**Where the pin list must come from:** the pin lives on **the shared root node's own
`NodeWriteBody`** (D-03a) — i.e. the SAME node currently being processed by
`re_mint_grants_rooted_at(node_id, ...)`/`reMintGrantsRootedAt`. Today, neither function
receives that node's write-body content — they only receive `node_id`, `new_read_key`,
`new_generation`, and (via the grant query) the grant rows. **This is the one non-mechanical
design gap in the phase** — see Open Questions.

### Pattern 4: Defensive copy at the collection boundary, not the mutation boundary (D-04)

**What:** The bug is specifically that `rotatedNodes.set(...)` stores the SAME
`Uint8Array` object reference that `ParentTrackingState.parentNewReadKey` also holds — not
that the key is computed wrong. The fix is narrowly scoped to the `.set()` call, not to
where `childReadKey`/`parentNewReadKey` is minted or consumed elsewhere in the 2700-line
engine.

**Confirmed exact lines (verified this session, corrects CONTEXT's approximate line
numbers):**

```typescript
// Source: packages/sdk-core/src/rotation/engine.ts:2055-2060 (root branch)
rotatedNodes.set(rootNodeIpnsName, {
  ipnsName: rootNodeIpnsName,
  readKey: rootResult.childReadKey,      // <-- D-04 bug: same ref as line 2066
  generation: rootResult.newGeneration,
  sequenceNumber: rootResult.newSequenceNumber,
});
// ...
rootParentState = {
  parentNewReadKey: rootResult.childReadKey,  // :2066 — SAME object
  ...
};
```
```typescript
// Source: packages/sdk-core/src/rotation/engine.ts:2226-2231 (BFS child branch)
rotatedNodes.set(item.childRef.ipnsName, {
  ipnsName: item.childRef.ipnsName,
  readKey: result.childReadKey,          // <-- D-04 bug: same ref as line 2287
  generation: result.newGeneration,
  sequenceNumber: result.newSequenceNumber,
});
// ...
thisNodeParentState = {
  parentNewReadKey: result.childReadKey,  // :2287 — SAME object
  ...
};
```

**Fix:** `readKey: new Uint8Array(rootResult.childReadKey)` and
`readKey: new Uint8Array(result.childReadKey)` at the two `.set()` calls ONLY — leave
`parentNewReadKey: rootResult.childReadKey` / `parentNewReadKey: result.childReadKey`
untouched (that live reference is what the walk actively uses to seal children; D-09's
terminal-owner rule means only the RETURNED map should be independently owned).

**`RotatedNodeKey` type** (`packages/sdk-core/src/rotation/engine.ts:345-350`):
```typescript
export type RotatedNodeKey = {
  ipnsName: string;
  readKey: Uint8Array;
  generation: number;
  sequenceNumber: bigint;
};
```
Rust twin: `crates/sdk/src/rotation/engine.rs` (search `RotatedNodeKey`) — already
`.clone()`s into `Zeroizing<[u8;32]>` per CONTEXT D-04, confirmed correct; no Rust change
needed.

**Regression test target:** `refresh_rotated_inode_read_keys` (Rust,
`crates/fuse/src/write_ops/grant_scope.rs:613-638`) is the FUSE consumer that would
mis-decrypt on a future TS-side zero-write bug — but it's Rust-only, so the actual D-04
regression test is TS-only (per CONTEXT: "Add a TS regression test asserting every
`rotatedNodes` value's `readKey` is non-aliased with `parentNewReadKey`").

### Anti-Patterns to Avoid

- **Bumping `generation` to update the write-body pin list (D-03c):** `generation` is the
  READ-KEY rotation clock (`docs/METADATA_SCHEMAS.md` §10 invariants table). Writing a new
  pin into `NodeWriteBody` does NOT require touching the read-body or its generation — the
  read-body and write-body are independently sealed under the SAME AAD generation value
  (`seal_published_node` seals both under `node.generation()`), but re-sealing the
  write-body alone with the CURRENT generation, republishing an updated `PublishedNode`
  with an unchanged `readSealed` and a new `writeSealed`, is a valid, self-consistent
  operation. Do not invent a "pin generation" counter.
- **Re-implementing AEAD or hand-rolling the pin's AAD binding:** the pin list is just
  another field inside the existing `NodeWriteBody` JSON body, sealed by the EXISTING
  `seal_node`/`seal_aes_gcm_aad(..., ROLE_BODY)` call — no new role byte, no ADR 0003
  amendment needed (confirmed: adding a field to an already-role-`0x01`-sealed body does
  not require a new AAD role, unlike adding a NEW independently-sealed sub-object).
- **`deny_unknown_fields` on `NodeWriteBody` (Rust):** confirmed absent today
  (`crates/core/src/node/types.rs:136-145` has no `#[serde(deny_unknown_fields)]`, unlike
  `SealedChildRef` at `:100` which explicitly has it). Do NOT add `deny_unknown_fields` to
  `NodeWriteBody` when adding the pin field — that would make the type forward-INcompatible
  and contradict the additive-change contract in `METADATA_EVOLUTION_PROTOCOL.md` §3.1.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| ECIES key wrap for the re-minted read key | A custom secp256k1/AES hybrid wrap | `cipherbox_crypto::wrap_key` / `@cipherbox/crypto`'s `wrapKey` | Already the mandated primitive at all 3+ existing call sites (T-64-04c parity comment explicit in `engine.rs:594-596`) |
| AEAD sealing of the new pin field | A separate encryption pass for just the pin list | The EXISTING `seal_node`/`sealNode` role-`0x01` body seal (the pin rides inside the same `NodeWriteBody` JSON that's already sealed) | AAD/role-byte table is FROZEN (ADR 0003) — adding a new role for a field-level change is unnecessary and would require a KAT extension for no benefit |
| Sent-shares fetch caching | A new global/static cache singleton | A per-job-scoped field on `FuseRotationDeps`/the `queryGrantsFn` closure | Global caches leak stale data across rotation jobs and complicate testing (the codebase already prefers injectable seams — see `RotationTransport`, `RotationDeps` traits) |

**Key insight:** every primitive this phase needs (AEAD seal, ECIES wrap, InodeTable
lookup-by-ipns-name) already exists and is exercised by directly adjacent code in the same
files. The only genuinely new code is (1) the reconstruction logic inside D-01, (2) the
cache field inside D-02, (3) the pin-list plumbing + a new SDK write method inside D-03,
and (4) a one-line `new Uint8Array(...)` wrap for D-04.

## Common Pitfalls

### Pitfall 1: Adding the pin field breaks the FULL-SEAL cross-language vector silently

**What goes wrong:** `tests/vectors/node-codec.json`'s single `seal_vectors[0]` entry
locks the EXACT byte output of `encodeWriteBody`/`encode_write_body` for a write-body with
`writeChildren: []` and no pin field. If the pin field is added to the wire JSON
unconditionally (even as `[]`), the frozen `expected_published_node.writeSealed` base64
string changes and BOTH the TS test (`packages/core/src/__tests__/node-codec-vectors.test.ts:229-257`)
and the Rust `cross_language.rs` seal-vector assertion break.

**Why it happens:** `encodeWriteBody` (`packages/core/src/node/encode.ts:140-155`)
currently builds `wireBody = { ipnsPrivateKey, writeChildren }` as a plain object literal —
adding a third key unconditionally changes every output, even when the pin list is empty.

**How to avoid:** Only include the pin field in the wire object when non-empty/present
(mirror the existing `skip_serializing_if` convention used elsewhere in this codebase for
optional array fields), so the EXISTING zero-pin fixture's bytes are preserved exactly, and
add a SECOND `seal_vectors[1]` entry (with a non-empty pin) as the new lockstep vector both
TS and Rust must assert against — per `METADATA_EVOLUTION_PROTOCOL.md` §6.2/§6.4's
explicit lockstep rule ("Extending one without the other is forbidden").

**Warning signs:** `cargo test -p cipherbox-crypto` or `pnpm test` in `packages/core`
failing on the EXISTING `folder node writeSealed base64 matches frozen vector` test with no
apparent code change to seal.ts/seal.rs — check `encodeWriteBody`'s field-inclusion logic
first.

### Pitfall 2: `NodeWriteBody`'s TS type change breaks the existing literal-object test fixtures

**What goes wrong:** `packages/core/src/__tests__/node-codec-vectors.test.ts:244` and
`:340-344` construct `writeBody: { ipnsPrivateKey, writeChildren: [] }` object literals
directly. If the new pin field is added as a REQUIRED TS field
(`recipientPubkeyPins: string[]`), these literals fail to type-check.

**Why it happens:** TS structural typing enforces every field on an object literal
assigned to a typed variable.

**How to avoid:** Make the field optional in the TS type (`recipientPubkeyPins?: string[]`)
— consistent with `writeBody?` itself being optional on `Node`, and with the
additive-field convention. Existing test literals then continue to compile unchanged.

### Pitfall 3: The Phase-78 recovery tool concern (D-03b) is likely a non-issue — verify, don't assume work is needed

**What goes wrong:** CONTEXT flags "the Phase-78 offline recovery tool must tolerate the
new NodeWriteBody field" as a verification item. Investigation this session
(`apps/web/recovery-src/walk.ts:22,162`) shows the recovery tool calls the SAME production
`unsealNode(published, childReadKey)` from `@cipherbox/core` with **only the readKey
argument** — `writeKey` is optional (`packages/core/src/node/seal.ts:124`,
`writeKey?: Uint8Array`) and when omitted, `unsealNode` skips write-body unsealing
entirely (`seal.ts:142`, `if (published.writeSealed && writeKey)`). The recovery tool
never has write-key material (by design — it's a read-only disaster-recovery path) and
therefore never parses `NodeWriteBody` — with or without the pin field.

**How to avoid:** Do not add speculative recovery-tool changes. Confirm this finding with a
direct grep for `writeKey`/`writeSealed`/`NodeWriteBody` in `apps/web/recovery-src/` during
planning (already done this session — zero matches), then close this checklist item as
"verified no-op, not applicable" rather than writing dead code.

### Pitfall 4: D-03's issuance write (D-03c) has no existing SDK mutation path — this is new surface, not a wire-up

**What goes wrong:** `ShareDialog.tsx::handleShare` (`apps/web/src/components/file-browser/ShareDialog.tsx:162-218`)
currently only calls `resolveShareEncryptedWriteKey` (`packages/sdk/src/client.ts:3839`),
which **derives** the item's writeKey by walking the parent's write-chain
(`walkChildWriteKey`) — it never mutates or republishes the item's own write-body. There is
currently **no SDK method that appends to a node's own `NodeWriteBody.recipientPubkeyPins`
and republishes it**. Planning this as "wire the pin into the existing create-share call"
will underestimate the work — it requires: unsealing the item's CURRENT write-body (if any
— items shared for the first time may have no `writeBody` at all yet, since it's `Option`
in Rust / optional in TS), appending the new pin, re-sealing via `seal_published_node`
(Rust) / `sealNode` (TS) at the item's CURRENT generation, and CAS-publishing the updated
`PublishedNode`.

**Why it happens:** The existing write-chain code (`getWriteBodyParams`,
`walkChildWriteKey` in `packages/sdk/src/write-body-params.ts`) is read-oriented (resolve a
descendant's writeKey), not a write-body mutation API.

**How to avoid:** Budget D-03c as a genuinely new SDK method
(e.g. `client.ts::addRecipientPubkeyPin(itemIpnsName, recipientPublicKey)` or fold it into
a parameter on a new share-creation SDK wrapper), following the SAME CAS-publish pattern
already used by `updateFolderMetadataAndPublish` / the rotation engine's own republish
calls — not a bolt-on to `resolveShareEncryptedWriteKey`. Flag as its own plan/task, not a
one-line change alongside D-03d's read-side enforcement.

### Pitfall 5: `is_revoked` is always `false` from `GET /shares/sent` — the pin-mismatch fail-closed path must not be conflated with revocation

**What goes wrong:** Both `query_grants_rooted_at` (Rust) and `queryGrantsFn` (TS) source
`GrantRow.isRevoked`/`is_revoked` from `GET /shares/sent`, which — per the project's
hard-delete revocation convention (confirmed in `rotation_deps.rs:262-263` comment and
`owner-reconcile.service.ts:38-42` comment) — NEVER returns a revoked row at all (revoked =
row deleted server-side). A pin MISMATCH is a DIFFERENT failure mode (compromised-relay
substitution, not owner-initiated revocation) and must fail the ENTIRE rotation/re-mint
operation closed (per D-03e: "hard fail-closed invariant violation"), not silently skip
that one grant the way `is_revoked` skip does.

**How to avoid:** Model the pin check as a hard `Err`/`throw` that aborts
`re_mint_grants_rooted_at`/`reMintGrantsRootedAt` for the WHOLE node (or even the whole
job, per planner discretion — CONTEXT doesn't specify granularity), never as a per-grant
skip-and-continue like the `is_revoked` branch.

## Code Examples

### Verified pattern: fail-closed InodeTable lookup returning `Option`

```rust
// Source: crates/fuse/src/write_ops/rotation_deps.rs:582-599 (find_grant_root_state)
// Mirrors the shape D-01's write-body reconstruction lookup should follow.
pub(crate) fn find_grant_root_state(
    inodes: &InodeTable,
    ipns_name: &str,
) -> Option<(String, Zeroizing<[u8; 32]>)> {
    inodes.inodes.values().find_map(|inode| match &inode.kind {
        InodeKind::Root { ipns_name: n, read_key, .. } if n == ipns_name =>
            Some((inode.node_id.clone(), Zeroizing::new(**read_key))),
        InodeKind::Folder { ipns_name: n, read_key, .. } if n == ipns_name =>
            Some((inode.node_id.clone(), Zeroizing::new(**read_key))),
        _ => None,
    })
}
```

### Verified pattern: the exact D-01 durability failure this phase closes

```rust
// Source: crates/fuse/src/replay.rs (recover_signing_seed, ~:261-297)
fn recover_signing_seed(
    published: &PublishedNode,
    write_key: &[u8; 32],
    kind: NodeKind,
) -> Result</* ... */> {
    let write_sealed = published.write_sealed.as_ref().ok_or_else(|| {
        /* error: "node {} has no write_sealed body — cannot recover signing seed
           — retaining entry" */
    })?;
    // ... unseal + decode_write_body(...) -> Zeroizing::new(write_body.ipns_private_key)
}
```
This is the EXACT error path the 607→0 prototype fix (D-01) eliminates.

### Verified pattern: the D-03d wrap call sites needing a pin check inserted

```rust
// Source: crates/sdk/src/rotation/engine.rs:597-626 (re_mint_grants_rooted_at)
async fn re_mint_grants_rooted_at<D: RotationDeps>(
    deps: &D, node_id: &str, new_read_key: &[u8; 32], new_generation: u32,
) -> Result<(), RotationError> {
    let grants = deps.query_grants_rooted_at(node_id).await?;
    for grant in grants {
        if grant.is_revoked {
            deps.delete_grant(&grant.share_id).await?;
        } else {
            // D-03d insertion point: verify grant.recipient_public_key against
            // the pin list BEFORE this wrap_key call.
            let wrapped = cipherbox_crypto::wrap_key(new_read_key, &grant.recipient_public_key)?;
            let encrypted_read_key = hex::encode(&wrapped);
            deps.update_grant(&grant.share_id, &encrypted_read_key, new_generation).await?;
        }
    }
    Ok(())
}
```

```typescript
// Source: packages/sdk-core/src/rotation/engine.ts (reMintGrantsRootedAt, ~:563-590)
export async function reMintGrantsRootedAt(
  nodeId, newReadKey, newGeneration, job, ctx, callbacks?: GrantRemintCallbacks
) {
  const grants = await callbacks.queryGrantsFn(nodeId);
  for (const grant of grants) {
    if (grant.isRevoked) {
      await callbacks.deleteGrantFn(grant.shareId);
    } else {
      // D-03d insertion point.
      const wrappedBytes = await wrapKey(newReadKey, grant.recipientPublicKey);
      // ...
      await callbacks.updateGrantFn(grant.shareId, encryptedReadKey, newGeneration);
    }
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Rotation republish drops `write_sealed` | D-01 reconstructs it from `InodeTable` | This phase | Fixes the 607×/run `list_folder_owned` flood AND the signing-seed-recovery durability hole |
| `GET /shares/sent` per rotated node (O(nodes×shares)) | D-02 caches once per rotation job | This phase | O(1) network fetch per job instead of O(nodes) |
| Server-trusted `recipient_public_key` at re-mint | D-03 pins the issuance-time pubkey inside the owner-sealed `NodeWriteBody` | This phase | Closes a confidentiality break where a compromised relay substitutes the recipient at re-mint time |
| TS `rotatedNodes` aliases `parentNewReadKey` | D-04 defensive 32-byte copy | This phase | Prevents a FUTURE zeroization tightening from silently zeroing the returned map |

**Deprecated/outdated:** None — this phase does not retire any prior schema or API; it is
purely additive (new optional `NodeWriteBody` field) plus internal correctness fixes.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `re_mint_grants_rooted_at`/`reMintGrantsRootedAt` need a NEW parameter or seam method to receive the current node's pin list (no existing plumbing carries write-body content into these functions) | Pattern 3, Open Questions | If the planner instead threads pins via a different mechanism (e.g., the caller pre-filters grants before calling), the exact function signature change described here would be wrong — but the underlying gap (no current pin access) is verified fact, not assumption |
| A2 | `InodeKind::{Root,Folder,File}` variants may not currently cache a per-node `write_key`/child write-key material needed for D-01's full reconstruction — flagged, not confirmed by reading `inode.rs` this session | Pattern 1 | If they DO already cache this (likely, since `ipns_private_key` is cached), D-01 is simpler than described; if not, D-01 needs an additional InodeTable field, expanding scope |
| A3 | D-03's three named consumers do NOT include `rotateWriteFromNode`'s co-writer re-wrap (`engine.rs:2762`), based on CONTEXT's explicit enumeration of exactly 3 consumers (Rust re-mint, TS re-mint, web upgrade/reconcile) | Pattern 3 | If write-revocation co-writer re-wrap is actually in scope, a 4th enforcement site is needed — see Open Questions |

**None of these are HIGH-risk to the phase's core mechanics** — all are scoping-boundary
questions for the planner to resolve with the CONTEXT author, not open technical unknowns.

## Open Questions

1. **How does `re_mint_grants_rooted_at`/`reMintGrantsRootedAt` obtain the pin list for
   the node it's currently processing?**
   - What we know: the pin lives in "the shared root node's owner-sealed `NodeWriteBody`"
     (D-03a) — i.e., the pin for a given `share_id`'s grants is stored on the node whose
     `id == root_node_id` for that grant (the same node `re_mint_grants_rooted_at(node_id, ...)`
     is invoked for, since `query_grants_rooted_at` filters `root_node_id == node_id`).
   - What's unclear: neither function currently receives that node's write-body content —
     only `node_id: &str`/`nodeId: string`, `new_read_key`, `new_generation`. The caller
     (`rotate_one`/`rotateOne`) DOES have (or can obtain) the node's writeKey during a
     rotation walk (the owner always holds it for owned nodes), but the write-body
     content itself isn't currently threaded to this call.
   - Recommendation: the cleanest fix is a new `RotationDeps`/`RotationTransport` method
     (mirroring the D-01 pattern of "read from the already-mounted `InodeTable`") — e.g.
     `get_recipient_pubkey_pins(node_id) -> Vec<Vec<u8>>` on the Rust side, resolved by
     `FuseRotationDeps` from the InodeTable's in-memory write-body cache (same source D-01's
     reconstruction reads from). For TS, thread an equivalent optional parameter/callback
     into `reMintGrantsRootedAt`'s `GrantRemintCallbacks` shape (a new
     `getPinsFn?: (nodeId: string) => Promise<string[]>`). Confirm this shape with the user
     during `/gsd-discuss-phase` if not already settled — this is the one place CONTEXT's
     locked decisions don't fully specify a call-site mechanism.

2. **Is `rotateWriteFromNode`'s co-writer re-wrap (`crates/sdk/src/rotation/engine.rs:2762`)
   in scope for D-03d's fail-closed pin check?**
   - What we know: it has the IDENTICAL trust pattern (`wrap_key(rootResult.newWriteKey,
     grant.recipient_public_key)` with no pin verification) but operates on the WRITE
     chain (write-revocation), not the READ chain (scope-exit rotation) this phase's SC1-3
     bullets describe.
   - What's unclear: CONTEXT names exactly 3 consumers and doesn't mention this 4th site.
   - Recommendation: treat as out of scope for Phase 80 unless the planner/user confirms
     otherwise — flag it as a follow-up todo (mirrors the phase's own "closeout straggler"
     todo-sourcing convention) rather than silently expanding D-03's surface.

3. **Does `FuseRotationDeps` get reconstructed once per rotation job or once per node?**
   (D-02 cache-lifetime correctness — see Pattern 2's Landmine.) Grep the call site in
   `crates/fuse/src/write_ops/` (search for `FuseRotationDeps::new`) before finalizing the
   D-02 cache-field design.

## Environment Availability

Not applicable — no external tools/services/runtimes are newly required by this phase.
All work is inside the existing Rust workspace (`cargo test -p cipherbox-core -p
cipherbox-crypto -p cipherbox-fuse -p cipherbox-sdk`) and TS workspace (`pnpm test` in
`packages/core`, `packages/sdk-core`, `packages/sdk`, `apps/web`) plus the existing
`tests/sdk-e2e` suite.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework (Rust) | `cargo test` (workspace crates: `cipherbox-core`, `cipherbox-crypto`, `cipherbox-fuse`, `cipherbox-sdk`) |
| Framework (TS) | Vitest (`packages/core`, `packages/sdk-core`, `packages/sdk`) |
| Framework (cross-package) | `tests/sdk-e2e` (Vitest, live API — the only real client→API IPNS round-trip gate) |
| Config files | Standard `Cargo.toml` workspace + each package's `vitest.config.ts` (no new config needed) |
| Quick run command | `cargo test -p cipherbox-core -p cipherbox-crypto` (unit-level, D-01/D-03b codec changes); `pnpm --filter @cipherbox/core test` / `pnpm --filter @cipherbox/sdk-core test` |
| Full suite command | `cargo test --workspace` + `pnpm test` (root) + `tests/sdk-e2e` live-API run (per `project-sdk-e2e-only-cross-package-publish-gate` memory — run before shipping IPNS/key-lifecycle changes) |

### Phase Requirements → Test Map

| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|--------------------|--------------|
| SC1 (D-01) | Rotation republish reconstructs `write_sealed`; owned-walk + replay signing-seed recovery survive rotation | unit + regression | `cargo test -p cipherbox-fuse rotation_deps` (extend existing test module at `crates/fuse/src/write_ops/rotation_deps.rs:601`) | ✅ (module + `#[cfg(test)]` scaffold exists — prototype tests already authored per CONTEXT D-01c) |
| SC1 (D-01) | `replay.rs::recover_signing_seed` no longer hits the "no write_sealed body" fail path for a rotated node | regression | `cargo test -p cipherbox-fuse replay` | ✅ file exists (`crates/fuse/src/replay.rs`), needs a NEW test exercising a rotation-then-replay sequence — ❌ Wave 0 gap |
| SC2 perf (D-02) | A scope-exit rotation over N nodes performs ≤1 `/shares/sent` fetch | unit (call-count assertion) | `cargo test -p cipherbox-fuse query_grants_rooted_at` (extend the existing `FakeTransport` call-count pattern already used at `rotation_deps.rs:664-672`, `publish_count_for`) | ✅ pattern exists, needs a new `collect_sent_shares` call-counter added to `FakeTransportInner` |
| SC2 perf (D-02, TS mirror) | `queryGrantsFn` caches `listSentGrants()` across repeated calls | unit | `pnpm --filter @cipherbox/sdk test owner-reconcile` (extend `packages/sdk/src/__tests__/owner-reconcile.test.ts`) | ✅ test file exists |
| SC2 binding (D-03) | Re-mint fails closed on a pin mismatch (simulated compromised-relay substitution) | unit | New test in `rotation_deps.rs` test module + `packages/sdk-core` engine tests | ❌ Wave 0 gap — new test cases needed on both sides |
| SC2 binding (D-03) | No-legacy-share invariant: pin absent at re-mint = hard fail-closed | unit | Same test modules as above, negative case | ❌ Wave 0 gap |
| SC2 binding (D-03b) | Cross-language wire parity for the new `NodeWriteBody` pin field | KAT | `cargo test -p cipherbox-crypto node_aad_cross_language` (extend `crates/crypto/tests/cross_language.rs:272`) + `pnpm --filter @cipherbox/core test node-codec-vectors` | ✅ file/harness exists, needs a NEW `seal_vectors[1]` fixture entry with a non-empty pin |
| SC3 (D-04) | `rotatedNodes` values are non-aliased, non-zero copies | unit | `pnpm --filter @cipherbox/sdk-core test rotation/engine` | ❌ Wave 0 gap — new assertion, existing engine test file to extend (search `packages/sdk-core/src/rotation/__tests__/` or co-located `engine.test.ts`) |
| Full round-trip | End-to-end scope-exit rotation + re-mint against a live API | e2e | `tests/sdk-e2e` (see README for run instructions; requires local API stack per `project-sdk-e2e-worktree-live-checkpoint-run` memory) | ✅ suite exists — the mandatory pre-ship gate |

### Sampling Rate

- **Per task commit:** the relevant crate/package's quick unit-test command (Rust:
  `cargo test -p <crate>`; TS: `pnpm --filter <package> test`)
- **Per wave merge:** `cargo test --workspace` + `pnpm test` (root)
- **Phase gate:** `tests/sdk-e2e` full live-API round-trip must be green before
  `/gsd-verify-work` — this is the ONLY suite that exercises a real client→API IPNS
  resolve/publish cycle, and IPNS/key-lifecycle changes (D-01, D-03) are exactly the class
  of change that suite exists to gate (per `project-sdk-e2e-only-cross-package-publish-gate`
  memory).

### Wave 0 Gaps

- [ ] `crates/fuse/src/replay.rs` — no existing test exercises a rotation-then-replay
      signing-seed-recovery sequence; needed to prove D-01 closes the durability hole (not
      just the flood).
- [ ] `crates/fuse/src/write_ops/rotation_deps.rs` — new `FakeTransportInner` call-counter
      for `collect_sent_shares` (D-02 perf assertion) and new pin-mismatch fixtures (D-03
      fail-closed assertion).
- [ ] `packages/sdk-core/src/rotation/__tests__/` (or co-located engine test file) — new
      assertion that `rotatedNodes` entries are non-aliased with `parentNewReadKey` (D-04).
- [ ] `packages/core/src/__tests__/node-codec-vectors.test.ts` + `tests/vectors/node-codec.json`
      — new `seal_vectors[1]` entry with a non-empty `recipientPubkeyPins` (D-03b lockstep).
- [ ] `crates/crypto/tests/cross_language.rs` — extend the `NodeSealVector`-driven assertion
      loop (currently hardcoded to `seal_vectors.len() == 1`, `cross_language.rs:310`) to
      accept 2 vectors once the new one is added — **this length-guard assertion will need
      updating or it will hard-fail on the new fixture**.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|-------------------|
| V6 Cryptography | Yes | AES-256-GCM + AAD (`seal_aes_gcm_aad`/`encryptAesGcmAad`) for the write-body; ECIES (`wrap_key`/`wrapKey`) for the re-mint — both existing, never hand-rolled |
| V4 Access Control | Yes | The pin comparison IS an access-control check: it verifies the re-mint target is the ORIGINALLY authorized recipient, not merely "a key the server currently associates with this share" |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Compromised relay substitutes `recipient_public_key` in `GET /shares/sent` at re-mint time | Spoofing / Tampering | D-03's owner-sealed pin, verified client-side before every re-wrap (this phase's core deliverable) |
| A future TS zeroization tightening zeros `rotatedNodes` entries via the `parentNewReadKey` alias | Tampering (self-inflicted) | D-04's defensive copy |
| Stale/missing `write_sealed` silently degrading owned-walk + losing signing-seed recoverability | Denial of Service / Repudiation (owner loses ability to sign) | D-01's reconstruct-and-reseal fix |

## Sources

### Primary (HIGH confidence — direct code reads this session)

- `crates/fuse/src/write_ops/rotation_deps.rs` (full file, 1270 lines) — D-01/D-02/D-03 Rust FUSE transport adapter
- `crates/core/src/node/types.rs`, `encode.rs`, `decode.rs`, `seal.rs` — `NodeWriteBody` schema + codec, both Rust and TS twins
- `packages/core/src/node/types.ts`, `encode.ts`, `decode.ts` — TS `NodeWriteBody` twin
- `crates/sdk/src/rotation/engine.rs` (`re_mint_grants_rooted_at`, `RotationDeps` trait, `GrantRow`) — Rust rotation engine
- `packages/sdk-core/src/rotation/engine.ts` (`reMintGrantsRootedAt`, `RotatedNodeKey`, `RotateReadResult`, the D-04 aliasing bug) — TS rotation engine
- `packages/sdk/src/share/owner-reconcile.ts`, `apps/web/src/services/owner-reconcile.service.ts` — the TS/web re-mint consumers
- `apps/web/src/components/file-browser/ShareDialog.tsx` — issuance + upgrade/downgrade UI, D-03c/D-03d web sites
- `apps/web/recovery-src/walk.ts` — confirmed Phase-78 recovery tool never parses write-bodies (Pitfall 3)
- `crates/fuse/src/replay.rs` (`recover_signing_seed`) — D-01 durability consumer
- `crates/fuse/src/write_ops/grant_scope.rs` (`refresh_rotated_inode_read_keys`) — D-04 downstream Rust consumer (already correct)
- `packages/core/src/__tests__/node-codec-vectors.test.ts`, `tests/vectors/node-codec.json`, `crates/crypto/tests/cross_language.rs` — cross-language KAT discipline and exact vector structure
- `packages/sdk/src/client.ts` (`resolveShareEncryptedWriteKey`, ~:3839-3899) — closest existing pattern for D-03c's needed new write-body mutation method
- `docs/METADATA_EVOLUTION_PROTOCOL.md`, `docs/METADATA_SCHEMAS.md` — schema evolution rules and current `NodeWriteBody` documentation

### Secondary (MEDIUM confidence)

- None — every claim in this document traces to a direct file read this session; no
  WebSearch or external documentation was needed (closed-codebase surgical phase).

### Tertiary (LOW confidence)

- None.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new dependencies; all primitives directly verified in-repo
- Architecture: HIGH — every function/line cited was read directly this session
- Pitfalls: HIGH — each pitfall is backed by a specific file:line contradiction risk found by reading the actual test fixtures and encode/decode logic
- D-03's SDK-mutation-path gap (Pitfall 4, Open Question 1): MEDIUM — the GAP itself is
  verified fact (no such method exists), but the RECOMMENDED shape of the fix is a design
  proposal, not a located pattern

**Research date:** 2026-07-12
**Valid until:** No expiry driver — this is closed-codebase internal research, not
dependent on external library versions or ecosystem state. Re-verify only if the
`node/v3` codec, rotation engine, or share-grant API surface changes before this phase is
planned/executed.
