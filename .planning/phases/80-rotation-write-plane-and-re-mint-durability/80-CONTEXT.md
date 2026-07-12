# Phase 80: Rotation Write-Plane and Re-Mint Durability - Context

**Gathered:** 2026-07-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the remaining scope-exit rotation and re-mint correctness/durability gaps so rotated nodes stay owned-walkable and replay-recoverable, and re-mint stops trusting server-supplied recipient keys or doing O(nodes×shares) work.

Bounded by the four ROADMAP source todos:

- `2026-07-11-rotation-republish-drops-write-sealed-body` (HIGH) — SC1
- `2026-07-11-remint-refetches-sent-shares-per-rotated-node` — SC2 (perf half)
- `2026-07-11-remint-trusts-server-recipient-pubkey-binding` (MED) — SC2 (binding half)
- `2026-07-11-ts-rotatednodes-defensive-copy-parity` (LOW) — SC3

**Scope note:** The recipient-pubkey binding decision (D-03) deliberately expands this phase from a "closeout straggler" into a genuine sharing-crypto phase. This was chosen knowingly during discuss-phase (the alternative — documenting server-trusted recipient binding as an accepted risk — was declined). All other items are mechanical fixes, one with a verified prototype.

**Depends on:** Phase 74 (made the FUSE re-mint path reachable), Phase 70.1.

</domain>

<decisions>
## Implementation Decisions

### SC1 — Rotation republish drops `write_sealed` body
- **D-01:** A scope-exit read-key rotation currently republishes every rotated node with `write_sealed: None` (the engine never populates it — read-key rotation is a read-plane op — and the FUSE adapter, a documented Phase-72 deferral, doesn't reconstruct it). This breaks `list_folder_owned` ("owned child … has no write_sealed body", observed 607× per run on macOS → the owner's background folder-metadata refresh permanently fails for any scope-exit-rotated shared subtree) AND is a **durability hole** (`replay.rs` can't recover the node's signing seed from the write body → after rotation + remount the owner may lose the ability to sign updates to the rotated subtree).
- **D-01a (fix):** In `ApiClientTransport::publish` (`crates/fuse/src/write_ops/rotation_deps.rs`), when `node.write_sealed` is `None`, **reconstruct** `NodeWriteBody` from the mount's in-memory `InodeTable` — the node's own **stable write key** + `ipns_private_key` + child `WriteChildRef`s rebuilt from the child inodes (child write keys are **read-key-rotation-independent**) — and re-seal under the node's write key at the node's **NEW generation** via `seal_node` (which shares the `ROLE_BODY` AAD with `seal_published_node`'s write-body path). Round-trip: unseal under the write key at the new generation recovers the write body + child refs.
- **D-01b (fallback):** Fail-open to `None` for a node **not locally materialized** (matches the existing signing-seed fail-closed lookup). Write-key *rotation* remains a separate Phase-72 concern — this only re-seals the **unchanged** write plane at the bumped generation.
- **D-01c (tests):** Unit tests for the reconstruction round-trip + the `None` fallback (were authored in the prototype). Prototype verified locally: the "no write_sealed body" flood drops **607→0**.

### SC2 (perf) — Re-mint refetches `/shares/sent` per node
- **D-02:** `re_mint_grants_rooted_at` runs after **each** per-node commit during a rotation walk, and `query_grants_rooted_at` calls `collect_sent_shares()` (a full `GET /shares/sent`) every time → O(nodes × shares) network work. **Cache** the `collect_sent_shares()` result for the lifetime of a single rotation job and filter the cached list by `root_node_id` per node. Preserve the existing 0x-strip / hex-decode key parsing and per-share error handling. Mirror the optimization in the TS owner-reconcile `queryGrantsFn` for parity.
- **D-02a (acceptance):** A scope-exit rotation over an N-node subtree performs **≤1** `/shares/sent` fetch (not N); re-mint results unchanged (retained recipients re-minted, revoked recipients cut by **absence** — revoked shares are hard-deleted server-side).

### SC2 (binding) — Re-mint trusts the ZK relay for recipient-pubkey identity
- **D-03:** **Pin the recipient pubkey end-to-end.** The recipient pubkey is authentic only at **issuance** (the owner pastes it out-of-band into ShareDialog; the server merely confirms a user exists via `lookupUser` and stores it). It becomes **server-trusted** whenever it round-trips back through the relay via `GET /shares/sent` — used by **three** consumers, all of which re-wrap the read key to the server-returned key without re-checking it:
  1. **Rust re-mint** — `rotation_deps.rs::query_grants_rooted_at` → `engine.rs::re_mint_grants_rooted_at` → `wrap_key(new_read_key, &grant.recipient_public_key)`.
  2. **TS re-mint** — `owner-reconcile.ts` `queryGrantsFn` → `sdk-core/rotation/engine.ts` wrap site.
  3. **Web upgrade/reconcile** — `owner-reconcile.service.ts` + the ShareDialog upgrade/downgrade path both read `share.recipientPublicKey` straight from the server-fed store and re-wrap to it.

  A compromised relay that substitutes the pubkey in any of these responses causes the owner to ECIES-wrap the fresh post-rotation read key **to the attacker** — a confidentiality break against the exact adversary the zero-knowledge model names as untrusted. This trust is **inherited** (initial issuance already trusts the relay for recipient identity binding); pinning only re-mint would be incoherent, so the fix must cover **all three** consumers.

- **D-03a (storage):** Store the issuance-time recipient pubkey(s) in the **shared root node's owner-sealed `NodeWriteBody`** — already sealed + AAD-bound under the owner's write key and IPNS-published, so it is **server-opaque** and **cross-device** by construction (a re-mint on a different owner device than the issuing one can still verify). A node shared to N recipients holds N pins (a list). The existing wrapped `encryptedReadKey` can't help: ECIES doesn't let the owner recover/verify the recipient pubkey from the blob without the recipient's private key, so the pubkey must be stored owner-side at issuance.

- **D-03b (schema):** Adding the pin field to `NodeWriteBody` is a **metadata-schema change** — follow `METADATA_EVOLUTION_PROTOCOL` + update `METADATA_SCHEMAS`, and maintain **Rust/TS CBOR parity** for the new field (this repo's cross-language contract-test discipline applies; see `[[project-cross-language-verification-parity-gotchas]]`). The Phase-78 offline recovery tool must **tolerate** the new `NodeWriteBody` field (ignore-unknown) — verify it does not fail-closed on the added field.

- **D-03c (issuance write):** At grant creation, write the pasted recipient pubkey into the shared root node's `NodeWriteBody` pin list (alongside the existing server-side create-share call).

- **D-03d (enforcement):** On **all three** round-trip consumers, compare the `/shares/sent`-returned pubkey against the pin and **fail closed on mismatch**.

- **D-03e (no legacy):** There are **no legacy shares** — the staging env is reset to a clean slate at milestone completion / deployment, so only the forward-looking case exists. Therefore **a pin absent at re-mint/upgrade is an invariant violation → hard fail-closed** (not a migration case). No TOFU, no backfill, no migration versioning.

- **D-03f (server untouched):** The pin is purely client-side owner-sealed. The server still stores/returns `recipient_public_key` for its own `lookupUser`/response path — we just stop *trusting* it. **No API/DTO change → no `pnpm api:generate`.**

### SC3 — TS `rotatedNodes` defensive-copy parity
- **D-04:** The Rust engine `.clone()`s each node's key into an independent `Zeroizing<[u8;32]>` in `rotated_nodes`; the TS engine stores the **same `Uint8Array` reference** (`engine.ts:2064` root, `:2235` child), also aliased into `ParentTrackingState.parentNewReadKey`. Not a live bug today (`parentNewReadKey` is never zeroed), but a natural future D-09 tightening that zeroes it would silently zero the returned `rotatedNodes` entry → the FUSE consumer (`grant_scope.rs::refresh_rotated_inode_read_keys`) would refresh an inode read key to **all-zeros** → mis-decryption / data loss. Store a **defensive 32-byte copy**: `readKey: new Uint8Array(rootResult.childReadKey)` (root) and `new Uint8Array(result.childReadKey)` (child). Add a TS regression test asserting every `rotatedNodes` value's `readKey` is non-aliased with `parentNewReadKey`, non-zero, and equals the node's expected new key after `rotateReadFromNode`.

</decisions>

<success_criteria>
## Success Criteria (from ROADMAP)

1. Rotation republish no longer emits `write_sealed: None` for rotated nodes — owned-walks and replay signing-seed recovery survive a read-key rotation, locked by a regression test. **(D-01)**
2. Scope-exit re-mint binds the new read key to a **verified** recipient public key (pinned/verified rather than blindly server-supplied) across all three round-trip consumers, and refetches `/shares/sent` once per rotation job (cached), not once per rotated node. **(D-02, D-03)**
3. TS `rotatedNodes` stores a defensive 32-byte copy of `readKey` (no aliasing with `parentNewReadKey`), matching Rust parity. **(D-04)**

</success_criteria>

<references>
## Relevant Memories / Prior Art

- `[[project-fuse-scope-exit-rotation-stale-refresh-clobber]]` — the Part-D fix this bug was found orthogonally alongside (this is NOT the Part-D cause).
- `[[project-write-plane-keyed-by-uuid-read-plane-by-ipnsname]]` — write-plane (UUID) vs read-plane (ipnsName) threading discipline.
- `[[project-zeroization-callee-must-not-zero-reused-buffer]]` — zeroization ownership rules relevant to D-04.
- `[[project-cross-language-verification-parity-gotchas]]` — CBOR Rust/TS parity gotchas relevant to D-03b.
- `[[project-sdk-e2e-only-cross-package-publish-gate]]` — the gate to run before shipping IPNS/key-lifecycle changes.

</references>
