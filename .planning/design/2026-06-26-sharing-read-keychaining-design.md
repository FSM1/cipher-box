# CipherBox Read Key-Chaining — Implementation-Ready Design

Status: design complete, implementation-ready. Tier 1 (read chain) is firm. Tier 2 (write revocation) is **ratified as approach (c) full Ed25519 rotation** (see [`docs/adr/0001-write-revocation-full-ed25519-rotation.md`](../../docs/adr/0001-write-revocation-full-ed25519-rotation.md)). Tier 3 is a non-required forward-compatibility note.

This document integrates four design slices (schema, flows, rotation, cutover), the fixes from three adversarial reviews, **and two maintainer grilling sessions** (2026-06-26): session 1 (schema / flows / rotation / write-revocation) and session 2 (resolve / republish / TEE). Blocker and major findings are resolved inline; deferred items are flagged with rationale. The grilling-session decisions (originally captured as a separate amendments delta) have been folded in directly; this document is the single source of truth.

Cross-references: [`docs/adr/0001-write-revocation-full-ed25519-rotation.md`](../../docs/adr/0001-write-revocation-full-ed25519-rotation.md), [`docs/adr/0002-read-revocation-protects-future-content-only.md`](../../docs/adr/0002-read-revocation-protects-future-content-only.md), and the root [`CONTEXT.md`](../../CONTEXT.md) glossary, which pins the terminology used throughout (`readKey` / `writeKey`, the three counters `generation` / `keyEpoch` / `sequenceNumber`, `shares` + descriptor refs, `ipns_records`).

## 1. Overview and rationale

### 1.1 What we are building

CipherBox is a zero-knowledge encrypted IPFS/IPNS vault: the server is a dumb relay that never sees plaintext or any unwrapped/derivable key. We are replacing the DB-driven sharing model (a per-`(share, item, keyType)` `share_keys` table — `O(items × recipients)` rows) with **metadata-driven read key-chaining**, and fixing two confirmed revocation gaps.

The core idea: every node's metadata carries the wrapped keys to reach its children, sealed so that a holder of the node's `readKey` can unwrap its children's read keys, recursing down. Sharing read access = hand the recipient **one** wrapped key at the share-root node (any node — deep folder or single file). No per-item DB rows, no separate lockbox or sidechain object. The only data-plane DB residue is `O(recipients)` read-root grants.

### 1.2 The no-sidechain win

Today, each `FolderEntry` ECIES-wraps **both** a `folderKeyEncrypted` (read) **and** an `ipnsPrivateKeyEncrypted` (write) to the owner, inline per child (`packages/core/src/folder/types.ts:30-46`). Reads are `O(children)` ECIES; sharing fans out into the `share_keys` table. The read chain replaces all of this with **one ECIES at the share-root, then `O(depth)` symmetric AES** down the tree. Creating a child no longer fans out per recipient — the child key is sealed under the parent `readKey` every covering grant-holder already holds transitively.

### 1.3 The two gaps being fixed

1. **Read revocation is lazy, folder-coarse, and unsound.** `executeLazyRotation` (`apps/web/src/services/share.service.ts:602-660`) rotates **only** the share-root `folderKey` and never walks descendants. A revoked reader who cached subtree keys keeps reading. `revokeShare` soft-deletes and keeps `ShareKey` rows "for lazy rotation" (`apps/api/src/shares/shares.service.ts:256-269`).

2. **Write delegation hands out an un-rotatable key.** `shared-write.ts` ECIES-wraps the **real Ed25519 IPNS private key** to the recipient (`packages/sdk/src/share/shared-write.ts:138-141,311`). Deleting the `share_keys` row has zero cryptographic effect — the recipient already cached the 32-byte seed. Publish authorization today is **key-possession only**: `ipns.service.ts:226` confirms "no ownership/share check"; whoever holds the Ed25519 key publishes regardless of `userId`.

### 1.4 The read/write revocation asymmetry (real and accepted)

Read-revoke is **irreducibly `O(items)` IPNS republishes**. Content lives on IPFS, content-addressed: once a reader holds a node's `readKey` and a child CID, any IPFS node serves that ciphertext forever. The only cutoff for **future** content is to change keys on every reachable node and republish. There is no chokepoint on reads.

Write-revoke **can** be cheaper in theory, because writes pass through the relay at publish time — a chokepoint that can deny an action. But under the ratified (c) mechanism (Section 5) write-revoke is itself an `O(subtree)` cascade; the chokepoint is used for a structural tombstone (Section 5.5), not to make rotation cheap.

### 1.5 Tiering of this document

- **Tier 1 (firm):** Sections 2, 3, 4. The read chain, the unified Node schema, the rotation engine, the unified scope-exit rule. Designed within the maintainer's committed direction; not relitigated.
- **Tier 2 (ratified):** Sections 5 and 6. The write-revocation mechanism — **(c) full Ed25519 rotation** (ADR 0001) — and the resolve / republish / TEE contract that the write plane depends on. Separable PRs, but no longer an open decision.
- **Tier 3 (not required):** Section 8. Forward-looking capability-layer fit. Explicitly not built now.

### 1.6 Greenfield: there is no migration

There is no production instance and staging was wiped, so the earlier silent live-data-cutover assumption is void. **Build `node/v3` as the sole codec; delete the v1/v2 read paths and the `share_keys` entity outright** — no dual-codec, no `version`-discriminator bridge. Terminology can be renamed cleanly in code from day one (no transitional coexistence; fully retire `folderKey` / `fileKey` / `rootFolderKey`).

The vault-key recovery blob is **re-designed** (not migrated) to carry **two** keys — `ECIES(rootReadKey)` + `ECIES(rootWriteKey)` — since the root Node has both a read-body and a write-body.

## 2. The reorganized metadata schema

### 2.1 Unified Node model — why, and the boundary

Today `FolderMetadata`, `FileMetadata`, and the vault root each re-implement "how do I reach my children's keys," and each mutation path special-cases folder-vs-file. The read chain is structurally identical for all three. A single `Node` with a `kind` discriminator collapses the chaining and rotation logic to one code path and directly enables the unified scope-exit rule (Section 3.8).

This is a genuine simplification, not ceremony. Confirmed duplications it removes:

- Two schemas with two codecs; `decryptFileMetadata` is keyed by the **parent** `folderKey` (`packages/core/src/file/metadata.ts:232`) while folder metadata is keyed by its own key — the asymmetry that blocks single-file sharing today.
- Root stops being a bespoke vault field: `encryptedRootFolderKey` becomes "the root Node's `readKey`," and root is just `kind: 'root'` with no parent.
- `delete.rs`, `rename.rs`, and `executeLazyRotation` stop branching folder-vs-file.

Boundary on over-unifying: `content` is file-only, `children` is folder/root-only. In TypeScript/JSON a tagged struct is fine. In Rust (`crates/fuse`) model `kind` as a **real enum** (`enum Node { Folder { children }, File { content }, Root { children } }`), not a struct with `Option<content>` + `Option<children>`, so the unification does not leak "impossible states are representable" into the strictest consumer.

### 2.2 Two sealed bodies — the read/write separation fix (write-body shape resolved)

Applying review finding **B1 (blocker):** a node has **two independent sealed bodies**, not one.

- **Read-body** sealed under the node's `readKey` — carries `children[]` (`SealedChildRef[]`) and, for files, `content`.
- **Write-body** sealed under a separate `writeKey` — carries the node's Ed25519 signing material and the write chain to its children.

A read grant ships only the `readKey`. Because the write material is sealed under a different key the read grant never conveys, a read-only holder can never reach a signing key. The earlier single-GCM-body design was wrong: you cannot selectively strip one sub-object from a single AEAD seal, and the relay (untrusted) cannot strip what it cannot decrypt. Two bodies makes the separation structural.

The write-body shape is now **resolved** (no longer a deferred opaque blob): because approach (c) is ratified (Section 5), the write-body is a **structured recursive write chain** mirroring the read chain. Each node's write-body holds its Ed25519 signing material, and each parent write-body seals the child's `writeKey` (`writeKeySealed = AES-GCM(child.writeKey, key=parent.writeKey, …role=child-writekey)`). The **write link lives in the parent write-body, not in `SealedChildRef`** — `SealedChildRef` stays read-only (one sealed field, `readKeySealed`). Reserve AAD `role = 0x04 child-writekey` (Section 2.5) for the write link.

### 2.3 Node schema (decrypted, in-memory)

```jsonc
{
  "schema": "node/v3",
  "kind": "folder" | "file" | "root",
  "id": "uuid",
  "generation": 7,              // u32, per-node read-key rotation clock

  // READ-CHAIN: sealed under THIS node's readKey (role=body)
  "children": [ /* SealedChildRef[] — folder/root only */ ],

  // CONTENT: file only, sealed under THIS node's readKey (role=content)
  "content": {
    "cid": "bafy...",
    "fileIv": "hex",
    "size": 12345,
    "mimeType": "application/pdf",
    "encryptionMode": "GCM" | "CTR",      // CTR powers large-file range reads
    "fileKey": "<32B, inside the sealed body — NOT ECIES>",
    "versions": [ /* VersionEntry[], each with its own inline fileKey + encryptionMode */ ]
  },

  // WRITE-BODY: sealed under a SEPARATE writeKey (role=body)
  "writeBody": {
    "ipnsPrivateKey": "<Ed25519 signing seed, raw, inside the sealed body>",
    "writeChildren": [
      { "childId": "uuid", "writeKeySealed": "AES-GCM(child.writeKey, key=parent.writeKey, …role=child-writekey)" }
    ]
  },                              // omitted on read-only nodes (the read grant never conveys writeKey)

  "createdAt": 0,
  "modifiedAt": 0
}
```

`content.encryptionMode` and each `VersionEntry.encryptionMode` are mandatory: CTR drives large-file range reads (`aes_ctr::decrypt_aes_ctr_range`); do **not** normalise to GCM-only. The `fileKeyEncrypted → content.fileKey` change is a **semantic type change** (ECIES hex string → raw 32-byte key inside the sealed body), applied to both `content` and every `VersionEntry`; document it as a type change in `METADATA_SCHEMAS.md`, not a rename.

### 2.4 Published object — plaintext envelope vs sealed bodies

```jsonc
{
  "schema": "node/v3",
  "kind": "folder",          // PLAINTEXT — AAD input
  "id": "uuid",              // PLAINTEXT — AAD input
  "generation": 7,           // PLAINTEXT — AAD input; lets honest readers detect "I'm behind"
  "aeadVersion": 1,          // PLAINTEXT — primitive/version tag
  "readSealed": "base64",    // AES-256-GCM(read-body, key=readKey, aad=H(domain‖id‖kind‖generation‖role=body))
  "writeSealed": "base64"    // AES-256-GCM(write-body, key=writeKey, …role=body) — omitted on read-only nodes
}
```

`generation` is plaintext on the envelope and folded into AAD (tamper-evident). The metadata CID is signature-covered by IPNS (`ipns.service.ts` anchors the signed value strictly to `/ipfs/${metadataCid}`), so a generation change implies a different CID — see the M1 fix in Section 4.3.

The node's IPNS k51 name is still derived from its Ed25519 write key (`deriveIpnsName`). Read and write keys are independent; the name is a write-plane artifact. A read-only holder gets the name plus `readKey`, never the Ed25519 key.

### 2.5 The new crypto primitive (AAD-bound seal)

`sealAesGcm`/`encryptAesGcm` take no AAD today (`packages/crypto/src/aes/seal.ts:34`, `encrypt.ts:23`). Web Crypto already supports `additionalData`; it is just not plumbed. Add:

```ts
// packages/crypto/src/aes/seal.ts (NEW)
sealAesGcmAad(plaintext: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array>
unsealAesGcmAad(sealed: Uint8Array, key: Uint8Array, aad: Uint8Array): Promise<Uint8Array>
```

Each seal mints a fresh random IV (preserve the `seal.ts:42` behavior — review **m3**: never reuse an IV; keep `readKey` rotation coupled to the generation bump so re-seals always use a fresh key).

Canonical AAD builder (a byte-identical Rust twin must live in `cipherbox_crypto` for FUSE):

```text
aad = "cipherbox/node-seal/v1" ‖ 0x00 ‖ nodeId(16B) ‖ kind(1B) ‖ generation(4B BE) ‖ role(1B)
```

**Byte encoding frozen** (it blocks the cross-language KAT, so freeze it first):

- `kind` = `folder 0x01 / file 0x02 / root 0x03`
- `nodeId` = the raw 16 RFC-4122 bytes (`uuid.as_bytes()`, canonical field order) — **not** a hash
- `generation` = 4-byte big-endian
- `role` ∈ `{0x01 body, 0x02 child-readkey, 0x03 content, 0x04 child-writekey}`

Pin all of it as the **first vector** in `crates/crypto/tests/cross_language.rs`, asserted by `packages/crypto` too.

What each field buys:

- `domain` prevents cross-protocol reuse.
- `nodeId` binds a sealed blob to one node — a relay cannot transplant child-keys to another node-id.
- `generation` binds to the current read-key epoch — a rotated-out reader's cached key fails against the new generation.
- The load-bearing role distinction is `body` vs `child-readkey` vs `child-writekey` (different keys); `content` is defense-in-depth (review **A1** — keep the byte, do not over-justify).

**What AAD does *not* do (transplant claim reworded).** The AAD does **not** bind `parentId`, and a legitimate move re-seals byte-identical AAD under a new parent — so **the AAD does not enforce topology**. State it precisely: the AAD prevents stale-generation replay and cross-node-id confusion; **topology is enforced by parent-`readKey` possession**, not by AAD.

### 2.6 SealedChildRef — the chain link

```jsonc
{
  "childId": "uuid",
  "kind": "folder" | "file",
  "name": "report.pdf",        // plaintext WITHIN the parent's sealed read-body
  "ipnsName": "k51...",        // child node's IPNS name
  "generation": 7,             // CONVERGENCE WITNESS — see 2.7 (the authoritative value is the child's own envelope; this mirror is the reader's key-material AAD source, never the child's envelope — see 2.6)
  "versionFloor": 42,          // owner-vouched seq floor bound at (re)share — see 6.5
  "readKeySealed": "base64"    // AES-GCM(child.readKey, key=parent.readKey,
                               //   aad=domain‖childId‖child.kind‖child.generation‖role=child-readkey)
}
```

`SealedChildRef` is **read-only**: its single sealed field is `readKeySealed`. The write link to the child lives in the parent's *write-body* (`writeChildren[].writeKeySealed`, Section 2.2), never here.

Unwrap walk (replaces the per-child user-privkey ECIES unwrap at `crates/fuse/src/inode.rs:434,452` — also `:658,716`, `replay.rs:365`):

1. Hold the parent `readKey` (from a grant, or unwrapped one level up).
2. Unseal the parent read-body with `parent.readKey` and parent AAD.
3. For each child: `child.readKey = unsealAesGcmAad(child.readKeySealed, parent.readKey, aad(childId, child.kind, child.generation, role=child-readkey))`.
4. Fetch the child node by `ipnsName`; unseal its read-body with `child.readKey`. Recurse.

The AAD in step 3 uses the **child's** id/kind/generation, so re-pointing a parent at a different child, or replaying a stale child generation, breaks the unwrap — this is what makes delete/move/rename-over genuinely cut off (Section 3.8).

**Generation source (where the reader's expected AAD `generation` comes from).** The reader's expected `generation` for a child comes from the parent's `SealedChildRef.generation` mirror (integrity-anchored via the signed CID chain), or, for a share-root, from the grant's `rootGeneration`. The node's **own envelope plaintext `generation`** is used only for the M1 high-water check (Section 4.3) and dirty-edge detection — **never as unseal key-material input**. This makes a stale-child serve fail closed.

### 2.7 `generation` is a single source of truth

`generation` is **per-node and authoritative only on the child's own published envelope**. Every other place it appears — `SealedChildRef.generation` (the parent mirror) and `shares.rootGeneration` (Section 2.8) — is a **convergence/staleness witness**, never an independent value. The rotation engine (Section 4) defines a "dirty edge" precisely as the case where the parent mirror disagrees with the child envelope; the redundancy is the crash-detection mechanism. This rule must be stated once in `METADATA_SCHEMAS.md`, not rediscovered per consumer.

`generation` (per-node read-key clock) is distinct from `keyEpoch` (TEE-pubkey rotation, write-plane) and from `sequenceNumber` (IPNS publish counter). Never conflate the three — see the Counters sub-table in `CONTEXT.md`.

### 2.8 The read-root grant — the only DB residue

Replaces both `share_keys` (deleted) and the fat `shares` row. The table stays `shares`; one row is one **grant** (the glossary term) conveying read or write access to a share-root node for a single recipient.

```jsonc
{
  "id": "uuid",
  "sharerId": "uuid",
  "recipientPublicKey": "secp256k1 65B",
  "rootNodeId": "uuid",
  "rootIpnsName": "k51...",
  "permission": "read" | "write",
  "rootGeneration": 7,           // convergence witness; bumped on rotate
  "readDescriptorRef": "base64", // ECIES(shareRootNode.readKey -> recipientPublicKey) — the ONE wrapped read key
  "writeDescriptorRef": null,    // ECIES(shareRootNode.writeKey -> recipientPublicKey); populated only for write grants
  "revokedAt": null,
  "createdAt": 0
}
```

The recipient ECIES-unwraps `readDescriptorRef` once to get the share-root `readKey`, then chains down with symmetric AES — no further ECIES, no per-item rows. Sharing any node (deep folder or single file) is uniform: `rootNodeId` is whatever node you grant. (Retire the legacy `readKeyEcies` field name and the `ShareGrant` type name; use `readDescriptorRef` / `writeDescriptorRef`.)

### 2.9 File content self-seals under its own readKey (single-file-share enabler)

Today `FileMetadata` is sealed under the parent `folderKey` (`packages/core/src/file/metadata.ts:232`), so a leaf cannot be shared alone. In v3, the file node's `content` (including `content.fileKey`) seals under the file node's **own** `readKey` (role `content`). Therefore:

- A single-file read grant = ECIES-wrap that one file node's `readKey`. The recipient fetches the node by name, unseals `content`, recovers `cid`, `fileIv`, `encryptionMode`, and `content.fileKey`.
- No separate ECIES-to-owner `fileKeyEncrypted`; the `fileKeyEncrypted → content.fileKey` change is a **semantic type change** (Section 2.3), not just a rename. Each `VersionEntry` keeps its own `fileKey` + `encryptionMode` inline.
- A move keeps the file's own `readKey`; only the parent's `SealedChildRef` is rewritten. This kills `spawn_file_meta_reencrypt` (defined at `crates/fuse/src/metadata.rs:655`), whose callers are `write_ops/implementation/rename.rs:248` **and** `platform/windows/write_ops.rs:1182` (the WinFsp twin — killing it must touch both and round-trip the Windows CI gate).

This is mandatory for single-file shares, not optional.

## 3. Flows: Big-O and IPNS-republish counts

Baseline: `N = 1e6` items in the shared subtree, `R = 10` recipients, balanced tree so depth `d = O(log N) ≈ 20`. "Republish" = one IPNS publish (one sequence bump + signature via the chosen write mechanism). The publish/sign step is held abstract; no read-chain flow depends on which write mechanism signs — only on how many nodes republish.

### 3.1 Per-operation cost table

The rotation rows below are the **scope-exit** case (the node leaves a grantee's reachable scope). A delete/move/rename of a node with **no covering grant is a pure relink — zero rotations** (Section 3.6, decision: scope-exit-only).

| Operation | Crypto | ECIES | Nodes resealed | IPNS republishes | Worst case (N=1e6, R=10) |
|---|---|---|---|---|---|
| Issue read grant | 1 wrap | 1 | 0 | 0 | 0 |
| Navigate to depth-`d` child | `d` unseals + `d` unwraps | 1 (once) | 0 | 0 | 0 |
| Add item | 1 reseal + 1 parent-link | 0 | 2 | 2 | 2 |
| Copy | decrypt + re-encrypt under a fresh `fileKey` → new CID | 0 | 1 (new node) | 1 | O(content); new CID pins under the copier's quota |
| Move within scope | 2 parent-link rewrites | 0 | 2 | 2 | 2 |
| Private delete / move / rename (no covering grant) | unlink + relink (+ `BinEntry` on delete) | 0 | parents | parents | 2 |
| Move out of scope (scope exit) | rotate subtree | re-mint affected grants | \|subtree\| + 2 | \|subtree\| + parents | ~1e6 + 2 |
| Rename over destination (scope exit) | rotate displaced dest | re-mint affected grants | \|dest-subtree\| + 1 | \|dest-subtree\| + 1 | ~1e6 + 1 |
| Shared delete (scope exit) | rotate deleted subtree + revoke grant rows | re-mint affected grants | \|subtree\| + 1 | \|subtree\| + 1 | ~1e6 + 1 |
| Read-revoke (1 of R) | rotate share-root subtree | re-mint R−1 grants | \|subtree\| | \|subtree\| | ~1e6 |
| Write-revoke (1 of R) | full Ed25519 rotation (c) + tombstone old name | re-wrap co-grants | O(subtree) | O(subtree) | ~1e6 |

Copy cannot alias the source CID: content self-seal (Section 2.9) means a copy must decrypt and re-encrypt under a fresh `fileKey`, yielding a new CID. No re-grant, no rotation.

### 3.2 Issue a read grant — `O(1)` crypto, 1 ECIES, 0 republishes

`readDescriptorRef = ECIES_wrap(shareRootNode.readKey → recipientPublicKey)`; insert one `shares` row. No node is touched. Granting a single file is identical to granting a deep folder.

### 3.3 Navigate to a deep child — `O(d)` symmetric, 1 ECIES once, 0 republishes

One-time ECIES-unwrap of the grant, then symmetric walk (Section 2.6) to depth `d`. At a file node, unseal `content` for `cid`/`fileIv`/`encryptionMode`/`content.fileKey`, fetch and decrypt the IPFS blob. Verify the envelope `generation` against the grant (Section 4.6 distinguishes "behind" from "revoked").

### 3.4 Add an item — `O(1)` crypto, 0 ECIES, 2 republishes

Create the new node (fresh `readKey`, fresh `writeKey`, `generation = 0`, seal its bodies). Add a `SealedChildRef` to the parent read-body and a `writeChildren` entry to the parent write-body, reseal both bodies, publish the new node then the parent. **No per-recipient fan-out** — the child read key is sealed under the parent `readKey` every covering grant-holder already has. Deletes `reWrapForRecipients`/`addShareKeys` (`share.service.ts:337,469`).

### 3.5 Move within scope — `O(1)`, 0 ECIES, 2 republishes, no rotation

Remove the `SealedChildRef` from the old parent (reseal + republish); add it to the new parent (reseal + republish). The node keeps its own `readKey`/`generation`. Kills the move-reencrypt storm.

Caveat from review **m2 (per-grant scope):** "within scope" is a **per-grant** property, not a global one. A reader granted at the **old parent only** cached the moved node's `readKey`; after a move to a sibling they do not cover, "within scope for the owner" is "out of scope for that reader." Therefore: **any move that changes a node's ancestor set must rotate if any active grant sits on an ancestor that is no longer an ancestor.** Because FUSE gains a grant-root concept (Section 3.9) and already holds the mounted tree, it can compute **exact per-grant scope** rather than the conservative "rotate on any ancestor-set change" — a move that is genuinely within-scope for all grants (owner-only, or both parents under the same grant root) stays at 2 republishes. This disposes of old open question Q3 (no over-rotation on benign within-scope moves).

### 3.6 Delete / move-out / rename-over — rotate **iff** scope exit (not "always rotate")

The earlier "delete = rotate" / "these three collapse to rotate" framing was **wrong**. The correct, tested invariant:

> Rotate iff the node leaves the reachable scope of at least one active grant; "reachable" means reachable by a **grantee**, not the owner. A node with no covering grant is a pure relink (zero rotations).

`"No covering grant ⇒ 0 rotation"` must be a hard test. Taken literally, the old wording would rotate on every private delete — an `O(subtree)` storm over the unshared 99 % of a vault.

- **Private case** (no covering grant): pure relink. Delete → unlink + `BinEntry` (Section 3.10), no rotation. Move/rename → parent-link rewrites only.
- **Shared case** (node leaves a grantee's scope): do the link mechanics (detach/repoint, reseal + republish parent), then call `rotateReadFromNode` over the departing subtree (Section 4), **composed with** the shipped `revoke-for-items` row-revoke (#563) — preserving its ordering invariant (never a window where the item is gone but its key is not yet rotated). Single-file cases are 2 republishes; million-node subtrees are ~1e6.

Why rotate a **deleted** (shared) node: delete only removes the parent pointer; the CIDs remain on IPFS and a grantee who cached subtree keys can still fetch by CID. Bumping `generation` + new `readKey` (and, per CRIT-1, a new `fileKey` for files, applied lazily) makes cached keys fail against republished blobs and protects future versions. It does **not** protect already-distributed content (ADR 0002, Section 4.1).

### 3.7 Concurrency note for add-during-rotation (HIGH-4)

Applying review **HIGH-4 (data loss):** `rotateOne` re-seals the parent read-body from its in-memory `children[]`. A concurrent add that CAS-wins first will be clobbered when rotation retries from a stale decrypted child list. **Rotation must re-fetch and re-merge `SealedChildRef`s on every CAS-409, not merely re-seal the body.** Section 4.5 makes this explicit. Without it, a concurrent upload during a million-node rotation silently drops the new child.

### 3.8 The unification: one rule, four call sites

> A node leaving a **grantee's** reachable scope ⇒ `rotateReadFromNode(node)`. A node with no covering grant ⇒ pure relink, zero rotations.

This collapses the bug class CipherBox kept patching per mutation-path (`delete.rs`, `rename.rs`, `executeLazyRotation` each special-cased). Defining rotation **recursively** structurally eliminates the `executeLazyRotation:602` single-node bug — there is no un-rotated tail because the walk *is* the definition. Modulo the per-grant scoping in Section 3.5.

### 3.9 Scope computation is client-side (and the FUSE blind spot)

The scope predicate ("is node X reachable from any active grant root?") is **inherently client-side** — the relay cannot answer it, because parent-to-child links live in the sealed read-body and only a key-holder can walk ancestry.

- The relay supplies the **active grant-root set** (`shares` keyed by `rootIpnsName` — plaintext it already holds). The client walks the mutated node's ancestor chain against that set. **Treat the relay set as a completeness aid, not an authority:** the *owner's* client issued these grants, so it must cross-check against its own locally-known grant record. A malicious relay that omits a grant-root from the returned set would otherwise suppress that revoke (a silent missed rotation) — an accepted relay-integrity residual bounded only by the client's own grant bookkeeping, since the relay cannot be trusted to enumerate grants honestly.
- Web computes coverage from `folderTree` **reconciled to the current `sequenceNumber` first** (per the existing reconcile-before-publish discipline). A wrong "don't rotate" is a silent missed revoke, so when the tree cannot be reconciled the mutation **defers** rather than skips rotation.
- **FUSE must gain a grant-root concept** in its `delete` / `rename` / `move` paths (net-new work; add to the blast radius). It already holds the mounted tree, so ancestry is cheap — compute exact per-grant scope (Section 3.5).

### 3.10 Bin (recoverable delete)

The bin is shipped (`packages/core/src/bin/*`, `sdk/src/bin/*`, `spawn_bin_entry_publish`) and was absent from the original design. Under `node/v3`:

- A `BinEntry` is a `SealedChildRef`-shaped link sealed under the **bin's own `readKey`**. **Restore = pure re-link** (re-seal the node's `readKey` under the destination parent), identical to a move. `originalFolderKeyEncrypted` and the re-encrypt-on-restore path become dead code — delete them.
- Private delete → unlink + `BinEntry`, no rotation. Shared delete → rotate the departing subtree + revoke the grant rows (composing #563) + `BinEntry`. Permanent delete → unpin CIDs + drop grant rows.
- Add `bin/*` to the blast radius.

### 3.11 Invites (link / email sharing)

Invites are shipped (`share_invites` table, `share-invite.service.ts`) and in-scope per `CLAUDE.md`, but the original design omitted them. Under `node/v3`:

- An invite wraps the **single share-root `readKey`** to an ephemeral public key; the ephemeral private key travels in the **URL fragment** (never reaches the server — zero-knowledge holds). Delete the `encryptedChildKeys[]` fan-out (JSONB column) — the read chain obsoletes it.
- On claim, the claimer unwraps `readKey` with the URL-fragment ephemeral private key, **re-wraps it to their own public key**, and the server stores a standard `shares` grant. A multi-claim invite mints one standard grant per claimer of the same `readKey`. Revoke = rotate the `readKey` (cuts the link and all claimers at once).
- Accepted exposure: a v3 invite link carries the subtree-root `readKey`; anyone with the link reads the granted subtree — identical in spirit to today's link semantics.

## 4. Read-side resumable rotation

`rotateReadFromNode(nodeId)` backs read-revoke and every scope-exit mutation. It is the expensive side of the asymmetry, and the design's job is to make paying the `O(items)` cost **safe** under crashes, concurrency, and the 6-hour republisher — not to dodge it.

### 4.1 Revocation is lazy and honest — content-key rotation (CRIT-1 + ADR 0002)

Applying review **CRIT-1 (critical):** re-sealing the read-body under a new `readKey` is **not sufficient** for file nodes. A revoked reader cached the old `readKey`, already unsealed `content.fileKey`, and holds the raw AES content key. If a new file version is encrypted under the same `fileKey`, the revoked reader decrypts it the moment they learn the new CID.

Therefore `rotateOne(N)` **for a file node mints a new `fileKey`**, and the next content write re-encrypts under it — surfaced as a per-node `contentRekeyPending` marker. **The re-key is lazy** (applied on the next content write), per ADR 0002: a cold file that is never rewritten keeps its old `fileKey` valid, and the still-pinned CID remains decryptable by anyone who held the key.

This is the honest threat-model stance (ADR 0002): **read-revocation protects future writes, navigation, and filenames — not already-distributed content or prior versions.** Once a reader has held a node's `readKey` and seen a content CID, any IPFS node serves that ciphertext indefinitely and the reader may already hold the plaintext. Every revoke flow must carry the caveat that already-distributed content and all prior versions stay readable. Optionally offer per-file "re-encrypt now" and an `O(versions)` "purge history" operation for high-sensitivity cases.

The Section 4.7 "zero new-content exposure" guarantee holds **only** with this content-key rotation, and only for *future* content. Keep `fileKey` rotation coupled to `readKey` rotation coupled to the `generation` bump.

### 4.2 Ordering: scope-root first

The reader reaches the subtree through one door: the parent's `SealedChildRef[R].readKeySealed` plus, for grantees, the `readDescriptorRef` in their `shares` row. The atomic root step:

1. `R.readKey' ← random32`; `R.generation' ← R.generation + 1`; for files, `R.fileKey' ← random32` (lazy, `contentRekeyPending`).
2. Re-seal R's read-body under `readKey'` with AAD bound to `generation'`.
3. Rewrite R's parent's `SealedChildRef[R].readKeySealed` and mirror `.generation = generation'`.
4. Re-mint `readDescriptorRef` for **every remaining recipient whose grant root is R** against `readKey'`; bump `rootGeneration`; **delete the revoked recipient's row**. (Descendant grant re-mint is handled in Section 4.4 — HIGH-3.)
5. Publish parent then R (entry-point latency preferred for the scope-root; interior nodes use child-first — Section 4.6).

After this one step the revoked reader is cut off from the entry point **for future navigation** — already-fetched CIDs they have seen remain decryptable (ADR 0002); this is a navigation/future-write cut, not retroactive content protection. The residual exposure window is bounded to "already-seen content under not-yet-rotated descendants," never the whole tree, and only ever shrinks as the walk proceeds. This is the precise sense of "a crash must not leave a revoked reader on the un-rotated tail."

### 4.3 Generation downgrade defense (M1) — net-new durable client state

Applying review **M1 (major):** the IPNS signature covers `value=/ipfs/CID` and `sequence` only — **not** `generation`. The parent-mirror AAD defense works for descendants reached through a parent, but a grantee reaches the share-root **directly** via `rootIpnsName`/`rootGeneration`, both relay-served DB values. A colluding relay that simply does not apply the rotation publish (drops it, keeps serving the old signed record) leaves the revoked reader alive with no signed signal.

Confirmed against code: **no resolve path enforces a per-node `generation` check today.** `resolve_sequence_strict` (`crates/fuse/src/publish.rs:140`) tracks only `sequence`, **in-memory, lost on restart**; `VerifiedResolve` exposes `{cid, sequence_number}` and never decodes node metadata; web `resolveIpnsRecord` performs the same sequence-only checks. So the M1 defence is **new work**, not an extension:

- **Persist `{nodeId → highestGeneration}` durably** (IndexedDB / sqlite, beside the sequence cache), seeded from the grant's `rootGeneration` (owner-vouched floor).
- Thread it into `resolve_ipns_verified` (Rust) and `resolveIpnsRecord` (web); **fail closed on generation regression**. On a first-ever resolve with no high-water mark, cross-check the envelope generation against the parent's `SealedChildRef.generation` mirror.
- **Server-side generation gate (defence-in-depth).** Because `generation` is plaintext on the published envelope, extend the publish gate to enforce **forward-only generation per node**, mirroring the sequence anti-rollback and its wild-jump / wedge-poison handling (`ipns.service.ts:313`).

Add a distinct domain tag if `generation` is ever folded into a signed envelope field (review **m4**), to keep AES-GCM AAD inputs and Ed25519 signing inputs from sharing un-separated bytes.

**Irreducible residual:** a colluding relay can serve a victim a self-consistent OLD whole-subtree snapshot if it never lets them see any newer node (no signed generation closes this). The durable client floor (this section) plus the seq high-water (Section 6.5) are the signed-signal-independent defenses that bound it.

### 4.4 Multi-rooted grant re-mint (HIGH-3)

Applying review **HIGH-3 (orphaned grant):** the rotated subtree may contain nodes that were **independently shared** (e.g., a single-file share to Carol deep inside a folder being deleted). Re-minting grants only at the rotation root orphans Carol's grant — her `readDescriptorRef` wraps a now-rotated key and is never re-minted, locking her out with no recovery.

Fix: rotation must **enumerate all `shares` rows whose `rootNodeId` ∈ the rotated set** and, for each non-revoked recipient, re-mint `readDescriptorRef` against that node's new `readKey`/`generation` and bump its `rootGeneration`. The grant re-mint is multi-rooted because the tree is multi-rooted. This is an indexed query on `shares.rootNodeId` per rotated node (or one batched query over the rotated set).

### 4.5 Per-node commit, idempotency, resume

The walk is a frontier traversal with **per-node commit**; each node's published state is its own checkpoint. A client-local job record (IndexedDB/sqlite) makes resume fast but is **advisory** — the published IPNS records are the source of truth.

```jsonc
{
  "jobId": "uuid", "rootNodeId": "R",
  "reason": "revoke" | "delete" | "rename-over" | "move-out",
  "revokedRecipient": "pubkey" | null,
  "rootStepDone": false,
  "frontier": ["childId", ...],
  "done": ["nodeId", ...],
  "status": "running" | "crashed" | "complete"
}
```

`rotateOne(N, parentReadKey)`:

1. Resolve N → envelope `{generation: gN}`.
2. If N is already done for this job (convergence test below) → skip (idempotent).
3. Unseal N's read-body with the key chained from the parent.
4. `readKey' = random32`; `gN' = gN + 1`; for files `fileKey' = random32`, set `contentRekeyPending`.
5. **Re-fetch the current child list and merge any `SealedChildRef`s added since step 3 (HIGH-4)**, then re-seal N's read-body under `readKey'` (AAD `gN'`).
6. Rewrite parent's `SealedChildRef[N].readKeySealed` + `.generation = gN'`.
7. Publish N (CAS on `expectedSequenceNumber`); on 409 → re-resolve, re-run from step 3 (which re-merges children).
8. Fold the parent-link update into the parent's next batched publish.
9. Re-mint any grants rooted at N (Section 4.4); mark N done; push N's children with `readKey'`.

There is no global `targetGeneration` — generations are per-node. The rotation target is per-node `current + 1`.

Convergence test: **N is done iff `parent.SealedChildRef[N].generation == N.envelope.generation` and that generation exceeds the baseline observed when N was enqueued.** If the job record is lost, fall back to "parent mirror agrees with child envelope ⇒ done; disagree ⇒ in-flight."

Crash recovery and double-rotation safety: if the job record is lost between "published N at `readKey'`" and "rewrote parent link," the new key is gone and the parent link cannot be re-sealed to match. Resolution: **a fresh full `rotateOne(N)` is the recovery path** — generate `readKey''`/`gN''`, seal the parent link with `readKey''`, publish both. An extra rotation only strengthens revocation and costs one republish. Double-rotation safety is what lets the published IPNS state be the sole source of truth. Publish-child-then-parent ordering guarantees the worst a crash leaves is a child ahead of its parent — exactly what a plain re-rotation fixes.

`verifySubtreeClean(R)`: an `O(items)` read-only pass that flags any edge where `parent.link.generation ≠ child.envelope.generation`. It is the resume entry point (rebuilds the frontier) and the post-completion audit (a converged job has zero dirty edges).

### 4.6 Concurrency, convergence, and the 6-hour republisher (corrected)

- **Sequence races (CAS 409).** Publishing is `dbSeq + 1` forward-only CAS (`ipns.service.ts:301-317`). Rotation treats 409 as "refetch + re-apply," never failure: re-resolve, re-run `rotateOne` from current state (re-merging children). Bounded exponential backoff; the FUSE `PublishCoordinator.get_lock(name)` serializes the job against the user's own client.
- **Same-parent serialization.** Add/rename/move on a node take the same `PublishCoordinator.get_lock(name)` the rotation holds, so a stale-key add cannot interleave with that node's rotation locally.
- **The 6-hour TEE republisher is NOT orthogonal.** The original "orthogonal, never touches generation" claim was wrong and security-critical. A read-key rotation does not rotate the Ed25519 key, so a republisher that re-signs from a stale snapshot can re-sign the **pre-rotation (revoked-readable) CID at a forward sequence** — a read-revocation bypass. The full diagnosis and the structural fix live in **Section 6** (the republisher signs no CID scalar; it renews the lease on the canonical record, and republish never increments the sequence). Keep this cross-reference; do not re-derive the fix here.

**Corrected convergence invariant.** The earlier claim that "every operation is a forward-only function on `generation` + `sequence`" is **false as stated**: the CAS gate enforces forward-only **sequence** only; `generation` lives in the body/envelope and is **not** gated by CAS. A stale-key holder can republish a cached pre-rotation body (re-sealed under the old `readKey`) at a forward sequence, regressing `generation` and silently undoing the cut. HIGH-4's re-merge covers dropped children, not this. The real invariant is:

> Forward-only **sequence** (CAS-enforced) **and** forward-only **generation** (same-parent serialization + the M1 client check + the server-side generation gate, Section 4.3) — **not** by the CAS alone.

The AAD design makes the race windows **fail closed** (security) but **fail loud** (a legitimate reader hitting a momentary parent/child generation mismatch retries) — acceptable only because the walk converges quickly.

Honest-reader liveness (review **MED-6**): after any rotation, a still-authorized reader sees a generation bump and must re-fetch their re-minted grant; if they resolve the new root body before the API has the re-minted `readDescriptorRef`, they hard-fail. Provide a "soft behind, retry" vs "hard revoked" distinction on the read path (re-minted grant present but generation ahead ⇒ retry; grant row deleted ⇒ revoked). This mirrors the documented `#489`/`#494` "Folder not loaded" desync class — reconcile `folderTree` against `sequenceNumber` before rotation publishes.

### 4.7 Exposure window and where the job runs

Read-key material is client-only (zero-knowledge). The rotation walk generates new keys and re-seals bodies, so it **must run client-side** on a client holding the share-root `readKey` (owner or write-grantee). The relay only provides IPNS CAS and IPFS storage. It cannot be offloaded to the relay/TEE — the TEE only renews record leases (write plane, Section 6) and never decrypts read content.

At 1e6 nodes the job is owner-online and resumable across sessions (persist the frontier each batch; resume via `verifySubtreeClean`). Desktop (FUSE/Tauri) is the natural host (long-lived process, `PublishCoordinator`, keys in memory). UX: the revoke is effectively complete for the revoked reader the instant the root step lands; surface "revoked" immediately and "fully rotated N/M" as background progress.

Exposure guarantee, eager: entry-point window = 0; interior **future** content protected as soon as its nearest-rotated-ancestor rotates (≤ walk duration), **provided CRIT-1 content-key rotation is applied**; already-published content is irreducible (IPFS, ADR 0002). Batch parent-link rewrites — when many children of one parent rotate, publish the parent **once** per batch — the main constant-factor win at scale.

### 4.8 Eager is the committed model; lazy walk is deferred

**Commit to eager rotation** (Tier-1 item 3 accepts the `O(items)` cost). Note the precise meaning, per ADR 0002: **"eager rotation" means an eager cut of navigation + future writes, not eager content protection.** A file rotated on revoke gets a fresh `fileKey` only on its next content write (`contentRekeyPending`); already-distributed CIDs stay decryptable.

The lazy *walk* variant ("rotate-on-next-write across the subtree") is **deferred**, not part of the core deliverable — it doubles the rotation surface and reintroduces the mixed-generation, cold-node-filename-leak surface that the unsound `executeLazyRotation` had (review **MED-5**: a revoked reader holding a cold node's old key reads `SealedChildRef.name` of items added after revocation, because the name is plaintext within the sealed body). For a user-initiated revoke, the eager walk is **mandatory**, not merely the default.

The genuinely useful nuance — "delete of one file shouldn't walk anything" — is just **subtree size 1**, not a separate algorithm. Keep one deferred sentence: the `generation`/`rotateOne` primitive is amortizable on-write later if the eager cost proves painful. Do not build two rotation modes now.

## 5. Write-revocation: ratified as (c) full Ed25519 rotation

The read schema is invariant across all candidates (the write material is a separate sealed body, Section 2.2). This decision was deferrable without reworking the read chain; it is now **ratified as (c)** (ADR 0001).

### 5.1 Comparison

| Dimension | (a) Mediated (relay→TEE sign) | (b) Per-grant subkey | **(c) Full Ed25519 rotation (RATIFIED)** | (d) Hybrid: owner self-signs, delegated mediated |
|---|---|---|---|---|
| Recipient holds Ed25519 key? | No | Yes (ephemeral) | Yes (shared) | No for delegated |
| Revoke cost | O(1), no republish | O(subtree) cascade | O(subtree) cascade | O(1) for delegated |
| New k51 / stable-name break? | No | Yes | Yes | No |
| Seq race | relocated into relay | reintroduced + desync | reintroduced | **not serialized under (d)** |
| New infra | synchronous `POST /ipns/sign` (does not exist) | none | none | the `/ipns/sign` endpoint |
| New trust | TEE + relay on write path | none cryptographic | none cryptographic | TEE + relay for delegated subset |
| Write integrity | depends on API token validation | cryptographic | cryptographic | depends on API for delegated |
| Read schema impact | zero | zero | zero | zero |

Only **full (a)** uniquely serializes the sequence race (the server assigns sequences atomically). (c), (b), and (d) do not — and (d) does not even relocate it cleanly (two signing paths contend on one counter). This is (a)'s only real edge; do **not** erase it (it was the §5.4-vs-§8 inconsistency in the pre-amendment draft).

### 5.2 Ground truth

- The gap is real: `shared-write.ts:138-141,311` ECIES-wraps the raw Ed25519 key; deleting the row is cryptographically inert.
- Publish auth is key-possession only — `ipns.service.ts:226` confirms "no ownership/share check." The `existing.publicKey.equals(...)` check only ensures the **same** key keeps writing a name; it is not identity-bound. Whoever holds the key publishes.
- **No synchronous TEE sign endpoint exists.** TEE signing is batch-republish-only (`tee.service.ts:110`, driven by `republish.service.ts`). (a)/(d) would require building a new enclave-facing endpoint, an authz-token table, and a client publish-path rewrite.
- The k51 name is bound to the Ed25519 key (`deriveIpnsName`/`publicKeyFromIpnsName`), strict-verified from the name (`publish.rs:156`). Any key rotation changes the name → parent re-point → cascade. This is what dominates (b)/(c).
- Sequence is a single per-row `dbSeq + 1` counter; every co-writer races it regardless of which key signs (see Section 6.6 for the atomic-CAS fix).

### 5.3 Decision: (c), and its honest cost

The security review and the correctness review both land on **(c)** (ADR 0001). The mediated path turns the **untrusted relay into a write-forgery / confused-deputy signing oracle**:

- The TEE would sign whatever record the API authorizes, with the **owner's** key. A token-validation bug, SSRF, or auth bypass forges IPNS records **under the owner's identity** for the whole delegated scope — write-integrity now depends on API correctness, which the entire system was designed not to trust.
- Scope-escalation: unless the TEE verifies the unsigned record's name/sequence/CID is within the granted subtree, a delegate with a token for node X can submit a record for node Y. Key-possession candidates (b)/(c) structurally cannot have this — you can only sign names whose key you hold.
- Hybrid (d) does **not** serialize the sequence race (review **HIGH-2**): owner self-writes (self-signed) and delegated mediated-writes contend on the same counter from two signing paths, with a TOCTOU window. The seed's "fixes the race" framing is false.

**Re-cost (c) honestly.** (c) is **not** "a strict subset of the read-rotation machinery" — it is strictly heavier. Read-revoke keeps k51 names stable and descends; write-revoke under (c):

- mints a new keypair and k51 name **per node**,
- cascades parent re-points **upward** to the share root,
- re-enrolls / unenrolls the TEE per node,
- re-points all co-grants **and** owner devices.

So (c)'s true cost is `O(subtree republishes) + O(co-writers re-wraps)`. **(b) is dominated by (c)** — same k51 break and cascade, an extra ephemeral-key indirection, no compensating benefit; the "revoke one grant without disturbing others" edge is illusory because all writers to one mutable node share one IPNS identity.

Co-writer re-key (review **m1**, must be designed, not hand-waved): surviving co-writers receive the rotated Ed25519 key re-wrapped into their write-grant row (`writeDescriptorRef`). A co-writer offline during rotation cannot write until they re-fetch — acceptable, but explicit.

### 5.4 Runner-up and flip conditions

Runner-up: **(a) full mediated** (all writes mediated, single signer) — **only** if the maintainer accepts TEE+relay in the write-trust base and builds a TEE that **verifies the record is within the token's authorized name/subtree** before signing. Full (a) genuinely serializes the sequence race (Section 5.1), which (c) does not.

The choice would flip from (c) to (a) if: the `O(subtree)` write-revoke cascade is judged unacceptable for the expected revoke frequency; AND a TEE sign-endpoint with airtight token-to-name binding can be delivered to a trustworthy standard; AND write-time coupling to TEE/relay liveness (today's 30s TEE timeout, "TEE unavailable is expected in dev") is acceptable for delegated writers. Absent all three, **(c) stands** — it is the zero-new-infra option consistent with the system's untrusted-relay premise.

Honest residue regardless of pick: the single-counter IPNS sequence race is mitigated, not eliminated, by the atomic CAS (Section 6.6). Do not let "fixes the race" factor into the mechanism choice.

### 5.5 Tombstone the rotated-out IPNS name (tombstone-and-keep)

Approach (c) changes the k51 name and re-points parents, but `unenrollIpns` deletes **only** the schedule row (`republish.service.ts:257`) — the old `ipns_records` row persists and the publish gate has **zero revocation awareness**, so a revoked writer's cached key can publish to the old name **forever**, and resolve still serves it to stale links.

On rotation, **tombstone** the old row (keep it, do **not** hard-delete):

- the publish gate **rejects all writes** to a tombstoned name,
- resolve returns a tombstone / `410` (never stale content),
- the name is **TEE-unenrolled** — concretely, **removed from the republish batch** (today `unenrollIpns` only deletes the schedule row, which is *not* sufficient), so the lease-renewer (Section 6.4) is never handed the old name to re-extend. The renewal write is itself a publish, so the publish-gate tombstone check (Section 6.6) **must also reject the EOL-only renewal CAS** for a tombstoned name — otherwise a malicious relay that re-feeds the old signed record to an honest TEE could keep a revoked name's lease alive, defeating the "never stale content" promise.

Tombstone-and-keep (rather than hard-delete) so stale links/bookmarks get an explicit "moved/revoked" signal rather than silent stale content.

## 6. Resolve, republish, and the TEE signing contract

This section is the resolve/republish/TEE model ratified in session 2 (decisions 14–20; the rotated-out-name tombstone, decision 21, lives in Section 5.5 since it is a write-revocation mechanic). It **supersedes the original "republisher is orthogonal" claim** (Section 4.6) and the interim "republisher sources canonical `latestCid`" patch: the fix is now achieved **structurally** (decisions 16–17) rather than by refreshing a snapshot. All claims below were verified against current code.

### 6.1 Resolve precedence: `generation` is the anti-rollback authority; resolve-source is a latency layer

The IPFS/IPNS network is permissionless — its only anti-rollback is **"higher sequence wins; on equal sequence, later EOL wins"** (verified against boxo/go-ipns `compare`). So the network **cannot be the integrity authority**; `generation` (M1, Section 4.3) is. Resolve-source (network vs DB) is a **latency / availability layer beneath** that authority.

Near-term the **DB is canonical**: the relay writes the DB **synchronously before** the fire-and-forget someguy push (`ipns.service.ts:106-144`), so the DB **leads** the DHT by ~10–30 s. The intuition that "the network is fresher" is **inverted** in this relay-mediated topology. "Network strictly ahead of DB" is therefore an **alarm**, not a normal branch.

The maintainer's "network as the single source of truth, DB as fallback" ideal is reachable for **confidentiality** once M1 ships (generation rejects any cross-generation rollback regardless of source), **but it stays gated on the within-generation floor (Section 6.5) — M1 alone does not unlock it.** A re-pointed network-first resolve therefore remains a post-M1 **v2 move**, not something this design enables; near-term, DB-canonical with M1 + the seq-floor is the resolve posture.

### 6.2 Sequence advances iff the CID changes; republish never increments

**A republish re-signs the *same* sequence with a fresh EOL.** IPNS record selection's equal-sequence→later-EOL tiebreak lets the refreshed record win without consuming a sequence. The relay publish path already does this on the idempotent branch (`ipns.service.ts:306-317`, "D-09"); but the **TEE 6-hour republisher still does `+ 1n`** (`apps/tee-worker/src/routes/republish.ts:79`) and must be unified to the no-increment path.

Incrementing on republish is not just unnecessary, it is **harmful** — it races client writes for sequence numbers and widens the replay window. This invariant **alone** closes the Section 4.6 republisher-stale-CID rollback: a re-signed stale CID stays at its old sequence and is dominated by any genuine forward client publish. Increment policy moves **out of the enclave into the relay**.

### 6.3 Collapse the dual-source record state

`ipns_republish_schedule` duplicates `latestCid` / `sequenceNumber` / `encryptedIpnsKey` / `keyEpoch` (`republish-schedule.entity.ts:39-60`) and the TEE signs **that** snapshot (`republish.service.ts:101-102`), which goes stale on a normal content write (refreshed only on key-enrollment).

Make the canonical **`ipns_records` row the sole source** of the TEE's signing inputs; reduce the schedule to scheduling metadata (`next_republish_at`, `consecutive_failures`, `status`) — or fold those columns into `ipns_records` and drop the table. This structurally kills both the stale-CID rollback **and** a latent availability bug: today the republisher keeps the *old* CID's network record fresh while the canonical *new* CID's record expires ~48 h after the client's one-time publish (masked only by DB-canonical resolve).

### 6.4 The TEE is a record-lease-renewer, not a signer of supplied scalars

Clients self-sign every content change with their client-held Ed25519 key (`packages/core/src/ipns/create-record.ts`; the relay only verifies, `ipns.service.ts:100`), so the TEE never needs to originate a CID. New enclave contract:

- The relay sends the **marshaled existing `signedRecord`**.
- The TEE **parses it, verifies its signature**, and re-emits a record with the **same value (CID) and same sequence**, only a **later EOL**.
- The TEE therefore **cannot originate or repoint a CID** — it can only extend a lease.

"Verify against what the network resolves" was **rejected** as the mechanism: it is circular (the relay controls the enclave's network view), inverts the ratified source-of-truth (the network is the lagging untrusted replica), and fights the propagation window. Worst residual on an **honest** enclave: a malicious relay replays an *old* lower-seq validly-signed record for renewal — dominated by sequence and caught by M1.

### 6.5 Complete the resolve anti-rollback (the seq-floor companion to M1)

`generation` only bumps on rotation, so **within-generation** version rollback — serving an old, genuinely-signed, lower-seq record in the *same* generation — passes every current check. Add:

1. **Durable per-node `{nodeId → highestSeq}` high-water** on the client (the sequence analog of the M1 generation map), rejecting `seq < high-water` regardless of resolve source.
2. **Bind a version floor** into the `SealedChildRef` at (re)share (the `versionFloor` field, Section 2.6), so first-contact and cold/reset devices inherit an **owner-vouched floor** from the parent chain (the `SealedChildRef` mirrors generation but not version today). The operative form is a **seq integer** driving the `seq ≥ versionFloor` check; a head-Node hash is an alternative that pins the *exact* first-contact head (rejecting all forward versions until the durable seq high-water takes over), so do not use the hash form as a standing floor — once the high-water of item 1 is established it supersedes the share-time floor.
3. The relay must **never silently fall through to an ungated network record.** When the canonical DB row is unparseable (`parseCachedRecord` null), the response is **case-dependent** — do not leave it as an undifferentiated "fail closed *or* floor":
   - **Expected null `signedRecord` (shared-folder rows).** This is the *normal* state for shared-folder rows (`signedRecord`/`public_key` legitimately null, see Section 7.1), not corruption — failing closed here would break legitimate shared-folder resolve. Apply the `seq ≥ storedSeq` floor from the DB `sequenceNumber` column to the network record.
   - **`signedRecord`-CID ≠ `latestCid` mismatch.** This is corruption or an attack (a row whose signed bytes disagree with the canonical CID). **Fail closed** — never serve it and never fall through.

This closes the Section 4.3-M1 colluding-relay-drops-publish residual — the durable client floor is the signed-signal-independent defense.

### 6.6 Atomic publish CAS

`publishRecord` is a non-atomic `findOne → gate → save` with no row lock / `@VersionColumn` / conditional UPDATE, so two concurrent forward writers both at `dbSeq = N` both pass the gate and the second `save` clobbers the first — a `200`'d write silently lost (generation cannot help; same generation). Decision 16's single canonical row makes it the sole serialization point, and the lease-renewal of Section 6.4 hits the idempotent branch on it, **widening** the race.

Fix: a single compare-and-set —

```sql
UPDATE ipns_records SET … WHERE ipnsName = :n AND sequenceNumber = :expected
```

— 0 rows affected ⇒ 409. The idempotent / renewal write is guarded identically (`WHERE sequenceNumber = :loaded`) so an EOL-only renewal can **never** regress `latestCid` / `sequenceNumber` from a stale in-memory row.

### 6.7 Three enclave bindings beyond the lease-renewer contract

The relay still feeds the enclave the epoch scalars, the wrapped key, and the claimed name. Harden:

1. **Internal epoch derivation.** The TEE derives `currentEpoch` / `previousEpoch` from its **own clock + epoch schedule** (never the relay's scalars), with re-wrap targets restricted to an **enclave-enumerated set** — else a malicious relay coerces re-wrapping every IPNS key under an attacker-chosen epoch pubkey for later offline forgery.
2. **Name↔key binding.** Before emitting, assert `publicKeyFromIpnsName(ipnsName) == pubkey(decryptedKey) == record.pubkey` (closes batch cross-contamination / key-confusion / cross-name forgery).
3. **Migration durability.** Because a malicious relay can drop the returned `upgradedEncryptedKey` and brick a name at epoch retirement, make the **client** the recovery path (periodic re-enroll / re-wrap from its held key), or have the TEE **refuse to renew a key older than `currentEpoch − 1`**.

### 6.8 Accepted residuals (resolve / republish / TEE)

- **Compromised enclave / leaked epoch key = total loss** — every wrapped IPNS key is unwrappable offline and every vault repointable. The lease-renewer contract (Section 6.4) bounds the *honest* enclave's worst case to lower-seq replay; it does **not** contain a malicious enclave. This rests entirely on **Phala remote-attestation** (enforced on every epoch-key provisioning) + **epoch-rotation cadence** (bounds the exposure window). Stated as the explicit systemic residual.
- **Equal-sequence EOL selection** is a freshness/availability nuisance only: under decisions 6.2 + 6.4 same-sequence records must share a CID, so the relay's choice of which equal-seq record a client sees cannot fork content. Escalate only if equal-seq distinct-CID records can ever be minted.
- **Already-distributed ciphertext stays readable** (ADR 0002) — unchanged.

## 7. Blast radius, cutover ordering, and test strategy

### 7.1 Blast radius (most → least invasive)

| Layer | Change | Invasiveness |
|---|---|---|
| `packages/core` | Replace `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` + vault `encryptedRootFolderKey` with `Node`/`SealedChildRef`/`PublishedNode` + codecs (two sealed bodies, content self-seal, structured write chain) | Highest (keystone) |
| `crates/fuse` | Symmetric child-key unwrap; delete `spawn_file_meta_reencrypt`; add `rotateReadFromNode`; unify scope-exit; **grant-root awareness in `delete`/`rename`/`move`**; durable M1 generation + seq high-water; `Node` as Rust enum | High (Rust, two clients) |
| `apps/tee-worker` + `packages/core/src/ipns` | **TEE enclave contract rewrite** (lease-renewer: receive marshaled record, verify signature, extend EOL; internal epoch derivation; name↔key binding); republish no longer increments | High |
| `packages/sdk` + `sdk-core` | Read-chain navigation; rewrite `shared-write.ts` (structured write-body, role `0x04`); delete `addShareKeys`/`reWrapForRecipients`; rotation driver; `bin/*` re-link; invite claim re-wrap | High |
| `apps/web` | Replace `executeLazyRotation` with `rotateReadFromNode`; drop per-mutation fan-out; reconcile `folderTree`; durable M1 generation + seq high-water | Medium-High |
| `apps/api` | Delete `share_keys`; slim `shares` (`readDescriptorRef`/`writeDescriptorRef`); rotation bookkeeping; **collapse `ipns_republish_schedule` duplicated columns into `ipns_records`**; **atomic conditional-UPDATE publish CAS**; **tombstone state + publish-gate rejection + resolve tombstone/410 + TEE unenroll**; client-side re-enroll/re-wrap recovery path; `resolveRecord` fail-closed fall-through; **rename `folder_ipns` → `ipns_records`** (entity `IpnsRecord`, repository) and **drop `folder_ipns.public_key`** | Medium-High |
| `packages/crypto` | Add `sealAesGcmAad`/`unsealAesGcmAad` + `buildNodeAad` (TS + Rust twin + KAT; frozen byte encoding incl. role `0x04`) | Low (additive) |

`folder_ipns` → `ipns_records`: the table holds the IPNS records for files, root, bin, and the vault-key blob too, not just folders — rename it (free under greenfield). Drop `folder_ipns.public_key`: it is the raw 32-byte Ed25519 IPNS pubkey (`ipns.service.ts:72-79` validates length 32 and `deriveIpnsName(pubkey) === ipnsName`), not the user's secp256k1 `publicKey` (the owner is tracked by `userId`); it is null for shared-folder rows and derivable from the k51 name via `publicKeyFromIpnsName`, so drop the nullable column and always recover from the name (removes the null-row footgun behind two Phase-60 regressions).

### 7.2 Buildable cutover order

1. `packages/crypto` — `sealAesGcmAad`/`unsealAesGcmAad` + `buildNodeAad` (TS) + byte-identical Rust twin + a committed cross-language KAT fixture (frozen byte encoding, role `0x04`) asserted by both. Self-contained, no consumers break.
2. `packages/core` — `Node`/`SealedChildRef`/`PublishedNode` + codecs, two sealed bodies, content self-seal, structured write chain, `versionFloor`. Keystone — nothing below typechecks until done.
3. `packages/sdk-core` — read-chain navigation + `rotateReadFromNode` driver (in named files, not a fat `index.ts` barrel — coverage excludes barrels). Rebuild dist before consumers.
4. `packages/sdk` — `shared-write.ts` rewrite (structured write-body, (c) full rotation); delete `addShareKeys`/`reWrapForRecipients`; `bin/*` re-link; invite claim re-wrap.
5. `apps/api` — delete `share_keys`; slim `shares`; rename `folder_ipns` → `ipns_records` + drop `public_key`; collapse the schedule's duplicated columns; atomic publish CAS; tombstone state + publish-gate rejection + resolve fail-closed fall-through. Run `pnpm api:generate`, commit the regenerated client (pre-commit `check-api-client.sh`).
6. `apps/tee-worker` — lease-renewer contract (verify marshaled record, extend EOL, no increment); internal epoch derivation; name↔key binding. Round-trip the TEE/republish E2E.
7. `apps/web` — `executeLazyRotation` → `rotateReadFromNode`; drop per-mutation fan-out; reconcile `folderTree` against `sequenceNumber` before publishes; durable M1 generation + seq high-water.
8. `crates/fuse` — symmetric unwrap; delete reencrypt; unify scope-exit; grant-root awareness; durable client floors; strict-verify each republish; `Node` enum. Budget a Windows CI round-trip for winfsp (`windows/*` can't compile on macOS; `Cargo Check & Test (Windows)` is authoritative; watch the `super::` vs `super::super::` nesting trap, and the `platform/windows/write_ops.rs:1182` reencrypt twin).

Strict-verify caveat: recover the Ed25519 pubkey from the k51 name via `publicKeyFromIpnsName`, **never** from the (now-dropped) `public_key` column. Each rotation republish must round-trip the verified chokepoint.

### 7.3 Test strategy (must-pass-before-merge first)

1. **Rotation crash-safety / resume (the suite that must exist before merge).** Deterministic fault-injection that aborts the walk after each node and asserts: (i) the revoked recipient can't unwrap from root after the root step; (ii) re-run converges; (iii) no incorrect double-bump. Extend `tests/sdk-e2e` (the only real client→API IPNS publish/resolve round-trip) with abort-and-resume cases.
2. **CRIT-1 content-key rotation.** Rotate a file node, publish a new version, assert a holder of the **old** `readKey`/`fileKey` cannot decrypt the new version.
3. **HIGH-3 multi-rooted re-mint.** Independently-shared single file inside a deleted/moved subtree — assert the inner grantee's `readDescriptorRef` is re-minted (not orphaned), and a revoked recipient is cut.
4. **HIGH-4 add-during-rotation.** Concurrent upload during rotation — assert the new child is not dropped (re-merge on 409).
5. **M1 generation downgrade.** Relay serves a stale signed record post-rotation — assert the client fails closed on generation regression (durable high-water survives restart).
6. **AAD transplant resistance.** Replay a valid `readKeySealed` under a different `childId`/`role`/`generation` — assert `unsealAesGcmAad` rejects.
7. **TS↔Rust AAD KAT.** One committed fixture asserted by both `packages/crypto/__tests__` and a Rust `#[test]` — a byte mismatch is silent total decryption failure.
8. **CTR content + version.** A CTR content and a CTR `VersionEntry` both decrypt under the v3 content schema.
9. **Scope-exit only.** A private delete/move (no covering grant) performs **zero** rotations (pure relink); a shared delete rotates + revokes.
10. **Bin restore.** Restore is a pure re-link (no re-encrypt).
11. **Invite claim.** Claim re-wraps the share-root `readKey` to the claimer; revoke (rotate) cuts the link and all claimers at once.
12. **Republisher stale-CID.** Republisher re-signs mid-rotation → assert the revoked CID is never re-signed and never served; assert republish does **not** increment the sequence.
13. **Within-generation rollback.** Relay serves an old lower-seq same-generation signed record → client rejects via the seq high-water.
14. **First-contact / cold-device rollback.** Fresh client with no local high-water → the `SealedChildRef` `versionFloor` rejects a below-floor seq.
15. **`parseCachedRecord`-null fall-through.** An unparseable canonical DB row → resolve fails closed (or applies the seq floor), never serving an ungated network record.
16. **Concurrent forward publishes.** Two devices at the same `dbSeq` → exactly one 409, zero lost updates.
17. **Lease-renewal racing a forward publish.** The renewal never regresses `latestCid`/`sequenceNumber`.
18. **TEE name↔key binding.** A swapped wrapped key / wrong-name slot → the enclave refuses to emit.
19. **TEE epoch self-derivation.** An attacker-supplied `currentEpoch` is ignored; re-wrap only targets an enclave-valid epoch.
20. **Tombstoned name.** Writes to a tombstoned name are rejected; resolve returns the tombstone, not stale content.
21. **winfsp read-path.** `gh workflow run "Cargo Check & Test (Windows)"` is authoritative.

Keep checker subagents to static analysis only (no concurrent vitest — RAM starvation).

## 8. Forward-looking capability-layer fit (Tier 3 — not required)

Bottom line: the Tier-1 core is cleanly extensible to the speculative agent-capability ideas (TTL, per-file/read-only scope, op-count caps), the extension point is the write/grant plane and never the read chain, and building any of it now would be premature. The deliverable stands on Tier 1+2 alone.

What is already delivered by Tier 1 (not future work): **per-file and read-only scope.** Single-file shares fall out of content self-sealing (Section 2.9); read-only-vs-write is the `permission` column plus the omitted write body. Nothing to add later.

What is sound to extend later, for free: the grant row is already `O(recipients)` and column-extensible — adding `ttl`/`opCap`/`capabilityId` columns is a non-breaking migration; `generation` already gives per-node revocation granularity.

What is unsound and must not be built as described: **read-side TTL/op-caps are cryptographically unenforceable.** Once a reader holds key + CID, IPFS serves the content forever; a "read expires in 1h" claim is security theater unless you re-encrypt + rotate at expiry, which is just scheduled read-revocation (the Section 4 machinery), not a cheap TTL. Time-boxing and op-caps are meaningful **only on the write path**, and only if a mediated mechanism is ever chosen.

The two cheap, non-committal hooks already in this design: the write body is sealed and separable (the forward-compat surface), and revocation routes through `rotateReadFromNode` keyed on `generation`. Do **not** add `ttl`/`opCap`/`capabilityId` to `Node` or `SealedChildRef`, and do not name an `authzTokenId` as the hook (that pre-decides mediated writes). If a capability layer is ever built, it attaches to the write/grant plane, is unenforceable on reads, and needs nothing in the node schema. If Tier 3 is never pursued, nothing here is wasted.

## 9. Decisions resolved and remaining open questions

### 9.1 Resolved by the grilling sessions (ADRs + decisions)

- **Write mechanism** → **(c) full Ed25519 rotation**, ratified (ADR 0001). (Full (a) mediated remains the documented runner-up with explicit flip conditions, Section 5.4.)
- **Terminology** → `readKey` / `writeKey` adopted; `folderKey` / `fileKey` / `rootFolderKey` retired; `shares` row uses `readDescriptorRef` / `writeDescriptorRef`; `folder_ipns` → `ipns_records`; `public_key` column dropped (CONTEXT.md).
- **Move-within-scope cost** → FUSE gains grant-root awareness and computes **exact per-grant scope** (Section 3.5); benign within-scope moves do not over-rotate.
- **Migration** → none; greenfield, `node/v3` is the sole codec (Section 1.6).
- **Republisher / resolve / TEE** → DB-canonical resolve with M1 + seq-floor authority; republish never increments; TEE is a lease-renewer; atomic publish CAS; tombstone rotated-out names (Section 6).

### 9.2 Remaining open questions

1. **Co-writer offline handling.** Under (c), a co-writer offline during a write-key rotation cannot write until they re-fetch the re-wrapped key (Section 5.3). Accepted as explicit, or is a grace/notification mechanism wanted?
2. **Rotation host.** Eager million-node rotation is owner-online and resumable; desktop (FUSE) is the natural host. Is it acceptable that a pure-web user without the desktop app pays a long, chunked, multi-session rotation for a large revoke?
3. **Write-recipient deletions vs owner-held sub-shares.** When a write-recipient (C) deletes, moves out, or overwrites a node inside a shared folder that the OWNER had *independently* sub-shared to a third party (e.g. a single file shared to D), C can unlink it immediately (C holds the folder's write keys and signs the folder publish) but **cannot** cryptographically revoke D's grant — only the owner holds that node's rotation keys and authority over the `shares` rows. So the unlink and the revocation are split across two principals. Options: (a) leave the sub-share dangling until the owner's next sync runs a reconciliation/rotation pass — bounded exposure window in which D retains read access to the now-binned snapshot (already irreducibly readable via IPFS, ADR 0002, so arguably acceptable); (b) block a write-recipient from destroying a node that carries owner-owned sub-shares — but that requires the relay to tell the writer "this node has active grants," leaking share existence to a delegate; (c) have C's mutation enqueue an owner-signed revocation request that the owner (or the owner's desktop/TEE-mediated agent) executes on next online. Decide the authority model and the acceptable exposure window. (Surfaced from the FS-permutations walkthrough — flow `write-recipient-c-delete-file1`.)
