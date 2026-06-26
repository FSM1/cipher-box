# CipherBox Read Key-Chaining — Implementation-Ready Design

Status: design complete, implementation-ready. Tier 1 is firm. Tier 2 (write revocation) is a maintainer decision with a recommendation. Tier 3 is a non-required forward-compatibility note.

This document integrates four design slices (schema, flows, rotation, cutover) and applies the fixes from three adversarial reviews. Blocker and major findings are resolved inline; deferred items are flagged with rationale.

## 1. Overview and rationale

### 1.1 What we are building

CipherBox is a zero-knowledge encrypted IPFS/IPNS vault: the server is a dumb relay that never sees plaintext or any unwrapped/derivable key. We are replacing the DB-driven sharing model (a per-`(share, item, keyType)` `share_keys` table — `O(items × recipients)` rows) with **metadata-driven read key-chaining**, and fixing two confirmed revocation gaps.

The core idea: every node's metadata carries the wrapped keys to reach its children, sealed so that a holder of the node's read key can unwrap its children's read keys, recursing down. Sharing read access = hand the recipient **one** wrapped key at the share-root node (any node — deep folder or single file). No per-item DB rows, no separate lockbox or sidechain object. The only data-plane DB residue is `O(recipients)` read-root grants.

### 1.2 The no-sidechain win

Today, each `FolderEntry` ECIES-wraps **both** a `folderKeyEncrypted` (read) **and** an `ipnsPrivateKeyEncrypted` (write) to the owner, inline per child (`packages/core/src/folder/types.ts:30-46`). Reads are `O(children)` ECIES; sharing fans out into the `share_keys` table. The read chain replaces all of this with **one ECIES at the share-root, then `O(depth)` symmetric AES** down the tree. Creating a child no longer fans out per recipient — the child key is sealed under the parent key every covering grant-holder already holds transitively.

### 1.3 The two gaps being fixed

1. **Read revocation is lazy, folder-coarse, and unsound.** `executeLazyRotation` (`apps/web/src/services/share.service.ts:602-660`) rotates **only** the share-root `folderKey` and never walks descendants. A revoked reader who cached subtree keys keeps reading. `revokeShare` soft-deletes and keeps `ShareKey` rows "for lazy rotation" (`apps/api/src/shares/shares.service.ts:256-269`).

2. **Write delegation hands out an un-rotatable key.** `shared-write.ts` ECIES-wraps the **real Ed25519 IPNS private key** to the recipient (`packages/sdk/src/share/shared-write.ts:138-141,311`). Deleting the `share_keys` row has zero cryptographic effect — the recipient already cached the 32-byte seed. Publish authorization today is **key-possession only**: `ipns.service.ts:226` confirms "no ownership/share check"; whoever holds the Ed25519 key publishes regardless of `userId`.

### 1.4 The read/write revocation asymmetry (real and accepted)

Read-revoke is **irreducibly `O(items)` IPNS republishes**. Content lives on IPFS, content-addressed: once a reader holds a node's read key and a child CID, any IPFS node serves that ciphertext forever. The only cutoff for **future** content is to change keys on every reachable node and republish. There is no chokepoint on reads.

Write-revoke **can** be cheaper, because writes pass through the relay at publish time — a chokepoint that can deny an action. The cost ranges from `O(1)` to `O(items)` depending on the Tier-2 mechanism chosen (Section 5).

### 1.5 Tiering of this document

- **Tier 1 (firm):** Sections 2, 3, 4. The read chain, the unified Node schema, the rotation engine, the unified scope-exit rule. Designed within the maintainer's committed direction; not relitigated.
- **Tier 2 (maintainer decision):** Section 5. The write-revocation mechanism, evaluated with honest tradeoffs and a recommendation.
- **Tier 3 (not required):** Section 7. Forward-looking capability-layer fit. Explicitly not built now.

## 2. The reorganized metadata schema

### 2.1 Unified Node model — why, and the boundary

Today `FolderMetadata`, `FileMetadata`, and the vault root each re-implement "how do I reach my children's keys," and each mutation path special-cases folder-vs-file. The read chain is structurally identical for all three. A single `Node` with a `kind` discriminator collapses the chaining and rotation logic to one code path and directly enables the unified scope-exit rule (Section 3.8).

This is a genuine simplification, not ceremony. Confirmed duplications it removes:

- Two schemas with two codecs; `decryptFileMetadata` is keyed by the **parent** `folderKey` (`packages/core/src/file/metadata.ts:232`) while folder metadata is keyed by its own key — the asymmetry that blocks single-file sharing today.
- Root stops being a bespoke vault field: `encryptedRootFolderKey` becomes "the root Node's read key," and root is just `kind: 'root'` with no parent.
- `delete.rs`, `rename.rs`, and `executeLazyRotation` stop branching folder-vs-file.

Boundary on over-unifying: `content` is file-only, `children` is folder/root-only. In TypeScript/JSON a tagged struct is fine. In Rust (`crates/fuse`) model `kind` as a **real enum** (`enum Node { Folder { children }, File { content }, Root { children } }`), not a struct with `Option<content>` + `Option<children>`, so the unification does not leak "impossible states are representable" into the strictest consumer.

### 2.2 Two sealed bodies — the read/write separation fix

Applying review finding **B1 (blocker):** a node has **two independent sealed bodies**, not one.

- **Read-body** sealed under the node's `readKey` — carries `children[]` and, for files, `content`.
- **Write-body** sealed under a separate `writeKey` — carries the write capability material (whatever Tier-2 puts there, including any `ipnsPrivateKeyEncrypted`).

A read grant ships only the `readKey`. Because the write material is sealed under a different key the read grant never conveys, a read-only holder can never reach a signing key. The earlier single-GCM-body design was wrong: you cannot selectively strip one sub-object from a single AEAD seal, and the relay (untrusted) cannot strip what it cannot decrypt. Two bodies makes the separation structural.

Per the simplicity review, the write-body is shipped **opaque** for now: `writeBodySealed?: base64`. The internal `writeModel` discriminator is deferred to the Tier-2 PR (Section 5), since baking a four-way enum in before the decision is anticipatory.

### 2.3 Node schema (decrypted, in-memory)

```jsonc
{
  "schema": "node/v3",
  "kind": "folder" | "file" | "root",
  "id": "uuid",
  "generation": 7,              // u32, per-node read-key rotation clock

  // READ-CHAIN: sealed under THIS node's readKey
  "children": [ /* SealedChildRef[] — folder/root only */ ],

  // CONTENT: file only, sealed under THIS node's readKey
  "content": {
    "cid": "bafy...",
    "fileIv": "hex",
    "size": 12345,
    "mimeType": "application/pdf",
    "fileKey": "<32B, inside the sealed body — NOT ECIES>",
    "versions": [ /* VersionEntry[], each with its own fileKey inline */ ]
  },

  // WRITE: opaque, sealed under a SEPARATE writeKey (Tier-2 shaped)
  "writeBodySealed": "base64",   // omitted on read-only nodes

  "createdAt": 0,
  "modifiedAt": 0
}
```

### 2.4 Published object — plaintext envelope vs sealed bodies

```jsonc
{
  "schema": "node/v3",
  "kind": "folder",          // PLAINTEXT — AAD input
  "id": "uuid",              // PLAINTEXT — AAD input
  "generation": 7,           // PLAINTEXT — AAD input; lets honest readers detect "I'm behind"
  "aeadVersion": 1,          // PLAINTEXT — primitive/version tag
  "readSealed": "base64",    // AES-256-GCM(read-body, key=readKey, aad=H(domain‖id‖kind‖generation‖role=body))
  "writeSealed": "base64"    // AES-256-GCM(write-body, key=writeKey, ...) — omitted on read-only nodes
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

- `domain` prevents cross-protocol reuse.
- `nodeId` binds a sealed blob to one node — a relay cannot transplant child-keys to another node.
- `generation` binds to the current read-key epoch — a rotated-out reader's cached key fails against the new generation.
- `role` ∈ {`0x01 body`, `0x02 child-readkey`, `0x03 content`}. The load-bearing distinction is `body` vs `child-readkey` (different keys); `content` is defense-in-depth (review **A1** — keep the byte, do not over-justify).

### 2.6 SealedChildRef — the chain link

```jsonc
{
  "childId": "uuid",
  "kind": "folder" | "file",
  "name": "report.pdf",        // plaintext WITHIN the parent's sealed read-body
  "ipnsName": "k51...",        // child node's IPNS name
  "generation": 7,             // CONVERGENCE WITNESS — see 2.7; child envelope is authoritative
  "readKeySealed": "base64"    // AES-GCM(child.readKey, key=parent.readKey,
                               //   aad=domain‖childId‖child.kind‖child.generation‖role=child-readkey)
}
```

Unwrap walk (replaces the user-privkey unwrap at `crates/fuse/src/metadata.rs:428-453`):

1. Hold the parent `readKey` (from a grant, or unwrapped one level up).
2. Unseal the parent read-body with `parent.readKey` and parent AAD.
3. For each child: `child.readKey = unsealAesGcmAad(child.readKeySealed, parent.readKey, aad(childId, child.kind, child.generation, role=child-readkey))`.
4. Fetch the child node by `ipnsName`; unseal its read-body with `child.readKey`. Recurse.

The AAD in step 3 uses the **child's** id/kind/generation, so re-pointing a parent at a different child, or replaying a stale child generation, breaks the unwrap — this is what makes delete/move/rename-over genuinely cut off (Section 3.8).

### 2.7 `generation` is a single source of truth

Applying the simplicity review: `generation` is **per-node and authoritative only on the child's own published envelope**. Every other place it appears — `SealedChildRef.generation` (the parent mirror) and `shares.rootGeneration` (Section 2.8) — is a **convergence/staleness witness**, never an independent value. The rotation engine (Section 4) defines a "dirty edge" precisely as the case where the parent mirror disagrees with the child envelope; the redundancy is the crash-detection mechanism. This rule must be stated once in `METADATA_SCHEMAS.md`, not rediscovered per consumer.

`generation` (per-node read-key clock) is distinct from `keyEpoch` (TEE-pubkey rotation, write-plane). Do not conflate them.

### 2.8 The read-root grant — the only DB residue

Replaces both `share_keys` (deleted) and the fat `shares` row.

```jsonc
{
  "id": "uuid",
  "sharerId": "uuid",
  "recipientPublicKey": "secp256k1 65B",
  "rootNodeId": "uuid",
  "rootIpnsName": "k51...",
  "permission": "read" | "write",
  "rootGeneration": 7,           // convergence witness; bumped on rotate
  "readKeyEcies": "base64",      // ECIES(shareRootNode.readKey -> recipientPublicKey) — the ONE wrapped key
  "writeDescriptorRef": null,    // populated only for write grants (Tier-2)
  "revokedAt": null,
  "createdAt": 0
}
```

The recipient ECIES-unwraps `readKeyEcies` once to get the share-root `readKey`, then chains down with symmetric AES — no further ECIES, no per-item rows. Sharing any node (deep folder or single file) is uniform: `rootNodeId` is whatever node you grant.

### 2.9 File content self-seals under its own readKey (single-file-share enabler)

Today `FileMetadata` is sealed under the parent `folderKey` (`packages/core/src/file/metadata.ts:232`), so a leaf cannot be shared alone. In v3, the file node's `content` (including `content.fileKey`) seals under the file node's **own** `readKey` (role `content`). Therefore:

- A single-file read grant = ECIES-wrap that one file node's `readKey`. The recipient fetches the node by name, unseals `content`, recovers `cid`, `fileIv`, and `content.fileKey`.
- No separate ECIES-to-owner `fileKeyEncrypted`; the rename `fileKeyEncrypted → content.fileKey` is a **semantic change** (the value is no longer ECIES ciphertext), not just a rename. Each `VersionEntry` keeps its own `fileKey` inline.
- A move keeps the file's own `readKey`; only the parent's `SealedChildRef` is rewritten. This kills `spawn_file_meta_reencrypt` (`crates/fuse/src/metadata.rs:655`, called from `rename.rs:247`).

This is mandatory for single-file shares, not optional.

## 3. Flows: Big-O and IPNS-republish counts

Baseline: `N = 1e6` items in the shared subtree, `R = 10` recipients, balanced tree so depth `d = O(log N) ≈ 20`. "Republish" = one IPNS publish (one sequence bump + signature via the chosen write mechanism). The publish/sign step is held abstract; no read-chain flow depends on which Tier-2 mechanism signs — only on how many nodes republish.

### 3.1 Per-operation cost table

| Operation | Crypto | ECIES | Nodes resealed | IPNS republishes | Worst case (N=1e6, R=10) |
|---|---|---|---|---|---|
| Issue read grant | 1 wrap | 1 | 0 | 0 | 0 |
| Navigate to depth-`d` child | `d` unseals + `d` unwraps | 1 (once) | 0 | 0 | 0 |
| Add item | 1 reseal + 1 parent-link | 0 | 2 | 2 | 2 |
| Move within scope | 2 parent-link rewrites | 0 | 2 | 2 | 2 |
| Move out of scope | rotate subtree | re-mint affected grants | \|subtree\| + 2 | \|subtree\| + parents | ~1e6 + 2 |
| Rename over destination | rotate displaced dest | re-mint affected grants | \|dest-subtree\| + 1 | \|dest-subtree\| + 1 | ~1e6 + 1 |
| Delete | rotate deleted subtree | re-mint affected grants | \|subtree\| + 1 | \|subtree\| + 1 | ~1e6 + 1 |
| Read-revoke (1 of R) | rotate share-root subtree | re-mint R−1 grants | \|subtree\| | \|subtree\| | ~1e6 |
| Write-revoke (1 of R) | mechanism-dependent | — | 0 read-plane | 0 → O(subtree) | 0 (mediated) to ~1e6 (rotation) |

### 3.2 Issue a read grant — `O(1)` crypto, 1 ECIES, 0 republishes

`readKeyEcies = ECIES_wrap(shareRootNode.readKey → recipientPublicKey)`; insert one `shares` row. No node is touched. Granting a single file is identical to granting a deep folder.

### 3.3 Navigate to a deep child — `O(d)` symmetric, 1 ECIES once, 0 republishes

One-time ECIES-unwrap of the grant, then symmetric walk (Section 2.6) to depth `d`. At a file node, unseal `content` for `cid`/`fileIv`/`content.fileKey`, fetch and decrypt the IPFS blob. Verify the envelope `generation` against the grant (Section 4.6 distinguishes "behind" from "revoked").

### 3.4 Add an item — `O(1)` crypto, 0 ECIES, 2 republishes

Create the new node (fresh `readKey`, `generation = 0`, seal its bodies). Add a `SealedChildRef` to the parent, reseal the parent read-body, publish the new node then the parent. **No per-recipient fan-out** — the child key is sealed under the parent `readKey` every covering grant-holder already has. Deletes `reWrapForRecipients`/`addShareKeys` (`share.service.ts:337,469`).

### 3.5 Move within scope — `O(1)`, 0 ECIES, 2 republishes, no rotation

Remove the `SealedChildRef` from the old parent (reseal + republish); add it to the new parent (reseal + republish). The node keeps its own `readKey`/`generation`. Kills the move-reencrypt storm.

Caveat from review **m2 (per-grant scope):** "within scope" is a **per-grant** property, not a global one. A reader granted at the **old parent only** cached the moved node's `readKey`; after a move to a sibling they do not cover, "within scope for the owner" is "out of scope for that reader." Therefore: **any move that changes a node's ancestor set must rotate if any active grant sits on an ancestor that is no longer an ancestor.** Compute scope-exit per-grant; conservatively, rotate on any move whose old and new parent differ in their grant-ancestor set. A move that is genuinely within-scope for all grants (e.g., owner-only, or both parents under the same grant root) stays at 2 republishes.

### 3.6 Move out of scope, rename over destination, delete — collapse to rotate

These three are the same operation: a node's content leaves a reader's reachable scope while its CIDs persist on IPFS. Each does the link mechanics (detach/repoint, reseal + republish parent) then calls `rotateReadFromNode` over the departing subtree (Section 4). Single-file cases are 2 republishes; million-node subtrees are ~1e6.

Why rotate a **deleted** node: delete only removes the parent pointer; the CIDs remain on IPFS and a reader who cached subtree keys can still fetch by CID. Bumping `generation` + new `readKey` (and, per CRIT-1, new `fileKey` for files) makes cached keys fail against republished blobs and protects future versions.

### 3.7 Concurrency note for add-during-rotation (HIGH-4)

Applying review **HIGH-4 (data loss):** `rotateOne` re-seals the parent read-body from its in-memory `children[]`. A concurrent add that CAS-wins first will be clobbered when rotation retries from a stale decrypted child list. **Rotation must re-fetch and re-merge `SealedChildRef`s on every CAS-409, not merely re-seal the body.** Section 4.5 makes this explicit. Without it, a concurrent upload during a million-node rotation silently drops the new child.

### 3.8 The unification: one rule, four call sites

> A node leaving a reader's reachable scope ⇒ `rotateReadFromNode(node)`.

This collapses the bug class CipherBox kept patching per mutation-path (`delete.rs`, `rename.rs`, `executeLazyRotation` each special-cased). Defining rotation **recursively** structurally eliminates the `executeLazyRotation:602` single-node bug — there is no un-rotated tail because the walk is the definition. Modulo the per-grant scoping in Section 3.5.

## 4. Read-side resumable rotation

`rotateReadFromNode(nodeId)` backs read-revoke and every scope-exit mutation. It is the expensive side of the asymmetry, and the design's job is to make paying the `O(items)` cost **safe** under crashes, concurrency, and the 6-hour republisher — not to dodge it.

### 4.1 The content-key rotation fix (CRIT-1)

Applying review **CRIT-1 (critical):** re-sealing the read-body under a new `readKey` is **not sufficient** for file nodes. A revoked reader cached the old `readKey`, already unsealed `content.fileKey`, and holds the raw AES content key. If a new file version is encrypted under the same `fileKey`, the revoked reader decrypts it the moment they learn the new CID.

Therefore `rotateOne(N)` **for a file node MUST mint a new `fileKey`**, and the next content write re-encrypts under it. Until that write, the node is "rotated for the read-chain but not for content" — surfaced as a per-node `contentRekeyPending` marker. The Section 4.7 "zero new-content exposure" guarantee holds **only** with this content-key rotation; without it, read-revoke silently fails for the exact case users most expect protected (a new file version). Keep `fileKey` rotation coupled to `readKey` rotation coupled to the `generation` bump.

### 4.2 Ordering: scope-root first

The reader reaches the subtree through one door: the parent's `SealedChildRef[R].readKeySealed` plus, for grantees, the `readKeyEcies` in their `shares` row. The atomic root step:

1. `R.readKey' ← random32`; `R.generation' ← R.generation + 1`; for files, `R.fileKey' ← random32`.
2. Re-seal R's read-body under `readKey'` with AAD bound to `generation'`.
3. Rewrite R's parent's `SealedChildRef[R].readKeySealed` and mirror `.generation = generation'`.
4. Re-mint `readKeyEcies` for **every remaining recipient whose grant root is R** against `readKey'`; bump `rootGeneration`; delete the revoked recipient's row. (Descendant grant re-mint is handled in Section 4.4 — HIGH-3.)
5. Publish parent then R (entry-point latency preferred for the scope-root; interior nodes use child-first — Section 4.6).

After this one step the revoked reader is cut off from the entry point. The residual exposure window is bounded to "already-seen content under not-yet-rotated descendants," never the whole tree, and only ever shrinks as the walk proceeds. This is the precise sense of "a crash must not leave a revoked reader on the un-rotated tail."

### 4.3 Generation downgrade defense (M1)

Applying review **M1 (major):** the IPNS signature covers `value=/ipfs/CID` and `sequence` only — **not** `generation` (confirmed: the publish gate anchors the signed value strictly to `/ipfs/${metadataCid}`). The parent-mirror AAD defense works for descendants reached through a parent, but a grantee reaches the share-root **directly** via `rootIpnsName`/`rootGeneration`, both relay-served DB values. A colluding relay that simply does not apply the rotation publish (drops it, keeps serving the old signed record) leaves the revoked reader alive with no signed signal.

Fix: `generation` is a field of the metadata at the signed CID, so a generation change **is** a CID change, and the CID is signature-covered. The client must **fail-closed on generation regression across resolves**: the strict-resolve path (`resolve_sequence_strict` in `crates/fuse`) tracks the highest generation seen per node and rejects a resolve whose envelope `generation` is lower than the last verified one. Because the new CID is signed at a higher sequence, the anti-rollback gate (`ipns.service.ts:240`) already rejects the stale record for the canonical row; the client-side generation-monotonicity check closes the colluding-relay-serves-stale-to-victim path. Add a distinct domain tag if `generation` is ever folded into a signed envelope field (review **m4**), to keep AES-GCM AAD inputs and Ed25519 signing inputs from sharing un-separated bytes.

### 4.4 Multi-rooted grant re-mint (HIGH-3)

Applying review **HIGH-3 (orphaned grant):** the rotated subtree may contain nodes that were **independently shared** (e.g., a single-file share to Carol deep inside a folder being deleted). Re-minting grants only at the rotation root orphans Carol's grant — her `readKeyEcies` wraps a now-rotated key and is never re-minted, locking her out with no recovery.

Fix: rotation must **enumerate all `shares` rows whose `rootNodeId` ∈ the rotated set** and, for each non-revoked recipient, re-mint `readKeyEcies` against that node's new `readKey`/`generation` and bump its `rootGeneration`. The grant re-mint is multi-rooted because the tree is multi-rooted. This is an indexed query on `shares.rootNodeId` per rotated node (or one batched query over the rotated set).

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

### 4.6 Interaction with concurrency and the 6-hour republisher

- **Sequence races (CAS 409).** Publishing is `dbSeq + 1` forward-only CAS (`ipns.service.ts:301-317`). Rotation treats 409 as "refetch + re-apply," never failure: re-resolve, re-run `rotateOne` from current state (re-merging children). Bounded exponential backoff; the FUSE `PublishCoordinator.get_lock(name)` serializes the job against the user's own client.
- **6-hour TEE republisher is orthogonal.** It re-signs existing record bytes at `sequence + 1`; it never touches `readKey`/`generation` (`republish.service.ts:139,394`). It can only cause a 409 (handled) or keep the current generation alive. No coordination beyond CAS. This is the payoff of keeping `generation` orthogonal to `sequence`.
- **Concurrent user mutations.** A child added under a not-yet-rotated node inherits the old key; the walk rotates both on arrival (re-merge ensures it is not dropped). A child added under an already-rotated node is sealed under the new key (correct). A concurrent delete/move is itself a `rotateFromNode`; both jobs converge because every op is a forward-only function of current state.

The invariant making all of this safe: **every operation is a forward-only, idempotent, current-state function on per-node `generation` + `sequence`.** No operation decrements a generation or depends on a specific intermediate state. The AAD design makes the race windows **fail closed** (security) but **fail loud** (a legitimate reader hitting a momentary parent/child generation mismatch retries) — acceptable only because the walk converges quickly.

Honest-reader liveness (review **MED-6**): after any rotation, a still-authorized reader sees a generation bump and must re-fetch their re-minted grant; if they resolve the new root body before the API has the re-minted `readKeyEcies`, they hard-fail. Provide a "soft behind, retry" vs "hard revoked" distinction on the read path (re-minted grant present but generation ahead ⇒ retry; grant row deleted ⇒ revoked). This mirrors the documented `#489`/`#494` "Folder not loaded" desync class — reconcile `folderTree` against `sequenceNumber` before rotation publishes.

### 4.7 Exposure window and where the job runs

Read-key material is client-only (zero-knowledge). The rotation walk generates new keys and re-seals bodies, so it **must run client-side** on a client holding the share-root `readKey` (owner or write-grantee). The relay only provides IPNS CAS and IPFS storage. It cannot be offloaded to the relay/TEE — the TEE only signs (write plane) and never decrypts read content.

At 1e6 nodes the job is owner-online and resumable across sessions (persist the frontier each batch; resume via `verifySubtreeClean`). Desktop (FUSE/Tauri) is the natural host (long-lived process, `PublishCoordinator`, keys in memory). UX: the revoke is effectively complete for the revoked reader the instant the root step lands; surface "revoked" immediately and "fully rotated N/M" as background progress.

Exposure guarantee, eager: entry point window = 0; interior new-content protected as soon as its nearest-rotated-ancestor rotates (≤ walk duration), **provided CRIT-1 content-key rotation is applied**; already-published content is irreducible (IPFS). Batch parent-link rewrites — when many children of one parent rotate, publish the parent **once** per batch — the main constant-factor win at scale.

### 4.8 Eager is the committed model; lazy is deferred

Applying the simplicity review: **commit to eager rotation** (Tier-1 item 3 accepts the `O(items)` cost). The lazy "rotate-on-next-write" variant is **deferred**, not part of the core deliverable — it doubles the rotation surface and reintroduces the mixed-generation, cold-node-filename-leak surface that the unsound `executeLazyRotation` had (review **MED-5**: lazy leaks post-revocation filenames of cold subtrees, because `SealedChildRef.name` is plaintext within the sealed body; a revoked reader holding a cold node's old key reads names of items added after revocation). For a user-initiated revoke, eager is **mandatory**, not merely the default.

The genuinely useful nuance — "delete of one file shouldn't walk anything" — is just **subtree size 1**, not a separate algorithm. Keep one deferred sentence: the `generation`/`rotateOne` primitive is amortizable on-write later if the eager cost proves painful. Do not build two rotation modes now.

## 5. Write-revocation decision (Tier 2 — maintainer's call)

The read schema is invariant across all candidates (the write material is a separate sealed body, Section 2.2). This decision can be deferred without reworking the read chain. The candidates, including untested seed proposals, are evaluated on their merits.

### 5.1 Comparison

| Dimension | (a) Mediated (relay→TEE sign) | (b) Per-grant subkey | (c) Full Ed25519 rotation | (d) Hybrid: owner self-signs, delegated mediated |
|---|---|---|---|---|
| Recipient holds Ed25519 key? | No | Yes (ephemeral) | Yes (shared) | No for delegated |
| Revoke cost | O(1), no republish | O(subtree) cascade | O(subtree) cascade | O(1) for delegated |
| New k51 / stable-name break? | No | Yes | Yes | No |
| Seq race | relocated into relay | reintroduced + desync | reintroduced | not serialized under (d) — see below |
| New infra | synchronous `POST /ipns/sign` (does not exist) | none | none | the `/ipns/sign` endpoint |
| New trust | TEE + relay on write path | none cryptographic | none cryptographic | TEE + relay for delegated subset |
| Write integrity | depends on API token validation | cryptographic | cryptographic | depends on API for delegated |
| Read schema impact | zero | zero | zero | zero |

### 5.2 Ground truth

- The gap is real: `shared-write.ts:138-141,311` ECIES-wraps the raw Ed25519 key; deleting the row is cryptographically inert.
- Publish auth is key-possession only — `ipns.service.ts:226` confirms "no ownership/share check." The `existing.publicKey.equals(...)` check only ensures the **same** key keeps writing a name; it is not identity-bound. Whoever holds the key publishes.
- **No synchronous TEE sign endpoint exists.** TEE signing is batch-republish-only (`tee.service.ts:110`, driven by `republish.service.ts`). The seed's "the TEE already signs via sign-and-discard" framing is misleading for one-off writes — (a)/(d) require building a new enclave-facing endpoint, an authz-token table, and a client publish-path rewrite.
- The k51 name is bound to the Ed25519 key (`deriveIpnsName`/`publicKeyFromIpnsName`), strict-verified from the name (`publish.rs:156`). Any key rotation changes the name → parent re-point → cascade. This is what dominates (b)/(c).
- Sequence is a single per-row `dbSeq + 1` counter; every co-writer races it regardless of which key signs.

### 5.3 Recommendation: (c) full Ed25519 rotation

The security review flips the recommendation to **(c)**, and the correctness review confirms the flaw in (d). The mediated path turns the **untrusted relay into a write-forgery / confused-deputy signing oracle**:

- The TEE signs whatever record the API authorizes, with the **owner's** key. A token-validation bug, SSRF, or auth bypass forges IPNS records **under the owner's identity** for the whole delegated scope — write-integrity now depends on API correctness, which the entire system was designed not to trust.
- Scope-escalation: unless the TEE verifies the unsigned record's name/sequence/CID is within the granted subtree, a delegate with a token for node X can submit a record for node Y. Key-possession candidates (b)/(c) structurally cannot have this — you can only sign names whose key you hold.
- Hybrid (d) does **not** serialize the sequence race (review **HIGH-2**): owner self-writes (self-signed) and delegated mediated-writes contend on the same counter from two signing paths, with a TOCTOU window between "recipient reads sequence N" and "TEE signs N+1." The seed's "fixes the race" framing is false — at best it relocates and partially mitigates; under (d) it does neither.

**(c) full Ed25519 rotation** keeps write-integrity cryptographic (no signing oracle), needs no new enclave endpoint, and is strictly a subset of the read-rotation machinery already being built. Its cost is an `O(subtree)` IPNS cascade per write-revoke (the accepted asymmetry) plus a co-writer re-key. **(b) is dominated by (c)** — same k51 break and cascade, an extra ephemeral-key indirection, no compensating benefit; the "revoke one grant without disturbing others" edge is illusory because all writers to one mutable node share one IPNS identity.

Co-writer re-key (review **m1**, must be designed, not hand-waved): surviving co-writers receive the rotated Ed25519 key re-wrapped into their write-grant row (`writeDescriptorRef`). This is `O(co-writers)` write-grant rewrites, so (c)'s true cost is `O(subtree republishes) + O(co-writers re-wraps)`. A co-writer offline during rotation cannot write until they re-fetch — acceptable, but explicit.

### 5.4 Runner-up and flip conditions

Runner-up: **(a) full mediated** (all writes mediated, single signer) — **only** if the maintainer accepts TEE+relay in the write-trust base and builds a TEE that **verifies the record is within the token's authorized name/subtree** before signing. Full (a) at least genuinely serializes the sequence race (the server assigns sequences atomically), which (d) does not.

The choice flips from (c) to (a) if: the `O(subtree)` write-revoke cascade is judged unacceptable for the expected revoke frequency; AND a TEE sign-endpoint with airtight token-to-name binding can be delivered to a trustworthy standard; AND write-time coupling to TEE/relay liveness (today's 30s TEE timeout, "TEE unavailable is expected in dev") is acceptable for delegated writers. Absent all three, **(c) is the default** — it is the zero-new-infra option consistent with the system's untrusted-relay premise.

Honest residue regardless of pick: the single-counter IPNS sequence race is not solved by any candidate. Do not let "fixes the race" factor into the decision.

## 6. Blast radius, cutover ordering, and test strategy

### 6.1 Blast radius (most → least invasive)

| Layer | Change | Invasiveness |
|---|---|---|
| `packages/core` | Replace `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` + vault `encryptedRootFolderKey` with `Node`/`SealedChildRef`/`PublishedNode` + codecs | Highest (keystone) |
| `crates/fuse` | Symmetric child-key unwrap; delete `spawn_file_meta_reencrypt`; add `rotateReadFromNode`; unify scope-exit; `Node` as Rust enum | High (Rust, two clients) |
| `packages/sdk` + `sdk-core` | Read-chain navigation; rewrite `shared-write.ts`; delete `addShareKeys`/`reWrapForRecipients`; rotation driver | High |
| `apps/web` | Replace `executeLazyRotation` with `rotateReadFromNode`; drop per-mutation fan-out; reconcile `folderTree` | Medium-High |
| `apps/api` | Delete `share_keys` (entity+table+endpoints+DTOs); slim `shares`; rotation bookkeeping | Medium (mostly deletion) |
| `packages/crypto` | Add `sealAesGcmAad`/`unsealAesGcmAad` + `buildNodeAad` (TS + Rust twin + KAT) | Low (additive) |

### 6.2 Buildable cutover order

1. `packages/crypto` — `sealAesGcmAad`/`unsealAesGcmAad` + `buildNodeAad` (TS) + byte-identical Rust twin + a committed cross-language KAT fixture asserted by both. Self-contained, no consumers break.
2. `packages/core` — `Node`/`SealedChildRef`/`PublishedNode` + codecs, two sealed bodies, content self-seal. Keystone — nothing below typechecks until done.
3. `packages/sdk-core` — read-chain navigation + `rotateReadFromNode` driver (in named files, not a fat `index.ts` barrel — coverage excludes barrels). Rebuild dist before consumers.
4. `packages/sdk` — `shared-write.ts` rewrite (write-body opaque stub, Tier-2 shape TBD); delete `addShareKeys`/`reWrapForRecipients`.
5. `apps/api` — delete `share_keys`; slim `shares`; rotation bookkeeping. Run `pnpm api:generate`, commit the regenerated client (pre-commit `check-api-client.sh`).
6. `apps/web` — `executeLazyRotation` → `rotateReadFromNode`; drop per-mutation fan-out; reconcile `folderTree` against `sequenceNumber` before publishes.
7. `crates/fuse` — symmetric unwrap; delete reencrypt; unify scope-exit; strict-verify each republish; `Node` enum. Budget a Windows CI round-trip for winfsp (`windows/*` can't compile on macOS; `Cargo Check & Test (Windows)` is authoritative; watch the `super::` vs `super::super::` nesting trap).
8. Tier-2 write mechanism lands on the opaque write body (decided separately). Steps 1–7 are write-mechanism-agnostic.

Strict-verify caveat: recover the Ed25519 pubkey from the k51 name via `publicKeyFromIpnsName`, **never** from the nullable `folder_ipns.public_key` column (null for shared rows; caused two Phase-60 regressions). Each rotation republish must round-trip the verified chokepoint.

### 6.3 Test strategy (must-pass-before-merge first)

1. **Rotation crash-safety / resume (the suite that must exist before merge).** Deterministic fault-injection that aborts the walk after each node and asserts: (i) the revoked recipient can't unwrap from root after the root step; (ii) re-run converges; (iii) no incorrect double-bump. Extend `tests/sdk-e2e` (the only real client→API IPNS publish/resolve round-trip) with abort-and-resume cases.
2. **CRIT-1 content-key rotation.** Rotate a file node, publish a new version, assert a holder of the **old** `readKey`/`fileKey` cannot decrypt the new version.
3. **HIGH-3 multi-rooted re-mint.** Independently-shared single file inside a deleted/moved subtree — assert the inner grantee's `readKeyEcies` is re-minted (not orphaned), and a revoked recipient is cut.
4. **HIGH-4 add-during-rotation.** Concurrent upload during rotation — assert the new child is not dropped (re-merge on 409).
5. **M1 generation downgrade.** Simulate a relay serving a stale signed record post-rotation — assert the client fails closed on generation regression.
6. **AAD transplant resistance.** Replay a valid `readKeySealed` under a different `childId`/`role`/`generation` — assert `unsealAesGcmAad` rejects.
7. **TS↔Rust AAD KAT.** One committed fixture asserted by both `packages/crypto/__tests__` and a Rust `#[test]` — a byte mismatch is silent total decryption failure.
8. **winfsp read-path.** `gh workflow run "Cargo Check & Test (Windows)"` is authoritative.

Keep checker subagents to static analysis only (no concurrent vitest — RAM starvation).

## 7. Forward-looking capability-layer fit (Tier 3 — not required)

Bottom line: the Tier-1 core is cleanly extensible to the speculative agent-capability ideas (TTL, per-file/read-only scope, op-count caps), the extension point is the write/grant plane and never the read chain, and building any of it now would be premature. The deliverable stands on Tier 1+2 alone.

What is already delivered by Tier 1 (not future work): **per-file and read-only scope.** Single-file shares fall out of content self-sealing (Section 2.9); read-only-vs-write is the `permission` column plus the omitted write body. Nothing to add later.

What is sound to extend later, for free: the grant row is already `O(recipients)` and column-extensible — adding `ttl`/`opCap`/`capabilityId` columns is a non-breaking migration; `generation` already gives per-node revocation granularity.

What is unsound and must not be built as described: **read-side TTL/op-caps are cryptographically unenforceable.** Once a reader holds key + CID, IPFS serves the content forever; a "read expires in 1h" claim is security theater unless you re-encrypt + rotate at expiry, which is just scheduled read-revocation (the Section 4 machinery), not a cheap TTL. Time-boxing and op-caps are meaningful **only on the write path**, and only if a mediated mechanism is ever chosen.

The two cheap, non-committal hooks already in this design: the write body is opaque and sealed (one nullable field — the entire forward-compat surface), and revocation routes through `rotateReadFromNode` keyed on `generation`. Do **not** add `ttl`/`opCap`/`capabilityId` to `Node` or `SealedChildRef`, and do not name an `authzTokenId` as the hook (that pre-decides mediated writes). If a capability layer is ever built, it attaches to the write/grant plane, is unenforceable on reads, and needs nothing in the node schema. If Tier 3 is never pursued, nothing here is wasted.

## 8. Open questions for the maintainer

1. **Tier-2 write mechanism.** The recommendation is (c) full Ed25519 rotation (cryptographic write-integrity, no new infra, `O(subtree)` cascade + co-writer re-key per revoke). Accept (c), or pick full (a) mediated — which requires building a synchronous `/ipns/sign` endpoint with TEE-side token-to-name verification and accepting TEE+relay in the write-trust base and write-time liveness coupling? (Hybrid (d) is not recommended — it does not serialize the sequence race.)
2. **Terminology.** The unified read key is named `readKey` here, distinct from today's `folderKey`/`fileKey`. Adopt `readKey` and formally deprecate `folderKey`/`fileKey` in `METADATA_SCHEMAS.md` in the same PR, or rename to `nodeKey` to match the `Node` vocabulary? (Either is fine; leaving both live is terminology drift the project rules warn against.)
3. **Move-within-scope cost.** The per-grant scope-exit rule (Section 3.5) means some "within-scope" moves still rotate if a grant sits on a no-longer-ancestor. Accept the conservative "rotate on any ancestor-set change" default, or invest in exact per-grant scope computation to avoid unnecessary rotations?
4. **Co-writer offline handling.** Under (c), a co-writer offline during a write-key rotation cannot write until they re-fetch the re-wrapped key. Acceptable, or is a grace/notification mechanism wanted?
5. **Rotation host.** Eager million-node rotation is owner-online and resumable; desktop (FUSE) is the natural host. Is it acceptable that a pure-web user without the desktop app pays a long, chunked, multi-session rotation for a large revoke?
6. **Write-recipient deletions vs owner-held sub-shares.** When a write-recipient (C) deletes, moves out, or overwrites a node inside a shared folder that the OWNER had *independently* sub-shared to a third party (e.g. a single file shared to D), C can unlink it immediately (C holds the folder's write keys and signs the folder publish) but CANNOT cryptographically revoke D's grant — only the owner holds that node's rotation keys and authority over the `shares` rows. So the unlink and the revocation are split across two principals. Options: (a) leave the sub-share dangling until the owner's next sync runs a reconciliation/rotation pass — bounded exposure window in which D retains read access to the now-binned snapshot (already irreducibly readable via IPFS, so arguably acceptable); (b) block a write-recipient from destroying a node that carries owner-owned sub-shares — but that requires the relay to tell the writer "this node has active grants," leaking share existence to a delegate; (c) have C's mutation enqueue an owner-signed revocation request that the owner (or the owner's desktop/TEE-mediated agent) executes on next online. Decide the authority model and the acceptable exposure window. (Surfaced from the FS-permutations walkthrough — flow `write-recipient-c-delete-file1`.)