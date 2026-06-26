# Sharing Redesign — End-to-End Flow Walkthrough

A step-by-step trace of data and keys through every layer, under the **new read
key-chaining design**, for six flows. Where infrastructure carries over unchanged
from today it is marked _(existing)_; where the new schema changes behaviour it is
marked _(new)_.

## Conventions

### Layers

- **CLIENT** — web app / `@cipherbox/sdk` / `@cipherbox/sdk-core` / `@cipherbox/crypto` (all crypto is here; zero-knowledge).
- **API** — `apps/api` NestJS relay (JWT-guarded; stores only ciphertext + bookkeeping).
- **DB** — Postgres (`vaults`, `folder_ipns`, `shares`, `pinned_cids`, `ipns_republish_schedule`).
- **IPFS** — Kubo; content-addressed encrypted blobs.
- **IPNS** — mutable name → CID records; client-signed; server enforces sequence/anti-rollback.
- **TEE** — Phala enclave; 6-hourly re-sign of enrolled IPNS records (batch only).

### Key model recap (new)

Each **Node** (`kind: folder | file | root`) owns three independent secrets:

| Secret | Type | Role | Recovery |
| --- | --- | --- | --- |
| `readKey` | 32B AES | seals the node's **read-body** (children refs / file content) | chained from parent `readKey`; root's is ECIES-wrapped to owner in the recovery blob |
| `writeKey` | 32B AES | seals the node's **write-body** (the Ed25519 key + write-chain links) | chained from parent `writeKey`; root's is ECIES-wrapped to owner |
| Ed25519 keypair | sign | the IPNS identity (`ipnsName = deriveIpnsName(pub)`); signs records | root's is HKDF-derived from the user key; others are random, recovered via the write chain |

- **Read chain:** a `SealedChildRef` carries `readKeySealed = AES-GCM(child.readKey, parent.readKey, AAD)`. Hold a node's `readKey` ⇒ unwrap every descendant `readKey` with symmetric AES, no ECIES per item.
- **Write chain (the Tier-2 (c) instantiation of the opaque write-body):** the write-body carries the node's `ed25519PrivateKey` plus, per child, `writeKeySealed = AES-GCM(child.writeKey, parent.writeKey)`. Hold a node's `writeKey` ⇒ reach every descendant Ed25519 signing key. A **read-only** grant ships only `readKey`, so the write-body is unreachable — read/write separation is structural.
- `generation` (u32, per node) bumps **only** on a read-key rotation (revocation); it is the AAD epoch + the rotation convergence witness. It is distinct from the IPNS `sequenceNumber`, which bumps on every publish.

> Tier-2 note: flows 5–6 assume the recommended **(c) full Ed25519 rotation** write model — write delegates hold the real signing keys; revocation rotates them. Under the alternative **(a) mediated writes**, the write-body would hold no keys and writes would route through a (not-yet-built) TEE signing endpoint; the read-side flows (1–4) are identical either way.

### Crypto primitives (real, `@cipherbox/crypto`)

`generateRandomBytes`/`generateFileKey` (32B), `generateIv` (12B GCM), `generateEd25519Keypair`, `deriveIpnsName(pub)`/`publicKeyFromIpnsName`, `wrapKey`/`unwrapKey` (ECIES secp256k1), `encryptAesGcm`/`decryptAesGcm` (content), and the **new** `sealAesGcmAad`/`unsealAesGcmAad` (replacing `sealAesGcm`, which has no AAD today). AAD = `"cipherbox/node-seal/v1" ‖ nodeId ‖ kind ‖ generation ‖ role`.

---

## Flow 1 — User A initializes a new vault

Goal: stand up the root Node and register the vault. A is authenticated (JWT; holds secp256k1 `userPrivateKey`/`publicKey`).

1. **CLIENT** — generate root secrets: `rootReadKey = generateRandomBytes(32)`, `rootWriteKey = generateRandomBytes(32)`. Derive the root IPNS identity deterministically: `rootIpns = deriveVaultIpnsKeypair(userPrivateKey)` (HKDF; recoverable, no storage) ⇒ `rootIpnsName`.
2. **CLIENT** — build the **recovery blob**: `ECIES(rootReadKey → userPublicKey)` + `ECIES(rootWriteKey → userPublicKey)` (so A can recover both from `userPrivateKey`). This is the v2 vault-key blob, published under a separate HKDF-derived `vaultKeyIpnsName` _(existing mechanism, new contents)_.
3. **CLIENT** — build the root Node `{ schema:"node/v3", kind:"root", id, generation:0 }`. Read-body `= sealAesGcmAad({children:[]}, rootReadKey, aad(id,root,0,body))`. No write-body yet (no delegates; A signs with the derived root Ed25519 key). Serialize the `PublishedNode` envelope `{ kind, id, generation:0, aeadVersion:1, readSealed }`.
4. **API/IPFS** — `POST /ipfs/upload` the recovery blob and the root metadata envelope → two CIDs, pinned. `DB: pinned_cids += {A, cid}` for each.
5. **CLIENT** — sign IPNS records: `createIpnsRecord(rootIpns.priv, "/ipfs/<rootMetaCid>", seq=1n)` and the same for the vault-key blob. Also compute `encryptedIpnsPrivateKey = ECIES(rootIpns.priv → teePublicKey)` + `keyEpoch` for TEE republish.
6. **API** — `POST /ipns/publish { ipnsName:rootIpnsName, record, publicKey, metadataCid, encryptedIpnsPrivateKey, keyEpoch }` (and one for the vault-key name). Server verifies the signature, enforces first-publish `sequence==1`. `DB: folder_ipns += {A, rootIpnsName, latestCid, seq=1, encryptedIpnsPrivateKey, keyEpoch}`. Because `encryptedIpnsPrivateKey` is present and ownership matches, it auto-enrolls TEE: `DB: ipns_republish_schedule += {A, rootIpnsName, nextRepublishAt=+6h}`.
7. **API** — `POST /vault/init { ownerPublicKey, rootIpnsName }`. `DB: vaults += {owner_id:A, owner_public_key, root_ipns_name}`; marks `folder_ipns.isRoot=true`.
8. **TEE** — from now re-signs `rootIpnsName` every 6h.

State after: A holds `userPrivateKey` (recovers everything) → `rootReadKey`, `rootWriteKey` (recovery blob), root Ed25519 (derived). One empty root Node on IPFS/IPNS. No shares.

---

## Flow 2 — User A creates sub-folder "Folder A" in root

1. **CLIENT** — generate Folder A secrets: `fa.readKey`, `fa.writeKey` (random 32B), `fa.ed25519 = generateEd25519Keypair()`, `fa.ipnsName = deriveIpnsName(fa.ed25519.pub)`, `generation:0`.
2. **CLIENT** — build Folder A Node: read-body `= sealAesGcmAad({children:[]}, fa.readKey, aad(faId,folder,0,body))`; write-body `= sealAesGcmAad({ ed25519PrivateKey: fa.ed25519.priv, childLinks:[] }, fa.writeKey, aad(faId,folder,0,write))`. Upload envelope → `faMetaCid` _(API/IPFS, pinned)_.
3. **CLIENT** — link Folder A into root. A already holds `rootReadKey`/`rootWriteKey`. Build the child ref:
   - `readKeySealed = sealAesGcmAad(fa.readKey, rootReadKey, aad(faId,folder,0,child-readkey))`
   - `writeKeySealed = sealAesGcmAad(fa.writeKey, rootWriteKey, aad(faId,folder,0,child-writekey))`
   - `SealedChildRef = { childId:faId, kind:"folder", name:"Folder A", ipnsName:fa.ipnsName, generation:0, readKeySealed }` (the `writeKeySealed` goes in root's write-body child-links).
4. **CLIENT** — re-seal root's read-body and write-body with the updated child list (same `rootReadKey`/`rootWriteKey`, fresh IV, `generation` unchanged at 0 — this is an add, not a rotation). Upload new root envelope → `rootMetaCid'` _(pinned; old root CID now unreferenced)_.
5. **API/IPNS** — publish **child before parent**: `POST /ipns/publish` for `fa.ipnsName` (seq 1, with `encryptedIpnsPrivateKey`/`keyEpoch` ⇒ TEE-enroll Folder A), then for `rootIpnsName` (seq 2, `expectedSequenceNumber:1` CAS). `DB: folder_ipns += fa row (seq1)`, `root → seq2`; `ipns_republish_schedule += fa`.

State after: root now has one child (`generation` still 0, so its ref to itself in nobody changes). Folder A is an empty folder Node, TEE-enrolled. A reaches `fa.readKey`/`fa.writeKey`/`fa.ed25519` by chaining from the root keys.

---

## Flow 3 — User A uploads 5 files to Folder A

Per file `i` (1..5):

1. **CLIENT** — `fileKey = generateFileKey()`, `iv = generateIv()`; `ciphertext = encryptAesGcm(plaintext, fileKey, iv)`.
2. **API/IPFS** — `POST /ipfs/upload` ciphertext → `contentCid_i`, pinned. `DB: pinned_cids += {A, contentCid_i, size}` (quota-checked).
3. **CLIENT** — generate file Node secrets `fi.readKey`, `fi.writeKey`, `fi.ed25519`, `fi.ipnsName`, `generation:0`. Read-body content `= { cid:contentCid_i, fileIv:iv, size, mimeType, fileKey, versions:[] }` sealed under `fi.readKey` (role `content`); write-body `= { ed25519PrivateKey: fi.ed25519.priv }` under `fi.writeKey`. **Note:** `fileKey` lives _inside_ the file node's own read-body (sealed under `fi.readKey`), not ECIES-wrapped to the owner — this is what makes a single file shareable on its own. Upload envelope → `fiMetaCid` _(pinned)_.
4. **CLIENT** — build `SealedChildRef` for file `i` into Folder A (`readKeySealed` under `fa.readKey`; `writeKeySealed` under `fa.writeKey`; `generation:0`).

After all 5:

5. **CLIENT** — re-seal Folder A's read-body + write-body with the 5 new children (same `fa.readKey`/`fa.writeKey`, `generation` still 0). Upload new Folder A envelope → `faMetaCid'` _(pinned)_.
6. **API/IPNS** — `POST /ipns/publish-batch`: 5 file records (seq 1 each, TEE-enroll each) + Folder A (seq 2, CAS `expected:1`). `DB: folder_ipns += 5 file rows`, `fa → seq2`; `ipns_republish_schedule += 5 files`.

State after: 5 file Nodes under Folder A. **Root is untouched** — Folder A's `ipnsName` and `generation` (0) are unchanged, so root's `SealedChildRef[FolderA].generation==0` still matches Folder A's envelope. Writes localize to the subtree.

---

## Flow 4 — User A shares Folder A with User B (read-only)

The payoff flow: one wrapped key, no `share_keys` fan-out, no republish.

1. **CLIENT (A)** — A holds `fa.readKey` (chained from root). Compute the single grant: `readKeyEcies = wrapKey(fa.readKey, B_publicKey)` (ECIES). **No** write material, **no** per-child keys.
2. **API** — `POST /shares { recipientPublicKey:B, rootNodeId:faId, rootIpnsName:fa.ipnsName, permission:"read", readKeyEcies }` _(new grant shape; `share_keys` table removed)_.
3. **DB** — `shares += { sharerId:A, recipientPublicKey:B, rootNodeId:faId, rootIpnsName, permission:"read", rootGeneration:0, readKeyEcies, writeDescriptorRef:null, revokedAt:null }`. Nothing else changes — no IPFS, no IPNS, no TEE.

B's read path (later):

4. **CLIENT (B)** — `GET /shares` → `readKeyEcies`; `fa.readKey = unwrapKey(readKeyEcies, B_privateKey)` (one ECIES). Resolve `fa.ipnsName` → Folder A envelope → `unsealAesGcmAad(readSealed, fa.readKey, aad)` → children refs. For each child: `child.readKey = unsealAesGcmAad(child.readKeySealed, fa.readKey, aad(childId,kind,gen,child-readkey))` → resolve child `ipnsName` → unseal → for files, recover `content.fileKey` + `contentCid` → fetch → `decryptAesGcm`. B chains the whole subtree with symmetric AES.

B never receives any `writeKey`, write-body, or Ed25519 key. Read-only is enforced by what was wrapped, not by a server flag.

---

## Flow 5 — User A shares Folder A with User C (read/write)

Same read grant as B, **plus** the write chain root.

1. **CLIENT (A)** — `readKeyEcies = wrapKey(fa.readKey, C_publicKey)` and `writeKeyEcies = wrapKey(fa.writeKey, C_publicKey)`. The `writeKey` is the root of Folder A's write chain: with it C can unseal Folder A's write-body (→ Folder A's Ed25519 key + each child's `writeKeySealed`) and recurse to every file's Ed25519 signing key.
2. **API** — `POST /shares { recipientPublicKey:C, rootNodeId:faId, rootIpnsName:fa.ipnsName, permission:"write", readKeyEcies, writeDescriptorRef:<writeKeyEcies> }`.
3. **DB** — `shares += { …, permission:"write", readKeyEcies, writeDescriptorRef }`. Again no IPFS/IPNS/TEE change at share time.

Tier-2 (c) consequence: C now **holds** the Ed25519 signing keys for Folder A and its files (reachable via `fa.writeKey`). Revoking C's _write_ later means **rotating those Ed25519 keypairs** (new k51 → rewrite parent pointer → republish) — the `O(subtree)` write-revoke cascade. (Under (a) mediated, C would instead hold a capability token and the keys would never leave the owner/TEE; revoke = kill the token.)

---

## Flow 6 — User C edits the contents of a file in Folder A

C edits `file3`. C may be on web or desktop (FUSE); the key/data flow is identical — only the trigger differs.

1. **CLIENT (C)** — derive the keys by chaining from the grant:
   - Read: `fa.readKey = unwrapKey(readKeyEcies, C_priv)` → Folder A read-body → `file3.readKeySealed` → `file3.readKey`.
   - Write: `fa.writeKey = unwrapKey(writeDescriptorRef, C_priv)` → Folder A write-body → `file3.writeKeySealed` → `file3.writeKey` → file3 write-body → `file3.ed25519.priv`.
2. **CLIENT (C)** — read current content: resolve `file3.ipnsName` → file3 read-body → `{ contentCid, fileIv, fileKey }` → fetch `contentCid` → `decryptAesGcm`. C edits the plaintext.
3. **CLIENT (C)** — encrypt the new version: `newFileKey = generateFileKey()`, `newIv = generateIv()`, `ciphertext' = encryptAesGcm(newPlaintext, newFileKey, newIv)` (fresh key+IV per version; the previous version is retained in `content.versions[]`).
4. **API/IPFS** — `POST /ipfs/upload` ciphertext' → `newContentCid`, pinned **under C's userId**. `DB: pinned_cids += {C, newContentCid}` (counts against C's quota — a delegated-write nuance).
5. **CLIENT (C)** — rebuild file3 content `{ cid:newContentCid, fileIv:newIv, size', fileKey:newFileKey, versions:[…old…] }`, re-seal file3 read-body under the **same** `file3.readKey`, `generation` **unchanged** (an edit is not a revocation). Upload new file3 envelope → `file3MetaCid'` _(pinned)_.
6. **CLIENT (C)** — sign the IPNS update: `createIpnsRecord(file3.ed25519.priv, "/ipfs/<file3MetaCid'>", seq=2n)`.
7. **API** — `POST /ipns/publish { ipnsName:file3.ipnsName, record, metadataCid:file3MetaCid', expectedSequenceNumber:1 }`. Server **verifies the Ed25519 signature** (valid — C holds the correct file3 key) → key-possession authz passes (`ipns.service.ts:226` does no share/ownership check). Sequence gate: `dbSeq 1 → 2` forward, CAS matches. `DB: folder_ipns[file3] → { latestCid:file3MetaCid', seq:2, signedRecord }`.
8. **Folder A is NOT touched.** file3's `ipnsName` and `generation` are unchanged, so Folder A's `SealedChildRef[file3]` (generation 0, same name) stays valid. The edit localizes to file3's own record.

Two real subtleties to design through (flagged, not hand-waved):

- **TEE republish sync on delegated write.** file3 was TEE-enrolled by **A** (`ipns_republish_schedule.userId = A`). C's publish updates the canonical `folder_ipns` row but the enroll-update path is ownership-guarded (`existing.userId == userId`), so a naive implementation leaves the schedule pointing at the **old** CID — the 6-hourly re-sign would regress file3 to stale content. The redesign must make the republish schedule follow the canonical `folder_ipns.latestCid` regardless of which authorized writer published (this is the same `folderTree`/sequence-desync class the project already tracks).
- **Pin ownership / quota.** The new content pins under C, the old version stays pinned under A until version pruning. Garbage-collection and quota accounting across a shared writer need an explicit policy.

---

## Flow 7 — User A revokes User B's read access to Folder A

The **read-key rotation walk** (design §4) — the expensive, irreducible side of the asymmetry. Read-revoke keeps every IPNS k51 name **unchanged**; it rotates the symmetric `readKey` (and each file's `fileKey`) of every node in B's scope and re-seals the chain.

Why deleting B's grant row is not enough: B cached `fa.readKey` and, via the chain, every descendant `readKey` and `fileKey`. Removing the `shares` row is cryptographically inert — B keeps resolving the (unchanged) k51 names and decrypting with cached keys. The unsound `executeLazyRotation` rotated only the share-root and is exactly this bug.

Ordering: **scope-root first**, then walk down, so B is cut at the entry point even if the tail lags.

1. **CLIENT (A)** — start a resumable job `{ jobId, rootNodeId:faId, reason:"revoke", revokedRecipient:B, frontier:[], done:[] }` (persisted locally — advisory; the published IPNS records are the source of truth).
2. **CLIENT (A) — root step (Folder A):**
   - `fa.readKey' = generateRandomBytes(32)`; `fa.generation: 0 → 1`.
   - Re-seal Folder A's read-body under `fa.readKey'` with `aad(faId,folder,1,body)`. The child refs inside are re-wrapped under `fa.readKey'` (each child's *own* readKey hasn't rotated yet — that happens when the walk reaches it).
   - Rewrite **root's** `SealedChildRef[FolderA]`: `readKeySealed = sealAesGcmAad(fa.readKey', rootReadKey, aad(faId,folder,1,child-readkey))`, mirror `.generation = 1`.
   - **Re-mint remaining readers:** C keeps read, so `C.readKeyEcies' = wrapKey(fa.readKey', C_pub)`; update C's `shares` row, bump `rootGeneration → 1`. **Delete B's `shares` row.**
   - **API/IPNS:** publish Folder A (new envelope, `seq+1`) and root (updated child-ref, `seq+1`, CAS).
   - After this step B is cut from Folder A's listing: B resolves `fa.ipnsName` (unchanged) → the new envelope, which B's cached old `fa.readKey` cannot unseal (**M1:** the client also fails closed on a `generation` regression, so a colluding relay can't serve B the stale envelope). Residual: B can still directly read already-known children with cached child keys until the walk rotates them — a strictly shrinking window.
3. **CLIENT (A) — walk each child (the 5 files), `rotateOne`:**
   - `fi.readKey' = random`; `fi.generation: 0 → 1`.
   - **CRIT-1:** also mint `fi.fileKey' = random` and set `contentRekeyPending`. Existing content stays under the old `fileKey`/CID (legit readers still read it); the **next** content write re-encrypts under `fileKey'`, so a revoked reader who cached the old `fileKey` can't read future versions even if a new CID leaks via a side channel.
   - Re-seal fi's read-body under `fi.readKey'`; rewrite Folder A's `SealedChildRef[fi].readKeySealed` under `fa.readKey'` + `.generation = 1`.
   - **HIGH-3:** if any descendant has its own independent grant (e.g. a single file separately shared to a third party), re-mint that grant against the new key — or it is orphaned. (None in this scenario.)
   - **HIGH-4:** if C concurrently uploads into Folder A mid-walk, the publish CAS-409s; re-fetch and **re-merge** the child list before re-sealing so the new upload isn't clobbered.
   - **API/IPNS:** publish each file (`seq+1`); batch the Folder A parent-link rewrites into one Folder A publish.
4. **CLIENT (A) — finalize:** `verifySubtreeClean(FolderA)` — an O(items) read pass asserting every `parent.link.generation == child.envelope.generation`; zero dirty edges ⇒ done. If A crashed mid-walk, re-running converges (re-rotating an already-done node only strengthens the cut and costs one republish).

State delta:

- **DB:** `folder_ipns` — Folder A + 5 files bumped (`seq+1`, new `latestCid`); `shares` — **B deleted**, C updated (`readKeyEcies'`, `rootGeneration:1`). `pinned_cids += 6` new metadata CIDs.
- **IPNS / k51 names: UNCHANGED.** Read-revoke never touches Ed25519 keys. **TEE:** enrollments untouched (same names; the 6h re-sign just picks up the new CIDs).
- **Cost:** O(items) republishes — **6** here, ~1e6 for a million-node subtree. Already-published content CIDs stay fetchable from IPFS forever (irreducible).

---

## Flow 8 — User A revokes User C's *write* access (downgrade to read-only)

The **Tier-2 (c) Ed25519 rotation cascade** (design §5.3) — and the honest cost of choosing (c): write-revoke is **not** cheap.

Why deleting C's grant is not enough: C cached the **Ed25519 signing keys** for Folder A and its files (via the write chain). The relay authorizes publishes by key-possession (`ipns.service.ts:226` — no share check) and the TEE keeps republishing, so C can keep writing to those k51 names indefinitely. The only cryptographic cut is to **rotate the Ed25519 keypairs**, which changes the k51 names and forces a parent-pointer rewrite up to the share root.

1. **CLIENT (A) — per node in C's write scope (Folder A + 5 files):**
   - `node.ed25519' = generateEd25519Keypair()` → `node.ipnsName' = deriveIpnsName(node.ed25519'.pub)` — **the k51 name changes**.
   - `node.writeKey' = random`; re-seal the node's write-body (now holding `ed25519'.priv`) under `writeKey'`; re-mint the write-chain links. Read side untouched (C keeps read), so `readKey`/`fileKey`/content are unchanged.
2. **CLIENT (A) — parent-pointer cascade (the expensive part):** because each child's `ipnsName` changed, every parent's `SealedChildRef.ipnsName` must be updated and the parent's read-body re-sealed (under the *same* `readKey` — read unchanged). Folder A's refs to the 5 files get the new names; **root's** ref to Folder A gets `fa.ipnsName'`. The cascade runs **leaves → up to root**.
3. **CLIENT (A) — publish under the new names, abandon the old:**
   - Each node publishes under its **new** k51 (`seq=1`, fresh name) with a new `encryptedIpnsPrivateKey`/`keyEpoch` ⇒ **TEE-enroll the new names**.
   - **`POST /ipns/unenroll`** the old k51 names ⇒ TEE stops republishing them; the old names go dark (C's cached keys now sign records nobody resolves).
   - Order children-before-parent; CAS + the FUSE `PublishCoordinator` lock serialize against concurrent writers (the sequence-race / `folderTree`-desync surface).
4. **CLIENT (A) — update grants (a consequence of the share-root name change):** rotating Folder A's Ed25519 changed `fa.ipnsName`, which is the **entry point** recorded in every grant on that node. So update **both** B's and C's `shares.rootIpnsName → fa.ipnsName'`. Downgrade C: `permission:"read"`, `writeDescriptorRef:null` (C keeps `readKeyEcies`). Re-mint any remaining **writer** grants against `fa.writeKey'` (none besides A here).

State delta:

- **DB:** `folder_ipns` — **6 new rows** (new k51, `seq=1`) + 6 old rows abandoned; `ipns_republish_schedule` — 6 enrolled, 6 unenrolled; `shares` — C downgraded + both grants' `rootIpnsName` updated. `pinned_cids += 6` new metadata CIDs. **Content CIDs unchanged** (no re-encryption — read access preserved).
- **Cost:** O(subtree) republishes + the parent-pointer cascade to root + TEE re-enroll/unenroll + grant updates. A co-writer offline during the rotation can't publish until they re-fetch the rotated keys.

Full revoke of C (read **and** write) = compose Flow 8 (Ed25519 / name rotation) **with** Flow 7 (readKey / fileKey rotation) in one walk per node, and **delete** C's grant entirely.

Decision teeth: under **(c)**, write-revoke is an O(subtree) cascade and — because of the k51 name change + TEE re-enroll + grant-entry updates — is arguably *heavier per node* than read-revoke. The "instant, O(1) write-revoke" only exists under Tier-2 **(a) mediated writes** (kill the capability token; the keys were never C's). Seeing the (c) cascade laid out is itself a useful input to the Tier-2 decision.

---

## Keys-at-rest summary

| Holder | Has | Reaches |
| --- | --- | --- |
| A (owner) | `userPrivateKey` | root `readKey`+`writeKey` (recovery blob), root Ed25519 (derived) → entire tree (read + write) by chaining |
| B (read-only) | `B_privateKey` + `readKeyEcies(fa.readKey)` | Folder A subtree **read** only; no write-body, no Ed25519 key |
| C (read/write) | `C_privateKey` + `readKeyEcies` + `writeKeyEcies` | Folder A subtree read **and** write (the Ed25519 signing keys via the write chain) |
| Relay/API | ciphertext + bookkeeping rows | nothing in plaintext |
| TEE | per-node `ECIES(ed25519.priv → teePublicKey)` | signs enrolled records in-enclave; never exposes the key |

## What changed vs today

- `FolderMetadata`/`FileMetadata` (child keys ECIES-wrapped to owner, per child) → unified **Node** with a symmetric **read chain**; sharing collapses from an `O(items×recipients)` `share_keys` fan-out to **one** ECIES-wrapped root key.
- `FileMetadata` sealed under the parent folderKey → file content self-sealed under the file's own `readKey` (enables single-file shares; kills `spawn_file_meta_reencrypt` on move).
- Write delegation via raw un-rotatable key handed inline → **write chain** + Tier-2 (c) rotation-on-revoke (or (a) mediated).
- Unchanged infra: `/vault/init`, `/ipfs/upload`, `/ipns/publish(-batch)` + the sequence/anti-rollback/CAS gate, TEE 6h republish enrollment, client-side signing.
