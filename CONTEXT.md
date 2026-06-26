# CipherBox

A zero-knowledge encrypted IPFS/IPNS vault. The server is an untrusted relay that never sees plaintext or any unwrapped key. This glossary pins the vocabulary for the metadata, key-chaining, and sharing model (the `node/v3` design). It complements — does not replace — the terminology table in `CLAUDE.md`.

## Keys

**readKey**:
A per-node 32-byte AES key that seals a node's read-body (its children and, for a file, its content). Chained parent-to-child: a parent seals each child's `readKey` under its own. Holding a node's `readKey` unwraps its whole subtree with symmetric AES.
_Avoid_: folderKey, fileKey, rootFolderKey, nodeKey

**writeKey**:
A per-node 32-byte AES key that seals a node's write-body (the Ed25519 signing material). A read grant never conveys it, so a read-only holder can never reach a signing key.
_Avoid_: (none)

## Counters

Three distinct clocks; never conflate them.

**generation**:
A per-node `u32` that bumps only on a read-key rotation (revocation / scope exit). It is the AAD epoch and the rotation convergence witness; authoritative only on the child's own published envelope.
_Avoid_: epoch, version (for this concept)

**keyEpoch**:
The TEE public-key rotation counter (write-plane). Unrelated to read-key rotation.
_Avoid_: generation, bare "epoch"

**sequenceNumber**:
The IPNS record counter that bumps on every publish; enforced forward-only by the relay's CAS gate.
_Avoid_: generation, "seq" in prose

## Metadata model

**Node**:
The single metadata object for a folder, file, or vault root, discriminated by `kind`. Carries an independently sealed read-body and write-body.
_Avoid_: FolderMetadata, FileMetadata, FilePointer, FolderEntry (all v2-legacy, retired)

**SealedChildRef**:
A parent's link to one child, living inside the parent's read-body: the child's name, `ipnsName`, `generation` mirror, and the child's `readKey` sealed under the parent's `readKey`.
_Avoid_: FolderChild, FolderEntry

**ipnsRecord**:
The signed IPNS data structure (name to CID, sequence, signature) and the row that stores it.
_Avoid_: "IPNS entry"; the table is `ipns_records`, not `folder_ipns`

## Sharing

**grant**:
One row in the `shares` table conveying read or write access to a share-root node — the wrapped key(s) for a single recipient. The only data-plane DB residue of a share.
_Avoid_: ShareGrant (type name), share_keys (the deleted per-item table)

**readDescriptorRef / writeDescriptorRef**:
The ECIES-wrapped `readKey` / `writeKey` on a grant row, sealed to the recipient's secp256k1 public key.
_Avoid_: readKeyEcies, encryptedKey

**scope exit**:
The condition where a node leaves the reachable scope of an active grantee. The only trigger for a read-key rotation; a node with no covering grant rotates never.
_Avoid_: (none)

**bin**:
The owner's recoverable-delete space. A deleted node is re-linked into it as a `BinEntry` sealed under the bin's own `readKey`, rather than purged.
_Avoid_: trash, recycle bin (in code identifiers)

**invite**:
A claimable share to an as-yet-unknown recipient: the share-root `readKey` wrapped to an ephemeral key whose private half travels in the link, re-wrapped to the claimer's key on claim.
_Avoid_: "link share" (in code identifiers — use invite)
