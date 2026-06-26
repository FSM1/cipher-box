---
status: accepted
date: 2026-06-26
---

# Read-revocation protects future writes and navigation, not already-distributed content

Content is encrypted client-side and stored content-addressed on IPFS. Once a reader has held a node's `readKey` and seen a content CID, any IPFS node serves that ciphertext indefinitely, and the reader may already hold the plaintext. We therefore define read-revocation to rotate `readKey` + `generation` (and mint a fresh `fileKey` for files, applied lazily on the next content write — the `contentRekeyPending` marker), which cuts the revoked party's navigation (chaining from the parent), filename visibility, and access to future versions — but we do **not** eagerly re-encrypt already-published content, and we do not touch prior versions. The threat-model stance is explicit: a shared ciphertext is presumed leaked; the control is who you share with, not after-the-fact rotation.

## Why

Eagerly re-encrypting an entire subtree on every revoke is brutal at scale and, for already-distributed CIDs, usually theatre — the revoked reader may already have the bytes. Lazy content re-keying with honest semantics is the only coherent stance for content-addressed storage.

## Consequences

Granting read on a folder hands over the full version history of every file in it (each `VersionEntry` carries its own inline `fileKey`). Revoke and share UX must state plainly that content already shared may remain readable, and that revocation stops future changes and removes access to new versions. For high-sensitivity cases, offer an opt-in per-file "re-encrypt now" and an O(versions) "purge history" operation. The design's "eager rotation" (§4.8) therefore means an eager cut of navigation and future writes, not eager content protection — wording corrected in the design amendments.
