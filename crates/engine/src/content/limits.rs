//! Shared content-plane size limits.

use cipherbox_core::suite::ed25519::SIGNATURE_LEN as ED_SIG_LEN;

use super::chunk::SEALED_LEAF_OVERHEAD;
use super::profile::ContentProfile;

/// Hard ceiling on a resolved content block, the single source of truth for both
/// the decode side ([`super::read::read_block`], which rejects any fetched block
/// over this before it is hashed, decoded, or gated — gate work is linear in the
/// fetched byte count) and the encode side ([`super::dag::assemble`], which fails
/// closed rather than emit a root manifest over this cap; and the reassembly
/// buffer's preallocation budget). A resolved record's
/// envelope-content rides in an IPFS block fetched by CID; capping it here bounds
/// gate work to a fixed budget and fails closed on anything larger
/// (blueprint/engine.md "Content plane").
///
/// The value is core's [`MAX_BLOCK_BYTES`](cipherbox_core::seal::MAX_BLOCK_BYTES)
/// — the IPFS single-block ceiling, since `block/put` refuses anything over
/// 2 MiB (blueprint/api.md), so a larger record is authorable but unpinnable,
/// signed by this engine and then refused by its own ingress. Aliased rather
/// than restated: core's frozen `MAX_WRITE_BODY_BYTES` reserves its re-seal
/// headroom under the same number, and two copies drift.
///
/// Must exceed the 1 MiB sealed leaf, which [`ContentProfile::new`] enforces
/// for every injected profile. A legitimate flat-DAG root inlines every
/// leaf CID, so it fits only up to the flat-DAG ceiling (~54 GiB at a 1 MiB chunk
/// size); `assemble` enforces that ceiling as a release-active `Err`, so this
/// crate never publishes a root its own `read_block` rejects (the encode/decode
/// fail-closed symmetry of AGENTS.md rule 8).
pub(crate) const MAX_RESOLVED_RECORD_BYTES: usize = cipherbox_core::seal::MAX_BLOCK_BYTES;

/// One signed grant blob's det-CBOR wire cost: a 32-byte tag, a 32-byte HPKE
/// `enc`, the sealed [`GrantBlobPayload`](cipherbox_core::seal::GrantBlobPayload)
/// (three secrets, an epoch, and the AEAD tag), a 64-byte structure signature,
/// and the map framing around them.
const GRANT_BLOB_WIRE_BYTES: usize = 384;

/// One grant-ledger row: two public keys, a permission, a blinded tag, the
/// owner's compact ECDSA signature, an optional deadline, and framing.
const LEDGER_ROW_WIRE_BYTES: usize = 224;

/// One `directChildScopeIndex` entry: a 16-byte scope id and an `ipnsName`.
const CHILD_SCOPE_REF_WIRE_BYTES: usize = 128;

/// One retained history link: the sealed prev-epoch seed and a 64-byte
/// structure signature.
const HISTORY_LINK_WIRE_BYTES: usize = 256;

/// The widest `sealed` blob a re-seal retains on a history link.
///
/// A link this engine mints is a fixed-width seal of a fixed-width payload, so
/// this bound never drops one. The carried set is attacker-influenced, though —
/// the adoption gate authenticates each link's signature and nothing about its
/// length — so a re-seal that carried one verbatim would let a committed write
/// grantee inflate a scope past the section budget and stall its re-key for
/// good. An over-long link is dropped rather than refused, exactly as an
/// over-long write history link already is
/// ([`MAX_WRITE_HISTORY_LINK_BYTES`](cipherbox_core::seal::MAX_WRITE_HISTORY_LINK_BYTES)).
pub(crate) const MAX_RETAINED_HISTORY_LINK_BYTES: usize = 128;

/// The retained link, its structure signature, and 32 bytes for the det-CBOR
/// map framing around the two must fit the per-link budget above, or the
/// section budget is not a bound. Compile-time, so it cannot reach a release
/// build (AGENTS.md rule 8).
const _: () = assert!(MAX_RETAINED_HISTORY_LINK_BYTES + ED_SIG_LEN + 32 <= HISTORY_LINK_WIRE_BYTES);

/// The owner blobs, the ascent link, the write history link, and the map
/// framing around every run — none of them count-driven, all of them small.
const SECTION_FRAMING_SLACK_BYTES: usize = 64 * 1024;

/// The largest grant section a scope-root re-seal can mint, and so the room its
/// record must always leave beside itself ([`MAX_RESEALABLE_ROOT_REST_BYTES`]).
///
/// A re-seal rebuilds the section from the committed set, so it mints one grant
/// blob per committed row even where the record it re-read carried none — growth
/// that record never showed. Left uncoordinated, a scope root sits under the
/// block ceiling with no authorable re-seal, and the owner's revocation cascade
/// refuses on it identically for ever: whoever can grow that record makes the
/// scope rotation-proof.
///
/// Derived from the frozen count bounds rather than picked, so a change to any
/// of them moves the budget with it. Every per-item size is bounded too: the
/// re-seal drops each ledger row's and each child ref's preserved unknown map
/// and bounds a retained history link's `sealed`
/// ([`MAX_RETAINED_HISTORY_LINK_BYTES`]), so no attacker-chosen run rides
/// forward. A section over the budget is still a **retryable** refusal on the
/// record the next pass re-resolves, never a trust verdict.
pub(crate) const MAX_RESEALABLE_SECTION_BYTES: usize = cipherbox_core::seal::MAX_GRANT_BLOBS
    * (GRANT_BLOB_WIRE_BYTES + LEDGER_ROW_WIRE_BYTES)
    + cipherbox_core::seal::MAX_DIRECT_CHILD_SCOPES * CHILD_SCOPE_REF_WIRE_BYTES
    + cipherbox_core::seal::MAX_HISTORY_LINKS * HISTORY_LINK_WIRE_BYTES
    + SECTION_FRAMING_SLACK_BYTES;

/// The budget every byte of a scope root **outside** its grant section is held
/// under — the read-sealed body, the typed envelope fields, and the carried
/// unknown maps. The complement of the section budget, so a root this build
/// authors always has an authorable re-seal.
pub(crate) const MAX_RESEALABLE_ROOT_REST_BYTES: usize =
    MAX_RESOLVED_RECORD_BYTES - MAX_RESEALABLE_SECTION_BYTES;

/// The reservation must leave the body the larger share, or a wire-cost edit has
/// quietly turned a re-seal budget into a cap on ordinary folders. Compile-time,
/// so it cannot reach a release build (AGENTS.md rule 8).
const _: () = assert!(
    MAX_RESEALABLE_ROOT_REST_BYTES > MAX_RESEALABLE_SECTION_BYTES,
    "the re-seal reservation must not outweigh the body it reserves against"
);

/// The shipped framing's sealed leaf must fit the block ceiling, or every
/// content block this engine authors is refused by the ingress it publishes
/// through. Compile-time, so a framing edit cannot reach a release build
/// (AGENTS.md rule 8).
const _: () = assert!(
    ContentProfile::PRODUCTION.chunk_size() as u64 + SEALED_LEAF_OVERHEAD
        <= MAX_RESOLVED_RECORD_BYTES as u64,
    "a production sealed leaf must fit the IPFS block ceiling"
);

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::seal_chunk;
    use cipherbox_core::suite::aead::{KEY_LEN, NONCE_LEN};

    /// The const assertion above computes the leaf size from
    /// `SEALED_LEAF_OVERHEAD`; this measures a real sealed leaf, so a seal
    /// layout that outgrows that constant still fails.
    #[test]
    fn a_production_sealed_leaf_fits_the_ceiling() {
        let plaintext = vec![0u8; ContentProfile::PRODUCTION.chunk_size()];
        let sealed = seal_chunk(&[0u8; KEY_LEN], &[0u8; NONCE_LEN], &plaintext);
        assert!(
            sealed.len() <= MAX_RESOLVED_RECORD_BYTES,
            "a {}-byte sealed leaf is unpinnable at a {MAX_RESOLVED_RECORD_BYTES}-byte ceiling",
            sealed.len()
        );
    }
}
