//! Shared content-plane size limits.

use cipherbox_core::seal::MAX_READ_SEALED_BYTES;
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
const HISTORY_LINK_WIRE_BYTES: usize = 352;

/// The widest `sealed` blob a re-seal retains on a read-plane history link.
///
/// The carried set is attacker-influenced — the adoption gate authenticates
/// each link's signature and nothing about its length — so a re-seal that
/// carried one verbatim would let a committed write grantee inflate a scope
/// past the section budget and stall its re-key for good. An over-long link is
/// dropped rather than refused, exactly as an over-long write history link
/// already is.
///
/// Tighter than core's
/// [`MAX_WRITE_HISTORY_LINK_BYTES`](cipherbox_core::seal::MAX_WRITE_HISTORY_LINK_BYTES),
/// which bounds the same payload shape on the write plane. That one is a frozen
/// wire bound; this one is a retention budget for links the re-seal keeps, and
/// [`resealable_section_bytes`] budgets [`HISTORY_LINK_WIRE_BYTES`] for
/// each of them. An honest link seals to at most 103 bytes at a `u64::MAX`
/// epoch, so the margin holds several additive payload fields — the headroom
/// matters, because a link over the bound takes every older link with it and
/// truncates the key-regression ratchet.
pub(crate) const MAX_RETAINED_HISTORY_LINK_BYTES: usize = 256;

/// The retained link, its structure signature, and 32 bytes for the det-CBOR
/// map framing around the two must fit the per-link budget above. Compile-time,
/// so it cannot reach a release build (AGENTS.md rule 8).
const _: () = assert!(
    MAX_RETAINED_HISTORY_LINK_BYTES + ED_SIG_LEN + 32 <= HISTORY_LINK_WIRE_BYTES,
    "a retained history link must fit the per-link share of the re-seal budget"
);

/// The owner blobs, the ascent link, the write history link, and the map
/// framing around every run — none of them count-driven, all of them small.
const SECTION_FRAMING_SLACK_BYTES: usize = 64 * 1024;

/// The granularity [`resealable_section_bytes`] charges the committed grant
/// count at. A reservation that tracked the count exactly would shrink on every
/// grant, so a root the owner authored inside its budget could stop fitting the
/// moment the owner granted once more. Charging a step at a time keeps the
/// budget flat across ordinary grant churn while still returning most of what
/// the frozen ceiling reserved.
const GRANT_RESERVATION_STEP: usize = 64;

/// The largest grant section a scope-root re-seal can mint for a root carrying
/// `committed_grants` owner-committed entries, and so the room that record must
/// always leave beside itself ([`resealable_root_rest_bytes`]).
///
/// A re-seal rebuilds the section from the committed set, so it mints one grant
/// blob per committed row even where the record it re-read carried none. Left
/// uncoordinated, a scope root sits under the block ceiling with no authorable
/// re-seal and the owner's revocation cascade refuses on it for ever: whoever
/// can grow that record makes the scope rotation-proof.
///
/// The count is the record's **own**, and owner-signed, so a writer that edits
/// it breaks the commitment signature the gate verifies a stage later. It is
/// charged in whole [`GRANT_RESERVATION_STEP`]s, so a root keeps its budget
/// across the grants that share its step and only a step crossing can find it
/// too full. The remaining runs keep their frozen ceilings, because a committed
/// writer authors both the child index and the carried links.
///
/// A section over the budget is a **retryable** refusal on the record the next
/// pass re-resolves, never a trust verdict. The clamp keeps
/// [`resealable_root_rest_bytes`]'s complement a total: every caller feeds a
/// decode-bounded count, and an unclamped one would underflow it.
pub(crate) const fn resealable_section_bytes(committed_grants: usize) -> usize {
    // One whole step above the count, so the step a root was authored in always
    // holds at least one more grant than it committed.
    let stepped = (committed_grants / GRANT_RESERVATION_STEP + 1) * GRANT_RESERVATION_STEP;
    let grants = if stepped > cipherbox_core::seal::MAX_GRANT_BLOBS {
        cipherbox_core::seal::MAX_GRANT_BLOBS
    } else {
        stepped
    };
    grants * (GRANT_BLOB_WIRE_BYTES + LEDGER_ROW_WIRE_BYTES)
        + cipherbox_core::seal::MAX_DIRECT_CHILD_SCOPES * CHILD_SCOPE_REF_WIRE_BYTES
        + cipherbox_core::seal::MAX_HISTORY_LINKS * HISTORY_LINK_WIRE_BYTES
        + SECTION_FRAMING_SLACK_BYTES
}

/// The budget every byte of a scope root **outside** its grant section is held
/// under — the read-sealed body, the typed envelope fields, and the carried
/// unknown maps. The complement of [`resealable_section_bytes`] at the same
/// committed count, so a root this build authors always has an authorable
/// re-seal. A root whose body alone fills it is refused on both sides, because
/// no cut shrinks a read-sealed body.
///
/// Only a committed write grantee authors such a root, and the refusal alone
/// would leave that grantee un-revocable on the scope: the owner cannot adopt
/// the record, so it can neither re-key nor replace it. The owner's rotation
/// therefore falls back to the last gate-passing copy of the root it cached,
/// and publishes the re-seal over that body above the refused record's
/// sequence. What the writer published after that copy goes with the record
/// the rotation steps over
/// (`crate::net::rotation::OwnerRotationNet::last_known_good_root`).
pub(crate) const fn resealable_root_rest_bytes(committed_grants: usize) -> usize {
    MAX_RESOLVED_RECORD_BYTES - resealable_section_bytes(committed_grants)
}

/// The listing budget one folder's children are held to at the facade boundary
/// ([`refuse_full_parent`](crate::facade)). A scope root must leave room beside
/// its listing for the grant section a re-key rebuilds, so it is charged the
/// same reservation the author side enforces; an ordinary folder is charged the
/// read-body seal bound alone. One home for both numbers, so a wire-cost edit
/// that moves the reservation moves the boundary with it.
///
/// The reservation is charged at the ungranted count, which is the loosest one
/// and exact below the first [`GRANT_RESERVATION_STEP`]: the boundary never
/// refuses a create the author would take, and a root over its own tighter
/// budget still meets [`AuthorError::ScopeRootNotResealable`].
///
/// [`AuthorError::ScopeRootNotResealable`]:
///     crate::net::author::AuthorError::ScopeRootNotResealable
pub(crate) const fn folder_listing_budget(is_scope_root: bool) -> usize {
    if is_scope_root {
        MAX_READ_SEALED_BYTES - resealable_section_bytes(0)
    } else {
        MAX_READ_SEALED_BYTES
    }
}

/// A scope root's listing budget must stay well clear of zero, or the
/// reservation has eaten the folder it reserves against. Compile-time, so it
/// cannot reach a release build (AGENTS.md rule 8).
const _: () = assert!(
    folder_listing_budget(true) > MAX_READ_SEALED_BYTES / 2,
    "a scope root must keep the larger half of the read-body bound for its own listing"
);

/// The bytes of a scope root that sit **outside** its grant section — what
/// [`resealable_root_rest_bytes`] holds. One home for the measure, so the
/// author side that enforces it and the adoption side that refuses a foreign
/// root over it can never charge it differently (AGENTS.md rule 8).
pub(crate) fn scope_root_rest_bytes(block_len: usize, section_len: usize) -> usize {
    block_len.saturating_sub(section_len)
}

/// The reservation must leave the body the larger share even at the frozen grant
/// ceiling, or a wire-cost edit has quietly turned a re-seal budget into a cap on
/// ordinary folders. Compile-time, so it cannot reach a release build
/// (AGENTS.md rule 8).
const _: () = assert!(
    resealable_root_rest_bytes(cipherbox_core::seal::MAX_GRANT_BLOBS)
        > resealable_section_bytes(cipherbox_core::seal::MAX_GRANT_BLOBS),
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
