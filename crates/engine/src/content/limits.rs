//! Shared content-plane size limits.

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

/// The largest grant section a scope-root re-seal may mint, and the budget the
/// rest of that root's record is held under ([`MAX_RESEALABLE_ROOT_REST_BYTES`]).
///
/// A re-seal rebuilds the section from the committed set, so it can mint one
/// grant blob per committed row where the record it re-read carried none —
/// growth the record itself never showed. Left uncoordinated, a scope root can
/// sit under the block ceiling and still have no authorable re-seal, and the
/// owner's revocation cascade refuses on it identically for ever: a party who
/// can grow that record makes the scope rotation-proof.
///
/// The re-seal mints one blob per committed row, one ledger row per committed
/// row, one entry per direct child scope, and a bounded run of history links.
/// Every one of those runs is count-bounded in core, so the budget is those
/// counts at their wire cost.
pub(crate) const MAX_RESEALABLE_SECTION_BYTES: usize = 1024 * 1024;

/// The budget every byte of a scope root **outside** its grant section is held
/// under — the read-sealed body, the typed envelope fields, and the carried
/// unknown maps. Its complement is reserved for the section the next re-seal
/// mints, so a root this build authors always has an authorable re-seal.
pub(crate) const MAX_RESEALABLE_ROOT_REST_BYTES: usize =
    MAX_RESOLVED_RECORD_BYTES - MAX_RESEALABLE_SECTION_BYTES;

/// The section budget must hold everything a full committed set mints, or the
/// re-seal refuses sections the author side promised room for and the two limits
/// stop coordinating. Compile-time, so an edit to either cannot reach a release
/// build (AGENTS.md rule 8).
const _: () = assert!(
    MAX_RESEALABLE_SECTION_BYTES
        >= cipherbox_core::seal::MAX_GRANT_BLOBS * (GRANT_BLOB_WIRE_BYTES + LEDGER_ROW_WIRE_BYTES)
            + cipherbox_core::seal::MAX_DIRECT_CHILD_SCOPES * CHILD_SCOPE_REF_WIRE_BYTES
            + cipherbox_core::seal::MAX_HISTORY_LINKS * HISTORY_LINK_WIRE_BYTES,
    "a re-seal's section budget must hold a full committed set"
);

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
