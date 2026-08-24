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
/// The value is the IPFS single-block ceiling: `block/put` refuses anything over
/// 2 MiB (blueprint/api.md), so a larger record is authorable but unpinnable —
/// signed by this engine and then refused by its own ingress.
///
/// Must exceed the 1 MiB sealed leaf, which [`ContentProfile::new`] enforces
/// for every injected profile. A legitimate flat-DAG root inlines every
/// leaf CID, so it fits only up to the flat-DAG ceiling (~54 GiB at a 1 MiB chunk
/// size); `assemble` enforces that ceiling as a release-active `Err`, so this
/// crate never publishes a root its own `read_block` rejects (the encode/decode
/// fail-closed symmetry of AGENTS.md rule 8).
pub(crate) const MAX_RESOLVED_RECORD_BYTES: usize = 2 * 1024 * 1024;

/// The shipped framing's sealed leaf must fit the block ceiling, or every
/// content block this engine authors is refused by the ingress it publishes
/// through. Compile-time, so a framing edit cannot reach a release build
/// (AGENTS.md rule 8).
const _: () = assert!(
    ContentProfile::PRODUCTION.chunk_size() as u64 + SEALED_LEAF_OVERHEAD
        <= MAX_RESOLVED_RECORD_BYTES as u64,
    "a production sealed leaf must fit the IPFS block ceiling"
);

/// The codec derives its write-body bound from a restated copy of this ceiling
/// (`cipherbox_core::seal::MAX_HEAD_BLOCK_BYTES`), because it sits below this
/// crate. Compile-time, so the two cannot drift apart into a bound that reserves
/// no re-seal headroom at all (AGENTS.md rule 8).
const _: () = assert!(
    cipherbox_core::seal::MAX_WRITE_BODY_BYTES
        + cipherbox_core::seal::WRITE_BODY_RESEAL_HEADROOM_BYTES
        <= MAX_RESOLVED_RECORD_BYTES,
    "the write-body bound must reserve its re-seal headroom under the block ceiling"
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
