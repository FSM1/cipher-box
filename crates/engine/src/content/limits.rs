//! Shared content-plane size limits.

use super::chunk::SEALED_LEAF_OVERHEAD;
use super::profile::ContentProfile;

/// Hard ceiling on a resolved content block, the single source of truth for both
/// the decode side ([`super::read::read_block`], which rejects any fetched block
/// over this before it is hashed, decoded, or gated — gate work is linear in the
/// fetched byte count) and the encode side ([`super::dag::assemble`], which fails
/// closed rather than emit a root manifest over this cap). A resolved record's
/// envelope-content rides in an IPFS block fetched by CID; capping it here bounds
/// gate work to a fixed budget and fails closed on anything larger
/// (blueprint/engine.md "Content plane").
///
/// The value is the IPFS single-block ceiling: `block/put` refuses anything over
/// 2 MiB (blueprint/api.md), so a larger record is authorable but unpinnable —
/// signed by this engine and then refused by its own ingress.
///
/// Must exceed the 1 MiB sealed leaf. A legitimate flat-DAG root inlines every
/// leaf CID, so it fits only up to the flat-DAG ceiling (~54 GiB at a 1 MiB chunk
/// size); `assemble` enforces that ceiling as a release-active `Err`, so this
/// crate never publishes a root its own `read_block` rejects (the encode/decode
/// fail-closed symmetry of AGENTS.md rule 8).
pub(crate) const MAX_RESOLVED_RECORD_BYTES: usize = 2 * 1024 * 1024;

/// The shipped framing's sealed leaf must fit the block ceiling, or every
/// content block this engine authors is refused by the ingress it publishes
/// through. Enforced at compile time — the one form of rule 8's release-active
/// check that a framing edit cannot outrun, since there is no encode path left
/// to reach.
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

    /// The ceiling is the ingress's, not a number of the engine's own choosing:
    /// `block/put` refuses anything over 2 MiB, so authoring past it signs a
    /// pointer to a block that can never be pinned.
    #[test]
    fn the_ceiling_is_the_ipfs_single_block_limit() {
        assert_eq!(MAX_RESOLVED_RECORD_BYTES, 2 * 1024 * 1024);
    }

    /// The const assertion above pins the same relationship at build time; this
    /// measures it against a real sealed leaf in whatever build runs the suite,
    /// so a seal-layout change that the overhead constant misses still fails.
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
