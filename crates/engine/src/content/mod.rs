//! The content plane: chunk framing, DAG assembly, the pin-provider layer,
//! verified reads, and version retention (blueprint/engine.md "Content plane").
//!
//! The engine frames content into fixed-size chunks and seals each with core's
//! content-seal primitive under a fresh per-version content key, assembles a DAG
//! addressed by the version's `contentCid`, and reads blocks back through the
//! trustless gateway with a fail-closed CID verify on every response. All crypto
//! and the content-address codec are core's ([`cipherbox_core::content`], #691);
//! this plane composes them and owns the framing/DAG shape and the placement,
//! quota, and retention judgment (#630).
//!
//! - [`chunk`] — fixed-size framing + per-version key + core seal + leaf CID.
//! - [`dag`] — the version root addressed by its `contentCid`, chunk-aligned.
//! - [`provider`] — the pin-provider layer and BYO reachability probe.
//! - [`read`] — verified reads (accelerator + public fallback), fail-closed.
//! - [`retention`] — pre-flight quota and the explicit prune op.
//! - [`profile`] — the open-edge chunk-size constant.

pub mod chunk;
pub mod dag;
pub mod profile;
pub mod provider;
pub mod read;
pub mod retention;

pub use chunk::{ContentKey, SealedChunk, frame_and_seal};
pub use dag::{ContentDag, DAG_ROOT_CODEC, RootManifest, assemble, decode_root};
pub use profile::ContentProfile;
pub use provider::{ByoIpfsConfig, ByoKind, PinMode, ProviderError, test_connection};
pub use read::{
    ContentPlane, Gateway, GatewaySource, ReadError, leaf_range_for_byte_range, read_block,
};
pub use retention::{ContentVersion, PrunePlan, QuotaExceeded, plan_prune, pre_flight_quota_check};

use crate::entropy::{Entropy, EntropyError};

/// A fully sealed content version, ready to pin and register: the version's
/// `contentCid`, the DAG root block it addresses, and every sealed leaf block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContent {
    /// The version's `contentCid` — the DAG root's content address, pinned by
    /// the version metadata and the authenticity anchor for a verified read.
    pub content_cid: Vec<u8>,
    /// The DAG root block bytes (`dag-cbor`) that `content_cid` addresses.
    pub root_block: Vec<u8>,
    /// The sealed leaf blocks in file order, each carrying its own `raw` CID.
    pub leaves: Vec<SealedChunk>,
}

/// Frame, seal, and assemble `plaintext` into a content version under `key`
/// (blueprint/engine.md "Content plane"). Composes [`frame_and_seal`] and
/// [`assemble`]; deterministic under a fixed key and seeded entropy. Fails
/// closed only if entropy acquisition fails.
pub fn seal_content(
    plaintext: &[u8],
    key: &ContentKey,
    entropy: &mut impl Entropy,
    profile: &ContentProfile,
) -> Result<SealedContent, EntropyError> {
    let leaves = frame_and_seal(plaintext, key, entropy, profile)?;
    let dag = assemble(&leaves, plaintext.len() as u64, profile);
    Ok(SealedContent {
        content_cid: dag.content_cid,
        root_block: dag.root_block,
        leaves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::SeededEntropy;
    use cipherbox_core::content::{open_chunk, verify_cid};
    use cipherbox_core::suite::aead::KEY_LEN;

    #[test]
    fn seal_content_round_trips_through_the_dag() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let key = ContentKey::from_bytes([9u8; KEY_LEN]);
        let sealed = seal_content(
            &plaintext,
            &key,
            &mut SeededEntropy::new(1),
            &ContentProfile::CI,
        )
        .unwrap();

        // The root verifies, and its manifest lists the leaves in order.
        assert!(verify_cid(&sealed.content_cid, &sealed.root_block).is_ok());
        let manifest = decode_root(&sealed.root_block).unwrap();
        assert_eq!(manifest.size, plaintext.len() as u64);
        assert_eq!(
            manifest.leaf_cids,
            sealed
                .leaves
                .iter()
                .map(|l| l.cid.clone())
                .collect::<Vec<_>>()
        );

        // Every leaf verifies against its listed CID and opens to reassemble.
        let mut recovered = Vec::new();
        for (leaf, cid) in sealed.leaves.iter().zip(&manifest.leaf_cids) {
            assert!(verify_cid(cid, &leaf.sealed).is_ok());
            recovered.extend(open_chunk(key.as_bytes(), &leaf.sealed).unwrap());
        }
        assert_eq!(
            recovered, plaintext,
            "verified reassembly equals the original"
        );
    }

    #[test]
    fn seal_content_is_deterministic() {
        let key = ContentKey::from_bytes([2u8; KEY_LEN]);
        let a = seal_content(
            b"determinism",
            &key,
            &mut SeededEntropy::new(7),
            &ContentProfile::CI,
        );
        let b = seal_content(
            b"determinism",
            &key,
            &mut SeededEntropy::new(7),
            &ContentProfile::CI,
        );
        assert_eq!(a.unwrap(), b.unwrap());
    }
}
