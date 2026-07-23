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
mod limits;
pub mod profile;
pub mod provider;
pub mod read;
pub mod retention;

pub use chunk::{ContentKey, SealedChunk, frame_and_seal};
pub use dag::{ContentDag, DAG_ROOT_CODEC, DagError, RootManifest, assemble, decode_root};
pub use profile::ContentProfile;
pub use provider::{
    ByoIpfsConfig, ByoKind, PinMode, ProviderError, test_connection, validate_endpoint,
};
pub use read::{
    ContentPlane, Gateway, GatewayConfig, GatewaySource, ReadError, leaf_range_for_byte_range,
    read_block,
};
pub use retention::{ContentVersion, PrunePlan, QuotaExceeded, plan_prune, pre_flight_quota_check};

use cipherbox_core::content::{encode_content_cid_str, open_chunk};
use cipherbox_core::seal::Version;

use crate::entropy::{Entropy, EntropyError};
use crate::seams::Http;

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

/// Why sealing a content version failed, fail-closed: entropy acquisition, or a
/// leaf set that would assemble a root [`decode_root`] rejects. An `Ok` return is
/// a version whose own DAG root this crate can decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Entropy acquisition for chunk sealing failed.
    Entropy(EntropyError),
    /// DAG assembly rejected the leaf set (see [`DagError`]).
    Dag(DagError),
}

impl From<EntropyError> for SealError {
    fn from(error: EntropyError) -> Self {
        Self::Entropy(error)
    }
}

impl From<DagError> for SealError {
    fn from(error: DagError) -> Self {
        Self::Dag(error)
    }
}

/// Frame, seal, and assemble `plaintext` into a content version under `key`
/// (blueprint/engine.md "Content plane"). Composes [`frame_and_seal`] and
/// [`assemble`]; deterministic under a fixed key and seeded entropy. Fails
/// closed if entropy acquisition fails or the assembled leaf count would not
/// round-trip through [`decode_root`].
pub fn seal_content(
    plaintext: &[u8],
    key: &ContentKey,
    entropy: &mut impl Entropy,
    profile: &ContentProfile,
) -> Result<SealedContent, SealError> {
    let leaves = frame_and_seal(plaintext, key, entropy, profile)?;
    let dag = assemble(&leaves, plaintext.len() as u64, profile)?;
    Ok(SealedContent {
        content_cid: dag.content_cid,
        root_block: dag.root_block,
        leaves,
    })
}

/// Why a verified content read failed — the read dual of [`SealError`]. The
/// classification is fail-closed: a CID, manifest, or unseal disagreement is
/// trust; no reachable source or an over-cap block is availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// A fail-closed trust violation; the message names the check, never key
    /// material.
    Trust(String),
    /// Availability — retryable, never a trust verdict.
    Unavailable(String),
}

/// Map a content-block read failure onto the [`OpenError`] classification.
fn open_read_error(e: ReadError) -> OpenError {
    match e {
        ReadError::TrustViolation(e) => {
            OpenError::Trust(format!("content block rejected: [{}]", e.check()))
        }
        ReadError::Unavailable => OpenError::Unavailable("content block unavailable".to_owned()),
        ReadError::TooLarge { size, limit } => {
            OpenError::Unavailable(format!("content block exceeds the cap ({size} > {limit})"))
        }
    }
}

/// Fetch, verify, and reassemble one content version's plaintext — the read
/// dual of [`seal_content`]: DAG root fetch (CID-verified fail-closed) →
/// manifest-vs-version size cross-check → per-leaf CID-verified fetch + unseal
/// under the version content key → reassembled-length cross-check.
pub async fn open_content<H: Http>(
    gateway: &Gateway,
    http: &H,
    version: &Version,
) -> Result<Vec<u8>, OpenError> {
    let root_cid_str = encode_content_cid_str(&version.content_cid);
    let root_block = read_block(
        gateway,
        http,
        &root_cid_str,
        &version.content_cid,
        ContentPlane::Root,
    )
    .await
    .map_err(open_read_error)?;
    let manifest = decode_root(&root_block)
        .map_err(|e| OpenError::Trust(format!("content DAG root rejected: {e:?}")))?;
    if manifest.size != version.size {
        return Err(OpenError::Trust(format!(
            "manifest size {} disagrees with version size {}",
            manifest.size, version.size
        )));
    }

    // Preallocate up to a fixed budget, then grow as leaves arrive: the size is
    // authenticated but unproven until every leaf is fetched, so a large size
    // field must not commit an outsized allocation upfront (on wasm32 it would
    // also truncate). The reassembled-length cross-check below is the gate.
    let prealloc = manifest.size.min(limits::MAX_RESOLVED_RECORD_BYTES as u64) as usize;
    let mut plaintext = Vec::with_capacity(prealloc);
    for leaf_cid in &manifest.leaf_cids {
        let leaf_cid_str = encode_content_cid_str(leaf_cid);
        let sealed = read_block(gateway, http, &leaf_cid_str, leaf_cid, ContentPlane::Leaf)
            .await
            .map_err(open_read_error)?;
        let chunk = open_chunk(version.content_key(), &sealed)
            .map_err(|e| OpenError::Trust(format!("leaf unseal rejected: [{}]", e.check())))?;
        plaintext.extend_from_slice(&chunk);
    }
    if plaintext.len() as u64 != manifest.size {
        return Err(OpenError::Trust(format!(
            "reassembled length {} disagrees with manifest size {}",
            plaintext.len(),
            manifest.size
        )));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::SeededEntropy;
    use cipherbox_core::content::verify_cid;
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
