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

pub(crate) mod budget;
pub mod chunk;
pub mod dag;
pub(crate) mod limits;
pub mod profile;
pub mod provider;
pub mod read;
pub mod retention;
pub mod write;

pub(crate) use budget::{Refused, StagingLedger, sealed_total_bytes};
pub use chunk::{ContentKey, SealedChunk, frame_and_seal, seal_one_chunk};
pub use dag::{
    ContentDag, DAG_ROOT_CODEC, DagError, ROOT_FORMAT_VERSION, RootManifest, assemble, decode_root,
    root_block_cid,
};
pub use profile::ContentProfile;
pub use provider::{
    ByoIpfsConfig, ByoKind, PinMode, ProviderError, test_connection, validate_byo_config,
};
pub use read::{
    ContentPlane, Gateway, GatewayConfig, GatewaySource, ReadError, is_plane_anchor,
    leaf_range_for_byte_range, read_block,
};
pub use retention::{
    ContentVersion, PrunePlan, QuotaExceeded, RetentionPolicy, plan_prune, pre_flight_quota_check,
};
pub use write::{ContentWriter, FinishedContent};

use cipherbox_core::content::{compute_cid, encode_content_cid_str, open_chunk};
use cipherbox_core::seal::Version;
use cipherbox_core::suite::secret::SECRET_LEN;

use crate::entropy::EntropyError;
use crate::seams::Http;

/// The published identity of one sealed content version: the `contentCid` its
/// metadata pins, the plaintext length that address reassembles to, and the leaf
/// addresses under it.
///
/// The three always come from one decoded root manifest, so the published
/// [`Version`] cannot disagree with the manifest [`open_content`] checks it
/// against — the encode side of that reject is unrepresentable rather than
/// merely guarded (AGENTS.md rule 8; #812 guard 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContent {
    content_cid: Vec<u8>,
    size: u64,
    leaf_cids: Vec<Vec<u8>>,
}

impl SealedContent {
    /// The identity of a version this process just assembled. `pub(crate)` so
    /// the only public constructor is [`Self::from_root_block`], which derives
    /// every field from bytes this crate's own decoder accepted.
    pub(crate) fn new(content_cid: Vec<u8>, size: u64, leaf_cids: Vec<Vec<u8>>) -> Self {
        Self {
            content_cid,
            size,
            leaf_cids,
        }
    }

    /// Recover a version's identity from its staged DAG root block, fail-closed.
    /// The drain reads its blocks back this way, so the `Version` it publishes
    /// is built from the manifest a reader will verify against, never from a
    /// separately-carried size.
    pub fn from_root_block(root_block: &[u8]) -> Result<Self, DagError> {
        let manifest = decode_root(root_block)?;
        Ok(Self {
            content_cid: compute_cid(DAG_ROOT_CODEC, root_block),
            size: manifest.size,
            leaf_cids: manifest.leaf_cids,
        })
    }

    /// The version's `contentCid` — the DAG root's content address, pinned by
    /// the version metadata and the authenticity anchor for a verified read.
    pub fn content_cid(&self) -> &[u8] {
        &self.content_cid
    }

    /// The plaintext byte length this version reassembles to.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The leaf content addresses, in file order.
    pub fn leaf_cids(&self) -> &[Vec<u8>] {
        &self.leaf_cids
    }

    /// The published [`Version`] for this content under `content_key`.
    pub fn version(&self, content_key: [u8; SECRET_LEN], modified_at: u64) -> Version {
        Version::new(
            self.content_cid.clone(),
            content_key,
            self.size,
            modified_at,
        )
    }
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
    /// The root declared a root-manifest format this build cannot read; see
    /// [`DagError::UnsupportedFormat`].
    UnsupportedFormat {
        /// The version the root declared.
        version: u64,
    },
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

/// Map a DAG-root rejection onto the [`OpenError`] classification. Exhaustive
/// for the same reason [`DagError::class`] is: a new variant must state its
/// classification here rather than inherit a trust verdict from a wildcard.
fn open_dag_error(e: DagError) -> OpenError {
    match e {
        DagError::UnsupportedFormat { version } => OpenError::UnsupportedFormat { version },
        DagError::RootTooLarge { size, limit } => OpenError::Unavailable(format!(
            "content DAG root exceeds the cap: {size} > {limit}"
        )),
        e @ (DagError::Cbor(_)
        | DagError::ZeroChunkSize
        | DagError::MalformedLeafCid
        | DagError::LinkCountMismatch) => {
            OpenError::Trust(format!("content DAG root rejected: [{}]", e.check()))
        }
    }
}

/// Fetch, verify, and reassemble one content version's plaintext — the read
/// dual of [`ContentWriter`]: DAG root fetch (CID-verified fail-closed) →
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
    let manifest = decode_root(&root_block).map_err(open_dag_error)?;
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
    use cipherbox_core::error::Malformed;
    use cipherbox_core::suite::aead::KEY_LEN;

    /// Frame `plaintext` through the streaming writer, returning the assembled
    /// root block and the version identity it addresses.
    fn sealed(plaintext: &[u8], seed: u64) -> (Vec<u8>, SealedContent) {
        let mut entropy = SeededEntropy::new(seed);
        let mut writer = ContentWriter::new(
            ContentKey::from_bytes([9u8; KEY_LEN]),
            ContentProfile::CI,
            plaintext.len() as u64,
        );
        let mut rest = plaintext;
        while !rest.is_empty() {
            let (remaining, _) = writer.push(rest, &mut entropy).unwrap();
            rest = remaining;
        }
        let finished = writer.finish(&mut entropy).unwrap();
        (finished.root_block, finished.content)
    }

    #[test]
    fn a_version_identity_recovered_from_its_root_block_matches_the_assembled_one() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (root_block, content) = sealed(&plaintext, 1);
        assert!(verify_cid(content.content_cid(), &root_block).is_ok());
        assert_eq!(
            SealedContent::from_root_block(&root_block).unwrap(),
            content,
            "the drain's keyless recovery equals what the writer assembled"
        );
        assert_eq!(content.size(), plaintext.len() as u64);
    }

    /// The encode side of [`open_content`]'s manifest-vs-version size reject:
    /// both figures come from one value, so they cannot be made to disagree
    /// (AGENTS.md rule 8; #812 guard 3). Fires in a release build.
    #[test]
    fn a_published_version_carries_its_own_manifests_size() {
        let (root_block, content) = sealed(&(0..40u8).collect::<Vec<_>>(), 3);
        let version = content.version([4u8; KEY_LEN], 99);
        assert_eq!(version.size, decode_root(&root_block).unwrap().size);
        assert_eq!(version.content_cid, content.content_cid());
        assert_eq!(version.modified_at, 99);
    }

    #[test]
    fn a_root_block_this_build_cannot_decode_yields_no_version() {
        assert!(SealedContent::from_root_block(b"not a root block").is_err());
    }

    #[test]
    fn an_unreadable_root_format_is_classified_apart_from_a_trust_verdict() {
        assert_eq!(
            open_dag_error(DagError::UnsupportedFormat { version: 2 }),
            OpenError::UnsupportedFormat { version: 2 },
            "an out-of-date client is not a forged record (#820)"
        );
        assert!(matches!(
            open_dag_error(DagError::LinkCountMismatch),
            OpenError::Trust(_)
        ));
        assert!(matches!(
            open_dag_error(DagError::Cbor(
                Malformed::MissingField { field: "v" }.into()
            )),
            OpenError::Trust(_)
        ));
        assert!(
            matches!(
                open_dag_error(DagError::RootTooLarge { size: 5, limit: 4 }),
                OpenError::Unavailable(_)
            ),
            "an over-cap root matches read_block's own cap verdict"
        );
    }

    #[test]
    fn framing_is_deterministic() {
        assert_eq!(sealed(b"determinism", 7).0, sealed(b"determinism", 7).0);
    }
}
