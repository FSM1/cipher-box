//! The content plane: chunk framing, DAG assembly, the pin-provider layer,
//! verified reads, and version retention (blueprint/engine.md "Content plane").
//!
//! The engine frames content into fixed-size chunks and seals each with core's
//! content-seal primitive under a fresh per-version content key, assembles a DAG
//! addressed by the version's `contentCid`, and reads blocks back through the
//! trustless gateway with a fail-closed CID verify on every response. All crypto
//! and the content-address codec are core's ([`cipherbox_core::content`]); this
//! plane composes them and owns the framing/DAG shape and the placement, quota,
//! and retention judgment.

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
    ByoIpfsConfig, ByoKind, PinMode, Placement, PlacementDecision, PlacementRefusal, ProviderError,
    decide_placement, place_block, test_connection, validate_byo_config,
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
use zeroize::Zeroizing;

use crate::entropy::EntropyError;
use crate::seams::Http;

/// The published identity of one sealed content version: the `contentCid` its
/// metadata pins, the plaintext length that address reassembles to, and the leaf
/// addresses under it.
///
/// The three always come from one decoded root manifest, so the published
/// [`Version`] cannot disagree with the manifest [`open_content_range`] checks it
/// against — the encode side of that reject is unrepresentable rather than
/// merely guarded (AGENTS.md rule 8).
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
            leaf_cids: manifest.leaf_cid_vecs(),
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

/// Make room in `buf` for `additional` more bytes, wiping the allocation it
/// leaves behind.
///
/// A `Zeroizing<Vec<u8>>` wipes only the allocation it currently owns, so
/// letting `Vec` reallocate would free the old one with plaintext still in it
/// (AGENTS.md 7). Doubling keeps the new allocation within twice the leaves
/// already authenticated, so an unproven size field still cannot commit an
/// outsized one.
fn grow_wiping(buf: &mut Zeroizing<Vec<u8>>, additional: usize) {
    let needed = buf.len().saturating_add(additional);
    if needed <= buf.capacity() {
        return;
    }
    let mut grown = Zeroizing::new(Vec::with_capacity(
        buf.capacity().saturating_mul(2).max(needed),
    ));
    grown.extend_from_slice(buf);
    std::mem::swap(buf, &mut grown);
}

/// Fetch and verify one version's DAG root, returning the manifest its leaves
/// are read against. The manifest is complete on its own, so a caller may hold
/// it and read many windows without re-verifying the root.
pub(crate) async fn open_content_root<H: Http>(
    gateway: &Gateway,
    http: &H,
    version: &Version,
) -> Result<RootManifest, OpenError> {
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
    Ok(manifest)
}

/// Fetch, verify, and reassemble the plaintext window `[offset, offset +
/// length)` of one content version, fetching only the leaves it covers. The
/// request is clamped to the version, so an offset at or past the end yields no
/// bytes.
///
/// Every leaf must unseal to the length the flat framing implies — `chunk_size`
/// but for the final one. A disagreement is a fail-closed trust violation: a
/// short middle leaf shifts every downstream byte, so tolerating one would serve
/// silently misaligned plaintext.
pub async fn open_content_range<H: Http>(
    gateway: &Gateway,
    http: &H,
    version: &Version,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, OpenError> {
    let manifest = open_content_root(gateway, http, version).await?;
    read_pinned_range(gateway, http, version, &manifest, offset, length).await
}

/// [`open_content_range`]'s leaf half, against a `manifest` [`open_content_root`]
/// already verified against `version`.
pub(crate) async fn read_pinned_range<H: Http>(
    gateway: &Gateway,
    http: &H,
    version: &Version,
    manifest: &RootManifest,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, OpenError> {
    // `manifest` and `version` arrive as separate arguments: re-assert the
    // pairing rather than trust the caller, or another version's manifest frames
    // this version's leaves with only the AEAD to catch it.
    if manifest.size != version.size {
        return Err(OpenError::Trust(format!(
            "manifest size {} disagrees with version size {}",
            manifest.size, version.size
        )));
    }
    let length = length.min(manifest.size.saturating_sub(offset));
    if length == 0 {
        return Ok(Vec::new());
    }
    let chunk_size = manifest.chunk_size;
    let leaves = leaf_range_for_byte_range(offset, length, chunk_size, manifest.leaf_cids.len());
    // Preallocate up to a fixed budget, then grow through `grow_wiping` as
    // leaves arrive: the size is authenticated but unproven until every leaf is
    // fetched, so a large size field must not commit an outsized allocation
    // upfront (on wasm32 it would also truncate). The assembled-length
    // cross-check below is the gate.
    let prealloc = length.min(limits::MAX_RESOLVED_RECORD_BYTES as u64) as usize;
    // Owns already-assembled plaintext until it is handed to the caller: the
    // trust rejects below abandon a partly-filled buffer (AGENTS.md 7).
    let mut plaintext = Zeroizing::new(Vec::with_capacity(prealloc));
    for index in leaves {
        let leaf_cid = &manifest.leaf_cids[index];
        let leaf_cid_str = encode_content_cid_str(leaf_cid);
        let sealed = read_block(gateway, http, &leaf_cid_str, leaf_cid, ContentPlane::Leaf)
            .await
            .map_err(open_read_error)?;
        // Terminal owner of this leaf's plaintext: a ranged read discards the
        // trimmed head and tail, so they must not outlive the loop (AGENTS.md 7).
        let chunk = Zeroizing::new(
            open_chunk(version.content_key(), &sealed)
                .map_err(|e| OpenError::Trust(format!("leaf unseal rejected: [{}]", e.check())))?,
        );

        let leaf_start = (index as u64).saturating_mul(chunk_size);
        let expected = chunk_size.min(manifest.size.saturating_sub(leaf_start));
        if chunk.len() as u64 != expected {
            return Err(OpenError::Trust(format!(
                "leaf {index} unsealed to {} bytes, not the {expected} the manifest implies",
                chunk.len()
            )));
        }
        let from = offset.saturating_sub(leaf_start).min(expected) as usize;
        let to = (offset.saturating_add(length))
            .saturating_sub(leaf_start)
            .min(expected) as usize;
        grow_wiping(&mut plaintext, to - from);
        plaintext.extend_from_slice(&chunk[from..to]);
    }
    if plaintext.len() as u64 != length {
        return Err(OpenError::Trust(format!(
            "assembled length {} disagrees with the {length}-byte range requested",
            plaintext.len(),
        )));
    }
    // The caller becomes the terminal owner of the window it asked for.
    Ok(std::mem::take(&mut *plaintext))
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

    /// The encode side of [`open_content_range`]'s manifest-vs-version size reject:
    /// both figures come from one value, so they cannot be made to disagree
    /// (AGENTS.md rule 8). Fires in a release build.
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
            "an out-of-date client is not a forged record"
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

    mod ranged {
        use super::*;
        use crate::testkit::fakes::ScriptedHttp;
        use crate::testkit::{block_on, block_store, gateway, requested_cid, serve};
        use std::collections::BTreeMap;

        const CONTENT_KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];

        /// A version and the blocks that serve it, keyed by gateway address.
        struct Fixture {
            version: Version,
            blocks: BTreeMap<String, Vec<u8>>,
        }

        /// Frame `plaintext` at the CI profile (16-byte chunks) into a version
        /// whose every block is served by the returned store.
        fn fixture(plaintext: &[u8]) -> Fixture {
            let key = ContentKey::from_bytes(CONTENT_KEY);
            let leaves = frame_and_seal(
                plaintext,
                &key,
                &mut SeededEntropy::new(1),
                &ContentProfile::CI,
            )
            .unwrap();
            from_leaves(leaves, plaintext.len() as u64)
        }

        /// Assemble a version over already-sealed `leaves` declaring `size` —
        /// the seam a hostile manifest is built through.
        fn from_leaves(leaves: Vec<SealedChunk>, size: u64) -> Fixture {
            let leaf_cids: Vec<Vec<u8>> = leaves.iter().map(|leaf| leaf.cid.clone()).collect();
            let dag = assemble(&leaf_cids, size, &ContentProfile::CI).unwrap();
            let mut blocks = block_store(&leaves);
            blocks.insert(
                encode_content_cid_str(&dag.content_cid),
                dag.root_block.clone(),
            );
            Fixture {
                version: Version::new(dag.content_cid, CONTENT_KEY, size, 0),
                blocks,
            }
        }

        /// Every CID fetched, in request order.
        fn fetched(http: &ScriptedHttp) -> Vec<String> {
            http.requests()
                .iter()
                .map(|request| requested_cid(&request.url))
                .collect()
        }

        /// The gateway address of leaf `index` of `fixture`'s version.
        fn leaf_address(fixture: &Fixture, index: usize) -> String {
            let root =
                fixture.blocks[&encode_content_cid_str(&fixture.version.content_cid)].clone();
            encode_content_cid_str(&decode_root(&root).unwrap().leaf_cids[index])
        }

        fn read_range(fixture: &Fixture, offset: u64, length: u64) -> (Vec<u8>, Vec<String>) {
            let http = serve(&fixture.blocks);
            let out = block_on(open_content_range(
                &gateway(),
                &http,
                &fixture.version,
                offset,
                length,
            ))
            .unwrap();
            (out, fetched(&http))
        }

        #[test]
        fn a_chunk_aligned_range_serves_exactly_its_own_leaf() {
            let plaintext: Vec<u8> = (0..48u8).collect();
            let fixture = fixture(&plaintext);
            let (out, cids) = read_range(&fixture, 16, 16);
            assert_eq!(out, plaintext[16..32]);
            assert_eq!(
                cids,
                vec![
                    encode_content_cid_str(&fixture.version.content_cid),
                    leaf_address(&fixture, 1),
                ],
                "the root plus the one leaf the range covers, nothing else"
            );
        }

        #[test]
        fn a_range_straddling_a_leaf_boundary_is_assembled_from_both() {
            let plaintext: Vec<u8> = (0..48u8).collect();
            let fixture = fixture(&plaintext);
            let (out, cids) = read_range(&fixture, 15, 2);
            assert_eq!(out, plaintext[15..17]);
            assert_eq!(
                cids,
                vec![
                    encode_content_cid_str(&fixture.version.content_cid),
                    leaf_address(&fixture, 0),
                    leaf_address(&fixture, 1),
                ]
            );
        }

        #[test]
        fn a_suffix_range_running_past_the_end_is_clamped() {
            let plaintext: Vec<u8> = (0..40u8).collect();
            let fixture = fixture(&plaintext);
            let (out, _) = read_range(&fixture, 33, 1000);
            assert_eq!(out, plaintext[33..], "clamped to the version's own size");
        }

        #[test]
        fn an_offset_at_or_past_the_end_yields_no_bytes_and_no_leaf_fetch() {
            let fixture = fixture(&(0..40u8).collect::<Vec<_>>());
            for offset in [40u64, 41, u64::MAX] {
                let (out, cids) = read_range(&fixture, offset, 16);
                assert!(out.is_empty(), "offset {offset} is past the end");
                assert_eq!(
                    cids,
                    vec![encode_content_cid_str(&fixture.version.content_cid)],
                    "only the root is consulted"
                );
            }
        }

        #[test]
        fn a_zero_length_range_yields_no_bytes() {
            let fixture = fixture(&(0..40u8).collect::<Vec<_>>());
            let (out, cids) = read_range(&fixture, 8, 0);
            assert!(out.is_empty());
            assert_eq!(cids.len(), 1, "no leaf is fetched for an empty window");
        }

        #[test]
        fn only_the_leaves_the_window_covers_are_fetched() {
            // 5 leaves at 16 bytes; the window sits inside leaves 2..4.
            let plaintext: Vec<u8> = (0..80u8).collect();
            let fixture = fixture(&plaintext);
            let (out, cids) = read_range(&fixture, 40, 20);
            assert_eq!(out, plaintext[40..60]);
            assert_eq!(
                cids,
                vec![
                    encode_content_cid_str(&fixture.version.content_cid),
                    leaf_address(&fixture, 2),
                    leaf_address(&fixture, 3),
                ]
            );
        }

        #[test]
        fn every_offset_and_length_matches_the_whole_file_slice() {
            let plaintext: Vec<u8> = (0..48u8).collect();
            let fixture = fixture(&plaintext);
            for offset in 0..=48u64 {
                for length in 0..=8u64 {
                    let (out, _) = read_range(&fixture, offset, length);
                    let start = offset.min(48) as usize;
                    let end = (offset + length).min(48) as usize;
                    assert_eq!(out, plaintext[start..end], "range {offset}+{length}");
                }
            }
            // The whole-file read `Engine::read_content` issues.
            let (out, _) = read_range(&fixture, 0, u64::MAX);
            assert_eq!(out, plaintext, "an unbounded window is the whole file");
        }

        /// The encode side of the per-leaf length reject: the framer splits on
        /// the chunk boundary, so a short non-final leaf is unrepresentable
        /// rather than merely guarded (AGENTS.md rule 8). Fires in a release
        /// build.
        #[test]
        fn the_framer_cannot_produce_a_short_non_final_leaf() {
            let chunk_size = ContentProfile::CI.chunk_size();
            let key = ContentKey::from_bytes(CONTENT_KEY);
            for len in [0usize, 1, 15, 16, 17, 40, 100] {
                let leaves = frame_and_seal(
                    &vec![7u8; len],
                    &key,
                    &mut SeededEntropy::new(1),
                    &ContentProfile::CI,
                )
                .unwrap();
                for (index, leaf) in leaves.iter().enumerate() {
                    let chunk = open_chunk(&CONTENT_KEY, &leaf.sealed).unwrap();
                    let expected = if index + 1 < leaves.len() {
                        chunk_size
                    } else {
                        len - index * chunk_size
                    };
                    assert_eq!(chunk.len(), expected, "{len}-byte version, leaf {index}");
                }
            }
        }

        #[test]
        fn a_short_middle_leaf_fails_closed_as_a_trust_violation() {
            // Leaf 1 carries 8 bytes where the framing implies 16; the manifest
            // is otherwise well-formed — 3 leaves for 40 bytes at a 16-byte chunk.
            let key = ContentKey::from_bytes(CONTENT_KEY);
            let mut entropy = SeededEntropy::new(2);
            let leaves: Vec<SealedChunk> = [16usize, 8, 16]
                .into_iter()
                .map(|len| seal_one_chunk(&key, &vec![0xA5u8; len], &mut entropy).unwrap())
                .collect();
            let fixture = from_leaves(leaves, 40);
            let http = serve(&fixture.blocks);

            let err = block_on(open_content_range(
                &gateway(),
                &http,
                &fixture.version,
                0,
                40,
            ))
            .unwrap_err();
            match err {
                OpenError::Trust(message) => assert!(
                    message.contains("leaf 1"),
                    "the reject names the offending leaf: {message}"
                ),
                other => panic!("expected a trust violation, got {other:?}"),
            }
        }

        #[test]
        fn a_final_leaf_disagreeing_with_the_declared_size_fails_closed() {
            // Two full leaves declared as 24 bytes: the final leaf unseals to 16
            // where the manifest implies 8.
            let key = ContentKey::from_bytes(CONTENT_KEY);
            let mut entropy = SeededEntropy::new(3);
            let leaves: Vec<SealedChunk> = (0..2)
                .map(|_| seal_one_chunk(&key, &[0xC3u8; 16], &mut entropy).unwrap())
                .collect();
            let fixture = from_leaves(leaves, 24);
            let http = serve(&fixture.blocks);

            let err = block_on(open_content_range(
                &gateway(),
                &http,
                &fixture.version,
                16,
                8,
            ))
            .unwrap_err();
            assert!(matches!(err, OpenError::Trust(_)), "got {err:?}");
        }

        #[test]
        fn a_manifest_disagreeing_with_the_version_size_fails_closed_before_any_leaf() {
            let fixture = fixture(&(0..40u8).collect::<Vec<_>>());
            let version = Version::new(fixture.version.content_cid.clone(), CONTENT_KEY, 41, 0);
            let http = serve(&fixture.blocks);
            let err = block_on(open_content_range(&gateway(), &http, &version, 0, 16)).unwrap_err();
            assert!(matches!(err, OpenError::Trust(_)), "got {err:?}");
            assert_eq!(
                fetched(&http).len(),
                1,
                "no leaf is fetched past the reject"
            );
        }
    }
}
