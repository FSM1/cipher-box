//! Verified content reads over the trustless gateway (blueprint/engine.md
//! "Content plane": "the token-authed trustless gateway is a member
//! accelerator; any public trustless gateway is the no-auth fallback. The
//! engine verifies CIDs client-side via core on every block/CAR response").
//!
//! The authenticity anchor is the block's `contentCid`: every fetched block is
//! run through [`cipherbox_core::content::verify_cid`] against the requested
//! CID, and a mismatch fails **closed** as a [`TrustViolation`] — never a silent
//! degrade to staleness (AGENTS.md rule 6). Only availability (transport error,
//! non-2xx) rotates to the next source; a mismatch is terminal, because a
//! content-address disagreement is an integrity signal to surface, not a
//! retryable fetch miss.

use core::fmt;
use core::ops::Range;

use cipherbox_core::content::{CONTENT_CID_CODEC, CONTENT_CID_LEN, verify_cid};
use cipherbox_core::error::{CodecError, TrustViolation};
use zeroize::Zeroizing;

use super::dag::DAG_ROOT_CODEC;
use crate::seams::{Http, HttpMethod, HttpRequest};

const AUTHORIZATION: &str = "Authorization";
const ACCEPT: &str = "Accept";
/// The trustless-gateway raw-block content type (IPIP-0402).
const RAW_BLOCK: &str = "application/vnd.ipld.raw";
/// Byte offset of the multicodec in the fixed CIDv1 framing (version at 0).
const CID_CODEC_INDEX: usize = 1;

/// Hard ceiling on a fetched content block, enforced at this fetch boundary
/// before the block is hashed, decoded, or gated. A resolved record's
/// envelope-content (grant blobs, history links) rides in an IPFS block fetched
/// by CID, and the adoption gate then hashes and verifies every structure it
/// carries — gate work is linear in the fetched byte count. Capping the block
/// here bounds that work to a fixed budget and fails closed on anything larger,
/// before any per-structure cost is paid (#742; blueprint/engine.md "Content
/// plane"). Must stay above the production content chunk size (1 MiB) so a
/// legitimate leaf or root block always fits.
const MAX_RESOLVED_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Which content-plane a fetched CID must address. Core's [`verify_cid`] accepts
/// any single-byte multicodec (`< 0x80`), not just the frozen content-plane set,
/// so the engine pins the expected codec here and fails closed on a valid-but-
/// wrong-plane (or out-of-set) codec — a raw leaf and a dag-cbor root are not
/// interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentPlane {
    /// A sealed leaf block, addressed with the `raw` codec (0x55).
    Leaf,
    /// The DAG root block, addressed with the `dag-cbor` codec (0x71).
    Root,
}

impl ContentPlane {
    /// The multicodec byte a CID in this plane must carry.
    fn codec(self) -> u8 {
        match self {
            Self::Leaf => CONTENT_CID_CODEC,
            Self::Root => DAG_ROOT_CODEC,
        }
    }
}

/// One trustless-gateway endpoint. The member accelerator carries a bearer
/// token; a public fallback carries none. The token is a credential: held in a
/// zeroizing buffer and redacted from `Debug` (security rule 2).
#[derive(Clone, PartialEq, Eq)]
pub struct GatewaySource {
    /// Gateway base URL (no trailing slash needed; one is tolerated).
    pub base_url: String,
    /// Bearer token for the token-authed accelerator; `None` for a public
    /// gateway. Zeroized on drop, never logged.
    pub bearer: Option<Zeroizing<String>>,
}

impl fmt::Debug for GatewaySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewaySource")
            .field("base_url", &self.base_url)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The ordered read source set: the token-authed accelerator is tried first as
/// a member convenience, then the public no-auth fallbacks in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    /// The member accelerator (token-authed), consulted first when present.
    pub accelerator: Option<GatewaySource>,
    /// Public trustless-gateway fallbacks, tried in order after the accelerator.
    pub public_fallbacks: Vec<GatewaySource>,
}

impl Gateway {
    /// Accelerator (if any) first, then public fallbacks — read consult order.
    fn sources(&self) -> impl Iterator<Item = &GatewaySource> {
        self.accelerator.iter().chain(self.public_fallbacks.iter())
    }
}

/// Why a verified read did not return bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// A fetched block did not content-address to the requested CID: fail-closed
    /// integrity violation, surfaced verbatim from core. Terminal — never
    /// retried against another source, never degraded to staleness.
    TrustViolation(CodecError),
    /// The fetched block exceeded [`MAX_RESOLVED_RECORD_BYTES`]: rejected at the
    /// fetch boundary before any hash/decode/gate work. Terminal and fail-closed
    /// — a record over the size bound is never adoptable, so it is not retried
    /// against another source (#742).
    TooLarge {
        /// The oversized response body length.
        size: usize,
        /// The enforced ceiling ([`MAX_RESOLVED_RECORD_BYTES`]).
        limit: usize,
    },
    /// No source served the block: every gateway failed at the transport or
    /// status level (unreachable, aborted, or non-2xx). Availability, not
    /// integrity — the caller may retry later.
    Unavailable,
}

/// Fetch and verify one block addressed by `cid_str` against its binary
/// `expected_cid`. `cid_str` is the gateway address (the canonical CIDv1
/// base32 string as it appears in metadata/links); `expected_cid` is the binary
/// CIDv1 that is the trust anchor — verification binds to it, so a mismatched
/// address at worst fails closed. `plane` pins the codec the CID must carry (raw
/// leaf vs dag-cbor root), rejecting an out-of-set or wrong-plane codec
/// fail-closed before any fetch — core's [`verify_cid`] alone would accept any
/// single-byte codec.
///
/// `cid_str` is a distinct parameter because the engine has no CID-multibase
/// codec (base encoders live in core; content CIDs have none yet), so the caller
/// supplies the address form. It is validated to be a canonical content-CID
/// string before it reaches the URL, so a non-CID or a path/query-bearing string
/// (`../`, `?`, `#`) cannot be injected; misuse still fails closed on the binary
/// anchor either way.
///
/// Tries each source in [`Gateway`] order; returns the first block that
/// verifies. A CID mismatch on any response is terminal
/// ([`ReadError::TrustViolation`]); only availability failures rotate to the
/// next source. All sources exhausted without a verified block is
/// [`ReadError::Unavailable`].
pub async fn read_block(
    gateway: &Gateway,
    http: &impl Http,
    cid_str: &str,
    expected_cid: &[u8],
    plane: ContentPlane,
) -> Result<Vec<u8>, ReadError> {
    // Reject a non-anchor request before any fetch, fail-closed (codec
    // out-of-set/wrong-plane, or a non-canonical address).
    let codec_ok =
        expected_cid.len() == CONTENT_CID_LEN && expected_cid[CID_CODEC_INDEX] == plane.codec();
    if !codec_ok || !is_canonical_content_cid_str(cid_str) {
        return Err(ReadError::TrustViolation(
            TrustViolation::ContentCidMismatch.into(),
        ));
    }
    for source in gateway.sources() {
        let Some(response) = fetch(source, http, cid_str).await else {
            continue; // transport-level failure: try the next source
        };
        if !(200..300).contains(&response.status) {
            continue; // availability (not found / server error): next source
        }
        // Fail closed on an oversized block before it is hashed or decoded: gate
        // work is linear in these bytes, so this cap bounds it at the fetch
        // boundary (#742), ahead of the verify hash below and all downstream
        // decode/gate work.
        if response.body.len() > MAX_RESOLVED_RECORD_BYTES {
            return Err(ReadError::TooLarge {
                size: response.body.len(),
                limit: MAX_RESOLVED_RECORD_BYTES,
            });
        }
        // Every 2xx body is verified before it can be returned. A mismatch is a
        // fail-closed trust violation, not a reason to try another source.
        return verify_cid(expected_cid, &response.body)
            .map(|()| response.body)
            .map_err(ReadError::TrustViolation);
    }
    Err(ReadError::Unavailable)
}

/// Whether `cid_str` is the canonical CIDv1 base32 string of a content CID: the
/// multibase base32-lower prefix `b` over the fixed [`CONTENT_CID_LEN`] bytes.
/// A pure format check (base encoders live in core), tied to the CID length so
/// only a real content-CID shape reaches the gateway URL — the base32 alphabet
/// excludes `/`, `?`, `#`, and `.`, so no path/query fragment can slip through.
fn is_canonical_content_cid_str(cid_str: &str) -> bool {
    // Unpadded base32 length of CONTENT_CID_LEN bytes, plus the 'b' multibase tag.
    const CID_STR_LEN: usize = 1 + (CONTENT_CID_LEN * 8).div_ceil(5);
    cid_str.len() == CID_STR_LEN
        && cid_str.as_bytes()[0] == b'b'
        && cid_str
            .bytes()
            .skip(1)
            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

/// Send the raw-block GET to one source; `None` on a transport-level failure
/// (the seam's reserved `Err`), which is an availability signal, not a trust one.
async fn fetch(
    source: &GatewaySource,
    http: &impl Http,
    cid_str: &str,
) -> Option<crate::seams::HttpResponse> {
    let base = source.base_url.trim_end_matches('/');
    let mut headers = vec![(ACCEPT.to_owned(), RAW_BLOCK.to_owned())];
    if let Some(bearer) = &source.bearer {
        headers.push((
            AUTHORIZATION.to_owned(),
            format!("Bearer {}", bearer.as_str()),
        ));
    }
    let request = HttpRequest {
        method: HttpMethod::Get,
        url: format!("{base}/ipfs/{cid_str}?format=raw"),
        headers,
        body: None,
    };
    http.send(request).await.ok()
}

/// The leaf-index range covering the plaintext byte range `[offset, offset +
/// length)` for a flat DAG framed at `chunk_size` (blueprint/engine.md: "shaped
/// so ranged block/CAR fetches map chunk-aligned"). The flat shape makes this a
/// pure division: the first leaf is `offset / chunk_size`. Clamped to
/// `leaf_count`; an offset at or past the end yields an empty range.
pub fn leaf_range_for_byte_range(
    offset: u64,
    length: u64,
    chunk_size: u64,
    leaf_count: usize,
) -> Range<usize> {
    // A zero chunk size is a nonsensical (never-produced) manifest value; guard
    // the division fail-safe rather than panic on it in any build.
    if chunk_size == 0 {
        return 0..0;
    }
    let leaf_count = leaf_count as u64;
    let first = (offset / chunk_size).min(leaf_count);
    // The last byte touched is offset+length-1; a zero length touches nothing.
    // Every step is saturating so an extreme range can never overflow the +1.
    let last_exclusive = if length == 0 {
        first
    } else {
        (offset.saturating_add(length).saturating_sub(1) / chunk_size)
            .saturating_add(1)
            .min(leaf_count)
    };
    (first as usize)..(last_exclusive as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::chunk::{ContentKey, frame_and_seal};
    use crate::content::profile::ContentProfile;
    use crate::seams::HttpResponse;
    use crate::testkit::SeededEntropy;
    use crate::testkit::block_on;
    use crate::testkit::fakes::ScriptedHttp;
    use cipherbox_core::content::compute_cid;
    use cipherbox_core::suite::aead::KEY_LEN;

    fn raw_response(body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), RAW_BLOCK.into())],
            body,
        }
    }

    fn one_leaf() -> super::super::chunk::SealedChunk {
        let key = ContentKey::from_bytes([4u8; KEY_LEN]);
        frame_and_seal(
            b"a sealed block",
            &key,
            &mut SeededEntropy::new(1),
            &ContentProfile::CI,
        )
        .unwrap()
        .remove(0)
    }

    /// A syntactically canonical CIDv1 base32 address (`b` + 58 base32 chars).
    /// The trust anchor is the binary `expected_cid`, so a valid address need
    /// only be well-formed here, not the encoding of that specific CID.
    fn cid_str() -> String {
        format!("b{}", "a".repeat(58))
    }

    fn accelerator_only() -> Gateway {
        Gateway {
            accelerator: Some(GatewaySource {
                base_url: "https://gw.cipherbox.test/".into(),
                bearer: Some(Zeroizing::new("member-token".to_owned())),
            }),
            public_fallbacks: vec![GatewaySource {
                base_url: "https://public.gw.test".into(),
                bearer: None,
            }],
        }
    }

    #[test]
    fn verified_block_is_returned_and_addressed_via_the_accelerator() {
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        http.enqueue_response(raw_response(leaf.sealed.clone()));

        let out = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap();
        assert_eq!(out, leaf.sealed);

        let request = &http.requests()[0];
        assert_eq!(
            request.url,
            format!("https://gw.cipherbox.test/ipfs/{}?format=raw", cid_str())
        );
        assert!(
            request
                .headers
                .iter()
                .any(|(n, v)| n == AUTHORIZATION && v == "Bearer member-token"),
            "accelerator request carries the member bearer token"
        );
    }

    #[test]
    fn tampered_bytes_fail_closed_as_a_trust_violation() {
        let leaf = one_leaf();
        let mut tampered = leaf.sealed.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        let http = ScriptedHttp::default();
        http.enqueue_response(raw_response(tampered));

        let err = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap_err();
        match err {
            ReadError::TrustViolation(e) => assert_eq!(e.check(), "content-cid-mismatch"),
            other => panic!("expected a trust violation, got {other:?}"),
        }
        // Terminal: the mismatch is not retried against the public fallback.
        assert_eq!(
            http.requests().len(),
            1,
            "a mismatch does not rotate sources"
        );
    }

    #[test]
    fn an_over_cap_block_is_rejected_before_any_hash_or_rotation() {
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        // An over-cap body that would NOT content-address to `leaf.cid`: getting
        // TooLarge (not a content-cid-mismatch) proves the size gate fired
        // before verify_cid hashed the body, and before any decode/gate work.
        http.enqueue_response(raw_response(vec![0u8; MAX_RESOLVED_RECORD_BYTES + 1]));
        // A good block is queued behind it; a terminal rejection must not consume it.
        http.enqueue_response(raw_response(leaf.sealed.clone()));

        let err = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap_err();
        assert_eq!(
            err,
            ReadError::TooLarge {
                size: MAX_RESOLVED_RECORD_BYTES + 1,
                limit: MAX_RESOLVED_RECORD_BYTES,
            }
        );
        assert_eq!(
            http.requests().len(),
            1,
            "an over-cap block is terminal — it does not rotate to another source"
        );
    }

    #[test]
    fn a_block_at_the_cap_passes_the_size_gate_and_reaches_verify() {
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        // Exactly at the cap: the boundary is exclusive (`>`), so this passes the
        // size gate and reaches verify_cid, which then rejects the garbage bytes
        // as a content-cid-mismatch — proving at-cap content proceeds.
        http.enqueue_response(raw_response(vec![0u8; MAX_RESOLVED_RECORD_BYTES]));

        let err = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap_err();
        match err {
            ReadError::TrustViolation(e) => assert_eq!(e.check(), "content-cid-mismatch"),
            other => panic!("expected a content-cid-mismatch, got {other:?}"),
        }
    }

    #[test]
    fn availability_failure_rotates_to_the_public_fallback() {
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        // Accelerator 503, then the public fallback serves the real block.
        http.enqueue_response(HttpResponse {
            status: 503,
            headers: Vec::new(),
            body: Vec::new(),
        });
        http.enqueue_response(raw_response(leaf.sealed.clone()));

        let out = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap();
        assert_eq!(out, leaf.sealed);

        let urls: Vec<_> = http.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(urls.len(), 2);
        assert!(
            urls[1].starts_with("https://public.gw.test/ipfs/"),
            "fell back to public gateway"
        );
        assert!(
            !http.requests()[1]
                .headers
                .iter()
                .any(|(n, _)| n == AUTHORIZATION),
            "public fallback carries no bearer token"
        );
    }

    #[test]
    fn all_sources_unavailable_is_unavailable_not_a_violation() {
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        http.enqueue_response(HttpResponse {
            status: 502,
            headers: Vec::new(),
            body: Vec::new(),
        });
        http.enqueue_response(HttpResponse {
            status: 504,
            headers: Vec::new(),
            body: Vec::new(),
        });

        let err = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap_err();
        assert_eq!(err, ReadError::Unavailable);
    }

    #[test]
    fn transport_error_is_an_availability_failure() {
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        http.enqueue_error(crate::seams::SeamError::new("connection refused"));
        http.enqueue_response(raw_response(leaf.sealed.clone()));
        let out = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Leaf,
        ))
        .unwrap();
        assert_eq!(out, leaf.sealed);
    }

    #[test]
    fn out_of_set_codec_is_rejected_before_any_fetch() {
        // A CID whose codec is a single byte < 0x80 but outside the frozen set
        // (0x60) would pass core's verify_cid over the very block it addresses,
        // yet the engine must reject it: it is not a raw leaf.
        let leaf = one_leaf();
        let rogue_cid = compute_cid(0x60, &leaf.sealed);
        let http = ScriptedHttp::default();
        http.enqueue_response(raw_response(leaf.sealed.clone()));

        let err = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &rogue_cid,
            ContentPlane::Leaf,
        ))
        .unwrap_err();
        match err {
            ReadError::TrustViolation(e) => assert_eq!(e.check(), "content-cid-mismatch"),
            other => panic!("expected a trust violation, got {other:?}"),
        }
        assert!(
            http.requests().is_empty(),
            "an out-of-set codec is rejected before any fetch"
        );
    }

    #[test]
    fn a_valid_leaf_cid_requested_as_a_root_is_rejected() {
        // The leaf's own valid raw (0x55) CID, requested on the root plane
        // (dag-cbor 0x71), must fail closed — planes are not interchangeable.
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        let err = block_on(read_block(
            &accelerator_only(),
            &http,
            &cid_str(),
            &leaf.cid,
            ContentPlane::Root,
        ))
        .unwrap_err();
        assert!(matches!(err, ReadError::TrustViolation(_)));
        assert!(
            http.requests().is_empty(),
            "wrong-plane codec rejected pre-fetch"
        );
    }

    #[test]
    fn a_non_canonical_address_is_rejected_before_any_fetch() {
        // A path-traversal / query-bearing address must never reach the URL,
        // even though the binary anchor (`expected_cid`) is valid.
        let leaf = one_leaf();
        let http = ScriptedHttp::default();
        // Correct length and 'b' tag, but a non-base32 tail char.
        let wrong_charset = format!("b{}", "!".repeat(58));
        for bad in [
            "../../etc/passwd",
            "bafyleaf?foo=bar",
            "bafyleaf#frag",
            "BAFYUPPERCASE",
            wrong_charset.as_str(),
        ] {
            let err = block_on(read_block(
                &accelerator_only(),
                &http,
                bad,
                &leaf.cid,
                ContentPlane::Leaf,
            ))
            .unwrap_err();
            assert!(
                matches!(err, ReadError::TrustViolation(_)),
                "address {bad:?} must be rejected fail-closed"
            );
        }
        assert!(
            http.requests().is_empty(),
            "a non-canonical address never reaches the network"
        );
    }

    #[test]
    fn gateway_source_debug_redacts_the_bearer_token() {
        let source = GatewaySource {
            base_url: "https://gw.test".into(),
            bearer: Some(Zeroizing::new("super-secret-token".to_owned())),
        };
        let debug = format!("{source:?}");
        assert!(
            !debug.contains("super-secret-token"),
            "bearer must never render"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn zero_chunk_size_yields_an_empty_range_not_a_panic() {
        assert_eq!(leaf_range_for_byte_range(0, 10, 0, 3), 0..0);
    }

    #[test]
    fn extreme_range_saturates_without_overflow() {
        // Debug builds enable overflow checks; the +1 must not panic at u64::MAX.
        assert_eq!(
            leaf_range_for_byte_range(u64::MAX, u64::MAX, 1, 3),
            3..3,
            "clamped to leaf count, no overflow"
        );
    }

    #[test]
    fn byte_range_maps_chunk_aligned_to_leaf_indices() {
        // 16-byte chunks, 3 leaves (48 bytes of capacity).
        assert_eq!(leaf_range_for_byte_range(0, 16, 16, 3), 0..1);
        assert_eq!(
            leaf_range_for_byte_range(0, 17, 16, 3),
            0..2,
            "spills into leaf 1"
        );
        assert_eq!(leaf_range_for_byte_range(16, 16, 16, 3), 1..2);
        assert_eq!(
            leaf_range_for_byte_range(15, 2, 16, 3),
            0..2,
            "straddles the boundary"
        );
        assert_eq!(
            leaf_range_for_byte_range(40, 100, 16, 3),
            2..3,
            "clamped to leaf count"
        );
        assert_eq!(
            leaf_range_for_byte_range(100, 10, 16, 3),
            3..3,
            "past end is empty"
        );
        assert_eq!(
            leaf_range_for_byte_range(5, 0, 16, 3),
            0..0,
            "zero length touches nothing"
        );
    }
}
