//! The content-DAG CID codec (blueprint/core.md "Open edges").
//!
//! The deterministic CIDv1 content address of a content blob. The digest is the
//! frozen suite hash BLAKE3-256 ([`crate::suite::hash::hash`]), so the CID is
//! byte-identical on native and wasm32.
//!
//! CIDv1 layout — all four framing bytes are single-byte multicodec varints, so
//! the CID is a fixed 4-byte prefix followed by the digest:
//!
//! | byte   | meaning                                                     |
//! | ------ | ----------------------------------------------------------- |
//! | `0x01` | CID version 1                                               |
//! | codec  | multicodec — `raw` (0x55) for a leaf, engine-chosen at root |
//! | `0x1e` | multihash `blake3` (the frozen suite hash)                  |
//! | `0x20` | multihash digest length = 32                                |
//! | …      | 32-byte BLAKE3 digest of `bytes`                            |
//!
//! Core addresses *leaf* sealed chunks as `raw` ([`CONTENT_CID_CODEC`]); a
//! version's `contentCid` is a DAG **root** whose codec is engine-owned (#630,
//! engine.md:497), so the codec is a parameter here, not a constant.
//! [`verify_cid`] therefore keys off the claimed CID's *own* codec byte —
//! validating a raw leaf and a DAG root alike (engine.md:468) — while the
//! version, multihash, and length framing stay fixed and fail-closed.

use crate::error::{CodecError, Malformed, TrustViolation};
use crate::suite::hash::hash;
use crate::suite::secret::SECRET_LEN;

/// CIDv1 version byte (version 1).
const CID_VERSION: u8 = 0x01;

/// Byte offset of the multicodec within the CIDv1 framing.
const CID_CODEC_INDEX: usize = 1;

/// The leaf (raw, 0x55) multicodec: core content-addresses each opaque sealed
/// chunk as raw bytes. The DAG-root `contentCid` codec is engine-owned (#630,
/// engine.md:497), passed to [`compute_cid`] by the engine — not fixed here.
pub const CONTENT_CID_CODEC: u8 = 0x55;

/// Multihash code for BLAKE3-256 (0x1e) — the frozen suite hash
/// ([`crate::suite::hash::hash`]).
pub const CONTENT_CID_MULTIHASH: u8 = 0x1e;

/// The multihash digest width: the suite BLAKE3 hash output, `SECRET_LEN`
/// (32 bytes). Tied to the suite so a hash-width change is a compile-time break.
const DIGEST_LEN: usize = SECRET_LEN;

/// Number of fixed framing bytes preceding the digest (version||codec||mh||len).
const CID_PREFIX_LEN: usize = 4;

/// Total CIDv1 byte length: the 4-byte prefix plus the 32-byte digest.
pub const CONTENT_CID_LEN: usize = CID_PREFIX_LEN + DIGEST_LEN;

/// Compute the content CID (binary CIDv1) of `bytes` under multicodec `codec`.
/// Leaf sealed chunks pass [`CONTENT_CID_CODEC`] (`raw`); the engine passes the
/// DAG-root codec for a version's `contentCid` (#630). Deterministic and
/// byte-identical across native and wasm32; a public content address, so no key
/// material flows through here.
///
/// # Panics
///
/// If `codec >= 0x80`: a multi-byte unsigned varint is outside the frozen
/// single-byte content-plane set — `raw` 0x55 leaf, `dag-cbor` 0x71 root
/// (core.md:56) — and unrepresentable in this fixed layout.
pub fn compute_cid(codec: u8, bytes: &[u8]) -> Vec<u8> {
    // `assert!` (not `debug_assert!`): a one-byte-truncated CID from a
    // multi-byte codec must fail closed in release too (core.md:56).
    assert!(
        codec < 0x80,
        "content-plane multicodec must be single-byte (< 0x80, core.md:56)"
    );
    let digest = hash(bytes);
    let mut cid = Vec::with_capacity(CONTENT_CID_LEN);
    cid.extend_from_slice(&[CID_VERSION, codec, CONTENT_CID_MULTIHASH, DIGEST_LEN as u8]);
    cid.extend_from_slice(&digest);
    cid
}

/// Verify that `bytes` content-addresses to `claimed_cid`, fail-closed. The
/// codec is read from `claimed_cid` itself (#630 owns the DAG-root codec,
/// engine.md:497), so a raw leaf and a DAG-root `contentCid` both verify while
/// the version, multihash code, digest length, and digest are recomputed and
/// compared byte-for-byte. A malformed/truncated/foreign claimed CID, a codec byte
/// outside the frozen single-byte set, a wrong multihash code, or a digest mismatch
/// is [`TrustViolation::ContentCidMismatch`], never mere staleness. The comparison
/// is over a public content address (no secret), so ordinary equality is used.
pub fn verify_cid(claimed_cid: &[u8], bytes: &[u8]) -> Result<(), CodecError> {
    // Untrusted claimed CID: reject a multi-byte-varint codec byte (>= 0x80)
    // before mirroring it into `compute_cid`. A full-length CID with a high codec
    // byte would otherwise either trip that guard (panic-as-DoS) or, in a build
    // with asserts stripped, fail open by matching the recomputed malformed CID.
    if claimed_cid.len() == CONTENT_CID_LEN
        && claimed_cid[CID_CODEC_INDEX] < 0x80
        && compute_cid(claimed_cid[CID_CODEC_INDEX], bytes) == claimed_cid
    {
        Ok(())
    } else {
        Err(TrustViolation::ContentCidMismatch.into())
    }
}

// ---------------------------------------------------------------------------
// Content-CID string codec (blueprint/core.md "Content-CID string codec"). A
// scope's metadata IPNS record carries `/ipfs/<head_cid>`: the binary CIDv1
// above in base32-lowercase multibase (leading `b`), the form IPFS emits. The
// Adopter must recover the binary anchor from that string before a fetched head
// can be trust-checked, so encode + strict decode are core exports.
// ---------------------------------------------------------------------------

/// The multibase prefix for lowercase base32 (RFC 4648 `base32`, no padding).
const MULTIBASE_BASE32: char = 'b';

/// The RFC 4648 base32 lowercase alphabet (`a`=0 … `z`=25, `2`=26 … `7`=31).
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Whether `cid` is the frozen content-plane CIDv1 framing: 36 bytes,
/// `version=1`, a single-byte multicodec (`< 0x80`, engine-owned #630), the
/// BLAKE3 multihash code, and the 32-byte digest length. The invariant both the
/// encoder guards (release-active) and the decoder rejects on, kept symmetric.
pub fn is_wellformed_content_cid(cid: &[u8]) -> bool {
    cid.len() == CONTENT_CID_LEN
        && cid[0] == CID_VERSION
        && cid[CID_CODEC_INDEX] < 0x80
        && cid[2] == CONTENT_CID_MULTIHASH
        && cid[3] == DIGEST_LEN as u8
}

/// Encode a binary content CIDv1 as its canonical base32-lowercase multibase
/// string (leading `b`). Every valid content CID has exactly one such string.
///
/// # Panics
///
/// If `cid` is not the frozen framing: emitting a `b…` string over bytes the
/// decoder rejects would publish an unresolvable scope head (AGENTS.md rule 8
/// encode/decode symmetry), so the guard is release-active.
pub fn encode_content_cid_str(cid: &[u8]) -> String {
    assert!(
        is_wellformed_content_cid(cid),
        "content CID must be the frozen CIDv1 framing (core.md)"
    );
    let mut out = String::with_capacity(1 + base32_len(cid.len()));
    out.push(MULTIBASE_BASE32);
    base32_encode_into(cid, &mut out);
    out
}

/// Strictly decode a base32-lowercase multibase content-CID string into its
/// binary CIDv1 bytes, fail-closed ([`Malformed::ContentCidStrMalformed`]).
/// Rejects a wrong/missing `b` prefix, a non-base32 or non-canonical body, and
/// anything that is not the frozen content-plane CIDv1 framing — the recovered
/// anchor must be trustworthy before a fetch trusts it (AGENTS.md rule 6).
pub fn decode_content_cid_str(s: &str) -> Result<Vec<u8>, CodecError> {
    // Fixed-width anchor: reject an over-long string up front (cheap, never
    // rejects a real 36-byte CID — the base32 bound always exceeds its width).
    if s.len() > 1 + base32_len(CONTENT_CID_LEN) {
        return Err(malformed_cid_str());
    }
    let mut chars = s.chars();
    if chars.next() != Some(MULTIBASE_BASE32) {
        return Err(malformed_cid_str());
    }
    let cid = base32_decode(chars.as_str()).ok_or_else(malformed_cid_str)?;
    if !is_wellformed_content_cid(&cid) {
        return Err(malformed_cid_str());
    }
    // Re-derive the canonical string and byte-compare: a body that decoded but
    // is not the byte-exact canonical rendering (e.g. a dangling zero-bit char)
    // never survives as a distinct string (mirrors ipns/name.rs).
    if encode_content_cid_str(&cid) != s {
        return Err(malformed_cid_str());
    }
    Ok(cid)
}

fn malformed_cid_str() -> CodecError {
    Malformed::ContentCidStrMalformed.into()
}

/// A loose upper bound on the base32 length of `n` bytes: 8 bits/byte over
/// 5 bits/char is 1.6, so `2*n` always suffices (for capacity and the cap).
fn base32_len(n: usize) -> usize {
    2 * n
}

/// Append the canonical base32-lowercase (no-padding) rendering of `input`.
fn base32_encode_into(input: &[u8], out: &mut String) {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
}

/// Decode a canonical base32-lowercase (no-padding) body. Returns `None` on any
/// non-alphabet char or a non-zero trailing-bit remainder (a non-canonical tail).
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    for c in text.chars() {
        acc = (acc << 5) | u32::from(base32_digit(c)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

fn base32_digit(c: char) -> Option<u8> {
    match c {
        'a'..='z' => Some(c as u8 - b'a'),
        '2'..='7' => Some(c as u8 - b'2' + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_shape_is_the_frozen_prefix_plus_digest() {
        let cid = compute_cid(CONTENT_CID_CODEC, b"sealed bytes");
        assert_eq!(cid.len(), CONTENT_CID_LEN);
        assert_eq!(
            &cid[..4],
            &[CID_VERSION, CONTENT_CID_CODEC, CONTENT_CID_MULTIHASH, 0x20],
            "version||raw||blake3||len prefix"
        );
        assert_eq!(&cid[4..], &hash(b"sealed bytes"), "suite BLAKE3 digest");
    }

    #[test]
    fn compute_cid_carries_the_caller_codec() {
        // The DAG-root codec (dag-cbor 0x71) is engine-chosen (#630).
        let cid = compute_cid(0x71, b"dag root bytes");
        assert_eq!(cid[CID_CODEC_INDEX], 0x71, "codec byte is the parameter");
        assert_eq!(
            &cid[..4],
            &[CID_VERSION, 0x71, CONTENT_CID_MULTIHASH, 0x20],
            "v1||dag-cbor||blake3||len prefix"
        );
        assert_eq!(&cid[4..], &hash(b"dag root bytes"), "suite BLAKE3 digest");
        // Same bytes, different codec → distinct CID, identical digest tail.
        let raw = compute_cid(CONTENT_CID_CODEC, b"dag root bytes");
        assert_ne!(cid, raw, "codec separates the CID");
        assert_eq!(&cid[4..], &raw[4..], "digest is codec-independent");
    }

    #[test]
    fn cid_is_deterministic_and_content_separated() {
        assert_eq!(
            compute_cid(CONTENT_CID_CODEC, b"a"),
            compute_cid(CONTENT_CID_CODEC, b"a"),
            "deterministic"
        );
        assert_ne!(
            compute_cid(CONTENT_CID_CODEC, b"a"),
            compute_cid(CONTENT_CID_CODEC, b"b"),
            "distinct bytes"
        );
    }

    #[test]
    fn verify_accepts_the_matching_raw_leaf_cid() {
        let bytes = b"the sealed content blob";
        let cid = compute_cid(CONTENT_CID_CODEC, bytes);
        assert!(verify_cid(&cid, bytes).is_ok());
    }

    #[test]
    fn verify_accepts_a_dag_root_cid_off_its_own_codec() {
        // Core keys off the claimed CID's codec byte, not a hardcoded raw prefix.
        let bytes = b"the assembled dag root node";
        let cid = compute_cid(0x71, bytes);
        assert_ne!(cid[CID_CODEC_INDEX], CONTENT_CID_CODEC, "non-raw codec");
        assert!(verify_cid(&cid, bytes).is_ok());
    }

    #[test]
    fn verify_rejects_mismatched_bytes_fail_closed() {
        let cid = compute_cid(CONTENT_CID_CODEC, b"original");
        assert_eq!(
            verify_cid(&cid, b"tampered").unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn verify_rejects_a_wrong_multihash_code_fail_closed() {
        let bytes = b"content";
        let mut cid = compute_cid(CONTENT_CID_CODEC, bytes);
        cid[2] ^= 0xff; // corrupt the multihash-code byte, digest still matches
        assert_eq!(
            verify_cid(&cid, bytes).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    // Native-only: the guard is release-active, but `#[should_panic]` is unsafe
    // on the panic=abort wasm legs.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[should_panic(expected = "single-byte")]
    fn compute_cid_guards_a_multibyte_codec_fail_closed() {
        // A codec >= 0x80 must trip the guard, not emit a truncated CID.
        let _ = compute_cid(0x80, b"multi-byte codec is out of the frozen set");
    }

    #[test]
    fn verify_rejects_a_multibyte_prefixed_oversized_cid_fail_closed() {
        // A real multi-byte-codec CID (dag-json 0x0129 = varint [0xa9, 0x02]) is
        // 37 bytes: the fixed-length check rejects it even with a matching digest.
        let bytes = b"content";
        let cid = compute_cid(CONTENT_CID_CODEC, bytes);
        let mut oversized = vec![CID_VERSION, 0xa9, 0x02];
        oversized.extend_from_slice(&cid[CID_CODEC_INDEX + 1..]); // multihash||len||digest
        assert_eq!(
            oversized.len(),
            CONTENT_CID_LEN + 1,
            "two-byte codec prefix"
        );
        assert_eq!(
            verify_cid(&oversized, bytes).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn verify_rejects_a_high_codec_byte_exact_len_cid_fail_closed() {
        // A full-length CID with a high codec byte, valid framing, and a
        // *matching* digest: without the codec guard this fails open (asserts
        // stripped) or panics (asserts live). `verify_cid` must return Err in
        // both, so this runs on every leg including wasm.
        let bytes = b"content";
        let mut cid = vec![CID_VERSION, 0x80, CONTENT_CID_MULTIHASH, DIGEST_LEN as u8];
        cid.extend_from_slice(&hash(bytes));
        assert_eq!(cid.len(), CONTENT_CID_LEN, "exact-length malformed CID");
        assert_eq!(
            verify_cid(&cid, bytes).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn verify_rejects_a_truncated_or_foreign_claimed_cid() {
        let bytes = b"content";
        let cid = compute_cid(CONTENT_CID_CODEC, bytes);
        assert_eq!(
            verify_cid(&cid[..cid.len() - 1], bytes)
                .unwrap_err()
                .check(),
            "content-cid-mismatch"
        );
        assert_eq!(
            verify_cid(b"not a cid", bytes).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn content_cid_str_round_trips_and_is_lowercase_b_prefixed() {
        for codec in [CONTENT_CID_CODEC, 0x71u8] {
            let cid = compute_cid(codec, b"head block bytes");
            let s = encode_content_cid_str(&cid);
            assert!(s.starts_with('b'), "base32-lower multibase prefix");
            assert!(
                s.bytes()
                    .skip(1)
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "base32-lower body: {s}"
            );
            assert_eq!(
                decode_content_cid_str(&s).expect("own string decodes"),
                cid,
                "string codec round-trips byte-for-byte"
            );
        }
    }

    #[test]
    fn decode_rejects_foreign_and_non_canonical_strings() {
        let cid = compute_cid(CONTENT_CID_CODEC, b"anchor");
        let s = encode_content_cid_str(&cid);
        for bad in [
            String::new(),                // empty
            "b".to_string(),              // prefix only
            format!("k{}", &s[1..]),      // wrong multibase (base36 k)
            format!("z{}", &s[1..]),      // wrong multibase (base58 z)
            s.to_uppercase(),             // uppercase (base32 upper 'B…')
            format!("{s}a"),              // trailing extra char
            s[..s.len() - 1].to_string(), // truncated
            format!("b1{}", &s[1..]),     // '1' not in base32 alphabet
        ] {
            assert_eq!(
                decode_content_cid_str(&bad).unwrap_err().check(),
                "content-cid-str-malformed",
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn decode_rejects_wrong_framing_even_when_base32_canonical() {
        // Valid base32 body, corrupted multihash code → wrong framing, fail closed.
        let mut cid = compute_cid(CONTENT_CID_CODEC, b"anchor");
        cid[2] ^= 0xff;
        let mut s = String::from("b");
        super::base32_encode_into(&cid, &mut s);
        assert_eq!(
            decode_content_cid_str(&s).unwrap_err().check(),
            "content-cid-str-malformed"
        );
    }

    // Native-only, like `compute_cid`'s guard test: `#[should_panic]` is unsafe
    // on the panic=abort wasm legs.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[should_panic(expected = "frozen CIDv1 framing")]
    fn encode_guards_malformed_cid_fail_closed() {
        let _ = encode_content_cid_str(b"not a well-framed content cid");
    }
}
