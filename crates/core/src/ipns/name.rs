//! The IPNS name codec (blueprint/core.md "IPNS records — Name codec").
//!
//! `ipnsName` = the multibase-base36 (`k`-prefixed) CIDv1 with the libp2p-key
//! multicodec of the node's Ed25519 public key. For Ed25519 the serialized
//! public key is short, so libp2p uses the **identity** multihash and the key
//! rides inline in the name — which is exactly what makes verification's trust
//! anchor the name itself: [`IpnsName::public_key`] extracts the Ed25519 key
//! from the name, never from a side channel or a DB column (#39 D7).
//!
//! Decode is deliberately strict: it matches the one canonical
//! Ed25519-identity layout byte-for-byte and re-derives the canonical text,
//! rejecting anything that does not round-trip to the exact bytes we would emit
//! (the cross-language `$`-before-`\n` lesson: keep the Rust side strict).

use crate::error::{CodecError, Malformed};
use crate::suite::ed25519::{Ed25519Verifier, PUBLIC_LEN};

/// The multibase prefix for lowercase base36 (`base36btc`).
const MULTIBASE_BASE36: char = 'k';

/// The canonical fixed prefix of the CIDv1 bytes for an Ed25519 IPNS key,
/// everything before the 32-byte public key:
///
/// | byte   | meaning                                                  |
/// | ------ | -------------------------------------------------------- |
/// | `0x01` | CID version 1                                            |
/// | `0x72` | multicodec `libp2p-key`                                  |
/// | `0x00` | multihash function `identity`                           |
/// | `0x24` | multihash digest length = 36                            |
/// | `0x08` | protobuf `PublicKey.Type` tag (field 1, varint)         |
/// | `0x01` | key type `Ed25519`                                      |
/// | `0x12` | protobuf `PublicKey.Data` tag (field 2, len-delimited)  |
/// | `0x20` | data length = 32                                        |
const CID_PREFIX: [u8; 8] = [0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

/// Total length of the CIDv1 byte string: the fixed prefix plus the 32-byte
/// Ed25519 public key.
const CID_LEN: usize = CID_PREFIX.len() + PUBLIC_LEN;

/// The widest a name string can be. The one canonical layout makes this a law,
/// not a policy: [`IpnsName::parse`] refuses anything longer, and any codec
/// carrying opaque `ipnsName` bytes bounds them here rather than picking its own
/// number. The base36 upper bound exceeds a real name's 62-byte width, so it
/// never rejects one.
pub const MAX_IPNS_NAME_BYTES: usize = 1 + base36_len(CID_LEN);

/// A validated IPNS name: the canonical `k`-prefixed base36 string plus the
/// Ed25519 public key it names. Parsing enforces the single canonical layout,
/// so [`public_key`](Self::public_key) is infallible and the "pubkey from the
/// name" law is enforced in exactly one place.
#[derive(Clone, PartialEq, Eq)]
pub struct IpnsName {
    text: String,
    key: Ed25519Verifier,
}

impl IpnsName {
    /// Build the name of an Ed25519 public key. Infallible: every valid
    /// verifying key has exactly one canonical name.
    pub fn from_public_key(key: &Ed25519Verifier) -> Self {
        let mut cid = Vec::with_capacity(CID_LEN);
        cid.extend_from_slice(&CID_PREFIX);
        cid.extend_from_slice(&key.to_bytes());
        let mut text = String::with_capacity(1 + base36_len(cid.len()));
        text.push(MULTIBASE_BASE36);
        text.push_str(&base36_encode(&cid));
        Self { text, key: *key }
    }

    /// Strictly decode a name string. Rejects (`ipns-name-malformed`) any input
    /// that is not the exact canonical base36 CIDv1 libp2p-key encoding of a
    /// valid Ed25519 public key: wrong multibase prefix, non-base36 characters,
    /// a wrong CID/multihash/protobuf layout, or a 32-byte digest that is not a
    /// valid compressed Edwards point.
    pub fn parse(text: &str) -> Result<Self, CodecError> {
        // Bound the input before the O(n^2) base36 division so a giant string
        // cannot burn work.
        if text.len() > MAX_IPNS_NAME_BYTES {
            return Err(malformed());
        }
        let mut chars = text.chars();
        if chars.next() != Some(MULTIBASE_BASE36) {
            return Err(malformed());
        }
        let cid = base36_decode(chars.as_str()).ok_or_else(malformed)?;
        if cid.len() != CID_LEN || cid[..CID_PREFIX.len()] != CID_PREFIX {
            return Err(malformed());
        }
        let mut pk = [0u8; PUBLIC_LEN];
        pk.copy_from_slice(&cid[CID_PREFIX.len()..]);
        let key = Ed25519Verifier::from_bytes(pk).ok_or_else(malformed)?;
        // Re-derive the canonical text so a name that decoded but is not the
        // byte-exact canonical form (e.g. a stray leading base36 '0') never
        // survives as a distinct string.
        let canonical = Self::from_public_key(&key);
        if canonical.text != text {
            return Err(malformed());
        }
        Ok(canonical)
    }

    /// The Ed25519 public key this name names — extracted from the name itself.
    pub fn public_key(&self) -> Ed25519Verifier {
        self.key
    }

    /// The canonical `k`-prefixed base36 string.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl core::fmt::Debug for IpnsName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IpnsName({})", self.text)
    }
}

impl core::fmt::Display for IpnsName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

fn malformed() -> CodecError {
    CodecError::Malformed(Malformed::IpnsNameMalformed)
}

// ---------------------------------------------------------------------------
// base36 (`base36btc`) — big-endian byte string <-> lowercase base36, with the
// multibase leading-zero convention (each leading 0x00 byte is one leading
// '0'). No bignum dependency: repeated division over the byte buffer.
// ---------------------------------------------------------------------------

const BASE36_ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// A loose upper bound on the base36 length of `n` bytes, for string capacity:
/// log(256)/log(36) < 1.55, so `2*n` always suffices.
const fn base36_len(n: usize) -> usize {
    2 * n
}

fn base36_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut buf = input.to_vec();
    let mut digits: Vec<u8> = Vec::new();
    let mut start = zeros;
    while start < buf.len() {
        let mut remainder = 0u32;
        for byte in buf.iter_mut().skip(start) {
            let acc = (remainder << 8) | u32::from(*byte);
            *byte = (acc / 36) as u8;
            remainder = acc % 36;
        }
        digits.push(remainder as u8);
        while start < buf.len() && buf[start] == 0 {
            start += 1;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('0');
    }
    for &d in digits.iter().rev() {
        out.push(BASE36_ALPHABET[d as usize] as char);
    }
    out
}

fn base36_decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text.chars().take_while(|&c| c == '0').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.chars() {
        let value = base36_digit(c)?;
        let mut carry = u32::from(value);
        for byte in bytes.iter_mut() {
            let acc = u32::from(*byte) * 36 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

fn base36_digit(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='z' => Some(c as u8 - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::ed25519::Ed25519Signer;

    fn verifier(seed: u8) -> Ed25519Verifier {
        Ed25519Signer::from_seed([seed; 32]).verifying_key()
    }

    #[test]
    fn round_trips_encode_then_parse() {
        for seed in [0u8, 1, 7, 42, 255] {
            let key = verifier(seed);
            let name = IpnsName::from_public_key(&key);
            assert!(name.as_str().starts_with('k'), "base36 multibase prefix");
            let parsed = IpnsName::parse(name.as_str()).expect("own name must parse");
            assert_eq!(
                parsed.public_key(),
                key,
                "pubkey from name is the source key"
            );
            assert_eq!(parsed.as_str(), name.as_str(), "byte-stable text");
        }
    }

    #[test]
    fn base36_round_trips_arbitrary_bytes_and_leading_zeros() {
        for input in [
            vec![],
            vec![0x00],
            vec![0x00, 0x00, 0x01],
            vec![0x01, 0x72, 0x00, 0x24],
            (0u8..=255).collect::<Vec<_>>(),
        ] {
            let encoded = base36_encode(&input);
            assert_eq!(base36_decode(&encoded).as_deref(), Some(input.as_slice()));
        }
    }

    #[test]
    fn parse_rejects_non_canonical_and_foreign_names() {
        for bad in ["bxyz", "", "kABC!"] {
            assert_eq!(
                IpnsName::parse(bad).unwrap_err().check(),
                "ipns-name-malformed",
                "must reject {bad:?}"
            );
        }
        // Valid base36 but a wrong (too short) CID layout.
        let short = format!("k{}", base36_encode(&[0x01, 0x72, 0x00]));
        assert_eq!(
            IpnsName::parse(&short).unwrap_err().check(),
            "ipns-name-malformed"
        );
    }

    #[test]
    fn parse_rejects_bad_edwards_point() {
        // Canonical prefix + a 32-byte digest that is not a valid compressed
        // Edwards point (found by search: y=2 has no matching x on the curve).
        let mut cid = super::CID_PREFIX.to_vec();
        let mut off_curve = [0u8; PUBLIC_LEN];
        off_curve[0] = 0x02;
        cid.extend_from_slice(&off_curve);
        let name = format!("k{}", base36_encode(&cid));
        assert_eq!(
            IpnsName::parse(&name).unwrap_err().check(),
            "ipns-name-malformed"
        );
    }

    #[test]
    fn distinct_keys_get_distinct_names() {
        assert_ne!(
            IpnsName::from_public_key(&verifier(1)).as_str().to_string(),
            IpnsName::from_public_key(&verifier(2)).as_str().to_string()
        );
    }
}
