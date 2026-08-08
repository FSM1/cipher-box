//! The received-shares blob: the recipient's share bookmarks sealed to their
//! own enc subkey (blueprint/engine.md "Grants and ledger — Accept flow").
//!
//! Local durable state like the op record and the content-key blob, not a
//! published body — so it binds its own clear header rather than an
//! [`AadContext`](super::AadContext). Each bookmark carries the scope's stable
//! `pointerReadKey`, which nothing re-derives once the mailbox item that
//! delivered it is acked, so this is the durable carrier of secret material and
//! never a cache.
//!
//! HPKE **auth mode to self** under the enc subkey closes the blob across
//! accounts; its own structure tag and `info` string keep it distinct from every
//! other structure sealed under that same key.
//!
//! The body is opaque here — core seals the engine's encoded list and never
//! interprets it.

use zeroize::Zeroizing;

use crate::codec::{Map, Value, decode, encode, encode_fixed_depth};
use crate::error::{CodecError, Malformed};
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_RECEIVED_SHARES};
use crate::seal::body::{bytes_fixed, req};
use crate::suite::hpke::{self, ENC_LEN};
use crate::suite::x25519::X25519Secret;

/// The received-shares blob format version this build writes and can open.
/// Carried in the clear header *and* bound into the AAD, so rewriting the clear
/// copy fails the tag.
pub const RECEIVED_SHARES_V: u64 = 1;

/// The HPKE `info` string — the key-schedule domain separator, distinct from the
/// settings record's, the op record's, and the grant family's so structures
/// sealed to the same enc subkey are never mutually transplantable. Frozen in
/// the KAT manifest.
pub const RECEIVED_SHARES_HPKE_INFO: &[u8] = b"cipherbox/v2/received-shares";

/// The AAD inputs of a received-shares blob. Only [`Self::version`] rides the
/// wire; [`Self::owner_tag`] is reconstructed from the opening key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSharesHeader {
    /// The format version the blob was written at, as declared.
    pub version: u64,
    /// The owner's `enc-subkey` public half, verbatim.
    pub owner_tag: Vec<u8>,
}

/// The AAD of a received-shares blob: its own clear header under the
/// `cipherbox/v2` domain separator and the `received-shares` structure tag.
/// Public — the frozen layout, so the KAT generator pins it directly.
pub fn received_shares_aad(header: &ReceivedSharesHeader) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(header.version),
        Value::Unsigned(u64::from(STRUCT_TAG_RECEIVED_SHARES)),
        Value::Bytes(header.owner_tag.clone()),
    ]))
}

/// Seal `body` into a received-shares blob addressed to the owner's own enc
/// subkey, with that same key as the HPKE static sender. The owner tag is
/// derived from `owner_enc_secret`, so a blob can never carry a tag naming a key
/// that does not open it, and only the secret's holder can author one.
///
/// `ephemeral_scalar` must be **fresh per seal**: HPKE ephemeral reuse across
/// two seals under one recipient key is a confidentiality break
/// ([`hpke::hpke_seal`]).
pub fn seal_received_shares(
    owner_enc_secret: &X25519Secret,
    ephemeral_scalar: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let owner_enc_pub = owner_enc_secret.public();
    let header = ReceivedSharesHeader {
        version: RECEIVED_SHARES_V,
        owner_tag: owner_enc_pub.to_bytes().to_vec(),
    };
    let sealed = hpke::hpke_seal_auth(
        owner_enc_secret,
        &owner_enc_pub,
        ephemeral_scalar,
        RECEIVED_SHARES_HPKE_INFO,
        &received_shares_aad(&header),
        body,
    );
    let mut m = Map::new();
    m.insert("ciphertext", Value::Bytes(sealed.ciphertext));
    m.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    m.insert("v", Value::Unsigned(header.version));
    encode(&Value::Map(m))
}

/// Open a received-shares blob sealed to `owner_enc_secret`, returning the
/// opaque body.
///
/// The version gate runs before the AEAD: opening a future blob under this
/// build's body grammar would misread its intent. Every other refusal is
/// [`TrustViolation::HpkeOpenFailed`](crate::error::TrustViolation), including a
/// rewritten `v` — the version is the AAD. The owner tag is rebuilt from the
/// opening key rather than read off the wire, so a blob another identity's key
/// would open is unrepresentable rather than compared away.
pub fn open_received_shares(
    owner_enc_secret: &X25519Secret,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let value = decode(blob)?;
    let map = value.as_map()?;
    let owner_enc_pub = owner_enc_secret.public();
    let header = ReceivedSharesHeader {
        version: req(map, "v")?.as_unsigned()?,
        owner_tag: owner_enc_pub.to_bytes().to_vec(),
    };
    if header.version != RECEIVED_SHARES_V {
        return Err(Malformed::UnsupportedRecordVersion {
            version: header.version,
        }
        .into());
    }
    if let Some((key, _)) = map
        .entries()
        .iter()
        .find(|(key, _)| !FRAME_KEYS.contains(&key.as_str()))
    {
        return Err(Malformed::UnknownRecordField { key: key.clone() }.into());
    }
    let enc = bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?;
    let ciphertext = req(map, "ciphertext")?.as_bytes()?;
    // Sender = recipient: the caller's own key, not the declared tag.
    Ok(hpke::hpke_open_auth(
        owner_enc_secret,
        &owner_enc_pub,
        &enc,
        RECEIVED_SHARES_HPKE_INFO,
        &received_shares_aad(&header),
        ciphertext,
    )?)
}

/// The three frame keys, exhaustive at [`RECEIVED_SHARES_V`].
const FRAME_KEYS: [&str; 3] = ["ciphertext", "enc", "v"];

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; 32])
    }

    fn reframe(blob: &[u8], key: &str, value: Value) -> Vec<u8> {
        let decoded = decode(blob).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        map.insert(key, value);
        encode(&Value::Map(map)).unwrap()
    }

    /// A received-shares blob at this version, framed from parts.
    fn framed(enc: impl Into<Vec<u8>>, ciphertext: Vec<u8>) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(ciphertext));
        m.insert("enc", Value::Bytes(enc.into()));
        m.insert("v", Value::Unsigned(RECEIVED_SHARES_V));
        encode(&Value::Map(m)).unwrap()
    }

    #[test]
    fn a_received_shares_blob_round_trips_under_the_owners_enc_subkey() {
        let owner = secret(7);
        let blob = seal_received_shares(&owner, &[1; 32], b"share list").unwrap();
        let body = open_received_shares(&owner, &blob).unwrap();
        assert_eq!(&body[..], b"share list");
    }

    #[test]
    fn a_foreign_blob_never_opens() {
        let owner = secret(1);
        let blob = seal_received_shares(&owner, &[3; 32], b"mine").unwrap();
        assert_eq!(
            open_received_shares(&secret(2), &blob).unwrap_err().check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_tampered_ciphertext_fails_closed() {
        let owner = secret(6);
        let blob = seal_received_shares(&owner, &[7; 32], b"shares").unwrap();
        let decoded = decode(&blob).unwrap();
        let mut ct = decoded
            .as_map()
            .unwrap()
            .get("ciphertext")
            .unwrap()
            .as_bytes()
            .unwrap()
            .to_vec();
        ct[0] ^= 1;
        assert_eq!(
            open_received_shares(&owner, &reframe(&blob, "ciphertext", Value::Bytes(ct)))
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    /// The blob holds `pointerReadKey` material for every bookmarked scope, so
    /// the owner's enc-subkey public half must not sit beside it in host storage
    /// naming whose keys they are.
    #[test]
    fn the_stored_blob_names_no_key() {
        let owner = secret(20);
        let blob = seal_received_shares(&owner, &[21; 32], b"shares").unwrap();
        let decoded = decode(&blob).unwrap();
        let mut keys: Vec<&str> = decoded
            .as_map()
            .unwrap()
            .entries()
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        keys.sort_unstable();
        let mut expected = FRAME_KEYS;
        expected.sort_unstable();
        assert_eq!(
            keys, expected,
            "encode/decode key-set symmetry: a key the reader refuses is never emitted",
        );
        let tag = owner.public().to_bytes();
        assert!(
            !blob.windows(tag.len()).any(|w| w == tag),
            "the enc-subkey public half never appears in the stored blob",
        );
    }

    #[test]
    fn a_forward_version_never_reaches_the_aead() {
        let owner = secret(11);
        let blob = seal_received_shares(&owner, &[12; 32], b"shares").unwrap();
        let future = reframe(&blob, "v", Value::Unsigned(RECEIVED_SHARES_V + 1));
        assert_eq!(
            open_received_shares(&owner, &future).unwrap_err().check(),
            "unsupported-record-version"
        );
    }

    #[test]
    fn an_unknown_field_at_this_version_is_malformed() {
        let owner = secret(13);
        let blob = seal_received_shares(&owner, &[14; 32], b"shares").unwrap();
        let extended = reframe(&blob, "extra", Value::Unsigned(1));
        assert_eq!(
            open_received_shares(&owner, &extended).unwrap_err().check(),
            "unknown-record-field"
        );
    }

    #[test]
    fn a_blob_forged_from_the_public_owner_tag_never_opens() {
        let owner = secret(30);
        let forged = hpke::hpke_seal(
            &owner.public(),
            &[31; 32],
            RECEIVED_SHARES_HPKE_INFO,
            &received_shares_aad(&ReceivedSharesHeader {
                version: RECEIVED_SHARES_V,
                owner_tag: owner.public().to_bytes().to_vec(),
            }),
            b"attacker shares",
        );

        assert_eq!(
            open_received_shares(&owner, &framed(forged.enc, forged.ciphertext))
                .unwrap_err()
                .check(),
            "hpke-open-failed",
            "base mode is not sender-authenticated; auth mode must refuse it"
        );
    }

    /// The claim the `received-shares` tag and its own HPKE `info` string exist
    /// to make. Re-framed rather than handed over whole, so the unknown-field
    /// check cannot fire and the key schedule is what refuses it.
    #[test]
    fn a_reframed_settings_record_fails_the_received_shares_key_schedule() {
        let owner = secret(40);
        let record =
            super::super::settings_record::seal_settings_record(&owner, &[41; 32], b"config")
                .unwrap();
        let decoded = decode(&record).unwrap();
        let map = decoded.as_map().unwrap();
        let enc = map.get("enc").unwrap().as_bytes().unwrap().to_vec();
        let ciphertext = map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec();

        assert_eq!(
            open_received_shares(&owner, &framed(enc, ciphertext))
                .unwrap_err()
                .check(),
            "hpke-open-failed",
        );
    }

    #[test]
    fn a_truncated_blob_is_malformed_not_a_panic() {
        let owner = secret(3);
        let blob = seal_received_shares(&owner, &[4; 32], b"shares").unwrap();
        assert!(open_received_shares(&owner, &blob[..blob.len() / 2]).is_err());
        assert!(open_received_shares(&owner, b"").is_err());
    }

    #[test]
    fn a_short_enc_never_reaches_the_aead() {
        let owner = secret(9);
        let blob = seal_received_shares(&owner, &[10; 32], b"shares").unwrap();
        let short = reframe(&blob, "enc", Value::Bytes(vec![0; ENC_LEN - 1]));
        assert_eq!(
            open_received_shares(&owner, &short).unwrap_err().check(),
            "invalid-field-length",
        );
    }

    #[test]
    fn a_missing_frame_field_is_malformed() {
        for missing in FRAME_KEYS {
            let owner = secret(5);
            let blob = seal_received_shares(&owner, &[6; 32], b"shares").unwrap();
            let decoded = decode(&blob).unwrap();
            let mut map = decoded.as_map().unwrap().clone();
            map.remove(missing);
            let reframed = encode(&Value::Map(map)).unwrap();
            assert_eq!(
                open_received_shares(&owner, &reframed).unwrap_err().check(),
                "missing-field",
                "{missing}",
            );
        }
    }
}
