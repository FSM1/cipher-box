//! The vault settings record: `v || sealed(body)` (CONTEXT.md "Vault settings
//! record").
//!
//! Published at an IPNS name derived from the login secret and sealed
//! HPKE-to-self under the owner's `enc-subkey`, so the record fetch needs no
//! CipherBox infrastructure and runs before any vault resolve.
//!
//! The owner tag — the enc-subkey public half — is bound into the AAD but
//! **never serialized**, unlike the op record's, which is a local queue's
//! routing key. This record is published and its block is server-visible, and
//! the enc-subkey public half is otherwise disclosed only by out-of-band
//! contact-code exchange; emitting it would hand a zero-knowledge server a
//! durable `account → enc subkey` binding. Nothing is lost: a wrong opener
//! computes a different AAD and fails the tag.
//!
//! Auth mode, the enc subkey being both static sender and recipient, is
//! defence in depth behind the name's Ed25519 signature — base mode would let
//! anyone holding the owner's public enc half frame a body that opens, and
//! this body names endpoints the engine will later talk to.
//!
//! The body is opaque here — core seals the engine's config bytes and never
//! interprets them.

use zeroize::Zeroizing;

use crate::codec::{Map, Value, decode, encode, encode_fixed_depth};
use crate::error::{CodecError, Malformed};
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_SETTINGS_RECORD};
use crate::seal::body::{bytes_fixed, req};
use crate::suite::hpke::{self, ENC_LEN};
use crate::suite::x25519::X25519Secret;

/// The settings-record format version this build writes and can open. Carried
/// in the clear header *and* bound into the AAD, so rewriting the clear copy
/// fails the tag.
pub const SETTINGS_RECORD_V: u64 = 1;

/// The HPKE `info` string — the key-schedule domain separator, distinct from
/// the op-record's and the grant family's so structures sealed to the same enc
/// subkey are never mutually transplantable. Frozen in the KAT manifest.
pub const SETTINGS_RECORD_HPKE_INFO: &[u8] = b"cipherbox/v2/settings-record";

/// The AAD inputs of a vault settings record. Only [`Self::version`] rides the
/// wire; [`Self::owner_tag`] is reconstructed from the opening key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsRecordHeader {
    /// The format version the record was written at, as declared.
    pub version: u64,
    /// The owner's `enc-subkey` public half, verbatim.
    pub owner_tag: Vec<u8>,
}

/// The AAD of a settings record: its own clear header under the `cipherbox/v2`
/// domain separator and the `settings-record` structure tag. The tag is the
/// separator — the other enc-subkey structures are held apart by it and by their
/// own HPKE `info`. Public — the frozen layout, so the KAT generator pins it
/// directly.
pub fn settings_record_aad(header: &SettingsRecordHeader) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(header.version),
        Value::Unsigned(u64::from(STRUCT_TAG_SETTINGS_RECORD)),
        Value::Bytes(header.owner_tag.clone()),
    ]))
}

/// Seal `body` into a settings record addressed to the owner's own enc subkey,
/// with that same key as the HPKE static sender. The owner tag is derived from
/// `owner_enc_secret`, so a record can never carry a tag naming a key that does
/// not open it, and only the secret's holder can author one.
///
/// `ephemeral_scalar` must be **fresh per record**: HPKE ephemeral reuse across
/// two seals under one recipient key is a confidentiality break
/// ([`hpke::hpke_seal`]).
pub fn seal_settings_record(
    owner_enc_secret: &X25519Secret,
    ephemeral_scalar: &[u8; 32],
    body: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let owner_enc_pub = owner_enc_secret.public();
    let header = SettingsRecordHeader {
        version: SETTINGS_RECORD_V,
        owner_tag: owner_enc_pub.to_bytes().to_vec(),
    };
    let sealed = hpke::hpke_seal_auth(
        owner_enc_secret,
        &owner_enc_pub,
        ephemeral_scalar,
        SETTINGS_RECORD_HPKE_INFO,
        &settings_record_aad(&header),
        body,
    );
    let mut m = Map::new();
    m.insert("ciphertext", Value::Bytes(sealed.ciphertext));
    m.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    m.insert("v", Value::Unsigned(header.version));
    encode(&Value::Map(m))
}

/// Open a settings record sealed to `owner_enc_secret`, returning the opaque
/// body.
///
/// The version gate runs before the AEAD: opening a future record under this
/// build's body grammar would misread its intent. Every other refusal is
/// [`TrustViolation::HpkeOpenFailed`](crate::error::TrustViolation), including
/// a rewritten `v` — the version
/// is the AAD. The owner tag is rebuilt from the opening key rather than read
/// off the wire, so a record another identity's key would open is
/// unrepresentable rather than compared away.
pub fn open_settings_record(
    owner_enc_secret: &X25519Secret,
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let value = decode(record)?;
    let map = value.as_map()?;
    let owner_enc_pub = owner_enc_secret.public();
    let header = SettingsRecordHeader {
        version: req(map, "v")?.as_unsigned()?,
        owner_tag: owner_enc_pub.to_bytes().to_vec(),
    };
    if header.version != SETTINGS_RECORD_V {
        return Err(Malformed::UnsupportedRecordVersion {
            version: header.version,
        }
        .into());
    }
    if let Some((key, _)) = map
        .entries()
        .iter()
        .find(|(key, _)| !HEADER_KEYS.contains(&key.as_str()))
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
        SETTINGS_RECORD_HPKE_INFO,
        &settings_record_aad(&header),
        ciphertext,
    )?)
}

/// The three clear-header keys, exhaustive at [`SETTINGS_RECORD_V`].
const HEADER_KEYS: [&str; 3] = ["ciphertext", "enc", "v"];

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; 32])
    }

    fn reframe(record: &[u8], key: &str, value: Value) -> Vec<u8> {
        let decoded = decode(record).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        map.insert(key, value);
        encode(&Value::Map(map)).unwrap()
    }

    #[test]
    fn a_settings_record_round_trips_under_the_owners_enc_subkey() {
        let owner = secret(7);
        let record = seal_settings_record(&owner, &[1; 32], b"config bytes").unwrap();
        let body = open_settings_record(&owner, &record).unwrap();
        assert_eq!(&body[..], b"config bytes");
    }

    #[test]
    fn a_foreign_record_never_opens() {
        let owner = secret(1);
        let record = seal_settings_record(&owner, &[3; 32], b"mine").unwrap();
        assert_eq!(
            open_settings_record(&secret(2), &record)
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_tampered_ciphertext_fails_closed() {
        let owner = secret(6);
        let record = seal_settings_record(&owner, &[7; 32], b"config").unwrap();
        let decoded = decode(&record).unwrap();
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
            open_settings_record(&owner, &reframe(&record, "ciphertext", Value::Bytes(ct)))
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    /// The published block must not carry the owner's enc-subkey public half:
    /// it is server-visible, and the grant plane blinds that same identifier.
    #[test]
    fn the_wire_record_names_no_key() {
        let owner = secret(20);
        let record = seal_settings_record(&owner, &[21; 32], b"config").unwrap();
        let decoded = decode(&record).unwrap();
        let mut keys: Vec<&str> = decoded
            .as_map()
            .unwrap()
            .entries()
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        keys.sort_unstable();
        let mut expected = HEADER_KEYS;
        expected.sort_unstable();
        assert_eq!(
            keys, expected,
            "encode/decode key-set symmetry: a key the reader refuses is never emitted",
        );
        let tag = owner.public().to_bytes();
        assert!(
            !record.windows(tag.len()).any(|w| w == tag),
            "the enc-subkey public half never appears on the wire",
        );
    }

    #[test]
    fn a_forward_version_never_reaches_the_aead() {
        let owner = secret(11);
        let record = seal_settings_record(&owner, &[12; 32], b"config").unwrap();
        let future = reframe(&record, "v", Value::Unsigned(SETTINGS_RECORD_V + 1));
        assert_eq!(
            open_settings_record(&owner, &future).unwrap_err().check(),
            "unsupported-record-version"
        );
    }

    #[test]
    fn an_unknown_field_at_this_version_is_malformed() {
        let owner = secret(13);
        let record = seal_settings_record(&owner, &[14; 32], b"config").unwrap();
        let extended = reframe(&record, "extra", Value::Unsigned(1));
        assert_eq!(
            open_settings_record(&owner, &extended).unwrap_err().check(),
            "unknown-record-field"
        );
    }

    #[test]
    fn a_record_forged_from_the_public_owner_tag_never_opens() {
        let owner = secret(30);
        let forged = hpke::hpke_seal(
            &owner.public(),
            &[31; 32],
            SETTINGS_RECORD_HPKE_INFO,
            &settings_record_aad(&SettingsRecordHeader {
                version: SETTINGS_RECORD_V,
                owner_tag: owner.public().to_bytes().to_vec(),
            }),
            b"http://attacker.example",
        );
        let record = framed(forged.enc, forged.ciphertext);

        assert_eq!(
            open_settings_record(&owner, &record).unwrap_err().check(),
            "hpke-open-failed",
            "base mode is not sender-authenticated; auth mode must refuse it"
        );
    }

    /// The claim the `settings-record` tag and its own HPKE `info` string
    /// exist to make. Re-framed rather than handed over whole, so the
    /// unknown-field check cannot fire and the key schedule is what refuses it.
    #[test]
    fn a_reframed_op_record_ciphertext_fails_the_settings_key_schedule() {
        let owner = secret(40);
        let op =
            super::super::op_record::seal_op_record(&owner, &[41; 32], None, b"intent").unwrap();
        let decoded = decode(&op).unwrap();
        let map = decoded.as_map().unwrap();
        let enc = map.get("enc").unwrap().as_bytes().unwrap().to_vec();
        let ciphertext = map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec();

        assert_eq!(
            open_settings_record(&owner, &framed(enc, ciphertext))
                .unwrap_err()
                .check(),
            "hpke-open-failed",
        );
    }

    #[test]
    fn a_truncated_record_is_malformed_not_a_panic() {
        let owner = secret(3);
        let record = seal_settings_record(&owner, &[4; 32], b"config").unwrap();
        assert!(open_settings_record(&owner, &record[..record.len() / 2]).is_err());
        assert!(open_settings_record(&owner, b"").is_err());
    }

    #[test]
    fn a_short_enc_never_reaches_the_aead() {
        let owner = secret(9);
        let record = seal_settings_record(&owner, &[10; 32], b"config").unwrap();
        let short = reframe(&record, "enc", Value::Bytes(vec![0; ENC_LEN - 1]));
        assert_eq!(
            open_settings_record(&owner, &short).unwrap_err().check(),
            "invalid-field-length",
        );
    }

    #[test]
    fn a_missing_clear_field_is_malformed() {
        for missing in HEADER_KEYS {
            let owner = secret(5);
            let record = seal_settings_record(&owner, &[6; 32], b"config").unwrap();
            let decoded = decode(&record).unwrap();
            let mut map = decoded.as_map().unwrap().clone();
            map.remove(missing);
            let framed = encode(&Value::Map(map)).unwrap();
            assert_eq!(
                open_settings_record(&owner, &framed).unwrap_err().check(),
                "missing-field",
                "{missing}",
            );
        }
    }

    /// A settings record at this version, framed from parts.
    fn framed(enc: impl Into<Vec<u8>>, ciphertext: Vec<u8>) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(ciphertext));
        m.insert("enc", Value::Bytes(enc.into()));
        m.insert("v", Value::Unsigned(SETTINGS_RECORD_V));
        encode(&Value::Map(m)).unwrap()
    }
}
