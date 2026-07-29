//! The vault settings record: `v || ownerTag || sealed(body)` (CONTEXT.md
//! "Vault settings record").
//!
//! Published at an IPNS name derived from the login secret and sealed
//! HPKE-to-self under the owner's `enc-subkey`, so it resolves at cold start
//! with no CipherBox infrastructure and before any vault resolve.
//!
//! The seal is HPKE **auth mode**, the enc subkey being both static sender and
//! recipient: the recipient half is public by construction and stamped in the
//! clear beside the ciphertext, so base mode would let anyone who has seen the
//! owner's tag frame a settings body that opens — and this body names the
//! endpoints the engine will later talk to.
//!
//! The body is opaque here — core seals the engine's config bytes and never
//! interprets them.

use zeroize::Zeroizing;

use crate::codec::{Map, Value, decode, encode, encode_fixed_depth};
use crate::error::{CodecError, Malformed, TrustViolation};
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

/// The clear header of a vault settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsRecordHeader {
    /// The format version the record was written at, as declared.
    pub version: u64,
    /// The owner's `enc-subkey` public half, verbatim.
    pub owner_tag: Vec<u8>,
}

/// The AAD of a settings record: its own clear header under the `cipherbox/v2`
/// domain separator and the `settings-record` structure tag. A four-element
/// array, structurally non-unifiable with the op record's five and the grant
/// family's six. Public — the frozen layout, so the KAT generator pins it
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
    m.insert("ownerTag", Value::Bytes(header.owner_tag));
    m.insert("v", Value::Unsigned(header.version));
    encode(&Value::Map(m))
}

/// Open a settings record sealed to `owner_enc_secret`, returning the opaque
/// body.
///
/// The version gate runs before the AEAD: opening a future record under this
/// build's body grammar would misread its intent. Fails closed with
/// [`Malformed::UnsupportedRecordVersion`] on a version this build does not
/// implement, and with [`TrustViolation::HpkeOpenFailed`] when the record is
/// another identity's, tampered, forged by a writer who lacked the enc secret,
/// or carries a rewritten header — the header is the AAD, so it is
/// authenticated rather than merely present.
///
/// The declared `ownerTag` is re-bound to the key that opens the record, so the
/// encoder's "a record can never carry a tag naming a key that does not open
/// it" invariant is re-established here rather than assumed from caller
/// ordering (AGENTS.md rule 8).
pub fn open_settings_record(
    owner_enc_secret: &X25519Secret,
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let value = decode(record)?;
    let map = value.as_map()?;
    let unknown_field = map
        .entries()
        .iter()
        .find(|(key, _)| !HEADER_KEYS.contains(&key.as_str()))
        .map(|(key, _)| key.clone());
    let header = SettingsRecordHeader {
        version: req(map, "v")?.as_unsigned()?,
        owner_tag: req(map, "ownerTag")?.as_bytes()?.to_vec(),
    };
    if header.version != SETTINGS_RECORD_V {
        return Err(Malformed::UnsupportedRecordVersion {
            version: header.version,
        }
        .into());
    }
    if let Some(key) = unknown_field {
        return Err(Malformed::UnknownRecordField { key }.into());
    }
    let owner_enc_pub = owner_enc_secret.public();
    if header.owner_tag != owner_enc_pub.to_bytes() {
        return Err(TrustViolation::HpkeOpenFailed.into());
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

/// The four clear-header keys, exhaustive at [`SETTINGS_RECORD_V`].
const HEADER_KEYS: [&str; 4] = ["ciphertext", "enc", "ownerTag", "v"];

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

    #[test]
    fn a_tag_naming_a_key_that_does_not_open_the_record_is_refused() {
        // The encoder cannot emit this — it derives the tag from the recipient.
        let owner = secret(20);
        let record = seal_settings_record(&owner, &[21; 32], b"config").unwrap();
        let lying = reframe(
            &record,
            "ownerTag",
            Value::Bytes(secret(22).public().to_bytes().to_vec()),
        );
        assert_eq!(
            open_settings_record(&owner, &lying).unwrap_err().check(),
            "hpke-open-failed"
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
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(forged.ciphertext));
        m.insert("enc", Value::Bytes(forged.enc.to_vec()));
        m.insert("ownerTag", Value::Bytes(owner.public().to_bytes().to_vec()));
        m.insert("v", Value::Unsigned(SETTINGS_RECORD_V));
        let record = encode(&Value::Map(m)).unwrap();

        assert_eq!(
            open_settings_record(&owner, &record).unwrap_err().check(),
            "hpke-open-failed",
            "base mode is not sender-authenticated; auth mode must refuse it"
        );
    }

    #[test]
    fn an_op_record_body_is_not_openable_as_a_settings_record() {
        let owner = secret(40);
        let op =
            super::super::op_record::seal_op_record(&owner, &[41; 32], None, b"intent").unwrap();
        // Same clear framing except the extra contentRootCid key; the info
        // string and AAD arity keep the families apart regardless.
        assert!(open_settings_record(&owner, &op).is_err());
    }

    #[test]
    fn a_truncated_record_is_malformed_not_a_panic() {
        let owner = secret(3);
        let record = seal_settings_record(&owner, &[4; 32], b"config").unwrap();
        assert!(open_settings_record(&owner, &record[..record.len() / 2]).is_err());
        assert!(open_settings_record(&owner, b"").is_err());
    }

    #[test]
    fn a_missing_owner_tag_is_malformed() {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(vec![0; 16]));
        m.insert("enc", Value::Bytes(vec![0; ENC_LEN]));
        m.insert("v", Value::Unsigned(SETTINGS_RECORD_V));
        let record = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            open_settings_record(&secret(5), &record)
                .unwrap_err()
                .check(),
            "missing-field"
        );
    }
}
