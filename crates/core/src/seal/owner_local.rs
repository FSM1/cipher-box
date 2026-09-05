//! The owner-local sealed store: one structure for every durable store the
//! owner alone authors and reads (ADR 0006 in FSM1/cipher-box-next).
//!
//! Local durable state like the op record and the content-key blob, not a
//! published body — so it binds its own clear header rather than an
//! [`AadContext`](super::AadContext).
//!
//! HPKE **auth mode to self** under the enc subkey closes a blob across
//! accounts, and the shared `owner-local` structure tag keeps the family
//! distinct from every other structure sealed under that same key.
//!
//! The **store kind** is bound into the HPKE `info` and into the AAD, and never
//! rides the wire: the reader always knows which store it opened, so a blob
//! offered as the wrong kind is refused by the key schedule rather than by a
//! comparison — a decryption failure, not a parse failure.
//!
//! The body is opaque here — core seals the engine's encoded state and never
//! interprets it.
//!
//! What the structure does **not** buy: freshness. Nothing in the AAD counts, so
//! an earlier blob of the same kind replayed by the host opens as current state.
//! A kind whose contents are an authorization input carries a monotone
//! generation in its own body, against a high-water mark held where the host
//! cannot roll it back. The AAD binds no instance id either, so one kind is one
//! blob per owner.

use zeroize::Zeroizing;

use crate::codec::{Map, Value, decode, encode, encode_fixed_depth};
use crate::error::{CodecError, Malformed};
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_OWNER_LOCAL};
use crate::seal::body::{bytes_fixed, req};
use crate::suite::hpke::{self, ENC_LEN};
use crate::suite::secret::SECRET_LEN;
use crate::suite::x25519::X25519Secret;

/// The owner-local blob format version this build writes and can open. Carried
/// in the clear header *and* bound into the AAD, so rewriting the clear copy
/// fails the tag.
pub const OWNER_LOCAL_V: u64 = 1;

/// The common stem of every kind's HPKE `info` string. The full string is this
/// prefix followed by [`OwnerLocalKind::name`]; frozen in the KAT manifest.
pub const OWNER_LOCAL_HPKE_INFO_PREFIX: &[u8] = b"cipherbox/v2/owner-local/";

/// The durable stores that ride this structure. The kind is the domain
/// separator between them, so adding one extends [`OwnerLocalKind::ALL`] and the
/// KAT manifest before merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerLocalKind {
    /// The recipient's share bookmarks.
    ReceivedShares,
    /// The owner's imported contacts.
    ContactBook,
    /// The invite records conversion reads a link's permission and deadline
    /// from.
    InviteRecords,
    /// The pinned bytes a published prune or delete still owes the registry.
    RetireLedger,
    /// What a delete still owes once its unlink is live: the detached subtree's
    /// write-plane names, and the target's own retire debt.
    DoomedJournal,
    /// The scope roots a move out of a granted scope owes a scope-exit cut for,
    /// until each cut lands.
    ScopeExitDebt,
}

impl OwnerLocalKind {
    /// Every kind, in discriminator order. Frozen in the KAT manifest.
    pub const ALL: [Self; 6] = [
        Self::ReceivedShares,
        Self::ContactBook,
        Self::InviteRecords,
        Self::RetireLedger,
        Self::DoomedJournal,
        Self::ScopeExitDebt,
    ];

    /// The kind's stable name — the `info` suffix and the manifest key.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReceivedShares => "received-shares",
            Self::ContactBook => "contact-book",
            Self::InviteRecords => "invite-records",
            Self::RetireLedger => "retire-ledger",
            Self::DoomedJournal => "doomed-journal",
            Self::ScopeExitDebt => "scope-exit-debt",
        }
    }

    /// The kind's AAD discriminator byte. Assigned once and never reused.
    pub const fn discriminator(self) -> u8 {
        match self {
            Self::ReceivedShares => 0x01,
            Self::ContactBook => 0x02,
            Self::InviteRecords => 0x03,
            Self::RetireLedger => 0x04,
            Self::DoomedJournal => 0x05,
            Self::ScopeExitDebt => 0x06,
        }
    }

    /// The kind's HPKE `info` string: its key-schedule domain separator. This is
    /// what makes a cross-kind open fail the AEAD instead of a comparison.
    pub fn hpke_info(self) -> Vec<u8> {
        let mut info = OWNER_LOCAL_HPKE_INFO_PREFIX.to_vec();
        info.extend_from_slice(self.name().as_bytes());
        info
    }
}

/// The AAD inputs of an owner-local blob. Only [`Self::version`] rides the wire;
/// [`Self::kind`] is the caller's and [`Self::owner_tag`] is reconstructed from
/// the opening key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerLocalHeader {
    /// The format version the blob was written at, as declared.
    pub version: u64,
    /// The store the blob belongs to.
    pub kind: OwnerLocalKind,
    /// The owner's `enc-subkey` public half, verbatim.
    pub owner_tag: [u8; SECRET_LEN],
}

/// The AAD of an owner-local blob: its own clear header under the `cipherbox/v2`
/// domain separator, the `owner-local` structure tag, and the kind
/// discriminator. Public — the frozen layout, so the KAT generator pins it
/// directly.
pub fn owner_local_aad(header: &OwnerLocalHeader) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(header.version),
        Value::Unsigned(u64::from(STRUCT_TAG_OWNER_LOCAL)),
        Value::Unsigned(u64::from(header.kind.discriminator())),
        Value::Bytes(header.owner_tag.to_vec()),
    ]))
}

/// Seal `body` into a `kind` blob addressed to the owner's own enc subkey, with
/// that same key as the HPKE static sender. The owner tag is derived from
/// `owner_enc_secret`, so a blob can never carry a tag naming a key that does
/// not open it, and only the secret's holder can author one.
///
/// `ephemeral_scalar` must be **fresh per seal**: HPKE ephemeral reuse across
/// two seals under one recipient key and `info` is a confidentiality break
/// ([`hpke::hpke_seal`]).
pub fn seal_owner_local(
    owner_enc_secret: &X25519Secret,
    kind: OwnerLocalKind,
    ephemeral_scalar: &[u8; SECRET_LEN],
    body: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let owner_enc_pub = owner_enc_secret.public();
    let header = OwnerLocalHeader {
        version: OWNER_LOCAL_V,
        kind,
        owner_tag: owner_enc_pub.to_bytes(),
    };
    let sealed = hpke::hpke_seal_auth(
        owner_enc_secret,
        &owner_enc_pub,
        ephemeral_scalar,
        &kind.hpke_info(),
        &owner_local_aad(&header),
        body,
    );
    let mut m = Map::new();
    m.insert("ciphertext", Value::Bytes(sealed.ciphertext));
    m.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    m.insert("v", Value::Unsigned(header.version));
    encode(&Value::Map(m))
}

/// Open a `kind` blob sealed to `owner_enc_secret`, returning the opaque body.
///
/// The version gate runs before the AEAD: opening a future blob under this
/// build's body grammar would misread its intent. Every other refusal is
/// [`TrustViolation::HpkeOpenFailed`](crate::error::TrustViolation), including a
/// rewritten `v` — the version is the AAD — and a blob written under another
/// kind. The owner tag is rebuilt from the opening key rather than read off the
/// wire, so a blob another identity's key would open is unrepresentable rather
/// than compared away.
pub fn open_owner_local(
    owner_enc_secret: &X25519Secret,
    kind: OwnerLocalKind,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let value = decode(blob)?;
    let map = value.as_map()?;
    let owner_enc_pub = owner_enc_secret.public();
    let header = OwnerLocalHeader {
        version: req(map, "v")?.as_unsigned()?,
        kind,
        owner_tag: owner_enc_pub.to_bytes(),
    };
    if header.version != OWNER_LOCAL_V {
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
        &kind.hpke_info(),
        &owner_local_aad(&header),
        ciphertext,
    )?)
}

/// The three frame keys, exhaustive at [`OWNER_LOCAL_V`].
const FRAME_KEYS: [&str; 3] = ["ciphertext", "enc", "v"];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn secret(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; SECRET_LEN])
    }

    fn reframe(blob: &[u8], key: &str, value: Value) -> Vec<u8> {
        let decoded = decode(blob).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        map.insert(key, value);
        encode(&Value::Map(map)).unwrap()
    }

    /// An owner-local blob at this version, framed from parts.
    fn framed(enc: impl Into<Vec<u8>>, ciphertext: Vec<u8>) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(ciphertext));
        m.insert("enc", Value::Bytes(enc.into()));
        m.insert("v", Value::Unsigned(OWNER_LOCAL_V));
        encode(&Value::Map(m)).unwrap()
    }

    #[test]
    fn every_kind_round_trips_under_the_owners_enc_subkey() {
        let owner = secret(7);
        for kind in OwnerLocalKind::ALL {
            let blob = seal_owner_local(&owner, kind, &[1; SECRET_LEN], b"state").unwrap();
            let body = open_owner_local(&owner, kind, &blob).unwrap();
            assert_eq!(&body[..], b"state", "{}", kind.name());
        }
    }

    /// The claim the kind discriminator exists to make: separate `info` strings
    /// used to give this for free, so every ordered pair is checked.
    #[test]
    fn a_blob_sealed_under_one_kind_never_opens_under_another() {
        let owner = secret(8);
        for sealed_as in OwnerLocalKind::ALL {
            let blob = seal_owner_local(&owner, sealed_as, &[2; SECRET_LEN], b"state").unwrap();
            for opened_as in OwnerLocalKind::ALL {
                if opened_as == sealed_as {
                    continue;
                }
                assert_eq!(
                    open_owner_local(&owner, opened_as, &blob)
                        .unwrap_err()
                        .check(),
                    "hpke-open-failed",
                    "{} opened as {}: the key schedule must refuse it, not a comparison",
                    sealed_as.name(),
                    opened_as.name(),
                );
            }
        }
    }

    /// Every separation proof iterates [`OwnerLocalKind::ALL`], so the registry
    /// is only a guarantee while it is complete and injective. The match below
    /// is exhaustive: a new variant does not compile until it is placed here,
    /// and the position it claims must be the one `ALL` gives it.
    #[test]
    fn the_kind_registry_lists_every_kind_exactly_once() {
        let mut names = BTreeSet::new();
        let mut discriminators = BTreeSet::new();
        let mut infos = BTreeSet::new();
        for kind in OwnerLocalKind::ALL {
            let index = match kind {
                OwnerLocalKind::ReceivedShares => 0,
                OwnerLocalKind::ContactBook => 1,
                OwnerLocalKind::InviteRecords => 2,
                OwnerLocalKind::RetireLedger => 3,
                OwnerLocalKind::DoomedJournal => 4,
                OwnerLocalKind::ScopeExitDebt => 5,
            };
            assert_eq!(
                OwnerLocalKind::ALL[index],
                kind,
                "{} is not at its registry position",
                kind.name()
            );
            assert!(names.insert(kind.name()), "duplicate name {}", kind.name());
            assert!(
                discriminators.insert(kind.discriminator()),
                "duplicate discriminator {:#x}",
                kind.discriminator()
            );
            assert!(
                infos.insert(kind.hpke_info()),
                "duplicate info string for {}",
                kind.name()
            );
            assert_eq!(
                kind.discriminator() as usize,
                index + 1,
                "{} out of discriminator order",
                kind.name()
            );
        }
    }

    #[test]
    fn a_foreign_blob_never_opens() {
        let owner = secret(1);
        let kind = OwnerLocalKind::ReceivedShares;
        let blob = seal_owner_local(&owner, kind, &[3; SECRET_LEN], b"mine").unwrap();
        assert_eq!(
            open_owner_local(&secret(2), kind, &blob)
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_tampered_ciphertext_fails_closed() {
        let owner = secret(6);
        let kind = OwnerLocalKind::ContactBook;
        let blob = seal_owner_local(&owner, kind, &[7; SECRET_LEN], b"contacts").unwrap();
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
            open_owner_local(
                &owner,
                kind,
                &reframe(&blob, "ciphertext", Value::Bytes(ct))
            )
            .unwrap_err()
            .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn the_stored_blob_names_no_key_and_no_kind() {
        let owner = secret(20);
        let kind = OwnerLocalKind::InviteRecords;
        let blob = seal_owner_local(&owner, kind, &[21; SECRET_LEN], b"invites").unwrap();
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
        assert!(
            !blob
                .windows(kind.name().len())
                .any(|w| w == kind.name().as_bytes()),
            "the kind is a key-schedule input, not a wire field",
        );
    }

    #[test]
    fn a_forward_version_never_reaches_the_aead() {
        let owner = secret(11);
        let kind = OwnerLocalKind::ReceivedShares;
        let blob = seal_owner_local(&owner, kind, &[12; SECRET_LEN], b"state").unwrap();
        let future = reframe(&blob, "v", Value::Unsigned(OWNER_LOCAL_V + 1));
        assert_eq!(
            open_owner_local(&owner, kind, &future).unwrap_err().check(),
            "unsupported-record-version"
        );
    }

    #[test]
    fn an_unknown_field_at_this_version_is_malformed() {
        let owner = secret(13);
        let kind = OwnerLocalKind::ReceivedShares;
        let blob = seal_owner_local(&owner, kind, &[14; SECRET_LEN], b"state").unwrap();
        let extended = reframe(&blob, "extra", Value::Unsigned(1));
        assert_eq!(
            open_owner_local(&owner, kind, &extended)
                .unwrap_err()
                .check(),
            "unknown-record-field"
        );
    }

    #[test]
    fn a_blob_forged_from_the_public_owner_tag_never_opens() {
        let owner = secret(30);
        let kind = OwnerLocalKind::ContactBook;
        let forged = hpke::hpke_seal(
            &owner.public(),
            &[31; SECRET_LEN],
            &kind.hpke_info(),
            &owner_local_aad(&OwnerLocalHeader {
                version: OWNER_LOCAL_V,
                kind,
                owner_tag: owner.public().to_bytes(),
            }),
            b"attacker state",
        );

        assert_eq!(
            open_owner_local(&owner, kind, &framed(forged.enc, forged.ciphertext))
                .unwrap_err()
                .check(),
            "hpke-open-failed",
            "base mode is not sender-authenticated; auth mode must refuse it"
        );
    }

    /// The claim the `owner-local` tag and its info prefix exist to make.
    /// Re-framed rather than handed over whole, so the unknown-field check
    /// cannot fire and the key schedule is what refuses it.
    #[test]
    fn a_reframed_settings_record_fails_the_owner_local_key_schedule() {
        let owner = secret(40);
        let record = super::super::settings_record::seal_settings_record(
            &owner,
            &[41; SECRET_LEN],
            b"config",
        )
        .unwrap();
        let decoded = decode(&record).unwrap();
        let map = decoded.as_map().unwrap();
        let enc = map.get("enc").unwrap().as_bytes().unwrap().to_vec();
        let ciphertext = map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec();

        for kind in OwnerLocalKind::ALL {
            assert_eq!(
                open_owner_local(&owner, kind, &framed(enc.clone(), ciphertext.clone()))
                    .unwrap_err()
                    .check(),
                "hpke-open-failed",
                "{}",
                kind.name(),
            );
        }
    }

    /// The reverse of the transplant above: neither direction unifies.
    #[test]
    fn a_reframed_owner_local_blob_fails_the_settings_key_schedule() {
        let owner = secret(45);
        let blob = seal_owner_local(
            &owner,
            OwnerLocalKind::ReceivedShares,
            &[46; SECRET_LEN],
            b"state",
        )
        .unwrap();
        let decoded = decode(&blob).unwrap();
        let map = decoded.as_map().unwrap();
        let enc = map.get("enc").unwrap().as_bytes().unwrap().to_vec();
        let ciphertext = map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec();

        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(ciphertext));
        m.insert("enc", Value::Bytes(enc));
        m.insert(
            "v",
            Value::Unsigned(super::super::settings_record::SETTINGS_RECORD_V),
        );
        assert_eq!(
            super::super::settings_record::open_settings_record(
                &owner,
                &encode(&Value::Map(m)).unwrap()
            )
            .unwrap_err()
            .check(),
            "hpke-open-failed",
        );
    }

    #[test]
    fn a_truncated_blob_is_malformed_not_a_panic() {
        let owner = secret(3);
        let kind = OwnerLocalKind::ReceivedShares;
        let blob = seal_owner_local(&owner, kind, &[4; SECRET_LEN], b"state").unwrap();
        assert!(open_owner_local(&owner, kind, &blob[..blob.len() / 2]).is_err());
        assert!(open_owner_local(&owner, kind, b"").is_err());
    }

    #[test]
    fn a_short_enc_never_reaches_the_aead() {
        let owner = secret(9);
        let kind = OwnerLocalKind::ReceivedShares;
        let blob = seal_owner_local(&owner, kind, &[10; SECRET_LEN], b"state").unwrap();
        let short = reframe(&blob, "enc", Value::Bytes(vec![0; ENC_LEN - 1]));
        assert_eq!(
            open_owner_local(&owner, kind, &short).unwrap_err().check(),
            "invalid-field-length",
        );
    }

    #[test]
    fn a_missing_frame_field_is_malformed() {
        for missing in FRAME_KEYS {
            let owner = secret(5);
            let kind = OwnerLocalKind::ReceivedShares;
            let blob = seal_owner_local(&owner, kind, &[6; SECRET_LEN], b"state").unwrap();
            let decoded = decode(&blob).unwrap();
            let mut map = decoded.as_map().unwrap().clone();
            map.remove(missing);
            let reframed = encode(&Value::Map(map)).unwrap();
            assert_eq!(
                open_owner_local(&owner, kind, &reframed)
                    .unwrap_err()
                    .check(),
                "missing-field",
                "{missing}",
            );
        }
    }
}
