//! The owner's durable record of the invite links it minted — what lets a link
//! minted in one session be converted or revoked in the next.
//!
//! [`convert_invite_claim`](super::convert_invite_claim) and
//! [`revoke_invite_link`](super::revoke_invite_link) both take a
//! [`RecordedInvite`] back as input, and nothing in a resolved record marks a
//! row as an invite, so this store is the owner's authority over its own links
//! rather than a cache of published state.
//!
//! It is therefore sealed HPKE-to-self under the session's `enc-subkey`
//! (`owner-local`, kind `invite-records`; ADR 0006) rather than written in the
//! clear. Conversion matches a claim's sender against the recorded
//! `ephemeralIdentityPk` and the tag binds only the **encryption** half, so a
//! party who could author a record would pair a real link's `ephemeralEncPk`
//! with an identity key it holds and drive the owner into minting a genuine
//! grant at that link's committed permission. The recorded deadline is the
//! authority for expiry on the same rule.
//!
//! What the seal does *not* buy, because the structure carries no monotone
//! generation: a host replaying an earlier sealed set restores a deadline the
//! owner has since shortened, and dropping the stored key entirely reads as an
//! owner who minted nothing — leaving a live commitment entry no
//! [`revoke_invite_link`](super::revoke_invite_link) call can name, since the
//! cut is derived from the record rather than looked up by tag. The
//! owner-signed commitment caps both: conversion reads the permission there and
//! treats absence as revocation, and honours the published deadline as a
//! further restriction. Closing them needs a monotone generation held where the
//! host cannot roll it back.
//!
//! Like its siblings it rides the staging store's opaque key space, on the
//! [`RetireLedger`](crate::seams::RetireLedger) shape.

use core::cell::RefCell;
use core::fmt;

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::error::CodecError;
use cipherbox_core::seal::{OwnerLocalKind, open_owner_local, seal_owner_local};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::entropy::{Entropy, fresh_ephemeral};
use crate::seams::{SeamError, SeamResult, StagingStore, UnixMillis};
use crate::sync::owner_scoped_key;

use super::accept::{TooLong, fixed, reject_unknown, req, within};
use super::invite::RecordedInvite;

/// The staging-key prefix the invite records are stored under, scoped per
/// identity by [`owner_scoped_key`]. `is_bookkeeping` treats the whole prefix as
/// referenced.
///
/// Kept short: the desktop store spells a staging key as a hex filename, twice
/// its byte length, inside Windows' whole-path budget.
pub const INVITE_RECORDS_PREFIX: &[u8] = b"cbx/iv/";

/// The stored-body grammar version this build writes and can read.
const INVITE_RECORDS_V: u64 = 1;

/// The frozen bound on recorded links, enforced release-active in both codec
/// directions (AGENTS.md rule 8). One record per live link across every scope
/// the owner has invited to; it bounds reader CPU and the staging budget alike.
pub(crate) const MAX_INVITE_RECORDS: usize = 1024;

/// Why encoding or decoding a stored record set failed.
///
/// Engine-owned rather than a bare [`CodecError`] so a check this format needs
/// does not extend core's frozen `Malformed` registry, whose names the KAT
/// manifest pins.
#[derive(Debug)]
enum InviteRecordsCodecError {
    /// The det-CBOR framing was malformed.
    Codec(CodecError),
    /// Two records under one tag: no defined authority for that link's
    /// permission or deadline, refused in both directions (AGENTS.md rule 8).
    DuplicateTag,
    /// A recorded deadline of `0`. `mint_invite_grant` refuses one
    /// ([`InviteError::InvalidExpiry`](super::InviteError::InvalidExpiry)), so
    /// reading it as "no deadline" would resurrect a link the mint never made.
    ZeroDeadline,
    /// A set written at a grammar version this build does not read. Never
    /// treated as empty: the links are there, this build cannot read them.
    UnsupportedVersion { version: u64 },
    /// A collection or field past its frozen bound.
    TooLong(TooLong),
}

impl fmt::Display for InviteRecordsCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteRecordsCodecError::Codec(e) => write!(f, "codec: {e}"),
            InviteRecordsCodecError::DuplicateTag => f.write_str("names one tag twice"),
            InviteRecordsCodecError::ZeroDeadline => f.write_str("records a zero deadline"),
            InviteRecordsCodecError::UnsupportedVersion { version } => {
                write!(f, "is at version {version}, which is not readable")
            }
            InviteRecordsCodecError::TooLong(e) => write!(f, "{e}"),
        }
    }
}

impl From<TooLong> for InviteRecordsCodecError {
    fn from(e: TooLong) -> Self {
        InviteRecordsCodecError::TooLong(e)
    }
}

impl<E: Into<CodecError>> From<E> for InviteRecordsCodecError {
    fn from(e: E) -> Self {
        InviteRecordsCodecError::Codec(e.into())
    }
}

/// Durable persistence for the owner's minted invite links.
///
/// Whole-list replacement, like the received-shares store: the caller's list is
/// the authority, so a revoked link is dropped by persisting the list without
/// it.
pub trait InviteStore {
    /// Durably persist the whole set of recorded links.
    async fn persist(&self, links: &[RecordedInvite]) -> SeamResult<()>;

    /// The persisted records, or an empty set when the backing holds no entry
    /// at all — the module header states what a dropped entry costs.
    ///
    /// Fail-closed on an entry it cannot read: a link's fragment is already in
    /// a holder's hands, so a stored set this build cannot open is
    /// unrecoverable authority, and reporting it as empty would let the next
    /// [`persist`](Self::persist) overwrite every link behind it.
    async fn load(&self) -> SeamResult<Vec<RecordedInvite>>;
}

/// The invite store the engine ships over a host's [`StagingStore`].
///
/// One staging key holds the whole set; the replacement is failure-atomic at
/// the seam ([`StagingStore::put_staged_bytes`]).
pub struct StagingInviteStore<'a, St, E> {
    staging: &'a St,
    enc_secret: &'a X25519Secret,
    entropy: &'a RefCell<E>,
    staging_key: Vec<u8>,
}

impl<'a, St: StagingStore, E: Entropy> StagingInviteStore<'a, St, E> {
    /// Wraps a staging store as the invite store for one session.
    pub fn new(staging: &'a St, enc_secret: &'a X25519Secret, entropy: &'a RefCell<E>) -> Self {
        Self {
            staging,
            enc_secret,
            entropy,
            staging_key: owner_scoped_key(INVITE_RECORDS_PREFIX, enc_secret),
        }
    }

    /// The staging key this identity's records occupy — the entry under
    /// [`INVITE_RECORDS_PREFIX`] that orphan GC must treat as referenced.
    pub fn staging_key(&self) -> &[u8] {
        &self.staging_key
    }
}

impl<St: StagingStore, E: Entropy> InviteStore for StagingInviteStore<'_, St, E> {
    async fn persist(&self, links: &[RecordedInvite]) -> SeamResult<()> {
        let body = encode_records(links)
            .map_err(|e| SeamError::new(format!("invite records encode failed: {e}")))?;
        let ephemeral = fresh_ephemeral(&mut *self.entropy.borrow_mut())
            .map_err(|e| SeamError::new(format!("invite records: {}", e.message())))?;
        let blob = seal_owner_local(
            self.enc_secret,
            OwnerLocalKind::InviteRecords,
            &ephemeral,
            &body,
        )
        .map_err(|e| SeamError::new(format!("invite records seal failed: {e}")))?;
        self.staging
            .put_staged_bytes(self.staging_key(), &blob)
            .await
    }

    async fn load(&self) -> SeamResult<Vec<RecordedInvite>> {
        let Some(blob) = self.staging.staged_bytes(self.staging_key()).await? else {
            return Ok(Vec::new());
        };
        let body = open_owner_local(self.enc_secret, OwnerLocalKind::InviteRecords, &blob)
            .map_err(|_| SeamError::new("invite records: the stored set did not open"))?;
        decode_records(&body).map_err(|e| {
            SeamError::new(format!(
                "invite records: the stored set did not decode: {e}"
            ))
        })
    }
}

/// Encode the durable record set to det-CBOR, records in tag order so one set
/// has one spelling.
///
/// Rejects the bound, a duplicate tag and a zero deadline release-active — the
/// three invariants [`decode_records`] hard-rejects (AGENTS.md rule 8). A zero
/// deadline is `mint_invite_grant`'s
/// [`InviteError::InvalidExpiry`](super::InviteError::InvalidExpiry): storing
/// one would durably record a link the reader must refuse to distinguish from
/// "no deadline".
fn encode_records(links: &[RecordedInvite]) -> Result<Vec<u8>, InviteRecordsCodecError> {
    within("links", links.len(), MAX_INVITE_RECORDS)?;
    let mut sorted: Vec<&RecordedInvite> = links.iter().collect();
    sorted.sort_by_key(|link| link.tag);
    if sorted.windows(2).any(|pair| pair[0].tag == pair[1].tag) {
        return Err(InviteRecordsCodecError::DuplicateTag);
    }
    let mut encoded = Vec::with_capacity(sorted.len());
    for link in sorted {
        let mut m = Map::new();
        m.insert(
            "ephemeralEncPk",
            Value::Bytes(link.ephemeral_enc_pk.to_vec()),
        );
        m.insert(
            "ephemeralIdentityPk",
            Value::Bytes(link.ephemeral_identity_pk.to_vec()),
        );
        if let Some(deadline) = link.expires_at {
            if deadline.0 == 0 {
                return Err(InviteRecordsCodecError::ZeroDeadline);
            }
            m.insert("expiresAt", Value::Unsigned(deadline.0));
        }
        m.insert("tag", Value::Bytes(link.tag.to_vec()));
        encoded.push(Value::Map(m));
    }
    let mut body = Map::new();
    body.insert("links", Value::Array(encoded));
    body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
    Ok(encode_fixed_depth(&Value::Map(body)))
}

/// Decode a stored record set (strict det-CBOR).
///
/// A missing or mistyped field, an unknown key, an unreadable version, a bound
/// breach, a duplicate tag or a zero deadline is an error — never a partial set,
/// which would silently un-record links the owner still holds.
fn decode_records(bytes: &[u8]) -> Result<Vec<RecordedInvite>, InviteRecordsCodecError> {
    let tree = decode(bytes)?;
    let map = tree.as_map()?;
    reject_unknown(map, &["links", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != INVITE_RECORDS_V {
        return Err(InviteRecordsCodecError::UnsupportedVersion { version });
    }
    let raw = req(map, "links")?.as_array()?;
    within("links", raw.len(), MAX_INVITE_RECORDS)?;
    let mut links: Vec<RecordedInvite> = Vec::with_capacity(raw.len());
    for item in raw {
        let record = item.as_map()?;
        reject_unknown(
            record,
            &["ephemeralEncPk", "ephemeralIdentityPk", "expiresAt", "tag"],
        )?;
        let expires_at = match record.get("expiresAt") {
            None => None,
            Some(value) => match value.as_unsigned()? {
                0 => return Err(InviteRecordsCodecError::ZeroDeadline),
                millis => Some(UnixMillis(millis)),
            },
        };
        let tag = fixed::<32>(req(record, "tag")?, "tag")?;
        if links.iter().any(|held| held.tag == tag) {
            return Err(InviteRecordsCodecError::DuplicateTag);
        }
        links.push(RecordedInvite {
            tag,
            ephemeral_identity_pk: fixed::<IDENTITY_PUBLIC_LEN>(
                req(record, "ephemeralIdentityPk")?,
                "ephemeralIdentityPk",
            )?,
            ephemeral_enc_pk: fixed::<SECRET_LEN>(
                req(record, "ephemeralEncPk")?,
                "ephemeralEncPk",
            )?,
            expires_at,
        });
    }
    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::EntropyError;
    use crate::sync::orphan_staging_keys;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on, conformance};

    fn enc(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn seeded(seed: u64) -> RefCell<SeededEntropy> {
        RefCell::new(SeededEntropy::new(seed))
    }

    fn record(byte: u8, expires_at: Option<UnixMillis>) -> RecordedInvite {
        RecordedInvite {
            tag: [byte; 32],
            ephemeral_identity_pk: [byte ^ 0x0f; IDENTITY_PUBLIC_LEN],
            ephemeral_enc_pk: [byte ^ 0xf0; SECRET_LEN],
            expires_at,
        }
    }

    fn sealed_as(secret: &X25519Secret, kind: OwnerLocalKind, seed: u64, body: &[u8]) -> Vec<u8> {
        let ephemeral = fresh_ephemeral(&mut SeededEntropy::new(seed)).expect("ephemeral");
        seal_owner_local(secret, kind, &ephemeral, body).expect("seal")
    }

    /// Reports success while writing nothing, so the caller's ephemeral stays
    /// all-zero — a seam that would silently reuse one HPKE ephemeral forever.
    struct SilentEntropy;

    impl Entropy for SilentEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Ok(())
        }
    }

    struct FailingEntropy;

    impl Entropy for FailingEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new("no entropy"))
        }
    }

    /// The HPKE ephemeral public half a stored blob carries.
    fn enc_of(blob: &[u8]) -> Vec<u8> {
        decode(blob)
            .expect("frame")
            .as_map()
            .expect("map")
            .get("enc")
            .expect("enc")
            .as_bytes()
            .expect("bytes")
            .to_vec()
    }

    #[test]
    fn the_staging_store_passes_the_invite_store_kit() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x11);
        let entropy = seeded(9);
        block_on(conformance::invite_store::check(async || {
            StagingInviteStore::new(&staging, &secret, &entropy)
        }));
    }

    /// The gap this store closes: a link minted in one session must still be
    /// convertible and revocable in the next, and every field conversion trusts
    /// has to survive the round trip byte-exact.
    #[test]
    fn a_recorded_link_survives_a_restart_field_for_field() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x21);
        let entropy = seeded(21);
        let links = [
            record(0x33, Some(UnixMillis(1_700_000_000_000))),
            record(0x44, None),
        ];
        block_on(StagingInviteStore::new(&staging, &secret, &entropy).persist(&links))
            .expect("persist");

        let mut restored =
            block_on(StagingInviteStore::new(&staging, &secret, &entropy).load()).expect("load");
        restored.sort_by_key(|link| link.tag);
        assert_eq!(restored, links);
    }

    /// The disclosure and forgery surface the seal closes: the host must not be
    /// able to read a record, and therefore cannot author one either.
    #[test]
    fn the_persisted_blob_never_holds_a_recorded_key_in_the_clear() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x22);
        let entropy = seeded(22);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        let link = record(0x33, Some(UnixMillis(1_700_000_000_000)));
        block_on(store.persist(&[link])).expect("persist");

        let stored = block_on(staging.staged_bytes(store.staging_key()))
            .expect("staged")
            .expect("the set is stored");
        for (bytes, what) in [
            (&link.tag[..], "tag"),
            (&link.ephemeral_identity_pk[..], "ephemeral identity key"),
            (&link.ephemeral_enc_pk[..], "ephemeral encryption subkey"),
        ] {
            assert!(
                !stored.windows(bytes.len()).any(|w| w == bytes),
                "the {what} must never sit in host storage in the clear"
            );
        }
    }

    #[test]
    fn a_set_this_session_cannot_open_fails_closed_rather_than_reading_empty() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x31);
        let entropy = seeded(31);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&[record(0x33, None)])).expect("persist");

        block_on(staging.put_staged_bytes(store.staging_key(), b"not a sealed set"))
            .expect("clobber");
        assert!(
            block_on(store.load()).is_err(),
            "an unreadable stored set is an error, never an empty set"
        );
    }

    /// The other arm of the same rule: bytes that open under this session's key
    /// but carry a body grammar this build does not read are still authority,
    /// not an empty set.
    #[test]
    fn a_stored_set_this_build_cannot_decode_fails_closed_rather_than_reading_empty() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x32);
        let entropy = seeded(32);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&[record(0x33, None)])).expect("persist");

        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed_as(
                &secret,
                OwnerLocalKind::InviteRecords,
                32,
                b"opens, but is not a record set",
            ),
        ))
        .expect("clobber");
        assert!(
            block_on(store.load()).is_err(),
            "a body this build cannot decode is an error, never an empty set"
        );
    }

    /// The store names its owner-local kind, so a sibling store's blob is
    /// unreadable state even when its body is a record set this build decodes
    /// perfectly — separation is the kind, not the body grammar.
    #[test]
    fn a_blob_from_another_owner_local_store_fails_closed() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x33);
        let entropy = seeded(33);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        let body = encode_records(&[record(0x33, None)]).expect("encode");
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed_as(&secret, OwnerLocalKind::ContactBook, 33, &body),
        ))
        .expect("stage");

        assert!(
            block_on(store.load()).is_err(),
            "another store's blob is an error, never a set to adopt"
        );
    }

    /// A record the host altered never reaches conversion as altered content:
    /// the seal binds the whole body, so a forged `ephemeralIdentityPk` is a
    /// load failure rather than a link the owner never minted.
    #[test]
    fn a_host_altered_record_fails_to_load_rather_than_loading_as_altered() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x34);
        let entropy = seeded(34);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        let honest = record(0x33, None);
        block_on(store.persist(&[honest])).expect("persist");

        let mut forged = honest;
        forged.ephemeral_identity_pk = [0x77; IDENTITY_PUBLIC_LEN];
        let body = encode_records(&[forged]).expect("encode");
        // Sealed to a key the attacker holds — the closest an unprivileged
        // writer of host storage can get to authoring a record.
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed_as(&enc(0x99), OwnerLocalKind::InviteRecords, 34, &body),
        ))
        .expect("clobber");

        assert!(
            block_on(store.load()).is_err(),
            "a record the owner did not seal never loads"
        );
    }

    #[test]
    fn another_identitys_records_are_not_this_sessions_records() {
        let staging = InMemoryStagingStore::default();
        let entropy = seeded(41);
        let alice = enc(0x41);
        let bob = enc(0x42);
        block_on(
            StagingInviteStore::new(&staging, &alice, &entropy).persist(&[record(0x33, None)]),
        )
        .expect("persist");

        assert!(
            block_on(StagingInviteStore::new(&staging, &bob, &entropy).load())
                .expect("load")
                .is_empty(),
            "one store is shared across accounts; a link must not cross identities"
        );
    }

    #[test]
    fn an_all_zero_ephemeral_fails_closed_before_the_seal() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x51);
        let entropy = RefCell::new(SilentEntropy);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        assert!(block_on(store.persist(&[record(0x33, None)])).is_err());
        assert!(
            block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged bytes")
                .is_none(),
            "a refused seal writes nothing"
        );
    }

    /// Rule 8: the decoder refuses two records under one tag, so the encoder
    /// must too.
    #[test]
    fn two_records_under_one_tag_are_refused_in_both_directions() {
        let mut clash = record(0x33, None);
        clash.ephemeral_enc_pk = [0x01; SECRET_LEN];
        assert!(matches!(
            encode_records(&[record(0x33, None), clash]),
            Err(InviteRecordsCodecError::DuplicateTag)
        ));

        let mut body = Map::new();
        let one = |link: &RecordedInvite| {
            let mut m = Map::new();
            m.insert(
                "ephemeralEncPk",
                Value::Bytes(link.ephemeral_enc_pk.to_vec()),
            );
            m.insert(
                "ephemeralIdentityPk",
                Value::Bytes(link.ephemeral_identity_pk.to_vec()),
            );
            m.insert("tag", Value::Bytes(link.tag.to_vec()));
            Value::Map(m)
        };
        body.insert(
            "links",
            Value::Array(vec![one(&record(0x33, None)), one(&clash)]),
        );
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::DuplicateTag)
        ));
    }

    /// Rule 8: `0` is not "no deadline" — the mint refuses it, the decoder
    /// refuses it, and so must the encoder, or a release build would durably
    /// record a link its own reader rejects.
    #[test]
    fn a_zero_deadline_is_refused_in_both_directions() {
        assert!(matches!(
            encode_records(&[record(0x33, Some(UnixMillis(0)))]),
            Err(InviteRecordsCodecError::ZeroDeadline)
        ));

        let mut m = Map::new();
        m.insert("ephemeralEncPk", Value::Bytes(vec![0x01; SECRET_LEN]));
        m.insert(
            "ephemeralIdentityPk",
            Value::Bytes(vec![0x02; IDENTITY_PUBLIC_LEN]),
        );
        m.insert("expiresAt", Value::Unsigned(0));
        m.insert("tag", Value::Bytes(vec![0x03; 32]));
        let mut body = Map::new();
        body.insert("links", Value::Array(vec![Value::Map(m)]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::ZeroDeadline)
        ));
    }

    /// Rule 8: the bound the decoder enforces is enforced at encode too.
    #[test]
    fn a_set_past_its_bound_is_refused_in_both_directions() {
        let links: Vec<RecordedInvite> = (0..=MAX_INVITE_RECORDS)
            .map(|i| {
                let mut link = record(0x33, None);
                link.tag[..2].copy_from_slice(&u16::try_from(i).expect("in range").to_be_bytes());
                link
            })
            .collect();
        assert!(matches!(
            encode_records(&links),
            Err(InviteRecordsCodecError::TooLong(TooLong {
                field: "links",
                ..
            }))
        ));

        // The decoder's own bound, on a body the encoder would never emit —
        // otherwise this test would only ever exercise one direction.
        let mut body = Map::new();
        body.insert(
            "links",
            Value::Array(
                links
                    .iter()
                    .map(|link| {
                        let mut m = Map::new();
                        m.insert(
                            "ephemeralEncPk",
                            Value::Bytes(link.ephemeral_enc_pk.to_vec()),
                        );
                        m.insert(
                            "ephemeralIdentityPk",
                            Value::Bytes(link.ephemeral_identity_pk.to_vec()),
                        );
                        m.insert("tag", Value::Bytes(link.tag.to_vec()));
                        Value::Map(m)
                    })
                    .collect(),
            ),
        );
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::TooLong(TooLong {
                field: "links",
                ..
            }))
        ));
    }

    #[test]
    fn a_set_at_an_unreadable_version_is_refused() {
        let mut body = Map::new();
        body.insert("links", Value::Array(vec![]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V + 1));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::UnsupportedVersion { version })
                if version == INVITE_RECORDS_V + 1
        ));
    }

    #[test]
    fn a_set_with_an_unknown_key_is_refused() {
        let mut body = Map::new();
        body.insert("extra", Value::Unsigned(1));
        body.insert("links", Value::Array(vec![]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::Codec(_))
        ));
    }

    /// The set shares a key space with staged upload blocks and is referenced by
    /// no op, so without the prefix carve-out orphan GC would collect every live
    /// link on the next sweep.
    #[test]
    fn orphan_gc_never_collects_the_persisted_records() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x71);
        let entropy = seeded(71);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&[record(0x33, None)])).expect("persist");
        block_on(staging.put_staged_bytes(b"upload-residue", b"stale")).expect("stage");

        assert_eq!(
            block_on(orphan_staging_keys(&staging, &[])).expect("sweep"),
            vec![b"upload-residue".to_vec()],
            "only the residue is collected, never the invite records"
        );
    }

    /// The failure a durable whole-set record must survive: the host loses the
    /// replacement write. `put_staged_bytes` is failure-atomic, so the set the
    /// store already holds is what the next load must still read.
    #[test]
    fn a_lost_write_never_destroys_the_recorded_set() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x81);
        let entropy = seeded(81);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        block_on(store.persist(&[record(0x33, None)])).expect("first persist");

        staging.interrupt_staged_write_after(store.staging_key(), 0);
        assert!(block_on(store.persist(&[])).is_err());
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "the set the store already held is still the one it serves"
        );
    }

    #[test]
    fn an_entropy_failure_leaves_the_recorded_set_untouched() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x52);
        let good = seeded(52);
        block_on(StagingInviteStore::new(&staging, &secret, &good).persist(&[record(0x33, None)]))
            .expect("persist");

        let broken = RefCell::new(FailingEntropy);
        let store = StagingInviteStore::new(&staging, &secret, &broken);
        assert!(block_on(store.persist(&[])).is_err());
        assert_eq!(
            block_on(store.load()).expect("load").len(),
            1,
            "a failed persist never clears the set it could not replace"
        );
    }

    /// The freshness invariant the seal rests on: two persists must not share an
    /// HPKE ephemeral. `fresh_ephemeral` only rejects an all-zero draw, so a seam
    /// stuck on any other constant is caught here or nowhere.
    #[test]
    fn two_persists_never_share_an_hpke_ephemeral() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x53);
        let entropy = seeded(53);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);

        block_on(store.persist(&[record(0x33, None)])).expect("first persist");
        let first = enc_of(
            &block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .expect("stored"),
        );
        block_on(store.persist(&[record(0x44, None)])).expect("second persist");
        let second = enc_of(
            &block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .expect("stored"),
        );

        assert_ne!(
            first, second,
            "an ephemeral reused across two seals under one key and info is a confidentiality break"
        );
    }
}
