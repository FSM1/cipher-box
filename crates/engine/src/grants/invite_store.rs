//! The owner's durable record of the invite links it minted and the claims it
//! has already converted — what lets a link minted in one session be converted
//! or revoked in the next, and what keeps a claim single-use.
//!
//! [`convert_invite_claim`](super::convert_invite_claim) and
//! [`locate_invite_link`](super::locate_invite_link) both read a
//! [`RecordedInvite`] back as input, and nothing in a resolved record marks a
//! row as an invite, so this store is the owner's authority over its own links
//! rather than a cache of published state. The spent-claim half
//! ([`ConvertedClaimRecord`]) is authority the network cannot hold at all: the
//! mailbox chooses what to redeliver, so only the owner can remember what it
//! already converted.
//!
//! It is therefore sealed HPKE-to-self under the session's `enc-subkey`
//! (`owner-local`, kind `invite-records`; ADR 0006) rather than written in the
//! clear. Conversion matches a claim's sender against the recorded
//! `ephemeralIdentityPk` and the tag binds only the **encryption** half, so a
//! party who could author a record would pair a real link's `ephemeralEncPk`
//! with an identity key it holds and drive the owner into minting a genuine
//! grant at that link's committed permission. The same authorship cuts the other
//! way now that a revoke names its link here: a record pairing an ordinary
//! grantee's `encPk` with that grantee's committed tag re-derives under the
//! owner's own half, so it would drive the owner into cutting a grant it never
//! revoked. The recorded deadline is the authority for expiry on the same rule.
//!
//! What the seal does *not* buy, because the structure carries no monotone
//! generation: a host replaying an earlier sealed set restores a deadline the
//! owner has since shortened, and dropping the stored key entirely reads as an
//! owner who minted nothing — leaving a live commitment entry no
//! [`locate_invite_link`](super::locate_invite_link) call can name, since the
//! cut is derived from the record rather than looked up by tag. The
//! owner-signed commitment caps both: conversion reads the permission there and
//! treats absence as revocation, and honours the published deadline as a
//! further restriction. It caps nothing on the spent-claim half, whose whole
//! rule is how to read that same absence — a restored blob un-spends claims, and
//! for a claim whose grant was cut both refusals fail open together. Closing
//! them needs a monotone generation held where the host cannot roll it back.
//!
//! Like its siblings it rides the staging store's opaque key space, on the
//! [`RetireLedger`](crate::seams::RetireLedger) shape.

use core::cell::RefCell;
use core::fmt;
use std::collections::BTreeSet;

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::error::CodecError;
use cipherbox_core::seal::{OwnerLocalKind, open_owner_local, seal_owner_local};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::entropy::{Entropy, EntropyError, fresh_ephemeral};
use crate::seams::{SeamError, StagingStore, UnixMillis};
use crate::sync::owner_scoped_key;

use super::accept::{TooLong, fixed, reject_unknown, req, within};
use super::invite::{CLAIM_ID_LEN, ConvertedClaimRecord, RecordedInvite};

/// The staging-key prefix the invite records are stored under, scoped per
/// identity by [`owner_scoped_key`]. `is_bookkeeping` treats the whole prefix as
/// referenced.
///
/// Kept short: the desktop store spells a staging key as a hex filename, twice
/// its byte length, inside Windows' whole-path budget.
pub const INVITE_RECORDS_PREFIX: &[u8] = b"cbx/iv/";

/// The stored-body grammar version this build writes and can read.
const INVITE_RECORDS_V: u64 = 3;

/// The frozen bound on recorded links, enforced release-active in both codec
/// directions (AGENTS.md rule 8). One record per live link across every scope
/// the owner has invited to; it bounds reader CPU and the staging budget alike.
///
/// A record whose scope root never published spends a slot that nothing can
/// reclaim on its own: no record resolves at that name for a prune to read a
/// commitment out of, and dropping one on an unresolvable name is the fail-open
/// the prune exists to avoid. A later mint at the same node publishes a
/// commitment that supersedes it, and the prune reclaims it then.
pub const MAX_INVITE_RECORDS: usize = 1024;

/// The frozen bound on spent-claim records, on the same rule as
/// [`MAX_INVITE_RECORDS`]. Larger because one link is multi-claim: it bounds the
/// claims every live link has produced, not the links.
pub const MAX_CONVERTED_CLAIMS: usize = 4096;

/// Why encoding or decoding a stored record set failed.
///
/// Engine-owned rather than a bare [`CodecError`] so a check this format needs
/// does not extend core's frozen `Malformed` registry, whose names the KAT
/// manifest pins.
#[derive(Debug)]
pub enum InviteRecordsCodecError {
    /// The det-CBOR framing was malformed.
    Codec(CodecError),
    /// The stored blob did not open under this session's `enc-subkey` as an
    /// `invite-records` blob — tampered, another identity's, or another
    /// owner-local store's.
    DidNotOpen(CodecError),
    /// Two records under one tag: no defined authority for that link's
    /// permission or deadline, refused in both directions (AGENTS.md rule 8).
    DuplicateTag,
    /// Two spent-claim records under one claim id, or two under one
    /// `(linkTag, tag)` pair. Refused in both directions (AGENTS.md rule 8):
    /// one record per grantee per link is what bounds the set by the grants the
    /// owner published, rather than by how many claims a bearer-link holder
    /// chooses to post.
    DuplicateClaim,
    /// A recorded deadline of `0`. `mint_invite_grant` refuses one
    /// ([`InviteError::InvalidExpiry`](super::InviteError::InvalidExpiry)), so
    /// reading it as "no deadline" would resurrect a link the mint never made.
    ZeroDeadline,
    /// A set written at a grammar version this build does not read. Never
    /// treated as empty: the links are there, this build cannot read them.
    UnsupportedVersion {
        /// The version the stored body declared.
        version: u64,
    },
    /// A collection or field past its frozen bound.
    TooLong(TooLong),
}

impl fmt::Display for InviteRecordsCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteRecordsCodecError::Codec(e) => write!(f, "codec: {e}"),
            InviteRecordsCodecError::DidNotOpen(e) => write!(f, "did not open: {}", e.check()),
            InviteRecordsCodecError::DuplicateTag => f.write_str("names one tag twice"),
            InviteRecordsCodecError::DuplicateClaim => f.write_str("names one conversion twice"),
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

/// The owner's whole invite state: the links it minted, and the claims it has
/// already spent converting.
///
/// One unit because the two are read and written together — conversion consults
/// both and appends to the second — and because a torn pair would let a claim
/// whose record was lost be converted a second time.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InviteRecords {
    /// The live links, the authority for what may be claimed.
    pub links: Vec<RecordedInvite>,
    /// The claims already converted, the authority for what may not be claimed
    /// again.
    pub claims: Vec<ConvertedClaimRecord>,
}

impl InviteRecords {
    /// Drop the links `tags` names, and the conversions they produced.
    ///
    /// A spent-claim record is what makes a claim single-use, and it is
    /// collectable exactly when the link it came in on is gone: no claim on a
    /// link the owner no longer records can convert
    /// ([`ConvertedClaimRecord::link_tag`](super::ConvertedClaimRecord::link_tag)),
    /// so dropping the pair together re-admits nothing.
    pub fn forget_links(&mut self, tags: &BTreeSet<[u8; 32]>) {
        self.links.retain(|link| !tags.contains(&link.tag));
        self.claims.retain(|claim| !tags.contains(&claim.link_tag));
    }
}

/// Durable persistence for the owner's invite state.
///
/// Whole-set replacement, like the received-shares store: the caller's set is
/// the authority, so a revoked link is dropped by persisting the set without it.
pub trait InviteStore {
    /// Durably persist the whole set.
    async fn persist(&self, records: &InviteRecords) -> Result<(), InviteStoreError>;

    /// The persisted state, or an empty set when the backing holds no entry
    /// at all — the module header states what a dropped entry costs.
    ///
    /// Fail-closed on an entry it cannot read: a link's fragment is already in
    /// a holder's hands, so a stored set this build cannot open is
    /// unrecoverable authority, and reporting it as empty would let the next
    /// [`persist`](Self::persist) overwrite every link behind it and re-admit
    /// every spent claim.
    async fn load(&self) -> Result<InviteRecords, InviteStoreError>;
}

/// Why an invite-store operation failed.
///
/// Classified on the shape the owner-local stores share
/// ([`ReceivedShareStoreError`](super::ReceivedShareStoreError) carries the
/// rationale). The records are an authorization input — `convert_invite_claim`
/// decides what may be claimed from them — so "the stored set did not open" is
/// a report that the owner's own authority was tampered with, and must never
/// reach a host as a retryable outage.
#[derive(Debug)]
pub enum InviteStoreError {
    /// Stored bytes this build cannot read as an invite record set. Never
    /// reported as an empty set: the next persist would overwrite links whose
    /// fragments are already in holders' hands.
    Unreadable(InviteRecordsCodecError),
    /// The offered set is past a bound. The stored bytes are fine — the offered
    /// set is the one past it — so a host can act rather than report
    /// corruption: revoke a live link for `links`, and for `claims` revoke a
    /// link and drop the records naming it
    /// ([`ConvertedClaimRecord::link_tag`](super::ConvertedClaimRecord::link_tag)).
    Full {
        /// The collection that overflowed, as the stored body spells it.
        collection: &'static str,
        /// The bound it passed.
        limit: usize,
    },
    /// The offered set is not one this build may store: two records under one
    /// tag, two conversions under one claim id or one `(linkTag, tag)` pair, or
    /// a zero deadline. A write-path refusal, so never
    /// [`Unreadable`](Self::Unreadable) — nothing was read.
    Encode(InviteRecordsCodecError),
    /// Entropy acquisition failed, so no set is sealed and none is written.
    Entropy(EntropyError),
    /// Sealing the set for storage failed.
    Seal(CodecError),
    /// The durable backing failed.
    Seam(SeamError),
}

impl fmt::Display for InviteStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteStoreError::Unreadable(e) => write!(f, "the stored invite record set {e}"),
            InviteStoreError::Full { collection, limit } => {
                write!(f, "the invite records already hold {limit} {collection}")
            }
            InviteStoreError::Encode(e) => write!(f, "the invite record set to store {e}"),
            InviteStoreError::Entropy(e) => write!(f, "invite records: {e}"),
            InviteStoreError::Seal(e) => write!(f, "invite records seal failed: {}", e.check()),
            InviteStoreError::Seam(e) => write!(f, "invite records: {e}"),
        }
    }
}

impl std::error::Error for InviteStoreError {}

impl From<SeamError> for InviteStoreError {
    fn from(e: SeamError) -> Self {
        InviteStoreError::Seam(e)
    }
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
    async fn persist(&self, records: &InviteRecords) -> Result<(), InviteStoreError> {
        if records.links.len() > MAX_INVITE_RECORDS {
            return Err(InviteStoreError::Full {
                collection: "links",
                limit: MAX_INVITE_RECORDS,
            });
        }
        if records.claims.len() > MAX_CONVERTED_CLAIMS {
            return Err(InviteStoreError::Full {
                collection: "claims",
                limit: MAX_CONVERTED_CLAIMS,
            });
        }
        let body = encode_records(records).map_err(InviteStoreError::Encode)?;
        let ephemeral =
            fresh_ephemeral(&mut *self.entropy.borrow_mut()).map_err(InviteStoreError::Entropy)?;
        let blob = seal_owner_local(
            self.enc_secret,
            OwnerLocalKind::InviteRecords,
            &ephemeral,
            &body,
        )
        .map_err(InviteStoreError::Seal)?;
        self.staging
            .put_staged_bytes(self.staging_key(), &blob)
            .await?;
        Ok(())
    }

    async fn load(&self) -> Result<InviteRecords, InviteStoreError> {
        let Some(blob) = self.staging.staged_bytes(self.staging_key()).await? else {
            return Ok(InviteRecords::default());
        };
        let body = open_owner_local(self.enc_secret, OwnerLocalKind::InviteRecords, &blob)
            .map_err(|e| InviteStoreError::Unreadable(InviteRecordsCodecError::DidNotOpen(e)))?;
        decode_records(&body).map_err(InviteStoreError::Unreadable)
    }
}

/// One conversion, as the stored body spells it.
fn encode_claim(claim: &ConvertedClaimRecord) -> Value {
    let mut m = Map::new();
    m.insert("claimId", Value::Bytes(claim.claim_id.to_vec()));
    m.insert("linkTag", Value::Bytes(claim.link_tag.to_vec()));
    m.insert("tag", Value::Bytes(claim.tag.to_vec()));
    Value::Map(m)
}

/// The spent set is a membership map on two keys: the claim id, and the
/// `(linkTag, tag)` pair that bounds it to one record per grantee per link.
fn check_claims_unique(
    claims: impl Iterator<Item = ConvertedClaimRecord>,
) -> Result<(), InviteRecordsCodecError> {
    let mut ids = BTreeSet::new();
    let mut grantees = BTreeSet::new();
    for claim in claims {
        if !ids.insert(claim.claim_id) || !grantees.insert((claim.link_tag, claim.tag)) {
            return Err(InviteRecordsCodecError::DuplicateClaim);
        }
    }
    Ok(())
}

/// Encode the durable record set to det-CBOR, links in tag order and claims in
/// claim-id order so one set has one spelling.
///
/// Rejects every bound, a duplicate tag, a repeated conversion and a zero
/// deadline release-active — the invariants [`decode_records`] hard-rejects
/// (AGENTS.md rule 8). A zero deadline is `mint_invite_grant`'s
/// [`InviteError::InvalidExpiry`](super::InviteError::InvalidExpiry): storing
/// one would durably record a link the reader must refuse to distinguish from
/// "no deadline".
fn encode_records(records: &InviteRecords) -> Result<Vec<u8>, InviteRecordsCodecError> {
    within("links", records.links.len(), MAX_INVITE_RECORDS)?;
    within("claims", records.claims.len(), MAX_CONVERTED_CLAIMS)?;
    let mut claims: Vec<&ConvertedClaimRecord> = records.claims.iter().collect();
    claims.sort_by_key(|claim| claim.claim_id);
    check_claims_unique(claims.iter().copied().copied())?;
    let encoded_claims: Vec<Value> = claims.into_iter().map(encode_claim).collect();
    let mut sorted: Vec<&RecordedInvite> = records.links.iter().collect();
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
        m.insert("scopeId", Value::Bytes(link.scope_id.to_vec()));
        m.insert("tag", Value::Bytes(link.tag.to_vec()));
        encoded.push(Value::Map(m));
    }
    let mut body = Map::new();
    body.insert("claims", Value::Array(encoded_claims));
    body.insert("links", Value::Array(encoded));
    body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
    Ok(encode_fixed_depth(&Value::Map(body)))
}

/// Decode a stored record set (strict det-CBOR).
///
/// A missing or mistyped field, an unknown key, an unreadable version, a bound
/// breach, a duplicate tag, a repeated conversion or a zero deadline is an
/// error — never a partial set, which would silently un-record links the owner
/// still holds or re-admit a claim it already spent.
fn decode_records(bytes: &[u8]) -> Result<InviteRecords, InviteRecordsCodecError> {
    let tree = decode(bytes)?;
    let map = tree.as_map()?;
    reject_unknown(map, &["claims", "links", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != INVITE_RECORDS_V {
        return Err(InviteRecordsCodecError::UnsupportedVersion { version });
    }
    let raw_claims = req(map, "claims")?.as_array()?;
    within("claims", raw_claims.len(), MAX_CONVERTED_CLAIMS)?;
    let mut claims: Vec<ConvertedClaimRecord> = Vec::with_capacity(raw_claims.len());
    for item in raw_claims {
        let record = item.as_map()?;
        reject_unknown(record, &["claimId", "linkTag", "tag"])?;
        claims.push(ConvertedClaimRecord {
            claim_id: fixed::<CLAIM_ID_LEN>(req(record, "claimId")?, "claimId")?,
            link_tag: fixed::<32>(req(record, "linkTag")?, "linkTag")?,
            tag: fixed::<32>(req(record, "tag")?, "tag")?,
        });
    }
    check_claims_unique(claims.iter().copied())?;
    let raw = req(map, "links")?.as_array()?;
    within("links", raw.len(), MAX_INVITE_RECORDS)?;
    let mut links: Vec<RecordedInvite> = Vec::with_capacity(raw.len());
    for item in raw {
        let record = item.as_map()?;
        reject_unknown(
            record,
            &[
                "ephemeralEncPk",
                "ephemeralIdentityPk",
                "expiresAt",
                "scopeId",
                "tag",
            ],
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
            scope_id: fixed::<16>(req(record, "scopeId")?, "scopeId")?,
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
    Ok(InviteRecords { links, claims })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::orphan_staging_keys;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{FailingEntropy, SeededEntropy, SilentEntropy, block_on, conformance};

    fn enc(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn seeded(seed: u64) -> RefCell<SeededEntropy> {
        RefCell::new(SeededEntropy::new(seed))
    }

    fn record(byte: u8, expires_at: Option<UnixMillis>) -> RecordedInvite {
        RecordedInvite {
            scope_id: [byte ^ 0x33; 16],
            tag: [byte; 32],
            ephemeral_identity_pk: [byte ^ 0x0f; IDENTITY_PUBLIC_LEN],
            ephemeral_enc_pk: [byte ^ 0xf0; SECRET_LEN],
            expires_at,
        }
    }

    /// State holding links and no spent claims.
    fn only(links: &[RecordedInvite]) -> InviteRecords {
        InviteRecords {
            links: links.to_vec(),
            ..Default::default()
        }
    }

    fn spent(byte: u8) -> ConvertedClaimRecord {
        ConvertedClaimRecord {
            claim_id: [byte; CLAIM_ID_LEN],
            link_tag: [byte ^ 0xa5; 32],
            tag: [byte ^ 0x5a; 32],
        }
    }

    fn sealed_as(secret: &X25519Secret, kind: OwnerLocalKind, seed: u64, body: &[u8]) -> Vec<u8> {
        let ephemeral = fresh_ephemeral(&mut SeededEntropy::new(seed)).expect("ephemeral");
        seal_owner_local(secret, kind, &ephemeral, body).expect("seal")
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
        block_on(StagingInviteStore::new(&staging, &secret, &entropy).persist(&only(&links)))
            .expect("persist");

        let mut restored =
            block_on(StagingInviteStore::new(&staging, &secret, &entropy).load()).expect("load");
        restored.links.sort_by_key(|link| link.tag);
        assert_eq!(restored, only(&links));
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
        block_on(store.persist(&only(&[link]))).expect("persist");

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
        block_on(store.persist(&only(&[record(0x33, None)]))).expect("persist");

        block_on(staging.put_staged_bytes(store.staging_key(), b"not a sealed set"))
            .expect("clobber");
        assert!(
            matches!(
                block_on(store.load()),
                Err(InviteStoreError::Unreadable(
                    InviteRecordsCodecError::DidNotOpen(_)
                ))
            ),
            "an unreadable stored set is a trust verdict, never a retryable seam failure"
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
        block_on(store.persist(&only(&[record(0x33, None)]))).expect("persist");

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
            matches!(
                block_on(store.load()),
                Err(InviteStoreError::Unreadable(
                    InviteRecordsCodecError::Codec(_)
                ))
            ),
            "a body this build cannot decode is a trust verdict, never an empty set"
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
        let body = encode_records(&only(&[record(0x33, None)])).expect("encode");
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed_as(&secret, OwnerLocalKind::ContactBook, 33, &body),
        ))
        .expect("stage");

        assert!(
            matches!(
                block_on(store.load()),
                Err(InviteStoreError::Unreadable(
                    InviteRecordsCodecError::DidNotOpen(_)
                ))
            ),
            "another store's blob is a trust verdict, never a set to adopt"
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
        block_on(store.persist(&only(&[honest]))).expect("persist");

        let mut forged = honest;
        forged.ephemeral_identity_pk = [0x77; IDENTITY_PUBLIC_LEN];
        let body = encode_records(&only(&[forged])).expect("encode");
        // Sealed to a key the attacker holds — the closest an unprivileged
        // writer of host storage can get to authoring a record.
        block_on(staging.put_staged_bytes(
            store.staging_key(),
            &sealed_as(&enc(0x99), OwnerLocalKind::InviteRecords, 34, &body),
        ))
        .expect("clobber");

        assert!(
            matches!(
                block_on(store.load()),
                Err(InviteStoreError::Unreadable(
                    InviteRecordsCodecError::DidNotOpen(_)
                ))
            ),
            "a record the owner did not seal is a trust verdict, never a link to convert"
        );
    }

    #[test]
    fn another_identitys_records_are_not_this_sessions_records() {
        let staging = InMemoryStagingStore::default();
        let entropy = seeded(41);
        let alice = enc(0x41);
        let bob = enc(0x42);
        block_on(
            StagingInviteStore::new(&staging, &alice, &entropy)
                .persist(&only(&[record(0x33, None)])),
        )
        .expect("persist");

        assert_eq!(
            block_on(StagingInviteStore::new(&staging, &bob, &entropy).load()).expect("load"),
            InviteRecords::default(),
            "one store is shared across accounts; a link must not cross identities"
        );
    }

    #[test]
    fn an_all_zero_ephemeral_fails_closed_before_the_seal() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x51);
        let entropy = RefCell::new(SilentEntropy);
        let store = StagingInviteStore::new(&staging, &secret, &entropy);
        assert!(matches!(
            block_on(store.persist(&only(&[record(0x33, None)]))),
            Err(InviteStoreError::Entropy(_))
        ));
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
            encode_records(&only(&[record(0x33, None), clash])),
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
            m.insert("scopeId", Value::Bytes(link.scope_id.to_vec()));
            m.insert("tag", Value::Bytes(link.tag.to_vec()));
            Value::Map(m)
        };
        body.insert("claims", Value::Array(vec![]));
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

    /// A spent claim is what keeps a claim single-use, so losing it across a
    /// restart would re-admit every claim the owner already converted.
    #[test]
    fn a_spent_claim_survives_a_restart_field_for_field() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x23);
        let entropy = seeded(23);
        let state = InviteRecords {
            links: vec![record(0x33, None)],
            claims: vec![spent(0x61), spent(0x62)],
        };
        block_on(StagingInviteStore::new(&staging, &secret, &entropy).persist(&state))
            .expect("persist");

        let mut restored =
            block_on(StagingInviteStore::new(&staging, &secret, &entropy).load()).expect("load");
        restored.claims.sort_by_key(|claim| claim.claim_id);
        assert_eq!(restored, state);
    }

    /// A body carrying `claims`, so a decode test states only its own deviation.
    fn claims_body(claims: &[ConvertedClaimRecord]) -> Vec<u8> {
        let mut body = Map::new();
        body.insert(
            "claims",
            Value::Array(claims.iter().map(encode_claim).collect()),
        );
        body.insert("links", Value::Array(vec![]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        encode_fixed_depth(&Value::Map(body))
    }

    fn claims_only(claims: &[ConvertedClaimRecord]) -> InviteRecords {
        InviteRecords {
            claims: claims.to_vec(),
            ..Default::default()
        }
    }

    /// Rule 8: the decoder refuses a repeated conversion, so the encoder must
    /// too — under one claim id, and under one `(linkTag, tag)` pair, which is
    /// what keeps the set bounded by the grants the owner actually published
    /// rather than by how many claims a link holder posts.
    #[test]
    fn a_repeated_conversion_is_refused_in_both_directions() {
        for clash in [
            {
                let mut c = spent(0x61);
                c.tag = [0x07; 32];
                c
            },
            {
                let mut c = spent(0x61);
                c.claim_id = [0x07; CLAIM_ID_LEN];
                c
            },
        ] {
            assert!(matches!(
                encode_records(&claims_only(&[spent(0x61), clash])),
                Err(InviteRecordsCodecError::DuplicateClaim)
            ));
            assert!(matches!(
                decode_records(&claims_body(&[spent(0x61), clash])),
                Err(InviteRecordsCodecError::DuplicateClaim)
            ));
        }
    }

    /// Rule 8: the spent-claim bound is enforced at encode as well as decode.
    #[test]
    fn a_claim_set_past_its_bound_is_refused_in_both_directions() {
        let claims: Vec<ConvertedClaimRecord> = (0..=MAX_CONVERTED_CLAIMS)
            .map(|i| {
                let mut claim = spent(0x61);
                let n = u16::try_from(i).expect("in range").to_be_bytes();
                claim.claim_id[..2].copy_from_slice(&n);
                claim.tag[..2].copy_from_slice(&n);
                claim
            })
            .collect();
        assert!(matches!(
            encode_records(&claims_only(&claims)),
            Err(InviteRecordsCodecError::TooLong(TooLong {
                field: "claims",
                ..
            }))
        ));
        assert!(matches!(
            decode_records(&claims_body(&claims)),
            Err(InviteRecordsCodecError::TooLong(TooLong {
                field: "claims",
                ..
            }))
        ));
    }

    /// The downgrade the version bump has to catch: a body at the previous
    /// grammar carries no `claims` key at all, and reading it as zero spent
    /// claims would re-admit every claim the owner converted.
    #[test]
    fn a_body_at_the_previous_grammar_is_refused_rather_than_read_as_no_spent_claims() {
        let mut body = Map::new();
        body.insert("links", Value::Array(vec![]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V - 1));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::UnsupportedVersion { version })
                if version == INVITE_RECORDS_V - 1
        ));
    }

    /// A spent-claim record is the authority for one claim's single use, so an
    /// unknown key in it is refused like one in a link record.
    #[test]
    fn a_claim_record_with_an_unknown_key_is_refused() {
        let mut m = Map::new();
        m.insert("claimId", Value::Bytes(vec![0x01; CLAIM_ID_LEN]));
        m.insert("extra", Value::Unsigned(1));
        m.insert("linkTag", Value::Bytes(vec![0x03; 32]));
        m.insert("tag", Value::Bytes(vec![0x02; 32]));
        let mut body = Map::new();
        body.insert("claims", Value::Array(vec![Value::Map(m)]));
        body.insert("links", Value::Array(vec![]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::Codec(_))
        ));
    }

    /// Rule 8: `0` is not "no deadline" — the mint refuses it, the decoder
    /// refuses it, and so must the encoder, or a release build would durably
    /// record a link its own reader rejects.
    #[test]
    fn a_zero_deadline_is_refused_in_both_directions() {
        assert!(matches!(
            encode_records(&only(&[record(0x33, Some(UnixMillis(0)))])),
            Err(InviteRecordsCodecError::ZeroDeadline)
        ));

        let mut m = Map::new();
        m.insert("ephemeralEncPk", Value::Bytes(vec![0x01; SECRET_LEN]));
        m.insert(
            "ephemeralIdentityPk",
            Value::Bytes(vec![0x02; IDENTITY_PUBLIC_LEN]),
        );
        m.insert("expiresAt", Value::Unsigned(0));
        m.insert("scopeId", Value::Bytes(vec![0x04; 16]));
        m.insert("tag", Value::Bytes(vec![0x03; 32]));
        let mut body = Map::new();
        body.insert("claims", Value::Array(vec![]));
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
            encode_records(&only(&links)),
            Err(InviteRecordsCodecError::TooLong(TooLong {
                field: "links",
                ..
            }))
        ));

        // The decoder's own bound, on a body the encoder would never emit —
        // otherwise this test would only ever exercise one direction.
        let mut body = Map::new();
        body.insert("claims", Value::Array(vec![]));
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
                        m.insert("scopeId", Value::Bytes(link.scope_id.to_vec()));
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
        body.insert("claims", Value::Array(vec![]));
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
        body.insert("claims", Value::Array(vec![]));
        body.insert("links", Value::Array(vec![]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::Codec(_))
        ));
    }

    /// The set rejects an unknown key at the record too, not only at the top
    /// level — a record is the authority for one link's permission.
    #[test]
    fn a_record_with_an_unknown_key_is_refused() {
        let mut m = Map::new();
        m.insert("ephemeralEncPk", Value::Bytes(vec![0x01; SECRET_LEN]));
        m.insert(
            "ephemeralIdentityPk",
            Value::Bytes(vec![0x02; IDENTITY_PUBLIC_LEN]),
        );
        m.insert("extra", Value::Unsigned(1));
        m.insert("scopeId", Value::Bytes(vec![0x04; 16]));
        m.insert("tag", Value::Bytes(vec![0x03; 32]));
        let mut body = Map::new();
        body.insert("claims", Value::Array(vec![]));
        body.insert("links", Value::Array(vec![Value::Map(m)]));
        body.insert("v", Value::Unsigned(INVITE_RECORDS_V));
        assert!(matches!(
            decode_records(&encode_fixed_depth(&Value::Map(body))),
            Err(InviteRecordsCodecError::Codec(_))
        ));
    }

    /// The scope a record was minted over is what attributes it, so a record
    /// without one is refused rather than read as belonging to every scope.
    #[test]
    fn a_record_without_a_scope_id_is_refused() {
        let mut m = Map::new();
        m.insert("ephemeralEncPk", Value::Bytes(vec![0x01; SECRET_LEN]));
        m.insert(
            "ephemeralIdentityPk",
            Value::Bytes(vec![0x02; IDENTITY_PUBLIC_LEN]),
        );
        m.insert("tag", Value::Bytes(vec![0x03; 32]));
        let mut body = Map::new();
        body.insert("claims", Value::Array(vec![]));
        body.insert("links", Value::Array(vec![Value::Map(m)]));
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
        block_on(store.persist(&only(&[record(0x33, None)]))).expect("persist");
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
        block_on(store.persist(&only(&[record(0x33, None)]))).expect("first persist");

        staging.interrupt_staged_write_after(store.staging_key(), 0);
        assert!(block_on(store.persist(&only(&[]))).is_err());
        assert_eq!(
            block_on(store.load()).expect("load").links.len(),
            1,
            "the set the store already held is still the one it serves"
        );
    }

    #[test]
    fn an_entropy_failure_leaves_the_recorded_set_untouched() {
        let staging = InMemoryStagingStore::default();
        let secret = enc(0x52);
        let good = seeded(52);
        block_on(
            StagingInviteStore::new(&staging, &secret, &good).persist(&only(&[record(0x33, None)])),
        )
        .expect("persist");

        let broken = RefCell::new(FailingEntropy);
        let store = StagingInviteStore::new(&staging, &secret, &broken);
        assert!(block_on(store.persist(&only(&[]))).is_err());
        assert_eq!(
            block_on(store.load()).expect("load").links.len(),
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

        block_on(store.persist(&only(&[record(0x33, None)]))).expect("first persist");
        let first = enc_of(
            &block_on(staging.staged_bytes(store.staging_key()))
                .expect("staged")
                .expect("stored"),
        );
        block_on(store.persist(&only(&[record(0x44, None)]))).expect("second persist");
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
