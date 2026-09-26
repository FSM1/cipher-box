//! The owner's durable conversion record (ADR 0023 D5, D6; ADR 0026 E1).
//!
//! An owner device acks a claim item first, and converts only when the ack
//! removed it. The entry is written before the delete runs, because from the
//! delete on the entry here is the owner's only copy of the claim. A
//! conversion that fails on availability stays pending and runs again, checks
//! included, on a later pass. A converted entry stays until its share pointer
//! lands. A conversion refused at a cap stays as a refused entry, so the
//! people list can show the refusal, and it never blocks the pending ones.
//!
//! One key per identity, under the owner tag every durable bookkeeping surface
//! is scoped by ([`owner_scoped_key`]), sealed under
//! [`OwnerLocalKind::PendingConversions`] ([`crate::sync::bookkeeping`]).

use core::fmt;

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::seal::{OwnerLocalKind, Permission};
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;

use super::accept::{
    CLAIM_MAX_POSTS, CLAIM_REPOST_MAX_WAIT, TooLong, fixed, reject_unknown, req, within,
};
use super::invite::{AckedClaim, MAX_INVITE_FRAGMENT_BYTES};
use crate::facade::Event;
use crate::seams::{SeamError, SeamResult, StagingStore, UnixMillis};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::owner_scoped_key;

/// The staging-key prefix of the conversion record.
pub const CONVERSION_RECORD_PREFIX: &[u8] = b"cbx/pc/";

/// Where a record this build cannot read is set aside. Under
/// [`CONVERSION_RECORD_PREFIX`], so the same bookkeeping rule keeps it.
const QUARANTINE_PREFIX: &[u8] = b"cbx/pc/q/";

/// The body format version this build writes and reads.
const FORMAT_V: u64 = 1;

/// How many entries the record holds, refused ones included. An owner device
/// acks no further claim while the record is full, so the rest wait on the
/// mailbox.
pub const MAX_CONVERSION_ENTRIES: usize = 256;

/// How many refused entries the record keeps. Past it the oldest goes, and
/// the pass reports it ([`Event::RefusedClaimDropped`]).
pub const MAX_REFUSED_CONVERSIONS: usize = 64;

/// The bound on a stored claim payload. A claim fits well inside the bound of
/// the fragment that carried its link.
pub const MAX_CLAIM_PAYLOAD_BYTES: usize = MAX_INVITE_FRAGMENT_BYTES;

/// How long after its conversion a claim's share pointer is posted again.
/// Past it a post that still fails settles the entry, so an account the API no
/// longer holds keeps no slot. It outlasts the claimant's own re-post
/// schedule, whose waits never pass [`CLAIM_REPOST_MAX_WAIT`].
pub const POINTER_RETRY_WINDOW: u64 = CLAIM_MAX_POSTS * CLAIM_REPOST_MAX_WAIT;

/// Why a conversion was refused for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionRefusal {
    /// The scope is at the grant-set ceiling.
    GrantSetFull,
    /// The link's admission cap is reached.
    AdmissionCapReached,
    /// The converting device's contact book cannot record the claimant, so
    /// this device could not cut the grant it minted.
    ContactBookFull,
    /// A claim from a known identity carries another encryption subkey. The
    /// owner revokes and grants again to move the grant to the new key. Also a
    /// claim whose subkey the book binds to another identity.
    RecipientKeyChanged,
}

impl ConversionRefusal {
    const ALL: [Self; 4] = [
        Self::GrantSetFull,
        Self::AdmissionCapReached,
        Self::ContactBookFull,
        Self::RecipientKeyChanged,
    ];

    /// The stable wire and host-facing name.
    pub fn check(self) -> &'static str {
        match self {
            Self::GrantSetFull => "grant-set-full",
            Self::AdmissionCapReached => "link-admission-cap-reached",
            Self::ContactBookFull => "contact-book-full",
            Self::RecipientKeyChanged => "claim-recipient-key-changed",
        }
    }

    fn from_check(check: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|refusal| refusal.check() == check)
    }
}

/// What one pass decided for a conversion entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It converted and its share pointer landed, or it can never convert:
    /// the entry goes.
    Settled,
    /// The set carrying its row landed, and its share pointer did not.
    PointerDue(PointerDue),
    /// A cap refused it.
    Refused(ConversionRefusal),
}

/// A converted claim whose share pointer is not posted yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerDue {
    /// The permission the pointer names.
    pub permission: Permission,
    /// The read epoch of the grant this owner minted and published, which the
    /// grant floor records. `None` when the set already held the row.
    pub grant_floor: Option<u64>,
    /// When the claim converted, which [`POINTER_RETRY_WINDOW`] runs from.
    pub since: UnixMillis,
}

/// Where one conversion entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Written before the mailbox delete runs, so a crash after the delete
    /// keeps the claim. It converts as a pending entry does: a second
    /// conversion of one identity is a no-op (ADR 0023 D3).
    Acking,
    /// The delete removed the item, and the conversion waits.
    Pending,
    /// Converted; the share pointer post runs again on each pass.
    PointerDue(PointerDue),
    /// A cap refused it for good.
    Refused(ConversionRefusal),
}

/// What [`ConversionRecord::hold_for_ack`] found for a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    /// A new entry holds the claim now. It stays only if the delete removes
    /// the item.
    Fresh,
    /// An entry from a delete whose answer was lost holds it. It stays
    /// whatever the delete answers now.
    Resumed,
    /// An entry past its ack holds it: the item is a copy, and the delete
    /// only clears it.
    Held,
}

/// One conversion entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionEntry {
    /// The acked claim.
    pub claim: AckedClaim,
    /// Where the entry stands.
    pub state: EntryState,
}

impl ConversionEntry {
    /// Whether this entry holds the claim `claim` carries: one sender, one
    /// payload. The ack time is the entry's own.
    fn holds(&self, claim: &AckedClaim) -> bool {
        self.claim.sender == claim.sender && self.claim.payload == claim.payload
    }

    /// Whether the conversion of this entry has not run to a row yet.
    pub fn converts(&self) -> bool {
        matches!(self.state, EntryState::Acking | EntryState::Pending)
    }

    /// The refusal of a refused entry.
    pub fn refused(&self) -> Option<ConversionRefusal> {
        match self.state {
            EntryState::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }
}

/// Every conversion entry this identity holds, in ack order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConversionRecord {
    entries: Vec<ConversionEntry>,
}

impl ConversionRecord {
    /// Every entry, in ack order.
    pub fn entries(&self) -> &[ConversionEntry] {
        &self.entries
    }

    /// The claims whose conversion waits.
    pub fn pending(&self) -> impl Iterator<Item = &AckedClaim> {
        self.entries
            .iter()
            .filter(|entry| entry.converts())
            .map(|entry| &entry.claim)
    }

    /// Whether one more acked claim fits.
    pub fn has_room(&self) -> bool {
        self.entries.len() < MAX_CONVERSION_ENTRIES
    }

    /// Hold `claim` before the delete of its item runs, or `None` when a new
    /// entry does not fit. A fresh copy of a refused claim replaces the
    /// refusal: a cut since may have freed the slot it lacked (ADR 0023 D9).
    pub fn hold_for_ack(&mut self, claim: AckedClaim) -> Option<Hold> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.refused().is_none() && entry.holds(&claim))
        {
            return Some(match entry.state {
                EntryState::Acking => Hold::Resumed,
                _ => Hold::Held,
            });
        }
        let refused = self
            .entries
            .iter()
            .any(|entry| entry.refused().is_some() && entry.holds(&claim));
        if !refused && !self.has_room() {
            return None;
        }
        self.entries
            .retain(|entry| entry.refused().is_none() || !entry.holds(&claim));
        self.entries.push(ConversionEntry {
            claim,
            state: EntryState::Acking,
        });
        Some(Hold::Fresh)
    }

    /// Settle the delete of the item `claim` came in: the entry waits for its
    /// conversion when `keep`, and goes otherwise.
    pub fn settle_ack(&mut self, claim: &AckedClaim, keep: bool) {
        let at = self
            .entries
            .iter()
            .position(|entry| entry.state == EntryState::Acking && entry.holds(claim));
        match at {
            Some(at) if keep => self.entries[at].state = EntryState::Pending,
            Some(at) => {
                self.entries.remove(at);
            }
            None => {}
        }
    }

    /// Apply one pass's verdicts, one slot per entry in entry order. Past
    /// [`MAX_REFUSED_CONVERSIONS`] the oldest refused entries go; answers how
    /// many, so the caller can report each.
    pub fn apply(&mut self, verdicts: &[Option<Verdict>]) -> usize {
        let mut at = 0;
        self.entries.retain_mut(|entry| {
            let verdict = verdicts.get(at).copied().flatten();
            at += 1;
            match verdict {
                Some(Verdict::Settled) => false,
                Some(Verdict::PointerDue(due)) => {
                    entry.state = EntryState::PointerDue(due);
                    true
                }
                Some(Verdict::Refused(refusal)) => {
                    entry.state = EntryState::Refused(refusal);
                    true
                }
                None => true,
            }
        });
        let refused = self
            .entries
            .iter()
            .filter(|entry| entry.refused().is_some())
            .count();
        let mut over = refused.saturating_sub(MAX_REFUSED_CONVERSIONS);
        let evicted = over;
        self.entries.retain(|entry| {
            let evict = over > 0 && entry.refused().is_some();
            over -= usize::from(evict);
            !evict
        });
        evicted
    }

    /// Drop every refused entry `retired` names, and answer how many went.
    pub fn retire_refused(&mut self, retired: impl Fn(&AckedClaim) -> bool) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|entry| entry.refused().is_none() || !retired(&entry.claim));
        before - self.entries.len()
    }
}

/// Why a stored conversion record did not decode.
#[derive(Debug)]
pub enum ConversionCodecError {
    /// The det-CBOR framing or a field was malformed.
    Codec(CodecError),
    /// A collection or field past its frozen bound.
    TooLong(TooLong),
}

impl From<CodecError> for ConversionCodecError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<Malformed> for ConversionCodecError {
    fn from(error: Malformed) -> Self {
        Self::Codec(error.into())
    }
}

impl From<TooLong> for ConversionCodecError {
    fn from(error: TooLong) -> Self {
        Self::TooLong(error)
    }
}

impl fmt::Display for ConversionCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(f, "{error}"),
            Self::TooLong(error) => write!(f, "{error}"),
        }
    }
}

/// Encode the record body to det-CBOR, in ack order.
pub fn encode_conversions(record: &ConversionRecord) -> Result<Vec<u8>, TooLong> {
    within("entries", record.entries.len(), MAX_CONVERSION_ENTRIES)?;
    let entries = record
        .entries
        .iter()
        .map(|entry| {
            within("claim", entry.claim.payload.len(), MAX_CLAIM_PAYLOAD_BYTES)?;
            let mut m = Map::new();
            m.insert("ackedAt", Value::Unsigned(entry.claim.acked_at.0));
            m.insert("claim", Value::Bytes(entry.claim.payload.clone()));
            match entry.state {
                EntryState::Acking => {
                    m.insert("acking", Value::Bool(true));
                }
                EntryState::Pending => {}
                EntryState::PointerDue(due) => {
                    if let Some(epoch) = due.grant_floor {
                        m.insert("grantFloor", Value::Unsigned(epoch));
                    }
                    m.insert(
                        "pointerDue",
                        Value::Text(due.permission.as_wire().to_owned()),
                    );
                    m.insert("pointerDueAt", Value::Unsigned(due.since.0));
                }
                EntryState::Refused(refusal) => {
                    m.insert("refused", Value::Text(refusal.check().to_owned()));
                }
            }
            m.insert("sender", Value::Bytes(entry.claim.sender.to_vec()));
            Ok(Value::Map(m))
        })
        .collect::<Result<Vec<_>, TooLong>>()?;
    let mut body = Map::new();
    body.insert("entries", Value::Array(entries));
    body.insert("v", Value::Unsigned(FORMAT_V));
    Ok(encode_fixed_depth(&Value::Map(body)))
}

/// Decode a record body (strict det-CBOR). An unknown key, an unknown refusal
/// or a version this build does not write is refused.
pub fn decode_conversions(bytes: &[u8]) -> Result<ConversionRecord, ConversionCodecError> {
    let tree = decode(bytes)?;
    let map = tree.as_map()?;
    reject_unknown(map, &["entries", "v"])?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != FORMAT_V {
        return Err(CodecError::from(Malformed::UnsupportedRecordVersion { version }).into());
    }
    let raw = req(map, "entries")?.as_array()?;
    within("entries", raw.len(), MAX_CONVERSION_ENTRIES)?;
    let entries = raw
        .iter()
        .map(|item| {
            let entry = item.as_map()?;
            reject_unknown(
                entry,
                &[
                    "ackedAt",
                    "acking",
                    "claim",
                    "grantFloor",
                    "pointerDue",
                    "pointerDueAt",
                    "refused",
                    "sender",
                ],
            )?;
            let payload = req(entry, "claim")?.as_bytes()?.to_vec();
            within("claim", payload.len(), MAX_CLAIM_PAYLOAD_BYTES)?;
            Ok(ConversionEntry {
                claim: AckedClaim {
                    sender: fixed::<IDENTITY_PUBLIC_LEN>(req(entry, "sender")?, "sender")?,
                    payload,
                    acked_at: UnixMillis(req(entry, "ackedAt")?.as_unsigned()?),
                },
                state: decode_state(entry)?,
            })
        })
        .collect::<Result<Vec<_>, ConversionCodecError>>()?;
    Ok(ConversionRecord { entries })
}

/// The state one entry's optional fields name. At most one of `acking`,
/// `pointerDue` and `refused` is present, `acking` is only ever `true`,
/// `pointerDueAt` goes with `pointerDue` both ways, and `grantFloor` only goes
/// with `pointerDue`: the encoder writes no other shape.
fn decode_state(entry: &Map) -> Result<EntryState, ConversionCodecError> {
    let malformed = |key: &str| {
        CodecError::from(Malformed::UnknownRecordField {
            key: key.to_owned(),
        })
    };
    let acking = entry.get("acking");
    let due = entry.get("pointerDue");
    let refused = entry.get("refused");
    let floor = entry.get("grantFloor");
    let due_at = entry.get("pointerDueAt");
    if usize::from(acking.is_some()) + usize::from(due.is_some()) + usize::from(refused.is_some())
        > 1
        || (floor.is_some() && due.is_none())
        || due_at.is_some() != due.is_some()
    {
        return Err(malformed("state").into());
    }
    if let Some(acking) = acking {
        return if acking.as_bool()? {
            Ok(EntryState::Acking)
        } else {
            Err(malformed("acking").into())
        };
    }
    if let (Some(due), Some(due_at)) = (due, due_at) {
        let wire = due.as_text()?;
        return Ok(EntryState::PointerDue(PointerDue {
            permission: Permission::from_wire(wire).ok_or_else(|| malformed(wire))?,
            grant_floor: floor.map(Value::as_unsigned).transpose()?,
            since: UnixMillis(due_at.as_unsigned()?),
        }));
    }
    if let Some(refused) = refused {
        let check = refused.as_text()?;
        return Ok(EntryState::Refused(
            ConversionRefusal::from_check(check).ok_or_else(|| malformed(check))?,
        ));
    }
    Ok(EntryState::Pending)
}

/// This identity's one conversion record key.
#[must_use]
pub fn conversions_key(enc_secret: &X25519Secret) -> Vec<u8> {
    owner_scoped_key(CONVERSION_RECORD_PREFIX, enc_secret)
}

/// The durable record, or an empty one where none is stored.
///
/// Bytes this identity's key and this build's grammar do not both accept are
/// moved to a quarantine key, and the record starts empty: a persist over them
/// would lose them, and leaving them would stop every conversion on this
/// device. Each claimant posts its claim again until a pointer lands, which is
/// the recovery (ADR 0023 D5). The move is reported once
/// ([`Event::ConversionRecordUnreadable`]).
pub async fn load_conversions<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    events: &mpsc::UnboundedSender<Event>,
) -> SeamResult<ConversionRecord> {
    let key = conversions_key(enc_secret);
    let Some(blob) = staging.staged_bytes(&key).await? else {
        return Ok(ConversionRecord::default());
    };
    if let Some(record) = seal
        .open(OwnerLocalKind::PendingConversions, &blob)
        .and_then(|body| decode_conversions(&body).ok())
    {
        return Ok(record);
    }
    staging
        .put_staged_bytes(&owner_scoped_key(QUARANTINE_PREFIX, enc_secret), &blob)
        .await?;
    staging.remove_staged_bytes(&key).await?;
    let _ = events.unbounded_send(Event::ConversionRecordUnreadable);
    Ok(ConversionRecord::default())
}

/// Write `record` through, removing the key once it holds nothing.
pub async fn persist_conversions<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    record: &ConversionRecord,
) -> SeamResult<()> {
    let key = conversions_key(enc_secret);
    if record.entries.is_empty() {
        return staging.remove_staged_bytes(&key).await;
    }
    let body = encode_conversions(record).map_err(|e| SeamError::new(e.to_string()))?;
    let blob = seal.seal(OwnerLocalKind::PendingConversions, &body)?;
    staging.put_staged_bytes(&key, &blob).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hold `claim` as the delete of its item removed it.
    fn pend(record: &mut ConversionRecord, claim: AckedClaim) {
        record.hold_for_ack(claim.clone());
        record.settle_ack(&claim, true);
    }

    fn claim(seed: u8) -> AckedClaim {
        AckedClaim {
            sender: [seed; IDENTITY_PUBLIC_LEN],
            payload: vec![seed; 40],
            acked_at: UnixMillis(u64::from(seed) * 1_000),
        }
    }

    #[test]
    fn a_record_round_trips_with_its_refusals() {
        let mut record = ConversionRecord::default();
        pend(&mut record, claim(1));
        pend(&mut record, claim(2));
        record.apply(&[
            None,
            Some(Verdict::Refused(ConversionRefusal::AdmissionCapReached)),
        ]);
        let decoded =
            decode_conversions(&encode_conversions(&record).expect("encodes")).expect("decodes");
        assert_eq!(decoded, record);
        assert_eq!(decoded.pending().collect::<Vec<_>>(), vec![&claim(1)]);
    }

    /// A record this build cannot open is set aside, never written over, and
    /// the owner is told once.
    #[test]
    fn a_record_that_does_not_open_is_quarantined_and_reported() {
        use crate::testkit::fakes::InMemoryStagingStore;
        use crate::testkit::{SeededEntropy, block_on};
        use core::cell::RefCell;

        let staging = InMemoryStagingStore::default();
        let enc = X25519Secret::from_scalar([0x21; 32]);
        let entropy: RefCell<SeededEntropy> = RefCell::new(SeededEntropy::new(3));
        let (events, mut stream) = mpsc::unbounded();
        let unreadable = b"not a sealed record".to_vec();
        block_on(staging.put_staged_bytes(&conversions_key(&enc), &unreadable)).expect("stages");

        let loaded = block_on(load_conversions(
            &staging,
            BookkeepingSeal::new(&enc, &entropy),
            &enc,
            &events,
        ))
        .expect("the load goes on empty");
        assert!(loaded.entries().is_empty());
        assert_eq!(
            block_on(staging.staged_bytes(&owner_scoped_key(QUARANTINE_PREFIX, &enc)))
                .expect("reads"),
            Some(unreadable),
            "the unreadable bytes are kept"
        );
        assert_eq!(
            block_on(staging.staged_bytes(&conversions_key(&enc))).expect("reads"),
            None
        );
        assert!(matches!(
            stream.try_recv(),
            Ok(Event::ConversionRecordUnreadable)
        ));
    }

    #[test]
    fn one_claim_acked_twice_is_held_once() {
        let mut record = ConversionRecord::default();
        assert_eq!(record.hold_for_ack(claim(1)), Some(Hold::Fresh));
        assert_eq!(record.hold_for_ack(claim(1)), Some(Hold::Resumed));
        record.settle_ack(&claim(1), true);
        assert_eq!(record.hold_for_ack(claim(1)), Some(Hold::Held));
        assert_eq!(record.entries().len(), 1);
    }

    /// ADR 0023 D5: a fresh claim whose delete removed nothing leaves the
    /// record, because another owner device holds it.
    #[test]
    fn a_fresh_hold_whose_delete_removed_nothing_goes() {
        let mut record = ConversionRecord::default();
        pend(&mut record, claim(1));
        assert_eq!(record.hold_for_ack(claim(2)), Some(Hold::Fresh));
        record.settle_ack(&claim(2), false);
        assert_eq!(record.pending().collect::<Vec<_>>(), vec![&claim(1)]);
    }

    /// An entry written before its delete converts, and a converted entry
    /// waits for its share pointer; both survive a restart.
    #[test]
    fn every_state_round_trips() {
        let mut record = ConversionRecord::default();
        record.hold_for_ack(claim(1));
        pend(&mut record, claim(2));
        pend(&mut record, claim(3));
        pend(&mut record, claim(4));
        let due = PointerDue {
            permission: Permission::Write,
            grant_floor: Some(7),
            since: UnixMillis(9_000),
        };
        record.apply(&[
            None,
            Some(Verdict::PointerDue(due)),
            Some(Verdict::PointerDue(PointerDue {
                permission: Permission::Read,
                grant_floor: None,
                since: UnixMillis(9_000),
            })),
            Some(Verdict::Refused(ConversionRefusal::GrantSetFull)),
        ]);
        let decoded =
            decode_conversions(&encode_conversions(&record).expect("encodes")).expect("decodes");
        assert_eq!(decoded, record);
        assert_eq!(decoded.entries()[0].state, EntryState::Acking);
        assert_eq!(decoded.entries()[1].state, EntryState::PointerDue(due));
        assert_eq!(decoded.pending().collect::<Vec<_>>(), vec![&claim(1)]);
    }

    /// The decoder refuses an entry shape the encoder never writes.
    #[test]
    fn an_entry_with_two_states_is_refused() {
        let entry = |extra: &[(&str, Value)]| {
            let mut m = Map::new();
            m.insert("ackedAt", Value::Unsigned(1));
            m.insert("claim", Value::Bytes(vec![1; 40]));
            m.insert("sender", Value::Bytes(vec![1; IDENTITY_PUBLIC_LEN]));
            for (key, value) in extra {
                m.insert(*key, value.clone());
            }
            let mut body = Map::new();
            body.insert("entries", Value::Array(vec![Value::Map(m)]));
            body.insert("v", Value::Unsigned(FORMAT_V));
            decode_conversions(&encode_fixed_depth(&Value::Map(body)))
        };
        assert!(entry(&[]).is_ok());
        assert!(entry(&[("acking", Value::Bool(false))]).is_err());
        assert!(entry(&[("grantFloor", Value::Unsigned(3))]).is_err());
        assert!(
            entry(&[
                ("acking", Value::Bool(true)),
                ("refused", Value::Text("grant-set-full".to_owned())),
            ])
            .is_err()
        );
        assert!(
            entry(&[
                ("pointerDue", Value::Text("read".to_owned())),
                ("pointerDueAt", Value::Unsigned(2)),
            ])
            .is_ok()
        );
        assert!(entry(&[("pointerDue", Value::Text("read".to_owned()))]).is_err());
        assert!(entry(&[("pointerDueAt", Value::Unsigned(2))]).is_err());
        assert!(
            entry(&[
                ("pointerDue", Value::Text("admin".to_owned())),
                ("pointerDueAt", Value::Unsigned(2)),
            ])
            .is_err()
        );
    }

    /// ADR 0023 D9: a cut frees a slot, so a fresh copy of a refused claim is
    /// pending again, and the refusal goes.
    #[test]
    fn a_fresh_copy_of_a_refused_claim_is_pending_again() {
        let mut record = ConversionRecord::default();
        pend(&mut record, claim(1));
        record.apply(&[Some(Verdict::Refused(
            ConversionRefusal::AdmissionCapReached,
        ))]);
        assert_eq!(record.hold_for_ack(claim(1)), Some(Hold::Fresh));
        record.settle_ack(&claim(1), true);
        assert_eq!(record.entries().len(), 1);
        assert_eq!(record.pending().collect::<Vec<_>>(), vec![&claim(1)]);
    }

    /// A full record holds no new claim and keeps every entry, and a fresh
    /// copy of a refused claim replaces the refusal in its slot.
    #[test]
    fn a_full_record_holds_no_new_claim_and_keeps_its_refusals() {
        let mut record = ConversionRecord::default();
        let seeds = u8::try_from(MAX_CONVERSION_ENTRIES - 1).expect("fits");
        for seed in 0..=seeds {
            pend(&mut record, claim(seed));
        }
        let mut verdicts = vec![None; MAX_CONVERSION_ENTRIES];
        verdicts[0] = Some(Verdict::Refused(ConversionRefusal::GrantSetFull));
        record.apply(&verdicts);
        let before = record.clone();

        let mut stranger = claim(1);
        stranger.sender = [0xFF; IDENTITY_PUBLIC_LEN];
        assert_eq!(record.hold_for_ack(stranger), None);
        assert_eq!(record, before, "the refusal is kept");

        assert_eq!(record.hold_for_ack(claim(0)), Some(Hold::Fresh));
        assert_eq!(record.entries().len(), MAX_CONVERSION_ENTRIES);
        assert!(record.entries().iter().all(|e| e.refused().is_none()));
    }

    #[test]
    fn the_oldest_refusal_goes_past_the_bound_and_is_answered() {
        let mut record = ConversionRecord::default();
        let past = u8::try_from(MAX_REFUSED_CONVERSIONS).expect("fits");
        for seed in 0..=past {
            pend(&mut record, claim(seed));
        }
        pend(&mut record, claim(past + 1));
        let mut verdicts =
            vec![Some(Verdict::Refused(ConversionRefusal::GrantSetFull)); record.entries().len()];
        verdicts[usize::from(past) + 1] = None;
        assert_eq!(record.apply(&verdicts), 1, "one refusal went");
        assert_eq!(record.entries().len(), MAX_REFUSED_CONVERSIONS + 1);
        assert_eq!(record.entries()[0].claim, claim(1), "the oldest");
        assert_eq!(
            record.pending().collect::<Vec<_>>(),
            vec![&claim(past + 1)],
            "and never a pending entry"
        );
    }

    #[test]
    fn a_settled_verdict_drops_only_its_own_entry() {
        let mut record = ConversionRecord::default();
        pend(&mut record, claim(1));
        pend(&mut record, claim(2));
        assert_eq!(record.apply(&[Some(Verdict::Settled), None]), 0);
        assert_eq!(record.pending().collect::<Vec<_>>(), vec![&claim(2)]);
    }

    #[test]
    fn retiring_refusals_keeps_the_pending_entries() {
        let mut record = ConversionRecord::default();
        pend(&mut record, claim(1));
        pend(&mut record, claim(2));
        record.apply(&[
            None,
            Some(Verdict::Refused(ConversionRefusal::ContactBookFull)),
        ]);
        assert_eq!(record.retire_refused(|_| true), 1);
        assert_eq!(record.pending().collect::<Vec<_>>(), vec![&claim(1)]);
    }

    /// Encode and decode refuse a payload past the bound alike (AGENTS.md
    /// rule 8).
    #[test]
    fn a_payload_past_its_bound_is_refused_at_both_ends() {
        let mut record = ConversionRecord::default();
        let mut long = claim(1);
        long.payload = vec![0; MAX_CLAIM_PAYLOAD_BYTES + 1];
        pend(&mut record, long.clone());
        assert!(encode_conversions(&record).is_err());

        let mut m = Map::new();
        m.insert("ackedAt", Value::Unsigned(1));
        m.insert("claim", Value::Bytes(long.payload));
        m.insert("sender", Value::Bytes(long.sender.to_vec()));
        let mut body = Map::new();
        body.insert("entries", Value::Array(vec![Value::Map(m)]));
        body.insert("v", Value::Unsigned(FORMAT_V));
        assert!(decode_conversions(&encode_fixed_depth(&Value::Map(body))).is_err());
    }

    #[test]
    fn an_unknown_refusal_or_key_is_refused() {
        let mut record = ConversionRecord::default();
        pend(&mut record, claim(1));
        let bytes = encode_conversions(&record).expect("encodes");
        let mut tree = decode(&bytes).expect("det-CBOR");
        let Value::Map(body) = &mut tree else {
            panic!("a map");
        };
        let Some(Value::Array(entries)) = body.get("entries").cloned() else {
            panic!("entries");
        };
        let Value::Map(mut entry) = entries[0].clone() else {
            panic!("an entry map");
        };
        entry.insert("refused", Value::Text("tired".to_owned()));
        body.insert("entries", Value::Array(vec![Value::Map(entry.clone())]));
        assert!(decode_conversions(&encode_fixed_depth(&tree)).is_err());

        entry.insert("refused", Value::Text("grant-set-full".to_owned()));
        entry.insert("extra", Value::Unsigned(1));
        let Value::Map(body) = &mut tree else {
            panic!("a map");
        };
        body.insert("entries", Value::Array(vec![Value::Map(entry)]));
        assert!(decode_conversions(&encode_fixed_depth(&tree)).is_err());
    }
}
