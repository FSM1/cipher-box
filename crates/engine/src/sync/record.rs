//! The durable op record — `v || ownerTag || contentRootCid? || sealed(op)`
//! (CONTEXT.md "Op record", "Owner tag", "Retained record").
//!
//! Sealing and framing live in [`cipherbox_core::seal::op_record`]; this module
//! is the engine-side edge that binds an [`Op`] to it, and it owns the one
//! decision core cannot make: which failures mean "not mine to act on" and
//! which mean "delete this".

use cipherbox_core::seal::op_record::{
    OP_RECORD_V, decode_op_record_header, open_op_record, seal_op_record,
};
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::{Zeroize, Zeroizing};

use crate::sync::op::Op;

/// One record's sealing inputs.
///
/// `ephemeral_scalar` must be **fresh for every record**: HPKE ephemeral reuse
/// under one recipient key is a confidentiality break. Consumed by value and
/// deliberately not `Clone`, so one scalar seals one record.
pub struct RecordSeal<'a> {
    /// The owner's `enc-subkey` — recipient, HPKE static sender, and the source
    /// of the owner tag the record is stamped with. The secret, not the public
    /// half: authoring a record is what the seal authenticates.
    pub owner_enc_secret: &'a X25519Secret,
    /// Fresh entropy from the engine's injected [`Entropy`](crate::Entropy).
    pub ephemeral_scalar: Zeroizing<[u8; 32]>,
}

/// Seal `op` into the bytes the durable op queue stores.
///
/// Fails closed when the op references a staged root that is not a well-formed
/// content CID: the header is what a keyless GC pass expands, so a record the
/// decoder refuses would strand its staged bytes unreachable.
pub fn encode_op_record(seal: RecordSeal<'_>, op: &Op) -> Result<Vec<u8>, OpRecordError> {
    // The encoded intent is the plaintext this call is terminal owner of.
    let mut body = op.encode_body();
    let record = seal_op_record(
        seal.owner_enc_secret,
        &seal.ephemeral_scalar,
        op.content_root_cid(),
        &body,
    )
    .map_err(|e| OpRecordError(e.check()));
    body.zeroize();
    record
}

/// The staged content DAG root a queued record references, read without a key.
///
/// `Err` when the header itself is unreadable: such a record may still hold
/// staged bytes, so a GC pass must not read the absent CID as "references
/// nothing".
pub fn record_content_root_cid(record: &[u8]) -> Result<Option<Vec<u8>>, OpRecordError> {
    decode_op_record_header(record)
        .map(|h| h.content_root_cid)
        .map_err(|e| OpRecordError(e.check()))
}

/// The owner's op-record custody: the clear tag every reader compares against,
/// and the secret that opens a record bearing it. One key answers both "is this
/// mine?" and "can I open this?".
pub struct RecordReader<'a> {
    owner_tag: [u8; 32],
    enc_secret: &'a X25519Secret,
}

impl<'a> RecordReader<'a> {
    /// Adopt the session's `enc-subkey` as op-record custody.
    pub fn new(enc_secret: &'a X25519Secret) -> Self {
        Self {
            owner_tag: enc_secret.public().to_bytes(),
            enc_secret,
        }
    }

    /// The clear tag this reader answers to — the owner's `enc-subkey` public
    /// half, and so the identity a classification is only valid for.
    pub(crate) fn owner_tag(&self) -> [u8; 32] {
        self.owner_tag
    }

    /// Classify one durable record. Every discriminator that can say "not for
    /// me" runs before the [`Undecodable`](RecordClass::Undecodable) verdict,
    /// because that verdict *deletes*.
    pub fn classify(&self, record: &[u8]) -> RecordClass {
        let header = match decode_op_record_header(record) {
            Ok(header) => header,
            Err(e) => return RecordClass::Undecodable(OpRecordError(e.check())),
        };
        if header.version != OP_RECORD_V {
            return RecordClass::Retained(RetainedReason::UnsupportedVersion);
        }
        if header.owner_tag != self.owner_tag {
            return RecordClass::Retained(RetainedReason::ForeignOwner);
        }
        match open_op_record(self.enc_secret, record) {
            // The AEAD tag has verified, so this plaintext is what a holder of
            // our own enc-subkey wrote — a grammar it does not satisfy is a
            // newer build's intent, never corruption.
            Ok((header, body)) => match Op::decode_body(&body) {
                // `encode_op_record` derives the clear root from the body's, so
                // a disagreement is a hand-framed record: GC would pin one root
                // while the drain published another (AGENTS.md rule 8).
                Ok(op) if op.content_root_cid() != header.content_root_cid.as_deref() => {
                    RecordClass::Undecodable(OpRecordError("content-cid-mismatch"))
                }
                Ok(op) => RecordClass::Mine(op),
                Err(_) => RecordClass::Retained(RetainedReason::UnsupportedBody),
            },
            Err(e) => RecordClass::Undecodable(OpRecordError(e.check())),
        }
    }
}

/// What a durable queue record is to the identity reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordClass {
    /// The reader's own, and its intent opened.
    Mine(Op),
    /// Held, not acted on: never replayed, never surfaced as this account's,
    /// never removed, and its staged root still counts as referenced so orphan
    /// GC leaves its bytes alone.
    Retained(RetainedReason),
    /// Unreadable — corrupt, truncated, or forged under this reader's own tag
    /// by a co-tenant of the store. Dead-lettered and dropped from the durable
    /// queue, so it is not re-emitted every boot.
    Undecodable(OpRecordError),
}

/// Why a record is held rather than replayed (CONTEXT.md "Retained record").
/// Every reason is terminal for *this* session and none is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedReason {
    /// Another identity's record.
    ForeignOwner,
    /// A header version this build does not implement.
    UnsupportedVersion,
    /// The header version matched and the seal opened, but the intent body is
    /// a grammar this build does not implement — a newer build wrote it
    /// without bumping the header version.
    UnsupportedBody,
}

/// A durable record could not be produced or read back: the record framing,
/// its header, or its seal failed core's check of that name (a stable check id,
/// never key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRecordError(pub &'static str);

impl core::fmt::Display for OpRecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "op record rejected: {}", self.0)
    }
}

impl std::error::Error for OpRecordError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::NodeId;
    use crate::seams::UnixMillis;
    use cipherbox_core::codec;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};

    fn owner(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; 32])
    }

    fn seal_for(secret: &X25519Secret, scalar: u8) -> RecordSeal<'_> {
        RecordSeal {
            owner_enc_secret: secret,
            ephemeral_scalar: Zeroizing::new([scalar; 32]),
        }
    }

    fn staged(root_cid: Vec<u8>, plaintext_size: u64) -> crate::sync::op::StagedContent {
        crate::sync::op::StagedContent {
            root_cid,
            plaintext_size,
            sealed_content_key: b"sealed-key-blob".to_vec(),
            epoch: 1,
        }
    }

    fn rename_op() -> Op {
        Op::rename(NodeId([1; 16]), "b.txt", 3, UnixMillis(1_700))
    }

    /// Re-frame a sealed record at another declared version — what a build
    /// ahead of this one writes. Its body no longer opens here, which is the
    /// point: only the clear header may be read.
    fn at_version(record: &[u8], version: u64) -> Vec<u8> {
        let value = codec::decode(record).unwrap();
        let mut map = value.as_map().unwrap().clone();
        map.insert("v", codec::Value::Unsigned(version));
        codec::encode(&codec::Value::Map(map)).unwrap()
    }

    #[test]
    fn a_record_round_trips_for_the_identity_that_sealed_it() {
        let me = owner(1);
        let record = encode_op_record(seal_for(&me, 9), &rename_op()).unwrap();
        assert_eq!(
            RecordReader::new(&me).classify(&record),
            RecordClass::Mine(rename_op())
        );
    }

    #[test]
    fn a_foreign_record_is_retained_rather_than_undecodable() {
        let me = owner(1);
        let stranger = owner(2);
        let record = encode_op_record(seal_for(&me, 9), &rename_op()).unwrap();
        assert_eq!(
            RecordReader::new(&stranger).classify(&record),
            RecordClass::Retained(RetainedReason::ForeignOwner),
            "a foreign record must never reach the dead-letter path"
        );
    }

    #[test]
    fn a_forward_version_record_is_retained_even_for_its_own_owner() {
        let me = owner(1);
        let record = at_version(
            &encode_op_record(seal_for(&me, 9), &rename_op()).unwrap(),
            OP_RECORD_V + 1,
        );
        assert_eq!(
            RecordReader::new(&me).classify(&record),
            RecordClass::Retained(RetainedReason::UnsupportedVersion),
            "a format bump must not dead-letter and delete the owner's own queue"
        );
    }

    #[test]
    fn a_forward_version_record_still_yields_its_staged_root() {
        let me = owner(3);
        let cid = compute_cid(CONTENT_CID_CODEC, b"sealed root");
        let op = Op::update_content(NodeId([4; 16]), staged(cid.clone(), 11), 1, UnixMillis(5));
        let record = at_version(
            &encode_op_record(seal_for(&me, 8), &op).unwrap(),
            OP_RECORD_V + 1,
        );
        assert_eq!(
            record_content_root_cid(&record),
            Ok(Some(cid)),
            "retention is only durable if GC can still see the root it pins"
        );
    }

    #[test]
    fn a_record_bearing_our_tag_but_a_tampered_body_is_undecodable() {
        let me = owner(4);
        let mut record = encode_op_record(seal_for(&me, 5), &rename_op()).unwrap();
        // Flip a byte inside the sealed body; the clear tag still reads as ours.
        let last = record.len() - 1;
        record[last] ^= 1;
        assert!(matches!(
            RecordReader::new(&me).classify(&record),
            RecordClass::Undecodable(_)
        ));
    }

    /// Seal an arbitrary body to `secret`, bypassing [`encode_op_record`] —
    /// the only way to build the records a conforming encoder never emits.
    fn seal_body(secret: &X25519Secret, scalar: u8, cid: Option<&[u8]>, body: &[u8]) -> Vec<u8> {
        cipherbox_core::seal::op_record::seal_op_record(secret, &[scalar; 32], cid, body).unwrap()
    }

    #[test]
    fn an_authenticated_body_in_an_unknown_grammar_is_retained_not_deleted() {
        let me = owner(11);
        // The AEAD tag verifies, so only a holder of our own enc-subkey wrote
        // this — a newer build's intent, never corruption. Deleting it would
        // destroy that build's queue.
        let record = seal_body(&me, 12, None, b"{\"someFutureOp\":true}");
        assert_eq!(
            RecordReader::new(&me).classify(&record),
            RecordClass::Retained(RetainedReason::UnsupportedBody)
        );
    }

    #[test]
    fn a_header_root_disagreeing_with_the_body_is_undecodable() {
        let me = owner(13);
        let cid = compute_cid(CONTENT_CID_CODEC, b"header root");
        // A conforming encoder derives the clear root from the body's, so this
        // is hand-framed: the header claims a staged root the intent does not.
        // GC would pin one root while the drain published another.
        let body = rename_op().encode_body();
        let record = seal_body(&me, 14, Some(&cid), &body);
        assert_eq!(
            RecordReader::new(&me).classify(&record),
            RecordClass::Undecodable(OpRecordError("content-cid-mismatch"))
        );
    }

    #[test]
    fn a_record_forged_from_our_public_owner_tag_is_never_replayed() {
        // #879: the tag is our enc-subkey public half, in the clear on every
        // record in a store the op queue shares per origin, not per account. A
        // co-tenant can seal to it in HPKE base mode; only the auth-mode open
        // stops the intent riding our write keys. It must not classify as
        // `Mine`, and — unlike an unknown grammar — must not be retained either:
        // nothing authored it that this device owes custody to.
        let me = owner(31);
        let header = cipherbox_core::seal::op_record::OpRecordHeader {
            version: OP_RECORD_V,
            owner_tag: me.public().to_bytes().to_vec(),
            content_root_cid: None,
        };
        let forged = cipherbox_core::suite::hpke::hpke_seal(
            &me.public(),
            &[32; 32],
            cipherbox_core::seal::op_record::OP_RECORD_HPKE_INFO,
            &cipherbox_core::seal::op_record::op_record_aad(&header),
            &Op::delete(NodeId([9; 16]), 1, UnixMillis(1), 1).encode_body(),
        );
        let mut map = codec::Map::new();
        map.insert("ciphertext", codec::Value::Bytes(forged.ciphertext));
        map.insert("contentRootCid", codec::Value::Null);
        map.insert("enc", codec::Value::Bytes(forged.enc.to_vec()));
        map.insert("ownerTag", codec::Value::Bytes(header.owner_tag.clone()));
        map.insert("v", codec::Value::Unsigned(OP_RECORD_V));
        let record = codec::encode(&codec::Value::Map(map)).unwrap();

        assert_eq!(
            RecordReader::new(&me).classify(&record),
            RecordClass::Undecodable(OpRecordError("hpke-open-failed"))
        );
    }

    #[test]
    fn garbage_bytes_are_undecodable_not_foreign() {
        let me = owner(7);
        assert!(matches!(
            RecordReader::new(&me).classify(b"not a record"),
            RecordClass::Undecodable(_)
        ));
    }

    #[test]
    fn a_content_record_exposes_its_root_cid_keylessly() {
        let me = owner(3);
        let cid = compute_cid(CONTENT_CID_CODEC, b"sealed root");
        let op = Op::update_content(NodeId([4; 16]), staged(cid.clone(), 11), 1, UnixMillis(5));
        let record = encode_op_record(seal_for(&me, 8), &op).unwrap();

        assert_eq!(record_content_root_cid(&record), Ok(Some(cid)));
    }

    #[test]
    fn a_metadata_record_references_no_staged_root() {
        let me = owner(5);
        let record = encode_op_record(seal_for(&me, 7), &rename_op()).unwrap();
        assert_eq!(record_content_root_cid(&record), Ok(None));
    }

    #[test]
    fn an_unreadable_header_is_an_error_not_an_absent_root() {
        assert!(record_content_root_cid(b"not a record").is_err());
    }

    #[test]
    fn an_op_referencing_a_malformed_root_is_refused_at_encode() {
        let me = owner(6);
        let op = Op::update_content(
            NodeId([1; 16]),
            staged(b"not a cid".to_vec(), 9),
            1,
            UnixMillis(1),
        );
        // Returned, never asserted: the guard must fire in a release build too.
        assert_eq!(
            encode_op_record(seal_for(&me, 6), &op),
            Err(OpRecordError("content-cid-mismatch"))
        );
    }
}
