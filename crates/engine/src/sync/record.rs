//! The durable op record — `ownerTag || contentRootCid? || sealed(op)`
//! (CONTEXT.md "Op record", "Owner tag").
//!
//! The staging store is namespaced per origin, not per account, so two accounts
//! on one browser profile share one op queue. The record's clear owner tag is
//! what keeps them apart, and it is read **strictly before** any open: an
//! unreadable record is dead-lettered and removed from the queue, so deciding
//! ownership from a failed open would let a second account's first login
//! destroy the first account's whole queue.
//!
//! Sealing and framing live in [`cipherbox_core::seal::op_record`]; this module
//! is the engine-side edge that binds an [`Op`] to it.

use cipherbox_core::seal::op_record::{decode_op_record_header, open_op_record, seal_op_record};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::{Zeroize, Zeroizing};

use crate::sync::op::{Op, OpDecodeError};

/// One record's sealing inputs.
///
/// `ephemeral_scalar` must be **fresh for every record**: HPKE ephemeral reuse
/// under one recipient key is a confidentiality break. Consumed by value and
/// deliberately not `Clone`, so one scalar seals one record. It is also secret
/// material in its own right — the recipient public half rides the record's
/// clear header, so the scalar alone reopens the body.
pub struct RecordSeal {
    /// The owner's `enc-subkey` public half — the sealing recipient, and the
    /// owner tag the record is stamped with.
    pub owner_enc_pub: X25519Public,
    /// Fresh entropy from the engine's injected [`Entropy`](crate::Entropy).
    pub ephemeral_scalar: Zeroizing<[u8; 32]>,
}

/// Seal `op` into the bytes the durable op queue stores.
///
/// Fails closed when the op references a staged root that is not a well-formed
/// content CID: the header is what a keyless GC pass expands, so a record the
/// decoder refuses would strand its staged bytes unreachable.
pub fn encode_op_record(seal: RecordSeal, op: &Op) -> Result<Vec<u8>, OpRecordError> {
    // The encoded intent is the plaintext this call is terminal owner of.
    let mut body = op.encode_body();
    let record = seal_op_record(
        &seal.owner_enc_pub,
        &seal.ephemeral_scalar,
        op.content_root_cid(),
        &body,
    )
    .map_err(|e| OpRecordError::Malformed(e.check()));
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
        .map_err(|e| OpRecordError::Malformed(e.check()))
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

    /// Classify one durable record: tag first, open second, nothing between.
    pub fn classify(&self, record: &[u8]) -> RecordClass {
        let header = match decode_op_record_header(record) {
            Ok(header) => header,
            Err(e) => return RecordClass::Undecodable(OpRecordError::Malformed(e.check())),
        };
        if header.owner_tag != self.owner_tag {
            return RecordClass::Foreign;
        }
        match open_op_record(self.enc_secret, record) {
            Ok((_, body)) => match Op::decode_body(&body) {
                Ok(op) => RecordClass::Mine(op),
                Err(e) => RecordClass::Undecodable(OpRecordError::Body(e)),
            },
            Err(e) => RecordClass::Undecodable(OpRecordError::Malformed(e.check())),
        }
    }
}

/// What a durable queue record is to the identity reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordClass {
    /// The reader's own, and its intent opened.
    Mine(Op),
    /// Another identity's. Invisible: never replayed, never surfaced, never
    /// removed — deleting it would destroy that account's unpublished offline
    /// work, and dead-lettering it would hand this account a permanent notice
    /// about an op it cannot see.
    Foreign,
    /// Unreadable — corrupt, truncated, or a forward-version entry.
    Undecodable(OpRecordError),
}

/// A durable record could not be produced or read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpRecordError {
    /// The record framing, its header, or its seal failed core's check of that
    /// name (a stable check id, never key material).
    Malformed(&'static str),
    /// The record opened, but its sealed intent body did not decode.
    Body(OpDecodeError),
}

impl core::fmt::Display for OpRecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(check) => write!(f, "op record rejected: {check}"),
            Self::Body(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpRecordError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::NodeId;
    use crate::seams::UnixMillis;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};

    fn owner(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; 32])
    }

    fn seal_for(secret: &X25519Secret, scalar: u8) -> RecordSeal {
        RecordSeal {
            owner_enc_pub: secret.public(),
            ephemeral_scalar: Zeroizing::new([scalar; 32]),
        }
    }

    fn rename_op() -> Op {
        Op::rename(NodeId([1; 16]), "b.txt", 3, UnixMillis(1_700))
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
    fn a_foreign_record_classifies_foreign_rather_than_undecodable() {
        let me = owner(1);
        let stranger = owner(2);
        let record = encode_op_record(seal_for(&me, 9), &rename_op()).unwrap();
        assert_eq!(
            RecordReader::new(&stranger).classify(&record),
            RecordClass::Foreign,
            "a foreign record must never reach the dead-letter path"
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
        let op = Op::update_content(NodeId([4; 16]), cid.clone(), 1, UnixMillis(5));
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
        let op = Op::update_content(NodeId([1; 16]), b"not a cid".to_vec(), 1, UnixMillis(1));
        // Returned, never asserted: the guard must fire in a release build too.
        assert_eq!(
            encode_op_record(seal_for(&me, 6), &op),
            Err(OpRecordError::Malformed("content-cid-mismatch"))
        );
    }
}
