//! The durable op record: `v || ownerTag || contentRootCid? || sealed(body)`
//! (blueprint/engine.md "Sync core: Ops").
//!
//! The op queue is namespaced per origin, not per account, so a record must say
//! whose it is *before* anything tries to open it. The owner tag is the owner's
//! `enc-subkey` public half verbatim: it names exactly the key that opens the
//! body, so "is this mine?" and "can I open this?" are one question.
//!
//! Three fields stay in the clear. The version, because a build that cannot
//! interpret a record must still be able to tell that apart from corruption —
//! the engine retains a forward-version record instead of dead-lettering and
//! deleting an unpublished queue. The tag, because routing precedes decryption.
//! The content root CID, because orphan GC must expand a staged root without a
//! key. All three are the AAD, so rewriting any of them fails the HPKE tag.
//!
//! **The clear-header framing is frozen across versions.** A future `v` may
//! change the sealed body, the suite, or the AAD layout, but every op record
//! ever written carries these five keys with these types, so this build can
//! read a later build's header — which is what keeps a retained record's staged
//! bytes reachable and pinned rather than orphan-collected.
//!
//! The body is opaque here — core seals the engine's intent bytes and never
//! interprets them.

use zeroize::Zeroizing;

use crate::codec::{Map, Value, decode, encode, encode_fixed_depth};
use crate::content::is_wellformed_content_cid;
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_OP_RECORD};
use crate::seal::body::{bytes_fixed, req};
use crate::suite::hpke::{self, ENC_LEN};
use crate::suite::x25519::{X25519Public, X25519Secret};

/// The op-record format version this build writes and can open. Carried in the
/// clear header *and* bound into the AAD: the clear copy lets a reader classify
/// a version it cannot open, the AAD binding makes rewriting that copy fail the
/// tag.
pub const OP_RECORD_V: u64 = 2;

/// The HPKE `info` string — the key-schedule domain separator, distinct from
/// the grant family's so an owner blob and an op record, both HPKE-to-self
/// under the same enc subkey, are never mutually transplantable.
const OP_RECORD_HPKE_INFO: &[u8] = b"cipherbox/v2/op-record";

/// The clear header of a durable op record. Readable at any version — see the
/// module's frozen-framing note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRecordHeader {
    /// The format version the record was written at, as declared. Only
    /// [`OP_RECORD_V`] opens; any other is a record to retain, not to reject.
    pub version: u64,
    /// The owner's `enc-subkey` public half, verbatim.
    pub owner_tag: [u8; ENC_LEN],
    /// The staged content DAG root's CID — simultaneously the root's staging
    /// key and the published version's `contentCid` — for a content op.
    pub content_root_cid: Option<Vec<u8>>,
}

/// The invariant the seal path guards and the decode path rejects, kept
/// symmetric through this one function (AGENTS.md rule 8): a present content
/// root CID is the frozen content-plane framing. Release-active — a record the
/// decoder refuses would strand its staged bytes with no way to reach them.
fn check_content_root_cid(cid: Option<&[u8]>) -> Result<(), CodecError> {
    match cid {
        Some(cid) if !is_wellformed_content_cid(cid) => {
            Err(TrustViolation::ContentCidMismatch.into())
        }
        _ => Ok(()),
    }
}

fn cid_value(cid: Option<&[u8]>) -> Value {
    cid.map_or(Value::Null, |c| Value::Bytes(c.to_vec()))
}

/// The AAD of an op record: its own clear header under the `cipherbox/v2`
/// domain separator and the `op-record` structure tag.
///
/// Deliberately not an [`AadContext`](super::AadContext): that frozen shape
/// binds a node id, scope, and epoch, none of which a local journal entry has.
/// What an op record must bind is the header it carries in the clear.
fn op_record_aad(header: &OpRecordHeader) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(header.version),
        Value::Unsigned(u64::from(STRUCT_TAG_OP_RECORD)),
        Value::Bytes(header.owner_tag.to_vec()),
        cid_value(header.content_root_cid.as_deref()),
    ]))
}

/// Seal `body` into a durable op record addressed to the owner's own enc
/// subkey. The owner tag is derived from `owner_enc_pub`, so a record can never
/// carry a tag naming a key that does not open it.
///
/// `ephemeral_scalar` must be **fresh per record**: HPKE ephemeral reuse across
/// two seals under one recipient key is a confidentiality break
/// ([`hpke::hpke_seal`]).
pub fn seal_op_record(
    owner_enc_pub: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    content_root_cid: Option<&[u8]>,
    body: &[u8],
) -> Result<Vec<u8>, CodecError> {
    check_content_root_cid(content_root_cid)?;
    let header = OpRecordHeader {
        version: OP_RECORD_V,
        owner_tag: owner_enc_pub.to_bytes(),
        content_root_cid: content_root_cid.map(<[u8]>::to_vec),
    };
    let sealed = hpke::hpke_seal(
        owner_enc_pub,
        ephemeral_scalar,
        OP_RECORD_HPKE_INFO,
        &op_record_aad(&header),
        body,
    );
    let mut m = Map::new();
    m.insert("ciphertext", Value::Bytes(sealed.ciphertext));
    m.insert("contentRootCid", cid_value(content_root_cid));
    m.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    m.insert("ownerTag", Value::Bytes(header.owner_tag.to_vec()));
    m.insert("v", Value::Unsigned(header.version));
    encode(&Value::Map(m))
}

/// The clear header of `record`, read **without a key** and **at any version**:
/// the ownership check that precedes every open, and the root a keyless
/// orphan-GC pass expands.
///
/// Deliberately does not reject an unrecognised [`OpRecordHeader::version`] —
/// that is [`open_op_record`]'s job. A caller that cannot open a record must
/// still learn its owner and its staged root, or a forward-version entry looks
/// like corruption and its bytes are collected out from under it.
pub fn decode_op_record_header(record: &[u8]) -> Result<OpRecordHeader, CodecError> {
    Ok(decode_parts(record)?.0)
}

/// Open a record sealed to `owner_enc_secret`, returning its clear header and
/// the opaque body.
///
/// Fails closed with [`Malformed::UnsupportedRecordVersion`] when the record
/// declares a version this build does not implement — release-active, because
/// opening a future record under this build's body grammar would misread its
/// intent. Fails closed with [`TrustViolation::HpkeOpenFailed`] when the record
/// is another identity's, tampered, or carries a rewritten header — the header
/// is the AAD, so it is authenticated rather than merely present.
pub fn open_op_record(
    owner_enc_secret: &X25519Secret,
    record: &[u8],
) -> Result<(OpRecordHeader, Zeroizing<Vec<u8>>), CodecError> {
    let (header, enc, ciphertext) = decode_parts(record)?;
    if header.version != OP_RECORD_V {
        return Err(Malformed::UnsupportedRecordVersion {
            version: header.version,
        }
        .into());
    }
    let body = hpke::hpke_open(
        owner_enc_secret,
        &enc,
        OP_RECORD_HPKE_INFO,
        &op_record_aad(&header),
        &ciphertext,
    )?;
    Ok((header, body))
}

fn decode_parts(record: &[u8]) -> Result<(OpRecordHeader, [u8; ENC_LEN], Vec<u8>), CodecError> {
    let value = decode(record)?;
    let map = value.as_map()?;
    let version = req(map, "v")?.as_unsigned()?;
    let owner_tag = bytes_fixed::<ENC_LEN>(req(map, "ownerTag")?, "ownerTag")?;
    let enc = bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?;
    let ciphertext = req(map, "ciphertext")?.as_bytes()?.to_vec();
    let content_root_cid = match req(map, "contentRootCid")? {
        Value::Null => None,
        other => Some(other.as_bytes()?.to_vec()),
    };
    check_content_root_cid(content_root_cid.as_deref())?;
    Ok((
        OpRecordHeader {
            version,
            owner_tag,
            content_root_cid,
        },
        enc,
        ciphertext,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{CONTENT_CID_CODEC, compute_cid};

    fn secret(b: u8) -> X25519Secret {
        X25519Secret::from_scalar([b; 32])
    }

    fn cid() -> Vec<u8> {
        compute_cid(CONTENT_CID_CODEC, b"sealed root block")
    }

    #[test]
    fn a_metadata_record_round_trips_and_tags_its_owner() {
        let owner = secret(7);
        let record = seal_op_record(&owner.public(), &[1; 32], None, b"intent bytes").unwrap();

        let header = decode_op_record_header(&record).unwrap();
        assert_eq!(header.version, OP_RECORD_V);
        assert_eq!(header.owner_tag, owner.public().to_bytes());
        assert_eq!(header.content_root_cid, None);

        let (opened, body) = open_op_record(&owner, &record).unwrap();
        assert_eq!(opened, header);
        assert_eq!(&body[..], b"intent bytes");
    }

    #[test]
    fn a_content_record_exposes_its_root_cid_without_a_key() {
        let owner = secret(9);
        let record = seal_op_record(&owner.public(), &[2; 32], Some(&cid()), b"intent").unwrap();
        assert_eq!(
            decode_op_record_header(&record).unwrap().content_root_cid,
            Some(cid())
        );
    }

    #[test]
    fn a_foreign_record_never_opens() {
        let owner = secret(1);
        let stranger = secret(2);
        let record = seal_op_record(&owner.public(), &[3; 32], None, b"mine").unwrap();

        // The tag is readable — that is how a foreign record is skipped rather
        // than dead-lettered — but the body is not.
        assert_ne!(
            decode_op_record_header(&record).unwrap().owner_tag,
            stranger.public().to_bytes()
        );
        assert_eq!(
            open_op_record(&stranger, &record).unwrap_err().check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_swapped_header_fails_closed() {
        let owner = secret(4);
        let record = seal_op_record(&owner.public(), &[5; 32], Some(&cid()), b"intent").unwrap();

        // Re-frame the record with a different (well-formed) root CID: the
        // header is the AAD, so the ciphertext no longer authenticates.
        let value = decode(&record).unwrap();
        let mut map = value.as_map().unwrap().clone();
        let other = compute_cid(CONTENT_CID_CODEC, b"another root block");
        map.insert("contentRootCid", Value::Bytes(other));
        let tampered = encode(&Value::Map(map)).unwrap();

        assert_eq!(
            open_op_record(&owner, &tampered).unwrap_err().check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_tampered_ciphertext_fails_closed() {
        let owner = secret(6);
        let record = seal_op_record(&owner.public(), &[7; 32], None, b"intent").unwrap();
        let value = decode(&record).unwrap();
        let mut map = value.as_map().unwrap().clone();
        let mut ct = map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec();
        ct[0] ^= 1;
        map.insert("ciphertext", Value::Bytes(ct));
        let tampered = encode(&Value::Map(map)).unwrap();

        assert_eq!(
            open_op_record(&owner, &tampered).unwrap_err().check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn a_forward_version_record_reads_its_header_but_never_opens() {
        let owner = secret(11);
        let record = seal_op_record(&owner.public(), &[12; 32], Some(&cid()), b"intent").unwrap();
        let value = decode(&record).unwrap();
        let mut map = value.as_map().unwrap().clone();
        map.insert("v", Value::Unsigned(OP_RECORD_V + 1));
        let future = encode(&Value::Map(map)).unwrap();

        // Keyless: owner and staged root stay reachable, so the record can be
        // retained and its bytes pinned rather than dead-lettered and deleted.
        let header = decode_op_record_header(&future).unwrap();
        assert_eq!(header.version, OP_RECORD_V + 1);
        assert_eq!(header.owner_tag, owner.public().to_bytes());
        assert_eq!(header.content_root_cid, Some(cid()));

        assert_eq!(
            open_op_record(&owner, &future).unwrap_err().check(),
            "unsupported-record-version",
            "an unimplemented version must not reach the AEAD"
        );
    }

    #[test]
    fn a_missing_version_is_malformed() {
        let owner = secret(15);
        let record = seal_op_record(&owner.public(), &[16; 32], None, b"intent").unwrap();
        let value = decode(&record).unwrap();
        let mut map = value.as_map().unwrap().clone();
        map.remove("v");
        let headerless = encode(&Value::Map(map)).unwrap();
        assert_eq!(
            decode_op_record_header(&headerless).unwrap_err().check(),
            "missing-field"
        );
    }

    #[test]
    fn a_malformed_root_cid_is_refused_at_seal_and_at_decode() {
        let owner = secret(8);
        // Seal side: release-active `Err`, never a stripped assertion.
        assert_eq!(
            seal_op_record(&owner.public(), &[9; 32], Some(b"not a cid"), b"intent")
                .unwrap_err()
                .check(),
            "content-cid-mismatch"
        );

        // Decode side: the same check on a hand-framed record.
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(vec![0; 16]));
        m.insert("contentRootCid", Value::Bytes(b"not a cid".to_vec()));
        m.insert("enc", Value::Bytes(vec![0; ENC_LEN]));
        m.insert("ownerTag", Value::Bytes(vec![0; ENC_LEN]));
        m.insert("v", Value::Unsigned(OP_RECORD_V));
        let hand_framed = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_op_record_header(&hand_framed).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn a_truncated_record_is_malformed_not_a_panic() {
        let owner = secret(3);
        let record = seal_op_record(&owner.public(), &[4; 32], None, b"intent").unwrap();
        assert!(decode_op_record_header(&record[..record.len() / 2]).is_err());
        assert!(decode_op_record_header(b"").is_err());
    }

    #[test]
    fn a_missing_owner_tag_is_malformed() {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(vec![0; 16]));
        m.insert("contentRootCid", Value::Null);
        m.insert("enc", Value::Bytes(vec![0; ENC_LEN]));
        m.insert("v", Value::Unsigned(OP_RECORD_V));
        let record = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_op_record_header(&record).unwrap_err().check(),
            "missing-field"
        );
    }
}
