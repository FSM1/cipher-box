//! The scope-root grant section (blueprint/core.md "Envelope and structures:
//! Grant section", CONTEXT.md "Grant section").
//!
//! A scope root publishes, in `envelope.grantSection`, every seed-bearing
//! structure it carries bundled with that structure's detached signature, plus
//! the owner-signed grant-set commitment. This module is the **framing codec**
//! that assembles and parses that bundle: it composes the per-structure seal
//! outputs of [`super::grant`]/[`super::write_body`] as **opaque sealed bytes**
//! and introduces no crypto of its own. The adoption gate (`crates/engine`)
//! consumes a decoded [`GrantSection`], enumerates its structures, and
//! recomputes each `H(ciphertext)` before verifying the signatures — so the
//! record itself is the completeness authority, never a side list.
//!
//! The frame is a det-CBOR map under one strictness policy, unknown fields
//! preserved; its members are enumerated and documented on [`GrantSection`].
//! Each `sig` is the 64-byte Ed25519 structure signature over the
//! `{scopeId, epoch, structTag, recipientTag?, H(ciphertext)}` preimage
//! ([`super::structure`]); the byte string it binds is the HPKE `ciphertext`
//! (**not** `enc`) for grant blob / owner blob / ascent link, and the whole
//! symmetric sealed blob `nonce||ct||tag` for history link / write-body.
//!
//! Signatures are carried as raw fixed-width bytes and never parsed or verified
//! here — that is the gate's crypto step. This codec only frames and enforces
//! structure (lengths, required fields, tag uniqueness), fail-closed.

use std::collections::BTreeSet;

use crate::codec::scrub::{ScrubOnDrop, ScrubOwned};
use crate::codec::{Map, Value, decode, encode, encoded_len};
use crate::error::{CodecError, Malformed};
use crate::suite::ecdsa::SIGNATURE_LEN as ECDSA_SIG_LEN;
use crate::suite::ed25519::SIGNATURE_LEN as ED_SIG_LEN;
use crate::suite::hpke::ENC_LEN;
use crate::suite::secret::SECRET_LEN;

use super::body::{
    PreservedFields, assert_grant_tags_unique, assert_unknown_disjoint, assert_within_bound,
    bytes_fixed, collect_unknown, merge_unknown, req,
};
use super::envelope::{MAX_BLOCK_BYTES, MAX_CRITICAL_CARRIED_BYTES};
use super::grant::{GrantSetCommitment, decode_grant_set_commitment, encode_grant_set_commitment};
use super::write_body::MAX_WRITE_BODY_BYTES;

/// A grant blob as published in the grant section: its recipient blinded `tag`
/// (the lookup key and the structure signature's `recipientTag`), the HPKE
/// `enc`/`ciphertext` the recipient opens, and the `signature` over
/// `H(ciphertext)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGrantBlob {
    /// The recipient's blinded tag.
    pub tag: [u8; SECRET_LEN],
    /// The HPKE encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// The HPKE ciphertext (`ciphertext || tag`).
    pub ciphertext: Vec<u8>,
    /// The 64-byte Ed25519 structure signature over `H(ciphertext)`.
    pub signature: [u8; ED_SIG_LEN],
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const GRANT_BLOB_KNOWN: &[&str] = &["ciphertext", "enc", "sig", "tag"];

impl SignedGrantBlob {
    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        Ok(Self {
            tag: bytes_fixed::<SECRET_LEN>(req(map, "tag")?, "tag")?,
            enc: bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?,
            ciphertext: req(map, "ciphertext")?.as_bytes()?.to_vec(),
            signature: bytes_fixed::<ED_SIG_LEN>(req(map, "sig")?, "sig")?,
            unknown: collect_unknown(map, GRANT_BLOB_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(self.ciphertext.clone()));
        m.insert("enc", Value::Bytes(self.enc.to_vec()));
        m.insert("sig", Value::Bytes(self.signature.to_vec()));
        m.insert("tag", Value::Bytes(self.tag.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

/// The owner blob: the override seed HPKE-sealed to the owner enc subkey, with
/// its structure signature over `H(ciphertext)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOwnerBlob {
    /// The HPKE encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// The HPKE ciphertext (`ciphertext || tag`).
    pub ciphertext: Vec<u8>,
    /// The 64-byte Ed25519 structure signature over `H(ciphertext)`.
    pub signature: [u8; ED_SIG_LEN],
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const OWNER_BLOB_KNOWN: &[&str] = &["ciphertext", "enc", "sig"];

impl SignedOwnerBlob {
    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        Ok(Self {
            enc: bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?,
            ciphertext: req(map, "ciphertext")?.as_bytes()?.to_vec(),
            signature: bytes_fixed::<ED_SIG_LEN>(req(map, "sig")?, "sig")?,
            unknown: collect_unknown(map, OWNER_BLOB_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(self.ciphertext.clone()));
        m.insert("enc", Value::Bytes(self.enc.to_vec()));
        m.insert("sig", Value::Bytes(self.signature.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

/// The owner-write-blob: the write-scope seed HPKE-sealed to the owner enc
/// subkey (the write-plane mirror of the owner blob), with its structure
/// signature over `H(ciphertext)`. Present only where the record carries a
/// write-scope root the owner owns (`Option` = additive wire evolution: older
/// records that predate the tag decode with `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOwnerWriteBlob {
    /// The HPKE encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// The HPKE ciphertext (`ciphertext || tag`).
    pub ciphertext: Vec<u8>,
    /// The 64-byte Ed25519 structure signature over `H(ciphertext)`.
    pub signature: [u8; ED_SIG_LEN],
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const OWNER_WRITE_BLOB_KNOWN: &[&str] = &["ciphertext", "enc", "sig"];

impl SignedOwnerWriteBlob {
    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        Ok(Self {
            enc: bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?,
            ciphertext: req(map, "ciphertext")?.as_bytes()?.to_vec(),
            signature: bytes_fixed::<ED_SIG_LEN>(req(map, "sig")?, "sig")?,
            unknown: collect_unknown(map, OWNER_WRITE_BLOB_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ciphertext", Value::Bytes(self.ciphertext.clone()));
        m.insert("enc", Value::Bytes(self.enc.to_vec()));
        m.insert("sig", Value::Bytes(self.signature.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

/// The ascent link as published: the plaintext ascent public half, the HPKE
/// `enc`/`ciphertext`, and the structure signature over [`Self::sig_body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAscentLink {
    /// The plaintext ascent X25519 public key (the derive-and-verify anchor).
    pub ascent_public: [u8; ENC_LEN],
    /// The HPKE encapsulated key.
    pub enc: [u8; ENC_LEN],
    /// The HPKE ciphertext (`ciphertext || tag`).
    pub ciphertext: Vec<u8>,
    /// The 64-byte Ed25519 structure signature over `H(`[`Self::sig_body`]`)`.
    pub signature: [u8; ED_SIG_LEN],
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const ASCENT_LINK_KNOWN: &[&str] = &["ascentPublic", "ciphertext", "enc", "sig"];

impl SignedAscentLink {
    /// The bytes this link's structure signature is taken over
    /// ([`super::ascent_link_sig_body`]) — the ascent link alone signs over more
    /// than its ciphertext.
    pub fn sig_body(&self) -> Vec<u8> {
        super::ascent_link_sig_body(&self.ascent_public, &self.enc, &self.ciphertext)
    }
}

impl SignedAscentLink {
    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        Ok(Self {
            ascent_public: bytes_fixed::<ENC_LEN>(req(map, "ascentPublic")?, "ascentPublic")?,
            enc: bytes_fixed::<ENC_LEN>(req(map, "enc")?, "enc")?,
            ciphertext: req(map, "ciphertext")?.as_bytes()?.to_vec(),
            signature: bytes_fixed::<ED_SIG_LEN>(req(map, "sig")?, "sig")?,
            unknown: collect_unknown(map, ASCENT_LINK_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ascentPublic", Value::Bytes(self.ascent_public.to_vec()));
        m.insert("ciphertext", Value::Bytes(self.ciphertext.clone()));
        m.insert("enc", Value::Bytes(self.enc.to_vec()));
        m.insert("sig", Value::Bytes(self.signature.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

/// A symmetrically-sealed structure (history link or write-body): the opaque
/// wire sealed blob `nonce||ct||tag` and its structure signature over
/// `H(sealed)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSealed {
    /// The opaque symmetric sealed blob (`nonce(24) || ciphertext||tag`).
    pub sealed: Vec<u8>,
    /// The 64-byte Ed25519 structure signature over `H(sealed)`.
    pub signature: [u8; ED_SIG_LEN],
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const SEALED_KNOWN: &[&str] = &["sealed", "sig"];

impl SignedSealed {
    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        Ok(Self {
            sealed: req(map, "sealed")?.as_bytes()?.to_vec(),
            signature: bytes_fixed::<ED_SIG_LEN>(req(map, "sig")?, "sig")?,
            unknown: collect_unknown(map, SEALED_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("sealed", Value::Bytes(self.sealed.clone()));
        m.insert("sig", Value::Bytes(self.signature.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

/// The scope-root grant section: every seed-bearing structure plus the
/// owner-signed grant-set commitment. Rides `envelope.grantSection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSection {
    /// The owner-signed, epoch-free grant-set commitment.
    pub commitment: GrantSetCommitment,
    /// The 64-byte compact ECDSA owner signature over the commitment.
    pub commitment_sig: [u8; ECDSA_SIG_LEN],
    /// The per-recipient grant blobs (unique tags, fail-closed).
    pub grant_blobs: Vec<SignedGrantBlob>,
    /// The owner blob (present at every scope root).
    pub owner_blob: SignedOwnerBlob,
    /// The owner-write-blob — the write-plane mirror of the owner blob, present
    /// at every write-scope root the owner owns (`None` on records predating the
    /// tag, or read-only records). Its presence is not covered by the owner-signed
    /// `GrantSetCommitment`: a stripped blob adopts as `None` (availability-only
    /// loss of owner fresh-device write-recovery), so the owner cold-start consume
    /// path treats a missing blob on an owner-owned scope as re-authorable, not a
    /// hard failure.
    pub owner_write_blob: Option<SignedOwnerWriteBlob>,
    /// The ascent link, present only when the scope has a parent.
    pub ascent_link: Option<SignedAscentLink>,
    /// The per-epoch history links (empty at epoch 1).
    pub history_links: Vec<SignedSealed>,
    /// The scope root's sealed write-body.
    pub write_body: SignedSealed,
    /// Preserved unknown top-level fields (never any of the known keys).
    pub unknown: PreservedFields,
}

/// The frozen bound on a section's history links: the gate's stage-3 work is
/// `pseudonyms + structures` (blueprint/engine.md "One section, one signer"), so
/// an unbounded collection on either side lets one record dictate another
/// reader's CPU budget. Producers prune to a far smaller retained window
/// (`rotation/reseal.rs`), leaving this a malformed-input guard an honest
/// rotator never approaches.
pub const MAX_HISTORY_LINKS: usize = 256;

/// The frozen bound on a section's grant blobs — one per committed grantee.
/// It is equally the bound on [`GrantSetCommitment::entries`]: the ledger must
/// match the committed set exactly and a re-seal wraps one blob per ledger row,
/// so a commitment past this ceiling can only ever mint a section its own
/// encoder refuses.
pub const MAX_GRANT_BLOBS: usize = 1024;

/// The frozen headroom reserved above [`MAX_GRANT_SECTION_BYTES`] for the
/// envelope a section rides inside: its typed fields, the section's own key, and
/// the carried critical fields
/// [`MAX_CRITICAL_CARRIED_BYTES`](super::MAX_CRITICAL_CARRIED_BYTES) budgets.
///
/// A band left for those fields, not a proof they fit: `readSealed` carries no
/// byte bound of its own, so the whole-record ceiling stays the real backstop.
pub const GRANT_SECTION_ENVELOPE_HEADROOM_BYTES: usize = 48 * 1024;

/// The frozen bound on a grant section's **total encoded size**.
///
/// The section's per-collection bounds cap counts, not bytes: every sealed blob
/// is opaque and every level carries a preserved `unknown` map, and none of
/// those bytes is covered by the grant-set commitment or by a per-structure
/// signature. Unbounded, a committed writer inflates the framing once and every
/// later re-author of that root carries it verbatim past the block ceiling.
///
/// The value sits in the one band the surrounding constants leave. Its floor is
/// [`MAX_WRITE_BODY_BYTES`](super::MAX_WRITE_BODY_BYTES): the sealed write-body
/// rides in [`GrantSection::write_body`], so a smaller bound would refuse a body
/// the write-body codec mints. Its ceiling is
/// [`MAX_BLOCK_BYTES`](super::MAX_BLOCK_BYTES) less the envelope framing above.
/// It narrows the head-size lever rather than closing it — the section's own
/// maxima and the write-body's are not jointly reachable inside one block, and
/// the whole-record ceiling stays the engine's backstop.
pub const MAX_GRANT_SECTION_BYTES: usize = MAX_BLOCK_BYTES - GRANT_SECTION_ENVELOPE_HEADROOM_BYTES;

// The section's bound is defined against its neighbours on both sides, so these
// are one wire reservation rather than independent tunings. Compile-time,
// because a build that breaks the chain must not run at all.
//
// Only the relations that constrain a free choice are asserted: with
// `MAX_GRANT_SECTION_BYTES` *defined* as the block ceiling less its headroom,
// restating that subtraction would assert an identity that no retune can fail.

/// The floor: the sealed write-body rides inside the section, so a bound at or
/// under the write-body's would refuse a body the write-body codec mints — a
/// produce-side wedge one layer up.
///
/// The 1 KiB is headroom over the ~570 bytes such a section actually needs above
/// the body — the seal's nonce and tag, the `writeBody` entry, the structure
/// signature, and the required sibling fields; the executed floor is
/// `a_maximal_write_body_still_frames_inside_the_section_bound`.
///
/// Since the gap between the two bounds is exactly the gap between the two
/// headrooms, this is equally the re-seal constraint: the envelope framing above
/// a section must leave the section framing above a carried write-body inside
/// [`WRITE_BODY_RESEAL_HEADROOM_BYTES`](super::WRITE_BODY_RESEAL_HEADROOM_BYTES).
const _: () = assert!(MAX_GRANT_SECTION_BYTES >= MAX_WRITE_BODY_BYTES + 1024);

/// Carried critical fields are part of that envelope framing, so a maximal
/// critical set must leave room for the envelope's typed fields beside it.
const _: () = assert!(MAX_CRITICAL_CARRIED_BYTES < GRANT_SECTION_ENVELOPE_HEADROOM_BYTES);

/// The collection label the section's total-size refusal reports. Private to
/// core; consumers that must tell it from the per-collection bounds it shares
/// `too-many-structures` with go through [`is_grant_section_over_bound`].
const GRANT_SECTION_SIZE_CHECK: &str = "grantSection";

/// True when `e` is the section's total-size refusal rather than one of the
/// per-collection bounds that raise the same check name.
pub fn is_grant_section_over_bound(e: &CodecError) -> bool {
    matches!(
        e,
        CodecError::Malformed(Malformed::TooManyStructures {
            collection: GRANT_SECTION_SIZE_CHECK,
            ..
        })
    )
}

/// Release-active uniqueness check over history-link sealed bytes, symmetric
/// across decode and encode. Each epoch mints one link under a fresh nonce over
/// a distinct payload, so equal sealed bytes are never an honest rotator's
/// output — a repeat is an authored anomaly, rejected before any signature work.
fn assert_history_links_unique(links: &[SignedSealed]) -> Result<(), CodecError> {
    let mut seen = BTreeSet::new();
    for link in links {
        if !seen.insert(link.sealed.as_slice()) {
            return Err(Malformed::DuplicateHistoryLink.into());
        }
    }
    Ok(())
}

const GRANT_SECTION_KNOWN: &[&str] = &[
    "ascentLink",
    "commitment",
    "commitmentSig",
    "grantBlobs",
    "historyLinks",
    "ownerBlob",
    "ownerWriteBlob",
    "writeBody",
];

/// Decode a grant section (strict det-CBOR, unknown fields preserved). Fails
/// closed on a malformed frame, a duplicate grant-blob tag (`duplicate-grant-tag`,
/// #39 D7), or a duplicate-tag commitment (surfaced by the commitment codec).
///
/// The transient decoded tree copies the whole signed blob set, so it is
/// scrubbed on drop.
pub fn decode_grant_section(bytes: &[u8]) -> Result<GrantSection, CodecError> {
    // Before the codec walks anything: the per-collection bounds below cap
    // counts, and the preserved-unknown maps at every level are open by
    // construction, so the total is the only cap on the walk itself.
    assert_within_bound(
        GRANT_SECTION_SIZE_CHECK,
        bytes.len(),
        MAX_GRANT_SECTION_BYTES,
    )?;
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;

    let commitment = decode_grant_set_commitment(req(map, "commitment")?.as_bytes()?)?;
    let commitment_sig = bytes_fixed::<ECDSA_SIG_LEN>(req(map, "commitmentSig")?, "commitmentSig")?;

    let raw_grant_blobs = req(map, "grantBlobs")?.as_array()?;
    assert_within_bound("grantBlobs", raw_grant_blobs.len(), MAX_GRANT_BLOBS)?;
    let mut grant_blobs = Vec::with_capacity(raw_grant_blobs.len());
    for item in raw_grant_blobs {
        grant_blobs.push(SignedGrantBlob::from_value(item)?);
    }
    // A recipient tag names at most one grant blob; a duplicate is a confused
    // deputy over read-vs-write authority (#39 D7), rejected at decode.
    assert_grant_tags_unique(grant_blobs.iter().map(|b| b.tag))?;

    let owner_blob = SignedOwnerBlob::from_value(req(map, "ownerBlob")?)?;
    let owner_write_blob = match map.get("ownerWriteBlob") {
        Some(v) => Some(SignedOwnerWriteBlob::from_value(v)?),
        None => None,
    };
    let ascent_link = match map.get("ascentLink") {
        Some(v) => Some(SignedAscentLink::from_value(v)?),
        None => None,
    };
    let raw_history_links = req(map, "historyLinks")?.as_array()?;
    assert_within_bound("historyLinks", raw_history_links.len(), MAX_HISTORY_LINKS)?;
    let mut history_links = Vec::with_capacity(raw_history_links.len());
    for item in raw_history_links {
        history_links.push(SignedSealed::from_value(item)?);
    }
    assert_history_links_unique(&history_links)?;
    let write_body = SignedSealed::from_value(req(map, "writeBody")?)?;

    Ok(GrantSection {
        commitment,
        commitment_sig,
        grant_blobs,
        owner_blob,
        owner_write_blob,
        ascent_link,
        history_links,
        write_body,
        unknown: collect_unknown(map, GRANT_SECTION_KNOWN),
    })
}

/// Encode a grant section to its canonical det-CBOR form.
///
/// Release-active fail-closed guards, symmetric with [`decode_grant_section`]:
/// a duplicate grant-blob tag (or a duplicate-tag commitment), a collection past
/// its frozen bound, a repeated history link, or a total past
/// [`MAX_GRANT_SECTION_BYTES`] each returns `Err` with the same verdict the
/// decoder raises, so a release build never hands back bytes its own decoder
/// rejects (AGENTS.md encode/decode symmetry rule).
pub fn encode_grant_section(section: &GrantSection) -> Result<Vec<u8>, CodecError> {
    // `ascentLink`/`ownerWriteBlob` are optional, so `merge_unknown`'s
    // presence-based precedence does not cover them.
    assert_unknown_disjoint(&section.unknown, GRANT_SECTION_KNOWN)?;
    // Count bounds before the uniqueness walks, the order the decoder checks
    // that pair in, so a value violating both gets the same verdict from either
    // side. The total-size bound is measured last here — it needs the assembled
    // value the decoder gets for free — so a section over the total *and*
    // otherwise malformed reports the other defect from this side.
    assert_within_bound("grantBlobs", section.grant_blobs.len(), MAX_GRANT_BLOBS)?;
    assert_within_bound(
        "historyLinks",
        section.history_links.len(),
        MAX_HISTORY_LINKS,
    )?;
    assert_grant_tags_unique(section.grant_blobs.iter().map(|b| b.tag))?;
    assert_history_links_unique(&section.history_links)?;
    let commitment_bytes = encode_grant_set_commitment(&section.commitment)?;

    let mut m = Map::new();
    if let Some(ascent) = &section.ascent_link {
        m.insert("ascentLink", ascent.to_value());
    }
    m.insert("commitment", Value::Bytes(commitment_bytes));
    m.insert(
        "commitmentSig",
        Value::Bytes(section.commitment_sig.to_vec()),
    );
    m.insert(
        "grantBlobs",
        Value::Array(
            section
                .grant_blobs
                .iter()
                .map(SignedGrantBlob::to_value)
                .collect(),
        ),
    );
    m.insert(
        "historyLinks",
        Value::Array(
            section
                .history_links
                .iter()
                .map(SignedSealed::to_value)
                .collect(),
        ),
    );
    m.insert("ownerBlob", section.owner_blob.to_value());
    if let Some(owner_write) = &section.owner_write_blob {
        m.insert("ownerWriteBlob", owner_write.to_value());
    }
    m.insert("writeBody", section.write_body.to_value());
    merge_unknown(&mut m, &section.unknown);
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    // Measured rather than encoded first: an over-bound section never
    // materializes the buffer it would only be refused and wiped for.
    assert_within_bound(
        GRANT_SECTION_SIZE_CHECK,
        encoded_len(guard.0)?,
        MAX_GRANT_SECTION_BYTES,
    )?;
    encode(guard.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::grant::{GrantSetEntry, Permission};

    fn commitment(entries: Vec<GrantSetEntry>) -> GrantSetCommitment {
        GrantSetCommitment {
            ipns_name: b"scope-root-name".to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            entries,
            unknown: PreservedFields::new(),
        }
    }

    fn blob(tag: u8) -> SignedGrantBlob {
        SignedGrantBlob {
            tag: [tag; SECRET_LEN],
            enc: [0x0a; ENC_LEN],
            ciphertext: vec![0x0b, 0x0c],
            signature: [0x0d; ED_SIG_LEN],
            unknown: PreservedFields::new(),
        }
    }

    fn sample() -> GrantSection {
        GrantSection {
            commitment: commitment(vec![
                GrantSetEntry::new([0x01; 32], Permission::Read, [0x02; 32]),
                GrantSetEntry::new([0x03; 32], Permission::Write, [0x04; 32]),
            ]),
            commitment_sig: [0x11; ECDSA_SIG_LEN],
            grant_blobs: vec![blob(0x01), blob(0x03)],
            owner_blob: SignedOwnerBlob {
                enc: [0x20; ENC_LEN],
                ciphertext: vec![0x21, 0x22],
                signature: [0x23; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            },
            owner_write_blob: Some(SignedOwnerWriteBlob {
                enc: [0x24; ENC_LEN],
                ciphertext: vec![0x25, 0x26],
                signature: [0x27; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            }),
            ascent_link: Some(SignedAscentLink {
                ascent_public: [0x30; ENC_LEN],
                enc: [0x31; ENC_LEN],
                ciphertext: vec![0x32, 0x33],
                signature: [0x34; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            }),
            history_links: vec![SignedSealed {
                sealed: vec![0x40, 0x41],
                signature: [0x42; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            }],
            write_body: SignedSealed {
                sealed: vec![0x50, 0x51],
                signature: [0x52; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            },
            unknown: PreservedFields::new(),
        }
    }

    #[test]
    fn round_trips_byte_stable() {
        let section = sample();
        let bytes = encode_grant_section(&section).expect("encodes");
        let decoded = decode_grant_section(&bytes).expect("decodes");
        assert_eq!(decoded, section);
        assert_eq!(
            encode_grant_section(&decoded).unwrap(),
            bytes,
            "byte-stable"
        );
    }

    /// The encode guard wipes its own transient tree, never the caller's
    /// section — see [`super::super::write_body`]'s sibling test.
    #[test]
    fn encoding_one_borrowed_section_twice_is_byte_identical() {
        let section = sample();
        assert_eq!(
            encode_grant_section(&section).unwrap(),
            encode_grant_section(&section).unwrap()
        );
    }

    #[test]
    fn minimal_section_epoch_one_round_trips() {
        // Epoch 1: no history links, no grant blobs, no ascent link (vault root).
        let section = GrantSection {
            commitment: commitment(Vec::new()),
            commitment_sig: [0x11; ECDSA_SIG_LEN],
            grant_blobs: Vec::new(),
            owner_blob: SignedOwnerBlob {
                enc: [0x20; ENC_LEN],
                ciphertext: vec![0x21],
                signature: [0x23; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            },
            owner_write_blob: None,
            ascent_link: None,
            history_links: Vec::new(),
            write_body: SignedSealed {
                sealed: vec![0x50],
                signature: [0x52; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            },
            unknown: PreservedFields::new(),
        };
        let bytes = encode_grant_section(&section).expect("encodes");
        assert_eq!(decode_grant_section(&bytes).unwrap(), section);
    }

    #[test]
    fn duplicate_grant_blob_tag_rejects_at_decode_and_encode() {
        // Two grant blobs under one tag: a confused deputy over read-vs-write
        // authority. Both the decode and the release-active encode guard reject.
        let mut section = sample();
        section.grant_blobs = vec![blob(0x01), blob(0x01)];
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "duplicate-grant-tag"
        );
        // Hand-build the wire bytes a hostile peer would send (past the encode
        // guard) and prove decode rejects them too.
        let mut m = Map::new();
        m.insert(
            "commitment",
            Value::Bytes(encode_grant_set_commitment(&section.commitment).unwrap()),
        );
        m.insert(
            "commitmentSig",
            Value::Bytes(section.commitment_sig.to_vec()),
        );
        m.insert(
            "grantBlobs",
            Value::Array(vec![blob(0x01).to_value(), blob(0x01).to_value()]),
        );
        m.insert("historyLinks", Value::Array(Vec::new()));
        m.insert("ownerBlob", section.owner_blob.to_value());
        m.insert("writeBody", section.write_body.to_value());
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_grant_section(&bytes).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }

    /// A history link whose sealed bytes are unique to `n`.
    fn link(n: usize) -> SignedSealed {
        SignedSealed {
            sealed: (n as u64).to_be_bytes().to_vec(),
            signature: [0x42; ED_SIG_LEN],
            unknown: PreservedFields::new(),
        }
    }

    /// Hand-build the wire bytes a hostile peer would send, past the encode
    /// guard, from a caller-chosen `historyLinks` / `grantBlobs` array.
    fn wire_section(grant_blobs: Vec<Value>, history_links: Vec<Value>) -> Vec<u8> {
        let section = sample();
        let mut m = Map::new();
        m.insert(
            "commitment",
            Value::Bytes(encode_grant_set_commitment(&section.commitment).unwrap()),
        );
        m.insert(
            "commitmentSig",
            Value::Bytes(section.commitment_sig.to_vec()),
        );
        m.insert("grantBlobs", Value::Array(grant_blobs));
        m.insert("historyLinks", Value::Array(history_links));
        m.insert("ownerBlob", section.owner_blob.to_value());
        m.insert("writeBody", section.write_body.to_value());
        encode(&Value::Map(m)).unwrap()
    }

    #[test]
    fn an_optional_field_key_in_the_preserved_unknowns_is_refused_at_encode() {
        // `merge_unknown`'s precedence is presence-based, so it does not cover an
        // absent optional field: without this guard a section with
        // `ascent_link: None` would encode bytes that decode back carrying one.
        let mut section = sample();
        section.ascent_link = None;
        section.unknown = [("ascentLink".to_owned(), Value::Unsigned(0))]
            .into_iter()
            .collect();
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "unknown-field-collision"
        );
    }

    #[test]
    fn history_links_past_the_bound_reject_at_decode_and_encode() {
        // All distinct, so the bound is what fires — not the duplicate guard.
        let over: Vec<SignedSealed> = (0..=MAX_HISTORY_LINKS).map(link).collect();
        let mut section = sample();
        section.history_links = over.clone();
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "too-many-structures"
        );
        assert_eq!(
            decode_grant_section(&wire_section(
                Vec::new(),
                over.iter().map(SignedSealed::to_value).collect()
            ))
            .unwrap_err()
            .check(),
            "too-many-structures"
        );
    }

    #[test]
    fn grant_blobs_past_the_bound_reject_at_decode_and_encode() {
        let mut section = sample();
        section.grant_blobs = (0..=MAX_GRANT_BLOBS)
            .map(|i| {
                let mut b = blob(0);
                b.tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
                b
            })
            .collect();
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "too-many-structures"
        );

        let over = section.grant_blobs.iter().map(|b| b.to_value()).collect();
        assert_eq!(
            decode_grant_section(&wire_section(over, Vec::new()))
                .unwrap_err()
                .check(),
            "too-many-structures"
        );

        // Violating both invariants at once — over the bound and every tag
        // equal — must name the bound on either side, so encode and decode do
        // not disagree on which guard owns the verdict.
        let dup: Vec<SignedGrantBlob> = (0..=MAX_GRANT_BLOBS).map(|_| blob(0)).collect();
        section.grant_blobs = dup.clone();
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "too-many-structures"
        );
        assert_eq!(
            decode_grant_section(&wire_section(
                dup.iter().map(SignedGrantBlob::to_value).collect(),
                Vec::new()
            ))
            .unwrap_err()
            .check(),
            "too-many-structures"
        );
    }

    #[test]
    fn duplicate_history_link_rejects_at_decode_and_encode() {
        let mut section = sample();
        section.history_links = vec![link(7), link(7)];
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "duplicate-history-link"
        );
        assert_eq!(
            decode_grant_section(&wire_section(
                Vec::new(),
                vec![link(7).to_value(), link(7).to_value()]
            ))
            .unwrap_err()
            .check(),
            "duplicate-history-link"
        );
    }

    #[test]
    fn distinct_history_links_at_the_bound_round_trip() {
        // Anti-vacuity for both guards: exactly at the bound, all distinct, the
        // section still encodes and decodes.
        let mut section = sample();
        section.history_links = (0..MAX_HISTORY_LINKS).map(link).collect();
        let bytes = encode_grant_section(&section).expect("at the bound encodes");
        assert_eq!(decode_grant_section(&bytes).unwrap(), section);
    }

    #[test]
    fn missing_owner_blob_rejects() {
        let section = sample();
        let mut m = Map::new();
        m.insert(
            "commitment",
            Value::Bytes(encode_grant_set_commitment(&section.commitment).unwrap()),
        );
        m.insert(
            "commitmentSig",
            Value::Bytes(section.commitment_sig.to_vec()),
        );
        m.insert("grantBlobs", Value::Array(Vec::new()));
        m.insert("historyLinks", Value::Array(Vec::new()));
        m.insert("writeBody", section.write_body.to_value());
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_grant_section(&bytes).unwrap_err().check(),
            "missing-field"
        );
    }

    #[test]
    fn short_signature_rejects() {
        let section = sample();
        let mut owner = section.owner_blob.to_value().as_map().unwrap().clone();
        owner.insert("sig", Value::Bytes(vec![0x01; ED_SIG_LEN - 1]));
        let mut m = Map::new();
        m.insert(
            "commitment",
            Value::Bytes(encode_grant_set_commitment(&section.commitment).unwrap()),
        );
        m.insert(
            "commitmentSig",
            Value::Bytes(section.commitment_sig.to_vec()),
        );
        m.insert("grantBlobs", Value::Array(Vec::new()));
        m.insert("historyLinks", Value::Array(Vec::new()));
        m.insert("ownerBlob", Value::Map(owner));
        m.insert("writeBody", section.write_body.to_value());
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_grant_section(&bytes).unwrap_err().check(),
            "invalid-field-length"
        );
    }

    #[test]
    fn unknown_top_level_field_preserved_byte_stable() {
        let section = sample();
        let bytes = encode_grant_section(&section).unwrap();
        let mut m = decode(&bytes).unwrap().as_map().unwrap().clone();
        m.insert("futureField", Value::Text("keep".into()));
        let extended = encode(&Value::Map(m)).unwrap();
        let decoded = decode_grant_section(&extended).expect("tolerant decode");
        assert_eq!(decoded.unknown.len(), 1);
        assert_eq!(
            encode_grant_section(&decoded).unwrap(),
            extended,
            "unknown preserved byte-stable"
        );
    }

    /// The residual the byte bound closes: the section's counts are bounded but
    /// its framing was not, so a committed writer could park bulk in a field no
    /// signature covers and every later re-author of the root carried it. Both
    /// ends refuse it, release-active, on the same verdict.
    #[test]
    fn a_section_past_the_byte_bound_is_refused_symmetrically() {
        let mut section = sample();
        section.unknown.insert(
            "pad".to_string(),
            Value::Bytes(vec![0xab; MAX_GRANT_SECTION_BYTES]),
        );
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "too-many-structures",
            "encode refuses, release-active"
        );

        // The length check precedes the walk, so any over-bound buffer is
        // refused before the decoder allocates anything from it.
        assert_eq!(
            decode_grant_section(&vec![0xab; MAX_GRANT_SECTION_BYTES + 1])
                .unwrap_err()
                .check(),
            "too-many-structures",
            "decode refuses an over-bound buffer without walking it"
        );
    }

    /// The floor the const assertion states, executed: a write-body at its own
    /// frozen bound must still frame inside a section, or the two bounds
    /// contradict and a legal body has nowhere to sit.
    #[test]
    fn a_maximal_write_body_still_frames_inside_the_section_bound() {
        let mut section = sample();
        // A sealed blob is `nonce(24) || ciphertext||tag(16)` over the plaintext.
        section.write_body.sealed = vec![0xab; MAX_WRITE_BODY_BYTES + 24 + 16];
        section.grant_blobs.clear();
        section.history_links.clear();
        let bytes = encode_grant_section(&section).expect("the floor clears");
        assert!(bytes.len() <= MAX_GRANT_SECTION_BYTES);
        assert_eq!(decode_grant_section(&bytes).expect("and decodes"), section);
    }

    /// The joint ceiling the section bound imposes, pinned so it is a decision
    /// rather than an accident: a maximal write-body and a full history window
    /// are not both reachable inside one section.
    #[test]
    fn a_maximal_write_body_and_a_full_history_window_are_not_jointly_reachable() {
        let mut section = sample();
        section.write_body.sealed = vec![0xab; MAX_WRITE_BODY_BYTES + 24 + 16];
        section.history_links = (0..MAX_HISTORY_LINKS)
            .map(|i| SignedSealed {
                sealed: vec![i as u8; 143],
                signature: [0x31; ED_SIG_LEN],
                unknown: PreservedFields::new(),
            })
            .collect();
        assert_eq!(
            encode_grant_section(&section).unwrap_err().check(),
            "too-many-structures"
        );
    }
}
