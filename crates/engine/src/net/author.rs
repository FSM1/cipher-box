//! Record authoring — the write plane's producer half: build a node's read
//! body, seal it into an envelope, and mint the parent's ref to it
//! (blueprint/engine.md "Resolve/publish pipeline: Publish").
//!
//! Home of the encode-side fail-closed guards the engine owns rather than core
//! (security rule 8). None is a `debug_assert!`, so a release build refuses
//! exactly the bytes a debug build does:
//!
//! - a child envelope carrying a grant section returns `Err`, off core's own
//!   `has_grant_section` — the produce guard and the decode reject cannot drift;
//! - a scope root missing its grant section, carrying one whose commitment
//!   names another `ipnsName` or is not signed by the anchored owner identity,
//!   or carrying one whose structure signatures do not recompute at the
//!   envelope's own scope/epoch, returns `Err` off the same decoder and the same
//!   stage-2/stage-3 predicates the gate runs. The mirror stops where the gate
//!   needs a reader's secrets: stage 3's ascent-link seed cross-check takes an
//!   ancestor node seed [`EnvelopeAuthoring`] does not carry, so it is enforced
//!   where that seed lives, in `rotation/reseal.rs`;
//! - a kind transplant and a non-canonical child-ref `ipnsName` are
//!   unrepresentable: [`new_child`] feeds one [`NodeKind`] and one typed
//!   [`IpnsName`] to both the body and the parent's ref.

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{
    CarriedCut, ChildRef, Envelope, GrantSection, GrantSetBindingError, NodeKind, PreservedFields,
    ReadBody, Version, decode_grant_section, encode_envelope_within, encode_grant_section,
    envelope_over_bound, grant_section_bytes, has_grant_section, is_grant_section_over_bound,
    seal_read_body, set_grant_section, verify_grant_set_bound,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};

use crate::content::limits::{MAX_RESEALABLE_ROOT_REST_BYTES, MAX_RESOLVED_RECORD_BYTES};
use crate::content::root_block_cid;
use crate::gate::authenticate_section_structures;

/// The envelope format+suite version this build authors (blueprint/core.md).
pub const ENVELOPE_V: u64 = 1;

/// An authoring refusal. Every variant is release-active: authoring returns
/// `Err` rather than asserting, so a debug and a release build refuse the same
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorError {
    /// A child envelope carried a `grantSection` key — the scope-root marker
    /// child adoption always rejects (`net/child.rs`). Refusing here keeps the
    /// produce side and the decode side on the same predicate.
    GrantSectionOnChild,
    /// A scope root carried no `grantSection` — the marker every root adoption
    /// requires (`net/adopter.rs` step 5).
    MissingGrantSection,
    /// A scope root's carried `grantSection` did not decode. The same bytes are
    /// a whole-record reject on arrival (`net/adopter.rs` step 5), so they are a
    /// trust refusal here rather than a codec failure of this pass's own body.
    InvalidGrantSection,
    /// The carried grant-set commitment names a different `ipnsName` than the
    /// record is published under, which the gate's stage 2 rejects.
    CommitmentNameMismatch,
    /// The carried grant-set commitment is unsigned, malformed, or not signed by
    /// the contact-anchored owner identity, which the gate's stage 2 rejects.
    CommitmentSignatureInvalid,
    /// A structure signature in the carried grant section does not recompute at
    /// the envelope's own scope and epoch, which the gate's stage 3 rejects
    /// whole-record.
    SectionSignatureInvalid,
    /// Core refused to seal or encode the authored body (a body decode would
    /// refuse to reopen, e.g. duplicate child ids).
    Seal(CodecError),
    /// The encoded head met one of the codec's frozen envelope byte bounds —
    /// the block ceiling every read enforces, or one of the fields inside it.
    /// Publishing it would sign a pointer to a block this build's own reader
    /// always refuses, leaving the node permanently unopenable.
    HeadTooLarge {
        /// The bounded field's wire name, or `envelope` for the record's total.
        /// Which one refused is what tells an operator where the bytes went.
        field: &'static str,
        /// The refused size.
        size: usize,
        /// The ceiling it met.
        limit: usize,
    },
    /// A scope root's bytes outside its grant section met
    /// [`MAX_RESEALABLE_ROOT_REST_BYTES`]. The root fits the block ceiling, but
    /// the section its own next re-seal mints would not fit beside it — and a
    /// scope whose re-seal cannot be authored cannot be revoked. Refused where
    /// the record is grown, since nothing downstream can shrink it.
    ScopeRootNotResealable {
        /// The bytes outside the section.
        size: usize,
        /// The budget they met.
        limit: usize,
    },
    /// The authored grant section is past the codec's frozen total bound
    /// ([`cipherbox_core::seal::MAX_GRANT_SECTION_BYTES`]) — bytes this build's
    /// own decoder always rejects. Named apart from the generic encode fold so
    /// an operator can tell an over-bound section from an encoder fault; the
    /// authoring most likely to meet it is the rotation that revokes a writer
    /// whose bytes inflated the section.
    GrantSectionTooLarge,
}

impl AuthorError {
    /// The stable kebab-case name of this refusal — the produce-side counterpart
    /// of [`GateRejection::check`], and what [`Display`] renders, so a
    /// regression in the epoch or commitment pairing is legible in the field
    /// rather than a silent retry.
    ///
    /// [`GateRejection::check`]: crate::gate::GateRejection::check
    /// [`Display`]: core::fmt::Display
    pub fn check(&self) -> &'static str {
        match self {
            Self::GrantSectionOnChild => "grant-section-on-child",
            Self::MissingGrantSection => "missing-grant-section",
            Self::InvalidGrantSection => "invalid-grant-section",
            // Stage 2's single `commitment-invalid` verdict, split by cause: the
            // producer knows which half of its own bytes is wrong, where a
            // reader deliberately tells an attacker nothing.
            Self::CommitmentNameMismatch => "commitment-name-mismatch",
            Self::CommitmentSignatureInvalid => "commitment-signature-invalid",
            // The gate's own verdict name: this is the same predicate.
            Self::SectionSignatureInvalid => "structure-signature-invalid",
            Self::Seal(e) => e.check(),
            Self::HeadTooLarge { .. } => "head-too-large",
            Self::ScopeRootNotResealable { .. } => "scope-root-not-resealable",
            Self::GrantSectionTooLarge => "grant-section-too-large",
        }
    }

    /// Whether this is a **trust** refusal on the record's own bytes — the
    /// produce-side mirror of an adoption-gate rejection — rather than a codec
    /// or size refusal of the body this pass happened to build, which a rebase
    /// onto other state may not reproduce. Re-authoring the same inputs repeats
    /// a trust refusal verbatim, so a retry loop must charge it
    /// (`sync/drain.rs::classify_author`).
    pub fn is_trust_refusal(&self) -> bool {
        match self {
            Self::GrantSectionOnChild
            | Self::MissingGrantSection
            | Self::InvalidGrantSection
            | Self::CommitmentNameMismatch
            | Self::CommitmentSignatureInvalid
            | Self::SectionSignatureInvalid => true,
            Self::Seal(_)
            | Self::HeadTooLarge { .. }
            | Self::ScopeRootNotResealable { .. }
            | Self::GrantSectionTooLarge => false,
        }
    }
}

impl core::fmt::Display for AuthorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "record authoring refused [{}]", self.check())?;
        match self {
            Self::HeadTooLarge { field, size, limit } => write!(f, ": {field} {size} > {limit}")?,
            Self::ScopeRootNotResealable { size, limit } => {
                write!(f, ": outside the grant section {size} > {limit}")?
            }
            _ => {}
        }
        Ok(())
    }
}

impl std::error::Error for AuthorError {}

/// Split the section encode's own total-size refusal out of the generic encode
/// fold, so the oversize verdict reaches a caller under its own name.
fn grant_section_encode_error(error: CodecError) -> AuthorError {
    if is_grant_section_over_bound(&error) {
        AuthorError::GrantSectionTooLarge
    } else {
        AuthorError::Seal(error)
    }
}

/// The same split for the envelope's own byte bounds: folding them into the
/// generic encode error would charge a blocked publish as an encoder fault and
/// dead-letter it under the wrong reason.
fn envelope_encode_error(error: CodecError) -> AuthorError {
    match envelope_over_bound(&error) {
        Some(bound) => AuthorError::HeadTooLarge {
            field: bound.field,
            size: bound.size,
            limit: bound.limit,
        },
        None => AuthorError::Seal(error),
    }
}

/// A sealed record head, ready for the pre-publish preflight: the encoded
/// envelope block and the CID the published record's `Value` will point at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredHead {
    /// The sealed envelope.
    pub envelope: Envelope,
    /// The canonical det-CBOR encoding of [`Self::envelope`] — the head block.
    pub block: Vec<u8>,
    /// `block`'s content CID as a record `Value` spells it.
    pub cid: String,
    /// The carried keys the encode had to drop to fit the block ceiling. A cut
    /// is data destroyed under pressure someone else applied, so a publisher
    /// reports it rather than doing it quietly.
    pub cut: CarriedCut,
}

/// The inputs one node's envelope is sealed from. `carried_*` are the unknown
/// fields a republish preserves byte-stable (#27 D10) — empty for a node's
/// first record.
pub struct EnvelopeAuthoring<'a> {
    /// The node id this record is for.
    pub node_id: [u8; 16],
    /// The scope this record belongs to.
    pub scope_id: [u8; 16],
    /// The scope's read epoch.
    pub epoch: u64,
    /// The per-node read key (`node-seed` → `read-key`).
    pub read_key: &'a [u8; 32],
    /// Injected per-seal nonce (entropy is a parameter, never read here).
    pub nonce: &'a [u8; 24],
    /// The body to seal.
    pub body: &'a ReadBody,
    /// Top-level envelope fields carried forward from the previous record.
    pub carried_unknown: PreservedFields,
    /// `epochTag` fields carried forward from the previous record.
    pub carried_epoch_tag_unknown: PreservedFields,
}

/// Author a **child** record's envelope: a non-scope-root node, which must
/// carry no grant section (guard 1, release-active).
pub fn author_child_envelope(
    authoring: EnvelopeAuthoring<'_>,
) -> Result<AuthoredHead, AuthorError> {
    let envelope = seal(&authoring)?;
    if has_grant_section(&envelope) {
        return Err(AuthorError::GrantSectionOnChild);
    }
    encode(envelope)
}

/// Author a **scope root**'s envelope for publication under `name`. The grant
/// section is the root's marker and rides `carried_unknown` verbatim, so the
/// seed-bearing structures and their signatures survive a metadata republish
/// untouched — which also means a republish must not carry a section belonging
/// to some other name, authored at some other epoch, or authored by anyone but
/// `owner_identity`, so the checks the gate makes on arrival run here first
/// (release-active).
pub fn author_scope_root_envelope(
    authoring: EnvelopeAuthoring<'_>,
    name: &IpnsName,
    owner_identity: &EcdsaVerifier,
) -> Result<AuthoredHead, AuthorError> {
    let envelope = seal(&authoring)?;
    check_scope_root(&envelope, name, owner_identity)?;
    encode_scope_root(envelope)
}

/// Author a scope root that installs a **freshly assembled** `section` — the
/// re-seal path, where the section is not the carried one. `section` replaces
/// whatever `carried_unknown` holds under the grant-section key, so the previous
/// record's envelope fields can be carried in verbatim; the same release-active
/// checks then run on the result.
pub fn author_scope_root_with_section(
    authoring: EnvelopeAuthoring<'_>,
    name: &IpnsName,
    section: &GrantSection,
    owner_identity: &EcdsaVerifier,
) -> Result<AuthoredHead, AuthorError> {
    let mut envelope = seal(&authoring)?;
    set_grant_section(
        &mut envelope,
        encode_grant_section(section).map_err(grant_section_encode_error)?,
    );
    check_scope_root(&envelope, name, owner_identity)?;
    encode_scope_root(envelope)
}

/// The checks the gate makes on arrival, run here first so a root this build's
/// own gate always rejects is never signed (release-active). Stages 2 and 3 in
/// the gate's own order: without the commitment signature the stage-3 pass is
/// self-referential — it authenticates structures against the pseudonyms the
/// section's own commitment names, so a wholly attacker-authored section is
/// internally consistent.
fn check_scope_root(
    envelope: &Envelope,
    name: &IpnsName,
    owner_identity: &EcdsaVerifier,
) -> Result<(), AuthorError> {
    let section = decode_grant_section(
        grant_section_bytes(envelope).ok_or(AuthorError::MissingGrantSection)?,
    )
    .map_err(|_| AuthorError::InvalidGrantSection)?;
    let commitment_sig = EcdsaSignature::from_compact(&section.commitment_sig)
        .ok_or(AuthorError::CommitmentSignatureInvalid)?;
    verify_grant_set_bound(
        owner_identity,
        &section.commitment,
        &commitment_sig,
        name.as_str().as_bytes(),
    )
    .map_err(|e| match e {
        GrantSetBindingError::Verify(_) => AuthorError::CommitmentSignatureInvalid,
        GrantSetBindingError::ScopeMismatch => AuthorError::CommitmentNameMismatch,
    })?;
    authenticate_section_structures(&section, envelope)
        .map_err(|_| AuthorError::SectionSignatureInvalid)?;
    Ok(())
}

fn seal(authoring: &EnvelopeAuthoring<'_>) -> Result<Envelope, AuthorError> {
    let mut envelope = seal_read_body(
        authoring.read_key,
        authoring.nonce,
        ENVELOPE_V,
        authoring.node_id,
        authoring.scope_id,
        authoring.epoch,
        authoring.body,
    )
    .map_err(AuthorError::Seal)?;
    envelope.unknown = authoring.carried_unknown.clone();
    envelope.epoch_tag_unknown = authoring.carried_epoch_tag_unknown.clone();
    Ok(envelope)
}

/// Encode the authored envelope within the ceiling every block read enforces —
/// which the codec refuses at under its own `envelope` bound, so any block that
/// comes back already fits it ([`encode_envelope_within`] owns what a cut may
/// take, and refuses only what no cut can shrink).
fn encode(mut envelope: Envelope) -> Result<AuthoredHead, AuthorError> {
    let (block, cut) = encode_envelope_within(&mut envelope, MAX_RESOLVED_RECORD_BYTES)
        .map_err(envelope_encode_error)?;
    let cid = root_block_cid(&block);
    Ok(AuthoredHead {
        envelope,
        block,
        cid,
        cut,
    })
}

/// Encode a scope root, holding everything outside its grant section to
/// [`MAX_RESEALABLE_ROOT_REST_BYTES`] (release-active, security rule 8).
///
/// The record only ever grows, so this is the one place a root with no
/// authorable re-seal is still preventable.
fn encode_scope_root(envelope: Envelope) -> Result<AuthoredHead, AuthorError> {
    let head = encode(envelope)?;
    let section = grant_section_bytes(&head.envelope).map_or(0, <[u8]>::len);
    let rest = head.block.len().saturating_sub(section);
    if rest > MAX_RESEALABLE_ROOT_REST_BYTES {
        return Err(AuthorError::ScopeRootNotResealable {
            size: rest,
            limit: MAX_RESEALABLE_ROOT_REST_BYTES,
        });
    }
    Ok(head)
}

/// What a newly created node is, carrying exactly the body content its kind can
/// hold. The one value [`new_child`] derives both the sealed body variant and
/// the parent ref's `kind` from.
pub enum NewNodeBody {
    /// A folder, always created empty.
    Folder,
    /// A file, with the versions its first record publishes (newest first).
    File {
        /// The file's version list; empty for a file created with no content.
        versions: Vec<Version>,
    },
}

impl NewNodeBody {
    fn kind(&self) -> NodeKind {
        match self {
            Self::Folder => NodeKind::Folder,
            Self::File { .. } => NodeKind::File,
        }
    }
}

/// A newly created node: its own read body and the ref its parent links it by.
/// Both are built from one [`NewNodeBody`] and one typed [`IpnsName`], so a kind
/// transplant and a non-canonical `ipnsName` are unrepresentable rather than
/// rejected (guards 2 and 4).
pub struct NewChild {
    /// The child's own read body.
    pub body: ReadBody,
    /// The ref the parent folder carries for it.
    pub child_ref: ChildRef,
}

/// Build a newly created node and its parent ref. `authored_at` is the op's
/// journaled time (never a clock read here), and `link_counter` comes from the
/// rebased snapshot's link allocation.
pub fn new_child(
    node_id: [u8; 16],
    name: String,
    ipns_name: &IpnsName,
    node: NewNodeBody,
    link_counter: u64,
    authored_at: u64,
) -> NewChild {
    let kind = node.kind();
    let body = match node {
        NewNodeBody::Folder => ReadBody::Folder {
            created_at: authored_at,
            modified_at: authored_at,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        },
        NewNodeBody::File { versions } => ReadBody::File {
            created_at: authored_at,
            modified_at: authored_at,
            versions,
            unknown: PreservedFields::new(),
        },
    };
    NewChild {
        child_ref: ChildRef {
            id: node_id,
            name,
            ipns_name: ipns_name.as_str().as_bytes().to_vec(),
            kind,
            link_counter,
            unknown: PreservedFields::new(),
        },
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::codec::Value;
    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::ipns::IpnsName;
    use cipherbox_core::kdf;
    use cipherbox_core::seal::{
        GrantSetEntry, Permission, STRUCT_TAG_WRITE_BODY, StructureSigInput, decode_envelope,
        encode_grant_section, open_read_body, sign_grant_set, sign_structure,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use crate::content::DAG_ROOT_CODEC;
    use crate::testkit::{OWNER_ROOT_EPOCH, OwnerRootFixture, OwnerRootSpec, owner_root_fixture};

    const READ_KEY: [u8; 32] = [9u8; 32];
    const NONCE: [u8; 24] = [5u8; 24];

    fn name() -> IpnsName {
        IpnsName::from_public_key(&kdf::ipns_keypair(&[3u8; 32]).verifying_key())
    }

    fn folder() -> ReadBody {
        ReadBody::Folder {
            created_at: 1,
            modified_at: 2,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        }
    }

    fn authoring(body: &ReadBody, carried: PreservedFields) -> EnvelopeAuthoring<'_> {
        authoring_at(body, carried, OWNER_ROOT_EPOCH)
    }

    /// `authoring` at a caller-chosen read epoch — the axis a scope root's
    /// carried section must agree with.
    fn authoring_at(
        body: &ReadBody,
        carried: PreservedFields,
        epoch: u64,
    ) -> EnvelopeAuthoring<'_> {
        EnvelopeAuthoring {
            node_id: [1u8; 16],
            scope_id: [2u8; 16],
            epoch,
            read_key: &READ_KEY,
            nonce: &NONCE,
            body,
            carried_unknown: carried,
            carried_epoch_tag_unknown: PreservedFields::new(),
        }
    }

    fn grant_section_field() -> PreservedFields {
        [("grantSection".to_owned(), Value::Bytes(b"section".to_vec()))]
            .into_iter()
            .collect()
    }

    /// The identity this suite's roots are anchored to.
    fn owner() -> EcdsaVerifier {
        EcdsaSigner::from_scalar(&[0x11; 32])
            .expect("valid scalar")
            .verifying_key()
    }

    /// A real scope root's grant section and the name its commitment binds.
    /// Only the signer varies between fixtures: the name comes off the fixed
    /// write seed, so a section signed by anyone else still binds this name.
    fn root_signed_by(scalar: &[u8; 32]) -> OwnerRootFixture {
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &EcdsaSigner::from_scalar(scalar).expect("valid scalar"),
            owner_enc: &kdf::enc_subkey(&[0x33; 32]).public(),
            scope_id: [2u8; 16],
            root_id: [1u8; 16],
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: None,
            write_history_link: Vec::new(),
            grants: Vec::new(),
        })
    }

    fn owner_root() -> OwnerRootFixture {
        root_signed_by(&[0x11; 32])
    }

    fn carried_section(section: &GrantSection) -> PreservedFields {
        [(
            "grantSection".to_owned(),
            Value::Bytes(encode_grant_section(section).expect("encodes")),
        )]
        .into_iter()
        .collect()
    }

    /// A folder listing larger than one record can carry — the author's own
    /// work, which no cut of a carried set shrinks.
    fn folder_past_the_read_cap() -> ReadBody {
        let children = (0..40_000u32)
            .map(|i| ChildRef {
                id: {
                    let mut id = [0u8; 16];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    id
                },
                name: "x".repeat(96),
                ipns_name: i.to_be_bytes().to_vec(),
                kind: NodeKind::File,
                link_counter: 1,
                unknown: PreservedFields::new(),
            })
            .collect();
        ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children,
            unknown: PreservedFields::new(),
        }
    }

    #[test]
    fn a_child_envelope_carrying_a_grant_section_is_refused() {
        // Release-active: the guard returns `Err`, so this assertion holds
        // identically in a `--release` build (security rule 8).
        assert_eq!(
            author_child_envelope(authoring(&folder(), grant_section_field())).unwrap_err(),
            AuthorError::GrantSectionOnChild,
        );
    }

    #[test]
    fn a_scope_root_envelope_carries_its_grant_section_through() {
        let fixture = owner_root();
        let head = author_scope_root_envelope(
            authoring(&folder(), carried_section(&fixture.grant_section)),
            &fixture.name,
            &owner(),
        )
        .unwrap();
        assert!(has_grant_section(&head.envelope));
        assert!(has_grant_section(&decode_envelope(&head.block).unwrap()));
    }

    #[test]
    fn a_scope_root_envelope_republished_under_another_name_is_refused() {
        // The commitment signs the name it belongs to, so a section carried onto
        // a record published elsewhere is one the gate's stage 2 always rejects.
        let fixture = owner_root();
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), carried_section(&fixture.grant_section)),
                &name(),
                &owner(),
            )
            .unwrap_err(),
            AuthorError::CommitmentNameMismatch,
        );
    }

    #[test]
    fn a_scope_root_envelope_authored_off_its_sections_epoch_is_refused() {
        // Release-active (security rule 8): a read rotation moves the read epoch
        // while the write plane's clock stands still, so nothing else stops a
        // section signed at one epoch from riding an envelope authored at
        // another — bytes the gate's stage 3 always rejects.
        let fixture = owner_root();
        assert_eq!(
            author_scope_root_envelope(
                authoring_at(
                    &folder(),
                    carried_section(&fixture.grant_section),
                    OWNER_ROOT_EPOCH + 1
                ),
                &fixture.name,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::SectionSignatureInvalid,
        );
    }

    #[test]
    fn a_freshly_assembled_section_off_the_envelopes_epoch_is_refused() {
        // The re-seal path installs its own section rather than carrying one, and
        // gets the same release-active refusal.
        let fixture = owner_root();
        assert_eq!(
            author_scope_root_with_section(
                authoring_at(&folder(), PreservedFields::new(), OWNER_ROOT_EPOCH + 1),
                &fixture.name,
                &fixture.grant_section,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::SectionSignatureInvalid,
        );
    }

    #[test]
    fn a_scope_root_envelope_whose_section_was_tampered_is_refused() {
        // Release-active: the produce side runs the gate's own stage-3 predicate,
        // so a section that lost a valid structure signature is never signed.
        let fixture = owner_root();
        let mut section = fixture.grant_section.clone();
        section.owner_blob.signature[0] ^= 0xFF;
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), carried_section(&section)),
                &fixture.name,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::SectionSignatureInvalid,
        );
    }

    #[test]
    fn a_scope_root_envelope_whose_section_has_two_signers_is_refused() {
        // Release-active (security rule 8). Both signers are committed and the
        // commitment is re-signed, so stages 2 and 3's other checks pass and
        // only the section-signer pin can reject this.
        let fixture = owner_root();
        let second = Ed25519Signer::from_seed([0x55; 32]);
        let mut section = fixture.grant_section.clone();
        section.commitment.entries.push(GrantSetEntry::new(
            [0x66; 32],
            Permission::Write,
            second.verifying_key().to_bytes(),
        ));
        section.commitment_sig = sign_grant_set(
            &EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar"),
            &section.commitment,
        )
        .expect("commitment signs")
        .to_compact();
        let input = StructureSigInput::over_ciphertext(
            [2u8; 16],
            OWNER_ROOT_EPOCH,
            STRUCT_TAG_WRITE_BODY,
            None,
            &section.write_body.sealed,
        );
        section.write_body.signature = sign_structure(&second, &input).to_bytes();
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), carried_section(&section)),
                &fixture.name,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::SectionSignatureInvalid,
        );
    }

    #[test]
    fn a_scope_root_envelope_whose_commitment_another_identity_signed_is_refused() {
        // Release-active (security rule 8): stage 3 authenticates structures
        // against the pseudonyms the section's *own* commitment names, so
        // without stage 2's signature half a wholly attacker-authored section —
        // own commitment, own pseudonym, own signatures, correct ipnsName —
        // authors cleanly and is only caught by a reader.
        let fixture = root_signed_by(&[0x44; 32]);
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), carried_section(&fixture.grant_section)),
                &fixture.name,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::CommitmentSignatureInvalid,
        );
    }

    #[test]
    fn a_scope_root_envelope_whose_commitment_signature_is_unusable_is_refused() {
        // The other half of the gate's stage-2 reject: bytes that are not a
        // compact ECDSA signature at all, which parse before they verify.
        let fixture = owner_root();
        let mut section = fixture.grant_section.clone();
        section.commitment_sig = [0u8; 64];
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), carried_section(&section)),
                &fixture.name,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::CommitmentSignatureInvalid,
        );
    }

    #[test]
    fn a_freshly_assembled_section_another_identity_signed_is_refused() {
        // The re-seal path installs its own section and gets the same stage-2
        // refusal, so neither scope-root authoring path can drift from the gate.
        let fixture = root_signed_by(&[0x44; 32]);
        assert_eq!(
            author_scope_root_with_section(
                authoring(&folder(), PreservedFields::new()),
                &fixture.name,
                &fixture.grant_section,
                &owner(),
            )
            .unwrap_err(),
            AuthorError::CommitmentSignatureInvalid,
        );
    }

    /// An over-bound section is named apart from the generic encode fold: the
    /// authoring most likely to meet it is the rotation that revokes the writer
    /// whose bytes inflated the section, and that must not read as a codec fault.
    #[test]
    fn an_over_bound_grant_section_is_named_apart_from_an_encoder_fault() {
        let oversize = cipherbox_core::error::Malformed::TooManyStructures {
            collection: "grantSection",
            count: cipherbox_core::seal::MAX_GRANT_SECTION_BYTES + 1,
            limit: cipherbox_core::seal::MAX_GRANT_SECTION_BYTES,
        };
        assert_eq!(
            grant_section_encode_error(oversize.into()).check(),
            "grant-section-too-large"
        );

        // A different collection at the same verdict stays the generic fold.
        let other = cipherbox_core::error::Malformed::TooManyStructures {
            collection: "grantBlobs",
            count: 2,
            limit: 1,
        };
        assert_eq!(
            grant_section_encode_error(other.into()).check(),
            "too-many-structures"
        );
    }

    /// Every trust refusal carries a distinct stable name, and only the trust
    /// class is charged by the write plane — a codec or size refusal is a
    /// property of the body this pass built, which a rebase may not reproduce.
    #[test]
    fn every_authoring_refusal_has_its_own_stable_check_name() {
        let refusals = [
            (AuthorError::GrantSectionOnChild, true),
            (AuthorError::MissingGrantSection, true),
            (AuthorError::InvalidGrantSection, true),
            (AuthorError::CommitmentNameMismatch, true),
            (AuthorError::CommitmentSignatureInvalid, true),
            (AuthorError::SectionSignatureInvalid, true),
            (
                AuthorError::HeadTooLarge {
                    field: "envelope",
                    size: 1,
                    limit: 0,
                },
                false,
            ),
            (
                AuthorError::ScopeRootNotResealable { size: 1, limit: 0 },
                false,
            ),
            (AuthorError::GrantSectionTooLarge, false),
        ];
        let mut names = std::collections::BTreeSet::new();
        for (error, trust) in &refusals {
            assert_eq!(error.is_trust_refusal(), *trust, "{error}");
            assert!(names.insert(error.check()), "{error} reuses a check name");
            assert!(format!("{error}").contains(error.check()), "{error:?}");
        }
    }

    #[test]
    fn a_scope_root_envelope_whose_grant_section_does_not_decode_is_refused() {
        // Release-active (security rule 8).
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), grant_section_field()),
                &name(),
                &owner(),
            )
            .unwrap_err(),
            AuthorError::InvalidGrantSection,
        );
    }

    #[test]
    fn a_scope_root_envelope_without_a_grant_section_is_refused() {
        // A root that lost its section is a root no reader can open: child
        // adoption refuses the missing marker and the gate has no commitment.
        assert_eq!(
            author_scope_root_envelope(
                authoring(&folder(), PreservedFields::new()),
                &name(),
                &owner(),
            )
            .unwrap_err(),
            AuthorError::MissingGrantSection,
        );
    }

    #[test]
    fn an_authored_head_decodes_back_to_the_body_it_sealed() {
        let body = folder();
        let head = author_child_envelope(authoring(&body, PreservedFields::new())).unwrap();
        let decoded = decode_envelope(&head.block).unwrap();
        assert_eq!(decoded, head.envelope, "the block is the envelope");
        assert_eq!(open_read_body(&decoded, &READ_KEY).unwrap(), body);
        assert_eq!(
            head.cid,
            encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head.block)),
            "the record value points at the block's own address"
        );
    }

    #[test]
    fn a_head_block_past_the_read_cap_is_never_published() {
        // Release-active (security rule 8): every block read refuses an
        // over-cap body, so authoring one would sign a pointer to a block this
        // build's own reader always rejects — an unopenable node.
        assert!(
            matches!(
                author_child_envelope(authoring(
                    &folder_past_the_read_cap(),
                    PreservedFields::new()
                ))
                .unwrap_err(),
                // The sealed read-body is what overflowed, and the refusal says
                // so rather than reporting only that the head was too big.
                AuthorError::HeadTooLarge {
                    field: "readSealed",
                    ..
                }
            ),
            "an over-cap head must fail closed on the produce side"
        );
    }

    /// A folder listing that fits the block ceiling but leaves the next
    /// re-seal's section no room beside it.
    fn folder_past_the_resealable_budget() -> ReadBody {
        // Aimed at the midpoint of the two ceilings off an approximate per-child
        // cost, and the test asserts it landed between them — so a wire-cost
        // drift fails loudly rather than testing nothing.
        const PER_CHILD_BYTES: usize = 165;
        let target = (MAX_RESEALABLE_ROOT_REST_BYTES + MAX_RESOLVED_RECORD_BYTES) / 2;
        let children = (0..(target / PER_CHILD_BYTES) as u32)
            .map(|i| ChildRef {
                id: {
                    let mut id = [0u8; 16];
                    id[..4].copy_from_slice(&i.to_be_bytes());
                    id
                },
                name: "x".repeat(96),
                ipns_name: i.to_be_bytes().to_vec(),
                kind: NodeKind::File,
                link_counter: 1,
                unknown: PreservedFields::new(),
            })
            .collect();
        ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children,
            unknown: PreservedFields::new(),
        }
    }

    #[test]
    fn a_scope_root_with_no_room_for_its_own_re_seal_is_never_authored() {
        // The block ceiling alone would pass this root, and every later
        // rotation would then refuse the section it mints — the scope becomes
        // rotation-proof. The budget is enforced where the root is grown.
        let fixture = owner_root();
        let body = folder_past_the_resealable_budget();
        let carried = carried_section(&fixture.grant_section);
        // Matched rather than unwrapped: the `Ok` side is a whole authored head,
        // and a failure would render megabytes of it.
        let Err(AuthorError::ScopeRootNotResealable { size, limit }) =
            author_scope_root_envelope(authoring(&body, carried), &fixture.name, &owner())
        else {
            panic!("a root with no re-seal headroom must be refused");
        };
        assert_eq!(limit, MAX_RESEALABLE_ROOT_REST_BYTES);
        assert!(size > limit);
        assert!(
            size < MAX_RESOLVED_RECORD_BYTES,
            "the block ceiling alone would have let this root through"
        );
    }

    #[test]
    fn a_child_record_is_held_to_the_block_ceiling_alone() {
        // Only a scope root owes a re-seal, so reserving that headroom on every
        // interior node would shrink an honest folder for nothing.
        author_child_envelope(authoring(
            &folder_past_the_resealable_budget(),
            PreservedFields::new(),
        ))
        .expect("an interior node fills the block ceiling");
    }

    #[test]
    fn a_carried_set_that_would_overflow_the_read_cap_is_cut_rather_than_refused() {
        let carried: PreservedFields = [
            (
                "bloat".to_owned(),
                Value::Bytes(vec![0xab; MAX_RESOLVED_RECORD_BYTES]),
            ),
            ("keepMe".to_owned(), Value::Bytes(vec![0xcd; 32])),
        ]
        .into_iter()
        .collect();
        let head = author_child_envelope(authoring(&folder(), carried))
            .expect("a carried set is cut, never refused");
        assert!(head.block.len() <= MAX_RESOLVED_RECORD_BYTES);
        assert_eq!(
            head.envelope
                .unknown
                .entries()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["keepMe"],
            "the cut takes the field that overflowed, not the whole set"
        );
        assert_eq!(
            decode_envelope(&head.block).unwrap(),
            head.envelope,
            "the block is the cut envelope, not the one that overflowed"
        );
    }

    /// The cut runs after the scope-root checks and must not undo them: the
    /// grant section rides the same carried set, and losing it authors a root
    /// every adoption rejects.
    #[test]
    fn a_cut_scope_root_keeps_the_grant_section_that_marks_it() {
        let fixture = owner_root();
        let mut carried = carried_section(&fixture.grant_section);
        carried = carried
            .entries()
            .iter()
            .cloned()
            .chain([(
                "bloat".to_owned(),
                Value::Bytes(vec![0xab; MAX_RESOLVED_RECORD_BYTES]),
            )])
            .collect();
        let head =
            author_scope_root_envelope(authoring(&folder(), carried), &fixture.name, &owner())
                .expect("a carried set is cut, never refused");
        assert!(head.block.len() <= MAX_RESOLVED_RECORD_BYTES);
        assert!(has_grant_section(&decode_envelope(&head.block).unwrap()));
    }

    /// No cut reaches the body, so the produce-side refusal stands even where
    /// the carried set was cut to nothing (security rule 8).
    #[test]
    fn a_body_over_the_read_cap_is_still_refused_after_every_cut() {
        let carried: PreservedFields = [("bloat".to_owned(), Value::Bytes(vec![0xab; 4096]))]
            .into_iter()
            .collect();
        assert!(matches!(
            author_child_envelope(authoring(&folder_past_the_read_cap(), carried)).unwrap_err(),
            AuthorError::HeadTooLarge {
                field: "readSealed",
                ..
            }
        ));
    }

    #[test]
    fn a_body_the_decoder_would_refuse_is_never_sealed() {
        // Release-active (security rule 8): core's `assert_children_unique`
        // returns `Err` on both halves of the uniqueness invariant, so a folder
        // rewrite — a create's parent add, a relink's dest-add — can never sign
        // a listing its own decoder always rejects.
        let child = |id: u8, ipns_name: &[u8]| ChildRef {
            id: [id; 16],
            name: "a".into(),
            ipns_name: ipns_name.to_vec(),
            kind: NodeKind::File,
            link_counter: 1,
            unknown: PreservedFields::new(),
        };
        let folder = |children| ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children,
            unknown: PreservedFields::new(),
        };
        for children in [
            vec![child(7, b"n"), child(7, b"other")],
            vec![child(7, b"n"), child(8, b"n")],
        ] {
            assert!(matches!(
                author_child_envelope(authoring(&folder(children), PreservedFields::new()))
                    .unwrap_err(),
                AuthorError::Seal(_)
            ));
        }
    }

    /// The encode side of `read_content`'s kind-transplant reject (rule 8).
    /// Structural in every build: the body variant and the parent ref's kind
    /// are two reads of one value, including for a file that carries a version.
    #[test]
    fn a_new_child_agrees_with_its_parent_ref_on_kind_for_every_kind() {
        let versioned = NewNodeBody::File {
            versions: vec![Version::new(vec![1, 2, 3], [4u8; 32], 9, 77)],
        };
        for (node, expected) in [
            (NewNodeBody::Folder, NodeKind::Folder),
            (
                NewNodeBody::File {
                    versions: Vec::new(),
                },
                NodeKind::File,
            ),
            (versioned, NodeKind::File),
        ] {
            let child = new_child([4u8; 16], "n".into(), &name(), node, 1, 77);
            assert_eq!(child.child_ref.kind, child.body.kind());
            assert_eq!(child.child_ref.kind, expected);
        }
    }

    #[test]
    fn a_new_file_child_carries_the_versions_it_was_built_from() {
        let version = Version::new(vec![1, 2, 3], [4u8; 32], 9, 77);
        let child = new_child(
            [4u8; 16],
            "n".into(),
            &name(),
            NewNodeBody::File {
                versions: vec![version.clone()],
            },
            1,
            77,
        );
        let ReadBody::File { versions, .. } = child.body else {
            panic!("file");
        };
        assert_eq!(versions, vec![version]);
    }

    #[test]
    fn a_new_child_ref_carries_the_canonical_ipns_name_the_read_path_parses() {
        let ipns = name();
        let child = new_child([4u8; 16], "n".into(), &ipns, NewNodeBody::Folder, 1, 77);
        // The read path's exact chain (`facade.rs` child-ref resolution).
        let parsed =
            IpnsName::parse(core::str::from_utf8(&child.child_ref.ipns_name).unwrap()).unwrap();
        assert_eq!(parsed, ipns);
    }

    #[test]
    fn a_new_child_stamps_the_journaled_time_not_a_clock() {
        let child = new_child(
            [4u8; 16],
            "n".into(),
            &name(),
            NewNodeBody::Folder,
            1,
            4_242,
        );
        let ReadBody::Folder {
            created_at,
            modified_at,
            ..
        } = child.body
        else {
            panic!("folder");
        };
        assert_eq!((created_at, modified_at), (4_242, 4_242));
    }
}
