//! Record authoring — the write plane's producer half: build a node's read
//! body, seal it into an envelope, and mint the parent's ref to it
//! (blueprint/engine.md "Resolve/publish pipeline: Publish").
//!
//! Home of the encode-side fail-closed guards #823 assigned to the engine
//! rather than to core (security rule 8). None is a `debug_assert!`, so a
//! release build refuses exactly the bytes a debug build does:
//!
//! - a child envelope carrying a grant section returns `Err`, off core's own
//!   `has_grant_section` — the produce guard and the decode reject cannot drift;
//! - a scope root missing its grant section, or carrying one whose commitment
//!   names another `ipnsName`, returns `Err` off the same decoder the gate's
//!   stages 2 and 5 run;
//! - a kind transplant and a non-canonical child-ref `ipnsName` are
//!   unrepresentable: [`new_child`] feeds one [`NodeKind`] and one typed
//!   [`IpnsName`] to both the body and the parent's ref.

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{
    ChildRef, Envelope, NodeKind, PreservedFields, ReadBody, Version, decode_grant_section,
    encode_envelope, grant_section_bytes, has_grant_section, seal_read_body,
};

use crate::content::limits::MAX_RESOLVED_RECORD_BYTES;
use crate::content::root_block_cid;

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
    /// A scope root carried no decodable `grantSection` — the marker every root
    /// adoption requires (`net/adopter.rs` step 5).
    MissingGrantSection,
    /// The carried grant-set commitment names a different `ipnsName` than the
    /// record is published under, which the gate's stage 2 rejects.
    CommitmentNameMismatch,
    /// Core refused to seal or encode the authored body (a body decode would
    /// refuse to reopen, e.g. duplicate child ids).
    Seal(CodecError),
    /// The encoded head block exceeds the ceiling every block read enforces
    /// ([`MAX_RESOLVED_RECORD_BYTES`]). Publishing it would sign a pointer to a
    /// block this build's own reader always refuses, leaving the node
    /// permanently unopenable.
    HeadTooLarge {
        /// The encoded block's size.
        size: usize,
        /// The enforced ceiling.
        limit: usize,
    },
}

impl core::fmt::Display for AuthorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GrantSectionOnChild => f.write_str("child envelope carries a grantSection"),
            Self::MissingGrantSection => f.write_str("scope root carries no grantSection"),
            Self::CommitmentNameMismatch => {
                f.write_str("carried commitment names another ipnsName")
            }
            Self::Seal(e) => write!(f, "seal failed: {}", e.check()),
            Self::HeadTooLarge { size, limit } => {
                write!(f, "head block exceeds the content cap ({size} > {limit})")
            }
        }
    }
}

impl std::error::Error for AuthorError {}

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
/// to some other name, so the two checks the gate's stages 2 and 5 make on
/// arrival run here first (release-active).
pub fn author_scope_root_envelope(
    authoring: EnvelopeAuthoring<'_>,
    name: &IpnsName,
) -> Result<AuthoredHead, AuthorError> {
    let envelope = seal(&authoring)?;
    let section = grant_section_bytes(&envelope)
        .and_then(|bytes| decode_grant_section(bytes).ok())
        .ok_or(AuthorError::MissingGrantSection)?;
    if section.commitment.ipns_name != name.as_str().as_bytes() {
        return Err(AuthorError::CommitmentNameMismatch);
    }
    encode(envelope)
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

fn encode(envelope: Envelope) -> Result<AuthoredHead, AuthorError> {
    let block = encode_envelope(&envelope).map_err(AuthorError::Seal)?;
    if block.len() > MAX_RESOLVED_RECORD_BYTES {
        return Err(AuthorError::HeadTooLarge {
            size: block.len(),
            limit: MAX_RESOLVED_RECORD_BYTES,
        });
    }
    let cid = root_block_cid(&block);
    Ok(AuthoredHead {
        envelope,
        block,
        cid,
    })
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
    use cipherbox_core::seal::{decode_envelope, encode_grant_section, open_read_body};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::content::DAG_ROOT_CODEC;
    use crate::testkit::{OwnerRootFixture, OwnerRootSpec, owner_root_fixture};

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
        EnvelopeAuthoring {
            node_id: [1u8; 16],
            scope_id: [2u8; 16],
            epoch: 3,
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

    /// A real scope root's grant section and the name its commitment binds.
    fn owner_root() -> OwnerRootFixture {
        let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar");
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &owner_identity,
            owner_enc: &kdf::enc_subkey(&[0x33; 32]).public(),
            scope_id: [2u8; 16],
            root_id: [1u8; 16],
            children: Vec::new(),
            owner_write_blob_epoch: None,
        })
    }

    fn carried_section(fixture: &OwnerRootFixture) -> PreservedFields {
        [(
            "grantSection".to_owned(),
            Value::Bytes(encode_grant_section(&fixture.grant_section).expect("encodes")),
        )]
        .into_iter()
        .collect()
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
            authoring(&folder(), carried_section(&fixture)),
            &fixture.name,
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
            author_scope_root_envelope(authoring(&folder(), carried_section(&fixture)), &name())
                .unwrap_err(),
            AuthorError::CommitmentNameMismatch,
        );
    }

    #[test]
    fn a_scope_root_envelope_without_a_grant_section_is_refused() {
        // A root that lost its section is a root no reader can open: child
        // adoption refuses the missing marker and the gate has no commitment.
        assert_eq!(
            author_scope_root_envelope(authoring(&folder(), PreservedFields::new()), &name())
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
        let body = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children,
            unknown: PreservedFields::new(),
        };
        assert!(
            matches!(
                author_child_envelope(authoring(&body, PreservedFields::new())).unwrap_err(),
                AuthorError::HeadTooLarge { limit, .. } if limit == MAX_RESOLVED_RECORD_BYTES
            ),
            "an over-cap head must fail closed on the produce side"
        );
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

    /// The encode side of `read_content`'s kind-transplant reject (rule 8;
    /// #812 guard 2). Structural in every build: the body variant and the
    /// parent ref's kind are two reads of one value, including for a file that
    /// carries a version.
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
