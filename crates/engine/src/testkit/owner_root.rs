//! The owner-root head-block fixture: an envelope carrying a grant section
//! whose owner blob, write body, and optional owner-write-blob are all
//! authored the way a real owner root is, so it passes the adoption gate.
//!
//! Sealing inputs (nonces, HPKE ephemerals, the pseudonym seed) are fixed
//! constants, keeping the head block byte-for-byte reproducible across runs.

use cipherbox_core::content::{compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildRef, ChildScopeRef, Envelope, GrantBlobPayload, GrantSection,
    GrantSetCommitment, OverrideSeedPayload, OwnerWriteBlobPayload, Permission, PreservedFields,
    ReadBody, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_OWNER_BLOB,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY, SignedAscentLink, SignedGrantBlob,
    SignedOwnerBlob, SignedOwnerWriteBlob, SignedSealed, StructureSigInput, WriteBody,
    encode_envelope, encode_grant_section, encode_write_body, seal, seal_ascent_link,
    seal_grant_blob, seal_owner_blob, seal_owner_write_blob, seal_read_body, set_grant_section,
    sign_grant_set, sign_structure,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Public;

use crate::content::DAG_ROOT_CODEC;
use crate::grants::GrantRow;

/// The read-scope seed the fixture's owner blob overrides to.
pub const OWNER_ROOT_SCOPE_SEED: [u8; 32] = [0x66; 32];
/// The write-scope seed the fixture's IPNS name derives from, and that its
/// owner-write-blob wraps.
pub const OWNER_ROOT_WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
/// The read epoch every structure in the fixture is authored at.
pub const OWNER_ROOT_EPOCH: u64 = 1;
/// A stand-in for the write-plane history link a scope past write epoch 1
/// carries. The bytes are opaque to a re-seal, which only bounds them, and a
/// fixture that leaves the link empty above write epoch 1 is refused
/// (`rotation::reseal::ResealError::EmptyWriteHistoryAboveFirstEpoch`).
pub const CARRIED_WRITE_HISTORY_LINK: &[u8] = b"opaque-write-history-link";
/// The seed of the writer pseudonym the fixture detach-signs every structure
/// with — the key a re-seal of this root must sign under to stay committed.
pub const OWNER_ROOT_PSEUDONYM_SEED: [u8; 32] = [0x22; 32];

const V: u64 = 1;
/// The stable per-scope pointer read key the fixture's grant blobs carry.
pub const OWNER_ROOT_POINTER_READ_KEY: [u8; 32] = [0x88; 32];
const NONCE_READ_BODY: [u8; 24] = [11u8; 24];
const NONCE_WRITE_BODY: [u8; 24] = [22u8; 24];
const EPH_OWNER: [u8; 32] = [3u8; 32];
const EPH_OWNER_WRITE: [u8; 32] = [4u8; 32];
const EPH_ASCENT: [u8; 32] = [5u8; 32];
const EPH_GRANT_BASE: u8 = 0x60;

/// The inputs that diverge between owner-root fixtures.
///
/// Nonces and HPKE ephemerals are fixed constants, and the body keys derive from
/// `root_id` alone (the owner-write blob's HPKE key from `owner_enc` alone), so
/// two specs sharing those seal differing plaintexts under one `(key, nonce)`
/// pair. Nothing in this corpus is secret, so that costs the fixtures nothing —
/// but it is why they are a gate/resolve harness and never a KAT source.
pub struct OwnerRootSpec<'a> {
    /// Signs the grant-set commitment; its verifying key is the owner identity
    /// the adoption gate checks against.
    pub owner_identity: &'a EcdsaSigner,
    /// Recipient of the owner blob and owner-write-blob HPKE seals.
    pub owner_enc: &'a X25519Public,
    /// The scope every structure's AAD and structure signature binds.
    pub scope_id: [u8; 16],
    /// The scope-root node id; also the seed-tree edge the read/write keys hang off.
    pub root_id: [u8; 16],
    /// The root folder's children.
    pub children: Vec<ChildRef>,
    /// The write-body's direct-child-scope index — the eager-set adjacency a
    /// rotation walk reads out of this root.
    pub child_scope_index: Vec<ChildScopeRef>,
    /// The committed grant set: one commitment entry, one ledger row and one
    /// grant blob per row. Mint them at this fixture's own name
    /// ([`derive_write_name`](crate::rotation::derive_write_name) over
    /// [`OWNER_ROOT_WRITE_SCOPE_SEED`] and `root_id`), or a recipient cannot
    /// self-locate its blob.
    pub grants: Vec<GrantRow>,
    /// `Some(nodeSeed(parentOverrideSeed, scope_id))` authors the ascent link
    /// every interior scope root carries; `None` is a vault root.
    pub parent_node_seed: Option<[u8; 32]>,
    /// `Some(epoch)` authors an owner-write-blob whose AAD binds that **write**
    /// epoch (its structure signature still binds the read epoch — mirrors
    /// reseal); `None` leaves the root held keyless.
    pub owner_write_blob_epoch: Option<u64>,
    /// The write-body's opaque write-plane history link. Any committed writer can
    /// author these bytes, so a fixture plants them to prove where they do and do
    /// not survive a re-seal.
    pub write_history_link: Vec<u8>,
}

/// The authored owner root: the head block plus the pieces a caller asserts on.
pub struct OwnerRootFixture {
    /// The record's write-plane IPNS name.
    pub name: IpnsName,
    /// The grant section the envelope carries under its `grantSection` key.
    pub grant_section: GrantSection,
    /// The sealed read body, grant section attached.
    pub envelope: Envelope,
    /// The encoded envelope — the block the record's value addresses.
    pub head_block: Vec<u8>,
    /// `head_block`'s content CID, as the record value spells it.
    pub head_cid_str: String,
}

/// The same root with its grant set re-signed at `cut_epoch` — the commitment a
/// cut of this scope publishes. Nothing else moves, so a test that serves both
/// tells the cut apart from every other difference.
pub fn with_cut_epoch(
    fixture: OwnerRootFixture,
    owner_identity: &EcdsaSigner,
    cut_epoch: u64,
) -> OwnerRootFixture {
    let OwnerRootFixture {
        name,
        mut grant_section,
        mut envelope,
        ..
    } = fixture;
    grant_section.commitment.cut_epoch = cut_epoch;
    grant_section.commitment_sig = sign_grant_set(owner_identity, &grant_section.commitment)
        .unwrap()
        .to_compact();
    set_grant_section(&mut envelope, encode_grant_section(&grant_section).unwrap());
    let head_block = encode_envelope(&envelope).unwrap();
    let head_cid_str = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
    OwnerRootFixture {
        name,
        grant_section,
        envelope,
        head_block,
        head_cid_str,
    }
}

/// Author an owner-root head block from `spec` at [`OWNER_ROOT_EPOCH`].
pub fn owner_root_fixture(spec: OwnerRootSpec<'_>) -> OwnerRootFixture {
    owner_root_fixture_at(spec, OWNER_ROOT_EPOCH)
}

/// The same root authored at `read_epoch`, for a test that must serve two
/// epochs of one scope at one name — the shape a read rotation leaves behind.
pub fn owner_root_fixture_at(spec: OwnerRootSpec<'_>, read_epoch: u64) -> OwnerRootFixture {
    let OwnerRootSpec {
        owner_identity,
        owner_enc,
        scope_id,
        root_id,
        children,
        child_scope_index,
        parent_node_seed,
        owner_write_blob_epoch,
        grants,
        write_history_link,
    } = spec;
    let owner_pseudonym = Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED);

    let node_seed = kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &root_id);
    let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
    let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &root_id);
    let name = IpnsName::from_public_key(&kdf::ipns_keypair(write_seed.as_bytes()).verifying_key());
    let write_key = kdf::write_key(write_seed.as_bytes());

    let sign_for = |tag: u8, recipient_tag: Option<[u8; 32]>, ct: &[u8]| -> [u8; 64] {
        let input =
            StructureSigInput::over_ciphertext(scope_id, read_epoch, tag, recipient_tag, ct);
        sign_structure(&owner_pseudonym, &input).to_bytes()
    };
    let sign = |tag: u8, ct: &[u8]| -> [u8; 64] { sign_for(tag, None, ct) };
    let aad = |epoch: u64, struct_tag: u8| AadContext {
        v: V,
        id: root_id,
        scope: scope_id,
        epoch,
        struct_tag,
    };

    // Owner blob — the seed-bearing structure, and the owner's seed source.
    let sealed_owner = seal_owner_blob(
        owner_enc,
        &EPH_OWNER,
        &aad(read_epoch, STRUCT_TAG_OWNER_BLOB),
        &OverrideSeedPayload::new(OWNER_ROOT_SCOPE_SEED, read_epoch),
    )
    .unwrap();
    let owner_blob = SignedOwnerBlob {
        signature: sign(STRUCT_TAG_OWNER_BLOB, &sealed_owner.ciphertext),
        enc: sealed_owner.enc,
        ciphertext: sealed_owner.ciphertext,
        unknown: PreservedFields::new(),
    };

    // Write body — a second seed-bearing structure the gate authenticates.
    let write_body_sealed = seal(
        write_key.as_bytes(),
        &NONCE_WRITE_BODY,
        &aad(read_epoch, STRUCT_TAG_WRITE_BODY),
        &encode_write_body(&WriteBody {
            grant_ledger: grants.iter().map(|g| g.ledger_entry.clone()).collect(),
            write_history_link,
            direct_child_scope_index: child_scope_index,
            unknown: PreservedFields::new(),
        })
        .unwrap(),
    );
    let write_body = SignedSealed {
        signature: sign(STRUCT_TAG_WRITE_BODY, &write_body_sealed),
        sealed: write_body_sealed,
        unknown: PreservedFields::new(),
    };

    let owner_write_blob = owner_write_blob_epoch.map(|write_epoch| {
        let sealed = seal_owner_write_blob(
            owner_enc,
            &EPH_OWNER_WRITE,
            &aad(write_epoch, STRUCT_TAG_OWNER_WRITE_BLOB),
            &OwnerWriteBlobPayload::new(OWNER_ROOT_WRITE_SCOPE_SEED, write_epoch),
        )
        .unwrap();
        SignedOwnerWriteBlob {
            signature: sign(STRUCT_TAG_OWNER_WRITE_BLOB, &sealed.ciphertext),
            enc: sealed.enc,
            ciphertext: sealed.ciphertext,
            unknown: PreservedFields::new(),
        }
    });

    // Ascent link — the marker of an interior scope root: the override seed
    // sealed to the keypair its parent's node seed derives.
    let ascent_link = parent_node_seed.map(|parent_node_seed| {
        let link = seal_ascent_link(
            &parent_node_seed,
            &EPH_ASCENT,
            &aad(read_epoch, STRUCT_TAG_ASCENT_LINK),
            &OverrideSeedPayload::new(OWNER_ROOT_SCOPE_SEED, read_epoch),
        )
        .unwrap();
        SignedAscentLink {
            signature: sign(STRUCT_TAG_ASCENT_LINK, &link.sig_body()),
            ascent_public: link.ascent_public,
            enc: link.enc,
            ciphertext: link.ciphertext,
            unknown: PreservedFields::new(),
        }
    });

    // Grant blobs — one per committed grantee, each wrapped to the key its own
    // ledger row names, as a real re-seal publishes them.
    let mut grant_blobs: Vec<SignedGrantBlob> = grants
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let recipient = X25519Public::from_bytes(row.ledger_entry.recipient_enc_pk)
                .expect("a usable recipient encryption key");
            let write_scope_seed = match row.ledger_entry.permission {
                Permission::Write => Some(OWNER_ROOT_WRITE_SCOPE_SEED),
                Permission::Read => None,
            };
            // The index widens into the tail, so a large grant set neither
            // overflows the base byte nor repeats a scalar.
            let mut ephemeral = [EPH_GRANT_BASE; 32];
            ephemeral[24..].copy_from_slice(&(i as u64).to_be_bytes());
            let sealed = seal_grant_blob(
                &recipient,
                &ephemeral,
                &aad(read_epoch, STRUCT_TAG_GRANT_BLOB),
                &GrantBlobPayload::new(
                    OWNER_ROOT_SCOPE_SEED,
                    write_scope_seed,
                    read_epoch,
                    OWNER_ROOT_POINTER_READ_KEY,
                ),
            )
            .unwrap();
            SignedGrantBlob {
                signature: sign_for(STRUCT_TAG_GRANT_BLOB, Some(row.tag), &sealed.ciphertext),
                tag: row.tag,
                enc: sealed.enc,
                ciphertext: sealed.ciphertext,
                unknown: PreservedFields::new(),
            }
        })
        .collect();
    grant_blobs.sort_by(|a, b| a.tag.cmp(&b.tag));

    let commitment = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
        entries: grants.iter().map(|g| g.commitment_entry.clone()).collect(),
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(owner_identity, &commitment)
        .unwrap()
        .to_compact();
    let grant_section = GrantSection {
        commitment,
        commitment_sig,
        grant_blobs,
        owner_blob,
        owner_write_blob,
        ascent_link,
        history_links: Vec::new(),
        write_body,
        unknown: PreservedFields::new(),
    };

    let folder = ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children,
        unknown: PreservedFields::new(),
    };
    let mut envelope = seal_read_body(
        &read_key,
        &NONCE_READ_BODY,
        V,
        root_id,
        scope_id,
        read_epoch,
        &folder,
    )
    .unwrap();
    set_grant_section(&mut envelope, encode_grant_section(&grant_section).unwrap());

    let head_block = encode_envelope(&envelope).unwrap();
    let head_cid_str = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));

    OwnerRootFixture {
        name,
        grant_section,
        envelope,
        head_block,
        head_cid_str,
    }
}
