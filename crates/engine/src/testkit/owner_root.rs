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
    AadContext, ChildRef, Envelope, GrantSection, GrantSetCommitment, OverrideSeedPayload,
    OwnerWriteBlobPayload, PreservedFields, ReadBody, STRUCT_TAG_OWNER_BLOB,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY, SignedOwnerBlob, SignedOwnerWriteBlob,
    SignedSealed, StructureSigInput, WriteBody, encode_envelope, encode_grant_section,
    encode_write_body, seal, seal_owner_blob, seal_owner_write_blob, seal_read_body,
    set_grant_section, sign_grant_set, sign_structure,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Public;

use crate::content::DAG_ROOT_CODEC;

/// The read-scope seed the fixture's owner blob overrides to.
pub const OWNER_ROOT_SCOPE_SEED: [u8; 32] = [0x66; 32];
/// The write-scope seed the fixture's IPNS name derives from, and that its
/// owner-write-blob wraps.
pub const OWNER_ROOT_WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
/// The read epoch every structure in the fixture is authored at.
pub const OWNER_ROOT_EPOCH: u64 = 1;

const V: u64 = 1;
const PSEUDONYM_SEED: [u8; 32] = [0x22; 32];
const NONCE_READ_BODY: [u8; 24] = [11u8; 24];
const NONCE_WRITE_BODY: [u8; 24] = [22u8; 24];
const EPH_OWNER: [u8; 32] = [3u8; 32];
const EPH_OWNER_WRITE: [u8; 32] = [4u8; 32];

/// The inputs that diverge between owner-root fixtures.
///
/// Nonces and HPKE ephemerals are fixed, so the two varying plaintexts must be
/// kept apart on independent axes: the read body's key comes from `root_id`
/// alone, so specs with differing `children` need differing `root_id`; the
/// owner-write-blob's HPKE key comes from `owner_enc` alone, so specs with
/// differing `owner_write_blob_epoch` need differing `owner_enc`.
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
    /// `Some(epoch)` authors an owner-write-blob whose AAD binds that **write**
    /// epoch (its structure signature still binds the read epoch — mirrors
    /// reseal); `None` leaves the root held keyless.
    pub owner_write_blob_epoch: Option<u64>,
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

/// Author an owner-root head block from `spec`.
pub fn owner_root_fixture(spec: OwnerRootSpec<'_>) -> OwnerRootFixture {
    let OwnerRootSpec {
        owner_identity,
        owner_enc,
        scope_id,
        root_id,
        children,
        owner_write_blob_epoch,
    } = spec;
    let owner_pseudonym = Ed25519Signer::from_seed(PSEUDONYM_SEED);

    let node_seed = kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &root_id);
    let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();
    let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &root_id);
    let name = IpnsName::from_public_key(&kdf::ipns_keypair(write_seed.as_bytes()).verifying_key());
    let write_key = kdf::write_key(write_seed.as_bytes());

    let sign = |tag: u8, ct: &[u8]| -> [u8; 64] {
        let input = StructureSigInput::over_ciphertext(scope_id, OWNER_ROOT_EPOCH, tag, None, ct);
        sign_structure(&owner_pseudonym, &input).to_bytes()
    };
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
        &aad(OWNER_ROOT_EPOCH, STRUCT_TAG_OWNER_BLOB),
        &OverrideSeedPayload::new(OWNER_ROOT_SCOPE_SEED, OWNER_ROOT_EPOCH),
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
        &aad(OWNER_ROOT_EPOCH, STRUCT_TAG_WRITE_BODY),
        &encode_write_body(&WriteBody {
            grant_ledger: Vec::new(),
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
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

    let commitment = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
        entries: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(owner_identity, &commitment)
        .unwrap()
        .to_compact();
    let grant_section = GrantSection {
        commitment,
        commitment_sig,
        grant_blobs: Vec::new(),
        owner_blob,
        owner_write_blob,
        ascent_link: None,
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
        OWNER_ROOT_EPOCH,
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
