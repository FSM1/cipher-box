//! The grants + mailbox simulation harness: two engine instances (owner and
//! read-grantee) exchange a share over one fake mailbox hub and one fake record
//! store on virtual time, plus the adversarial reject rows the design demands.
//!
//! Every record and grant blob is hand-fed: the IPNS record plane rides the
//! shared fake record store and the scope root's metadata is built directly with
//! `crates/core`'s crypto, exactly as the owner would publish it. The engine
//! layer under test composes only core's verify/unseal/open, so the reject rows
//! assert core's named checks or the engine's own fail-closed classifications,
//! never a reinvented crypto code.

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, Envelope, GrantBlobPayload, GrantSection, GrantSetCommitment, GrantSetEntry,
    OverrideSeedPayload, Permission, PreservedFields, ReadBody, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_WRITE_BODY, SignedGrantBlob, SignedOwnerBlob, SignedSealed,
    StructureSigInput, WriteBody, encode_write_body, seal, seal_grant_blob, seal_owner_blob,
    seal_read_body, sign_grant_set, sign_structure,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::{
    EcdsaSignature, EcdsaSigner, EcdsaVerifier, IDENTITY_PUBLIC_LEN,
};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::ct_eq;
use cipherbox_core::suite::x25519::X25519Secret;

use cipherbox_engine::api::ApiClient;
use cipherbox_engine::gate::Candidate;
use cipherbox_engine::grants::owner_entry::{OwnerEntry, cross_check};
use cipherbox_engine::grants::revocation::{ResolutionClass, ResolutionFacts, classify};
use cipherbox_engine::grants::{
    AcceptError, PublishedGrantBlob, ReceivedSharesList, SentIndex, SentShare, SharePointer,
    accept_share, import_contact, self_locate,
};
use cipherbox_engine::mailbox::{VerifiedMailboxItem, poll_verified, post_sealed};
use cipherbox_engine::net::MAX_RECORD_BYTES;
use cipherbox_engine::seams::{FloorStore, HttpMethod, HttpResponse, Mailbox, RecordTransport};
use cipherbox_engine::testkit::fakes::InMemoryCredentialStore;
use cipherbox_engine::testkit::fakes::ScriptedHttp;
use cipherbox_engine::testkit::{FakeDevice, FakeWorld, block_on};

const V: u64 = 1;
const TTL_NANOS: u64 = 2_000_000_000;
const EOL: &str = "2027-01-01T00:00:00Z";
const RECORD_VALUE: &[u8] = b"/ipfs/AAAAAAAAAA";
const NONCE_READ_BODY: [u8; 24] = [11u8; 24];
const NONCE_WRITE_BODY: [u8; 24] = [22u8; 24];
const EPH_GRANT: [u8; 32] = [5u8; 32];
const EPH_GRANT_2: [u8; 32] = [6u8; 32];
const EPH_OWNER: [u8; 32] = [8u8; 32];
const EPH_MAILBOX: [u8; 32] = [7u8; 32];
const POINTER_READ_KEY: [u8; 32] = [0x8A; 32];

/// A read-grantee-readable scope root: the owner shares one folder with one
/// recipient by filing a read grant blob under the recipient's blinded tag and
/// committing that tag.
struct GrantFixture {
    owner_identity: EcdsaSigner,
    owner_identity_pub: EcdsaVerifier,
    recipient_enc: X25519Secret,
    recipient_identity: EcdsaVerifier,
    scope_id: [u8; 16],
    scope_seed: [u8; 32],
    epoch: u64,
    ipns_signer: Ed25519Signer,
    name: IpnsName,
    tag: [u8; 32],
    grant_blob_enc: [u8; 32],
    grant_blob_ct: Vec<u8>,
    commitment: GrantSetCommitment,
    commitment_sig: EcdsaSignature,
    /// The record's grant section (commitment, grant blob, owner blob, write-body
    /// with real structure signatures) the gate enumerates and recomputes over
    /// rather than trusting any caller-supplied hash.
    grant_section: GrantSection,
    envelope: Envelope,
    owner_contact: Vec<u8>,
}

impl GrantFixture {
    fn new() -> Self {
        let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar");
        let owner_identity_pub = owner_identity.verifying_key();
        let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let owner_enc = X25519Secret::from_scalar([0x33; 32]);
        let recipient_enc = X25519Secret::from_scalar([0x44; 32]);
        let recipient_identity = EcdsaSigner::from_scalar(&[0x45; 32])
            .expect("valid scalar")
            .verifying_key();

        let scope_id = [0x55; 16];
        let root_id = [0x55; 16];
        let scope_seed = [0x66; 32];
        let write_scope_seed = [0x77; 32];
        let epoch = 1;

        let node_seed = kdf::node_seed(&scope_seed, &root_id);
        let read_key = *kdf::read_key(node_seed.as_bytes()).as_bytes();

        let write_seed = kdf::write_seed(&write_scope_seed, &root_id);
        let ipns_signer = kdf::ipns_keypair(write_seed.as_bytes());
        let name = IpnsName::from_public_key(&ipns_signer.verifying_key());
        let write_key = kdf::write_key(write_seed.as_bytes());

        // The recipient's blinded tag: pairwise ECDH of the two enc subkeys plus
        // the scope root name (symmetric — the recipient re-derives the same).
        let shared = owner_enc
            .diffie_hellman(&recipient_enc.public())
            .expect("contributory");
        let tag = kdf::blinded_tag(shared.as_bytes(), name.as_str().as_bytes());

        // The read grant blob, HPKE-sealed to the recipient's enc subkey.
        let grant_aad = AadContext {
            v: V,
            id: root_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        let grant_payload = GrantBlobPayload::new(scope_seed, None, epoch, POINTER_READ_KEY);
        let grant_blob = seal_grant_blob(
            &recipient_enc.public(),
            &EPH_GRANT,
            &grant_aad,
            &grant_payload,
        )
        .unwrap();
        // Sign a seed-bearing structure's ciphertext with the owner pseudonym.
        let sign = |tag: u8, recipient: Option<[u8; 32]>, ct: &[u8]| -> [u8; 64] {
            let input = StructureSigInput::over_ciphertext(scope_id, epoch, tag, recipient, ct);
            sign_structure(&owner_pseudonym, &input).to_bytes()
        };
        let grant_blob_signed = SignedGrantBlob {
            tag,
            enc: grant_blob.enc,
            ciphertext: grant_blob.ciphertext.clone(),
            signature: sign(STRUCT_TAG_GRANT_BLOB, Some(tag), &grant_blob.ciphertext),
            unknown: PreservedFields::new(),
        };

        // The owner blob (a mandatory scope-root structure): the override seed
        // sealed to the owner enc subkey, structure-signed by the owner pseudonym.
        let owner_blob_aad = AadContext {
            v: V,
            id: root_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_OWNER_BLOB,
        };
        let owner_blob = seal_owner_blob(
            &owner_enc.public(),
            &EPH_OWNER,
            &owner_blob_aad,
            &OverrideSeedPayload::new(scope_seed, epoch),
        )
        .unwrap();
        let owner_blob_signed = SignedOwnerBlob {
            enc: owner_blob.enc,
            ciphertext: owner_blob.ciphertext.clone(),
            signature: sign(STRUCT_TAG_OWNER_BLOB, None, &owner_blob.ciphertext),
            unknown: PreservedFields::new(),
        };

        // A write-body structure, to exercise the multi-structure loop.
        let write_body = WriteBody {
            grant_ledger: Vec::new(),
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let write_body_aad = AadContext {
            v: V,
            id: root_id,
            scope: scope_id,
            epoch,
            struct_tag: STRUCT_TAG_WRITE_BODY,
        };
        let write_body_sealed = seal(
            write_key.as_bytes(),
            &NONCE_WRITE_BODY,
            &write_body_aad,
            &encode_write_body(&write_body).expect("encodes"),
        );
        let write_body_signed = SignedSealed {
            signature: sign(STRUCT_TAG_WRITE_BODY, None, &write_body_sealed),
            sealed: write_body_sealed,
            unknown: PreservedFields::new(),
        };

        // The owner-signed commitment: the recipient's tag is committed as a read
        // grant. Read entries carry a pseudonym field that never authorizes a
        // structure (only write entries do), so a placeholder is fine.
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
            entries: vec![GrantSetEntry::new(tag, Permission::Read, [0xC0; 32])],
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner_identity, &commitment).expect("signs");
        let grant_section = GrantSection {
            commitment: commitment.clone(),
            commitment_sig: commitment_sig.to_compact(),
            grant_blobs: vec![grant_blob_signed],
            owner_blob: owner_blob_signed,
            owner_write_blob: None,
            ascent_link: None,
            history_links: Vec::new(),
            write_body: write_body_signed,
            unknown: PreservedFields::new(),
        };

        let folder = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let envelope = seal_read_body(
            &read_key,
            &NONCE_READ_BODY,
            V,
            root_id,
            scope_id,
            epoch,
            &folder,
        )
        .expect("folder seals");

        let owner_contact = ContactCode::create(&owner_identity, owner_enc.public()).encode();

        Self {
            owner_identity,
            owner_identity_pub,
            recipient_enc,
            recipient_identity,
            scope_id,
            scope_seed,
            epoch,
            ipns_signer,
            name,
            tag,
            grant_blob_enc: grant_blob.enc,
            grant_blob_ct: grant_blob.ciphertext,
            commitment,
            commitment_sig,
            grant_section,
            envelope,
            owner_contact,
        }
    }

    fn record_bytes(&self, sequence: u64) -> Vec<u8> {
        IpnsRecord::create_v2(&self.ipns_signer, RECORD_VALUE, sequence, TTL_NANOS, EOL).marshal()
    }

    fn candidate_with_record(&self, record_bytes: Vec<u8>) -> Candidate {
        Candidate {
            name: self.name.clone(),
            record_bytes,
            grant_section: self.grant_section.clone(),
            envelope: self.envelope.clone(),
        }
    }

    fn candidate(&self) -> Candidate {
        self.candidate_with_record(self.record_bytes(1))
    }

    fn grant_blobs(&self) -> Vec<PublishedGrantBlob> {
        vec![PublishedGrantBlob {
            tag: self.tag,
            enc: self.grant_blob_enc,
            ciphertext: self.grant_blob_ct.clone(),
        }]
    }

    fn share_pointer(&self) -> SharePointer {
        SharePointer {
            scope_root_name: self.name.as_str().as_bytes().to_vec(),
            sharer_identity_pk: self.owner_identity_pub.to_sec1(),
            display_name: "Shared Folder".to_string(),
            permission: Permission::Read,
        }
    }

    /// A re-accept variant of the SAME scope root (same name, same blinded tag,
    /// same read key so the adoption gate still passes) in which the owner has
    /// re-committed the tag with a new `permission` and re-sealed the grant blob
    /// with a rotated `pointer_read_key`. The record advances to sequence 2 so it
    /// clears the floor the first accept raised. Exercises the self-healing
    /// bookmark: the freshly-verified metadata is authority.
    fn reaccept_variant(
        &self,
        permission: Permission,
        rotated_pointer_read_key: [u8; 32],
    ) -> (Vec<PublishedGrantBlob>, Candidate) {
        let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let root_id = self.scope_id;

        let grant_aad = AadContext {
            v: V,
            id: root_id,
            scope: self.scope_id,
            epoch: self.epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        let grant_payload =
            GrantBlobPayload::new(self.scope_seed, None, self.epoch, rotated_pointer_read_key);
        let grant_blob = seal_grant_blob(
            &self.recipient_enc.public(),
            &EPH_GRANT_2,
            &grant_aad,
            &grant_payload,
        )
        .unwrap();
        let grant_blob_signed = SignedGrantBlob {
            tag: self.tag,
            enc: grant_blob.enc,
            ciphertext: grant_blob.ciphertext.clone(),
            signature: sign_structure(
                &owner_pseudonym,
                &StructureSigInput::over_ciphertext(
                    self.scope_id,
                    self.epoch,
                    STRUCT_TAG_GRANT_BLOB,
                    Some(self.tag),
                    &grant_blob.ciphertext,
                ),
            )
            .to_bytes(),
            unknown: PreservedFields::new(),
        };

        let mut commitment = self.commitment.clone();
        commitment.entries = vec![GrantSetEntry::new(self.tag, permission, [0xC0; 32])];
        let commitment_sig = sign_grant_set(&self.owner_identity, &commitment).expect("signs");

        // Keep the owner blob + write-body; swap the re-sealed grant blob.
        let mut grant_section = self.grant_section.clone();
        grant_section.commitment = commitment;
        grant_section.commitment_sig = commitment_sig.to_compact();
        grant_section.grant_blobs = vec![grant_blob_signed];

        let candidate = Candidate {
            name: self.name.clone(),
            record_bytes: self.record_bytes(2),
            grant_section,
            envelope: self.envelope.clone(),
        };
        let blobs = vec![PublishedGrantBlob {
            tag: self.tag,
            enc: grant_blob.enc,
            ciphertext: grant_blob.ciphertext,
        }];
        (blobs, candidate)
    }
}

// ---------------------------------------------------------------------------
// The two-instance share-accept end-to-end.
// ---------------------------------------------------------------------------

#[test]
fn two_instance_share_accept_end_to_end() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient_address = fx.recipient_identity.to_sec1();
    let owner_device = world.device(b"owner-inbox");
    let recipient_device = world.device(&recipient_address);

    block_on(post_sealed(
        &owner_device.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        &fx.owner_identity,
        &fx.share_pointer().encode(),
        "share-1",
    ))
    .expect("post");

    let mut sent = SentIndex::new();
    let recipient_identity = EcdsaSigner::from_scalar(&[0xAA; 32]).unwrap();
    sent.record(SentShare {
        scope_root_name: fx.name.as_str().as_bytes().to_vec(),
        recipient_identity_pk: recipient_identity.verifying_key().to_sec1(),
        permission: Permission::Read,
    });
    assert_eq!(sent.len(), 1);

    let endpoint = world.record_store.endpoints()[0].clone();
    world
        .record_store
        .seed_record(&endpoint, fx.name.as_str(), fx.record_bytes(1));

    let contact = import_contact(&fx.owner_contact).expect("valid contact imports");
    let items = block_on(poll_verified(
        &recipient_device.mailbox,
        &fx.recipient_enc,
        V,
    ))
    .expect("poll");
    assert_eq!(
        items.len(),
        1,
        "the sealed, sender-authed pointer is delivered"
    );
    assert_eq!(items[0].sender_identity, fx.owner_identity_pub);

    let bytes = block_on(recipient_device.record_store.get_record(
        &endpoint,
        fx.name.as_str(),
        MAX_RECORD_BYTES,
    ))
    .unwrap()
    .expect("record present");
    let candidate = fx.candidate_with_record(bytes);
    let mut received = ReceivedSharesList::new();
    let outcome = block_on(accept_share(
        &recipient_device.floor_store,
        &recipient_device.mailbox,
        &recipient_device.received_share_store,
        &items[0],
        &contact,
        &fx.recipient_enc,
        &candidate,
        &fx.grant_blobs(),
        &mut received,
    ))
    .expect("accept succeeds end to end");

    assert_eq!(outcome.permission, Permission::Read, "committed permission");
    assert_eq!(outcome.sequence, 1);
    assert!(outcome.newly_added);
    assert!(received.contains(fx.name.as_str().as_bytes()));
    // The pointer read key was persisted from the unsealed grant blob.
    assert!(
        ct_eq(
            received.iter().next().unwrap().pointer_read_key(),
            &POINTER_READ_KEY
        ),
        "pointer read key mismatch"
    );

    assert!(
        block_on(poll_verified(
            &recipient_device.mailbox,
            &fx.recipient_enc,
            V
        ))
        .unwrap()
        .is_empty(),
        "accept acks after the durable append"
    );

    // A redelivered pointer re-accepts idempotently: the item resolves a newer
    // record (seq 2, past the advanced floor), the gate passes, and the list is
    // a self-healing no-op bookmark.
    block_on(post_sealed(
        &owner_device.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        &fx.owner_identity,
        &fx.share_pointer().encode(),
        "share-2",
    ))
    .unwrap();
    let again = block_on(poll_verified(
        &recipient_device.mailbox,
        &fx.recipient_enc,
        V,
    ))
    .unwrap();
    let outcome2 = block_on(accept_share(
        &recipient_device.floor_store,
        &recipient_device.mailbox,
        &recipient_device.received_share_store,
        &again[0],
        &contact,
        &fx.recipient_enc,
        &fx.candidate_with_record(fx.record_bytes(2)),
        &fx.grant_blobs(),
        &mut received,
    ))
    .expect("re-accept");
    assert!(
        !outcome2.newly_added,
        "metadata is authority; the list self-heals"
    );
    assert_eq!(received.len(), 1);
}

// ---------------------------------------------------------------------------
// Uncommitted-tag rejection.
// ---------------------------------------------------------------------------

#[test]
fn uncommitted_tag_is_rejected_before_the_gate() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient_address = fx.recipient_identity.to_sec1();
    let recipient_device = world.device(&recipient_address);
    let poster = world.device(b"owner-inbox");

    block_on(post_sealed(
        &poster.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        &fx.owner_identity,
        &fx.share_pointer().encode(),
        "s",
    ))
    .unwrap();
    let contact = import_contact(&fx.owner_contact).unwrap();
    let items = block_on(poll_verified(
        &recipient_device.mailbox,
        &fx.recipient_enc,
        V,
    ))
    .unwrap();

    // A blob is present at the recipient's tag, but the owner never committed
    // that tag: the recipient refuses to trust the grant.
    let mut candidate = fx.candidate();
    candidate.grant_section.commitment.entries.clear();
    candidate.grant_section.commitment_sig =
        sign_grant_set(&fx.owner_identity, &candidate.grant_section.commitment)
            .unwrap()
            .to_compact();

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient_device.floor_store,
        &recipient_device.mailbox,
        &recipient_device.received_share_store,
        &items[0],
        &contact,
        &fx.recipient_enc,
        &candidate,
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::UncommittedTag), "got {err}");
    assert!(received.is_empty());
    // Not acked: the item survives for a later legitimate resolve.
    assert_eq!(
        block_on(poll_verified(
            &recipient_device.mailbox,
            &fx.recipient_enc,
            V
        ))
        .unwrap()
        .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Sender-auth drop (poll level) + not-the-contact reject (accept level).
// ---------------------------------------------------------------------------

#[test]
fn unauthenticated_sender_is_dropped_and_wrong_contact_is_rejected() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient_address = fx.recipient_identity.to_sec1();
    let recipient_device = world.device(&recipient_address);
    let poster = world.device(b"poster");

    // (1) Junk that never HPKE-opens is dropped before any resolve.
    block_on(
        poster
            .mailbox
            .post(&recipient_address, b"not a sealed block", "junk"),
    )
    .unwrap();

    // (2) An item authentically sealed and signed by an ATTACKER identity (not
    // the owner contact) survives the poll (it is authenticated), but accept
    // binds the sender to the contact and rejects it.
    let attacker = EcdsaSigner::from_scalar(&[0x9E; 32]).unwrap();
    block_on(post_sealed(
        &poster.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        &attacker,
        &fx.share_pointer().encode(),
        "attacker",
    ))
    .unwrap();

    let items = block_on(poll_verified(
        &recipient_device.mailbox,
        &fx.recipient_enc,
        V,
    ))
    .unwrap();
    assert_eq!(
        items.len(),
        1,
        "junk dropped; the attacker item is authentic-from-attacker"
    );
    assert_eq!(items[0].sender_identity, attacker.verifying_key());

    let contact = import_contact(&fx.owner_contact).unwrap();
    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient_device.floor_store,
        &recipient_device.mailbox,
        &recipient_device.received_share_store,
        &items[0],
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::SenderNotContact), "got {err}");
}

// ---------------------------------------------------------------------------
// Ack-after-durable: a gate rejection never acks.
// ---------------------------------------------------------------------------

#[test]
fn a_failed_gate_never_acks_the_item() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient_address = fx.recipient_identity.to_sec1();
    let recipient_device = world.device(&recipient_address);
    let poster = world.device(b"owner-inbox");

    block_on(post_sealed(
        &poster.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        &fx.owner_identity,
        &fx.share_pointer().encode(),
        "s",
    ))
    .unwrap();
    let contact = import_contact(&fx.owner_contact).unwrap();
    let items = block_on(poll_verified(
        &recipient_device.mailbox,
        &fx.recipient_enc,
        V,
    ))
    .unwrap();

    // Tamper the record so the adoption gate rejects at record-verify.
    let mut candidate = fx.candidate();
    let last = candidate.record_bytes.len() - 1;
    candidate.record_bytes[last] ^= 0x01;

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient_device.floor_store,
        &recipient_device.mailbox,
        &recipient_device.received_share_store,
        &items[0],
        &contact,
        &fx.recipient_enc,
        &candidate,
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::Gate(_)), "got {err}");
    assert!(received.is_empty(), "nothing durable was recorded");
    assert_eq!(
        block_on(poll_verified(
            &recipient_device.mailbox,
            &fx.recipient_enc,
            V
        ))
        .unwrap()
        .len(),
        1,
        "a rejected accept leaves the item un-acked"
    );
}

// ---------------------------------------------------------------------------
// Ack-after-durable: a durable-persist failure never acks (P1-1).
// ---------------------------------------------------------------------------

/// The gate passes and the bookmark is reconciled, but the durable
/// `ReceivedShareStore` is offline: the accept flow rolls the in-memory bookmark
/// back and returns un-acked, so the item redelivers rather than advancing the
/// durable floor while losing the share. Mirrors `a_failed_gate_never_acks`.
#[test]
fn a_failed_persist_never_acks_the_item() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();

    recipient.received_share_store.set_failing(true);

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::Persist(_)), "got {err}");
    assert!(
        received.is_empty(),
        "the in-memory bookmark rolled back to its pre-accept state"
    );
    assert_eq!(recipient.received_share_store.persist_count(), 0);
    assert_eq!(
        inbox_len(&fx, &recipient),
        1,
        "un-acked: the item redelivers"
    );
}

/// The durable sequence floor must not advance unless the accepted bookmark is
/// durably persisted (floor/bookmark atomicity, P1 durability). A persist
/// failure leaves the floor UNCHANGED, so redelivery with a recovered store
/// re-adopts cleanly instead of being stranded below an already-advanced floor —
/// a permanently-unrecoverable share.
#[test]
fn a_persist_failure_leaves_the_floor_unadvanced_and_redelivery_recovers() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();
    let name_bytes = fx.name.as_str().as_bytes();

    // Pre-accept: no durable sequence floor for this name yet.
    assert_eq!(
        block_on(recipient.floor_store.sequence_floor(name_bytes)).unwrap(),
        None
    );

    // First attempt: the durable store is offline, so the persist fails.
    recipient.received_share_store.set_failing(true);
    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::Persist(_)), "got {err}");

    // (a) un-acked: the item redelivers.
    assert_eq!(
        inbox_len(&fx, &recipient),
        1,
        "un-acked: the item redelivers"
    );
    // (b) the durable sequence floor is UNCHANGED from its pre-accept state.
    assert_eq!(
        block_on(recipient.floor_store.sequence_floor(name_bytes)).unwrap(),
        None,
        "the floor never advanced past a share that did not durably persist"
    );

    // (c) redelivery with a recovered store re-adopts and restores the bookmark.
    recipient.received_share_store.set_failing(false);
    let redelivered = block_on(poll_verified(&recipient.mailbox, &fx.recipient_enc, V))
        .unwrap()
        .remove(0);
    let outcome = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &redelivered,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .expect("redelivery re-adopts once the store recovers");
    assert!(outcome.newly_added, "the share was appended, not stranded");
    assert_eq!(outcome.sequence, 1);
    assert!(received.contains(name_bytes));
    // The floor advanced exactly now, and the item is acked.
    assert_eq!(
        block_on(recipient.floor_store.sequence_floor(name_bytes)).unwrap(),
        Some(1),
        "the floor advances only with the durable bookmark"
    );
    assert_eq!(
        inbox_len(&fx, &recipient),
        0,
        "acked after the durable persist and floor advance"
    );
}

/// The commit-succeeds-but-ack-fails window: after the floor advanced and the
/// bookmark is durable, a transient ack failure leaves the item pending. On
/// redelivery `adopt_deferred` hits the strict-sequence anti-replay reject, but
/// the durable bookmark proves prior adoption, so the flow re-acks idempotently
/// (no re-adopt, no re-persist) instead of redelivering-and-failing forever.
#[test]
fn a_failed_ack_after_commit_recovers_via_idempotent_reack() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();
    let name_bytes = fx.name.as_str().as_bytes();

    // First delivery: the durable persist and the floor commit both succeed, but
    // the ack fails transiently.
    recipient.mailbox.set_ack_failing(true);
    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::Ack(_)), "got {err}");

    // The share IS durably recorded and the floor DID advance to the record's
    // sequence — the accepted state is committed.
    assert!(received.contains(name_bytes));
    assert_eq!(recipient.received_share_store.persist_count(), 1);
    assert_eq!(
        block_on(recipient.floor_store.sequence_floor(name_bytes)).unwrap(),
        Some(1)
    );
    assert_eq!(
        inbox_len(&fx, &recipient),
        1,
        "the ack failed: the item is still pending"
    );

    // Redelivery with a working mailbox: stage 4 rejects (sequence not newer than
    // the floor), but the durable bookmark short-circuits to an idempotent ack.
    recipient.mailbox.set_ack_failing(false);
    let redelivered = block_on(poll_verified(&recipient.mailbox, &fx.recipient_enc, V))
        .unwrap()
        .remove(0);
    let outcome = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &redelivered,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .expect("redelivery takes the idempotent ack-only path");

    assert!(
        !outcome.newly_added,
        "already-accepted no-op, not a fresh add"
    );
    assert_eq!(outcome.sequence, 1, "reports the held sequence");
    assert_eq!(outcome.permission, Permission::Read);
    // No re-adopt and no re-persist: the bookmark and floor are untouched.
    assert_eq!(received.len(), 1, "the bookmark is unchanged");
    assert_eq!(
        recipient.received_share_store.persist_count(),
        1,
        "no re-persist on the ack-only path"
    );
    assert_eq!(
        block_on(recipient.floor_store.sequence_floor(name_bytes)).unwrap(),
        Some(1),
        "the floor is unchanged"
    );
    assert_eq!(
        inbox_len(&fx, &recipient),
        0,
        "the stuck item is finally acked"
    );
}

/// Anti-replay stays intact: a strict-sequence reject for a scope NOT in the
/// durable bookmark is a genuine replay and returns the gate error un-acked — the
/// idempotent ack-only short-circuit fires ONLY with durable proof of prior
/// adoption for that scope.
#[test]
fn a_sequence_replay_for_an_unheld_scope_stays_rejected() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();
    let name_bytes = fx.name.as_str().as_bytes();

    // The sequence floor is already at the record's sequence, but we hold NO
    // bookmark for this scope — a genuine replay, not a lost ack.
    block_on(recipient.floor_store.raise_sequence_floor(name_bytes, 1)).unwrap();

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();

    let rejection = match &err {
        AcceptError::Gate(e) => e.rejection().expect("a fail-closed gate rejection"),
        other => panic!("expected a gate rejection, got {other}"),
    };
    assert_eq!(rejection.check(), "sequence-not-newer");
    assert!(received.is_empty(), "no bookmark was created for a replay");
    assert_eq!(
        inbox_len(&fx, &recipient),
        1,
        "un-acked: a genuine replay is not swallowed"
    );
}

// ---------------------------------------------------------------------------
// Self-healing bookmark: a re-accept with drifted authority heals (P1-2).
// ---------------------------------------------------------------------------

/// Accept a Read grant, then re-accept the SAME scope root after the owner
/// changed the committed permission to Write and rotated the pointer read key.
/// The stored entry heals to the NEW values (the metadata is authority) and is
/// acked only after the durable heal persists — a stale entry is never kept.
#[test]
fn reaccept_self_heals_changed_permission_and_rotated_pointer_key() {
    const ROTATED_POINTER_READ_KEY: [u8; 32] = [0x9C; 32];

    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient_address = fx.recipient_identity.to_sec1();
    let recipient = world.device(&recipient_address);
    let poster = world.device(b"owner-inbox");
    let contact = import_contact(&fx.owner_contact).unwrap();
    let mut received = ReceivedSharesList::new();

    // First accept: Read permission, original pointer read key.
    let item1 = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let outcome1 = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item1,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .expect("first accept");
    assert!(outcome1.newly_added);
    assert_eq!(received.iter().next().unwrap().permission, Permission::Read);
    assert!(
        ct_eq(
            received.iter().next().unwrap().pointer_read_key(),
            &POINTER_READ_KEY
        ),
        "pointer read key mismatch"
    );
    let persists_after_first = recipient.received_share_store.persist_count();
    assert_eq!(
        persists_after_first, 1,
        "the first accept persisted durably"
    );

    // Re-accept the SAME scope with drifted authority. A fresh mailbox item (a
    // distinct idempotency key) redelivers the pointer.
    let (blobs2, candidate2) = fx.reaccept_variant(Permission::Write, ROTATED_POINTER_READ_KEY);
    block_on(post_sealed(
        &poster.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        &fx.owner_identity,
        &fx.share_pointer().encode(),
        "share-2",
    ))
    .unwrap();
    let item2 = block_on(poll_verified(&recipient.mailbox, &fx.recipient_enc, V))
        .unwrap()
        .remove(0);

    let outcome2 = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item2,
        &contact,
        &fx.recipient_enc,
        &candidate2,
        &blobs2,
        &mut received,
    ))
    .expect("re-accept self-heals");
    assert!(!outcome2.newly_added, "existing scope, healed not appended");
    assert_eq!(
        outcome2.permission,
        Permission::Write,
        "committed authority"
    );
    assert_eq!(received.len(), 1, "still one self-healing bookmark");

    let healed = received.iter().next().unwrap();
    assert_eq!(
        healed.permission,
        Permission::Write,
        "permission healed to the new committed value"
    );
    assert!(
        ct_eq(healed.pointer_read_key(), &ROTATED_POINTER_READ_KEY),
        "pointer read key healed to the rotated value"
    );
    assert_eq!(
        recipient.received_share_store.persist_count(),
        persists_after_first + 1,
        "the heal was durably persisted before the ack"
    );
    assert_eq!(
        inbox_len(&fx, &recipient),
        0,
        "acked after the durable heal"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed reject arms on the accept path (each leaves the item un-acked).
// ---------------------------------------------------------------------------

/// Post `pointer` sealed + signed by `signer` to the recipient's inbox, then
/// poll it back as the single verified item — the common accept-test setup.
fn deliver_pointer(
    fx: &GrantFixture,
    recipient: &FakeDevice,
    poster: &FakeDevice,
    signer: &EcdsaSigner,
    pointer: &SharePointer,
) -> VerifiedMailboxItem {
    block_on(post_sealed(
        &poster.mailbox,
        &fx.recipient_enc.public(),
        &fx.recipient_identity,
        &EPH_MAILBOX,
        V,
        signer,
        &pointer.encode(),
        "share",
    ))
    .expect("post");
    let mut items =
        block_on(poll_verified(&recipient.mailbox, &fx.recipient_enc, V)).expect("poll");
    assert_eq!(
        items.len(),
        1,
        "the sealed, sender-authed pointer is delivered"
    );
    items.remove(0)
}

/// The count of currently-deliverable (un-acked) items in the recipient inbox.
fn inbox_len(fx: &GrantFixture, recipient: &FakeDevice) -> usize {
    block_on(poll_verified(&recipient.mailbox, &fx.recipient_enc, V))
        .unwrap()
        .len()
}

/// A valid contact sender, but the pointer's `sharerPub` is a different identity
/// than the verified contact's owner: bind-to-contact rejects it, un-acked.
#[test]
fn pointer_sharer_mismatch_is_rejected_and_unacked() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");

    let mut pointer = fx.share_pointer();
    pointer.sharer_identity_pk = [0x07; IDENTITY_PUBLIC_LEN]; // not the owner identity
    let item = deliver_pointer(&fx, &recipient, &poster, &fx.owner_identity, &pointer);

    let contact = import_contact(&fx.owner_contact).unwrap();
    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::SharerMismatch), "got {err}");
    assert!(received.is_empty());
    assert_eq!(inbox_len(&fx, &recipient), 1, "un-acked");
}

/// The tag stays committed (so the pre-gate committed-tag check passes), but the
/// commitment is re-signed by an ATTACKER: the gate's owner-anchored commitment
/// verify fails. Contrast `a_failed_gate_never_acks_the_item`, which tampers the
/// record bytes and rejects earlier at record-verify.
#[test]
fn tampered_commitment_is_rejected_at_the_gate_and_unacked() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();

    let attacker = EcdsaSigner::from_scalar(&[0x9E; 32]).unwrap();
    let mut candidate = fx.candidate();
    candidate.grant_section.commitment_sig =
        sign_grant_set(&attacker, &candidate.grant_section.commitment)
            .unwrap()
            .to_compact();

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &candidate,
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::Gate(_)), "got {err}");
    assert!(received.is_empty(), "nothing durable was recorded");
    assert_eq!(inbox_len(&fx, &recipient), 1, "un-acked");
}

/// A fresh owner-signed record with NO grant blob at the recipient's blinded tag
/// — the revocation-signal shape: self-locate returns the fail-closed arm.
#[test]
fn no_blob_at_tag_is_rejected_and_unacked() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();

    let no_blobs: Vec<PublishedGrantBlob> = Vec::new();
    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &no_blobs,
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::NoBlobAtTag), "got {err}");
    assert!(received.is_empty());
    assert_eq!(inbox_len(&fx, &recipient), 1, "un-acked");
}

/// A blob is at the right (committed) tag, but its ciphertext is tampered:
/// opening the grant blob fails closed. `UnusableSharerKey` — the sibling arm —
/// is unreachable by construction here: `X25519Public` rejects small-order
/// points at `from_bytes`/`.public()`, so a `Contact`'s enc subkey is always
/// contributory and the ECDH never returns `None`.
#[test]
fn tampered_grant_blob_fails_open_and_is_unacked() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();

    let mut blobs = fx.grant_blobs();
    blobs[0].ciphertext[0] ^= 0x01; // tag unchanged, so self-locate still finds it

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &fx.candidate(),
        &blobs,
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::GrantBlobOpen(_)), "got {err}");
    assert!(received.is_empty());
    assert_eq!(inbox_len(&fx, &recipient), 1, "un-acked");
}

/// The pointer names one scope root but a DIFFERENT record is fed as the
/// candidate: the explicit name/tag coupling check rejects it up front.
#[test]
fn resolved_name_mismatch_is_rejected_and_unacked() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();
    let recipient = world.device(&fx.recipient_identity.to_sec1());
    let poster = world.device(b"owner-inbox");
    let item = deliver_pointer(
        &fx,
        &recipient,
        &poster,
        &fx.owner_identity,
        &fx.share_pointer(),
    );
    let contact = import_contact(&fx.owner_contact).unwrap();

    let other_signer = Ed25519Signer::from_seed([0xAB; 32]);
    let mut candidate = fx.candidate();
    candidate.name = IpnsName::from_public_key(&other_signer.verifying_key());

    let mut received = ReceivedSharesList::new();
    let err = block_on(accept_share(
        &recipient.floor_store,
        &recipient.mailbox,
        &recipient.received_share_store,
        &item,
        &contact,
        &fx.recipient_enc,
        &candidate,
        &fx.grant_blobs(),
        &mut received,
    ))
    .unwrap_err();
    assert!(matches!(err, AcceptError::NameMismatch), "got {err}");
    assert!(received.is_empty());
    assert_eq!(inbox_len(&fx, &recipient), 1, "un-acked");
}

// ---------------------------------------------------------------------------
// The revocation-classification triple.
// ---------------------------------------------------------------------------

#[test]
fn revocation_classification_triple() {
    let fx = GrantFixture::new();
    let world = FakeWorld::new();

    // Owner-signed fact: does the commitment verify against the contact-anchored
    // owner identity? (True for a fresh owner-signed record.)
    let owner_signed = cipherbox_core::seal::verify_grant_set(
        &fx.owner_identity_pub,
        &fx.commitment,
        &fx.commitment_sig,
    )
    .is_ok();
    assert!(owner_signed);

    // (a) Revocation signal: a fresh owner-signed record with NO blob at the tag.
    let no_blobs: Vec<PublishedGrantBlob> = Vec::new();
    let blob_present = self_locate(&no_blobs, &fx.tag).is_some();
    let signal = classify(&ResolutionFacts {
        owner_signed_record: owner_signed,
        blob_present,
        record_epoch: fx.epoch,
        epoch_floor: 0,
    });
    assert_eq!(signal, ResolutionClass::RevocationSignal);

    // (b) Unresolvable: the name is not in the store, so no owner-signed record.
    let recipient_device = world.device(b"reader");
    let endpoint = world.record_store.endpoints()[0].clone();
    let resolved = block_on(recipient_device.record_store.get_record(
        &endpoint,
        fx.name.as_str(),
        MAX_RECORD_BYTES,
    ))
    .unwrap();
    let unresolvable = classify(&ResolutionFacts {
        owner_signed_record: resolved.is_some(),
        blob_present: false,
        record_epoch: 0,
        epoch_floor: 0,
    });
    assert_eq!(unresolvable, ResolutionClass::Unresolvable);

    // (c) Epoch lag: a fresh owner-signed record, blob present, but its epoch is
    // below the recipient's durable read-epoch floor.
    let floor = block_on(
        recipient_device
            .floor_store
            .raise_epoch_floor(&fx.scope_id, 5),
    )
    .unwrap();
    let lag = classify(&ResolutionFacts {
        owner_signed_record: true,
        blob_present: self_locate(&fx.grant_blobs(), &fx.tag).is_some(),
        record_epoch: fx.epoch,
        epoch_floor: floor,
    });
    assert_eq!(lag, ResolutionClass::EpochLag);

    // Anti-vacuity: the three are distinct.
    assert_ne!(signal, unresolvable);
    assert_ne!(signal, lag);
    assert_ne!(unresolvable, lag);
}

// ---------------------------------------------------------------------------
// Owner-entry cross-check disagreement → attributable abuse.
// ---------------------------------------------------------------------------

#[test]
fn owner_entry_seed_disagreement_raises_an_abuse_event() {
    let fx = GrantFixture::new();

    // The seed that actually unsealed the read body is the real scope seed.
    let unseal_seed = fx.scope_seed;

    // Agreement: owner-blob seed and ascent-link seed both equal the unseal seed
    // → a confirmed owner read (no abuse).
    match cross_check(&unseal_seed, Some(&unseal_seed), &unseal_seed, fx.epoch) {
        OwnerEntry::Confirmed { seed, epoch } => {
            assert!(ct_eq(&seed, &unseal_seed), "seed mismatch");
            assert_eq!(epoch, fx.epoch);
        }
        OwnerEntry::Abuse(_) => panic!("agreement must confirm"),
    }

    // A write-grantee published an owner blob carrying a DIFFERENT seed than the
    // one that unseals: an attributable abuse event, surfaced — never silent.
    let rogue_owner_blob_seed = [0xEE; 32];
    match cross_check(&rogue_owner_blob_seed, None, &unseal_seed, fx.epoch) {
        OwnerEntry::Abuse(event) => {
            assert_eq!(event.check(), "owner-seed-cross-check-disagreement");
            // The description maps straight onto the facade abuse event and
            // carries no key material.
            let facade_event = cipherbox_engine::facade::Event::AttributableAbuse {
                description: event.description.clone(),
            };
            assert!(matches!(
                facade_event,
                cipherbox_engine::facade::Event::AttributableAbuse { .. }
            ));
        }
        OwnerEntry::Confirmed { .. } => panic!("a seed disagreement must raise abuse"),
    }
}

// ---------------------------------------------------------------------------
// The contract-suite mailbox lifecycle through the engine's API client.
// ---------------------------------------------------------------------------

/// A 200 JSON response with a raw body (no serde_json dev-dependency needed).
fn json_ok(body: &[u8]) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body: body.to_vec(),
    }
}

#[test]
fn mailbox_lifecycle_through_the_api_client() {
    let http = ScriptedHttp::default();
    let creds = InMemoryCredentialStore::default();
    let client = ApiClient::new(http.clone(), creds, "http://api.test");

    // post → poll → ack, the mailbox surface the contract suite exercises.
    http.enqueue_response(json_ok(br#"{"id":"m1"}"#));
    // "hi" base64 is "aGk=" — hard-coded so the test needs no base64 dep.
    http.enqueue_response(json_ok(
        br#"{"messages":[{"id":"m1","receivedAt":"2026-01-01T00:00:00Z","blob":"aGk="}]}"#,
    ));
    http.enqueue_response(json_ok(br#"{"success":true}"#));

    let posted = block_on(client.mailbox_post("02abc-recipient", b"hi", "idem-1")).expect("post");
    assert_eq!(posted, "m1", "post returns the server-assigned id");
    let items = block_on(client.mailbox_poll()).expect("poll");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, "m1");
    assert_eq!(items[0].blob, b"hi", "blob decodes from base64");
    block_on(client.mailbox_ack("m1")).expect("ack");

    let requests = http.requests();
    assert_eq!(requests.len(), 3);

    // post: JSON body carries the base64 blob and the idempotency key.
    assert_eq!(requests[0].url, "http://api.test/mailbox/messages");
    assert_eq!(requests[0].method, HttpMethod::Post);
    let post_body = String::from_utf8(requests[0].body.clone().unwrap()).unwrap();
    assert!(
        post_body.contains("\"blob\":\"aGk=\""),
        "base64 blob: {post_body}"
    );
    assert!(post_body.contains("idem-1"), "idempotency key: {post_body}");
    assert!(
        post_body.contains("02abc-recipient"),
        "recipient: {post_body}"
    );

    assert_eq!(requests[1].url, "http://api.test/mailbox/messages");
    assert_eq!(requests[1].method, HttpMethod::Get);

    assert_eq!(requests[2].url, "http://api.test/mailbox/messages/m1");
    assert_eq!(requests[2].method, HttpMethod::Delete);
}
