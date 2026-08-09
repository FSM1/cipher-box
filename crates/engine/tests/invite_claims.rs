//! Invite claim delivery end to end over the mailbox seam: a link holder posts
//! a sealed, ephemeral-key-signed claim and the owner converts it into a
//! personal grant anchored to the claimant's contact.
//!
//! The unit suite in `grants::invite` covers conversion's reject rows against
//! hand-built items; this suite runs the same conversion over the real
//! [`Mailbox`] seam so the sender authentication a claim depends on is the
//! transport's own, not a test double's.

use cipherbox_core::seal::{GrantSetCommitment, Permission, PreservedFields, sign_grant_set};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;

use cipherbox_engine::grants::{
    ClaimOutcome, CommittedScope, EphemeralInvitee, InviteClaim, InviteStore, OwnerAuthority,
    RecordedInvite, StagingInviteStore, convert_invite_claim, import_contact, mint_invite_grant,
    post_invite_claim, revoke_invite_link,
};
use cipherbox_engine::mailbox::poll_verified;
use cipherbox_engine::rotation::derive_write_name;
use cipherbox_engine::seams::{Mailbox, UnixMillis};
use cipherbox_engine::testkit::fakes::{InMemoryMailboxHub, InMemoryStagingStore};
use cipherbox_engine::testkit::{SeededEntropy, block_on};

use core::cell::RefCell;

const V: u64 = 2;
const SCOPE: [u8; 16] = [0x5c; 16];
const WRITE_SCOPE_SEED: [u8; 32] = [0x55; 32];
const EPH_MAILBOX: [u8; 32] = [0x71; 32];
const EPH_FORGED: [u8; 32] = [0x72; 32];
const EPH_TRANSPORT: [u8; 32] = [0x73; 32];

fn owner_enc() -> X25519Secret {
    X25519Secret::from_scalar([0x11; 32])
}

fn owner_identity() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&[0x33; 32]).expect("valid scalar")
}

fn scope_name() -> Vec<u8> {
    derive_write_name(&WRITE_SCOPE_SEED, &SCOPE)
        .as_str()
        .as_bytes()
        .to_vec()
}

/// The owner's contact bundle, exactly as an invite URL carries it.
fn owner_contact_code() -> Vec<u8> {
    ContactCode::create(&owner_identity(), owner_enc().public()).encode()
}

/// The published set committing one invite link, the owner's record of it, and
/// the ephemeral identity a fragment holder reconstructs.
struct Link {
    commitment: GrantSetCommitment,
    commitment_sig: cipherbox_core::suite::ecdsa::EcdsaSignature,
    ledger: Vec<cipherbox_core::seal::GrantLedgerEntry>,
    recorded: RecordedInvite,
    invitee: EphemeralInvitee,
}

impl Link {
    fn scope(&self) -> CommittedScope<'_> {
        CommittedScope {
            scope_id: &SCOPE,
            commitment: &self.commitment,
            commitment_sig: &self.commitment_sig,
            ledger: &self.ledger,
        }
    }
}

/// The owner's two halves, held so an `OwnerAuthority` can borrow them.
struct Owner {
    identity: EcdsaSigner,
    enc: X25519Secret,
}

impl Owner {
    fn new() -> Self {
        Self {
            identity: owner_identity(),
            enc: owner_enc(),
        }
    }

    fn authority(&self) -> OwnerAuthority<'_> {
        OwnerAuthority {
            identity_signer: &self.identity,
            enc_secret: &self.enc,
        }
    }
}

fn link(permission: Permission) -> Link {
    link_until(permission, None)
}

fn link_until(permission: Permission, expires_at: Option<UnixMillis>) -> Link {
    let invitee = EphemeralInvitee::from_secret(&[0x4e; 32]).expect("valid");
    let minted = mint_invite_grant(
        &owner_enc(),
        &invitee,
        &SCOPE,
        &WRITE_SCOPE_SEED,
        permission,
        expires_at,
    )
    .expect("mints");
    let commitment = GrantSetCommitment {
        ipns_name: scope_name(),
        owner_pseudonym_pk: Ed25519Signer::from_seed([0x22; 32])
            .verifying_key()
            .to_bytes(),
        entries: vec![minted.row.commitment_entry.clone()],
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(&owner_identity(), &commitment).expect("signs");
    Link {
        commitment,
        commitment_sig,
        ledger: vec![minted.row.ledger_entry],
        recorded: minted.link,
        invitee,
    }
}

#[test]
fn a_link_holder_claims_over_the_mailbox_and_the_owner_converts_it() {
    let hub = InMemoryMailboxHub::default();
    let owner_address = owner_identity().verifying_key().to_sec1();
    let owner_box = hub.mailbox_for(&owner_address);
    let holder_box = hub.mailbox_for(b"holder-outbox");

    let l = link(Permission::Read);
    let claimant_identity = EcdsaSigner::from_scalar(&[0x61; 32]).expect("valid scalar");
    let claimant_enc = X25519Secret::from_scalar([0x62; 32]);
    let owner_contact = import_contact(&owner_contact_code()).expect("valid bundle");

    block_on(post_invite_claim(
        &holder_box,
        &owner_contact,
        &l.invitee,
        &EPH_MAILBOX,
        V,
        &InviteClaim {
            scope_root_name: scope_name(),
            contact_code: ContactCode::create(&claimant_identity, claimant_enc.public()).encode(),
        },
        "claim-1",
    ))
    .expect("posts");

    let items = block_on(poll_verified(&owner_box, &owner_enc(), V)).expect("polls");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].sender_identity,
        l.invitee.identity_pk(),
        "the claim authenticates as the link's ephemeral identity",
    );

    let keys = Owner::new();
    let converted = convert_invite_claim(
        &keys.authority(),
        &l.scope(),
        &[l.recorded],
        &items[0],
        cipherbox_engine::seams::UnixMillis(0),
    )
    .expect("converts");

    assert_eq!(converted.outcome, ClaimOutcome::Granted);
    assert_eq!(
        converted.row.ledger_entry.recipient_identity_pk,
        claimant_identity.verifying_key().to_sec1(),
    );
    assert_eq!(converted.commitment.entries.len(), 2, "the link stays live");
}

#[test]
fn a_claim_signed_by_a_key_the_link_does_not_commit_never_becomes_a_grant() {
    let hub = InMemoryMailboxHub::default();
    let owner_address = owner_identity().verifying_key().to_sec1();
    let owner_box = hub.mailbox_for(&owner_address);
    let forger_box = hub.mailbox_for(b"forger-outbox");

    let l = link(Permission::Read);
    let stranger = EphemeralInvitee::from_secret(&[0x4f; 32]).expect("valid");
    let claimant_identity = EcdsaSigner::from_scalar(&[0x63; 32]).expect("valid scalar");
    let claimant_enc = X25519Secret::from_scalar([0x64; 32]);
    let owner_contact = import_contact(&owner_contact_code()).expect("valid bundle");

    block_on(post_invite_claim(
        &forger_box,
        &owner_contact,
        &stranger,
        &EPH_FORGED,
        V,
        &InviteClaim {
            scope_root_name: scope_name(),
            contact_code: ContactCode::create(&claimant_identity, claimant_enc.public()).encode(),
        },
        "forged-1",
    ))
    .expect("posts");

    // The mailbox authenticates it — the forger signed honestly, just with a key
    // the owner never recorded — so the fail-closed reject is conversion's.
    let items = block_on(poll_verified(&owner_box, &owner_enc(), V)).expect("polls");
    assert_eq!(items.len(), 1);

    let keys = Owner::new();
    assert_eq!(
        convert_invite_claim(
            &keys.authority(),
            &l.scope(),
            &[l.recorded],
            &items[0],
            cipherbox_engine::seams::UnixMillis(0),
        )
        .unwrap_err()
        .check(),
        "link-not-committed",
    );
}

#[test]
fn the_transport_sees_no_claim_field_in_the_clear() {
    let hub = InMemoryMailboxHub::default();
    let owner_address = owner_identity().verifying_key().to_sec1();
    let holder_box = hub.mailbox_for(b"holder-outbox");

    let l = link(Permission::Read);
    let claimant_identity = EcdsaSigner::from_scalar(&[0x65; 32]).expect("valid scalar");
    let claimant_enc = X25519Secret::from_scalar([0x66; 32]);
    let contact_code = ContactCode::create(&claimant_identity, claimant_enc.public()).encode();
    let owner_contact = import_contact(&owner_contact_code()).expect("valid bundle");

    block_on(post_invite_claim(
        &holder_box,
        &owner_contact,
        &l.invitee,
        &EPH_TRANSPORT,
        V,
        &InviteClaim {
            scope_root_name: scope_name(),
            contact_code: contact_code.clone(),
        },
        "claim-1",
    ))
    .expect("posts");

    let sealed = block_on(hub.mailbox_for(&owner_address).poll()).expect("polls")[0]
        .sealed_payload
        .clone();
    for secret in [
        contact_code.as_slice(),
        &claimant_identity.verifying_key().to_sec1(),
        scope_name().as_slice(),
    ] {
        // `windows` yields nothing when the payload is shorter than the needle,
        // which would pass the scan below without scanning anything.
        assert!(
            sealed.len() >= secret.len(),
            "the sealed payload is too short for this scan to mean anything",
        );
        assert!(
            !sealed.windows(secret.len()).any(|w| w == secret),
            "the transport must carry no claim field in the clear",
        );
    }
}

/// A claim from `link`'s fragment holder, delivered over the real mailbox and
/// handed back sender-verified — the item conversion actually consumes.
fn delivered_claim(l: &Link, claimant_seed: u8) -> cipherbox_engine::mailbox::VerifiedMailboxItem {
    let hub = InMemoryMailboxHub::default();
    let claimant_identity = EcdsaSigner::from_scalar(&[claimant_seed; 32]).expect("valid scalar");
    let claimant_enc = X25519Secret::from_scalar([claimant_seed ^ 0xff; 32]);
    block_on(post_invite_claim(
        &hub.mailbox_for(b"holder-outbox"),
        &import_contact(&owner_contact_code()).expect("valid bundle"),
        &l.invitee,
        &EPH_MAILBOX,
        V,
        &InviteClaim {
            scope_root_name: scope_name(),
            contact_code: ContactCode::create(&claimant_identity, claimant_enc.public()).encode(),
        },
        "claim-1",
    ))
    .expect("posts");
    let owner_box = hub.mailbox_for(&owner_identity().verifying_key().to_sec1());
    block_on(poll_verified(&owner_box, &owner_enc(), V))
        .expect("polls")
        .pop()
        .expect("the claim was delivered")
}

/// The gap the invite store closes: a link minted in one session is converted
/// and revoked in the next, against the record the owner recovered rather than
/// against the published row.
#[test]
fn a_link_minted_in_one_session_converts_and_revokes_in_the_next() {
    let staging = InMemoryStagingStore::default();
    let enc = owner_enc();
    let l = link(Permission::Read);
    {
        let entropy = RefCell::new(SeededEntropy::new(5));
        let minting_session = StagingInviteStore::new(&staging, &enc, &entropy);
        block_on(minting_session.persist(&[l.recorded])).expect("the mint records its link");
    }

    // A later session: a fresh handle over the same durable backing, nothing
    // carried over in memory.
    let entropy = RefCell::new(SeededEntropy::new(6));
    let recovered = block_on(StagingInviteStore::new(&staging, &enc, &entropy).load())
        .expect("the records load");
    assert_eq!(recovered, vec![l.recorded]);

    let keys = Owner::new();
    let converted = convert_invite_claim(
        &keys.authority(),
        &l.scope(),
        &recovered,
        &delivered_claim(&l, 0x67),
        UnixMillis(0),
    )
    .expect("the recovered record converts the claim");
    assert_eq!(converted.outcome, ClaimOutcome::Granted);

    let cut = revoke_invite_link(&keys.authority(), &l.scope(), &recovered[0])
        .expect("the recovered record revokes its link");
    assert!(
        !cut.commitment
            .entries
            .iter()
            .any(|e| e.tag == l.recorded.tag),
        "the link the earlier session minted is cut from the owner-signed set"
    );
}

/// The recorded deadline is what conversion judges expiry on, so it has to
/// survive the round trip — an expired link must stay expired after a restart.
#[test]
fn a_recovered_record_carries_the_deadline_conversion_judges_expiry_on() {
    let staging = InMemoryStagingStore::default();
    let deadline = UnixMillis(1_700_000_000_000);
    let l = link_until(Permission::Read, Some(deadline));
    let enc = owner_enc();
    let entropy = RefCell::new(SeededEntropy::new(7));
    block_on(StagingInviteStore::new(&staging, &enc, &entropy).persist(&[l.recorded]))
        .expect("persist");
    let recovered =
        block_on(StagingInviteStore::new(&staging, &enc, &entropy).load()).expect("load");
    assert_eq!(recovered[0].expires_at, Some(deadline));

    let keys = Owner::new();
    assert_eq!(
        convert_invite_claim(
            &keys.authority(),
            &l.scope(),
            &recovered,
            &delivered_claim(&l, 0x69),
            deadline,
        )
        .unwrap_err()
        .check(),
        "link-expired",
    );
}
