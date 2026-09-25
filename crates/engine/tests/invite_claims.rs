//! Invite claim delivery end to end over the mailbox seam: a link holder posts
//! a sealed, ephemeral-key-signed claim and the owner converts it into a
//! personal grant anchored to the claimant's contact.
//!
//! The unit suite in `grants::invite` covers conversion's reject rows against
//! hand-built items; this suite runs the same conversion over the real
//! [`Mailbox`] seam so the sender authentication a claim depends on is the
//! transport's own, not a test double's.

use std::sync::OnceLock;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{
    ChildScopeRef, GrantSetCommitment, Permission, PreservedFields, sign_grant_set,
};
use cipherbox_core::suite::contact::ContactCode;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;

use cipherbox_engine::grants::{
    CLAIM_ID_LEN, ClaimOutcome, CommittedScope, ConvertedClaim, EphemeralInvitee, InviteClaim,
    InviteError, LinkTerms, OwnerAuthority, convert_invite_claim, import_contact,
    mint_invite_grant, post_invite_claim,
};
use cipherbox_engine::mailbox::{VerifiedMailboxItem, poll_verified};
use cipherbox_engine::rotation::derive_write_name;
use cipherbox_engine::seams::{Mailbox, UnixMillis};
use cipherbox_engine::sync::pointer::scope_pointer_name;
use cipherbox_engine::testkit::fakes::InMemoryMailboxHub;
use cipherbox_engine::testkit::{SeededEntropy, block_on};

const V: u64 = 2;
const SCOPE: [u8; 16] = [0x5c; 16];
const WRITE_SCOPE_SEED: [u8; 32] = [0x55; 32];
/// The scope pointer read key every fixture masks its recipients under.
const POINTER_READ_KEY: [u8; 32] = [0x66; 32];
const POINTER_SEED: [u8; 32] = [0x67; 32];
const DEADLINE: UnixMillis = UnixMillis(10_000);
const EPH_MAILBOX: [u8; 32] = [0x71; 32];
const EPH_FORGED: [u8; 32] = [0x72; 32];
const EPH_TRANSPORT: [u8; 32] = [0x73; 32];

fn owner_enc() -> X25519Secret {
    X25519Secret::from_scalar([0x11; 32])
}

fn owner_identity() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&[0x33; 32]).expect("valid scalar")
}

/// The gated reference a resolve of `SCOPE` at its current name hands back.
fn scope_ref() -> &'static ChildScopeRef {
    static REF: OnceLock<ChildScopeRef> = OnceLock::new();
    REF.get_or_init(|| ChildScopeRef::new(SCOPE, scope_name()))
}

fn scope_name() -> Vec<u8> {
    derive_write_name(&WRITE_SCOPE_SEED, &SCOPE)
        .as_str()
        .as_bytes()
        .to_vec()
}

fn pointer_name() -> IpnsName {
    scope_pointer_name(&POINTER_SEED, &SCOPE)
}

/// The owner's contact bundle, exactly as an invite URL carries it.
fn owner_contact_code() -> Vec<u8> {
    ContactCode::create(&owner_identity(), owner_enc().public()).encode()
}

/// The published set committing one link entry, and the ephemeral identity a
/// fragment holder reconstructs. The set is the owner's only record of it.
struct Link {
    commitment: GrantSetCommitment,
    commitment_sig: cipherbox_core::suite::ecdsa::EcdsaSignature,
    ledger: Vec<cipherbox_core::seal::GrantLedgerEntry>,
    invitee: EphemeralInvitee,
}

impl Link {
    fn scope(&self) -> CommittedScope<'_> {
        CommittedScope::bind(
            scope_ref(),
            &self.commitment,
            &self.commitment_sig,
            &self.ledger,
        )
        .expect("the gated reference names the scope root the set carries")
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
    let invitee = EphemeralInvitee::from_secret(&[0x4e; 32]).expect("valid");
    let row = mint_invite_grant(
        &owner_identity(),
        &owner_enc(),
        &POINTER_READ_KEY,
        &invitee,
        &SCOPE,
        &WRITE_SCOPE_SEED,
        &LinkTerms {
            deadline: Some(DEADLINE),
            conversion_permission: permission,
            admission_cap: 5,
        },
    )
    .expect("mints");
    let commitment = GrantSetCommitment {
        ipns_name: scope_name(),
        owner_pseudonym_pk: Ed25519Signer::from_seed([0x22; 32])
            .verifying_key()
            .to_bytes(),
        cut_epoch: 0,
        entries: vec![row.commitment_entry.clone()],
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(&owner_identity(), &commitment).expect("signs");
    Link {
        commitment,
        commitment_sig,
        ledger: vec![row.ledger_entry],
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
            claim_id: [0x01; CLAIM_ID_LEN],
            scope_pointer_name: pointer_name(),
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
        &pointer_name(),
        &POINTER_READ_KEY,
        &items[0],
        UnixMillis(0),
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
            claim_id: [0x01; CLAIM_ID_LEN],
            scope_pointer_name: pointer_name(),
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
            &pointer_name(),
            &POINTER_READ_KEY,
            &items[0],
            UnixMillis(0),
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
    let claim_id = InviteClaim::mint(
        &mut SeededEntropy::new(4),
        pointer_name(),
        contact_code.clone(),
    )
    .expect("mints")
    .claim_id;

    block_on(post_invite_claim(
        &holder_box,
        &owner_contact,
        &l.invitee,
        &EPH_TRANSPORT,
        V,
        &InviteClaim {
            claim_id,
            scope_pointer_name: pointer_name(),
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
        pointer_name().as_str().as_bytes(),
        &claim_id,
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

/// A claim from `l`'s fragment holder, delivered over the real mailbox and
/// handed back sender-verified: the item conversion consumes.
fn delivered_claim(
    l: &Link,
    claimant_seed: u8,
    claim_id: [u8; CLAIM_ID_LEN],
    scope_pointer: IpnsName,
) -> VerifiedMailboxItem {
    let hub = InMemoryMailboxHub::default();
    let claimant_identity = EcdsaSigner::from_scalar(&[claimant_seed; 32]).expect("valid scalar");
    let claimant_enc = X25519Secret::from_scalar([claimant_seed ^ 0xff; 32]);
    let mut ephemeral = EPH_MAILBOX;
    ephemeral[..CLAIM_ID_LEN].copy_from_slice(&claim_id);
    ephemeral[CLAIM_ID_LEN] = claimant_seed;
    block_on(post_invite_claim(
        &hub.mailbox_for(b"holder-outbox"),
        &import_contact(&owner_contact_code()).expect("valid bundle"),
        &l.invitee,
        &ephemeral,
        V,
        &InviteClaim {
            claim_id,
            scope_pointer_name: scope_pointer,
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

fn convert(
    scope: &CommittedScope<'_>,
    item: &VerifiedMailboxItem,
    now: UnixMillis,
) -> Result<ConvertedClaim, InviteError> {
    let keys = Owner::new();
    convert_invite_claim(
        &keys.authority(),
        scope,
        &pointer_name(),
        &POINTER_READ_KEY,
        item,
        now,
    )
}

/// ADR 0023 D3: a claimant the published set already grants is a no-op. The
/// set comes back unchanged, so the owner publishes nothing.
#[test]
fn a_claim_from_a_committed_grantee_changes_nothing() {
    let l = link(Permission::Read);
    let first = convert(
        &l.scope(),
        &delivered_claim(&l, 0x68, [0xb1; CLAIM_ID_LEN], pointer_name()),
        UnixMillis(0),
    )
    .expect("converts");
    assert_eq!(first.outcome, ClaimOutcome::Granted);

    let sig = sign_grant_set(&owner_identity(), &first.commitment).expect("signs");
    let live =
        CommittedScope::bind(scope_ref(), &first.commitment, &sig, &first.ledger).expect("binds");
    for claim_id in [[0xb1; CLAIM_ID_LEN], [0xb2; CLAIM_ID_LEN]] {
        let again = convert(
            &live,
            &delivered_claim(&l, 0x68, claim_id, pointer_name()),
            UnixMillis(1),
        )
        .expect("a known identity converts to a no-op");
        assert_eq!(again.outcome, ClaimOutcome::Unchanged);
        assert_eq!(again.commitment, first.commitment);
        assert_eq!(again.ledger, first.ledger);
    }
}

/// A write link converts at read, because a write grant needs a write cut that
/// conversion does not run.
#[test]
fn a_write_link_converts_to_a_read_grant() {
    let l = link(Permission::Write);
    let converted = convert(
        &l.scope(),
        &delivered_claim(&l, 0x69, [0xc1; CLAIM_ID_LEN], pointer_name()),
        UnixMillis(0),
    )
    .expect("converts");
    assert_eq!(converted.outcome, ClaimOutcome::Granted);
    assert_eq!(converted.row.ledger_entry.permission, Permission::Read);
}

/// ADR 0023 D3: the deadline must be later than now.
#[test]
fn a_claim_at_the_link_deadline_is_refused() {
    let l = link(Permission::Read);
    let item = delivered_claim(&l, 0x6a, [0xd1; CLAIM_ID_LEN], pointer_name());
    assert!(convert(&l.scope(), &item, UnixMillis(DEADLINE.0 - 1)).is_ok());
    assert_eq!(
        convert(&l.scope(), &item, DEADLINE).unwrap_err().check(),
        "link-expired"
    );
}

/// The claim names the scope pointer. A claim that names the pointer of another
/// scope is refused, whatever link signed it.
#[test]
fn a_claim_naming_another_scope_pointer_is_refused() {
    let l = link(Permission::Read);
    let item = delivered_claim(
        &l,
        0x6b,
        [0xe1; CLAIM_ID_LEN],
        scope_pointer_name(&POINTER_SEED, &[0x5d; 16]),
    );
    assert_eq!(
        convert(&l.scope(), &item, UnixMillis(0))
            .unwrap_err()
            .check(),
        "claim-scope-mismatch"
    );
}
