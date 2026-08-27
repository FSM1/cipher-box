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
    CLAIM_ID_LEN, ClaimOutcome, CommittedScope, ConvertedClaim, ConvertedClaimRecord,
    EphemeralInvitee, InviteClaim, InviteRecords, InviteStore, OwnerAuthority, RecordedInvite,
    StagingInviteStore, convert_invite_claim, import_contact, locate_invite_link,
    mint_invite_grant, post_invite_claim,
};
use cipherbox_engine::mailbox::poll_verified;
use cipherbox_engine::rotation::derive_write_name;
use cipherbox_engine::seams::{Mailbox, Scheduler, UnixMillis};
use cipherbox_engine::testkit::fakes::{
    InMemoryMailboxHub, InMemoryStagingStore, VirtualScheduler,
};
use cipherbox_engine::testkit::{SeededEntropy, block_on};

use core::cell::RefCell;
use core::time::Duration;

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

/// The store's unit of persistence, spelled out at each call site so a test
/// says what it recorded.
fn records(links: &[RecordedInvite], claims: &[ConvertedClaimRecord]) -> InviteRecords {
    InviteRecords {
        links: links.to_vec(),
        claims: claims.to_vec(),
    }
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
        &owner_identity(),
        &owner_enc(),
        &invitee,
        &SCOPE,
        &derive_write_name(&WRITE_SCOPE_SEED, &SCOPE),
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
            claim_id: [0x01; CLAIM_ID_LEN],
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
        &[],
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
            claim_id: [0x01; CLAIM_ID_LEN],
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
            &[],
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
    let claim_id = InviteClaim::mint(
        &mut SeededEntropy::new(4),
        scope_name(),
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

/// A claim from `link`'s fragment holder, delivered over the real mailbox and
/// handed back sender-verified — the item conversion actually consumes.
///
/// Deterministic in its arguments, so calling it twice with one `claim_id` is
/// the redelivery the transport is free to make. The HPKE ephemeral varies with
/// them for the same reason a real one is fresh per seal.
fn delivered_claim(
    l: &Link,
    claimant_seed: u8,
    claim_id: [u8; CLAIM_ID_LEN],
) -> cipherbox_engine::mailbox::VerifiedMailboxItem {
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
        block_on(minting_session.persist(&records(&[l.recorded], &[])))
            .expect("the mint records its link");
    }

    // A later session: a fresh handle over the same durable backing, nothing
    // carried over in memory.
    let entropy = RefCell::new(SeededEntropy::new(6));
    let recovered = block_on(StagingInviteStore::new(&staging, &enc, &entropy).load())
        .expect("the records load");
    assert_eq!(recovered, records(&[l.recorded], &[]));

    let keys = Owner::new();
    let converted = convert_invite_claim(
        &keys.authority(),
        &l.scope(),
        &recovered.links,
        &recovered.claims,
        &delivered_claim(&l, 0x67, [0x11; CLAIM_ID_LEN]),
        UnixMillis(0),
    )
    .expect("the recovered record converts the claim");
    assert_eq!(converted.outcome, ClaimOutcome::Granted);

    let located = locate_invite_link(&keys.authority(), &l.scope(), &recovered.links)
        .expect("the recovered record names its link");
    assert_eq!(
        located.tag, l.recorded.tag,
        "the link a later session revokes is the one the earlier session minted",
    );
}

/// The recorded deadline is what conversion judges expiry on, so it has to
/// survive the round trip — an expired link must stay expired after a restart.
#[test]
fn a_recovered_record_carries_the_deadline_conversion_judges_expiry_on() {
    let staging = InMemoryStagingStore::default();
    let deadline = UnixMillis(1_700_000_000_000);
    let mut l = link_until(Permission::Read, Some(deadline));
    // The published deadline is the copy a write-grantee can strip
    // (`RecordedInvite::expires_at`). Clearing it leaves the recovered record
    // as the only thing that can still refuse the claim.
    for entry in &mut l.ledger {
        entry.expires_at = None;
    }
    let enc = owner_enc();
    let entropy = RefCell::new(SeededEntropy::new(7));
    block_on(
        StagingInviteStore::new(&staging, &enc, &entropy).persist(&records(&[l.recorded], &[])),
    )
    .expect("persist");
    let recovered =
        block_on(StagingInviteStore::new(&staging, &enc, &entropy).load()).expect("load");
    assert_eq!(recovered.links[0].expires_at, Some(deadline));

    let keys = Owner::new();
    assert_eq!(
        convert_invite_claim(
            &keys.authority(),
            &l.scope(),
            &recovered.links,
            &recovered.claims,
            &delivered_claim(&l, 0x69, [0x12; CLAIM_ID_LEN]),
            deadline,
        )
        .unwrap_err()
        .check(),
        "link-expired",
    );
}

/// The owner's session as a simulation drives it: the durable store it recovers
/// its invite state from, and the deterministic clock every instant comes from.
struct OwnerSession {
    staging: InMemoryStagingStore,
    entropy: RefCell<SeededEntropy>,
    clock: VirtualScheduler,
    enc: X25519Secret,
}

impl OwnerSession {
    fn new(seed: u64) -> Self {
        Self {
            staging: InMemoryStagingStore::default(),
            entropy: RefCell::new(SeededEntropy::new(seed)),
            clock: VirtualScheduler::starting_at(UnixMillis(1_700_000_000_000)),
            enc: owner_enc(),
        }
    }

    fn store(&self) -> StagingInviteStore<'_, InMemoryStagingStore, SeededEntropy> {
        StagingInviteStore::new(&self.staging, &self.enc, &self.entropy)
    }

    fn load(&self) -> InviteRecords {
        block_on(self.store().load()).expect("the recorded state loads")
    }

    fn persist(&self, state: &InviteRecords) {
        block_on(self.store().persist(state)).expect("the state records");
    }
}

/// A link whose deadline outlasts the whole simulation, so `now` is genuinely
/// consulted at every conversion rather than ignored for want of a deadline.
fn dated_link() -> Link {
    link_until(Permission::Read, Some(UnixMillis(1_900_000_000_000)))
}

/// The state a simulation starts from: the link recorded, nothing spent.
fn recorded(session: &OwnerSession, l: &Link) {
    session.persist(&records(&[l.recorded], &[]));
}

/// Convert one claim from `l`'s holder and record what it spent, exactly as the
/// caller contract requires before it acks.
fn convert_and_record(
    session: &OwnerSession,
    keys: &Owner,
    scope: &CommittedScope<'_>,
    l: &Link,
    claimant_seed: u8,
    claim_id: [u8; CLAIM_ID_LEN],
) -> ConvertedClaim {
    let held = session.load();
    let converted = convert_invite_claim(
        &keys.authority(),
        scope,
        &held.links,
        &held.claims,
        &delivered_claim(l, claimant_seed, claim_id),
        session.clock.now(),
    )
    .expect("the claim converts");
    let mut claims = held.claims;
    claims.extend(converted.record);
    session.persist(&records(&held.links, &claims));
    converted
}

/// The scope a set reads as once the owner has signed and published it.
fn published<'a>(
    commitment: &'a GrantSetCommitment,
    sig: &'a cipherbox_core::suite::ecdsa::EcdsaSignature,
    ledger: &'a [cipherbox_core::seal::GrantLedgerEntry],
) -> CommittedScope<'a> {
    CommittedScope {
        scope_id: &SCOPE,
        commitment,
        commitment_sig: sig,
        ledger,
    }
}

/// Convert one claim and refuse it, returning the refusal's stable name.
fn refuse(
    session: &OwnerSession,
    keys: &Owner,
    scope: &CommittedScope<'_>,
    item: &cipherbox_engine::mailbox::VerifiedMailboxItem,
) -> &'static str {
    let held = session.load();
    convert_invite_claim(
        &keys.authority(),
        scope,
        &held.links,
        &held.claims,
        item,
        session.clock.now(),
    )
    .expect_err("the claim is not convertible")
    .check()
}

/// A claim the server re-serves after the owner cut the grant it made.
/// Re-converting it would have the owner re-sign a set that undoes its own
/// revocation.
#[test]
fn a_claim_redelivered_after_its_grant_was_cut_does_not_resurrect_it() {
    let session = OwnerSession::new(11);
    let keys = Owner::new();
    let l = dated_link();
    recorded(&session, &l);

    let claim = delivered_claim(&l, 0x67, [0xa1; CLAIM_ID_LEN]);
    let converted = convert_and_record(&session, &keys, &l.scope(), &l, 0x67, [0xa1; CLAIM_ID_LEN]);
    assert_eq!(converted.outcome, ClaimOutcome::Granted);
    let granted_tag = converted.row.tag;

    // The owner publishes the conversion, then cuts that grantee: absence from
    // the committed set is the revocation.
    let mut after_cut = converted.commitment.clone();
    after_cut.entries.retain(|e| e.tag != granted_tag);
    let after_cut_sig = sign_grant_set(&owner_identity(), &after_cut).expect("signs");
    let after_cut_ledger: Vec<_> = converted
        .ledger
        .iter()
        .filter(|e| e.tag != granted_tag)
        .cloned()
        .collect();
    let cut_scope = published(&after_cut, &after_cut_sig, &after_cut_ledger);

    session.clock.advance(Duration::from_secs(3_600));
    let redelivered = delivered_claim(&l, 0x67, [0xa1; CLAIM_ID_LEN]);
    assert_eq!(
        redelivered.payload, claim.payload,
        "the transport re-serves the same claim, so this is a redelivery and not a second claim"
    );
    assert_eq!(
        refuse(&session, &keys, &cut_scope, &redelivered),
        "claim-already-converted",
    );

    // Nor may a fresh claim through the same link undo the cut while the link is
    // still live: the record is per link, and this is that link.
    let fresh = delivered_claim(&l, 0x67, [0xa2; CLAIM_ID_LEN]);
    assert_eq!(refuse(&session, &keys, &cut_scope, &fresh), "grant-was-cut");
}

/// The same redelivery before any cut. The committed set already carries the
/// grant, so the answer is a refusal that changes nothing — the caller acks and
/// publishes nothing.
#[test]
fn a_claim_redelivered_before_any_cut_is_an_idempotent_no_op() {
    let session = OwnerSession::new(12);
    let keys = Owner::new();
    let l = dated_link();
    recorded(&session, &l);

    let converted = convert_and_record(&session, &keys, &l.scope(), &l, 0x68, [0xb1; CLAIM_ID_LEN]);
    assert_eq!(converted.outcome, ClaimOutcome::Granted);
    let sig = sign_grant_set(&owner_identity(), &converted.commitment).expect("signs");
    let live = published(&converted.commitment, &sig, &converted.ledger);
    let spent = session.load();

    session.clock.advance(Duration::from_secs(60));
    assert_eq!(
        refuse(
            &session,
            &keys,
            &live,
            &delivered_claim(&l, 0x68, [0xb1; CLAIM_ID_LEN]),
        ),
        "claim-already-converted",
    );

    // A second claim from a grantee already committed is the reachable
    // `Unchanged` path, and it must not grow the spent set — one record per
    // grantee per link is what keeps a link holder from filling it.
    let again = convert_and_record(&session, &keys, &live, &l, 0x68, [0xb2; CLAIM_ID_LEN]);
    assert_eq!(again.outcome, ClaimOutcome::Unchanged);
    assert_eq!(again.record, None, "the grantee is already recorded");
    assert_eq!(session.load(), spent, "the spent set did not grow");
}
