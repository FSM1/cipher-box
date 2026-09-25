use core::cell::RefCell;

use super::super::rotate_write::derive_write_name;
use super::*;
use crate::testkit::block_on;
use cipherbox_core::seal::{PreservedFields, sign_recipient_binding, verify_grant_set};
use cipherbox_core::suite::ecdsa::EcdsaSignature;

use crate::grants::ledger::{mint_grant_row, recipient_blinded_tag};
use cipherbox_core::suite::x25519::X25519Secret;

/// Records the roots it was asked to cut, failing the ones named in
/// `refuse` — the driver's only view of the rotation edge.
struct FakeRotator {
    seen: RefCell<Vec<NodeId>>,
    refuse: Vec<NodeId>,
}

impl FakeRotator {
    fn refusing(refuse: &[NodeId]) -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            refuse: refuse.to_vec(),
        }
    }
}

impl ScopeExitRotator for FakeRotator {
    async fn rotate_on_scope_exit(
        &self,
        scope_root: NodeId,
    ) -> Result<RotationOutcome, RotateError> {
        self.seen.borrow_mut().push(scope_root);
        if self.refuse.contains(&scope_root) {
            return Err(RotateError::Publish(
                super::super::rotate::RotationPublishError::NotPublished,
            ));
        }
        Ok(RotationOutcome {
            new_read_epoch: 2,
            epoch_floor: 2,
        })
    }
}

fn node(b: u8) -> NodeId {
    NodeId([b; 16])
}

#[test]
fn each_queued_root_is_cut_once_in_order() {
    let rotator = FakeRotator::refusing(&[]);
    let roots = [node(1), node(2)];
    let report = block_on(consume_scope_exit_triggers(&rotator, &roots));

    assert_eq!(*rotator.seen.borrow(), roots);
    assert_eq!(
        report.rotated.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
        roots
    );
    assert!(report.is_complete());
}

#[test]
fn a_failed_rotation_surfaces_and_the_rest_still_cut() {
    // A swallowed failure is a revokee left holding a live seed, and a
    // short-circuit would strand every later root behind it.
    let rotator = FakeRotator::refusing(&[node(2)]);
    let report = block_on(consume_scope_exit_triggers(
        &rotator,
        &[node(1), node(2), node(3)],
    ));

    assert_eq!(*rotator.seen.borrow(), [node(1), node(2), node(3)]);
    assert_eq!(
        report.rotated.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
        [node(1), node(3)]
    );
    assert_eq!(
        report.failed.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
        [node(2)]
    );
    assert!(
        !report.is_complete(),
        "an unsettled trigger keeps the pass incomplete"
    );
}

const NO_SIG: [u8; ECDSA_SIG_LEN] = [0u8; ECDSA_SIG_LEN];

/// The three recipients the fixture commits, by their X25519 scalar seed.
/// The scope pointer read key every fixture masks its recipients under.
const PRK: [u8; SECRET_LEN] = [0x66; SECRET_LEN];
const READ_RECIPIENT: u8 = 0x11;
const LINK_RECIPIENT: u8 = 0x12;
const WRITE_RECIPIENT: u8 = 0x13;

fn owner_enc() -> X25519Secret {
    X25519Secret::from_scalar([0x5b; 32])
}

fn recipient_enc(seed: u8) -> X25519Secret {
    X25519Secret::from_scalar([seed; 32])
}

fn scope_name() -> IpnsName {
    derive_write_name(&[0x5a; 32], &[0x01; 16])
}

/// The tag the owner commits `seed`'s recipient under at [`scope_name`].
fn tag_of(seed: u8) -> [u8; 32] {
    recipient_blinded_tag(
        &owner_enc(),
        &recipient_enc(seed).public(),
        scope_name().as_str().as_bytes(),
    )
    .expect("a contributory recipient key")
}

fn read_tag() -> [u8; 32] {
    tag_of(READ_RECIPIENT)
}

fn link_tag() -> [u8; 32] {
    tag_of(LINK_RECIPIENT)
}

fn write_tag() -> [u8; 32] {
    tag_of(WRITE_RECIPIENT)
}

/// Three grants the owner committed at one scope root: a plain read grant, a
/// read link the owner minted with a deadline, and a write grant.
struct Fixture {
    owner: EcdsaSigner,
    name: IpnsName,
    commitment: GrantSetCommitment,
    commitment_sig: [u8; ECDSA_SIG_LEN],
    ledger: Vec<GrantLedgerEntry>,
}

impl Fixture {
    fn new() -> Self {
        let owner = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
        let name = scope_name();
        let mint = |seed: u8, identity: [u8; 33], permission| {
            mint_grant_row(
                &owner,
                &owner_enc(),
                &PRK,
                identity,
                &recipient_enc(seed).public(),
                &[0x01; 16],
                name.as_str().as_bytes(),
                permission,
            )
            .expect("a contributory recipient key")
        };
        let rows = [
            mint(READ_RECIPIENT, [0x02; 33], Permission::Read),
            mint(LINK_RECIPIENT, [0x04; 33], Permission::Read),
            mint(WRITE_RECIPIENT, [0x03; 33], Permission::Write),
        ];
        let commitment = GrantSetCommitment {
            ipns_name: name.as_str().as_bytes().to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            cut_epoch: 0,
            entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
            unknown: PreservedFields::new(),
        };
        let commitment_sig = sign_grant_set(&owner, &commitment).unwrap().to_compact();
        let ledger = rows.into_iter().map(|r| r.ledger_entry).collect();
        Self {
            owner,
            name,
            commitment,
            commitment_sig,
            ledger,
        }
    }

    fn plan(&self) -> GrantCutPlan<'_> {
        GrantCutPlan {
            commitment: &self.commitment,
            commitment_sig: &self.commitment_sig,
            grant_ledger: &self.ledger,
            scope_root_name: &self.name,
            owner_signer: &self.owner,
            pointer_read_key: &PRK,
        }
    }

    /// The same plan bound to a different scope root.
    fn plan_at<'a>(&'a self, name: &'a IpnsName) -> GrantCutPlan<'a> {
        GrantCutPlan {
            scope_root_name: name,
            ..self.plan()
        }
    }

    /// The same plan presented by a party that is not the owner.
    fn plan_signed_by<'a>(&'a self, signer: &'a EcdsaSigner) -> GrantCutPlan<'a> {
        GrantCutPlan {
            owner_signer: signer,
            ..self.plan()
        }
    }

    fn verify(&self, cut: &RevokedCommittedSet) {
        let sig = EcdsaSignature::from_compact(&cut.commitment_sig).unwrap();
        verify_grant_set(&self.owner.verifying_key(), &cut.commitment, &sig)
            .expect("the owner's fresh signature covers the cut set");
    }
}

fn stranger() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&[0x44; 32]).unwrap()
}

#[test]
fn revoke_removes_tag_from_both_and_resigns() {
    let fx = Fixture::new();
    let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("revoke");

    assert!(!cut.commitment.entries.iter().any(|e| e.tag == link_tag()));
    assert!(!cut.grant_ledger.iter().any(|e| e.tag == link_tag()));
    assert_eq!(cut.commitment.entries.len(), 2);
    assert_eq!(cut.grant_ledger.len(), 2);
    fx.verify(&cut);
}

#[test]
fn a_cut_names_the_recipient_it_removed_and_no_survivor() {
    // The cascade carries this down every descendant, where a blinded tag
    // cannot reach: a tag is per-scope, a recipient key is vault-wide.
    let fx = Fixture::new();
    let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("revoke");
    assert_eq!(
        cut.revoked_recipients,
        vec![recipient_enc(LINK_RECIPIENT).public().to_bytes()]
    );

    let downgraded = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
        .expect("downgrade");
    assert!(
        downgraded.revoked_recipients.is_empty(),
        "a downgrade keeps the recipient committed, so nothing is revoked"
    );
}

/// Relabel the link grant's ledger row. `attest` picks whether the writer
/// leaves the owner's stale signature in place or the owner is tricked into
/// re-signing the row as presented — the strongest form of the attack.
fn relabel_link_row(fx: &mut Fixture, enc_pk: [u8; 32], attest: bool) {
    let owner = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
    let name = fx.name.as_str().as_bytes().to_vec();
    for row in &mut fx.ledger {
        if row.tag == link_tag() {
            row.recipient_enc_pk = enc_pk;
            if attest {
                row.owner_sig = sign_recipient_binding(&owner, &name, row).to_compact();
            }
        }
    }
}

/// Relabel the link grant's committed recipient key and owner-re-sign the
/// set, so the cut reads the new key from the owner's own attestation.
fn relabel_link_entry(fx: &mut Fixture, enc_pk: [u8; 32]) {
    for entry in &mut fx.commitment.entries {
        if entry.tag == link_tag() {
            entry.set_recipient_enc_pk(&PRK, enc_pk);
        }
    }
    fx.commitment_sig = sign_grant_set(&fx.owner, &fx.commitment)
        .expect("the owner signs the set as presented")
        .to_compact();
}

#[test]
fn a_cut_names_the_committed_recipient_though_its_row_was_relabelled() {
    // Any committed writer authors a ledger row. The cut names its revokees
    // from the owner-signed commitment, so relabelling a row neither lets its
    // author escape the cascade nor points the cascade at a bystander whose
    // grants would then be stripped vault-wide.
    let bystander = recipient_enc(0x99).public().to_bytes();
    for attest in [false, true] {
        let mut fx = Fixture::new();
        relabel_link_row(&mut fx, bystander, attest);

        let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("revoke");
        assert_eq!(
            cut.revoked_recipients,
            vec![recipient_enc(LINK_RECIPIENT).public().to_bytes()],
            "the commitment names the revokee, whatever the row was relabelled to"
        );
        assert!(
            !cut.commitment.entries.iter().any(|e| e.tag == link_tag()),
            "the tag still leaves the owner-signed set"
        );
    }
}

/// A cofactor twin and a non-canonical spelling both blind to the honest
/// key's tag, so nothing but core's adoption gate separates them from it.
/// The cut still lands and names nobody for that entry: no blob was ever
/// sealed to a key core will not adopt, and a refusal would leave the cut
/// that removes the bad entry the one operation the scope cannot run.
#[test]
fn a_cut_names_nobody_off_a_committed_key_core_will_not_adopt() {
    let honest = recipient_enc(LINK_RECIPIENT).public();
    let mut high_bit = honest.to_bytes();
    high_bit[31] |= 0x80;

    for enc_pk in cipherbox_core::suite::x25519::cofactor_twins(&honest)
        .into_iter()
        .chain([high_bit])
    {
        let mut fx = Fixture::new();
        relabel_link_entry(&mut fx, enc_pk);

        let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("the cut still lands");
        assert!(cut.revoked_recipients.is_empty());
        assert_eq!(
            cut.unnamed_drops, 1,
            "the caller must see the harvest was incomplete"
        );
        assert!(cut.commitment.entries.iter().all(|e| e.tag != link_tag()));
    }
}

/// A committed write grantee authors its own ledger row, so it can strip the
/// `ownerSig` off it before the owner reads the record for the cut. The
/// commitment entry it cannot touch, and that alone names the recipient.
#[test]
fn a_cut_names_the_committed_recipient_with_no_owner_signature_on_the_row() {
    let mut fx = Fixture::new();
    for row in &mut fx.ledger {
        if row.tag == write_tag() {
            row.owner_sig = NO_SIG;
        }
    }
    let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
        .expect("full write revoke");
    assert_eq!(
        cut.revoked_recipients,
        vec![recipient_enc(WRITE_RECIPIENT).public().to_bytes()],
        "the commitment names the recipient the stripped signature no longer does"
    );
}

#[test]
fn revoke_preserves_survivors_and_owner_fields() {
    let fx = Fixture::new();
    let cut = revoke_read_grant(&fx.plan(), &read_tag()).expect("revoke");
    assert!(cut.commitment.entries.iter().any(|e| e.tag == link_tag()));
    assert!(cut.commitment.entries.iter().any(|e| e.tag == write_tag()));
    assert_eq!(cut.commitment.ipns_name, fx.commitment.ipns_name);
    assert_eq!(
        cut.commitment.owner_pseudonym_pk,
        fx.commitment.owner_pseudonym_pk
    );
}

/// Every cut that re-signs steps the counter, and the one that re-uses the
/// set the owner already signed does not. A step the write-grant cut made
/// would raise the floor over a set no cut removed anybody from.
#[test]
fn every_re_signed_cut_steps_the_cut_epoch_and_the_re_used_set_does_not() {
    let fx = Fixture::new();
    let before = fx.commitment.cut_epoch;

    for cut in [
        revoke_read_grant(&fx.plan(), &read_tag()).expect("read revoke"),
        revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full).expect("write revoke"),
        revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
            .expect("downgrade"),
    ] {
        assert_eq!(cut.commitment.cut_epoch, before + 1);
        assert!(
            verify_grant_set(
                &fx.owner.verifying_key(),
                &cut.commitment,
                &EcdsaSignature::from_compact(&cut.commitment_sig).expect("compact"),
            )
            .is_ok(),
            "and the stepped counter is inside what the owner signed"
        );
    }

    let reused = cut_for_write_scope(&fx.plan()).expect("write-grant cut");
    assert_eq!(reused.commitment.cut_epoch, before);
}

/// A wrapped counter would sit below the floor the previous cut installed,
/// so every later replay of a pre-cut set would pass. Release-active, never
/// a debug_assert.
#[test]
fn a_cut_at_the_counter_ceiling_fails_closed() {
    let mut fx = Fixture::new();
    fx.commitment.cut_epoch = u64::MAX;
    fx.commitment_sig = sign_grant_set(&fx.owner, &fx.commitment)
        .expect("signs")
        .to_compact();

    let err = revoke_read_grant(&fx.plan(), &read_tag()).expect_err("the ceiling");
    assert_eq!(err.check(), "rot-revoke-cut-epoch-exhausted");
}

#[test]
fn revoke_unknown_tag_fails_closed() {
    let fx = Fixture::new();
    let err = revoke_read_grant(&fx.plan(), &[0xff; 32]).expect_err("not granted");
    assert_eq!(err.check(), "rot-revoke-not-granted");
}

/// A read revoke that drops a write grantee reads as complete — tag gone,
/// commitment re-signed — while the holder still authors at every current
/// write name. Only `revoke_write_grant` finishes that cut.
#[test]
fn read_revoking_a_write_grantee_fails_closed() {
    let fx = Fixture::new();
    let err = revoke_read_grant(&fx.plan(), &write_tag()).expect_err("write granted");
    assert_eq!(err.check(), "rot-revoke-write-granted");
}

#[test]
fn revoke_wrong_signer_fails_closed() {
    // A signer that did not sign the current commitment is rejected before the
    // cut — the encode-side mirror of the gate's owner-identity verify.
    let fx = Fixture::new();
    let stranger = stranger();
    let err = revoke_read_grant(&fx.plan_signed_by(&stranger), &link_tag())
        .expect_err("unauthorized signer");
    assert_eq!(err.check(), "rot-revoke-unauthorized-signer");
}

#[test]
fn revoke_tampered_commitment_preimage_fails_closed() {
    // A real owner signer presents a signature it genuinely produced, but over
    // a *different* commitment than the one being cut. verify_grant_set binds
    // the signature to THIS commitment's preimage, so the mismatch is rejected
    // as UnauthorizedSigner — a mutated commitment cannot ride a valid
    // signature over a sibling commitment. Complements the key-identity case
    // (`revoke_wrong_signer_fails_closed`) and the core-layer tamper KAT.
    let fx = Fixture::new();
    let mut tampered = fx.commitment.clone();
    tampered.owner_pseudonym_pk = [0x99; 32];
    let tampered_sig = sign_grant_set(&fx.owner, &tampered).unwrap().to_compact();
    assert_ne!(tampered_sig, fx.commitment_sig);

    let plan = GrantCutPlan {
        commitment_sig: &tampered_sig,
        ..fx.plan()
    };
    let err = revoke_read_grant(&plan, &link_tag()).expect_err("tampered commitment preimage");
    assert_eq!(err.check(), "rot-revoke-unauthorized-signer");
}

/// The owner gate alone would let one owner-signed commitment be cut against
/// any scope, so every cut carries the same scope binding `rotate_scope_write`
/// enforces (`WriteRotateError::CommitmentScopeMismatch`).
#[test]
fn a_cut_against_another_scope_fails_closed() {
    let fx = Fixture::new();
    let other = derive_write_name(&[0x5a; 32], &[0x02; 16]);
    assert_ne!(other.as_str(), fx.name.as_str());
    let plan = fx.plan_at(&other);

    for err in [
        revoke_read_grant(&plan, &link_tag()).expect_err("read revoke"),
        revoke_write_grant(&plan, &write_tag(), WriteRevokeKind::Full).expect_err("write revoke"),
    ] {
        assert_eq!(err.check(), "rot-revoke-commitment-scope-mismatch");
    }
}

/// A write-grantee authors the ledger, so it can present one that no longer
/// matches the owner's committed set. Signing a cut over it would mint a set
/// the resolver hard-rejects.
#[test]
fn a_cut_over_a_diverging_ledger_is_refused_release_active() {
    let fx = Fixture::new();
    let mut injected = fx.ledger.clone();
    injected.push(GrantLedgerEntry::new(
        [0x09; 33],
        [0x1f; 32],
        Permission::Write,
        [0x77; 32], // never committed by the owner
        NO_SIG,
    ));
    let plan = GrantCutPlan {
        grant_ledger: &injected,
        ..fx.plan()
    };
    let err = revoke_read_grant(&plan, &link_tag()).expect_err("diverging ledger");
    assert_eq!(err.check(), "ledger-diverges-from-commitment");
}

#[test]
fn a_full_write_revoke_removes_the_writer_and_rotates_both_planes() {
    let fx = Fixture::new();
    let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
        .expect("full write revoke");

    assert!(!cut.commitment.entries.iter().any(|e| e.tag == write_tag()));
    assert!(!cut.grant_ledger.iter().any(|e| e.tag == write_tag()));
    fx.verify(&cut);
    assert_eq!(
        cut.planes,
        RotationPlanes {
            read: true,
            write: true
        }
    );
}

#[test]
fn a_downgrade_demotes_the_writer_and_rotates_the_write_plane_only() {
    let fx = Fixture::new();
    let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
        .expect("downgrade");

    // The downgraded recipient keeps a live grant at the same tag — the read
    // plane is untouched, so its blob is still there to find.
    let entry = cut
        .commitment
        .entries
        .iter()
        .find(|e| e.tag == write_tag())
        .expect("the downgraded grant is still committed");
    assert_eq!(entry.permission, Permission::Read);
    let committed = fx
        .commitment
        .entries
        .iter()
        .find(|e| e.tag == write_tag())
        .expect("the write grant the fixture committed");
    assert_eq!(
        entry.pseudonym_pk, committed.pseudonym_pk,
        "the pseudonym authorizes structure signing and is the owner's to keep"
    );
    let row = cut
        .grant_ledger
        .iter()
        .find(|e| e.tag == write_tag())
        .expect("the downgraded ledger row survives");
    assert_eq!(row.permission, Permission::Read);
    assert_eq!(cut.commitment.entries.len(), fx.commitment.entries.len());
    fx.verify(&cut);

    assert_eq!(
        cut.planes,
        RotationPlanes {
            read: false,
            write: true
        }
    );
}

#[test]
fn a_write_revoke_of_a_read_grant_fails_closed() {
    // Rotating the write plane for a read-only tag would move every name in
    // the scope without cutting anything.
    let fx = Fixture::new();
    for (tag, check) in [
        (read_tag(), "rot-revoke-not-write-granted"),
        ([0xff; 32], "rot-revoke-not-granted"),
    ] {
        let err = revoke_write_grant(&fx.plan(), &tag, WriteRevokeKind::Full)
            .expect_err("no write grant");
        assert_eq!(err.check(), check);
    }
}

/// Records which arms fired, in call order, failing the ones named. Each
/// arm also records the permission the cut carries at [`write_tag()`], so a
/// test can prove the write wave ran over the demoted set rather than the
/// set the cut replaced.
struct FakeCutRotator {
    seen: RefCell<Vec<&'static str>>,
    committed_at_write_tag: RefCell<Vec<(&'static str, Permission)>>,
    refuse_read: bool,
    refuse_write: bool,
    refuse_publish: bool,
}

impl FakeCutRotator {
    fn new() -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            committed_at_write_tag: RefCell::new(Vec::new()),
            refuse_read: false,
            refuse_write: false,
            refuse_publish: false,
        }
    }

    fn record(&self, arm: &'static str, cut: &RevokedCommittedSet) {
        self.seen.borrow_mut().push(arm);
        if let Some(entry) = cut.commitment.entries.iter().find(|e| e.tag == write_tag()) {
            self.committed_at_write_tag
                .borrow_mut()
                .push((arm, entry.permission));
        }
    }
}

impl CutRotator for FakeCutRotator {
    async fn publish_cut_set(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<(), CascadeError> {
        self.record("publish-cut", cut);
        if self.refuse_publish {
            return Err(CascadeError::Resolve {
                scope_id: scope_root.0,
                reason: super::super::eager_set::ResolveFailure::Unavailable,
            });
        }
        Ok(())
    }

    async fn rotate_read_plane(
        &self,
        scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<CascadeOutcome, CascadeError> {
        self.record("read", cut);
        if self.refuse_read {
            return Err(CascadeError::Resolve {
                scope_id: scope_root.0,
                reason: super::super::eager_set::ResolveFailure::Unavailable,
            });
        }
        Ok(CascadeOutcome {
            rekeyed: vec![super::super::cascade::RekeyedScope {
                scope_id: scope_root.0,
                new_read_epoch: 2,
                epoch_floor: 2,
            }],
        })
    }

    async fn rotate_write_plane(
        &self,
        _scope_root: NodeId,
        cut: &RevokedCommittedSet,
    ) -> Result<WriteRotationOutcome, WriteRotateError> {
        self.record("write", cut);
        if self.refuse_write {
            return Err(WriteRotateError::EpochExhausted);
        }
        Ok(WriteRotationOutcome {
            new_write_epoch: 2,
            new_root_name: derive_write_name(&[0x77; 32], &[0x01; 16]),
            interior_node_count: 0,
        })
    }
}

fn full_write_revoke() -> RevokedCommittedSet {
    let fx = Fixture::new();
    revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full).expect("cut")
}

#[test]
fn a_full_write_revoke_drives_the_read_plane_before_the_write_plane() {
    let rotator = FakeCutRotator::new();
    let report =
        block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke())).expect("both planes");

    assert_eq!(
        *rotator.seen.borrow(),
        ["read", "write"],
        "the read cut lands at the name survivors still read, then the names move"
    );
    assert!(report.read.is_some());
    assert!(report.write.is_some());
}

#[test]
fn a_write_only_cut_that_withholds_a_read_grant_is_refused_before_anything_publishes() {
    // Only the read cascade records a withheld recipient in the durable
    // revocation floor. A write-only cut carrying one would withhold a blob
    // the engine forgets it withheld, and the next re-key would hand it
    // back. Both cuts that reach here build an empty list, so this pins the
    // property rather than a coincidence.
    let fx = Fixture::new();
    let mut cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
        .expect("downgrade");
    cut.revoked_recipients.push([0x5e; SECRET_LEN]);
    let rotator = FakeCutRotator::new();

    let err = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect_err("refused");
    assert_eq!(err.check(), "rot-cut-write-only-cut-withdraws-read");
    assert!(!err.is_retryable());
    assert!(
        rotator.seen.borrow().is_empty(),
        "nothing is cut on either plane"
    );
}

#[test]
fn a_downgrade_leaves_the_read_plane_alone() {
    let fx = Fixture::new();
    let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
        .expect("downgrade");
    let rotator = FakeCutRotator::new();
    let report = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("write plane");

    assert_eq!(*rotator.seen.borrow(), ["publish-cut", "write"]);
    assert!(report.read.is_none());
    assert!(report.write.is_some());
}

/// The write wave re-mints only from a root already carrying the authorized
/// set, so a write-only cut owes the publish before the wave — otherwise the
/// wave reads the pre-cut record and refuses permanently.
#[test]
fn a_downgrade_publishes_the_demoted_set_before_the_wave_runs() {
    let fx = Fixture::new();
    let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
        .expect("downgrade");
    let rotator = FakeCutRotator::new();
    block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("write plane");

    assert_eq!(
        *rotator.committed_at_write_tag.borrow(),
        [
            ("publish-cut", Permission::Read),
            ("write", Permission::Read)
        ],
        "the demoted row reaches the record before the wave re-mints from it"
    );
}

#[test]
fn a_refused_cut_set_publish_never_reaches_the_write_plane() {
    let fx = Fixture::new();
    let cut = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::DowngradeToRead)
        .expect("downgrade");
    let mut rotator = FakeCutRotator::new();
    rotator.refuse_publish = true;
    let err = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect_err("publish refused");

    assert!(matches!(err, RotateOnCutError::PublishCut(_)));
    assert_eq!(*rotator.seen.borrow(), ["publish-cut"]);
    assert!(err.is_retryable());
}

/// A cut that rotates both planes has its set published by the read cascade,
/// so the pre-wave publish is not owed and never runs.
#[test]
fn a_two_plane_cut_owes_no_pre_wave_publish() {
    let rotator = FakeCutRotator::new();
    block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke())).expect("both planes");

    assert_eq!(*rotator.seen.borrow(), ["read", "write"]);
}

/// The grant-time write-scope cut drives the same write-only arm: the mint
/// published the set, so the publish arm still runs and finds it in place.
#[test]
fn a_write_grant_cut_carries_the_minted_set_through_the_write_plane() {
    let fx = Fixture::new();
    let cut = cut_for_write_scope(&fx.plan()).expect("the owner's own minted set");

    assert!(!cut.planes().read(), "a grant re-keys no read plane");
    assert!(cut.planes().write());
    assert!(
        cut.revoked_recipients.is_empty(),
        "a grant cuts no recipient"
    );
    assert_eq!(cut.commitment, *fx.plan().commitment);

    let rotator = FakeCutRotator::new();
    block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("the write plane");
    assert_eq!(*rotator.seen.borrow(), ["publish-cut", "write"]);
}

#[test]
fn a_write_grant_cut_refuses_a_set_the_owner_did_not_sign() {
    let fx = Fixture::new();
    let err = cut_for_write_scope(&fx.plan_signed_by(&stranger()))
        .expect_err("a set this signer never authorized");
    assert_eq!(err.check(), "rot-revoke-unauthorized-signer");
}

/// A write conversion cuts a scope whose set commits no write row yet: the
/// claimant's write row is appended at the moved name after the wave.
#[test]
fn a_write_conversion_cut_drives_a_read_only_set_through_the_write_plane() {
    let fx = Fixture::new();
    let read_only = revoke_write_grant(&fx.plan(), &write_tag(), WriteRevokeKind::Full)
        .expect("the write row leaves the set");
    let sig = read_only.commitment_sig;
    let plan = GrantCutPlan {
        commitment: &read_only.commitment,
        commitment_sig: &sig,
        grant_ledger: &read_only.grant_ledger,
        ..fx.plan()
    };
    let cut = cut_for_write_scope(&plan).expect("a read-only set cuts");
    assert!(!cut.planes().read());
    assert!(cut.planes().write());
    assert_eq!(cut.commitment, read_only.commitment);

    let rotator = FakeCutRotator::new();
    block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("the write plane");
    assert_eq!(*rotator.seen.borrow(), ["publish-cut", "write"]);

    let err = cut_for_write_scope(&fx.plan_signed_by(&stranger()))
        .expect_err("a set this signer never authorized");
    assert_eq!(err.check(), "rot-revoke-unauthorized-signer");
}

#[test]
fn a_read_revoke_leaves_the_write_plane_alone() {
    let fx = Fixture::new();
    let cut = revoke_read_grant(&fx.plan(), &link_tag()).expect("cut");
    let rotator = FakeCutRotator::new();
    let report = block_on(rotate_on_cut(&rotator, node(1), &cut)).expect("read plane");

    assert_eq!(*rotator.seen.borrow(), ["read"]);
    assert!(report.write.is_none());
}

#[test]
fn a_refused_read_plane_never_reaches_the_write_plane() {
    // A partial report would be mistakable for a finished revoke.
    let mut rotator = FakeCutRotator::new();
    rotator.refuse_read = true;
    let err = block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke()))
        .expect_err("read plane refused");

    assert!(matches!(err, RotateOnCutError::Read(_)));
    assert_eq!(*rotator.seen.borrow(), ["read"]);
    assert!(err.is_retryable());
}

#[test]
fn a_refused_write_plane_fails_the_whole_revoke() {
    let mut rotator = FakeCutRotator::new();
    rotator.refuse_write = true;
    let err = block_on(rotate_on_cut(&rotator, node(1), &full_write_revoke()))
        .expect_err("write plane refused");

    assert_eq!(err.check(), "rot-write-epoch-exhausted");
    assert!(!err.is_retryable());
}

#[test]
fn trigger_names_are_stable() {
    assert_eq!(RotationTrigger::ScopeExit.name(), "scope-exit");
    assert_eq!(RotationTrigger::ReadRevoke.name(), "read-revoke");
    assert_eq!(RotationTrigger::WriteRevoke.name(), "write-revoke");
    assert_eq!(
        RotationTrigger::DiscoveredExpiry.name(),
        "discovered-expiry"
    );
    assert_eq!(RotationTrigger::Manual.name(), "manual");
}

/// A new variant that inherits another variant's check name, or is appended out
/// of order, fails here rather than reaching a reject vector unnamed.
/// `LedgerDiverges` surfaces the grant plane's verdict and stays off the
/// surface, so the walk names it and skips it.
#[test]
fn the_revoke_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [
        RevokeError::UnauthorizedSigner,
        RevokeError::CommitmentScopeMismatch,
        RevokeError::NotGranted,
        RevokeError::NotWriteGranted,
        RevokeError::WriteGranted,
        RevokeError::CutEpochExhausted,
        RevokeError::Sign(cipherbox_core::error::TrustViolation::DuplicateGrantTag.into()),
    ]
    .iter()
    .map(RevokeError::check)
    .collect();
    assert_eq!(named, RevokeError::CHECKS);
}

/// The three per-plane variants delegate, so the cut driver owns exactly one
/// check of its own.
#[test]
fn the_cut_check_surface_matches_the_variants_in_order() {
    let named: Vec<&str> = [RotateOnCutError::WriteOnlyCutWithdrawsRead]
        .iter()
        .map(RotateOnCutError::check)
        .collect();
    assert_eq!(named, RotateOnCutError::CHECKS);

    assert_eq!(
        RotateOnCutError::Write(WriteRotateError::NotOwner).check(),
        WriteRotateError::NotOwner.check(),
    );
}

/// ADR 0025 D4: every row one revoke removes leaves in one cut set, with one
/// cut-epoch step and one re-sign.
#[test]
fn one_revoke_cuts_every_named_row_in_one_step() {
    let fx = Fixture::new();
    let cut = revoke_grants(&fx.plan(), &BTreeSet::from([read_tag(), link_tag()]))
        .expect("the cut lands");

    assert_eq!(
        cut.commitment
            .entries
            .iter()
            .map(|e| e.tag)
            .collect::<Vec<_>>(),
        vec![write_tag()]
    );
    assert_eq!(cut.grant_ledger.len(), 1);
    assert_eq!(cut.commitment.cut_epoch, fx.commitment.cut_epoch + 1);
    assert_eq!(cut.revoked_recipients.len(), 2);
    assert!(cut.planes().read() && !cut.planes().write());
    fx.verify(&cut);
}

/// A write row in the cut set ends only with the name wave, so the write plane
/// joins the read plane.
#[test]
fn a_cut_set_holding_a_write_row_rotates_both_planes() {
    let fx = Fixture::new();
    let cut = revoke_grants(&fx.plan(), &BTreeSet::from([link_tag(), write_tag()]))
        .expect("the cut lands");
    assert!(cut.planes().read() && cut.planes().write());
}

#[test]
fn a_cut_set_naming_an_uncommitted_tag_or_nothing_is_refused() {
    let fx = Fixture::new();
    assert_eq!(
        revoke_grants(&fx.plan(), &BTreeSet::from([read_tag(), [0xee; 32]])),
        Err(RevokeError::NotGranted)
    );
    assert_eq!(
        revoke_grants(&fx.plan(), &BTreeSet::new()),
        Err(RevokeError::NotGranted)
    );
    assert_eq!(
        revoke_grants(
            &fx.plan_signed_by(&stranger()),
            &BTreeSet::from([read_tag()])
        ),
        Err(RevokeError::UnauthorizedSigner)
    );
}
