use super::*;
use crate::entropy::EntropyError;
use crate::seams::SeamResult;
use crate::testkit::fakes::{InMemoryFloorStore, VirtualScheduler};
use crate::testkit::{CARRIED_WRITE_HISTORY_LINK, SeededEntropy, SilentEntropy, block_on};
use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, Permission, PreservedFields,
    sign_grant_set, sign_recipient_binding,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use std::cell::RefCell;
use std::rc::Rc;

const SCOPE: [u8; 16] = [0x5c; 16];

/// The caller-side bound needs one classifier it can trust: an availability
/// stall — including one at the entropy seam — and the C2 label conflict the
/// re-point wave repairs are re-drivable; a refused publish, a re-seal this
/// build will not sign and an exhausted epoch are verdicts no retry reaches
/// differently.
#[test]
fn only_availability_and_the_repairable_label_conflict_are_retryable() {
    for retryable in [
        RotateError::Resolve(ResolveFailure::Unavailable),
        RotateError::Resolve(ResolveFailure::ConflictingChildLabel),
        RotateError::Reseal(ResealError::Entropy(EntropyError::new("no entropy"))),
        RotateError::Publish(RotationPublishError::NotPublished),
        RotateError::Publish(RotationPublishError::LostRace),
        RotateError::Floor(SeamError::new("floor store unavailable")),
    ] {
        assert!(
            retryable.is_retryable(),
            "{} must be re-drivable",
            retryable.check()
        );
    }
    for terminal in [
        RotateError::Resolve(ResolveFailure::Rejected),
        RotateError::Reseal(ResealError::SignerNotCommitted),
        RotateError::Publish(RotationPublishError::Rejected),
        RotateError::EpochExhausted,
    ] {
        assert!(
            !terminal.is_retryable(),
            "{} is a verdict, not an outage",
            terminal.check()
        );
    }
}

/// A publisher that records what it was handed and returns a scripted result;
/// it snapshots the floor at publish time so a test can prove publish-before-
/// floor ordering.
struct FakePublisher {
    result: Result<(), RotationPublishError>,
    seen: Rc<RefCell<Vec<ResealedScopeRoot>>>,
    floor_at_publish: Rc<RefCell<Option<Option<u64>>>>,
    floors: InMemoryFloorStore,
}

impl ScopeRootPublisher for FakePublisher {
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        // Snapshot the durable floor BEFORE the rotation raises it.
        let floor = self.floors.epoch_floor(&SCOPE).await.unwrap();
        *self.floor_at_publish.borrow_mut() = Some(floor);
        self.seen.borrow_mut().push(record.clone());
        self.result.clone()
    }
}

/// A floor store whose epoch-floor raise always fails — drives the documented
/// crash window (publish landed, floor raise failed). The other methods stay
/// benign so it can also back the publisher's snapshot if needed.
struct FailingFloorStore;

impl FloorStore for FailingFloorStore {
    async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }
    async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
        Err(SeamError::new("floor raise failed"))
    }
    async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }
    async fn raise_sequence_floor(&self, _ipns_name: &[u8], _sequence: u64) -> SeamResult<u64> {
        Err(SeamError::new("floor raise failed"))
    }
    async fn clear(&self) -> SeamResult<()> {
        Ok(())
    }
}

struct Fixture {
    owner_enc: X25519Secret,
    pseudonym: Ed25519Signer,
    owner_ecdsa: EcdsaSigner,
    write_scope_seed: [u8; 32],
    pointer_read_key: [u8; 32],
    grantee: X25519Secret,
}

impl Fixture {
    fn new() -> Self {
        let owner_ecdsa = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
        Self {
            owner_enc: X25519Secret::from_scalar([0x11; 32]),
            pseudonym: Ed25519Signer::from_seed([0x22; 32]),
            owner_ecdsa,
            write_scope_seed: [0x55; 32],
            pointer_read_key: [0x66; 32],
            grantee: X25519Secret::from_scalar([0x77; 32]),
        }
    }

    fn committed(&self) -> (GrantSetCommitment, [u8; 64], Vec<GrantLedgerEntry>) {
        let commitment = GrantSetCommitment {
            ipns_name: b"scope-root".to_vec(),
            owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
            cut_epoch: 0,
            entries: vec![GrantSetEntry::new(
                &[0x66; 32],
                [0xa1; 32],
                self.grantee.public().to_bytes(),
                Permission::Read,
                [0x02; 32],
            )],
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
            .unwrap()
            .to_compact();
        let mut row = GrantLedgerEntry::new(
            [0x02; 33],
            self.grantee.public().to_bytes(),
            Permission::Read,
            [0xa1; 32],
            [0u8; 64],
        );
        row.owner_sig = sign_recipient_binding(&self.owner_ecdsa, b"scope-root", &row).to_compact();
        let ledger = vec![row];
        (commitment, sig, ledger)
    }
}

/// Drive a rotation with a scripted publisher result; returns the outcome, the
/// records the publisher saw, the floor it snapshotted at publish time, the
/// spawned-task count, and the final durable floor.
#[allow(clippy::type_complexity)]
fn run_rotation<E: Entropy>(
    mut entropy: E,
    publish_result: Result<(), RotationPublishError>,
) -> (
    Result<RotationOutcome, RotateError>,
    Vec<ResealedScopeRoot>,
    Option<Option<u64>>,
    usize,
    Option<u64>,
) {
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed();
    let floors = InMemoryFloorStore::default();
    let scheduler = VirtualScheduler::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let floor_at_publish = Rc::new(RefCell::new(None));
    let publisher = FakePublisher {
        result: publish_result,
        seen: Rc::clone(&seen),
        floor_at_publish: Rc::clone(&floor_at_publish),
        floors: floors.clone(),
    };
    let current_seed = [0xaa; 32];

    let outcome = block_on(async {
        let plan = RotateScopePlan {
            identity: ScopeRootIdentity {
                v: 2,
                scope_id: SCOPE,
                ipns_name: b"scope-root",
                owner_enc_pub: &owner_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &fx.pseudonym,
            },
            committed: CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                direct_child_scope_index: &[],
                revoked_recipients: &[],
            },
            current_override_seed: &current_seed,
            current_read_epoch: 4,
            write_scope_seed: &fx.write_scope_seed,
            write_epoch: 3,
            write_history_link: CARRIED_WRITE_HISTORY_LINK,
            pointer_read_key: &fx.pointer_read_key,
            carried_history_links: &[],
        };
        rotate_scope(&mut entropy, &floors, &scheduler, &publisher, &plan, || {
            Box::pin(async {})
        })
        .await
    });

    let final_floor = block_on(floors.epoch_floor(&SCOPE)).unwrap();
    let spawned = scheduler.take_spawned_tasks().len();
    let seen = seen.borrow().clone();
    let floor_snap = *floor_at_publish.borrow();
    (outcome, seen, floor_snap, spawned, final_floor)
}

#[test]
fn a_silent_entropy_seam_cuts_no_epoch_and_publishes_nothing() {
    // Release-active, before the re-seal: the epoch's fresh history link
    // would hand out the seed this cut is revoking.
    let (outcome, seen, _, spawned, floor) = run_rotation(SilentEntropy, Ok(()));

    assert!(matches!(
        outcome.expect_err("the zero draw is refused"),
        RotateError::Reseal(ResealError::Entropy(_)),
    ));
    assert!(seen.is_empty(), "nothing is published under a zero seed");
    assert_eq!(spawned, 0, "and no lazy wave is enqueued behind it");
    assert_eq!(floor, None, "the revocation floor never moved");
}

#[test]
fn happy_path_publishes_then_bumps_floor_then_enqueues_sweep() {
    let (outcome, seen, floor_at_publish, spawned, final_floor) =
        run_rotation(SeededEntropy::new(9), Ok(()));
    let outcome = outcome.expect("rotation succeeds");
    assert_eq!(outcome.new_read_epoch, 5, "read epoch bumped 4 -> 5");
    assert_eq!(
        outcome.epoch_floor, 5,
        "minReadEpoch raised to the new epoch"
    );

    // One record published, at the new read epoch, write epoch unchanged.
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].read_epoch, 5);
    assert_eq!(seen[0].write_epoch, 3, "read rotation leaves writeEpoch");
    assert_eq!(seen[0].scope_id, SCOPE);

    // Ordering: at publish time the floor was still unset (publish precedes
    // the raise); afterwards it is durably 5.
    assert_eq!(
        floor_at_publish,
        Some(None),
        "floor not raised before publish"
    );
    assert_eq!(final_floor, Some(5));

    // Sweep enqueued exactly once, after the cut is durable.
    assert_eq!(spawned, 1, "one sweep task enqueued");
}

#[test]
fn publish_failure_does_not_bump_floor_or_enqueue_sweep() {
    // The lockout guard: a failed publish leaves the floor untouched (old
    // records still gate-pass) and enqueues no sweep.
    let (outcome, seen, _floor_at_publish, spawned, final_floor) = run_rotation(
        SeededEntropy::new(9),
        Err(RotationPublishError::NotPublished),
    );
    assert_eq!(outcome.unwrap_err().check(), "publish-failed");
    assert_eq!(seen.len(), 1, "publish was attempted");
    assert_eq!(final_floor, None, "floor NOT raised on a failed publish");
    assert_eq!(spawned, 0, "no sweep enqueued on failure");
}

#[test]
fn lost_cas_race_does_not_bump_floor() {
    let (outcome, _seen, _snap, spawned, final_floor) =
        run_rotation(SeededEntropy::new(9), Err(RotationPublishError::LostRace));
    assert_eq!(outcome.unwrap_err().check(), "publish-failed");
    assert_eq!(final_floor, None, "a lost race advances no floor");
    assert_eq!(spawned, 0);
}

#[test]
fn mints_a_fresh_override_seed_distinct_from_the_current() {
    // The published owner blob decrypts to a NEW seed, not the current one.
    use cipherbox_core::seal::{STRUCT_TAG_OWNER_BLOB, open_owner_blob};
    use cipherbox_core::suite::secret::ct_eq;

    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed();
    let floors = InMemoryFloorStore::default();
    let scheduler = VirtualScheduler::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let publisher = FakePublisher {
        result: Ok(()),
        seen: Rc::clone(&seen),
        floor_at_publish: Rc::new(RefCell::new(None)),
        floors: floors.clone(),
    };
    let current_seed = [0xaa; 32];

    block_on(async {
        let mut entropy = SeededEntropy::new(1);
        let plan = RotateScopePlan {
            identity: ScopeRootIdentity {
                v: 2,
                scope_id: SCOPE,
                ipns_name: b"scope-root",
                owner_enc_pub: &owner_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &fx.pseudonym,
            },
            committed: CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                direct_child_scope_index: &[],
                revoked_recipients: &[],
            },
            current_override_seed: &current_seed,
            current_read_epoch: 1,
            write_scope_seed: &fx.write_scope_seed,
            write_epoch: 1,
            write_history_link: b"",
            pointer_read_key: &fx.pointer_read_key,
            carried_history_links: &[],
        };
        rotate_scope(&mut entropy, &floors, &scheduler, &publisher, &plan, || {
            Box::pin(async {})
        })
        .await
        .unwrap();
    });

    let record = &seen.borrow()[0];
    let ob = &record.section.owner_blob;
    let ctx = cipherbox_core::seal::AadContext {
        v: 2,
        id: SCOPE,
        scope: SCOPE,
        epoch: 2,
        struct_tag: STRUCT_TAG_OWNER_BLOB,
    };
    let payload = open_owner_blob(&fx.owner_enc, &ob.enc, &ctx, &ob.ciphertext).unwrap();
    assert!(
        !ct_eq(payload.override_seed(), &current_seed),
        "rotation minted a fresh seed, not the current one"
    );
}

#[test]
fn floor_raise_failure_after_publish_returns_floor_error_and_skips_sweep() {
    // The documented crash window: publish lands, the floor raise fails. The
    // record WAS published (old records still gate-pass — no lockout), the error
    // is RotateError::Floor, and the sweep is NOT enqueued (spawn count == 0).
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed();
    let floors = FailingFloorStore;
    let scheduler = VirtualScheduler::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let publisher = FakePublisher {
        result: Ok(()),
        seen: Rc::clone(&seen),
        floor_at_publish: Rc::new(RefCell::new(None)),
        floors: InMemoryFloorStore::default(),
    };
    let current_seed = [0xaa; 32];

    let outcome = block_on(async {
        let mut entropy = SeededEntropy::new(9);
        let plan = RotateScopePlan {
            identity: ScopeRootIdentity {
                v: 2,
                scope_id: SCOPE,
                ipns_name: b"scope-root",
                owner_enc_pub: &owner_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &fx.pseudonym,
            },
            committed: CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                direct_child_scope_index: &[],
                revoked_recipients: &[],
            },
            current_override_seed: &current_seed,
            current_read_epoch: 4,
            write_scope_seed: &fx.write_scope_seed,
            write_epoch: 3,
            write_history_link: CARRIED_WRITE_HISTORY_LINK,
            pointer_read_key: &fx.pointer_read_key,
            carried_history_links: &[],
        };
        rotate_scope(&mut entropy, &floors, &scheduler, &publisher, &plan, || {
            Box::pin(async {})
        })
        .await
    });

    assert_eq!(outcome.unwrap_err().check(), "floor-raise-failed");
    assert_eq!(
        seen.borrow().len(),
        1,
        "record WAS published before the floor raise"
    );
    assert_eq!(
        scheduler.take_spawned_tasks().len(),
        0,
        "no sweep enqueued when the floor raise fails after publish"
    );
}

#[test]
fn exhausted_epoch_fails_closed_without_publishing() {
    // current_read_epoch == u64::MAX: a bump would reuse the epoch with fresh
    // key material, so the rotation fails closed before minting or publishing.
    let fx = Fixture::new();
    let owner_pub = fx.owner_enc.public();
    let (commitment, sig, ledger) = fx.committed();
    let floors = InMemoryFloorStore::default();
    let scheduler = VirtualScheduler::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let publisher = FakePublisher {
        result: Ok(()),
        seen: Rc::clone(&seen),
        floor_at_publish: Rc::new(RefCell::new(None)),
        floors: floors.clone(),
    };
    let current_seed = [0xaa; 32];

    let outcome = block_on(async {
        let mut entropy = SeededEntropy::new(9);
        let plan = RotateScopePlan {
            identity: ScopeRootIdentity {
                v: 2,
                scope_id: SCOPE,
                ipns_name: b"scope-root",
                owner_enc_pub: &owner_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &fx.pseudonym,
            },
            committed: CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                direct_child_scope_index: &[],
                revoked_recipients: &[],
            },
            current_override_seed: &current_seed,
            current_read_epoch: u64::MAX,
            write_scope_seed: &fx.write_scope_seed,
            write_epoch: 3,
            write_history_link: CARRIED_WRITE_HISTORY_LINK,
            pointer_read_key: &fx.pointer_read_key,
            carried_history_links: &[],
        };
        rotate_scope(&mut entropy, &floors, &scheduler, &publisher, &plan, || {
            Box::pin(async {})
        })
        .await
    });

    assert_eq!(outcome.unwrap_err().check(), "epoch-exhausted");
    assert_eq!(
        seen.borrow().len(),
        0,
        "nothing published on an exhausted epoch"
    );
    assert_eq!(
        block_on(floors.epoch_floor(&SCOPE)).unwrap(),
        None,
        "no floor raised"
    );
    assert_eq!(scheduler.take_spawned_tasks().len(), 0, "no sweep enqueued");
}
