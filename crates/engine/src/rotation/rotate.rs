//! `rotateScope` — the read-plane root cut (blueprint/engine.md "Rotation
//! primitives: rotateScope", #26 D2/D8, #38 D4/D5).
//!
//! The read-plane rotation: mint a fresh random override seed at the scope root
//! (via the injected entropy seam — never a direct RNG), re-seal the scope root's
//! [`GrantSection`](cipherbox_core::seal::GrantSection) at the next read epoch
//! through the shared [`reseal_scope_root`] helper, publish it CAS through the
//! injected [`ScopeRootPublisher`] seam, raise the durable `minReadEpoch` floor,
//! and enqueue the lazy-wave sweep. **Read-plane only**: `minReadEpoch` moves,
//! `writeEpoch` does not — the write-plane name wave (`rotateScopeWrite`) is a
//! separate primitive.
//!
//! # Effect ordering is crash-safety
//!
//! The three durable effects run in a fixed order — **publish → raise floor →
//! enqueue sweep** — each returning before the next on failure, so no
//! partially-rotated, fail-open, or locked-out state is left behind:
//!
//! - Publishing the new-epoch record **before** raising the floor means a crash
//!   between them leaves the old-epoch records still gate-passing (the floor has
//!   not moved) rather than demanding an epoch no published record satisfies — a
//!   lockout. The rotation simply re-runs; it is monotonic (a fresh seed, a
//!   higher epoch) and idempotent-safe under CAS. Raising the floor first would
//!   invert this into that lockout.
//! - The residual window this accepts — a revoked reader whose old-epoch
//!   forgeries still pass until the floor rises on the completing run — is the
//!   documented read-only-survivor residual (#38, "~one pointer-consult
//!   interval"), never a lost revocation boundary.
//! - The sweep is enqueued **last**, only after the cut is durable; it is
//!   best-effort and idempotent, so losing it to a crash costs only a delayed
//!   lazy wave the next ordinary write or scheduled sweep advances.
//!
//! This primitive is the root cut alone; the descendant re-key runs through the
//! same [`reseal_scope_root`] helper in [`cascade`](super::cascade).

use cipherbox_core::seal::{GrantSection, SignedSealed};
use cipherbox_core::suite::secret::SECRET_LEN;

use super::eager_set::ResolveFailure;
use super::reseal::{
    CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity, WriteHistory,
    reseal_scope_root,
};
use crate::entropy::{Entropy, fresh_seed};
use crate::seams::{BoxedTask, FloorStore, Scheduler, SeamError};

/// A fully re-sealed scope-root record handed to the [`ScopeRootPublisher`]: its
/// identity, the epochs it publishes at, and the signed grant section. Assembling
/// the envelope bytes (read-body re-seal + IPNS record signing) and moving them
/// CAS over the content plane + `/routing/v1` transport is the publisher's job.
/// It carries no seed: the publisher recovers the freshly minted override seed
/// from `section`'s own owner blob, so this type is not a key-material carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResealedScopeRoot {
    /// The scope-root node id (== scope id).
    pub scope_id: [u8; 16],
    /// The scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// The read epoch this cut publishes at (bumped).
    pub read_epoch: u64,
    /// The write epoch (unchanged by a read rotation).
    pub write_epoch: u64,
    /// The freshly re-sealed, structure-signed grant section.
    pub section: GrantSection,
}

/// Why a **rotation's** publish did not durably land as the freshest record at
/// its name. Every variant means the rotation must not advance its floor —
/// nothing was cut.
///
/// The rotation primitives publish two kinds of record — a re-sealed scope root
/// and, on the sweep and grant-creation paths, a re-sealed interior node — and
/// this is the verdict on either. It is the *caller's* classification of an
/// attempt, on rule 6's retryable-vs-trust axis;
/// [`RecordPublishError`](crate::net::record_publish::RecordPublishError) is the
/// publish *pipeline's* own report of what went wrong on the wire, which the
/// rotation seams fold into this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationPublishError {
    /// Register-first or the record PUT failed; nothing durable landed. Retryable.
    NotPublished,
    /// A concurrent writer's record at a higher sequence won the CAS race; the
    /// caller re-resolves and rebases before retrying.
    LostRace,
    /// The record the publish had to read first failed the adoption gate — a
    /// fail-closed trust violation, never staleness (AGENTS.md rule 6). Kept
    /// distinct from [`Self::NotPublished`] so a forged or transplanted record
    /// is never retried as if it were a flaky endpoint.
    Rejected,
}

impl RotationPublishError {
    /// Whether re-running the publish could clear this: an availability stall or
    /// a lost race, but never a trust rejection.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::NotPublished | Self::LostRace)
    }
}

impl core::fmt::Display for RotationPublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RotationPublishError::NotPublished => f.write_str("rotation record not published"),
            RotationPublishError::LostRace => f.write_str("rotation publish lost the CAS race"),
            RotationPublishError::Rejected => {
                f.write_str("rotation record rejected by adoption gate")
            }
        }
    }
}

impl std::error::Error for RotationPublishError {}

/// The publish effect of a rotation: CAS-publish a re-sealed scope-root record.
///
/// The one impure edge of `rotate_scope` besides the seams, mirroring the
/// eager-set walk's `ChildIndexResolver`: the traversal/composition is pure and
/// deterministic, and only this edge touches the content plane and the
/// `/routing/v1` transport. The production implementation
/// ([`crate::net::rotation::OwnerRotationNet`]) wraps the content-plane block
/// store, register-first, and [`net::publish`](crate::net::publish) CAS; tests
/// fake it.
pub trait ScopeRootPublisher {
    /// Register-first CAS-publish `record` at its scope root's `ipnsName`. `Ok`
    /// means the record is durably the freshest at the name; `Err` means nothing
    /// was cut (the caller must not advance the floor).
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError>;
}

/// The inputs to one scope root's read-plane rotation: its identity, its current
/// committed set, its current read-plane state (seed + epoch, which become the
/// history link's prior), the unchanged write-plane material, and its carried
/// history links.
pub struct RotateScopePlan<'a> {
    /// The scope root's stable identity and the rotator's pseudonym signer.
    pub identity: ScopeRootIdentity<'a>,
    /// The owner-committed grant set to re-wrap for (unchanged for a grantee/
    /// manual rotation; already-pruned by `revoke_read_grant` for a read revoke).
    pub committed: CommittedSet<'a>,
    /// The scope's current override (read scope) seed — becomes the new record's
    /// history-link prior. Caller-owned; never zeroized here.
    pub current_override_seed: &'a [u8; SECRET_LEN],
    /// The scope's current read epoch — the new record publishes at `+ 1`.
    pub current_read_epoch: u64,
    /// The write-plane scope seed (unchanged by a read rotation).
    pub write_scope_seed: &'a [u8; SECRET_LEN],
    /// The write epoch (unchanged by a read rotation).
    pub write_epoch: u64,
    /// The root's existing write-plane history link. A read rotation cuts no
    /// write plane, so it is carried verbatim ([`WriteHistory::Carried`]).
    pub write_history_link: &'a [u8],
    /// The stable per-scope pointer read key carried in every grant blob.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
    /// The scope's existing per-epoch history links, oldest first. Re-signed and
    /// pruned to the retained window by the re-seal — see
    /// [`reseal_scope_root`](super::reseal::reseal_scope_root).
    pub carried_history_links: &'a [SignedSealed],
}

/// A fail-closed rotation failure. On every variant nothing durable was left
/// half-done: the floor is advanced only after a confirmed publish, and the sweep
/// only after a confirmed floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateError {
    /// The scope root the rotation had to resolve yielded no plan: its record
    /// failed the adoption gate, or the rotator holds no seed source in it.
    /// Fail-closed on the resolve's own axis, so a trust verdict is never
    /// retried as an availability stall (AGENTS.md rule 6).
    Resolve(ResolveFailure),
    /// Re-sealing the scope root failed (divergent ledger, unusable recipient
    /// key, or entropy failure) — nothing was published.
    Reseal(ResealError),
    /// The scope-root record did not land — nothing was cut, retry later.
    Publish(RotationPublishError),
    /// The durable epoch floor could not be raised after a confirmed publish. The
    /// record is published (no lockout); the cut completes on retry.
    Floor(SeamError),
    /// The read epoch is exhausted (`current_read_epoch == u64::MAX`). Rotating
    /// would reuse the epoch with fresh key material, violating key-regression
    /// monotonicity, so nothing is minted or published. Unreachable in practice.
    EpochExhausted,
}

impl core::fmt::Display for RotateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RotateError::Resolve(e) => write!(f, "scope-root resolve failed: {e}"),
            RotateError::Reseal(e) => write!(f, "re-seal failed: {e}"),
            RotateError::Publish(e) => write!(f, "publish failed: {e}"),
            RotateError::Floor(e) => write!(f, "epoch-floor raise failed: {e}"),
            RotateError::EpochExhausted => f.write_str("read epoch exhausted (u64::MAX)"),
        }
    }
}

impl std::error::Error for RotateError {}

impl RotateError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RotateError::Resolve(_) => "resolve-failed",
            RotateError::Reseal(_) => "reseal-failed",
            RotateError::Publish(_) => "publish-failed",
            RotateError::Floor(_) => "floor-raise-failed",
            RotateError::EpochExhausted => "epoch-exhausted",
        }
    }

    /// Whether re-running the rotation could clear this failure — an
    /// availability stall, or a C2 label conflict the re-point wave repairs —
    /// versus a trust violation no retry can fix. Mirrors
    /// [`CascadeError::is_retryable`](super::cascade::CascadeError::is_retryable);
    /// a caller MUST still bound its retries, because a permanent label
    /// disagreement is retryable and never self-heals.
    pub fn is_retryable(&self) -> bool {
        match self {
            RotateError::Resolve(reason) => matches!(
                reason,
                ResolveFailure::Unavailable | ResolveFailure::ConflictingChildLabel
            ),
            RotateError::Reseal(error) => matches!(error, ResealError::Entropy(_)),
            RotateError::Publish(error) => error.is_retryable(),
            RotateError::Floor(_) => true,
            RotateError::EpochExhausted => false,
        }
    }
}

/// The result of a completed read-plane root cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationOutcome {
    /// The new read epoch the scope was cut to (`current_read_epoch + 1`).
    pub new_read_epoch: u64,
    /// The durable `minReadEpoch` floor after the raise (`>= new_read_epoch`).
    pub epoch_floor: u64,
}

/// Perform the read-plane root cut for the scope root in `plan`.
///
/// Mints a fresh random override seed via `entropy` (determinism law: never a
/// direct RNG), re-seals through [`reseal_scope_root`], publishes CAS via
/// `publisher`, raises `minReadEpoch` via `floors`, and enqueues the sweep task
/// (`make_sweep_task`) on `scheduler` — in that fixed, crash-safe order (module
/// docs). Read-plane only: the write epoch is unchanged.
///
/// `make_sweep_task` is invoked only on the success path, after the floor is
/// durably raised, and its future is the Slice-3 lazy-wave sweep entry.
pub async fn rotate_scope<E, F, S, P, Mk>(
    entropy: &mut E,
    floors: &F,
    scheduler: &S,
    publisher: &P,
    plan: &RotateScopePlan<'_>,
    make_sweep_task: Mk,
) -> Result<RotationOutcome, RotateError>
where
    E: Entropy,
    F: FloorStore,
    S: Scheduler,
    P: ScopeRootPublisher,
    Mk: FnOnce() -> BoxedTask,
{
    // Fail-closed BEFORE minting: a saturating bump at u64::MAX would republish
    // fresh key material under the same epoch (a key-regression violation), so an
    // exhausted epoch is rejected rather than silently reused.
    let new_read_epoch = plan
        .current_read_epoch
        .checked_add(1)
        .ok_or(RotateError::EpochExhausted)?;

    // Mint the fresh random override seed at the scope root (the read-plane cut).
    // `rotate_scope` is this seed's terminal owner: `Zeroizing` wipes it on every
    // return path, including the error paths and a panic unwind.
    let new_override_seed =
        fresh_seed(entropy).map_err(|e| RotateError::Reseal(ResealError::Entropy(e)))?;

    let seeds = ResealSeeds {
        override_seed: &new_override_seed,
        read_epoch: new_read_epoch,
        prev: Some(PrevEpochSeed {
            seed: plan.current_override_seed,
            epoch: plan.current_read_epoch,
        }),
        write_scope_seed: plan.write_scope_seed,
        write_epoch: plan.write_epoch,
        write_history: WriteHistory::Carried(plan.write_history_link),
        pointer_read_key: plan.pointer_read_key,
    };

    let section = reseal_scope_root(
        entropy,
        &plan.identity,
        &seeds,
        &plan.committed,
        plan.carried_history_links,
    )
    .map_err(RotateError::Reseal)?;

    let record = ResealedScopeRoot {
        scope_id: plan.identity.scope_id,
        ipns_name: plan.identity.ipns_name.to_vec(),
        read_epoch: new_read_epoch,
        write_epoch: plan.write_epoch,
        section,
    };

    // 1) Publish CAS. Nothing durable is left on failure — the floor is untouched.
    publisher
        .publish_scope_root(&record)
        .await
        .map_err(RotateError::Publish)?;

    // 2) Raise the durable minReadEpoch floor — only after a confirmed publish, so
    // a crash between the two never demands an unpublished epoch (no lockout).
    let epoch_floor = floors
        .raise_epoch_floor(&plan.identity.scope_id, new_read_epoch)
        .await
        .map_err(RotateError::Floor)?;

    // 3) Enqueue the lazy-wave sweep — last, only after the cut is durable.
    scheduler.spawn(make_sweep_task());

    Ok(RotationOutcome {
        new_read_epoch,
        epoch_floor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::SeamResult;
    use crate::testkit::fakes::{InMemoryFloorStore, VirtualScheduler};
    use crate::testkit::{SeededEntropy, SilentEntropy, block_on};
    use cipherbox_core::seal::{
        GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, Permission, PreservedFields,
        sign_grant_set,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::x25519::X25519Secret;
    use std::cell::RefCell;
    use std::rc::Rc;

    const SCOPE: [u8; 16] = [0x5c; 16];

    /// The caller-side bound needs one classifier it can trust: an availability
    /// stall and the C2 label conflict the re-point wave repairs are re-drivable;
    /// a refused publish, a re-seal this build will not sign and an exhausted
    /// epoch are verdicts no retry reaches differently.
    #[test]
    fn only_availability_and_the_repairable_label_conflict_are_retryable() {
        for retryable in [
            RotateError::Resolve(ResolveFailure::Unavailable),
            RotateError::Resolve(ResolveFailure::ConflictingChildLabel),
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
            Self {
                owner_enc: X25519Secret::from_scalar([0x11; 32]),
                pseudonym: Ed25519Signer::from_seed([0x22; 32]),
                owner_ecdsa: EcdsaSigner::from_scalar(&[0x33; 32]).unwrap(),
                write_scope_seed: [0x55; 32],
                pointer_read_key: [0x66; 32],
                grantee: X25519Secret::from_scalar([0x77; 32]),
            }
        }

        fn committed(&self) -> (GrantSetCommitment, [u8; 64], Vec<GrantLedgerEntry>) {
            let commitment = GrantSetCommitment {
                ipns_name: b"scope-root".to_vec(),
                owner_pseudonym_pk: self.pseudonym.verifying_key().to_bytes(),
                entries: vec![GrantSetEntry::new([0xa1; 32], Permission::Read, [0x02; 32])],
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(&self.owner_ecdsa, &commitment)
                .unwrap()
                .to_compact();
            let ledger = vec![GrantLedgerEntry::new(
                [0x02; 33],
                self.grantee.public().to_bytes(),
                Permission::Read,
                [0xa1; 32],
            )];
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
                },
                current_override_seed: &current_seed,
                current_read_epoch: 4,
                write_scope_seed: &fx.write_scope_seed,
                write_epoch: 3,
                write_history_link: b"",
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
                },
                current_override_seed: &current_seed,
                current_read_epoch: 4,
                write_scope_seed: &fx.write_scope_seed,
                write_epoch: 3,
                write_history_link: b"",
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
                },
                current_override_seed: &current_seed,
                current_read_epoch: u64::MAX,
                write_scope_seed: &fx.write_scope_seed,
                write_epoch: 3,
                write_history_link: b"",
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
}
