//! The gated fan-out read: the below-floor rule of ADR 0071 D1, stated once
//! for every read route, and the scope root gate ladder of the rotation reads.

use cipherbox_core::error::TrustViolation;
use cipherbox_core::ipns::{IpnsName, VerifiedRecord};
use cipherbox_core::seal::{Envelope, GrantSection, OwnerSeedRecord, ReadBody};
use cipherbox_core::suite::secret::SECRET_LEN;
use zeroize::Zeroizing;

use super::adopter::{RecoveredScopeRoot, RecoveredSeeds, RootAdopter};
use super::fanout::{TiedFetch, fanout_get_tied_classified};
use super::fork::{Fork, cached_fork, fork_of, served_fork};
use super::last_known_good::{keep_served_last_known_good, keep_then_commit};
use super::publish::{Observed, PublishError};
use crate::gate::{Candidate, GateError, PendingAdoption, RejectionReason};
use crate::rotation::{ResolveFailure, SweepResolveFailure};
use crate::seams::{FloorStore, Http, RecordTransport, SnapshotCache};

/// What a record strictly below its sequence floor reads as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BelowFloor {
    /// An endpoint failed and can hold a newer record (ADR 0071 D1).
    Unavailable,
    /// Every endpoint answered, so the record is a rollback (ADR 0071 D4).
    Rollback,
}

impl BelowFloor {
    /// The verdict on a record already known to be below the floor.
    pub(crate) fn after_fanout(endpoint_failed: bool) -> Self {
        if endpoint_failed {
            Self::Unavailable
        } else {
            Self::Rollback
        }
    }
}

/// The verdict on `sequence` against `floor`; `None` at or above the floor.
pub(crate) fn below_floor(sequence: u64, floor: u64, endpoint_failed: bool) -> Option<BelowFloor> {
    (sequence < floor).then(|| BelowFloor::after_fanout(endpoint_failed))
}

/// The verdict on a gate refusal; `None` for a refusal that is not the
/// sequence stage's below-floor refusal.
pub(crate) fn sequence_refusal(
    reason: &RejectionReason,
    endpoint_failed: bool,
) -> Option<BelowFloor> {
    match reason {
        RejectionReason::SequenceNotNewer { floor, sequence } => {
            below_floor(*sequence, *floor, endpoint_failed)
        }
        _ => None,
    }
}

/// One scope root as the adoption gate authenticated it, plus the seeds the
/// owner recovered from its own blobs. Terminal owner of those seeds: they
/// zeroize when the value is dropped.
pub(super) struct GatedScopeRoot {
    pub(super) write_epoch: Option<u64>,
    pub(super) observed: Result<Observed, PublishError>,
    pub(super) envelope: Envelope,
    pub(super) section: GrantSection,
    pub(super) read_body: ReadBody,
    /// The record's own IPNS sequence, as the gate authenticated it.
    pub(super) sequence: u64,
    /// The override seed recovered from this root's own owner blob — the
    /// ancestor seed its descendants' ascent links are derived from.
    pub(super) read_scope_seed: Zeroizing<[u8; SECRET_LEN]>,
    /// `None` when the root is held keyless — no owner-write-blob, or no
    /// durable write-epoch floor to open it under.
    pub(super) write_scope_seed: Option<Zeroizing<[u8; SECRET_LEN]>>,
}

impl GatedScopeRoot {
    /// Whether a re-seal or a republish of `scope_id` can build on this root.
    /// The root gate binds `envelope.scope` but not `envelope.id`, and every
    /// AAD a re-seal authors binds the id, so a root whose record claims
    /// another node would be re-sealed under a key no reader re-derives. A
    /// republish also needs an `Observed`.
    pub(super) fn reseals_as(&self, scope_id: &[u8; 16]) -> bool {
        self.envelope.id == *scope_id && self.observed.is_ok()
    }

    /// A copy bound to `expected_child`, when the caller expects one.
    pub(super) fn names_child(&self, expected_child: Option<[u8; 16]>) -> bool {
        expected_child.is_none_or(|id| self.envelope.id == id && self.section.ascent_link.is_some())
    }

    pub(super) fn recovered(name: &IpnsName, root: RecoveredScopeRoot) -> Self {
        Self {
            write_epoch: root.write_epoch,
            observed: Observed::gated(name, root.sequence, root.envelope.v, &root.record_bytes),
            envelope: root.envelope,
            section: root.grant_section,
            read_body: root.read_body,
            sequence: root.sequence,
            read_scope_seed: root.read_scope_seed,
            write_scope_seed: root.write_scope_seed,
        }
    }
}

/// A rotation root read's verdict, carrying ADR 0003 D2's below-floor split: a
/// scope root under its own read-epoch floor is a **superseded name**, not a
/// trust rejection — rotations publish before they raise the floor, so the
/// condition cannot mean the root lags. The sweep routes that verdict
/// through the pointer consult, and the boundary walk's `walk_verdict` and the
/// renewal walk's `admit_owned_scope_root` read it as availability; every other arm folds it
/// back into a fail-closed rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootGateVerdict {
    Rejected,
    OwnerSeedRefused,
    Unavailable,
    Superseded,
    /// The record's own body fills the re-seal reservation, so no re-seal of it
    /// is authorable (`content::limits::resealable_root_rest_bytes`). Only the
    /// owner's rotation tells this apart from a plain rejection, and only to
    /// step over the record ([`OwnerRotationNet::last_known_good_root`](super::rotation::OwnerRotationNet::last_known_good_root)); every
    /// other reader folds it back into one.
    NotResealable,
    /// Every block source answered that it holds no head block for the CID
    /// the record names. Only an owner cut's fallback tells this and
    /// [`Self::HeadBlockRefused`] apart from a rejection (ADR 0068 D1); every
    /// other reader folds both back into one.
    HeadBlockAbsent,
    /// The head block does not match the CID the record names, which one bad
    /// source serves and the record bytes do not cause.
    HeadBlockRefused,
    /// The sequence stage refused a record strictly below the floor, which a
    /// lagging endpoint serves. A rejection, unless the fan-out that served it
    /// met a failed endpoint ([`Self::after_fanout`]).
    BelowFloor,
    /// No endpoint served a record, and the endpoints agree the name holds
    /// none ([`TiedFetch::absent`]).
    Absent,
}

impl RootGateVerdict {
    /// A below-floor pick from a fan-out with a failed endpoint is
    /// unavailable, not a rollback (ADR 0071 D1), and so is a head block that
    /// no block source holds: the failed endpoint can hold a newer record.
    pub(super) fn after_fanout(self, endpoint_failed: bool) -> Self {
        match self {
            Self::BelowFloor => match BelowFloor::after_fanout(endpoint_failed) {
                BelowFloor::Unavailable => Self::Unavailable,
                BelowFloor::Rollback => Self::BelowFloor,
            },
            Self::HeadBlockAbsent if endpoint_failed => Self::Unavailable,
            verdict => verdict,
        }
    }
}

impl From<RootGateVerdict> for ResolveFailure {
    fn from(verdict: RootGateVerdict) -> Self {
        match verdict {
            RootGateVerdict::Unavailable | RootGateVerdict::Absent => Self::Unavailable,
            RootGateVerdict::Rejected
            | RootGateVerdict::OwnerSeedRefused
            | RootGateVerdict::Superseded
            | RootGateVerdict::NotResealable
            | RootGateVerdict::HeadBlockAbsent
            | RootGateVerdict::HeadBlockRefused
            | RootGateVerdict::BelowFloor => Self::Rejected,
        }
    }
}

impl From<RootGateVerdict> for SweepResolveFailure {
    fn from(verdict: RootGateVerdict) -> Self {
        match verdict {
            RootGateVerdict::Unavailable | RootGateVerdict::Absent => Self::Unavailable,
            RootGateVerdict::Rejected
            | RootGateVerdict::OwnerSeedRefused
            | RootGateVerdict::NotResealable
            | RootGateVerdict::HeadBlockAbsent
            | RootGateVerdict::HeadBlockRefused
            | RootGateVerdict::BelowFloor => Self::Rejected,
            RootGateVerdict::Superseded => Self::Superseded,
        }
    }
}

pub(super) fn cache_gate_verdict(error: GateError) -> RootGateVerdict {
    match error {
        GateError::Seam(_) => RootGateVerdict::Unavailable,
        GateError::Rejected(_) => RootGateVerdict::Rejected,
    }
}

/// The rejection arm of a rotation's gated read, recovered at the durable
/// sequence floor.
///
/// Adopting a scope root raises that name's sequence floor, so re-reading the
/// **unchanged** record rejects as not-newer — and a rotation reads in order to
/// re-key, so a pass that aborts before publishing must be able to read again or
/// the revoke can never complete. Only the exact floor recovers; a strictly
/// lower sequence is [`RootGateVerdict::BelowFloor`] (ADR 0071), and every
/// other rejection stays a fail-closed trust violation (rule 6).
async fn reread_at_floor<H: Http, F: FloorStore>(
    adopter: &RootAdopter<'_, H, F>,
    name: &IpnsName,
    record_bytes: &[u8],
    reason: &RejectionReason,
) -> Result<(GatedScopeRoot, Option<OwnerSeedRecord>), RootGateVerdict> {
    let RejectionReason::SequenceNotNewer { floor, sequence } = reason else {
        return Err(RootGateVerdict::Rejected);
    };
    if sequence < floor {
        return Err(RootGateVerdict::BelowFloor);
    }
    let mut recovered = adopter
        .recover_own_scope_root(name, record_bytes)
        .await
        .map_err(|e| match e {
            GateError::Rejected(ref rejection) if super::adopter::owner_seed_refused(rejection) => {
                RootGateVerdict::OwnerSeedRefused
            }
            e => cache_gate_verdict(e),
        })?
        // Nothing to re-check is no recovery; the rotation keeps the gate's
        // own verdict.
        .ok_or(RootGateVerdict::Rejected)?;
    let record = recovered.owner_seed_record.take();
    Ok((GatedScopeRoot::recovered(name, recovered), record))
}

/// A rotation root read the gate passed, with any floor advance not yet
/// committed.
enum RootPass {
    Pending(Box<(IpnsName, Candidate, PendingAdoption, RecoveredSeeds)>),
    /// This reader's own already-adopted record, recovered at the floor
    /// ([`reread_at_floor`]): nothing left to commit.
    AtFloor(Box<(GatedScopeRoot, Option<OwnerSeedRecord>)>),
}

impl RootPass {
    async fn commit<H: Http, F: FloorStore>(
        self,
        adopter: &RootAdopter<'_, H, F>,
    ) -> Result<GatedScopeRoot, RootGateVerdict> {
        match self {
            Self::Pending(pass) => {
                let (name, candidate, pending, seeds) = *pass;
                let adopted = adopter
                    .commit_root(pending)
                    .await
                    .map_err(|_| RootGateVerdict::Unavailable)?;
                Ok(GatedScopeRoot {
                    write_epoch: seeds.write_epoch,
                    observed: Observed::gated(
                        &name,
                        adopted.sequence,
                        candidate.envelope.v,
                        &candidate.record_bytes,
                    ),
                    envelope: candidate.envelope,
                    section: candidate.grant_section,
                    sequence: adopted.sequence,
                    read_body: adopted.read_body,
                    read_scope_seed: seeds.read_scope_seed,
                    write_scope_seed: seeds.write_scope_seed,
                })
            }
            Self::AtFloor(pass) => {
                let (root, record) = *pass;
                adopter.remember_confirmed(record.as_ref()).await;
                Ok(root)
            }
        }
    }
}

/// Gate `record_bytes` under the binding `anchor` names, recovering this
/// reader's own already-adopted record through [`reread_at_floor`]. The one
/// ladder every rotation arm's root read runs; the floor advance waits on
/// [`RootPass::commit`], so a binding this refuses raises no floor.
///
/// `Some(expected_id)` binds a claimed **child** scope of the one `adopter`
/// carries the parent node seed for; `None` a vault-anchored root. Two bindings prove it,
/// and the caller supplies neither: the owner-signed commitment binds the name,
/// and the **ascent link** — required here, release-active — binds the record
/// to `nodeSeed(parent read seed, child)`. The gate verifies an ascent link
/// only when the record carries one and the vault root carries none, so
/// without this requirement any owner-signed root planted by a committed writer
/// would gate cleanly as this scope's descendant.
async fn gate_root_pass<H: Http, F: FloorStore>(
    adopter: &RootAdopter<'_, H, F>,
    name: &IpnsName,
    record_bytes: &[u8],
    expected_child: Option<[u8; 16]>,
) -> Result<RootPass, RootGateVerdict> {
    let bound = |envelope: &Envelope, section: &GrantSection| {
        expected_child
            .is_none_or(|expected| envelope.id == expected && section.ascent_link.is_some())
    };
    match adopter.gate_and_recover(name, record_bytes).await {
        Ok((candidate, pending, seeds)) => {
            if !bound(&candidate.envelope, &candidate.grant_section) {
                return Err(RootGateVerdict::Rejected);
            }
            Ok(RootPass::Pending(Box::new((
                name.clone(),
                candidate,
                pending,
                seeds,
            ))))
        }
        Err(GateError::Seam(seam)) if seam.is_block_not_held() => {
            Err(RootGateVerdict::HeadBlockAbsent)
        }
        Err(GateError::Seam(_)) => Err(RootGateVerdict::Unavailable),
        Err(GateError::Rejected(rejection))
            if matches!(rejection.reason, RejectionReason::EpochBelowFloor { .. }) =>
        {
            Err(RootGateVerdict::Superseded)
        }
        Err(GateError::Rejected(rejection))
            if matches!(
                rejection.reason,
                RejectionReason::ScopeRootNotResealable { .. }
            ) =>
        {
            Err(RootGateVerdict::NotResealable)
        }
        Err(GateError::Rejected(rejection)) if super::adopter::owner_seed_refused(&rejection) => {
            Err(RootGateVerdict::OwnerSeedRefused)
        }
        Err(GateError::Rejected(rejection))
            if rejection.reason
                == RejectionReason::Trust(TrustViolation::ContentCidMismatch.into()) =>
        {
            Err(RootGateVerdict::HeadBlockRefused)
        }
        Err(GateError::Rejected(rejection)) => {
            let (root, record) =
                reread_at_floor(adopter, name, record_bytes, &rejection.reason).await?;
            if !bound(&root.envelope, &root.section) {
                return Err(RootGateVerdict::Rejected);
            }
            Ok(RootPass::AtFloor(Box::new((root, record))))
        }
    }
}

/// [`gate_root_pass`], committed.
pub(super) async fn gated_root<H: Http, F: FloorStore>(
    adopter: &RootAdopter<'_, H, F>,
    name: &IpnsName,
    record_bytes: &[u8],
    expected_child: Option<[u8; 16]>,
) -> Result<GatedScopeRoot, RootGateVerdict> {
    gate_root_pass(adopter, name, record_bytes, expected_child)
        .await?
        .commit(adopter)
        .await
}

/// [`gate_root_pass`], committed after `record_bytes` is left as last-known-good
/// ([`keep_then_commit`]).
async fn gated_root_cached<H: Http, F: FloorStore, S: SnapshotCache>(
    adopter: &RootAdopter<'_, H, F>,
    snapshot_cache: &S,
    name: &IpnsName,
    record_bytes: &[u8],
    expected_child: Option<[u8; 16]>,
) -> Result<GatedScopeRoot, RootGateVerdict> {
    let pass = gate_root_pass(adopter, name, record_bytes, expected_child).await?;
    keep_then_commit(snapshot_cache, name, record_bytes, async {
        Ok(pass.commit(adopter).await)
    })
    .await
    .map_err(|_| RootGateVerdict::Unavailable)?
}

/// [`gated_root_cached`] for a read that can meet a same-sequence fork (ADR
/// 0066 D1): a tie of `pick` that gates at the floor the pass left, or another
/// record the cache held at its sequence.
async fn gated_root_forked<H: Http, F: FloorStore, S: SnapshotCache>(
    adopter: &RootAdopter<'_, H, F>,
    snapshot_cache: &S,
    name: &IpnsName,
    pick: &VerifiedRecord,
    record_bytes: &[u8],
    tied: &[Vec<u8>],
    expected_child: Option<[u8; 16]>,
) -> Result<(GatedScopeRoot, Option<Fork>), RootGateVerdict> {
    let pass = gate_root_pass(adopter, name, record_bytes, expected_child).await?;
    let cached = keep_served_last_known_good(snapshot_cache, name, record_bytes)
        .await
        .map_err(|_| RootGateVerdict::Unavailable)?;
    let root = pass.commit(adopter).await?;
    let served = served_fork(name, pick, tied, async |tie| {
        matches!(
            gate_root_pass(adopter, name, tie, expected_child).await,
            Ok(RootPass::AtFloor(_))
        )
    })
    .await;
    let fork = fork_of(
        pick,
        served,
        cached_fork(name, cached.as_deref(), record_bytes, pick),
    );
    Ok((root, fork))
}

/// One scope root read: the fan-out, the root gate ladder over the record it
/// picks, and the fold of [`RootGateVerdict::after_fanout`]. The bytes it
/// gates are left as last-known-good ([`keep_then_commit`]).
pub(super) struct RootRead<'a, H, F, S> {
    adopter: &'a RootAdopter<'a, H, F>,
    snapshot_cache: &'a S,
    /// The child binding of [`gate_root_pass`].
    expected_child: Option<[u8; 16]>,
}

/// A root read the gate refused, with the verdict already folded.
pub(super) struct RootRefusal {
    pub(super) verdict: RootGateVerdict,
    /// The sequence and bytes of the refused record; `None` when no endpoint
    /// served one.
    pub(super) served: Option<(u64, Vec<u8>)>,
}

/// A root read that can meet a same-sequence fork (ADR 0066 D1), passed.
pub(super) struct RootReadPass {
    pub(super) root: GatedScopeRoot,
    pub(super) fork: Option<Fork>,
    /// The signed `data` of the record the gate passed.
    pub(super) data: Vec<u8>,
    pub(super) bytes: Vec<u8>,
}

impl<'a, H: Http, F: FloorStore, S: SnapshotCache> RootRead<'a, H, F, S> {
    pub(super) fn new(
        adopter: &'a RootAdopter<'a, H, F>,
        snapshot_cache: &'a S,
        expected_child: Option<[u8; 16]>,
    ) -> Self {
        Self {
            adopter,
            snapshot_cache,
            expected_child,
        }
    }

    /// The root at `name`, read over `transport`.
    pub(super) async fn read<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
    ) -> Result<GatedScopeRoot, RootRefusal> {
        let (pick, bytes, _, endpoint_failed) = picked(transport, name).await?;
        self.gate_served(name, &bytes, endpoint_failed)
            .await
            .map_err(|verdict| RootRefusal {
                verdict,
                served: Some((pick.sequence, bytes)),
            })
    }

    /// [`Self::read`], and the fork the pick or the cache shows.
    pub(super) async fn read_forked<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
    ) -> Result<RootReadPass, RootRefusal> {
        let (pick, bytes, tied, endpoint_failed) = picked(transport, name).await?;
        match gated_root_forked(
            self.adopter,
            self.snapshot_cache,
            name,
            &pick,
            &bytes,
            &tied,
            self.expected_child,
        )
        .await
        {
            Ok((root, fork)) => Ok(RootReadPass {
                root,
                fork,
                data: pick.data,
                bytes,
            }),
            Err(verdict) => Err(RootRefusal {
                verdict: verdict.after_fanout(endpoint_failed),
                served: Some((pick.sequence, bytes)),
            }),
        }
    }

    /// Gate `bytes`, which a fan-out served at `name`, and fold the verdict
    /// by whether that fan-out met a failed endpoint.
    pub(super) async fn gate_served(
        &self,
        name: &IpnsName,
        bytes: &[u8],
        endpoint_failed: bool,
    ) -> Result<GatedScopeRoot, RootGateVerdict> {
        gated_root_cached(
            self.adopter,
            self.snapshot_cache,
            name,
            bytes,
            self.expected_child,
        )
        .await
        .map_err(|verdict| verdict.after_fanout(endpoint_failed))
    }
}

/// The record the fan-out at `name` picks, its ties, and whether an endpoint
/// failed.
async fn picked<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> Result<(VerifiedRecord, Vec<u8>, Vec<Vec<u8>>, bool), RootRefusal> {
    let TiedFetch {
        pick,
        absent,
        endpoint_failed,
    } = fanout_get_tied_classified(transport, name).await;
    let (pick, bytes, tied) = pick.ok_or(RootRefusal {
        verdict: if absent {
            RootGateVerdict::Absent
        } else {
            RootGateVerdict::Unavailable
        },
        served: None,
    })?;
    Ok((pick, bytes, tied, endpoint_failed))
}

#[cfg(test)]
mod tests {
    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::*;
    use crate::seams::EndpointId;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryRecordStore;

    #[test]
    fn a_sequence_below_the_floor_is_unavailable_only_while_an_endpoint_fails() {
        for (sequence, endpoint_failed, expected) in [
            (4, true, Some(BelowFloor::Unavailable)),
            (4, false, Some(BelowFloor::Rollback)),
            (5, true, None),
            (5, false, None),
            (6, true, None),
            (6, false, None),
        ] {
            assert_eq!(
                below_floor(sequence, 5, endpoint_failed),
                expected,
                "sequence {sequence}, endpoint failed {endpoint_failed}"
            );
            assert_eq!(
                sequence_refusal(
                    &RejectionReason::SequenceNotNewer { floor: 5, sequence },
                    endpoint_failed
                ),
                expected,
                "sequence {sequence}, endpoint failed {endpoint_failed}"
            );
        }
    }

    #[test]
    fn a_refusal_off_the_sequence_stage_is_no_below_floor_verdict() {
        let reason = RejectionReason::EpochBelowFloor { floor: 5, epoch: 4 };
        assert_eq!(sequence_refusal(&reason, true), None);
        assert_eq!(sequence_refusal(&reason, false), None);
    }

    /// Only a below-floor pick and an absent head block read as unavailable
    /// while an endpoint fails; every other verdict passes the fold as it is.
    #[test]
    fn the_fold_makes_only_the_endpoint_causes_unavailable_while_an_endpoint_fails() {
        for verdict in [
            RootGateVerdict::Rejected,
            RootGateVerdict::OwnerSeedRefused,
            RootGateVerdict::Unavailable,
            RootGateVerdict::Superseded,
            RootGateVerdict::NotResealable,
            RootGateVerdict::HeadBlockAbsent,
            RootGateVerdict::HeadBlockRefused,
            RootGateVerdict::BelowFloor,
            RootGateVerdict::Absent,
        ] {
            let folded = match verdict {
                RootGateVerdict::BelowFloor | RootGateVerdict::HeadBlockAbsent => {
                    RootGateVerdict::Unavailable
                }
                other => other,
            };
            assert_eq!(verdict.after_fanout(true), folded, "{verdict:?}, failed");
            assert_eq!(
                verdict.after_fanout(false),
                verdict,
                "{verdict:?}, answered"
            );
        }
    }

    /// A name with no record is absent only when every endpoint answers so.
    #[test]
    fn a_name_with_no_record_is_absent_only_when_every_endpoint_answers() {
        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let endpoints = vec![EndpointId::new("a"), EndpointId::new("b")];
        let store = InMemoryRecordStore::new(endpoints.clone());
        let unserved = |store: &InMemoryRecordStore| match block_on(picked(store, &name)) {
            Err(RootRefusal {
                verdict,
                served: None,
            }) => verdict,
            _ => panic!("no record is served"),
        };

        assert_eq!(unserved(&store), RootGateVerdict::Absent);
        store.fail_endpoint(&endpoints[0]);
        assert_eq!(unserved(&store), RootGateVerdict::Unavailable);

        let record =
            IpnsRecord::create_v2(&signer, b"/ipfs/one", 4, 1, "2099-01-01T00:00:00Z").marshal();
        store.seed_record(&endpoints[1], name.as_str(), record.clone());
        let Ok((pick, bytes, _, endpoint_failed)) = block_on(picked(&store, &name)) else {
            panic!("the record is served");
        };
        assert_eq!((pick.sequence, bytes, endpoint_failed), (4, record, true));
    }
}
