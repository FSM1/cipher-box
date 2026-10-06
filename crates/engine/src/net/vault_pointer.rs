//! The vault pointer's read-epoch vouch: a read cut of the vault root publishes
//! the root, then vouches its epoch here, then raises the floor
//! (blueprint/engine.md "Pointer planes"; [`floor::repoint_regression`]).

use core::cell::RefCell;

use cipherbox_core::payload::RepointObject;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;

use cipherbox_core::ipns::VerifiedRecord;
use cipherbox_core::kdf;
use cipherbox_core::suite::ecdsa::EcdsaVerifier;

use super::fanout::{FanoutRecord, TiedFetch, fanout_get_classified, fanout_get_tied_classified};
use super::publish::Observed;
use super::renewal_walk::RenewalSeams;
use super::resolve::unavailable_below_floor;
use super::revival::{
    Admitted, PlaneRead, PlaneRefusal, RecoveryPace, ReviveError, ReviveRequest, Revived, revive,
};
use super::rotation::{PointerPipeline, publish_pointer_over};
use crate::api::ApiClient;
use crate::entropy::Entropy;
use crate::gate::GateError;
use crate::gate::floor::{self, PointerPlane, Strictness};
use crate::profile::SyncTimingProfile;
use crate::rotation::{ResealedScopeRoot, RotationPublishError, ScopeRootPublisher};
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamResult};
use crate::sync::pointer::{
    MAX_VAULT_POINTER_PROBE, PointerError, SessionRole, open_repoint, seal_repoint,
    vault_pointer_name,
};
use cipherbox_core::ipns::IpnsName;

/// The vault pointer at the index this session adopted, and the owner material
/// that re-seals it. Owner sessions only.
pub(crate) struct VaultPointerVoucher<'a, T, H: Http, C: CredentialStore, F, Sch, E> {
    pub transport: &'a T,
    pub api: &'a ApiClient<H, C>,
    pub floors: &'a F,
    pub scheduler: &'a Sch,
    pub profile: &'a SyncTimingProfile,
    pub entropy: &'a RefCell<E>,
    /// Signs the re-point payload; every reader verifies it against the
    /// contact-anchored owner identity.
    pub owner: &'a EcdsaSigner,
    /// The root scope's stable `pointerReadKey`.
    pub pointer_read_key: SecretBytes,
    /// The record signer of the adopted vault-pointer index.
    pub signer: Ed25519Signer,
    /// The session's root scope — the scope the vault pointer names.
    pub scope_id: [u8; 16],
    pub payload_version: u64,
}

/// The re-point the vault pointer carries now, and the sequence it sits at.
pub(crate) struct StandingVouch {
    sequence: u64,
    repoint: RepointObject,
}

impl StandingVouch {
    /// The read epoch the vault pointer vouches.
    pub(crate) fn min_read_epoch(&self) -> u64 {
        self.repoint.min_read_epoch
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch, E> VaultPointerVoucher<'_, T, H, C, F, Sch, E>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    /// The vault-pointer name this voucher publishes at.
    pub(crate) fn name(&self) -> IpnsName {
        IpnsName::from_public_key(&self.signer.verifying_key())
    }

    /// Raise the vault pointer's `minReadEpoch` to `read_epoch` for the root at
    /// `root_name`, carrying every other field of the standing re-point.
    pub(crate) async fn vouch_read_epoch(
        &self,
        root_name: &[u8],
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        let standing = self.standing(root_name).await?;
        self.vouch_over(standing, read_epoch).await
    }

    /// The standing re-point, refused when it names a root other than
    /// `root_name`, or sits below the vouched floor or the sequence this device
    /// published: a vouch signs every other field of it again.
    pub(crate) async fn standing(
        &self,
        root_name: &[u8],
    ) -> Result<StandingVouch, RotationPublishError> {
        let name = self.name();
        let TiedFetch {
            pick,
            absent,
            endpoint_failed,
        } = fanout_get_tied_classified(self.transport, &name).await;
        let standing = match pick {
            Some((record, _, _)) => record,
            None if absent => return Err(RotationPublishError::Rejected),
            None => return Err(RotationPublishError::NotPublished),
        };
        let vouched = open_repoint(
            self.pointer_read_key.as_bytes(),
            self.payload_version,
            &self.scope_id,
            &self.owner.verifying_key(),
            &standing.value,
        )
        .map_err(|_| RotationPublishError::Rejected)?;
        if vouched.current_root.as_str().as_bytes() != root_name {
            return Err(RotationPublishError::Rejected);
        }
        let vouched_floor = floor::vouched_floor(self.floors, &self.scope_id)
            .await
            .map_err(|_| RotationPublishError::NotPublished)?;
        if vouched_floor.is_some_and(|floor| vouched.min_read_epoch < floor) {
            return Err(RotationPublishError::Rejected);
        }
        floor::check_sequence(
            self.floors,
            name.as_str().as_bytes(),
            standing.sequence,
            Strictness::AtOrAboveFloor,
        )
        .await
        .map_err(|error| standing_verdict(error, endpoint_failed))?;
        Ok(StandingVouch {
            sequence: standing.sequence,
            repoint: vouched,
        })
    }

    /// Raise `standing`'s `minReadEpoch` to `read_epoch` under a CAS over its
    /// sequence. A standing re-point already at or past it is left alone. Once
    /// the vault pointer vouches `read_epoch`, the vouched floor records it.
    pub(crate) async fn vouch_over(
        &self,
        standing: StandingVouch,
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        if standing.repoint.min_read_epoch < read_epoch {
            self.publish_vouch(standing, read_epoch).await?;
        }
        floor::raise_vouched_floor(self.floors, &self.scope_id, read_epoch)
            .await
            .map_err(|_| RotationPublishError::FloorUnrecorded)
    }

    async fn publish_vouch(
        &self,
        standing: StandingVouch,
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        let repoint = RepointObject {
            min_read_epoch: read_epoch,
            ..standing.repoint
        };
        // The produce bar (ADR 0067 D4).
        if floor::repoint_regression(
            self.floors,
            &repoint,
            &self.scope_id,
            PointerPlane::VaultPointer,
        )
        .await
        .map_err(|_| RotationPublishError::NotPublished)?
        .is_some()
        {
            return Err(RotationPublishError::Rejected);
        }
        let block = seal_repoint(
            SessionRole::Owner,
            &mut *self.entropy.borrow_mut(),
            self.pointer_read_key.as_bytes(),
            self.payload_version,
            self.owner,
            &repoint,
        )
        .map_err(|error| match error {
            PointerError::Entropy(_) => RotationPublishError::NotPublished,
            _ => RotationPublishError::Rejected,
        })?;
        publish_pointer_over(
            PointerPipeline {
                transport: self.transport,
                api: self.api,
                floors: self.floors,
                scheduler: self.scheduler,
                profile: self.profile,
            },
            &Observed::record(&self.name(), standing.sequence),
            &self.signer,
            &block,
        )
        .await
        .map(drop)
        .map_err(RotationPublishError::from)
    }
}

/// A scope-root publisher whose publish of the vault root also vouches the
/// published read epoch at the anchor, so the cut's floor raise follows both.
pub(crate) struct VouchedRoot<'a, P, A> {
    pub root: &'a P,
    pub anchor: Option<&'a A>,
}

impl<P, T, H: Http, C: CredentialStore, F, Sch, E> ScopeRootPublisher
    for VouchedRoot<'_, P, VaultPointerVoucher<'_, T, H, C, F, Sch, E>>
where
    P: ScopeRootPublisher,
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    E: Entropy,
{
    async fn publish_scope_root(
        &self,
        record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        self.root.publish_scope_root(record).await?;
        let Some(anchor) = self.anchor else {
            return Ok(());
        };
        // A fresh read, not the cut's refusal check: the CAS bar must follow
        // the root publish, or another device's re-point in between is lost.
        anchor
            .vouch_read_epoch(&record.ipns_name, record.read_epoch)
            .await
    }
}

/// `open_repoint` and the vault-pointer bar of one index of the chain (ADR
/// 0062 D1 step 3).
pub(crate) struct VaultPointerRead<'a, F> {
    pub(crate) floors: &'a F,
    pub(crate) pointer_read_key: &'a [u8; 32],
    pub(crate) owner_identity: &'a EcdsaVerifier,
    /// The session's root scope, the scope the vault pointer names.
    pub(crate) scope_id: [u8; 16],
    pub(crate) payload_version: u64,
}

impl<F> Clone for VaultPointerRead<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F> Copy for VaultPointerRead<'_, F> {}

impl<F: FloorStore> PlaneRead for VaultPointerRead<'_, F> {
    async fn admit<T: RecordTransport>(
        &self,
        _: &T,
        name: &IpnsName,
        recovered: &VerifiedRecord,
        bytes: &[u8],
    ) -> Result<Admitted, PlaneRefusal> {
        let repoint = open_repoint(
            self.pointer_read_key,
            self.payload_version,
            &self.scope_id,
            self.owner_identity,
            &recovered.value,
        )
        .map_err(|_| PlaneRefusal::Rejected)?;
        match floor::repoint_regression(
            self.floors,
            &repoint,
            &self.scope_id,
            PointerPlane::VaultPointer,
        )
        .await
        {
            Ok(None) => Ok(Admitted::unbarred(name, recovered.sequence, bytes)),
            Ok(Some(_)) => Err(PlaneRefusal::Rejected),
            Err(_) => Err(PlaneRefusal::Unavailable),
        }
    }

    /// A device that never walked the chain holds no index floor.
    async fn floorless<G: FloorStore>(&self, floors: &G, _: &IpnsName) -> SeamResult<bool> {
        Ok(floor::vault_pointer_index_floor(floors, &self.scope_id)
            .await?
            .is_none())
    }
}

/// Revive each lapsed index of the vault pointer chain, from the durable index
/// floor up, before `resolve_vault_pointer` reads it (ADR 0062 D3). An index
/// that the fan-out reads `Absent` revives from the recovery endpoint. The
/// first index the recovery endpoint holds no record for ends the chain, as
/// the probe one index past the last does.
pub(crate) async fn revive_vault_pointer_chain<T, H, C, F, Sch>(
    api: &ApiClient<H, C>,
    seams: &RenewalSeams<'_, T, F, Sch>,
    pace: &RecoveryPace,
    login_secret: &[u8],
    read: VaultPointerRead<'_, F>,
) -> Vec<(String, Result<Revived, ReviveError>)>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let mut revivals = Vec::new();
    // An index below the floor is abandoned, so its revival would re-sign a
    // superseded pointer.
    let Ok(floor) = floor::vault_pointer_index_floor(seams.floors, &read.scope_id).await else {
        return revivals;
    };
    let mut revived = None;
    let mut index = floor.unwrap_or(0);
    while index < MAX_VAULT_POINTER_PROBE {
        let name = vault_pointer_name(login_secret, index);
        match fanout_get_classified(seams.transport, &name).await {
            FanoutRecord::Found(..) => index += 1,
            FanoutRecord::Absent if revived != Some(index) => {
                let signer = kdf::vault_pointer_index(login_secret, index);
                let request = ReviveRequest {
                    name: &name,
                    signer: Some(&signer),
                    plane: read,
                };
                let result = revive(api, seams, pace, &[request]).await.remove(0);
                let signed = result.is_ok();
                revivals.push((name.as_str().to_owned(), result));
                if !signed {
                    return revivals;
                }
                // The next read finds the record the endpoints now serve.
                revived = Some(index);
            }
            FanoutRecord::Absent | FanoutRecord::Unavailable(_) => return revivals,
        }
    }
    revivals
}

/// The standing re-point's sequence check on rule 6's axis: a record below the
/// floor while an endpoint failed is unavailable (ADR 0071 D1).
fn standing_verdict(error: GateError, endpoint_failed: bool) -> RotationPublishError {
    match error {
        GateError::Rejected(rejection)
            if !unavailable_below_floor(&rejection.reason, endpoint_failed) =>
        {
            RotationPublishError::Rejected
        }
        _ => RotationPublishError::NotPublished,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{GateRejection, GateStage, RejectionReason};

    fn sequence(floor: u64, sequence: u64) -> GateError {
        GateError::Rejected(GateRejection {
            stage: GateStage::Sequence,
            reason: RejectionReason::SequenceNotNewer { floor, sequence },
        })
    }

    #[test]
    fn a_below_floor_standing_pointer_is_unavailable_only_while_an_endpoint_fails() {
        assert_eq!(
            standing_verdict(sequence(3, 2), true),
            RotationPublishError::NotPublished
        );
        assert_eq!(
            standing_verdict(sequence(3, 2), false),
            RotationPublishError::Rejected
        );
    }
}
