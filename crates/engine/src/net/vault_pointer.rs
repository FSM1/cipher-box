//! The vault pointer's read-epoch vouch: a read cut of the vault root publishes
//! the root, then vouches its epoch here, then raises the floor
//! (blueprint/engine.md "Pointer planes"; [`floor::repoint_regression`]).

use core::cell::RefCell;

use cipherbox_core::payload::RepointObject;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;

use super::fanout::{FanoutRecord, fanout_get_classified};
use super::publish::Observed;
use super::rotation::{PointerPipeline, publish_pointer_over};
use crate::api::ApiClient;
use crate::entropy::Entropy;
use crate::gate::GateError;
use crate::gate::floor::{self, PointerPlane, Strictness};
use crate::profile::SyncTimingProfile;
use crate::rotation::{ResealedScopeRoot, RotationPublishError, ScopeRootPublisher};
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::sync::pointer::{PointerError, SessionRole, open_repoint, seal_repoint};
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
    /// `root_name`: a vouch over it would prove nothing about that root. Also
    /// refused below the vouched floor or below the sequence this device
    /// published at the name: a vouch carries every other field over, so one
    /// over a replay would sign the rolled-back fields again, above it.
    pub(crate) async fn standing(
        &self,
        root_name: &[u8],
    ) -> Result<StandingVouch, RotationPublishError> {
        let standing = match fanout_get_classified(self.transport, &self.name()).await {
            FanoutRecord::Found(record, _) => record,
            FanoutRecord::Absent => return Err(RotationPublishError::Rejected),
            FanoutRecord::Unavailable(_) => return Err(RotationPublishError::NotPublished),
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
            self.name().as_str().as_bytes(),
            standing.sequence,
            Strictness::AtOrAboveFloor,
        )
        .await
        .map_err(|error| match error {
            GateError::Seam(_) => RotationPublishError::NotPublished,
            GateError::Rejected(_) => RotationPublishError::Rejected,
        })?;
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
