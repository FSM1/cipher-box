//! The vault pointer's read-epoch vouch: a read cut of the vault root publishes
//! the root, then vouches its epoch here, then raises the floor
//! (blueprint/engine.md "Pointer planes"; [`floor::repoint_regression`]).

use core::cell::{Cell, RefCell};

use cipherbox_core::payload::RepointObject;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;

use super::fanout::{FanoutRecord, fanout_get_classified};
use super::rotation::{PointerPipeline, publish_pointer_over};
use crate::api::ApiClient;
use crate::entropy::Entropy;
use crate::gate::floor::{self, PointerPlane};
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
    /// The epoch a cut landed at the root. A retry finishes that cut: a re-cut
    /// would adopt the root and raise the floor past the anchor.
    pub landed: Cell<Option<u64>>,
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
    ///
    /// Refused when the standing re-point names another root: this pass proved
    /// nothing about that root's read epoch. A standing re-point already at or
    /// past `read_epoch` is left alone.
    pub(crate) async fn vouch_read_epoch(
        &self,
        root_name: &[u8],
        read_epoch: u64,
    ) -> Result<(), RotationPublishError> {
        let name = self.name();
        let standing = match fanout_get_classified(self.transport, &name).await {
            FanoutRecord::Found(record, _) => record,
            FanoutRecord::Absent => return Err(RotationPublishError::Rejected),
            FanoutRecord::Unavailable => return Err(RotationPublishError::NotPublished),
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
        if vouched.min_read_epoch >= read_epoch {
            return Ok(());
        }
        let repoint = RepointObject {
            min_read_epoch: read_epoch,
            ..vouched
        };
        // Rule 8, through the predicate the cold start reads it with.
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
            &name,
            &self.signer,
            &block,
            standing.sequence,
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
        anchor.landed.set(Some(record.read_epoch));
        anchor
            .vouch_read_epoch(&record.ipns_name, record.read_epoch)
            .await
    }
}
