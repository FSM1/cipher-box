//! The production publish arm of first-run vault provisioning
//! ([`crate::sync::provision`]) — the same register-first CAS pipeline every
//! other write rides, with no crypto and no trust logic added.

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use crate::api::{ApiClient, ApiError};
use crate::net::MAX_RECORD_BYTES;
use crate::net::publish::{
    InlineRecordRequest, PublishError, PublishOutcome, PublishReceipt, publish_inline,
};
use crate::net::record_publish::{
    PreflightedHead, RecordPublishError, RecordPublishRequest, publish_record,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::WritePublishError;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};
use crate::sync::provision::{VaultPointerProbe, VaultProvisionPublisher};

/// The provisioning publish seams over the live net plane.
pub struct VaultProvisionNet<'a, T, H: Http, C: CredentialStore, F, Sch> {
    /// The record-plane transport the CAS PUT fans out over.
    pub transport: &'a T,
    /// The API client: register-first and the head-block upload.
    pub api: &'a ApiClient<H, C>,
    /// The durable floors the publish pipeline reads its CAS sequence from.
    pub floors: &'a F,
    /// The scheduler the publish pipeline's background re-PUT rides.
    pub scheduler: &'a Sch,
    /// The publish pipeline's timing policy.
    pub profile: &'a SyncTimingProfile,
}

/// Carry a publish failure onto rule 6's axis: only this build's own
/// release-active refusals and a mis-echoed CID are verdicts a retry repeats.
fn publish_verdict(error: PublishError) -> WritePublishError {
    match error {
        PublishError::Register(_) => WritePublishError::RegistryFull,
        PublishError::EmptyHeadCid | PublishError::RecordTooLarge { .. } => {
            WritePublishError::Rejected
        }
        PublishError::AllEndpointsFailed | PublishError::FloorRead(_) => {
            WritePublishError::NotLanded
        }
    }
}

/// Whether a publish durably landed. The per-name sequence floor is left alone:
/// it moves on the AAD-confirmed unseal of an adopt (`gate::floor`), and the
/// session's first resolve of the genesis root is that adopt — the one that also
/// caches the bytes every later write re-authors from.
fn landed(outcome: PublishOutcome) -> Result<(), WritePublishError> {
    match outcome {
        PublishOutcome::Published { .. } => Ok(()),
        PublishOutcome::LostRace { .. } => Err(WritePublishError::LostRace),
        PublishOutcome::Unconfirmed { .. } => Err(WritePublishError::NotLanded),
    }
}

impl<T, H: Http, C: CredentialStore, F, Sch> VaultProvisionPublisher
    for VaultProvisionNet<'_, T, H, C, F, Sch>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    async fn require_vacant_vault_pointer(&self, name: &IpnsName) -> Result<(), VaultPointerProbe> {
        // The API's record cache outlives an IPNS EOL lapse, so it still answers
        // for a vault whose record has aged out of the routing tables. It is an
        // accelerator, never an authority — but used only to *refuse*, a hostile
        // or lagging answer can block a mint and never cause a wrong one. A 404
        // is the sole affirmative "no such record"; anything else is silence.
        match self.api.recovery_fetch(name.as_str()).await {
            Ok(_) => return Err(VaultPointerProbe::AlreadyPublished),
            Err(ApiError::Status { status: 404, .. }) => {}
            Err(_) => return Err(VaultPointerProbe::Indeterminate),
        }
        // Then the record plane itself, per endpoint so a failure is not read as
        // an absence: any record at the name means the account has published.
        let mut answered = false;
        for endpoint in self.transport.endpoints() {
            match self
                .transport
                .get_record(&endpoint, name.as_str(), MAX_RECORD_BYTES)
                .await
            {
                Ok(Some(_)) => return Err(VaultPointerProbe::AlreadyPublished),
                Ok(None) => answered = true,
                Err(_) => {}
            }
        }
        answered
            .then_some(())
            .ok_or(VaultPointerProbe::Indeterminate)
    }

    async fn publish_root_record(
        &self,
        name: &IpnsName,
        signer: &Ed25519Signer,
        head: &PreflightedHead,
    ) -> Result<(), WritePublishError> {
        let PublishReceipt { outcome, .. } = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name,
                signer,
                head,
                content_cids: Vec::new(),
                min_current_sequence: None,
            },
        )
        .await
        .map_err(|error| match error {
            // A CID the API echoes back wrong is deterministic on the bytes this
            // run built: re-uploading them reaches the same answer.
            RecordPublishError::HeadCidMismatch { .. } => WritePublishError::Rejected,
            RecordPublishError::Upload(_) => WritePublishError::NotLanded,
            RecordPublishError::Publish(e) => publish_verdict(e),
        })?;
        landed(outcome)
    }

    async fn publish_vault_pointer(
        &self,
        name: &IpnsName,
        signer: &Ed25519Signer,
        block: &[u8],
    ) -> Result<(), WritePublishError> {
        let PublishReceipt { outcome, .. } = publish_inline(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &InlineRecordRequest {
                name,
                signer,
                value: block,
                min_current_sequence: None,
            },
        )
        .await
        .map_err(publish_verdict)?;
        landed(outcome)
    }
}
