//! Revival after a >EOL lapse (blueprint/engine.md "Resolve/publish pipeline:
//! Revival", #24 lapse semantics).
//!
//! A lapse is an availability event, never loss. A key-holding session fetches
//! the cached (possibly expired) record bytes from the authenticated recovery
//! endpoint, extracts the last-known CID, and mints a fresh record with a fresh
//! signature at a strictly-newer sequence through the normal publish path — the
//! recovered sequence raises the CAS floor so the re-mint supersedes whatever
//! lapsed. (The pin set's name→CID mapping is the designed-for alternate source
//! behind the same recovery endpoint.)

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;

use super::publish::{PublishError, PublishOutcome, PublishRequest, head_cid_from_value, publish};
use crate::api::{ApiClient, ApiError};
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// What to revive: the lapsed name, its node signing key, and the session's
/// known content CIDs to re-register for pinning (empty is valid — a name-only
/// re-mint). The CID to re-point at is recovered from the endpoint, not carried
/// here.
pub struct ReviveRequest<'a> {
    /// The lapsed IPNS name.
    pub name: &'a IpnsName,
    /// The node's Ed25519 signing key (injected; this slice owns no derivation).
    pub signer: &'a Ed25519Signer,
    /// The session's content CIDs to re-register for pinning.
    pub content_cids: Vec<String>,
}

/// A fail-closed revival failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviveError {
    /// The recovery fetch failed (auth, rate limit, or the name is unknown).
    Recovery(ApiError),
    /// The recovered bytes are not a valid record for this name, or its value is
    /// not an `/ipfs/<cid>` path — nothing safe to revive from.
    Unrecoverable,
    /// The re-mint publish failed.
    Publish(PublishError),
}

/// Revive after a >EOL lapse: fetch the last-known record from the recovery
/// endpoint, extract its CID, and republish a fresh record at a strictly-newer
/// sequence.
pub async fn revive<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: ReviveRequest<'_>,
) -> Result<PublishOutcome, ReviveError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let bytes = api
        .recovery_fetch(request.name.as_str())
        .await
        .map_err(ReviveError::Recovery)?;

    // The recovered record is authenticated against the name before we trust its
    // CID/sequence — a recovery endpoint is an accelerator, never an authority.
    let verified = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(request.name))
        .map_err(|_| ReviveError::Unrecoverable)?;
    let head_cid = head_cid_from_value(&verified.value).ok_or(ReviveError::Unrecoverable)?;

    let publish_request = PublishRequest {
        name: request.name,
        signer: request.signer,
        head_cid,
        content_cids: request.content_cids,
        // Strictly newer than the lapsed record, even if this device's floor is
        // stale after the lapse.
        min_current_sequence: Some(verified.sequence),
    };
    publish(transport, api, floors, scheduler, profile, &publish_request)
        .await
        .map_err(ReviveError::Publish)
}
