//! Revival after a >EOL lapse (blueprint/engine.md "Resolve/publish pipeline:
//! Revival", #24 lapse semantics).
//!
//! A lapse is an availability event, never loss. A key-holding session takes the
//! freshest record the authenticated recovery endpoint and the routing fan-out
//! between them can produce, and mints its CID afresh at a strictly-newer
//! sequence through the normal publish path — that record's sequence raises the
//! CAS floor so the re-mint supersedes whatever lapsed. (The pin set's name→CID
//! mapping is the designed-for alternate source behind the same recovery
//! endpoint.)
//!
//! A signature attests authorship, never freshness, so the recovery endpoint's
//! record is corroborated rather than believed: the fan-out outranks it whenever
//! it can, and a basis below the sequence this device durably adopted is refused
//! outright (the floor law).

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;

use super::fanout::fanout_get_verify;
use super::publish::{PublishError, PublishOutcome, PublishRequest, head_cid_from_value, publish};
use crate::api::{ApiClient, ApiError};
use crate::gate::floor;
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamError};

/// What to revive: the lapsed name, its node signing key, and the session's
/// known content CIDs to re-register for pinning (empty is valid — a name-only
/// re-mint). The CID to re-point at is recovered from the network, not carried
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
    /// Every reachable source served a record older than the sequence this
    /// device durably adopted for the name — a replay, not a lapse. Reviving
    /// from it would republish superseded content at a fresh sequence and roll
    /// the name back to a state the device itself has already left.
    StaleSource {
        /// The device's durable sequence floor for the name.
        floor: u64,
        /// The freshest sequence any source could produce.
        sequence: u64,
    },
    /// The durable sequence floor could not be read — as fail-closed as
    /// [`PublishError::FloorRead`], and for the same reason.
    FloorRead(SeamError),
    /// The re-mint publish failed.
    Publish(PublishError),
}

/// Revive after a >EOL lapse: recover the last-known record, corroborate it, and
/// republish its CID as a fresh record at a strictly-newer sequence.
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
    let recovered = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(request.name))
        .map_err(|_| ReviveError::Unrecoverable)?;

    // The routing set is the canonical plane, so it takes the tie: a same-sequence
    // fork is a designed-for state after an unconfirmed publish retry, and the
    // recovery endpoint must not get to pick which side of one is re-minted.
    let basis = match fanout_get_verify(transport, request.name).await {
        Some((observed, _)) if observed.sequence >= recovered.sequence => observed,
        _ => recovered,
    };

    // A basis below the durable floor is a rolled-back source (the floor law).
    let floor = floor::sequence_floor(floors, request.name.as_str().as_bytes())
        .await
        .map_err(ReviveError::FloorRead)?
        .unwrap_or(0);
    if basis.sequence < floor {
        return Err(ReviveError::StaleSource {
            floor,
            sequence: basis.sequence,
        });
    }

    // The CID rides out of the same record as the sequence, so a corroborated
    // sequence can never re-mint superseded content.
    let head_cid = head_cid_from_value(&basis.value).ok_or(ReviveError::Unrecoverable)?;
    let publish_request = PublishRequest {
        name: request.name,
        signer: request.signer,
        head_cid,
        content_cids: request.content_cids,
        // Strictly newer than what lapsed, even if this device's floor is stale.
        min_current_sequence: Some(basis.sequence),
        // A revival re-mints the lapsed record's own value, whose epoch was
        // barred at the publish that authored it.
        epoch_bar: None,
    };
    publish(transport, api, floors, scheduler, profile, &publish_request)
        .await
        .map(|receipt| receipt.outcome)
        .map_err(ReviveError::Publish)
}
