//! The publish pipeline: register-first, core-signed, parallel PUT with
//! any-ack success + background retry, and confirm-by-re-resolve
//! (blueprint/engine.md "Resolve/publish pipeline: Publish", #23 D3/D4,
//! #34 D2, #24 D6).
//!
//! Register-first is built into the pipeline, not left to callers (#28 D5):
//! the API registration precedes the record PUT and publish blocks on it, so
//! an unregistered name never reaches the transport (fail-closed). Core signs
//! (first publish embeds sequence 1; a CAS publish embeds the exact expected
//! sequence = durable floor + 1), then a parallel PUT fans out to every
//! endpoint — success is the first ack, the rest retry in the background — and
//! a confirm-by-re-resolve detects a lost CAS race for the caller to rebase.

use core::time::Duration;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;

use super::eol;
use super::fanout::{fanout_get_verify, fanout_put};
use super::register::register;
use crate::api::{ApiClient, ApiError, NameRegistration};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    CredentialStore, EndpointId, FloorStore, Http, RecordTransport, Scheduler, SeamError,
};

/// The `/ipfs/` path prefix a record's `Value` carries in front of the head CID.
const IPFS_PREFIX: &str = "/ipfs/";

/// Bounded background re-PUT attempts for endpoints that missed the first ack.
/// Liveness is backstopped by the ~hourly keyless re-PUT job and the API
/// republisher, so this loop stays short — it closes the common transient gap,
/// not a durability guarantee.
const MAX_REPUT_ATTEMPTS: u32 = 3;

/// One publish request: the name and its node signing key, the head (metadata)
/// CID to point at, and the content CIDs to register for pinning.
pub struct PublishRequest<'a> {
    /// The IPNS name being published (its Ed25519 key is [`Self::signer`]'s).
    pub name: &'a IpnsName,
    /// The node's Ed25519 signing key (derived in the key-lifecycle slice;
    /// injected here so this slice owns no key derivation).
    pub signer: &'a Ed25519Signer,
    /// The head/metadata CID this record points at (`Value = /ipfs/<head_cid>`).
    pub head_cid: String,
    /// The content CIDs to register/pin under this name.
    pub content_cids: Vec<String>,
    /// Raises the CAS expected-current sequence to at least this value before
    /// the +1. Normal writes pass `None` and derive it from the durable floor;
    /// revival passes the sequence recovered from the last-known record so the
    /// re-minted record is strictly newer than what lapsed.
    pub min_current_sequence: Option<u64>,
}

impl PublishRequest<'_> {
    /// The record `Value` bytes: `/ipfs/<head_cid>`.
    fn value(&self) -> Vec<u8> {
        format!("{IPFS_PREFIX}{}", self.head_cid).into_bytes()
    }

    /// The single-item registration batch for this publish (ordinary writes
    /// register one name; name waves and sweeps batch — that is the caller's
    /// concern, blueprint/engine.md). [`register`] carries the registry's batch
    /// bounds, so a version past the per-entry cap splits there.
    fn registration(&self) -> NameRegistration {
        NameRegistration {
            ipns_name: self.name.as_str().to_owned(),
            head_cid: Some(self.head_cid.clone()),
            content_cids: self.content_cids.clone(),
        }
    }
}

/// The result of a completed publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The record landed and confirm-by-re-resolve saw it as the freshest
    /// record at the name.
    Published {
        /// The sequence embedded in the published record.
        sequence: u64,
    },
    /// The PUT was acknowledged but confirm-by-re-resolve did not read **our**
    /// bytes back at our sequence: nothing resolvable, a stale lower sequence,
    /// or different bytes at the same sequence (a fork from a retry that
    /// re-authored after an earlier unconfirmed PUT). Availability, never a
    /// trust verdict.
    /// Retrying is idempotent-in-sequence — the caller must not adopt these
    /// bytes, so the sequence floor stays put and a re-publish re-mints the
    /// same sequence.
    Unconfirmed {
        /// The sequence embedded in the published record.
        sequence: u64,
    },
    /// A concurrent writer's record at a strictly higher sequence was observed
    /// on the confirm re-resolve: a lost CAS race. The caller re-resolves and
    /// rebases (rebase is a later slice; this slice only reports the race).
    LostRace {
        /// The sequence this publish embedded.
        published_sequence: u64,
        /// The higher sequence a concurrent writer landed first.
        observed_sequence: u64,
    },
}

/// A completed publish: the outcome plus the signed record bytes that were PUT,
/// so a caller can feed its own record back through the adoption gate without a
/// re-fetch (the write path's self-adopt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReceipt {
    /// The confirm-by-re-resolve verdict.
    pub outcome: PublishOutcome,
    /// The signed record bytes this publish PUT.
    pub record_bytes: Vec<u8>,
}

/// A fail-closed publish failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// Register-first failed: the API rejected (or could not reach) the
    /// registration, so no record was PUT — the fail-closed ordering law.
    Register(ApiError),
    /// No endpoint acknowledged the record PUT (the whole endpoint set is
    /// unreachable). Nothing durable happened; the caller retries later.
    AllEndpointsFailed,
    /// The durable sequence floor could not be read. A floor-read failure is a
    /// fail-closed trust event, never "no floor": publish stops rather than mint
    /// a sequence from assumed-empty state (blueprint/engine.md floor law).
    FloorRead(SeamError),
    /// The request carried an empty head CID, which would sign `/ipfs/` — a
    /// value the decode side ([`head_cid_from_value`]) always rejects. Refused
    /// release-active so no path can ever PUT an unopenable pointer (security
    /// rule 8; encode/decode fail-closed symmetry).
    EmptyHeadCid,
}

/// Run the publish pipeline for `request`. Register-first and fail-closed:
/// on a registration failure nothing is PUT.
pub async fn publish<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: &PublishRequest<'_>,
) -> Result<PublishReceipt, PublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    // Encode/decode fail-closed symmetry (security rule 8): head_cid_from_value
    // rejects an empty CID, so refuse to sign+PUT `/ipfs/` here — release-active,
    // never a debug_assert stripped in release.
    if request.head_cid.is_empty() {
        return Err(PublishError::EmptyHeadCid);
    }

    // Register-first, fail-closed: the record never reaches the transport unless
    // the registration succeeds (#24 D6 / #34 D2).
    register(api, std::slice::from_ref(&request.registration()))
        .await
        .map_err(PublishError::Register)?;

    // CAS expected sequence: floor + 1 (first publish → 1, the "no floor" 0
    // sentinel reserved). Revival raises the floor read to the recovered
    // sequence so the re-mint is strictly newer than what lapsed. A floor-read
    // failure is fail-closed — only a successful read with no floor defaults to
    // 0 (blueprint/engine.md floor law).
    let name_bytes = request.name.as_str().as_bytes();
    let durable = floors
        .sequence_floor(name_bytes)
        .await
        .map_err(PublishError::FloorRead)?
        .unwrap_or(0);
    let sequence = durable.max(request.min_current_sequence.unwrap_or(0)) + 1;

    // Core signs; the engine injects the explicit TTL (from the profile, never a
    // library default) and the 90-day client-signed EOL (from the injected clock).
    let ttl_nanos = u64::try_from(profile.record_ttl.as_nanos()).unwrap_or(u64::MAX);
    let eol = eol::eol_from(scheduler.now());
    let record_bytes =
        IpnsRecord::create_v2(request.signer, &request.value(), sequence, ttl_nanos, &eol)
            .marshal();

    // Parallel PUT: success is the first ack; the rest retry in the background.
    let key = request.name.as_str();
    let fanout = fanout_put(transport, key, &record_bytes).await;
    if !fanout.any_acked() {
        return Err(PublishError::AllEndpointsFailed);
    }
    if !fanout.not_acked.is_empty() {
        spawn_background_reput(
            transport.clone(),
            scheduler.clone(),
            key.to_owned(),
            record_bytes.clone(),
            fanout.not_acked,
            profile.poll_cadence,
        );
    }

    // Confirm by re-resolve: a strictly higher record means a concurrent writer
    // won the CAS race; observing nothing at all confirms nothing, so it must
    // not report success (that arm is how an acked-but-unresolvable publish used
    // to pass for `Published`).
    let observed = fanout_get_verify(transport, request.name).await;
    let outcome = match observed {
        // `fanout_get_verify` reports the freshest record across the endpoint
        // set. Only our own bytes prove a readable endpoint holds *our* record:
        // a different record at the same sequence is a fork — a retry that
        // re-authored after an unconfirmed PUT — and adopting it would advance
        // the floor past bytes the network may never serve.
        Some((observed_sequence, bytes)) if observed_sequence == sequence => {
            if bytes == record_bytes {
                PublishOutcome::Published { sequence }
            } else {
                PublishOutcome::Unconfirmed { sequence }
            }
        }
        Some((observed_sequence, _)) if observed_sequence > sequence => PublishOutcome::LostRace {
            published_sequence: sequence,
            observed_sequence,
        },
        _ => PublishOutcome::Unconfirmed { sequence },
    };
    Ok(PublishReceipt {
        outcome,
        record_bytes,
    })
}

/// Spawn the background re-PUT for endpoints that missed the first ack: sleep a
/// poll cadence, re-PUT the still-missing endpoints (idempotent), repeat up to
/// [`MAX_REPUT_ATTEMPTS`]. Fire-and-forget on the [`Scheduler`] — the publish
/// already succeeded on the first ack.
fn spawn_background_reput<T, Sch>(
    transport: T,
    scheduler: Sch,
    key: String,
    record_bytes: Vec<u8>,
    mut remaining: Vec<EndpointId>,
    retry_delay: Duration,
) where
    T: RecordTransport + 'static,
    Sch: Scheduler + Clone + 'static,
{
    let task_scheduler = scheduler.clone();
    scheduler.spawn(Box::pin(async move {
        for _ in 0..MAX_REPUT_ATTEMPTS {
            if remaining.is_empty() {
                return;
            }
            task_scheduler.sleep(retry_delay).await;
            let mut still_missing = Vec::new();
            for endpoint in remaining {
                if transport
                    .put_record(&endpoint, &key, &record_bytes)
                    .await
                    .is_err()
                {
                    still_missing.push(endpoint);
                }
            }
            remaining = still_missing;
        }
    }));
}

/// Extract the head CID from a record `Value` (`/ipfs/<cid>`). `None` when the
/// value is not an `/ipfs/` path — a malformed record, handled fail-closed by
/// the caller.
pub(super) fn head_cid_from_value(value: &[u8]) -> Option<String> {
    core::str::from_utf8(value)
        .ok()?
        .strip_prefix(IPFS_PREFIX)
        .filter(|cid| !cid.is_empty())
        .map(str::to_owned)
}
