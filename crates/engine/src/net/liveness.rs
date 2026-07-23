//! The engine's half of the two re-PUT layers (blueprint/engine.md
//! "Resolve/publish pipeline: Liveness", #24 D2/D5).
//!
//! Two jobs keep a session's records alive without depending on the API's
//! background loop (no client resolve path ever touches the API's record cache,
//! #24 D3):
//!
//! - **Keyless re-PUT** ([`keyless_re_put`]): an ~hourly Scheduler job that
//!   re-PUTs every record the session holds, byte-for-byte with no key material
//!   (core's keyless marshal, blueprint/core.md), so actively used vaults keep
//!   themselves alive on endpoints that may have dropped the record.
//! - **Sub-EOL renewal** ([`eol_republish`]): on session start and periodically,
//!   a name with below-threshold EOL remaining is republished at seq+1 through
//!   the normal CAS path with a fresh 90-day EOL.
//!
//! The API republisher (~12 h inventory walk) backstops dormant vaults only.

use core::fmt;
use core::future::Future;
use core::time::Duration;
use std::collections::BTreeMap;

use cipherbox_core::ipns::IpnsRecord;
use zeroize::Zeroizing;

use super::eol::{self, EOL_RENEW_THRESHOLD};
use super::fanout::{fanout_get_verify, fanout_put};
use super::publish::{PublishError, PublishOutcome, PublishRequest, publish};
use crate::api::ApiClient;
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// The ~hourly cadence of the keyless re-PUT job (blueprint: "an ~hourly
/// Scheduler job keyless-re-PUTs every record the session holds").
///
/// Designed-for cadence, not yet a frozen profile constant — like the sweep
/// cadence (blueprint/engine.md "Open edges"), it joins the sync timing profile
/// once measured.
pub const RE_PUT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// One held record to keep alive across both re-PUT layers.
///
/// [`keyless_re_put`] needs only [`routing_key`](Self::routing_key) +
/// [`record_bytes`](Self::record_bytes); the sub-EOL seq+1 renewal (#750)
/// rebuilds a [`PublishRequest`] from the rest. It stores the derivation
/// **inputs**, never a live signer: the per-name signer is re-derived on demand
/// via `SessionIdentity::write_name_signer(write_scope_seed, node_id)` at
/// renewal, so no session key material lingers in the held set
/// (blueprint/engine.md "Liveness").
#[derive(Clone)]
pub struct HeldRecord {
    /// The routing key — the record's `ipnsName`.
    pub routing_key: String,
    /// The signed record bytes (re-PUT verbatim; keyless).
    pub record_bytes: Vec<u8>,
    /// The node id (`id16`) — the held-set key and the write-seed input the
    /// renewal signer re-derives from.
    pub node_id: [u8; 16],
    /// The scope's unsealed write seed — a derivation input, not a signer.
    /// Zeroized on drop and redacted from [`Debug`]; never printed or logged
    /// (security rule 2).
    pub write_scope_seed: Zeroizing<[u8; 32]>,
    /// The head/metadata CID the renewal record points at.
    pub head_cid: String,
    /// The content CIDs to re-register/pin at renewal.
    pub content_cids: Vec<String>,
}

impl fmt::Debug for HeldRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The write seed is secret: redact it, and print record bytes by length
        // only (they are large, not secret).
        f.debug_struct("HeldRecord")
            .field("routing_key", &self.routing_key)
            .field(
                "record_bytes",
                &format_args!("<{} bytes>", self.record_bytes.len()),
            )
            .field("node_id", &self.node_id)
            .field("write_scope_seed", &"<redacted>")
            .field("head_cid", &self.head_cid)
            .field("content_cids", &self.content_cids)
            .finish()
    }
}

/// The session's live held-record set, keyed by node id (`id16`): the resolve
/// path inserts each gate-passing record and the liveness loop re-PUTs the
/// map's values. Keyed by node id so a re-resolve replaces in place and an
/// eviction removes in O(1) — the loop never re-PUTs a stale record
/// (blueprint/engine.md "Liveness"). `BTreeMap` for a deterministic iteration
/// order across platforms.
pub type HeldRecords = BTreeMap<[u8; 16], HeldRecord>;

/// The result of re-PUTting one held record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RePutResult {
    /// The routing key re-PUT.
    pub routing_key: String,
    /// Whether at least one endpoint acknowledged (the record stays alive).
    pub kept_alive: bool,
}

/// Run one pass of the keyless re-PUT job over the records the session holds:
/// re-PUT each byte-for-byte to the endpoint set. Keyless — no signing key is
/// touched; a malformed held record (which cannot round-trip core's byte-stable
/// marshal) is skipped rather than re-PUT.
///
/// This is the job **body**; the ~hourly [`Scheduler`] loop that drives it at
/// [`RE_PUT_INTERVAL`] is wired by the facade.
pub async fn keyless_re_put<T: RecordTransport>(
    transport: &T,
    held: &[HeldRecord],
) -> Vec<RePutResult> {
    let mut results = Vec::with_capacity(held.len());
    for record in held {
        // Byte-stable keyless re-PUT (blueprint/core.md): a record that does not
        // round-trip marshal is not a record we can keep alive — skip it.
        let bytes = match IpnsRecord::unmarshal(&record.record_bytes) {
            Ok(parsed) => parsed.marshal(),
            Err(_) => {
                results.push(RePutResult {
                    routing_key: record.routing_key.clone(),
                    kept_alive: false,
                });
                continue;
            }
        };
        let fanout = fanout_put(transport, &record.routing_key, &bytes).await;
        results.push(RePutResult {
            routing_key: record.routing_key.clone(),
            kept_alive: fanout.any_acked(),
        });
    }
    results
}

/// Whether the liveness loop keeps running after a pass (mirrors
/// [`TickControl`](crate::sync::TickControl) for the sync tick loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessControl {
    /// Run the next pass after the interval.
    Continue,
    /// Stop the loop (session end / logout).
    Stop,
}

/// Drive a liveness pass on a fixed cadence off the injected [`Scheduler`]
/// clock: sleep `interval`, run `pass`, repeat until it returns
/// [`LivenessControl::Stop`]. This is the ~hourly loop the facade spawns at
/// [`RE_PUT_INTERVAL`] over [`keyless_re_put`] (and, once cold-start derives the
/// per-name signers, the sub-EOL [`eol_republish`] renewal composes into the
/// same `pass`). Determinism law: the only time source is `scheduler.sleep`.
pub async fn run_liveness_loop<Sch, F, Fut>(scheduler: &Sch, interval: Duration, mut pass: F)
where
    Sch: Scheduler,
    F: FnMut() -> Fut,
    Fut: Future<Output = LivenessControl>,
{
    loop {
        scheduler.sleep(interval).await;
        if pass().await == LivenessControl::Stop {
            break;
        }
    }
}

/// Republish `request`'s name at seq+1 with a fresh 90-day EOL **iff** its
/// current record is still live but within the renewal window
/// ([`EOL_RENEW_THRESHOLD`]). Returns `Ok(None)` when the record's EOL is
/// comfortably ahead (no renewal needed) or when no current record can be
/// resolved to inspect. A lapsed record is out of scope here — that is revival.
pub async fn eol_republish<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: &PublishRequest<'_>,
) -> Result<Option<PublishOutcome>, PublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    // Inspect the name's current record EOL against the injected clock.
    let Some((_sequence, bytes)) = fanout_get_verify(transport, request.name).await else {
        return Ok(None);
    };
    let Ok(record) = IpnsRecord::unmarshal(&bytes) else {
        return Ok(None);
    };
    let Ok(verified) = record.verify(request.name) else {
        return Ok(None);
    };
    if !eol::needs_renewal(scheduler.now(), &verified.validity, EOL_RENEW_THRESHOLD) {
        return Ok(None);
    }

    // Republish the same content at seq+1 (floor + 1) with a fresh EOL.
    publish(transport, api, floors, scheduler, profile, request)
        .await
        .map(Some)
}
