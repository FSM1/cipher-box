//! The engine's half of the two re-PUT layers (blueprint/engine.md
//! "Resolve/publish pipeline: Liveness", #24 D2/D5).
//!
//! Two jobs keep a session's records alive without depending on the API's
//! background loop (no client resolve path ever touches the API's record cache,
//! #24 D3):
//!
//! - **Keyless re-PUT** ([`keyless_re_put`]): an ~hourly Scheduler job that
//!   resolves every record the session holds and re-PUTs the freshest of the
//!   held and the live copy, byte-for-byte with no key material (core's keyless
//!   marshal, blueprint/core.md), so actively used vaults keep themselves alive
//!   on endpoints that may have dropped the record.
//! - **Sub-EOL renewal** ([`eol_renew_pass`]): on session start and hourly,
//!   a name with below-threshold EOL remaining is republished at seq+1 through
//!   the renewal walk's signature path with a fresh EOL.
//!
//! The renewal walk ([`super::renewal_walk`]) renews every other name of the
//! vault. The API republisher (~12 h inventory walk) re-PUTs the same bytes and
//! backstops dormant vaults only.

use core::cell::RefCell;
use core::fmt;
use core::future::Future;
use core::time::Duration;
use std::collections::BTreeMap;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;

use super::eol::{self, EOL_RENEW_THRESHOLD};
use super::fanout::{FanoutRecord, fanout_get_classified, fanout_get_verify, fanout_put};
use super::publish::{
    Observed, PublishBar, PublishError, PublishOutcome, PublishReceipt, PublishRequest, publish,
};
use super::register::register;
use super::renewal_walk::{FloorRule, RenewalSeams, renew_admitted};
use crate::api::{ApiClient, NameRegistration};
use crate::grants::grafted::FloorNamespace;
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// The ~hourly cadence of the keyless re-PUT job (blueprint: "an ~hourly
/// Scheduler job keyless-re-PUTs every record the session holds").
///
/// Designed-for cadence, not yet a frozen profile constant; it joins
/// [`SyncTimingProfile`] once measured, as the sweep cadence already has.
pub const RE_PUT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The `Value` a held record's sub-EOL renewal re-signs.
///
/// The two record shapes the publish pipeline mints: an `/ipfs/` head pointer
/// ([`publish`]) and an inline payload ([`publish_inline`]). A held record
/// carries the shape its own plane publishes under, so the renewal re-signs the
/// same `Value` the record already serves.
#[derive(Clone, PartialEq, Eq)]
pub enum HeldValue {
    /// The head/metadata CID the renewal record points at. Never empty: an
    /// empty CID encodes `/ipfs/`, which the decode side always rejects
    /// (security rule 8).
    Head(String),
    /// The sealed block the record carries in its `Value` itself — the pointer
    /// plane's shape ([`RecordPointerFetch`](super::pointer_fetch::RecordPointerFetch)).
    Inline(Vec<u8>),
}

impl HeldValue {
    /// The record `Value` bytes this shape publishes under.
    pub fn record_value(&self) -> Vec<u8> {
        match self {
            HeldValue::Head(cid) => format!("/ipfs/{cid}").into_bytes(),
            HeldValue::Inline(block) => block.clone(),
        }
    }
}

impl fmt::Debug for HeldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeldValue::Head(cid) => f.debug_tuple("Head").field(cid).finish(),
            // The sealed block is large; print it by length only.
            HeldValue::Inline(block) => f
                .debug_tuple("Inline")
                .field(&format_args!("<{} bytes>", block.len()))
                .finish(),
        }
    }
}

/// One held record to keep alive across both re-PUT layers.
///
/// [`keyless_re_put`] needs only [`routing_key`](Self::routing_key) +
/// [`record_bytes`](Self::record_bytes); the sub-EOL seq+1 renewal rebuilds a
/// publish request from the rest. It stores the **narrow per-name signer**
/// the renewal signs with — not the scope's write seed, which would
/// derive the full write plane (content + IPNS) for every node in the scope
/// (least privilege; security rules 2 and 5). The signer is derived once at
/// insert from the scope seed + node id (see `HeldMaterial`) and the seed is
/// dropped there — it never lingers in the held set (blueprint/engine.md
/// "Liveness").
#[derive(Clone)]
pub struct HeldRecord {
    /// The routing key — the record's `ipnsName`.
    pub routing_key: String,
    /// The signed record bytes (re-PUT verbatim; keyless).
    pub record_bytes: Vec<u8>,
    /// The per-name IPNS signer the sub-EOL seq+1 renewal signs with. Zeroizes
    /// on drop and its `Debug` is redacted; never printed or logged (security
    /// rule 2).
    pub signer: Ed25519Signer,
    /// The `Value` the renewal re-signs.
    pub value: HeldValue,
    /// The content CIDs to re-register/pin at renewal.
    pub content_cids: Vec<String>,
    /// The envelope of a node record, which its renewal is gated on. `None`
    /// for a plane whose record carries no envelope.
    pub envelope: Option<HeldEnvelope>,
}

/// What a held node record's envelope binds: the renewal refuses a version this
/// build does not author, and signs under the scope bar, as the renewal walk
/// does (ADR 0061 D3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HeldEnvelope {
    /// The envelope version the record carries.
    pub version: u64,
    /// The floors the record's renewal must clear at its signature.
    pub bar: PublishBar,
    /// The namespace the bar's epoch floors ratchet in: a granted scope's
    /// floors sit under its sharer's label.
    pub(crate) namespace: FloorNamespace,
}

impl fmt::Debug for HeldEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The namespace label is a cross-scope correlator, so it is not printed.
        f.debug_struct("HeldEnvelope")
            .field("version", &self.version)
            .field("bar", &self.bar)
            .finish_non_exhaustive()
    }
}

impl HeldRecord {
    /// The head CID this record points at, or `None` for an inline-value plane.
    pub fn head_cid(&self) -> Option<&str> {
        match &self.value {
            HeldValue::Head(cid) => Some(cid.as_str()),
            HeldValue::Inline(_) => None,
        }
    }
}

impl fmt::Debug for HeldRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The signer redacts itself in Debug; print record bytes by length only
        // (they are large, not secret).
        f.debug_struct("HeldRecord")
            .field("routing_key", &self.routing_key)
            .field(
                "record_bytes",
                &format_args!("<{} bytes>", self.record_bytes.len()),
            )
            .field("signer", &self.signer)
            .field("value", &self.value)
            .field("content_cids", &self.content_cids)
            .field("envelope", &self.envelope)
            .finish()
    }
}

/// The held set's key: which record plane an entry lives in, and — for the two
/// planes that hold many — which 16-byte id inside it.
///
/// A scope root's node id **is** its scope id (`grants/create.rs`), so an id on
/// its own cannot separate a root's own record from that scope's pointer: one
/// would evict the other in the held set, and the survivor would decide which
/// of the two names the liveness loop keeps alive. The plane separates them.
///
/// The two account-level planes carry no id: an account has one vault settings
/// record and one bin index, each at a name derived from the login secret
/// alone. They are keyed here rather than in slots of their own, so the renewal
/// set is one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeldKey {
    /// A node's own record, keyed by its node id (`id16`).
    Node([u8; 16]),
    /// A scope's canonical re-point pointer, keyed by its scope id
    /// (`sync/pointer.rs::scope_pointer_name`).
    ScopePointer([u8; 16]),
    /// The account's vault settings record (`settings::settings_name`).
    VaultSettings,
    /// The account's bin index record (`bin_index::BinIndexKeys`).
    BinIndex,
}

impl HeldKey {
    /// Whether the resolve tick replaces this plane's entries in place, which is
    /// what keeps a renewal off a stale record.
    ///
    /// The planes it does not refresh need [`drop_superseded`] ahead of every
    /// renewal pass: a renewal re-signs at `floor + 1` with a fresh validity, so
    /// re-signing a record another device superseded wins record selection and
    /// rolls that name back to the body this session published.
    #[must_use]
    pub fn refreshed_by_resolve(&self) -> bool {
        matches!(self, HeldKey::Node(_))
    }
}

/// The record bytes the set holds at `key`. Read before a load begins, and
/// handed back to [`hold_if_unchanged`] when it ends.
#[must_use]
pub fn observed_at(held: &RefCell<HeldRecords>, key: HeldKey) -> Option<Vec<u8>> {
    held.borrow()
        .get(&key)
        .map(|record| record.record_bytes.clone())
}

/// Put `record` at `key`, but only while the set still holds `observed` there.
///
/// `observed` is the record bytes the key held when the load that produced
/// `record` began. A save that landed across that load installed its own
/// confirmed record, and the renewal re-signs at `floor + 1`: writing this
/// pass's older read back over it would win record selection and roll the name
/// back to the body the save replaced.
pub fn hold_if_unchanged(
    held: &RefCell<HeldRecords>,
    key: HeldKey,
    record: HeldRecord,
    observed: Option<&[u8]>,
) {
    let mut held = held.borrow_mut();
    if held
        .get(&key)
        .map(|current| current.record_bytes.as_slice())
        == observed
    {
        held.insert(key, record);
    }
}

/// The session's live held-record set, keyed by [`HeldKey`]: the liveness loop
/// re-PUTs the map's values on the hourly cadence (blueprint/engine.md
/// "Liveness"). `BTreeMap` for a deterministic iteration order across platforms.
///
/// **What enters the set**, and nothing else does:
///
/// - the **vault root**, from the resolve tick's gate-passing resolve
///   (`resolve::resolve_and_hold`) — the only record a resolve ever holds, so a
///   child this session did not itself publish never enters;
/// - **any node this session published**, from the drain's confirmed publish
///   (`sync::drain`);
/// - an **owned scope pointer**, from a confirmed mint or re-point flip and from
///   the hourly re-enrolment (`net::rotation`) — a grantee derives neither that
///   name nor its signer, so it holds no pointer;
/// - the **vault settings record** and the **bin index**, from their loads and
///   their confirmed publishes.
///
/// The set is session memory: it starts empty, is never persisted, and is
/// cleared at teardown, so a session keeps alive only what it proved current
/// itself. Every other name of the vault renews through the renewal walk
/// ([`super::renewal_walk`], ADR 0061), which holds nothing here.
pub type HeldRecords = BTreeMap<HeldKey, HeldRecord>;

/// Drop every held record whose plane no longer serves it, across every plane
/// the resolve tick does not refresh ([`HeldKey::refreshed_by_resolve`]).
///
/// Only a positively observed *different* record supersedes: a plane this pass
/// cannot read is availability, and the renewal itself refuses to renew what it
/// cannot resolve.
pub async fn drop_superseded<R: RecordTransport>(transport: &R, held: &RefCell<HeldRecords>) {
    let unrefreshed: Vec<(HeldKey, HeldRecord)> = held
        .borrow()
        .iter()
        .filter(|(key, _)| !key.refreshed_by_resolve())
        .map(|(key, record)| (*key, record.clone()))
        .collect();
    for (key, record) in unrefreshed {
        let Ok(name) = IpnsName::parse(&record.routing_key) else {
            continue;
        };
        let Some((live, _)) = fanout_get_verify(transport, &name).await else {
            continue;
        };
        if live.value == record.value.record_value() {
            continue;
        }
        // The verdict names the record this pass read: a publish that landed
        // across the fetch installed its own confirmed entry, and dropping that
        // one would take the fresh record out of the renewal.
        let mut held = held.borrow_mut();
        if held
            .get(&key)
            .is_some_and(|current| current.record_bytes == record.record_bytes)
        {
            held.remove(&key);
        }
    }
}

/// The result of re-PUTting one held record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RePutResult {
    /// The routing key re-PUT.
    pub routing_key: String,
    /// Whether at least one endpoint acknowledged (the record stays alive).
    pub kept_alive: bool,
}

/// Run one pass of the keyless re-PUT job over the records the session holds:
/// resolve each name, then re-PUT the freshest record of the two — the network
/// copy when its sequence is strictly higher than the held one, else the held
/// copy. Keyless throughout: no signing key is touched and the bytes go back
/// byte-for-byte through core's marshal (blueprint/core.md).
///
/// A held record ages between the pass that installed it and this one, so
/// without the resolve a device that has not re-resolved the name re-PUTs a
/// sequence below the live one — which a validating endpoint refuses and a
/// non-validating endpoint accepts as a rollback.
///
/// Both non-`Found` answers keep the held record: neither an absent name nor an
/// unavailable endpoint set is evidence that the held record is stale
/// ([`FanoutRecord`]). A record that does not verify under its own routing key
/// is skipped rather than re-PUT — the produce side refuses what the resolve
/// side rejects (security rule 8).
///
/// This is the job **body**; the ~hourly [`Scheduler`] loop that drives it at
/// [`RE_PUT_INTERVAL`] is wired by the facade.
pub async fn keyless_re_put<T: RecordTransport>(
    transport: &T,
    held: &[HeldRecord],
) -> Vec<RePutResult> {
    let mut results = Vec::with_capacity(held.len());
    for record in held {
        let unusable = RePutResult {
            routing_key: record.routing_key.clone(),
            kept_alive: false,
        };
        let (Ok(name), Ok(parsed)) = (
            IpnsName::parse(&record.routing_key),
            IpnsRecord::unmarshal(&record.record_bytes),
        ) else {
            results.push(unusable);
            continue;
        };
        let Ok(mine) = parsed.verify(&name) else {
            results.push(unusable);
            continue;
        };
        let mut bytes = parsed.marshal();
        if let FanoutRecord::Found(live, live_bytes) = fanout_get_classified(transport, &name).await
        {
            if live.sequence > mine.sequence {
                bytes = live_bytes;
            }
        }
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
    /// Run the next pass after this delay instead of the interval.
    ContinueAfter(Duration),
    /// Stop the loop (session end / logout).
    Stop,
}

/// Drive a liveness pass on a fixed cadence off the injected [`Scheduler`]
/// clock: run `pass` immediately, then sleep `interval` between passes until
/// [`LivenessControl::Stop`]. This is the ~hourly loop the facade spawns at
/// [`RE_PUT_INTERVAL`] over [`keyless_re_put`]. Determinism law: the only time
/// source is `scheduler.sleep`.
pub async fn run_liveness_loop<Sch, F, Fut>(scheduler: &Sch, interval: Duration, mut pass: F)
where
    Sch: Scheduler,
    F: FnMut() -> Fut,
    Fut: Future<Output = LivenessControl>,
{
    loop {
        let delay = match pass().await {
            LivenessControl::Stop => break,
            LivenessControl::Continue => interval,
            LivenessControl::ContinueAfter(delay) => delay,
        };
        scheduler.sleep(delay).await;
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
    let Some((verified, _bytes)) = fanout_get_verify(transport, request.observed.name()).await
    else {
        return Ok(None);
    };
    if !eol::needs_renewal(scheduler.now(), &verified.validity, EOL_RENEW_THRESHOLD) {
        return Ok(None);
    }

    // Republish the same content at seq+1 (floor + 1) with a fresh EOL.
    publish(transport, api, floors, scheduler, profile, request)
        .await
        .map(|receipt| Some(receipt.outcome))
}

/// Renew one due held record through the renewal walk's signature path (ADR
/// 0061 D3 steps 3 to 6), while the network serves exactly that record. A
/// node record's [`HeldEnvelope`] also refuses a foreign version once the
/// record is due, and signs under the scope bar. `Ok(None)` when the drain is
/// publishing the name, when the record is not due, when the network serves
/// another record, or when the durable floor moved. The flag beside the
/// receipt says whether the held entry may follow the renewal.
async fn renew_held<T, H, C, F, Sch>(
    api: &ApiClient<H, C>,
    seams: &RenewalSeams<'_, T, F, Sch>,
    name: &IpnsName,
    held: &HeldRecord,
) -> Result<Option<(PublishReceipt, bool)>, PublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    // The drain's publish confirms its own record; a renewal now would sign
    // over it with the held value.
    if seams.publishing.borrow().contains(&held.routing_key) {
        return Ok(None);
    }
    let Some(admitted) = super::fork::verified(name, &held.record_bytes) else {
        return Ok(None);
    };
    if admitted.value != held.value.record_value()
        || !eol::needs_renewal(
            seams.scheduler.now(),
            &admitted.validity,
            EOL_RENEW_THRESHOLD,
        )
    {
        return Ok(None);
    }
    // Only the record the device admitted renews (ADR 0061 D3 step 4).
    match fanout_get_verify(seams.transport, name).await {
        Some((_, served)) if served == held.record_bytes => {}
        _ => return Ok(None),
    }
    let rule = match held.value {
        HeldValue::Head(_) => FloorRule::Exact,
        HeldValue::Inline(_) => FloorRule::AtMost,
    };
    let (observed, namespace, bar) = match held.envelope {
        Some(envelope) => (
            Observed::gated(
                name,
                admitted.sequence,
                envelope.version,
                &held.record_bytes,
            )?,
            envelope.namespace,
            Some(envelope.bar),
        ),
        None => (
            Observed::admitted(name, admitted.sequence, &held.record_bytes),
            FloorNamespace::Own,
            None,
        ),
    };
    register(
        api,
        &[NameRegistration {
            ipns_name: name.as_str().to_owned(),
            head_cid: held.head_cid().map(str::to_owned),
            content_cids: held.content_cids.clone(),
        }],
    )
    .await
    .map_err(PublishError::Register)?;
    let floors = namespace.view(seams.floors);
    let seams = RenewalSeams {
        transport: seams.transport,
        floors: &floors,
        scheduler: seams.scheduler,
        profile: seams.profile,
        publishing: seams.publishing,
    };
    let Some(receipt) =
        renew_admitted(&seams, &observed, bar, rule, &held.signer, &admitted.value).await
    else {
        return Ok(None);
    };
    let receipt = receipt?;
    // This device authored the renewal from the admitted value, so the next
    // pass renews from it under the same exact-floor rule. A floor that did
    // not reach the renewal keeps the held entry at the record it renewed: the
    // next pass then finds another pick and signs nothing, and the next
    // adoption through the gate raises the floor.
    let follow = match (&receipt.outcome, rule) {
        (PublishOutcome::Published { sequence }, FloorRule::Exact) => {
            floors
                .raise_sequence_floor(name.as_str().as_bytes(), *sequence)
                .await
                == Ok(*sequence)
        }
        (outcome, _) => matches!(outcome, PublishOutcome::Published { .. }),
    };
    Ok(Some((receipt, follow)))
}

/// One held record's sub-EOL renewal outcome.
#[derive(Debug)]
#[must_use = "renewal outcomes carry LostRace/PublishError; surface them when the held set is live"]
pub struct EolRenewResult {
    /// The routing key considered for renewal.
    pub routing_key: String,
    /// `Ok(None)` when the record was comfortably ahead of the threshold (no
    /// renewal), `Ok(Some(_))` on a seq+1 republish (including a reported lost
    /// CAS race), `Err` on a fail-closed publish failure.
    pub outcome: Result<Option<PublishOutcome>, PublishError>,
}

/// Run one sub-EOL renewal pass over the held set: for each record still live
/// but within [`EOL_RENEW_THRESHOLD`], republish the same value at seq+1
/// through [`renew_held`] (blueprint/engine.md "Liveness"), and point the
/// held entry at the renewal while it still holds the record the pass read,
/// so the next pass finds the held record as the pick. A lost race is
/// reported, never silently overwritten.
///
/// This is the renewal-pass **body**; the ~hourly [`Scheduler`] loop that drives
/// it alongside [`keyless_re_put`] is wired by the facade.
#[must_use = "renewal outcomes carry LostRace/PublishError; surface them when the held set is live"]
pub(crate) async fn eol_renew_pass<T, H, C, F, Sch>(
    api: &ApiClient<H, C>,
    seams: &RenewalSeams<'_, T, F, Sch>,
    held: &RefCell<HeldRecords>,
) -> Vec<EolRenewResult>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let records: Vec<(HeldKey, HeldRecord)> = held
        .borrow()
        .iter()
        .map(|(key, record)| (*key, record.clone()))
        .collect();
    let mut results = Vec::with_capacity(records.len());
    for (key, hr) in records {
        // A routing key that no longer parses to its IPNS name is not renewable
        // — skip fail-closed rather than publish under a malformed name.
        let Ok(name) = IpnsName::parse(&hr.routing_key) else {
            continue;
        };
        // The held signer signs for this name by the insert-time bind
        // (`resolve_and_hold` rejects a signer whose derived name is not the
        // routing key), so no signing key is derived in the loop.
        // Belt-and-suspenders (security rule 8): a held record with an empty
        // head CID would encode `/ipfs/` and clobber the tip. The insert-time
        // derivation makes this unreachable; the guard keeps the invariant
        // explicit.
        if hr.head_cid() == Some("") {
            continue;
        }
        let outcome = renew_held(api, seams, &name, &hr).await.map(|renewed| {
            renewed.map(|(receipt, follow)| {
                if follow {
                    hold_if_unchanged(
                        held,
                        key,
                        HeldRecord {
                            record_bytes: receipt.record_bytes,
                            ..hr.clone()
                        },
                        Some(&hr.record_bytes),
                    );
                }
                receipt.outcome
            })
        });
        results.push(EolRenewResult {
            routing_key: hr.routing_key,
            outcome,
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::{
        EolRenewResult, HeldEnvelope, HeldKey, HeldRecord, HeldRecords, HeldValue, eol_renew_pass,
        keyless_re_put,
    };

    use core::cell::RefCell;
    use core::time::Duration;
    use std::collections::BTreeSet;

    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::suite::ed25519::Ed25519Signer;

    use super::super::eol;
    use super::super::fanout::MAX_RECORD_BYTES;
    use super::super::publish::{
        BarFloor, InlineRecordRequest, Observed, PublishBar, PublishError, PublishOutcome,
        PublishRequest, publish, publish_inline,
    };
    use super::super::renewal_walk::RenewalSeams;
    use crate::api::ApiClient;
    use crate::grants::grafted::FloorNamespace;
    use crate::net::author::ENVELOPE_V;
    use crate::profile::SyncTimingProfile;
    use crate::seams::{ContactLabel, FloorStore, HttpResponse, RecordTransport, UnixMillis};
    use crate::session::SessionIdentity;
    use crate::testkit::{FakeDevice, FakeWorld, block_on};

    const DAY: u64 = 24 * 60 * 60;
    const TTL_NANOS: u64 = 2_000_000_000;

    /// A held record carrying the per-name signer derived from
    /// `(write_scope_seed, node_id)` and a record minted at `mint_millis` with a
    /// 90-day EOL.
    fn seeded_held(
        device: &FakeDevice,
        write_scope_seed: [u8; 32],
        node_id: [u8; 16],
        head_cid: &str,
        mint_millis: u64,
    ) -> (IpnsName, HeldRecord) {
        let signer: Ed25519Signer = SessionIdentity::write_name_signer(&write_scope_seed, &node_id);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let value = format!("/ipfs/{head_cid}").into_bytes();
        let validity = eol::eol_from(UnixMillis(mint_millis));
        let bytes = IpnsRecord::create_v2(&signer, &value, 1, TTL_NANOS, &validity).marshal();
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), bytes.clone());
        }
        // Model the gate's job: the durable floor sits at the adopted sequence.
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 1),
        )
        .unwrap();
        let held = HeldRecord {
            routing_key: name.as_str().to_owned(),
            record_bytes: bytes,
            signer,
            value: HeldValue::Head(head_cid.to_owned()),
            content_cids: Vec::new(),
            envelope: None,
        };
        (name, held)
    }

    /// An inline-plane held record — the scope pointer's shape: the record's
    /// `Value` is the sealed block itself, not an `/ipfs/` head.
    fn seeded_inline_held(
        device: &FakeDevice,
        seed: [u8; 32],
        block: &[u8],
        served: &[u8],
        mint_millis: u64,
    ) -> (IpnsName, HeldRecord) {
        let signer = Ed25519Signer::from_seed(seed);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let validity = eol::eol_from(UnixMillis(mint_millis));
        let bytes = IpnsRecord::create_v2(&signer, served, 1, TTL_NANOS, &validity).marshal();
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), bytes.clone());
        }
        let held = HeldRecord {
            routing_key: name.as_str().to_owned(),
            record_bytes: bytes,
            signer,
            value: HeldValue::Inline(block.to_vec()),
            content_cids: Vec::new(),
            envelope: None,
        };
        (name, held)
    }

    fn ok_200() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: Vec::new().into(),
        }
    }

    /// `records` as a held set, each under a node key of its own, in order.
    fn held_set(records: impl IntoIterator<Item = HeldRecord>) -> RefCell<HeldRecords> {
        RefCell::new(
            (0u8..)
                .zip(records)
                .map(|(index, record)| (HeldKey::Node([index; 16]), record))
                .collect(),
        )
    }

    fn outcome_of<'a>(results: &'a [EolRenewResult], name: &IpnsName) -> &'a EolRenewResult {
        results
            .iter()
            .find(|r| r.routing_key == name.as_str())
            .expect("held name has a result")
    }

    #[test]
    fn publish_fails_closed_on_an_empty_head_cid() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone();
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let signer = Ed25519Signer::from_seed([9u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let request = PublishRequest {
            observed: &Observed::unread(&name),
            signer: &signer,
            head_cid: String::new(),
            content_cids: Vec::new(),
            bar: None,
        };
        // Encode/decode fail-closed symmetry (security rule 8): an empty head CID
        // would sign `/ipfs/`, which head_cid_from_value always rejects — so
        // publish refuses release-active, before any registration or PUT.
        let out = block_on(publish(
            &device.record_store,
            &api,
            &device.floor_store,
            &scheduler,
            &SyncTimingProfile::CI,
            &request,
        ));
        assert_eq!(out, Err(PublishError::EmptyHeadCid));
        assert!(
            device.http.requests().is_empty(),
            "an empty head CID never reaches the API",
        );
    }

    /// Release-active, so this assertion fires in a release build too.
    #[test]
    fn publish_inline_fails_closed_on_an_empty_value() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = Ed25519Signer::from_seed([13u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        // Encode/decode fail-closed symmetry (security rule 8): the pointer
        // plane's `open_repoint` rejects empty bytes as a trust violation, so
        // the inline arm refuses before any registration or PUT.
        let out = block_on(publish_inline(
            &device.record_store,
            &api,
            &device.floor_store,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &InlineRecordRequest {
                observed: &Observed::unread(&name),
                signer: &signer,
                value: &[],
            },
        ));
        assert_eq!(out, Err(PublishError::EmptyInlineValue));
        assert!(
            device.http.requests().is_empty(),
            "an empty inline value never reaches the API",
        );
        let endpoint = device.record_store.endpoints()[0].clone();
        assert!(
            device
                .record_store
                .record_at(&endpoint, name.as_str())
                .is_none(),
            "and it never reaches the transport",
        );
    }

    /// Release-active, so this assertion fires in a release build too.
    #[test]
    fn publish_fails_closed_on_a_record_over_the_resolve_cap() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone();
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        device.http.enqueue_response(ok_200()); // register
        let signer = Ed25519Signer::from_seed([11u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let request = PublishRequest {
            observed: &Observed::unread(&name),
            signer: &signer,
            head_cid: "b".repeat(MAX_RECORD_BYTES),
            content_cids: Vec::new(),
            bar: None,
        };
        // Encode/decode fail-closed symmetry (security rule 8): fanout_get_verify
        // skips an over-cap record, so publishing one would mint bytes this
        // client can never re-resolve.
        let out = block_on(publish(
            &device.record_store,
            &api,
            &device.floor_store,
            &scheduler,
            &SyncTimingProfile::CI,
            &request,
        ));
        assert!(
            matches!(out, Err(PublishError::RecordTooLarge { limit, .. }) if limit == MAX_RECORD_BYTES),
            "expected RecordTooLarge, got {out:?}"
        );
        let endpoint = device.record_store.endpoints()[0].clone();
        assert!(
            device
                .record_store
                .record_at(&endpoint, name.as_str())
                .is_none(),
            "an over-cap record never reaches the transport",
        );
    }

    fn seq_at(device: &FakeDevice, name: &IpnsName) -> u64 {
        let endpoint = device.record_store.endpoints()[0].clone();
        let bytes = device
            .record_store
            .record_at(&endpoint, name.as_str())
            .expect("record present");
        IpnsRecord::unmarshal(&bytes)
            .unwrap()
            .verify(name)
            .unwrap()
            .sequence
    }

    #[test]
    fn liveness_renews_a_held_name_before_the_first_sleep() {
        use crate::seams::Scheduler;
        use core::future::Future;
        use core::task::{Context, Poll, Waker};

        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone();
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (name, held) = seeded_held(&device, [1; 32], [2; 16], "bafyhead", 0);
        scheduler.advance(Duration::from_secs(65 * DAY));
        let start = scheduler.now();
        let held = vec![held];
        device.http.enqueue_response(ok_200());
        let profile = SyncTimingProfile::CI;
        let mut task = Box::pin(super::run_liveness_loop(
            &scheduler,
            super::RE_PUT_INTERVAL,
            || async {
                let outcomes = eol_renew_pass(
                    &api,
                    &RenewalSeams {
                        transport: &device.record_store,
                        floors: &device.floor_store,
                        scheduler: &scheduler,
                        profile: &profile,
                        publishing: &Default::default(),
                    },
                    &held_set(held.clone()),
                )
                .await;
                assert!(outcomes.iter().all(|result| result.outcome.is_ok()));
                super::LivenessControl::Continue
            },
        ));
        assert_eq!(
            task.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
        assert_eq!(scheduler.now(), start);
        assert_eq!(seq_at(&device, &name), 2);
        let endpoint = device.record_store.endpoints()[0].clone();
        let bytes = device
            .record_store
            .record_at(&endpoint, name.as_str())
            .unwrap();
        assert_eq!(
            IpnsRecord::unmarshal(&bytes)
                .unwrap()
                .verify(&name)
                .unwrap()
                .validity,
            eol::renewal_eol_from(start).into_bytes(),
        );
    }

    /// A held name inside the renewal threshold, which is the pick, renews over
    /// the other branch of a same-sequence fork that one endpoint serves (ADR
    /// 0066 D3).
    #[test]
    fn a_held_pick_renews_over_the_other_branch_of_a_fork() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (name, held) = due(&world, &device, Arm::Head);
        let held_value = IpnsRecord::unmarshal(&held.record_bytes)
            .unwrap()
            .verify(&name)
            .unwrap()
            .value;
        let other = IpnsRecord::create_v2(
            &held.signer,
            b"/ipfs/bafyother",
            1,
            TTL_NANOS,
            &eol::renewal_eol_from(UnixMillis(0)),
        )
        .marshal();
        let endpoint = device.record_store.endpoints()[1].clone();
        device
            .record_store
            .seed_record(&endpoint, name.as_str(), other);
        device.http.enqueue_response(ok_200());

        let result = renew_one(&world, &device, &RefCell::default(), held);
        assert!(matches!(
            result.outcome,
            Ok(Some(PublishOutcome::Published { sequence: 2 }))
        ));
        let endpoint = device.record_store.endpoints()[0].clone();
        let renewed = IpnsRecord::unmarshal(
            &device
                .record_store
                .record_at(&endpoint, name.as_str())
                .unwrap(),
        )
        .unwrap()
        .verify(&name)
        .unwrap();
        assert_eq!(renewed.sequence, 2);
        assert_eq!(renewed.value, held_value, "the held record's value");
    }

    #[test]
    fn renews_only_the_below_threshold_name_and_runs_beside_keyless() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone(); // virtual clock, now = 0
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let profile = SyncTimingProfile::CI;

        // Two held names, both at seq 1 with a 90-day EOL: one minted at T0
        // (25 days left at T+65d — inside the renewal window) and one minted at
        // T+60d (85 days left at T+65d — comfortably ahead).
        let (below, below_held) = seeded_held(&device, [1u8; 32], [2u8; 16], "bafybelow", 0);
        let (ahead, ahead_held) =
            seeded_held(&device, [3u8; 32], [4u8; 16], "bafyahead", 60 * DAY * 1000);
        let held = vec![below_held, ahead_held];

        // At T0 both records are far from EOL: the pass no-ops for both, proving
        // the renewal decision is driven purely off the injected scheduler clock.
        let at_zero = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &profile,
                publishing: &Default::default(),
            },
            &held_set(held.clone()),
        ));
        assert_eq!(
            outcome_of(&at_zero, &below).outcome.as_ref().unwrap(),
            &None
        );
        assert_eq!(
            outcome_of(&at_zero, &ahead).outcome.as_ref().unwrap(),
            &None
        );

        // Advance the injected clock into the below name's renewal window.
        scheduler.advance(Duration::from_secs(65 * DAY));

        // Keyless re-PUT runs in the same pass and keeps every held record alive.
        let keyless = block_on(keyless_re_put(&device.record_store, &held));
        assert!(
            keyless.iter().all(|r| r.kept_alive),
            "keyless keeps both names alive"
        );

        // The renewal pass then republishes only the near-expiry name at seq+1.
        device.http.enqueue_response(ok_200()); // register-first for the one renewal
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &profile,
                publishing: &Default::default(),
            },
            &held_set(held.clone()),
        ));
        assert_eq!(
            outcome_of(&results, &below).outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 2 }),
            "the near-expiry name is republished at seq+1",
        );
        assert_eq!(
            outcome_of(&results, &ahead).outcome.as_ref().unwrap(),
            &None,
            "the comfortably-ahead name is not renewed",
        );

        // The renewed record is live at seq 2 with a fresh, strictly-later EOL;
        // the ahead name is untouched at seq 1.
        assert_eq!(seq_at(&device, &below), 2);
        let endpoint = device.record_store.endpoints()[0].clone();
        let renewed = device
            .record_store
            .record_at(&endpoint, below.as_str())
            .unwrap();
        let renewed_validity = IpnsRecord::unmarshal(&renewed)
            .unwrap()
            .verify(&below)
            .unwrap()
            .validity;
        assert!(
            renewed_validity > eol::eol_from(UnixMillis(0)).into_bytes(),
            "renewal stamps a fresh, later EOL",
        );
        assert_eq!(seq_at(&device, &ahead), 1);
    }
    #[test]
    fn the_two_planes_hold_one_id_side_by_side() {
        // A scope root's node id IS its scope id, so both planes key on the same
        // 16 bytes; a lookup in one plane never reaches the other's entry.
        let device = FakeWorld::new().device(b"me");
        let id = [7u8; 16];
        let (_, root) = seeded_held(&device, [1u8; 32], id, "bafyroothead", 0);
        let (pointer_name, pointer) =
            seeded_inline_held(&device, [2u8; 32], b"a-repoint", b"a-repoint", 0);

        let mut held = HeldRecords::new();
        held.insert(HeldKey::Node(id), root.clone());
        held.insert(HeldKey::ScopePointer(id), pointer);

        assert_eq!(held.len(), 2, "one id, two planes, two live records");
        assert_eq!(
            held[&HeldKey::Node(id)].routing_key,
            root.routing_key,
            "the node plane still names the scope root",
        );
        assert_eq!(
            held[&HeldKey::ScopePointer(id)].routing_key,
            pointer_name.as_str(),
            "the pointer plane names the pointer",
        );
    }

    #[test]
    fn an_inline_plane_record_renews_its_own_block_before_its_eol() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone(); // virtual clock, now = 0
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let profile = SyncTimingProfile::CI;
        let block = b"a-sealed-repoint-object";
        let (pointer, held) = seeded_inline_held(&device, [5u8; 32], block, block, 0);
        let held = vec![held];

        scheduler.advance(Duration::from_secs(65 * DAY));
        device.http.enqueue_response(ok_200()); // register-first for the renewal
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &profile,
                publishing: &Default::default(),
            },
            &held_set(held.clone()),
        ));

        assert_eq!(
            outcome_of(&results, &pointer).outcome.as_ref().unwrap(),
            &Some(PublishOutcome::Published { sequence: 2 }),
            "the pointer renews at seq+1 over the sequence the network serves",
        );
        let endpoint = device.record_store.endpoints()[0].clone();
        let renewed = IpnsRecord::unmarshal(
            &device
                .record_store
                .record_at(&endpoint, pointer.as_str())
                .expect("the renewed pointer record"),
        )
        .unwrap()
        .verify(&pointer)
        .unwrap();
        assert_eq!(
            renewed.value, block,
            "the renewal re-signs the same sealed block, never an /ipfs/ head",
        );
        assert!(
            renewed.validity > eol::eol_from(UnixMillis(0)).into_bytes(),
            "renewal stamps a fresh, later EOL",
        );
    }

    #[test]
    fn an_inline_plane_record_the_network_superseded_is_never_renewed() {
        // Nothing gates a pointer record, so a re-point another device landed is
        // visible only here. Renewing this session's own stale block at a higher
        // sequence would roll the scope back to a root name that no longer holds.
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let scheduler = world.scheduler.clone();
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (pointer, held) =
            seeded_inline_held(&device, [6u8; 32], b"our-repoint", b"a-newer-repoint", 0);
        let held = vec![held];

        scheduler.advance(Duration::from_secs(65 * DAY));
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &held_set(held.clone()),
        ));

        assert_eq!(
            outcome_of(&results, &pointer).outcome.as_ref().unwrap(),
            &None,
            "a superseded block refuses its own renewal",
        );
        assert!(
            device.http.requests().is_empty(),
            "the refusal lands before register-first, so nothing is signed",
        );
        assert_eq!(
            seq_at(&device, &pointer),
            1,
            "the network record is untouched"
        );
    }

    const SCOPE: [u8; 16] = [0x5c; 16];

    /// A granted scope's floor namespace.
    fn granted() -> FloorNamespace {
        let label_seed = cipherbox_core::kdf::contact_label_seed(&[0x4c; 32]);
        FloorNamespace::GrantedBy(ContactLabel::of(&label_seed, &[0x02; 33]))
    }

    /// One due node record held under `version` and a read-epoch bar of 1 in
    /// `namespace`, whose read-epoch floor is `read_floor`, renewed once.
    fn renew_sealed(version: u64, read_floor: u64) -> (FakeDevice, IpnsName, EolRenewResult) {
        renew_sealed_in(FloorNamespace::Own, version, read_floor)
    }

    fn renew_sealed_in(
        namespace: FloorNamespace,
        version: u64,
        read_floor: u64,
    ) -> (FakeDevice, IpnsName, EolRenewResult) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (name, mut held) = seeded_held(&device, [5u8; 32], [6u8; 16], "bafysealed", 0);
        held.envelope = Some(HeldEnvelope {
            version,
            bar: PublishBar {
                scope_id: SCOPE,
                read_epoch: 1,
                write_epoch: None,
                cut_epoch: None,
            },
            namespace,
        });
        block_on(
            namespace
                .view(&device.floor_store)
                .raise_epoch_floor(&SCOPE, read_floor),
        )
        .unwrap();
        world.scheduler.advance(Duration::from_secs(65 * DAY));
        device.http.enqueue_response(ok_200());
        let mut results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &world.scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &held_set([held]),
        ));
        let result = results.remove(0);
        (device, name, result)
    }

    #[test]
    fn a_held_node_renews_under_its_own_version_and_bar() {
        let (device, name, result) = renew_sealed(ENVELOPE_V, 1);
        assert_eq!(
            result.outcome,
            Ok(Some(PublishOutcome::Published { sequence: 2 }))
        );
        assert_eq!(seq_at(&device, &name), 2);
    }

    #[test]
    fn a_held_node_at_a_foreign_envelope_version_is_refused_and_reported() {
        let (device, name, result) = renew_sealed(ENVELOPE_V + 1, 1);
        assert_eq!(
            result.outcome,
            Err(PublishError::ForeignVersion {
                version: ENVELOPE_V + 1
            })
        );
        assert_eq!(seq_at(&device, &name), 1, "the record is not re-signed");
    }

    #[test]
    fn a_held_node_whose_epoch_floor_rose_above_its_bar_is_refused() {
        let (device, name, result) = renew_sealed(ENVELOPE_V, 2);
        assert_eq!(
            result.outcome,
            Err(PublishError::BelowBar {
                floor: BarFloor::Read,
                at: 2,
                epoch: 1,
            })
        );
        assert_eq!(seq_at(&device, &name), 1, "the record is not re-signed");
    }

    #[test]
    fn a_granted_node_whose_epoch_floor_rose_above_its_bar_is_refused() {
        let (device, name, result) = renew_sealed_in(granted(), ENVELOPE_V, 2);
        assert_eq!(
            result.outcome,
            Err(PublishError::BelowBar {
                floor: BarFloor::Read,
                at: 2,
                epoch: 1,
            })
        );
        assert_eq!(seq_at(&device, &name), 1, "the record is not re-signed");
    }

    #[test]
    fn a_held_node_that_a_newer_write_superseded_is_not_renewed() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (name, mut held) = seeded_held(&device, [5u8; 32], [6u8; 16], "bafyheld", 0);
        held.envelope = Some(HeldEnvelope {
            version: ENVELOPE_V,
            bar: PublishBar {
                scope_id: SCOPE,
                read_epoch: 1,
                write_epoch: None,
                cut_epoch: None,
            },
            namespace: FloorNamespace::Own,
        });
        // Another device wrote at 2; this device's floor and held record stay at 1.
        let newer = IpnsRecord::create_v2(
            &held.signer,
            b"/ipfs/bafynewer",
            2,
            TTL_NANOS,
            &eol::eol_from(UnixMillis(0)),
        )
        .marshal();
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), newer.clone());
        }
        world.scheduler.advance(Duration::from_secs(65 * DAY));
        device.http.enqueue_response(ok_200());
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &world.scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &Default::default(),
            },
            &held_set([held]),
        ));
        assert_eq!(outcome_of(&results, &name).outcome, Ok(None));
        let endpoint = device.record_store.endpoints()[0].clone();
        assert_eq!(
            device.record_store.record_at(&endpoint, name.as_str()),
            Some(newer),
            "the newer write stands"
        );
    }

    /// The three renewal arms of a held record.
    #[derive(Clone, Copy)]
    enum Arm {
        /// A node record under its envelope.
        Sealed,
        /// A head record with no envelope: the settings record, the bin index.
        Head,
        /// A scope pointer.
        Inline,
    }

    /// A due held record of `arm`, with the clock inside its renewal window.
    fn due(world: &FakeWorld, device: &FakeDevice, arm: Arm) -> (IpnsName, HeldRecord) {
        let (name, held) = match arm {
            Arm::Sealed => {
                let (name, mut held) = seeded_held(device, [5u8; 32], [6u8; 16], "bafyheld", 0);
                held.envelope = Some(HeldEnvelope {
                    version: ENVELOPE_V,
                    bar: PublishBar {
                        scope_id: SCOPE,
                        read_epoch: 1,
                        write_epoch: None,
                        cut_epoch: None,
                    },
                    namespace: FloorNamespace::Own,
                });
                (name, held)
            }
            Arm::Head => seeded_held(device, [5u8; 32], [6u8; 16], "bafyheld", 0),
            Arm::Inline => seeded_inline_held(device, [7u8; 32], b"a-repoint", b"a-repoint", 0),
        };
        world.scheduler.advance(Duration::from_secs(65 * DAY));
        (name, held)
    }

    fn renew_one(
        world: &FakeWorld,
        device: &FakeDevice,
        publishing: &RefCell<BTreeSet<String>>,
        held: HeldRecord,
    ) -> EolRenewResult {
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &world.scheduler,
                profile: &SyncTimingProfile::CI,
                publishing,
            },
            &held_set([held]),
        ))
        .remove(0)
    }

    /// Seed `record` on every endpoint when the renewal registers its name.
    fn land_at_the_registration(device: &FakeDevice, name: &IpnsName, record: Vec<u8>) {
        let (store, key) = (device.record_store.clone(), name.as_str().to_owned());
        device.http.enqueue_derived(move |_| {
            for endpoint in store.endpoints() {
                store.seed_record(&endpoint, &key, record.clone());
            }
            Ok(ok_200())
        });
    }

    /// Another writer's record at sequence 2 lands on every endpoint while the
    /// renewal waits for its registration; its floor is not raised yet.
    fn a_write_lands_during_the_registration_and_stands(arm: Arm) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (name, held) = due(&world, &device, arm);
        let landed = IpnsRecord::create_v2(
            &held.signer,
            b"/ipfs/bafylanded",
            2,
            TTL_NANOS,
            &eol::eol_from(UnixMillis(65 * DAY * 1000)),
        )
        .marshal();
        land_at_the_registration(&device, &name, landed.clone());

        let result = renew_one(&world, &device, &RefCell::default(), held);
        assert_eq!(result.outcome, Ok(None));
        let endpoint = device.record_store.endpoints()[0].clone();
        assert_eq!(
            device.record_store.record_at(&endpoint, name.as_str()),
            Some(landed),
            "the landed record stands"
        );
    }

    /// The name's sequence floor rises to 2 while the renewal waits for its
    /// registration.
    fn a_floor_rise_during_the_registration_refuses_the_signature(arm: Arm) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (name, held) = due(&world, &device, arm);
        let (floors, key) = (device.floor_store.clone(), name.as_str().to_owned());
        device.http.enqueue_derived(move |_| {
            block_on(floors.raise_sequence_floor(key.as_bytes(), 2)).unwrap();
            Ok(ok_200())
        });

        let result = renew_one(&world, &device, &RefCell::default(), held);
        assert_eq!(result.outcome, Ok(None));
        assert_eq!(seq_at(&device, &name), 1, "the record is not re-signed");
    }

    #[test]
    fn a_drain_publish_that_lands_during_the_registration_is_never_signed_over() {
        a_write_lands_during_the_registration_and_stands(Arm::Sealed);
    }

    #[test]
    fn a_floor_that_rose_during_the_registration_refuses_the_signature() {
        a_floor_rise_during_the_registration_refuses_the_signature(Arm::Sealed);
    }

    #[test]
    fn a_save_that_lands_during_a_head_renewal_registration_is_never_signed_over() {
        a_write_lands_during_the_registration_and_stands(Arm::Head);
    }

    #[test]
    fn a_floor_that_rose_during_a_head_renewal_registration_refuses_the_signature() {
        a_floor_rise_during_the_registration_refuses_the_signature(Arm::Head);
    }

    #[test]
    fn a_repoint_that_lands_during_a_pointer_renewal_registration_is_never_signed_over() {
        a_write_lands_during_the_registration_and_stands(Arm::Inline);
    }

    #[test]
    fn a_pointer_floor_that_rose_above_the_held_sequence_refuses_the_signature() {
        a_floor_rise_during_the_registration_refuses_the_signature(Arm::Inline);
    }

    /// One endpoint serves another branch at the held sequence with the later
    /// EOL, so the pick is not the held record.
    fn a_held_record_that_is_not_the_pick_is_never_signed(arm: Arm) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (name, held) = due(&world, &device, arm);
        let other = IpnsRecord::create_v2(
            &held.signer,
            b"/ipfs/bafyother",
            1,
            TTL_NANOS,
            &eol::eol_from(UnixMillis(DAY * 1000)),
        )
        .marshal();
        let endpoint = device.record_store.endpoints()[1].clone();
        device
            .record_store
            .seed_record(&endpoint, name.as_str(), other);
        device.http.enqueue_response(ok_200());

        let result = renew_one(&world, &device, &RefCell::default(), held);
        assert_eq!(result.outcome, Ok(None));
        assert!(device.http.requests().is_empty(), "nothing is registered");
        assert_eq!(seq_at(&device, &name), 1, "nothing is signed");
    }

    #[test]
    fn a_held_node_that_is_not_the_pick_is_never_signed() {
        a_held_record_that_is_not_the_pick_is_never_signed(Arm::Sealed);
    }

    #[test]
    fn a_held_head_record_that_is_not_the_pick_is_never_signed() {
        a_held_record_that_is_not_the_pick_is_never_signed(Arm::Head);
    }

    #[test]
    fn a_held_pointer_that_is_not_the_pick_is_never_signed() {
        a_held_record_that_is_not_the_pick_is_never_signed(Arm::Inline);
    }

    #[test]
    fn a_pick_that_changes_during_the_registration_is_never_signed() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (name, held) = due(&world, &device, Arm::Sealed);
        let third = IpnsRecord::create_v2(
            &held.signer,
            b"/ipfs/bafythird",
            1,
            TTL_NANOS,
            &eol::eol_from(UnixMillis(DAY * 1000)),
        )
        .marshal();
        land_at_the_registration(&device, &name, third.clone());

        let result = renew_one(&world, &device, &RefCell::default(), held);
        assert_eq!(result.outcome, Ok(None));
        let endpoint = device.record_store.endpoints()[0].clone();
        assert_eq!(
            device.record_store.record_at(&endpoint, name.as_str()),
            Some(third),
            "the third record stands"
        );
    }

    /// A renewed held record renews again when its own renewal falls due, so
    /// a long session keeps the name alive.
    fn a_followed_renewal_renews_again(arm: Arm, key: HeldKey) -> (FakeDevice, IpnsName) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (name, record) = due(&world, &device, arm);
        let held = RefCell::new(HeldRecords::from([(key, record)]));
        let pass = || {
            device.http.enqueue_response(ok_200());
            let results = block_on(eol_renew_pass(
                &api,
                &RenewalSeams {
                    transport: &device.record_store,
                    floors: &device.floor_store,
                    scheduler: &world.scheduler,
                    profile: &SyncTimingProfile::CI,
                    publishing: &RefCell::default(),
                },
                &held,
            ));
            results.into_iter().next().unwrap().outcome
        };

        assert_eq!(pass(), Ok(Some(PublishOutcome::Published { sequence: 2 })));
        world.scheduler.advance(Duration::from_secs(65 * DAY));
        assert_eq!(pass(), Ok(Some(PublishOutcome::Published { sequence: 3 })));
        assert_eq!(seq_at(&device, &name), 3);
        (device, name)
    }

    #[test]
    fn a_renewed_pointer_renews_again_when_it_falls_due() {
        let (device, name) =
            a_followed_renewal_renews_again(Arm::Inline, HeldKey::ScopePointer([7u8; 16]));
        assert_eq!(
            block_on(crate::gate::floor::sequence_floor(
                &device.floor_store,
                name.as_str().as_bytes()
            ))
            .unwrap(),
            None,
            "a pointer renewal raises no floor"
        );
    }

    #[test]
    fn a_renewed_settings_record_renews_again_when_it_falls_due() {
        a_followed_renewal_renews_again(Arm::Head, HeldKey::VaultSettings);
    }

    #[test]
    fn a_renewed_node_record_renews_again_when_it_falls_due() {
        a_followed_renewal_renews_again(Arm::Sealed, HeldKey::Node([6u8; 16]));
    }

    /// A renewal whose floor raise the store did not take leaves the held
    /// entry at the record it renewed, and reports only the publish.
    fn a_renewal_whose_floor_did_not_rise_is_not_followed(arm: Arm, key: HeldKey) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let api = ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        );
        let (name, record) = due(&world, &device, arm);
        let renewed = record.record_bytes.clone();
        let held = RefCell::new(HeldRecords::from([(key, record)]));
        device
            .floor_store
            .under_report_sequence_raises_for(name.as_str().as_bytes());
        device.http.enqueue_response(ok_200());
        let results = block_on(eol_renew_pass(
            &api,
            &RenewalSeams {
                transport: &device.record_store,
                floors: &device.floor_store,
                scheduler: &world.scheduler,
                profile: &SyncTimingProfile::CI,
                publishing: &RefCell::default(),
            },
            &held,
        ));

        assert_eq!(seq_at(&device, &name), 2);
        assert_eq!(
            results.into_iter().next().unwrap().outcome,
            Ok(Some(PublishOutcome::Published { sequence: 2 })),
        );
        assert_eq!(
            held.borrow().get(&key).unwrap().record_bytes,
            renewed,
            "the held entry stays at the record it renewed",
        );
    }

    #[test]
    fn a_settings_renewal_whose_floor_did_not_rise_is_not_followed() {
        a_renewal_whose_floor_did_not_rise_is_not_followed(Arm::Head, HeldKey::VaultSettings);
    }

    #[test]
    fn a_node_renewal_whose_floor_did_not_rise_is_not_followed() {
        a_renewal_whose_floor_did_not_rise_is_not_followed(Arm::Sealed, HeldKey::Node([6u8; 16]));
    }

    #[test]
    fn a_held_name_the_drain_is_publishing_is_not_renewed() {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        let (name, held) = due(&world, &device, Arm::Sealed);
        let publishing = RefCell::new(BTreeSet::from([name.as_str().to_owned()]));

        let result = renew_one(&world, &device, &publishing, held);
        assert_eq!(result.outcome, Ok(None));
        assert!(device.http.requests().is_empty(), "nothing is registered");
        assert_eq!(seq_at(&device, &name), 1, "the record is not re-signed");
    }
}
