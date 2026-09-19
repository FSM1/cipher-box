//! The law every owner record plane loads under, written once.
//!
//! The vault settings record ([`crate::settings`]) and the bin index record
//! ([`crate::bin_index`]) are the same class of record: keyed off the login
//! secret alone, signed and read by one account, belonging to no scope and
//! carrying no epoch. So the per-name sequence floor and the adopted body
//! revision are their whole floor law, and the degradation ladder is the same
//! ladder. It lives here so a hardening of it reaches both planes in one edit.
//!
//! Each plane supplies only what is genuinely its own: the name and signer, the
//! three durable-mark keys, the function that opens a head block into its body,
//! and whether a lapsed EOL is a refusal.

use core::future::{Future, poll_fn};
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use crate::content::Gateway;
use crate::gate::floor;
use crate::net::eol::is_expired;
use crate::net::liveness::{HeldRecord, HeldValue};
use crate::net::publish::head_cid_from_value;
use crate::net::{fanout_get_verify, fetch_head_block};
use crate::seams::{FloorStore, Http, RecordTransport, Scheduler, SnapshotCache, UnixMillis};

/// Why a load did not use the published record, carried by both degraded
/// outcomes. Reported rather than collapsed, because the reasons are not
/// equally benign: `UnprovenFirstRun` is the one that still authorises a write,
/// while `Suppressed` and `RolledBack` are what an adversary who controls the
/// record plane produces, and reverting a member's placement choice to the
/// hosted default is exactly what they gain by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultsReason {
    /// No endpoint served a record, and this device holds none of the three
    /// durable marks one leaves: the sequence floor, the adopted body revision,
    /// or the publish mint counter. Named for what it is rather than what it
    /// looks like — absence is a statement about *this device*, never proof
    /// that the account has never published, so the first run it reports is
    /// assumed and not established. Durable-mark evidence only: a cached
    /// last-known-good block can accompany it, since no raise is gated on the
    /// cache write.
    UnprovenFirstRun,
    /// No usable record, but a durable mark proves this device already adopted
    /// one: the record is being withheld or its head block is unreachable.
    Suppressed,
    /// No usable record, and the publish mint counter is this device's only
    /// mark: a publish minted a revision and then failed, or landed and lost
    /// its floor write before the store could record it. Refused like
    /// [`Self::Suppressed`], because the second case is a record this device
    /// must not publish over — and reported apart from it, because no other
    /// device is needed to reach it and none may be needed to leave it
    /// (blueprint/engine.md "Bin index record").
    StrandedMint,
    /// A record below the durable sequence floor — a replay, not staleness.
    RolledBack {
        /// The durable floor the record failed.
        floor: u64,
        /// The sequence the replayed record carried.
        sequence: u64,
    },
    /// A record whose sealed body revision is below this device's durable
    /// revision high-water: a same-sequence fork or a replay the outer sequence
    /// cannot tell apart, never staleness.
    RevisionRolledBack {
        /// The durable revision high-water the record failed.
        floor: u64,
        /// The revision the refused body carried.
        revision: u64,
    },
    /// The record's client-signed EOL has lapsed, so it is no longer
    /// authoritative about the member's current configuration.
    Expired,
    /// The load did not finish inside the profile's budget.
    TimedOut,
    /// A record was found but yielded no usable body: it will not open under
    /// the plane's key, or its body is malformed or invalid.
    Unreadable,
    /// The durable sequence floor could not be read, so no record could be
    /// held to its rollback bar. Host I/O, not a verdict on any record.
    FloorUnreadable,
}

impl DefaultsReason {
    /// The stable check name a host renders, carrying no record figures — the
    /// floors and sequences the data-carrying variants hold are this device's
    /// own state, and a host has no use for them.
    #[must_use]
    pub fn check(self) -> &'static str {
        match self {
            Self::UnprovenFirstRun => "unproven-first-run",
            Self::Suppressed => "suppressed",
            Self::StrandedMint => "stranded-mint",
            Self::RolledBack { .. } => "rolled-back",
            Self::RevisionRolledBack { .. } => "revision-rolled-back",
            Self::Expired => "expired",
            Self::TimedOut => "timed-out",
            Self::Unreadable => "unreadable",
            Self::FloorUnreadable => "floor-unreadable",
        }
    }

    /// Whether the load refused bytes the plane actually served, rather than
    /// failing to reach it (blueprint/engine.md "Vault settings load" and "Bin
    /// index record"). A caller
    /// that retries on availability must not retry on a verdict, and a verdict
    /// reaches the member as a trust violation.
    pub(crate) fn is_verdict(self) -> bool {
        match self {
            Self::RolledBack { .. } | Self::RevisionRolledBack { .. } | Self::Unreadable => true,
            Self::UnprovenFirstRun
            | Self::Suppressed
            | Self::StrandedMint
            | Self::Expired
            | Self::TimedOut
            | Self::FloorUnreadable => false,
        }
    }
}

/// The verdict a load reaches when no endpoint served a record, from the three
/// durable marks a publish leaves. Stated once, because both record planes read
/// it and the drain must not learn a rule of its own.
///
/// The two adoption marks answer first: either one proves a record this device
/// already took, so an absent one is withheld. The mint counter alone is an
/// attempt this device made, and the residual case where it is also a landed
/// publish whose floor write was lost is why it refuses too.
pub(crate) fn unresolved_reason(
    durable: Option<u64>,
    minted: Option<u64>,
    adopted: Option<u64>,
) -> DefaultsReason {
    match (durable.or(adopted), minted) {
        (Some(_), _) => DefaultsReason::Suppressed,
        (None, Some(_)) => DefaultsReason::StrandedMint,
        (None, None) => DefaultsReason::UnprovenFirstRun,
    }
}

/// A durable-store key under `prefix`. Every prefix ends in `/`, so none can
/// collide with the bare `ipnsName` the per-name sequence floor is keyed by —
/// a name carries no `/`.
pub(crate) fn prefixed_key(prefix: &[u8], name: &IpnsName) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(name.as_str().as_bytes());
    key
}

/// Run `work`, giving up once `budget` has elapsed on the injected scheduler.
/// `None` is the timeout.
pub(crate) async fn within<S: Scheduler, W: Future>(
    scheduler: &S,
    budget: Duration,
    work: W,
) -> Option<W::Output> {
    let mut work = pin!(work);
    let mut expiry = pin!(scheduler.sleep(budget));
    poll_fn(|cx| match work.as_mut().poll(cx) {
        Poll::Ready(out) => Poll::Ready(Some(out)),
        Poll::Pending => expiry.as_mut().poll(cx).map(|()| None),
    })
    .await
}

/// What a lapsed client-signed EOL means on this plane.
#[derive(Clone, Copy)]
pub(crate) enum EolRule {
    /// Refuse the record as of this instant. The reader of the settings record
    /// is always its signer, so a lapsed EOL is a refusal here rather than the
    /// availability event it is plane-wide (blueprint/engine.md "Vault settings
    /// load").
    RefuseAt(UnixMillis),
    /// Leave the EOL to the renewal enrolment the load returns
    /// (blueprint/engine.md "Bin index record").
    LeaveToRenewal,
}

/// The record one plane loads, and the three durable marks it is held to.
pub(crate) struct RecordPlane<'a> {
    /// The record's IPNS name; its bytes are also the sequence-floor key.
    pub name: &'a IpnsName,
    /// Re-signs the record when the caller acts on the renewal enrolment.
    pub signer: &'a Ed25519Signer,
    /// Where this plane's last-known-good sealed head block is cached.
    pub cache_key: Vec<u8>,
    /// The reader's body-revision bar.
    pub adopted_key: Vec<u8>,
    /// The writer's body-revision counter, read only when nothing resolved.
    pub mint_key: Vec<u8>,
    pub eol: EolRule,
}

/// A head block this plane opened: the body the caller wanted, and the revision
/// the floor law arbitrates a same-sequence fork on.
pub(crate) struct OpenedBody<B> {
    pub body: B,
    pub revision: u64,
}

/// The rung a load came to rest on.
pub(crate) enum RecordLoad<B> {
    /// The published record cleared the whole ladder.
    Resolved(B),
    /// This device's last-known-good copy, and why the published record was
    /// not used.
    Stale { body: B, reason: DefaultsReason },
    /// Neither, so the caller falls back to its own plane's empty value.
    Degraded(DefaultsReason),
}

/// A load outcome, with the record to enrol for renewal when one cleared every
/// bar.
pub(crate) struct RecordRead<B> {
    pub load: RecordLoad<B>,
    pub renewable: Option<HeldRecord>,
}

/// Load one owner record plane under the shared ladder.
///
/// Never fails: a record that will not resolve, will not open, or will not
/// clear the floor law degrades to this device's last-known-good copy and only
/// then to [`RecordLoad::Degraded`]. The whole load is bounded by `budget`
/// measured on the injected scheduler.
///
/// `open` turns a sealed head block into the plane's body. The cached copy and
/// the fetched copy both go through it, so being cached buys bytes nothing: a
/// copy this build cannot authenticate is discarded rather than applied.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn load_record<T, H, F, Sn, Sch, B>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    scheduler: &Sch,
    budget: Duration,
    plane: &RecordPlane<'_>,
    open: impl Fn(&[u8]) -> Option<OpenedBody<B>>,
) -> RecordRead<B>
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler,
{
    // Held outside the budget so a load that runs out of it mid-resolve still
    // has the cached ciphertext the resolve read on its way in.
    let mut cached = None;
    let resolve = resolve_record(
        transport,
        gateway,
        http,
        floors,
        snapshots,
        &mut cached,
        plane,
        &open,
    );
    let reason = match within(scheduler, budget, resolve).await {
        Some(Ok((body, renewable))) => {
            return RecordRead {
                load: RecordLoad::Resolved(body),
                renewable,
            };
        }
        Some(Err(reason)) => reason,
        None => DefaultsReason::TimedOut,
    };
    // A rollback takes this arm like every other reason: pinning last-known-good
    // is what the record plane already owes a gate failure (blueprint/engine.md).
    let load = match cached.and_then(|block| open(&block)) {
        Some(opened) => RecordLoad::Stale {
            body: opened.body,
            reason,
        },
        None => RecordLoad::Degraded(reason),
    };
    RecordRead {
        load,
        renewable: None,
    }
}

/// The resolved body and the record to enrol for renewal, or the reason the
/// ladder degrades.
#[allow(clippy::too_many_arguments)]
async fn resolve_record<T, H, F, Sn, B>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    cached: &mut Option<Vec<u8>>,
    plane: &RecordPlane<'_>,
    open: impl Fn(&[u8]) -> Option<OpenedBody<B>>,
) -> Result<(B, Option<HeldRecord>), DefaultsReason>
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
{
    let name = plane.name;
    let key = name.as_str().as_bytes();
    // Read ahead of the resolve so a degraded outcome has last-known-good to
    // fall back on; the cache never short-circuits the fetch.
    *cached = snapshots.get(&plane.cache_key).await.ok().flatten();
    // A floor the host cannot read is never treated as no floor.
    let Ok(durable) = floor::sequence_floor(floors, key).await else {
        return Err(DefaultsReason::FloorUnreadable);
    };
    let Some((verified, record_bytes)) = fanout_get_verify(transport, name).await else {
        // The other two marks join the sequence floor only here, because only
        // here does their absence still authorise a write, and each is raised
        // where the sequence floor is not. The mint counter is raised ahead of
        // everything a publish can fail at, so it outlives any save that got as
        // far as minting a revision. The adopted revision is raised by a
        // separate, non-atomic store write, so it can outlive a lost one.
        let (Ok(minted), Ok(adopted)) = (
            floor::sequence_floor(floors, &plane.mint_key).await,
            floor::sequence_floor(floors, &plane.adopted_key).await,
        ) else {
            return Err(DefaultsReason::FloorUnreadable);
        };
        return Err(unresolved_reason(durable, minted, adopted));
    };
    if let EolRule::RefuseAt(now) = plane.eol
        && is_expired(now, &verified.validity)
    {
        return Err(DefaultsReason::Expired);
    }
    let sequence = verified.sequence;
    let floor = durable.unwrap_or(0);
    if sequence < floor {
        return Err(DefaultsReason::RolledBack { floor, sequence });
    }

    // The record verified under a name only this account can sign for, so a
    // head block that will not come back is a withheld record.
    let Ok((_, block)) = fetch_head_block(gateway, http, name, &record_bytes, None).await else {
        return Err(DefaultsReason::Suppressed);
    };
    let opened = open(&block).ok_or(DefaultsReason::Unreadable)?;
    let Ok(adopted) = floor::sequence_floor(floors, &plane.adopted_key).await else {
        return Err(DefaultsReason::FloorUnreadable);
    };
    let adopted = adopted.unwrap_or(0);
    // The revision arbitrates only what the sequence cannot: a fork *at* the
    // sequence this device already adopted. A strictly newer record won its CAS
    // against the network, and holding it to a device-local revision counter
    // would refuse a second device's legitimate publish forever.
    if sequence == floor && opened.revision < adopted {
        return Err(DefaultsReason::RevisionRolledBack {
            floor: adopted,
            revision: opened.revision,
        });
    }
    // Both bars are behind this point, so the record may be enrolled for
    // renewal.
    let renewable = durable
        .and_then(|_| head_cid_from_value(&verified.value))
        .map(|head_cid| HeldRecord {
            routing_key: name.as_str().to_owned(),
            record_bytes,
            signer: plane.signer.clone(),
            value: HeldValue::Head(head_cid),
            // An owner record anchors its sealed body and nothing else.
            content_cids: Vec::new(),
        });
    // Only a record that cleared its floor and opened becomes last-known-good,
    // and what is stored is the sealed block, so ciphertext-only-at-rest holds.
    let _ = snapshots.put(&plane.cache_key, &block).await;
    // Advancing behind the open, never ahead of it, is the floor law: a record
    // that will not open must not raise the bar the next resolve is held to.
    // Neither store failing is a verdict on a record we just authenticated.
    let _ = floor::advance_sequence_on_unseal(floors, key, sequence).await;
    let _ = floor::advance_sequence_on_unseal(floors, &plane.adopted_key, opened.revision).await;
    Ok((opened.body, renewable))
}
