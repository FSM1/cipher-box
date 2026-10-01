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
    /// mark: the attempt it marks may have landed and lost its floor write
    /// before the store could record it. Refused like
    /// [`Self::Suppressed`], because a landed attempt is a record this device
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
    Expired {
        /// The sequence the lapsed record carried.
        sequence: u64,
        /// What its head block showed of its release. It only restricts a
        /// save; the load still refuses the record.
        head: LapsedHead,
    },
    /// The load did not finish inside the profile's budget.
    TimedOut,
    /// A record was found but yielded no usable body: it will not open under
    /// the plane's key, or its body is malformed or invalid.
    Unreadable {
        /// The sequence the record carried.
        sequence: u64,
        /// Why its head block yielded no body.
        cause: Unopened,
    },
    /// The durable sequence floor could not be read, so no record could be
    /// held to its rollback bar. Host I/O, not a verdict on any record.
    FloorUnreadable,
}

/// What a bin index hold waits on, by the check name of its load outcome. One
/// variant per outcome a hold can carry, so a host's table of notices is
/// checked against this set at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, tsify::Tsify))]
#[cfg_attr(feature = "wasm", serde(rename_all = "kebab-case"))]
pub enum BinIndexHoldCheck {
    /// `unproven-first-run`.
    UnprovenFirstRun,
    /// `suppressed`.
    Suppressed,
    /// `expired`.
    Expired,
    /// `timed-out`.
    TimedOut,
    /// `floor-unreadable`.
    FloorUnreadable,
}

impl DefaultsReason {
    /// Every defaults reason, in declaration order — the surface
    /// `crates/engine/tests/kat_checks.rs` pins (see the crate header).
    pub const CHECKS: &'static [&'static str] = &[
        "unproven-first-run",
        "suppressed",
        "stranded-mint",
        "rolled-back",
        "revision-rolled-back",
        "expired",
        "timed-out",
        "unreadable",
        "floor-unreadable",
    ];

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
            Self::Expired { .. } => "expired",
            Self::TimedOut => "timed-out",
            Self::Unreadable { .. } => "unreadable",
            Self::FloorUnreadable => "floor-unreadable",
        }
    }

    /// The class label used in reject vectors: `trust` for a verdict,
    /// `availability` otherwise.
    #[must_use]
    pub fn class(self) -> &'static str {
        if self.is_verdict() {
            "trust"
        } else {
            "availability"
        }
    }

    /// Whether the load refused bytes the plane actually served, rather than
    /// failing to reach it (blueprint/engine.md "Bin index record"). A caller
    /// that retries on availability must not retry on a verdict.
    #[must_use]
    pub(crate) fn is_verdict(self) -> bool {
        self.split() == LoadSplit::Verdict
    }

    /// The one split of a load that did not establish the record: a verdict,
    /// the stranded mint, or an availability outcome a bin index hold waits on.
    #[must_use]
    pub(crate) fn split(self) -> LoadSplit {
        match self {
            Self::RolledBack { .. } | Self::RevisionRolledBack { .. } | Self::Unreadable { .. } => {
                LoadSplit::Verdict
            }
            Self::StrandedMint => LoadSplit::StrandedMint,
            Self::UnprovenFirstRun => LoadSplit::Held(BinIndexHoldCheck::UnprovenFirstRun),
            Self::Suppressed => LoadSplit::Held(BinIndexHoldCheck::Suppressed),
            Self::Expired { .. } => LoadSplit::Held(BinIndexHoldCheck::Expired),
            Self::TimedOut => LoadSplit::Held(BinIndexHoldCheck::TimedOut),
            Self::FloorUnreadable => LoadSplit::Held(BinIndexHoldCheck::FloorUnreadable),
        }
    }
}

/// [`DefaultsReason::split`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadSplit {
    /// The load refused bytes the plane served.
    Verdict,
    /// [`DefaultsReason::StrandedMint`].
    StrandedMint,
    /// Availability, under the check a hold renders.
    Held(BinIndexHoldCheck),
}

/// The verdict a load reaches when no endpoint served a record, from the three
/// durable marks a publish leaves. Stated once, because both record planes read
/// it and the drain must not learn a rule of its own.
///
/// The two adoption marks answer first: either one proves a record this device
/// already took, so an absent one is withheld. The mint counter alone is the
/// [`DefaultsReason::StrandedMint`] state.
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

/// [`unresolved_reason`] over the marks `floors` holds now, beside the sequence
/// floor `durable` the caller already read. A mark the host cannot read is
/// [`DefaultsReason::FloorUnreadable`], never an absent one.
pub(crate) async fn unresolved_marks<F: FloorStore>(
    floors: &F,
    durable: Option<u64>,
    mint_key: &[u8],
    adopted_key: &[u8],
    refused_key: Option<&[u8]>,
) -> DefaultsReason {
    let (Ok(minted), Ok(adopted)) = (
        floor::sequence_floor(floors, mint_key).await,
        floor::sequence_floor(floors, adopted_key).await,
    ) else {
        return DefaultsReason::FloorUnreadable;
    };
    let Ok(minted) = live_mint(floors, minted, refused_key).await else {
        return DefaultsReason::FloorUnreadable;
    };
    unresolved_reason(durable, minted, adopted)
}

/// The mint counter as a mark: `None` once a stated refusal of every endpoint
/// covers the revision it names. A refusal key the host cannot read is never
/// read as an absent one.
pub(crate) async fn live_mint<F: FloorStore>(
    floors: &F,
    minted: Option<u64>,
    refused_key: Option<&[u8]>,
) -> Result<Option<u64>, crate::seams::SeamError> {
    let (Some(mint), Some(refused_key)) = (minted, refused_key) else {
        return Ok(minted);
    };
    let refused = floor::sequence_floor(floors, refused_key).await?;
    Ok(refused.is_none_or(|refused| refused < mint).then_some(mint))
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
    /// The highest revision whose PUT every endpoint refused by a stated
    /// answer, on a plane whose mint marks the PUT (ADR 0056 D1). A mint at or
    /// below it marks no PUT that can have landed.
    pub refused_key: Option<Vec<u8>>,
    pub eol: EolRule,
}

/// Why a head block yielded no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unopened {
    /// The clear header does not decode at a version this build knows, so the
    /// release is unknown.
    Undecodable,
    /// The header decodes at this build's version, and the seal does not open
    /// under the plane's key.
    Unsealed,
    /// The block opened, and its body is malformed or invalid.
    Malformed,
    /// A newer release wrote the block: its header names a later version, or
    /// its body a key or a variant outside this build's schema.
    NewerRelease,
}

/// The head block of a lapsed record, fetched only to learn its release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapsedHead {
    /// This release opened the body.
    Opened,
    /// The block came back and yielded no body.
    Unopened(Unopened),
    /// The block did not come back, so its release is unknown.
    Unavailable,
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
    open: impl Fn(&[u8]) -> Result<OpenedBody<B>, Unopened>,
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
    let load = match cached.and_then(|block| open(&block).ok()) {
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
    open: impl Fn(&[u8]) -> Result<OpenedBody<B>, Unopened>,
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
        // where the sequence floor is not. The mint counter outlives the
        // attempt it marks ([`DefaultsReason::StrandedMint`]). The adopted
        // revision is raised by a separate, non-atomic store write, so it can
        // outlive a lost one.
        return Err(unresolved_marks(
            floors,
            durable,
            &plane.mint_key,
            &plane.adopted_key,
            plane.refused_key.as_deref(),
        )
        .await);
    };
    let lapsed = matches!(plane.eol, EolRule::RefuseAt(now) if is_expired(now, &verified.validity));
    let sequence = verified.sequence;
    let floor = durable.unwrap_or(0);
    if !lapsed && sequence < floor {
        return Err(DefaultsReason::RolledBack { floor, sequence });
    }

    let fetched = fetch_head_block(gateway, http, name, &record_bytes, None).await;
    if lapsed {
        let head = match &fetched {
            Ok((_, block)) => open(block).map_or_else(LapsedHead::Unopened, |_| LapsedHead::Opened),
            Err(_) => LapsedHead::Unavailable,
        };
        return Err(DefaultsReason::Expired { sequence, head });
    }
    // The record verified under a name only this account can sign for, so a
    // head block that will not come back is a withheld record.
    let Ok((_, block)) = fetched else {
        return Err(DefaultsReason::Suppressed);
    };
    let opened = open(&block).map_err(|unopened| DefaultsReason::Unreadable {
        sequence,
        cause: unopened,
    })?;
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
