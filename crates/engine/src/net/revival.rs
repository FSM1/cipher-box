//! Revival of a lapsed name (ADR 0062 D1, D2 and D5; blueprint/engine.md
//! "Resolve/publish pipeline: Revival").
//!
//! A signature attests authorship, never freshness, so the recovery endpoint's
//! record is corroborated by the fan-out and then given to the read of its own
//! plane, the same read that admits a served record. Only a record that read
//! admits is signed again, through the renewal walk's signature path.

use core::cell::RefCell;
use core::time::Duration;
use std::collections::VecDeque;

use cipherbox_core::content::decode_content_cid_str;
use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use super::child::{ChildAdopter, ChildRecord, ChildResolveError, resolve_child_record};
use super::fanout::{FanoutRecord, MAX_RECORD_BYTES, fanout_get_classified, signed_data};
use super::pointer_fetch::{PointerConsult, PointerConsultError};
use super::publish::{
    Observed, PublishBar, PublishError, PublishOutcome, RefusedRead, head_cid_from_value,
};
use super::register::register;
use super::renewal_walk::{FloorRule, RenewalSeams, sign_admitted};
use super::rotation::{ScopeRootAdmission, admit_owned_scope_root};
use crate::api::{ApiClient, ApiError, NameRegistration};
use crate::bin_index::{BinIndexKeys, BinIndexLoad, load_bin_index};
use crate::content::Gateway;
use crate::gate::{GateError, floor};
use crate::grants::owner_entry::OwnerSeedCache;
use crate::profile::SyncTimingProfile;
use crate::record_plane::{DefaultsReason, Unopened};
use crate::rotation::derive_write_name;
use crate::seams::{
    CredentialStore, EndpointId, FloorStore, Http, RecordTransport, Scheduler, SeamError,
    SeamResult, SnapshotCache, UnixMillis,
};
use crate::session::SessionIdentity;
use crate::sync::tick::ResolveMode;

/// A record the read of its plane admitted, and the floors its signature
/// must clear.
pub(crate) struct Admitted {
    pub(crate) observed: Observed,
    pub(crate) bar: Option<PublishBar>,
    /// The signer the read recovered with the record, for a name whose seed
    /// only the admitted body carries.
    pub(crate) signer: Option<Ed25519Signer>,
}

impl Admitted {
    /// A record admitted under no scope's floors.
    pub(crate) fn unbarred(name: &IpnsName, sequence: u64, bytes: &[u8]) -> Self {
        Self {
            observed: Observed::admitted(name, sequence, bytes),
            bar: None,
            signer: None,
        }
    }

    /// The admission of a gated read, under the floors `bar`.
    fn gated(
        observed: Result<Observed, RefusedRead>,
        bar: PublishBar,
    ) -> Result<Self, PlaneRefusal> {
        Ok(Self {
            observed: observed.map_err(|refused| PlaneRefusal::Unsignable(refused.error))?,
            bar: Some(bar),
            signer: None,
        })
    }
}

/// Why the read of a plane admitted no record.
#[derive(Debug)]
pub(crate) enum PlaneRefusal {
    /// The read refused the bytes it was served.
    Rejected,
    /// The read could not reach what it needs, such as the head block.
    Unavailable,
    /// The read admitted the record, and the publish basis refused it.
    Unsignable(PublishError),
    /// The caller built the read for another name or another scope.
    Mismatch,
    /// The plane revives only at this device's floor, and the floor is
    /// another sequence or absent.
    NotAtFloor,
}

impl PlaneRefusal {
    /// The refusal of a record plane load that degraded for `reason`. A body
    /// that a newer release wrote accuses nobody: the revival holds nothing and
    /// tries again later (ADR 0062 D4).
    pub(crate) fn of_load(reason: DefaultsReason) -> Self {
        match reason {
            DefaultsReason::Unreadable {
                cause: Unopened::NewerRelease,
                ..
            } => Self::Unavailable,
            reason if reason.is_verdict() => Self::Rejected,
            _ => Self::Unavailable,
        }
    }

    /// Refuse a head record whose value names no block, before any fetch: a
    /// load reads a block it cannot fetch as withheld.
    pub(crate) fn unless_addressed(recovered: &VerifiedRecord) -> Result<(), Self> {
        if head_cid_from_value(&recovered.value)
            .is_none_or(|cid| decode_content_cid_str(&cid).is_err())
        {
            return Err(Self::Rejected);
        }
        Ok(())
    }
}

/// The read of the plane a lapsed name lives on (ADR 0062 D1 step 3).
pub(crate) trait PlaneRead {
    /// Admit the record that `transport` serves at `name`: `recovered`,
    /// verified from `bytes`.
    async fn admit<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
        recovered: &VerifiedRecord,
        bytes: &[u8],
    ) -> Result<Admitted, PlaneRefusal>;

    /// Whether this device holds no floor for the record, read before
    /// [`Self::admit`] (ADR 0062 D5).
    async fn floorless<F: FloorStore>(&self, floors: &F, name: &IpnsName) -> SeamResult<bool> {
        Ok(floor::sequence_floor(floors, name.as_str().as_bytes())
            .await?
            .is_none())
    }
}

/// One lapsed name to revive: the name, its signer, and the read of its plane.
pub(crate) struct ReviveRequest<'a, P> {
    pub(crate) name: &'a IpnsName,
    /// `None` when only the admitted record carries the seed of the name,
    /// as for a scope root after a write rotation.
    pub(crate) signer: Option<&'a Ed25519Signer>,
    pub(crate) plane: P,
}

/// A revival that signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Revived {
    pub(crate) outcome: PublishOutcome,
    /// This device held no floor for the record, so the revival restored the
    /// server copy (ADR 0062 D5).
    pub(crate) restored_from_server_copy: bool,
}

/// A fail-closed revival failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviveError {
    /// The signer does not sign for the name.
    WrongSigner,
    /// The recovery endpoint answered 429. Nothing failed; a later pass tries
    /// again.
    Throttled,
    /// The recovery fetch failed.
    Recovery(ApiError),
    /// The recovered bytes are not a record of the name.
    Unrecoverable,
    /// No endpoint answer corroborates the recovered record.
    Uncorroborated,
    /// The fan-out serves a record above the recovered one, or another record
    /// at its sequence: the recovered record is superseded.
    Superseded {
        /// The sequence the fan-out served.
        sequence: u64,
    },
    /// The recovered record is below this device's durable floor.
    StaleSource {
        /// The durable sequence floor of the name.
        floor: u64,
        /// The sequence of the recovered record.
        sequence: u64,
    },
    /// A durable floor did not read.
    FloorRead(SeamError),
    /// The read of the plane refused the recovered record.
    TrustViolation,
    /// The read of the plane could not reach what it needs.
    Unavailable,
    /// The caller built the read of the plane for another name or another
    /// scope, so no read ran.
    PlaneMismatch,
    /// The settings record revives only on a device whose floor equals the
    /// recovered sequence (ADR 0062 D4).
    NotAtFloor,
    /// The durable floor rose above the admitted sequence, or the drain
    /// publishes the name, before the signature.
    Moved,
    /// The registration, the signature or the PUT failed.
    Publish(PublishError),
}

/// The transport a plane read runs over in a revival: every endpoint serves
/// the recovered record at the lapsed name, and every other name reads through.
struct Recovered<'a, T> {
    inner: &'a T,
    key: &'a str,
    record: &'a [u8],
}

impl<T: RecordTransport> RecordTransport for Recovered<'_, T> {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.inner.endpoints()
    }

    fn accelerator(&self) -> Option<EndpointId> {
        self.inner.accelerator()
    }

    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
        bearer: Option<&str>,
    ) -> SeamResult<Option<Vec<u8>>> {
        if routing_key != self.key {
            return self
                .inner
                .get_record(endpoint, routing_key, max_bytes, bearer)
                .await;
        }
        if self.record.len() > max_bytes {
            return Err(SeamError::new("the recovered record is over the cap"));
        }
        Ok(Some(self.record.to_vec()))
    }

    async fn put_record(&self, _: &EndpointId, _: &str, _: &[u8]) -> SeamResult<()> {
        Err(SeamError::new("a plane read in a revival writes no record"))
    }
}

/// The most recovery fetches one session makes in [`RECOVERY_PACE_WINDOW`],
/// below the API's `recovery` throttle of 30 a minute for each account (ADR
/// 0062 consequence 2).
pub(crate) const RECOVERY_PACE: usize = 25;

/// The window [`RECOVERY_PACE`] counts over.
pub(crate) const RECOVERY_PACE_WINDOW: Duration = Duration::from_secs(60);

/// The session's recovery fetch times inside the last window. Session memory
/// only: a new session starts with an empty pace.
#[derive(Default)]
pub(crate) struct RecoveryPace {
    fetches: RefCell<VecDeque<UnixMillis>>,
}

impl RecoveryPace {
    /// Wait until one more fetch keeps the pace, then count it.
    pub(crate) async fn slot<Sch: Scheduler>(&self, scheduler: &Sch) {
        loop {
            let now = scheduler.now();
            let wait = {
                let mut fetches = self.fetches.borrow_mut();
                while fetches
                    .front()
                    .is_some_and(|at| now.reached(Some(at.saturating_add(RECOVERY_PACE_WINDOW))))
                {
                    fetches.pop_front();
                }
                if fetches.len() < RECOVERY_PACE {
                    fetches.push_back(now);
                    return;
                }
                fetches.front().map_or(RECOVERY_PACE_WINDOW, |oldest| {
                    Duration::from_millis(
                        oldest
                            .saturating_add(RECOVERY_PACE_WINDOW)
                            .0
                            .saturating_sub(now.0),
                    )
                })
            };
            scheduler.sleep(wait).await;
        }
    }
}

/// Steps 2 and 5: the fan-out reads `Absent`, or serves a record below `S`,
/// which the signature at `S + 1` supersedes, or exactly the record at `S`.
async fn corroborate<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
    sequence: u64,
    bytes: &[u8],
) -> Result<(), ReviveError> {
    match fanout_get_classified(transport, name).await {
        FanoutRecord::Absent => Ok(()),
        FanoutRecord::Found(served, _) if served.sequence < sequence => Ok(()),
        // ADR 0066 D1: a copy with an unsigned field added is the same record.
        FanoutRecord::Found(served, _)
            if served.sequence == sequence
                && signed_data(name, bytes).as_deref() == Some(&served.data[..]) =>
        {
            Ok(())
        }
        FanoutRecord::Found(served, _) => Err(ReviveError::Superseded {
            sequence: served.sequence,
        }),
        FanoutRecord::Unavailable(_) => Err(ReviveError::Uncorroborated),
    }
}

/// A lapsed name that passed steps 1 to 3.
struct Lapsed<'a> {
    name: &'a IpnsName,
    signer: Ed25519Signer,
    admitted: Admitted,
    value: Vec<u8>,
    restored: bool,
}

/// Revive each lapsed name in `requests` (ADR 0062 D1): admit each through
/// the read of its plane, register the admitted names in one batch, then sign
/// each at `S + 1` with the renewal EOL. Each recovery fetch waits for a slot
/// of `pace`. One result for each request, in order.
pub(crate) async fn revive<T, H, C, F, Sch, P>(
    api: &ApiClient<H, C>,
    seams: &RenewalSeams<'_, T, F, Sch>,
    pace: &RecoveryPace,
    requests: &[ReviveRequest<'_, P>],
) -> Vec<Result<Revived, ReviveError>>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
    P: PlaneRead,
{
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        results.push(admit_lapsed(api, seams, pace, request).await);
    }
    let registrations: Vec<NameRegistration> = results
        .iter()
        .flatten()
        .map(|lapsed| NameRegistration {
            ipns_name: lapsed.name.as_str().to_owned(),
            head_cid: head_cid_from_value(&lapsed.value),
            content_cids: Vec::new(),
        })
        .collect();
    let registered = if registrations.is_empty() {
        Ok(())
    } else {
        register(api, &registrations).await
    };
    let mut revived = Vec::with_capacity(results.len());
    for result in results {
        revived.push(match (result, &registered) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(ReviveError::Publish(PublishError::Register(error.clone()))),
            (Ok(lapsed), Ok(())) => sign_lapsed(seams, &lapsed).await,
        });
    }
    revived
}

/// Steps 1 to 3: fetch the recovered record, corroborate it, and admit it
/// through the read of its plane.
async fn admit_lapsed<'a, T, H, C, F, Sch, P>(
    api: &ApiClient<H, C>,
    seams: &RenewalSeams<'_, T, F, Sch>,
    pace: &RecoveryPace,
    request: &ReviveRequest<'a, P>,
) -> Result<Lapsed<'a>, ReviveError>
where
    T: RecordTransport,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler,
    P: PlaneRead,
{
    let name = request.name;
    let signs_for =
        |signer: &Ed25519Signer| IpnsName::from_public_key(&signer.verifying_key()) == *name;
    if request.signer.is_some_and(|signer| !signs_for(signer)) {
        return Err(ReviveError::WrongSigner);
    }
    pace.slot(seams.scheduler).await;
    let bytes = match api.recovery_fetch(name.as_str()).await {
        Ok(bytes) => bytes,
        Err(ApiError::Status { status: 429, .. }) => return Err(ReviveError::Throttled),
        Err(error) => return Err(ReviveError::Recovery(error)),
    };
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ReviveError::Unrecoverable);
    }
    let recovered = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .map_err(|_| ReviveError::Unrecoverable)?;

    corroborate(seams.transport, name, recovered.sequence, &bytes).await?;
    let floor = floor::sequence_floor(seams.floors, name.as_str().as_bytes())
        .await
        .map_err(ReviveError::FloorRead)?;
    if let Some(floor) = floor
        && recovered.sequence < floor
    {
        return Err(ReviveError::StaleSource {
            floor,
            sequence: recovered.sequence,
        });
    }
    let restored = request
        .plane
        .floorless(seams.floors, name)
        .await
        .map_err(ReviveError::FloorRead)?;

    let served = Recovered {
        inner: seams.transport,
        key: name.as_str(),
        record: &bytes,
    };
    let mut admitted = request
        .plane
        .admit(&served, name, &recovered, &bytes)
        .await
        .map_err(|refusal| match refusal {
            PlaneRefusal::Rejected => ReviveError::TrustViolation,
            PlaneRefusal::Unavailable => ReviveError::Unavailable,
            PlaneRefusal::Unsignable(error) => ReviveError::Publish(error),
            PlaneRefusal::Mismatch => ReviveError::PlaneMismatch,
            PlaneRefusal::NotAtFloor => ReviveError::NotAtFloor,
        })?;
    let signer = request
        .signer
        .cloned()
        .or_else(|| admitted.signer.take())
        .filter(signs_for)
        .ok_or(ReviveError::WrongSigner)?;
    // D2: the value the plane admitted, unchanged.
    let value = super::fork::verified(name, admitted.observed.bytes())
        .ok_or(ReviveError::TrustViolation)?
        .value;
    Ok(Lapsed {
        name,
        signer,
        admitted,
        value,
        restored,
    })
}

/// Steps 5 and 6: the fan-out still corroborates the admitted record, then the
/// renewal walk's signature path signs at `S + 1`.
async fn sign_lapsed<T, F, Sch>(
    seams: &RenewalSeams<'_, T, F, Sch>,
    lapsed: &Lapsed<'_>,
) -> Result<Revived, ReviveError>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let observed = &lapsed.admitted.observed;
    corroborate(
        seams.transport,
        lapsed.name,
        observed.sequence(),
        observed.bytes(),
    )
    .await?;
    let receipt = sign_admitted(
        seams,
        observed,
        lapsed.admitted.bar,
        FloorRule::AtMost,
        &lapsed.signer,
        &lapsed.value,
    )
    .await
    .ok_or(ReviveError::Moved)?
    .map_err(ReviveError::Publish)?;
    Ok(Revived {
        outcome: receipt.outcome,
        restored_from_server_copy: lapsed.restored,
    })
}

/// The root adopt of an owned scope root.
pub(crate) struct ScopeRootRead<'a, H, F, S> {
    pub(crate) gateway: &'a Gateway,
    pub(crate) http: &'a H,
    pub(crate) floors: &'a F,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) owner_seed_cache: Option<OwnerSeedCache<'a>>,
    pub(crate) enc_secret: &'a X25519Secret,
    pub(crate) identity: &'a EcdsaVerifier,
    pub(crate) scope_id: [u8; 16],
    /// The ancestor node seed of a scope below the vault root.
    pub(crate) ascent: Option<&'a Zeroizing<[u8; 32]>>,
}

impl<H: Http, F: FloorStore, S: SnapshotCache> PlaneRead for ScopeRootRead<'_, H, F, S> {
    async fn admit<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
        _: &VerifiedRecord,
        _: &[u8],
    ) -> Result<Admitted, PlaneRefusal> {
        let admitted = admit_owned_scope_root(
            transport,
            self.gateway,
            self.http,
            self.floors,
            self.snapshot_cache,
            self.owner_seed_cache.clone(),
            self.enc_secret,
            self.identity,
            self.scope_id,
            self.ascent,
            name,
        )
        .await
        .map_err(|admission| match admission {
            ScopeRootAdmission::Rejected => PlaneRefusal::Rejected,
            ScopeRootAdmission::Unavailable
            | ScopeRootAdmission::Gone
            | ScopeRootAdmission::HeadBlockAbsent => PlaneRefusal::Unavailable,
        })?;
        let signer = admitted
            .write_scope_seed
            .as_ref()
            .filter(|seed| derive_write_name(seed, &self.scope_id) == *name)
            .map(|seed| SessionIdentity::write_name_signer(seed, &self.scope_id));
        Ok(Admitted {
            signer,
            ..Admitted::gated(admitted.observed, admitted.bar)?
        })
    }
}

/// The gated child resolve of a node below a scope root.
pub(crate) struct ChildRead<'a, H, F, S> {
    pub(crate) adopter: ChildAdopter<'a, H, F>,
    pub(crate) snapshot_cache: &'a S,
    /// The scope root a record below the read-epoch floor is read under.
    pub(crate) scope_root: Option<&'a IpnsName>,
    /// The floors of the scope the node is sealed in.
    pub(crate) bar: PublishBar,
}

impl<H: Http, F: FloorStore, S: SnapshotCache> PlaneRead for ChildRead<'_, H, F, S> {
    async fn admit<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
        _: &VerifiedRecord,
        _: &[u8],
    ) -> Result<Admitted, PlaneRefusal> {
        if self.bar.scope_id != self.adopter.scope_id() {
            return Err(PlaneRefusal::Mismatch);
        }
        match resolve_child_record(
            transport,
            self.snapshot_cache,
            &self.adopter,
            name,
            self.scope_root,
            ResolveMode::NoCache,
        )
        .await
        {
            Ok(ChildRecord::Admitted(read)) => Admitted::gated(read.observed, self.bar),
            Ok(ChildRecord::Absent)
            | Err(
                ChildResolveError::Unavailable(_) | ChildResolveError::Gate(GateError::Seam(_)),
            ) => Err(PlaneRefusal::Unavailable),
            Err(ChildResolveError::Gate(GateError::Rejected(_))) => Err(PlaneRefusal::Rejected),
        }
    }
}

/// `open_repoint` and the pointer bar of an owned scope pointer.
pub(crate) struct ScopePointerRead<'a, F> {
    pub(crate) consult: PointerConsult<'a>,
    pub(crate) floors: &'a F,
    pub(crate) scope_id: [u8; 16],
}

impl<F: FloorStore> PlaneRead for ScopePointerRead<'_, F> {
    async fn admit<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
        recovered: &VerifiedRecord,
        bytes: &[u8],
    ) -> Result<Admitted, PlaneRefusal> {
        if self.consult.scope_keys.pointer_name(&self.scope_id) != *name {
            return Err(PlaneRefusal::Mismatch);
        }
        match self
            .consult
            .run(transport, self.floors, &self.scope_id)
            .await
        {
            Ok(Some(_)) => Ok(Admitted::unbarred(name, recovered.sequence, bytes)),
            Ok(None) | Err(PointerConsultError::Unavailable) => Err(PlaneRefusal::Unavailable),
            Err(PointerConsultError::Rejected) => Err(PlaneRefusal::Rejected),
        }
    }

    /// A pointer name carries no sequence floor, so the scope's write-epoch
    /// floor, which a consult raises, stands for it.
    async fn floorless<G: FloorStore>(&self, floors: &G, _: &IpnsName) -> SeamResult<bool> {
        Ok(floor::write_epoch_floor(floors, &self.scope_id)
            .await?
            .is_none())
    }
}

/// The bin index load.
pub(crate) struct BinIndexRead<'a, H, F, Sn, Sch> {
    pub(crate) gateway: &'a Gateway,
    pub(crate) http: &'a H,
    pub(crate) floors: &'a F,
    pub(crate) snapshots: &'a Sn,
    pub(crate) scheduler: &'a Sch,
    pub(crate) profile: &'a SyncTimingProfile,
    pub(crate) keys: &'a BinIndexKeys,
}

impl<H, F, Sn, Sch> PlaneRead for BinIndexRead<'_, H, F, Sn, Sch>
where
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler,
{
    async fn admit<T: RecordTransport>(
        &self,
        transport: &T,
        name: &IpnsName,
        recovered: &VerifiedRecord,
        bytes: &[u8],
    ) -> Result<Admitted, PlaneRefusal> {
        if self.keys.name() != name {
            return Err(PlaneRefusal::Mismatch);
        }
        PlaneRefusal::unless_addressed(recovered)?;
        let read = load_bin_index(
            transport,
            self.gateway,
            self.http,
            self.floors,
            self.snapshots,
            self.scheduler,
            self.profile,
            self.keys,
        )
        .await;
        match read.load {
            BinIndexLoad::Resolved(_) => Ok(Admitted::unbarred(name, recovered.sequence, bytes)),
            BinIndexLoad::Stale { reason, .. } | BinIndexLoad::Empty(reason) => {
                Err(PlaneRefusal::of_load(reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::cell::RefCell;
    use core::time::Duration;

    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::kdf;
    use cipherbox_core::payload::RepointObject;
    use cipherbox_core::seal::{
        BinIndex, PreservedFields, ReadBody, encode_envelope, seal_bin_index, seal_read_body,
    };
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::content::{DAG_ROOT_CODEC, GatewaySource};
    use crate::net::LocalHead;
    use crate::net::author::ENVELOPE_V;
    use crate::net::eol::{eol_from, ranks_above, renewal_eol_from};
    use crate::net::rotation::OwnerPointerRead;
    use crate::seams::{HttpRequest, HttpResponse, UnixMillis};
    use crate::sync::pointer::{SessionRole, scope_pointer_name, seal_repoint};
    use crate::testkit::fakes::{
        InMemoryCredentialStore, InMemoryFloorStore, InMemorySnapshotCache, ScriptedHttp,
        VirtualScheduler,
    };
    use crate::testkit::{
        FakeDevice, FakeWorld, OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY,
        OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture, OwnerRootSpec, SeededEntropy, block_on,
        owner_root_fixture, owner_root_pseudonym,
    };

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);
    const TTL_NANOS: u64 = 2_000_000_000;
    const SCOPE: [u8; 16] = [0x44; 16];
    const NODE: [u8; 16] = [0x55; 16];
    const READ_SCOPE_SEED: [u8; 32] = [0xA1; 32];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
    const EPOCH: u64 = 1;

    /// A plane whose record carries no envelope: it admits what it is served.
    struct Admits;

    impl PlaneRead for Admits {
        async fn admit<T: RecordTransport>(
            &self,
            transport: &T,
            name: &IpnsName,
            _: &VerifiedRecord,
            _: &[u8],
        ) -> Result<Admitted, PlaneRefusal> {
            match fanout_get_classified(transport, name).await {
                FanoutRecord::Found(served, bytes) => {
                    Ok(Admitted::unbarred(name, served.sequence, &bytes))
                }
                FanoutRecord::Absent | FanoutRecord::Unavailable(_) => {
                    Err(PlaneRefusal::Unavailable)
                }
            }
        }
    }

    fn api(device: &FakeDevice) -> ApiClient<ScriptedHttp, InMemoryCredentialStore> {
        ApiClient::new(
            device.http.clone(),
            device.credential_store.clone(),
            "http://api.test",
        )
    }

    fn answer(status: u16, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn name_of(signer: &Ed25519Signer) -> IpnsName {
        IpnsName::from_public_key(&signer.verifying_key())
    }

    /// A record signed on day 0 with a 90-day EOL, so it lapsed by day 100.
    fn minted(signer: &Ed25519Signer, value: &[u8], sequence: u64) -> Vec<u8> {
        IpnsRecord::create_v2(signer, value, sequence, TTL_NANOS, &eol_from(UnixMillis(0)))
            .marshal()
    }

    /// A world on day 100, with one device.
    fn after_100_days() -> (FakeWorld, FakeDevice) {
        let world = FakeWorld::new();
        let device = world.device(b"me");
        world.scheduler.advance(100 * DAY);
        (world, device)
    }

    fn revive_all<P: PlaneRead>(
        world: &FakeWorld,
        device: &FakeDevice,
        requests: &[ReviveRequest<'_, P>],
    ) -> Vec<Result<Revived, ReviveError>> {
        revive_paced(&world.scheduler, device, &RecoveryPace::default(), requests)
    }

    fn revive_paced<P: PlaneRead>(
        scheduler: &VirtualScheduler,
        device: &FakeDevice,
        pace: &RecoveryPace,
        requests: &[ReviveRequest<'_, P>],
    ) -> Vec<Result<Revived, ReviveError>> {
        let publishing = RefCell::default();
        let seams = RenewalSeams {
            transport: &device.record_store,
            floors: &device.floor_store,
            scheduler,
            profile: &SyncTimingProfile::CI,
            publishing: &publishing,
        };
        block_on(revive(&api(device), &seams, pace, requests))
    }

    fn revive_one<P: PlaneRead>(
        world: &FakeWorld,
        device: &FakeDevice,
        signer: &Ed25519Signer,
        plane: P,
    ) -> Result<Revived, ReviveError> {
        let name = name_of(signer);
        revive_all(
            world,
            device,
            &[ReviveRequest {
                name: &name,
                signer: Some(signer),
                plane,
            }],
        )
        .remove(0)
    }

    fn served(device: &FakeDevice, name: &IpnsName) -> Option<VerifiedRecord> {
        let endpoint = device.record_store.endpoints()[0].clone();
        let bytes = device.record_store.record_at(&endpoint, name.as_str())?;
        Some(IpnsRecord::unmarshal(&bytes).unwrap().verify(name).unwrap())
    }

    /// No endpoint holds a record at `name`.
    fn nothing_published(device: &FakeDevice, name: &IpnsName) -> bool {
        device.record_store.endpoints().iter().all(|endpoint| {
            device
                .record_store
                .record_at(endpoint, name.as_str())
                .is_none()
        })
    }

    fn floor_of(device: &FakeDevice, name: &IpnsName) -> Option<u64> {
        block_on(floor::sequence_floor(
            &device.floor_store,
            name.as_str().as_bytes(),
        ))
        .unwrap()
    }

    fn registrations(device: &FakeDevice) -> Vec<HttpRequest> {
        device
            .http
            .requests()
            .into_iter()
            .filter(|request| request.url.ends_with("/registry/register"))
            .collect()
    }

    /// Recovery serves `recovered`, and the registration succeeds.
    fn recover(device: &FakeDevice, recovered: Vec<u8>) {
        device.http.enqueue_response(answer(200, recovered));
        device.http.enqueue_response(answer(200, Vec::new()));
    }

    #[test]
    fn a_lapsed_record_revives_at_s_plus_one_and_its_eol_loses_a_tie() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([1; 32]);
        let name = name_of(&signer);
        recover(&device, minted(&signer, b"/ipfs/bafyrecovered", 5));

        let revived = revive_one(&world, &device, &signer, Admits).expect("the name revives");

        assert_eq!(
            revived,
            Revived {
                outcome: PublishOutcome::Published { sequence: 6 },
                restored_from_server_copy: true,
            }
        );
        let record = served(&device, &name).expect("the revival is served");
        assert_eq!(record.sequence, 6);
        assert_eq!(record.value, b"/ipfs/bafyrecovered", "the value unchanged");
        let now = world.scheduler.now();
        assert_eq!(record.validity, renewal_eol_from(now).into_bytes());
        assert!(
            ranks_above((eol_from(now).as_bytes(), b""), (&record.validity, b"")),
            "a real write at the same sequence wins the tie"
        );
    }

    #[test]
    fn a_429_from_the_recovery_endpoint_fails_nothing() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([2; 32]);
        device.http.enqueue_response(answer(429, Vec::new()));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Throttled)
        );
        assert_eq!(device.http.requests().len(), 1, "no registration");
        assert!(nothing_published(&device, &name_of(&signer)));
    }

    #[test]
    fn a_fan_out_that_does_not_answer_corroborates_nothing() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([3; 32]);
        // One endpoint answers "no record", and the other gives no answer.
        device
            .record_store
            .fail_endpoint(&device.record_store.endpoints()[0]);
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 3)));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Uncorroborated)
        );
        assert!(registrations(&device).is_empty());
    }

    #[test]
    fn a_recovered_record_below_the_floor_is_refused() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([4; 32]);
        let name = name_of(&signer);
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 9),
        )
        .unwrap();
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 3)));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::StaleSource {
                floor: 9,
                sequence: 3
            })
        );
        assert!(registrations(&device).is_empty());
        assert!(nothing_published(&device, &name));
    }

    #[test]
    fn a_fan_out_record_above_the_recovered_one_is_never_re_signed() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([5; 32]);
        let name = name_of(&signer);
        let newer = minted(&signer, b"/ipfs/bafynewer", 9);
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), newer.clone());
        }
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 5)));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Superseded { sequence: 9 })
        );
        assert!(registrations(&device).is_empty());
        assert_eq!(served(&device, &name).unwrap().sequence, 9);
    }

    #[test]
    fn a_record_the_fan_out_serves_after_the_registration_stops_the_revival() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([6; 32]);
        let name = name_of(&signer);
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 5)));
        let (store, key) = (device.record_store.clone(), name.as_str().to_owned());
        let other = minted(&signer, b"/ipfs/bafyother", 5);
        device.http.enqueue_derived(move |_| {
            for endpoint in store.endpoints() {
                store.seed_record(&endpoint, &key, other.clone());
            }
            Ok(answer(200, Vec::new()))
        });

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Superseded { sequence: 5 })
        );
        assert_eq!(
            served(&device, &name).unwrap().value,
            b"/ipfs/bafyother",
            "nothing signed over it"
        );
    }

    #[test]
    fn a_floor_raised_before_the_signature_stops_the_revival() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([7; 32]);
        let name = name_of(&signer);
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 5)));
        let (floors, key) = (device.floor_store.clone(), name.as_str().to_owned());
        device.http.enqueue_derived(move |_| {
            block_on(floors.raise_sequence_floor(key.as_bytes(), 6)).unwrap();
            Ok(answer(200, Vec::new()))
        });

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Moved)
        );
        assert!(nothing_published(&device, &name), "nothing signed");
    }

    #[test]
    fn an_older_fan_out_record_does_not_stop_the_revival() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([16; 32]);
        let name = name_of(&signer);
        device.record_store.seed_record(
            &device.record_store.endpoints()[0],
            name.as_str(),
            minted(&signer, b"/ipfs/bafyolder", 4),
        );
        recover(&device, minted(&signer, b"/ipfs/bafyrecovered", 5));

        let revived = revive_one(&world, &device, &signer, Admits).expect("the name revives");
        assert_eq!(revived.outcome, PublishOutcome::Published { sequence: 6 });
        assert_eq!(
            served(&device, &name).unwrap().value,
            b"/ipfs/bafyrecovered"
        );
    }

    #[test]
    fn a_record_above_s_after_the_registration_stops_the_revival() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([17; 32]);
        let name = name_of(&signer);
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 5)));
        let (store, key) = (device.record_store.clone(), name.as_str().to_owned());
        let newer = minted(&signer, b"/ipfs/bafynewer", 7);
        device.http.enqueue_derived(move |_| {
            store.seed_record(&store.endpoints()[0], &key, newer);
            Ok(answer(200, Vec::new()))
        });

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Superseded { sequence: 7 })
        );
        assert_eq!(served(&device, &name).unwrap().sequence, 7);
    }

    #[test]
    fn a_fork_at_the_recovered_sequence_refuses_before_the_plane_read() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([18; 32]);
        let name = name_of(&signer);
        device.record_store.seed_record(
            &device.record_store.endpoints()[0],
            name.as_str(),
            minted(&signer, b"/ipfs/bafyfanoutside", 5),
        );
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyrecoveryside", 5)));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Superseded { sequence: 5 })
        );
        assert!(registrations(&device).is_empty());
        assert_eq!(floor_of(&device, &name), None);
    }

    #[test]
    fn a_refused_recovery_fetch_publishes_nothing() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([19; 32]);
        device.http.enqueue_response(answer(403, Vec::new()));

        assert!(matches!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Recovery(_))
        ));
        assert!(nothing_published(&device, &name_of(&signer)));
    }

    #[test]
    fn a_floor_store_that_does_not_read_stops_the_revival() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([20; 32]);
        device.floor_store.fail_floor_reads();
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 5)));

        assert!(matches!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::FloorRead(_))
        ));
        assert!(registrations(&device).is_empty());
        assert!(nothing_published(&device, &name_of(&signer)));
    }

    #[test]
    fn a_routing_set_that_does_not_answer_corroborates_nothing() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([21; 32]);
        for endpoint in device.record_store.endpoints() {
            device.record_store.fail_endpoint(&endpoint);
        }
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 3)));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Uncorroborated)
        );
        assert!(registrations(&device).is_empty());
    }

    #[test]
    fn an_endpoint_that_serves_bytes_that_do_not_verify_corroborates_nothing() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([22; 32]);
        let name = name_of(&signer);
        device.record_store.seed_record(
            &device.record_store.endpoints()[0],
            name.as_str(),
            b"not a record".to_vec(),
        );
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 3)));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Uncorroborated)
        );
        assert!(registrations(&device).is_empty());
        for endpoint in &device.record_store.endpoints()[1..] {
            assert_eq!(device.record_store.record_at(endpoint, name.as_str()), None);
        }
    }

    #[test]
    fn a_device_at_the_floor_restores_no_server_copy() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([8; 32]);
        let name = name_of(&signer);
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 5),
        )
        .unwrap();
        recover(&device, minted(&signer, b"/ipfs/bafyheld", 5));

        let revived = revive_one(&world, &device, &signer, Admits).expect("the name revives");
        assert!(!revived.restored_from_server_copy);
        assert_eq!(revived.outcome, PublishOutcome::Published { sequence: 6 });
    }

    #[test]
    fn the_admitted_names_register_in_one_batch() {
        let (world, device) = after_100_days();
        let signers = [9u8, 10].map(|seed| Ed25519Signer::from_seed([seed; 32]));
        let names = signers.each_ref().map(name_of);
        for signer in &signers {
            device
                .http
                .enqueue_response(answer(200, minted(signer, b"/ipfs/bafyold", 2)));
        }
        device.http.enqueue_response(answer(200, Vec::new()));

        let requests: Vec<_> = signers
            .iter()
            .zip(&names)
            .map(|(signer, name)| ReviveRequest {
                name,
                signer: Some(signer),
                plane: Admits,
            })
            .collect();
        let results = revive_all(&world, &device, &requests);

        let published = Ok(PublishOutcome::Published { sequence: 3 });
        assert!(
            results
                .into_iter()
                .all(|result| result.map(|revived| revived.outcome) == published)
        );
        let registered = registrations(&device);
        assert_eq!(registered.len(), 1, "one registration for both names");
        let body = registered[0].body.clone().unwrap_or_default();
        let body = String::from_utf8_lossy(&body);
        assert!(names.iter().all(|name| body.contains(name.as_str())));
    }

    #[test]
    fn a_signer_of_another_name_is_refused() {
        let (world, device) = after_100_days();
        let (signer, other) = (
            Ed25519Signer::from_seed([11; 32]),
            Ed25519Signer::from_seed([12; 32]),
        );
        let name = name_of(&other);
        let results = revive_all(
            &world,
            &device,
            &[ReviveRequest {
                name: &name,
                signer: Some(&signer),
                plane: Admits,
            }],
        );
        assert_eq!(results, [Err(ReviveError::WrongSigner)]);
        assert!(device.http.requests().is_empty());
    }

    /// Release-active, so this assertion fires in a release build too.
    #[test]
    fn a_revival_at_the_sequence_ceiling_is_refused_by_the_signature_gate() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([13; 32]);
        recover(&device, minted(&signer, b"/ipfs/bafyhead", u64::MAX));

        assert_eq!(
            revive_one(&world, &device, &signer, Admits),
            Err(ReviveError::Publish(PublishError::SequenceExhausted))
        );
        assert!(
            nothing_published(&device, &name_of(&signer)),
            "nothing reached the transport"
        );
    }

    /// A file record at `sequence`, sealed under `seal_seed`, signed under the
    /// write scope seed, and its head block.
    fn file_record(seal_seed: [u8; 32], sequence: u64) -> (Ed25519Signer, Vec<u8>, LocalHead) {
        let node_seed = kdf::node_seed(&seal_seed, &NODE);
        let read_key = kdf::read_key(node_seed.as_bytes());
        let body = ReadBody::File {
            created_at: 0,
            modified_at: 0,
            versions: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let envelope = seal_read_body(
            read_key.as_bytes(),
            &[0x31; 24],
            ENVELOPE_V,
            NODE,
            SCOPE,
            EPOCH,
            &body,
        )
        .expect("the body seals");
        let block = encode_envelope(&envelope).expect("the envelope encodes");
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &NODE).as_bytes());
        let record = minted(&signer, format!("/ipfs/{cid}").as_bytes(), sequence);
        (signer, record, LocalHead { cid, block })
    }

    fn gateway() -> Gateway {
        Gateway {
            accelerator: Some(GatewaySource::public("https://gw.test")),
            public_fallbacks: Vec::new(),
            ..Default::default()
        }
    }

    fn child_read<'a>(
        device: &'a FakeDevice,
        gateway: &'a Gateway,
        http: &'a ScriptedHttp,
        head: Option<LocalHead>,
    ) -> ChildRead<'a, ScriptedHttp, InMemoryFloorStore, InMemorySnapshotCache> {
        let adopter = ChildAdopter::new(
            gateway,
            http,
            &device.floor_store,
            SCOPE,
            Zeroizing::new(READ_SCOPE_SEED),
            NODE,
        );
        if let Some(head) = head {
            adopter.hold_local_head(head);
        }
        ChildRead {
            adopter,
            snapshot_cache: &device.snapshot_cache,
            scope_root: None,
            bar: PublishBar {
                scope_id: SCOPE,
                read_epoch: EPOCH,
                write_epoch: None,
                cut_epoch: None,
            },
        }
    }

    #[test]
    fn a_lapsed_file_record_revives_through_the_gate() {
        let (world, device) = after_100_days();
        let (signer, record, head) = file_record(READ_SCOPE_SEED, 4);
        let name = name_of(&signer);
        recover(&device, record);
        let (gateway, http) = (gateway(), ScriptedHttp::default());

        let revived = revive_one(
            &world,
            &device,
            &signer,
            child_read(&device, &gateway, &http, Some(head.clone())),
        )
        .expect("the gate admits the recovered record");

        assert_eq!(revived.outcome, PublishOutcome::Published { sequence: 5 });
        assert!(revived.restored_from_server_copy);
        let record = served(&device, &name).unwrap();
        assert_eq!(record.value, format!("/ipfs/{}", head.cid).into_bytes());
        assert_eq!(
            record.validity,
            renewal_eol_from(world.scheduler.now()).into_bytes()
        );
        assert_eq!(
            floor_of(&device, &name),
            Some(4),
            "the gate raised the floor to the admitted record, and the signature raised none"
        );
    }

    #[test]
    fn a_device_that_adopted_the_file_record_revives_it_at_its_floor() {
        let (world, device) = after_100_days();
        let (signer, record, head) = file_record(READ_SCOPE_SEED, 4);
        let name = name_of(&signer);
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 4),
        )
        .unwrap();
        recover(&device, record);
        let (gateway, http) = (gateway(), ScriptedHttp::default());

        let revived = revive_one(
            &world,
            &device,
            &signer,
            child_read(&device, &gateway, &http, Some(head)),
        )
        .expect("the at-floor read admits the recovered record");

        assert_eq!(
            revived,
            Revived {
                outcome: PublishOutcome::Published { sequence: 5 },
                restored_from_server_copy: false,
            }
        );
        assert_eq!(floor_of(&device, &name), Some(4));
    }

    #[test]
    fn a_file_record_the_gate_refuses_is_a_trust_violation() {
        let (world, device) = after_100_days();
        let (signer, record, head) = file_record([0xB2; 32], 4);
        let name = name_of(&signer);
        recover(&device, record);
        let (gateway, http) = (gateway(), ScriptedHttp::default());

        assert_eq!(
            revive_one(
                &world,
                &device,
                &signer,
                child_read(&device, &gateway, &http, Some(head)),
            ),
            Err(ReviveError::TrustViolation)
        );
        assert!(registrations(&device).is_empty());
        assert_eq!(floor_of(&device, &name), None);
        assert!(nothing_published(&device, &name));
    }

    #[test]
    fn a_file_record_whose_body_is_not_available_is_no_trust_violation() {
        let (world, device) = after_100_days();
        let (signer, record, _) = file_record(READ_SCOPE_SEED, 4);
        recover(&device, record);
        // The gateway answers no request, so the head block never arrives.
        let (gateway, http) = (gateway(), ScriptedHttp::default());

        assert_eq!(
            revive_one(
                &world,
                &device,
                &signer,
                child_read(&device, &gateway, &http, None),
            ),
            Err(ReviveError::Unavailable)
        );
        assert!(registrations(&device).is_empty());
    }

    const POINTER_SECRET: &[u8] = b"revival-pointer-secret";

    struct PointerKeys;

    impl OwnerPointerRead for PointerKeys {
        fn pointer_read_key(&self, scope_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
            let seed = kdf::owner_pointer_seed(POINTER_SECRET);
            Zeroizing::new(*kdf::pointer_read_key(seed.as_bytes(), scope_id).as_bytes())
        }

        fn pointer_name(&self, scope_id: &[u8; 16]) -> IpnsName {
            scope_pointer_name(kdf::owner_pointer_seed(POINTER_SECRET).as_bytes(), scope_id)
        }
    }

    #[test]
    fn a_lapsed_scope_pointer_revives_with_its_inline_value_unchanged() {
        let (world, device) = after_100_days();
        let owner = EcdsaSigner::from_scalar(&[3; 32]).expect("a valid scalar");
        let block = seal_repoint(
            SessionRole::Owner,
            &mut SeededEntropy::new(1),
            &PointerKeys.pointer_read_key(&SCOPE),
            1,
            &owner,
            &RepointObject {
                scope_id: SCOPE,
                current_root: name_of(&Ed25519Signer::from_seed([14; 32])),
                write_epoch: 2,
                min_read_epoch: 1,
                prev_root: None,
            },
        )
        .expect("an owner session seals");
        let signer = kdf::scope_pointer(kdf::owner_pointer_seed(POINTER_SECRET).as_bytes(), &SCOPE);
        let name = name_of(&signer);
        recover(&device, minted(&signer, &block, 1));
        let identity = owner.verifying_key();

        let revived = revive_one(
            &world,
            &device,
            &signer,
            ScopePointerRead {
                consult: PointerConsult {
                    scope_keys: &PointerKeys,
                    owner_identity: &identity,
                    payload_version: 1,
                },
                floors: &device.floor_store,
                scope_id: SCOPE,
            },
        )
        .expect("the pointer read admits the recovered record");

        assert_eq!(
            revived,
            Revived {
                outcome: PublishOutcome::Published { sequence: 2 },
                restored_from_server_copy: true,
            }
        );
        assert_eq!(served(&device, &name).unwrap().value, block);
    }

    /// A gateway that serves `block` under `cid` and nothing else.
    fn serving(cid: &str, block: &[u8]) -> ScriptedHttp {
        let http = ScriptedHttp::default();
        for _ in 0..4 {
            let (cid, block) = (cid.to_owned(), block.to_vec());
            http.enqueue_derived(move |request| {
                if request.url.contains(&cid) {
                    Ok(answer(200, block))
                } else {
                    Err(SeamError::new("the gateway serves one block"))
                }
            });
        }
        http
    }

    /// Revive a lapsed owned scope root at sequence 3, its head block served
    /// by the gateway `http_for` builds.
    fn revive_root(
        world: &FakeWorld,
        device: &FakeDevice,
        http_for: impl FnOnce(&OwnerRootFixture) -> ScriptedHttp,
    ) -> (Result<Revived, ReviveError>, OwnerRootFixture) {
        let owner = EcdsaSigner::from_scalar(&[0x4e; 32]).expect("a valid scalar");
        let enc = X25519Secret::from_scalar([0x5f; 32]);
        let fixture = owner_root_fixture(OwnerRootSpec {
            writer_pseudonym: &owner_root_pseudonym(),
            pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
            owner_identity: &owner,
            owner_enc: &enc.public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            parent_node_seed: None,
            owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
            write_history_link: Vec::new(),
            grants: Vec::new(),
        });
        let signer =
            kdf::ipns_keypair(kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE).as_bytes());
        assert_eq!(name_of(&signer), fixture.name);
        let value = format!("/ipfs/{}", fixture.head_cid_str).into_bytes();
        recover(device, minted(&signer, &value, 3));
        let (gateway, http) = (gateway(), http_for(&fixture));
        let identity = owner.verifying_key();

        let result = revive_one(
            world,
            device,
            &signer,
            ScopeRootRead {
                gateway: &gateway,
                http: &http,
                floors: &device.floor_store,
                snapshot_cache: &device.snapshot_cache,
                owner_seed_cache: None,
                enc_secret: &enc,
                identity: &identity,
                scope_id: SCOPE,
                ascent: None,
            },
        );
        (result, fixture)
    }

    #[test]
    fn a_lapsed_scope_root_revives_through_the_root_adopt() {
        let (world, device) = after_100_days();
        let (result, fixture) = revive_root(&world, &device, |fixture| {
            serving(&fixture.head_cid_str, &fixture.head_block)
        });

        let revived = result.expect("the root adopt admits the recovered record");
        assert_eq!(revived.outcome, PublishOutcome::Published { sequence: 4 });
        assert_eq!(
            served(&device, &fixture.name).unwrap().value,
            format!("/ipfs/{}", fixture.head_cid_str).into_bytes()
        );
        assert_eq!(floor_of(&device, &fixture.name), Some(3));
    }

    #[test]
    fn a_scope_root_whose_head_block_no_gateway_holds_is_unavailable() {
        let (world, device) = after_100_days();
        let (result, fixture) = revive_root(&world, &device, |_| {
            let http = ScriptedHttp::default();
            for _ in 0..4 {
                http.enqueue_response(answer(404, Vec::new()));
            }
            http
        });

        assert_eq!(result, Err(ReviveError::Unavailable));
        assert!(registrations(&device).is_empty());
        assert!(nothing_published(&device, &fixture.name));
    }

    #[test]
    fn a_lapsed_bin_index_revives_through_the_bin_index_load() {
        const SECRET: &[u8] = b"revival-bin-secret";
        let (world, device) = after_100_days();
        let keys = BinIndexKeys::derive(SECRET);
        let block = seal_bin_index(
            kdf::bin_index_seal_key(SECRET).as_bytes(),
            &[0x29; 24],
            &BinIndex::new(1),
        )
        .expect("the index seals");
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        let signer = kdf::bin_index_ipns_keypair(SECRET);
        let value = format!("/ipfs/{cid}").into_bytes();
        recover(&device, minted(&signer, &value, 2));
        let (gateway, http) = (gateway(), serving(&cid, &block));

        let revived = revive_one(
            &world,
            &device,
            &signer,
            BinIndexRead {
                gateway: &gateway,
                http: &http,
                floors: &device.floor_store,
                snapshots: &device.snapshot_cache,
                scheduler: &world.scheduler,
                profile: &SyncTimingProfile::CI,
                keys: &keys,
            },
        )
        .expect("the bin index load admits the recovered record");

        assert_eq!(revived.outcome, PublishOutcome::Published { sequence: 3 });
        assert_eq!(served(&device, keys.name()).unwrap().value, value);
    }

    fn bin_read<'a>(
        world: &'a FakeWorld,
        device: &'a FakeDevice,
        gateway: &'a Gateway,
        http: &'a ScriptedHttp,
        keys: &'a BinIndexKeys,
    ) -> BinIndexRead<'a, ScriptedHttp, InMemoryFloorStore, InMemorySnapshotCache, VirtualScheduler>
    {
        BinIndexRead {
            gateway,
            http,
            floors: &device.floor_store,
            snapshots: &device.snapshot_cache,
            scheduler: &world.scheduler,
            profile: &SyncTimingProfile::CI,
            keys,
        }
    }

    #[test]
    fn a_bin_index_value_that_names_no_block_is_refused_before_any_fetch() {
        const SECRET: &[u8] = b"revival-bin-secret";
        let (world, device) = after_100_days();
        let keys = BinIndexKeys::derive(SECRET);
        let signer = kdf::bin_index_ipns_keypair(SECRET);
        recover(&device, minted(&signer, b"/ipfs/not-a-cid", 2));
        let (gateway, http) = (gateway(), ScriptedHttp::default());

        assert_eq!(
            revive_one(
                &world,
                &device,
                &signer,
                bin_read(&world, &device, &gateway, &http, &keys)
            ),
            Err(ReviveError::TrustViolation)
        );
        assert!(http.requests().is_empty(), "no block fetch");
        assert!(registrations(&device).is_empty());
    }

    #[test]
    fn a_bin_index_read_for_another_name_is_a_caller_mismatch() {
        let (world, device) = after_100_days();
        let keys = BinIndexKeys::derive(b"revival-bin-secret");
        let signer = Ed25519Signer::from_seed([15; 32]);
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/bafyold", 2)));
        let (gateway, http) = (gateway(), ScriptedHttp::default());

        assert_eq!(
            revive_one(
                &world,
                &device,
                &signer,
                bin_read(&world, &device, &gateway, &http, &keys)
            ),
            Err(ReviveError::PlaneMismatch)
        );
    }

    #[test]
    fn a_child_read_whose_bar_names_another_scope_is_a_caller_mismatch() {
        let (world, device) = after_100_days();
        let (signer, record, head) = file_record(READ_SCOPE_SEED, 4);
        device.http.enqueue_response(answer(200, record));
        let (gateway, http) = (gateway(), ScriptedHttp::default());
        let mut read = child_read(&device, &gateway, &http, Some(head));
        read.bar.scope_id = [0x45; 16];

        assert_eq!(
            revive_one(&world, &device, &signer, read),
            Err(ReviveError::PlaneMismatch)
        );
        assert_eq!(floor_of(&device, &name_of(&signer)), None);
    }

    #[test]
    fn a_fetch_over_the_pace_waits_for_the_next_slot() {
        let world = FakeWorld::new();
        let scheduler = world.scheduler.clone().with_auto_advance();
        let pace = RecoveryPace::default();
        let start = scheduler.now();
        for _ in 0..RECOVERY_PACE {
            block_on(pace.slot(&scheduler));
        }
        assert_eq!(scheduler.now(), start, "the pace holds 25 fetches at once");

        block_on(pace.slot(&scheduler));
        assert_eq!(
            scheduler.now(),
            start.saturating_add(RECOVERY_PACE_WINDOW),
            "the 26th fetch waits until the first leaves the window"
        );
    }

    #[test]
    fn a_revival_waits_for_a_slot_of_the_session_pace() {
        let (world, device) = after_100_days();
        let scheduler = world.scheduler.clone().with_auto_advance();
        let pace = RecoveryPace::default();
        for _ in 0..RECOVERY_PACE {
            block_on(pace.slot(&scheduler));
        }
        let start = scheduler.now();
        let signer = Ed25519Signer::from_seed([23; 32]);
        let name = name_of(&signer);
        recover(&device, minted(&signer, b"/ipfs/bafyrecovered", 5));

        let result = revive_paced(
            &scheduler,
            &device,
            &pace,
            &[ReviveRequest {
                name: &name,
                signer: Some(&signer),
                plane: Admits,
            }],
        )
        .remove(0);

        assert_eq!(
            result.map(|revived| revived.outcome),
            Ok(PublishOutcome::Published { sequence: 6 })
        );
        assert_eq!(
            scheduler.now(),
            start.saturating_add(RECOVERY_PACE_WINDOW),
            "the recovery fetch waited for the next slot"
        );
    }

    #[test]
    fn a_copy_with_an_unsigned_field_corroborates_the_recovered_record() {
        let (world, device) = after_100_days();
        let signer = Ed25519Signer::from_seed([24; 32]);
        let name = name_of(&signer);
        let recovered = minted(&signer, b"/ipfs/bafyrecovered", 5);
        let copy = crate::net::fork::with_unsigned_field(&recovered);
        assert_ne!(copy, recovered);
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), copy.clone());
        }
        recover(&device, recovered);

        let revived = revive_one(&world, &device, &signer, Admits).expect("the name revives");
        assert_eq!(revived.outcome, PublishOutcome::Published { sequence: 6 });
        let record = served(&device, &name).unwrap();
        assert_eq!(record.sequence, 6);
        assert_eq!(record.value, b"/ipfs/bafyrecovered", "the admitted value");
    }

    const SETTINGS_SECRET: &[u8] = b"revival-settings-secret";

    /// A lapsed settings record at `sequence` in recovery, its head block
    /// served by the gateway: the signer, the record value and the gateway.
    fn lapsed_settings(
        device: &FakeDevice,
        sequence: u64,
    ) -> (Ed25519Signer, Vec<u8>, ScriptedHttp) {
        lapsed_settings_with(device, sequence, settings_block(SETTINGS_SECRET))
    }

    /// A settings head block sealed under the keys of `secret`.
    fn settings_block(secret: &[u8]) -> Vec<u8> {
        crate::settings::cached_settings_block(
            secret,
            &crate::settings::VaultSettings::default(),
            &mut SeededEntropy::new(0x5E),
        )
        .1
    }

    /// [`lapsed_settings`] over the head block `block`.
    fn lapsed_settings_with(
        device: &FakeDevice,
        sequence: u64,
        block: Vec<u8>,
    ) -> (Ed25519Signer, Vec<u8>, ScriptedHttp) {
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        let signer = kdf::settings_ipns_keypair(SETTINGS_SECRET);
        let value = format!("/ipfs/{cid}").into_bytes();
        device
            .http
            .enqueue_response(answer(200, minted(&signer, &value, sequence)));
        (signer, value, serving(&cid, &block))
    }

    fn revive_settings(
        world: &FakeWorld,
        device: &FakeDevice,
        signer: &Ed25519Signer,
        http: &ScriptedHttp,
    ) -> Result<Revived, ReviveError> {
        let gateway = gateway();
        let enc_secret = kdf::enc_subkey(SETTINGS_SECRET);
        revive_one(
            world,
            device,
            signer,
            crate::settings::SettingsRevivalRead {
                gateway: &gateway,
                http,
                floors: &device.floor_store,
                snapshots: &device.snapshot_cache,
                scheduler: &world.scheduler,
                profile: &SyncTimingProfile::CI,
                enc_secret: &enc_secret,
                signer,
            },
        )
    }

    #[test]
    fn a_device_at_the_floor_revives_the_settings_record_with_the_renewal_eol() {
        let (world, device) = after_100_days();
        let (signer, value, http) = lapsed_settings(&device, 5);
        let name = name_of(&signer);
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 5),
        )
        .unwrap();
        device.http.enqueue_response(answer(200, Vec::new()));

        let revived = revive_settings(&world, &device, &signer, &http)
            .expect("the settings load admits the lapsed record at the floor");

        assert_eq!(
            revived,
            Revived {
                outcome: PublishOutcome::Published { sequence: 6 },
                restored_from_server_copy: false,
            }
        );
        let record = served(&device, &name).expect("the revival is served");
        assert_eq!(record.value, value, "the value unchanged");
        assert_eq!(
            record.validity,
            renewal_eol_from(world.scheduler.now()).into_bytes()
        );
    }

    #[test]
    fn a_device_off_the_floor_does_not_revive_the_settings_record() {
        for (floor, sequence) in [(None, 5), (None, 0), (Some(4), 5)] {
            let (world, device) = after_100_days();
            let (signer, _, http) = lapsed_settings(&device, sequence);
            let name = name_of(&signer);
            if let Some(floor) = floor {
                block_on(
                    device
                        .floor_store
                        .raise_sequence_floor(name.as_str().as_bytes(), floor),
                )
                .unwrap();
            }

            assert_eq!(
                revive_settings(&world, &device, &signer, &http),
                Err(ReviveError::NotAtFloor),
                "floor {floor:?}, sequence {sequence}"
            );
            assert!(
                http.requests().is_empty(),
                "floor {floor:?}: no block fetch"
            );
            assert!(registrations(&device).is_empty(), "floor {floor:?}");
            assert!(nothing_published(&device, &name), "floor {floor:?}");
        }
    }

    /// The settings revival at the floor over `block`: the result, and whether
    /// the name stays unpublished.
    fn revive_settings_at_the_floor(block: Vec<u8>) -> (Result<Revived, ReviveError>, bool) {
        let (world, device) = after_100_days();
        let (signer, _, http) = lapsed_settings_with(&device, 5, block);
        let name = name_of(&signer);
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 5),
        )
        .unwrap();
        let result = revive_settings(&world, &device, &signer, &http);
        (result, nothing_published(&device, &name))
    }

    #[test]
    fn a_settings_body_from_a_newer_release_does_not_revive_and_accuses_nobody() {
        let enc_secret = kdf::enc_subkey(SETTINGS_SECRET);
        let body = cipherbox_core::seal::open_settings_record(
            &enc_secret,
            &settings_block(SETTINGS_SECRET),
        )
        .expect("the block opens");
        let mut body = cipherbox_core::codec::decode(&body).expect("the body decodes");
        if let cipherbox_core::codec::Value::Map(map) = &mut body {
            map.insert("zFutureField", cipherbox_core::codec::Value::Unsigned(1));
        }
        let body = cipherbox_core::codec::encode(&body).expect("the body encodes");
        let block = cipherbox_core::seal::seal_settings_record(&enc_secret, &[0x5F; 32], &body)
            .expect("the body seals");

        let (result, unpublished) = revive_settings_at_the_floor(block);
        assert_eq!(result, Err(ReviveError::Unavailable));
        assert!(unpublished, "nothing re-signed");
    }

    #[test]
    fn a_settings_copy_sealed_under_another_key_is_a_trust_violation() {
        let (result, unpublished) =
            revive_settings_at_the_floor(settings_block(b"another-account-secret"));
        assert_eq!(result, Err(ReviveError::TrustViolation));
        assert!(unpublished, "nothing re-signed");
    }

    #[test]
    fn a_settings_value_that_names_no_block_is_a_trust_violation() {
        let (world, device) = after_100_days();
        let signer = kdf::settings_ipns_keypair(SETTINGS_SECRET);
        let name = name_of(&signer);
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 5),
        )
        .unwrap();
        device
            .http
            .enqueue_response(answer(200, minted(&signer, b"/ipfs/not-a-cid", 5)));
        let http = ScriptedHttp::default();

        assert_eq!(
            revive_settings(&world, &device, &signer, &http),
            Err(ReviveError::TrustViolation)
        );
        assert!(http.requests().is_empty(), "no block fetch");
        assert!(registrations(&device).is_empty());
        assert!(nothing_published(&device, &name));
    }

    /// The bin index load reports every block that does not open as
    /// malformed, so the newer-release rule of both reads is tested here.
    #[test]
    fn a_load_refusal_for_a_newer_release_is_no_trust_verdict() {
        let unreadable = |cause| DefaultsReason::Unreadable { sequence: 3, cause };
        assert!(matches!(
            PlaneRefusal::of_load(unreadable(Unopened::NewerRelease)),
            PlaneRefusal::Unavailable
        ));
        for cause in [
            Unopened::Undecodable,
            Unopened::Unsealed,
            Unopened::Malformed,
        ] {
            assert!(
                matches!(
                    PlaneRefusal::of_load(unreadable(cause)),
                    PlaneRefusal::Rejected
                ),
                "{cause:?}"
            );
        }
        assert!(matches!(
            PlaneRefusal::of_load(DefaultsReason::RolledBack {
                floor: 4,
                sequence: 3
            }),
            PlaneRefusal::Rejected
        ));
    }
}
