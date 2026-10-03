//! The publish pipeline: register-first, core-signed, parallel PUT with
//! any-ack success + background retry, and confirm-by-re-resolve
//! (blueprint/engine.md "Resolve/publish pipeline: Publish", #23 D3/D4,
//! #34 D2, #24 D6).
//!
//! Register-first is built into the pipeline, not left to callers (#28 D5):
//! the API registration precedes the record PUT and publish blocks on it, so
//! an unregistered name never reaches the transport (fail-closed). Every
//! signature goes through one produce-side gate ([`SignatureGate`]): it reads
//! the durable floors last, refuses a record below its [`PublishBar`], and
//! signs strictly above both the durable sequence floor and the [`Observed`]
//! record the author built on. A parallel PUT then fans out to every endpoint
//! — success is the first ack, the rest retry in the background — and a
//! confirm-by-re-resolve detects a lost CAS race for the caller to rebase.

use core::time::Duration;

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::suite::ed25519::Ed25519Signer;

use super::author::ENVELOPE_V;
use super::eol;
use super::fanout::{MAX_RECORD_BYTES, fanout_get_tied, fanout_put};
use super::register::register;
use crate::api::{ApiClient, ApiError, NameRegistration};
use crate::gate::{floor, read_cut_epoch_floor};
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

/// The durable epoch floors one record must clear at its signature.
///
/// A record below any of them is one the adoption gate refuses for good, and a
/// signed record cannot be unpublished (AGENTS.md rule 8). The floors are read
/// by the [`SignatureGate`], as the last durable reads before the signature and
/// with no await between the two — an author's own floor read goes stale while
/// the head block uploads and the registration lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishBar {
    /// The scope whose floors bar the record.
    pub scope_id: [u8; 16],
    /// The read epoch the record binds, held to the read-epoch (revocation)
    /// floor (gate stage 5).
    pub read_epoch: u64,
    /// For a scope root, the write epoch its owner-write-blob binds, held to
    /// the write-epoch floor: below it the root publishes write-plane dead.
    pub write_epoch: Option<u64>,
    /// For a scope root, its grant-set commitment's cut epoch, held to the
    /// cut-epoch floor gate stage 2 holds every commitment to.
    pub cut_epoch: Option<u64>,
}

impl PublishBar {
    /// Read this bar's floors and refuse a record below any of them — for an
    /// author that must refuse before a step it cannot undo. The signature
    /// still runs the same check ([`SignatureGate`]).
    pub(crate) async fn refuse_below<F: FloorStore>(&self, floors: &F) -> Result<(), PublishError> {
        let at = self.read_floors(floors).await?;
        self.refuse(at)
    }

    /// The read-, write- and cut-epoch floors this bar is held to, zero where
    /// none was raised. A read failure is fail-closed, never "no floor".
    async fn read_floors<F: FloorStore>(&self, floors: &F) -> Result<[u64; 3], PublishError> {
        let read = floor::read_epoch_floor(floors, &self.scope_id)
            .await
            .map_err(PublishError::FloorRead)?
            .unwrap_or(0);
        let write = if self.write_epoch.is_some() {
            floor::write_epoch_floor(floors, &self.scope_id)
                .await
                .map_err(PublishError::FloorRead)?
                .unwrap_or(0)
        } else {
            0
        };
        let cut = if self.cut_epoch.is_some() {
            read_cut_epoch_floor(floors, &self.scope_id)
                .await
                .map_err(PublishError::FloorRead)?
        } else {
            0
        };
        Ok([read, write, cut])
    }

    fn refuse(&self, [read, write, cut]: [u64; 3]) -> Result<(), PublishError> {
        let axes = [
            (BarFloor::Read, Some(self.read_epoch), read),
            (BarFloor::Write, self.write_epoch, write),
            (BarFloor::Cut, self.cut_epoch, cut),
        ];
        for (floor, epoch, at) in axes {
            if let Some(epoch) = epoch
                && epoch < at
            {
                return Err(PublishError::BelowBar { floor, at, epoch });
            }
        }
        Ok(())
    }
}

/// Which durable floor a [`PublishBar`] refusal met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarFloor {
    /// The scope's read-epoch floor.
    Read,
    /// The scope's write-epoch floor.
    Write,
    /// The scope's cut-epoch floor.
    Cut,
}

/// The record an author built its publish on: the name, and the sequence of
/// the record it read there. [`publish`] signs strictly above it, so a second
/// publish in one pass, or a publish over a record the floor has not adopted,
/// cannot re-mint a sequence already spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    name: IpnsName,
    sequence: u64,
    bytes: Vec<u8>,
}

impl Observed {
    /// No read at `name`, only for a body authored fresh or one its source read
    /// version-checked. The name's own sequence floor still bars the sequence.
    pub(crate) fn unread(name: &IpnsName) -> Self {
        Self {
            name: name.clone(),
            sequence: 0,
            bytes: Vec::new(),
        }
    }

    /// A record-verified read of `name` at `sequence` that no gate opened —
    /// the pointer plane, a revival basis, or a name a crossing moves a node to.
    pub(crate) fn record(name: &IpnsName, sequence: u64) -> Self {
        Self {
            name: name.clone(),
            sequence,
            bytes: Vec::new(),
        }
    }

    /// A gated read of `name` at `sequence`, whose envelope carries `version`.
    ///
    /// This build authors exactly [`ENVELOPE_V`], so re-sealing a newer
    /// client's record under its own `v` would mint structures whose AAD this
    /// build can never reproduce, and republishing it would downgrade `v` — the
    /// rollback the read-body AAD defends against.
    pub fn gated(
        name: &IpnsName,
        sequence: u64,
        version: u64,
        bytes: &[u8],
    ) -> Result<Self, PublishError> {
        refuse_foreign_version(version)?;
        Ok(Self {
            name: name.clone(),
            sequence,
            bytes: bytes.to_vec(),
        })
    }

    /// This observation, also clearing `sequence`: a record this device's own
    /// PUT may have left at the name, or one a landed publish already spent.
    #[must_use]
    pub(crate) fn clearing(self, sequence: u64) -> Self {
        Self {
            sequence: self.sequence.max(sequence),
            ..self
        }
    }

    /// Carry a gated source to a fresh name during a name wave. Its sequence
    /// belongs to the old name; the destination keeps its own durable floor.
    pub(crate) fn at_fresh_name(&self, name: &IpnsName) -> Self {
        Self {
            name: name.clone(),
            sequence: 0,
            bytes: Vec::new(),
        }
    }

    /// The name the publish signs for.
    pub fn name(&self) -> &IpnsName {
        &self.name
    }

    /// The gated record bytes, empty for a fresh name or a record-only observation.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The sequence the publish signs strictly above.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// [`Observed::gated`]'s version rule, for a read whose record carries its
/// fields to a publish at another name, or to no publish. A read that a publish
/// at its own name builds on takes the rule through [`Observed::gated`].
pub(crate) fn refuse_foreign_version(version: u64) -> Result<(), PublishError> {
    if version != ENVELOPE_V {
        return Err(PublishError::ForeignVersion { version });
    }
    Ok(())
}

/// One publish request: the observed name and its node signing key, the head
/// (metadata) CID to point at, and the content CIDs to register for pinning.
///
/// A publish cannot omit its observation:
/// ```compile_fail
/// use cipherbox_core::suite::ed25519::Ed25519Signer;
/// use cipherbox_engine::net::PublishRequest;
/// fn unobserved(signer: &Ed25519Signer) {
///     let _ = PublishRequest {
///         signer,
///         head_cid: "bafyhead".into(),
///         content_cids: Vec::new(),
///         bar: None,
///     };
/// }
/// ```
pub struct PublishRequest<'a> {
    /// The record the publish builds on, and the name it publishes under (its
    /// Ed25519 key is [`Self::signer`]'s).
    pub observed: &'a Observed,
    /// The node's Ed25519 signing key (derived in the key-lifecycle slice;
    /// injected here so this slice owns no key derivation).
    pub signer: &'a Ed25519Signer,
    /// The head/metadata CID this record points at (`Value = /ipfs/<head_cid>`).
    pub head_cid: String,
    /// The content CIDs to register/pin under this name.
    pub content_cids: Vec<String>,
    /// The floors this record must clear at its signature, for the record
    /// families that bind a scope epoch. `None` is a family that binds none —
    /// the pointer plane, the vault settings record and the bin index.
    pub bar: Option<PublishBar>,
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
            ipns_name: self.observed.name.as_str().to_owned(),
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
    /// The PUT was acknowledged but confirm-by-re-resolve read nothing at or
    /// above our sequence: nothing resolvable, or a stale lower sequence.
    /// Availability, never a trust verdict.
    /// Retrying is idempotent-in-sequence — the caller must not adopt these
    /// bytes, so the sequence floor stays put and a re-publish re-mints the
    /// same sequence.
    Unconfirmed {
        /// The sequence embedded in the published record.
        sequence: u64,
    },
    /// The confirm re-resolve read another record at our sequence or above it:
    /// a lost CAS race. The endpoints cannot order two records at one sequence,
    /// so a tie is lost too, and the caller re-resolves, rebases, and signs
    /// above what it observed.
    LostRace {
        /// The sequence this publish embedded.
        published_sequence: u64,
        /// The sequence of the record the confirm read instead of ours.
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
    /// On a [`PublishOutcome::LostRace`], the record that won: the higher one,
    /// or at a tie a record other than ours. Record-verified only. A caller
    /// that rebases gates it first, so its retry builds on the winner and not
    /// on our own record, which the first-endpoint tie can still serve.
    pub winner: Option<Vec<u8>>,
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
    /// Every endpoint stated a refusal of the PUT
    /// ([`PutOutcome::Refused`](super::fanout::PutOutcome::Refused)), so the
    /// record did not leave through any of them.
    AllEndpointsRefused,
    /// A durable sequence or epoch floor could not be read. A floor-read
    /// failure is a fail-closed trust event, never "no floor": publish stops
    /// rather than mint a sequence from assumed-empty state (blueprint/engine.md
    /// floor law).
    FloorRead(SeamError),
    /// The request carried an empty head CID, which would sign `/ipfs/` — a
    /// value the decode side ([`head_cid_from_value`]) always rejects. Refused
    /// release-active so no path can ever PUT an unopenable pointer (security
    /// rule 8; encode/decode fail-closed symmetry).
    EmptyHeadCid,
    /// The inline request carried an empty `Value`. The pointer plane's decode
    /// side (`sync/pointer.rs::open_repoint`) rejects empty bytes as a trust
    /// violation, so signing them would mint an unopenable re-point channel
    /// that the liveness loop would then renew for 90 days. Refused
    /// release-active (security rule 8; encode/decode fail-closed symmetry).
    EmptyInlineValue,
    /// The marshalled record exceeded [`MAX_RECORD_BYTES`], which
    /// [`fanout_get_verify`](super::fanout_get_verify) skips. Publishing it
    /// would mint bytes this client can never re-resolve — the sequence floor
    /// would never advance and the name would lapse at EOL. Refused
    /// release-active (security rule 8; encode/decode fail-closed symmetry).
    RecordTooLarge {
        /// The marshalled record size.
        size: usize,
        /// The enforced ceiling ([`MAX_RECORD_BYTES`]).
        limit: usize,
    },
    /// The record sits below one of its scope's durable floors ([`PublishBar`]).
    /// Refused release-active at the signature (security rule 8).
    BelowBar {
        /// The floor it met.
        floor: BarFloor,
        /// The durable floor in force at the signature.
        at: u64,
        /// The record's own epoch on that axis.
        epoch: u64,
    },
    /// The record built on carries an envelope version this build does not
    /// author ([`Observed::gated`]).
    ForeignVersion {
        /// The version the record carried.
        version: u64,
    },
    /// The durable floor sits at `u64::MAX`, so no sequence above it exists.
    SequenceExhausted,
    /// The durable mark the caller asked to raise ahead of the PUT could not
    /// be written, so nothing was PUT.
    MarkUnrecorded(SeamError),
}

/// A publish failure on rule 6's retryable-versus-trust axis, split as finely
/// as any author reads it ([`PublishError::verdict`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishVerdict {
    /// The registry refused the register-first step.
    RegistryRefused,
    /// This build's own release-active refusal of the bytes it would sign: a
    /// retry over the same inputs reaches it again.
    Refused,
    /// [`Self::Refused`], reached before the request addressed any head block.
    RefusedUnaddressed,
    /// [`Self::Refused`] for size: the record is over the cap, and its size
    /// follows a body a committed writer can grow.
    RefusedOversized,
    /// Stopped before the PUT; a retry may land.
    NotLanded,
    /// The PUT left and no endpoint acknowledged it.
    PutUnacknowledged,
    /// Every endpoint stated a refusal of the PUT.
    PutRefused,
}

impl PublishError {
    /// The verdict every author's own translation folds from.
    pub fn verdict(&self) -> PublishVerdict {
        match self {
            Self::Register(_) => PublishVerdict::RegistryRefused,
            Self::EmptyHeadCid | Self::EmptyInlineValue => PublishVerdict::RefusedUnaddressed,
            Self::RecordTooLarge { .. } => PublishVerdict::RefusedOversized,
            Self::BelowBar { .. } | Self::ForeignVersion { .. } | Self::SequenceExhausted => {
                PublishVerdict::Refused
            }
            Self::FloorRead(_) | Self::MarkUnrecorded(_) => PublishVerdict::NotLanded,
            Self::AllEndpointsFailed => PublishVerdict::PutUnacknowledged,
            Self::AllEndpointsRefused => PublishVerdict::PutRefused,
        }
    }
}

impl core::fmt::Display for PublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self.verdict() {
            PublishVerdict::RegistryRefused => "register-first publish failed",
            PublishVerdict::Refused => "record refused by the produce-side gate (never published)",
            PublishVerdict::RefusedUnaddressed => "empty record value (never published)",
            PublishVerdict::RefusedOversized => "record exceeds the byte cap (never published)",
            PublishVerdict::NotLanded => "durable publish state could not be read or written",
            PublishVerdict::PutUnacknowledged => "all record endpoints failed",
            PublishVerdict::PutRefused => "every record endpoint refused the record",
        })
    }
}

/// A durable mark raised just before the record PUT leaves the engine, so it
/// marks exactly the attempts whose PUT can have landed. A monotonic-max raise
/// in the sequence namespace, like every floor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PutMark<'a> {
    /// The floor-store key the mark lives at.
    pub(crate) key: &'a [u8],
    /// The value it is raised to.
    pub(crate) value: u64,
}

/// The durable floors one signature is checked against, read last before it.
///
/// [`Self::sign`] is synchronous, so no await can come between these reads and
/// the signature: the one produce-side check every record passes (AGENTS.md
/// rule 8).
pub(crate) struct SignatureGate<'a> {
    observed: &'a Observed,
    bar: Option<(PublishBar, [u64; 3])>,
    sequence_floor: Option<u64>,
}

impl<'a> SignatureGate<'a> {
    /// Read the floors `observed`'s name and `bar` are checked against. A read
    /// failure is fail-closed, never "no floor" (blueprint/engine.md floor law).
    pub(crate) async fn read<F: FloorStore>(
        floors: &F,
        observed: &'a Observed,
        bar: Option<PublishBar>,
    ) -> Result<Self, PublishError> {
        let sequence_floor = floor::sequence_floor(floors, observed.name.as_str().as_bytes())
            .await
            .map_err(PublishError::FloorRead)?;
        let bar = match bar {
            Some(bar) => Some((bar, bar.read_floors(floors).await?)),
            None => None,
        };
        Ok(Self {
            observed,
            bar,
            sequence_floor,
        })
    }

    /// Renewal's exact-sequence skip must read the sequence after all epoch
    /// awaits (ADR 0061 D3). The root bar authenticates an unchanged value,
    /// including a lagging interior admitted under its ratchet (ADR 0021).
    pub(crate) async fn read_for_renewal<F: FloorStore>(
        floors: &F,
        observed: &'a Observed,
        bar: PublishBar,
    ) -> Result<Self, PublishError> {
        let at = bar.read_floors(floors).await?;
        let sequence_floor = floor::sequence_floor(floors, observed.name.as_str().as_bytes())
            .await
            .map_err(PublishError::FloorRead)?;
        Ok(Self {
            observed,
            bar: Some((bar, at)),
            sequence_floor,
        })
    }

    /// The durable sequence floor of the observed name, `None` where none was
    /// ever raised.
    pub(crate) fn sequence_floor(&self) -> Option<u64> {
        self.sequence_floor
    }

    /// Refuse a record below its bar, then sign `value` strictly above both
    /// the durable sequence floor and the observed sequence. Returns the
    /// marshalled record and the sequence it carries.
    pub(crate) fn sign(
        &self,
        signer: &Ed25519Signer,
        value: &[u8],
        ttl_nanos: u64,
        eol: &str,
    ) -> Result<(Vec<u8>, u64), PublishError> {
        if let Some((bar, at)) = &self.bar {
            bar.refuse(*at)?;
        }
        let sequence = self
            .sequence_floor
            .unwrap_or(0)
            .max(self.observed.sequence)
            .checked_add(1)
            .ok_or(PublishError::SequenceExhausted)?;
        let record_bytes = IpnsRecord::create_v2(signer, value, sequence, ttl_nanos, eol).marshal();
        if record_bytes.len() > MAX_RECORD_BYTES {
            return Err(PublishError::RecordTooLarge {
                size: record_bytes.len(),
                limit: MAX_RECORD_BYTES,
            });
        }
        Ok((record_bytes, sequence))
    }
}

/// One record the pipeline is about to sign: the observed name, its signer,
/// the `Value` bytes, and the registration that must land first. The shape
/// both entry points reduce to, so the publish laws are stated once.
struct Publishable<'a> {
    observed: &'a Observed,
    signer: &'a Ed25519Signer,
    value: Vec<u8>,
    registration: NameRegistration,
    bar: Option<PublishBar>,
}

/// One record whose `Value` is the payload itself rather than an `/ipfs/` head
/// pointer — the pointer plane's shape, which
/// [`RecordPointerFetch`](super::pointer_fetch::RecordPointerFetch) reads back
/// verbatim.
pub struct InlineRecordRequest<'a> {
    /// The record the publish builds on, and the name it publishes under (its
    /// Ed25519 key is [`Self::signer`]'s).
    pub observed: &'a Observed,
    /// The name's Ed25519 signing key.
    pub signer: &'a Ed25519Signer,
    /// The record `Value` bytes.
    pub value: &'a [u8],
}

/// Publish an inline-value record. Same pipeline as [`publish`], same laws;
/// only the record `Value` differs.
pub async fn publish_inline<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: &InlineRecordRequest<'_>,
) -> Result<PublishReceipt, PublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    // Encode/decode fail-closed symmetry (security rule 8), the inline arm's
    // mirror of `publish`'s empty-head refusal below.
    if request.value.is_empty() {
        return Err(PublishError::EmptyInlineValue);
    }
    run(
        transport,
        api,
        floors,
        scheduler,
        profile,
        Publishable {
            observed: request.observed,
            signer: request.signer,
            value: request.value.to_vec(),
            registration: NameRegistration {
                ipns_name: request.observed.name.as_str().to_owned(),
                head_cid: None,
                content_cids: Vec::new(),
            },
            // The pointer plane binds no scope read epoch.
            bar: None,
        },
        None,
    )
    .await
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
    publish_marked(transport, api, floors, scheduler, profile, request, None).await
}

/// [`publish`], raising `mark` just before the PUT.
pub(crate) async fn publish_marked<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: &PublishRequest<'_>,
    mark: Option<PutMark<'_>>,
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
    run(
        transport,
        api,
        floors,
        scheduler,
        profile,
        Publishable {
            observed: request.observed,
            signer: request.signer,
            value: request.value(),
            registration: request.registration(),
            bar: request.bar,
        },
        mark,
    )
    .await
}

async fn run<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    request: Publishable<'_>,
    mark: Option<PutMark<'_>>,
) -> Result<PublishReceipt, PublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    // Register-first, fail-closed: the record never reaches the transport unless
    // the registration succeeds (#24 D6 / #34 D2).
    register(api, std::slice::from_ref(&request.registration))
        .await
        .map_err(PublishError::Register)?;

    // Core signs; the engine injects the explicit TTL (from the profile, never a
    // library default) and the 90-day client-signed EOL (from the injected clock).
    let ttl_nanos = u64::try_from(profile.record_ttl.as_nanos()).unwrap_or(u64::MAX);
    let gate = SignatureGate::read(floors, request.observed, request.bar).await?;
    let (record_bytes, sequence) = gate.sign(
        request.signer,
        &request.value,
        ttl_nanos,
        &eol::eol_from(scheduler.now()),
    )?;

    if let Some(mark) = mark {
        let stored = floors
            .raise_sequence_floor(mark.key, mark.value)
            .await
            .map_err(PublishError::MarkUnrecorded)?;
        if stored < mark.value {
            return Err(PublishError::MarkUnrecorded(SeamError::new(
                "the floor store did not take the mark",
            )));
        }
    }

    put_and_confirm(
        transport,
        scheduler,
        profile,
        request.observed.name(),
        record_bytes,
        sequence,
    )
    .await
}

/// PUT the signed `record_bytes` at `sequence` to every endpoint, then confirm
/// by re-resolve. Success is the first ack; the rest retry in the background.
pub(crate) async fn put_and_confirm<T, Sch>(
    transport: &T,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    name: &IpnsName,
    record_bytes: Vec<u8>,
    sequence: u64,
) -> Result<PublishReceipt, PublishError>
where
    T: RecordTransport + Clone + 'static,
    Sch: Scheduler + Clone + 'static,
{
    let key = name.as_str();
    let fanout = fanout_put(transport, key, &record_bytes).await;
    if fanout.all_refused {
        return Err(PublishError::AllEndpointsRefused);
    }
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

    // Only our own bytes, uncontested at their sequence, confirm the publish.
    let (outcome, winner) = match fanout_get_tied(transport, name).await {
        Some((_, bytes, tied)) if bytes == record_bytes && tied.is_empty() => {
            (PublishOutcome::Published { sequence }, None)
        }
        Some((observed, bytes, tied)) if observed.sequence >= sequence => {
            let winner = if bytes == record_bytes {
                tied.into_iter().next()
            } else {
                Some(bytes)
            };
            (
                PublishOutcome::LostRace {
                    published_sequence: sequence,
                    observed_sequence: observed.sequence,
                },
                winner,
            )
        }
        _ => (PublishOutcome::Unconfirmed { sequence }, None),
    };
    Ok(PublishReceipt {
        outcome,
        record_bytes,
        winner,
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
pub(crate) fn head_cid_from_value(value: &[u8]) -> Option<String> {
    core::str::from_utf8(value)
        .ok()?
        .strip_prefix(IPFS_PREFIX)
        .filter(|cid| !cid.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::SeamResult;
    use crate::testkit::{block_on, fakes::InMemoryFloorStore};

    struct ConcurrentAdopt {
        inner: InMemoryFloorStore,
        name: IpnsName,
    }

    impl FloorStore for ConcurrentAdopt {
        async fn epoch_floor(&self, key: &[u8]) -> SeamResult<Option<u64>> {
            self.inner
                .raise_sequence_floor(self.name.as_str().as_bytes(), 8)
                .await?;
            self.inner.epoch_floor(key).await
        }
        async fn sequence_floor(&self, key: &[u8]) -> SeamResult<Option<u64>> {
            self.inner.sequence_floor(key).await
        }
        async fn raise_epoch_floor(&self, key: &[u8], value: u64) -> SeamResult<u64> {
            self.inner.raise_epoch_floor(key, value).await
        }
        async fn raise_sequence_floor(&self, key: &[u8], value: u64) -> SeamResult<u64> {
            self.inner.raise_sequence_floor(key, value).await
        }
        async fn clear(&self) -> SeamResult<()> {
            self.inner.clear().await
        }
    }

    #[test]
    fn a_renewal_sees_a_sequence_advanced_during_its_epoch_reads() {
        let signer = Ed25519Signer::from_seed([0x53; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let floors = ConcurrentAdopt {
            inner: InMemoryFloorStore::default(),
            name: name.clone(),
        };
        block_on(floors.raise_sequence_floor(name.as_str().as_bytes(), 7)).unwrap();
        let observed = Observed::gated(&name, 7, ENVELOPE_V, &[]).unwrap();
        let bar = PublishBar {
            scope_id: [0; 16],
            read_epoch: 1,
            write_epoch: Some(1),
            cut_epoch: Some(0),
        };
        let gate = block_on(SignatureGate::read_for_renewal(&floors, &observed, bar)).unwrap();
        assert_eq!(
            gate.sequence_floor(),
            Some(8),
            "renewal skips the observation at 7"
        );
    }
}
