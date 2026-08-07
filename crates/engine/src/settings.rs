//! The vault settings plane: publish and resolve the owner's own client
//! configuration as a record on the network (CONTEXT.md "Vault settings
//! record").
//!
//! The name is the `settings-ipns-keypair` edge and the seal is HPKE-to-self
//! under `enc-subkey`, both pure functions of the login secret, so the record
//! resolves at cold start before any vault resolve — a self-hosting owner never
//! needs CipherBox to tell them where their own node is. The record fetch is
//! server-free; the head block still comes from the gateway set, and publishing
//! still traverses registration like every other record.
//!
//! **A settings record that will not resolve never blocks cold start.** A
//! degraded load prefers this device's last-known-good copy and only then
//! [`VaultSettings::default`], and the whole load is bounded by
//! [`SyncTimingProfile::settings_load_budget`] measured on the injected
//! scheduler. The reason is reported rather than swallowed
//! ([`DefaultsReason`]) — silently reverting a member's placement choice to the
//! hosted default is what an adversary who can withhold the record gains.

use core::fmt;
use core::future::{Future, poll_fn};
use core::num::NonZeroU64;
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;

use cipherbox_core::codec::{Map, Value, decode, encode};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{open_settings_record, seal_settings_record};
use cipherbox_core::suite::hash::hash;
use cipherbox_core::suite::secret::SECRET_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::content::validate_byo_config;
use crate::content::{ByoIpfsConfig, ByoKind, Gateway, PinMode, ProviderError, RetentionPolicy};
use crate::entropy::{Entropy, EntropyError};
use crate::gate::floor;
use crate::net::eol::is_expired;
use crate::net::fanout_get_verify;
use crate::net::fetch_head_block;
use crate::net::publish::{PublishOutcome, PublishReceipt};
use crate::net::record_publish::{
    PreflightError, RecordPublishError, RecordPublishRequest, preflight_settings, publish_record,
};
use crate::net::retire::{OrphanHeads, orphaned_head};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamError, SeamResult,
    SnapshotCache, UnixMillis,
};

/// The owner's client configuration, sealed into the vault settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSettings {
    /// Where a version's bytes are pinned.
    pub pin_mode: PinMode,
    /// The member's own IPFS provider, when they run one.
    pub byo: Option<ByoIpfsConfig>,
    /// The content-version retention policy.
    pub retention: RetentionPolicy,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            pin_mode: PinMode::Hosted,
            byo: None,
            retention: RetentionPolicy::KeepAll,
        }
    }
}

// ---------------------------------------------------------------------------
// The placement decision: which byte destinations a settings load authorises.
// ---------------------------------------------------------------------------

/// Where one write's bytes go, decided from the vault settings load and held
/// for the session. The hosted leg is authoritative in both directions (#34 D1):
/// only it can fail an op, and only it is quota-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// CipherBox's hosted pin store only.
    Hosted,
    /// The member's own provider only. No *content* block reaches the hosted
    /// store; record heads and registration still traverse it
    /// (blueprint/engine.md "Content plane").
    External(ByoIpfsConfig),
    /// Both legs.
    Dual(ByoIpfsConfig),
}

impl Placement {
    /// Whether this placement puts bytes in the hosted store — what the account
    /// quota gates.
    #[must_use]
    pub fn has_hosted_leg(&self) -> bool {
        !matches!(self, Self::External(_))
    }

    /// The byte destinations this placement names, as durable upload progress
    /// records them.
    #[must_use]
    pub fn destinations(&self) -> Destinations {
        match self {
            Self::Hosted => Destinations {
                hosted: true,
                external: None,
            },
            Self::External(config) => Destinations {
                hosted: false,
                external: Some(byo_tag(config)),
            },
            Self::Dual(config) => Destinations {
                hosted: true,
                external: Some(byo_tag(config)),
            },
        }
    }
}

/// A provider's identity as the upload mark records it: the kind, plus the
/// endpoint naming the node or service the blocks land on.
///
/// The bearer is deliberately out of the preimage. It rotates while the
/// destination stays put, and a mark that stops matching is not merely ignored —
/// the leaves it covered are already released from staging, so under
/// external-only a rotation would leave the version unpublishable. That mode is
/// Kubo-only ([`placement_of`]), where the endpoint *is* the member's node and
/// the bearer only fronts it. On a multi-tenant pin service two accounts do
/// share an endpoint, but such a config only ever reaches
/// [`Destinations::mirror_leg_holds`], which reports a gap and never fails an op.
fn byo_tag(config: &ByoIpfsConfig) -> [u8; SECRET_LEN] {
    let mut tagged = b"cipherbox/byo-destination\0".to_vec();
    // The kind is one fixed byte ahead of the endpoint, so no two configs share
    // a preimage without sharing both fields.
    tagged.push(config.kind as u8);
    tagged.extend_from_slice(config.endpoint.as_bytes());
    hash(&tagged)
}

/// The set of byte destinations one write's blocks go to. Durable per-version
/// upload progress is written under it, so a resumed version reads a previous
/// session's progress only where the destinations it must reach now already
/// hold those blocks — progress releases them from staging, after which they
/// can never be placed anywhere else.
///
/// The two legs are kept apart rather than folded into one tag because they
/// fail differently: only the leg that can fail an op has to hold the released
/// blocks for the version to publish (#34 D1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Destinations {
    hosted: bool,
    external: Option<[u8; SECRET_LEN]>,
}

impl fmt::Debug for Destinations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Destinations")
            .field("hosted", &self.hosted)
            .field("external", &self.external.map(|_| "<tag>"))
            .finish()
    }
}

impl Destinations {
    /// The fixed width of the encoded form.
    pub const LEN: usize = 2 + SECRET_LEN;

    /// The wire form the upload mark carries.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = u8::from(self.hosted);
        out[1] = u8::from(self.external.is_some());
        if let Some(tag) = &self.external {
            out[2..].copy_from_slice(tag);
        }
        out
    }

    /// Recover destinations from a stored mark, fail-closed: a leg flag outside
    /// `{0, 1}`, a tag under an absent leg, or a set naming no destination at
    /// all is not something [`encode`](Self::encode) can produce, so it says
    /// nothing about where any block went.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; Self::LEN] = bytes.try_into().ok()?;
        let (hosted, external) = match (bytes[0], bytes[1]) {
            (0, 1) => (false, true),
            (1, 0) => (true, false),
            (1, 1) => (true, true),
            _ => return None,
        };
        let tag: [u8; SECRET_LEN] = bytes[2..].try_into().ok()?;
        if !external && tag != [0u8; SECRET_LEN] {
            return None;
        }
        Some(Self {
            hosted,
            external: external.then_some(tag),
        })
    }

    /// Whether blocks already placed at `earlier` reached every leg that can
    /// fail an op under *these* destinations — the hosted store, except under
    /// external-only where the member's own provider is the only leg there is.
    ///
    /// This is what makes a leaf missing from staging safe to skip: it is not
    /// that some destination once took it, but that the destination this
    /// version must publish from holds it.
    #[must_use]
    pub fn required_legs_hold(&self, earlier: &Self) -> bool {
        match self.hosted {
            true => earlier.hosted,
            false => self.external.is_some() && earlier.external == self.external,
        }
    }

    /// Whether a dual write's best-effort mirror also holds those blocks. A
    /// mirror that does not is reported, never fatal: it is the same gap a live
    /// [`ProviderError`] on the external leg leaves.
    #[must_use]
    pub fn mirror_leg_holds(&self, earlier: &Self) -> bool {
        !self.hosted || self.external.is_none() || earlier.external == self.external
    }

    /// Drop the mirror from what a mark may claim, because the external leg did
    /// not take some block the mark covers. Progress is one high-water prefix
    /// under one destination set, so a mirror that missed anything inside that
    /// prefix cannot be named by it — otherwise a later external-only session
    /// reads [`required_legs_hold`](Self::required_legs_hold) as satisfied and
    /// skips blocks that provider never received.
    ///
    /// Only a leg that cannot fail the op is droppable, which is why this is a
    /// no-op without a hosted leg: the set must never narrow to no destination
    /// at all, which [`decode`](Self::decode) rejects.
    pub fn mirror_missed(&mut self) {
        if self.hosted {
            self.external = None;
        }
    }
}

/// The session's placement decision, as the command path and the drain both
/// read it: where bytes go, or why no destination could be authenticated.
pub type PlacementDecision = Result<Placement, PlacementRefusal>;

/// Why no byte destination could be decided. Every variant refuses the write:
/// a placement that cannot be authenticated must not widen to the hosted
/// default (blueprint/engine.md "Settings-load policy").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// The settings load degraded past a first run with no last-known-good copy,
    /// so the member's own placement choice is unavailable.
    SettingsUnavailable(DefaultsReason),
    /// The mode names an external leg the settings carry no config for.
    NoProvider,
    /// External-only over a pin-by-CID provider, which has no byte ingress: no
    /// leg would hold the block for it to fetch.
    NoExternalIngress(ByoKind),
}

/// The byte destinations a settings load authorises.
///
/// The built-in defaults describe an unproven first run and nothing else: every
/// other degraded reason with no last-known-good copy refuses rather than
/// resolving to [`PinMode::Hosted`] (blueprint/engine.md "Settings-load
/// policy"). The assumed placement is read off [`VaultSettings::default`] so it
/// cannot drift from the documented default it stands in for.
///
/// Residual, stated there too: absence of a settings record is only ever a
/// verdict about *this device*, so a record-plane adversary who withholds it
/// from one that holds no [`SettingsTraces`] still reaches the first-run
/// default. What narrows that window is the trace set, not this decision.
pub fn decide_placement(load: &SettingsLoad) -> Result<Placement, PlacementRefusal> {
    match load {
        SettingsLoad::Resolved(settings) | SettingsLoad::Stale { settings, .. } => {
            placement_of(settings)
        }
        SettingsLoad::Defaults(DefaultsReason::UnprovenFirstRun) => {
            placement_of(&VaultSettings::default())
        }
        SettingsLoad::Defaults(reason) => Err(PlacementRefusal::SettingsUnavailable(*reason)),
    }
}

/// The byte destinations `settings` name, in the two places that must agree:
/// the reader deciding where this session's bytes go, and the writer refusing
/// to publish settings no reader could place under (AGENTS.md rule 8).
pub fn placement_of(settings: &VaultSettings) -> Result<Placement, PlacementRefusal> {
    let config = || settings.byo.clone().ok_or(PlacementRefusal::NoProvider);
    match settings.pin_mode {
        PinMode::Hosted => Ok(Placement::Hosted),
        PinMode::Dual => Ok(Placement::Dual(config()?)),
        PinMode::External => match config()? {
            config @ ByoIpfsConfig {
                kind: ByoKind::Kubo,
                ..
            } => Ok(Placement::External(config)),
            config => Err(PlacementRefusal::NoExternalIngress(config.kind)),
        },
    }
}

/// Why a settings publish did not reach the network. Every variant is
/// fail-closed: nothing is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsPublishError {
    /// The BYO config is not one the Http seam may be pointed at.
    Byo(ProviderError),
    /// The settings name a mode no reader could place bytes under, so
    /// publishing them would strand every device on the account.
    Placement(PlacementRefusal),
    /// Core refused to encode or seal the body.
    Codec(CodecError),
    /// The host could not supply the per-record HPKE ephemeral scalar.
    Entropy(EntropyError),
    /// The sealed record failed its pre-publish dry run.
    Preflight(PreflightError),
    /// The shared publish port failed.
    Publish(RecordPublishError),
    /// The record reached the network but the confirm re-resolve did not return
    /// our own bytes at our own sequence, so the update is not known to have
    /// landed and the floor must not advance behind it.
    Unconfirmed,
    /// The confirmed publish could not be recorded durably.
    Floor(SeamError),
    /// The durable revision counter did not advance, so this publish would mint
    /// a body revision the reader refuses (AGENTS.md rule 8).
    Revision,
}

/// Why a load did not use the published record, carried by both degraded
/// outcomes. Reported rather than collapsed, because the reasons are not
/// equally benign: `UnprovenFirstRun` is the one that still authorises a write,
/// while `Suppressed` and `RolledBack` are what an adversary who controls the
/// record plane produces, and reverting a member's placement choice to the
/// hosted default is exactly what they gain by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultsReason {
    /// No endpoint served a record, and this device holds no durable mark of
    /// one ([`SettingsTraces`]). Named for what it is rather than what it looks
    /// like: absence here is a statement about *this device*, never a proof
    /// that the account has never published, so the first run it reports is
    /// assumed and not established. Floor and mint evidence only — a cached
    /// last-known-good block can accompany it, since neither raise is gated on
    /// the cache write.
    UnprovenFirstRun,
    /// No usable record, but a durable mark proves this device already adopted
    /// a settings record, or already tried to publish one: the record is being
    /// withheld or its head block is unreachable.
    Suppressed,
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
    /// A record was found but yielded no usable settings: it will not open
    /// under the enc subkey, or its body is malformed or invalid.
    Unreadable,
    /// The durable sequence floor could not be read, so no record could be
    /// held to its rollback bar. Host I/O, not a verdict on any record.
    FloorUnreadable,
}

/// What a load produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsLoad {
    /// The published record opened and validated.
    Resolved(VaultSettings),
    /// No usable published record, but this device's last-known-good copy
    /// opened and validated: stale but still the member's own choice.
    Stale {
        /// The settings this device last resolved.
        settings: VaultSettings,
        /// Why the published record was not used.
        reason: DefaultsReason,
    },
    /// Neither a published record nor a cached one: nothing here is the
    /// member's choice, only the documented defaults. What a placement decision
    /// owes this outcome is the settings-load policy in blueprint/engine.md.
    Defaults(DefaultsReason),
}

/// The IPNS name the vault settings record is published under
/// (`settings-ipns-keypair`).
#[must_use]
pub fn settings_name(login_secret: &[u8]) -> IpnsName {
    IpnsName::from_public_key(&kdf::settings_ipns_keypair(login_secret).verifying_key())
}

/// The highest body revision this device has *adopted* — the reader's bar. Kept
/// apart from [`revision_mint_key`], the highest it has ever *minted*: an
/// attempt that never landed advances only the latter, so it never makes this
/// device refuse the live record it failed to replace. Both are prefixed, so
/// neither can collide with the bare `ipnsName` the per-name sequence floor is
/// keyed by — a name carries no `/`.
fn revision_adopted_key(name: &IpnsName) -> Vec<u8> {
    prefixed_key(b"settings-revision/", name)
}

fn revision_mint_key(name: &IpnsName) -> Vec<u8> {
    prefixed_key(b"settings-revision-mint/", name)
}

fn prefixed_key(prefix: &[u8], name: &IpnsName) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(name.as_str().as_bytes());
    key
}

/// Every durable mark a settings record leaves on this device. Read together,
/// because [`DefaultsReason::UnprovenFirstRun`] is the one degraded outcome that
/// still authorises a write, and the only thing separating it from
/// [`DefaultsReason::Suppressed`] is whether *any* of these was ever raised.
#[derive(Debug, Clone, Copy)]
struct SettingsTraces {
    /// The per-name sequence floor: a record was adopted here.
    sequence: Option<u64>,
    /// The adopted body revision: a body opened and cleared its bar here.
    adopted_revision: Option<u64>,
    /// The mint counter, raised **before** the PUT, so it survives a publish
    /// that never confirmed — the member expressed a choice this device could
    /// not authenticate, which is the moment a withheld record is most valuable
    /// to an adversary.
    minted_revision: Option<u64>,
}

impl SettingsTraces {
    fn any(&self) -> bool {
        self.sequence
            .or(self.adopted_revision)
            .or(self.minted_revision)
            .is_some()
    }
}

/// Read all three marks. A floor the host cannot read is never treated as no
/// floor: the whole set fails closed together, so a partial read can never
/// downgrade a suppression into a first run.
async fn settings_traces<F: FloorStore>(floors: &F, name: &IpnsName) -> SeamResult<SettingsTraces> {
    Ok(SettingsTraces {
        sequence: floor::sequence_floor(floors, name.as_str().as_bytes()).await?,
        adopted_revision: floor::sequence_floor(floors, &revision_adopted_key(name)).await?,
        minted_revision: floor::sequence_floor(floors, &revision_mint_key(name)).await?,
    })
}

/// Mint the next body revision, advancing the durable counter **before** the
/// PUT. Attempt-scoped, which is the whole point: a revision derived from the
/// confirm-gated sequence floor re-mints the same value on a retry and so
/// cannot tell two same-sequence forks apart.
///
/// AGENTS.md rule 8: the reader refuses a revision below its durable high-water,
/// so a counter that did not actually advance fails the publish here,
/// release-active, rather than sealing bytes the reader would reject.
async fn next_revision<F: FloorStore>(
    floors: &F,
    name: &IpnsName,
) -> Result<u64, SettingsPublishError> {
    let mint_key = revision_mint_key(name);
    let read = |key| async move {
        floor::sequence_floor(floors, key)
            .await
            .map(|floor| floor.unwrap_or(0))
            .map_err(SettingsPublishError::Floor)
    };
    let next = read(&mint_key)
        .await?
        .max(read(&revision_adopted_key(name)).await?)
        .checked_add(1)
        .ok_or(SettingsPublishError::Revision)?;
    // A local mint counter, not a record-plane advance, so it raises the store
    // directly. Rule 8's guard is the compare: a store that reports a floor
    // other than the one we asked for did not take our value.
    let stored = floors
        .raise_sequence_floor(&mint_key, next)
        .await
        .map_err(SettingsPublishError::Floor)?;
    if stored != next {
        return Err(SettingsPublishError::Revision);
    }
    Ok(next)
}

/// Seal `settings` and publish them at [`settings_name`] through the shared
/// publish port, so the record inherits register-first, seq-CAS, and confirm
/// like every other record.
#[allow(clippy::too_many_arguments)]
pub async fn publish_settings<T, H, C, F, Sn, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    snapshots: &Sn,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    entropy: &mut dyn Entropy,
    orphans: &OrphanHeads,
    login_secret: &[u8],
    settings: &VaultSettings,
) -> Result<PublishReceipt, SettingsPublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler + Clone + 'static,
{
    validate(settings).map_err(SettingsPublishError::Byo)?;
    // Rule 8, one layer out from the codec: `decide_placement` hard-refuses a
    // mode with no usable byte destination, so a record carrying one would be a
    // durable, account-wide refusal of every content write. Release-active, and
    // the reader's own predicate rather than a restatement of it.
    placement_of(settings).map_err(SettingsPublishError::Placement)?;
    let signer = kdf::settings_ipns_keypair(login_secret);
    let name = IpnsName::from_public_key(&signer.verifying_key());
    let revision = next_revision(floors, &name).await?;
    let body = encode_settings_body(settings, revision).map_err(SettingsPublishError::Codec)?;
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    entropy
        .fill(ephemeral.as_mut_slice())
        .map_err(SettingsPublishError::Entropy)?;
    // A seam that reports success having written nothing would reuse one
    // ephemeral across every version of a published record — a confidentiality
    // break, so it fails closed here rather than reaching the network.
    if ephemeral.iter().all(|byte| *byte == 0) {
        return Err(SettingsPublishError::Entropy(EntropyError::new(
            "entropy seam produced an all-zero HPKE ephemeral",
        )));
    }
    let enc_secret = kdf::enc_subkey(login_secret);
    let block = seal_settings_record(&enc_secret, &ephemeral, &body)
        .map_err(SettingsPublishError::Codec)?;
    let head =
        preflight_settings(&enc_secret, block.clone()).map_err(SettingsPublishError::Preflight)?;

    let receipt = match publish_record(
        transport,
        api,
        floors,
        scheduler,
        profile,
        &RecordPublishRequest {
            name: &name,
            signer: &signer,
            head: &head,
            content_cids: Vec::new(),
            min_current_sequence: None,
        },
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            // This publish runs outside a drain pass, so it clears its own
            // orphan set rather than deferring to a pass boundary.
            if orphaned_head(&error) {
                orphans.record(head.cid());
                orphans.retire_pending(api).await;
            }
            return Err(SettingsPublishError::Publish(error));
        }
    };

    // Only a confirmed publish advances the floor. Returning `Ok` on an
    // unconfirmed one would leave the writer's floor behind the network's
    // sequence, so the next publish would mint a colliding sequence and the
    // update would silently never land.
    let PublishOutcome::Published { sequence } = receipt.outcome else {
        return Err(SettingsPublishError::Unconfirmed);
    };
    // The confirm re-resolve read back our own bytes, so the writer has adopted
    // what it just published: the bar rises, and last-known-good becomes these
    // settings rather than the generation they replaced — otherwise a record
    // withheld right after a change pins this device to a credential the member
    // has already rotated away from.
    let _ = snapshots.put(&settings_cache_key(&name), &block).await;
    floor::advance_sequence_on_unseal(floors, name.as_str().as_bytes(), sequence)
        .await
        .map_err(SettingsPublishError::Floor)?;
    floor::advance_sequence_on_unseal(floors, &revision_adopted_key(&name), revision)
        .await
        .map_err(SettingsPublishError::Floor)?;
    Ok(receipt)
}

/// Resolve the vault settings record, bounded by
/// [`SyncTimingProfile::settings_load_budget`]. Never fails: a record that will
/// not resolve, will not open, or will not validate degrades to this device's
/// last-known-good settings and only then to the documented defaults, because
/// cold start must proceed without one.
#[allow(clippy::too_many_arguments)]
pub async fn load_settings<T, H, F, Sn, Sch>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    login_secret: &[u8],
) -> SettingsLoad
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
    Sch: Scheduler,
{
    let name = settings_name(login_secret);
    let enc_secret = kdf::enc_subkey(login_secret);
    // Held outside the budget so a load that runs out of it mid-resolve still
    // has the cached ciphertext the resolve read on its way in.
    let mut cached = None;
    let load = resolve_settings(
        transport,
        gateway,
        http,
        floors,
        snapshots,
        &mut cached,
        &enc_secret,
        &name,
        scheduler.now(),
    );
    let reason = match within(scheduler, profile.settings_load_budget, load).await {
        Some(Ok(settings)) => return SettingsLoad::Resolved(settings),
        Some(Err(reason)) => reason,
        None => DefaultsReason::TimedOut,
    };
    // A rollback takes this arm like every other reason: pinning last-known-good
    // is what the record plane already owes a gate failure (blueprint/engine.md).
    match cached.and_then(|block| open_settings_head(&enc_secret, &block)) {
        Some(body) => SettingsLoad::Stale {
            settings: body.settings,
            reason,
        },
        None => SettingsLoad::Defaults(reason),
    }
}

/// The settings head block's own snapshot-cache key, kept apart from the
/// record-plane keys [`crate::net::resolve`] writes — those hold record bytes,
/// this holds the block the record anchors.
fn settings_cache_key(name: &IpnsName) -> Vec<u8> {
    let mut key = b"settings-head/".to_vec();
    key.extend_from_slice(name.as_str().as_bytes());
    key
}

/// Open a settings head block. Being cached buys bytes nothing — the cached and
/// the fetched copy reach their verdict here, through one seal open and one
/// body grammar — so a copy this build cannot authenticate is discarded rather
/// than applied.
fn open_settings_head(enc_secret: &X25519Secret, block: &[u8]) -> Option<SettingsBody> {
    decode_settings_body(&open_settings_record(enc_secret, block).ok()?).ok()
}

#[allow(clippy::too_many_arguments)]
async fn resolve_settings<T, H, F, Sn>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    snapshots: &Sn,
    cached: &mut Option<Vec<u8>>,
    enc_secret: &X25519Secret,
    name: &IpnsName,
    now: UnixMillis,
) -> Result<VaultSettings, DefaultsReason>
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
{
    let key = name.as_str().as_bytes();
    let cache_key = settings_cache_key(name);
    // Read ahead of the resolve so a degraded outcome has last-known-good to
    // fall back on; the cache never short-circuits the fetch.
    *cached = snapshots.get(&cache_key).await.ok().flatten();
    // The settings record belongs to no scope and carries no epoch, so the
    // per-name sequence floor and the adopted body revision are its whole floor
    // law. A floor the host cannot read is never treated as no floor.
    let Ok(traces) = settings_traces(floors, name).await else {
        return Err(DefaultsReason::FloorUnreadable);
    };
    let Some((verified, record_bytes)) = fanout_get_verify(transport, name).await else {
        return Err(match traces.any() {
            true => DefaultsReason::Suppressed,
            false => DefaultsReason::UnprovenFirstRun,
        });
    };
    // The reader of this record is always its signer, so a lapsed EOL is a
    // refusal here rather than the availability event it is plane-wide
    // (blueprint/engine.md "Vault settings load").
    if is_expired(now, &verified.validity) {
        return Err(DefaultsReason::Expired);
    }
    let sequence = verified.sequence;
    let floor = traces.sequence.unwrap_or(0);
    if sequence < floor {
        return Err(DefaultsReason::RolledBack { floor, sequence });
    }

    // The record verified under a name only this account can sign for, so a
    // head block that will not come back is a withheld settings record.
    let Ok((_, block)) = fetch_head_block(gateway, http, name, &record_bytes, None).await else {
        return Err(DefaultsReason::Suppressed);
    };
    let body = open_settings_head(enc_secret, &block).ok_or(DefaultsReason::Unreadable)?;
    let adopted_key = revision_adopted_key(name);
    let adopted = traces.adopted_revision.unwrap_or(0);
    // The revision arbitrates only what the sequence cannot: a fork *at* the
    // sequence this device already adopted. A strictly newer record won its CAS
    // against the network, and holding it to a device-local revision counter
    // would refuse a second device's legitimate publish forever.
    if sequence == floor && body.revision < adopted {
        return Err(DefaultsReason::RevisionRolledBack {
            floor: adopted,
            revision: body.revision,
        });
    }
    // Only a record that cleared its floor and opened becomes last-known-good,
    // and what is stored is the sealed block, so ciphertext-only-at-rest holds.
    let _ = snapshots.put(&cache_key, &block).await;
    // Advancing behind the open, never ahead of it, is the floor law: a record
    // that will not open must not raise the bar the next resolve is held to.
    // Neither store failing is a verdict on settings we just authenticated.
    let _ = floor::advance_sequence_on_unseal(floors, key, sequence).await;
    let _ = floor::advance_sequence_on_unseal(floors, &adopted_key, body.revision).await;
    Ok(body.settings)
}

/// Run `work`, giving up once `budget` has elapsed on the injected scheduler.
/// `None` is the timeout.
async fn within<S: Scheduler, W: Future>(
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

// ---------------------------------------------------------------------------
// The settings body: a det-CBOR map in core's profile
// ([`cipherbox_core::codec`]), opaque to core's seal.
// ---------------------------------------------------------------------------

const PIN_MODE_HOSTED: &str = "hosted";
const PIN_MODE_EXTERNAL: &str = "external";
const PIN_MODE_DUAL: &str = "dual";
const BYO_KIND_KUBO: &str = "kubo";
const BYO_KIND_PSA: &str = "psa";
const BYO_KIND_PINATA: &str = "pinata";

/// A settings body this build cannot act on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyError {
    /// The bytes are not a settings body in core's det-CBOR profile.
    Codec(CodecError),
    /// A tagged-union discriminant carried a string outside its set.
    UnknownVariant { field: &'static str },
    /// A key outside this version's schema.
    UnknownField { key: String },
    /// A retention policy keeping zero versions, which would plan the retire of
    /// the live version along with its history. Unrepresentable on the encode
    /// side ([`RetentionPolicy::KeepLatest`] takes a [`NonZeroU64`]).
    RetainsNoVersions,
    /// A BYO config the Http seam may not be pointed at. A resolved record is
    /// network input naming a host the engine will later talk to, so it clears
    /// the same bar as a member-typed config (AGENTS.md rule 8: the encode
    /// path refuses the same value, release-active).
    Byo(ProviderError),
}

impl From<CodecError> for BodyError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<Malformed> for BodyError {
    fn from(e: Malformed) -> Self {
        Self::Codec(e.into())
    }
}

/// The one invariant the decode path rejects that a constructed payload can
/// still violate, re-checked here so the seal path never publishes settings it
/// would refuse to read back.
fn validate(settings: &VaultSettings) -> Result<(), ProviderError> {
    match &settings.byo {
        Some(byo) => validate_byo_config(byo),
        None => Ok(()),
    }
}

/// The sealed body: the member's settings plus the attempt-scoped monotonic
/// revision that orders two records the outer sequence cannot tell apart.
#[derive(Debug)]
struct SettingsBody {
    settings: VaultSettings,
    revision: u64,
}

/// Encode a settings body. Both the returned buffer and the transient `Value`
/// tree carry the BYO access token verbatim, so this is the tree's terminal
/// owner and the buffer is handed back in a zeroizing one.
fn encode_settings_body(
    settings: &VaultSettings,
    revision: u64,
) -> Result<Zeroizing<Vec<u8>>, CodecError> {
    let mut m = Map::new();
    m.insert(
        "byo",
        settings.byo.as_ref().map_or(Value::Null, |config| {
            let mut byo = Map::new();
            byo.insert(
                "accessToken",
                config
                    .access_token
                    .as_ref()
                    .map_or(Value::Null, |token| Value::Text(token.to_string())),
            );
            byo.insert("endpoint", Value::Text(config.endpoint.clone()));
            byo.insert("kind", Value::Text(kind_str(config.kind).to_string()));
            Value::Map(byo)
        }),
    );
    m.insert(
        "keepLatest",
        match settings.retention {
            RetentionPolicy::KeepAll => Value::Null,
            RetentionPolicy::KeepLatest(n) => Value::Unsigned(n.get()),
        },
    );
    m.insert(
        "pinMode",
        Value::Text(pin_mode_str(settings.pin_mode).to_string()),
    );
    m.insert("revision", Value::Unsigned(revision));

    let mut tree = Value::Map(m);
    let encoded = encode(&tree).map(Zeroizing::new);
    tree.zeroize_bytes();
    encoded
}

fn decode_settings_body(bytes: &[u8]) -> Result<SettingsBody, BodyError> {
    let mut tree = decode(bytes)?;
    let decoded = read_settings_map(&mut tree);
    // Terminal owner of the decoded tree: the credential inside is wiped on
    // every exit, including the early returns a malformed body takes.
    tree.zeroize_bytes();
    let body = decoded?;
    validate(&body.settings).map_err(BodyError::Byo)?;
    Ok(body)
}

/// The body's keys, exhaustive at this version — a body carrying any other key
/// was written by a build this one does not share a schema with.
const BODY_KEYS: [&str; 4] = ["byo", "keepLatest", "pinMode", "revision"];
const BYO_KEYS: [&str; 3] = ["accessToken", "endpoint", "kind"];

fn read_settings_map(tree: &mut Value) -> Result<SettingsBody, BodyError> {
    let Value::Map(map) = tree else {
        return Err(tree.as_map().unwrap_err().into());
    };
    reject_unknown_keys(map, &BODY_KEYS)?;
    let pin_mode = match req(map, "pinMode")?.as_text()? {
        PIN_MODE_HOSTED => PinMode::Hosted,
        PIN_MODE_EXTERNAL => PinMode::External,
        PIN_MODE_DUAL => PinMode::Dual,
        _ => return Err(BodyError::UnknownVariant { field: "pinMode" }),
    };
    let retention = match req(map, "keepLatest")? {
        Value::Null => RetentionPolicy::KeepAll,
        other => RetentionPolicy::KeepLatest(
            NonZeroU64::new(other.as_unsigned()?).ok_or(BodyError::RetainsNoVersions)?,
        ),
    };
    let revision = req(map, "revision")?.as_unsigned()?;
    let byo = read_byo(map.get_mut("byo"))?;
    Ok(SettingsBody {
        settings: VaultSettings {
            pin_mode,
            byo,
            retention,
        },
        revision,
    })
}

/// Read the BYO config in place, leaving the subtree attached to its owner so a
/// rejection still wipes the credential it holds.
fn read_byo(value: Option<&mut Value>) -> Result<Option<ByoIpfsConfig>, BodyError> {
    let byo = match value {
        None => return Err(Malformed::MissingField { field: "byo" }.into()),
        Some(Value::Null) => return Ok(None),
        Some(Value::Map(byo)) => byo,
        Some(other) => return Err(other.as_map().unwrap_err().into()),
    };
    reject_unknown_keys(byo, &BYO_KEYS)?;
    let endpoint = req(byo, "endpoint")?.as_text()?.to_string();
    let kind = match req(byo, "kind")?.as_text()? {
        BYO_KIND_KUBO => ByoKind::Kubo,
        BYO_KIND_PSA => ByoKind::Psa,
        BYO_KIND_PINATA => ByoKind::Pinata,
        _ => return Err(BodyError::UnknownVariant { field: "kind" }),
    };
    // Moved out rather than copied: the credential lands in its zeroizing owner
    // without leaving a second live String behind.
    let access_token = match byo.remove("accessToken") {
        None => {
            return Err(Malformed::MissingField {
                field: "accessToken",
            }
            .into());
        }
        Some(Value::Null) => None,
        Some(Value::Text(token)) => Some(Zeroizing::new(token)),
        Some(other) => return Err(other.as_text().unwrap_err().into()),
    };
    Ok(Some(ByoIpfsConfig {
        endpoint,
        kind,
        access_token,
    }))
}

fn reject_unknown_keys(map: &Map, known: &[&str]) -> Result<(), BodyError> {
    match map
        .entries()
        .iter()
        .find(|(key, _)| !known.contains(&key.as_str()))
    {
        Some((key, _)) => Err(BodyError::UnknownField { key: key.clone() }),
        None => Ok(()),
    }
}

fn req<'a>(map: &'a Map, field: &'static str) -> Result<&'a Value, BodyError> {
    map.get(field)
        .ok_or_else(|| Malformed::MissingField { field }.into())
}

fn pin_mode_str(mode: PinMode) -> &'static str {
    match mode {
        PinMode::Hosted => PIN_MODE_HOSTED,
        PinMode::External => PIN_MODE_EXTERNAL,
        PinMode::Dual => PIN_MODE_DUAL,
    }
}

fn kind_str(kind: ByoKind) -> &'static str {
    match kind {
        ByoKind::Kubo => BYO_KIND_KUBO,
        ByoKind::Psa => BYO_KIND_PSA,
        ByoKind::Pinata => BYO_KIND_PINATA,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{FakeWorld, SeededEntropy, block_on};

    fn keep(n: u64) -> RetentionPolicy {
        RetentionPolicy::KeepLatest(NonZeroU64::new(n).expect("nonzero"))
    }

    fn byo(endpoint: &str, kind: ByoKind, token: Option<&str>) -> ByoIpfsConfig {
        ByoIpfsConfig {
            endpoint: endpoint.to_owned(),
            kind,
            access_token: token.map(|t| Zeroizing::new(t.to_owned())),
        }
    }

    /// The revision the round-trip fixtures mint; any value works, so long as
    /// the reader hands back the one the writer sealed.
    const REVISION: u64 = 42;

    fn round_trip(settings: &VaultSettings) -> VaultSettings {
        let body = decode_settings_body(&encode_settings_body(settings, REVISION).expect("encode"))
            .expect("decode");
        assert_eq!(body.revision, REVISION, "the revision round-trips");
        body.settings
    }

    #[test]
    fn every_tenant_of_the_record_round_trips() {
        for pin_mode in [PinMode::Hosted, PinMode::External, PinMode::Dual] {
            for kind in [ByoKind::Kubo, ByoKind::Psa, ByoKind::Pinata] {
                for retention in [RetentionPolicy::KeepAll, keep(7)] {
                    let settings = VaultSettings {
                        pin_mode,
                        byo: Some(byo("https://node.example", kind, Some("tok"))),
                        retention,
                    };
                    assert_eq!(round_trip(&settings), settings);
                }
            }
        }
        let bare = VaultSettings::default();
        assert_eq!(round_trip(&bare), bare);
        let tokenless = VaultSettings {
            byo: Some(byo("http://127.0.0.1:5001", ByoKind::Kubo, None)),
            ..VaultSettings::default()
        };
        assert_eq!(round_trip(&tokenless), tokenless);
    }

    #[test]
    fn the_encoding_is_deterministic() {
        let settings = VaultSettings {
            byo: Some(byo("https://node.example", ByoKind::Psa, Some("tok"))),
            ..VaultSettings::default()
        };
        assert_eq!(
            encode_settings_body(&settings, REVISION).expect("encode"),
            encode_settings_body(&settings, REVISION).expect("encode"),
        );
    }

    #[test]
    fn a_body_this_version_does_not_share_a_schema_with_is_refused() {
        let settings = VaultSettings::default();
        let mut tree =
            decode(&encode_settings_body(&settings, REVISION).expect("encode")).expect("decode");
        let Value::Map(map) = &mut tree else {
            unreachable!("the body is a map")
        };
        map.insert("prefetch", Value::Bool(true));
        assert_eq!(
            decode_settings_body(&encode(&tree).expect("encode")).unwrap_err(),
            BodyError::UnknownField {
                key: "prefetch".to_owned()
            },
        );
    }

    #[test]
    fn a_discriminant_outside_its_set_is_refused() {
        let mut m = Map::new();
        m.insert("byo", Value::Null);
        m.insert("keepLatest", Value::Null);
        m.insert("pinMode", Value::Text("everywhere".to_owned()));
        m.insert("revision", Value::Unsigned(1));
        assert_eq!(
            decode_settings_body(&encode(&Value::Map(m)).expect("encode")).unwrap_err(),
            BodyError::UnknownVariant { field: "pinMode" },
        );
    }

    /// AGENTS.md rule 8, the retention half: the encode side cannot express a
    /// policy keeping zero versions, and the decode side refuses the wire form
    /// of one — a plan that would retire the live version with its history.
    #[test]
    fn a_wire_retention_of_zero_versions_is_refused() {
        let mut m = Map::new();
        m.insert("byo", Value::Null);
        m.insert("keepLatest", Value::Unsigned(0));
        m.insert("pinMode", Value::Text("hosted".to_owned()));
        m.insert("revision", Value::Unsigned(1));
        assert_eq!(
            decode_settings_body(&encode(&Value::Map(m)).expect("encode")).unwrap_err(),
            BodyError::RetainsNoVersions,
        );
    }

    /// A body from a build that predates the revision is not a body this one
    /// can hold to a monotonic bar, so it is refused rather than read as zero.
    #[test]
    fn a_body_without_a_revision_is_refused() {
        let mut m = Map::new();
        m.insert("byo", Value::Null);
        m.insert("keepLatest", Value::Null);
        m.insert("pinMode", Value::Text("hosted".to_owned()));
        assert_eq!(
            decode_settings_body(&encode(&Value::Map(m)).expect("encode")).unwrap_err(),
            BodyError::Codec(Malformed::MissingField { field: "revision" }.into()),
        );
    }

    /// The BYO half: one predicate, both directions. The encode guard is
    /// release-active (`publish_settings` returns `Err`), and the reader reaches
    /// the same verdict on bytes hand-sealed past it.
    #[test]
    fn a_byo_config_the_seam_may_not_be_pointed_at_is_refused_on_both_sides() {
        for (endpoint, token) in [
            ("file:///etc/passwd", None),
            ("ftp://node.example", None),
            ("node.example", None),
            ("http://node.example", None),
            ("https://169.254.169.254", None),
            ("https://node.example", Some("tok\r\nX-Evil: 1")),
        ] {
            let settings = VaultSettings {
                byo: Some(byo(endpoint, ByoKind::Kubo, token)),
                ..VaultSettings::default()
            };
            let refused = validate(&settings).unwrap_err();
            assert_eq!(
                decode_settings_body(&encode_settings_body(&settings, REVISION).expect("encode"))
                    .unwrap_err(),
                BodyError::Byo(refused),
                "{endpoint}: the reader must refuse what the writer refuses",
            );
        }
    }
    // -----------------------------------------------------------------------
    // Placement: what a settings load authorises, and what it refuses.
    // -----------------------------------------------------------------------

    fn placed(mode: PinMode, config: Option<ByoIpfsConfig>) -> VaultSettings {
        VaultSettings {
            pin_mode: mode,
            byo: config,
            ..VaultSettings::default()
        }
    }

    fn kubo() -> ByoIpfsConfig {
        byo("https://node.example", ByoKind::Kubo, Some("tok"))
    }

    #[test]
    fn a_resolved_record_places_bytes_where_the_member_chose() {
        for (mode, expected) in [
            (PinMode::Hosted, Placement::Hosted),
            (PinMode::External, Placement::External(kubo())),
            (PinMode::Dual, Placement::Dual(kubo())),
        ] {
            let load = SettingsLoad::Resolved(placed(mode, Some(kubo())));
            assert_eq!(decide_placement(&load).unwrap(), expected);
        }
    }

    /// The last-known-good copy is the member's own choice, so it decides
    /// placement exactly as a resolved record does — that is the whole point of
    /// keeping it (blueprint/engine.md "Settings-load policy").
    #[test]
    fn a_stale_copy_decides_placement_like_a_resolved_record() {
        let load = SettingsLoad::Stale {
            settings: placed(
                PinMode::External,
                Some(byo("https://node.example", ByoKind::Kubo, None)),
            ),
            reason: DefaultsReason::Suppressed,
        };
        assert_eq!(
            decide_placement(&load).unwrap(),
            Placement::External(byo("https://node.example", ByoKind::Kubo, None))
        );
    }

    /// The built-in defaults describe an unproven first run and nothing else:
    /// every other degraded reason refuses rather than widening an unknown
    /// choice onto the hosted store.
    #[test]
    fn only_an_unproven_first_run_falls_back_to_the_hosted_default() {
        assert_eq!(
            decide_placement(&SettingsLoad::Defaults(DefaultsReason::UnprovenFirstRun)).unwrap(),
            Placement::Hosted
        );
        for reason in [
            DefaultsReason::Suppressed,
            DefaultsReason::RolledBack {
                floor: 4,
                sequence: 2,
            },
            DefaultsReason::RevisionRolledBack {
                floor: 4,
                revision: 2,
            },
            DefaultsReason::Expired,
            DefaultsReason::TimedOut,
            DefaultsReason::Unreadable,
            DefaultsReason::FloorUnreadable,
        ] {
            assert_eq!(
                decide_placement(&SettingsLoad::Defaults(reason)).unwrap_err(),
                PlacementRefusal::SettingsUnavailable(reason),
                "{reason:?} must not widen placement"
            );
        }
    }

    #[test]
    fn a_mode_naming_an_external_leg_with_no_provider_is_refused() {
        for mode in [PinMode::External, PinMode::Dual] {
            let load = SettingsLoad::Resolved(placed(mode, None));
            assert_eq!(
                decide_placement(&load).unwrap_err(),
                PlacementRefusal::NoProvider
            );
        }
    }

    /// A pinning service fetches content from the network rather than receiving
    /// it, so external-only over one would publish a record naming bytes no leg
    /// holds. Paired with a hosted leg it is exactly right.
    #[test]
    fn a_pin_by_cid_provider_cannot_be_the_only_byte_destination() {
        for kind in [ByoKind::Psa, ByoKind::Pinata] {
            let provider = Some(byo("https://node.example", kind, Some("tok")));
            assert_eq!(
                decide_placement(&SettingsLoad::Resolved(placed(
                    PinMode::External,
                    provider.clone()
                )))
                .unwrap_err(),
                PlacementRefusal::NoExternalIngress(kind)
            );
            assert!(
                decide_placement(&SettingsLoad::Resolved(placed(PinMode::Dual, provider))).is_ok(),
                "{kind:?} is a fine second leg"
            );
        }
    }

    /// Rule 8: the publish path refuses the very shapes `decide_placement`
    /// refuses, so no record can strand every device on the account.
    #[test]
    fn publishing_settings_no_reader_could_place_under_is_refused() {
        let world = FakeWorld::new();
        let device = world.device(b"alice");
        for (settings, refusal) in [
            (
                placed(PinMode::External, None),
                PlacementRefusal::NoProvider,
            ),
            (placed(PinMode::Dual, None), PlacementRefusal::NoProvider),
            (
                placed(
                    PinMode::External,
                    Some(byo("https://api.pinata.cloud", ByoKind::Pinata, Some("t"))),
                ),
                PlacementRefusal::NoExternalIngress(ByoKind::Pinata),
            ),
        ] {
            let api = ApiClient::new(
                device.http.clone(),
                device.credential_store.clone(),
                String::new(),
            );
            let outcome = block_on(publish_settings(
                &device.record_store,
                &api,
                &device.floor_store,
                &device.snapshot_cache,
                &world.scheduler,
                &SyncTimingProfile::CI,
                &mut SeededEntropy::new(3),
                &OrphanHeads::default(),
                &[7u8; 32],
                &settings,
            ));
            assert_eq!(
                outcome.unwrap_err(),
                SettingsPublishError::Placement(refusal),
                "{settings:?} must never be published"
            );
            assert!(
                device.http.requests().is_empty(),
                "a refused publish never reaches the network"
            );
        }
    }

    /// Placement is what the durable upload mark is keyed by, so two placements
    /// must not share destinations — a resumed version would otherwise read
    /// progress towards destinations these are not. One endpoint is not one
    /// destination: the provider kind names it too.
    #[test]
    fn each_set_of_destinations_tags_itself_apart() {
        let one = "https://a.example";
        let variants = [
            Placement::Hosted,
            Placement::External(byo(one, ByoKind::Kubo, Some("tok"))),
            Placement::External(byo("https://b.example", ByoKind::Kubo, Some("tok"))),
            Placement::Dual(byo(one, ByoKind::Kubo, Some("tok"))),
            Placement::Dual(byo(one, ByoKind::Psa, Some("tok"))),
            Placement::Dual(byo(one, ByoKind::Pinata, Some("tok"))),
        ]
        .map(|placement| placement.destinations().encode());
        for (i, tag) in variants.iter().enumerate() {
            for other in &variants[i + 1..] {
                assert_ne!(tag, other, "distinct destinations, distinct tags");
            }
        }
    }

    /// Rotating the credential does not move the destination. The blocks are
    /// still on that node, and re-tagging would strand every leaf already
    /// released to it.
    #[test]
    fn a_rotated_bearer_is_the_same_destination() {
        let endpoint = "https://a.example";
        let tag = |token| byo_tag(&byo(endpoint, ByoKind::Kubo, token));
        assert_eq!(tag(Some("tok")), tag(Some("rotated")));
        assert_eq!(tag(Some("tok")), tag(None));
    }

    /// A leaf released from staging is safe to skip only where the leg that can
    /// fail this op already holds it. The hosted leg is that leg everywhere but
    /// external-only, so switching the mirror on or off never strands a version
    /// whose bytes the hosted store already took.
    ///
    /// The `External` reading of a prior `Dual` mark rests on
    /// [`Destinations::mirror_missed`]: a dual write only names its mirror in a
    /// mark that mirror actually took.
    #[test]
    fn progress_carries_exactly_where_the_op_failing_leg_already_holds_the_bytes() {
        let one = byo("https://a.example", ByoKind::Kubo, Some("tok"));
        let two = byo("https://b.example", ByoKind::Kubo, Some("tok"));
        let carries = |here: &Placement, earlier: &Placement| {
            here.destinations()
                .required_legs_hold(&earlier.destinations())
        };

        let hosted = Placement::Hosted;
        let dual_one = Placement::Dual(one.clone());
        let dual_two = Placement::Dual(two.clone());
        let external_one = Placement::External(one);
        let external_two = Placement::External(two);

        for (here, earlier) in [
            (&dual_one, &hosted),
            (&hosted, &dual_one),
            (&dual_one, &dual_two),
            (&external_one, &dual_one),
            (&external_one, &external_one),
        ] {
            assert!(carries(here, earlier), "the required leg holds the bytes");
        }
        for (here, earlier) in [
            (&hosted, &external_one),
            (&dual_one, &external_one),
            (&external_one, &hosted),
            (&external_one, &external_two),
            (&external_one, &dual_two),
        ] {
            assert!(
                !carries(here, earlier),
                "the required leg never received them"
            );
        }
    }

    /// A dual mirror that missed the released blocks is a gap to report, and
    /// only dual has a mirror to gap.
    #[test]
    fn only_a_dual_mirror_can_gap() {
        let one = byo("https://a.example", ByoKind::Kubo, Some("tok"));
        let two = byo("https://b.example", ByoKind::Kubo, Some("tok"));
        let holds = |here: &Placement, earlier: &Placement| {
            here.destinations()
                .mirror_leg_holds(&earlier.destinations())
        };
        let dual_one = Placement::Dual(one.clone());

        assert!(!holds(&dual_one, &Placement::Hosted));
        assert!(!holds(&dual_one, &Placement::Dual(two)));
        assert!(holds(&dual_one, &dual_one));
        assert!(holds(&Placement::Hosted, &dual_one));
        assert!(holds(&Placement::External(one), &Placement::Hosted));
    }

    /// A mirror that missed a block narrows the mark to the hosted leg, so a
    /// later external-only session no longer reads it as progress — and the set
    /// never narrows to no destination at all.
    #[test]
    fn a_missed_mirror_narrows_the_mark_to_the_hosted_leg() {
        let one = byo("https://a.example", ByoKind::Kubo, Some("tok"));
        let mut dual = Placement::Dual(one.clone()).destinations();
        dual.mirror_missed();
        assert_eq!(dual, Placement::Hosted.destinations());
        assert!(
            !Placement::External(one.clone())
                .destinations()
                .required_legs_hold(&dual)
        );
        assert!(
            Placement::Dual(one.clone())
                .destinations()
                .required_legs_hold(&dual)
        );

        let mut external = Placement::External(one).destinations();
        external.mirror_missed();
        assert_eq!(
            Destinations::decode(&external.encode()),
            Some(external),
            "the only leg there is never drops out of the set"
        );
    }

    /// AGENTS.md rule 8: the reader accepts exactly what the writer can emit.
    #[test]
    fn destinations_decode_only_what_encode_can_produce() {
        let one = byo("https://a.example", ByoKind::Kubo, Some("tok"));
        for placement in [
            Placement::Hosted,
            Placement::External(one.clone()),
            Placement::Dual(one),
        ] {
            let encoded = placement.destinations().encode();
            assert_eq!(
                Destinations::decode(&encoded),
                Some(placement.destinations()),
            );
        }
        let mut hosted = Placement::Hosted.destinations().encode();
        hosted[2] = 1;
        assert_eq!(
            Destinations::decode(&hosted),
            None,
            "a tag under an absent external leg is not an encoding"
        );
        assert_eq!(Destinations::decode(&[0u8; Destinations::LEN]), None);
        assert_eq!(Destinations::decode(&[2u8; Destinations::LEN]), None);
        assert_eq!(Destinations::decode(&[]), None);
    }
}
