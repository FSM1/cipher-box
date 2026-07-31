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
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::content::validate_byo_config;
use crate::content::{ByoIpfsConfig, ByoKind, Gateway, PinMode, ProviderError, RetentionPolicy};
use crate::entropy::{Entropy, EntropyError};
use crate::gate::floor;
use crate::net::fanout_get_verify;
use crate::net::fetch_head_block;
use crate::net::publish::{PublishOutcome, PublishReceipt};
use crate::net::record_publish::{
    PreflightError, RecordPublishError, RecordPublishRequest, preflight_settings, publish_record,
};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SeamError, SnapshotCache,
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

/// Why a settings publish did not reach the network. Every variant is
/// fail-closed: nothing is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsPublishError {
    /// The BYO config is not one the Http seam may be pointed at.
    Byo(ProviderError),
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
}

/// Why a load did not use the published record, carried by both degraded
/// outcomes. Reported rather than collapsed, because the reasons are not
/// equally benign: `NoRecord` is a first run, while `Suppressed` and
/// `RolledBack` are what an adversary who controls the record plane produces,
/// and reverting a member's placement choice to the hosted default is exactly
/// what they gain by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultsReason {
    /// No endpoint served a record, and this device has no durable floor for
    /// the name — no evidence here that the account has ever published
    /// settings.
    NoRecord,
    /// No usable record, but the durable sequence floor proves one was adopted
    /// here before: the record is being withheld or its head block is
    /// unreachable.
    Suppressed,
    /// A record below the durable sequence floor — a replay, not staleness.
    RolledBack {
        /// The durable floor the record failed.
        floor: u64,
        /// The sequence the replayed record carried.
        sequence: u64,
    },
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

/// Seal `settings` and publish them at [`settings_name`] through the shared
/// publish port, so the record inherits register-first, seq-CAS, and confirm
/// like every other record.
#[allow(clippy::too_many_arguments)]
pub async fn publish_settings<T, H, C, F, Sch>(
    transport: &T,
    api: &ApiClient<H, C>,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    entropy: &mut dyn Entropy,
    login_secret: &[u8],
    settings: &VaultSettings,
) -> Result<PublishReceipt, SettingsPublishError>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    validate(settings).map_err(SettingsPublishError::Byo)?;
    let body = encode_settings_body(settings).map_err(SettingsPublishError::Codec)?;
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
    let head = preflight_settings(&enc_secret, block).map_err(SettingsPublishError::Preflight)?;

    let signer = kdf::settings_ipns_keypair(login_secret);
    let name = IpnsName::from_public_key(&signer.verifying_key());
    let receipt = publish_record(
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
    .map_err(SettingsPublishError::Publish)?;

    // Only a confirmed publish advances the floor. Returning `Ok` on an
    // unconfirmed one would leave the writer's floor behind the network's
    // sequence, so the next publish would mint a colliding sequence and the
    // update would silently never land.
    let PublishOutcome::Published { sequence } = receipt.outcome else {
        return Err(SettingsPublishError::Unconfirmed);
    };
    floor::advance_sequence_on_unseal(floors, name.as_str().as_bytes(), sequence)
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
    );
    let reason = match within(scheduler, profile.settings_load_budget, load).await {
        Some(Ok(settings)) => return SettingsLoad::Resolved(settings),
        Some(Err(reason)) => reason,
        None => DefaultsReason::TimedOut,
    };
    // A rollback takes this arm like every other reason: pinning last-known-good
    // is what the record plane already owes a gate failure (blueprint/engine.md).
    match cached.and_then(|block| open_settings_head(&enc_secret, &block)) {
        Some(settings) => SettingsLoad::Stale { settings, reason },
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
fn open_settings_head(enc_secret: &X25519Secret, block: &[u8]) -> Option<VaultSettings> {
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
) -> Result<VaultSettings, DefaultsReason>
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sn: SnapshotCache,
{
    let key = name.as_str().as_bytes();
    let cache_key = settings_cache_key(name);
    // Cache-first, like every resolve (blueprint/engine.md).
    *cached = snapshots.get(&cache_key).await.ok().flatten();
    // The settings record belongs to no scope and carries no epoch, so the
    // per-name sequence floor is its whole floor law. A floor the host cannot
    // read is never treated as no floor.
    let Ok(durable) = floor::sequence_floor(floors, key).await else {
        return Err(DefaultsReason::FloorUnreadable);
    };
    let Some((sequence, record_bytes)) = fanout_get_verify(transport, name).await else {
        // A durable floor is proof this account has published settings, so
        // finding none now is a suppression rather than a first run.
        return Err(match durable {
            Some(_) => DefaultsReason::Suppressed,
            None => DefaultsReason::NoRecord,
        });
    };
    let floor = durable.unwrap_or(0);
    if sequence < floor {
        return Err(DefaultsReason::RolledBack { floor, sequence });
    }

    // The record verified under a name only this account can sign for, so a
    // head block that will not come back is a withheld settings record.
    let Ok((_, block)) = fetch_head_block(gateway, http, name, &record_bytes, None).await else {
        return Err(DefaultsReason::Suppressed);
    };
    let settings = open_settings_head(enc_secret, &block).ok_or(DefaultsReason::Unreadable)?;
    // Only a record that cleared its floor and opened becomes last-known-good,
    // and what is stored is the sealed block, so ciphertext-only-at-rest holds.
    let _ = snapshots.put(&cache_key, &block).await;
    // Advancing behind the open, never ahead of it, is the floor law: a record
    // that will not open must not raise the bar the next resolve is held to.
    // Neither store failing is a verdict on settings we just authenticated.
    let _ = floor::advance_sequence_on_unseal(floors, key, sequence).await;
    Ok(settings)
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

/// Encode a settings body. Both the returned buffer and the transient `Value`
/// tree carry the BYO access token verbatim, so this is the tree's terminal
/// owner and the buffer is handed back in a zeroizing one.
fn encode_settings_body(settings: &VaultSettings) -> Result<Zeroizing<Vec<u8>>, CodecError> {
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

    let mut tree = Value::Map(m);
    let encoded = encode(&tree).map(Zeroizing::new);
    tree.zeroize_bytes();
    encoded
}

fn decode_settings_body(bytes: &[u8]) -> Result<VaultSettings, BodyError> {
    let mut tree = decode(bytes)?;
    let decoded = read_settings_map(&mut tree);
    // Terminal owner of the decoded tree: the credential inside is wiped on
    // every exit, including the early returns a malformed body takes.
    tree.zeroize_bytes();
    let settings = decoded?;
    validate(&settings).map_err(BodyError::Byo)?;
    Ok(settings)
}

/// The body's keys, exhaustive at this version — a body carrying any other key
/// was written by a build this one does not share a schema with.
const BODY_KEYS: [&str; 3] = ["byo", "keepLatest", "pinMode"];
const BYO_KEYS: [&str; 3] = ["accessToken", "endpoint", "kind"];

fn read_settings_map(tree: &mut Value) -> Result<VaultSettings, BodyError> {
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
    let byo = read_byo(map.get_mut("byo"))?;
    Ok(VaultSettings {
        pin_mode,
        byo,
        retention,
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

    fn round_trip(settings: &VaultSettings) -> VaultSettings {
        decode_settings_body(&encode_settings_body(settings).expect("encode")).expect("decode")
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
            encode_settings_body(&settings).expect("encode"),
            encode_settings_body(&settings).expect("encode"),
        );
    }

    #[test]
    fn a_body_this_version_does_not_share_a_schema_with_is_refused() {
        let settings = VaultSettings::default();
        let mut tree = decode(&encode_settings_body(&settings).expect("encode")).expect("decode");
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
        assert_eq!(
            decode_settings_body(&encode(&Value::Map(m)).expect("encode")).unwrap_err(),
            BodyError::RetainsNoVersions,
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
                decode_settings_body(&encode_settings_body(&settings).expect("encode"))
                    .unwrap_err(),
                BodyError::Byo(refused),
                "{endpoint}: the reader must refuse what the writer refuses",
            );
        }
    }
}
