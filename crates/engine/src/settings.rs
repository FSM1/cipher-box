//! The vault settings plane: publish and resolve the owner's own client
//! configuration as a record on the network (CONTEXT.md "Vault settings
//! record").
//!
//! Server-free by construction. The name is the `settings-ipns-keypair` edge
//! and the seal is HPKE-to-self under `enc-subkey`, both pure functions of the
//! login secret, so the record resolves at cold start before any vault
//! resolve — a self-hosting owner never needs CipherBox to find their own node.
//!
//! **A settings record that will not resolve never blocks cold start.** Every
//! failure degrades to [`VaultSettings::default`], and the whole load is
//! bounded by [`SyncTimingProfile::settings_load_budget`] measured on the
//! injected scheduler.

use core::future::{Future, poll_fn};
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;

use cipherbox_core::codec::{Map, Value, decode, encode};
use cipherbox_core::content::decode_content_cid_str;
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{open_settings_record, seal_settings_record};
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::content::limits::MAX_RESOLVED_RECORD_BYTES;
use crate::content::{
    ByoIpfsConfig, ByoKind, ContentPlane, Gateway, PinMode, ProviderError, read_block,
    validate_endpoint,
};
use crate::entropy::{Entropy, EntropyError};
use crate::gate::floor;
use crate::net::fanout_get_verify;
use crate::net::publish::{PublishReceipt, head_cid_from_value};
use crate::net::record_publish::{
    PreflightError, RecordPublishError, RecordPublishRequest, preflight_settings, publish_record,
};
use crate::profile::SyncTimingProfile;
use crate::seams::{CredentialStore, FloorStore, Http, RecordTransport, Scheduler};

/// How many versions of a file's content the vault retains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetentionPolicy {
    /// Keep every version within quota (blueprint/engine.md "Content plane").
    #[default]
    KeepAll,
    /// Keep the newest `n` versions; an explicit prune retires the rest. `n` is
    /// never zero — see [`SettingsInvalid::RetainsNoVersions`].
    KeepLatest(u64),
}

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

/// The documented defaults every degraded load falls back to: CipherBox's
/// hosted pin store, no member provider, keep every version.
impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            pin_mode: PinMode::Hosted,
            byo: None,
            retention: RetentionPolicy::KeepAll,
        }
    }
}

/// A settings payload no build may publish or act on. Enforced release-active
/// on both sides (AGENTS.md rule 8): the encode path returns `Err` rather than
/// sealing bytes the decode path would refuse, and the decode path re-runs the
/// same check on the network's copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsInvalid {
    /// The BYO endpoint is not one the Http seam may be pointed at. A resolved
    /// record is network input naming a host the engine will later talk to, so
    /// it clears the same bar as a member-typed endpoint.
    Endpoint(ProviderError),
    /// A retention policy keeping zero versions, which would plan the retire of
    /// the live version along with its history.
    RetainsNoVersions,
}

/// Why a settings publish did not reach the network. Every variant is
/// fail-closed: nothing is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsPublishError {
    /// The payload would not decode back (see [`SettingsInvalid`]).
    Invalid(SettingsInvalid),
    /// Core refused to encode or seal the body.
    Codec(CodecError),
    /// The host could not supply the per-record HPKE ephemeral scalar.
    Entropy(EntropyError),
    /// The sealed record does not reopen under the enc subkey the reader will
    /// use — an encoder bug caught before it reaches the network.
    Preflight(PreflightError),
    /// The sealed record exceeds the ceiling every block read enforces, so this
    /// build's own reader would always refuse it.
    TooLarge {
        /// The sealed record's size.
        size: usize,
        /// The enforced ceiling.
        limit: usize,
    },
    /// The shared publish port failed.
    Publish(RecordPublishError),
}

/// Why a load fell back to [`VaultSettings::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultsReason {
    /// No endpoint served a record that verifies under the settings name.
    NoRecord,
    /// The load did not finish inside the profile's budget.
    TimedOut,
    /// A record was found but yielded no usable settings: its head block is
    /// unavailable or mis-addressed, it will not open under the enc subkey, its
    /// body is malformed or invalid, or its sequence is below the durable floor
    /// (a rollback).
    Unreadable,
}

/// What a load produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsLoad {
    /// The published record opened and validated.
    Resolved(VaultSettings),
    /// No usable record; the documented defaults apply.
    Defaults(DefaultsReason),
}

impl SettingsLoad {
    /// The settings to run with either way — the defaults on a degraded load.
    #[must_use]
    pub fn settings(self) -> VaultSettings {
        match self {
            Self::Resolved(settings) => settings,
            Self::Defaults(_) => VaultSettings::default(),
        }
    }
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
    let body = encode_settings_body(settings)?;
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    entropy
        .fill(ephemeral.as_mut_slice())
        .map_err(SettingsPublishError::Entropy)?;
    let enc_secret = kdf::enc_subkey(login_secret);
    let block = seal_settings_record(&enc_secret, &ephemeral, &body)
        .map_err(SettingsPublishError::Codec)?;
    if block.len() > MAX_RESOLVED_RECORD_BYTES {
        return Err(SettingsPublishError::TooLarge {
            size: block.len(),
            limit: MAX_RESOLVED_RECORD_BYTES,
        });
    }
    let head = preflight_settings(&enc_secret, block).map_err(SettingsPublishError::Preflight)?;

    let signer = kdf::settings_ipns_keypair(login_secret);
    let name = IpnsName::from_public_key(&signer.verifying_key());
    publish_record(
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
    .map_err(SettingsPublishError::Publish)
}

/// Resolve the vault settings record, bounded by
/// [`SyncTimingProfile::settings_load_budget`]. Never fails: a record that will
/// not resolve, will not open, or will not validate yields the documented
/// defaults, because cold start must proceed without one.
pub async fn load_settings<T, H, F, Sch>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    scheduler: &Sch,
    profile: &SyncTimingProfile,
    login_secret: &[u8],
) -> SettingsLoad
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
    Sch: Scheduler,
{
    let name = settings_name(login_secret);
    let enc_secret = kdf::enc_subkey(login_secret);
    let load = resolve_settings(transport, gateway, http, floors, &enc_secret, &name);
    within(scheduler, profile.settings_load_budget, load)
        .await
        .unwrap_or(SettingsLoad::Defaults(DefaultsReason::TimedOut))
}

async fn resolve_settings<T, H, F>(
    transport: &T,
    gateway: &Gateway,
    http: &H,
    floors: &F,
    enc_secret: &X25519Secret,
    name: &IpnsName,
) -> SettingsLoad
where
    T: RecordTransport,
    H: Http,
    F: FloorStore,
{
    let Some((sequence, record_bytes)) = fanout_get_verify(transport, name).await else {
        return SettingsLoad::Defaults(DefaultsReason::NoRecord);
    };
    let key = name.as_str().as_bytes();
    // The settings record belongs to no scope and carries no epoch, so the
    // per-name sequence floor is its whole floor law. A floor the host cannot
    // read is never treated as no floor.
    let Ok(durable) = floor::sequence_floor(floors, key).await else {
        return SettingsLoad::Defaults(DefaultsReason::Unreadable);
    };
    if sequence < durable.unwrap_or(0) {
        return SettingsLoad::Defaults(DefaultsReason::Unreadable);
    }

    let Some(block) = fetch_head_block(gateway, http, name, &record_bytes).await else {
        return SettingsLoad::Defaults(DefaultsReason::Unreadable);
    };
    let Ok(body) = open_settings_record(enc_secret, &block) else {
        return SettingsLoad::Defaults(DefaultsReason::Unreadable);
    };
    let Ok(settings) = decode_settings_body(&body) else {
        return SettingsLoad::Defaults(DefaultsReason::Unreadable);
    };
    // The floor advances only behind a confirmed open, so an unopenable record
    // can never raise the bar the next resolve is held to.
    if floor::advance_sequence_on_unseal(floors, key, sequence)
        .await
        .is_err()
    {
        return SettingsLoad::Defaults(DefaultsReason::Unreadable);
    }
    SettingsLoad::Resolved(settings)
}

/// The head block the verified record anchors, taken fail-closed on its CID.
async fn fetch_head_block<H: Http>(
    gateway: &Gateway,
    http: &H,
    name: &IpnsName,
    record_bytes: &[u8],
) -> Option<Vec<u8>> {
    let verified = IpnsRecord::unmarshal(record_bytes)
        .and_then(|record| record.verify(name))
        .ok()?;
    let cid_str = head_cid_from_value(&verified.value)?;
    let expected_cid = decode_content_cid_str(&cid_str).ok()?;
    read_block(gateway, http, &cid_str, &expected_cid, ContentPlane::Root)
        .await
        .ok()
}

/// Run `work`, giving up once `budget` has elapsed on the injected scheduler.
/// `None` is the timeout. Time enters only through [`Scheduler::sleep`] — no
/// clock is read here.
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
    /// The body decoded but names a configuration no build may act on.
    Invalid(SettingsInvalid),
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

/// The invariants the decode path rejects, re-checked on a constructed payload
/// so the seal path never publishes settings it would refuse to read back.
fn validate(settings: &VaultSettings) -> Result<(), SettingsInvalid> {
    if let Some(byo) = &settings.byo {
        validate_endpoint(&byo.endpoint).map_err(SettingsInvalid::Endpoint)?;
    }
    if settings.retention == RetentionPolicy::KeepLatest(0) {
        return Err(SettingsInvalid::RetainsNoVersions);
    }
    Ok(())
}

/// Encode a settings body. The returned buffer and the transient `Value` tree
/// both carry the BYO access token verbatim, so this is the tree's terminal
/// owner (it is wiped here) and the buffer is handed back in a zeroizing owner.
fn encode_settings_body(
    settings: &VaultSettings,
) -> Result<Zeroizing<Vec<u8>>, SettingsPublishError> {
    validate(settings).map_err(SettingsPublishError::Invalid)?;

    let mut byo = Map::new();
    if let Some(config) = &settings.byo {
        byo.insert(
            "accessToken",
            match &config.access_token {
                None => Value::Null,
                Some(token) => Value::Text(token.to_string()),
            },
        );
        byo.insert("endpoint", Value::Text(config.endpoint.clone()));
        byo.insert("kind", Value::Text(kind_str(config.kind).to_string()));
    }

    let mut m = Map::new();
    m.insert(
        "byo",
        match settings.byo {
            None => Value::Null,
            Some(_) => Value::Map(byo),
        },
    );
    m.insert(
        "keepLatest",
        match settings.retention {
            RetentionPolicy::KeepAll => Value::Null,
            RetentionPolicy::KeepLatest(n) => Value::Unsigned(n),
        },
    );
    m.insert(
        "pinMode",
        Value::Text(pin_mode_str(settings.pin_mode).to_string()),
    );

    let mut tree = Value::Map(m);
    let encoded = encode(&tree).map(Zeroizing::new);
    tree.zeroize_bytes();
    encoded.map_err(SettingsPublishError::Codec)
}

fn decode_settings_body(bytes: &[u8]) -> Result<VaultSettings, BodyError> {
    let mut tree = decode(bytes)?;
    let decoded = read_settings_map(&mut tree);
    tree.zeroize_bytes();
    let settings = decoded?;
    validate(&settings).map_err(BodyError::Invalid)?;
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
        other => RetentionPolicy::KeepLatest(other.as_unsigned()?),
    };
    // Taken by value so the credential inside moves into its zeroizing owner
    // rather than leaving a second live copy behind.
    let byo = match map.remove("byo") {
        None => return Err(Malformed::MissingField { field: "byo" }.into()),
        Some(byo) => read_byo(byo)?,
    };
    Ok(VaultSettings {
        pin_mode,
        byo,
        retention,
    })
}

fn read_byo(value: Value) -> Result<Option<ByoIpfsConfig>, BodyError> {
    let mut byo = match value {
        Value::Null => return Ok(None),
        Value::Map(byo) => byo,
        other => return Err(other.as_map().unwrap_err().into()),
    };
    reject_unknown_keys(&byo, &BYO_KEYS)?;
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
    let endpoint = req(&byo, "endpoint")?.as_text()?.to_string();
    let kind = match req(&byo, "kind")?.as_text()? {
        BYO_KIND_KUBO => ByoKind::Kubo,
        BYO_KIND_PSA => ByoKind::Psa,
        BYO_KIND_PINATA => ByoKind::Pinata,
        _ => return Err(BodyError::UnknownVariant { field: "kind" }),
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

    fn byo(endpoint: &str, kind: ByoKind, token: Option<&str>) -> ByoIpfsConfig {
        ByoIpfsConfig {
            endpoint: endpoint.to_owned(),
            kind,
            access_token: token.map(|t| Zeroizing::new(t.to_owned())),
        }
    }

    fn round_trip(settings: &VaultSettings) -> VaultSettings {
        let body = encode_settings_body(settings).expect("encode");
        decode_settings_body(&body).expect("decode")
    }

    #[test]
    fn every_tenant_of_the_record_round_trips() {
        for pin_mode in [PinMode::Hosted, PinMode::External, PinMode::Dual] {
            for kind in [ByoKind::Kubo, ByoKind::Psa, ByoKind::Pinata] {
                for retention in [RetentionPolicy::KeepAll, RetentionPolicy::KeepLatest(7)] {
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
            byo: Some(byo("http://node.example", ByoKind::Kubo, None)),
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
        let extended = encode(&tree).expect("encode");
        assert_eq!(
            decode_settings_body(&extended).unwrap_err(),
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

    /// The encode guard and the decode reject are the same predicate, so a
    /// build can never seal settings its own reader refuses (AGENTS.md rule 8).
    #[test]
    fn the_encode_guard_and_the_decode_reject_agree() {
        for settings in [
            VaultSettings {
                retention: RetentionPolicy::KeepLatest(0),
                ..VaultSettings::default()
            },
            VaultSettings {
                byo: Some(byo("ftp://node.example", ByoKind::Kubo, None)),
                ..VaultSettings::default()
            },
        ] {
            let invalid = match encode_settings_body(&settings) {
                Err(SettingsPublishError::Invalid(invalid)) => invalid,
                other => panic!("encode admitted {settings:?}: {other:?}"),
            };
            // Hand-encode past the guard: the reader must reach the same verdict.
            let mut m = Map::new();
            m.insert(
                "byo",
                match &settings.byo {
                    None => Value::Null,
                    Some(config) => {
                        let mut b = Map::new();
                        b.insert("accessToken", Value::Null);
                        b.insert("endpoint", Value::Text(config.endpoint.clone()));
                        b.insert("kind", Value::Text(kind_str(config.kind).to_string()));
                        Value::Map(b)
                    }
                },
            );
            m.insert(
                "keepLatest",
                match settings.retention {
                    RetentionPolicy::KeepAll => Value::Null,
                    RetentionPolicy::KeepLatest(n) => Value::Unsigned(n),
                },
            );
            m.insert(
                "pinMode",
                Value::Text(pin_mode_str(settings.pin_mode).to_string()),
            );
            assert_eq!(
                decode_settings_body(&encode(&Value::Map(m)).expect("encode")).unwrap_err(),
                BodyError::Invalid(invalid),
            );
        }
    }
}
