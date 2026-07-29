//! The vault settings record, joined end to end: sealed HPKE-to-self under
//! `enc-subkey`, published through the shared publish port at the
//! `settings-ipns-keypair` name, and resolved back by a second device of the
//! same account that only ever saw the network (#870).
//!
//! Its contract is the inverse of the write plane's: a settings record that
//! will not resolve must never block cold start, so every failure degrades to
//! the documented defaults inside a scheduler-measured budget.

use core::future::poll_fn;
use core::num::NonZeroU64;
use core::task::Poll;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use cipherbox_core::content::{compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::seal_settings_record;
use zeroize::Zeroizing;

use cipherbox_engine::api::ApiClient;
use cipherbox_engine::content::{ByoIpfsConfig, ByoKind, DAG_ROOT_CODEC, PinMode};
use cipherbox_engine::seams::{
    EndpointId, FloorStore, HttpRequest, HttpResponse, RecordTransport, Scheduler, SeamError,
    SeamResult, UnixMillis,
};
use cipherbox_engine::testkit::fakes::VirtualScheduler;
use cipherbox_engine::testkit::{FakeDevice, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    DefaultsReason, Gateway, GatewayConfig, GatewaySource, ProviderError, RetentionPolicy,
    SettingsLoad, SettingsPublishError, SyncTimingProfile, VaultSettings, load_settings,
    publish_settings, settings_name,
};

const SECRET: [u8; 32] = [7u8; 32];
/// A second account signed in on the same device set.
const OTHER_SECRET: [u8; 32] = [9u8; 32];
const TTL_NANOS: u64 = 2_000_000_000;
const EOL: &str = "2099-01-01T00:00:00Z";

// ---------------------------------------------------------------------------
// One content-addressed block store behind both the pin API and the gateway.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Blocks {
    store: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl Blocks {
    fn put(&self, block: Vec<u8>) -> String {
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        self.store.lock().expect("lock").insert(cid.clone(), block);
        cid
    }

    fn reply(&self, request: &HttpRequest) -> SeamResult<HttpResponse> {
        let ok = |body: Vec<u8>| {
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body,
            })
        };
        let url = &request.url;
        if url.ends_with("/content/upload") {
            let block = request.body.clone().unwrap_or_default();
            let size = block.len();
            let cid = self.put(block);
            return ok(format!("{{\"cid\":\"{cid}\",\"size\":{size}}}").into_bytes());
        }
        if url.contains("/registry/") {
            return ok(Vec::new());
        }
        let cid = url
            .rsplit('/')
            .next()
            .and_then(|tail| tail.split('?').next())
            .unwrap_or_default();
        match self.store.lock().expect("lock").get(cid) {
            Some(block) => ok(block.clone()),
            None => Err(SeamError::new("no such block")),
        }
    }
}

fn serve_http(device: &FakeDevice, blocks: &Blocks, calls: usize) {
    for _ in 0..calls {
        let blocks = blocks.clone();
        device
            .http
            .enqueue_derived(move |request| blocks.reply(request));
    }
}

fn gateway() -> Gateway {
    GatewayConfig {
        accelerator: None,
        public_fallbacks: vec![GatewaySource {
            base_url: "http://gateway.test".to_owned(),
            bearer: None,
        }],
    }
    .into_gateway()
}

fn configured() -> VaultSettings {
    VaultSettings {
        pin_mode: PinMode::Dual,
        byo: Some(ByoIpfsConfig {
            endpoint: "https://kubo.example".to_owned(),
            kind: ByoKind::Kubo,
            access_token: Some(Zeroizing::new("s3cret".to_owned())),
        }),
        retention: RetentionPolicy::KeepLatest(NonZeroU64::new(3).expect("nonzero")),
    }
}

/// Publish `settings` from `device`, asserting the publish confirmed.
fn publish(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    secret: &[u8],
    settings: &VaultSettings,
) {
    serve_http(device, blocks, 4);
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    block_on(publish_settings(
        &device.record_store,
        &api,
        &device.floor_store,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(1),
        secret,
        settings,
    ))
    .expect("the settings record publishes");
}

/// Put `body` on the block plane and publish a record anchoring it at the
/// account's settings name and `sequence`, bypassing the publish path. The
/// ephemeral varies with the sequence: two bodies sealed under one key must
/// never share one, in fixtures as in production.
fn seed_settings(device: &FakeDevice, blocks: &Blocks, body: &[u8], sequence: u64) {
    let mut ephemeral = [8u8; 32];
    ephemeral[0] = u8::try_from(sequence).expect("fixture sequences are small");
    let block = seal_settings_record(&kdf::enc_subkey(&SECRET), &ephemeral, body).expect("seal");
    let cid = blocks.put(block);
    let record = IpnsRecord::create_v2(
        &kdf::settings_ipns_keypair(&SECRET),
        format!("/ipfs/{cid}").as_bytes(),
        sequence,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, settings_name(&SECRET).as_str(), record.clone());
    }
}

fn load(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks, secret: &[u8]) -> SettingsLoad {
    serve_http(device, blocks, 4);
    block_on(load_settings(
        &device.record_store,
        &gateway(),
        &device.http,
        &device.floor_store,
        &world.scheduler,
        &SyncTimingProfile::CI,
        secret,
    ))
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[test]
fn settings_written_on_one_device_resolve_on_a_second_device_of_the_account() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice-laptop");
    publish(&world, &alice, &blocks, &SECRET, &configured());

    // Device B shares only the network and the clock.
    let bob = world.device(b"alice-phone");
    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Resolved(configured()),
        "the second device opens the record under its own enc-subkey"
    );
}

/// A publish that does not advance the writer's own floor mints the same
/// sequence next time, so the second update collides and silently never lands —
/// and this is the path a leaked BYO credential is rotated on.
#[test]
fn a_second_publish_from_the_same_device_supersedes_the_first() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice-laptop");
    let name = settings_name(&SECRET);

    publish(&world, &alice, &blocks, &SECRET, &configured());
    assert_eq!(
        block_on(alice.floor_store.sequence_floor(name.as_str().as_bytes())).expect("read"),
        Some(1),
        "a confirmed publish advances the writer's own floor",
    );

    let rotated = VaultSettings {
        byo: Some(ByoIpfsConfig {
            endpoint: "https://kubo.example".to_owned(),
            kind: ByoKind::Kubo,
            access_token: Some(Zeroizing::new("rotated".to_owned())),
        }),
        ..configured()
    };
    publish(&world, &alice, &blocks, &SECRET, &rotated);

    let bob = world.device(b"alice-phone");
    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Resolved(rotated),
        "the second device sees the rotated credential, not the superseded one",
    );
}

/// HPKE ephemeral reuse across two seals under one recipient key is a
/// confidentiality break, so every publish must draw a fresh one.
#[test]
fn consecutive_publishes_never_reuse_the_hpke_ephemeral() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    // One entropy source across both calls: a hoisted or cached scalar shows up
    // as two identical `enc` values.
    let mut entropy = SeededEntropy::new(4);
    let mut encs = Vec::new();
    for settings in [VaultSettings::default(), configured()] {
        serve_http(&device, &blocks, 4);
        block_on(publish_settings(
            &device.record_store,
            &api,
            &device.floor_store,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut entropy,
            &SECRET,
            &settings,
        ))
        .expect("publish");
        let block = published_block(&device, &blocks, &settings_name(&SECRET));
        let decoded = cipherbox_core::codec::decode(&block).expect("decode");
        encs.push(
            decoded
                .as_map()
                .expect("map")
                .get("enc")
                .expect("enc")
                .as_bytes()
                .expect("bytes")
                .to_vec(),
        );
    }
    assert_ne!(encs[0], encs[1], "each publish draws a fresh ephemeral");
}

/// The head block the record currently published at `name` anchors.
fn published_block(device: &FakeDevice, blocks: &Blocks, name: &IpnsName) -> Vec<u8> {
    let record = device
        .record_store
        .record_at(&device.record_store.endpoints()[0], name.as_str())
        .expect("published");
    let value = IpnsRecord::unmarshal(&record)
        .and_then(|r| r.verify(name))
        .expect("verifiable")
        .value;
    let cid = core::str::from_utf8(&value)
        .expect("utf8")
        .trim_start_matches("/ipfs/");
    blocks
        .store
        .lock()
        .expect("lock")
        .get(cid)
        .cloned()
        .expect("block on the plane")
}

#[test]
fn the_settings_name_is_derived_from_the_login_secret_alone() {
    assert_eq!(
        settings_name(&SECRET),
        IpnsName::from_public_key(&kdf::settings_ipns_keypair(&SECRET).verifying_key()),
        "the published name is the settings-ipns-keypair edge",
    );
    assert_ne!(
        settings_name(&SECRET),
        settings_name(&OTHER_SECRET),
        "another account publishes at another name",
    );
}

#[test]
fn a_second_account_cannot_open_the_first_accounts_settings() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"shared-device");
    publish(&world, &alice, &blocks, &SECRET, &configured());

    // Re-publish the same bytes under the second account's own settings name,
    // so the record verifies and only the seal can refuse it.
    let record = alice
        .record_store
        .record_at(
            &alice.record_store.endpoints()[0],
            settings_name(&SECRET).as_str(),
        )
        .expect("alice published");
    let value = IpnsRecord::unmarshal(&record)
        .and_then(|r| r.verify(&settings_name(&SECRET)))
        .expect("verifiable")
        .value;
    let other_name = settings_name(&OTHER_SECRET);
    let transplanted = IpnsRecord::create_v2(
        &kdf::settings_ipns_keypair(&OTHER_SECRET),
        &value,
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in alice.record_store.endpoints() {
        alice
            .record_store
            .seed_record(&endpoint, other_name.as_str(), transplanted.clone());
    }

    let other = world.device(b"shared-device-second-account");
    assert_eq!(
        load(&world, &other, &blocks, &OTHER_SECRET),
        SettingsLoad::Defaults(DefaultsReason::Unreadable),
        "a record sealed to another enc-subkey never opens",
    );
    // The control: those same bytes are readable by the account they belong to,
    // so the refusal above is the seal and nothing upstream of it.
    assert!(matches!(
        load(&world, &other, &blocks, &SECRET),
        SettingsLoad::Resolved(_)
    ));
}

// ---------------------------------------------------------------------------
// Degradation: a settings record must never block cold start
// ---------------------------------------------------------------------------

#[test]
fn a_missing_settings_record_yields_defaults_not_an_error() {
    let world = FakeWorld::new();
    let device = world.device(b"cold");
    let load = load(&world, &device, &Blocks::default(), &SECRET);

    assert_eq!(
        load,
        SettingsLoad::Defaults(DefaultsReason::NoRecord),
        "no record and no durable floor is a first run, not a suppression",
    );
    assert_eq!(
        VaultSettings::default(),
        VaultSettings {
            pin_mode: PinMode::Hosted,
            byo: None,
            retention: RetentionPolicy::KeepAll,
        },
        "the documented defaults: hosted pinning, no member provider, keep all",
    );
}

/// A transport whose GET never settles — the shape of an unresolvable name.
#[derive(Clone)]
struct NeverAnswers;

impl RecordTransport for NeverAnswers {
    fn endpoints(&self) -> Vec<EndpointId> {
        vec![EndpointId::new("fake:hangs")]
    }

    async fn get_record(
        &self,
        _endpoint: &EndpointId,
        _routing_key: &str,
    ) -> SeamResult<Option<Vec<u8>>> {
        poll_fn(|_| Poll::<SeamResult<Option<Vec<u8>>>>::Pending).await
    }

    async fn put_record(
        &self,
        _endpoint: &EndpointId,
        _routing_key: &str,
        _record: &[u8],
    ) -> SeamResult<()> {
        Err(SeamError::new("never answers"))
    }
}

#[test]
fn an_unresolvable_settings_name_does_not_block_cold_start_past_the_budget() {
    // Auto-advance: virtual time moves only when the load's own budget sleep is
    // polled, so the clock reading below is the budget the load actually spent.
    let scheduler = VirtualScheduler::new().with_auto_advance();
    let device = FakeWorld::new().device(b"offline");
    let profile = SyncTimingProfile::CI;

    let load = block_on(load_settings(
        &NeverAnswers,
        &gateway(),
        &device.http,
        &device.floor_store,
        &scheduler,
        &profile,
        &SECRET,
    ));

    assert_eq!(load, SettingsLoad::Defaults(DefaultsReason::TimedOut));
    assert_eq!(
        scheduler.now(),
        UnixMillis(profile.settings_load_budget.as_millis() as u64),
        "the load gave up after exactly the profile's budget, measured on the seam",
    );
}

#[test]
fn a_rolled_back_record_yields_defaults_and_never_lowers_the_floor() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let name = settings_name(&SECRET);
    let key = name.as_str().as_bytes();

    // A perfectly openable record, below the device's durable floor: the
    // settings name carries no epoch, so the sequence floor is its whole
    // rollback defence.
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body("https://kubo.example"),
        3,
    );
    block_on(device.floor_store.raise_sequence_floor(key, 9)).expect("raise");

    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Defaults(DefaultsReason::RolledBack {
            floor: 9,
            sequence: 3
        }),
        "a sequence below the durable floor is a replay, reported as one",
    );
    assert_eq!(
        block_on(device.floor_store.sequence_floor(key)).expect("read"),
        Some(9),
        "a refused record never moves the floor",
    );
}

#[test]
fn an_unavailable_head_block_yields_defaults() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let name = settings_name(&SECRET);
    // A record anchoring a CID no gateway serves.
    let record = IpnsRecord::create_v2(
        &kdf::settings_ipns_keypair(&SECRET),
        format!("/ipfs/{}", blocks.put(b"never uploaded".to_vec())).as_bytes(),
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }

    // No HTTP is scripted, so every gateway source fails.
    assert_eq!(
        block_on(load_settings(
            &device.record_store,
            &gateway(),
            &device.http,
            &device.floor_store,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &SECRET,
        )),
        SettingsLoad::Defaults(DefaultsReason::Suppressed),
        "a verified record whose block will not come back is being withheld",
    );
}

// ---------------------------------------------------------------------------
// Encode/decode fail-closed symmetry (AGENTS.md rule 8)
// ---------------------------------------------------------------------------

#[test]
fn settings_the_reader_would_refuse_are_never_published() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );

    // A scheme the Http seam must never be pointed at.
    for endpoint in ["file:///etc/passwd", "ftp://node.example"] {
        let settings = VaultSettings {
            byo: Some(ByoIpfsConfig {
                endpoint: endpoint.to_owned(),
                kind: ByoKind::Kubo,
                access_token: None,
            }),
            ..VaultSettings::default()
        };
        serve_http(&device, &blocks, 4);
        let outcome = block_on(publish_settings(
            &device.record_store,
            &api,
            &device.floor_store,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut SeededEntropy::new(2),
            &SECRET,
            &settings,
        ));
        assert_eq!(
            outcome.unwrap_err(),
            SettingsPublishError::Endpoint(ProviderError::InvalidEndpoint),
            "the guard returns Err in every build, never a stripped assertion",
        );
        assert!(
            device
                .record_store
                .record_at(
                    &device.record_store.endpoints()[0],
                    settings_name(&SECRET).as_str()
                )
                .is_none(),
            "nothing reached the record plane",
        );
    }
}

#[test]
fn a_body_carrying_a_refused_endpoint_is_rejected_on_the_way_back_in() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");

    // The control: the same hand-sealed shape with an endpoint the seam may be
    // pointed at resolves, so the refusal below is the endpoint and nothing
    // upstream of it.
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body("https://kubo.example"),
        1,
    );
    assert!(matches!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(_)
    ));

    // Hand-sealed past the encode guard: the decode side must refuse the same
    // invariant, or a resolved record could point the engine at any URL.
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body("file:///etc/passwd"),
        2,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Defaults(DefaultsReason::Unreadable),
    );
}

/// A settings body built straight in core's codec, bypassing the encode guard.
fn hand_encoded_body(endpoint: &str) -> Vec<u8> {
    use cipherbox_core::codec::{Map, Value, encode};

    let mut byo = Map::new();
    byo.insert("accessToken", Value::Null);
    byo.insert("endpoint", Value::Text(endpoint.to_owned()));
    byo.insert("kind", Value::Text("kubo".to_owned()));
    let mut m = Map::new();
    m.insert("byo", Value::Map(byo));
    m.insert("keepLatest", Value::Null);
    m.insert("pinMode", Value::Text("hosted".to_owned()));
    encode(&Value::Map(m)).expect("encode")
}
