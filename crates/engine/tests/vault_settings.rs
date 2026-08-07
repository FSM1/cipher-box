//! The vault settings record, joined end to end: sealed HPKE-to-self under
//! `enc-subkey`, published through the shared publish port at the
//! `settings-ipns-keypair` name, and resolved back by a second device of the
//! same account that only ever saw the network.
//!
//! Its contract is the inverse of the write plane's: a settings record that
//! will not resolve must never block cold start, so every failure degrades —
//! to this device's last-known-good copy where one opens, and only then to the
//! documented defaults — inside a scheduler-measured budget.

use core::future::poll_fn;
use core::num::NonZeroU64;
use core::task::Poll;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use cipherbox_core::content::{compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{open_settings_record, seal_settings_record};
use zeroize::Zeroizing;

use cipherbox_engine::api::ApiClient;
use cipherbox_engine::content::{ByoIpfsConfig, ByoKind, DAG_ROOT_CODEC, PinMode};
use cipherbox_engine::seams::{
    EndpointId, FloorStore, HttpRequest, HttpResponse, RecordTransport, Scheduler, SeamError,
    SeamResult, SnapshotCache, UnixMillis,
};
use cipherbox_engine::testkit::fakes::VirtualScheduler;
use cipherbox_engine::testkit::{FakeDevice, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    DefaultsReason, Gateway, GatewayConfig, GatewaySource, OrphanHeads, ProviderError,
    RetentionPolicy, SettingsLoad, SettingsPublishError, SyncTimingProfile, VaultSettings,
    load_settings, publish_settings, settings_name,
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
    /// Answer register-first with a refusal, so the publish stops with its head
    /// block already uploaded and charged.
    refuse_register: Arc<Mutex<bool>>,
    /// Every retire request body, verbatim.
    retired: Arc<Mutex<Vec<String>>>,
}

impl Blocks {
    fn put(&self, block: Vec<u8>) -> String {
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        self.store.lock().expect("lock").insert(cid.clone(), block);
        cid
    }

    fn refuse_register(&self) {
        *self.refuse_register.lock().expect("lock") = true;
    }

    fn retired(&self) -> Vec<String> {
        self.retired.lock().expect("lock").clone()
    }

    /// The one block on the plane, for a fixture that uploaded exactly one.
    fn only_block(&self) -> String {
        let store = self.store.lock().expect("lock");
        assert_eq!(store.len(), 1, "exactly one block was uploaded");
        store.keys().next().expect("one block").clone()
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
        if url.ends_with("/registry/retire") {
            self.retired.lock().expect("lock").push(
                String::from_utf8(request.body.clone().unwrap_or_default())
                    .unwrap_or_else(|_| String::new()),
            );
            return ok(br#"{"retired":1,"unpinned":0}"#.to_vec());
        }
        if url.ends_with("/registry/register") && *self.refuse_register.lock().expect("lock") {
            return Ok(HttpResponse {
                status: 400,
                headers: Vec::new(),
                body: Vec::new(),
            });
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
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(1),
        &OrphanHeads::default(),
        secret,
        settings,
    ))
    .expect("the settings record publishes");
}

/// Publish `settings` from `device` over a transport that acks nothing back:
/// the attempt reaches the network, uploads its head block, and comes home
/// unconfirmed.
fn publish_unconfirmed(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    settings: &VaultSettings,
    entropy_seed: u64,
) -> SettingsPublishError {
    serve_http(device, blocks, 4);
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    block_on(publish_settings(
        &AcksNothingBack,
        &api,
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(entropy_seed),
        &OrphanHeads::default(),
        &SECRET,
        settings,
    ))
    .expect_err("a transport that acks nothing back never confirms")
}

/// Put `body` on the block plane and publish a record anchoring it at the
/// account's settings name and `sequence`, bypassing the publish path. The
/// ephemeral varies with the sequence: two bodies sealed under one key must
/// never share one, in fixtures as in production.
fn seed_settings(device: &FakeDevice, blocks: &Blocks, body: &[u8], sequence: u64) {
    seed_settings_until(device, blocks, body, sequence, EOL);
}

/// [`seed_settings`] with the record's client-signed EOL under the fixture's
/// control, so a lapsed one can be hand-minted.
fn seed_settings_until(
    device: &FakeDevice,
    blocks: &Blocks,
    body: &[u8],
    sequence: u64,
    eol: &str,
) {
    let mut ephemeral = [8u8; 32];
    ephemeral[0] = u8::try_from(sequence).expect("fixture sequences are small");
    let block = seal_settings_record(&kdf::enc_subkey(&SECRET), &ephemeral, body).expect("seal");
    let cid = blocks.put(block);
    let record = IpnsRecord::create_v2(
        &kdf::settings_ipns_keypair(&SECRET),
        format!("/ipfs/{cid}").as_bytes(),
        sequence,
        TTL_NANOS,
        eol,
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
        &device.snapshot_cache,
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
            &device.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut entropy,
            &OrphanHeads::default(),
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

/// A transport that acks every PUT and serves nothing back: the confirm
/// re-resolve reads no record at all.
#[derive(Clone)]
struct AcksNothingBack;

impl RecordTransport for AcksNothingBack {
    fn endpoints(&self) -> Vec<EndpointId> {
        vec![EndpointId::new("fake:write-only")]
    }

    async fn get_record(
        &self,
        _endpoint: &EndpointId,
        _routing_key: &str,
        _max_bytes: usize,
    ) -> SeamResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn put_record(
        &self,
        _endpoint: &EndpointId,
        _routing_key: &str,
        _record: &[u8],
    ) -> SeamResult<()> {
        Ok(())
    }
}

/// Retrying an unconfirmed publish is idempotent-in-sequence, so its floor must
/// stay put: raising it past bytes the network may never serve makes the retry
/// mint a fresh sequence instead of re-minting the same one.
#[test]
fn an_unconfirmed_publish_is_reported_and_never_advances_the_floor() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let outcome = publish_unconfirmed(&world, &device, &Blocks::default(), &configured(), 3);

    assert_eq!(outcome, SettingsPublishError::Unconfirmed);
    assert_eq!(
        block_on(
            device
                .floor_store
                .sequence_floor(settings_name(&SECRET).as_str().as_bytes())
        )
        .expect("read"),
        None,
        "an unconfirmed publish leaves the floor where it found it",
    );
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
        SettingsLoad::Defaults(DefaultsReason::UnprovenFirstRun),
        "no record and no durable mark of one is an assumed first run",
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

/// The mint counter is the only mark a save that never confirmed leaves, and it
/// is enough: withholding the record from that device is suppression, not a
/// first run.
#[test]
fn a_settings_publish_that_never_confirmed_is_still_a_mark_of_a_choice() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    assert_eq!(
        publish_unconfirmed(&world, &device, &blocks, &external_only(), 6),
        SettingsPublishError::Unconfirmed,
    );
    assert_eq!(
        block_on(
            device
                .floor_store
                .sequence_floor(settings_name(&SECRET).as_str().as_bytes())
        )
        .expect("read"),
        None,
        "the adopt-side marks stayed where they were",
    );

    // `Defaults` rather than `Stale`: nothing was cached, so the verdict rests
    // on the mint counter alone.
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Defaults(DefaultsReason::Suppressed),
        "the mint counter outlives the attempt, so absence is no longer credible",
    );

    // The refusal is a state the member can leave: saving again, successfully,
    // puts the record where every later load can authenticate it.
    publish(&world, &device, &blocks, &SECRET, &external_only());
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(external_only()),
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
        _max_bytes: usize,
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
        &device.snapshot_cache,
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
    let device = world.device(b"me");
    let name = settings_name(&SECRET);
    // The CID is computed, never uploaded, so no block plane anywhere holds it.
    let head = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, b"never uploaded"));
    let record = IpnsRecord::create_v2(
        &kdf::settings_ipns_keypair(&SECRET),
        format!("/ipfs/{head}").as_bytes(),
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
            &device.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &SECRET,
        )),
        SettingsLoad::Defaults(DefaultsReason::Suppressed),
        "a verified record whose block will not come back is being withheld",
    );
}

/// A floor store whose reads fail.
struct UnreadableFloors;

impl FloorStore for UnreadableFloors {
    async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Err(SeamError::new("floor store unreadable"))
    }

    async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
        Err(SeamError::new("floor store unreadable"))
    }

    async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Err(SeamError::new("floor store unreadable"))
    }

    async fn raise_sequence_floor(&self, _ipns_name: &[u8], _sequence: u64) -> SeamResult<u64> {
        Err(SeamError::new("floor store unreadable"))
    }
}

#[test]
fn a_floor_the_host_cannot_read_is_reported_apart_from_an_unusable_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body("https://kubo.example"),
        1,
    );

    // The control: these bytes resolve behind a readable floor, so the verdict
    // below is the host's storage and nothing about the record.
    assert!(matches!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(_)
    ));

    // A device that never resolved these settings, so nothing but the floor
    // read stands between the load and its verdict.
    let cold = world.device(b"cold");
    assert_eq!(
        block_on(load_settings(
            &cold.record_store,
            &gateway(),
            &cold.http,
            &UnreadableFloors,
            &cold.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &SECRET,
        )),
        SettingsLoad::Defaults(DefaultsReason::FloorUnreadable),
        "a floor the host cannot read is never treated as no floor",
    );
}

// ---------------------------------------------------------------------------
// Last-known-good: a degraded load never widens placement
// ---------------------------------------------------------------------------

/// "Never put my bytes in CipherBox's store" — the choice a degraded load must
/// not silently revert to [`PinMode::Hosted`].
fn external_only() -> VaultSettings {
    VaultSettings {
        pin_mode: PinMode::External,
        byo: Some(ByoIpfsConfig {
            endpoint: "https://kubo.example".to_owned(),
            kind: ByoKind::Kubo,
            access_token: None,
        }),
        retention: RetentionPolicy::KeepAll,
    }
}

/// A device holding `external_only` as its last-known-good copy, plus the
/// world and block plane it resolved them from.
fn device_with_warm_cache() -> (FakeWorld, Blocks, FakeDevice) {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice-laptop");
    publish(&world, &alice, &blocks, &SECRET, &external_only());

    let bob = world.device(b"alice-phone");
    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Resolved(external_only()),
        "the copy cached below is one this device actually resolved",
    );
    (world, blocks, bob)
}

/// Stop every endpoint serving records: the durable floor is then the only
/// proof the account ever published settings, which is a suppression.
fn withhold_the_record(device: &FakeDevice) {
    for endpoint in device.record_store.endpoints() {
        device.record_store.fail_endpoint(&endpoint);
    }
}

/// The headline. An adversary who can withhold the record must not be able to
/// move a member from `External` onto CipherBox's hosted store.
#[test]
fn a_withheld_record_never_downgrades_external_to_hosted() {
    let (world, blocks, bob) = device_with_warm_cache();
    withhold_the_record(&bob);

    let degraded = load(&world, &bob, &blocks, &SECRET);
    let SettingsLoad::Stale { settings, reason } = degraded else {
        panic!("a withheld record must degrade to last-known-good, got {degraded:?}");
    };
    assert_eq!(reason, DefaultsReason::Suppressed);
    assert_eq!(
        settings.pin_mode,
        PinMode::External,
        "withholding the record must never widen placement to the hosted default",
    );
    assert_eq!(
        settings,
        external_only(),
        "stale, but the member's own choice"
    );
}

#[test]
fn a_load_that_runs_out_of_budget_prefers_the_cached_copy() {
    let (_world, _blocks, bob) = device_with_warm_cache();
    let scheduler = VirtualScheduler::new().with_auto_advance();

    assert_eq!(
        block_on(load_settings(
            &NeverAnswers,
            &gateway(),
            &bob.http,
            &bob.floor_store,
            &bob.snapshot_cache,
            &scheduler,
            &SyncTimingProfile::CI,
            &SECRET,
        )),
        SettingsLoad::Stale {
            settings: external_only(),
            reason: DefaultsReason::TimedOut,
        },
    );
}

#[test]
fn a_record_this_build_cannot_read_prefers_the_cached_copy() {
    let (world, blocks, bob) = device_with_warm_cache();
    // Openable under the account's enc subkey, but carrying a discriminant no
    // build of this schema knows — the shape of a record that authenticates and
    // still yields no settings.
    seed_settings(&bob, &blocks, &body_with_an_unknown_pin_mode(), 2);

    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: external_only(),
            reason: DefaultsReason::Unreadable,
        },
        "the unreadable record is refused and the device's own copy stands in",
    );

    withhold_the_record(&bob);
    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: external_only(),
            reason: DefaultsReason::Suppressed,
        },
        "the refused record never became this device's last-known-good",
    );
}

#[test]
fn a_floor_the_host_cannot_read_prefers_the_cached_copy() {
    let (world, _blocks, bob) = device_with_warm_cache();

    assert_eq!(
        block_on(load_settings(
            &bob.record_store,
            &gateway(),
            &bob.http,
            &UnreadableFloors,
            &bob.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &SECRET,
        )),
        SettingsLoad::Stale {
            settings: external_only(),
            reason: DefaultsReason::FloorUnreadable,
        },
    );
}

/// With no cached copy the load reports `Defaults`, which is the verdict a
/// placement decision fails closed on (blueprint/engine.md) — it must never be
/// confusable with settings the member chose.
#[test]
fn a_degraded_load_with_no_cached_copy_reports_defaults_not_stale() {
    let (world, blocks, bob) = device_with_warm_cache();
    block_on(bob.snapshot_cache.clear()).expect("forget this device");
    withhold_the_record(&bob);

    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Defaults(DefaultsReason::Suppressed),
    );
}

/// A snapshot cache that answers every key with bytes of the test's choosing —
/// the shape of a tampered or transplanted last-known-good entry.
struct ServesCiphertext(Vec<u8>);

impl SnapshotCache for ServesCiphertext {
    async fn put(&self, _cache_key: &[u8], _ciphertext: &[u8]) -> SeamResult<()> {
        Ok(())
    }

    async fn get(&self, _cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        Ok(Some(self.0.clone()))
    }

    async fn remove(&self, _cache_key: &[u8]) -> SeamResult<()> {
        Ok(())
    }

    async fn clear(&self) -> SeamResult<()> {
        Ok(())
    }
}

#[test]
fn a_cached_copy_that_does_not_authenticate_is_not_used() {
    let world = FakeWorld::new();
    let device = world.device(b"me");

    // One planted copy per gate the cached bytes must clear: the seal, then
    // this build's body grammar.
    let wrong_owner = seal_settings_record(
        &kdf::enc_subkey(&OTHER_SECRET),
        &[5u8; 32],
        &hand_encoded_body("https://kubo.example"),
    )
    .expect("seal");
    let unknown_schema = seal_settings_record(
        &kdf::enc_subkey(&SECRET),
        &[6u8; 32],
        &body_with_an_unknown_pin_mode(),
    )
    .expect("seal");

    for planted in [wrong_owner, unknown_schema, b"not a block".to_vec()] {
        assert_eq!(
            block_on(load_settings(
                &device.record_store,
                &gateway(),
                &device.http,
                &device.floor_store,
                &ServesCiphertext(planted),
                &world.scheduler,
                &SyncTimingProfile::CI,
                &SECRET,
            )),
            SettingsLoad::Defaults(DefaultsReason::UnprovenFirstRun),
            "a cached copy is re-opened on every read, never trusted for being cached",
        );
    }
}

/// A snapshot cache that keeps what the engine writes visible to the test.
#[derive(Clone, Default)]
struct SpyCache {
    inner: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl SpyCache {
    fn values(&self) -> Vec<Vec<u8>> {
        self.inner.lock().expect("lock").values().cloned().collect()
    }
}

impl SnapshotCache for SpyCache {
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()> {
        self.inner
            .lock()
            .expect("lock")
            .insert(cache_key.to_vec(), ciphertext.to_vec());
        Ok(())
    }

    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        Ok(self.inner.lock().expect("lock").get(cache_key).cloned())
    }

    async fn remove(&self, cache_key: &[u8]) -> SeamResult<()> {
        self.inner.lock().expect("lock").remove(cache_key);
        Ok(())
    }

    async fn clear(&self) -> SeamResult<()> {
        self.inner.lock().expect("lock").clear();
        Ok(())
    }
}

/// The seam is ciphertext-only at rest, so what the load caches must be the
/// sealed head block. Caching the opened body instead would put the member's
/// BYO bearer in host storage in the clear, and every other test here would
/// still pass.
#[test]
fn the_cache_holds_the_sealed_block_never_the_opened_body() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice-laptop");
    publish(&world, &alice, &blocks, &SECRET, &configured());

    let bob = world.device(b"alice-phone");
    let cache = SpyCache::default();
    serve_http(&bob, &blocks, 4);
    assert_eq!(
        block_on(load_settings(
            &bob.record_store,
            &gateway(),
            &bob.http,
            &bob.floor_store,
            &cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &SECRET,
        )),
        SettingsLoad::Resolved(configured()),
    );

    let stored = cache.values();
    assert_eq!(stored.len(), 1, "one settings head block");
    assert!(
        !stored[0].windows(6).any(|window| window == b"s3cret"),
        "the BYO credential never reaches host storage in the clear",
    );
    assert!(
        open_settings_record(&kdf::enc_subkey(&SECRET), &stored[0]).is_ok(),
        "what is stored re-opens under the account's enc subkey",
    );
}

/// A replay must not become last-known-good. The cache write sits behind the
/// floor check and the open; hoisting it above either would let a chosen-record
/// adversary overwrite the member's own copy permanently.
#[test]
fn a_rolled_back_record_never_becomes_last_known_good() {
    let (world, blocks, bob) = device_with_warm_cache();
    let key = settings_name(&SECRET).as_str().as_bytes().to_vec();
    block_on(bob.floor_store.raise_sequence_floor(&key, 9)).expect("raise");
    // Openable, and carrying the hosted default the adversary wants applied.
    seed_settings(&bob, &blocks, &hand_encoded_body("https://kubo.example"), 3);

    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: external_only(),
            reason: DefaultsReason::RolledBack {
                floor: 9,
                sequence: 3
            },
        },
        "the replay is refused and the device's own copy stands in for it",
    );

    withhold_the_record(&bob);
    assert_eq!(
        load(&world, &bob, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: external_only(),
            reason: DefaultsReason::Suppressed,
        },
        "the refused record left the cached copy where it found it",
    );
}

#[test]
fn a_second_account_on_the_device_never_sees_the_first_accounts_cached_settings() {
    let (world, blocks, bob) = device_with_warm_cache();

    // The same device stores, driving the other account's load. Nothing is
    // published at its name, so only the cache could answer.
    serve_http(&bob, &blocks, 4);
    assert_eq!(
        block_on(load_settings(
            &bob.record_store,
            &gateway(),
            &bob.http,
            &bob.floor_store,
            &bob.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &OTHER_SECRET,
        )),
        SettingsLoad::Defaults(DefaultsReason::UnprovenFirstRun),
        "another account's copy is both keyed and sealed out of reach",
    );
}

/// A snapshot cache whose reads never settle — the shape of a stalled host
/// store.
struct NeverReads;

impl SnapshotCache for NeverReads {
    async fn put(&self, _cache_key: &[u8], _ciphertext: &[u8]) -> SeamResult<()> {
        Ok(())
    }

    async fn get(&self, _cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        poll_fn(|_| Poll::<SeamResult<Option<Vec<u8>>>>::Pending).await
    }

    async fn remove(&self, _cache_key: &[u8]) -> SeamResult<()> {
        Ok(())
    }

    async fn clear(&self) -> SeamResult<()> {
        Ok(())
    }
}

/// The cache read is inside the budget like every other stage: a stalled host
/// store must not turn the one load that never blocks cold start into one that
/// does, nor push the ceiling past the profile's single budget.
#[test]
fn a_snapshot_cache_that_never_answers_does_not_block_cold_start() {
    let scheduler = VirtualScheduler::new().with_auto_advance();
    let device = FakeWorld::new().device(b"offline");
    let profile = SyncTimingProfile::CI;

    assert_eq!(
        block_on(load_settings(
            &device.record_store,
            &gateway(),
            &device.http,
            &device.floor_store,
            &NeverReads,
            &scheduler,
            &profile,
            &SECRET,
        )),
        SettingsLoad::Defaults(DefaultsReason::TimedOut),
    );
    assert_eq!(
        scheduler.now(),
        UnixMillis(profile.settings_load_budget.as_millis() as u64),
        "one budget covers the whole load, cache read included",
    );
}

/// A body core's codec accepts and this build's schema does not.
fn body_with_an_unknown_pin_mode() -> Vec<u8> {
    use cipherbox_core::codec::{Map, Value, encode};

    let mut m = Map::new();
    m.insert("byo", Value::Null);
    m.insert("keepLatest", Value::Null);
    m.insert("pinMode", Value::Text("everywhere".to_owned()));
    encode(&Value::Map(m)).expect("encode")
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

    // Endpoints the Http seam must never be pointed at: a foreign scheme, and
    // the two policy refusals — plaintext to a non-loopback host, and the cloud
    // metadata address.
    for (endpoint, verdict) in [
        ("file:///etc/passwd", ProviderError::InvalidEndpoint),
        ("ftp://node.example", ProviderError::InvalidEndpoint),
        ("http://node.example", ProviderError::InsecureTransport),
        ("https://169.254.169.254", ProviderError::BlockedAddress),
    ] {
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
            &device.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut SeededEntropy::new(2),
            &OrphanHeads::default(),
            &SECRET,
            &settings,
        ));
        assert_eq!(
            outcome.unwrap_err(),
            SettingsPublishError::Byo(verdict),
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
    // invariant, or a resolved record could point the engine at any URL — or at
    // a public host over plaintext, putting the member's bearer on the wire.
    for (sequence, endpoint) in [(2, "file:///etc/passwd"), (3, "http://kubo.example")] {
        seed_settings(&device, &blocks, &hand_encoded_body(endpoint), sequence);
        let degraded = load(&world, &device, &blocks, &SECRET);
        let SettingsLoad::Stale { settings, reason } = degraded else {
            panic!("{endpoint}: the refused body degrades to last-known-good, got {degraded:?}");
        };
        assert_eq!(reason, DefaultsReason::Unreadable, "{endpoint}");
        assert_eq!(
            settings
                .byo
                .expect("the cached copy carries a provider")
                .endpoint,
            "https://kubo.example",
            "{endpoint}: the refused endpoint never reaches the caller",
        );
    }
}

/// A settings body built straight in core's codec, bypassing the encode guard.
fn hand_encoded_body(endpoint: &str) -> Vec<u8> {
    hand_encoded_body_at(endpoint, 1)
}

/// [`hand_encoded_body`] at a chosen body revision.
fn hand_encoded_body_at(endpoint: &str, revision: u64) -> Vec<u8> {
    use cipherbox_core::codec::{Map, Value, encode};

    let mut byo = Map::new();
    byo.insert("accessToken", Value::Null);
    byo.insert("endpoint", Value::Text(endpoint.to_owned()));
    byo.insert("kind", Value::Text("kubo".to_owned()));
    let mut m = Map::new();
    m.insert("byo", Value::Map(byo));
    m.insert("keepLatest", Value::Null);
    m.insert("pinMode", Value::Text("hosted".to_owned()));
    m.insert("revision", Value::Unsigned(revision));
    encode(&Value::Map(m)).expect("encode")
}

/// The settings [`hand_encoded_body`] describes, as a load hands them back.
fn hand_encoded_settings(endpoint: &str) -> VaultSettings {
    VaultSettings {
        pin_mode: PinMode::Hosted,
        byo: Some(ByoIpfsConfig {
            endpoint: endpoint.to_owned(),
            kind: ByoKind::Kubo,
            access_token: None,
        }),
        retention: RetentionPolicy::KeepAll,
    }
}

/// The `revision` the sealed body at `name` carries.
fn published_revision(device: &FakeDevice, blocks: &Blocks, name: &IpnsName) -> u64 {
    let block = published_block(device, blocks, name);
    let body = open_settings_record(&kdf::enc_subkey(&SECRET), &block).expect("open");
    cipherbox_core::codec::decode(&body)
        .expect("decode")
        .as_map()
        .expect("map")
        .get("revision")
        .expect("the body carries a revision")
        .as_unsigned()
        .expect("unsigned")
}

// ---------------------------------------------------------------------------
// Freshness: the EOL bound and the body revision
// ---------------------------------------------------------------------------

/// A 2026 instant, so a fixture EOL can sit either side of the clock.
const NOW: UnixMillis = UnixMillis(1_772_000_000_000);
const LAPSED_EOL: &str = "2020-01-01T00:00:00Z";

/// The settings record's reader is always its signer, so a lapsed EOL is a
/// refusal rather than the availability event a lapse is plane-wide: nothing
/// here waits on a dormant owner to revive.
#[test]
fn a_lapsed_eol_is_not_authoritative_and_degrades_to_last_known_good() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    world.scheduler.advance_to(NOW);

    // The control: the same shape inside its EOL resolves, so the verdict below
    // is the lapse and nothing upstream of it.
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body("https://kubo.example"),
        1,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(hand_encoded_settings("https://kubo.example")),
    );

    seed_settings_until(
        &device,
        &blocks,
        &hand_encoded_body_at("https://other.example", 2),
        2,
        LAPSED_EOL,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: hand_encoded_settings("https://kubo.example"),
            reason: DefaultsReason::Expired,
        },
        "a lapsed record never replaces the copy this device authenticated",
    );
}

/// A cold device has no last-known-good copy, so a lapsed record leaves it on
/// the documented defaults with the reason named.
#[test]
fn a_lapsed_eol_on_a_cold_device_reports_expiry_rather_than_applying_the_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    world.scheduler.advance_to(NOW);
    seed_settings_until(
        &device,
        &blocks,
        &hand_encoded_body("https://kubo.example"),
        1,
        LAPSED_EOL,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Defaults(DefaultsReason::Expired),
    );
}

/// Two owner-signed records at one sequence are equally fresh to the sequence
/// floor and equally live to the EOL. The sealed body revision is what orders
/// them, so the fork this device already adopted past is a replay.
#[test]
fn a_body_revision_below_the_adopted_high_water_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");

    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://kubo.example", 5),
        1,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(hand_encoded_settings("https://kubo.example")),
    );

    // The losing fork of the same publish: same name, same sequence, same
    // signer, a lower revision.
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://attacker.example", 4),
        1,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: hand_encoded_settings("https://kubo.example"),
            reason: DefaultsReason::RevisionRolledBack {
                floor: 5,
                revision: 4,
            },
        },
    );
}

/// A confirmed publish read our own bytes back, so the writer has adopted the
/// revision it minted. Without that the losing fork of the retry it just
/// replaced would stay admissible until some later load raised the bar.
#[test]
fn a_confirmed_publish_raises_the_writers_own_adopted_revision() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &SECRET, &configured());
    let published = published_revision(&device, &blocks, &settings_name(&SECRET));

    // The losing fork of that same publish, served back at the same sequence.
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://attacker.example", published - 1),
        1,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Stale {
            // The publish seeded last-known-good with what it published, so the
            // refused fork cannot pin this device to the generation it replaced.
            settings: configured(),
            reason: DefaultsReason::RevisionRolledBack {
                floor: published,
                revision: published - 1,
            },
        },
        "no load in between: the publish itself is what raised the bar",
    );
}

/// The revision is minted per publish **attempt**, before the PUT: one derived
/// from the confirm-gated sequence floor would re-mint the same value on the
/// retry and tell the two forks apart from nothing.
#[test]
fn a_retry_mints_a_revision_above_the_attempt_it_replaces() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    serve_http(&device, &blocks, 4);
    assert_eq!(
        block_on(publish_settings(
            &AcksNothingBack,
            &api,
            &device.floor_store,
            &device.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut SeededEntropy::new(6),
            &OrphanHeads::default(),
            &SECRET,
            &configured(),
        ))
        .unwrap_err(),
        SettingsPublishError::Unconfirmed,
    );

    publish(&world, &device, &blocks, &SECRET, &configured());
    assert_eq!(
        published_revision(&device, &blocks, &settings_name(&SECRET)),
        2,
        "the retry mints above the attempt that never landed",
    );
}

/// The revision arbitrates a fork at one sequence, never a record that won its
/// own CAS. Two devices keep independent counters, so holding a strictly newer
/// record to this device's bar would refuse a peer's legitimate publish forever.
#[test]
fn a_higher_sequence_record_is_admitted_whatever_revision_it_carries() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");

    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://kubo.example", 9),
        1,
    );
    assert!(matches!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(_)
    ));

    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://phone.example", 2),
        2,
    );
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(hand_encoded_settings("https://phone.example")),
    );
}

/// A refused record never becomes last-known-good: the cache write sits behind
/// the bar, so a replay cannot install itself as the copy the next degraded
/// load falls back to.
#[test]
fn a_revision_rolled_back_record_never_becomes_last_known_good() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");

    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://kubo.example", 5),
        1,
    );
    assert!(matches!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(_)
    ));
    seed_settings(
        &device,
        &blocks,
        &hand_encoded_body_at("https://attacker.example", 4),
        1,
    );
    assert!(matches!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Stale { .. }
    ));

    // Nothing serves a record now, so the load answers purely from the cache.
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, settings_name(&SECRET).as_str(), Vec::new());
    }
    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Stale {
            settings: hand_encoded_settings("https://kubo.example"),
            reason: DefaultsReason::Suppressed,
        },
        "the refused fork never displaced the copy this device authenticated",
    );
}

/// An attempt that never landed advances only the writer's mint counter, so the
/// live record it failed to replace stays admissible.
#[test]
fn an_unconfirmed_publish_leaves_the_live_record_still_admissible() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &SECRET, &configured());

    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    serve_http(&device, &blocks, 4);
    assert_eq!(
        block_on(publish_settings(
            &AcksNothingBack,
            &api,
            &device.floor_store,
            &device.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut SeededEntropy::new(9),
            &OrphanHeads::default(),
            &SECRET,
            &VaultSettings::default(),
        ))
        .unwrap_err(),
        SettingsPublishError::Unconfirmed,
    );

    assert_eq!(
        load(&world, &device, &blocks, &SECRET),
        SettingsLoad::Resolved(configured()),
        "the record on the network is still the member's own choice",
    );
}

/// AGENTS.md rule 8 for the revision: the reader refuses one below its durable
/// bar, so a counter that did not advance fails the publish in every build —
/// `Err`, never a stripped assertion — with nothing reaching the record plane.
#[test]
fn a_mint_counter_that_does_not_advance_refuses_the_publish() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    serve_http(&device, &Blocks::default(), 4);

    assert_eq!(
        block_on(publish_settings(
            &device.record_store,
            &api,
            &StuckCounter,
            &device.snapshot_cache,
            &world.scheduler,
            &SyncTimingProfile::CI,
            &mut SeededEntropy::new(10),
            &OrphanHeads::default(),
            &SECRET,
            &configured(),
        ))
        .unwrap_err(),
        SettingsPublishError::Revision,
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

/// A floor store that reports a floor other than the one it was asked to raise
/// to — the shape a non-monotonic mint would take.
struct StuckCounter;

impl FloorStore for StuckCounter {
    async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }

    async fn raise_epoch_floor(&self, _scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        Ok(epoch)
    }

    async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }

    async fn raise_sequence_floor(&self, _ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        Ok(sequence.saturating_add(1))
    }
}

// ---------------------------------------------------------------------------
// Orphan-head retirement
// ---------------------------------------------------------------------------

/// A transport that refuses every PUT, so the fan-out acknowledges nothing.
#[derive(Clone)]
struct AcksNoPut;

impl RecordTransport for AcksNoPut {
    fn endpoints(&self) -> Vec<EndpointId> {
        vec![EndpointId::new("fake:refuses-writes")]
    }

    async fn get_record(
        &self,
        _endpoint: &EndpointId,
        _routing_key: &str,
        _max_bytes: usize,
    ) -> SeamResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn put_record(
        &self,
        _endpoint: &EndpointId,
        _routing_key: &str,
        _record: &[u8],
    ) -> SeamResult<()> {
        Err(SeamError::new("endpoint refused the write"))
    }
}

/// The head block goes up under its own charged pin row before register-first
/// runs, and the retry re-seals under a fresh nonce, so a refusal there leaves
/// a block no record will ever name.
#[test]
fn a_register_first_refusal_retires_the_settings_head_it_uploaded() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    blocks.refuse_register();
    serve_http(&device, &blocks, 4);
    let orphans = OrphanHeads::default();

    let outcome = block_on(publish_settings(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(7),
        &orphans,
        &SECRET,
        &configured(),
    ));
    assert!(matches!(
        outcome.unwrap_err(),
        SettingsPublishError::Publish(_),
    ));

    let head = blocks.only_block();
    let retired = blocks.retired();
    assert_eq!(retired.len(), 1, "exactly one retire batch went out");
    assert!(
        retired[0].contains(&head),
        "the retire names the head block the refused publish charged",
    );
    assert!(
        orphans.pending().is_empty(),
        "an accepted retire clears the pending set",
    );
}

/// No ack is not proof nothing stored: unpinning a head a live record may still
/// name is loss, where leaving the row charged is only a leak.
#[test]
fn a_settings_publish_whose_fan_out_acked_nothing_retires_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    );
    serve_http(&device, &blocks, 4);
    let orphans = OrphanHeads::default();

    let outcome = block_on(publish_settings(
        &AcksNoPut,
        &api,
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(8),
        &orphans,
        &SECRET,
        &configured(),
    ));
    assert!(matches!(
        outcome.unwrap_err(),
        SettingsPublishError::Publish(_),
    ));
    assert!(blocks.retired().is_empty(), "nothing was retired");
    assert!(orphans.pending().is_empty(), "nothing is pending either");
}
