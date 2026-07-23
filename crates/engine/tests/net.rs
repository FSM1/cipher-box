//! The net-plane simulation harness: the gated resolve/publish pipeline, CAS
//! races, any-ack/retry fan-out, virtual-time multi-day EOL timelines, the
//! keyless re-PUT Scheduler job, and revival — driven over the in-memory fake
//! record store and virtual clock, no network and no docker
//! (blueprint/engine.md "Resolve/publish pipeline"; blueprint/testing.md
//! "the simulation harness").
//!
//! Records are real (core-signed via `IpnsRecord::create_v2`), so the fan-out
//! verify step runs core's actual chain; the adoption gate — whose full
//! candidate/reader assembly lands with the content/pointer/key slices — is
//! reached through a scripted [`Adopter`] so this slice can prove the pipeline
//! contract (every resolve is gated; only gate-passing records touch the
//! snapshot) without re-deriving the whole crypto fixture the adoption-gate
//! suite already owns.

use core::cell::RefCell;
use core::time::Duration;
use std::sync::{Arc, Mutex};

use cipherbox_core::error::TrustViolation;
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::seal::ReadBody;
use cipherbox_core::suite::ed25519::Ed25519Signer;

use cipherbox_engine::SyncTimingProfile;
use cipherbox_engine::api::ApiClient;
use cipherbox_engine::gate::{Adopted, GateError, GateRejection, GateStage, RejectionReason};
use cipherbox_engine::net::eol;
use cipherbox_engine::net::{
    Adopter, HeldRecord, HeldRecords, LivenessControl, PublishError, PublishOutcome,
    PublishRequest, RE_PUT_INTERVAL, ResolveOutcome, ReviveError, ReviveRequest, eol_republish,
    keyless_re_put, publish, resolve, revive, run_liveness_loop,
};
use cipherbox_engine::seams::{
    FloorStore, HttpResponse, RecordTransport, Scheduler, SeamError, SeamResult, SnapshotCache,
    UnixMillis,
};
use cipherbox_engine::testkit::fakes::{
    InMemoryCredentialStore, InMemoryRecordStore, ScriptedHttp,
};
use cipherbox_engine::testkit::{FakeDevice, FakeWorld, block_on};

// Deterministic fixture constants (KAT-style injected values; core reads no clock).
const TTL_NANOS: u64 = 2_000_000_000;
const VALUE: &[u8] = b"/ipfs/bafyfixturehead";
const DAY: u64 = 24 * 60 * 60;

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed([seed; 32])
}

fn name_of(signer: &Ed25519Signer) -> IpnsName {
    IpnsName::from_public_key(&signer.verifying_key())
}

/// A core-signed record for `signer` at `sequence`, minted with a 90-day EOL
/// from `mint_millis`.
fn record(signer: &Ed25519Signer, value: &[u8], sequence: u64, mint_millis: u64) -> Vec<u8> {
    let validity = eol::eol_from(UnixMillis(mint_millis));
    IpnsRecord::create_v2(signer, value, sequence, TTL_NANOS, &validity).marshal()
}

/// A held record for `name` carrying `bytes` plus a placeholder renewal signer
/// (#750 exercises the signer/CID fields; the keyless re-PUT layer reads only
/// routing key + bytes).
fn held_record(name: &IpnsName, bytes: Vec<u8>) -> HeldRecord {
    HeldRecord {
        routing_key: name.as_str().to_owned(),
        record_bytes: bytes,
        signer: Ed25519Signer::from_seed([0u8; 32]),
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
    }
}

fn verify_seq(name: &IpnsName, bytes: &[u8]) -> u64 {
    IpnsRecord::unmarshal(bytes)
        .expect("record parses")
        .verify(name)
        .expect("record verifies")
        .sequence
}

fn api_for(device: &FakeDevice) -> ApiClient<ScriptedHttp, InMemoryCredentialStore> {
    ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    )
}

/// A bare 2xx response (register/upload success — the client ignores the body).
fn ok_200() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// A 2xx response carrying `body` (recovery fetch returns the body verbatim).
fn ok_200_body(body: Vec<u8>) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: Vec::new(),
        body,
    }
}

/// Assert every configured endpoint holds a record for `name` at `sequence`.
fn assert_all_endpoints_at(store: &InMemoryRecordStore, name: &IpnsName, sequence: u64) {
    for endpoint in store.endpoints() {
        let bytes = store
            .record_at(&endpoint, name.as_str())
            .unwrap_or_else(|| panic!("endpoint {} holds no record", endpoint.0));
        assert_eq!(
            verify_seq(name, &bytes),
            sequence,
            "endpoint {}",
            endpoint.0
        );
    }
}

// --- the Adopter stub: a scripted gate verdict + the sequences it was fed ----

#[derive(Clone, Copy)]
enum Verdict {
    /// The record passes the gate.
    Accept,
    /// A non-floor trust violation (fail-closed, pins last-known-good).
    TrustViolation,
    /// Our own current record re-fetched: `sequence == floor` (a no-update,
    /// never a violation).
    EqualSequence,
}

/// Fronts the adoption gate for the resolve pipeline. Records every sequence it
/// is handed so a test can prove the gate ran on the freshest fetched record,
/// and returns a scripted verdict.
#[derive(Clone)]
struct StubAdopter {
    verdict: Verdict,
    seen: Arc<Mutex<Vec<u64>>>,
}

impl StubAdopter {
    fn new(verdict: Verdict) -> Self {
        Self {
            verdict,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn seen(&self) -> Vec<u64> {
        self.seen.lock().unwrap().clone()
    }
}

impl Adopter for StubAdopter {
    async fn adopt(&self, name: &IpnsName, record_bytes: &[u8]) -> Result<Adopted, GateError> {
        let sequence = verify_seq(name, record_bytes);
        self.seen.lock().unwrap().push(sequence);
        match self.verdict {
            Verdict::Accept => Ok(Adopted {
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
                    unknown: Vec::new(),
                },
                sequence,
                epoch: 1,
            }),
            Verdict::TrustViolation => Err(GateError::Rejected(GateRejection {
                stage: GateStage::RecordVerify,
                reason: RejectionReason::Trust(TrustViolation::IpnsSignatureInvalid.into()),
            })),
            Verdict::EqualSequence => Err(GateError::Rejected(GateRejection {
                stage: GateStage::Sequence,
                reason: RejectionReason::SequenceNotNewer {
                    floor: sequence,
                    sequence,
                },
            })),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolve — cache-first, fan-out verify, adoption gate on every resolve.
// ---------------------------------------------------------------------------

#[test]
fn resolve_is_cache_first_and_renders_last_known_good_with_no_network_record() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let name = name_of(&signer(1));
    let key = name.as_str().as_bytes();

    block_on(device.snapshot_cache.put(key, b"cached-lkg")).unwrap();
    let adopter = StubAdopter::new(Verdict::Accept);

    let resolved = block_on(resolve(
        &device.record_store,
        &device.snapshot_cache,
        &adopter,
        &name,
    ))
    .expect("resolve");

    assert_eq!(resolved.last_known_good, Some(b"cached-lkg".to_vec()));
    assert_eq!(resolved.outcome, ResolveOutcome::NoUpdate);
    assert!(
        adopter.seen().is_empty(),
        "with nothing fetched the gate is never invoked"
    );
}

#[test]
fn resolve_picks_freshest_verified_record_gates_it_and_writes_the_snapshot() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(2);
    let name = name_of(&s);
    let endpoints = world.record_store.endpoints();

    // One endpoint serves garbage, one an older valid record, one the freshest.
    world
        .record_store
        .seed_record(&endpoints[0], name.as_str(), b"not-a-record".to_vec());
    world
        .record_store
        .seed_record(&endpoints[1], name.as_str(), record(&s, VALUE, 4, 0));
    // Re-seed endpoint 0 with a valid older record to prove max-sequence wins.
    world
        .record_store
        .seed_record(&endpoints[0], name.as_str(), record(&s, VALUE, 2, 0));

    let adopter = StubAdopter::new(Verdict::Accept);
    let resolved = block_on(resolve(
        &device.record_store,
        &device.snapshot_cache,
        &adopter,
        &name,
    ))
    .expect("resolve");

    match resolved.outcome {
        ResolveOutcome::Adopted(adopted) => assert_eq!(adopted.sequence, 4),
        other => panic!("expected adoption, got {other:?}"),
    }
    assert_eq!(
        adopter.seen(),
        vec![4],
        "the gate ran on the freshest record"
    );

    // Only the gate-passing record touched the snapshot.
    let cached = block_on(device.snapshot_cache.get(name.as_str().as_bytes()))
        .unwrap()
        .expect("snapshot written");
    assert_eq!(verify_seq(&name, &cached), 4);
}

#[test]
fn resolve_gate_rejection_pins_last_known_good_and_never_overwrites_the_snapshot() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(3);
    let name = name_of(&s);
    let key = name.as_str().as_bytes();

    block_on(device.snapshot_cache.put(key, b"trusted-lkg")).unwrap();
    world.record_store.seed_record(
        &world.record_store.endpoints()[0],
        name.as_str(),
        record(&s, VALUE, 9, 0),
    );

    let adopter = StubAdopter::new(Verdict::TrustViolation);
    let resolved = block_on(resolve(
        &device.record_store,
        &device.snapshot_cache,
        &adopter,
        &name,
    ))
    .expect("resolve");

    assert!(matches!(
        resolved.outcome,
        ResolveOutcome::TrustViolation(_)
    ));
    assert_eq!(resolved.last_known_good, Some(b"trusted-lkg".to_vec()));
    assert_eq!(
        block_on(device.snapshot_cache.get(key)).unwrap(),
        Some(b"trusted-lkg".to_vec()),
        "a fail-closed rejection never overwrites last-known-good"
    );
}

#[test]
fn resolve_equal_sequence_is_no_update_not_a_trust_violation() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(4);
    let name = name_of(&s);
    let key = name.as_str().as_bytes();

    block_on(device.snapshot_cache.put(key, b"current")).unwrap();
    world.record_store.seed_record(
        &world.record_store.endpoints()[0],
        name.as_str(),
        record(&s, VALUE, 7, 0),
    );

    let adopter = StubAdopter::new(Verdict::EqualSequence);
    let resolved = block_on(resolve(
        &device.record_store,
        &device.snapshot_cache,
        &adopter,
        &name,
    ))
    .expect("resolve");

    assert_eq!(
        resolved.outcome,
        ResolveOutcome::NoUpdate,
        "re-fetching our own current record is a no-update, never a violation"
    );
    assert_eq!(
        block_on(device.snapshot_cache.get(key)).unwrap(),
        Some(b"current".to_vec())
    );
}

// ---------------------------------------------------------------------------
// Publish — register-first, sequence embedding, fan-out, confirm, CAS races.
// ---------------------------------------------------------------------------

#[test]
fn publish_registers_first_embeds_sequence_one_and_confirms() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(5);
    let name = name_of(&s);
    let api = api_for(&device);
    device.http.enqueue_response(ok_200()); // register

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: vec!["bafyc1".into()],
        min_current_sequence: None,
    };
    let outcome = block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("publish");

    assert_eq!(outcome, PublishOutcome::Published { sequence: 1 });
    assert_all_endpoints_at(&world.record_store, &name, 1);

    // The register call went out (register-first ordering), to the registry.
    let requests = device.http.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/registry/register"));
}

#[test]
fn publish_cas_embeds_the_exact_expected_sequence_floor_plus_one() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(6);
    let name = name_of(&s);
    let api = api_for(&device);

    // The last adopted record sat at sequence 3; the CAS publish embeds 4.
    block_on(
        device
            .floor_store
            .raise_sequence_floor(name.as_str().as_bytes(), 3),
    )
    .unwrap();
    device.http.enqueue_response(ok_200());

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    let outcome = block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("publish");

    assert_eq!(outcome, PublishOutcome::Published { sequence: 4 });
    assert_all_endpoints_at(&world.record_store, &name, 4);
}

#[test]
fn register_first_fail_closed_puts_no_record() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(7);
    let name = name_of(&s);
    let api = api_for(&device);

    // The registration is refused: the record must never reach the transport.
    device.http.enqueue_response(HttpResponse {
        status: 500,
        headers: Vec::new(),
        body: Vec::new(),
    });

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    let error = block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect_err("register-first is fail-closed");

    assert!(matches!(error, PublishError::Register(_)));
    for endpoint in world.record_store.endpoints() {
        assert!(
            world
                .record_store
                .record_at(&endpoint, name.as_str())
                .is_none(),
            "no record is PUT when registration fails"
        );
    }
}

/// A [`FloorStore`] whose sequence-floor read always fails — models a durable
/// floor-store I/O error so publish must fail closed rather than assume "no
/// floor" and mint a stale sequence.
#[derive(Clone, Default)]
struct FailingFloorStore;

impl FloorStore for FailingFloorStore {
    async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Ok(None)
    }
    async fn raise_epoch_floor(&self, _scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        Ok(epoch)
    }
    async fn sequence_floor(&self, _ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Err(SeamError::new("floor store unavailable"))
    }
    async fn raise_sequence_floor(&self, _ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        Ok(sequence)
    }
}

#[test]
fn publish_fails_closed_when_the_sequence_floor_cannot_be_read() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(9);
    let name = name_of(&s);
    let api = api_for(&device);
    let floors = FailingFloorStore;
    // Registration succeeds; the floor read then fails — the failure must stop
    // publish before any record is minted or PUT (never collapse to "no floor").
    device.http.enqueue_response(ok_200());

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    let error = block_on(publish(
        &device.record_store,
        &api,
        &floors,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect_err("a floor-read failure is fail-closed");

    assert!(matches!(error, PublishError::FloorRead(_)));
    for endpoint in world.record_store.endpoints() {
        assert!(
            world
                .record_store
                .record_at(&endpoint, name.as_str())
                .is_none(),
            "no record is PUT when the floor read fails"
        );
    }
}

#[test]
fn publish_succeeds_on_any_ack_and_the_background_retry_reaches_the_failed_endpoint() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(8);
    let name = name_of(&s);
    let api = api_for(&device);
    let endpoints = world.record_store.endpoints();

    // One endpoint is unreachable during the first attempt; the other acks.
    world.record_store.fail_endpoint(&endpoints[0]);
    device.http.enqueue_response(ok_200());
    // Auto-advance so the spawned background retry's sleeps resolve when drained.
    let scheduler = world.scheduler.clone().with_auto_advance();

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    let outcome = block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("publish");

    assert_eq!(
        outcome,
        PublishOutcome::Published { sequence: 1 },
        "any ack is success"
    );
    assert!(
        world
            .record_store
            .record_at(&endpoints[0], name.as_str())
            .is_none(),
        "the failed endpoint has no record yet"
    );
    assert!(
        world
            .record_store
            .record_at(&endpoints[1], name.as_str())
            .is_some()
    );

    // Heal the endpoint and drain the background re-PUT: it now converges.
    world.record_store.heal_endpoint(&endpoints[0]);
    let tasks = scheduler.take_spawned_tasks();
    assert_eq!(
        tasks.len(),
        1,
        "publish spawned exactly one background re-PUT"
    );
    for task in tasks {
        block_on(task);
    }
    assert_all_endpoints_at(&world.record_store, &name, 1);
}

#[test]
fn publish_all_endpoints_failing_is_fail_closed() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(9);
    let name = name_of(&s);
    let api = api_for(&device);

    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_endpoint(&endpoint);
    }
    device.http.enqueue_response(ok_200()); // registration succeeds; the PUT does not

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    let error = block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect_err("no endpoint acked");

    assert!(matches!(error, PublishError::AllEndpointsFailed));
}

#[test]
fn publish_confirm_detects_a_lost_cas_race() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(10);
    let name = name_of(&s);
    let api = api_for(&device);
    let endpoints = world.record_store.endpoints();

    // A concurrent writer already landed sequence 3 on one endpoint; that
    // endpoint rejects our stale (lower-sequence) PUT but still serves the
    // winner (IPNS higher-sequence-wins), so confirm-by-re-resolve sees it.
    world
        .record_store
        .seed_record(&endpoints[0], name.as_str(), record(&s, VALUE, 3, 0));
    world.record_store.fail_put_endpoint(&endpoints[0]);
    // Our floor is stale at 1, so we publish sequence 2 — behind the winner.
    block_on(
        device
            .floor_store
            .raise_sequence_floor(name.as_str().as_bytes(), 1),
    )
    .unwrap();
    device.http.enqueue_response(ok_200());

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    let outcome = block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("publish");

    assert_eq!(
        outcome,
        PublishOutcome::LostRace {
            published_sequence: 2,
            observed_sequence: 3,
        },
        "a strictly-higher record on confirm is a lost race for the caller to rebase"
    );
}

// ---------------------------------------------------------------------------
// Liveness — the keyless re-PUT Scheduler job and the sub-EOL seq+1 renewal.
// ---------------------------------------------------------------------------

#[test]
fn keyless_re_put_reposts_held_records_to_every_endpoint() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(11);
    let name = name_of(&s);
    let endpoints = world.record_store.endpoints();
    let bytes = record(&s, VALUE, 1, 0);

    // One endpoint dropped the record; the session still holds it.
    world
        .record_store
        .seed_record(&endpoints[1], name.as_str(), bytes.clone());
    let held = vec![held_record(&name, bytes)];

    let results = block_on(keyless_re_put(&device.record_store, &held));
    assert_eq!(results.len(), 1);
    assert!(results[0].kept_alive);
    // The record is now alive on every endpoint again — keyless, byte-stable.
    assert_all_endpoints_at(&world.record_store, &name, 1);
}

#[test]
fn keyless_re_put_runs_as_an_hourly_scheduler_job_on_virtual_time() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(12);
    let name = name_of(&s);
    let held = vec![held_record(&name, record(&s, VALUE, 1, 0))];

    let scheduler = world.scheduler.clone().with_auto_advance();
    let runs = Arc::new(Mutex::new(0u32));
    {
        let transport = device.record_store.clone();
        let loop_scheduler = scheduler.clone();
        let runs = runs.clone();
        scheduler.spawn(Box::pin(async move {
            for _ in 0..3 {
                loop_scheduler.sleep(RE_PUT_INTERVAL).await;
                keyless_re_put(&transport, &held).await;
                *runs.lock().unwrap() += 1;
            }
        }));
    }
    for task in scheduler.take_spawned_tasks() {
        block_on(task);
    }

    assert_eq!(
        *runs.lock().unwrap(),
        3,
        "the job fired once per hourly tick"
    );
    assert_eq!(
        scheduler.now(),
        UnixMillis(3 * 60 * 60 * 1000),
        "three hours elapsed on virtual time"
    );
    assert_all_endpoints_at(&world.record_store, &name, 1);
}

#[test]
fn a_held_record_dropped_from_an_endpoint_is_alive_again_after_one_interval() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(33);
    let name = name_of(&s);
    let endpoints = world.record_store.endpoints();
    // Only one endpoint still holds the record; the rest dropped it.
    world
        .record_store
        .seed_record(&endpoints[1], name.as_str(), record(&s, VALUE, 1, 0));

    let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
    held.borrow_mut()
        .insert([1u8; 16], held_record(&name, record(&s, VALUE, 1, 0)));

    // Drive exactly one interval over the populated set, then stop.
    let scheduler = world.scheduler.clone().with_auto_advance();
    block_on(run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
        let records: Vec<HeldRecord> = held.borrow().values().cloned().collect();
        keyless_re_put(&device.record_store, &records).await;
        LivenessControl::Stop
    }));

    assert_all_endpoints_at(&world.record_store, &name, 1);
    assert_eq!(
        scheduler.now(),
        UnixMillis(60 * 60 * 1000),
        "one interval elapsed"
    );
}

#[test]
fn an_evicted_record_is_not_re_put() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(34);
    let name = name_of(&s);

    let held: RefCell<HeldRecords> = RefCell::new(HeldRecords::new());
    held.borrow_mut()
        .insert([1u8; 16], held_record(&name, record(&s, VALUE, 1, 0)));
    // Eviction leaves the set before the loop runs.
    held.borrow_mut().remove(&[1u8; 16]);
    assert!(held.borrow().is_empty(), "eviction removes the record");

    let scheduler = world.scheduler.clone().with_auto_advance();
    block_on(run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
        let records: Vec<HeldRecord> = held.borrow().values().cloned().collect();
        keyless_re_put(&device.record_store, &records).await;
        LivenessControl::Stop
    }));

    // No endpoint ever received the evicted record — the loop never re-PUTs it.
    for endpoint in world.record_store.endpoints() {
        assert!(
            world
                .record_store
                .record_at(&endpoint, name.as_str())
                .is_none(),
            "endpoint {} must hold no record for an evicted name",
            endpoint.0
        );
    }
}

#[test]
fn held_record_debug_redacts_the_signer() {
    let s = signer(35);
    let name = name_of(&s);
    let mut hr = held_record(&name, record(&s, VALUE, 1, 0));
    hr.signer = Ed25519Signer::from_seed([0xAB; 32]);

    let debug = format!("{hr:?}");
    let seed_debug = format!("{:?}", [0xABu8; 32]);
    assert!(
        !debug.contains(&seed_debug),
        "the raw signing-key bytes must never appear in Debug"
    );
    assert!(
        debug.contains("Ed25519Signer(redacted)"),
        "the held signer must be redacted"
    );
    // Non-secret routing metadata is still visible for diagnostics.
    assert!(debug.contains(name.as_str()));
    assert!(debug.contains("bafyhead"));
}

#[test]
fn eol_republish_renews_at_seq_plus_one_only_inside_the_window() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(13);
    let name = name_of(&s);
    let api = api_for(&device);
    let scheduler = world.scheduler.clone(); // manual clock, now = 0

    // Publish the initial record at T0 (EOL = T0 + 90 days), then model its
    // adoption by advancing the durable sequence floor to 1 (the gate's job).
    device.http.enqueue_response(ok_200());
    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafyhead".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };
    block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("initial publish");
    block_on(
        device
            .floor_store
            .raise_sequence_floor(name.as_str().as_bytes(), 1),
    )
    .unwrap();

    // At T0 the EOL is ~90 days out: no renewal, no API call.
    let none = block_on(eol_republish(
        &device.record_store,
        &api,
        &device.floor_store,
        &scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("eol_republish");
    assert_eq!(none, None, "a record far from EOL is not renewed");

    // 65 days on (25 days remaining, inside the 30-day window): republish at 2.
    scheduler.advance(Duration::from_secs(65 * DAY));
    device.http.enqueue_response(ok_200());
    let outcome = block_on(eol_republish(
        &device.record_store,
        &api,
        &device.floor_store,
        &scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("eol_republish");
    assert_eq!(outcome, Some(PublishOutcome::Published { sequence: 2 }));

    // The renewed record carries a strictly-later EOL than the original.
    let endpoint = world.record_store.endpoints()[0].clone();
    let renewed = world
        .record_store
        .record_at(&endpoint, name.as_str())
        .unwrap();
    let renewed_validity = IpnsRecord::unmarshal(&renewed)
        .unwrap()
        .verify(&name)
        .unwrap()
        .validity;
    let original_eol = eol::eol_from(UnixMillis(0));
    assert_eq!(verify_seq(&name, &renewed), 2);
    assert!(
        renewed_validity > original_eol.into_bytes(),
        "renewal stamps a fresh, later EOL"
    );
}

// ---------------------------------------------------------------------------
// Revival — re-mint after a >EOL lapse via the recovery endpoint.
// ---------------------------------------------------------------------------

#[test]
fn revive_re_mints_a_fresh_record_strictly_newer_than_the_lapsed_one() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(14);
    let name = name_of(&s);
    let api = api_for(&device);

    // The recovery endpoint holds the last-known record (sequence 5) — the
    // network copy has lapsed and been GC'd.
    let lapsed = record(&s, b"/ipfs/bafyrecovered", 5, 0);
    device.http.enqueue_response(ok_200_body(lapsed)); // recovery fetch
    device.http.enqueue_response(ok_200()); // register for the re-mint

    let request = ReviveRequest {
        name: &name,
        signer: &s,
        content_cids: vec!["bafyrecovered".into()],
    };
    let outcome = block_on(revive(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        request,
    ))
    .expect("revive");

    // Strictly newer than the recovered sequence 5, even from a cold floor.
    assert_eq!(outcome, PublishOutcome::Published { sequence: 6 });
    for endpoint in world.record_store.endpoints() {
        let bytes = world
            .record_store
            .record_at(&endpoint, name.as_str())
            .unwrap();
        let verified = IpnsRecord::unmarshal(&bytes)
            .unwrap()
            .verify(&name)
            .unwrap();
        assert_eq!(verified.sequence, 6);
        assert_eq!(verified.value, b"/ipfs/bafyrecovered", "same CID re-minted");
    }
}

#[test]
fn revive_fails_closed_when_the_recovery_endpoint_is_unauthorized() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(15);
    let name = name_of(&s);
    let api = api_for(&device);

    device.http.enqueue_response(HttpResponse {
        status: 403,
        headers: Vec::new(),
        body: Vec::new(),
    });

    let request = ReviveRequest {
        name: &name,
        signer: &s,
        content_cids: Vec::new(),
    };
    let error = block_on(revive(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.scheduler,
        &SyncTimingProfile::CI,
        request,
    ))
    .expect_err("a refused recovery fetch fails closed");
    assert!(matches!(error, ReviveError::Recovery(_)));
    // Nothing was published.
    for endpoint in world.record_store.endpoints() {
        assert!(
            world
                .record_store
                .record_at(&endpoint, name.as_str())
                .is_none()
        );
    }
}

// ---------------------------------------------------------------------------
// An end-to-end multi-day EOL timeline on virtual time: publish → live →
// renewal → lapse → revival, one narrative over ~250 virtual days.
// ---------------------------------------------------------------------------

#[test]
fn multi_day_eol_timeline_publish_renew_lapse_revive() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(16);
    let name = name_of(&s);
    let api = api_for(&device);
    let scheduler = world.scheduler.clone(); // manual clock, now = 0
    let endpoint = world.record_store.endpoints()[0].clone();

    let request = PublishRequest {
        name: &name,
        signer: &s,
        head_cid: "bafytimeline".into(),
        content_cids: Vec::new(),
        min_current_sequence: None,
    };

    // T0: first publish (seq 1, EOL T0+90d); model adoption (floor → 1).
    device.http.enqueue_response(ok_200());
    block_on(publish(
        &device.record_store,
        &api,
        &device.floor_store,
        &scheduler,
        &SyncTimingProfile::CI,
        &request,
    ))
    .expect("publish seq 1");
    block_on(
        device
            .floor_store
            .raise_sequence_floor(name.as_str().as_bytes(), 1),
    )
    .unwrap();

    // T0+65d: inside the renewal window → republish seq 2; model adoption.
    scheduler.advance(Duration::from_secs(65 * DAY));
    device.http.enqueue_response(ok_200());
    assert_eq!(
        block_on(eol_republish(
            &device.record_store,
            &api,
            &device.floor_store,
            &scheduler,
            &SyncTimingProfile::CI,
            &request,
        ))
        .expect("renew"),
        Some(PublishOutcome::Published { sequence: 2 })
    );
    block_on(
        device
            .floor_store
            .raise_sequence_floor(name.as_str().as_bytes(), 2),
    )
    .unwrap();

    // Capture the live seq-2 bytes the recovery endpoint would return later.
    let seq2_bytes = world
        .record_store
        .record_at(&endpoint, name.as_str())
        .unwrap();
    let seq2_validity = IpnsRecord::unmarshal(&seq2_bytes)
        .unwrap()
        .verify(&name)
        .unwrap()
        .validity;

    // Advance well past the seq-2 EOL (T0+65d+90d = T0+155d): a >EOL lapse.
    scheduler.advance(Duration::from_secs(120 * DAY)); // now ≈ T0+185d
    assert!(
        eol::is_expired(scheduler.now(), &seq2_validity),
        "the record has lapsed past its EOL"
    );

    // Revival: recovery returns the last-known seq-2 record; re-mint at seq 3.
    device.http.enqueue_response(ok_200_body(seq2_bytes));
    device.http.enqueue_response(ok_200());
    let outcome = block_on(revive(
        &device.record_store,
        &api,
        &device.floor_store,
        &scheduler,
        &SyncTimingProfile::CI,
        ReviveRequest {
            name: &name,
            signer: &s,
            content_cids: Vec::new(),
        },
    ))
    .expect("revive after lapse");
    assert_eq!(outcome, PublishOutcome::Published { sequence: 3 });
    assert_all_endpoints_at(&world.record_store, &name, 3);
}

#[test]
fn run_liveness_loop_fires_a_pass_per_interval_off_the_injected_clock() {
    let world = FakeWorld::new();
    let scheduler = world.scheduler.clone().with_auto_advance();
    let passes = Arc::new(Mutex::new(0u32));

    let counter = passes.clone();
    block_on(run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || {
        let counter = counter.clone();
        async move {
            let mut n = counter.lock().unwrap();
            *n += 1;
            // Third pass ends the loop — the driver stops on `Stop`, not on a
            // hardcoded count of its own.
            if *n == 3 {
                LivenessControl::Stop
            } else {
                LivenessControl::Continue
            }
        }
    }));

    assert_eq!(*passes.lock().unwrap(), 3, "one pass per hourly interval");
    assert_eq!(
        scheduler.now(),
        UnixMillis(3 * 60 * 60 * 1000),
        "three hourly intervals elapsed on virtual time, no direct clock"
    );
}

#[test]
fn run_liveness_loop_keyless_re_puts_the_held_set_each_pass() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let s = signer(14);
    let name = name_of(&s);
    let endpoints = world.record_store.endpoints();

    // One endpoint dropped the record; the session still holds it.
    let bytes = record(&s, VALUE, 1, 0);
    world
        .record_store
        .seed_record(&endpoints[1], name.as_str(), bytes.clone());
    let held = vec![held_record(&name, bytes)];

    let scheduler = world.scheduler.clone().with_auto_advance();
    let transport = device.record_store.clone();
    block_on(run_liveness_loop(&scheduler, RE_PUT_INTERVAL, || async {
        keyless_re_put(&transport, &held).await;
        LivenessControl::Stop
    }));

    // The loop drove the job body: the dropped record is alive on every
    // endpoint again after one interval.
    assert_all_endpoints_at(&world.record_store, &name, 1);
    assert_eq!(scheduler.now(), UnixMillis(60 * 60 * 1000));
}
