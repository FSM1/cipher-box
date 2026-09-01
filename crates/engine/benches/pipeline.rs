//! Per-stage profiling over the engine's pipeline: chunk framing, pin,
//! register, publish, resolve, and the adoption gate
//! (blueprint/testing.md "The profile is where measured constants land").
//!
//! Dispatch-only, never a PR gate. Every stage runs against the test kit's
//! in-memory seam fakes on the virtual clock, so a run needs no stack and no
//! network: time comes from `VirtualScheduler` and entropy from
//! `SeededEntropy`, the two injected seams, and never from a host clock or RNG.
//!
//! Stages that mutate durable state — the gate advances floors, resolve fills
//! the snapshot cache — take fresh state per iteration through `iter_batched`,
//! so every sample measures the same path rather than the second-run shortcut.

use std::hint::black_box;

use zeroize::Zeroizing;

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{PreservedFields, ReadBody};

use cipherbox_engine::gate::{Adopted, Candidate, GateError, ReaderContext, adopt};
use cipherbox_engine::net::{AdoptOutcome, Adopter, PublishRequest, publish, resolve};
use cipherbox_engine::seams::{HttpResponse, RecordTransport};
use cipherbox_engine::sync::ResolveMode;
use cipherbox_engine::testkit::account::{Blocks, EOL, TTL_NANOS, owner_identity, serve_http};
use cipherbox_engine::testkit::fakes::{
    InMemoryCredentialStore, InMemoryFloorStore, InMemorySnapshotCache, ScriptedHttp,
};
use cipherbox_engine::testkit::{
    FakeDevice, FakeWorld, OWNER_ROOT_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture,
    OwnerRootSpec, SeededEntropy, block_on, owner_root_fixture,
};
use cipherbox_engine::{
    ApiClient, ContentKey, ContentProfile, IdentityChallengeSigner, NameRegistration,
    SyncTimingProfile, frame_and_seal, net,
};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const API_URL: &str = "http://api.test";
const ENTROPY_SEED: u64 = 0x5eed;
const CONTENT_KEY: [u8; 32] = [0x11; 32];
const SCOPE_ID: [u8; 16] = [0x44; 16];
const ROOT_ID: [u8; 16] = [0x55; 16];

/// The payload sizes the byte-shaped stages are measured at: below one
/// production chunk, just over it, and a multi-chunk version where the per-leaf
/// CID cost shows.
const PAYLOAD_SIZES: [usize; 3] = [64 * 1024, 1024 * 1024, 4 * 1024 * 1024];

/// Samples per framing point: criterion's default 100 cannot fit in its
/// measurement window once an iteration costs milliseconds.
const FRAMING_SAMPLES: usize = 20;

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// One device on a pristine world, past the challenge-signature handshake and
/// holding `acks` as the replies to the call under measurement.
///
/// Everything here is per-iteration on purpose. The acks are canned rather than
/// the [`Blocks`] fake's derived replies, which re-hash and re-parse each
/// request they answer — inside a timed closure the fake, not the stage, is
/// most of the number. A fresh device keeps `ScriptedHttp`'s request log, which
/// retains every body handed to it and is never trimmed, out of the
/// measurement, and a fresh world puts every publish on the first-publish path.
fn armed_device(
    blocks: &Blocks,
    acks: Vec<HttpResponse>,
) -> (FakeDevice, ApiClient<ScriptedHttp, InMemoryCredentialStore>) {
    let device = FakeWorld::new().device(b"bench");
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        API_URL,
    );
    serve_http(&device, blocks, 2);
    let signer = IdentityChallengeSigner::from_signer(owner_identity());
    block_on(api.login_identity(&signer)).expect("the fixture answers the handshake");
    for ack in acks {
        device.http.enqueue_response(ack);
    }
    (device, api)
}

/// Stands in for `testkit::account`'s in-bounds register reply, which the
/// canned acks replace to keep its body parsing out of the measurement.
fn registry_ack() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// Frame a payload into fixed-size chunks, seal each, and address it — the
/// per-byte cost every upload pays before a single request goes out.
fn bench_chunk_framing(c: &mut Criterion) {
    let key = ContentKey::from_bytes(CONTENT_KEY);
    let profile = ContentProfile::PRODUCTION;
    let mut group = c.benchmark_group("chunk_framing");
    group.sample_size(FRAMING_SAMPLES);
    for size in PAYLOAD_SIZES {
        let plaintext = payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &plaintext,
            |b, plaintext| {
                b.iter_batched_ref(
                    || SeededEntropy::new(ENTROPY_SEED),
                    |entropy| {
                        frame_and_seal(black_box(plaintext), &key, entropy, &profile)
                            .expect("seeded entropy never fails")
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

/// The pin: one already-sealed block over the hosted ingress.
fn bench_pin(c: &mut Criterion) {
    let blocks = Blocks::default();

    let mut group = c.benchmark_group("pin");
    for size in PAYLOAD_SIZES {
        let block = payload(size);
        let cid = encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, &block));
        let ack = format!("{{\"cid\":\"{cid}\",\"size\":{size}}}").into_bytes();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &block, |b, block| {
            b.iter_batched(
                || {
                    armed_device(
                        &blocks,
                        vec![HttpResponse {
                            status: 200,
                            headers: Vec::new(),
                            body: ack.clone(),
                        }],
                    )
                },
                |(_device, api)| {
                    block_on(api.upload(black_box(&cid), black_box(block))).expect("upload")
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Register, at one entry, at the batch ceiling, and one past it — the point
/// where a name wave's batch splits into a second call.
fn bench_register(c: &mut Criterion) {
    let blocks = Blocks::default();

    let mut group = c.benchmark_group("register");
    for names in [
        1usize,
        100,
        net::REGISTRY_BATCH_MAX,
        net::REGISTRY_BATCH_MAX + 1,
    ] {
        let chunks = names.div_ceil(net::REGISTRY_BATCH_MAX);
        let entries: Vec<NameRegistration> = (0..names)
            .map(|i| NameRegistration {
                ipns_name: format!("k51bench{i:06}"),
                head_cid: None,
                content_cids: Vec::new(),
            })
            .collect();
        group.throughput(Throughput::Elements(names as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(names),
            &entries,
            |b, entries| {
                b.iter_batched(
                    || armed_device(&blocks, (0..chunks).map(|_| registry_ack()).collect()),
                    |(_device, api)| {
                        block_on(net::register(&api, black_box(entries))).expect("register")
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

/// Publish: register-first, the CAS PUT fan-out to every endpoint, and the
/// confirm-by-re-resolve.
fn bench_publish(c: &mut Criterion) {
    let blocks = Blocks::default();

    let signer = kdf::ipns_keypair(&[0x99; 32]);
    let name = IpnsName::from_public_key(&signer.verifying_key());
    let request = PublishRequest {
        name: &name,
        signer: &signer,
        head_cid: "bafybenchhead".into(),
        content_cids: vec!["bafybenchleaf".into()],
        min_current_sequence: None,
    };

    c.bench_function("publish", |b| {
        b.iter_batched_ref(
            || armed_device(&blocks, vec![registry_ack()]),
            |(device, api)| {
                block_on(publish(
                    &device.record_store,
                    api,
                    &device.floor_store,
                    &device.scheduler,
                    &SyncTimingProfile::CI,
                    black_box(&request),
                ))
                .expect("publish")
            },
            BatchSize::PerIteration,
        );
    });
}

/// A stand-in for the gate on the resolve bench, so the fan-out, the record
/// verify and the snapshot write are measured apart from adoption
/// ([`bench_adoption_gate`] owns that cost).
struct AcceptingAdopter;

impl Adopter for AcceptingAdopter {
    async fn adopt(
        &self,
        _name: &IpnsName,
        _record_bytes: &[u8],
    ) -> Result<AdoptOutcome, GateError> {
        Ok(AdoptOutcome {
            adopted: Adopted {
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
                    unknown: PreservedFields::new(),
                },
                sequence: 1,
                epoch: 0,
            },
            write_scope_seed: None,
            node_id: ROOT_ID,
            read_scope_seed: None,
        })
    }

    async fn probe_read_scope_seed(
        &self,
        _name: &IpnsName,
        _record_bytes: &[u8],
    ) -> Result<Option<Zeroizing<[u8; 32]>>, GateError> {
        Ok(None)
    }
}

/// Resolve: the fan-out GET across every endpoint, the highest-sequence pick,
/// and the snapshot-cache write. A fresh cache per iteration keeps every sample
/// on the cold path rather than the second-run hit.
fn bench_resolve(c: &mut Criterion) {
    let world = FakeWorld::new();
    let signer = kdf::ipns_keypair(&[0xaa; 32]);
    let name = IpnsName::from_public_key(&signer.verifying_key());
    let record =
        IpnsRecord::create_v2(&signer, b"/ipfs/bafybenchhead", 3, TTL_NANOS, EOL).marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
    let adopter = AcceptingAdopter;

    c.bench_function("resolve", |b| {
        b.iter_batched_ref(
            InMemorySnapshotCache::default,
            |cache| {
                block_on(resolve(
                    &world.record_store,
                    cache,
                    &adopter,
                    black_box(&name),
                    ResolveMode::CacheFirst,
                ))
                .expect("resolve")
            },
            BatchSize::SmallInput,
        );
    });
}

/// The adoption gate: all six stages over a real owner-root head block. A fresh
/// floor store per iteration keeps the record strictly newer than the floor, so
/// every sample walks the accept path rather than the sequence refusal.
fn bench_adoption_gate(c: &mut Criterion) {
    let owner = owner_identity();
    let owner_verifier = owner.verifying_key();
    let owner_enc = kdf::enc_subkey(&[0x77; 32]);
    let OwnerRootFixture {
        name,
        grant_section,
        envelope,
        head_cid_str,
        ..
    } = owner_root_fixture(OwnerRootSpec {
        owner_identity: &owner,
        owner_enc: &owner_enc.public(),
        scope_id: SCOPE_ID,
        root_id: ROOT_ID,
        children: Vec::new(),
        child_scope_index: Vec::new(),
        parent_node_seed: None,
        owner_write_blob_epoch: None,
        write_history_link: Vec::new(),
        grants: Vec::new(),
    });

    let record_signer =
        kdf::ipns_keypair(kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &ROOT_ID).as_bytes());
    let candidate = Candidate {
        name,
        record_bytes: IpnsRecord::create_v2(
            &record_signer,
            format!("/ipfs/{head_cid_str}").as_bytes(),
            1,
            TTL_NANOS,
            EOL,
        )
        .marshal(),
        grant_section,
        envelope,
    };

    // The owner already holds the scope read key, so the gate opens no seed
    // blob — the shipped owner path (`SeedBlob` doc, gate/adoption.rs).
    let read_key = kdf::read_key(kdf::node_seed(&OWNER_ROOT_SCOPE_SEED, &ROOT_ID).as_bytes());
    let reader = ReaderContext {
        owner_identity: &owner_verifier,
        scope_id: SCOPE_ID,
        read_key: read_key.as_bytes(),
        parent_node_seed: None,
        seed_blob: None,
    };

    c.bench_function("adoption_gate", |b| {
        b.iter_batched_ref(
            InMemoryFloorStore::default,
            |floors| block_on(adopt(floors, &reader, black_box(&candidate))).expect("adopts"),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_chunk_framing,
    bench_pin,
    bench_register,
    bench_publish,
    bench_resolve,
    bench_adoption_gate,
);
criterion_main!(benches);
