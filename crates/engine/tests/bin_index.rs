//! The bin index record, joined end to end: sealed symmetrically under
//! `bin-index-seal-key`, published through the shared publish port at the
//! `bin-index-ipns-keypair` name, and resolved back by a second device of the
//! same account that only ever saw the network.
//!
//! Two contracts drive the suite. The seal key never rotates, so every publish
//! must draw a fresh nonce from the entropy seam. And the index is rewritten
//! whole, so a load that cannot establish the current index must refuse to be
//! published over.

use cipherbox_core::codec::decode;
use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    BinEntry, BinIndex, MAX_BIN_INDEX_BODY_BYTES, NodeKind, encode_bin_index, seal_bin_index,
};
use cipherbox_core::suite::aead::NONCE_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;

use cipherbox_engine::api::ApiClient;
use cipherbox_engine::entropy::{Entropy, EntropyError};
use cipherbox_engine::net::keyless_re_put;
use cipherbox_engine::seams::{EndpointId, FloorStore, RecordTransport, SeamResult};
use cipherbox_engine::testkit::account::{Blocks, serve_http};
use cipherbox_engine::testkit::fakes::{InMemoryCredentialStore, ScriptedHttp};
use cipherbox_engine::testkit::{FakeDevice, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    BinIndexKeys, BinIndexLoad, BinIndexPublishError, BinIndexRead, DefaultsReason, Gateway,
    GatewayConfig, OrphanHeads, SessionBearer, SyncTimingProfile, load_bin_index,
    publish_bin_index,
};

const SECRET: [u8; 32] = [7u8; 32];
/// A second account signed in on the same device set.
const OTHER_SECRET: [u8; 32] = [9u8; 32];
const TTL_NANOS: u64 = 2_000_000_000;
const EOL: &str = "2099-01-01T00:00:00Z";

fn gateway() -> Gateway {
    GatewayConfig {
        accelerator: None,
        public_fallbacks: vec!["http://gateway.test".to_owned()],
    }
    .into_gateway(SessionBearer::default())
}

fn keys() -> BinIndexKeys {
    BinIndexKeys::derive(&SECRET)
}

fn name() -> IpnsName {
    keys().name().clone()
}

fn entry(seed: u8) -> BinEntry {
    BinEntry::new(
        [seed; 16],
        vec![seed, seed.wrapping_add(1)],
        NodeKind::File,
        [seed.wrapping_add(0x10); 16],
        format!("note-{seed}.txt"),
        u64::from(seed) * 1000,
        [seed.wrapping_add(0x20); 16],
        Some([seed.wrapping_add(0x30); SECRET_LEN]),
    )
}

/// An index whose entries are the caller's; the revision the publish mints.
fn binned(seeds: &[u8]) -> BinIndex {
    BinIndex {
        entries: seeds.iter().copied().map(entry).collect(),
        ..BinIndex::new(0)
    }
}

fn api(device: &FakeDevice) -> ApiClient<ScriptedHttp, InMemoryCredentialStore> {
    ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        "http://api.test",
    )
}

/// Publish `index` from `device`, asserting the publish confirmed.
///
/// `seed` decides the nonce, so one seed names one body: this file seals every
/// fixture under one key, and two bodies that shared a seed would share a nonce.
/// The seeds are `1` for `binned(&[1])`, `2` for `binned(&[1, 2])`, and so on;
/// a test that publishes one body under two seeds on purpose takes its own.
fn publish(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks, index: &BinIndex, seed: u64) {
    publish_with(world, device, blocks, index, &mut SeededEntropy::new(seed))
        .expect("the bin index record publishes");
}

fn publish_with(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    index: &BinIndex,
    entropy: &mut dyn Entropy,
) -> Result<(), BinIndexPublishError> {
    serve_http(device, blocks, 4);
    block_on(publish_bin_index(
        &device.record_store,
        &api(device),
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        entropy,
        &OrphanHeads::default(),
        &keys(),
        index,
    ))
    .map(|_| ())
}

fn load(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    keys: &BinIndexKeys,
) -> BinIndexLoad {
    read(world, device, blocks, keys).load
}

fn read(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    keys: &BinIndexKeys,
) -> BinIndexRead {
    serve_http(device, blocks, 4);
    block_on(load_bin_index(
        &device.record_store,
        &gateway(),
        &device.http,
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        keys,
    ))
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
    blocks.get(cid).expect("block on the plane")
}

/// The signed `Validity` bytes the record currently published at `name` carries.
fn published_validity(device: &FakeDevice, name: &IpnsName) -> Vec<u8> {
    let record = device
        .record_store
        .record_at(&device.record_store.endpoints()[0], name.as_str())
        .expect("published");
    IpnsRecord::unmarshal(&record)
        .and_then(|r| r.verify(name))
        .expect("verifiable")
        .validity
}

/// The nonce the record at `name` was sealed under: the prefix of the framed
/// `sealed` blob its clear header carries.
fn published_nonce(device: &FakeDevice, blocks: &Blocks, name: &IpnsName) -> [u8; NONCE_LEN] {
    let block = published_block(device, blocks, name);
    let decoded = decode(&block).expect("decode");
    let sealed = decoded
        .as_map()
        .expect("map")
        .get("sealed")
        .expect("sealed")
        .as_bytes()
        .expect("bytes");
    sealed[..NONCE_LEN].try_into().expect("nonce prefix")
}

/// The nonce a fixture body is sealed under: derived from the body itself, so
/// two distinct bodies can never share one under this file's single seal key.
/// Two bodies sealed under one key must never share a nonce, in fixtures as in
/// production.
fn fixture_nonce(index: &BinIndex) -> [u8; NONCE_LEN] {
    let body = encode_bin_index(index).expect("encode");
    let cid = compute_cid(CONTENT_CID_CODEC, &body);
    cid[cid.len() - NONCE_LEN..]
        .try_into()
        .expect("digest tail")
}

/// Put a hand-sealed body on the block plane and publish a record anchoring it
/// at the account's bin name and `sequence`, bypassing the publish path.
fn seed_bin(
    device: &FakeDevice,
    blocks: &Blocks,
    index: &BinIndex,
    sequence: u64,
    key: &[u8; 32],
    eol: &str,
) {
    let block = seal_bin_index(key, &fixture_nonce(index), index).expect("seal");
    let cid = blocks.put(block);
    let record = IpnsRecord::create_v2(
        &kdf::bin_index_ipns_keypair(&SECRET),
        format!("/ipfs/{cid}").as_bytes(),
        sequence,
        TTL_NANOS,
        eol,
    )
    .marshal();
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, name().as_str(), record.clone());
    }
}

fn seal_key(secret: &[u8]) -> [u8; 32] {
    *kdf::bin_index_seal_key(secret).as_bytes()
}

/// One of the durable marks the bin record leaves, as the engine keys it.
fn mark(prefix: &[u8], name: &IpnsName) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(name.as_str().as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[test]
fn a_bin_written_on_one_device_resolves_on_a_second_device_of_the_account() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice-laptop");
    publish(&world, &alice, &blocks, &binned(&[1, 2]), 2);

    let bob = world.device(b"alice-phone");
    let BinIndexLoad::Resolved(index) = load(&world, &bob, &blocks, &keys()) else {
        panic!("the second device resolves the published record");
    };
    assert_eq!(index.entries, binned(&[1, 2]).entries);
    assert_eq!(index.revision, 1, "the publish minted the first revision");
}

#[test]
fn the_bin_name_is_derived_from_the_login_secret_alone() {
    assert_eq!(
        BinIndexKeys::derive(&SECRET).name(),
        &IpnsName::from_public_key(&kdf::bin_index_ipns_keypair(&SECRET).verifying_key()),
        "the published name is the bin-index-ipns-keypair edge",
    );
    assert_ne!(
        BinIndexKeys::derive(&SECRET).name(),
        BinIndexKeys::derive(&OTHER_SECRET).name(),
        "another account publishes at another name",
    );
}

/// Ownership is the whole access story for the bin: no grant carries the seal
/// key, so a record transplanted under a second account's name never opens.
#[test]
fn a_second_account_cannot_open_the_first_accounts_bin() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"shared-device");
    seed_bin(
        &device,
        &blocks,
        &binned(&[1]),
        1,
        &seal_key(&OTHER_SECRET),
        EOL,
    );

    assert_eq!(
        load(&world, &device, &blocks, &keys()),
        BinIndexLoad::Empty(DefaultsReason::Unreadable),
        "a body under a foreign key is refused, and named as unreadable",
    );
}

// ---------------------------------------------------------------------------
// The nonce rule: the seal key never rotates
// ---------------------------------------------------------------------------

/// Nonce reuse under one XChaCha20-Poly1305 key discloses every `heldKey` two
/// bodies carry and admits forgery, and this key never rotates, so no publish
/// may repeat one.
#[test]
fn consecutive_publishes_never_reuse_the_seal_nonce() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    let name = name();
    // One entropy source across every call: a hoisted or cached nonce shows up
    // as two identical prefixes.
    let mut entropy = SeededEntropy::new(4);
    let mut nonces = Vec::new();
    for entries in [&[1u8][..], &[1, 2], &[1, 2, 3]] {
        publish_with(&world, &device, &blocks, &binned(entries), &mut entropy).expect("publish");
        nonces.push(published_nonce(&device, &blocks, &name));
    }
    for (i, nonce) in nonces.iter().enumerate() {
        for other in &nonces[i + 1..] {
            assert_ne!(nonce, other, "every publish draws a fresh nonce");
        }
    }
}

/// The nonce is entropy, never a counter and never derived from the record: two
/// devices that publish the same body, at the same revision and the same
/// sequence, still seal under different nonces. A derived nonce would collide
/// here, which is the concurrent-publish case this record is CAS-guarded for.
#[test]
fn the_seal_nonce_comes_from_the_entropy_seam_and_not_from_the_record() {
    let name = name();
    let sealed_under = |seed| {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        let device = world.device(b"me");
        publish(&world, &device, &blocks, &binned(&[1, 2]), seed);
        assert_eq!(
            block_on(device.floor_store.sequence_floor(name.as_str().as_bytes())).expect("read"),
            Some(1),
            "both publishes land at the same sequence",
        );
        (
            published_nonce(&device, &blocks, &name),
            published_block(&device, &blocks, &name),
        )
    };
    let (first_nonce, first_block) = sealed_under(5);
    let (second_nonce, second_block) = sealed_under(6);
    assert_ne!(first_nonce, second_nonce);
    assert_ne!(
        first_block, second_block,
        "a fresh nonce also makes a no-op republish byte-indistinguishable from an edit",
    );
}

/// A seam that cannot supply a nonce fails the publish closed. Sealing under a
/// predictable one would be worse than not publishing.
#[test]
fn a_publish_without_entropy_never_reaches_the_network() {
    struct NoEntropy;
    impl Entropy for NoEntropy {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new("no entropy"))
        }
    }

    let world = FakeWorld::new();
    let device = world.device(b"me");
    let outcome = publish_with(
        &world,
        &device,
        &Blocks::default(),
        &binned(&[1]),
        &mut NoEntropy,
    );
    assert!(matches!(
        outcome,
        Err(BinIndexPublishError::Entropy(ref e)) if e.message() == "no entropy"
    ));
    assert!(
        device
            .record_store
            .record_at(&device.record_store.endpoints()[0], name().as_str())
            .is_none(),
        "a refused publish never reaches the network",
    );
}

// ---------------------------------------------------------------------------
// The floor law
// ---------------------------------------------------------------------------

/// A record below the durable sequence floor is a replay, and the load names it
/// as one rather than reading it as an older bin.
#[test]
fn a_replayed_sequence_is_refused_and_the_cached_copy_answers() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &binned(&[1]), 1);
    publish(&world, &device, &blocks, &binned(&[1, 2]), 2);

    seed_bin(&device, &blocks, &binned(&[9]), 1, &seal_key(&SECRET), EOL);
    let load = load(&world, &device, &blocks, &keys());
    let BinIndexLoad::Stale { index, reason } = load.clone() else {
        panic!("the load falls back to this device's last-known-good copy: {load:?}");
    };
    assert_eq!(
        reason,
        DefaultsReason::RolledBack {
            floor: 2,
            sequence: 1
        },
    );
    assert_eq!(
        index.entries,
        binned(&[1, 2]).entries,
        "the cached copy is what this device last adopted, not the replay",
    );
    assert_eq!(
        load.writable().unwrap_err(),
        reason,
        "a copy this device cannot show is current is never published over",
    );
}

/// The revision arbitrates what the outer sequence cannot: a fork *at* the
/// sequence this device already adopted.
#[test]
fn a_same_sequence_fork_below_the_adopted_revision_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &binned(&[1]), 1);
    publish(&world, &device, &blocks, &binned(&[1, 2]), 2);

    let mut fork = binned(&[9]);
    fork.revision = 1;
    seed_bin(&device, &blocks, &fork, 2, &seal_key(&SECRET), EOL);
    let BinIndexLoad::Stale { reason, .. } = load(&world, &device, &blocks, &keys()) else {
        panic!("the load falls back to this device's last-known-good copy");
    };
    assert_eq!(
        reason,
        DefaultsReason::RevisionRolledBack {
            floor: 2,
            revision: 1
        },
        "a fork at the adopted sequence is refused, not read as an older bin",
    );
}

/// A strictly newer record won its CAS against the network, so a second device's
/// legitimate publish is adopted even though this device's revision counter has
/// never seen it.
#[test]
fn a_newer_sequence_is_adopted_whatever_this_devices_revision_counter_holds() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &binned(&[1]), 1);
    publish(&world, &device, &blocks, &binned(&[1, 2]), 2);

    let mut newer = binned(&[9]);
    newer.revision = 1;
    seed_bin(&device, &blocks, &newer, 3, &seal_key(&SECRET), EOL);
    let BinIndexLoad::Resolved(index) = load(&world, &device, &blocks, &keys()) else {
        panic!("a record above the sequence floor is adopted");
    };
    assert_eq!(index.entries, newer.entries);
}

/// Retrying an unconfirmed publish is idempotent-in-sequence, so neither the
/// sequence floor nor the reader's revision bar may move behind bytes the
/// network may never serve.
#[test]
fn an_unconfirmed_publish_advances_neither_the_sequence_floor_nor_the_readers_bar() {
    /// A transport that acks every PUT and serves nothing back.
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

    let world = FakeWorld::new();
    let device = world.device(b"me");
    serve_http(&device, &Blocks::default(), 4);
    let outcome = block_on(publish_bin_index(
        &AcksNothingBack,
        &api(&device),
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(3),
        &OrphanHeads::default(),
        &keys(),
        &binned(&[1]),
    ));
    assert_eq!(outcome.unwrap_err(), BinIndexPublishError::Unconfirmed);

    let name = name();
    let read = |key: Vec<u8>| block_on(device.floor_store.sequence_floor(&key)).expect("read");
    assert_eq!(read(name.as_str().as_bytes().to_vec()), None);
    assert_eq!(
        read(mark(b"bin-index-revision/", &name)),
        None,
        "no reader adopted a revision this publish never landed",
    );
    // The mint counter is the one mark an unconfirmed attempt does leave, so the
    // retry mints a revision above the one it sealed rather than repeating it.
    assert_eq!(read(mark(b"bin-index-revision-mint/", &name)), Some(1));
}

// ---------------------------------------------------------------------------
// Degradation, and the rewrite guard
// ---------------------------------------------------------------------------

/// A vault that has never soft-deleted anything holds an empty bin. That is the
/// bottom rung of the ladder, not an error, and it is the one degraded outcome a
/// publish may build on.
#[test]
fn a_cold_start_with_no_published_record_loads_an_empty_bin() {
    let world = FakeWorld::new();
    let device = world.device(b"cold");
    let load = load(&world, &device, &Blocks::default(), &keys());

    assert_eq!(load, BinIndexLoad::Empty(DefaultsReason::UnprovenFirstRun));
    assert_eq!(load.writable(), Ok(BinIndex::new(0)));
}

/// A device that has adopted or attempted a record holds a durable mark, so a
/// withheld record reads as suppression. Publishing over it would drop every
/// entry the withheld record names — v1's whole-list rewrite.
#[test]
fn a_withheld_record_refuses_the_rewrite_rather_than_minting_a_first_bin() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let name = name();
    let marks = [
        name.as_str().as_bytes().to_vec(),
        mark(b"bin-index-revision/", &name),
        mark(b"bin-index-revision-mint/", &name),
    ];
    for mark in &marks {
        let device = world.device(b"cold");
        block_on(device.floor_store.raise_sequence_floor(mark, 3)).expect("the mark raises");
        let load = load(&world, &device, &blocks, &keys());
        assert_eq!(
            load,
            BinIndexLoad::Empty(DefaultsReason::Suppressed),
            "one mark alone must not read as a first run",
        );
        assert_eq!(load.writable().unwrap_err(), DefaultsReason::Suppressed);
    }
}

/// The liveness pass re-PUTs the record the session holds, byte for byte. The
/// record carries a client-signed 90-day EOL and the API republisher is keyless,
/// so a bin nobody renews becomes unreachable.
#[test]
fn the_liveness_pass_re_puts_the_held_bin_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    serve_http(&device, &blocks, 4);
    let held = block_on(publish_bin_index(
        &device.record_store,
        &api(&device),
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(2),
        &OrphanHeads::default(),
        &keys(),
        &binned(&[1]),
    ))
    .expect("publish");

    let name = name();
    assert_eq!(held.routing_key, name.as_str());
    let endpoints = device.record_store.endpoints();
    let published = device
        .record_store
        .record_at(&endpoints[0], name.as_str())
        .expect("published");
    for endpoint in &endpoints {
        device
            .record_store
            .seed_record(endpoint, name.as_str(), b"not the record".to_vec());
    }

    let results = block_on(keyless_re_put(&device.record_store, &[held]));
    assert!(results.iter().all(|result| result.kept_alive));
    for endpoint in &endpoints {
        assert_eq!(
            device.record_store.record_at(endpoint, name.as_str()),
            Some(published.clone()),
            "the pass re-PUT the bin index record",
        );
    }
}

/// Core refuses a body whose entries name one node twice, and the refusal
/// reaches the publish rather than the network: restore and purge would
/// otherwise pick a winner by position.
#[test]
fn a_body_naming_one_node_twice_is_never_published() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    let outcome = publish_with(
        &world,
        &device,
        &Blocks::default(),
        &binned(&[1, 1]),
        &mut SeededEntropy::new(7),
    );
    assert!(matches!(outcome, Err(BinIndexPublishError::Codec(_))));
    assert!(
        device
            .record_store
            .record_at(&device.record_store.endpoints()[0], name().as_str())
            .is_none(),
        "a refused body never reaches the network",
    );
}

// ---------------------------------------------------------------------------
// Exits from the states that hold the queue head
// ---------------------------------------------------------------------------

/// An EOL already lapsed at the virtual clock's own epoch.
const LAPSED_EOL: &str = "1970-01-01T00:00:00Z";

/// The lapse is the state the rewrite has to lift, so the record it builds on
/// carries the lapsed EOL and the whole floor law still passes.
///
/// The rewrite the load admits stamps the fresh EOL. Nothing else does: the
/// keyless re-PUT carries the record's own validity, and the sub-EOL renewal
/// skips a record already past its EOL.
#[test]
fn a_lapsed_bin_record_still_establishes_the_index_the_rewrite_builds_on() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &binned(&[1]), 1);
    seed_bin(
        &device,
        &blocks,
        &binned(&[1, 2]),
        2,
        &seal_key(&SECRET),
        LAPSED_EOL,
    );

    let index = read(&world, &device, &blocks, &keys())
        .load
        .writable()
        .expect("a lapse never refuses the rewrite");
    assert_eq!(
        index.entries.len(),
        2,
        "and the rewrite carries the entries the lapsed record named",
    );

    publish(&world, &device, &blocks, &binned(&[1, 2, 3]), 3);
    assert_ne!(
        published_validity(&device, &name()),
        LAPSED_EOL.as_bytes(),
        "the rewrite the load admitted is what re-signs the name",
    );
}

/// A read-only session keeps the name alive: the load enrols what it resolved,
/// so a vault that soft-deletes nothing never reaches the lapse at all.
#[test]
fn a_resolved_bin_record_is_offered_for_renewal_by_the_load_alone() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &binned(&[1]), 1);

    let read = read(&world, &device, &blocks, &keys());
    assert!(matches!(read.load, BinIndexLoad::Resolved(_)));
    assert_eq!(
        read.renewable
            .expect("resolved records are renewable")
            .routing_key,
        name().as_str(),
    );
}

/// A device that holds no sequence floor for the name has nothing of its own
/// against which to judge the age of what the plane served — the bar the
/// lapsed-EOL refusal used to carry. It resolves, and it re-signs nothing. The
/// resolve leaves the floor, so the next load enrols.
#[test]
fn a_device_that_has_never_adopted_the_bin_record_re_signs_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let author = world.device(b"alice-laptop");
    publish(&world, &author, &blocks, &binned(&[1]), 1);

    let fresh = world.device(b"alice-phone");
    let first = read(&world, &fresh, &blocks, &keys());
    assert!(matches!(first.load, BinIndexLoad::Resolved(_)));
    assert!(
        first.renewable.is_none(),
        "a first sight is not this device's to re-sign",
    );
    assert!(
        read(&world, &fresh, &blocks, &keys()).renewable.is_some(),
        "and the floor the first resolve left admits the next one",
    );
}

/// The renewal re-signs at `floor + 1`, so a record the floor law rejected must
/// never enter the set: renewing a replay would make it win record selection.
#[test]
fn a_replayed_bin_record_is_never_offered_for_renewal() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let device = world.device(b"me");
    publish(&world, &device, &blocks, &binned(&[1]), 1);
    publish(&world, &device, &blocks, &binned(&[1, 2]), 2);
    seed_bin(&device, &blocks, &binned(&[9]), 1, &seal_key(&SECRET), EOL);

    let read = read(&world, &device, &blocks, &keys());
    assert!(matches!(
        read.load.writable().unwrap_err(),
        DefaultsReason::RolledBack { .. },
    ));
    assert!(
        read.renewable.is_none(),
        "a replay the load refused is not this session's to re-sign",
    );
}

/// A bin no rung admits is the member's own state, and the publish names it as
/// one. Read as a codec fault it would spend the delete's attempt budget five
/// times over and dead-letter with nothing naming the cause.
#[test]
fn a_bin_past_the_top_rung_is_refused_as_a_full_bin_and_not_as_a_codec_fault() {
    let world = FakeWorld::new();
    let device = world.device(b"me");
    // Sized off the ceiling itself rather than a fixed count, so the test keeps
    // meaning if the rungs move: every entry costs well over these bytes.
    let entries = (0..u32::try_from(MAX_BIN_INDEX_BODY_BYTES / 64).expect("fits"))
        .map(|i| {
            let mut node_id = [0u8; 16];
            node_id[..4].copy_from_slice(&i.to_be_bytes());
            BinEntry::new(
                node_id,
                vec![1, 2],
                NodeKind::File,
                [7u8; 16],
                format!("note-{i}.txt"),
                1_000,
                [3u8; 16],
                Some([5u8; SECRET_LEN]),
            )
        })
        .collect();
    let over = BinIndex {
        entries,
        ..BinIndex::new(0)
    };

    let outcome = publish_with(
        &world,
        &device,
        &Blocks::default(),
        &over,
        &mut SeededEntropy::new(5),
    );
    assert_eq!(outcome, Err(BinIndexPublishError::Full));
    assert!(
        device
            .record_store
            .record_at(&device.record_store.endpoints()[0], name().as_str())
            .is_none(),
        "a refused publish never reaches the network",
    );
}
