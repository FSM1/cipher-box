//! The write plane, joined end to end: every metadata op kind is staged,
//! drained, authored, published, self-adopted, and resolved back — first by the
//! device that wrote it, then by a second device of the same account that only
//! ever saw the network.
//!
//! Later write-plane slices extend this file rather than starting their own.

use core::cell::RefCell;
use core::num::NonZeroU64;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cipherbox_core::codec::Value;
use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::MAX_READ_SEALED_BYTES;
use cipherbox_core::seal::{
    BinIndex, ChildRef, GrantSetCommitment, NodeKind as CoreNodeKind, PreservedFields, ReadBody,
    Version as CoreVersion, decode_envelope, encode_envelope, encode_grant_section,
    encode_read_body, open_read_body, seal_settings_record, set_grant_section, sign_grant_set,
};
use cipherbox_core::suite::aead::{NONCE_LEN, TAG_LEN};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use cipherbox_engine::api::RetireEntry;
use cipherbox_engine::content::chunk::SEALED_LEAF_OVERHEAD;
use cipherbox_engine::content::{
    ByoIpfsConfig, ByoKind, DAG_ROOT_CODEC, PinMode, RetentionPolicy, SealedChunk, SessionBearer,
    assemble, decode_root,
};
use cipherbox_engine::facade::{BinOrigin, PendingClass};
use cipherbox_engine::net::OrphanHeads;
use cipherbox_engine::net::author::{
    AuthoredHead, ENVELOPE_V, EnvelopeAuthoring, author_child_envelope,
    author_scope_root_with_section,
};
use cipherbox_engine::net::{
    ChildAdopter, REGISTRY_BATCH_MAX, ReclaimStall, ReclaimStallReason, ResolveOutcome,
    StagingRetireLedger, resolve,
};
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, HttpResponse, OpId, RecordTransport, SeamError, SeamResult,
    SnapshotCache, StagingStore, UnixMillis,
};
use cipherbox_engine::settings::{
    Destinations, SettingsOrigin, SettingsPublishError, VaultSettings, publish_settings,
    settings_name,
};
use cipherbox_engine::sync::pointer::{open_repoint, vault_pointer_name};
use cipherbox_engine::sync::{
    BookkeepingSeal, DRAINED_OP_MARK_PREFIX, MAX_BOOKKEEPING_OPENS, MAX_JOURNAL_REPLAYS,
    MAX_QUARANTINE_ATTEMPTS, PUBLISHED_OP_MARK_PREFIX, ResolveMode, StagedContent,
    UPLOAD_MARK_PREFIX, doomed_journal_key, encode_upload_mark, owner_scoped_key, owner_tag,
    record_content_root_cid, scope_exit_debt_key, seal_owed_cuts, upload_mark_key,
};
use cipherbox_engine::testkit::account::{
    Blocks, EOL, MEMBER_NODE, POINTER_PAYLOAD_VERSION, ROOT, SCOPE, SECRET, TTL_NANOS,
    owner_identity, registry_batch_refused, seed_account, sequence_floor_label, serve_http,
};
use cipherbox_engine::testkit::fakes::{InMemoryRecordStore, InMemoryStagingStore};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH, OWNER_ROOT_PSEUDONYM_SEED,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    OwnerRootSpec, SeededEntropy, block_on, frame_version as frame, owner_root_fixture,
    poll_tasks_once, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, ApiClient, BinIndexKeys, BinIndexLoad, BlockProgress, Command, CommandOutcome,
    CommittedSet, ContentProfile, DEFAULT_BIN_RETENTION_DAYS, DeadLetter, DeadLetterReason,
    DefaultsReason, Engine, EngineError, Entropy, EntropyError, Event, EventStream, GatewayConfig,
    LoginSecret, MAX_FOCUS_FILES, MAX_FOLDER_CHILDREN, MAX_OPEN_STREAMS, NodeId, NodeKind, Op,
    OpKind, OpPhase, OverBudgetCause, Placement, PlacementRefusal, PrevEpochSeed, RecordReader,
    RecordSeal, ResealSeeds, ScopeCrossing, ScopeRootIdentity, StoragePolicy, SyncTimingProfile,
    WriteHistory, WriteTarget, decode_queue, load_bin_index, publish_bin_index, reseal_scope_root,
    stage_op,
};

/// The override seed a rotation mints for `SCOPE`'s second read epoch.
const ROTATED_READ_SCOPE_SEED: [u8; 32] = [0xA5; 32];
/// The stable per-scope pointer read key the owner-root fixture's grant blobs
/// carry.
const POINTER_READ_KEY: [u8; 32] = [0x88; 32];
/// The destination set the upload mark opens on.
const DESTINATIONS_LEN: usize = Destinations::LEN;

// ---------------------------------------------------------------------------
// Upload refusals: the replies this suite scripts the block plane's upload hook
// with, each a different shape of failure the valve has to tell apart.
// ---------------------------------------------------------------------------

/// The pin store is unreachable: a transport failure carrying no server verdict.
fn unreachable_upload() -> SeamResult<HttpResponse> {
    Err(SeamError::new("upload refused"))
}

/// A server 413, optionally carrying the `code` discriminator that tells the
/// account-quota gate apart from the transport cap.
fn upload_413(code: Option<&str>) -> SeamResult<HttpResponse> {
    let code = code.map_or(String::new(), |code| format!(",\"code\":\"{code}\""));
    Ok(HttpResponse {
        status: 413,
        headers: Vec::new(),
        body: format!("{{\"statusCode\":413,\"message\":\"too large\"{code}}}").into_bytes(),
    })
}

/// The 503 `POST /content/upload` answers when its pin store is unreachable — a
/// refusal the API did answer, unlike [`unreachable_upload`].
fn pin_store_unavailable() -> SeamResult<HttpResponse> {
    Ok(HttpResponse {
        status: 503,
        headers: Vec::new(),
        body: br#"{"statusCode":503,"message":"pin store unavailable"}"#.to_vec(),
    })
}

/// A 413 from an intermediary that never reached the API: an HTML body, so no
/// error envelope parses out of it at all.
fn proxy_413() -> SeamResult<HttpResponse> {
    Ok(HttpResponse {
        status: 413,
        headers: Vec::new(),
        body: b"<html><body>413 Request Entity Too Large</body></html>".to_vec(),
    })
}

/// A 400 answered for a registry it never reached, so it stamps no `code` —
/// [`proxy_413`]'s counterpart on the register path.
fn proxy_400() -> Vec<u8> {
    b"<html><body>400 Bad Request</body></html>".to_vec()
}

fn engine_on(device: &FakeDevice, entropy_seed: u64) -> (Engine<FakeSeamTypes>, EventStream) {
    engine_with(device, Box::new(SeededEntropy::new(entropy_seed)))
}

fn engine_with(
    device: &FakeDevice,
    entropy: Box<dyn Entropy>,
) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        entropy,
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        // Offline: `start` skips login, because this suite exercises the record
        // plane, not the auth handshake.
        ApiBaseUrl::offline(),
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    )
}

fn secret() -> LoginSecret {
    LoginSecret::new(SECRET.to_vec())
}

/// The same engine against a configured API — the only mode that provisions a
/// first-run vault, since register-first has no offline form.
fn engine_on_api(device: &FakeDevice, entropy_seed: u64) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(entropy_seed)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        ApiBaseUrl::parse("http://api.test").expect("a configured base"),
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    )
}

/// The scope root the account's vault pointer currently names, read the way a
/// cold start reads it: the record at pointer index 0, opened under the owner's
/// own pointer read key.
fn vault_root_name(world: &FakeWorld) -> IpnsName {
    let pointer_name = vault_pointer_name(&SECRET, 0);
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], pointer_name.as_str())
        .expect("a vault pointer is published");
    let block = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(&pointer_name))
        .expect("the pointer record verifies under its own name")
        .value;
    open_repoint(
        kdf::pointer_read_key(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE).as_bytes(),
        POINTER_PAYLOAD_VERSION,
        &SCOPE,
        &owner_identity().verifying_key(),
        &block,
    )
    .expect("the owner's own pointer read key opens the re-point")
    .current_root
}

/// The sequence of the record published at `name`, verified under it.
fn sequence_at(world: &FakeWorld, name: &IpnsName) -> u64 {
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .expect("a record is published at the name");
    IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .expect("the published record verifies under its own name")
        .sequence
}

/// Run one resolve-tick interval, which is also one drain pass.
fn tick(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_tasks_until_parked(tasks);
}

/// Drive one command to completion with the spawned loops running beside it —
/// what a manual refresh needs, since it parks on the pass the tick loop runs.
fn command_while_ticking(
    engine: &mut Engine<FakeSeamTypes>,
    command: Command,
    tasks: &mut [BoxedTask],
) -> Result<CommandOutcome, EngineError> {
    let mut pending = Box::pin(engine.command(command));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(outcome) = pending.as_mut().poll(&mut cx) {
            return outcome;
        }
        poll_tasks_until_parked(tasks);
    }
    panic!("the command never settled against the running loops");
}

/// A cold-started engine on `device`, with both spawned loops parked at their
/// first sleep and the block plane wired for a whole scenario's worth of calls.
fn boot(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    boot_with(
        world,
        blocks,
        device,
        Box::new(SeededEntropy::new(entropy_seed)),
    )
}

/// The same, over a caller-supplied entropy source.
fn boot_with(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy: Box<dyn Entropy>,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_http(device, blocks, 400);
    let (mut engine, events) = engine_with(device, entropy);
    block_on(engine.start(secret())).expect("cold start adopts the owner root");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    (engine, events, tasks)
}

/// A real seeded source that can be silenced mid-scenario: once armed it
/// reports success having written nothing, which is the seam failure every
/// fresh draw in the engine is required to refuse.
struct SilenceableEntropy {
    inner: SeededEntropy,
    silent: Arc<AtomicBool>,
}

impl Entropy for SilenceableEntropy {
    // A seam implementation, not a consumer: it forwards the draw it wraps.
    #[allow(clippy::disallowed_methods)]
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        match self.silent.load(Ordering::Relaxed) {
            true => Ok(()),
            false => self.inner.fill(dest),
        }
    }
}

/// A seeded seam and the flag that silences it.
fn silenceable(seed: u64) -> (Box<dyn Entropy>, Arc<AtomicBool>) {
    let silent = Arc::new(AtomicBool::new(false));
    (
        Box::new(SilenceableEntropy {
            inner: SeededEntropy::new(seed),
            silent: silent.clone(),
        }),
        silent,
    )
}

// ---------------------------------------------------------------------------
// Record-plane inspection: what a node's published record actually carries.
// ---------------------------------------------------------------------------

/// A node's write-plane IPNS name (`writeSeed(writeScopeSeed, id)` → keypair).
fn write_name(node: NodeId) -> IpnsName {
    IpnsName::from_public_key(&write_signer(node).verifying_key())
}

/// A node's write-plane signer, from the same edge the name comes off.
fn write_signer(node: NodeId) -> Ed25519Signer {
    kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes())
}

/// A node's per-node read key (`nodeSeed(scopeSeed, id)` → `readKey`) under
/// `scope_seed` — the epoch's seed is the only thing that moves it.
fn read_key_under(scope_seed: &[u8; 32], node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(scope_seed, &node.0).as_bytes()).as_bytes()
}

/// A node's per-node read key under the account's first read-scope seed.
fn read_key_of(node: NodeId) -> [u8; 32] {
    read_key_under(&READ_SCOPE_SEED, node)
}

/// The `(sequence, headCid)` of the record currently published under `node`'s
/// write-plane name, verified under that name.
fn published(records: &InMemoryRecordStore, node: NodeId) -> (u64, String) {
    let name = write_name(node);
    let bytes = records
        .record_at(&records.endpoints()[0], name.as_str())
        .expect("the node has a published record");
    let verified = IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(&name))
        .expect("the published record verifies under its own name");
    let head_cid = core::str::from_utf8(&verified.value)
        .expect("utf8 value")
        .strip_prefix("/ipfs/")
        .expect("an /ipfs/ pointer")
        .to_owned();
    (verified.sequence, head_cid)
}

/// The child refs a node's published folder body seals.
fn published_children(
    records: &InMemoryRecordStore,
    blocks: &Blocks,
    node: NodeId,
) -> Vec<ChildRef> {
    let (_, head_cid) = published(records, node);
    let envelope =
        decode_envelope(&blocks.get(&head_cid).expect("the head block")).expect("decodes");
    match open_read_body(&envelope, &read_key_of(node)).expect("opens under the read-seed key") {
        ReadBody::Folder { children, .. } => children,
        ReadBody::File { .. } => panic!("expected a folder body"),
    }
}

/// The names a node's published folder body lists, sorted.
fn published_names(records: &InMemoryRecordStore, blocks: &Blocks, node: NodeId) -> Vec<String> {
    let mut names: Vec<String> = published_children(records, blocks, node)
        .iter()
        .map(|child| child.name.clone())
        .collect();
    names.sort();
    names
}

/// The node id every head block this device uploaded was sealed for, in upload
/// order — the observable record of what published before what.
fn uploaded_node_ids(device: &FakeDevice) -> Vec<[u8; 16]> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/content/upload"))
        .filter_map(|request| decode_envelope(request.body.as_deref()?).ok())
        .map(|envelope| envelope.id)
        .collect()
}

/// Every registration entry the device sent for `name`, in wire order across
/// however many batches it took.
fn registration_entries(device: &FakeDevice, name: &IpnsName) -> Vec<serde_json::Value> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/register"))
        .filter_map(|request| {
            serde_json::from_slice::<Vec<serde_json::Value>>(request.body.as_deref()?).ok()
        })
        .flatten()
        .filter(|entry| entry["ipnsName"] == name.as_str())
        .collect()
}

/// The `contentCids` of one registration entry.
fn entry_content_cids(entry: &serde_json::Value) -> Vec<String> {
    entry["contentCids"]
        .as_array()
        .expect("an entry carries contentCids")
        .iter()
        .map(|cid| cid.as_str().expect("a CID string").to_owned())
        .collect()
}

/// The `contentCids` the device's last registration for `name` carried — what a
/// sub-EOL renewal will re-pin. One registration is the entry carrying the head
/// plus every content-only entry the chunker split off after it.
fn registered_content_cids(device: &FakeDevice, name: &IpnsName) -> Vec<String> {
    let entries = registration_entries(device, name);
    let head = entries
        .iter()
        .rposition(|entry| entry["headCid"].is_string())
        .unwrap_or(0);
    entries[head..]
        .iter()
        .flat_map(entry_content_cids)
        .collect()
}

/// The node a head block about to be uploaded was sealed for.
fn head_of(block: &[u8]) -> Option<[u8; 16]> {
    decode_envelope(block).ok().map(|envelope| envelope.id)
}

/// The id of `parent`'s child named `name`, from the rendered view.
fn child_id(engine: &Engine<FakeSeamTypes>, parent: NodeId, name: &str) -> NodeId {
    block_on(engine.view())
        .expect("a rendered view")
        .children(parent)
        .into_iter()
        .find(|child| child.name == name)
        .unwrap_or_else(|| panic!("no child named {name}"))
        .id
}

// ---------------------------------------------------------------------------

/// The first-run path with **no account fixture**: nothing is published when the
/// engine starts, so `start` must mint the vault itself. Every other test in this
/// file plants the pointer and the root by hand; this one proves the step that
/// produces them, and that a write against a self-provisioned vault reaches the
/// record plane.
#[test]
fn a_first_run_account_provisions_its_vault_and_publishes_a_write() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 64);
    let (mut engine, _events) = engine_on_api(&alice, 42);

    block_on(engine.start(secret())).expect("start provisions the first-run vault");

    // The pointer chain is no longer empty, and the root it names is published.
    let root_name = vault_root_name(&world);
    assert_eq!(
        sequence_at(&world, &root_name),
        1,
        "the genesis root publishes at sequence 1"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "a provisioned vault starts empty"
    );

    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages")
    .op_id();

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    // The write reached the record plane: the child is in gate-passing state and
    // the provisioned root republished over its own genesis record.
    let view = block_on(engine.snapshot(ROOT)).unwrap();
    assert_eq!(view.children.len(), 1, "the create published");
    assert_eq!(view.children[0].name, "photos");
    assert_eq!(
        view.children[0].pending,
        PendingClass::None,
        "a published op is no longer pending"
    );
    assert_eq!(
        sequence_at(&world, &root_name),
        2,
        "the root advanced past its own genesis sequence"
    );
    assert!(
        uploaded_node_ids(&alice).contains(&view.children[0].id.0),
        "the child's own head block was uploaded"
    );
    assert_eq!(
        block_on(drained_mark(&alice)),
        op_id.map(|id| id.0),
        "the drained op raised the durable completion mark"
    );

    // The other end of the chain: a second device of the same account, with its
    // own floors, cache and queue, cold-starts off nothing but what provisioning
    // published — so the pointer, the root, and the seeds it hands out are the
    // ones `cold_start` reads back.
    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 16);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret()))
        .expect("the second device cold-starts off the provisioned vault");
    let children = block_on(engine_b.view()).unwrap().children(ROOT);
    assert_eq!(children.len(), 1, "device B resolves the provisioned write");
    assert_eq!(children[0].name, "photos");
    assert_eq!(children[0].id, view.children[0].id);
}

/// A mint that did not land must not cost the session its write path. The
/// forced-refresh command a host already drives retries it: the vault mints, the
/// resolve-tick loop starts on the root it just published, and the ops queued
/// while the account had no vault publish in the same session — no restart.
#[test]
fn a_refreshed_retry_of_a_failed_mint_publishes_a_write_in_the_same_session() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 64);
    // The genesis head block has nowhere to land, so the mint does not.
    blocks.refuse_upload(Box::new(|_| Some(unreachable_upload())));
    let (mut engine, mut events) = engine_on_api(&alice, 42);

    block_on(engine.start(secret())).expect("a mint that did not land is not a failed start");
    assert!(
        !engine.is_provisioned(),
        "the session starts with no vault and a dark write path"
    );
    assert!(
        core::iter::from_fn(|| events.try_next()).any(|event| matches!(
            event,
            Event::VaultUnprovisioned {
                retryable: true,
                ..
            }
        )),
        "the stall is announced as retryable"
    );

    // The host keeps working: the op queues against the unprovisioned vault.
    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages against an unprovisioned vault")
    .op_id();

    blocks.accept_uploads();
    block_on(engine.command(Command::ManualRefresh)).expect("the retry mints");
    assert!(engine.is_provisioned(), "the write path opened in-session");

    let root_name = vault_root_name(&world);
    assert_eq!(
        sequence_at(&world, &root_name),
        1,
        "the late mint publishes its genesis root at sequence 1"
    );

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).unwrap();
    assert_eq!(view.children.len(), 1, "the queued create published");
    assert_eq!(view.children[0].name, "photos");
    assert_eq!(
        view.children[0].pending,
        PendingClass::None,
        "a published op is no longer pending"
    );
    assert_eq!(
        sequence_at(&world, &root_name),
        2,
        "the root advanced past the genesis the retry minted"
    );
    assert_eq!(
        block_on(drained_mark(&alice)),
        op_id.map(|id| id.0),
        "the op the dark session queued is the one that drained"
    );
}

/// The retry runs the same vacancy probe the first mint did, so an account
/// another device published in between is **adopted**, never minted over: a
/// second genesis would sign a re-point rolling that vault's floors back to the
/// genesis epoch.
#[test]
fn a_retry_adopts_the_vault_another_device_published_rather_than_minting_a_second() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 64);
    blocks.refuse_upload(Box::new(|_| Some(unreachable_upload())));
    let (mut engine, _events) = engine_on_api(&alice, 42);
    block_on(engine.start(secret())).expect("a mint that did not land is not a failed start");
    assert!(!engine.is_provisioned());

    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages against an unprovisioned vault")
    .op_id();

    // A second device of the same account mints while this session sits dark.
    blocks.accept_uploads();
    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 64);
    let (mut engine_b, _events_b) = engine_on_api(&bob, 43);
    block_on(engine_b.start(secret())).expect("the second device provisions the vault");
    let root_name = vault_root_name(&world);
    let published = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root_name.as_str())
        .expect("the second device published the genesis root");

    block_on(engine.command(Command::ManualRefresh)).expect("the retry settles on that vault");
    assert!(
        engine.is_provisioned(),
        "the write path opened on the live vault"
    );
    assert_eq!(
        world
            .record_store
            .record_at(&world.record_store.endpoints()[0], root_name.as_str()),
        Some(published),
        "the retry published no second genesis over the live root",
    );

    // And the op the dark session queued drains onto the vault it adopted.
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);
    let view = block_on(engine.snapshot(ROOT)).unwrap();
    assert_eq!(view.children.len(), 1);
    assert_eq!(view.children[0].name, "photos");
    assert_eq!(
        block_on(drained_mark(&alice)),
        op_id.map(|id| id.0),
        "the queued op drained onto the adopted vault",
    );
}

/// The index of every `POST /content/upload` this device made, in request order.
fn upload_positions(device: &FakeDevice) -> Vec<usize> {
    device
        .http
        .requests()
        .iter()
        .enumerate()
        .filter(|(_, request)| request.url.ends_with("/content/upload"))
        .map(|(index, _)| index)
        .collect()
}

/// The first write onto a freshly provisioned vault rests on one ordering inside
/// the tick body: the resolve adopts the genesis root — populating the snapshot
/// cache and advancing the name's sequence floor — before the drain reads that
/// cache in `load_scope_root`. Provisioning deliberately publishes without
/// advancing the floor itself, precisely so the first resolve is an `Adopted`
/// rather than a `Current` (which caches nothing), so both halves of that are
/// asserted here rather than left to the downstream "the folder published".
#[test]
fn the_first_tick_adopts_the_genesis_root_before_the_drain_reads_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 64);
    let (mut engine, _events) = engine_on_api(&alice, 42);
    block_on(engine.start(secret())).expect("start provisions the first-run vault");
    let root_name = vault_root_name(&world);

    // Provisioning publishes the root; it does not cache it. Nothing the drain
    // could author onto exists yet.
    assert_eq!(
        block_on(alice.snapshot_cache.get(root_name.as_str().as_bytes())).unwrap(),
        None,
        "the mint caches nothing — the adopt is the cache's only source",
    );

    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages");
    // Counted on the same basis the assertion below indexes on, so the two
    // cannot drift: the mint's own head upload must not be mistaken for the
    // drain's.
    let uploads_before = upload_positions(&alice).len();

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    // The tick's resolve adopted the genesis record, which is what a `Current`
    // verdict would not have done.
    assert!(
        block_on(alice.snapshot_cache.get(root_name.as_str().as_bytes()))
            .unwrap()
            .is_some(),
        "the first resolve adopted the genesis root",
    );

    // And it did so before the drain authored anything: the drain's first head
    // upload follows the gateway read the adopt made.
    let urls: Vec<String> = alice
        .http
        .requests()
        .iter()
        .map(|request| request.url.clone())
        .collect();
    let first_head_read = urls
        .iter()
        .position(|url| url.starts_with("https://gw.test/ipfs/"))
        .expect("the adopt fetches the genesis head block");
    let first_drain_upload = upload_positions(&alice)
        .get(uploads_before)
        .copied()
        .expect("the drain uploads the child's head block");
    assert!(
        first_head_read < first_drain_upload,
        "the drain authors onto state the same tick's resolve adopted",
    );
}

#[test]
fn a_manual_refresh_publishes_a_queued_op_without_waiting_out_the_cadence() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages");

    let started_at = cipherbox_engine::seams::Scheduler::now(&world.scheduler);
    poll_tasks_until_parked(&mut tasks);
    assert_eq!(
        block_on(engine.snapshot(ROOT)).unwrap().children[0].pending,
        PendingClass::Metadata,
        "no cadence elapsed, so nothing has published yet"
    );

    assert_eq!(
        command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks),
        Ok(CommandOutcome::Done),
        "the forced pass reconciled the owner root"
    );
    // The drain rides the same pass; the refresh returns on its read legs.
    poll_tasks_until_parked(&mut tasks);

    assert_eq!(
        block_on(engine.snapshot(ROOT)).unwrap().children[0].pending,
        PendingClass::None,
        "the forced pass published the queued op"
    );
    assert_eq!(
        cipherbox_engine::seams::Scheduler::now(&world.scheduler),
        started_at,
        "the pass ran on the request, not on the poll cadence"
    );
}

#[test]
fn a_manual_refresh_resolves_the_owner_root_without_reading_the_cache() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);
    let root_key = root_name.as_str().as_bytes().to_vec();

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    tick(&world, &engine, &mut tasks);
    assert!(
        alice.snapshot_cache.reads().contains(&root_key),
        "a scheduled tick resolves the root cache-first"
    );

    let before = alice.snapshot_cache.reads().len();
    assert_eq!(
        command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks),
        Ok(CommandOutcome::Done)
    );
    assert!(
        !alice.snapshot_cache.reads()[before..].contains(&root_key),
        "a forced refresh bypasses the cache the scheduled tick honours"
    );
}

#[test]
fn a_manual_refresh_reports_an_unreachable_record_plane_as_a_failure() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    // Nothing gate-passing comes back off a dark record plane: the cached copy
    // must not be reported as a landed refresh.
    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_endpoint(&endpoint);
    }
    assert!(matches!(
        command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks),
        Err(EngineError::RefreshFailed { .. })
    ));
}

#[test]
fn a_manual_refresh_reports_a_rejected_record_as_a_trust_violation() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);
    let endpoint = world.record_store.endpoints()[0].clone();
    let seeded = world
        .record_store
        .record_at(&endpoint, root_name.as_str())
        .expect("the account's seeded root record");

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages");
    tick(&world, &engine, &mut tasks); // republishes the root, raising its floor

    // A replay of the record this device already moved past: fail-closed, and
    // reported as the verdict it is rather than as retryable staleness.
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, root_name.as_str(), seeded.clone());
    }
    assert!(matches!(
        command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks),
        Err(EngineError::TrustViolation { .. })
    ));
}

/// The forced pass reads the focus window as well as the root, so a folder in
/// view that no endpoint served leaves the user on last-known-good — reporting
/// that pass as landed would be a silent lie about what was reconciled.
#[test]
fn a_manual_refresh_reports_an_unreachable_focus_folder_as_a_failure() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    // Authored on another device, so the focusing device really descends into
    // the folder instead of reading back its own staged state.
    let author = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks_a) = boot(&world, &blocks, &author, 42);
    block_on(engine_a.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine_a, &mut tasks_a);
    let photos = child_id(&engine_a, ROOT, "photos");

    let alice = world.device(b"alice-second-device");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 7);
    block_on(engine.command(Command::SetFocus { node: Some(photos) })).unwrap();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks),
        Ok(CommandOutcome::Done),
        "the whole window answers while the folder's record stands"
    );

    // Only the focused folder's record goes dark; the root still answers, so a
    // root-only verdict would call this pass reconciled.
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, write_name(photos).as_str(), Vec::new());
    }
    assert!(matches!(
        command_while_ticking(&mut engine, Command::ManualRefresh, &mut tasks),
        Err(EngineError::RefreshFailed { .. })
    ));
}

#[test]
fn a_folder_create_publishes_and_resolves_back() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 16);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).expect("cold start adopts the owner root");
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "the account starts with an empty root"
    );

    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages")
    .op_id();
    assert!(
        op_id.is_some(),
        "a staged op is addressable by its queue id"
    );

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks); // park both loops at their first sleep
    tick(&world, &engine, &mut tasks);

    // The op left the queue and the child is in gate-passing state, not the
    // pending overlay: the drain published it and self-adopted its own bytes.
    let view = block_on(engine.snapshot(ROOT)).unwrap();
    assert_eq!(view.children.len(), 1, "the create published");
    assert_eq!(view.children[0].name, "photos");
    assert_eq!(view.children[0].kind, NodeKind::Folder);
    assert_eq!(
        view.children[0].pending,
        PendingClass::None,
        "a published op is no longer pending"
    );

    // The record plane really carries it: the root republished at sequence 2.
    let published = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root_name.as_str())
        .expect("the root record is published");
    let sequence = IpnsRecord::unmarshal(&published)
        .and_then(|record| record.verify(&root_name))
        .expect("the published root verifies under its own name")
        .sequence;
    assert_eq!(sequence, 2, "the root advanced past the seeded sequence 1");

    // The completion record marks the op as drained, so a restored copy of this
    // queue cannot replay it.
    assert_eq!(
        block_on(drained_mark(&alice)),
        op_id.map(|id| id.0),
        "the drained op raised the durable completion mark"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "and left the durable queue"
    );
}

/// The two KDF edges the write plane hangs off must not be crossed: a node's
/// name comes from the WRITE scope seed and its body opens under a key derived
/// from the READ scope seed. Swapping them would still publish, so only this
/// pins them.
#[test]
fn a_published_child_sits_on_the_write_name_edge_and_the_read_key_edge() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 16);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    let child = block_on(engine.view()).unwrap().children(ROOT)[0].id;

    // The name edge: `writeSeed(writeScopeSeed, id) -> ipnsKeypair`.
    let expected_name = IpnsName::from_public_key(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &child.0).as_bytes()).verifying_key(),
    );
    let record = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], expected_name.as_str())
        .expect("the child publishes under the write-seed name");
    let verified = IpnsRecord::unmarshal(&record)
        .and_then(|r| r.verify(&expected_name))
        .expect("and is signed by that name's own key");

    // The read-key edge: `nodeSeed(readScopeSeed, id) -> readKey`.
    let head_cid = core::str::from_utf8(&verified.value)
        .unwrap()
        .strip_prefix("/ipfs/")
        .unwrap();
    let envelope = decode_envelope(&blocks.get(head_cid).expect("the head block")).unwrap();
    let read_key = kdf::read_key(kdf::node_seed(&READ_SCOPE_SEED, &child.0).as_bytes());
    let body = open_read_body(&envelope, read_key.as_bytes())
        .expect("the child body opens under the read-seed key");
    assert!(
        matches!(body, ReadBody::Folder { ref children, .. } if children.is_empty()),
        "a fresh folder publishes an empty child list"
    );
}

/// A restart whose root is unchanged resolves `Current`, which adopts nothing.
/// The write plane must still keep the seeds it seals and signs under, or the
/// very bug this slice fixes — a `mkdir` that publishes nothing — returns on
/// the second run.
#[test]
fn a_restart_that_adopts_nothing_still_drains() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 40);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);
    drop(engine);

    // Same device, second run: the network root is exactly at this device's
    // durable floor, so cold start reconciles without adopting.
    let (mut engine, _events) = engine_on(&alice, 43);
    block_on(engine.start(secret())).unwrap();
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "docs".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    let mut names: Vec<String> = block_on(engine.view())
        .unwrap()
        .children(ROOT)
        .into_iter()
        .map(|child| child.name)
        .collect();
    names.sort();
    assert_eq!(names, ["docs", "photos"], "both runs published");

    let published = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root_name.as_str())
        .expect("the root record is published");
    let sequence = IpnsRecord::unmarshal(&published)
        .and_then(|record| record.verify(&root_name))
        .expect("the published root verifies under its own name")
        .sequence;
    assert_eq!(sequence, 3, "the second run advanced the root again");
}

/// The drain covers `Create` for both kinds: a file with no content yet is a
/// metadata-only create exactly like a folder, and its record is a file body
/// with an empty version list.
#[test]
fn an_empty_file_create_publishes_under_the_same_metadata_path() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 16);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "notes.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).unwrap();
    assert_eq!(view.children.len(), 1);
    assert_eq!(view.children[0].name, "notes.txt");
    assert_eq!(
        view.children[0].kind,
        NodeKind::File,
        "the kind the parent ref carries is the kind the child body was sealed as"
    );
    assert_eq!(view.children[0].pending, PendingClass::None);
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the queue drained rather than wedging on an unsupported kind"
    );
}

#[test]
fn a_second_device_of_the_same_account_resolves_the_write() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 16);
    let (mut engine_a, _events_a) = engine_on(&alice, 42);
    block_on(engine_a.start(secret())).unwrap();
    block_on(engine_a.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine_a, &mut tasks);

    // A second device of the same account, cold: its own floors, cache, and
    // queue, sharing only the network and the clock.
    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 8);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret()))
        .expect("the second device cold-starts off the published record plane");

    let children = block_on(engine_b.view()).unwrap().children(ROOT);
    assert_eq!(children.len(), 1, "device B resolves device A's write");
    assert_eq!(children[0].name, "photos");
    assert_eq!(
        children[0].id,
        block_on(engine_a.view()).unwrap().children(ROOT)[0].id
    );
}

/// Feed `plaintext` through a write handle in small slices, the way a host
/// slices a `File`, and commit it.
/// A new version of `node`, anchored on whatever the engine derives — the
/// shape every write here takes but the one that supplies its own version.
fn version(node: NodeId) -> WriteTarget {
    WriteTarget::Version {
        node,
        expected_version: None,
    }
}

fn write_file(
    engine: &mut Engine<FakeSeamTypes>,
    target: WriteTarget,
    plaintext: &[u8],
) -> Result<OpId, EngineError> {
    let handle = block_on(engine.begin_write(target, plaintext.len() as u64))?;
    for slice in plaintext.chunks(7) {
        block_on(engine.push_chunk(handle, slice))?;
    }
    block_on(engine.commit_write(handle))
}

/// One committed file under the root, for tests about what a write *triggers*
/// rather than what it stores.
fn write_photo(engine: &mut Engine<FakeSeamTypes>, name: &str) -> OpId {
    write_file(
        engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: name.to_owned(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits")
}

/// How many times this device asked the API to move the account's BYO flag.
fn byo_toggles(device: &FakeDevice) -> usize {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/account/byo"))
        .count()
}

/// Alice publishes `plaintext` as `clip.bin` under the root, handing back her
/// engine and pump tasks so a caller can republish over it.
fn publish_clip(
    world: &FakeWorld,
    blocks: &Blocks,
    plaintext: &[u8],
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>, NodeId) {
    let alice = world.device(b"alice");
    let (mut engine, events, mut tasks) = boot(world, blocks, &alice, 42);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "clip.bin".into(),
        },
        plaintext,
    )
    .expect("the write commits");
    tick(world, &engine, &mut tasks);
    let node = child_id(&engine, ROOT, "clip.bin");
    (engine, events, tasks, node)
}

/// A started second device of the same account, its block plane wired for
/// `calls` HTTP calls — the reader that only ever saw the network.
fn open_reader(
    world: &FakeWorld,
    blocks: &Blocks,
    calls: usize,
) -> (FakeDevice, Engine<FakeSeamTypes>, EventStream) {
    let device = world.device(b"alice-second-device");
    serve_http(&device, blocks, calls);
    let (mut engine, events) = engine_on(&device, 7);
    block_on(engine.start(secret())).unwrap();
    (device, engine, events)
}

/// The slice's headline: content bytes sliced by the client, sealed and staged
/// per block by the engine, uploaded and published by the drain, and downloaded
/// and verified byte-for-byte by a second device that only ever saw the network.
#[test]
fn a_file_create_round_trips_its_bytes_to_a_second_device() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    // Multi-leaf at the CI framing, so the DAG, the per-block staging, and the
    // upload ordering are all exercised rather than degenerate.
    let plaintext: Vec<u8> = (0..200u8).collect();

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine_a,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .expect("the write commits");
    tick(&world, &engine_a, &mut tasks);

    // Every staged block left with its upload: the drain releases the version's
    // blocks once its record has published, leaving only the queue bookkeeping.
    assert_eq!(
        block_on(alice.staging_store.staged_keys()).unwrap(),
        vec![drained_key(), mark_key()],
        "no staged block survives a published version, only queue bookkeeping"
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty(),
        "the op left the queue"
    );

    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 400);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret()))
        .expect("the second device cold-starts off the published record plane");

    let children = block_on(engine_b.view()).unwrap().children(ROOT);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].name, "photo.bin");
    assert_eq!(children[0].kind, NodeKind::File);

    assert_eq!(
        block_on(engine_b.read_content(children[0].id)).expect("the verified read serves it"),
        plaintext,
        "the bytes device A sealed are the bytes device B verifies"
    );
    assert_eq!(
        block_on(engine_b.view())
            .unwrap()
            .attrs(children[0].id)
            .unwrap()
            .size,
        Some(plaintext.len() as u64),
        "the published version carries its own manifest's size"
    );
}

/// A stream's windows serve the matching slices of the whole-file read — the
/// media pipe's read path.
#[test]
fn a_stream_window_serves_the_same_bytes_as_the_slice_of_the_whole_file() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    // Several CI leaves, so a window can land inside, across, and past them.
    let plaintext: Vec<u8> = (0..200u8).collect();

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine_a,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "clip.bin".into(),
        },
        &plaintext,
    )
    .expect("the write commits");
    tick(&world, &engine_a, &mut tasks);

    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 400);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret())).unwrap();
    let node = block_on(engine_b.view()).unwrap().children(ROOT)[0].id;

    let whole = block_on(engine_b.read_content(node)).expect("the verified read serves it");
    assert_eq!(whole, plaintext);

    let stream = block_on(engine_b.open_content_stream(node)).expect("the stream opens");
    for (offset, length) in [(0u64, 16u64), (16, 16), (15, 2), (40, 100), (190, 999)] {
        let end = (offset + length).min(whole.len() as u64) as usize;
        assert_eq!(
            block_on(engine_b.read_stream(stream, offset, length)).expect("the window serves it"),
            whole[offset as usize..end],
            "range {offset}+{length}"
        );
    }
    for offset in [whole.len() as u64, whole.len() as u64 + 1, u64::MAX] {
        assert!(
            block_on(engine_b.read_stream(stream, offset, 16))
                .unwrap()
                .is_empty(),
            "a window past the end is empty, not an error: offset {offset}"
        );
    }
    engine_b.close_stream(stream);
}

/// A node whose first version is published and whose second is staged and not
/// drained, with the durable id of the op that owes the staged one.
fn a_staged_second_version(
    world: &FakeWorld,
    alice: &FakeDevice,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) -> (NodeId, OpId) {
    write_file(
        engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "clip.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the first version commits");
    tick(world, engine, tasks);
    let node = block_on(engine.view()).unwrap().children(ROOT)[0].id;
    write_file(engine, version(node), &vec![0xBB; 323]).expect("the second version commits");
    let op_id = block_on(alice.staging_store.queued_ops()).unwrap()[0].0;
    (node, op_id)
}

/// The bytes a read serves and the length the rendered view reports must come
/// from one version, on both readers: the stream a mount composes over and the
/// whole-file read the web download takes. A staged version pairs them off the
/// staging store, so a file just written reads back before the drain publishes
/// it.
#[test]
fn both_readers_serve_the_staged_version_the_rendered_size_names() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (node, _) = a_staged_second_version(&world, &alice, &mut engine, &mut tasks);

    assert_eq!(
        block_on(engine.view()).unwrap().attrs(node).unwrap().size,
        Some(323),
        "the rendered size is the staged version's"
    );

    let staged = block_on(engine.open_content_stream(node)).expect("the staged version opens");
    assert_eq!(
        engine.stream_size(staged),
        Some(323),
        "the stream pins the length the rendered view reports"
    );
    assert_eq!(
        engine.stream_version_cid(staged),
        block_on(engine.rendered_version_cid(node)).unwrap(),
        "the stream pins the very version the rendered size names"
    );
    assert_eq!(
        block_on(engine.read_stream(staged, 0, 323)).expect("the window serves it"),
        vec![0xBB; 323],
        "the stream serves the staged bytes, never the published version's"
    );
    assert_eq!(
        block_on(engine.read_content(node)).expect("the whole-file read serves it"),
        vec![0xBB; 323],
        "the same version on the other surface"
    );
    engine.close_stream(staged);

    // The drain moves nothing the reader could see: the same bytes, now
    // published, and the reader stops paying the staging store for them.
    tick(&world, &engine, &mut tasks);
    let opened = block_on(engine.open_content_stream(node)).expect("the drained version opens");
    assert_eq!(
        block_on(engine.read_stream(opened, 0, 323)).expect("the window serves it"),
        vec![0xBB; 323],
        "the same open serves the version once it is published"
    );
    engine.close_stream(opened);
}

/// A staged version this device can no longer assemble is availability, and the
/// refusal names the queued op that still owes it: a bare "unavailable" leaves
/// the host nothing to route the member to.
#[test]
fn a_staged_version_missing_a_block_refuses_and_names_the_queued_op() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (node, op_id) = a_staged_second_version(&world, &alice, &mut engine, &mut tasks);
    // One leaf lost: no gateway serves what no drain has uploaded.
    evict_leaf(&alice, |_| 0);

    // The root manifest is still staged, so the stream opens on the version the
    // rendered length names; only the window that needs the lost leaf refuses.
    let stream = block_on(engine.open_content_stream(node)).expect("the staged root opens");
    for refusal in [
        block_on(engine.read_content(node)),
        block_on(engine.read_stream(stream, 0, 323)),
    ] {
        match refusal {
            Err(EngineError::ContentUnavailable { message }) => assert!(
                message.contains(&format!("queued op {}", op_id.0)),
                "the refusal names the op that owes the version: {message}"
            ),
            other => panic!("expected an availability refusal, got {other:?}"),
        }
    }
    engine.close_stream(stream);
}

/// A staged block that does not content-address is a trust violation, and it is
/// terminal: the nearer source is not the more trusted one, so the read never
/// asks a gateway for what its own store got wrong. The verdict names the op,
/// because every byte a staged read judges came from that one op.
#[test]
fn a_staged_block_that_does_not_address_is_terminal_and_names_the_queued_op() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (node, op_id) = a_staged_second_version(&world, &alice, &mut engine, &mut tasks);
    let (root_cid, _) = staged_version(&alice);
    block_on(
        alice
            .staging_store
            .put_staged_bytes(&root_cid, b"not the root this cid names"),
    )
    .expect("the store takes it");

    let before = alice.http.requests().len();
    match block_on(engine.read_content(node)) {
        Err(EngineError::TrustViolation { message }) => assert!(
            message.contains(&format!("queued op {}", op_id.0)),
            "the verdict names the op whose staged bytes disagree: {message}"
        ),
        other => panic!("expected a trust violation, got {other:?}"),
    }
    assert_eq!(
        alice.http.requests().len(),
        before,
        "a local mismatch is terminal: it never rotates to a gateway"
    );
}

/// Past [`MAX_OPEN_STREAMS`] an open is refused fail-closed, never evicting a
/// live stream, and the refusal costs no network: the slot is reserved before
/// the resolve, so a doomed open never pays for one.
#[test]
fn opening_past_the_stream_ceiling_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let plaintext: Vec<u8> = (0..64u8).collect();

    let (_engine_a, _events_a, _tasks, node) = publish_clip(&world, &blocks, &plaintext);
    // A few calls per open, plus the reads below.
    let (bob, engine_b, _events_b) = open_reader(&world, &blocks, MAX_OPEN_STREAMS * 8 + 64);

    let handles: Vec<_> = (0..MAX_OPEN_STREAMS)
        .map(|open| {
            block_on(engine_b.open_content_stream(node))
                .unwrap_or_else(|err| panic!("stream {open} opens: {err}"))
        })
        .collect();

    let fetches_at_ceiling = bob.http.requests().len();
    assert_eq!(
        block_on(engine_b.open_content_stream(node)),
        Err(EngineError::TooManyStreams),
        "the open past the ceiling is refused"
    );
    assert_eq!(
        bob.http.requests().len(),
        fetches_at_ceiling,
        "the refused open spent no network on a resolve it could not use"
    );

    // The refusal did not evict: an earlier handle still serves its version.
    assert_eq!(
        block_on(engine_b.read_stream(handles[0], 0, 16)).expect("the first stream still reads"),
        plaintext[..16]
    );

    // Closing one frees exactly one slot.
    engine_b.close_stream(handles[0]);
    let reopened = block_on(engine_b.open_content_stream(node)).expect("a freed slot admits one");
    assert_eq!(
        block_on(engine_b.open_content_stream(node)),
        Err(EngineError::TooManyStreams),
        "the table is full again"
    );
    engine_b.close_stream(reopened);
}

/// A stream pins the head version it opened on: a head change mid-stream leaves
/// every later window a slice of the pinned version, never a splice of two.
#[test]
fn a_stream_serves_the_pinned_version_across_a_head_change() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    // Same length, disjoint bytes: a spliced window is a wrong-byte failure, not
    // a length one, so the assertion catches the splice itself.
    let first: Vec<u8> = (0..200u8).collect();
    let second: Vec<u8> = (0..200u8).map(|byte| 255 - byte).collect();

    let (mut engine_a, _events_a, mut tasks, node) = publish_clip(&world, &blocks, &first);
    let (_bob, engine_b, _events_b) = open_reader(&world, &blocks, 400);

    let stream = block_on(engine_b.open_content_stream(node)).expect("the stream opens");
    let mut assembled = block_on(engine_b.read_stream(stream, 0, 16)).expect("the first window");

    // The owner's other device republishes the file under a new version while
    // the stream is mid-body.
    write_file(&mut engine_a, version(node), &second).expect("the update commits");
    tick(&world, &engine_a, &mut tasks);

    while (assembled.len() as u64) < first.len() as u64 {
        let window = block_on(engine_b.read_stream(stream, assembled.len() as u64, 16))
            .expect("a later window");
        assert!(
            !window.is_empty(),
            "a window short of the end made no progress"
        );
        assembled.extend_from_slice(&window);
    }
    assert_eq!(
        assembled, first,
        "the whole body is a slice of the version the stream opened on"
    );

    // The head really did move: a fresh read serves the new version, so the
    // pinning above is not just a stale-resolve artifact.
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head version reads"),
        second
    );

    engine_b.close_stream(stream);
    assert_eq!(
        block_on(engine_b.read_stream(stream, 0, 16)),
        Err(EngineError::UnknownStreamHandle),
        "a closed handle reads nothing"
    );
}

/// The size a stream reports is its pinned version's, never the head's: a
/// ranged reader that framed a response from a later, shorter version would
/// promise more bytes than the body it serves can carry.
#[test]
fn a_stream_reports_the_size_of_the_version_it_pinned() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let long: Vec<u8> = (0..200u8).collect();
    let short: Vec<u8> = (0..40u8).collect();

    let (mut engine_a, _events_a, mut tasks, node) = publish_clip(&world, &blocks, &long);
    let (_bob, engine_b, _events_b) = open_reader(&world, &blocks, 400);

    let stream = block_on(engine_b.open_content_stream(node)).expect("the stream opens");
    write_file(&mut engine_a, version(node), &short).expect("the update commits");
    tick(&world, &engine_a, &mut tasks);

    assert_eq!(engine_b.stream_size(stream), Some(long.len() as u64));
    // The head really did shrink, so the size above is the pin and not a stale
    // resolve.
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head version reads"),
        short
    );

    engine_b.close_stream(stream);
    assert_eq!(
        engine_b.stream_size(stream),
        None,
        "a closed handle pins no version"
    );
}

/// A stream resolves, gates, and verifies its root once, however many windows it
/// serves — the per-window cost the media pipe's ranged read paid on every
/// megabyte.
#[test]
fn a_stream_pays_one_resolve_and_one_root_fetch_for_the_whole_body() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let plaintext: Vec<u8> = (0..200u8).collect();
    let window = ContentProfile::CI.chunk_size();
    // One window per leaf, so the leaf fetches a stream makes are countable.
    let leaves = plaintext.len().div_ceil(window);

    let (_engine_a, _events_a, _tasks, node) = publish_clip(&world, &blocks, &plaintext);
    let (bob, engine_b, _events_b) = open_reader(&world, &blocks, 400);

    let stream = block_on(engine_b.open_content_stream(node)).expect("the stream opens");
    // Every routing endpoint goes dark once the stream is open: a window that
    // re-resolved the node would fail here rather than serve.
    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_endpoint(&endpoint);
    }

    let fetches_at_open = bob.http.requests().len();
    let mut assembled = Vec::new();
    while assembled.len() < plaintext.len() {
        let bytes = block_on(engine_b.read_stream(stream, assembled.len() as u64, window as u64))
            .expect("a window off the pinned version");
        assert!(
            !bytes.is_empty(),
            "a window short of the end made no progress"
        );
        assembled.extend_from_slice(&bytes);
    }
    assert_eq!(assembled, plaintext);
    assert_eq!(
        bob.http.requests().len() - fetches_at_open,
        leaves,
        "one leaf per window and no root re-fetch"
    );
}

/// A new version of an existing file takes the head of its version list and is
/// what a second device downloads.
#[test]
fn an_update_content_write_round_trips_the_new_version_to_a_second_device() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine_a,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        b"first version bytes",
    )
    .unwrap();
    tick(&world, &engine_a, &mut tasks);
    let node = child_id(&engine_a, ROOT, "notes.txt");

    write_file(
        &mut engine_a,
        version(node),
        b"second version bytes, longer than the first",
    )
    .unwrap();
    tick(&world, &engine_a, &mut tasks);

    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 400);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret())).unwrap();
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head version reads"),
        b"second version bytes, longer than the first",
        "the newest version is the head"
    );
}

/// The publish registers every block the version links, and the held record
/// keeps that list so a sub-EOL renewal re-pins the same content.
#[test]
fn a_published_version_registers_its_whole_block_set() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let plaintext: Vec<u8> = (0..200u8).collect();

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine_a,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .unwrap();
    tick(&world, &engine_a, &mut tasks);

    let node = child_id(&engine_a, ROOT, "photo.bin");
    let registered = registered_content_cids(&alice, &write_name(node));
    // 200 bytes at the CI framing frames to 13 leaves plus the root.
    assert_eq!(
        registered.len(),
        14,
        "every block the version links rides the registration"
    );
    assert!(
        registered.iter().all(|cid| blocks.get(cid).is_some()),
        "every registered CID names a block the provider holds"
    );
}

/// A version with more blocks than the registry's per-entry `contentCids` cap
/// splits across several entries under one name, so the registration that
/// register-first blocks the record PUT on is accepted and the version
/// publishes.
#[test]
fn a_version_past_the_registration_cap_registers_in_chunks_and_publishes() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    // 1001 leaves at the CI framing, plus the root: one past the cap.
    let leaves = REGISTRY_BATCH_MAX + 1;
    let plaintext: Vec<u8> = (0..leaves * 16).map(|byte| byte as u8).collect();

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    // An upload apiece for the leaves and the root, plus the metadata plane's
    // own calls, on top of what `boot` already scripted.
    serve_http(&alice, &blocks, 2 * leaves);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "big.bin".into(),
        },
        &plaintext,
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let node = child_id(&engine, ROOT, "big.bin");
    let entries = registration_entries(&alice, &write_name(node));
    let sizes: Vec<usize> = entries
        .iter()
        .map(|e| entry_content_cids(e).len())
        .collect();
    assert_eq!(
        sizes,
        vec![REGISTRY_BATCH_MAX, 2],
        "the registration splits at the per-entry cap"
    );
    let with_head: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry["headCid"].is_string())
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        with_head,
        vec![0],
        "the head rides the first entry alone, so the name and its pointer land first"
    );

    let registered = registered_content_cids(&alice, &write_name(node));
    assert!(
        registered.iter().all(|cid| blocks.get(cid).is_some()),
        "every registered CID names a block the provider holds"
    );
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "a chunked registration is accepted, so the op publishes"
    );
}

/// A registration the registry itself refuses is refused on every retry, and
/// the queue is strict FIFO — so the op dead-letters instead of holding the head
/// and re-registering every tick.
#[test]
fn a_registration_the_registry_refuses_dead_letters_instead_of_holding_the_queue_head() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_register(registry_batch_refused());

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();

    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert_eq!(
        passes, 1,
        "the registry's own verdict is permanent on sight"
    );
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::PayloadRefused
        }]
    );
    assert!(
        !retire_targets(&alice).is_empty(),
        "the abandonment retires what the refused registration's chunks charged"
    );
}

/// A `400` the registry did not stamp is evidence of nothing: the op is charged
/// like any other pre-PUT refusal and survives until its budget runs out, rather
/// than being abandoned on an intermediary's say-so.
#[test]
fn a_registration_400_from_an_intermediary_is_charged_not_permanent() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_register(proxy_400());

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();

    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert!(
        passes > 1,
        "an unattributable refusal is a charged attempt, not a verdict"
    );
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::AttemptsExhausted
        }]
    );
}

/// A head over the block ceiling is refused identically on every retry: a fresh
/// nonce moves the sealed bytes and never their count, so no re-author shrinks
/// it. Uncharged it would hold the strict-FIFO queue head forever with nothing
/// reported anywhere, so it spends the budget and every op behind it drains —
/// but only the record was over the ceiling, so ending it keeps the version it
/// would have named rather than unpinning and erasing it, and owes back only the
/// child name no parent record ever reached. It ends under its own reason: the
/// remedy is to split the listing, which a transport outage's "try again" never
/// reaches.
#[test]
fn an_authored_head_over_the_block_ceiling_dead_letters_with_its_version_intact() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    // An ordinary folder, not the scope root: a scope root reserves part of its
    // record for the grant section a re-key rebuilds, and the adoption gate
    // refuses a foreign root over that reservation before its listing is ever
    // read.
    create(&mut engine, "bulky");
    let bulky = child_id(&engine, ROOT, "bulky");
    tick(&world, &engine, &mut tasks);

    concurrent_add(
        &world.record_store,
        &blocks,
        bulky,
        child_at_the_block_ceiling(),
    );
    tick(&world, &engine, &mut tasks);

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: bulky,
            name: "one-child-too-many.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let doomed = child_id(&engine, bulky, "one-child-too-many.bin");

    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert!(
        passes > 1,
        "a size refusal is charged against the budget, not permanent on sight"
    );
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::HeadTooLarge
        }]
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the head no retry could publish leaves the queue"
    );
    assert_eq!(
        retire_targets(&alice),
        vec![write_name(doomed).as_str().to_owned()],
        "the version the oversized record would have named stays pinned — unpinning \
         it is loss no retry undoes — while the child name the parent never came to \
         reference is owed back like any abandoned create's"
    );
}

/// A peer-authored child carrying preserved bulk that leaves its folder one
/// child short of the block ceiling.
///
/// This is the route the facade bounds cannot close: the rendered view drops a
/// child's carried fields, so `refuse_full_parent` cannot charge them, while the
/// drain re-emits them into the record it authors.
fn child_at_the_block_ceiling() -> ChildRef {
    let padded = |pad: usize| {
        let mut child = file_ref([0xB1; 16], "peer-authored.bin");
        child.unknown = [("pad".to_owned(), Value::Bytes(vec![0u8; pad]))]
            .into_iter()
            .collect();
        child
    };
    let sealed = |child: &ChildRef| {
        let body = ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: vec![child.clone()],
            unknown: PreservedFields::new(),
        };
        encode_read_body(&body).expect("the body encodes").len() + NONCE_LEN + TAG_LEN
    };

    // Sized against the encoder, because a CBOR length head grows with what it
    // measures. The headroom left is smaller than one child ref, so the next
    // child this device authors puts the record over.
    let target = MAX_READ_SEALED_BYTES - 64;
    let mut pad = target - sealed(&padded(0));
    for _ in 0..8 {
        let short = target as isize - sealed(&padded(pad)) as isize;
        if short == 0 {
            break;
        }
        pad = pad.saturating_add_signed(short);
    }
    let child = padded(pad);
    let at = sealed(&child);
    assert!(
        at <= MAX_READ_SEALED_BYTES && MAX_READ_SEALED_BYTES - at < CHILD_REF_FLOOR,
        "the seed must open and leave less than one child ref: {at}"
    );
    child
}

/// Smaller than any child ref the engine authors, so the seed above is provably
/// one child short of the ceiling rather than approximately so.
const CHILD_REF_FLOOR: usize = 96;

/// The child ceiling is what keeps a folder this device authors inside the IPFS
/// block ceiling, and a peer decides how many children a folder already holds.
/// So the refusal is driven against a *published* over-full listing: the ceiling
/// has to bite on a record this device adopted from the network, and it has to
/// bite at the boundary rather than as a dead letter, because a queued op no
/// re-author can shrink spends a staging reservation and reports a failure where
/// the remedy is to split the folder.
#[test]
fn a_peer_overfilled_folder_refuses_a_further_child_and_stages_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let planted: Vec<ChildRef> = (0..MAX_FOLDER_CHILDREN)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            // One folder among them, so the last assertion has a parent with room.
            if i == 0 {
                child_ref(id, "planted-folder", CoreNodeKind::Folder)
            } else {
                file_ref(id, &format!("planted-{i}.bin"))
            }
        })
        .collect();
    concurrent_root_extend(&world.record_store, &blocks, planted);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        block_on(engine.view()).unwrap().children(ROOT).len(),
        MAX_FOLDER_CHILDREN,
        "the peer's listing is in gate-passing state"
    );

    assert_eq!(
        block_on(engine.command(Command::Create {
            parent: ROOT,
            name: "one-too-many.bin".into(),
            kind: NodeKind::File,
        })),
        Err(EngineError::MalformedInput {
            check: "folder-child-ceiling",
        }),
        "the boundary refuses, so the caller learns the folder is full"
    );
    assert_eq!(
        block_on(engine.begin_write(
            WriteTarget::NewFile {
                parent: ROOT,
                name: "one-too-many.bin".into(),
            },
            8,
        ))
        .err(),
        Some(EngineError::MalformedInput {
            check: "folder-child-ceiling",
        }),
        "a write handle creates a child too, and it reserves staging bytes first"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "a refusal at the boundary queues nothing for the drain to end"
    );

    // The ceiling bounds the folder, never the vault.
    block_on(engine.command(Command::Create {
        parent: child_id(&engine, ROOT, "planted-folder"),
        name: "under-a-sibling.bin".into(),
        kind: NodeKind::File,
    }))
    .expect("a folder with room still takes a child");
}

/// A `NewFile` handle takes no place in its folder until it commits, so two
/// handles opened together both see the same free one. The commit re-check is
/// what stops the second from overfilling the folder.
#[test]
fn the_second_handle_over_the_last_free_place_is_refused_at_its_commit() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let planted: Vec<ChildRef> = (0..MAX_FOLDER_CHILDREN - 1)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            file_ref(id, &format!("planted-{i}.bin"))
        })
        .collect();
    concurrent_root_extend(&world.record_store, &blocks, planted);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        block_on(engine.view()).unwrap().children(ROOT).len(),
        MAX_FOLDER_CHILDREN - 1,
        "exactly one place is free"
    );

    let first = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "first.bin".into(),
        },
        8,
    ))
    .expect("the free place admits the first handle");
    let second = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "second.bin".into(),
        },
        8,
    ))
    .expect("the second handle sees the same free place");

    for handle in [first, second] {
        block_on(engine.push_chunk(handle, &[0x7a; 8])).expect("the bytes stage");
    }
    block_on(engine.commit_write(first)).expect("the first commit takes the place");
    assert_eq!(
        block_on(engine.commit_write(second)),
        Err(EngineError::MalformedInput {
            check: "folder-child-ceiling",
        }),
        "the re-check refuses the second rather than overfilling the folder"
    );
}

/// Cache a scope root whose carried grant section is committed to a different
/// `ipnsName` — the account's own root bytes, re-sectioned and re-signed, so
/// only the commitment's name is wrong. The drain reads its anchor from the
/// cache under a floor check rather than the whole gate, which is how a section
/// the gate would have refused reaches the authoring path at all.
fn cache_a_root_committed_to_another_name(device: &FakeDevice, blocks: &Blocks) {
    let fixture = owner_root_fixture(OwnerRootSpec {
        owner_identity: &owner_identity(),
        owner_enc: &kdf::enc_subkey(&SECRET).public(),
        scope_id: SCOPE,
        root_id: ROOT.0,
        children: Vec::new(),
        child_scope_index: Vec::new(),
        parent_node_seed: None,
        owner_write_blob_epoch: Some(EPOCH),
        write_history_link: Vec::new(),
        grants: Vec::new(),
    });
    let mut section = fixture.grant_section;
    section.commitment.ipns_name = write_name(NodeId([0x5C; 16])).as_str().as_bytes().to_vec();
    section.commitment_sig = sign_grant_set(&owner_identity(), &section.commitment)
        .expect("the owner signs its own commitment")
        .to_compact();
    let mut envelope = fixture.envelope;
    set_grant_section(
        &mut envelope,
        encode_grant_section(&section).expect("the section encodes"),
    );
    let cid = blocks.put(encode_envelope(&envelope).expect("the envelope encodes"));

    let name = write_name(ROOT);
    let record = IpnsRecord::create_v2(
        &write_signer(ROOT),
        format!("/ipfs/{cid}").as_bytes(),
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    block_on(device.snapshot_cache.put(name.as_str().as_bytes(), &record))
        .expect("the cache takes the record");
}

/// A produce-side trust refusal is reported the way an arriving record's
/// rejection is — named, on the event stream, on the pass it happens. Left to
/// the dead letter a spent budget raises, it would surface under a reason a
/// network outage also reaches, which is exactly the trust-vs-availability
/// conflation the read side refuses (AGENTS.md rule 6).
#[test]
fn a_refused_root_authoring_names_the_check_that_fired_on_the_pass_it_fired() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);

    cache_a_root_committed_to_another_name(&alice, &blocks);
    create(&mut engine, "photos");
    let _ = events_so_far(&mut events);
    tick(&world, &engine, &mut tasks);

    let abuse: Vec<String> = events_so_far(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::AttributableAbuse { description } => Some(description),
            _ => None,
        })
        .collect();
    assert_eq!(abuse.len(), 1, "one refusal, one report: {abuse:?}");
    assert!(
        abuse[0].contains("commitment-name-mismatch"),
        "the report names the check, not just that something failed: {}",
        abuse[0]
    );
    // The report crosses to a host verbatim, and the refused record's name is a
    // live handle that resolves it. A base36 IPNS name is one long alphanumeric
    // run, which no classification this report carries ever is.
    let longest_run = abuse[0]
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(
        longest_run < 40,
        "the report withholds the ipnsName it refused: {}",
        abuse[0]
    );
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "and it arrives while the op is still being retried, not once its budget is spent"
    );
}

/// The drain's seal nonce is a fresh draw or nothing. A seam reporting success
/// having written nothing would seal every body on the engine's highest-volume
/// plane under one fixed nonce, and two seals under one key at one nonce is a
/// confidentiality break — so the pass halts with the op still queued.
#[test]
fn a_seam_that_draws_a_silent_nonce_publishes_no_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (entropy, silent) = silenceable(42);
    let (mut engine, _events, mut tasks) = boot_with(&world, &blocks, &alice, entropy);

    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("the create queues");
    silent.store(true, Ordering::Relaxed);
    tick(&world, &engine, &mut tasks);

    assert!(
        published_names(&world.record_store, &blocks, ROOT).is_empty(),
        "no record is sealed under a nonce the seam never wrote"
    );
    assert_eq!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .len(),
        1,
        "the op keeps its place for a later draw"
    );
}

/// Every queued op's record is sealed under a fresh HPKE ephemeral scalar. A
/// seam reporting success having written nothing would clamp to one X25519
/// scalar, so every op record would share one AEAD key and one base nonce — on
/// the records carrying each version's only copy of its content key.
#[test]
fn a_seam_that_draws_a_silent_record_ephemeral_queues_no_op() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (entropy, silent) = silenceable(42);
    let (mut engine, _events, _tasks) = boot_with(&world, &blocks, &alice, entropy);

    silent.store(true, Ordering::Relaxed);
    let refused = block_on(engine.command(Command::Rename {
        node: ROOT,
        new_name: "renamed".into(),
    }));

    assert!(
        matches!(&refused, Err(EngineError::Entropy { message }) if message.contains("ephemeral")),
        "a rename seals no record under an ephemeral the seam never wrote: {refused:?}"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "nothing reaches the durable queue"
    );
}

/// A node id is minted from the seam too. Two nodes minted under a silent seam
/// would share one id16, and so one node seed, one read key, and one IPNS
/// keypair — the id is also an AAD field, so their bodies would transplant.
#[test]
fn a_seam_that_draws_a_silent_node_id_creates_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (entropy, silent) = silenceable(42);
    let (mut engine, _events, _tasks) = boot_with(&world, &blocks, &alice, entropy);

    silent.store(true, Ordering::Relaxed);
    let refused = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }));

    assert!(
        matches!(&refused, Err(EngineError::Entropy { message }) if message.contains("node id")),
        "the create refuses rather than minting a predictable id: {refused:?}"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "no node is rendered for a create that never minted an id"
    );
}

/// The `pushChunk` total is cross-checked against the `beginWrite` declaration:
/// a backing file truncated mid-read fails the commit rather than publishing a
/// short version as a success.
#[test]
fn a_truncated_file_fails_the_commit_and_publishes_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    let handle = block_on(engine_a.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "truncated.bin".into(),
        },
        200,
    ))
    .unwrap();
    // The file shrinks: the host feeds 100 of the 200 bytes it promised.
    block_on(engine_a.push_chunk(handle, &(0..100u8).collect::<Vec<_>>())).unwrap();

    assert_eq!(
        block_on(engine_a.commit_write(handle)),
        Err(EngineError::ContentSizeMismatch {
            declared: 200,
            observed: 100
        })
    );
    tick(&world, &engine_a, &mut tasks);

    assert!(
        block_on(engine_a.view()).unwrap().children(ROOT).is_empty(),
        "nothing was journaled, so nothing publishes"
    );
    assert_eq!(
        block_on(alice.staging_store.staged_bytes_total()).unwrap(),
        0,
        "the failed write releases every block it staged"
    );
}

/// A framed version plus its content address.
fn frame_version(plaintext: &[u8]) -> (Vec<SealedChunk>, Vec<u8>, Vec<u8>) {
    let (leaves, root_block, content) = frame(plaintext, [0x3C; 32], 99);
    let root_cid = content.content_cid().to_vec();
    (leaves, root_block, root_cid)
}

/// Put a framed version's blocks into a device's staging store.
fn stage_blocks(device: &FakeDevice, leaves: &[SealedChunk], root_block: &[u8], root_cid: &[u8]) {
    block_on(async {
        for leaf in leaves {
            device
                .staging_store
                .put_staged_bytes(&leaf.cid, &leaf.sealed)
                .await
                .unwrap();
        }
        device
            .staging_store
            .put_staged_bytes(root_cid, root_block)
            .await
            .unwrap();
    });
}

/// A version whose key blob will not open can never be read again, whatever its
/// bytes say. The op dead-letters through the failure valve, which **releases**
/// its blocks: bytes no key opens are not the user's recoverable work.
#[test]
fn a_version_whose_content_key_will_not_open_dead_letters_and_releases_its_blocks() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "notes.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "notes.txt");
    let (file_sequence, _) = published(&world.record_store, file);

    let (leaves, root_block, root_cid) = frame_version(&(0..40u8).collect::<Vec<_>>());
    stage_blocks(&alice, &leaves, &root_block, &root_cid);
    stage(
        &alice,
        &Op::update_content(
            file,
            StagedContent {
                root_cid: root_cid.clone(),
                plaintext_size: 40,
                sealed_content_key: b"not a key blob".to_vec(),
                epoch: EPOCH,
            },
            // The create published no version, so this edit follows none.
            None,
            file_sequence,
            UnixMillis(4_242),
        ),
        Some(&root_block),
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::ContentUnrecoverable,
                ..
            }
        )),
        "the host learns the version is unrecoverable"
    );
    assert_eq!(
        block_on(alice.staging_store.staged_keys()).unwrap(),
        vec![drained_key(), mark_key()],
        "blocks no key opens are released, never held against the budget"
    );
    assert_eq!(
        published(&world.record_store, file).0,
        file_sequence,
        "nothing published"
    );
}

/// A leaf missing from *before* anything uploaded is indistinguishable from one
/// a previous pass already sent — unless progress is recorded. Without the
/// durable mark, an evicted prefix would publish a version whose manifest names
/// blocks nothing holds; with it, the absence is loss and fails closed.
#[test]
fn an_evicted_prefix_of_the_block_set_is_loss_not_progress() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .unwrap();

    // Storage pressure evicts the *first* leaf before the drain ever runs, so
    // nothing has uploaded and no mark exists.
    let version = evict_leaf(&alice, |_| 0);
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::ContentUnrecoverable,
                ..
            }
        )),
        "an unsent prefix is loss, never assumed progress"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "no version publishes over a block nothing holds"
    );
    assert_no_blocks_staged(&alice, &version);
}

/// The drain removes each block on its confirmed upload, so the blocks still
/// staged are always a suffix of the list. A block missing from the middle is
/// loss, not progress: the version can never be assembled, so it fails closed
/// rather than publishing a root whose links do not resolve.
#[test]
fn a_hole_in_the_staged_block_suffix_is_loss_and_fails_closed() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .unwrap();

    // The host loses one block from the middle of the set before the drain runs.
    let version = evict_leaf(&alice, |leaves| leaves / 2);
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::ContentUnrecoverable,
                ..
            }
        )),
        "a hole is loss, never progress"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "no short version publishes"
    );
    assert_no_blocks_staged(&alice, &version);
}

/// The mark is host-local storage, so a torn or bit-rotted one that still
/// parses is reachable. A count above the version's own leaf count is proof of
/// corruption: trusting it would let every absent leaf skip the hole guard and
/// publish a manifest naming blocks nothing holds, so it reads as no progress
/// at all.
#[test]
fn a_corrupt_upload_mark_is_no_progress_rather_than_blanket_coverage() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();

    // A mark under this session's own destinations, naming this very version
    // and claiming more leaves than it has.
    let version = evict_leaf(&alice, |leaves| leaves / 2);
    let (root_cid, _) = staged_version(&alice);
    let mut corrupt = Placement::Hosted.destinations().encode().to_vec();
    corrupt.extend_from_slice(&u32::MAX.to_be_bytes());
    block_on(
        alice
            .staging_store
            .put_staged_bytes(&upload_mark_key(&root_cid), &corrupt),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::ContentUnrecoverable,
                ..
            }
        )),
        "a corrupt mark covers nothing, so the hole is still loss"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "no version publishes over a block nothing holds"
    );
    assert_no_blocks_staged(&alice, &version);
}

/// The version the head queued op carries: its root CID and its leaf CIDs, in
/// file order — the order the drain uploads and releases them in.
fn staged_version(device: &FakeDevice) -> (Vec<u8>, Vec<Vec<u8>>) {
    block_on(async {
        let queued = device.staging_store.queued_ops().await.unwrap();
        let root_cid = record_content_root_cid(&queued[0].1).unwrap().unwrap();
        let root_block = device
            .staging_store
            .staged_bytes(&root_cid)
            .await
            .unwrap()
            .unwrap();
        let leaves = decode_root(&root_block)
            .unwrap()
            .leaf_cids
            .iter()
            .map(|cid| cid.to_vec())
            .collect();
        (root_cid, leaves)
    })
}

/// Remove one of the queued version's leaves, chosen by index from the leaf
/// count, and return every block the version framed.
fn evict_leaf(device: &FakeDevice, index: impl Fn(usize) -> usize) -> Vec<Vec<u8>> {
    let (root_cid, leaves) = staged_version(device);
    block_on(
        device
            .staging_store
            .remove_staged_bytes(&leaves[index(leaves.len())]),
    )
    .unwrap();
    leaves
        .into_iter()
        .chain(core::iter::once(root_cid))
        .collect()
}

/// The one durable upload mark this device holds: the version root its key names
/// and the leaf count it claims. Panics on a second, since every test below
/// writes one version at a time.
fn upload_mark(device: &FakeDevice) -> Option<(Vec<u8>, u32)> {
    let mut marks = block_on(device.staging_store.staged_keys())
        .unwrap()
        .into_iter()
        .filter(|key| key.starts_with(UPLOAD_MARK_PREFIX));
    let key = marks.next()?;
    assert!(marks.next().is_none(), "one version in flight at a time");
    let stored = block_on(device.staging_store.staged_bytes(&key))
        .unwrap()
        .expect("the key was just listed");
    let count = <[u8; 4]>::try_from(&stored[DESTINATIONS_LEN..]).unwrap();
    Some((
        key[UPLOAD_MARK_PREFIX.len()..].to_vec(),
        u32::from_be_bytes(count),
    ))
}

/// A second device that only ever saw the network reads `plaintext` back off
/// the published version — the end-to-end statement that no leaf was lost.
fn assert_round_trips(world: &FakeWorld, blocks: &Blocks, name: &str, plaintext: &[u8]) {
    let bob = world.device(b"alice-second-device");
    serve_http(&bob, blocks, 400);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret()))
        .expect("the second device cold-starts off the published record plane");
    let children = block_on(engine_b.view()).unwrap().children(ROOT);
    let file = children
        .iter()
        .find(|child| child.name == name)
        .expect("the version published");
    assert_eq!(
        block_on(engine_b.read_content(file.id)).expect("the verified read serves it"),
        plaintext,
        "every leaf is on the network and the version assembles from them"
    );
}

/// The per-leaf durable sequence is `upload → mark → release`, and an
/// interruption at the mark must cost the version nothing: those bytes reached
/// the pin store, so the write is recoverable by definition. Every leaf is
/// interrupted in turn, since the window is reachable on any of them.
#[test]
fn an_interrupted_leaf_mark_never_costs_the_version_its_uploaded_bytes() {
    let plaintext: Vec<u8> = (0..200u8).collect();
    let leaves = frame_version(&plaintext).0.len();
    assert!(
        leaves > 2,
        "a multi-leaf version, so the interior interruption points are real"
    );

    for interrupted in 0..leaves {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);

        let alice = world.device(b"alice");
        let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
        // The mark for leaf `interrupted` never lands: the process, or the
        // staging store, died the instant after that leaf uploaded.
        alice
            .staging_store
            .inner()
            .interrupt_staged_write_family_after(UPLOAD_MARK_PREFIX, interrupted as u64);
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &plaintext,
        )
        .expect("the write commits");
        let (root_cid, _) = staged_version(&alice);
        tick(&world, &engine, &mut tasks);

        assert_eq!(
            upload_mark(&alice),
            (interrupted > 0).then_some((root_cid, interrupted as u32)),
            "the pass stopped at exactly the interruption point under test"
        );
        assert!(
            !events_so_far(&mut events)
                .iter()
                .any(|event| matches!(event, Event::DeadLetter { .. })),
            "an interrupted durable sequence is an outage, never an abandonment"
        );
        assert!(
            !block_on(alice.staging_store.queued_ops())
                .unwrap()
                .is_empty(),
            "the op keeps its place at the head of the queue for the next pass"
        );

        // The staging store is back: the next pass must finish the very version
        // whose leaves already uploaded.
        tick(&world, &engine, &mut tasks);

        assert!(
            !events_so_far(&mut events)
                .iter()
                .any(|event| matches!(event, Event::DeadLetter { .. })),
            "the resumed pass reads the residue as progress, not as content loss"
        );
        assert_round_trips(&world, &blocks, "photo.bin", &plaintext);
    }
}

/// The residue that marking first leaves — a leaf both marked and still staged
/// — costs nothing: the next pass re-uploads it, a pinned CID short-circuiting
/// the transfer, and re-removes it.
#[test]
fn a_leaf_left_marked_and_staged_is_re_uploaded_and_released_by_the_next_pass() {
    let plaintext: Vec<u8> = (0..200u8).collect();
    let leaf_count = frame_version(&plaintext).0.len();

    for interrupted in 0..leaf_count {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);

        let alice = world.device(b"alice");
        let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &plaintext,
        )
        .expect("the write commits");
        let (root_cid, leaves) = staged_version(&alice);
        alice
            .staging_store
            .inner()
            .interrupt_staged_removal_after(&leaves[interrupted], 0);
        tick(&world, &engine, &mut tasks);

        assert_eq!(
            upload_mark(&alice),
            Some((root_cid, interrupted as u32 + 1)),
            "the mark covers the leaf whose release was interrupted"
        );
        assert!(
            block_on(alice.staging_store.staged_keys())
                .unwrap()
                .contains(&leaves[interrupted]),
            "that leaf is still staged: marked and present is the residue this ordering leaves"
        );

        tick(&world, &engine, &mut tasks);

        assert!(
            !events_so_far(&mut events)
                .iter()
                .any(|event| matches!(event, Event::DeadLetter { .. })),
            "a marked, still-staged leaf is re-uploaded, never read as loss"
        );
        assert_eq!(
            block_on(alice.staging_store.staged_keys()).unwrap(),
            vec![drained_key(), mark_key()],
            "the retry re-removes it, so the residue holds no staging budget"
        );
        assert_round_trips(&world, &blocks, "photo.bin", &plaintext);
    }
}

/// A release that is *reported done* and never persists is the other half of
/// the same crash: leaf 0 comes back from the dead behind a mark that later
/// leaves already advanced. Re-uploading it must not pull the mark back down
/// over the leaves between — those are released, so an uncovered one reads as
/// loss and the valve destroys the version. That is the interrupted-mark hazard
/// with one extra step, and it is reachable because `packages/client` flushes a
/// staged write but releases with a bare `removeEntry`.
#[test]
fn a_re_uploaded_leaf_never_pulls_the_mark_back_over_leaves_it_covers() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .expect("the write commits");
    let (root_cid, leaves) = staged_version(&alice);
    assert!(
        leaves.len() > 4,
        "enough leaves for the mark to advance past the lost release"
    );

    // Every pass stops at leaf 3, so what it leaves durably behind is what the
    // next pass has to work from.
    let stop_at = block_on(alice.staging_store.staged_bytes(&leaves[3]))
        .unwrap()
        .unwrap();
    blocks.refuse_upload(Box::new(move |block| {
        (block == stop_at).then(unreachable_upload)
    }));
    alice
        .staging_store
        .inner()
        .drop_staged_removal_after(&leaves[0], 0);

    tick(&world, &engine, &mut tasks);

    assert_eq!(
        upload_mark(&alice),
        Some((root_cid.clone(), 3)),
        "three leaves uploaded and marked before the pass stopped"
    );
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&leaves[0]),
        "the lost release left leaf 0 staged behind a mark that already covers it"
    );

    tick(&world, &engine, &mut tasks);

    assert_eq!(
        upload_mark(&alice),
        Some((root_cid, 3)),
        "re-uploading leaf 0 leaves the mark where it stood: it only ever rises"
    );

    blocks.accept_uploads();
    tick(&world, &engine, &mut tasks);

    assert!(
        !events_so_far(&mut events)
            .iter()
            .any(|event| matches!(event, Event::DeadLetter { .. })),
        "leaves 1 and 2 stay covered, so nothing reads their absence as loss"
    );
    assert_round_trips(&world, &blocks, "photo.bin", &plaintext);
}

/// The abandonment released the version: none of its blocks still hold staging
/// budget, which no other assertion in these tests would notice.
fn assert_no_blocks_staged(device: &FakeDevice, version: &[Vec<u8>]) {
    let staged = block_on(device.staging_store.staged_keys()).unwrap();
    for cid in version {
        assert!(
            !staged.contains(cid),
            "an abandoned version holds no staging budget"
        );
    }
}

/// Every upload progress event of one op, in emission order.
fn upload_progress(
    events: &mut EventStream,
    op_id: OpId,
    node: NodeId,
) -> Vec<(OpPhase, Option<BlockProgress>)> {
    events_so_far(events)
        .into_iter()
        .filter_map(|event| match event {
            Event::OpProgress {
                op_id: id,
                node: target,
                phase,
                progress,
                ..
            } => {
                assert_eq!(id, Some(op_id), "progress is keyed on the driving op");
                assert_eq!(target, node, "progress names the node being written");
                Some((phase, progress))
            }
            _ => None,
        })
        .collect()
}

/// The upload half of the progress surface: a host that committed a write is
/// told when its blocks start, how many of them are confirmed, and when the
/// whole version is on the network — all keyed on the op id `commitWrite`
/// returned, so per-file progress needs no node-to-upload guesswork.
#[test]
fn an_upload_reports_its_phases_and_block_counts_keyed_on_its_op_id() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    // Multi-leaf at the CI framing, so there is real progress to count.
    let plaintext: Vec<u8> = (0..200u8).collect();
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "photo.bin");

    let reported = upload_progress(&mut events, op_id, file);
    let total = reported[0]
        .1
        .expect("the opening phase counts blocks")
        .total;
    assert!(
        total > 2,
        "a multi-leaf version, not a degenerate single-block one"
    );
    let expected: Vec<(OpPhase, u32)> = core::iter::once((OpPhase::UploadStarted, 0))
        .chain((1..total).map(|confirmed| (OpPhase::UploadProgress, confirmed)))
        .chain(core::iter::once((OpPhase::UploadCompleted, total)))
        .collect();
    assert_eq!(
        reported
            .into_iter()
            .map(|(phase, count)| (
                phase,
                count.expect("every upload phase counts blocks").confirmed
            ))
            .collect::<Vec<_>>(),
        expected,
        "started, then one report per confirmed leaf, landing on the whole version"
    );
}

/// A pass that stopped partway resumes from its durable mark: the opening
/// report carries the leaves an earlier pass confirmed, and the counts pick up
/// from there rather than replaying a leaf already on the network.
#[test]
fn a_resumed_upload_opens_on_the_leaves_an_earlier_pass_confirmed() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    // Two leaves land, then the pin store goes away: the pass halts holding a
    // durable mark it must not lose.
    let mut sent = 0;
    blocks.refuse_upload(Box::new(move |_| {
        sent += 1;
        (sent > 2).then(unreachable_upload)
    }));
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "photo.bin");
    let first = upload_progress(&mut events, op_id, file);
    let total = first[0].1.expect("the opening phase counts blocks").total;

    blocks.accept_uploads();
    tick(&world, &engine, &mut tasks);

    let resumed = upload_progress(&mut events, op_id, file);
    let (phase, opening) = resumed[0];
    let confirmed = opening.expect("the opening phase counts blocks").confirmed;
    assert_eq!(phase, OpPhase::UploadStarted);
    assert!(
        confirmed > 0 && confirmed < total,
        "the resumed pass opens on real prior progress, not on zero"
    );
    let expected: Vec<(OpPhase, u32)> = core::iter::once((OpPhase::UploadStarted, confirmed))
        .chain((confirmed + 1..total).map(|count| (OpPhase::UploadProgress, count)))
        .chain(core::iter::once((OpPhase::UploadCompleted, total)))
        .collect();
    assert_eq!(
        resumed
            .into_iter()
            .map(|(phase, count)| (
                phase,
                count.expect("every upload phase counts blocks").confirmed
            ))
            .collect::<Vec<_>>(),
        expected,
        "the resumed counts continue upward and never re-report a confirmed leaf"
    );
}

/// A halted upload attempt is reported, but it is not terminal: the op keeps its
/// place at the head of the queue and the next tick retries it. Terminal failure
/// is the dead letter, with its reason.
///
/// Both shapes a stopped attempt takes are covered: a transport that never
/// answered, and an unattributable 413 that is charged against the budget but
/// abandons nothing on one response.
#[test]
fn a_halted_upload_attempt_is_reported_and_leaves_the_op_queued() {
    for refusal in [unreachable_upload(), proxy_413()] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);

        let alice = world.device(b"alice");
        let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
        blocks.refuse_upload(Box::new(move |_| Some(refusal.clone())));
        let op_id = write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &(0..200u8).collect::<Vec<_>>(),
        )
        .expect("the write commits");
        tick(&world, &engine, &mut tasks);

        let emitted = events_so_far(&mut events);
        assert!(
            emitted.iter().any(|event| matches!(
                event,
                Event::OpProgress {
                    op_id: Some(id),
                    phase: OpPhase::UploadFailed,
                    error: Some(_),
                    ..
                } if *id == op_id
            )),
            "the halted attempt reaches the host with a classification"
        );
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, Event::DeadLetter { .. })),
            "one stopped attempt is availability, never a terminal failure"
        );
        assert_eq!(
            block_on(alice.staging_store.queued_ops()).unwrap().len(),
            1,
            "the op keeps its place and its staged bytes"
        );
    }
}

/// A permanently refused upload reports the stopped attempt *and* the dead
/// letter that settles it. The pair is the contract: the phase says the transfer
/// stopped, the dead letter says the op will never publish.
#[test]
fn a_permanently_refused_upload_reports_the_attempt_and_the_dead_letter() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("UPLOAD_TOO_LARGE")))));
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);

    let emitted = events_so_far(&mut events);
    assert!(
        emitted.iter().any(|event| matches!(
            event,
            Event::OpProgress {
                op_id: Some(id),
                phase: OpPhase::UploadFailed,
                ..
            } if *id == op_id
        )),
        "the stopped transfer reaches the host"
    );
    assert!(
        emitted.contains(&Event::DeadLetter {
            op_id,
            reason: DeadLetterReason::PayloadRefused,
        }),
        "and the dead letter says it will never publish"
    );
}

/// A pin store answering 503 every pass has judged *these* bytes, so the attempt
/// budget escalates it to a terminal failure. Uncharged it would hold the
/// strict-FIFO head forever: a row that never settles and never errors.
#[test]
fn a_standing_server_refusal_dead_letters_instead_of_cycling_forever() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_upload(Box::new(|_| Some(pin_store_unavailable())));
    let op_id = write_photo(&mut engine, "photo.bin");

    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert!(
        passes > 1,
        "an unavailable pin store is a charged attempt, not a verdict on sight"
    );
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::AttemptsExhausted,
        }]
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty(),
        "and it has left the queue rather than parking its head"
    );
}

/// An over-quota refusal is a hold, not a failed attempt: the op and its
/// reservation stand until a probe finds room, and the host reads it from the
/// snapshot rather than from a failure it cannot act on.
///
/// The account fills *after* the write is admitted, which is the only way the
/// drain sees a 413 at all now that the command path pre-flights the quota —
/// and exactly why that pre-flight can never be the enforcement.
#[test]
fn an_over_quota_upload_holds_the_op_without_reporting_a_failure() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("QUOTA_EXCEEDED")))));
    blocks.set_quota(1_000, 1_000);
    tick(&world, &engine, &mut tasks);

    let emitted = events_so_far(&mut events);
    assert!(
        emitted.iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::UploadStarted,
                ..
            }
        )),
        "the transfer did start"
    );
    assert!(
        !emitted.iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::UploadFailed,
                ..
            }
        )),
        "a full account is not a failed upload attempt"
    );
    assert_eq!(
        block_on(engine.snapshot(ROOT))
            .expect("a snapshot")
            .blocked
            .expect("the over-quota head is held")
            .op_id,
        op_id,
        "the hold is what the host acts on"
    );
}

/// An op the completion record already covers is restore residue: a data dir
/// whose queue predates its own high-water mark. It leaves the queue without
/// publishing, so a restored backup cannot re-apply mutations the user never
/// asked for again.
#[test]
fn an_op_the_completion_record_already_covers_never_republishes() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);
    let seeded = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root_name.as_str())
        .expect("the account's initial root");

    let alice = world.device(b"alice");
    serve_http(&alice, &blocks, 16);
    // The restored dir's mark says op 1 already drained — the id the create
    // below reclaims from the stale queue.
    block_on(StagingStore::put_staged_bytes(
        &alice.staging_store,
        &drained_key(),
        &1u64.to_be_bytes(),
    ))
    .unwrap();

    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap()
    .op_id();
    assert_eq!(op_id, Some(OpId(1)), "the create reclaims the covered id");

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the residue op leaves the queue"
    );
    assert_eq!(
        world
            .record_store
            .record_at(&world.record_store.endpoints()[0], root_name.as_str()),
        Some(seeded),
        "and nothing was published under the root's name"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "so the folder it would have created never appears"
    );
}

/// The device's durable drained-op completion mark. It lives beside the op
/// queue it names, so a store that loses one loses the other.
async fn drained_mark(device: &FakeDevice) -> Option<u64> {
    StagingStore::staged_bytes(&device.staging_store, &drained_key())
        .await
        .expect("the staging store answers")
        .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("an 8-byte mark")))
}

// ---------------------------------------------------------------------------
// The four remaining op kinds, each to a second device.
// ---------------------------------------------------------------------------

/// The display name lives only in the parent's child ref
/// (`crates/core/src/seal/body.rs`), so a rename is one parent republish and
/// the renamed node's own record never moves.
#[test]
fn a_rename_republishes_only_the_parent_and_a_second_device_resolves_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let node = child_id(&engine, ROOT, "photos");
    let (child_sequence, _) = published(&world.record_store, node);

    block_on(engine.command(Command::Rename {
        node,
        new_name: "pictures".into(),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["pictures"]
    );
    assert_eq!(
        published(&world.record_store, node).0,
        child_sequence,
        "the renamed node's own record never republished"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the rename drained"
    );

    let bob = world.device(b"alice-second-device");
    let (engine_b, _events_b, _tasks_b) = boot(&world, &blocks, &bob, 7);
    let children = block_on(engine_b.view()).unwrap().children(ROOT);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].name, "pictures", "device B resolves the rename");
}

/// A delete drops the parent's ref.
#[test]
fn a_delete_drops_the_parent_ref_and_a_second_device_resolves_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    for name in ["photos", "notes.txt"] {
        block_on(engine.command(Command::Create {
            parent: ROOT,
            name: name.into(),
            kind: NodeKind::File,
        }))
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos"]
    );
    assert!(
        block_on(engine.view()).unwrap().attrs(doomed).is_none(),
        "the deleted node left the rendered view"
    );

    let bob = world.device(b"alice-second-device");
    let (engine_b, _events_b, _tasks_b) = boot(&world, &blocks, &bob, 7);
    let names: Vec<String> = block_on(engine_b.view())
        .unwrap()
        .children(ROOT)
        .into_iter()
        .map(|child| child.name)
        .collect();
    assert_eq!(names, ["photos"], "device B resolves the delete");
}

/// Seed a zero bin retention, so this session's deletes take the hard path —
/// unlink, retire, reclaim — that the narratives below assert
/// (CONTEXT.md "Soft delete").
fn seed_hard_delete(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks) {
    seed_vault_settings(
        world,
        device,
        blocks,
        &VaultSettings {
            bin_retention_days: 0,
            ..VaultSettings::default()
        },
    );
}

/// Whether the delete queued on `device` is soft, read off the durable op
/// journal under the owner's own `enc-subkey` — the way a replay reads it.
fn journaled_delete_to_bin(device: &FakeDevice) -> bool {
    let enc_secret = kdf::enc_subkey(&SECRET);
    let raw = block_on(device.staging_store.queued_ops()).expect("the journal reads");
    decode_queue(&RecordReader::new(&enc_secret), &raw)
        .mine
        .iter()
        .find_map(|(_, op)| match &op.kind {
            OpKind::Delete { to_bin, .. } => Some(*to_bin),
            _ => None,
        })
        .expect("the journal holds a delete")
}

/// The retention the session loaded decides the branch, and the verdict is
/// journaled on the op: a settings save between staging and publish must not
/// change what an already-queued delete does. A zero retention is the owner
/// asking for the delete to destroy the node, so it must journal the hard one.
#[test]
fn the_loaded_bin_retention_decides_the_journaled_delete_branch() {
    for (days, to_bin) in [(0u32, false), (DEFAULT_BIN_RETENTION_DAYS, true)] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);
        let alice = world.device(b"alice");
        seed_vault_settings(
            &world,
            &alice,
            &blocks,
            &VaultSettings {
                bin_retention_days: days,
                ..VaultSettings::default()
            },
        );

        let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
        create(&mut engine, "doomed");
        tick(&world, &engine, &mut tasks);
        let doomed = child_id(&engine, ROOT, "doomed");
        block_on(engine.command(Command::Delete { node: doomed })).expect("the delete stages");

        assert_eq!(
            journaled_delete_to_bin(&alice),
            to_bin,
            "a retention of {days} journals to_bin {to_bin}",
        );
    }
}

/// The owner's bin index, read back off the network the way a second device
/// reads it: no engine state, only the seams and the login secret.
fn load_bin(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks) -> BinIndexLoad {
    serve_http(device, blocks, 8);
    let gateway = GatewayConfig {
        accelerator: Some("https://gw.test".into()),
        public_fallbacks: Vec::new(),
    }
    .into_gateway(SessionBearer::default());
    block_on(load_bin_index(
        &device.record_store,
        &gateway,
        &device.http,
        &device.floors(&SECRET),
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &BinIndexKeys::derive(&SECRET),
    ))
    .load
}

/// The name the account's bin index publishes under.
fn bin_name() -> IpnsName {
    BinIndexKeys::derive(&SECRET).name().clone()
}

/// Start a session against the API and run the tasks it spawned, so the
/// publishes its start made have all landed.
fn start_on_api(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, Vec<BoxedTask>) {
    serve_http(device, blocks, 64);
    let (mut engine, _events) = engine_on_api(device, entropy_seed);
    block_on(engine.start(secret())).expect("the session starts");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    (engine, tasks)
}

/// Provision a first-run vault against the API and run the tasks its start
/// spawned, so the genesis publishes have all landed.
fn provision_first_run(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
) -> (Engine<FakeSeamTypes>, Vec<BoxedTask>) {
    start_on_api(world, blocks, device, 42)
}

/// The record's existence would otherwise say the bin is non-empty, and the
/// register-first step would tell the API both that this account has binned
/// something and when. So the vault publishes the empty index at genesis.
#[test]
fn a_first_run_vault_publishes_its_empty_bin_index_at_genesis() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    let (_engine, _tasks) = provision_first_run(&world, &blocks, &alice);

    assert_eq!(
        sequence_at(&world, &bin_name()),
        1,
        "a vault that has binned nothing still publishes the record",
    );
    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the genesis record resolves off the network");
    };
    assert!(
        index.entries.is_empty(),
        "and the body is the bottom rung: an empty index",
    );
}

/// What the API observes at the first soft delete is a revision of a record it
/// already registered, so the publish times nothing.
#[test]
fn the_first_soft_delete_revises_the_genesis_bin_index_rather_than_minting_one() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    let (mut engine, mut tasks) = provision_first_run(&world, &blocks, &alice);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..40u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        bin_entries(&world, &alice, &blocks),
        vec![doomed.0],
        "the delete binned the node",
    );
    assert_eq!(
        sequence_at(&world, &bin_name()),
        2,
        "and it published the second revision of a record that already existed",
    );
}

/// The genesis publish is derived-idempotent on ADR 0007's terms: the name comes
/// from the login secret alone, so a first run that already ran once finds the
/// record and mints no second one. A publish over it would drop every entry the
/// standing index holds.
#[test]
fn a_repeated_first_run_leaves_the_bin_index_the_last_run_published() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let previous = world.device(b"alice-previous-install");
    serve_http(&previous, &blocks, 8);
    block_on(publish_bin_index(
        &previous.record_store,
        &ApiClient::new(
            previous.http.clone(),
            previous.credential_store.clone(),
            "http://api.test",
        ),
        &previous.floors(&SECRET),
        &previous.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(9),
        &OrphanHeads::default(),
        &BinIndexKeys::derive(&SECRET),
        &BinIndex::new(0),
    ))
    .expect("the previous install published the record");
    let standing = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], bin_name().as_str())
        .expect("a bin index record stands at the name");

    let alice = world.device(b"alice");
    let (_engine, _tasks) = provision_first_run(&world, &blocks, &alice);

    assert_eq!(
        world
            .record_store
            .record_at(&world.record_store.endpoints()[0], bin_name().as_str()),
        Some(standing),
        "the repeated first run published no second record over it",
    );
}

fn standing_bin_record(world: &FakeWorld) -> Option<Vec<u8>> {
    world
        .record_store
        .record_at(&world.record_store.endpoints()[0], bin_name().as_str())
}

/// One genesis attempt that does not land would otherwise leave the account at
/// the disclosure the record exists to close, for good. Every start attempts it,
/// so the record arrives before the first soft delete asks the API for it.
#[test]
fn a_genesis_bin_index_that_did_not_land_is_published_by_a_later_start() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    world.record_store.fail_put_for(bin_name().as_str());
    let (_engine, _tasks) = provision_first_run(&world, &blocks, &alice);
    assert!(
        standing_bin_record(&world).is_none(),
        "the genesis publish did not land",
    );
    world.record_store.heal_put_for(bin_name().as_str());

    // A later start on a device that holds no mark for the name, with nothing
    // soft-deleted and no vault to mint.
    let bob = world.device(b"alice-second-install");
    let (_engine, _tasks) = start_on_api(&world, &blocks, &bob, 43);

    assert_eq!(
        sequence_at(&world, &bin_name()),
        1,
        "the later start published the record the first run owed",
    );
    let BinIndexLoad::Resolved(index) = load_bin(&world, &bob, &blocks) else {
        panic!("the record resolves off the network");
    };
    assert!(
        index.entries.is_empty(),
        "and it is the empty index, published ahead of any soft delete",
    );
}

/// The mark the failed attempt left is a mark like any other: the device cannot
/// tell an attempt that never reached the plane from one that did, so it never
/// publishes an empty index over what another device may hold. The account
/// recovers through the device that holds no mark, above.
#[test]
fn the_device_whose_genesis_publish_minted_a_revision_retries_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    world.record_store.fail_put_for(bin_name().as_str());
    let (_engine, _tasks) = provision_first_run(&world, &blocks, &alice);
    world.record_store.heal_put_for(bin_name().as_str());

    let (_engine, _tasks) = start_on_api(&world, &blocks, &alice, 43);

    assert!(
        standing_bin_record(&world).is_none(),
        "the marked device published nothing on its own retry",
    );
}

/// The gate is the device's own durable marks, which decide what a resolve
/// would: an account that already holds the record spends no publish, and the
/// start pays no network round trip to find that out.
#[test]
fn a_start_that_holds_the_bin_index_spends_no_publish_and_no_resolve() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let alice = world.device(b"alice");
    let (_engine, _tasks) = provision_first_run(&world, &blocks, &alice);
    let standing = standing_bin_record(&world).expect("the genesis publish landed");
    let resolves = world.record_store.get_count(bin_name().as_str());

    // A second session on the device the genesis publish left marked. The tasks
    // it spawns stay unpolled, so what follows is the start's own spend.
    serve_http(&alice, &blocks, 64);
    let (mut engine, _events) = engine_on_api(&alice, 43);
    block_on(engine.start(secret())).expect("the second session starts");

    assert_eq!(
        world.record_store.get_count(bin_name().as_str()),
        resolves,
        "the durable mark answered, so the start resolved nothing",
    );
    assert_eq!(
        standing_bin_record(&world),
        Some(standing.clone()),
        "and it published nothing over the standing record",
    );

    // Then the tasks the start spawned: a resolve or a publish the gate
    // deferred rather than refused would land here.
    let mut tasks = world.scheduler.take_spawned_tasks();
    assert!(!tasks.is_empty(), "the start spawned its loops");
    poll_tasks_until_parked(&mut tasks);
    assert_eq!(
        world.record_store.get_count(bin_name().as_str()),
        resolves,
        "and the session spawned no resolve of the name either",
    );
    assert_eq!(
        standing_bin_record(&world),
        Some(standing),
        "nor any publish over the standing record",
    );

    // The control: a device with no mark of its own does reach the network, so
    // the count above is one this fake actually moves.
    let carol = world.device(b"alice-third-install");
    let (_engine, _tasks) = start_on_api(&world, &blocks, &carol, 44);
    assert!(
        world.record_store.get_count(bin_name().as_str()) > resolves,
        "an unmarked device resolves the name once",
    );
}

/// The soft delete is an unlink and nothing more: the parent stops naming the
/// node, one bin entry records where it came from, and the reclamation the hard
/// path performs — retiring the name, unpinning the content — does not happen,
/// or a restore would have nothing left to restore.
#[test]
fn a_soft_delete_bins_the_node_and_reclaims_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_vault_settings(
        &world,
        &alice,
        &blocks,
        &VaultSettings {
            bin_retention_days: DEFAULT_BIN_RETENTION_DAYS,
            ..VaultSettings::default()
        },
    );
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &plaintext,
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);
    let content: Vec<String> = registration_entries(&alice, &name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the file published a version");
    let (sequence, _) = published(&world.record_store, doomed);
    let mark = retire_targets(&alice).len();

    let authored_at = cipherbox_engine::seams::Scheduler::now(&world.scheduler).0;
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        Vec::<String>::new(),
        "the parent stops naming the node"
    );
    assert!(
        block_on(engine.view()).unwrap().attrs(doomed).is_none(),
        "the binned node left the rendered view"
    );

    // Nothing is reclaimed: the same two observations the hard path makes, in
    // the negative.
    let retired = retired_since(&alice, mark);
    assert!(
        !retired.contains(&name.as_str().to_owned()),
        "the binned node keeps its place in the inventory the republisher walks"
    );
    for cid in &content {
        assert!(
            !retired.contains(cid),
            "the binned version keeps its pins: {cid}"
        );
    }
    assert_eq!(
        published(&world.record_store, doomed).0,
        sequence + 1,
        "the binned node's own record still resolves, re-keyed once"
    );

    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the soft delete published a bin index record");
    };
    assert_eq!(index.entries.len(), 1, "one delete, one entry");
    let entry = &index.entries[0];
    assert_eq!(entry.node_id, doomed.0);
    assert_eq!(entry.kind, CoreNodeKind::File);
    assert_eq!(entry.scope_id, SCOPE);
    // Where a restore puts the node back.
    assert_eq!(entry.origin_parent, ROOT.0);
    assert_eq!(entry.origin_name(), "notes.txt");
    assert_eq!(entry.ipns_name(), name.as_str().as_bytes());
    assert!(
        entry.held_key().is_some(),
        "the entry carries the key the doomed subtree was re-keyed under"
    );
    // The op's own authoring time, not a clock read at publish: the tick above
    // moved the injected clock between the two.
    assert_eq!(entry.deleted_at, authored_at);
    assert!(
        cipherbox_engine::seams::Scheduler::now(&world.scheduler).0 > authored_at,
        "the clock moved after authoring, so the equality above is a real one"
    );
}

/// Whether the record standing at `node`'s write name opens under `key`.
fn opens_under(world: &FakeWorld, blocks: &Blocks, node: NodeId, key: &[u8; 32]) -> bool {
    let (_, head_cid) = published(&world.record_store, node);
    let envelope =
        decode_envelope(&blocks.get(&head_cid).expect("the head block")).expect("decodes");
    open_read_body(&envelope, key).is_ok()
}

/// A vault whose settings name the default retention, so every delete is soft.
fn boot_binning(
    world: &FakeWorld,
    blocks: &Blocks,
    alice: &FakeDevice,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    seed_vault_settings(
        world,
        alice,
        blocks,
        &VaultSettings {
            bin_retention_days: DEFAULT_BIN_RETENTION_DAYS,
            ..VaultSettings::default()
        },
    );
    boot(world, blocks, alice, 42)
}

/// The access cut a soft delete owes (ADR 0010 item 3). Every node of the
/// doomed subtree leaves the scope's derivation before the unlink publishes, so
/// no holder of the scope read seed — a current grantee or a revoked one that
/// key regression hands every older epoch — opens a node the owner has binned.
#[test]
fn a_soft_delete_re_keys_the_whole_doomed_subtree_out_of_the_scope() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "box".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "box");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: doomed,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let leaf = child_id(&engine, doomed, "notes.txt");
    assert!(
        opens_under(&world, &blocks, leaf, &read_key_of(leaf)),
        "the scope read seed opens the subtree while it is linked"
    );

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the soft delete published a bin index record");
    };
    let held = *index.entries[0]
        .held_key()
        .expect("the entry carries the key the subtree re-keyed under");
    for node in [doomed, leaf] {
        assert!(
            !opens_under(&world, &blocks, node, &read_key_of(node)),
            "the scope read seed no longer opens the binned node"
        );
        assert!(
            opens_under(&world, &blocks, node, &read_key_under(&held, node)),
            "and the bin's held key does, so a restore can still read it"
        );
    }
}

/// The one ordering the re-key must not produce (ADR 0010 item 3). A subtree
/// this pass could not re-key stays linked in its parent, so the delete retries
/// whole rather than binning a node the cut never reached.
#[test]
fn a_re_key_that_cannot_publish_leaves_the_node_linked() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    let target = doomed.0;
    blocks.refuse_upload(Box::new(move |block| {
        decode_envelope(block)
            .ok()
            .filter(|envelope| envelope.id == target)
            .map(|_| unreachable_upload())
    }));
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["notes.txt".to_owned()],
        "the unlink waits on the re-key it never landed"
    );
}

/// The owner's capture of a grantee's unlink (ADR 0010 item 5). The poll leg
/// sees a folder stop naming a child this device did not unlink; the owner's
/// engine binds it and re-keys it, so the grantee that removed it stops reading
/// it. A second poll over the same unlink writes no second entry.
#[test]
fn an_unlink_this_device_did_not_author_is_adopted_into_the_bin_once() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "shared".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let shared = child_id(&engine, ROOT, "shared");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: shared,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let leaf = child_id(&engine, shared, "notes.txt");
    block_on(engine.command(Command::SetFocus { node: Some(shared) })).unwrap();

    // A write grantee republishes the folder without the child: a well-formed
    // record under the scope's own material, which is what a grantee authors.
    let body = ReadBody::Folder {
        created_at: 0,
        modified_at: 1,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    plant_record(
        &world.record_store,
        &blocks,
        shared,
        Planted {
            node_id: shared.0,
            scope_id: SCOPE,
            read_key: read_key_of(shared),
            body: &body,
        },
    );
    tick(&world, &engine, &mut tasks);

    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the adoption published a bin index record");
    };
    assert_eq!(index.entries.len(), 1, "one unlink, one entry");
    let entry = &index.entries[0];
    assert_eq!(entry.node_id, leaf.0);
    assert_eq!(entry.origin_parent, shared.0);
    assert_eq!(entry.origin_name(), "notes.txt");
    let held = *entry
        .held_key()
        .expect("adoption re-keys, so the entry carries the key");
    assert!(
        !opens_under(&world, &blocks, leaf, &read_key_of(leaf)),
        "the grantee that unlinked the node stops reading it"
    );
    assert!(opens_under(
        &world,
        &blocks,
        leaf,
        &read_key_under(&held, leaf)
    ));

    tick(&world, &engine, &mut tasks);
    let BinIndexLoad::Resolved(again) = load_bin(&world, &alice, &blocks) else {
        panic!("the bin index still resolves");
    };
    assert_eq!(
        again.entries.len(),
        1,
        "a second poll over one unlink writes one entry, not two"
    );
}

/// A child that leaves one parent but is still named by another moved; it did
/// not depart the tree. Binning it would seal a live node under a key no reader
/// derives, so the capture drops it.
#[test]
fn a_child_another_parent_still_names_is_never_captured() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    for name in ["left", "right"] {
        block_on(engine.command(Command::Create {
            parent: ROOT,
            name: name.into(),
            kind: NodeKind::Folder,
        }))
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);
    let left = child_id(&engine, ROOT, "left");
    let right = child_id(&engine, ROOT, "right");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: left,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let leaf = child_id(&engine, left, "notes.txt");

    // The second parent names it too, so the base carries both links.
    let shared_body = ReadBody::Folder {
        created_at: 0,
        modified_at: 1,
        children: vec![file_ref(leaf.0, "notes.txt")],
        unknown: PreservedFields::new(),
    };
    plant_record(
        &world.record_store,
        &blocks,
        right,
        Planted {
            node_id: right.0,
            scope_id: SCOPE,
            read_key: read_key_of(right),
            body: &shared_body,
        },
    );
    block_on(engine.command(Command::SetFocus { node: Some(right) })).unwrap();
    tick(&world, &engine, &mut tasks);

    // Now the first parent drops it: a move, not an unlink.
    let emptied = ReadBody::Folder {
        created_at: 0,
        modified_at: 2,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    plant_record(
        &world.record_store,
        &blocks,
        left,
        Planted {
            node_id: left.0,
            scope_id: SCOPE,
            read_key: read_key_of(left),
            body: &emptied,
        },
    );
    block_on(engine.command(Command::SetFocus { node: Some(left) })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        matches!(
            load_bin(&world, &alice, &blocks),
            BinIndexLoad::Empty { .. }
        ),
        "a node the tree still names is no capture"
    );
    assert!(
        opens_under(&world, &blocks, leaf, &read_key_of(leaf)),
        "and it still opens for every holder of the scope read seed"
    );
}

/// A capture the merge already dropped from the base outlives the pass that
/// could not settle it. Without that, one refused publish would leave the node
/// with no entry, no re-key, and no route back.
#[test]
fn a_capture_that_cannot_settle_is_adopted_by_a_later_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "shared".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let shared = child_id(&engine, ROOT, "shared");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: shared,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let leaf = child_id(&engine, shared, "notes.txt");
    block_on(engine.command(Command::SetFocus { node: Some(shared) })).unwrap();

    let target = leaf.0;
    blocks.refuse_upload(Box::new(move |block| {
        decode_envelope(block)
            .ok()
            .filter(|envelope| envelope.id == target)
            .map(|_| unreachable_upload())
    }));
    let body = ReadBody::Folder {
        created_at: 0,
        modified_at: 1,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    plant_record(
        &world.record_store,
        &blocks,
        shared,
        Planted {
            node_id: shared.0,
            scope_id: SCOPE,
            read_key: read_key_of(shared),
            body: &body,
        },
    );
    tick(&world, &engine, &mut tasks);
    assert!(
        matches!(
            load_bin(&world, &alice, &blocks),
            BinIndexLoad::Empty { .. }
        ),
        "the re-key did not land, so no entry claims the cut"
    );

    blocks.refuse_upload(Box::new(|_| None));
    tick(&world, &engine, &mut tasks);

    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the later pass published the bin index record");
    };
    assert_eq!(index.entries.len(), 1, "the held capture landed");
    let entry = &index.entries[0];
    assert_eq!(entry.node_id, leaf.0);
    let held = *entry.held_key().expect("the entry carries the key");
    assert!(
        !opens_under(&world, &blocks, leaf, &read_key_of(leaf)),
        "and the cut ran with it"
    );
    assert!(opens_under(
        &world,
        &blocks,
        leaf,
        &read_key_under(&held, leaf)
    ));
}

/// The owner who keeps no bin captures no unlink either. A vault at retention
/// `0` asked for no bin, and an adoption carries no owner command that could
/// overrule that.
#[test]
fn a_vault_at_retention_zero_captures_no_unlink() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_vault_settings(
        &world,
        &alice,
        &blocks,
        &VaultSettings {
            bin_retention_days: 0,
            ..VaultSettings::default()
        },
    );
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "shared".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let shared = child_id(&engine, ROOT, "shared");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: shared,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let leaf = child_id(&engine, shared, "notes.txt");
    block_on(engine.command(Command::SetFocus { node: Some(shared) })).unwrap();

    let body = ReadBody::Folder {
        created_at: 0,
        modified_at: 1,
        children: Vec::new(),
        unknown: PreservedFields::new(),
    };
    plant_record(
        &world.record_store,
        &blocks,
        shared,
        Planted {
            node_id: shared.0,
            scope_id: SCOPE,
            read_key: read_key_of(shared),
            body: &body,
        },
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        matches!(
            load_bin(&world, &alice, &blocks),
            BinIndexLoad::Empty { .. }
        ),
        "the observed unlink wrote no entry"
    );
    assert!(
        opens_under(&world, &blocks, leaf, &read_key_of(leaf)),
        "and nothing re-keyed the node"
    );
}

/// Every entry the owner's bin index currently holds.
fn bin_entries(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks) -> Vec<[u8; 16]> {
    match load_bin(world, device, blocks) {
        BinIndexLoad::Resolved(index) => index.entries.iter().map(|entry| entry.node_id).collect(),
        BinIndexLoad::Empty(_) => Vec::new(),
        BinIndexLoad::Stale { .. } => panic!("the bin index resolved from the network"),
    }
}

/// The key the entry for `node` says its doomed subtree was re-keyed under.
fn binned_held_key(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    node: NodeId,
) -> [u8; 32] {
    let BinIndexLoad::Resolved(index) = load_bin(world, device, blocks) else {
        panic!("the bin index resolved from the network");
    };
    *index
        .entries
        .iter()
        .find(|entry| entry.node_id == node.0)
        .expect("the node is binned")
        .held_key()
        .expect("the entry carries the key the subtree re-keyed under")
}

/// The deletion time the entry for `node` was stamped with.
fn binned_deleted_at(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks, node: NodeId) -> u64 {
    let BinIndexLoad::Resolved(index) = load_bin(world, device, blocks) else {
        panic!("the bin index resolved from the network");
    };
    index
        .entries
        .iter()
        .find(|entry| entry.node_id == node.0)
        .expect("the node is binned")
        .deleted_at
}

/// The default restore: the entry names the folder the node came from, and the
/// node goes back under the name it had there. The re-key runs in reverse, so
/// the destination scope reads it again and the bin-held key stops opening it
/// (ADR 0010 item 4).
#[test]
fn a_restore_with_no_destination_returns_the_node_to_the_folder_its_entry_names() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    let held = binned_held_key(&world, &alice, &blocks, doomed);

    block_on(engine.command(Command::Restore {
        node: doomed,
        into: None,
    }))
    .expect("the restore stages");
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["notes.txt".to_owned()],
        "the folder the entry named holds the node again"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "a restored node leaves the bin"
    );
    assert!(
        opens_under(&world, &blocks, doomed, &read_key_of(doomed)),
        "the destination scope reads the node again"
    );
    assert!(
        !opens_under(&world, &blocks, doomed, &read_key_under(&held, doomed)),
        "and the bin-held key no longer opens it"
    );
}

/// A vault holding `photos/deep.bin`, with `deep.bin` also linked under the
/// root by a second writer — the dual link `Snapshot` models and the delete
/// branch has to decide (blueprint/engine.md "Delete branch").
fn seed_dual_linked_file(
    world: &FakeWorld,
    blocks: &Blocks,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) -> (NodeId, NodeId) {
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(world, engine, tasks);
    let photos = child_id(engine, ROOT, "photos");
    write_file(
        engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "deep.bin".into(),
        },
        &(0..150u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(world, engine, tasks);
    let deep = child_id(engine, photos, "deep.bin");
    concurrent_root_add(&world.record_store, blocks, file_ref(deep.0, "deep.bin"));
    tick(world, engine, tasks);
    assert!(
        block_on(engine.view()).unwrap().attrs(deep).is_some(),
        "the second link is in gate-passing state"
    );
    (photos, deep)
}

/// The soft delete re-keys the node out of the scope, so a link it leaves
/// standing names a record that folder's own readers can no longer open. Every
/// link goes, under one entry.
#[test]
fn a_soft_delete_unlinks_a_dual_linked_node_from_every_folder() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);
    let (photos, deep) = seed_dual_linked_file(&world, &blocks, &mut engine, &mut tasks);

    block_on(engine.command(Command::Delete { node: deep })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["photos".to_owned()],
        "the root stops naming the node it linked second"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        Vec::<String>::new(),
        "and so does the folder the node was created in"
    );
    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the soft delete published a bin index record");
    };
    assert_eq!(index.entries.len(), 1, "two links, one entry");
    assert_eq!(index.entries[0].node_id, deep.0);
    assert!(
        [ROOT.0, photos.0].contains(&index.entries[0].origin_parent),
        "the entry names one of the folders that linked it"
    );
}

/// The entry names one folder, so a restore returns the node to that folder and
/// to no other: the second link was a delete's to remove, never a restore's to
/// put back.
#[test]
fn a_restore_returns_a_dual_linked_node_to_its_origin_parent_alone() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);
    let (photos, deep) = seed_dual_linked_file(&world, &blocks, &mut engine, &mut tasks);

    block_on(engine.command(Command::Delete { node: deep })).unwrap();
    tick(&world, &engine, &mut tasks);
    let BinIndexLoad::Resolved(index) = load_bin(&world, &alice, &blocks) else {
        panic!("the soft delete published a bin index record");
    };
    let origin = NodeId(index.entries[0].origin_parent);

    block_on(engine.command(Command::Restore {
        node: deep,
        into: None,
    }))
    .expect("the restore stages");
    tick(&world, &engine, &mut tasks);

    let other = if origin == ROOT { photos } else { ROOT };
    assert!(
        published_names(&world.record_store, &blocks, origin).contains(&"deep.bin".to_owned()),
        "the folder the entry named holds the node again"
    );
    assert!(
        !published_names(&world.record_store, &blocks, other).contains(&"deep.bin".to_owned()),
        "and the folder the entry did not name still does not"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "a restored node leaves the bin"
    );
}

/// The purge's own unlink proof passes because the delete left no link to find.
/// A delete that had unlinked one parent only would leave the purge refusing
/// for good, and the retention deadline queues it with no owner command.
#[test]
fn a_purge_after_a_dual_link_soft_delete_finds_no_link_to_refuse_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);
    let (_, deep) = seed_dual_linked_file(&world, &blocks, &mut engine, &mut tasks);
    let name = write_name(deep);
    let content: Vec<String> = registration_entries(&alice, &name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the file published a version");

    block_on(engine.command(Command::Delete { node: deep })).unwrap();
    tick(&world, &engine, &mut tasks);
    let mark = retire_targets(&alice).len();

    block_on(engine.command(Command::Purge { node: deep })).expect("the purge stages");
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&name.as_str().to_owned()),
        "the purged node leaves the inventory the republisher walks"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "and the entry goes with it"
    );
}

/// A withheld bin index otherwise stops every queued operation for the account
/// and reports nothing: the head waits, the member sees a stalled queue, and no
/// budget is spent that would ever end it. The hold names the cause and clears
/// when the record resolves.
#[test]
fn a_withheld_bin_index_reports_a_named_hold_that_clears_when_it_resolves() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);
    for name in ["a.txt", "b.txt"] {
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: name.into(),
            },
            &(0..40u8).collect::<Vec<u8>>(),
        )
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);

    // The first delete publishes the record, so this device holds the durable
    // marks that make a later withholding a suppression and not a first run.
    let first = child_id(&engine, ROOT, "a.txt");
    block_on(engine.command(Command::Delete { node: first })).unwrap();
    tick(&world, &engine, &mut tasks);

    let second = child_id(&engine, ROOT, "b.txt");
    let bin_name = bin_name();
    world.record_store.fail_get_for(bin_name.as_str());
    block_on(engine.command(Command::Delete { node: second })).unwrap();
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    let hold = view
        .bin_index_hold
        .expect("a bin index the pass cannot read holds the head");
    assert_eq!(hold.node, second);
    assert_eq!(hold.reason.check(), "suppressed");
    assert!(
        view.dead_letters.is_empty(),
        "a withheld record is not a failed op"
    );
    assert!(
        published_names(&world.record_store, &blocks, ROOT).contains(&"b.txt".to_owned()),
        "and nothing publishes behind the held head"
    );

    world.record_store.heal_get_for(bin_name.as_str());
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    assert!(
        view.bin_index_hold.is_none(),
        "the hold clears when the record resolves"
    );
    assert!(
        !published_names(&world.record_store, &blocks, ROOT).contains(&"b.txt".to_owned()),
        "and the delete lands"
    );
}

/// Soft-delete `count` files from the root in one pass, reporting how many GETs
/// that cost at the bin index name.
fn bin_gets_for_a_pass_deleting(count: usize) -> usize {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);
    let names: Vec<String> = (0..count).map(|i| format!("f{i}.txt")).collect();
    for name in &names {
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: name.clone(),
            },
            &(0..40u8).collect::<Vec<u8>>(),
        )
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);

    let doomed: Vec<NodeId> = names
        .iter()
        .map(|name| child_id(&engine, ROOT, name))
        .collect();
    let bin_name = bin_name();
    let before = world.record_store.get_count(bin_name.as_str());
    for node in doomed {
        block_on(engine.command(Command::Delete { node })).unwrap();
    }
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        bin_entries(&world, &alice, &blocks).len(),
        count,
        "every delete of the pass landed its entry"
    );
    world.record_store.get_count(bin_name.as_str()) - before
}

/// One pass establishes the index once and carries it; only the per-operation
/// publish and its confirm scale with the node count. Deleting a folder of two
/// hundred files would otherwise resolve a record padded to its rung two
/// hundred times over.
#[test]
fn a_bulk_soft_delete_resolves_the_bin_index_once_for_the_whole_pass() {
    let fanout = FakeWorld::new().record_store.endpoints().len();
    let one = bin_gets_for_a_pass_deleting(1);
    let four = bin_gets_for_a_pass_deleting(4);
    assert_eq!(
        four - one,
        3 * fanout,
        "three more deletes cost three more confirms and no further load",
    );
}

/// A rewrite that removes an entry never builds on the copy the pass carried
/// for its soft deletes. It runs after a re-key and several folder publishes,
/// and the index is rewritten whole, so a copy read before those would drop
/// every entry another device added since.
#[test]
fn a_restore_resolves_the_bin_index_rather_than_the_copy_the_pass_carried() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);
    for name in ["a.txt", "b.txt"] {
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: name.into(),
            },
            &(0..40u8).collect::<Vec<u8>>(),
        )
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);
    let restored = child_id(&engine, ROOT, "a.txt");
    let doomed = child_id(&engine, ROOT, "b.txt");
    block_on(engine.command(Command::Delete { node: restored })).unwrap();
    tick(&world, &engine, &mut tasks);

    // One fanout GET per resolve, and one per publish confirm.
    let fanout = world.record_store.endpoints().len();
    let before = world.record_store.get_count(bin_name().as_str());
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    block_on(engine.command(Command::Restore {
        node: restored,
        into: None,
    }))
    .expect("the restore stages");
    tick(&world, &engine, &mut tasks);
    let spent = world.record_store.get_count(bin_name().as_str()) - before;

    assert_eq!(
        bin_entries(&world, &alice, &blocks),
        vec![doomed.0],
        "the pass binned one node and unbinned the other"
    );
    assert_eq!(
        spent,
        bin_gets_for_a_pass_deleting(1) + 3 * fanout,
        "the delete carries one resolve; the restore resolves for its entry \
         read and again for its rewrite, then confirms",
    );
}

/// A restore may name any folder in the vault, and the node lands there rather
/// than at the entry's `originParent`.
#[test]
fn a_restore_into_a_chosen_folder_places_the_node_there_and_drops_its_entry() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    create(&mut engine, "elsewhere");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let elsewhere = child_id(&engine, ROOT, "elsewhere");
    let doomed = child_id(&engine, ROOT, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    block_on(engine.command(Command::Restore {
        node: doomed,
        into: Some(elsewhere),
    }))
    .expect("the restore stages");
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, elsewhere),
        vec!["notes.txt".to_owned()],
        "the chosen folder holds the node"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["elsewhere".to_owned()],
        "and the folder it came from does not"
    );
    assert!(bin_entries(&world, &alice, &blocks).is_empty());
}

/// A destination the vault no longer holds is reported apart from every other
/// refusal, so a host can offer another folder rather than say the restore
/// failed.
#[test]
fn a_restore_whose_destination_is_gone_reports_its_own_outcome() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    create(&mut engine, "box");
    tick(&world, &engine, &mut tasks);
    let folder = child_id(&engine, ROOT, "box");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: folder,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, folder, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    block_on(engine.command(Command::Delete { node: folder })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        matches!(
            block_on(engine.command(Command::Restore {
                node: doomed,
                into: None,
            })),
            Err(EngineError::RestoreTargetGone),
        ),
        "the folder the entry names is gone, and the refusal says so"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "and the refused restore left the entry standing"
    );
}

/// The `/bin` route's read: one row per soft-deleted node, carrying the origin
/// folder a restore defaults to and the deletion time expiry is measured from.
#[test]
fn the_bin_read_names_every_soft_deleted_node_with_its_origin_and_deletion_time() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    let cold = block_on(engine.bin()).expect("a bin with no index reads");
    assert!(cold.entries.is_empty());
    assert_eq!(
        cold.origin,
        SettingsOrigin::Defaults,
        "no index was established, so the emptiness is the fallback and not a read"
    );

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.bin()).expect("the bin reads");
    assert_eq!(view.origin, SettingsOrigin::Resolved);
    assert_eq!(view.entries.len(), 1, "one row per soft-deleted node");
    let row = &view.entries[0];
    assert_eq!(row.node, doomed);
    assert_eq!(row.kind, NodeKind::File);
    assert_eq!(row.origin_parent, ROOT, "a restore defaults to this folder");
    assert_eq!(row.origin_name, "notes.txt");
    assert_eq!(
        row.origin_folder,
        BinOrigin::Root,
        "the vault root carries no name, so it is its own state and not an empty one"
    );
    assert_eq!(
        row.deleted_at,
        binned_deleted_at(&world, &alice, &blocks, doomed),
        "the row carries the injected deletion time expiry is measured from"
    );
    assert!(
        !format!("{row:?}").contains("notes.txt"),
        "a row's Debug must not put a user's file name in a log"
    );
}

/// Two nodes of one name, deleted from two folders, are told apart by the row
/// itself: the origin id a purge routes on is not a thing a member can read, so
/// the row carries the origin folder's own name.
#[test]
fn the_bin_read_names_the_origin_folder_of_two_entries_that_share_a_name() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    for folder in ["left", "right"] {
        create(&mut engine, folder);
    }
    tick(&world, &engine, &mut tasks);
    for folder in ["left", "right"] {
        let parent = child_id(&engine, ROOT, folder);
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent,
                name: "notes.txt".into(),
            },
            &(0..200u8).collect::<Vec<u8>>(),
        )
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);

    for folder in ["left", "right"] {
        let doomed = child_id(&engine, child_id(&engine, ROOT, folder), "notes.txt");
        block_on(engine.command(Command::Delete { node: doomed })).unwrap();
        tick(&world, &engine, &mut tasks);
    }

    let view = block_on(engine.bin()).expect("the bin reads");
    let mut origins: Vec<String> = view
        .entries
        .iter()
        .inspect(|row| assert_eq!(row.origin_name, "notes.txt"))
        .map(|row| match &row.origin_folder {
            BinOrigin::Folder(name) => name.clone(),
            other => panic!("a folder the vault holds must read as itself, not {other:?}"),
        })
        .collect();
    origins.sort();
    assert_eq!(
        origins,
        vec!["left".to_owned(), "right".to_owned()],
        "one name in two folders reads as two rows a member can tell apart"
    );
    assert!(
        !format!("{:?}", view.entries).contains("left"),
        "a row's Debug must not put a folder name in a log"
    );
}

/// An entry whose origin folder is gone still lists, under the state a default
/// restore refuses on rather than a folder name the vault no longer holds.
#[test]
fn the_bin_read_lists_an_entry_whose_origin_folder_is_gone() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    create(&mut engine, "box");
    tick(&world, &engine, &mut tasks);
    let folder = child_id(&engine, ROOT, "box");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: folder,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, folder, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    block_on(engine.command(Command::Delete { node: folder })).unwrap();
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.bin()).expect("the bin reads");
    let orphan = view
        .entries
        .iter()
        .find(|row| row.node == doomed)
        .expect("the entry whose origin folder left still lists");
    assert_eq!(orphan.origin_folder, BinOrigin::Gone);
    assert!(
        matches!(
            block_on(engine.command(Command::Restore {
                node: doomed,
                into: None,
            })),
            Err(EngineError::RestoreTargetGone),
        ),
        "and the row reads gone exactly where the default restore refuses"
    );
    let binned_folder = view
        .entries
        .iter()
        .find(|row| row.node == folder)
        .expect("the folder itself was binned too");
    assert_eq!(
        binned_folder.origin_folder,
        BinOrigin::Root,
        "a folder deleted from the root keeps a destination a restore can reach"
    );
}

/// A replayed bin index is a verdict on bytes the plane served, so the read
/// refuses it. Rendering the cached copy as staleness would let a replay show a
/// bin that is missing whatever the owner deleted since (AGENTS.md rule 6).
#[test]
fn the_bin_read_refuses_a_replayed_index_rather_than_reading_it_as_stale() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    for name in ["first.txt", "second.txt"] {
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: name.into(),
            },
            &(0..200u8).collect::<Vec<u8>>(),
        )
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);

    let bin_keys = BinIndexKeys::derive(&SECRET);
    let bin_name = bin_keys.name();
    let first = child_id(&engine, ROOT, "first.txt");
    block_on(engine.command(Command::Delete { node: first })).unwrap();
    tick(&world, &engine, &mut tasks);
    let endpoint = world.record_store.endpoints()[0].clone();
    let replayed = world
        .record_store
        .record_at(&endpoint, bin_name.as_str())
        .expect("the first delete published a bin index");

    // A second delete moves the index past the record captured above.
    let second = child_id(&engine, ROOT, "second.txt");
    block_on(engine.command(Command::Delete { node: second })).unwrap();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        block_on(engine.bin()).expect("the bin reads").entries.len(),
        2
    );

    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, bin_name.as_str(), replayed.clone());
    }

    assert!(
        matches!(
            block_on(engine.bin()),
            Err(EngineError::TrustViolation { .. })
        ),
        "a replayed index is a verdict, never an empty or a stale bin"
    );
}

/// A purge is the reclamation a soft delete deferred: the node's name leaves the
/// republisher inventory and its pinned bytes leave the account, under the
/// reachability proof the hard delete already runs (ADR 0010 item 7).
#[test]
fn a_purge_charges_the_doomed_roots_and_drops_the_entry() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);
    let content: Vec<String> = registration_entries(&alice, &name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the file published a version");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    let mark = retire_targets(&alice).len();

    block_on(engine.command(Command::Purge { node: doomed })).expect("the purge stages");
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&name.as_str().to_owned()),
        "the purged node leaves the inventory the republisher walks"
    );
    for cid in &content {
        assert!(retired.contains(cid), "the purged version unpins: {cid}");
    }
    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "and the entry goes with it"
    );
}

/// The entry alone never licenses a purge. A soft delete writes the entry, then
/// unlinks, then republishes the parent, so a parent publish that spends its
/// attempt budget leaves an entry standing for a node the user still sees.
#[test]
fn a_purge_refuses_a_node_a_live_parent_still_names() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    // The parent's own republish is what the delete completes at; refusing it
    // leaves the entry the delete already wrote for a node ROOT still names.
    blocks.refuse_upload(Box::new(move |block| {
        decode_envelope(block)
            .ok()
            .filter(|envelope| envelope.id == ROOT.0)
            .map(|_| upload_413(Some("UPLOAD_TOO_LARGE")))
    }));
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "the entry landed ahead of the unlink that never published"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["notes.txt".to_owned()],
        "and the parent still names the node"
    );
    assert!(
        matches!(
            block_on(engine.command(Command::Purge { node: doomed })),
            Err(EngineError::UnsupportedTarget { .. }),
        ),
        "so the purge refuses rather than destroying a node the user still sees"
    );
}

/// Retention is enforced rather than advisory (ADR 0010 item 6). The poll tick
/// compares the journaled `deletedAt` against the injected clock and queues a
/// purge, which is a journaled op like any other.
#[test]
fn an_entry_past_the_retention_is_purged_on_a_poll_tick() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    let mark = retire_targets(&alice).len();
    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "the entry stands while the retention has not elapsed"
    );

    world.scheduler.advance(Duration::from_secs(
        u64::from(DEFAULT_BIN_RETENTION_DAYS) * 24 * 60 * 60,
    ));
    // One pass queues the purge off the expired entry; the next drains it.
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);

    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "the expired entry is purged without an owner command"
    );
    assert!(
        retired_since(&alice, mark).contains(&name.as_str().to_owned()),
        "and the purge reclaims what the soft delete deferred"
    );
}

/// Expiry destroys, so it acts only on a retention this device can show is the
/// owner's. A settings load that carried no member choice takes the documented
/// default, which is right for the delete branch because binning is reversible
/// and wrong here: an owner who set ten years and whose settings record will not
/// resolve must not have a month applied to their bin.
#[test]
fn a_settings_load_with_no_member_choice_expires_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    // No settings record is seeded, so the load falls to the documented
    // defaults and the delete still bins.
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "a defaulted retention still bins, which is the reversible error"
    );

    world.scheduler.advance(Duration::from_secs(
        u64::from(DEFAULT_BIN_RETENTION_DAYS) * 2 * 24 * 60 * 60,
    ));
    for _ in 0..3 {
        tick(&world, &engine, &mut tasks);
    }

    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "and it expires nothing, because no member ever chose it"
    );
}

/// The restore relinks the node and then drops its entry, so a drop that does
/// not land leaves a node that is both linked and binned. The retry has to
/// finish it: an entry left standing for a linked node is the entry a later
/// delete of that node would inherit, already past its retention.
#[test]
fn a_restore_whose_entry_drop_does_not_land_finishes_on_the_retry() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    let bin = BinIndexKeys::derive(&SECRET).name().as_str().to_owned();
    world.record_store.fail_put_for(&bin);
    block_on(engine.command(Command::Restore {
        node: doomed,
        into: None,
    }))
    .expect("the restore stages");
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["notes.txt".to_owned()],
        "the relink landed"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "and the entry did not"
    );

    world.record_store.heal_put_for(&bin);
    tick(&world, &engine, &mut tasks);

    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "the retry drops the entry rather than reading the relink as satisfaction"
    );
}

/// The destination's record can already name the target while the base does
/// not: a folder publish confirms and its own self-adopt fails, which leaves the
/// link on the network and nothing to repaint the base from. A second ref would
/// sign a listing the child-envelope author refuses, and the strict-FIFO head
/// would never move again.
#[test]
fn a_restore_retried_over_a_destination_that_already_names_it_publishes_one_ref() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot_binning(&world, &blocks, &alice);

    create(&mut engine, "box");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let folder = child_id(&engine, ROOT, "box");
    let doomed = child_id(&engine, ROOT, "notes.txt");
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    // The destination publishes, and only its self-adopt fails.
    alice
        .floor_store
        .fail_floor_raises_for(&sequence_floor_label(
            write_name(folder).as_str().as_bytes(),
        ));
    block_on(engine.command(Command::Restore {
        node: doomed,
        into: Some(folder),
    }))
    .expect("the restore stages");
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, folder),
        vec!["notes.txt".to_owned()],
        "the relink landed on the network"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).contains(&doomed.0),
        "and the op did not complete, so the entry stands"
    );

    alice.floor_store.heal_floors();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, folder),
        vec!["notes.txt".to_owned()],
        "the retry replaces the ref it finds rather than adding a second"
    );
    assert!(
        bin_entries(&world, &alice, &blocks).is_empty(),
        "and the retry finishes the op"
    );
}

/// A delete is also the reclamation: the deleted record leaves the republisher
/// inventory and its pinned bytes leave the account, or a vault pays quota for
/// content nothing can reach and a revoked grantee holding the old seed keeps
/// reading it — an unlinked node is in no eager set, so rotation never cuts it.
#[test]
fn a_delete_retires_the_nodes_name_and_reclaims_the_content_it_held() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &plaintext,
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);
    let content: Vec<String> = registration_entries(&alice, &name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the file published a version");
    let mark = retire_targets(&alice).len();

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&name.as_str().to_owned()),
        "the deleted record leaves the inventory the republisher walks"
    );
    for cid in &content {
        assert!(
            retired.contains(cid),
            "every block the deleted version pinned is reclaimed"
        );
    }

    // The registry refcounts a pin per referencing record, so what each batch
    // names decides whose edge goes. Only the content batches own a record.
    let batches = retire_entries(&alice);
    assert_eq!(
        batch_namings(&batches, name.as_str()),
        vec![None],
        "a name retire names no owning record, so every reference to it goes"
    );
    for cid in &content {
        assert_eq!(
            batch_namings(&batches, cid),
            vec![Some(name.as_str().to_owned())],
            "the owed retire drops this record's edge and no other's"
        );
    }
}

/// A folder delete reclaims its own target at once and leaves no parentless
/// node behind, but a descendant's name and pins wait a converged poll tick for
/// the proof (blueprint/engine.md "Retirement").
#[test]
fn a_folder_delete_quarantines_a_descendant_for_a_converged_tick() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "deep.bin".into(),
        },
        &(0..150u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let deep = child_id(&engine, photos, "deep.bin");
    let deep_name = write_name(deep);
    let content: Vec<String> = registration_entries(&alice, &deep_name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the descendant published a version");
    let mark = retire_targets(&alice).len();

    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&write_name(photos).as_str().to_owned()),
        "the delete's own target leaves the inventory the republisher walks"
    );
    assert!(
        !retired.contains(&deep_name.as_str().to_owned()),
        "the descendant's name stays registered through the quarantine"
    );
    for cid in &content {
        assert!(
            !retired.contains(cid),
            "and so do its pins — nothing irreversible fires on the delete's own pass"
        );
    }
    let view = block_on(engine.view()).unwrap();
    assert!(
        view.attrs(deep).is_none(),
        "no descendant is left behind as a parentless node"
    );

    // The tick converges the snapshot, the next pass proves the descendant, and
    // the pass after that spends the debt the proof owed.
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&deep_name.as_str().to_owned()),
        "the proof holds, so the descendant's record leaves the inventory too"
    );
    for cid in &content {
        assert!(
            retired.contains(cid),
            "and every block its version pinned is reclaimed"
        );
    }
}

/// The same bound across a restart. A journal entry is durable and the snapshot
/// is not: a restarted session opens the base empty, so the proof's first half
/// would read no link for any descendant and release on the record half alone.
/// The first pass of that session decides nothing (blueprint/engine.md
/// "Retirement").
#[test]
fn a_restart_holds_a_replayed_quarantine_until_one_of_its_own_polls_converges() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "deep.bin".into(),
        },
        &(0..150u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let deep = child_id(&engine, photos, "deep.bin");
    let deep_name = write_name(deep);
    let content: Vec<String> = registration_entries(&alice, &deep_name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the descendant published a version");

    // The delete journals its quarantine, and the process goes before any pass
    // of that session replays it.
    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    tick(&world, &engine, &mut tasks);
    drop(engine);

    let mark = retire_targets(&alice).len();
    serve_http(&alice, &blocks, 400);
    let (mut engine, _events) = engine_on(&alice, 43);
    block_on(engine.start(secret())).unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        !retired.contains(&deep_name.as_str().to_owned()),
        "the first pass of the restarted session decides no quarantine"
    );
    for cid in &content {
        assert!(
            !retired.contains(cid),
            "so nothing irreversible fires against the base a restart opens"
        );
    }

    // That pass converged the base, so the passes behind it decide as a
    // same-session pass does.
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&deep_name.as_str().to_owned()),
        "the descendant's record leaves the inventory once a poll has converged"
    );
    for cid in &content {
        assert!(
            retired.contains(cid),
            "and every block its version pinned is reclaimed"
        );
    }
}

/// The pending half of the same law: a queued folder delete renders its whole
/// detached subtree gone *before* the drain publishes anything, the way a delete
/// another device published does. A host holds descendant ids as inodes, so one
/// still answering is a path nothing can walk to.
#[test]
fn a_pending_folder_delete_renders_its_detached_subtree_gone() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    block_on(engine.command(Command::Create {
        parent: photos,
        name: "trip".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let trip = child_id(&engine, photos, "trip");
    assert!(
        block_on(engine.view()).unwrap().attrs(trip).is_some(),
        "the descendant is published and rendered"
    );

    // Queued only — no tick, so nothing has published and the overlay is the
    // whole of the divergence.
    block_on(engine.command(Command::Delete { node: photos })).unwrap();

    let view = block_on(engine.view()).unwrap();
    assert!(view.attrs(photos).is_none(), "the delete target is gone");
    assert!(
        view.attrs(trip).is_none(),
        "and so is the subtree the unlink detaches"
    );
}

/// The one ordering this pass must not produce. Everything reclaimable happens
/// after the unlink publishes, so a delete whose record never landed unpins
/// nothing and retires nothing — the parent still names the target, and
/// unpinning content a live record reaches is loss where a charged row is only
/// a leak (blueprint/engine.md "Retirement").
#[test]
fn a_delete_whose_unlink_never_published_reclaims_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let doomed = child_id(&engine, ROOT, "notes.txt");
    let content: Vec<String> = registration_entries(&alice, &write_name(doomed))
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the file published a version");
    let mark = retire_targets(&alice).len();

    // The unlink rides the parent's record, and that record will not publish.
    world.record_store.fail_put_for(write_name(ROOT).as_str());
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["notes.txt"],
        "the parent still names the target"
    );
    assert!(
        retired_since(&alice, mark).is_empty(),
        "nothing is retired or unpinned behind an unlink that never landed"
    );
}

/// A delete enumerates a subtree it cannot prove is reached from here alone —
/// a child ref is wire data, and nothing binds a node to the folder naming it.
/// A node a surviving parent also names is therefore not this delete's to stop
/// paying for: its record has to stay held and re-PUT, or the availability cut
/// lands on live data.
#[test]
fn a_delete_leaves_a_node_the_surviving_parent_still_names() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "deep.bin".into(),
        },
        &(0..150u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let deep = child_id(&engine, photos, "deep.bin");

    // Another writer links the same node under the root as well.
    concurrent_root_add(&world.record_store, &blocks, file_ref(deep.0, "deep.bin"));
    tick(&world, &engine, &mut tasks);
    assert!(
        block_on(engine.view()).unwrap().attrs(deep).is_some(),
        "the second link is in gate-passing state"
    );

    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.view()).unwrap();
    assert!(view.attrs(photos).is_none(), "the delete's own target goes");
    assert!(
        view.attrs(deep).is_some(),
        "a node the root still names survives the reclamation of the folder it also sat under"
    );
}

/// A descendant whose record no pass can establish never decides, so
/// MAX_QUARANTINE_ATTEMPTS drops it unspent: the name stays registered and the
/// content stays pinned.
#[test]
fn a_descendant_no_pass_can_establish_drops_out_of_the_quarantine() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "deep.bin".into(),
        },
        &(0..150u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let deep = child_id(&engine, photos, "deep.bin");
    let deep_name = write_name(deep);
    let content: Vec<String> = registration_entries(&alice, &deep_name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the descendant published a version");
    let mark = retire_targets(&alice).len();

    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    tick(&world, &engine, &mut tasks);

    let journal = doomed_journal_key(&owner_tag(&kdf::enc_subkey(&SECRET)), ROOT, photos);
    assert!(
        block_on(alice.staging_store.staged_bytes(&journal))
            .unwrap()
            .is_some(),
        "the delete journals its quarantine"
    );

    // The descendant's own record goes dark, which is what a rotation past an
    // unlinked node leaves behind.
    world.record_store.fail_get_for(deep_name.as_str());
    block_on(alice.snapshot_cache.remove(deep_name.as_str().as_bytes())).unwrap();
    for _ in 0..MAX_QUARANTINE_ATTEMPTS {
        tick(&world, &engine, &mut tasks);
    }

    assert!(
        block_on(alice.staging_store.staged_bytes(&journal))
            .unwrap()
            .is_none(),
        "the entry leaves rather than spend a proof slot on every pass for good"
    );
    let retired = retired_since(&alice, mark);
    assert!(
        !retired.contains(&deep_name.as_str().to_owned()),
        "an unproven descendant keeps its registration"
    );
    for cid in &content {
        assert!(
            !retired.contains(cid),
            "and every block it pins stays pinned"
        );
    }
}

/// The adversarial half of the same law. A co-writer plants a `ChildRef` naming
/// a node that lives elsewhere, the owner deletes the folder holding it, and the
/// walk enumerates a node it has no business reclaiming. The proof refuses it:
/// the converged snapshot still reaches the node, so neither its name nor its
/// pins are this delete's to spend, and unpinning is the half no retry undoes.
#[test]
fn a_delete_never_reclaims_a_descendant_a_surviving_parent_still_names() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "deep.bin".into(),
        },
        &(0..150u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let deep = child_id(&engine, photos, "deep.bin");
    let deep_name = write_name(deep);
    let content: Vec<String> = registration_entries(&alice, &deep_name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the descendant published a version");

    // The plant: another writer names the same node under the root.
    concurrent_root_add(&world.record_store, &blocks, file_ref(deep.0, "deep.bin"));
    tick(&world, &engine, &mut tasks);
    let mark = retire_targets(&alice).len();

    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    for _ in 0..3 {
        tick(&world, &engine, &mut tasks);
    }

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&write_name(photos).as_str().to_owned()),
        "the delete's own target still reclaims"
    );
    assert!(
        !retired.contains(&deep_name.as_str().to_owned()),
        "a node a surviving parent names keeps its registration"
    );
    for cid in &content {
        assert!(
            !retired.contains(cid),
            "and every block it pins stays pinned"
        );
    }
    assert!(
        block_on(engine.view()).unwrap().attrs(deep).is_some(),
        "the node is still rendered under the parent that survived"
    );
}

/// Two prunes reach a reclaimed subtree: the shortened parent's repaint, and the
/// reclamation's own loop. One invariant binds both — no node survives in the
/// snapshot that no walk reaches, or a host holds a live inode on a path nothing
/// can spell. A diamond is what breaks an order-dependent prune.
#[test]
fn a_reclamation_over_a_diamond_strands_no_child_in_the_snapshot() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    for name in ["left", "right"] {
        block_on(engine.command(Command::Create {
            parent: photos,
            name: name.into(),
            kind: NodeKind::Folder,
        }))
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);
    let left = child_id(&engine, photos, "left");
    let right = child_id(&engine, photos, "right");
    block_on(engine.command(Command::Create {
        parent: left,
        name: "shared".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let shared = child_id(&engine, left, "shared");

    // The second edge of the diamond: `right` names the same node, so both
    // parents of `shared` are inside the subtree the delete dooms.
    concurrent_add(
        &world.record_store,
        &blocks,
        right,
        child_ref(shared.0, "shared", CoreNodeKind::Folder),
    );
    block_on(engine.command(Command::SetFocus { node: Some(right) })).unwrap();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        listed_names(&engine, right),
        ["shared"],
        "both links are in gate-passing state"
    );

    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.view()).unwrap();
    for (node, what) in [
        (photos, "the delete's own target"),
        (left, "the parent the walk reached first"),
        (right, "the parent that held the shared child"),
        (shared, "the child both doomed parents named"),
    ] {
        assert!(view.attrs(node).is_none(), "{what} leaves the snapshot");
    }
}

/// A delete can ack its unlink and still lose the confirm — a crash in the
/// window, or a registry that will not answer. Nothing local survives to
/// re-derive the doomed set from: the parent no longer names the target, so the
/// retry finds nothing to remove and the early return is the end of it. The
/// journal written at unlink-ack is what a later run settles it from.
#[test]
fn a_delete_whose_confirm_never_landed_settles_from_the_journal_after_a_restart() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    serve_http(&alice, &blocks, 400);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);
    let content: Vec<String> = registration_entries(&alice, &name)
        .iter()
        .flat_map(entry_content_cids)
        .collect();
    assert!(!content.is_empty(), "the file published a version");

    // The unlink publishes; every retire behind it is refused.
    blocks.refuse_retire(true);
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);
    assert!(
        published_names(&world.record_store, &blocks, ROOT).is_empty(),
        "the unlink is live"
    );
    drop(engine);

    // Second run: the session-lived retry set went with the process, so the
    // durable journal is the only record of what this delete still owes.
    let mark = retire_targets(&alice).len();
    blocks.refuse_retire(false);
    serve_http(&alice, &blocks, 400);
    let (mut engine, _events) = engine_on(&alice, 43);
    block_on(engine.start(secret())).unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, mark);
    assert!(
        retired.contains(&name.as_str().to_owned()),
        "the doomed name retires on a later pass rather than being lost"
    );
    for cid in &content {
        assert!(
            retired.contains(cid),
            "and the content the delete detached reclaims"
        );
    }

    // Settled means settled: a third pass has nothing left to replay.
    let settled = retire_targets(&alice).len();
    tick(&world, &engine, &mut tasks);
    assert!(
        retired_since(&alice, settled).is_empty(),
        "the journal entry leaves once its reclamation lands"
    );
}

/// The replay budget bounds the registry batches a pass spends, so it may only
/// be charged for entries the pass can actually settle. An entry this build
/// refuses is never removed, and nothing sweeps the journal prefix; charging it
/// a slot would let a full budget's worth of them sit at the head of the sorted
/// listing and starve every real delete behind them on every pass thereafter.
#[test]
fn entries_this_build_refuses_never_starve_the_deletes_sorting_behind_them() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    serve_http(&alice, &blocks, 400);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);

    // The unlink publishes and the retire is refused, so the delete's own debt
    // is left standing in the journal for a later pass to replay.
    blocks.refuse_retire(true);
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    // A whole budget of entries this build's decoder refuses, filed under this
    // owner ahead of the real one: a leading zero id sorts below any the engine
    // mints.
    let owner = owner_tag(&kdf::enc_subkey(&SECRET));
    let real_key = doomed_journal_key(&owner, ROOT, doomed);
    for slot in 0..MAX_JOURNAL_REPLAYS {
        let mut id = [0u8; 16];
        id[15] = u8::try_from(slot).expect("the budget fits a byte");
        let key = doomed_journal_key(&owner, ROOT, NodeId(id));
        assert!(
            key < real_key,
            "the planted entry sorts ahead of the real one"
        );
        block_on(
            alice
                .staging_store
                .put_staged_bytes(&key, b"not a reclamation this build can decode"),
        )
        .expect("the staging store takes the planted entry");
    }

    let mark = retire_targets(&alice).len();
    blocks.refuse_retire(false);
    tick(&world, &engine, &mut tasks);
    assert!(
        retired_since(&alice, mark).contains(&name.as_str().to_owned()),
        "the real delete settles past the refused entries rather than queueing behind them"
    );
}

/// A wall of planted entries exactly one ceiling wide, sorting ahead of a real
/// delete: the first pass reaches no further than the wall, and the next
/// resumes past it and settles the delete
/// ([`MAX_BOOKKEEPING_OPENS`]).
#[test]
fn a_wall_of_planted_journal_keys_costs_a_pass_its_ceiling_and_not_the_delete() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    serve_http(&alice, &blocks, 400);
    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "notes.txt".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let doomed = child_id(&engine, ROOT, "notes.txt");
    let name = write_name(doomed);

    blocks.refuse_retire(true);
    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    // More planted entries than one pass may open, every one of them sorting
    // ahead of the real delete.
    let owner = owner_tag(&kdf::enc_subkey(&SECRET));
    let real_key = doomed_journal_key(&owner, ROOT, doomed);
    for slot in 0..MAX_BOOKKEEPING_OPENS {
        let mut id = [0u8; 16];
        id[14..].copy_from_slice(
            &u16::try_from(slot)
                .expect("the wall fits two bytes")
                .to_be_bytes(),
        );
        let key = doomed_journal_key(&owner, ROOT, NodeId(id));
        assert!(
            key < real_key,
            "the planted entry sorts ahead of the real one"
        );
        block_on(
            alice
                .staging_store
                .put_staged_bytes(&key, b"not a reclamation this build can decode"),
        )
        .expect("the staging store takes the planted entry");
    }

    let mark = retire_targets(&alice).len();
    blocks.refuse_retire(false);
    let settled = || retired_since(&alice, mark).contains(&name.as_str().to_owned());
    tick(&world, &engine, &mut tasks);
    assert!(
        !settled(),
        "the wall is exactly one pass's ceiling, so the first pass reaches no further"
    );
    tick(&world, &engine, &mut tasks);
    assert!(
        settled(),
        "the next pass resumes past the wall and reaches the delete"
    );
}

/// Fail-closed on structure: a descendant folder this pass cannot enumerate
/// hides an unknown subtree, so the delete refuses rather than unlinking above
/// it and stranding records and pins nothing can ever name again. A file that
/// will not open is the other half of the law — it costs only its content debt.
#[test]
fn a_delete_refuses_to_unlink_above_a_folder_it_cannot_enumerate() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    seed_hard_delete(&world, &alice, &blocks);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    block_on(engine.command(Command::Create {
        parent: photos,
        name: "inner".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let inner = child_id(&engine, photos, "inner");
    let mark = retire_targets(&alice).len();

    // A subfolder no source will serve and no cache holds.
    let hidden = write_name(inner);
    world.record_store.fail_get_for(hidden.as_str());
    block_on(alice.snapshot_cache.remove(hidden.as_str().as_bytes())).unwrap();

    block_on(engine.command(Command::Delete { node: photos })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos"],
        "the parent keeps the ref: half a reclamation is not a delete"
    );
    assert!(
        retired_since(&alice, mark).is_empty(),
        "and nothing in the subtree was retired on the way"
    );

    // The refusal is a retry, not an abandonment: the delete lands once the
    // subfolder is readable again.
    world.record_store.heal_get_for(hidden.as_str());
    tick(&world, &engine, &mut tasks);
    assert!(
        published_names(&world.record_store, &blocks, ROOT).is_empty(),
        "the same queued op publishes once the subtree enumerates"
    );
}

/// An intra-scope relink publishes the dest-add before the source-remove, so no
/// window leaves the child absent from both parents.
#[test]
fn a_relink_publishes_the_dest_before_the_source_and_a_second_device_resolves_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    let before = uploaded_node_ids(&alice).len();

    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["a.txt"]
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos"]
    );
    assert_eq!(
        uploaded_node_ids(&alice)[before..],
        [photos.0, ROOT.0],
        "dest-add published before the source-remove"
    );
    assert_eq!(
        block_on(engine.snapshot(photos)).unwrap().children.len(),
        1,
        "the dest folder's own children are projected into the base"
    );

    let bob = world.device(b"alice-second-device");
    let (engine_b, _events_b, _tasks_b) = boot(&world, &blocks, &bob, 7);
    let names: Vec<String> = block_on(engine_b.view())
        .unwrap()
        .children(ROOT)
        .into_iter()
        .map(|child| child.name)
        .collect();
    assert_eq!(names, ["photos"], "device B resolves the source-remove");
}

/// A replacing rename in place: the vacated ref and the moved one land in a
/// **single** destination record, so no observer sees the destination name
/// unresolvable.
#[test]
fn a_replacing_rename_lands_the_vacated_and_moved_refs_in_one_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    for name in ["new.txt", "target.txt"] {
        block_on(engine.command(Command::Create {
            parent: ROOT,
            name: name.into(),
            kind: NodeKind::File,
        }))
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);
    let source = child_id(&engine, ROOT, "new.txt");
    let replaced = child_id(&engine, ROOT, "target.txt");
    let (root_sequence, _) = published(&world.record_store, ROOT);

    block_on(engine.command(Command::Move {
        node: source,
        new_parent: ROOT,
        new_name: "target.txt".into(),
        replacing: Some(replaced),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let children = published_children(&world.record_store, &blocks, ROOT);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].name, "target.txt");
    assert_eq!(
        children[0].id, source.0,
        "the surviving entry is the moved node, not the one it replaced"
    );
    assert_eq!(
        published(&world.record_store, ROOT).0,
        root_sequence + 1,
        "one record carries the whole replace"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the move drained"
    );

    let bob = world.device(b"alice-second-device");
    let (engine_b, _events_b, _tasks_b) = boot(&world, &blocks, &bob, 7);
    let seen = block_on(engine_b.view()).unwrap().children(ROOT);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].id, source, "device B resolves the replace");
}

/// A move across folders keeps the relink's dest-first ordering while the
/// destination's replace rides the same record as the dest-add.
#[test]
fn a_cross_folder_move_that_replaces_publishes_the_dest_before_the_source() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    block_on(engine.command(Command::Create {
        parent: photos,
        name: "a.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let replaced = child_id(&engine, photos, "a.txt");
    let before = uploaded_node_ids(&alice).len();

    block_on(engine.command(Command::Move {
        node: moved,
        new_parent: photos,
        new_name: "a.txt".into(),
        replacing: Some(replaced),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let children = published_children(&world.record_store, &blocks, photos);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].name, "a.txt");
    assert_eq!(children[0].id, moved.0);
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos"]
    );
    assert_eq!(
        uploaded_node_ids(&alice)[before..],
        [photos.0, ROOT.0],
        "dest-add published before the source-remove"
    );
}

/// `updateContent` authors the file's own record and nothing else: its parent
/// holds no size/mtime mirror to republish. The record takes the new version at
/// the head of its list and stamps the op's journaled authoring time.
#[test]
fn an_update_content_republishes_the_files_own_record_and_not_its_parent() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "notes.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "notes.txt");
    let (file_sequence, _) = published(&world.record_store, file);
    let (root_sequence, _) = published(&world.record_store, ROOT);

    let authored_at = cipherbox_engine::seams::Scheduler::now(&world.scheduler).0;
    write_file(&mut engine, version(file), b"v2 bytes").unwrap();
    tick(&world, &engine, &mut tasks);

    let (sequence, head_cid) = published(&world.record_store, file);
    assert_eq!(
        sequence,
        file_sequence + 1,
        "the file's own record advanced"
    );
    assert_eq!(
        published(&world.record_store, ROOT).0,
        root_sequence,
        "a child write never republishes its parent"
    );
    let envelope = decode_envelope(&blocks.get(&head_cid).unwrap()).unwrap();
    let ReadBody::File {
        modified_at,
        versions,
        ..
    } = open_read_body(&envelope, &read_key_of(file)).unwrap()
    else {
        panic!("expected a file body");
    };
    assert_eq!(
        modified_at, authored_at,
        "the journaled authoring time, never a clock read at publish"
    );
    assert_eq!(versions.len(), 1, "the write authored exactly one version");
    assert_eq!(versions[0].size, b"v2 bytes".len() as u64);

    let bob = world.device(b"alice-second-device");
    let (engine_b, _events_b, _tasks_b) = boot(&world, &blocks, &bob, 7);
    assert_eq!(
        block_on(engine_b.view()).unwrap().children(ROOT).len(),
        1,
        "device B resolves a root the child write left alone"
    );
}

// ---------------------------------------------------------------------------
// The reference-ordering law and the dest-add compensation.
// ---------------------------------------------------------------------------

/// The one rule whose violation cannot be retracted: a reference must never
/// outlive its referent. A rename of a node whose create is still queued
/// publishes the child's own record before the parent that names it.
#[test]
fn a_rename_of_a_still_queued_create_publishes_child_before_parent() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap()
    .op_id();
    assert!(op.is_some());
    let node = child_id(&engine, ROOT, "photos");
    // Renamed while the create is still queued: both drain in one pass.
    block_on(engine.command(Command::Rename {
        node,
        new_name: "pictures".into(),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        uploaded_node_ids(&alice),
        [node.0, ROOT.0, ROOT.0],
        "the child's record precedes every parent that names it"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["pictures"]
    );
    // The parent's ref resolves: no reference outlived its referent.
    let child = &published_children(&world.record_store, &blocks, ROOT)[0];
    assert_eq!(child.ipns_name, write_name(node).as_str().as_bytes());
    assert!(
        world
            .record_store
            .record_at(
                &world.record_store.endpoints()[0],
                write_name(node).as_str()
            )
            .is_some(),
        "the name the parent points at resolves"
    );
}

/// A create below the scope root publishes, and its parent folder is authored
/// through the child envelope path rather than the root's.
#[test]
fn a_create_below_the_scope_root_publishes_and_projects() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");

    block_on(engine.command(Command::Create {
        parent: photos,
        name: "2026".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "a deeper create no longer halts the drain"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["2026"]
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos"],
        "a child write stops at the immediate parent"
    );
    let view = block_on(engine.snapshot(photos)).unwrap();
    assert_eq!(view.children.len(), 1);
    assert_eq!(view.children[0].name, "2026");
}

/// The deep create's round trip: a device that never authored it adopts the
/// non-root parent's own record — the only record that carries the depth-2
/// child — through the child gate, on its own cold floors and cache. The
/// assertion sits at the record plane; its facade half is
/// `a_second_device_lists_below_the_scope_root_once_it_focuses_there`.
#[test]
fn a_create_below_the_scope_root_is_adoptable_by_a_second_device() {
    let DeepCreate {
        bob,
        engine_b,
        photos,
        deep,
        ..
    } = deep_create_seen_by_a_second_device();

    let parents = block_on(engine_b.view()).unwrap().children(ROOT);
    assert_eq!(parents.len(), 1, "device B resolves the depth-1 parent");
    assert_eq!(parents[0].id, photos);

    let gateway = GatewayConfig {
        accelerator: Some("https://gw.test".into()),
        public_fallbacks: Vec::new(),
    }
    .into_gateway(SessionBearer::default());
    let adopter = ChildAdopter::new(
        &gateway,
        &bob.http,
        &bob.floor_store,
        SCOPE,
        Zeroizing::new(READ_SCOPE_SEED),
        photos.0,
    );
    let outcome = block_on(resolve(
        &bob.record_store,
        &bob.snapshot_cache,
        &adopter,
        &write_name(photos),
        ResolveMode::CacheFirst,
    ))
    .expect("the parent record resolves")
    .outcome;
    let ResolveOutcome::Adopted(adopted) = outcome else {
        panic!("the parent record passes device B's child gate, got {outcome:?}");
    };
    let ReadBody::Folder { children, .. } = adopted.read_body else {
        panic!("expected a folder body");
    };
    assert_eq!(children.len(), 1, "device B reads the depth-2 create");
    assert_eq!(children[0].name, "2026");
    assert_eq!(
        children[0].id, deep.0,
        "and the same node id device A published it under"
    );
}

/// Device A creates `photos/2026`, then a second device that never authored it
/// cold-boots onto the same network.
struct DeepCreate {
    world: FakeWorld,
    blocks: Blocks,
    /// Device B's own seams: its cold floor store, its own cache and HTTP. Only
    /// the account's scope read seed and the network are shared with device A.
    bob: FakeDevice,
    engine_b: Engine<FakeSeamTypes>,
    events_b: EventStream,
    tasks_b: Vec<BoxedTask>,
    photos: NodeId,
    deep: NodeId,
}

fn deep_create_seen_by_a_second_device() -> DeepCreate {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine_a.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine_a, &mut tasks);
    let photos = child_id(&engine_a, ROOT, "photos");

    block_on(engine_a.command(Command::Create {
        parent: photos,
        name: "2026".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine_a, &mut tasks);
    let deep = child_id(&engine_a, photos, "2026");

    let bob = world.device(b"alice-second-device");
    let (engine_b, events_b, tasks_b) = boot(&world, &blocks, &bob, 7);
    DeepCreate {
        world,
        blocks,
        bob,
        engine_b,
        events_b,
        tasks_b,
        photos,
        deep,
    }
}

/// The names a device's rendered view lists under `folder`, sorted.
fn listed_names(engine: &Engine<FakeSeamTypes>, folder: NodeId) -> Vec<String> {
    let mut names: Vec<String> = block_on(engine.snapshot(folder))
        .expect("a folder view")
        .children
        .into_iter()
        .map(|child| child.name)
        .collect();
    names.sort();
    names
}

/// A record planted under `folder`'s write name. It verifies under that name
/// and its head CID matches, so only the child gate's bindings stand between it
/// and the base snapshot; each field is one binding a test bends away from
/// `folder`'s own.
struct Planted<'a> {
    node_id: [u8; 16],
    scope_id: [u8; 16],
    read_key: [u8; 32],
    body: &'a ReadBody,
}

fn plant_record(
    records: &InMemoryRecordStore,
    blocks: &Blocks,
    folder: NodeId,
    planted: Planted<'_>,
) {
    let head = author_child_envelope(EnvelopeAuthoring {
        node_id: planted.node_id,
        scope_id: planted.scope_id,
        epoch: EPOCH,
        read_key: &planted.read_key,
        nonce: &[0x5A; 24],
        body: planted.body,
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("a well-formed child record");
    publish_next_record(records, blocks, folder, &head);
}

/// A folder body listing one child that exists nowhere else — what a planted
/// record would add if the gate let it through.
fn planted_body() -> ReadBody {
    ReadBody::Folder {
        created_at: 0,
        modified_at: 0,
        children: vec![child_ref([0x9B; 16], "planted", CoreNodeKind::Folder)],
        unknown: PreservedFields::new(),
    }
}

/// The facade half of the deep create's round trip: a device that never
/// authored the subtree sets focus on the depth-1 parent and lists the depth-2
/// child out of its own rendered view — the assertion the record-plane half
/// cannot make.
#[test]
fn a_second_device_lists_below_the_scope_root_once_it_focuses_there() {
    let DeepCreate {
        mut engine_b,
        photos,
        deep,
        ..
    } = deep_create_seen_by_a_second_device();

    assert!(
        listed_names(&engine_b, photos).is_empty(),
        "the vault-pointer leg lifts the root's direct children only"
    );

    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();

    let view = block_on(engine_b.snapshot(photos)).unwrap();
    assert_eq!(view.children.len(), 1, "the focus refresh descended");
    assert_eq!(view.children[0].name, "2026");
    assert_eq!(
        view.children[0].id, deep,
        "and under the node id device A published it with"
    );
}

/// The focus refresh is fail-closed on every binding the child gate holds. Each
/// planted record is strictly newer and otherwise well-formed; only the bent
/// binding stops it, and last-known-good stands through all three.
#[test]
fn a_planted_focus_record_never_renders() {
    let DeepCreate {
        world,
        blocks,
        mut engine_b,
        mut events_b,
        mut tasks_b,
        photos,
        deep,
        ..
    } = deep_create_seen_by_a_second_device();
    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(listed_names(&engine_b, photos), ["2026"]);

    // The tick leg is live: a legitimate concurrent record at the focused name
    // reconciles without any further navigation. Without this the negatives
    // below would pass on a leg that never ran.
    concurrent_add(
        &world.record_store,
        &blocks,
        photos,
        child_ref([0x27; 16], "2027", CoreNodeKind::Folder),
    );
    tick(&world, &engine_b, &mut tasks_b);
    assert_eq!(listed_names(&engine_b, photos), ["2026", "2027"]);

    let held = ["2026", "2027"];
    for (planted, bent) in [
        (
            Planted {
                node_id: deep.0,
                scope_id: SCOPE,
                read_key: read_key_of(deep),
                body: &planted_body(),
            },
            "a record sealed for another node",
        ),
        (
            Planted {
                node_id: photos.0,
                scope_id: [0xF0; 16],
                read_key: read_key_of(photos),
                body: &planted_body(),
            },
            "a record sealed under another scope",
        ),
        (
            Planted {
                node_id: photos.0,
                scope_id: SCOPE,
                read_key: read_key_of(photos),
                body: &ReadBody::File {
                    created_at: 0,
                    modified_at: 0,
                    versions: Vec::new(),
                    unknown: PreservedFields::new(),
                },
            },
            "a record whose sealed body is a file",
        ),
    ] {
        plant_record(&world.record_store, &blocks, photos, planted);
        let _ = events_so_far(&mut events_b);
        tick(&world, &engine_b, &mut tasks_b);
        assert_eq!(
            listed_names(&engine_b, photos),
            held,
            "{bent} never renders; last-known-good is pinned"
        );
        // Fail-closed is not silent: the focus leg surfaces the rejection so a
        // persistent forgery cannot look like an idle folder.
        assert_eq!(
            events_so_far(&mut events_b)
                .into_iter()
                .filter(|event| matches!(event, Event::AttributableAbuse { .. }))
                .count(),
            1,
            "{bent} raises exactly one abuse event"
        );
    }
}

/// Rotate `SCOPE`'s read plane: the vault root republishes at the next read
/// epoch under a freshly minted override seed, carrying the history link a
/// current-seed holder walks backward through (CONTEXT.md "History link"). The
/// write plane stands still, so the root keeps its name and its write epoch.
fn rotate_read_epoch(records: &InMemoryRecordStore, blocks: &Blocks) {
    let owner_identity = owner_identity();
    let owner_verifier = owner_identity.verifying_key();
    let owner_pseudonym = Ed25519Signer::from_seed(OWNER_ROOT_PSEUDONYM_SEED);
    let owner_enc = kdf::enc_subkey(&SECRET);
    let owner_enc_pub = owner_enc.public();
    let name = write_name(ROOT);

    let commitment = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
        cut_epoch: 0,
        entries: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let commitment_sig = sign_grant_set(&owner_identity, &commitment)
        .expect("the owner signs its own grant set")
        .to_compact();
    let section = reseal_scope_root(
        &mut SeededEntropy::new(EPOCH + 1),
        &ScopeRootIdentity {
            v: ENVELOPE_V,
            scope_id: SCOPE,
            ipns_name: name.as_str().as_bytes(),
            owner_enc_pub: &owner_enc_pub,
            owner_enc_secret: None,
            ascent: None,
            owes_ascent_link: false,
            pseudonym_signer: &owner_pseudonym,
        },
        &ResealSeeds {
            override_seed: &ROTATED_READ_SCOPE_SEED,
            read_epoch: EPOCH + 1,
            prev: Some(PrevEpochSeed {
                seed: &READ_SCOPE_SEED,
                epoch: EPOCH,
            }),
            write_scope_seed: &WRITE_SCOPE_SEED,
            write_epoch: EPOCH,
            write_history: WriteHistory::Carried(&[]),
            pointer_read_key: &POINTER_READ_KEY,
        },
        &CommittedSet {
            commitment: &commitment,
            commitment_sig: &commitment_sig,
            grant_ledger: &[],
            direct_child_scope_index: &[],
            revoked_recipients: &[],
        },
        &[],
    )
    .expect("the root re-seals at the next read epoch");

    // A cut re-seals the scope root and nothing else: its children keep the
    // records — and the epoch — they already published under.
    let head = author_scope_root_with_section(
        EnvelopeAuthoring {
            node_id: ROOT.0,
            scope_id: SCOPE,
            epoch: EPOCH + 1,
            read_key: &read_key_under(&ROTATED_READ_SCOPE_SEED, ROOT),
            nonce: &[0x7E; 24],
            body: &ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: published_children(records, blocks, ROOT),
                unknown: PreservedFields::new(),
            },
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        },
        &name,
        &section,
        &owner_verifier,
    )
    .expect("the rotated root authors");
    publish_next_record(records, blocks, ROOT, &head);
}

/// The lazy wave reaches `folder`: republish exactly the children it lists
/// today, re-sealed at the scope's current epoch under the rotation's seed.
fn sweep_folder(records: &InMemoryRecordStore, blocks: &Blocks, folder: NodeId) {
    let head = author_child_envelope(EnvelopeAuthoring {
        node_id: folder.0,
        scope_id: SCOPE,
        epoch: EPOCH + 1,
        read_key: &read_key_under(&ROTATED_READ_SCOPE_SEED, folder),
        nonce: &[0x6D; 24],
        body: &ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: published_children(records, blocks, folder),
            unknown: PreservedFields::new(),
        },
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the sweep authors a valid record");
    publish_next_record(records, blocks, folder, &head);
}

/// Epoch lag is sweep-pending staleness, not abuse (CONTEXT.md "Epoch lag"): a
/// focused folder the lazy wave has not swept yet rejects fail-closed, but the
/// owner's own rotation must not read as an attack on the host's abuse channel.
#[test]
fn an_epoch_lagged_focus_folder_rejects_without_raising_abuse() {
    let DeepCreate {
        world,
        blocks,
        mut engine_b,
        mut events_b,
        mut tasks_b,
        photos,
        ..
    } = deep_create_seen_by_a_second_device();
    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(listed_names(&engine_b, photos), ["2026"]);

    // A real rotation: the root republishes at the next read epoch under a
    // fresh seed, which is what raises this device's read-epoch floor. `photos`
    // is not swept, so its own writer keeps publishing at the old epoch.
    rotate_read_epoch(&world.record_store, &blocks);
    concurrent_add(
        &world.record_store,
        &blocks,
        photos,
        child_ref([0x27; 16], "2027", CoreNodeKind::Folder),
    );
    let _ = events_so_far(&mut events_b);
    tick(&world, &engine_b, &mut tasks_b);

    assert_eq!(
        listed_names(&engine_b, photos),
        ["2026"],
        "last-known-good stays pinned"
    );
    assert!(
        events_so_far(&mut events_b)
            .iter()
            .all(|event| !matches!(event, Event::AttributableAbuse { .. })),
        "an unswept folder is not an attacker"
    );

    // The control: the same children, re-sealed at the current epoch, do
    // render — so the leg above ran and rejected.
    sweep_folder(&world.record_store, &blocks, photos);
    tick(&world, &engine_b, &mut tasks_b);

    assert_eq!(
        listed_names(&engine_b, photos),
        ["2026", "2027"],
        "the wave's re-seal at the current epoch is adopted"
    );
}

/// An unreachable record plane is availability staleness, never data loss: the
/// focused folder keeps rendering the state it last adopted, off the cache.
#[test]
fn an_unreachable_record_plane_leaves_the_focused_folder_rendering() {
    let DeepCreate {
        world,
        mut engine_b,
        mut tasks_b,
        photos,
        ..
    } = deep_create_seen_by_a_second_device();
    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(listed_names(&engine_b, photos), ["2026"]);

    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_endpoint(&endpoint);
    }
    tick(&world, &engine_b, &mut tasks_b);

    assert_eq!(listed_names(&engine_b, photos), ["2026"]);
}

/// Navigation refreshes a folder only past the staleness threshold: a repeat
/// visit renders state already held, and the same navigation past the threshold
/// reconciles (blueprint/engine.md "Sync core").
#[test]
fn navigation_re_resolves_a_folder_only_past_the_staleness_threshold() {
    let DeepCreate {
        world,
        blocks,
        mut engine_b,
        photos,
        ..
    } = deep_create_seen_by_a_second_device();
    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(listed_names(&engine_b, photos), ["2026"]);

    concurrent_add(
        &world.record_store,
        &blocks,
        photos,
        child_ref([0x27; 16], "2027", CoreNodeKind::Folder),
    );

    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(
        listed_names(&engine_b, photos),
        ["2026"],
        "a repeat visit inside the threshold renders what is already held"
    );

    world.scheduler.advance(engine_b.profile().stale_after);
    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(
        listed_names(&engine_b, photos),
        ["2026", "2027"],
        "past the threshold the same navigation reconciles"
    );
}

/// A source-remove that will not publish compensates its own dest-add rather
/// than leaving the child linked under both parents.
#[test]
fn a_source_remove_that_cannot_publish_undoes_its_own_dest_add() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);

    // The root's own head upload is refused, so the source-remove cannot land.
    blocks.refuse_upload(Box::new(|block| {
        (head_of(block) == Some(ROOT.0)).then(unreachable_upload)
    }));
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        published_children(&world.record_store, &blocks, photos).is_empty(),
        "the dest-add was compensated, not left as a dual link"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["a.txt", "photos"],
        "the source kept the child it could not release"
    );
    assert_eq!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .len(),
        1,
        "the halted op stays queued for the next tick"
    );
}

/// The one mutation class whose ack waits on more than the fsync: a relocation
/// the engine cannot prove stays in scope is refused before it is journaled,
/// because an op the caller already heard success for can never be retro-failed
/// (blueprint/desktop.md "Conflicts, dead letters, and rotation"). Before this,
/// the op journaled and dead-lettered a drain pass later.
#[test]
fn a_relocation_the_engine_refuses_spends_no_journal_entry() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (_photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    let before = block_on(StagingStore::queued_ops(&alice.staging_store))
        .unwrap()
        .len();

    let refusal = block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: NodeId([0xee; 16]),
    }))
    .expect_err("a destination the render does not hold is refused");

    assert!(
        matches!(refusal, EngineError::UnknownNode),
        "expected the same verdict every other read gives a missing node, got {refusal:?}"
    );
    assert_eq!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .len(),
        before,
        "a refused relocation spends no journal entry"
    );
}

/// Set up a relink whose source-remove leg is refused with `refusal`, and hand
/// back the op the drain halts on. The dest-add lands and is compensated first,
/// so what the queue sees afterwards is the classification of the source-remove
/// alone.
fn relink_whose_source_remove_is_refused(
    world: &FakeWorld,
    blocks: &Blocks,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut Vec<BoxedTask>,
    refusal: impl Fn() -> SeamResult<HttpResponse> + Send + 'static,
) -> OpId {
    let (photos, moved) = seed_folder_and_file(world, engine, tasks);
    blocks.refuse_upload(Box::new(move |block| {
        (head_of(block) == Some(ROOT.0)).then(&refusal)
    }));
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap()
    .op_id()
    .expect("a relink journals an op")
}

/// An over-quota source-remove is a hold, not an unclassified retry: the op
/// keeps its place and the probe is given the byte figure it must find room for.
#[test]
fn an_over_quota_source_remove_holds_the_op_with_its_needed_bytes() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id =
        relink_whose_source_remove_is_refused(&world, &blocks, &mut engine, &mut tasks, || {
            upload_413(Some("QUOTA_EXCEEDED"))
        });
    tick(&world, &engine, &mut tasks);

    let blocked = block_on(engine.snapshot(ROOT))
        .expect("a snapshot")
        .blocked
        .expect("the over-quota source-remove is held");
    assert_eq!(blocked.op_id, op_id);
    assert!(
        blocked.needed_bytes > 0,
        "the figure the resume probe must find room for survives the leg"
    );
}

/// A permanently refused source-remove dead-letters instead of retrying the
/// same bytes forever.
#[test]
fn a_permanently_refused_source_remove_dead_letters() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id =
        relink_whose_source_remove_is_refused(&world, &blocks, &mut engine, &mut tasks, || {
            upload_413(Some("UPLOAD_TOO_LARGE"))
        });
    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);

    assert_eq!(passes, 1, "the server's own verdict is permanent on sight");
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::PayloadRefused
        }]
    );
}

/// An unattributable refusal on the source-remove is charged against the
/// attempt budget: `Unclassified` would retry free and forever, so the budget
/// that exists to bound exactly this pathology would never trip.
#[test]
fn an_unattributable_source_remove_refusal_spends_the_attempt_budget() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id =
        relink_whose_source_remove_is_refused(&world, &blocks, &mut engine, &mut tasks, || {
            upload_413(None)
        });
    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);

    assert!(
        passes > 1,
        "an unattributable refusal is a charged attempt, not a verdict"
    );
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::AttemptsExhausted
        }]
    );
}

/// The compensation must restore what the dest-add vacated too: a destination
/// left holding neither the moved node nor the one it replaced has lost an
/// entry outright.
#[test]
fn a_compensated_move_restores_the_ref_its_dest_add_replaced() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    block_on(engine.command(Command::Create {
        parent: photos,
        name: "a.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let replaced = child_id(&engine, photos, "a.txt");

    blocks.refuse_upload(Box::new(|block| {
        (head_of(block) == Some(ROOT.0)).then(unreachable_upload)
    }));
    block_on(engine.command(Command::Move {
        node: moved,
        new_parent: photos,
        new_name: "a.txt".into(),
        replacing: Some(replaced),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let children = published_children(&world.record_store, &blocks, photos);
    assert_eq!(children.len(), 1);
    assert_eq!(
        children[0].id, replaced.0,
        "the node the move never replaced is back where it was"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["a.txt", "photos"],
        "the source kept the child it could not release"
    );
    assert_eq!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .len(),
        1,
        "the halted op stays queued for the next tick"
    );
}

/// The compensation's restore is an inverse of **our own** edit, so it may only
/// run while our bytes are still the destination head. A winner that built on
/// the listing our dest-add published must not have the vacated ref re-asserted
/// over it (the versioned compare-and-remove rule, extended to the replace).
#[test]
fn a_compensated_move_does_not_resurrect_a_replaced_ref_over_a_concurrent_winner() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    block_on(engine.command(Command::Create {
        parent: photos,
        name: "a.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let replaced = child_id(&engine, photos, "a.txt");

    let winner = file_ref([0xAA; 16], "winner.txt");
    let records = world.record_store.clone();
    let plane = blocks.clone();
    blocks.refuse_upload(Box::new(move |block| {
        if head_of(block) != Some(ROOT.0) {
            return None;
        }
        // The instant our source-remove fails, another writer advances the dest.
        concurrent_add(&records, &plane, photos, winner.clone());
        Some(unreachable_upload())
    }));
    block_on(engine.command(Command::Move {
        node: moved,
        new_parent: photos,
        new_name: "a.txt".into(),
        replacing: Some(replaced),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["winner.txt"],
        "our dest-add was undone without re-asserting the ref we vacated"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["a.txt", "photos"],
        "the source kept the child it could not release"
    );
}

/// The adversarial interleave at the compensation seam: a concurrent writer
/// lands a strictly-newer dest record between the dest-add and its undo. The
/// versioned compare-and-remove refuses to replay a stale copy over the winner
/// and re-derives the removal onto the record the winner published.
#[test]
fn a_concurrent_dest_writer_is_re_derived_onto_never_clobbered() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);

    let winner = file_ref([0xAA; 16], "winner.txt");
    let records = world.record_store.clone();
    let plane = blocks.clone();
    blocks.refuse_upload(Box::new(move |block| {
        if head_of(block) != Some(ROOT.0) {
            return None;
        }
        // The instant our source-remove fails, another writer advances the dest.
        concurrent_add(&records, &plane, photos, winner.clone());
        Some(unreachable_upload())
    }));
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["winner.txt"],
        "the winner's entry survived and our dest-add was undone"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["a.txt", "photos"],
        "the source kept the child"
    );
}

/// The re-derive guarantee has to hold when the destination is the scope root —
/// the commonest move there is. The root is otherwise read from this device's
/// own cache, which could never show the concurrent writer the compare exists to
/// yield to.
#[test]
fn a_concurrent_writer_at_the_root_dest_is_re_derived_onto_never_clobbered() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    // Park the file inside `photos` so the move back out has the root as dest.
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["a.txt"]
    );

    let winner = file_ref([0xAA; 16], "winner.txt");
    let records = world.record_store.clone();
    let plane = blocks.clone();
    blocks.refuse_upload(Box::new(move |block| {
        if head_of(block) != Some(photos.0) {
            return None;
        }
        concurrent_root_add(&records, &plane, winner.clone());
        Some(unreachable_upload())
    }));
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: ROOT,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos", "winner.txt"],
        "the winner's entry survived and our dest-add was undone"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["a.txt"],
        "the source kept the child it could not release"
    );
}

/// The rebase resolves a move against a destination it has not loaded, so the
/// dest can already name the target — dual-link residue a failed compensation
/// leaves behind. A second ref would sign a listing `author_child_envelope`
/// always rejects, wedging the op on every retry.
#[test]
fn a_dest_that_already_names_the_target_gains_no_second_ref() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    concurrent_add(
        &world.record_store,
        &blocks,
        photos,
        file_ref(moved.0, "a.txt"),
    );

    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_children(&world.record_store, &blocks, photos)
            .iter()
            .filter(|child| child.id == moved.0)
            .count(),
        1,
        "the dest names the moved child exactly once"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos"],
        "the source released the child"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the op drained rather than wedging the queue"
    );
}

/// A move into the subtree it is moving would detach that subtree from the
/// scope root with nothing left to walk it from.
#[test]
fn a_relink_into_its_own_descendant_or_itself_is_refused() {
    for into_itself in [true, false] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);

        let alice = world.device(b"alice");
        let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
        block_on(engine.command(Command::Create {
            parent: ROOT,
            name: "photos".into(),
            kind: NodeKind::Folder,
        }))
        .unwrap();
        tick(&world, &engine, &mut tasks);
        let photos = child_id(&engine, ROOT, "photos");
        block_on(engine.command(Command::Create {
            parent: photos,
            name: "2026".into(),
            kind: NodeKind::Folder,
        }))
        .unwrap();
        tick(&world, &engine, &mut tasks);
        let inner = child_id(&engine, photos, "2026");

        block_on(engine.command(Command::Relink {
            node: photos,
            new_parent: if into_itself { photos } else { inner },
        }))
        .unwrap();
        tick(&world, &engine, &mut tasks);

        assert_eq!(
            published_names(&world.record_store, &blocks, ROOT),
            ["photos"],
            "the subtree stays reachable from the scope root"
        );
        assert_eq!(
            published_names(&world.record_store, &blocks, inner),
            Vec::<String>::new(),
            "no folder ever names its own ancestor"
        );
        assert!(
            block_on(StagingStore::queued_ops(&alice.staging_store))
                .unwrap()
                .is_empty(),
            "the op dead-letters rather than wedging the queue"
        );
    }
}

/// State below the scope root is the drain's own output. A remote root advance
/// must merge into the base, never replace it — a rebuilt base would erase the
/// deeper tree and dead-letter every queued op that rebases onto it.
#[test]
fn a_remote_root_advance_leaves_a_queued_deep_op_publishable() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");
    block_on(engine.command(Command::Create {
        parent: photos,
        name: "2026".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let inner = child_id(&engine, photos, "2026");

    // A depth-2 rename queued, then another device advances the root under us.
    block_on(engine.command(Command::Rename {
        node: inner,
        new_name: "2027".into(),
    }))
    .unwrap();
    concurrent_root_add(
        &world.record_store,
        &blocks,
        file_ref([0xAA; 16], "winner.txt"),
    );
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["2027"],
        "the deep rename published rather than dead-lettering onto a truncated base"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photos", "winner.txt"],
        "and the remote writer's own entry survived"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty()
    );
}

/// A pass now seals many records. Each must draw its own nonce: a reused nonce
/// under one key is a confidentiality break, not a degraded mode.
#[test]
fn every_record_one_pass_seals_carries_a_distinct_nonce() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    block_on(engine.command(Command::Rename {
        node: photos,
        new_name: "pictures".into(),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let nonces: Vec<Vec<u8>> = alice
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/content/upload"))
        .filter_map(|request| decode_envelope(request.body.as_deref()?).ok())
        // `readSealed` is `nonce(24) || ciphertext||tag`.
        .map(|envelope| envelope.read_sealed[..24].to_vec())
        .collect();
    let distinct: std::collections::BTreeSet<Vec<u8>> = nonces.iter().cloned().collect();
    assert!(nonces.len() > 3, "the pass sealed several records");
    assert_eq!(
        distinct.len(),
        nonces.len(),
        "every seal drew a fresh nonce"
    );
}

// ---------------------------------------------------------------------------
// The failure valve: dead-letter classification, the over-quota block, and the
// abandonment retire.
// ---------------------------------------------------------------------------

#[test]
fn an_over_quota_413_holds_the_head_and_a_quota_probe_with_room_resumes_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("QUOTA_EXCEEDED")))));
    blocks.set_quota(1_000, 1_000);
    let held = create(&mut engine, "photos");
    let photos = child_id(&engine, ROOT, "photos");
    // A second mutation behind it: the hold is at the head of a queue that has
    // more in it, not at the end of one.
    create(&mut engine, "notes");
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    let blocked = view.blocked.expect("the over-quota head is held");
    assert_eq!(blocked.op_id, held);
    assert_eq!(blocked.node, photos);
    assert!(
        blocked.needed_bytes > 0,
        "the hold records what the refused upload asked for"
    );
    assert!(
        view.dead_letters.is_empty(),
        "a full account is not a failed op"
    );
    assert!(
        published_names(&world.record_store, &blocks, ROOT).is_empty(),
        "nothing behind the held head published either"
    );
    assert_eq!(
        block_on(alice.staging_store.queued_ops()).unwrap().len(),
        2,
        "both ops keep their place and their staging reservation"
    );

    // Still full on the next tick: the hold stands, and the payload is never
    // re-offered — the probe is the only thing that can clear it.
    let before = uploads(&alice);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        uploads(&alice),
        before,
        "a held head re-probes the quota, never the upload"
    );
    assert!(block_on(engine.snapshot(ROOT)).unwrap().blocked.is_some());

    // Room appears.
    blocks.accept_uploads();
    blocks.set_quota(1_000, 1_000_000);
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    assert!(view.blocked.is_none(), "the probe cleared the hold");
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["notes".to_owned(), "photos".to_owned()],
        "the whole queue drained once the head was free"
    );
}

#[test]
fn an_over_cap_413_is_permanent_and_its_reason_reaches_the_host() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);

    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("UPLOAD_TOO_LARGE")))));
    let op_id = create(&mut engine, "photos");
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    assert!(
        view.blocked.is_none(),
        "the transport cap is not the account-quota gate"
    );
    assert_eq!(
        view.dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::PayloadRefused
        }],
        "the reason is on the read surface, not just the event"
    );
    assert!(
        events_so_far(&mut events).contains(&Event::DeadLetter {
            op_id,
            reason: DeadLetterReason::PayloadRefused
        }),
        "the dead letter reaches the host with its reason"
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty(),
        "a permanently refused op does not wedge the queue"
    );
}

/// A 413 the API did not stamp did not come from a gate that inspected these
/// bytes — a proxy body cap answers exactly that — so it is evidence for
/// neither verdict and must not abandon the op on one response.
#[test]
fn a_413_the_api_did_not_stamp_neither_blocks_nor_abandons_the_op() {
    for refusal in [upload_413(None), proxy_413()] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);
        let alice = world.device(b"alice");
        let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

        blocks.refuse_upload(Box::new(move |_| Some(refusal.clone())));
        create(&mut engine, "photos");
        tick(&world, &engine, &mut tasks);

        let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
        assert!(
            view.blocked.is_none(),
            "no positive quota evidence, no hold"
        );
        assert!(
            view.dead_letters.is_empty(),
            "one unattributable response must not destroy queued work"
        );
        assert_eq!(
            block_on(alice.staging_store.queued_ops()).unwrap().len(),
            1,
            "the op keeps its place and is retried"
        );
        assert!(retire_targets(&alice).is_empty());
    }
}

#[test]
fn a_publish_that_never_confirms_dead_letters_once_its_attempt_budget_runs_out() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id = create(&mut engine, "photos");
    jam_name(&world.record_store, child_id(&engine, ROOT, "photos"));

    // The budget is spent one non-confirming publish per pass: finite, but more
    // than one — a single lost race is a retry, not an abandonment.
    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert!(
        passes > 1,
        "one non-confirming publish is a retry, not an abandonment"
    );
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::AttemptsExhausted
        }]
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "an unconfirmed publish is never retired out from under itself"
    );
}

#[test]
fn an_abandoned_create_retires_the_child_name_it_registered_exactly_once() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("UPLOAD_TOO_LARGE")))));
    create(&mut engine, "photos");
    let photos = child_id(&engine, ROOT, "photos");
    tick(&world, &engine, &mut tasks);

    let retired = retire_targets(&alice);
    assert_eq!(
        retired,
        vec![write_name(photos).as_str().to_owned()],
        "an abandoned create's child name leaves the republish inventory with it"
    );

    tick(&world, &engine, &mut tasks);
    assert_eq!(
        retire_targets(&alice),
        retired,
        "the abandonment ran once; later passes retire nothing again"
    );
}

/// An abandoned `updateContent` uploaded a version no record will ever link —
/// its file still publishes the versions it had — so every block it uploaded
/// leaves the republish inventory with the op while the file's own name stays
/// live. Each upload creates its own charged pin row, so a leaf the root
/// retirement misses spends account quota forever.
#[test]
fn an_abandoned_version_retires_every_block_it_uploaded_and_keeps_the_files_name() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (engine, mut tasks, version) = stage_a_second_version(&world, &blocks, &alice);

    refuse_uploads_from(&blocks, MID_SET_UPLOAD, || {
        upload_413(Some("UPLOAD_TOO_LARGE"))
    });
    tick(&world, &engine, &mut tasks);

    let landed = version
        .iter()
        .filter(|cid| blocks.get(cid).is_some())
        .count();
    assert!(
        (1..version.len()).contains(&landed),
        "the halt came mid-set: some of the version is charged, not all of it"
    );
    assert_eq!(
        retire_targets(&alice),
        version,
        "every uploaded block leaves the inventory; the file's own name does not"
    );
}

/// A dead letter keeps its staged content by definition (CONTEXT.md), and a
/// spent budget is a dead letter: the version stays whole where a permanent
/// refusal erases it. An `updateContent`'s file already has a live name, so
/// nothing at all is owed back.
#[test]
fn a_version_whose_upload_budget_runs_out_keeps_the_bytes_it_already_charged() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (engine, mut tasks, _) = stage_a_second_version(&world, &blocks, &alice);
    let (root_cid, _) = staged_version(&alice);

    // An unattributable 413 is charged, never abandoned on one response, so the
    // set stalls with rows already charged until the budget runs out.
    refuse_uploads_from(&blocks, MID_SET_UPLOAD, proxy_413);
    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine, &mut tasks);

    assert_eq!(
        dead_letters
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted]
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "the blocks the halted set already charged are the version's own, and it keeps them"
    );
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&root_cid),
        "the manifest every retry re-derives its plan from stays staged"
    );
}

/// Preserving the version is only real if it outlives the op record, which a
/// cold start drops and a GC pass then sweeps behind. A create is the arm that
/// still owes something back: the name it derived, which no published record
/// ever came to reference.
#[test]
fn a_spent_budget_keeps_its_version_across_the_cold_start_that_drops_its_op() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let photo = child_id(&engine, ROOT, "photo.bin");
    let (root_cid, _) = staged_version(&alice);

    refuse_uploads_from(&blocks, MID_SET_UPLOAD, proxy_413);
    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::AttemptsExhausted
        }]
    );
    assert_eq!(
        retire_targets(&alice),
        vec![write_name(photo).as_str().to_owned()],
        "the name is owed back; not one block the halted set charged is"
    );
    drop(engine);

    let (engine, _events, mut tasks) = boot(&world, &blocks, &alice, 43);
    tick(&world, &engine, &mut tasks);
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&root_cid),
        "the preserved dead letter keeps its version across the cold start and its GC pass"
    );
}

/// The opposite arm: an acked PUT may already be resolvable at the name, so
/// exhausting the budget there retires nothing. Unpinning content a live record
/// still names is loss, where leaving the rows charged is only a leak.
#[test]
fn an_unconfirmed_publish_never_retires_the_version_it_may_already_name() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let target = WriteTarget::NewFile {
        parent: ROOT,
        name: "photo.bin".into(),
    };
    write_file(&mut engine, target, &(0..200u8).collect::<Vec<_>>()).unwrap();
    jam_name(&world.record_store, child_id(&engine, ROOT, "photo.bin"));

    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert_eq!(
        dead_letters
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted]
    );
    assert!(
        uploads(&alice) > 0,
        "the version uploaded before the publish burned its budget"
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "an acked PUT may be live at the name, so its blocks are not ours to unpin"
    );
}

/// The staging key the preserved dead-letter set lives under. A durable-format
/// fact of the store, so it is spelled out here rather than reached for through
/// an engine internal.
const PRESERVED_DEAD_LETTERS: &[u8] = b"cipherbox/preserved-dead-letters";

/// A preserved set this build cannot read is never overwritten — it holds dead
/// letters whose records carry the only copy of their content keys. That refusal
/// is terminal rather than a retry: returning the op to a strict-FIFO head would
/// freeze the whole queue behind bytes nothing will ever explain, and say nothing
/// on the event stream while it did.
#[test]
fn a_dead_letter_no_preserved_set_will_hold_still_reaches_the_host() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let planted = b"not a preserved record".to_vec();
    block_on(
        alice
            .staging_store
            .put_staged_bytes(PRESERVED_DEAD_LETTERS, &planted),
    )
    .expect("the foreign set stages");

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let version = queued_version(&alice, op_id);
    jam_name(&world.record_store, child_id(&engine, ROOT, "photo.bin"));

    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    let refused = DeadLetter {
        op_id,
        reason: DeadLetterReason::PreservationRefused,
    };
    assert_eq!(dead_letters, vec![refused]);
    assert!(
        events_so_far(&mut events).contains(&Event::DeadLetter {
            op_id: refused.op_id,
            reason: refused.reason
        }),
        "the abandonment the refusal decided reaches the host, not only the read surface"
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty(),
        "and the FIFO head it was holding is free"
    );
    assert_eq!(
        block_on(alice.staging_store.staged_bytes(PRESERVED_DEAD_LETTERS)).unwrap(),
        Some(planted),
        "the dead letters the foreign set already holds are left byte for byte"
    );
    // Nothing kept the record, so nothing can open these again — and the same
    // unreadable set stands orphan GC down, which would leave them staged for
    // as long as it is there.
    let staged = block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(!version.is_empty(), "the version had blocks to lose");
    for block in version {
        assert!(
            !staged.contains(&block),
            "a version whose only key carrier left is released, not leaked"
        );
    }
}

/// A refusal releases the version no preserved set will hold — but only once the
/// abandonment has retired what that version registered. The leaf CIDs are read
/// off the staged root manifest, so releasing first would leave every leaf row
/// charged against the account with no record left that could ever name them.
#[test]
fn a_refused_dead_letter_retires_its_blocks_before_it_releases_them() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    block_on(
        alice
            .staging_store
            .put_staged_bytes(PRESERVED_DEAD_LETTERS, b"not a preserved record"),
    )
    .expect("the foreign set stages");

    // A version of a node no gate-passing state holds: terminally unrebasable,
    // so the abandonment goes through the retire that reads the manifest.
    let (leaves, root_block, root_cid) = frame_version(&(0..40u8).collect::<Vec<_>>());
    stage_blocks(&alice, &leaves, &root_block, &root_cid);
    stage(
        &alice,
        &Op::update_content(
            NodeId([0xAB; 16]),
            StagedContent {
                root_cid: root_cid.clone(),
                plaintext_size: 40,
                sealed_content_key: b"never opened".to_vec(),
                epoch: EPOCH,
            },
            None,
            1,
            UnixMillis(4_242),
        ),
        Some(&root_block),
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::PreservationRefused,
                ..
            }
        )),
        "the refusal is what decided this abandonment"
    );
    let mut expected: Vec<String> = leaves
        .iter()
        .map(|leaf| encode_content_cid_str(&leaf.cid))
        .chain([encode_content_cid_str(&root_cid)])
        .collect();
    expected.sort();
    let mut retired = retire_targets(&alice);
    retired.sort();
    retired.dedup();
    assert_eq!(
        retired, expected,
        "every block the version registered is handed back, root and leaves alike"
    );
    let staged = block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(
        leaves.iter().all(|leaf| !staged.contains(&leaf.cid)) && !staged.contains(&root_cid),
        "and only then are they released"
    );
}

/// Register-first stops a publish only after its head block has uploaded and
/// charged its own pin row, and each attempt re-authors under a fresh seal
/// nonce — so a retrying op orphans a byte-different head every pass. Each
/// leaves the inventory on the pass that orphaned it, and the abandonment still
/// owes back the name on top. The refusal is an intermediary's `400`, so it is
/// charged rather than permanent and the op survives to retry.
#[test]
fn every_head_block_a_retrying_op_orphaned_leaves_the_inventory() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    create(&mut engine, "photos");
    let photos = child_id(&engine, ROOT, "photos");
    blocks.refuse_register(proxy_400());
    let mut heads = Vec::new();
    for attempt in 1..=3 {
        tick(&world, &engine, &mut tasks);
        heads = uploaded_cids(&alice);
        assert_eq!(heads.len(), attempt, "one head block per attempt");
        assert_eq!(
            retire_targets(&alice),
            heads,
            "an orphaned head leaves the inventory on its own pass, not on a retry that \
             re-authors"
        );
    }
    assert_eq!(
        heads
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        heads.len(),
        "every attempt authored its own head under a fresh nonce"
    );

    // The op kept its place; a permanent refusal now abandons it.
    blocks.accept_registrations();
    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("UPLOAD_TOO_LARGE")))));
    tick(&world, &engine, &mut tasks);

    let mut expected = heads;
    expected.push(write_name(photos).as_str().to_owned());
    assert_eq!(
        retire_targets(&alice),
        expected,
        "the abandonment owes back the name on top of every head the retries charged"
    );
}

/// A PUT fan-out that acknowledges nothing is not proof that nothing stored:
/// an endpoint may hold the record and have lost its ack. Retiring that head
/// would unpin the block a record still resolvable at the name points at —
/// loss, where leaving the row charged is only a leak.
#[test]
fn a_publish_that_reached_the_transport_never_retires_its_head() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    create(&mut engine, "photos");
    for endpoint in world.record_store.endpoints() {
        world.record_store.fail_put_endpoint(&endpoint);
    }
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        uploads(&alice),
        1,
        "the head block went up before the fan-out refused it"
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "a head the record plane may already hold is not ours to unpin"
    );
}

// ---------------------------------------------------------------------------
// Cancel, and the staged-byte lifetime around it.
// ---------------------------------------------------------------------------

/// The version an op has staged: its root first, then every leaf in file order.
fn queued_version(device: &FakeDevice, op_id: OpId) -> Vec<Vec<u8>> {
    block_on(async {
        let queued = device.staging_store.queued_ops().await.unwrap();
        let record = &queued
            .iter()
            .find(|(id, _)| *id == op_id)
            .expect("the op is queued")
            .1;
        let root_cid = record_content_root_cid(record).unwrap().unwrap();
        let root_block = device
            .staging_store
            .staged_bytes(&root_cid)
            .await
            .unwrap()
            .unwrap();
        let leaves = decode_root(&root_block).unwrap().leaf_cids;
        core::iter::once(root_cid)
            .chain(leaves.iter().map(|cid| cid.to_vec()))
            .collect()
    })
}

/// The focus window's folder refresh runs before the drain each pass and merges
/// a folder's *published* children into the base. A cancelled upload was never
/// published, so the refresh cannot carry it back into the folder the user is
/// looking at.
#[test]
fn a_focus_refresh_never_renders_back_an_upload_the_user_cancelled() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    // Authored on one device and resolved on another, so the focusing device
    // knows the folder's own name and its refresh really descends into it.
    let author = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks_a) = boot(&world, &blocks, &author, 42);
    block_on(engine_a.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    tick(&world, &engine_a, &mut tasks_a);
    let photos = child_id(&engine_a, ROOT, "photos");

    let alice = world.device(b"alice-second-device");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 7);
    block_on(engine.command(Command::SetFocus { node: Some(photos) })).unwrap();

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: photos,
            name: "holiday.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        listed_names(&engine, photos),
        vec!["holiday.bin".to_owned()]
    );
    let version = queued_version(&alice, op_id);

    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_tasks_once(&mut tasks);
    }
    assert!(uploads(&alice) > 0, "the cancel lands mid-transfer");
    block_on(engine.command(Command::CancelUpload { op_id })).unwrap();
    // Finish the pass the cancel interrupted: drain, then sweep.
    tick(&world, &engine, &mut tasks);

    // Another writer's child, discoverable only by the focus refresh — without
    // it this test could pass with the refresh never running at all.
    concurrent_add(
        &world.record_store,
        &blocks,
        photos,
        file_ref([0xC1; 16], "from-elsewhere.bin"),
    );
    // The next pass refreshes the focused folder before its drain, which is the
    // ordering the overlap turns on.
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        listed_names(&engine, photos),
        vec!["from-elsewhere.bin".to_owned()],
        "the refresh merged what published and left the cancelled upload gone"
    );
    assert!(
        published_names(&world.record_store, &blocks, photos)
            .iter()
            .all(|name| name != "holiday.bin"),
        "the cancelled version never reaches the record plane"
    );
    assert_no_blocks_staged(&alice, &version);
}

/// The acceptance case: a cancel that lands while the drain is mid-upload stops
/// it at the next block boundary, releases every block of the version, retires
/// what already reached the network, and publishes nothing.
#[test]
fn a_cancel_mid_upload_releases_every_block_and_returns_the_staging_budget() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    let version = queued_version(&alice, op_id);
    let file = block_on(engine.view()).unwrap().children(ROOT)[0].id;

    // Each poll resumes the drain at its next block boundary, so a handful of
    // them leave it parked with part of the version already on the network.
    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_tasks_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "the cancel must land mid-transfer, not before it started"
    );

    block_on(engine.command(Command::CancelUpload { op_id })).expect("the upload is cancellable");
    poll_tasks_until_parked(&mut tasks);

    assert_no_blocks_staged(&alice, &version);
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .iter()
            .all(|key| *key == drained_key()),
        "the staging budget holds nothing but queue bookkeeping"
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty(),
        "the cancelled op left the durable queue"
    );
    assert!(
        block_on(engine.view()).unwrap().children(ROOT).is_empty(),
        "nothing published"
    );
    // Every block that reached the network is a charged pin row with no
    // reachable record behind it, so the cancel must retire exactly those and
    // nothing the version never sent.
    let charged: Vec<String> = version
        .iter()
        .map(|cid| encode_content_cid_str(cid))
        .filter(|cid| blocks.get(cid).is_some())
        .collect();
    assert!(
        (1..version.len()).contains(&charged.len()),
        "the cancel landed mid-set: part of the version is charged, not all of it"
    );
    // Both halves of the retire fire — the facade's, against what it could see
    // when the cancel landed, and the drain's, against the complete confirmed
    // set once it stops. Their union is the invariant; the overlap is an
    // idempotent replay, which is why this compares sets and not batches.
    let batches = retire_batches(&alice);
    assert_eq!(
        batches.len(),
        2,
        "a block confirming inside the facade's window is only covered by the drain's batch"
    );
    let mut retired = retire_targets(&alice);
    retired.sort();
    retired.dedup();
    let mut expected = charged.clone();
    expected.sort();
    assert_eq!(retired, expected);
    assert!(
        events_so_far(&mut events).contains(&Event::OpProgress {
            op_id: Some(op_id),
            node: file,
            phase: OpPhase::UploadCancelled,
            progress: None,
            error: None,
        }),
        "the host is told the upload was cancelled, keyed on its own op"
    );
}

/// A cancel releases leaves the durable mark still covers. That mark must not
/// reach the next version: read as its progress, it would skip leaves that
/// version never sent and publish a manifest naming blocks nobody holds. It is
/// keyed to the version it marked, and the release that drops that version's
/// blocks drops it with them.
#[test]
fn a_cancelled_versions_upload_mark_never_counts_towards_the_next_one() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let cancelled = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "abandoned.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .unwrap();
    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_tasks_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "only a partial upload leaves a mark, so the cancel must land mid-transfer"
    );
    block_on(engine.command(Command::CancelUpload { op_id: cancelled })).unwrap();
    poll_tasks_until_parked(&mut tasks);

    assert_eq!(
        upload_mark(&alice),
        None,
        "the cancelled version's mark left with the blocks it marked"
    );

    let plaintext: Vec<u8> = (0..200u8).rev().collect();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "kept.bin".into(),
        },
        &plaintext,
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    let bob = world.device(b"alice-second-device");
    serve_http(&bob, &blocks, 400);
    let (mut engine_b, _events_b) = engine_on(&bob, 7);
    block_on(engine_b.start(secret())).unwrap();
    let kept = child_id(&engine_b, ROOT, "kept.bin");
    assert_eq!(
        block_on(engine_b.read_content(kept)).expect("every leaf of the next version was sent"),
        plaintext
    );
}

/// Cancel is guaranteed only until publish entry. Once the version's record has
/// published, the op has left the queue and a cancel is refused rather than
/// converted into a compensating delete of published state.
#[test]
fn a_cancel_after_the_version_published_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        b"published bytes",
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        block_on(engine.command(Command::CancelUpload { op_id })),
        Err(EngineError::TooLateToCancel { op_id })
    );
    assert_eq!(
        block_on(engine.view()).unwrap().children(ROOT).len(),
        1,
        "the published file is untouched"
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "a refused cancel unpins nothing"
    );
}

/// This account's published-op mark key. The mark is per-identity, so a store
/// shared with another account keeps one mark each.
fn mark_key() -> Vec<u8> {
    owner_scoped_key(PUBLISHED_OP_MARK_PREFIX, &kdf::enc_subkey(&SECRET))
}

/// This account's drained-op mark key.
fn drained_key() -> Vec<u8> {
    owner_scoped_key(DRAINED_OP_MARK_PREFIX, &kdf::enc_subkey(&SECRET))
}

/// Plant a published-op mark over `op_id` under `enc_secret`'s identity,
/// standing in for the crash between a confirmed record publish and the op's
/// removal from the queue.
fn plant_published_mark_for(device: &FakeDevice, enc_secret: &X25519Secret, op_id: OpId) {
    block_on(device.staging_store.put_staged_bytes(
        &owner_scoped_key(PUBLISHED_OP_MARK_PREFIX, enc_secret),
        &op_id.0.to_be_bytes(),
    ))
    .unwrap();
}

fn plant_published_mark(device: &FakeDevice, op_id: OpId) {
    plant_published_mark_for(device, &kdf::enc_subkey(&SECRET), op_id);
}

/// The durable interlock only holds if a real publish writes it, on every plan
/// that puts content on the network — a create with content as much as a
/// version update.
#[test]
fn every_content_publish_raises_the_published_op_mark() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let created = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    assert_eq!(published_op_mark(&alice), Some(created.0), "the create");

    let file = child_id(&engine, ROOT, "photo.bin");
    let updated = write_file(&mut engine, version(file), &(0..64u8).collect::<Vec<u8>>()).unwrap();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published_op_mark(&alice),
        Some(updated.0),
        "the version update"
    );
}

/// What the mark buys: the op leaves the queue without re-uploading a byte, its
/// staged blocks are released, and nothing a live record names is unpinned.
fn assert_dropped_without_replay(
    device: &FakeDevice,
    events: &mut EventStream,
    version: (Vec<u8>, Vec<Vec<u8>>),
) {
    assert!(
        !events_so_far(events).iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::UploadStarted,
                ..
            }
        )),
        "nothing re-uploads behind a record that already landed"
    );
    assert!(
        block_on(StagingStore::queued_ops(&device.staging_store))
            .unwrap()
            .is_empty(),
        "the op leaves the queue"
    );
    let leftover = version
        .1
        .into_iter()
        .chain(core::iter::once(version.0))
        .collect::<Vec<_>>();
    assert_no_blocks_staged(device, &leftover);
    assert!(
        retire_targets(device).is_empty(),
        "a drop is not an abandonment: nothing published is unpinned"
    );
}

/// The durable published-op high-water this device stored.
fn published_op_mark(device: &FakeDevice) -> Option<u64> {
    let stored = block_on(device.staging_store.staged_bytes(&mark_key())).unwrap()?;
    Some(u64::from_be_bytes(stored.try_into().unwrap()))
}

/// An op whose record PUT was acknowledged is already live at its name. A crash
/// before its removal from the queue leaves it replayable, and a replay would
/// re-upload every leaf into a set a cancel can retire — unpinning content a
/// published record names. It drops as already satisfied instead.
#[test]
fn an_op_whose_record_already_published_is_dropped_rather_than_replayed() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    let version = staged_version(&alice);
    plant_published_mark(&alice, op_id);
    tick(&world, &engine, &mut tasks);

    assert_dropped_without_replay(&alice, &mut events, version);
}

/// The mark's line is the **ack**, not the self-adopt. A record whose PUT
/// confirmed is live at its name whether or not this device managed to adopt its
/// own bytes, so an op left queued by a failed adopt must not replay: the replay
/// re-uploads every leaf into a set a cancel can retire, unpinning content that
/// live record names.
#[test]
fn a_publish_whose_self_adopt_failed_still_marks_the_op_published() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    let version = staged_version(&alice);
    assert_a_failed_root_adopt_still_marks(&world, &alice, &engine, &mut tasks, &root_name, op_id);

    // A restart clears the session interlock, leaving only the mark to stop the
    // replay.
    alice.floor_store.heal_floors();
    let _ = events_so_far(&mut events);
    let (restarted, mut events, mut tasks) = boot(&world, &blocks, &alice, 43);
    tick(&world, &restarted, &mut tasks);
    assert_dropped_without_replay(&alice, &mut events, version);
}

/// The other half of the rule: only the **last** record of a plan may raise the
/// mark. A create whose child published and whose parent never did has to stay
/// replayable — dropping it would strand a live child no parent names.
#[test]
fn a_create_whose_parent_publish_never_ran_leaves_the_mark_down() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    // The child's own self-adopt fails, so the plan stops before the parent
    // record that would name it.
    let child = child_id(&engine, ROOT, "photo.bin");
    alice
        .floor_store
        .fail_floor_raises_for(&sequence_floor_label(write_name(child).as_str().as_bytes()));
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_op_mark(&alice),
        None,
        "an unreferenced child is not a published op"
    );
    assert!(
        !block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "the create stays queued for the retry that completes it"
    );
}

/// The plan's last record confirms and marks the op, and only then does its
/// self-adopt fail. The fault sits on the scope root because that is the one
/// folder a pass reads from the cache rather than through an adopt, so the loads
/// the plan makes before that record are left intact.
fn assert_a_failed_root_adopt_still_marks(
    world: &FakeWorld,
    device: &FakeDevice,
    engine: &Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    root_name: &IpnsName,
    op_id: OpId,
) {
    device
        .floor_store
        .fail_floor_raises_for(&sequence_floor_label(root_name.as_str().as_bytes()));
    let before = published(&world.record_store, ROOT).0;
    tick(world, engine, tasks);

    assert_eq!(
        published(&world.record_store, ROOT).0,
        before + 1,
        "the record the mark rests on did land"
    );
    assert_eq!(
        published_op_mark(device),
        Some(op_id.0),
        "the ack raised the mark, not the adopt"
    );
    assert!(
        !block_on(StagingStore::queued_ops(&device.staging_store))
            .unwrap()
            .is_empty(),
        "the failed adopt left the op queued — that is the window"
    );
}

/// The restart the mark exists for: the op leaves the queue without re-authoring
/// the record it already landed, and unpins nothing while doing it.
fn assert_restart_drops_without_republishing(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
) {
    device.floor_store.heal_floors();
    let before = published(&world.record_store, ROOT).0;
    let (restarted, _events, mut tasks) = boot(world, blocks, device, 43);
    tick(world, &restarted, &mut tasks);

    assert!(
        block_on(StagingStore::queued_ops(&device.staging_store))
            .unwrap()
            .is_empty(),
        "the op leaves the queue"
    );
    assert_eq!(
        published(&world.record_store, ROOT).0,
        before,
        "a dropped op republishes nothing"
    );
    assert!(
        retire_targets(device).is_empty(),
        "a drop is not an abandonment: nothing published is unpinned"
    );
}

/// A delete authors exactly one record, so that record is its last and marks.
#[test]
fn a_delete_whose_self_adopt_failed_still_marks_the_op_published() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    create(&mut engine, "doomed");
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "doomed");

    let op_id = block_on(engine.command(Command::Delete { node: doomed }))
        .unwrap()
        .op_id()
        .expect("the delete queues");
    assert_a_failed_root_adopt_still_marks(&world, &alice, &engine, &mut tasks, &root_name, op_id);
    assert_restart_drops_without_republishing(&world, &blocks, &alice);
}

/// Source and destination being one folder collapses a reference move into a
/// single record, so the dest-add is also the plan's last.
#[test]
fn a_rename_whose_self_adopt_failed_still_marks_the_op_published() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    create(&mut engine, "before");
    tick(&world, &engine, &mut tasks);

    let op_id = block_on(engine.command(Command::Rename {
        node: child_id(&engine, ROOT, "before"),
        new_name: "after".into(),
    }))
    .unwrap()
    .op_id()
    .expect("the rename queues");
    assert_a_failed_root_adopt_still_marks(&world, &alice, &engine, &mut tasks, &root_name, op_id);
    assert_restart_drops_without_republishing(&world, &blocks, &alice);
}

/// Across folders the plan is dest-add then source-remove, so the **source**
/// record is the last one and the one that marks.
#[test]
fn a_cross_folder_moves_source_remove_is_the_record_that_marks() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    // The move leaves the root for `photos`, so the root carries the
    // source-remove and the destination publishes first and adopts cleanly.
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);

    let op_id = block_on(engine.command(Command::Move {
        node: moved,
        new_parent: photos,
        new_name: "a.txt".into(),
        replacing: None,
    }))
    .unwrap()
    .op_id()
    .expect("the move queues");
    assert_a_failed_root_adopt_still_marks(&world, &alice, &engine, &mut tasks, &root_name, op_id);
    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["a.txt"],
        "a confirmed source-remove is the move complete, never compensated"
    );
    assert_restart_drops_without_republishing(&world, &blocks, &alice);
}

/// A dest-add that lands while the source-remove never does is not a published
/// move: the compensation undoes it. Marking there would drop the op on restart
/// with the move rolled back and never retried, losing it outright.
#[test]
fn a_cross_folder_moves_dest_add_never_marks_on_its_own() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    let before = published_op_mark(&alice);
    let dest_sequence = published(&world.record_store, photos).0;

    // The root carries the source-remove, so refusing its PUT stops the plan
    // after the destination has published and adopted.
    world.record_store.fail_put_for(root_name.as_str());
    let op_id = block_on(engine.command(Command::Move {
        node: moved,
        new_parent: photos,
        new_name: "a.txt".into(),
        replacing: None,
    }))
    .unwrap()
    .op_id()
    .expect("the move queues");
    tick(&world, &engine, &mut tasks);

    assert!(
        before < Some(op_id.0),
        "the setup's own mark must not already cover the move"
    );
    assert_eq!(
        published_op_mark(&alice),
        before,
        "a dest-add the compensation undid is not a published op"
    );
    assert_eq!(
        published(&world.record_store, photos).0,
        dest_sequence + 2,
        "the dest-add published, then the compensation undid it"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        [] as [String; 0],
        "the destination keeps nothing the source still names"
    );
    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .iter()
            .any(|(id, _)| *id == op_id),
        "the move stays queued for the retry that completes it"
    );
}

/// The retry the compensation leaves queued does complete the move: once the
/// source-remove's PUT lands, the record that marks is the one that carries it.
#[test]
fn a_retried_cross_folder_move_marks_when_its_source_remove_lands() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let root_name = seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);
    let before = published_op_mark(&alice);

    world.record_store.fail_put_for(root_name.as_str());
    let op_id = block_on(engine.command(Command::Move {
        node: moved,
        new_parent: photos,
        new_name: "a.txt".into(),
        replacing: None,
    }))
    .unwrap()
    .op_id()
    .expect("the move queues");
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published_op_mark(&alice),
        before,
        "the compensated attempt must not have marked"
    );

    world.record_store.heal_put_for(root_name.as_str());
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, photos),
        ["a.txt"],
        "the retry republishes the dest-add the compensation undid"
    );
    assert_eq!(
        published_op_mark(&alice),
        Some(op_id.0),
        "the landed source-remove marks the move published"
    );
    assert!(
        !block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .iter()
            .any(|(id, _)| *id == op_id),
        "the completed move leaves the queue"
    );
}

/// The publish-entry interlock is session-scoped, so a reboot clears it. The
/// durable mark is what keeps a published version uncancellable across one.
#[test]
fn a_cancel_of_an_already_published_op_is_refused_across_a_restart() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let op_id = {
        let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
        let op_id = write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &(0..200u8).collect::<Vec<u8>>(),
        )
        .unwrap();
        // The record published and the crash landed before the dequeue, so the
        // op is still queued when this session ends.
        plant_published_mark(&alice, op_id);
        op_id
    };

    // A second session over the same device: fresh `UploadCancels`, so nothing
    // but the durable mark stands between the cancel and the published version.
    let (mut restarted, _events, _tasks) = boot(&world, &blocks, &alice, 43);
    assert_eq!(
        block_on(restarted.command(Command::CancelUpload { op_id })),
        Err(EngineError::TooLateToCancel { op_id })
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "a refused cancel unpins nothing"
    );
}

/// The drained mark has the same shape and a worse outcome: an op discarded as
/// restore residue never published, and nothing releases or retires it — the
/// mutation is simply gone.
#[test]
fn another_identitys_drained_mark_never_discards_this_ones_queued_op() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "notes".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap()
    .op_id()
    .expect("the create queues");

    let stranger = kdf::enc_subkey(&[9u8; 32]);
    block_on(alice.staging_store.put_staged_bytes(
        &owner_scoped_key(DRAINED_OP_MARK_PREFIX, &stranger),
        &(op_id.0 + 100).to_be_bytes(),
    ))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["notes"],
        "the stranger's completion record says nothing about this identity's op"
    );
}

/// The queue is shared with other identities, and op ids are per-store. A
/// device-wide mark would let one account's published op dequeue another's
/// unpublished one and release its blocks.
#[test]
fn another_identitys_published_mark_never_retires_this_ones_queued_op() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    // A second account sharing this staging store published far past alice's id.
    let stranger = kdf::enc_subkey(&[9u8; 32]);
    plant_published_mark_for(&alice, &stranger, OpId(op_id.0 + 100));

    assert_eq!(
        block_on(engine.command(Command::CancelUpload { op_id })),
        Ok(CommandOutcome::Done),
        "the stranger's mark says nothing about this identity's op"
    );

    // And the same op, re-queued, still publishes rather than being dropped.
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    plant_published_mark_for(&alice, &stranger, OpId(op_id.0 + 100));
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::UploadStarted,
                ..
            }
        )),
        "the op uploaded instead of being dropped as already published"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        ["photo.bin"],
        "the version published"
    );
}

/// Cancel is content-only: a metadata op is undone by a compensating mutation,
/// which costs neither the network nor the staging budget.
#[test]
fn a_cancel_of_a_metadata_op_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "folder".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap()
    .op_id()
    .expect("the create queues");

    assert_eq!(
        block_on(engine.command(Command::CancelUpload { op_id })),
        Err(EngineError::NotAnUpload { op_id })
    );
    assert_eq!(
        block_on(alice.staging_store.queued_ops()).unwrap().len(),
        1,
        "the refused cancel left the op queued"
    );
}

/// A cancelled create takes every later queued op on the node it will never
/// bring into being; a cancelled version takes nothing, since versions are
/// independent full writes.
#[test]
fn a_cancelled_create_cascades_onto_its_node_and_a_cancelled_version_does_not() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    // A landed file, so a later version of it has something to update.
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "kept.bin".into(),
        },
        b"kept bytes",
    )
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let kept = child_id(&engine, ROOT, "kept.bin");

    let create = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "doomed.bin".into(),
        },
        b"doomed bytes",
    )
    .unwrap();
    let doomed = child_id(&engine, ROOT, "doomed.bin");
    block_on(engine.command(Command::Rename {
        node: doomed,
        new_name: "renamed.bin".into(),
    }))
    .unwrap();
    let version = write_file(&mut engine, version(kept), b"a new version").unwrap();

    block_on(engine.command(Command::CancelUpload { op_id: create })).expect("the create cancels");
    let queued: Vec<OpId> = block_on(alice.staging_store.queued_ops())
        .unwrap()
        .into_iter()
        .map(|(op_id, _)| op_id)
        .collect();
    assert_eq!(
        queued,
        vec![version],
        "the rename of the cancelled node went with it; the unrelated version stayed"
    );

    block_on(engine.command(Command::CancelUpload { op_id: version }))
        .expect("the version cancels");
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty()
    );
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["kept.bin".to_owned()],
        "neither cancelled op published"
    );
}

/// A cancel that cannot carry out its removals must give the claim back and
/// unpin nothing: an op left both queued and claimed would halt every pass
/// behind it forever, and one left queued with its leading leaves retired would
/// publish a version whose blocks are gone.
#[test]
fn a_cancel_that_cannot_dequeue_retires_nothing_and_leaves_the_op_publishable() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .unwrap();

    // Part of the version is already on the network when the cancel arrives, so
    // there is a retire batch to get wrong.
    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_tasks_once(&mut tasks);
    }
    assert!(uploads(&alice) > 0);

    alice.staging_store.inner().fail_remove_op();
    assert!(
        block_on(engine.command(Command::CancelUpload { op_id })).is_err(),
        "the cancel could not remove the op, so it did not happen"
    );
    poll_tasks_until_parked(&mut tasks);

    assert!(
        retire_targets(&alice).is_empty(),
        "an op that is still publishable keeps every pin its upload charged"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["photo.bin".to_owned()],
        "the op the cancel could not take is published, not wedged"
    );
    let file = child_id(&engine, ROOT, "photo.bin");
    assert_eq!(
        block_on(engine.read_content(file)).expect("the published version reads back"),
        plaintext
    );
}

/// The facade publishes the cancel claim before its removal commits, so the pass
/// that stops on that claim cannot assume the op has left the queue. Its retire
/// is gated on a removal of its own: proving the op is gone is what makes
/// unpinning its leaves safe, and a removal it cannot make means it retires
/// nothing rather than stranding a still-publishable version.
#[test]
fn the_drains_cancel_retire_is_gated_on_the_op_leaving_the_durable_queue() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .unwrap();

    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_tasks_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "the cancel must land mid-transfer, not before it started"
    );
    block_on(engine.command(Command::CancelUpload { op_id })).expect("the upload is cancellable");
    let facade_batches = retire_batches(&alice).len();

    // The drain now stops on the claim with no removal available to it, which
    // is indistinguishable from the op never having left the queue.
    alice.staging_store.inner().fail_remove_op();
    poll_tasks_until_parked(&mut tasks);

    assert_eq!(
        retire_batches(&alice).len(),
        facade_batches,
        "a pass that cannot prove the op left the queue unpins nothing"
    );
}

/// The op-record header is clear and unauthenticated, and the owner tag on it is
/// a public key any co-tenant of the origin-shared store can copy. A record that
/// bears our tag but never opens is dead-lettered and dropped at cold start — it
/// must not also authorize deleting the blocks its header names, or planting one
/// would destroy a queued version whose key is intact.
#[test]
fn an_undecodable_record_never_authorizes_deleting_the_blocks_its_header_names() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext: Vec<u8> = (0..200u8).collect();
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .unwrap();
    let version = queued_version(&alice, op_id);

    // The forgery: the real op's record with its sealed body corrupted, so the
    // header — our owner tag, and the real op's content root — still reads.
    let mut forged = block_on(alice.staging_store.queued_ops()).unwrap()[0]
        .1
        .clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    block_on(alice.staging_store.enqueue_op(&forged)).unwrap();
    drop(engine);
    drop(tasks);

    let (engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 43);
    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::Undecodable,
                ..
            }
        )),
        "the forgery must reach the path under test, not be retained short of it"
    );
    let staged = block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(
        version.iter().all(|cid| staged.contains(cid)),
        "the forged record was dropped; the version it named was not"
    );

    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "photo.bin");
    assert_eq!(
        block_on(engine.read_content(file)).expect("the real op still publishes"),
        plaintext
    );
}

/// Orphan GC runs after each drain pass and reclaims blocks nothing references —
/// the residue of a crash between staging a version and journaling its op.
#[test]
fn orphan_residue_is_collected_and_a_live_handles_blocks_are_not() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (leaves, root_block, root_cid) = frame_version(&(0..40u8).collect::<Vec<_>>());
    stage_blocks(&alice, &leaves, &root_block, &root_cid);

    // A write handle mid-stream: its blocks are staged before any op references
    // them, so only the live set keeps GC off them.
    let handle = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "in-flight.bin".into(),
        },
        200,
    ))
    .unwrap();
    let plaintext: Vec<u8> = (0..200u8).collect();
    block_on(engine.push_chunk(handle, &plaintext[..64])).unwrap();

    tick(&world, &engine, &mut tasks);

    let staged = block_on(alice.staging_store.staged_keys()).unwrap();
    for orphan in leaves.iter().map(|leaf| leaf.cid.clone()).chain([root_cid]) {
        assert!(
            !staged.contains(&orphan),
            "unreferenced residue is collected"
        );
    }

    // The handle finishing and publishing is the only assertion that proves the
    // sweep left its blocks alone: a collected leaf fails the drain, not this.
    block_on(engine.push_chunk(handle, &plaintext[64..])).unwrap();
    block_on(engine.commit_write(handle)).expect("the handle still holds every block it staged");
    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "in-flight.bin");
    assert_eq!(
        block_on(engine.read_content(file)).expect("the published version reads back"),
        plaintext
    );
}

/// A release that reports done without dropping the bytes strands a staged
/// leaf. On the cancel path nothing re-runs that release — the op is gone from
/// the queue — so orphan GC is the only thing that reclaims it, and it does so
/// precisely because nothing references it any more.
#[test]
fn a_leaf_a_lost_release_stranded_on_a_cancel_is_reclaimed_by_the_next_sweep() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .unwrap();
    // The last leaf: far past where the cancel interrupts the upload, so the
    // drain never removes it and the facade's release is its only cleaner.
    let version = queued_version(&alice, op_id);
    let stranded = version.last().expect("a multi-leaf version").clone();

    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_tasks_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "the cancel must land mid-transfer, not before it started"
    );
    alice
        .staging_store
        .inner()
        .drop_staged_removal_after(&stranded, 0);
    block_on(engine.command(Command::CancelUpload { op_id })).unwrap();
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&stranded),
        "the fixture must actually strand a leaf, or the sweep has nothing to prove"
    );

    // The pass that notices the cancel sweeps behind itself, so the residue does
    // not wait a whole cadence.
    poll_tasks_until_parked(&mut tasks);
    assert!(
        !block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&stranded),
        "nothing references it once its op is gone, so the sweep takes it"
    );
}

/// A terminally unrebasable op keeps its staged bytes — and keeping them is only
/// real if they survive the cold start that drops the op record, and the GC pass
/// that runs there.
#[test]
fn a_dead_lettered_ops_blocks_survive_a_cold_start_and_a_gc_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    // A version of a node no gate-passing state holds: terminally unrebasable.
    let (leaves, root_block, root_cid) = frame_version(&(0..40u8).collect::<Vec<_>>());
    stage_blocks(&alice, &leaves, &root_block, &root_cid);
    stage(
        &alice,
        &Op::update_content(
            NodeId([0xAB; 16]),
            StagedContent {
                root_cid: root_cid.clone(),
                plaintext_size: 40,
                sealed_content_key: b"never opened".to_vec(),
                epoch: EPOCH,
            },
            None,
            1,
            UnixMillis(4_242),
        ),
        Some(&root_block),
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::TargetGone,
                ..
            }
        )),
        "the op is terminally unrebasable, not unrecoverable content"
    );
    let version: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| leaf.cid.clone())
        .chain([root_cid])
        .collect();
    let after_drain = block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(
        version.iter().all(|cid| after_drain.contains(cid)),
        "a dead letter preserves its staged bytes"
    );
    drop(engine);

    let (engine, _events, mut tasks) = boot(&world, &blocks, &alice, 43);
    tick(&world, &engine, &mut tasks);
    let after_restart = block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(
        version.iter().all(|cid| after_restart.contains(cid)),
        "and keeps them across the cold start that removed the op record"
    );
}

/// A dead letter with no staged version, and the id the host reads it by.
///
/// A rename of a node no gate-passing state holds is terminal, and it stages
/// nothing: the shape whose dead letter has no content key to keep custody of.
fn versionless_dead_letter(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
) -> (Engine<FakeSeamTypes>, Vec<BoxedTask>, DeadLetter) {
    let (engine, _events, mut tasks) = boot(world, blocks, device, 42);
    stage(
        device,
        &Op::rename(NodeId([0xAB; 16]), "renamed", 1, UnixMillis(4_242)),
        None,
    );
    tick(world, &engine, &mut tasks);

    let parked = block_on(engine.status())
        .expect("the status reads")
        .dead_letters;
    assert_eq!(
        parked.len(),
        1,
        "the op is terminally unrebasable, and it staged no version"
    );
    assert_eq!(parked[0].reason, DeadLetterReason::TargetGone);
    (engine, tasks, parked[0])
}

/// The preserved set holds a record because that record carries a version's
/// only content key, and it evicts oldest-first. An op with no version takes a
/// notice instead — and the notice map does not outlive the process, so the
/// notice is the only thing that can name it again.
#[test]
fn a_versionless_dead_letter_is_named_again_after_a_cold_start() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (engine, _tasks, parked) = versionless_dead_letter(&world, &blocks, &alice);
    drop(engine);
    assert_eq!(
        block_on(alice.staging_store.staged_bytes(PRESERVED_DEAD_LETTERS)).unwrap(),
        None,
        "and it spends none of the set that evicts oldest-first"
    );

    let (restarted, _events, _tasks) = boot(&world, &blocks, &alice, 43);

    assert_eq!(
        block_on(restarted.status())
            .expect("the status reads")
            .dead_letters,
        vec![parked],
        "the restart names it by the id its dead letter announced"
    );
    assert_eq!(
        block_on(alice.staging_store.staged_bytes(PRESERVED_DEAD_LETTERS)).unwrap(),
        None,
        "and the cold start reads the notice without writing a record for it"
    );
}

/// Listing it is half of what the host owes the member; the exit is the other.
#[test]
fn discarding_a_noticed_dead_letter_clears_it_across_the_next_restart() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (engine, _tasks, parked) = versionless_dead_letter(&world, &blocks, &alice);
    drop(engine);
    let (mut restarted, _events, _tasks) = boot(&world, &blocks, &alice, 43);

    assert!(
        matches!(
            block_on(restarted.command(Command::RecoverDeadLetter {
                op_id: parked.op_id
            })),
            Err(EngineError::MalformedInput { .. })
        ),
        "there is no version to re-stage, which is the refusal every metadata intent earns"
    );
    block_on(restarted.command(Command::DiscardDeadLetter {
        op_id: parked.op_id,
    }))
    .expect("the discard lands");
    assert!(
        block_on(restarted.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "the notice goes with it"
    );
    drop(restarted);

    let (again, _events, _tasks) = boot(&world, &blocks, &alice, 44);
    assert!(
        block_on(again.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "and no later boot brings it back"
    );
}

// ---------------------------------------------------------------------------
// Parked writes: durable identity, discard, and recover.
// ---------------------------------------------------------------------------

/// A device holding one parked write, and the op id it is named by.
fn parked_write(
    world: &FakeWorld,
    blocks: &Blocks,
) -> (
    FakeDevice,
    Engine<FakeSeamTypes>,
    Vec<BoxedTask>,
    NodeId,
    OpId,
) {
    seed_account(world, blocks);
    let (first, bobs, alices) = contested_bodies();
    let (mut engine_a, _events_a, mut tasks_a, node) = publish_clip(world, blocks, &first);
    let (bob, mut engine_b, mut tasks_b) = open_writer(world, blocks, node, &first);

    let op_id =
        write_file(&mut engine_b, version(node), &bobs).expect("the second device's edit commits");
    write_file(&mut engine_a, version(node), &alices).expect("the first device's edit commits");
    tick(world, &engine_a, &mut tasks_a);

    let (parked, _) = tick_until_dead_lettered(world, &engine_b, &mut tasks_b);
    assert_eq!(
        parked,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::BaseSuperseded
        }],
        "the conditional-edit loser parks rather than clobbering"
    );
    (bob, engine_b, tasks_b, node, op_id)
}

/// The preserved set outlives the process and the notice map does not, so the
/// identity a host discards or recovers by has to come back off the set.
#[test]
fn a_parked_write_keeps_its_op_id_and_its_reason_across_a_restart() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (bob, engine_b, _tasks_b, _node, op_id) = parked_write(&world, &blocks);
    drop(engine_b);

    let (restarted, _events, _tasks) = boot(&world, &blocks, &bob, 8);

    assert_eq!(
        block_on(restarted.status())
            .expect("the status reads")
            .dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::BaseSuperseded
        }],
        "the restart names the parked write by the id its dead letter announced"
    );
}

/// Discard is the exit the preserved set had none of: the entry goes and its
/// version's blocks go with it, and a second discard names nothing.
#[test]
fn discarding_a_parked_write_releases_the_version_it_held() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (bob, mut engine_b, _tasks_b, _node, op_id) = parked_write(&world, &blocks);
    let staged = || block_on(bob.staging_store.staged_keys()).unwrap();
    let before = staged().len();

    block_on(engine_b.command(Command::DiscardDeadLetter { op_id })).expect("the discard lands");

    assert!(
        block_on(engine_b.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "the notice goes with the entry"
    );
    assert!(
        staged().len() < before,
        "and the version it held is released"
    );
    assert_eq!(
        block_on(engine_b.command(Command::DiscardDeadLetter { op_id })),
        Err(EngineError::UnknownDeadLetter { op_id }),
        "a second discard names a write this device no longer holds"
    );
}

/// Recover re-queues the parked bytes under a **fresh** op anchored on the head
/// that beat them. Resuming the parked op instead would replay the conditional
/// edit it lost, so the member could never get their own bytes back.
#[test]
fn recovering_a_parked_write_queues_a_fresh_op_anchored_on_the_head_that_beat_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (_bob, mut engine_b, mut tasks_b, node, op_id) = parked_write(&world, &blocks);
    let (_, bobs, alices) = contested_bodies();
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head reads"),
        alices,
        "the version that beat the parked one stands until the recover"
    );

    let outcome = block_on(engine_b.command(Command::RecoverDeadLetter { op_id }))
        .expect("the recover lands");
    let CommandOutcome::Queued { op_id: fresh } = outcome else {
        panic!("a recover queues a fresh op, got {outcome:?}");
    };
    assert_ne!(fresh, op_id, "the parked op is never resumed");
    tick(&world, &engine_b, &mut tasks_b);

    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the recovered head reads"),
        bobs,
        "the recovered version publishes rather than parking again"
    );
    assert!(
        block_on(engine_b.status())
            .expect("the status reads")
            .dead_letters
            .is_empty(),
        "and the entry it recovered is gone"
    );
}

/// A recover forms a fresh op against the rendered view, so a target the member
/// deleted while the write was parked has to be refused the way `begin_write`
/// refuses one. Staging it instead would carry no anchor and the default base
/// sequence, and only the drain would end it.
#[test]
fn recovering_a_parked_write_onto_a_deleted_target_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (_bob, mut engine_b, _tasks_b, node, op_id) = parked_write(&world, &blocks);

    block_on(engine_b.command(Command::Delete { node })).expect("the delete stages");

    assert_eq!(
        block_on(engine_b.command(Command::RecoverDeadLetter { op_id })),
        Err(EngineError::UnknownNode),
        "the recover is refused at the command, not staged against nothing"
    );
    assert_eq!(
        block_on(engine_b.status())
            .expect("the status reads")
            .dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::BaseSuperseded
        }],
        "and the parked entry stands, so discard is still open to the member"
    );
}

/// The key the preserved set lives under, as the staging module spells it.
const PRESERVED_KEY: &[u8] = b"cipherbox/preserved-dead-letters";

/// One format-v3 preserved set holding exactly `entries`.
fn preserved_set(entries: &[(OpId, u8, &[u8])]) -> Vec<u8> {
    let mut bytes = vec![3u8];
    for (op_id, reason, record) in entries {
        bytes.extend_from_slice(&op_id.0.to_be_bytes());
        bytes.push(*reason);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&(record.len() as u32).to_be_bytes());
        bytes.extend_from_slice(record);
    }
    bytes
}

/// The drain writes the preserved entry before it dequeues the op, so a crash
/// in that gap leaves one version named by a live queue entry and by the
/// preserved set at once. Discarding then would release bytes an op is still
/// going to publish, so an op the queue still holds is pending, never parked.
#[test]
fn a_parked_entry_whose_op_is_still_queued_is_neither_listed_nor_discardable() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (bob, mut engine_b, _tasks_b, node, parked_op) = parked_write(&world, &blocks);

    // A live queued op of this session's own, then the crash shape: the
    // preserved set names it too, beside the write that really is parked.
    let (_, live_bytes, _) = contested_bodies();
    let queued_op = write_file(&mut engine_b, version(node), &live_bytes).expect("it queues");
    let queued = block_on(bob.staging_store.queued_ops()).unwrap();
    let (_, live_record) = queued
        .iter()
        .find(|(id, _)| *id == queued_op)
        .expect("the op this session just staged");
    let parked_record = block_on(bob.staging_store.staged_bytes(PRESERVED_KEY))
        .unwrap()
        .expect("the fixture parked one");
    block_on(bob.staging_store.put_staged_bytes(
        PRESERVED_KEY,
        &preserved_set(&[(queued_op, 9, live_record)]),
    ))
    .expect("the store takes the crash shape");

    assert_eq!(
        block_on(engine_b.command(Command::DiscardDeadLetter { op_id: queued_op })),
        Err(EngineError::UnknownDeadLetter { op_id: queued_op }),
        "a queued op is pending, so its version is not the set's to release"
    );
    assert_eq!(
        block_on(engine_b.command(Command::RecoverDeadLetter { op_id: queued_op })),
        Err(EngineError::UnknownDeadLetter { op_id: queued_op }),
        "and not one to queue a second time either"
    );
    assert_eq!(
        block_on(bob.staging_store.staged_bytes(PRESERVED_KEY)).unwrap(),
        Some(preserved_set(&[(queued_op, 9, live_record)])),
        "a refused command shortens nothing"
    );

    // The gate is the queue and not a blanket refusal: restore the write that
    // really is parked and it still answers.
    block_on(
        bob.staging_store
            .put_staged_bytes(PRESERVED_KEY, &parked_record),
    )
    .unwrap();
    block_on(engine_b.command(Command::DiscardDeadLetter { op_id: parked_op }))
        .expect("the genuinely parked write still discards");
}

/// An entry another identity parked is that identity's to act on. The staging
/// store is shared, so a session that could discard one would destroy another
/// account's only copy of those bytes.
#[test]
fn a_parked_entry_this_session_cannot_open_is_never_acted_on() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (bob, mut engine_b, _tasks_b, _node, _op_id) = parked_write(&world, &blocks);
    let stored = preserved_set(&[(OpId(77), 9, b"another identity's op record")]);
    block_on(bob.staging_store.put_staged_bytes(PRESERVED_KEY, &stored))
        .expect("the store holds it");

    assert_eq!(
        block_on(engine_b.command(Command::DiscardDeadLetter { op_id: OpId(77) })),
        Err(EngineError::UnknownDeadLetter { op_id: OpId(77) }),
        "a record this session cannot open is not this session's to release"
    );
    assert_eq!(
        block_on(engine_b.command(Command::RecoverDeadLetter { op_id: OpId(77) })),
        Err(EngineError::UnknownDeadLetter { op_id: OpId(77) })
    );
    assert_eq!(
        block_on(bob.staging_store.staged_bytes(PRESERVED_KEY)).unwrap(),
        Some(stored),
        "and the set it sits in is left standing"
    );
}

/// The upload a refusal lands on to halt a 200-byte version mid-set: past the
/// first leaves, well short of the 13 the CI framing produces.
const MID_SET_UPLOAD: usize = 8;

/// Refuse every upload from the `nth` on, so a halted set stays halted across
/// the passes that retry it.
fn refuse_uploads_from(blocks: &Blocks, nth: usize, refusal: fn() -> SeamResult<HttpResponse>) {
    let mut sent = 0;
    blocks.refuse_upload(Box::new(move |_| {
        sent += 1;
        (sent >= nth).then(refusal)
    }));
}

/// Land one multi-leaf file, then queue a second version over it. Returns the
/// queued version's whole block set as the registry names it: the root first,
/// then every leaf in file order.
fn stage_a_second_version(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
) -> (Engine<FakeSeamTypes>, Vec<BoxedTask>, Vec<String>) {
    let (mut engine, _events, mut tasks) = boot(world, blocks, device, 42);
    let target = WriteTarget::NewFile {
        parent: ROOT,
        name: "photo.bin".into(),
    };
    write_file(&mut engine, target, &(0..200u8).collect::<Vec<_>>()).unwrap();
    tick(world, &engine, &mut tasks);
    assert!(retire_targets(device).is_empty(), "the create landed");

    let file = child_id(&engine, ROOT, "photo.bin");
    let next: Vec<u8> = (0..200u8).rev().collect();
    write_file(&mut engine, version(file), &next).unwrap();
    let version = block_on(async {
        let queued = device.staging_store.queued_ops().await.unwrap();
        let root_cid = record_content_root_cid(&queued[0].1).unwrap().unwrap();
        let root_block = device
            .staging_store
            .staged_bytes(&root_cid)
            .await
            .unwrap()
            .unwrap();
        let leaves = decode_root(&root_block).unwrap().leaf_cids;
        core::iter::once(encode_content_cid_str(&root_cid))
            .chain(leaves.iter().map(|cid| encode_content_cid_str(cid)))
            .collect()
    });
    (engine, tasks, version)
}

/// Whether this stream carries the verdict a version whose released blocks are
/// gone ends on — the hole guard's, not a mere failed attempt.
fn content_lost(events: &mut EventStream) -> bool {
    events_so_far(events).iter().any(|event| {
        matches!(
            event,
            Event::DeadLetter {
                reason: DeadLetterReason::ContentUnrecoverable,
                ..
            }
        )
    })
}

/// A relocation that changes scope re-seals the moved subtree at the
/// destination scope's epoch, which this driver does not author. What it must
/// not do is hold the queue head with nothing charged and nothing reported: the
/// host would read `fresh`, no dead letter, and no warning, while the move never
/// publishes and every op behind it waits forever.
#[test]
fn a_cross_scope_relocation_the_drain_cannot_author_dead_letters_rather_than_wedging_the_queue() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 71);

    create(&mut engine, "photos");
    create(&mut engine, "archive");
    let photos = child_id(&engine, ROOT, "photos");
    let archive = child_id(&engine, ROOT, "archive");
    tick(&world, &engine, &mut tasks);

    stage(
        &alice,
        &Op::relink(
            photos,
            ROOT,
            archive,
            published(&world.record_store, photos).0,
            UnixMillis(1),
            ScopeCrossing::Cross,
        ),
        None,
    );
    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);

    assert_eq!(
        dead_letters
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted],
        "the halt is charged and classified, so the host is told"
    );
    assert!(
        passes > 1,
        "a classified halt spends a budget, never one pass"
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .unwrap()
            .is_empty(),
        "and the head leaves the queue, so nothing behind it is starved"
    );
}

/// Tick until the drain dead-letters something, and report how many passes that
/// took — the budget is finite, but spending it takes more than one pass.
fn tick_until_dead_lettered(
    world: &FakeWorld,
    engine: &Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) -> (Vec<DeadLetter>, usize) {
    let dead_letters = || block_on(engine.snapshot(ROOT)).unwrap().dead_letters;
    let mut passes = 0;
    while dead_letters().is_empty() {
        tick(world, engine, tasks);
        passes += 1;
        assert!(passes < 50, "the attempt budget must be finite");
    }
    (dead_letters(), passes)
}

#[test]
fn a_create_the_rebase_drops_as_already_satisfied_is_never_retired() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    create(&mut engine, "photos");
    let photos = child_id(&engine, ROOT, "photos");
    // One charged attempt, so by the retire record's reckoning this op has
    // reached the network.
    jam_name(&world.record_store, photos);
    tick(&world, &engine, &mut tasks);

    // The create then turns out to have landed: the root the network serves
    // names the child, so the rebase drops the op as already satisfied.
    world
        .record_store
        .heal_put_endpoint(&world.record_store.endpoints()[1]);
    concurrent_root_add(
        &world.record_store,
        &blocks,
        child_ref(photos.0, "photos", CoreNodeKind::Folder),
    );
    tick(&world, &engine, &mut tasks);

    assert!(
        block_on(engine.view())
            .unwrap()
            .children(ROOT)
            .iter()
            .any(|child| child.id == photos),
        "the create landed and the root names it"
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "retiring a landed create's name would cut a record its parent references"
    );
}

/// A queued op as a backup took it: the durable record, and every block its
/// version has staged, each under its own CID.
struct Backup {
    record: Vec<u8>,
    staged: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Take one.
fn back_up(device: &FakeDevice, op_id: OpId) -> Backup {
    let cids = queued_version(device, op_id);
    block_on(async move {
        let record = device
            .staging_store
            .queued_ops()
            .await
            .unwrap()
            .into_iter()
            .find(|(id, _)| *id == op_id)
            .expect("the op is queued")
            .1;
        let mut staged = Vec::new();
        for cid in cids {
            let bytes = device
                .staging_store
                .staged_bytes(&cid)
                .await
                .unwrap()
                .expect("the version's blocks are staged");
            staged.push((cid, bytes));
        }
        Backup { record, staged }
    })
}

/// Write one back over the store. The record re-enqueues under a fresh id, so no
/// drained-op mark this device still holds can take it for the op that already
/// published.
fn restore(device: &FakeDevice, backup: &Backup) {
    block_on(async {
        for (cid, bytes) in &backup.staged {
            device
                .staging_store
                .put_staged_bytes(cid, bytes)
                .await
                .expect("a block restores");
        }
        device
            .staging_store
            .enqueue_op(&backup.record)
            .await
            .expect("the record restores");
    });
}

/// The restore guard must not read the engine's own unconfirmed publish as a
/// forgotten one. An acked PUT whose confirm-by-re-resolve missed leaves the
/// record standing at the derived name with no sequence floor — the same two
/// facts a restore leaves — and the retry it is owed re-mints the same sequence.
/// The charged attempt is what tells them apart: this device remembers trying.
#[test]
fn an_unconfirmed_publish_that_did_land_is_retried_rather_than_read_as_a_replay() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let photo = child_id(&engine, ROOT, "photo.bin");
    let name = write_name(photo);

    // The PUT lands; nothing serves it back, so the publish cannot confirm.
    world.record_store.fail_get_for(name.as_str());
    tick(&world, &engine, &mut tasks);
    assert!(
        published_names(&world.record_store, &blocks, ROOT).is_empty(),
        "the parent never gained the child this pass"
    );
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "an unconfirmed publish is availability, not a verdict"
    );

    // It propagates. The record now resolves and passes its own gate, with no
    // floor behind it — the shape the guard refuses on a restore.
    world.record_store.heal_get_for(name.as_str());
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["photo.bin".to_owned()],
        "the create completes instead of abandoning itself"
    );
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "and nothing is dead-lettered"
    );
}

/// A data directory restored from before its own drain: the queue is back, the
/// marks and floors that record what already published are not, and the record
/// plane kept everything. Republishing the create would re-author a node the
/// account deleted in the meantime — on every device that adopts the parent.
#[test]
fn a_restored_queue_never_republishes_a_create_the_record_plane_already_carries() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let backup = back_up(&alice, op_id);
    tick(&world, &engine, &mut tasks);
    let photo = child_id(&engine, ROOT, "photo.bin");

    block_on(engine.command(Command::Delete { node: photo })).expect("the delete stages");
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        Vec::<String>::new(),
        "the delete landed: the root names nothing"
    );
    let retired_before = retire_targets(&alice).len();
    drop(engine);
    drop(tasks);

    restore(&alice, &backup);
    block_on(FloorStore::clear(&alice.floor_store)).expect("the ratchet resets");

    let (engine, _events, mut tasks) = boot(&world, &blocks, &alice, 43);
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        Vec::<String>::new(),
        "the deleted node is not resurrected in its parent"
    );
    assert_eq!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AlreadyPublished],
    );
    assert_eq!(
        retired_since(&alice, retired_before),
        vec![write_name(photo).as_str().to_owned()],
        "and the name no published parent references is handed back, so the \
         republisher stops keeping the resurrection candidate alive"
    );
    // The name goes back; the version does not. A refusal is the only
    // abandonment that releases, and this one preserved.
    let staged = block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(!backup.staged.is_empty(), "the restore had blocks to keep");
    for (cid, _) in &backup.staged {
        assert!(
            staged.contains(cid),
            "the restored version this create staged is kept, not released"
        );
    }
}

/// A parked create names a parent, and a peer can fill that parent to the child
/// ceiling while the create waits. The ordinary create path refuses a full
/// parent at the caller, so a recover onto one owes the member the same answer
/// rather than a queue entry only the drain can end.
#[test]
fn recovering_a_parked_create_into_a_filled_parent_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let backup = back_up(&alice, op_id);
    tick(&world, &engine, &mut tasks);
    let photo = child_id(&engine, ROOT, "photo.bin");
    block_on(engine.command(Command::Delete { node: photo })).expect("the delete stages");
    tick(&world, &engine, &mut tasks);
    drop(engine);
    drop(tasks);

    restore(&alice, &backup);
    block_on(FloorStore::clear(&alice.floor_store)).expect("the ratchet resets");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 43);
    tick(&world, &engine, &mut tasks);
    let parked = block_on(engine.status())
        .expect("the status reads")
        .dead_letters;
    assert_eq!(
        parked
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AlreadyPublished],
        "the restored create parks with its version kept"
    );

    let planted: Vec<ChildRef> = (0..MAX_FOLDER_CHILDREN)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            file_ref(id, &format!("planted-{i}.bin"))
        })
        .collect();
    concurrent_root_extend(&world.record_store, &blocks, planted);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        block_on(engine.view()).unwrap().children(ROOT).len(),
        MAX_FOLDER_CHILDREN,
        "the peer's full listing is in gate-passing state"
    );

    assert_eq!(
        block_on(engine.command(Command::RecoverDeadLetter {
            op_id: parked[0].op_id
        })),
        Err(EngineError::MalformedInput {
            check: "folder-child-ceiling",
        }),
        "the recover is refused at the command, the way a fresh create is"
    );
}

// ---------------------------------------------------------------------------

/// A child ref under this account's write-name edge.
fn child_ref(id: [u8; 16], name: &str, kind: CoreNodeKind) -> ChildRef {
    ChildRef {
        id,
        name: name.into(),
        ipns_name: write_name(NodeId(id)).as_str().as_bytes().to_vec(),
        kind,
        link_counter: 1,
        unknown: PreservedFields::new(),
    }
}

fn file_ref(id: [u8; 16], name: &str) -> ChildRef {
    child_ref(id, name, CoreNodeKind::File)
}

/// A root holding an empty `photos` folder and a file `a.txt`, both published.
fn seed_folder_and_file(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) -> (NodeId, NodeId) {
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .unwrap();
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "a.txt".into(),
        kind: NodeKind::File,
    }))
    .unwrap();
    tick(world, engine, tasks);
    (
        child_id(engine, ROOT, "photos"),
        child_id(engine, ROOT, "a.txt"),
    )
}

/// Stage a folder create under the root and hand back its durable queue id.
fn create(engine: &mut Engine<FakeSeamTypes>, name: &str) -> OpId {
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: name.into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages")
    .op_id()
    .expect("a create queues an op")
}

/// Every event the engine has emitted and not yet been read.
fn events_so_far(events: &mut EventStream) -> Vec<Event> {
    let mut out = Vec::new();
    while let Some(event) = events.try_next() {
        out.push(event);
    }
    out
}

/// How many content uploads this device has sent.
fn uploads(device: &FakeDevice) -> usize {
    uploaded_cids(device).len()
}

/// The address each of this device's uploads declared, in order.
fn uploaded_cids(device: &FakeDevice) -> Vec<String> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/content/upload"))
        .map(|request| {
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("X-Content-Cid"))
                .map(|(_, value)| value.clone())
                .expect("an upload declares its CID")
        })
        .collect()
}

/// Every target this device named past `mark` — a count taken from an earlier
/// [`retire_targets`]. A refused pass replays whole, so a per-pass property is
/// read off the window that actually settled.
fn retired_since(device: &FakeDevice, mark: usize) -> Vec<String> {
    retire_targets(device)[mark..].to_vec()
}

/// Every target this device has asked the registry to retire, in order.
fn retire_targets(device: &FakeDevice) -> Vec<String> {
    retire_batches(device).into_iter().flatten().collect()
}

/// Every batch that named `target`, as the record each scoped itself to and
/// `None` for the account-wide form. Every batch rather than the first, because
/// a second batch naming the same CID account-wide takes the edge the first one
/// kept.
fn batch_namings(batches: &[(Option<String>, Vec<String>)], target: &str) -> Vec<Option<String>> {
    batches
        .iter()
        .filter(|(_, targets)| targets.iter().any(|sent| sent == target))
        .map(|(record, _)| record.clone())
        .collect()
}

/// Every retire batch this device sent, as the record it names — which is what
/// separates a record-scoped retire from the account-wide form — and its
/// targets.
fn retire_entries(device: &FakeDevice) -> Vec<(Option<String>, Vec<String>)> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/retire"))
        .flat_map(|request| {
            serde_json::from_slice::<Vec<RetireEntry>>(
                request
                    .body
                    .as_deref()
                    .expect("a retire call carries a body"),
            )
            .expect("a retire body is a JSON array of entries")
        })
        .map(|entry| (entry.ipns_name, entry.targets))
        .collect()
}

/// The retire calls this device made, one entry per batch.
fn retire_batches(device: &FakeDevice) -> Vec<Vec<String>> {
    retire_entries(device)
        .into_iter()
        .map(|(_, targets)| targets)
        .collect()
}

/// Another writer parks a strictly higher sequence at `node`'s own name on one
/// endpoint, which then stops accepting our PUTs — so every publish there loses
/// the CAS race on the confirm re-resolve, indefinitely.
fn jam_name(records: &InMemoryRecordStore, node: NodeId) {
    let endpoint = records.endpoints()[1].clone();
    let record = IpnsRecord::create_v2(
        &write_signer(node),
        b"/ipfs/bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1_000,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    records.seed_record(&endpoint, write_name(node).as_str(), record);
    records.fail_put_endpoint(&endpoint);
}

/// Stage an op straight into the durable queue, for a mutation the facade
/// cannot form yet. A content op's `upload` is the root block `stage_op`
/// requires the store to already hold under the op's root CID.
fn stage(device: &FakeDevice, op: &Op, upload: Option<&[u8]>) {
    block_on(async {
        if let (Some(cid), Some(bytes)) = (op.content_root_cid(), upload) {
            device
                .staging_store
                .put_staged_bytes(cid, bytes)
                .await
                .expect("the root block stages");
        }
        stage_op(
            &device.staging_store,
            RecordSeal {
                owner_enc_secret: &kdf::enc_subkey(&SECRET),
                ephemeral_scalar: Zeroizing::new([0x5A; 32]),
            },
            op,
        )
        .await
        .expect("the op queues");
    });
}

/// Another writer publishes the **scope root**'s next record, adding `extra` on
/// top of whatever the root currently carries. The root carries a grant section,
/// so it re-authors through the owner-root fixture rather than the child path.
fn concurrent_root_add(records: &InMemoryRecordStore, blocks: &Blocks, extra: ChildRef) {
    concurrent_root_extend(records, blocks, vec![extra]);
}

/// The same, for a listing one call has to plant whole.
fn concurrent_root_extend(records: &InMemoryRecordStore, blocks: &Blocks, extra: Vec<ChildRef>) {
    let (sequence, _) = published(records, ROOT);
    let mut children = published_children(records, blocks, ROOT);
    children.extend(extra);
    let fixture = owner_root_fixture(OwnerRootSpec {
        owner_identity: &owner_identity(),
        owner_enc: &kdf::enc_subkey(&SECRET).public(),
        scope_id: SCOPE,
        root_id: ROOT.0,
        children,
        child_scope_index: Vec::new(),
        parent_node_seed: None,
        owner_write_blob_epoch: Some(EPOCH),
        write_history_link: Vec::new(),
        grants: Vec::new(),
    });
    blocks.put(fixture.head_block.clone());
    let record = IpnsRecord::create_v2(
        &write_signer(ROOT),
        format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
        sequence + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in records.endpoints() {
        records.seed_record(&endpoint, fixture.name.as_str(), record.clone());
    }
}

/// Another writer publishes `folder`'s next record, adding `extra` on top of
/// whatever the folder currently carries.
fn concurrent_add(records: &InMemoryRecordStore, blocks: &Blocks, folder: NodeId, extra: ChildRef) {
    let (_, head_cid) = published(records, folder);
    let envelope =
        decode_envelope(&blocks.get(&head_cid).expect("the head block")).expect("decodes");
    let read_key = read_key_of(folder);
    let ReadBody::Folder {
        created_at,
        modified_at,
        mut children,
        unknown,
    } = open_read_body(&envelope, &read_key).expect("opens")
    else {
        panic!("expected a folder body");
    };
    children.push(extra);

    let head = author_child_envelope(EnvelopeAuthoring {
        node_id: folder.0,
        scope_id: SCOPE,
        epoch: envelope.epoch,
        read_key: &read_key,
        nonce: &[0x3C; 24],
        body: &ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        },
        carried_unknown: envelope.unknown.clone(),
        carried_epoch_tag_unknown: envelope.epoch_tag_unknown.clone(),
    })
    .expect("the concurrent writer authors a valid record");
    publish_next_record(records, blocks, folder, &head);
}

/// Publish `head` under `folder`'s write name at the sequence after its current
/// record — how every "another writer moved this folder on" fixture lands.
fn publish_next_record(
    records: &InMemoryRecordStore,
    blocks: &Blocks,
    folder: NodeId,
    head: &AuthoredHead,
) {
    let (sequence, _) = published(records, folder);
    blocks.put(head.block.clone());
    let record = IpnsRecord::create_v2(
        &write_signer(folder),
        format!("/ipfs/{}", head.cid).as_bytes(),
        sequence + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in records.endpoints() {
        records.seed_record(&endpoint, write_name(folder).as_str(), record.clone());
    }
}

// ---------------------------------------------------------------------------
// The pin-provider layer: where a version's bytes go, decided from the vault
// settings record and dispatched across the hosted and external legs.
// ---------------------------------------------------------------------------

/// The member's own node, as a BYO config naming it.
fn member_node(kind: ByoKind) -> ByoIpfsConfig {
    ByoIpfsConfig {
        endpoint: MEMBER_NODE.to_owned(),
        kind,
        access_token: Some(Zeroizing::new("member-token".to_owned())),
    }
}

/// Publish the account's vault settings record from `device`, so a cold start on
/// it decides placement from the member's own choice rather than the first-run
/// defaults.
fn seed_settings(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks, mode: PinMode) {
    seed_vault_settings(
        world,
        device,
        blocks,
        &VaultSettings {
            pin_mode: mode,
            byo: Some(member_node(ByoKind::Kubo)),
            retention: RetentionPolicy::KeepAll,
            bin_retention_days: DEFAULT_BIN_RETENTION_DAYS,
        },
    );
}

/// [`seed_settings`] over a whole settings shape, for the fields a cold start
/// carries into the session beyond the placement decision.
fn seed_vault_settings(
    world: &FakeWorld,
    device: &FakeDevice,
    blocks: &Blocks,
    settings: &VaultSettings,
) {
    serve_http(device, blocks, 8);
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        String::new(),
    );
    block_on(publish_settings(
        &device.record_store,
        &api,
        &device.floors(&SECRET),
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(9),
        &OrphanHeads::default(),
        &SECRET,
        settings,
    ))
    .expect("the settings record publishes");
}

/// `External` means what it says: not one byte reaches CipherBox's store, and
/// the hosted quota — full here — never gates a write it will never see.
#[test]
fn an_external_write_places_every_block_on_the_members_node_and_none_on_the_hosted_store() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::External);
    blocks.set_quota(1_000, 1_000);

    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let plaintext = (0..200u8).collect::<Vec<_>>();
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .expect("a full hosted quota does not gate an external write");
    tick(&world, &engine, &mut tasks);

    let photo = child_id(&engine, ROOT, "photo.bin");
    let mut registered = registered_content_cids(&alice, &write_name(photo));
    registered.sort();
    registered.dedup();
    assert!(
        !registered.is_empty(),
        "every mode still registers for union-liveness accounting"
    );
    assert_eq!(
        blocks.member_node_cids(),
        registered,
        "the member's node holds exactly the block set the registration names"
    );
    let hosted = uploaded_cids(&alice);
    assert!(
        registered.iter().all(|cid| !hosted.contains(cid)),
        "not one of the version's blocks took the hosted path"
    );
    assert_eq!(
        published(&world.record_store, photo).0,
        1,
        "the version still published its own record"
    );
}

/// Leaves already released from staging can never be placed again, so a
/// placement changed mid-upload is decided on one question: does the leg this
/// version must now publish from already hold them?
///
/// Dropping the mirror leaves the hosted store holding everything it held, so
/// the version resumes. Moving off the leg that holds them does not, and the
/// hole guard reports the loss rather than publishing a manifest naming blocks
/// the new destination will never serve.
#[test]
fn a_placement_changed_mid_upload_resumes_only_where_the_bytes_already_are() {
    let plaintext: Vec<u8> = (0..200u8).collect();
    let leaves = frame_version(&plaintext).0.len();
    assert!(
        leaves > 2,
        "a multi-leaf version, so the resume point is real"
    );

    // `(started under, resumed under, the version still publishes)`.
    for (before, after, survives) in [
        (PinMode::Dual, PinMode::Hosted, true),
        (PinMode::Dual, PinMode::Dual, true),
        (PinMode::External, PinMode::Hosted, false),
    ] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);
        let alice = world.device(b"alice");
        seed_settings(&world, &alice, &blocks, before);

        let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
        // The mark for leaf 2 never lands: the process died the instant after
        // that leaf uploaded and the two before it were released.
        alice
            .staging_store
            .inner()
            .interrupt_staged_write_family_after(UPLOAD_MARK_PREFIX, 2);
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &plaintext,
        )
        .expect("the write commits");
        let (root_cid, _) = staged_version(&alice);
        tick(&world, &engine, &mut tasks);
        assert_eq!(
            upload_mark(&alice),
            Some((root_cid, 2)),
            "{before:?}: two leaves left staging for the destinations of the day"
        );
        drop(engine);

        // The member changes their mind while the version is half-placed.
        seed_settings(&world, &alice, &blocks, after);
        let (engine, mut events_after, mut tasks) = boot(&world, &blocks, &alice, 43);
        tick(&world, &engine, &mut tasks);
        tick(&world, &engine, &mut tasks);

        let lost = content_lost(&mut events) || content_lost(&mut events_after);
        assert_eq!(
            !lost, survives,
            "{before:?} -> {after:?}: the verdict follows where the released bytes are"
        );
        if survives {
            drop(engine);
            assert_round_trips(&world, &blocks, "photo.bin", &plaintext);
        }
    }
}

/// An external placement puts no byte in the hosted store, so nothing the quota
/// endpoint could say bears on a hold under one. The hold clears without asking
/// — an unanswerable probe must not park the queue head on a question with no
/// answer to wait for.
#[test]
fn a_hold_under_an_external_placement_clears_without_a_quota_probe() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::External);
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    // The record head block still traverses the hosted ingress, so it is what
    // the account quota can refuse under an external placement.
    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("QUOTA_EXCEEDED")))));
    create(&mut engine, "photos");
    tick(&world, &engine, &mut tasks);
    assert!(
        block_on(engine.snapshot(ROOT))
            .expect("a snapshot")
            .blocked
            .is_some(),
        "the refused head block held the op"
    );

    blocks.accept_uploads();
    blocks.set_quota_down(true);
    let probes = || {
        alice
            .http
            .requests()
            .iter()
            .filter(|request| request.url.ends_with("/account/quota"))
            .count()
    };
    let before = probes();
    tick(&world, &engine, &mut tasks);

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    assert!(
        view.blocked.is_none(),
        "an unreachable quota endpoint never gates a placement it does not cover"
    );
    assert_eq!(
        probes(),
        before,
        "and the hold clears without asking a question it cannot use"
    );
    assert_eq!(
        published_names(&world.record_store, &blocks, ROOT),
        vec!["photos".to_owned()],
        "the head drained once the stale hold was gone"
    );
}

/// Dual runs both legs and only the hosted one can fail the op: an offline home
/// node must not stall every later mutation in the vault. The outcome is
/// reported per op rather than swallowed.
#[test]
fn a_dual_write_publishes_and_reports_the_leg_the_members_node_did_not_take() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::Dual);

    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.set_member_node_down(true);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);

    let photo = child_id(&engine, ROOT, "photo.bin");
    assert_eq!(
        published(&world.record_store, photo).0,
        1,
        "the hosted leg landed, so the version published"
    );
    assert!(
        !uploaded_cids(&alice).is_empty(),
        "the hosted leg took the bytes"
    );
    assert!(
        blocks.member_node_cids().is_empty(),
        "the offline node took none"
    );
    let emitted = events_so_far(&mut events);
    assert_eq!(
        emitted
            .iter()
            .filter(|event| matches!(
                event,
                Event::OpProgress {
                    op_id: Some(id),
                    phase: OpPhase::ExternalPinFailed,
                    ..
                } if *id == op_id
            ))
            .count(),
        1,
        "the partial outcome is reported once for the op, not once per block"
    );
    assert!(
        !emitted.iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::UploadFailed,
                ..
            }
        )),
        "a mirror that did not take the bytes is not a failed upload"
    );
    assert!(
        block_on(engine.snapshot(ROOT))
            .expect("a snapshot")
            .dead_letters
            .is_empty(),
        "and never a dead letter"
    );
}

/// A dual write whose home node is up mirrors every block, and the hosted leg
/// still holds the whole set.
#[test]
fn a_dual_write_places_the_same_block_set_on_both_legs() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::Dual);

    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);

    let photo = child_id(&engine, ROOT, "photo.bin");
    let mut registered = registered_content_cids(&alice, &write_name(photo));
    registered.sort();
    registered.dedup();
    assert!(!registered.is_empty(), "the version has blocks");
    let hosted = uploaded_cids(&alice);
    assert!(
        registered.iter().all(|cid| hosted.contains(cid)),
        "the hosted leg took every block"
    );
    assert_eq!(
        blocks.member_node_cids(),
        registered,
        "and the member's node holds the same addresses, under its own hashing"
    );
    assert!(
        !events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::ExternalPinFailed,
                ..
            }
        )),
        "both legs took it, so there is no partial outcome to report"
    );
}

/// One refusal from the member's node is a blip, not a verdict: the op spends
/// another of its attempts and the mirror ends up whole, with nothing to report.
#[test]
fn a_mirror_refusal_the_op_retries_past_leaves_nothing_to_report() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::Dual);

    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.set_member_node_refusals(1);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);

    let photo = child_id(&engine, ROOT, "photo.bin");
    let mut registered = registered_content_cids(&alice, &write_name(photo));
    registered.sort();
    registered.dedup();
    assert_eq!(
        blocks.member_node_cids(),
        registered,
        "the retry put the refused block on the member's node"
    );
    assert!(
        !events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::OpProgress {
                phase: OpPhase::ExternalPinFailed,
                ..
            }
        )),
        "a refusal the op recovered from is not a shortfall"
    );
}

/// `ExternalPinFailed` promises the version published and its content is
/// retrievable — only the member's own node is short of it. A pass whose
/// registration is still being refused has published nothing, so it has no such
/// promise to make yet.
#[test]
fn a_mirror_shortfall_is_reported_only_once_the_record_published() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::Dual);

    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.set_member_node_down(true);
    blocks.refuse_register(proxy_400());
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);

    let shortfalls = |events: &mut EventStream| {
        events_so_far(events)
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    Event::OpProgress {
                        op_id: Some(id),
                        phase: OpPhase::ExternalPinFailed,
                        ..
                    } if *id == op_id
                )
            })
            .count()
    };
    assert_eq!(
        shortfalls(&mut events),
        0,
        "the blocks went up, but no record names them yet"
    );

    blocks.accept_registrations();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published(&world.record_store, child_id(&engine, ROOT, "photo.bin")).0,
        1,
        "the retry published the version"
    );
    assert_eq!(
        shortfalls(&mut events),
        1,
        "and only now is the mirror's shortfall the member's to act on"
    );
}

/// The attempt budget is the op's, not each block's: a node that is simply down
/// refuses every block alike, and re-asking it once per block would stall the
/// whole pass behind one dead endpoint.
#[test]
fn a_dead_mirror_costs_the_op_a_bounded_number_of_attempts() {
    let plaintext: Vec<u8> = (0..200u8).collect();
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::Dual);

    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let before = alice.http.requests().len();
    blocks.set_member_node_down(true);
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &plaintext,
    )
    .expect("the write commits");
    tick(&world, &engine, &mut tasks);

    let attempts = alice.http.requests()[before..]
        .iter()
        .filter(|request| request.url.starts_with(MEMBER_NODE))
        .count();
    assert!(
        attempts > 1,
        "the mirror leg retried inside the op rather than giving up on one refusal"
    );
    assert!(
        attempts < frame_version(&plaintext).0.len(),
        "and stopped well short of asking a dead node once per block"
    );
}

/// The hosted leg charges the account the instant a block lands, and the only
/// evidence a cancel has to retire it by is the confirmed set. So no block may
/// reach the hosted store without entering that set first — including under
/// dual, where the mirror's retries put awaits between the two.
#[test]
fn a_cancel_while_the_mirror_retries_still_retires_the_hosted_blocks() {
    let plaintext: Vec<u8> = (0..200u8).collect();
    for polls in 1..14 {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);
        let alice = world.device(b"alice");
        seed_settings(&world, &alice, &blocks, PinMode::Dual);

        let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
        // A mirror that refuses every attempt is what puts the cancel window
        // between the hosted upload and the end of the block.
        blocks.set_member_node_down(true);
        let op_id = write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &plaintext,
        )
        .expect("the write commits");
        let version: Vec<String> = queued_version(&alice, op_id)
            .iter()
            .map(|cid| encode_content_cid_str(cid))
            .collect();

        world.scheduler.advance(engine.profile().poll_cadence);
        for _ in 0..polls {
            poll_tasks_once(&mut tasks);
        }
        if block_on(engine.command(Command::CancelUpload { op_id })).is_err() {
            // Past publish entry, where a cancel is refused by design.
            continue;
        }
        poll_tasks_until_parked(&mut tasks);

        let retired: Vec<String> = retire_batches(&alice).into_iter().flatten().collect();
        for cid in uploaded_cids(&alice)
            .iter()
            .filter(|cid| version.contains(cid))
        {
            assert!(
                retired.contains(cid),
                "polls {polls}: the hosted store took {cid} and the cancel left it charged"
            );
        }
    }
}

/// A dual write's mark may name the mirror only where the mirror actually took
/// the bytes. Otherwise an external-only session resuming that version reads
/// blocks it never received as progress, skips them, and publishes a manifest
/// naming content the member's node cannot serve.
#[test]
fn a_dual_mark_names_the_mirror_only_where_the_mirror_took_the_bytes() {
    let plaintext: Vec<u8> = (0..200u8).collect();
    // `(the member's node was up for the dual session, the resume publishes)`.
    for (mirror_up, survives) in [(true, true), (false, false)] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);
        let alice = world.device(b"alice");
        seed_settings(&world, &alice, &blocks, PinMode::Dual);

        let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
        blocks.set_member_node_down(!mirror_up);
        // The process dies two leaves in, with those two already released.
        alice
            .staging_store
            .inner()
            .interrupt_staged_write_family_after(UPLOAD_MARK_PREFIX, 2);
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: "photo.bin".into(),
            },
            &plaintext,
        )
        .expect("the write commits");
        let (root_cid, _) = staged_version(&alice);
        tick(&world, &engine, &mut tasks);
        assert_eq!(
            upload_mark(&alice),
            Some((root_cid, 2)),
            "mirror up {mirror_up}: two leaves left staging either way"
        );
        drop(engine);

        // The member moves to external-only, and their node is reachable now.
        blocks.set_member_node_down(false);
        seed_settings(&world, &alice, &blocks, PinMode::External);
        let (engine, mut events_after, mut tasks) = boot(&world, &blocks, &alice, 43);
        tick(&world, &engine, &mut tasks);
        tick(&world, &engine, &mut tasks);

        let lost = content_lost(&mut events) || content_lost(&mut events_after);
        assert_eq!(
            !lost, survives,
            "mirror up {mirror_up}: the resume follows whether that node holds the released leaves"
        );
    }
}

/// The pre-flight's whole point: a hosted write the account cannot admit is
/// refused before the version is sealed and staged, not after a whole upload's
/// worth of work at the drain.
#[test]
fn a_hosted_write_over_quota_is_refused_at_command_time() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    blocks.set_quota(900, 1_000);

    let refused = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        200,
    ))
    .expect_err("the account cannot admit it");
    assert!(
        matches!(
            refused,
            EngineError::OverBudget {
                cause: OverBudgetCause::AccountQuota,
                available: 100,
                ..
            }
        ),
        "the refusal names the account quota and the room left: {refused:?}"
    );
    assert!(
        block_on(alice.staging_store.queued_ops())
            .expect("the queue reads")
            .is_empty(),
        "nothing was staged or journaled"
    );
    assert!(
        uploaded_cids(&alice).is_empty(),
        "and no byte was offered to the ingress"
    );
}

/// The account's server-side flag is reconciled to the vaulted mode, which is
/// the source of truth — the flag is an accounting display, never the gate.
#[test]
fn the_session_reconciles_the_accounts_byo_flag_to_the_vaulted_mode() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::External);
    assert!(
        !blocks.advisory(),
        "the account starts classified as hosted"
    );

    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    write_photo(&mut engine, "photo.bin");
    assert!(
        blocks.advisory(),
        "an external mode moved the account onto advisory accounting"
    );
    assert_eq!(byo_toggles(&alice), 1, "and only while the two disagreed");

    // The mode is fixed for the session, so no later write re-derives it.
    write_photo(&mut engine, "photo2.bin");
    assert_eq!(byo_toggles(&alice), 1, "at most once a session");

    // A second device on the same settings finds the flag already right.
    let bob = world.device(b"alice-second-device");
    let (mut engine_b, _events, _tasks) = boot(&world, &blocks, &bob, 43);
    write_photo(&mut engine_b, "photo3.bin");
    assert_eq!(byo_toggles(&bob), 0, "nothing to reconcile once they agree");
}

/// Ticks past the settings re-check interval, so a pass runs one re-decide.
fn tick_past_the_settings_recheck(
    world: &FakeWorld,
    engine: &Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) {
    let profile = *engine.profile();
    let passes = profile
        .settings_recheck_interval
        .div_duration_f64(profile.poll_cadence)
        .ceil() as usize;
    for _ in 0..=passes {
        tick(world, engine, tasks);
    }
}

/// The version blocks one node published, sorted and deduped — the set a
/// placement assertion compares a destination against.
fn version_blocks(device: &FakeDevice, engine: &Engine<FakeSeamTypes>, name: &str) -> Vec<String> {
    let node = child_id(engine, ROOT, name);
    let mut cids = registered_content_cids(device, &write_name(node));
    cids.sort();
    cids.dedup();
    assert!(!cids.is_empty(), "{name} registered its version's blocks");
    cids
}

/// A member who moves their bytes off a provider must stop feeding it inside a
/// bounded window, not at the next process start. A desktop mount stays up for
/// days: a session that never re-decides keeps placing every later block on the
/// endpoint the member revoked, and keeps presenting the withdrawn credential
/// to it.
#[test]
fn a_running_session_re_decides_its_placement_from_the_live_settings_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::External);

    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    write_photo(&mut engine, "photo.bin");
    tick(&world, &engine, &mut tasks);
    let first = version_blocks(&alice, &engine, "photo.bin");
    assert_eq!(
        blocks.member_node_cids(),
        first,
        "the first version went to the member's own node"
    );
    let hosted = uploaded_cids(&alice);
    assert!(
        first.iter().all(|cid| !hosted.contains(cid)),
        "and not one byte of it to the hosted store"
    );
    assert!(blocks.advisory(), "the account follows the external mode");

    // The member switches the account to hosted from another device. This
    // session is never restarted.
    seed_settings(&world, &alice, &blocks, PinMode::Hosted);
    tick_past_the_settings_recheck(&world, &engine, &mut tasks);

    write_photo(&mut engine, "photo2.bin");
    tick(&world, &engine, &mut tasks);
    let second = version_blocks(&alice, &engine, "photo2.bin");
    let hosted = uploaded_cids(&alice);
    assert!(
        second.iter().all(|cid| hosted.contains(cid)),
        "the next version takes the hosted path the live record names"
    );
    assert_eq!(
        blocks.member_node_cids(),
        first,
        "and the revoked provider receives nothing further"
    );
    assert!(
        !blocks.advisory(),
        "the re-decide re-armed the account flag reconcile, as a save does"
    );
}

/// A host holds the settings it read for as long as its surface is open, and it
/// states what a delete does from them. The tick must therefore report the
/// re-decide, or a tab keeps promising a bin the engine no longer keeps.
#[test]
fn a_settings_change_the_tick_adopts_is_reported_to_the_host() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_bin_retention(&world, &alice, &blocks, 30);

    let (engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    tick_past_the_settings_recheck(&world, &engine, &mut tasks);
    assert!(
        !reports_a_settings_change(&mut events),
        "the settings the start loaded are not a change",
    );

    // The member turns the bin off from another device.
    seed_bin_retention(&world, &alice, &blocks, 0);
    tick_past_the_settings_recheck(&world, &engine, &mut tasks);
    assert!(
        reports_a_settings_change(&mut events),
        "the adopted change reached the host",
    );

    tick_past_the_settings_recheck(&world, &engine, &mut tasks);
    assert!(
        !reports_a_settings_change(&mut events),
        "and a re-decide that adopted the same settings costs the host no read",
    );
}

/// Publishes settings that differ only in the owner's bin retention.
fn seed_bin_retention(world: &FakeWorld, device: &FakeDevice, blocks: &Blocks, days: u32) {
    seed_vault_settings(
        world,
        device,
        blocks,
        &VaultSettings {
            pin_mode: PinMode::Hosted,
            byo: Some(member_node(ByoKind::Kubo)),
            retention: RetentionPolicy::KeepAll,
            bin_retention_days: days,
        },
    );
}

fn reports_a_settings_change(events: &mut EventStream) -> bool {
    events_so_far(events)
        .iter()
        .any(|event| matches!(event, Event::VaultSettingsChanged))
}

/// The once-a-session guard latches on the reconcile *landing*, not on the
/// attempt. The hosted ingress rejects a BYO account, so a flag left disagreeing
/// by one transient PATCH failure would fail every hosted upload the session
/// makes until the process restarts.
#[test]
fn a_byo_reconcile_that_did_not_land_is_retried_by_the_next_write() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    // A published record, so the hosted placement is the member's own — an
    // assumed one latches nothing (blueprint/engine.md "Settings-load policy").
    seed_settings(&world, &alice, &blocks, PinMode::Hosted);
    // The account carries the flag an external session set; this one is hosted.
    blocks.set_advisory(true);
    blocks.set_byo_down(true);

    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    write_photo(&mut engine, "photo.bin");
    assert_eq!(byo_toggles(&alice), 1, "the session tried to reconcile");
    assert!(
        blocks.advisory(),
        "and the account still disagrees with the vaulted mode"
    );

    blocks.set_byo_down(false);
    write_photo(&mut engine, "photo2.bin");
    assert_eq!(byo_toggles(&alice), 2, "so the next write tries again");
    assert!(!blocks.advisory(), "and this one landed");

    write_photo(&mut engine, "photo3.bin");
    assert_eq!(
        byo_toggles(&alice),
        2,
        "a landed reconcile closes the window for good"
    );
}

/// A settings load that cannot authenticate the member's choice refuses the
/// write rather than placing it on the hosted default — the widening that
/// blueprint/engine.md's settings-load policy exists to prevent.
#[test]
fn a_withheld_settings_record_refuses_the_write_instead_of_widening_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    // A durable floor for the settings name and no record to meet it: this
    // device adopted one before, so its absence now is suppression.
    block_on(
        alice
            .floors(&SECRET)
            .raise_sequence_floor(settings_name(&SECRET).as_str().as_bytes(), 3),
    )
    .expect("the floor raises");

    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    let refused = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        200,
    ))
    .expect_err("no placement could be authenticated");
    assert!(
        matches!(
            refused,
            EngineError::NoPlacement {
                refusal: PlacementRefusal::SettingsUnavailable(DefaultsReason::Suppressed),
            }
        ),
        "the refusal says which rule bit: {refused:?}"
    );
    assert!(
        uploaded_cids(&alice).is_empty(),
        "and no byte went anywhere"
    );
}

/// Queue a content write on `alice`, then leave the engine: the op outlives the
/// session, so the next cold start drains it under whatever placement its own
/// settings load decides. Returns the op, its target, and the version's staged
/// manifest CID.
fn queue_a_write_and_leave(
    world: &FakeWorld,
    blocks: &Blocks,
    alice: &FakeDevice,
) -> (OpId, NodeId, Vec<u8>) {
    let (mut engine, _events, _tasks) = boot(world, blocks, alice, 42);
    let op_id = write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .expect("the write commits");
    let photo = child_id(&engine, ROOT, "photo.bin");
    let (root_cid, _) = staged_version(alice);
    (op_id, photo, root_cid)
}

/// Serve a settings record naming `external` with no provider — a placement
/// this build's own publisher refuses to mint (AGENTS.md rule 8), hand-sealed
/// past that guard because the reader still has to decide what to do with one
/// that arrives.
fn seed_settings_naming_no_provider(world: &FakeWorld, blocks: &Blocks) {
    use cipherbox_core::codec::{Map, Value, encode};

    let mut m = Map::new();
    m.insert(
        "binRetentionDays",
        Value::Unsigned(u64::from(DEFAULT_BIN_RETENTION_DAYS)),
    );
    m.insert("byo", Value::Null);
    m.insert("keepLatest", Value::Null);
    m.insert("pinMode", Value::Text("external".to_owned()));
    m.insert("revision", Value::Unsigned(1));
    let body = encode(&Value::Map(m)).expect("the body encodes");
    let block =
        seal_settings_record(&kdf::enc_subkey(&SECRET), &[0x5A; 32], &body).expect("the seal");
    let cid = blocks.put(block);
    let record = IpnsRecord::create_v2(
        &kdf::settings_ipns_keypair(&SECRET),
        format!("/ipfs/{cid}").as_bytes(),
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, settings_name(&SECRET).as_str(), record.clone());
    }
}

/// Ticks enough to spend the attempt budget several times over, so a head still
/// queued at the end is one no pass ever charged.
const PASSES_PAST_THE_BUDGET: usize = 12;

/// A placement refusal every re-read reaches again is the member's own settings
/// talking: charging it would spend the version's budget on a verdict no retry
/// moves, so the head keeps its place and its staging reservation until the
/// settings change, and the session says which rule it is waiting on.
#[test]
fn a_deterministic_placement_refusal_holds_the_queued_write_rather_than_charging_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (op_id, photo, root_cid) = queue_a_write_and_leave(&world, &blocks, &alice);

    seed_settings_naming_no_provider(&world, &blocks);
    let (engine, _events, mut tasks) = boot(&world, &blocks, &alice, 43);
    for _ in 0..PASSES_PAST_THE_BUDGET {
        tick(&world, &engine, &mut tasks);
    }

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    assert!(
        view.dead_letters.is_empty(),
        "a held head is not a failing one"
    );
    assert_eq!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .len(),
        1,
        "it keeps its place in the queue"
    );
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&root_cid),
        "and its staged version with it"
    );
    let hold = view.settings_hold.expect("the pass names what it waits on");
    assert_eq!(hold.op_id, op_id);
    assert_eq!(hold.node, photo);
    assert_eq!(
        hold.refusal.check(),
        "byo-provider-missing",
        "the rule that refused, never the settings it read"
    );
}

/// The other half of the same fork: a settings load that degraded has no member
/// action as its exit — a later tick may resolve the record — so the pass
/// retries the head uncharged and takes no hold, which a host would render as
/// "edit your settings" over a condition editing them does not clear.
#[test]
fn a_degraded_settings_load_retries_the_queued_write_and_takes_no_hold() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (_, _, root_cid) = queue_a_write_and_leave(&world, &blocks, &alice);

    // A durable floor for the settings name with no record to meet it: the
    // record is being withheld, not absent.
    block_on(
        alice
            .floors(&SECRET)
            .raise_sequence_floor(settings_name(&SECRET).as_str().as_bytes(), 3),
    )
    .expect("the floor raises");
    let (engine, _events, mut tasks) = boot(&world, &blocks, &alice, 43);
    for _ in 0..PASSES_PAST_THE_BUDGET {
        tick(&world, &engine, &mut tasks);
    }

    let view = block_on(engine.snapshot(ROOT)).expect("a snapshot");
    assert!(
        view.dead_letters.is_empty(),
        "an outage this pass could not resolve never spends the budget"
    );
    assert_eq!(
        view.settings_hold, None,
        "no settings change is what this head is waiting for"
    );
    assert_eq!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .len(),
        1,
        "the head stays queued for a pass that can place it"
    );
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&root_cid),
        "with its staged version intact"
    );
}

// ---------------------------------------------------------------------------
// Edit vs edit: the conditional-edit rule (blueprint/engine.md "Per-op rebase
// rules").
// ---------------------------------------------------------------------------

/// The three bodies one contested file goes through: what both devices read,
/// what the second one writes, and what the first one publishes over it.
fn contested_bodies() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        (0..200u8).collect(),
        (0..200u8).map(|byte| byte.wrapping_add(1)).collect(),
        (0..200u8).map(|byte| 255 - byte).collect(),
    )
}

/// A second write-capable device of the same account that has read the file, so
/// its edits anchor on the version it saw.
fn open_writer(
    world: &FakeWorld,
    blocks: &Blocks,
    node: NodeId,
    expected: &[u8],
) -> (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>) {
    let device = world.device(b"alice-second-device");
    let (engine, _events, tasks) = boot(world, blocks, &device, 7);
    assert_eq!(
        block_on(engine.read_content(node)).expect("the second device reads the head"),
        expected
    );
    (device, engine, tasks)
}

/// A file put in view is refreshed on the tick, off its own record.
///
/// A version publish authors one record — the file's — and a `ChildRef` mirrors
/// neither size nor mtime, so the parent's record does not move and no folder
/// refresh can repaint the file. Without the file leg an idle device reports a
/// reconciled tick over an indefinitely stale size.
#[test]
fn a_file_in_view_repaints_from_another_devices_version_on_the_tick() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let first: Vec<u8> = (0..120u8).collect();
    let second: Vec<u8> = (0..64u8).collect();
    let (engine_a, _events_a, mut tasks_a, node) = publish_clip(&world, &blocks, &first);
    let (_bob, mut engine_b, mut tasks_b) = open_writer(&world, &blocks, node, &first);

    write_file(&mut engine_b, version(node), &second).expect("the second device's write commits");
    tick(&world, &engine_b, &mut tasks_b);

    // Device A polls without the file in view: nothing it resolves carries the
    // new length.
    tick(&world, &engine_a, &mut tasks_a);
    assert_eq!(
        block_on(engine_a.view()).unwrap().attrs(node).unwrap().size,
        Some(first.len() as u64)
    );

    assert!(
        engine_a.note_focus_access(Some(node)),
        "a file no pass has refreshed is stale"
    );
    tick(&world, &engine_a, &mut tasks_a);
    assert_eq!(
        block_on(engine_a.view()).unwrap().attrs(node).unwrap().size,
        Some(second.len() as u64),
        "the file leg repainted the base off the file's own record"
    );
}

/// The on-access file queue is bounded: a host that stats a whole listing costs
/// the next tick a window's worth of resolves, never one per entry.
#[test]
fn the_on_access_file_queue_stops_admitting_past_its_ceiling() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    for i in 0..MAX_FOCUS_FILES + 8 {
        block_on(engine.command(Command::Create {
            parent: ROOT,
            name: format!("f{i}.bin"),
            kind: NodeKind::File,
        }))
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);

    let files: Vec<NodeId> = block_on(engine.view())
        .unwrap()
        .children(ROOT)
        .into_iter()
        .map(|child| child.id)
        .collect();
    assert_eq!(files.len(), MAX_FOCUS_FILES + 8);
    for file in &files {
        engine.note_focus_access(Some(*file));
    }

    // Each queued file costs the pass one cache-first resolve of its own name.
    let queued_names: BTreeSet<Vec<u8>> = files
        .iter()
        .map(|file| write_name(*file).as_str().as_bytes().to_vec())
        .collect();
    let refreshed = |device: &FakeDevice| {
        device
            .snapshot_cache
            .reads()
            .into_iter()
            .filter(|key| queued_names.contains(key))
            .count()
    };
    let before = refreshed(&alice);
    tick(&world, &engine, &mut tasks);
    let this_pass = refreshed(&alice) - before;
    assert!(this_pass > 0, "the pass ran the file leg at all");
    assert!(
        this_pass <= MAX_FOCUS_FILES,
        "the queue admits a bounded window, not the whole listing: {this_pass} resolves"
    );
}

/// Opening a folder is the whole trigger: a device that downloaded nothing
/// paints its listed rows off each child's own record on the next tick, and a
/// row whose record fails the gate paints nothing and is reported.
#[test]
fn a_folder_open_paints_the_rows_it_lists_and_refuses_a_bent_one() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks_a) = boot(&world, &blocks, &alice, 42);
    let served: Vec<u8> = (0..120u8).collect();
    for name in ["good.bin", "bent.bin"] {
        write_file(
            &mut engine_a,
            WriteTarget::NewFile {
                parent: ROOT,
                name: name.to_owned(),
            },
            &served,
        )
        .expect("the write commits");
    }
    tick(&world, &engine_a, &mut tasks_a);
    let good = child_id(&engine_a, ROOT, "good.bin");
    let bent = child_id(&engine_a, ROOT, "bent.bin");

    let bob = world.device(b"alice-second-device");
    let (engine_b, mut events_b, mut tasks_b) = boot(&world, &blocks, &bob, 7);
    tick(&world, &engine_b, &mut tasks_b);
    for node in [good, bent] {
        assert_eq!(
            block_on(engine_b.view()).unwrap().attrs(node).unwrap().size,
            None,
            "a ChildRef mirrors no size, so the listing alone paints none"
        );
    }

    // A record sealed for another node, published over the one the listing names.
    plant_record(
        &world.record_store,
        &blocks,
        bent,
        Planted {
            node_id: good.0,
            scope_id: SCOPE,
            read_key: read_key_of(good),
            body: &planted_body(),
        },
    );

    engine_b.note_focus_access(Some(ROOT));
    let mut expected = vec![good, bent];
    expected.sort();
    assert_eq!(
        engine_b.queued_focus_files(),
        expected,
        "the open folder puts every unprojected row on the file leg"
    );
    let _ = events_so_far(&mut events_b);
    tick(&world, &engine_b, &mut tasks_b);

    let painted = block_on(engine_b.view()).unwrap().attrs(good).unwrap();
    assert_eq!(painted.size, Some(served.len() as u64));
    assert!(painted.mtime.is_some(), "the mtime rides the same head");
    assert_eq!(painted.content_version, Some(1));
    assert_eq!(
        block_on(engine_b.view()).unwrap().attrs(bent).unwrap().size,
        None,
        "a refused record paints nothing; the row stays last-known-good"
    );
    assert_eq!(
        events_so_far(&mut events_b)
            .into_iter()
            .filter(|event| matches!(event, Event::AttributableAbuse { .. }))
            .count(),
        1,
        "fail-closed is not silent"
    );
}

/// A host with no kernel to answer opens a folder with `SetFocus` rather than
/// with the FUSE-op TTL check, so that arm queues the listing's unprojected rows
/// and runs the file leg over them. This is the path the web takes, and the one
/// the blank listing was reported on: a row paints within one resolve round trip
/// rather than a poll cadence later.
#[test]
fn a_set_focus_command_paints_the_folders_unprojected_rows() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let served: Vec<u8> = (0..48u8).collect();
    let (_engine_a, _events_a, _tasks_a, node) = publish_clip(&world, &blocks, &served);

    let bob = world.device(b"alice-second-device");
    let (mut engine_b, _events_b, mut tasks_b) = boot(&world, &blocks, &bob, 7);
    tick(&world, &engine_b, &mut tasks_b);
    assert_eq!(
        block_on(engine_b.view()).unwrap().attrs(node).unwrap().size,
        None,
        "the listing alone paints no length"
    );

    block_on(engine_b.command(Command::SetFocus { node: Some(ROOT) })).expect("the window opens");

    assert_eq!(
        block_on(engine_b.view()).unwrap().attrs(node).unwrap().size,
        Some(served.len() as u64),
        "the navigation itself paints the row, before any tick runs"
    );
    assert!(
        engine_b.queued_focus_files().is_empty(),
        "the pass attempted the row, so it leaves the queue"
    );
}

/// Re-opening a folder inside the staleness threshold renders the state already
/// held, so a host that navigates in a loop costs the record plane nothing.
///
/// The row here has published no version, so it projects no size however often a
/// pass resolves it. Only the staleness stamp the pass leaves can keep the
/// repeat visit off the record plane.
#[test]
fn a_repeat_set_focus_inside_the_threshold_resolves_no_file_again() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks_a) = boot(&world, &blocks, &alice, 42);
    block_on(engine_a.command(Command::Create {
        parent: ROOT,
        name: "unwritten.bin".to_owned(),
        kind: NodeKind::File,
    }))
    .expect("the create commits");
    tick(&world, &engine_a, &mut tasks_a);
    let node = child_id(&engine_a, ROOT, "unwritten.bin");

    let bob = world.device(b"alice-second-device");
    let (mut engine_b, _events_b, mut tasks_b) = boot(&world, &blocks, &bob, 7);
    tick(&world, &engine_b, &mut tasks_b);

    // A cache-first file resolve reads the row's own record name, so the reads
    // under that name count the resolves the file leg spent.
    let file_name = write_name(node).as_str().as_bytes().to_vec();
    let resolves = || {
        bob.snapshot_cache
            .reads()
            .into_iter()
            .filter(|key| *key == file_name)
            .count()
    };
    let before = resolves();
    block_on(engine_b.command(Command::SetFocus { node: Some(ROOT) })).expect("the window opens");
    let after_first = resolves();
    assert!(
        after_first > before,
        "the first navigation resolved the row it listed"
    );
    assert_eq!(
        block_on(engine_b.view()).unwrap().attrs(node).unwrap().size,
        None,
        "an unwritten row projects no size, so no size filter holds it back"
    );

    world
        .scheduler
        .advance(SyncTimingProfile::CI.stale_after / 2);
    block_on(engine_b.command(Command::SetFocus { node: Some(ROOT) })).expect("the window reopens");

    assert_eq!(
        resolves(),
        after_first,
        "the stamp the first pass left keeps the repeat visit off the record plane"
    );
}

/// A version another device published between the commit and the drain is not
/// superseded: the queued edit dead-letters with its own bytes preserved, and
/// the concurrent version stays the head every reader sees.
#[test]
fn an_edit_refuses_to_supersede_a_version_published_after_it_was_formed() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let (first, bobs, alices) = contested_bodies();
    let (mut engine_a, _events_a, mut tasks_a, node) = publish_clip(&world, &blocks, &first);
    let (bob, mut engine_b, mut tasks_b) = open_writer(&world, &blocks, node, &first);

    let op_id =
        write_file(&mut engine_b, version(node), &bobs).expect("the second device's write commits");
    let (root_cid, leaves) = staged_version(&bob);
    // The first device publishes over the version the queued edit was formed
    // against.
    write_file(&mut engine_a, version(node), &alices).expect("the first device's write commits");
    tick(&world, &engine_a, &mut tasks_a);

    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine_b, &mut tasks_b);

    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::BaseSuperseded
        }]
    );
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head still reads"),
        alices,
        "the concurrent version stands rather than being overwritten"
    );
    let after_drain = block_on(bob.staging_store.staged_keys()).unwrap();
    assert!(
        leaves
            .iter()
            .chain([&root_cid])
            .all(|cid| after_drain.contains(cid)),
        "the losing edit keeps its staged version — nothing is silently dropped"
    );
}

/// The verdict a dead letter carries is a claim about the member's bytes, so it
/// must be decided against them. Two halts, identical but for what their
/// version's upload mark covers: leaves the mark says reached a destination are
/// recoverable and the edit keeps its own reason, where leaves it says were
/// never handed off are gone, and a notice must not promise them.
///
/// The mark is what tells those apart, and it is readable here only because it
/// is keyed to the version rather than to whichever op last held the queue.
#[test]
fn a_losing_edits_verdict_is_decided_against_its_own_leaves() {
    for (uploaded, expected) in [
        (true, DeadLetterReason::BaseSuperseded),
        (false, DeadLetterReason::ContentUnrecoverable),
    ] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);
        let (first, bobs, alices) = contested_bodies();
        let (mut engine_a, _events_a, mut tasks_a, node) = publish_clip(&world, &blocks, &first);
        let (bob, mut engine_b, mut tasks_b) = open_writer(&world, &blocks, node, &first);

        let op_id = write_file(&mut engine_b, version(node), &bobs)
            .expect("the second device's write commits");
        let (root_cid, leaves) = staged_version(&bob);
        // Leaf zero left staging. Marked, it reached a destination and the
        // version is still assemblable; unmarked, those bytes are simply gone.
        let covered = if uploaded { leaves.len() } else { 0 };
        let mark = encode_upload_mark(&Placement::Hosted.destinations(), covered, leaves.len())
            .expect("in range");
        block_on(
            bob.staging_store
                .put_staged_bytes(&upload_mark_key(&root_cid), &mark),
        )
        .unwrap();
        // Leaf zero and the tail together: one absent leaf is a damaged store,
        // and the verdict takes both point reads before it destroys anything.
        for leaf in [&leaves[0], leaves.last().expect("a multi-leaf version")] {
            block_on(bob.staging_store.remove_staged_bytes(leaf)).unwrap();
        }

        write_file(&mut engine_a, version(node), &alices)
            .expect("the first device's write commits");
        tick(&world, &engine_a, &mut tasks_a);

        let (dead_letters, _) = tick_until_dead_lettered(&world, &engine_b, &mut tasks_b);
        assert_eq!(
            dead_letters,
            vec![DeadLetter {
                op_id,
                reason: expected
            }],
            "leaves uploaded: {uploaded}"
        );
    }
}

/// A desktop vault stages on the order of ten thousand keys, and the pass used
/// to enumerate them two and three times over for answers it could take once.
#[test]
fn a_drain_tick_enumerates_the_staged_key_set_once() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    let before = alice.staging_store.inner().key_listings();
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        alice.staging_store.inner().key_listings() - before,
        1,
        "a publishing tick lists once"
    );

    // And a tick that dead-letters, which used to pay a third enumeration for
    // the preserved set's byte accounting.
    blocks.refuse_register(registry_batch_refused());
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "refused.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    let before = alice.staging_store.inner().key_listings();
    let (_, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);
    assert_eq!(
        alice.staging_store.inner().key_listings() - before,
        passes as u64,
        "a dead-lettering tick lists once too"
    );
}

/// The preserved bounds are the device's, not the write path's. A budget cut
/// between one session and the next leaves the set over it with no write coming
/// to notice, so the store open is where it is enforced.
#[test]
fn a_shrunken_preserved_budget_is_enforced_at_the_next_store_open() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_register(proxy_400());

    let mut roots = Vec::new();
    for name in ["first.bin", "second.bin"] {
        write_file(
            &mut engine,
            WriteTarget::NewFile {
                parent: ROOT,
                name: name.into(),
            },
            &(0..200u8).collect::<Vec<u8>>(),
        )
        .unwrap();
        roots.push(staged_version(&alice).0);
        while block_on(engine.snapshot(ROOT)).unwrap().dead_letters.len() < roots.len() {
            tick(&world, &engine, &mut tasks);
        }
    }
    let staged = || block_on(alice.staging_store.staged_keys()).unwrap();
    assert!(
        roots.iter().all(|root| staged().contains(root)),
        "both losers are preserved under the budget they were parked at"
    );

    // Reopen the same store under a budget with no room, so only the newest
    // survivor can stand.
    drop(engine);
    let (mut reopened, _reopened_events) = Engine::new(
        alice.seam_set(),
        Box::new(SeededEntropy::new(42)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy {
            staging_budget_bytes: 0,
            ..StoragePolicy::CI
        },
        ApiBaseUrl::offline(),
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    );
    serve_http(&alice, &blocks, 400);
    block_on(reopened.start(secret())).expect("the second session cold-starts");

    assert!(
        !staged().contains(&roots[0]),
        "the oldest preserved version is cut back to the new budget at open, \
         before a single poll tick and with no dead letter written"
    );
    assert!(
        staged().contains(&roots[1]),
        "and the newest survivor stands, exactly as the write path would keep it"
    );
}

/// v1 capped a parked entry's age at thirty days. Without that bound a vault
/// that stays under the count and byte ceilings parks state nothing ever
/// reclaims, however long ago the member stopped caring.
#[test]
fn a_preserved_dead_letter_past_its_age_bound_is_purged_on_a_poll_tick() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_register(proxy_400());

    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "parked.bin".into(),
        },
        &(0..200u8).collect::<Vec<u8>>(),
    )
    .unwrap();
    let (root_cid, leaves) = staged_version(&alice);
    tick_until_dead_lettered(&world, &engine, &mut tasks);

    let staged = || block_on(alice.staging_store.staged_keys()).unwrap();
    tick(&world, &engine, &mut tasks);
    assert!(
        staged().contains(&root_cid),
        "inside the bound the version is held, so the member can still act on it"
    );

    // Time moves only where the test moves it: the purge is a decision about the
    // scheduler seam's clock, never the host's.
    world
        .scheduler
        .advance(engine.profile().preserved_dead_letter_ttl);
    tick(&world, &engine, &mut tasks);

    assert!(
        leaves
            .iter()
            .chain([&root_cid])
            .all(|cid| !staged().contains(cid)),
        "past it the entry is purged and its whole version leaves the budget"
    );
}

/// Two edits queued back to back follow each other, so the second inherits the
/// first one's fate: neither may land on a head that beat them both. An anchor
/// that counted versions instead of naming one would let the second through —
/// its count and the concurrent writer's are the same number.
#[test]
fn a_second_queued_edit_does_not_slip_past_the_writer_that_beat_the_first() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let (first, bobs, alices) = contested_bodies();
    let (mut engine_a, _events_a, mut tasks_a, node) = publish_clip(&world, &blocks, &first);
    let (_bob, mut engine_b, mut tasks_b) = open_writer(&world, &blocks, node, &first);

    let one = write_file(&mut engine_b, version(node), &bobs).expect("the first edit commits");
    let two = write_file(&mut engine_b, version(node), &first)
        .expect("the second edit commits on top of the first");
    write_file(&mut engine_a, version(node), &alices).expect("the first device's write commits");
    tick(&world, &engine_a, &mut tasks_a);

    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine_b, &mut tasks_b);
    // The pass stops at the first loser, so the second is reached on a later
    // tick; both must end the same way.
    let mut passes = 0;
    while block_on(engine_b.snapshot(ROOT))
        .unwrap()
        .dead_letters
        .len()
        < 2
    {
        tick(&world, &engine_b, &mut tasks_b);
        passes += 1;
        assert!(
            passes < 50,
            "the second loser must be reached in finite ticks"
        );
    }

    assert_eq!(dead_letters.len(), 1, "one loser per pass");
    assert_eq!(
        block_on(engine_b.snapshot(ROOT)).unwrap().dead_letters,
        vec![
            DeadLetter {
                op_id: one,
                reason: DeadLetterReason::BaseSuperseded
            },
            DeadLetter {
                op_id: two,
                reason: DeadLetterReason::BaseSuperseded
            },
        ]
    );
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head still reads"),
        alices,
        "the concurrent version stands"
    );
}

/// A draft held open across a refresh still refuses: the anchor is the
/// handle's, not the commit's (the web text editor's shape).
#[test]
fn an_edit_anchors_on_the_version_its_handle_opened_on() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let (first, bobs, alices) = contested_bodies();
    let (mut engine_a, _events_a, mut tasks_a, node) = publish_clip(&world, &blocks, &first);
    let (_bob, mut engine_b, mut tasks_b) = open_writer(&world, &blocks, node, &first);

    let handle = block_on(engine_b.begin_write(version(node), bobs.len() as u64))
        .expect("the handle opens against the version the caller read");

    // The other device publishes, and this one's own render advances past it
    // while the draft is still open.
    write_file(&mut engine_a, version(node), &alices).expect("the first device's write commits");
    tick(&world, &engine_a, &mut tasks_a);
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the refreshed head reads"),
        alices
    );

    for slice in bobs.chunks(7) {
        block_on(engine_b.push_chunk(handle, slice)).expect("the draft stages");
    }
    let op_id = block_on(engine_b.commit_write(handle)).expect("the draft commits");

    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine_b, &mut tasks_b);

    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::BaseSuperseded
        }]
    );
}

/// The window the handle's own anchor leaves open: a caller reads at one
/// version, a refresh advances this device's view past it, and only then does
/// the caller open its handle. The engine's derivation would call the newer
/// version the one the caller wrote against. The version the caller read is the
/// anchor when the caller names it.
#[test]
fn a_caller_supplied_version_anchors_the_write_the_caller_actually_read() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let (first, bobs, alices) = contested_bodies();
    let (mut engine_a, _events_a, mut tasks_a, node) = publish_clip(&world, &blocks, &first);
    let (_bob, mut engine_b, mut tasks_b) = open_writer(&world, &blocks, node, &first);

    // What the caller read, taken off the same projection a host renders.
    let read_at = block_on(engine_b.snapshot(ROOT))
        .unwrap()
        .children
        .into_iter()
        .find(|child| child.id == node)
        .and_then(|child| child.content_cid)
        .expect("the read projected a version");

    // The other device publishes and this device's own view advances past it,
    // all before the caller opens a handle for the bytes it read earlier.
    write_file(&mut engine_a, version(node), &alices).expect("the first device's write commits");
    tick(&world, &engine_a, &mut tasks_a);
    tick(&world, &engine_b, &mut tasks_b);
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the refreshed head reads"),
        alices
    );

    let op_id = write_file(
        &mut engine_b,
        WriteTarget::Version {
            node,
            expected_version: Some(read_at),
        },
        &bobs,
    )
    .expect("the write commits, and its fate is decided on the drain");

    let (dead_letters, _) = tick_until_dead_lettered(&world, &engine_b, &mut tasks_b);
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::BaseSuperseded
        }],
        "a write derived from a superseded version does not clobber the newer one"
    );
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head still reads"),
        alices,
        "the concurrent version stands"
    );
}

/// An anchor that is not a content CID can only ever park the write, and a
/// parked write spends a slot in a set that evicts oldest-first — so the shape
/// is refused where the caller can still act on the refusal.
#[test]
fn an_expected_version_that_is_not_a_content_cid_is_refused_at_the_handle() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let (first, _, _) = contested_bodies();
    let (mut engine, _events, _tasks, node) = publish_clip(&world, &blocks, &first);

    for bogus in [vec![], vec![0xAB; 4], vec![0xCD; 4096]] {
        assert_eq!(
            block_on(engine.begin_write(
                WriteTarget::Version {
                    node,
                    expected_version: Some(bogus.clone()),
                },
                8,
            )),
            Err(EngineError::MalformedInput {
                check: "expected-version-is-not-a-content-cid"
            }),
            "{} bytes is not a content CID",
            bogus.len()
        );
    }
}

/// A device that never read the file has no head to anchor on, so `beginWrite`
/// resolves one — before a byte is spent. The write then publishes like any
/// other rather than dead-lettering after a whole upload.
#[test]
fn an_edit_from_a_device_that_never_read_the_file_resolves_its_anchor() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let (first, bobs, _) = contested_bodies();
    let (_engine_a, _events_a, _tasks_a, node) = publish_clip(&world, &blocks, &first);

    let bob = world.device(b"alice-second-device");
    let (mut engine_b, _events_b, mut tasks_b) = boot(&world, &blocks, &bob, 7);
    write_file(&mut engine_b, version(node), &bobs)
        .expect("the write commits against the head it resolved");
    tick(&world, &engine_b, &mut tasks_b);

    assert!(
        block_on(engine_b.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "an anchored write is not a race"
    );
    assert_eq!(
        block_on(engine_b.read_content(node)).expect("the head reads"),
        bobs,
        "the version this device wrote is the head"
    );
}

/// The member picks "never put my bytes in CipherBox's store" and the save does
/// not land. The next cold start refuses the write rather than reading the
/// missing record as a first run.
#[test]
fn a_settings_save_that_never_landed_refuses_the_write_instead_of_widening_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");

    // No HTTP is scripted, so the head-block upload fails and nothing is ever
    // published at the settings name.
    let api = ApiClient::new(
        alice.http.clone(),
        alice.credential_store.clone(),
        String::new(),
    );
    let refused_save = block_on(publish_settings(
        &alice.record_store,
        &api,
        &alice.floors(&SECRET),
        &alice.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(9),
        &OrphanHeads::default(),
        &SECRET,
        &VaultSettings {
            pin_mode: PinMode::External,
            byo: Some(member_node(ByoKind::Kubo)),
            retention: RetentionPolicy::KeepAll,
            bin_retention_days: DEFAULT_BIN_RETENTION_DAYS,
        },
    ))
    .expect_err("the save does not reach the network");
    // Scoped to a publish failure: an earlier refusal would leave the mint
    // counter raised without ever attempting the head block this test counts.
    assert!(
        matches!(refused_save, SettingsPublishError::Publish(_)),
        "the head-block publish must be what failed, got {refused_save:?}"
    );
    // The refused save tried to upload its own head block; what the write adds
    // on top of that is the byte-destination property under test.
    let before = uploaded_cids(&alice).len();

    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    let refused = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        200,
    ))
    .expect_err("no placement could be authenticated");
    assert!(
        matches!(
            refused,
            EngineError::NoPlacement {
                refusal: PlacementRefusal::SettingsUnavailable(DefaultsReason::StrandedMint),
            }
        ),
        "an attempted save is a durable mark of a choice: {refused:?}"
    );
    assert_eq!(
        uploaded_cids(&alice).len(),
        before,
        "and no content byte went to the hosted store"
    );
}

// ---------------------------------------------------------------------------
// Prune: a shortened history at publish, the bytes back on the ledger's pass.
// ---------------------------------------------------------------------------

/// The versions a file's published record carries, newest first.
fn published_versions(
    records: &InMemoryRecordStore,
    blocks: &Blocks,
    file: NodeId,
) -> Vec<CoreVersion> {
    let (_, head_cid) = published(records, file);
    let envelope = decode_envelope(&blocks.get(&head_cid).expect("the head block")).unwrap();
    match open_read_body(&envelope, &read_key_of(file)).expect("opens under the read-seed key") {
        ReadBody::File { versions, .. } => versions,
        ReadBody::Folder { .. } => panic!("expected a file body"),
    }
}

/// A file under the root carrying `bodies.len()` versions, newest last.
fn file_with_history(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    bodies: &[Vec<u8>],
) -> NodeId {
    let (first, rest) = bodies.split_first().expect("at least one version");
    write_file(
        engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "clip.bin".into(),
        },
        first,
    )
    .expect("the create commits");
    tick(world, engine, tasks);
    let node = child_id(engine, ROOT, "clip.bin");
    for body in rest {
        write_file(engine, version(node), body).expect("the update commits");
        tick(world, engine, tasks);
    }
    node
}

/// Republish `file`'s record over a version list this engine would not author —
/// what a co-grantee holding the scope's write seed can put on the wire.
fn plant_versions(world: &FakeWorld, blocks: &Blocks, file: NodeId, versions: Vec<CoreVersion>) {
    plant_record(
        &world.record_store,
        blocks,
        file,
        Planted {
            node_id: file.0,
            scope_id: SCOPE,
            read_key: read_key_of(file),
            body: &ReadBody::File {
                created_at: 0,
                modified_at: 0,
                versions,
                unknown: PreservedFields::new(),
            },
        },
    );
}

/// One such version, naming `content_cid` for `plaintext_bytes` of plaintext.
fn planted_version(content_cid: &[u8], plaintext_bytes: u64) -> CoreVersion {
    CoreVersion::new(content_cid.to_vec(), [0u8; 32], plaintext_bytes, 0)
}

/// Queue a prune of `file` against its currently published sequence.
fn stage_prune(device: &FakeDevice, world: &FakeWorld, file: NodeId, keep_latest: u64) {
    let (sequence, _) = published(&world.record_store, file);
    stage(
        device,
        &Op::prune(
            file,
            NonZeroU64::new(keep_latest).expect("nonzero"),
            sequence,
            UnixMillis(9_000),
        ),
        None,
    );
}

#[test]
fn a_prune_publishes_a_shortened_history_and_reclaims_every_dropped_block() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let history = published_versions(&world.record_store, &blocks, file);
    assert_eq!(history.len(), 3, "three writes, three versions");
    let doomed: Vec<Vec<u8>> = history[1..]
        .iter()
        .map(|version| version.content_cid.clone())
        .collect();
    let head_cid = history[0].content_cid.clone();
    let retired_before = retire_targets(&alice).len();

    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);

    let kept = published_versions(&world.record_store, &blocks, file);
    assert_eq!(kept.len(), 1, "the record keeps exactly the newest version");
    assert_eq!(kept[0].content_cid, head_cid, "and it is the head");
    assert_eq!(
        block_on(engine.read_content(file)).expect("the head still reads"),
        bodies[2],
        "the surviving version's bytes are still retrievable"
    );

    // The registry saw every dropped block, each version's leaves ahead of the
    // root that names them.
    let retired = retired_since(&alice, retired_before);
    for root in &doomed {
        let root_str = encode_content_cid_str(root);
        let root_at = retired
            .iter()
            .position(|target| *target == root_str)
            .expect("the doomed root retires");
        let manifest = decode_root(&blocks.get(&root_str).expect("the root block")).unwrap();
        for leaf in &manifest.leaf_cids {
            let leaf_str = encode_content_cid_str(leaf);
            let leaf_at = retired
                .iter()
                .position(|target| *target == leaf_str)
                .expect("every leaf retires");
            assert!(
                leaf_at < root_at,
                "the expansion key must outlive everything it names"
            );
        }
    }
    assert!(
        !retired.contains(&encode_content_cid_str(&head_cid)),
        "the surviving version is never retired"
    );
    assert_eq!(
        engine.pending_reclaim_bytes(),
        0,
        "the ledger drained, so the vault owes nothing"
    );
}

/// The ledger is the only record of what a published prune owes, so an offline
/// registry must leave the debt whole and the figure visible.
#[test]
fn a_prune_whose_retire_is_refused_keeps_the_debt_until_a_later_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies: Vec<Vec<u8>> = (0..2u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let doomed = published_versions(&world.record_store, &blocks, file)[1]
        .content_cid
        .clone();

    blocks.refuse_retire(true);
    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_versions(&world.record_store, &blocks, file).len(),
        1,
        "the publish is not held behind the reclaim"
    );
    assert!(
        engine.pending_reclaim_bytes() > 0,
        "the vault still owes the dropped version"
    );

    // A later pass, with the registry back, re-expands from the still-pinned
    // root and clears the debt.
    blocks.refuse_retire(false);
    tick(&world, &engine, &mut tasks);
    assert!(
        retire_targets(&alice).contains(&encode_content_cid_str(&doomed)),
        "the resumed pass names the doomed root"
    );
    assert_eq!(
        engine.pending_reclaim_bytes(),
        0,
        "the debt clears on the registry's own answer"
    );
}

/// A prune that drops nothing publishes nothing: keeping at least as many
/// versions as exist must not spend a record sequence or a retire call.
#[test]
fn a_prune_that_keeps_the_whole_history_publishes_and_retires_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies = vec![(0..60u8).collect::<Vec<u8>>()];
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let (sequence, _) = published(&world.record_store, file);
    let retired_before = retire_targets(&alice).len();

    stage_prune(&alice, &world, file, 5);
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published(&world.record_store, file).0,
        sequence,
        "an empty plan authors no record"
    );
    assert_eq!(retire_targets(&alice).len(), retired_before);
    assert_eq!(engine.pending_reclaim_bytes(), 0);
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "a no-op prune is not a failure"
    );
}

/// Nothing on the wire forbids a version list naming one `contentCid` twice, so
/// a doomed version can share its bytes with a survivor. Retiring those bytes
/// would unpin the live file, so the whole prune is refused.
#[test]
fn a_prune_whose_doomed_version_shares_a_surviving_cid_is_refused() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies = vec![(0..60u8).collect::<Vec<u8>>()];
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let head = published_versions(&world.record_store, &blocks, file).remove(0);
    plant_record(
        &world.record_store,
        &blocks,
        file,
        Planted {
            node_id: file.0,
            scope_id: SCOPE,
            read_key: read_key_of(file),
            body: &ReadBody::File {
                created_at: 0,
                modified_at: 0,
                versions: vec![head.clone(), head],
                unknown: PreservedFields::new(),
            },
        },
    );
    let (sequence, _) = published(&world.record_store, file);
    let retired_before = retire_targets(&alice).len();

    stage_prune(&alice, &world, file, 1);
    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);

    assert_eq!(passes, 1, "a repeated history is refused on sight");
    assert_eq!(
        dead_letters
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::PayloadRefused]
    );
    assert_eq!(
        published(&world.record_store, file).0,
        sequence,
        "the history the refusal read is the history that stands"
    );
    assert_eq!(
        retire_targets(&alice).len(),
        retired_before,
        "and no retire names the CID a survivor still holds"
    );
    assert_eq!(engine.pending_reclaim_bytes(), 0);
}

/// A doomed root's link list is not this device's word for what that version
/// holds: in a shared scope a write-grantee authors versions of its own, and
/// their blocks register under the grantee's account until the owner syncs
/// (blueprint/api.md "Pin/name registry"). A root that content-addresses
/// correctly and whose link count matches the `size` it declares can therefore
/// name the owner's own live leaves, which the registry's `(account, cid)` pin
/// row would unpin under the owner's own token.
#[test]
fn a_doomed_root_naming_a_retained_versions_leaf_never_retires_that_leaf() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let body: Vec<u8> = (0..60u8).collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &[body.clone()]);
    let head = published_versions(&world.record_store, &blocks, file).remove(0);
    let live_leaves = leaves_of(&blocks, &head.content_cid);
    assert!(
        live_leaves.len() > 1,
        "a multi-chunk head is the normal case"
    );

    // The planted root links the owner's first live leaf plus one block only the
    // planted version names. Nothing about the block is malformed: it addresses
    // to its own CID and declares a `size` its link count matches.
    let chunk = ContentProfile::CI.chunk_size() as u64;
    let hostage = live_leaves[0].clone();
    let grantee_leaf = compute_cid(CONTENT_CID_CODEC, b"a block only the planted root names");
    let planted = assemble(
        &[hostage.clone(), grantee_leaf.clone()],
        2 * chunk,
        &ContentProfile::CI,
    )
    .expect("assembles");
    let planted_root = blocks.put(planted.root_block.clone());
    plant_versions(
        &world,
        &blocks,
        file,
        vec![
            head.clone(),
            planted_version(&planted.content_cid, 2 * chunk),
        ],
    );

    // With the registry down the debt stands unpaid, so the vault reports the
    // figure the prune quoted itself.
    blocks.refuse_retire(true);
    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        engine.pending_reclaim_bytes(),
        chunk + SEALED_LEAF_OVERHEAD + planted.root_block.len() as u64,
        "the quote counts the planted block and the root, never the hostage leaf"
    );

    blocks.refuse_retire(false);
    tick(&world, &engine, &mut tasks);

    let retired = retire_targets(&alice);
    assert!(
        !retired.contains(&encode_content_cid_str(&hostage)),
        "the leaf the retained head lives on is never retired"
    );
    assert!(
        retired.contains(&encode_content_cid_str(&grantee_leaf)),
        "the blocks the planted version really added still retire"
    );
    assert!(retired.contains(&planted_root), "and so does its own root");
    assert_eq!(
        block_on(engine.read_content(file)).expect("the head still reads"),
        body,
        "the retained version's bytes are still retrievable"
    );
    assert_eq!(
        engine.pending_reclaim_bytes(),
        0,
        "the debt clears on the registry's own answer"
    );
}

/// The same adversarial authoring lets two *doomed* roots name one leaf. A pin
/// row is keyed `(account, cid)`, so that leaf is a single row: charging it to
/// both debts would over-quote the reclaim and hand the registry one CID under
/// two entries.
#[test]
fn a_leaf_two_doomed_roots_share_is_charged_to_exactly_one_of_them() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let file = file_with_history(&world, &mut engine, &mut tasks, &[(0..60u8).collect()]);
    let head = published_versions(&world.record_store, &blocks, file).remove(0);

    // Two planted versions over one shared block, each with a block of its own.
    let chunk = ContentProfile::CI.chunk_size() as u64;
    let shared = compute_cid(CONTENT_CID_CODEC, b"a block both planted roots name");
    let plant = |only_mine: &[u8]| {
        let dag = assemble(
            &[shared.clone(), compute_cid(CONTENT_CID_CODEC, only_mine)],
            2 * chunk,
            &ContentProfile::CI,
        )
        .expect("assembles");
        blocks.put(dag.root_block.clone());
        dag
    };
    let (older, newer) = (plant(b"only the older"), plant(b"only the newer"));
    plant_versions(
        &world,
        &blocks,
        file,
        vec![
            head,
            planted_version(&newer.content_cid, 2 * chunk),
            planted_version(&older.content_cid, 2 * chunk),
        ],
    );

    blocks.refuse_retire(true);
    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);
    let leaf = chunk + SEALED_LEAF_OVERHEAD;
    assert_eq!(
        engine.pending_reclaim_bytes(),
        3 * leaf + (older.root_block.len() + newer.root_block.len()) as u64,
        "the shared block is quoted once, not once per doomed root"
    );

    let refused = retire_targets(&alice).len();
    blocks.refuse_retire(false);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, refused);
    let shared_cid = encode_content_cid_str(&shared);
    assert_eq!(
        retired.iter().filter(|cid| **cid == shared_cid).count(),
        1,
        "one pin row is named by one retire"
    );
    for dag in [&older, &newer] {
        assert!(
            retired.contains(&encode_content_cid_str(&dag.content_cid)),
            "both doomed roots still retire"
        );
    }
    assert_eq!(engine.pending_reclaim_bytes(), 0);
}

/// Nothing on the wire forbids one `contentCid` appearing twice in a version
/// list. The repeat is the same pin rows, so it owes nothing the first naming
/// does not already carry — and charging it again would leave an entry
/// protecting its own expansion key, which could never drain.
#[test]
fn a_root_a_history_names_twice_owes_one_debt_that_still_drains() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let file = file_with_history(&world, &mut engine, &mut tasks, &[(0..60u8).collect()]);
    let head = published_versions(&world.record_store, &blocks, file).remove(0);

    let chunk = ContentProfile::CI.chunk_size() as u64;
    let leaves: Vec<Vec<u8>> = [b"twice-a".as_slice(), b"twice-b".as_slice()]
        .iter()
        .map(|seed| compute_cid(CONTENT_CID_CODEC, seed))
        .collect();
    let planted = assemble(&leaves, 2 * chunk, &ContentProfile::CI).expect("assembles");
    blocks.put(planted.root_block.clone());
    let repeated = planted_version(&planted.content_cid, 2 * chunk);
    plant_versions(
        &world,
        &blocks,
        file,
        vec![head, repeated.clone(), repeated],
    );

    blocks.refuse_retire(true);
    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        engine.pending_reclaim_bytes(),
        2 * (chunk + SEALED_LEAF_OVERHEAD) + planted.root_block.len() as u64,
        "the repeat quotes nothing of its own"
    );

    blocks.refuse_retire(false);
    tick(&world, &engine, &mut tasks);

    let retired = retire_targets(&alice);
    for cid in leaves.iter().chain([&planted.content_cid]) {
        assert!(
            retired.contains(&encode_content_cid_str(cid)),
            "the one debt still names its whole expansion"
        );
    }
    assert_eq!(engine.pending_reclaim_bytes(), 0, "and clears");
}

/// A version whose root block no source will serve is authorable by anyone
/// holding the scope's write seed, and the prune has to fetch it to know what
/// the retire may name. An uncharged retry would let one such version hold the
/// FIFO head — and every op queued behind it — forever.
#[test]
fn a_prune_whose_root_no_source_serves_spends_its_budget_and_dead_letters() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let body: Vec<u8> = (0..60u8).collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &[body]);
    let head = published_versions(&world.record_store, &blocks, file).remove(0);
    let unserved = compute_cid(DAG_ROOT_CODEC, b"a root block no source ever stored");
    let planted_versions = vec![
        head,
        CoreVersion::new(
            unserved,
            [0u8; 32],
            ContentProfile::CI.chunk_size() as u64,
            0,
        ),
    ];
    plant_record(
        &world.record_store,
        &blocks,
        file,
        Planted {
            node_id: file.0,
            scope_id: SCOPE,
            read_key: read_key_of(file),
            body: &ReadBody::File {
                created_at: 0,
                modified_at: 0,
                versions: planted_versions.clone(),
                unknown: PreservedFields::new(),
            },
        },
    );
    let retired_before = retire_targets(&alice).len();

    stage_prune(&alice, &world, file, 1);
    let (dead_letters, passes) = tick_until_dead_lettered(&world, &engine, &mut tasks);

    assert!(passes > 1, "the budget is spent over several passes");
    assert_eq!(
        dead_letters
            .iter()
            .map(|letter| letter.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::AttemptsExhausted]
    );
    assert_eq!(
        retire_targets(&alice).len(),
        retired_before,
        "a prune that never expanded retires nothing"
    );
    assert_eq!(engine.pending_reclaim_bytes(), 0, "and journals no debt");
    assert_eq!(
        published_versions(&world.record_store, &blocks, file),
        planted_versions,
        "and leaves the history it could not expand standing, entry for entry"
    );
}

/// One device holding an owed retirement, the registry refusing it. The debt is
/// journaled, unsettled, and durable — the state a forget must not erase in
/// silence.
fn engine_owing_a_retirement(
    world: &FakeWorld,
    blocks: &Blocks,
    alice: &FakeDevice,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (mut engine, events, mut tasks) = boot(world, blocks, alice, 42);
    let bodies: Vec<Vec<u8>> = (0..2u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(world, &mut engine, &mut tasks, &bodies);

    blocks.refuse_retire(true);
    stage_prune(alice, world, file, 1);
    tick(world, &engine, &mut tasks);
    assert!(
        engine.pending_reclaim_bytes() > 0,
        "the prune journals a debt the refused retire leaves standing"
    );
    (engine, events, tasks)
}

/// The erase is the retire ledger's end of life: `clear()` drops entries the
/// ledger's own contract says only a settle removes, and the pinned bytes behind
/// them stay charged with no device left owing them. So the forget settles
/// first, and the debt is paid rather than dropped.
#[test]
fn a_forget_settles_the_owed_retirement_before_it_erases_the_store() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = engine_owing_a_retirement(&world, &blocks, &alice);

    blocks.refuse_retire(false);
    let mark = retire_targets(&alice).len();
    assert_eq!(
        command_while_ticking(&mut engine, Command::ForgetDevice, &mut tasks),
        Ok(CommandOutcome::Forgotten {
            unsettled_bytes: Some(0),
            unsettled_is_partial: false,
            stalls: 0
        }),
        "the pass ahead of the erase pays the whole debt"
    );
    assert!(
        !retired_since(&alice, mark).is_empty(),
        "and the registry heard the retire before the store was swept"
    );
    assert!(
        block_on(alice.staging_store.staged_keys())
            .expect("keys")
            .is_empty(),
        "the erase still runs"
    );
}

/// An offline forget still erases — a device that cannot reach the registry is
/// the one most likely to be forgotten, and holding the erase on the network
/// would be the worse failure. What the pass could not pay is reported instead
/// of dropped in silence.
#[test]
fn a_forget_the_registry_refuses_reports_the_residual_and_still_erases() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = engine_owing_a_retirement(&world, &blocks, &alice);

    let owed = engine.pending_reclaim_bytes();
    let outcome = command_while_ticking(&mut engine, Command::ForgetDevice, &mut tasks);

    let Ok(CommandOutcome::Forgotten {
        unsettled_bytes, ..
    }) = outcome
    else {
        panic!("a forget reports what it left owed: {outcome:?}");
    };
    assert_eq!(
        unsettled_bytes,
        Some(owed),
        "the bytes that stay charged reach the host"
    );
    assert!(
        block_on(alice.staging_store.staged_keys())
            .expect("keys")
            .is_empty(),
        "and the erase runs anyway"
    );
}

/// The staging key `StagingRetireLedger` journals `target`'s debt under, from
/// the ledger's own key derivation rather than a second copy of the layout.
fn retire_ledger_key(target: &[u8]) -> Vec<u8> {
    StagingRetireLedger::<InMemoryStagingStore>::key(
        &owner_tag(&kdf::enc_subkey(&SECRET)),
        &encode_content_cid_str(target),
    )
    .expect("a content CID keys an entry")
}

/// The leaf CIDs a published version's root block names.
fn leaves_of(blocks: &Blocks, content_cid: &[u8]) -> Vec<Vec<u8>> {
    decode_root(
        &blocks
            .get(&encode_content_cid_str(content_cid))
            .expect("the root block"),
    )
    .expect("a root manifest")
    .leaf_cid_vecs()
}

/// Nothing readable names a dropped root once the shortened history is live, so
/// a debt journaled after that publish is one no later pass could reconstruct:
/// the ledger write goes first, and a store that refuses it must leave the
/// history it was read from standing.
#[test]
fn a_prune_whose_ledger_write_fails_leaves_the_history_standing_and_still_reclaims() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies: Vec<Vec<u8>> = (0..2u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let history = published_versions(&world.record_store, &blocks, file);
    let doomed = history[1].content_cid.clone();
    let retired_before = retire_targets(&alice).len();
    alice
        .staging_store
        .inner()
        .interrupt_staged_write_after(&retire_ledger_key(&doomed), 0);

    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_versions(&world.record_store, &blocks, file),
        history,
        "a debt the ledger would not take never shortens the history it was read from"
    );
    assert_eq!(
        retire_targets(&alice).len(),
        retired_before,
        "and nothing is retired against a history still on the wire"
    );

    // The injector was one-shot, so the retry journals, publishes, and reclaims
    // the very versions the first pass could not record.
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        published_versions(&world.record_store, &blocks, file).len(),
        1,
        "the retried prune shortens the history"
    );
    assert!(
        retire_targets(&alice).contains(&encode_content_cid_str(&doomed)),
        "and the debt the first pass could not journal is still collected"
    );
    assert_eq!(engine.pending_reclaim_bytes(), 0);
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "a store hiccup is not a terminal prune"
    );
}

/// The retire can run passes after the prune journaled it — a registry outage,
/// a device offline. A version adopted inside that window is live by the time
/// the retire runs, so the protected set is re-derived then rather than frozen
/// at the prune.
#[test]
fn a_version_adopted_after_the_prune_journaled_its_debt_is_protected_too() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies: Vec<Vec<u8>> = (0..2u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let history = published_versions(&world.record_store, &blocks, file);
    let doomed = history[1].content_cid.clone();
    let hostage = leaves_of(&blocks, &doomed).remove(0);

    blocks.refuse_retire(true);
    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);
    assert!(
        engine.pending_reclaim_bytes() > 0,
        "the debt is journaled and unpaid"
    );

    // Between the journal and the retire, a version naming one of the doomed
    // root's leaves is published at the file's name.
    let chunk = ContentProfile::CI.chunk_size() as u64;
    let adopted = assemble(
        &[
            hostage.clone(),
            compute_cid(CONTENT_CID_CODEC, b"a block only the adopted version names"),
        ],
        2 * chunk,
        &ContentProfile::CI,
    )
    .expect("assembles");
    blocks.put(adopted.root_block.clone());
    plant_versions(
        &world,
        &blocks,
        file,
        vec![planted_version(&adopted.content_cid, 2 * chunk)],
    );

    let refused = retire_targets(&alice).len();
    blocks.refuse_retire(false);
    tick(&world, &engine, &mut tasks);

    let retired = retired_since(&alice, refused);
    assert!(
        !retired.contains(&encode_content_cid_str(&hostage)),
        "the leaf the newly adopted version lives on is never retired"
    );
    assert!(
        retired.contains(&encode_content_cid_str(&doomed)),
        "the doomed root itself still retires"
    );
    assert_eq!(engine.pending_reclaim_bytes(), 0);
}

/// A version this device cannot expand is authorable by anyone holding the
/// scope's write seed. One sitting in the **retained** half of a plan bears on
/// what the retire may name, never on whether the history may shorten, so it
/// must not refuse the prune — the debt is journaled and waits.
#[test]
fn a_retained_version_this_device_cannot_expand_still_lets_the_prune_publish() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);

    let bodies: Vec<Vec<u8>> = (0..2u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(&world, &mut engine, &mut tasks, &bodies);
    let history = published_versions(&world.record_store, &blocks, file);
    let unserved = CoreVersion::new(
        compute_cid(
            DAG_ROOT_CODEC,
            b"a retained root block no source ever stored",
        ),
        [0u8; 32],
        ContentProfile::CI.chunk_size() as u64,
        0,
    );
    plant_versions(
        &world,
        &blocks,
        file,
        vec![unserved.clone(), history[0].clone(), history[1].clone()],
    );

    stage_prune(&alice, &world, file, 1);
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_versions(&world.record_store, &blocks, file),
        vec![unserved],
        "the head this device cannot expand does not refuse the shortening"
    );
    assert!(
        block_on(engine.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "and it does not dead-letter the prune"
    );
    assert!(
        engine.pending_reclaim_bytes() > 0,
        "the debt is journaled, and stands until the retire can prove what is live"
    );
    assert!(
        retire_targets(&alice).is_empty(),
        "a pass that cannot establish the live set names nothing"
    );
}

/// One file with two published versions, its newest-first history, and a
/// journaled debt against the older one that the registry refused — the shape
/// every stall below starts from.
fn debt_owed_on_a_pruned_version(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) -> (NodeId, Vec<CoreVersion>) {
    let bodies: Vec<Vec<u8>> = (0..2u8)
        .map(|version| (0..60u8).map(|byte| byte ^ version).collect())
        .collect();
    let file = file_with_history(world, engine, tasks, &bodies);
    let history = published_versions(&world.record_store, blocks, file);

    blocks.refuse_retire(true);
    stage_prune(device, world, file, 1);
    tick(world, engine, tasks);
    assert!(
        engine.pending_reclaim_bytes() > 0,
        "the debt is journaled and unpaid"
    );
    assert!(
        engine.reclaim_stalls().is_empty(),
        "a registry that answered nothing is self-clearing, not a stall"
    );
    blocks.refuse_retire(false);
    (file, history)
}

/// A debt whose owing node's published record still names the doomed root is one
/// whose shortening has not landed, so it retires nothing and prices at nothing.
/// The byte figure therefore reads exactly as an empty ledger does, and only the
/// stall tells the two apart — a retained version naming the root pins the debt
/// for as long as that version stands.
#[test]
fn a_reclaim_stall_names_the_debt_a_live_target_prices_at_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (file, history) =
        debt_owed_on_a_pruned_version(&world, &blocks, &alice, &mut engine, &mut tasks);
    let doomed = encode_content_cid_str(&history[1].content_cid);

    // A co-writer republishes the whole history, so the target the debt names is
    // live again at the node's own name.
    plant_versions(&world, &blocks, file, history.clone());
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        engine.reclaim_stalls(),
        vec![ReclaimStall {
            node: file.0,
            target: doomed.clone(),
            reason: ReclaimStallReason::TargetStillLive,
        }]
    );
    assert_eq!(
        engine.pending_reclaim_bytes(),
        0,
        "live content is not pending reclaim, which is what hides the debt"
    );
    assert!(
        !retire_targets(&alice).contains(&doomed),
        "and nothing a live record still names is unpinned"
    );

    // The shortening lands after all, and the stall clears with the debt.
    plant_versions(&world, &blocks, file, vec![history[0].clone()]);
    tick(&world, &engine, &mut tasks);

    assert!(engine.reclaim_stalls().is_empty());
    assert_eq!(engine.pending_reclaim_bytes(), 0);
    assert!(
        retire_targets(&alice).contains(&doomed),
        "the debt settles on the publish that dropped its target"
    );
}

/// A node whose record this pass cannot establish stands its debts down: a
/// partial live set unpins what it failed to read. The figure that stands in the
/// meantime is the ceiling the prune quoted, which is what a debt merely waiting
/// on the registry reports too.
#[test]
fn a_reclaim_stall_names_the_node_whose_record_the_pass_could_not_read() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (file, history) =
        debt_owed_on_a_pruned_version(&world, &blocks, &alice, &mut engine, &mut tasks);
    let doomed = encode_content_cid_str(&history[1].content_cid);

    let name = write_name(file);
    world.record_store.fail_get_for(name.as_str());
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        engine.reclaim_stalls(),
        vec![ReclaimStall {
            node: file.0,
            target: doomed.clone(),
            reason: ReclaimStallReason::NodeUnreadable,
        }]
    );
    assert!(
        engine.pending_reclaim_bytes() > 0,
        "the debt stands at the figure the prune quoted"
    );
    assert!(
        !retire_targets(&alice).contains(&doomed),
        "a pass that cannot establish the live set names nothing"
    );

    world.record_store.heal_get_for(name.as_str());
    tick(&world, &engine, &mut tasks);

    assert!(engine.reclaim_stalls().is_empty());
    assert_eq!(engine.pending_reclaim_bytes(), 0);
    assert!(
        retire_targets(&alice).contains(&doomed),
        "the debt settles on the pass that could read the record again"
    );
}

// ---------------------------------------------------------------------------
// Cold-starting onto a vault another device of the same account already
// published: the two legs of `start` that leave the session dark.
// ---------------------------------------------------------------------------

/// [`serve_http`], with the record-recovery route answering `record` for `name`
/// — the API cache that still knows a vault this device's own fan-out cannot
/// resolve yet.
fn serve_http_with_cached_record(
    device: &FakeDevice,
    blocks: &Blocks,
    calls: usize,
    name: &IpnsName,
    record: Vec<u8>,
) {
    let route = format!("/recovery/{}", name.as_str());
    for _ in 0..calls {
        let blocks = blocks.clone();
        let route = route.clone();
        let record = record.clone();
        device.http.enqueue_derived(move |request| {
            if request.url.ends_with(&route) {
                return Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: record,
                });
            }
            blocks.reply(request)
        });
    }
}

/// Provision a vault on `world` from one device and write `photos` into it — a
/// mounted desktop that has been running for a while. Returns the root name and
/// the record it published there.
fn a_mounted_device_publishes_a_vault(world: &FakeWorld, blocks: &Blocks) -> (IpnsName, Vec<u8>) {
    let mount = world.device(b"alice");
    serve_http(&mount, blocks, 64);
    let (mut engine, _events) = engine_on_api(&mount, 42);
    block_on(engine.start(secret())).expect("the mount provisions the first-run vault");
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
    }))
    .expect("a metadata create stages");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(world, &engine, &mut tasks);

    let root_name = vault_root_name(world);
    let published = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root_name.as_str())
        .expect("the mount published its root");
    (root_name, published)
}

/// A tab whose routing view already serves the mount's root record but not yet
/// the vault pointer naming it. The mint sights that root and confirms by adopt
/// — a sighting it discards — so the probe must leave the name's sequence floor
/// where it found it. A probe that burned it would make the session's first
/// resolve an equal-floor `Current`, which projects nothing and caches nothing,
/// and the tab would render an empty tree with no way back.
#[test]
fn a_tab_that_adopts_a_published_genesis_root_converges_on_that_devices_tree() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (root_name, published_root) = a_mounted_device_publishes_a_vault(&world, &blocks);

    // The tab's own routing view: the root record has propagated, the pointer
    // has not.
    let tab_world = FakeWorld::new();
    for endpoint in tab_world.record_store.endpoints() {
        tab_world
            .record_store
            .seed_record(&endpoint, root_name.as_str(), published_root.clone());
    }
    let tab = tab_world.device(b"alice-tab");
    serve_http(&tab, &blocks, 64);
    let (mut engine, _events) = engine_on_api(&tab, 43);

    block_on(engine.start(secret())).expect("the tab settles on the published root");
    assert!(
        engine.is_provisioned(),
        "the tab holds the write seed of the vault it adopted"
    );
    assert_eq!(
        sequence_at(&tab_world, &root_name),
        2,
        "the tab published no second genesis over the live root",
    );
    assert_eq!(
        block_on(
            tab.floors(&SECRET)
                .sequence_floor(root_name.as_str().as_bytes())
        )
        .expect("the floor store answers"),
        None,
        "the mint's discarded sighting left the root name's sequence floor unspent",
    );

    let mut tasks = tab_world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    tick(&tab_world, &engine, &mut tasks);

    let children = block_on(engine.view()).unwrap().children(ROOT);
    assert_eq!(children.len(), 1, "the tab converged on the mount's tree");
    assert_eq!(children[0].name, "photos");
    assert!(
        block_on(tab.snapshot_cache.get(root_name.as_str().as_bytes()))
            .unwrap()
            .is_some(),
        "the first resolve was the adopt that caches, not an equal-floor Current",
    );
    assert_eq!(
        block_on(
            tab.floors(&SECRET)
                .sequence_floor(root_name.as_str().as_bytes())
        )
        .expect("the floor store answers"),
        Some(2),
        "and that adopt is what spends the floor",
    );
}

/// The other leg: the tab's fan-out sees nothing at all, while the API's record
/// cache still knows the account's vault. The vacancy probe refuses the mint on
/// that answer — a verdict about the account, not about this device — so the
/// session must stay retryable and converge on the refresh a host already
/// drives, rather than render an empty tree forever.
#[test]
fn a_vault_only_the_api_cache_can_see_leaves_a_retryable_session_that_converges() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (root_name, published_root) = a_mounted_device_publishes_a_vault(&world, &blocks);
    let pointer_name = vault_pointer_name(&SECRET, 0);
    let published_pointer = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], pointer_name.as_str())
        .expect("the mount published its vault pointer");

    let tab_world = FakeWorld::new();
    let tab = tab_world.device(b"alice-tab");
    serve_http_with_cached_record(&tab, &blocks, 64, &pointer_name, published_pointer.clone());
    let (mut engine, mut events) = engine_on_api(&tab, 43);

    block_on(engine.start(secret()))
        .expect("a vault this pass cannot resolve is not a failed start");
    assert!(
        !engine.is_provisioned(),
        "nothing resolved, so nothing was deposited"
    );
    assert!(
        core::iter::from_fn(|| events.try_next()).any(|event| matches!(
            event,
            Event::VaultUnprovisioned {
                retryable: true,
                ..
            }
        )),
        "an account that has a vault this device cannot see is a stall, never a refusal",
    );

    // The routing tables catch up, and the refresh the host drives converges.
    for endpoint in tab_world.record_store.endpoints() {
        tab_world.record_store.seed_record(
            &endpoint,
            pointer_name.as_str(),
            published_pointer.clone(),
        );
        tab_world
            .record_store
            .seed_record(&endpoint, root_name.as_str(), published_root.clone());
    }
    block_on(engine.command(Command::ManualRefresh)).expect("the retry settles on that vault");

    assert!(
        engine.is_provisioned(),
        "the write path opened on the vault the account already had"
    );
    assert_eq!(
        sequence_at(&tab_world, &root_name),
        2,
        "the retry published no second genesis over the live root",
    );
    let children = block_on(engine.view()).unwrap().children(ROOT);
    assert_eq!(children.len(), 1, "the tab converged on the mount's tree");
    assert_eq!(children[0].name, "photos");
}

/// The scope root a restart finds a cut owed for. It is no scope this vault
/// holds, so the rotation refuses and the debt stays owed — which is the state
/// the assertions read.
const OWED_SCOPE_ROOT: NodeId = NodeId([0x9e; 16]);

/// The failure the durable debt closes: the op that owed the cut published and
/// left the queue, so nothing re-derives its trigger. A restarted session must
/// drive that cut on a pass whose queue is empty, and must say which scope
/// still owes one when it cannot land it.
#[test]
fn a_restart_drives_an_owed_scope_exit_cut_on_an_empty_queue() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");

    // Written by the session that owed the cut, which is gone.
    let enc_secret = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(77));
    let debt = scope_exit_debt_key(&enc_secret);
    let sealed = seal_owed_cuts(
        BookkeepingSeal::new(&enc_secret, &entropy),
        &BTreeSet::from([OWED_SCOPE_ROOT]),
    )
    .expect("the debt seals");
    block_on(alice.staging_store.put_staged_bytes(&debt, &sealed)).expect("the debt persists");

    let (engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    tick(&world, &engine, &mut tasks);

    assert!(
        events_so_far(&mut events).iter().any(|event| matches!(
            event,
            Event::ScopeExitCutOwed { scope_root, .. } if *scope_root == OWED_SCOPE_ROOT
        )),
        "the member is told which scope still owes a cut",
    );
    assert!(
        block_on(alice.staging_store.staged_bytes(&debt))
            .expect("the store answers")
            .is_some(),
        "and the debt stands until the cut lands",
    );
}
