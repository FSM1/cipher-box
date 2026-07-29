//! The write plane, joined end to end: every metadata op kind is staged,
//! drained, authored, published, self-adopted, and resolved back — first by the
//! device that wrote it, then by a second device of the same account that only
//! ever saw the network (#865, #866).
//!
//! Later write-plane slices extend this file rather than starting their own.

use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    ChildRef, NodeKind as CoreNodeKind, ReadBody, decode_envelope, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use zeroize::Zeroizing;

use cipherbox_engine::content::{DAG_ROOT_CODEC, GatewaySource};
use cipherbox_engine::facade::PendingClass;
use cipherbox_engine::net::author::{EnvelopeAuthoring, author_child_envelope};
use cipherbox_engine::seams::{
    BoxedTask, HttpRequest, HttpResponse, OpId, RecordTransport, SeamError, SeamResult,
    StagingStore, UnixMillis,
};
use cipherbox_engine::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
use cipherbox_engine::sync::{DRAINED_OP_MARK_KEY, StagedContent};
use cipherbox_engine::testkit::fakes::InMemoryRecordStore;
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    OwnerRootSpec, SeededEntropy, block_on, owner_root_fixture,
};
use cipherbox_engine::{
    Command, Engine, EventStream, GatewayConfig, LoginSecret, NodeId, NodeKind, Op, RecordSeal,
    StoragePolicy, SyncTimingProfile, stage_op,
};

const SECRET: [u8; 32] = [7u8; 32];
/// The all-zero bootstrap anchor `start` binds its cold-start scope to.
const SCOPE: [u8; 16] = [0u8; 16];
const ROOT: NodeId = NodeId(SCOPE);
/// The sole v2 re-point payload version (`facade::POINTER_PAYLOAD_VERSION`).
const POINTER_PAYLOAD_VERSION: u64 = 1;
const TTL_NANOS: u64 = 2_000_000_000;
const EOL: &str = "2099-01-01T00:00:00Z";

fn owner_identity() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&SECRET).expect("valid scalar")
}

// ---------------------------------------------------------------------------
// The block plane: one content-addressed store behind both the pin API and the
// gateway, so a block the engine uploads is a block it can later fetch.
// ---------------------------------------------------------------------------

/// A test hook on the upload path: given a head block about to be stored,
/// answer whether the upload is refused. Lets a test fail exactly one record's
/// publish — and interleave a concurrent writer at that instant.
type UploadHook = Box<dyn FnMut(&[u8]) -> bool + Send>;

#[derive(Clone, Default)]
struct Blocks {
    store: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    on_upload: Arc<Mutex<Option<UploadHook>>>,
}

impl Blocks {
    fn put(&self, block: Vec<u8>) -> String {
        let cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        self.store.lock().expect("lock").insert(cid.clone(), block);
        cid
    }

    fn get(&self, cid: &str) -> Option<Vec<u8>> {
        self.store.lock().expect("lock").get(cid).cloned()
    }

    /// Install the upload hook, replacing any previous one.
    fn refuse_upload(&self, hook: UploadHook) {
        *self.on_upload.lock().expect("lock") = Some(hook);
    }

    /// Answer one engine HTTP call: a content upload lands its bytes here and
    /// echoes their address, a registry call acks, and a gateway GET serves the
    /// block back. Enqueued as many times as the pass needs, so no test depends
    /// on the exact order the engine happens to make its calls in.
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
            if let Some(hook) = self.on_upload.lock().expect("lock").as_mut()
                && hook(&block)
            {
                return Err(SeamError::new("upload refused"));
            }
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
        match self.get(cid) {
            Some(block) => ok(block),
            None => Err(SeamError::new("no such block")),
        }
    }
}

/// Wire `device`'s scripted HTTP to the block plane for `calls` requests.
fn serve_http(device: &FakeDevice, blocks: &Blocks, calls: usize) {
    for _ in 0..calls {
        let blocks = blocks.clone();
        device
            .http
            .enqueue_derived(move |request| blocks.reply(request));
    }
}

// ---------------------------------------------------------------------------
// Account fixture: the owner vault pointer and the initial empty scope root.
// ---------------------------------------------------------------------------

/// Publish the account's initial state to the shared network: an empty owner
/// root at sequence 1 and the vault pointer naming it. Returns the root's
/// write-plane name.
fn seed_account(world: &FakeWorld, blocks: &Blocks) -> IpnsName {
    let fixture = owner_root_fixture(OwnerRootSpec {
        owner_identity: &owner_identity(),
        owner_enc: &kdf::enc_subkey(&SECRET).public(),
        scope_id: SCOPE,
        root_id: ROOT.0,
        children: Vec::new(),
        // At the read epoch, so the cold-seeded write floor opens the
        // owner-write-blob and the owner recovers its scope write seed — the
        // seed the drain derives every new node's name and signer from.
        owner_write_blob_epoch: Some(EPOCH),
    });
    blocks.put(fixture.head_block.clone());

    let root_signer = {
        let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0);
        kdf::ipns_keypair(write_seed.as_bytes())
    };
    let root_record = IpnsRecord::create_v2(
        &root_signer,
        format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();

    let pointer_block = seal_repoint(
        SessionRole::Owner,
        &mut SeededEntropy::new(0),
        kdf::pointer_read_key(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE).as_bytes(),
        POINTER_PAYLOAD_VERSION,
        &owner_identity(),
        &RepointObject {
            scope_id: SCOPE,
            current_root: fixture.name.clone(),
            write_epoch: EPOCH,
            min_read_epoch: EPOCH,
            prev_root: None,
        },
    )
    .expect("seal the re-point");
    let pointer_record = IpnsRecord::create_v2(
        &kdf::vault_pointer_index(&SECRET, 0),
        &pointer_block,
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    let pointer_name = vault_pointer_name(&SECRET, 0);

    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, fixture.name.as_str(), root_record.clone());
        world
            .record_store
            .seed_record(&endpoint, pointer_name.as_str(), pointer_record.clone());
    }
    fixture.name
}

fn engine_on(device: &FakeDevice, entropy_seed: u64) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(entropy_seed)),
        SyncTimingProfile::CI,
        StoragePolicy::CI,
        // The API base URL is empty, so `start` skips login: this suite exercises
        // the record plane, not the auth handshake.
        String::new(),
        GatewayConfig {
            accelerator: Some(GatewaySource {
                base_url: "https://gw.test".into(),
                bearer: None,
            }),
            public_fallbacks: Vec::new(),
        },
    )
}

fn secret() -> LoginSecret {
    LoginSecret::new(SECRET.to_vec())
}

/// Poll every spawned loop once with a no-op waker (the loops never yield
/// inside a pass over the synchronous fakes).
fn poll_each(tasks: &mut [BoxedTask]) -> Vec<Poll<()>> {
    let mut cx = Context::from_waker(Waker::noop());
    tasks.iter_mut().map(|t| t.as_mut().poll(&mut cx)).collect()
}

/// Run one resolve-tick interval, which is also one drain pass.
fn tick(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_each(tasks);
}

/// A cold-started engine on `device`, with both spawned loops parked at their
/// first sleep and the block plane wired for a whole scenario's worth of calls.
fn boot(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_http(device, blocks, 400);
    let (mut engine, events) = engine_on(device, entropy_seed);
    block_on(engine.start(secret())).expect("cold start adopts the owner root");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
    (engine, events, tasks)
}

// ---------------------------------------------------------------------------
// Record-plane inspection: what a node's published record actually carries.
// ---------------------------------------------------------------------------

/// A node's write-plane IPNS name (`writeSeed(writeScopeSeed, id)` → keypair).
fn write_name(node: NodeId) -> IpnsName {
    IpnsName::from_public_key(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes()).verifying_key(),
    )
}

/// A node's per-node read key (`nodeSeed(readScopeSeed, id)` → `readKey`).
fn read_key_of(node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(&READ_SCOPE_SEED, &node.0).as_bytes()).as_bytes()
}

/// The `(sequence, headCid)` of the record currently published under `node`'s
/// write-plane name, verified under that name.
fn published(world: &FakeWorld, node: NodeId) -> (u64, String) {
    let name = write_name(node);
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
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
fn published_children(world: &FakeWorld, blocks: &Blocks, node: NodeId) -> Vec<ChildRef> {
    let (_, head_cid) = published(world, node);
    let envelope =
        decode_envelope(&blocks.get(&head_cid).expect("the head block")).expect("decodes");
    match open_read_body(&envelope, &read_key_of(node)).expect("opens under the read-seed key") {
        ReadBody::Folder { children, .. } => children,
        ReadBody::File { .. } => panic!("expected a folder body"),
    }
}

/// The names a node's published folder body lists, sorted.
fn published_names(world: &FakeWorld, blocks: &Blocks, node: NodeId) -> Vec<String> {
    let mut names: Vec<String> = published_children(world, blocks, node)
        .into_iter()
        .map(|child| child.name)
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
        content: None,
    }))
    .expect("a metadata create stages");
    assert!(
        op_id.is_some(),
        "a staged op is addressable by its queue id"
    );

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks); // park both loops at their first sleep
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
    // queue cannot replay it (#860).
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
        content: None,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
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
        content: None,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
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
        content: None,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
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

/// The drain covers `Create { content: None }`, which is both kinds: a file
/// with no content yet is a metadata-only create exactly like a folder, and its
/// record is a file body with an empty version list.
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
        content: None,
    }))
    .unwrap();

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
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
        content: None,
    }))
    .unwrap();
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
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

/// An op the completion record already covers is restore residue: a data dir
/// whose queue predates its own high-water mark. It leaves the queue without
/// publishing, so a restored backup cannot re-apply mutations the user never
/// asked for again (#860).
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
        DRAINED_OP_MARK_KEY,
        &1u64.to_be_bytes(),
    ))
    .unwrap();

    let (mut engine, _events) = engine_on(&alice, 42);
    block_on(engine.start(secret())).unwrap();
    let op_id = block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "photos".into(),
        kind: NodeKind::Folder,
        content: None,
    }))
    .unwrap();
    assert_eq!(op_id, Some(OpId(1)), "the create reclaims the covered id");

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_each(&mut tasks);
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
    StagingStore::staged_bytes(&device.staging_store, DRAINED_OP_MARK_KEY)
        .await
        .expect("the staging store answers")
        .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("an 8-byte mark")))
}

// ---------------------------------------------------------------------------
// The four remaining op kinds (#866), each to a second device.
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
        content: None,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let node = child_id(&engine, ROOT, "photos");
    let (child_sequence, _) = published(&world, node);

    block_on(engine.command(Command::Rename {
        node,
        new_name: "pictures".into(),
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(published_names(&world, &blocks, ROOT), ["pictures"]);
    assert_eq!(
        published(&world, node).0,
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

/// A delete drops the parent's ref. The name itself is not retired here —
/// retire fires on abandonment only (#819 as amended by #824), which is #867's.
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
            content: None,
        }))
        .unwrap();
    }
    tick(&world, &engine, &mut tasks);
    let doomed = child_id(&engine, ROOT, "notes.txt");

    block_on(engine.command(Command::Delete { node: doomed })).unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(published_names(&world, &blocks, ROOT), ["photos"]);
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

    assert_eq!(published_names(&world, &blocks, photos), ["a.txt"]);
    assert_eq!(published_names(&world, &blocks, ROOT), ["photos"]);
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

/// `updateContent`'s metadata half: a file's own record carries its
/// `modifiedAt`, and its parent holds no size/mtime mirror to republish. The
/// facade cannot form this op until the content slice (#868), so it is staged
/// straight into the durable queue the drain reads.
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
        content: None,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let file = child_id(&engine, ROOT, "notes.txt");
    let (file_sequence, _) = published(&world, file);
    let (root_sequence, _) = published(&world, ROOT);

    const STAGED_ROOT: &[u8] = b"a staged version root";
    stage(
        &alice,
        &Op::update_content(
            file,
            StagedContent {
                root_cid: compute_cid(CONTENT_CID_CODEC, STAGED_ROOT),
                plaintext_size: 11,
            },
            file_sequence,
            UnixMillis(4_242),
        ),
        Some(STAGED_ROOT),
    );
    tick(&world, &engine, &mut tasks);

    let (sequence, head_cid) = published(&world, file);
    assert_eq!(
        sequence,
        file_sequence + 1,
        "the file's own record advanced"
    );
    assert_eq!(
        published(&world, ROOT).0,
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
        modified_at, 4_242,
        "the journaled authoring time, never a clock read at publish"
    );
    assert!(
        versions.is_empty(),
        "the version this op stages is the content slice's"
    );

    let bob = world.device(b"alice-second-device");
    let (engine_b, _events_b, _tasks_b) = boot(&world, &blocks, &bob, 7);
    assert_eq!(
        block_on(engine_b.view()).unwrap().children(ROOT).len(),
        1,
        "device B resolves a root the metadata write left alone"
    );
}

// ---------------------------------------------------------------------------
// The reference-ordering law (#819) and the dest-add compensation (#786).
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
        content: None,
    }))
    .unwrap();
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
    assert_eq!(published_names(&world, &blocks, ROOT), ["pictures"]);
    // The parent's ref resolves: no reference outlived its referent.
    let child = &published_children(&world, &blocks, ROOT)[0];
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
/// through the child envelope path rather than the root's (#887).
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
        content: None,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);
    let photos = child_id(&engine, ROOT, "photos");

    block_on(engine.command(Command::Create {
        parent: photos,
        name: "2026".into(),
        kind: NodeKind::Folder,
        content: None,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        block_on(StagingStore::queued_ops(&alice.staging_store))
            .unwrap()
            .is_empty(),
        "a deeper create no longer halts the drain"
    );
    assert_eq!(published_names(&world, &blocks, photos), ["2026"]);
    assert_eq!(
        published_names(&world, &blocks, ROOT),
        ["photos"],
        "a child write stops at the immediate parent"
    );
    let view = block_on(engine.snapshot(photos)).unwrap();
    assert_eq!(view.children.len(), 1);
    assert_eq!(view.children[0].name, "2026");
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
    blocks.refuse_upload(Box::new(|block| head_of(block) == Some(ROOT.0)));
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert!(
        published_children(&world, &blocks, photos).is_empty(),
        "the dest-add was compensated, not left as a dual link"
    );
    assert_eq!(
        published_names(&world, &blocks, ROOT),
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

/// The adversarial interleave at the compensation seam: a concurrent writer
/// lands a strictly-newer dest record between the dest-add and its undo. The
/// versioned compare-and-remove refuses to replay a stale copy over the winner
/// and re-derives the removal onto the record the winner published (#786).
#[test]
fn a_concurrent_dest_writer_is_re_derived_onto_never_clobbered() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    let (photos, moved) = seed_folder_and_file(&world, &mut engine, &mut tasks);

    let winner = ChildRef {
        id: [0xAA; 16],
        name: "winner.txt".into(),
        ipns_name: write_name(NodeId([0xAA; 16])).as_str().as_bytes().to_vec(),
        kind: CoreNodeKind::File,
        link_counter: 1,
        unknown: Vec::new(),
    };
    let records = world.record_store.clone();
    let plane = blocks.clone();
    blocks.refuse_upload(Box::new(move |block| {
        if head_of(block) != Some(ROOT.0) {
            return false;
        }
        // The instant our source-remove fails, another writer advances the dest.
        concurrent_add(&records, &plane, photos, winner.clone());
        true
    }));
    block_on(engine.command(Command::Relink {
        node: moved,
        new_parent: photos,
    }))
    .unwrap();
    tick(&world, &engine, &mut tasks);

    assert_eq!(
        published_names(&world, &blocks, photos),
        ["winner.txt"],
        "the winner's entry survived and our dest-add was undone"
    );
    assert_eq!(
        published_names(&world, &blocks, ROOT),
        ["a.txt", "photos"],
        "the source kept the child"
    );
}

// ---------------------------------------------------------------------------

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
        content: None,
    }))
    .unwrap();
    block_on(engine.command(Command::Create {
        parent: ROOT,
        name: "a.txt".into(),
        kind: NodeKind::File,
        content: None,
    }))
    .unwrap();
    tick(world, engine, tasks);
    (
        child_id(engine, ROOT, "photos"),
        child_id(engine, ROOT, "a.txt"),
    )
}

/// Stage an op straight into the durable queue, for a mutation the facade
/// cannot form yet.
fn stage(device: &FakeDevice, op: &Op, upload: Option<&[u8]>) {
    block_on(stage_op(
        &device.staging_store,
        &StoragePolicy::CI,
        RecordSeal {
            owner_enc_pub: kdf::enc_subkey(&SECRET).public(),
            ephemeral_scalar: Zeroizing::new([0x5A; 32]),
        },
        op,
        upload,
    ))
    .expect("the op queues");
}

/// Another writer publishes `folder`'s next record, adding `extra` on top of
/// whatever the folder currently carries.
fn concurrent_add(records: &InMemoryRecordStore, blocks: &Blocks, folder: NodeId, extra: ChildRef) {
    let name = write_name(folder);
    let current = records
        .record_at(&records.endpoints()[0], name.as_str())
        .expect("the dest is published");
    let verified = IpnsRecord::unmarshal(&current)
        .and_then(|record| record.verify(&name))
        .expect("verifies");
    let head_cid = core::str::from_utf8(&verified.value)
        .expect("utf8")
        .strip_prefix("/ipfs/")
        .expect("an /ipfs/ pointer");
    let envelope =
        decode_envelope(&blocks.get(head_cid).expect("the head block")).expect("decodes");
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
    blocks.put(head.block.clone());

    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &folder.0).as_bytes());
    let record = IpnsRecord::create_v2(
        &signer,
        format!("/ipfs/{}", head.cid).as_bytes(),
        verified.sequence + 1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    for endpoint in records.endpoints() {
        records.seed_record(&endpoint, name.as_str(), record.clone());
    }
}
