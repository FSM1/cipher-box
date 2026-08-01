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
use cipherbox_core::suite::ed25519::Ed25519Signer;
use zeroize::Zeroizing;

use cipherbox_engine::content::{DAG_ROOT_CODEC, GatewaySource, SealedChunk, decode_root};
use cipherbox_engine::facade::PendingClass;
use cipherbox_engine::net::author::{AuthoredHead, EnvelopeAuthoring, author_child_envelope};
use cipherbox_engine::net::{ChildAdopter, ResolveOutcome, resolve};
use cipherbox_engine::seams::{
    BoxedTask, HttpRequest, HttpResponse, OpId, RecordTransport, SeamError, SeamResult,
    StagingStore, UnixMillis,
};
use cipherbox_engine::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
use cipherbox_engine::sync::{
    DRAINED_OP_MARK_KEY, StagedContent, UPLOAD_MARK_KEY, record_content_root_cid,
};
use cipherbox_engine::testkit::fakes::InMemoryRecordStore;
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    OwnerRootSpec, SeededEntropy, block_on, frame_version as frame, owner_root_fixture,
};
use cipherbox_engine::{
    BlockProgress, Command, ContentProfile, DeadLetter, DeadLetterReason, Engine, EngineError,
    Event, EventStream, GatewayConfig, LoginSecret, NodeId, NodeKind, Op, OpPhase, RecordSeal,
    StoragePolicy, SyncTimingProfile, WriteTarget, stage_op,
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
/// answer with the reply to send instead of storing it, or `None` to let the
/// upload through. Lets a test fail exactly one record's publish — and
/// interleave a concurrent writer at that instant.
type UploadHook = Box<dyn FnMut(&[u8]) -> Option<SeamResult<HttpResponse>> + Send>;

/// The pin store is unreachable: a transport failure carrying no server verdict.
fn unreachable_upload() -> SeamResult<HttpResponse> {
    Err(SeamError::new("upload refused"))
}

/// A server 413, optionally carrying the `code` discriminator that tells the
/// account-quota gate apart from the transport cap (#848).
fn upload_413(code: Option<&str>) -> SeamResult<HttpResponse> {
    let code = code.map_or(String::new(), |code| format!(",\"code\":\"{code}\""));
    Ok(HttpResponse {
        status: 413,
        headers: Vec::new(),
        body: format!("{{\"statusCode\":413,\"message\":\"too large\"{code}}}").into_bytes(),
    })
}

/// The registry's batch bounds (blueprint/api.md): at most this many entries
/// per register batch, and this many `contentCids` per entry.
const REGISTER_BATCH_CAP: usize = 1000;

/// The registry's fail-closed answer to a batch past its bounds: a `400`,
/// never a truncated or partial registration (blueprint/api.md "Batch bounds").
fn register_reply(body: Option<&[u8]>) -> SeamResult<HttpResponse> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(body.expect("a register call carries a body"))
            .expect("a register body is a JSON array");
    let over_cap = entries.len() > REGISTER_BATCH_CAP
        || entries.iter().any(|entry| {
            entry["contentCids"]
                .as_array()
                .is_some_and(|cids| cids.len() > REGISTER_BATCH_CAP)
        });
    Ok(HttpResponse {
        status: if over_cap { 400 } else { 200 },
        headers: Vec::new(),
        body: if over_cap {
            br#"{"statusCode":400,"message":"contentCids must contain no more than 1000 elements"}"#
                .to_vec()
        } else {
            Vec::new()
        },
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

#[derive(Clone, Default)]
struct Blocks {
    store: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    on_upload: Arc<Mutex<Option<UploadHook>>>,
    /// What `GET /account/quota` reports, as `(usedBytes, limitBytes)`.
    quota: Arc<Mutex<Option<(u64, u64)>>>,
    /// A status every `POST /registry/register` answers with instead of acking.
    register_refusal: Arc<Mutex<Option<u16>>>,
}

impl Blocks {
    /// Index a block by its own content address. The content plane addresses
    /// roots under `dag-cbor` and leaves under `raw`, and the ingress carries no
    /// codec, so a block is served under either address a reader may ask for.
    fn put(&self, block: Vec<u8>) -> String {
        let root_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        let leaf_cid = encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, &block));
        let mut store = self.store.lock().expect("lock");
        store.insert(leaf_cid, block.clone());
        store.insert(root_cid.clone(), block);
        root_cid
    }

    /// Store an uploaded block under the address its caller declared, refusing
    /// one the bytes do not hash to under either content-plane codec — the
    /// ingress's put-and-compare (#906).
    fn put_declared(&self, declared: &str, block: Vec<u8>) {
        let raw = encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, &block));
        let root = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &block));
        assert!(
            declared == raw || declared == root,
            "upload declared an address it does not hash to"
        );
        self.store
            .lock()
            .expect("lock")
            .insert(declared.to_owned(), block);
    }

    fn get(&self, cid: &str) -> Option<Vec<u8>> {
        self.store.lock().expect("lock").get(cid).cloned()
    }

    /// Install the upload hook, replacing any previous one.
    fn refuse_upload(&self, hook: UploadHook) {
        *self.on_upload.lock().expect("lock") = Some(hook);
    }

    /// Let every upload through again.
    fn accept_uploads(&self) {
        *self.on_upload.lock().expect("lock") = None;
    }

    /// Script what the quota endpoint reports.
    fn set_quota(&self, used_bytes: u64, limit_bytes: u64) {
        *self.quota.lock().expect("lock") = Some((used_bytes, limit_bytes));
    }

    /// Answer every registration with `status` instead of acking.
    fn refuse_register(&self, status: u16) {
        *self.register_refusal.lock().expect("lock") = Some(status);
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
            let declared = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("X-Content-Cid"))
                .map(|(_, value)| value.clone())
                .expect("upload declares its CID");
            let block = request.body.clone().unwrap_or_default();
            if let Some(hook) = self.on_upload.lock().expect("lock").as_mut()
                && let Some(reply) = hook(&block)
            {
                return reply;
            }
            let size = block.len();
            // Mirror the API's fail-closed bind (#906): the block is stored —
            // and served back — only under the address the caller declared,
            // and only once those bytes really address to it.
            self.put_declared(&declared, block);
            return ok(format!("{{\"cid\":\"{declared}\",\"size\":{size}}}").into_bytes());
        }
        if url.ends_with("/account/quota") {
            let (used, limit) = self
                .quota
                .lock()
                .expect("lock")
                .expect("the test scripted a quota before the drain probed it");
            return ok(format!(
                "{{\"usedBytes\":{used},\"limitBytes\":{limit},\"advisory\":false}}"
            )
            .into_bytes());
        }
        if url.ends_with("/registry/register") {
            if let Some(status) = *self.register_refusal.lock().expect("lock") {
                return Ok(HttpResponse {
                    status,
                    headers: Vec::new(),
                    body: format!("{{\"statusCode\":{status},\"message\":\"refused\"}}")
                        .into_bytes(),
                });
            }
            return register_reply(request.body.as_deref());
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
        ContentProfile::CI,
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
    IpnsName::from_public_key(&write_signer(node).verifying_key())
}

/// A node's write-plane signer, from the same edge the name comes off.
fn write_signer(node: NodeId) -> Ed25519Signer {
    kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes())
}

/// A node's per-node read key (`nodeSeed(readScopeSeed, id)` → `readKey`).
fn read_key_of(node: NodeId) -> [u8; 32] {
    *kdf::read_key(kdf::node_seed(&READ_SCOPE_SEED, &node.0).as_bytes()).as_bytes()
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

/// The `contentCids` the device's last registration for `name` carried — what a
/// sub-EOL renewal will re-pin (#797).
fn registered_content_cids(device: &FakeDevice, name: &IpnsName) -> Vec<String> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/register"))
        .filter_map(|request| {
            serde_json::from_slice::<serde_json::Value>(request.body.as_deref()?).ok()
        })
        .filter_map(|body| body.as_array()?.first().cloned())
        .filter(|entry| entry["ipnsName"] == name.as_str())
        .filter_map(|entry| {
            Some(
                entry["contentCids"]
                    .as_array()?
                    .iter()
                    .filter_map(|cid| cid.as_str().map(str::to_owned))
                    .collect::<Vec<_>>(),
            )
        })
        .next_back()
        .unwrap_or_default()
}

/// Every registration entry the device sent for `name`, in wire order across
/// however many batches it took — the shape a chunked registration is asserted
/// on (#920).
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

/// Feed `plaintext` through a write handle in small slices, the way a host
/// slices a `File`, and commit it.
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
        vec![DRAINED_OP_MARK_KEY.to_vec(), UPLOAD_MARK_KEY.to_vec()],
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
        WriteTarget::Version { node },
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
/// keeps that list so a sub-EOL renewal re-pins the same content (#797).
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
/// splits across several entries under one name, so the registration the
/// register-first ordering blocks on is accepted and the version publishes
/// (#920). Unchunked, the batch is refused fail-closed and nothing is PUT.
#[test]
fn a_version_past_the_registration_cap_registers_in_chunks_and_publishes() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    // 1001 leaves at the CI framing, plus the root: one past the cap.
    let leaves = REGISTER_BATCH_CAP + 1;
    let plaintext: Vec<u8> = (0..leaves * 16).map(|byte| byte as u8).collect();

    let alice = world.device(b"alice");
    let (mut engine_a, _events_a, mut tasks) = boot(&world, &blocks, &alice, 42);
    // One HTTP reply per block, plus the metadata plane's own calls.
    serve_http(&alice, &blocks, 4 * leaves);
    write_file(
        &mut engine_a,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "big.bin".into(),
        },
        &plaintext,
    )
    .unwrap();
    tick(&world, &engine_a, &mut tasks);

    let node = child_id(&engine_a, ROOT, "big.bin");
    let entries = registration_entries(&alice, &write_name(node));
    let sizes: Vec<usize> = entries
        .iter()
        .map(|entry| entry["contentCids"].as_array().expect("contentCids").len())
        .collect();
    assert_eq!(
        sizes,
        vec![REGISTER_BATCH_CAP, 2],
        "the registration splits at the per-entry cap"
    );
    let heads: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry["headCid"].as_str())
        .collect();
    assert_eq!(
        heads.len(),
        1,
        "the head rides one entry; the rest carry content only"
    );
    assert!(
        entries[0]["headCid"].is_string(),
        "the head rides the first entry, so the name and its pointer land first"
    );

    let registered: Vec<String> = entries
        .iter()
        .flat_map(|entry| {
            entry["contentCids"]
                .as_array()
                .expect("contentCids")
                .iter()
                .map(|cid| cid.as_str().expect("a CID string").to_owned())
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        registered.len(),
        leaves + 1,
        "every block the version links still rides the registration exactly once"
    );
    assert!(
        registered.iter().all(|cid| blocks.get(cid).is_some()),
        "every registered CID names a block the provider holds"
    );
    assert!(
        block_on(engine_a.snapshot(ROOT))
            .unwrap()
            .dead_letters
            .is_empty(),
        "a chunked registration is accepted, so the op publishes"
    );
}

/// A registration the registry refuses is refused on every retry, and the queue
/// is strict FIFO — so the op dead-letters instead of holding the head and
/// re-registering every tick (#920).
#[test]
fn a_refused_registration_dead_letters_instead_of_holding_the_queue_head() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_register(400);
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
    assert_eq!(passes, 1, "a refused registration is permanent on sight");
    assert_eq!(
        dead_letters,
        vec![DeadLetter {
            op_id,
            reason: DeadLetterReason::PayloadRefused
        }]
    );
}

/// The `pushChunk` total is cross-checked against the `beginWrite` declaration:
/// a backing file truncated mid-read fails the commit rather than publishing a
/// short version as a success (#830).
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
/// its blocks: bytes no key opens are not the user's recoverable work (#818).
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
        vec![DRAINED_OP_MARK_KEY.to_vec()],
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
        let leaves = decode_root(&root_block).unwrap().leaf_cids;
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

/// The durable upload mark as [`UPLOAD_MARK_KEY`] holds it: the version root it
/// names and the leaf count it claims.
fn upload_mark(device: &FakeDevice) -> Option<(Vec<u8>, u32)> {
    let stored = block_on(device.staging_store.staged_bytes(UPLOAD_MARK_KEY)).unwrap()?;
    let (root, count) = stored.split_at(stored.len() - 4);
    Some((root.to_vec(), u32::from_be_bytes(count.try_into().unwrap())))
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
/// interrupted in turn, since the window is reachable on any of them (#924).
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
            .interrupt_staged_write_after(UPLOAD_MARK_KEY, interrupted as u64);
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
/// the transfer (#819), and re-removes it.
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
            vec![DRAINED_OP_MARK_KEY.to_vec(), UPLOAD_MARK_KEY.to_vec()],
            "the retry re-removes it, so the residue holds no staging budget"
        );
        assert_round_trips(&world, &blocks, "photo.bin", &plaintext);
    }
}

/// A release that is *reported done* and never persists is the other half of
/// the same crash: leaf 0 comes back from the dead behind a mark that later
/// leaves already advanced. Re-uploading it must not pull the mark back down
/// over the leaves between — those are released, so an uncovered one reads as
/// loss and the valve destroys the version. That is #924 with one extra step,
/// and it is reachable because `packages/client` flushes a staged write but
/// releases with a bare `removeEntry`.
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
    alice.staging_store.drop_staged_removal_after(&leaves[0], 0);

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
/// abandons nothing on one response (#916).
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

/// An over-quota refusal is a hold, not a failed attempt: the op and its
/// reservation stand until a probe finds room (#841), and the host reads it from
/// the snapshot rather than from a failure it cannot act on.
#[test]
fn an_over_quota_upload_holds_the_op_without_reporting_a_failure() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);

    let alice = world.device(b"alice");
    let (mut engine, mut events, mut tasks) = boot(&world, &blocks, &alice, 42);
    blocks.refuse_upload(Box::new(|_| Some(upload_413(Some("QUOTA_EXCEEDED")))));
    blocks.set_quota(1_000, 1_000);
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
/// unresolvable (#884).
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
    write_file(
        &mut engine,
        WriteTarget::Version { node: file },
        b"v2 bytes",
    )
    .unwrap();
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
/// `a_second_device_lists_below_the_scope_root_once_it_focuses_there`
/// (#895, #917).
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
        accelerator: Some(GatewaySource {
            base_url: "https://gw.test".into(),
            bearer: None,
        }),
        public_fallbacks: Vec::new(),
    }
    .into_gateway();
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
    let (engine_b, _events_b, tasks_b) = boot(&world, &blocks, &bob, 7);
    DeepCreate {
        world,
        blocks,
        bob,
        engine_b,
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
        carried_unknown: Vec::new(),
        carried_epoch_tag_unknown: Vec::new(),
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
        unknown: Vec::new(),
    }
}

/// The facade half of the deep create's round trip: a device that never
/// authored the subtree sets focus on the depth-1 parent and lists the depth-2
/// child out of its own rendered view — the assertion #895 could not make.
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
                    unknown: Vec::new(),
                },
            },
            "a record whose sealed body is a file",
        ),
    ] {
        plant_record(&world.record_store, &blocks, photos, planted);
        tick(&world, &engine_b, &mut tasks_b);
        assert_eq!(
            listed_names(&engine_b, photos),
            held,
            "{bent} never renders; last-known-good is pinned"
        );
    }
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

/// The compensation must restore what the dest-add vacated too: a destination
/// left holding neither the moved node nor the one it replaced has lost an
/// entry outright (#884).
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
/// over it (#786's rule, extended to the replace).
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
/// and re-derives the removal onto the record the winner published (#786).
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

/// #786's guarantee has to hold when the destination is the scope root — the
/// commonest move there is. The root is otherwise read from this device's own
/// cache, which could never show the concurrent writer the compare exists to
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
// abandonment retire (#867).
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
/// retirement misses spends account quota forever (#916).
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

/// Exhausting the budget on refusals raised **before** any record PUT is an
/// abandonment too: nothing can link the version, so it retires what its uploads
/// charged, exactly as a permanent refusal does (#916). The acked-PUT arm is the
/// opposite case and retires nothing.
#[test]
fn a_version_whose_upload_budget_runs_out_retires_every_block_it_uploaded() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    let (engine, mut tasks, version) = stage_a_second_version(&world, &blocks, &alice);

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
    assert_eq!(
        retire_targets(&alice),
        version,
        "an exhausted budget retires the same block set a permanent refusal does"
    );
}

/// The opposite arm: an acked PUT may already be resolvable at the name, so
/// exhausting the budget there retires nothing. Unpinning content a live record
/// still names is loss, where leaving the rows charged is only a leak (#916).
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
    write_file(&mut engine, WriteTarget::Version { node: file }, &next).unwrap();
    let version = block_on(async {
        let queued = device.staging_store.queued_ops().await.unwrap();
        let root_cid = record_content_root_cid(&queued[0].1).unwrap().unwrap();
        let root_block = device
            .staging_store
            .staged_bytes(&root_cid)
            .await
            .unwrap()
            .unwrap();
        core::iter::once(&root_cid)
            .chain(&decode_root(&root_block).unwrap().leaf_cids)
            .map(|cid| encode_content_cid_str(cid))
            .collect()
    });
    (engine, tasks, version)
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

// ---------------------------------------------------------------------------

/// A child ref under this account's write-name edge.
fn child_ref(id: [u8; 16], name: &str, kind: CoreNodeKind) -> ChildRef {
    ChildRef {
        id,
        name: name.into(),
        ipns_name: write_name(NodeId(id)).as_str().as_bytes().to_vec(),
        kind,
        link_counter: 1,
        unknown: Vec::new(),
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
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/content/upload"))
        .count()
}

/// Every target this device has asked the registry to retire, in order.
fn retire_targets(device: &FakeDevice) -> Vec<String> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/retire"))
        .flat_map(|request| {
            let body = request
                .body
                .as_deref()
                .expect("a retire call carries a body");
            serde_json::from_slice::<Vec<String>>(body).expect("a retire body is a name array")
        })
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
    let (sequence, _) = published(records, ROOT);
    let mut children = published_children(records, blocks, ROOT);
    children.push(extra);
    let fixture = owner_root_fixture(OwnerRootSpec {
        owner_identity: &owner_identity(),
        owner_enc: &kdf::enc_subkey(&SECRET).public(),
        scope_id: SCOPE,
        root_id: ROOT.0,
        children,
        owner_write_blob_epoch: Some(EPOCH),
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
