//! The write plane, joined end to end: every metadata op kind is staged,
//! drained, authored, published, self-adopted, and resolved back — first by the
//! device that wrote it, then by a second device of the same account that only
//! ever saw the network.
//!
//! Later write-plane slices extend this file rather than starting their own.

use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::seal::{
    ChildRef, NodeKind as CoreNodeKind, PreservedFields, ReadBody, decode_envelope, open_read_body,
};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use cipherbox_engine::api::REGISTRY_BATCH_REFUSED;
use cipherbox_engine::content::{
    ByoIpfsConfig, ByoKind, DAG_ROOT_CODEC, GatewaySource, PinMode, RetentionPolicy, SealedChunk,
    decode_root,
};
use cipherbox_engine::facade::PendingClass;
use cipherbox_engine::net::OrphanHeads;
use cipherbox_engine::net::author::{AuthoredHead, EnvelopeAuthoring, author_child_envelope};
use cipherbox_engine::net::{ChildAdopter, REGISTRY_BATCH_MAX, ResolveOutcome, resolve};
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, HttpRequest, HttpResponse, OpId, RecordTransport, SeamError, SeamResult,
    StagingStore, UnixMillis,
};
use cipherbox_engine::settings::{VaultSettings, publish_settings, settings_name};
use cipherbox_engine::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};
use cipherbox_engine::sync::{
    DRAINED_OP_MARK_PREFIX, PUBLISHED_OP_MARK_PREFIX, StagedContent, UPLOAD_MARK_KEY, op_mark_key,
    record_content_root_cid,
};
use cipherbox_engine::testkit::fakes::InMemoryRecordStore;
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH as EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    OwnerRootSpec, SeededEntropy, block_on, frame_version as frame, owner_root_fixture,
};
use cipherbox_engine::{
    ApiBaseUrl, ApiClient, BlockProgress, Command, ContentProfile, DeadLetter, DeadLetterReason,
    DefaultsReason, Engine, EngineError, Event, EventStream, GatewayConfig, LoginSecret,
    MAX_OPEN_STREAMS, NodeId, NodeKind, Op, OpPhase, OverBudgetCause, PlacementRefusal, RecordSeal,
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
/// account-quota gate apart from the transport cap.
fn upload_413(code: Option<&str>) -> SeamResult<HttpResponse> {
    let code = code.map_or(String::new(), |code| format!(",\"code\":\"{code}\""));
    Ok(HttpResponse {
        status: 413,
        headers: Vec::new(),
        body: format!("{{\"statusCode\":413,\"message\":\"too large\"{code}}}").into_bytes(),
    })
}

/// The registry's own 400 for a batch past its bounds: the `code` the batch
/// gate stamps, which is what the valve classifies on.
fn registry_batch_refused() -> Vec<u8> {
    format!(r#"{{"statusCode":400,"message":"over cap","code":"{REGISTRY_BATCH_REFUSED}"}}"#)
        .into_bytes()
}

/// A 400 answered for a registry it never reached, so it stamps no `code` —
/// [`proxy_413`]'s counterpart on the register path.
fn proxy_400() -> Vec<u8> {
    b"<html><body>400 Bad Request</body></html>".to_vec()
}

/// Ack a registration, refusing one past the registry's bounds fail-closed —
/// never truncated or partially applied (blueprint/api.md "Batch bounds").
fn register_reply(body: Option<&[u8]>) -> SeamResult<HttpResponse> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(body.expect("a register call carries a body"))
            .expect("a register body is a JSON array");
    let over_cap = entries.len() > REGISTRY_BATCH_MAX
        || entries.iter().any(|entry| {
            entry["contentCids"]
                .as_array()
                .is_some_and(|cids| cids.len() > REGISTRY_BATCH_MAX)
        });
    Ok(HttpResponse {
        status: if over_cap { 400 } else { 200 },
        headers: Vec::new(),
        body: if over_cap {
            registry_batch_refused()
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

/// The member's own IPFS node, as their vault settings name it.
const MEMBER_NODE: &str = "https://kubo.member.test";

/// The one file part out of a `multipart/form-data` body, framed against the
/// boundary the request's own `Content-Type` declares. Deliberately strict: the
/// point of the fake is to catch framing the real Kubo would reject.
fn multipart_file(request: &HttpRequest) -> Vec<u8> {
    let content_type = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, value)| value.clone())
        .expect("a multipart body declares its content type");
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("the content type names the boundary")
        .to_owned();
    let body = request.body.clone().expect("a block/put carries a body");
    let head = format!("--{boundary}\r\n");
    let tail = format!("\r\n--{boundary}--\r\n");
    let body = std::str::from_utf8(&body[..head.len()])
        .ok()
        .filter(|opening| *opening == head)
        .map(|_| &body[head.len()..])
        .expect("the body opens on the declared boundary");
    let body = body
        .strip_suffix(tail.as_bytes())
        .expect("the body closes on the declared boundary");
    // Past the part headers: the blank line that ends them is the file's start.
    let start = body
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the part headers end")
        + 4;
    body[start..].to_vec()
}

#[derive(Clone, Default)]
struct Blocks {
    store: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    on_upload: Arc<Mutex<Option<UploadHook>>>,
    /// What `GET /account/quota` reports, as `(usedBytes, limitBytes)`. Unset is
    /// an account with room, so only a test about the quota scripts one.
    quota: Arc<Mutex<Option<(u64, u64)>>>,
    /// The account's server-side BYO flag, which `GET /account/quota` reports as
    /// `advisory` and `PATCH /account/byo` moves.
    advisory_quota: Arc<AtomicBool>,
    /// The member's own node: what it holds, keyed by the address it stored each
    /// block under, and whether it can be reached at all.
    member_node: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    member_node_down: Arc<AtomicBool>,
    /// The 400 body every `POST /registry/register` answers with instead of
    /// acking.
    register_refusal: Arc<Mutex<Option<Vec<u8>>>>,
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
    /// ingress's put-and-compare.
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

    /// Answer every registration with a 400 carrying `body` instead of acking.
    /// Retirement keeps answering, so a pass can still clear what it orphaned.
    fn refuse_register(&self, body: Vec<u8>) {
        *self.register_refusal.lock().expect("lock") = Some(body);
    }

    /// Let every registration through again.
    fn accept_registrations(&self) {
        *self.register_refusal.lock().expect("lock") = None;
    }

    /// Answer the member's own Kubo node: store the block the `block/put` body
    /// carries under the address that node computes for it, and answer with that
    /// address — the same put-and-compare the hosted ingress runs, so a
    /// mis-framed body or a wrong codec shows up as a disagreeing address rather
    /// than passing silently.
    fn member_node_reply(&self, request: &HttpRequest) -> SeamResult<HttpResponse> {
        if self.member_node_down.load(Ordering::Relaxed) {
            return Err(SeamError::new("the member's node is offline"));
        }
        assert!(
            request.url.contains("mhtype=blake3&mhlen=32"),
            "a block/put must name the frozen content-plane hash: {}",
            request.url
        );
        let codec = if request.url.contains("cid-codec=raw") {
            CONTENT_CID_CODEC
        } else {
            assert!(request.url.contains("cid-codec=dag-cbor"), "a known codec");
            DAG_ROOT_CODEC
        };
        let block = multipart_file(request);
        let cid = encode_content_cid_str(&compute_cid(codec, &block));
        self.member_node
            .lock()
            .expect("lock")
            .insert(cid.clone(), block);
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: format!("{{\"Key\":\"{cid}\",\"Size\":0}}\n").into_bytes(),
        })
    }

    /// Every address the member's own node holds.
    fn member_node_cids(&self) -> Vec<String> {
        self.member_node
            .lock()
            .expect("lock")
            .keys()
            .cloned()
            .collect()
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
            // Mirror the API's fail-closed bind: the block is stored —
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
                .unwrap_or((0, u64::MAX / 2));
            let advisory = self.advisory_quota.load(Ordering::Relaxed);
            return ok(format!(
                "{{\"usedBytes\":{used},\"limitBytes\":{limit},\"advisory\":{advisory}}}"
            )
            .into_bytes());
        }
        if url.starts_with(MEMBER_NODE) {
            return self.member_node_reply(request);
        }
        if url.ends_with("/account/byo") {
            let enabled = serde_json::from_slice::<serde_json::Value>(
                request
                    .body
                    .as_deref()
                    .expect("a byo toggle carries a body"),
            )
            .expect("a byo body is JSON")["byo"]
                .as_bool()
                .expect("the toggle names a boolean");
            self.advisory_quota.store(enabled, Ordering::Relaxed);
            return ok(Vec::new());
        }
        if url.ends_with("/registry/register") {
            if let Some(body) = self.register_refusal.lock().expect("lock").clone() {
                return Ok(HttpResponse {
                    status: 400,
                    headers: Vec::new(),
                    body,
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
        child_scope_index: Vec::new(),
        parent_node_seed: None,
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
        // Offline: `start` skips login, because this suite exercises the record
        // plane, not the auth handshake.
        ApiBaseUrl::offline(),
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

/// A waker that only records that it fired — enough to tell a cooperative
/// yield (which wakes itself) from a parked sleep (which does not).
struct WokenFlag(Mutex<bool>);

impl std::task::Wake for WokenFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        *self.0.lock().expect("lock") = true;
    }
}

/// Poll every spawned loop until each is parked on a timer rather than on the
/// drain's block-boundary yield, and report the last round's verdicts.
fn poll_each(tasks: &mut [BoxedTask]) -> Vec<Poll<()>> {
    let flag = Arc::new(WokenFlag(Mutex::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    loop {
        *flag.0.lock().expect("lock") = false;
        let polls: Vec<_> = tasks.iter_mut().map(|t| t.as_mut().poll(&mut cx)).collect();
        if !*flag.0.lock().expect("lock") {
            return polls;
        }
    }
}

/// Poll every spawned loop exactly once, leaving a yielded drain mid-pass.
fn poll_once(tasks: &mut [BoxedTask]) {
    let mut cx = Context::from_waker(Waker::noop());
    for task in tasks.iter_mut() {
        let _ = task.as_mut().poll(&mut cx);
    }
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
        vec![drained_key(), mark_key(), UPLOAD_MARK_KEY.to_vec()],
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
    write_file(&mut engine_a, WriteTarget::Version { node }, &second).expect("the update commits");
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

    // A mark naming this very version and claiming more leaves than it has.
    let version = evict_leaf(&alice, |leaves| leaves / 2);
    let (root_cid, _) = staged_version(&alice);
    let mut corrupt = root_cid;
    corrupt.extend_from_slice(&u32::MAX.to_be_bytes());
    block_on(
        alice
            .staging_store
            .put_staged_bytes(UPLOAD_MARK_KEY, &corrupt),
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
            vec![drained_key(), mark_key(), UPLOAD_MARK_KEY.to_vec()],
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

/// A delete drops the parent's ref. The name itself is not retired here —
/// retire fires on abandonment only, which the failure-valve suite covers.
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

/// Epoch lag is sweep-pending staleness, not abuse (CONTEXT.md "Epoch lag"): a
/// focused folder the lazy wave has not swept yet rejects fail-closed, but the
/// owner's own rotation must not read as an attack on the host's abuse channel.
#[test]
fn an_epoch_lagged_focus_folder_rejects_without_raising_abuse() {
    let DeepCreate {
        world,
        bob,
        mut engine_b,
        mut events_b,
        mut tasks_b,
        photos,
        ..
    } = deep_create_seen_by_a_second_device();
    block_on(engine_b.command(Command::SetFocus { node: Some(photos) })).unwrap();
    assert_eq!(listed_names(&engine_b, photos), ["2026"]);

    // A rotation raised the scope's read-epoch floor past the epoch this folder
    // still publishes under.
    block_on(bob.floor_store.raise_epoch_floor(&SCOPE, EPOCH + 1)).unwrap();
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

/// Exhausting the budget on refusals raised **before** any record PUT is an
/// abandonment too: nothing can link the version, so it retires what its uploads
/// charged, exactly as a permanent refusal does. The acked-PUT arm is the
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
        poll_once(&mut tasks);
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
        poll_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "the cancel must land mid-transfer, not before it started"
    );

    block_on(engine.command(Command::CancelUpload { op_id })).expect("the upload is cancellable");
    poll_each(&mut tasks);

    assert_no_blocks_staged(&alice, &version);
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .iter()
            .all(|key| *key == drained_key() || key.as_slice() == UPLOAD_MARK_KEY),
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

/// A cancel releases leaves the durable mark still covers, and leaves that mark
/// behind naming a root nothing will ever upload again. That residue must not
/// reach the next version: a mark read as this version's progress would skip
/// leaves it never sent and publish a manifest naming blocks nobody holds.
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
    let root_cid = queued_version(&alice, cancelled)[0].clone();

    world.scheduler.advance(engine.profile().poll_cadence);
    for _ in 0..4 {
        poll_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "only a partial upload leaves a mark, so the cancel must land mid-transfer"
    );
    block_on(engine.command(Command::CancelUpload { op_id: cancelled })).unwrap();
    poll_each(&mut tasks);

    let mark = block_on(alice.staging_store.staged_bytes(UPLOAD_MARK_KEY))
        .unwrap()
        .expect("the cancelled pass left its progress mark behind");
    assert!(
        mark.starts_with(&root_cid),
        "the residue names the cancelled root, so the next version must not read it as progress"
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
    op_mark_key(PUBLISHED_OP_MARK_PREFIX, &kdf::enc_subkey(&SECRET))
}

/// This account's drained-op mark key.
fn drained_key() -> Vec<u8> {
    op_mark_key(DRAINED_OP_MARK_PREFIX, &kdf::enc_subkey(&SECRET))
}

/// Plant a published-op mark over `op_id` under `enc_secret`'s identity,
/// standing in for the crash between a confirmed record publish and the op's
/// removal from the queue.
fn plant_published_mark_for(device: &FakeDevice, enc_secret: &X25519Secret, op_id: OpId) {
    block_on(device.staging_store.put_staged_bytes(
        &op_mark_key(PUBLISHED_OP_MARK_PREFIX, enc_secret),
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
    let updated = write_file(
        &mut engine,
        WriteTarget::Version { node: file },
        &(0..64u8).collect::<Vec<u8>>(),
    )
    .unwrap();
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
        .fail_floor_raises_for(write_name(child).as_str().as_bytes());
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
        .fail_floor_raises_for(root_name.as_str().as_bytes());
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
    .expect("the create queues");

    let stranger = kdf::enc_subkey(&[9u8; 32]);
    block_on(alice.staging_store.put_staged_bytes(
        &op_mark_key(DRAINED_OP_MARK_PREFIX, &stranger),
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
        Ok(None),
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
    let version = write_file(
        &mut engine,
        WriteTarget::Version { node: kept },
        b"a new version",
    )
    .unwrap();

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
        poll_once(&mut tasks);
    }
    assert!(uploads(&alice) > 0);

    alice.staging_store.fail_remove_op();
    assert!(
        block_on(engine.command(Command::CancelUpload { op_id })).is_err(),
        "the cancel could not remove the op, so it did not happen"
    );
    poll_each(&mut tasks);

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
        poll_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "the cancel must land mid-transfer, not before it started"
    );
    block_on(engine.command(Command::CancelUpload { op_id })).expect("the upload is cancellable");
    let facade_batches = retire_batches(&alice).len();

    // The drain now stops on the claim with no removal available to it, which
    // is indistinguishable from the op never having left the queue.
    alice.staging_store.fail_remove_op();
    poll_each(&mut tasks);

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
        poll_once(&mut tasks);
    }
    assert!(
        uploads(&alice) > 0,
        "the cancel must land mid-transfer, not before it started"
    );
    alice.staging_store.drop_staged_removal_after(&stranded, 0);
    block_on(engine.command(Command::CancelUpload { op_id })).unwrap();
    assert!(
        block_on(alice.staging_store.staged_keys())
            .unwrap()
            .contains(&stranded),
        "the fixture must actually strand a leaf, or the sweep has nothing to prove"
    );

    // The pass that notices the cancel sweeps behind itself, so the residue does
    // not wait a whole cadence.
    poll_each(&mut tasks);
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
        let leaves = decode_root(&root_block).unwrap().leaf_cids;
        core::iter::once(encode_content_cid_str(&root_cid))
            .chain(leaves.iter().map(|cid| encode_content_cid_str(cid)))
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

/// Every target this device has asked the registry to retire, in order.
fn retire_targets(device: &FakeDevice) -> Vec<String> {
    retire_batches(device).into_iter().flatten().collect()
}

/// The retire calls this device made, one entry per batch.
fn retire_batches(device: &FakeDevice) -> Vec<Vec<String>> {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/registry/retire"))
        .map(|request| {
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
        child_scope_index: Vec::new(),
        parent_node_seed: None,
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
    serve_http(device, blocks, 8);
    let api = ApiClient::new(
        device.http.clone(),
        device.credential_store.clone(),
        String::new(),
    );
    block_on(publish_settings(
        &device.record_store,
        &api,
        &device.floor_store,
        &device.snapshot_cache,
        &world.scheduler,
        &SyncTimingProfile::CI,
        &mut SeededEntropy::new(9),
        &OrphanHeads::default(),
        &SECRET,
        &VaultSettings {
            pin_mode: mode,
            byo: Some(member_node(ByoKind::Kubo)),
            retention: RetentionPolicy::KeepAll,
        },
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
    blocks.member_node_down.store(true, Ordering::Relaxed);
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

/// The command path reconciles the account's server-side flag against the
/// vaulted mode, which is the source of truth — the flag is an accounting
/// display, never the gate.
#[test]
fn the_command_path_reconciles_the_accounts_byo_flag_against_the_vaulted_mode() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let alice = world.device(b"alice");
    seed_settings(&world, &alice, &blocks, PinMode::External);

    let (mut engine, _events, _tasks) = boot(&world, &blocks, &alice, 42);
    assert!(
        !blocks.advisory_quota.load(Ordering::Relaxed),
        "the account starts classified as hosted"
    );
    write_file(
        &mut engine,
        WriteTarget::NewFile {
            parent: ROOT,
            name: "photo.bin".into(),
        },
        &(0..200u8).collect::<Vec<_>>(),
    )
    .expect("the write commits");
    assert!(
        blocks.advisory_quota.load(Ordering::Relaxed),
        "an external mode moved the account onto advisory accounting"
    );
    let toggles = alice
        .http
        .requests()
        .iter()
        .filter(|request| request.url.ends_with("/account/byo"))
        .count();
    assert_eq!(toggles, 1, "and only while the two disagreed");
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
            .floor_store
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
