//! The published-account fixture: one content-addressed block plane behind the
//! hosted ingress, the member's own node and the gateway, plus the initial
//! account state a cold start adopts.
//!
//! The seeding sequence encodes live wire invariants — the re-point payload
//! version, the `writeSeed(writeScopeSeed, root)` → `ipnsKeypair` edge, the
//! `writeEpoch`/`minReadEpoch` pairing, and sequence-1 on a first publish — so
//! a change to any of them lands here rather than in every suite that needs a
//! vault with real published content.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::suite::ecdsa::EcdsaSigner;

use super::{
    FakeDevice, FakeWorld, OWNER_ROOT_EPOCH, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootSpec,
    SeededEntropy, owner_root_fixture, requested_cid,
};
use crate::NodeId;
use crate::api::REGISTRY_BATCH_REFUSED;
use crate::content::DAG_ROOT_CODEC;
use crate::net::REGISTRY_BATCH_MAX;
use crate::seams::{HttpRequest, HttpResponse, RecordTransport, SeamError, SeamResult};
use crate::sync::pointer::{SessionRole, seal_repoint, vault_pointer_name};

/// The account's login secret — every key the fixture publishes under hangs off
/// it, so a suite reads the same vault back only by starting from this secret.
pub const SECRET: [u8; 32] = [7u8; 32];
/// The all-zero bootstrap anchor `start` binds its cold-start scope to.
pub const SCOPE: [u8; 16] = [0u8; 16];
/// The scope root's node id.
pub const ROOT: NodeId = NodeId(SCOPE);
/// The sole v2 re-point payload version (`facade::POINTER_PAYLOAD_VERSION`).
pub const POINTER_PAYLOAD_VERSION: u64 = 1;
/// The entropy seed the vault pointer's re-point seal draws its nonce from.
/// Named so that a fixture growing a second sealed body draws from a distinct
/// one: a single (key, nonce) pair must never cover two plaintexts
/// (blueprint/core.md "Crypto suite").
const POINTER_SEAL_ENTROPY_SEED: u64 = 0;
/// The TTL every seeded record carries.
pub const TTL_NANOS: u64 = 2_000_000_000;
/// The EOL every seeded record carries — far enough out that no suite's virtual
/// clock reaches it.
pub const EOL: &str = "2099-01-01T00:00:00Z";
/// The member's own IPFS node, as their vault settings name it.
pub const MEMBER_NODE: &str = "https://kubo.member.test";
/// Shaped as the API issues one; only a scenario that logs in ever reads it.
const LOGIN_CHALLENGE: &str =
    "cipherbox-login:v2:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The account owner's identity signer.
pub fn owner_identity() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&SECRET).expect("valid scalar")
}

/// A test hook on the upload path: given a head block about to be stored,
/// answer with the reply to send instead of storing it, or `None` to let the
/// upload through. Lets a test fail exactly one record's publish — and
/// interleave a concurrent writer at that instant.
pub type UploadHook = Box<dyn FnMut(&[u8]) -> Option<SeamResult<HttpResponse>> + Send>;

/// The registry's own 400 for a batch past its bounds: the `code` the batch
/// gate stamps, which is what the valve classifies on.
pub fn registry_batch_refused() -> Vec<u8> {
    format!(r#"{{"statusCode":400,"message":"over cap","code":"{REGISTRY_BATCH_REFUSED}"}}"#)
        .into_bytes()
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

/// One content-addressed block store behind the hosted ingress, the member's
/// own node and the gateway, so a block the engine uploads is a block it can
/// later fetch — plus the knobs a suite scripts a refusal or an outage with.
#[derive(Clone, Default)]
pub struct Blocks {
    store: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    on_upload: Arc<Mutex<Option<UploadHook>>>,
    /// Answer an upload with an address other than the one the bytes hash to.
    echo_other_address: Arc<AtomicBool>,
    /// What `GET /account/quota` reports, as `(usedBytes, limitBytes)`. Unset is
    /// an account with room, so only a test about the quota scripts one.
    quota: Arc<Mutex<Option<(u64, u64)>>>,
    /// The account's server-side BYO flag, which `GET /account/quota` reports as
    /// `advisory` and `PATCH /account/byo` moves.
    advisory_quota: Arc<AtomicBool>,
    /// Every `PATCH /account/byo` body, verbatim.
    byo_patches: Arc<Mutex<Vec<String>>>,
    /// The member's own node: what it holds, keyed by the address it stored each
    /// block under, and whether it can be reached at all.
    member_node: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    member_node_down: Arc<AtomicBool>,
    /// Requests the member's node refuses before answering normally again — the
    /// transient blip a mirror retry inside the op exists for.
    member_node_refusals: Arc<AtomicUsize>,
    /// The 400 body every `POST /registry/register` answers with instead of
    /// acking.
    register_refusal: Arc<Mutex<Option<Vec<u8>>>>,
    /// Every `POST /registry/retire` body, verbatim.
    retired: Arc<Mutex<Vec<String>>>,
    /// Whether `GET /account/quota` is reachable at all: the transport failure
    /// a flaky API leg gives, not a verdict.
    quota_down: Arc<AtomicBool>,
    /// The same for `PATCH /account/byo`.
    byo_down: Arc<AtomicBool>,
    /// Whether `POST /registry/retire` refuses — the outage a retire ledger's
    /// never-discard contract exists for.
    retire_down: Arc<AtomicBool>,
}

impl Blocks {
    /// Index a block by its own content address. The content plane addresses
    /// roots under `dag-cbor` and leaves under `raw`, and the ingress carries no
    /// codec, so a block is served under either address a reader may ask for.
    pub fn put(&self, block: Vec<u8>) -> String {
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

    /// The block stored under `cid`, if the plane holds one.
    pub fn get(&self, cid: &str) -> Option<Vec<u8>> {
        self.store.lock().expect("lock").get(cid).cloned()
    }

    /// The one block on the plane, for a fixture that uploaded exactly one.
    pub fn only_block(&self) -> String {
        let store = self.store.lock().expect("lock");
        assert_eq!(store.len(), 1, "exactly one block was uploaded");
        store.keys().next().expect("one block").clone()
    }

    /// Install the upload hook, replacing any previous one.
    pub fn refuse_upload(&self, hook: UploadHook) {
        *self.on_upload.lock().expect("lock") = Some(hook);
    }

    /// Let every upload through again.
    pub fn accept_uploads(&self) {
        *self.on_upload.lock().expect("lock") = None;
    }

    /// Answer the upload with an address other than the one the bytes hash to.
    pub fn echo_other_address(&self) {
        self.echo_other_address.store(true, Ordering::Relaxed);
    }

    /// Script what the quota endpoint reports.
    pub fn set_quota(&self, used_bytes: u64, limit_bytes: u64) {
        *self.quota.lock().expect("lock") = Some((used_bytes, limit_bytes));
    }

    /// Whether the quota endpoint is unreachable.
    pub fn set_quota_down(&self, down: bool) {
        self.quota_down.store(down, Ordering::Relaxed);
    }

    /// Whether the BYO endpoint is unreachable.
    pub fn set_byo_down(&self, down: bool) {
        self.byo_down.store(down, Ordering::Relaxed);
    }

    /// The account's server-side BYO flag, as the quota probe reports it.
    pub fn advisory(&self) -> bool {
        self.advisory_quota.load(Ordering::Relaxed)
    }

    /// Move the account's server-side BYO flag.
    pub fn set_advisory(&self, enabled: bool) {
        self.advisory_quota.store(enabled, Ordering::Relaxed);
    }

    /// Start the account already flagged BYO, so the first hosted write has a
    /// disagreement to reconcile.
    pub fn on_a_byo_account(self) -> Self {
        self.set_advisory(true);
        self
    }

    /// Every `PATCH /account/byo` body the account received, verbatim.
    pub fn byo_patches(&self) -> Vec<String> {
        self.byo_patches.lock().expect("lock").clone()
    }

    /// Answer every registration with a 400 carrying `body` instead of acking.
    /// Retirement keeps answering, so a pass can still clear what it orphaned.
    pub fn refuse_register(&self, body: Vec<u8>) {
        *self.register_refusal.lock().expect("lock") = Some(body);
    }

    /// Let every registration through again.
    pub fn accept_registrations(&self) {
        *self.register_refusal.lock().expect("lock") = None;
    }

    /// Whether every retire is refused with a 503 — the self-clearing outage a
    /// never-discard ledger backs off on.
    pub fn refuse_retire(&self, refuse: bool) {
        self.retire_down.store(refuse, Ordering::SeqCst);
    }

    /// Every retire request body the registry received, verbatim.
    pub fn retired(&self) -> Vec<String> {
        self.retired.lock().expect("lock").clone()
    }

    /// Whether the member's own node is reachable at all.
    pub fn set_member_node_down(&self, down: bool) {
        self.member_node_down.store(down, Ordering::Relaxed);
    }

    /// How many further requests the member's node refuses before answering
    /// normally again.
    pub fn set_member_node_refusals(&self, refusals: usize) {
        self.member_node_refusals.store(refusals, Ordering::Relaxed);
    }

    /// Every address the member's own node holds.
    pub fn member_node_cids(&self) -> Vec<String> {
        self.member_node
            .lock()
            .expect("lock")
            .keys()
            .cloned()
            .collect()
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
        if self
            .member_node_refusals
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(SeamError::new("the member's node refused this attempt"));
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

    /// Answer one engine HTTP call: a content upload lands its bytes here and
    /// echoes their address, a registry call acks, and a gateway GET serves the
    /// block back. Enqueued as many times as the pass needs, so no test depends
    /// on the exact order the engine happens to make its calls in.
    pub fn reply(&self, request: &HttpRequest) -> SeamResult<HttpResponse> {
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
            let other = self.echo_other_address.load(Ordering::Relaxed).then(|| {
                let mut other = block.clone();
                other.push(0);
                encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &other))
            });
            // Mirror the API's fail-closed bind: the block is stored —
            // and served back — only under the address the caller declared,
            // and only once those bytes really address to it.
            self.put_declared(&declared, block);
            let cid = other.unwrap_or(declared);
            return ok(format!("{{\"cid\":\"{cid}\",\"size\":{size}}}").into_bytes());
        }
        // The recovery cache has seen nothing: the vacancy probe first-run
        // provisioning runs before it mints anything.
        if url.contains("/recovery/") {
            return Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: br#"{"statusCode":404,"message":"No cached record for this name"}"#.to_vec(),
            });
        }
        // The auth handshake, for a scenario that runs against a configured API
        // rather than offline.
        if url.ends_with("/auth/challenge") {
            return ok(format!(
                r#"{{"challenge":"{LOGIN_CHALLENGE}","expiresAt":"2099-01-01T00:00:00Z"}}"#
            )
            .into_bytes());
        }
        if url.ends_with("/auth/login") {
            return ok(format!(
                r#"{{"accessToken":"jwt-1","refreshToken":"{}","isNewUser":true}}"#,
                "a".repeat(64)
            )
            .into_bytes());
        }
        if url.ends_with("/account/quota") && self.quota_down.load(Ordering::Relaxed) {
            return Err(SeamError::new("the quota endpoint is unreachable"));
        }
        if url.ends_with("/account/byo") && self.byo_down.load(Ordering::Relaxed) {
            return Err(SeamError::new("the byo endpoint is unreachable"));
        }
        if url.ends_with("/account/quota") {
            let (used, limit) = self
                .quota
                .lock()
                .expect("lock")
                .unwrap_or((0, u64::MAX / 2));
            let advisory = self.advisory();
            return ok(format!(
                "{{\"usedBytes\":{used},\"limitBytes\":{limit},\"advisory\":{advisory}}}"
            )
            .into_bytes());
        }
        if url.starts_with(MEMBER_NODE) {
            return self.member_node_reply(request);
        }
        if url.ends_with("/account/byo") {
            let raw = request.body.clone().expect("a byo toggle carries a body");
            let enabled = serde_json::from_slice::<serde_json::Value>(&raw)
                .expect("a byo body is JSON")["byo"]
                .as_bool()
                .expect("the toggle names a boolean");
            self.set_advisory(enabled);
            self.byo_patches
                .lock()
                .expect("lock")
                .push(String::from_utf8_lossy(&raw).into_owned());
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
        if url.ends_with("/registry/retire") {
            if self.retire_down.load(Ordering::SeqCst) {
                return Ok(HttpResponse {
                    status: 503,
                    headers: Vec::new(),
                    body: Vec::new(),
                });
            }
            // The registry answers a retire with what it deleted; the count is
            // the engine's done-signal, so a malformed body must fail the test
            // rather than ack a zero that reads as done.
            let body = request
                .body
                .as_deref()
                .expect("a retire call carries a body");
            let retired = serde_json::from_slice::<Vec<String>>(body)
                .expect("a retire body is a name array")
                .len();
            self.retired
                .lock()
                .expect("lock")
                .push(String::from_utf8_lossy(body).into_owned());
            return ok(format!(r#"{{"retired":{retired},"unpinned":0}}"#).into_bytes());
        }
        if url.contains("/registry/") {
            return ok(Vec::new());
        }
        match self.get(&requested_cid(url)) {
            Some(block) => ok(block),
            None => Err(SeamError::new("no such block")),
        }
    }
}

/// Wire `device`'s scripted HTTP to the block plane for `calls` requests.
pub fn serve_http(device: &FakeDevice, blocks: &Blocks, calls: usize) {
    for _ in 0..calls {
        let blocks = blocks.clone();
        device
            .http
            .enqueue_derived(move |request| blocks.reply(request));
    }
}

/// Publish the account's initial state to the shared network: an empty owner
/// root at sequence 1 and the vault pointer naming it. Returns the root's
/// write-plane name.
pub fn seed_account(world: &FakeWorld, blocks: &Blocks) -> IpnsName {
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
        owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
        write_history_link: Vec::new(),
        grants: Vec::new(),
    });
    blocks.put(fixture.head_block.clone());

    let root_signer = {
        let write_seed = kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &ROOT.0);
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
        &mut SeededEntropy::new(POINTER_SEAL_ENTROPY_SEED),
        kdf::pointer_read_key(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE).as_bytes(),
        POINTER_PAYLOAD_VERSION,
        &owner_identity(),
        &RepointObject {
            scope_id: SCOPE,
            current_root: fixture.name.clone(),
            write_epoch: OWNER_ROOT_EPOCH,
            min_read_epoch: OWNER_ROOT_EPOCH,
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
