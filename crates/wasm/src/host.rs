//! The production engine host: constructs the one engine instance over the
//! browser seams and exposes `start` / `command` / `snapshot` / `sharing` /
//! `siweChallenge` / `download` / `nextEvent` to the worker.
//!
//! Loaded inside `packages/client`'s dedicated engine worker (never the UI
//! realm). The single engine sits behind an async RwLock: `start`/`command`
//! take the write lock and serialize, while the reads (`snapshot`, `sharing`,
//! `siweChallenge`, `download`) share the read lock — a long download never
//! blocks a snapshot. `nextEvent`
//! reads the independent event stream and runs concurrently with a command.
//!
//! Key material lives only in this worker's WASM linear memory: the login
//! secret enters once through `start` (copied into the engine's `Zeroizing`
//! store, then dropped), and nothing key-shaped is ever returned across the
//! boundary — the command surface carries only intent, the event surface only
//! key-free view state (blueprint/web-client.md "Memory hygiene").

use std::rc::Rc;

use async_lock::{Mutex, RwLock};
use cipherbox_engine::facade::{ApiBaseUrl, Engine, EngineError, EventStream, LoginSecret};
use cipherbox_engine::{
    ContentProfile, Entropy, EntropyError, GatewayConfig, OverBudgetCause, SeamSet, SeamTypes,
    StoragePlatform, StoragePolicy, StreamHandle, SyncTimingProfile, WriteHandle, WriteTarget,
};
use js_sys::{Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use zeroize::Zeroizing;

use crate::seams_bridge::{
    CredentialStoreAdapter, FloorStoreAdapter, HttpAdapter, JsCredentialStoreSeam,
    JsFloorStoreSeam, JsHttpSeam, JsMailboxSeam, JsRecordTransportSeam, JsSchedulerSeam,
    JsSnapshotCacheSeam, JsStagingStoreSeam, MailboxAdapter, RecordTransportAdapter,
    SchedulerAdapter, SnapshotCacheAdapter, StagingStoreAdapter,
};
use crate::{Command, CommandOutcome, Event, NodeId, ReceivedShareRow, SharingView, SnapshotView};

/// The web host's concrete seam family (blueprint/engine.md `SeamTypes`): every
/// engine seam is a JS-object adapter from `seams_bridge`.
struct WebSeamTypes;

impl SeamTypes for WebSeamTypes {
    type FloorStore = FloorStoreAdapter;
    type RecordTransport = RecordTransportAdapter;
    type Http = HttpAdapter;
    type Mailbox = MailboxAdapter;
    type Scheduler = SchedulerAdapter;
    type StagingStore = StagingStoreAdapter;
    type SnapshotCache = SnapshotCacheAdapter;
    type CredentialStore = CredentialStoreAdapter;
}

/// Production entropy: the target's `getrandom`, whose wasm backend wires to
/// `crypto.getRandomValues` in the worker scope (`.cargo/config.toml`
/// `getrandom_backend="wasm_js"`). Fail-closed — never substitutes predictable
/// bytes.
struct GetrandomEntropy;

impl Entropy for GetrandomEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(dest).map_err(|error| EntropyError::new(error.to_string()))
    }
}

/// Pulls one named seam off the JS seam bag, failing closed if it is missing.
fn take_seam<T: JsCast>(bag: &JsValue, key: &str) -> Result<T, JsError> {
    let value = Reflect::get(bag, &JsValue::from_str(key))
        .map_err(|_| JsError::new(&format!("seams.{key} is not readable")))?;
    if value.is_undefined() || value.is_null() {
        return Err(JsError::new(&format!("seams.{key} is required")));
    }
    Ok(value.unchecked_into())
}

/// The one long-lived engine instance for this origin, hosted in the worker.
#[wasm_bindgen]
pub struct EngineHandle {
    engine: Rc<RwLock<Engine<WebSeamTypes>>>,
    events: Rc<Mutex<EventStream>>,
}

/// The web storage policy for the headroom figure the host measured
/// (`navigator.storage.estimate()` quota minus usage). The split itself is
/// computed here so one headroom figure yields one budget on every platform.
///
/// An absent or nonsensical figure is `UNMEASURED`, not a measured zero: both
/// admit no upload (there is no floor-up), but only one of them means the
/// origin is full, and the rejection says which. So a measurement is taken only
/// as a whole byte count the engine can hold — a fractional or out-of-range one
/// is a broken measurement, and truncating or saturating it would publish a
/// budget nothing measured.
///
/// The timing profile has no say here: a measured byte count belongs to no
/// named set, so a browser on the CI cadence still stages against the quota it
/// has.
fn web_storage_policy(headroom_bytes: Option<f64>) -> StoragePolicy {
    /// `2^64`, exactly representable as `f64`; the least value `as u64` saturates.
    const OVER_U64: f64 = 18_446_744_073_709_551_616.0;
    match headroom_bytes {
        // Rejects NaN and both infinities by the range comparisons alone.
        Some(bytes) if bytes >= 0.0 && bytes < OVER_U64 && bytes.fract() == 0.0 => {
            StoragePolicy::measured(StoragePlatform::WEB, bytes as u64)
        }
        _ => StoragePolicy::UNMEASURED,
    }
}

#[wasm_bindgen]
impl EngineHandle {
    /// Builds the engine over the browser seams. `seams` is a plain object with
    /// one property per engine seam (`floorStore`, `recordTransport`, `http`,
    /// `mailbox`, `scheduler`, `stagingStore`, `snapshotCache`,
    /// `credentialStore`); a missing seam fails closed. `profile` selects the
    /// sync timing policy (`"ci"` for the compressed e2e cadences, production
    /// otherwise). `apiBaseUrl` is required and non-blank. The content gateway
    /// is configured from `acceleratorBaseUrl` and `publicGateways` — the
    /// accelerator's credential is the engine's session token, so there is no
    /// host-supplied bearer to pass.
    #[wasm_bindgen(constructor)]
    pub fn new(
        seams: JsValue,
        profile: Option<String>,
        api_base_url: Option<String>,
        accelerator_base_url: Option<String>,
        public_gateways: Option<Vec<String>>,
        storage_headroom_bytes: Option<f64>,
    ) -> Result<EngineHandle, JsError> {
        console_error_panic_hook::set_once();

        let api_base_url = ApiBaseUrl::parse(api_base_url.as_deref().unwrap_or_default())?;

        let seam_set = SeamSet::<WebSeamTypes> {
            floor_store: FloorStoreAdapter {
                js: take_seam::<JsFloorStoreSeam>(&seams, "floorStore")?,
            },
            record_transport: RecordTransportAdapter {
                js: take_seam::<JsRecordTransportSeam>(&seams, "recordTransport")?,
            },
            http: HttpAdapter {
                js: take_seam::<JsHttpSeam>(&seams, "http")?,
            },
            mailbox: MailboxAdapter {
                js: take_seam::<JsMailboxSeam>(&seams, "mailbox")?,
            },
            scheduler: SchedulerAdapter {
                js: take_seam::<JsSchedulerSeam>(&seams, "scheduler")?,
            },
            staging_store: StagingStoreAdapter {
                js: take_seam::<JsStagingStoreSeam>(&seams, "stagingStore")?,
            },
            snapshot_cache: SnapshotCacheAdapter {
                js: take_seam::<JsSnapshotCacheSeam>(&seams, "snapshotCache")?,
            },
            credential_store: CredentialStoreAdapter {
                js: take_seam::<JsCredentialStoreSeam>(&seams, "credentialStore")?,
            },
        };

        let profile = match profile.as_deref() {
            Some("ci") => SyncTimingProfile::CI,
            _ => SyncTimingProfile::PRODUCTION,
        };

        let storage_policy = web_storage_policy(storage_headroom_bytes);

        // With no accelerator base URL and no fallbacks the gateway is empty and
        // reads fail closed as `Unavailable` (availability, never a trust
        // violation).
        let gateway = GatewayConfig {
            accelerator: accelerator_base_url,
            public_fallbacks: public_gateways.unwrap_or_default(),
        };

        let (engine, events) = Engine::new(
            seam_set,
            Box::new(GetrandomEntropy),
            profile,
            // The framing is frozen and pins the wire format, so the browser
            // always writes the shipped profile — never the CI one.
            ContentProfile::PRODUCTION,
            storage_policy,
            api_base_url,
            gateway,
        );
        Ok(EngineHandle {
            engine: Rc::new(RwLock::new(engine)),
            events: Rc::new(Mutex::new(events)),
        })
    }

    /// Cold start: consumes the login secret and brings the engine up (identity
    /// derivation, vault-pointer resolve, floor cold-seed, root adoption, first
    /// snapshot event — the engine's non-circular sequence). The secret is
    /// copied into the engine's `Zeroizing` store here and never leaves.
    /// Resolves on success; rejects with the engine error otherwise.
    pub fn start(&self, secret: Vec<u8>) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            engine
                .write()
                .await
                .start(LoginSecret::new(secret))
                .await
                .map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Executes one engine command — the single write entry point. Consumes the
    /// command value. Resolves with the [`CommandOutcome`] the arm produced —
    /// the staged op's durable queue id, a verified contact — or rejects with
    /// the engine error.
    pub fn command(&self, command: Command) -> Promise {
        let engine = self.engine.clone();
        let facade_command = command.into_facade();
        future_to_promise(async move {
            let outcome = engine
                .write()
                .await
                .command(facade_command)
                .await
                .map_err(engine_error)?;
            Ok(CommandOutcome::from_facade(outcome).into())
        })
    }

    /// Opens a write handle for a file of `size` plaintext bytes, reserving the
    /// exact sealed total it will occupy. `node` names an existing file for a
    /// new version; `parent` + `name` create one. Resolves with the handle id;
    /// rejects with the engine error (an over-budget refusal names which budget
    /// and how much room is left).
    #[wasm_bindgen(js_name = beginWrite)]
    pub fn begin_write(
        &self,
        parent: Option<NodeId>,
        name: Option<String>,
        node: Option<NodeId>,
        size: f64,
    ) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            let target = match (parent, name, node) {
                (Some(parent), Some(name), None) => WriteTarget::NewFile {
                    parent: parent.facade(),
                    name,
                },
                (None, None, Some(node)) => WriteTarget::Version {
                    node: node.facade(),
                },
                _ => {
                    return Err(JsError::new(
                        "beginWrite takes either (parent, name) or (node), never both",
                    )
                    .into());
                }
            };
            // A float-to-int cast saturates rather than failing, so a negative
            // or NaN size would silently reserve zero and only surface as a
            // `contentSizeMismatch` once real chunks arrive.
            if !size.is_finite() || size < 0.0 {
                return Err(
                    JsError::new("beginWrite size must be a non-negative finite number").into(),
                );
            }
            let handle = engine
                .write()
                .await
                .begin_write(target, size as u64)
                .await
                .map_err(engine_error)?;
            Ok(JsValue::from(handle.0))
        })
    }

    /// Feeds the next slice of the file to an open write handle. Seals and
    /// stages every whole chunk it completes; peak heap stays one chunk however
    /// large the file. Rejects — and spends the handle — if the pushes exceed
    /// the declared size.
    #[wasm_bindgen(js_name = pushChunk)]
    pub fn push_chunk(&self, handle: u64, chunk: Vec<u8>) -> Promise {
        let engine = self.engine.clone();
        // The copy wasm-bindgen makes out of the JS view is plaintext; wipe it
        // rather than leave it in the freed heap.
        let chunk = Zeroizing::new(chunk);
        future_to_promise(async move {
            engine
                .write()
                .await
                .push_chunk(WriteHandle(handle), &chunk)
                .await
                .map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Closes a write handle and journals its op. Resolves with the durable
    /// queue id; rejects if the pushes did not add up to the declared size.
    #[wasm_bindgen(js_name = commitWrite)]
    pub fn commit_write(&self, handle: u64) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            let op_id = engine
                .write()
                .await
                .commit_write(WriteHandle(handle))
                .await
                .map_err(engine_error)?;
            Ok(JsValue::from(op_id.0))
        })
    }

    /// Abandons a write handle, releasing its reservation and staged blocks.
    /// Always resolves — an unknown handle is already gone.
    #[wasm_bindgen(js_name = abortWrite)]
    pub fn abort_write(&self, handle: u64) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            engine.write().await.abort_write(WriteHandle(handle)).await;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Reads a key-free [`SnapshotView`] for a UI paint: of `folder`, or of the
    /// engine's own current root when `folder` is absent — a host asks for the
    /// root, it never names one (blueprint/web-client.md "UI state law").
    /// Resolves with the view; rejects with the engine error.
    pub fn snapshot(&self, folder: Option<NodeId>) -> Promise {
        let engine = self.engine.clone();
        let folder = folder.map(|node| node.facade());
        future_to_promise(async move {
            let engine = engine.read().await;
            let folder = folder.unwrap_or_else(|| engine.root());
            let view = engine.snapshot(folder).await.map_err(engine_error)?;
            Ok(SnapshotView::from_facade(view).into())
        })
    }

    /// Reads a key-free [`SharingView`] for a sharing UI: this vault's verified
    /// contact book, and the grants `scopeRoot`'s own record commits — of the
    /// engine's current root when `scopeRoot` is absent, as `snapshot` does.
    /// Resolves with the view; rejects with the engine error.
    pub fn sharing(&self, scope_root: Option<NodeId>) -> Promise {
        let engine = self.engine.clone();
        let scope_root = scope_root.map(|node| node.facade());
        future_to_promise(async move {
            let engine = engine.read().await;
            let scope_root = scope_root.unwrap_or_else(|| engine.root());
            let view = engine.sharing(scope_root).await.map_err(engine_error)?;
            Ok(SharingView::from_facade(view).into())
        })
    }

    /// Reads this vault's accepted shares for a `/shared` route: the durable
    /// received-share list, each row carrying the engine's own resolution
    /// verdict. Resolves with the rows; rejects with the engine error.
    #[wasm_bindgen(js_name = receivedShares)]
    pub fn received_shares(&self) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            let rows = engine
                .read()
                .await
                .received_shares()
                .await
                .map_err(engine_error)?;
            Ok(rows
                .into_iter()
                .map(ReceivedShareRow::from_facade)
                .map(JsValue::from)
                .collect::<js_sys::Array>()
                .into())
        })
    }

    /// Issues the single-use nonce an EIP-4361 message must embed. Resolves
    /// with the nonce as a string; rejects with the engine error.
    #[wasm_bindgen(js_name = siweChallenge)]
    pub fn siwe_challenge(&self) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            let nonce = engine
                .read()
                .await
                .siwe_challenge()
                .await
                .map_err(engine_error)?;
            Ok(JsValue::from_str(&nonce))
        })
    }

    /// Downloads and decrypts one file node's content through the verified
    /// read pipeline. Resolves with the plaintext bytes as a `Uint8Array`;
    /// rejects with the engine error.
    pub fn download(&self, node: &NodeId) -> Promise {
        let engine = self.engine.clone();
        let node = node.facade();
        future_to_promise(async move {
            let bytes = engine
                .read()
                .await
                .read_content(node)
                .await
                .map_err(engine_error)?;
            // Terminal owner of the Rust-side plaintext: the copy crosses into
            // the JS heap here, so this buffer is wiped rather than freed.
            let bytes = Zeroizing::new(bytes);
            Ok(Uint8Array::from(bytes.as_slice()).into())
        })
    }

    /// Opens a ranged-read stream over a file node, pinning the head version for
    /// the handle's whole life so no window can come from a different one.
    /// Resolves with the handle id; rejects with the engine error.
    #[wasm_bindgen(js_name = openContentStream)]
    pub fn open_content_stream(&self, node: &NodeId) -> Promise {
        let engine = self.engine.clone();
        let node = node.facade();
        future_to_promise(async move {
            let handle = engine
                .read()
                .await
                .open_content_stream(node)
                .await
                .map_err(engine_error)?;
            Ok(JsValue::from(handle.0))
        })
    }

    /// Decrypts one byte window of an open stream's pinned version, fetching
    /// only the leaves the window covers. The range is clamped to the version,
    /// so a window past the end resolves empty. Resolves with the plaintext
    /// bytes as a `Uint8Array`; rejects with the engine error.
    #[wasm_bindgen(js_name = readStream)]
    pub fn read_stream(&self, handle: u64, offset: f64, length: f64) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            // A float-to-int cast saturates and truncates, either of which would
            // silently read a different window than the caller named.
            let whole = |value: f64| {
                value.is_finite() && value >= 0.0 && value < u64::MAX as f64 && value.fract() == 0.0
            };
            if !whole(offset) || !whole(length) {
                return Err(JsError::new(
                    "readStream offset and length must be whole numbers in the u64 range",
                )
                .into());
            }
            let bytes = engine
                .read()
                .await
                .read_stream(StreamHandle(handle), offset as u64, length as u64)
                .await
                .map_err(engine_error)?;
            let bytes = Zeroizing::new(bytes);
            Ok(Uint8Array::from(bytes.as_slice()).into())
        })
    }

    /// Releases a read stream. Always resolves — an unknown handle is already gone.
    #[wasm_bindgen(js_name = closeStream)]
    pub fn close_stream(&self, handle: u64) -> Promise {
        let engine = self.engine.clone();
        future_to_promise(async move {
            engine.read().await.close_stream(StreamHandle(handle));
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Awaits the next event on the one-way stream, or resolves to `undefined`
    /// once the engine is gone. At most one call may be outstanding.
    #[wasm_bindgen(js_name = nextEvent)]
    pub fn next_event(&self) -> Promise {
        let events = self.events.clone();
        future_to_promise(async move {
            let next = events.lock().await.next().await;
            Ok(match next {
                Some(event) => Event::from_facade(event).into(),
                None => JsValue::UNDEFINED,
            })
        })
    }
}

/// Renders an engine error as a rejection value: a `js_sys::Error` whose
/// message is the diagnostic `Display` string (no key material — redacted by
/// construction) and whose `code` property is the stable camelCase variant
/// name the client matches on instead of the prose.
fn engine_error(error: EngineError) -> JsValue {
    let code = match &error {
        EngineError::NotStarted => "notStarted",
        EngineError::AlreadyStarted => "alreadyStarted",
        EngineError::InvalidSecret => "invalidSecret",
        EngineError::UnknownNode => "unknownNode",
        EngineError::NotAFolder => "notAFolder",
        EngineError::NotAFile => "notAFile",
        EngineError::ContentUnavailable { .. } => "contentUnavailable",
        EngineError::TrustViolation { .. } => "trustViolation",
        EngineError::MalformedInput { .. } => "malformedInput",
        EngineError::UnsupportedContentFormat { .. } => "unsupportedContentFormat",
        EngineError::Unimplemented { .. } => "unimplemented",
        // One code per cause, because the actions differ and prose is not a
        // branchable surface.
        EngineError::OverBudget { cause, .. } => match cause {
            OverBudgetCause::StagingLimit => "overBudgetStagingLimit",
            OverBudgetCause::DeviceFull => "overBudgetDeviceFull",
            OverBudgetCause::StagingBacklog => "overBudgetStagingBacklog",
            OverBudgetCause::TooManyWrites => "overBudgetTooManyWrites",
            OverBudgetCause::StorageUnmeasured => "overBudgetStorageUnmeasured",
            OverBudgetCause::AccountQuota => "overBudgetAccountQuota",
        },
        EngineError::NoPlacement { .. } => "noPlacement",
        EngineError::ContentSizeMismatch { .. } => "contentSizeMismatch",
        EngineError::UnknownWriteHandle => "unknownWriteHandle",
        EngineError::UnknownStreamHandle => "unknownStreamHandle",
        EngineError::TooManyStreams => "tooManyStreams",
        EngineError::TooLateToCancel { .. } => "tooLateToCancel",
        EngineError::NotAnUpload { .. } => "notAnUpload",
        EngineError::ContentTooLarge { .. } => "contentTooLarge",
        EngineError::ContentKeySealFailed { .. } => "contentKeySealFailed",
        EngineError::RefreshFailed { .. } => "refreshFailed",
        EngineError::Seam { .. } => "seam",
        EngineError::Entropy { .. } => "entropy",
        EngineError::Auth { .. } => "auth",
        EngineError::ColdStart { .. } => "coldStart",
        EngineError::ScopeExitRefused { .. } => "scopeExitRefused",
        EngineError::UnsupportedTarget { .. } => "unsupportedTarget",
    };
    let js = js_sys::Error::new(&error.to_string());
    // Setting a plain property on a fresh `Error` cannot fail.
    let _ = Reflect::set(&js, &JsValue::from_str("code"), &JsValue::from_str(code));
    js.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Permission;
    use cipherbox_core::kdf;
    use cipherbox_core::seal::Permission as CorePermission;
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_engine::facade::CommandOutcome as Outcome;
    use cipherbox_engine::import_contact;
    use cipherbox_engine::seams::OpId;
    use cipherbox_engine::{AcceptOutcome, Headroom, MintedInviteLink};
    use js_sys::BigInt;
    use wasm_bindgen_test::wasm_bindgen_test;

    const CONTACT_SCALAR: [u8; 32] = [3u8; 32];
    /// Stands in for an encoded fragment; nothing derives from it.
    const FRAGMENT: &str = "ZnJhZ21lbnQtdGV4dA";

    fn crossed(outcome: Outcome) -> JsValue {
        CommandOutcome::from_facade(outcome).into()
    }

    fn field(outcome: &JsValue, name: &str) -> JsValue {
        Reflect::get(outcome, &JsValue::from_str(name)).expect("outcome getter is readable")
    }

    fn bytes(value: JsValue) -> Vec<u8> {
        value.unchecked_into::<Uint8Array>().to_vec()
    }

    fn accepted_share(permission: CorePermission) -> Outcome {
        Outcome::ShareAccepted(AcceptOutcome {
            scope_id: [0x5c; 16],
            sequence: u64::MAX,
            permission,
            newly_added: true,
        })
    }

    fn minted_link() -> Outcome {
        Outcome::InviteLinkMinted(MintedInviteLink {
            fragment: Zeroizing::new(FRAGMENT.to_owned()),
        })
    }

    fn imported_contact() -> Outcome {
        let identity = EcdsaSigner::from_scalar(&CONTACT_SCALAR).expect("valid identity scalar");
        let code = ContactCode::create(&identity, kdf::enc_subkey(&CONTACT_SCALAR).public());
        Outcome::ContactImported(import_contact(&code.encode()).expect("the code imports"))
    }

    /// A byte figure that is not a whole number of bytes, or that the engine
    /// cannot hold, is a broken measurement — not a small or an enormous one.
    /// Truncating or saturating it would report `Measured` over a number the
    /// host never measured, and an over-budget rejection would then say "full"
    /// about an origin nobody sized.
    #[wasm_bindgen_test]
    fn only_a_whole_in_range_headroom_reads_as_measured() {
        for reported in [
            None,
            Some(f64::NAN),
            Some(f64::INFINITY),
            Some(f64::NEG_INFINITY),
            Some(-1.0),
            Some(1_048_576.5),
            // 2^64 and up: `as u64` would clamp these to `u64::MAX`.
            Some(18_446_744_073_709_551_616.0),
            Some(1e30),
        ] {
            assert_eq!(
                web_storage_policy(reported),
                StoragePolicy::UNMEASURED,
                "{reported:?} is not a byte count"
            );
        }

        let measured = web_storage_policy(Some(4_294_967_296.0));
        assert_eq!(measured.headroom, Headroom::Measured);
        assert_eq!(
            measured,
            StoragePolicy::measured(StoragePlatform::WEB, 4_294_967_296)
        );
        assert_eq!(
            web_storage_policy(Some(0.0)),
            StoragePolicy::measured(StoragePlatform::WEB, 0)
        );
    }

    /// `command()` resolves with the id an `opProgress`/`deadLetter` event
    /// later carries, so both must cross as the same JS type — an f64 `number`
    /// would neither compare equal to the event's `bigint` nor survive an id
    /// past 2^53.
    #[wasm_bindgen_test]
    fn a_staged_op_id_crosses_as_a_bigint() {
        let op_id = field(
            &crossed(Outcome::Queued {
                op_id: OpId(u64::MAX),
            }),
            "opId",
        );

        assert_eq!(op_id.js_typeof(), JsValue::from_str("bigint"));
        assert_eq!(
            String::from(
                op_id
                    .unchecked_into::<BigInt>()
                    .to_string(10)
                    .expect("bigint renders in base 10")
            ),
            u64::MAX.to_string(),
        );
    }

    /// A command that queues nothing carries no op id, never `0n`.
    #[wasm_bindgen_test]
    fn a_command_that_queues_nothing_carries_no_op_id() {
        assert!(field(&crossed(Outcome::Done), "opId").is_undefined());
    }

    /// The verified contact's two public keys are the whole point of the
    /// import, so both must survive the boundary — and no other kind may
    /// answer for them.
    #[wasm_bindgen_test]
    fn an_imported_contact_crosses_with_both_public_keys() {
        let identity = EcdsaSigner::from_scalar(&CONTACT_SCALAR).expect("valid identity scalar");
        let imported = crossed(imported_contact());

        assert_eq!(
            bytes(field(&imported, "identityPublicKey")),
            identity.verifying_key().to_sec1().to_vec(),
        );
        assert_eq!(
            bytes(field(&imported, "encPublicKey")),
            kdf::enc_subkey(&CONTACT_SCALAR)
                .public()
                .to_bytes()
                .to_vec(),
        );
        assert!(field(&imported, "opId").is_undefined());
        assert!(field(&crossed(Outcome::Done), "identityPublicKey").is_undefined());
    }

    /// An accepted share's payload is what tells a host the scope it may now
    /// open and on what terms, and the permission crossing is the
    /// **owner-committed** one — the share pointer's claim never reaches a host.
    /// The sequence rides the same `bigint` an op id does, so a record past 2^53
    /// survives.
    #[wasm_bindgen_test]
    fn an_accepted_share_crosses_with_its_committed_terms() {
        for (permission, expected) in [
            (CorePermission::Read, Permission::Read),
            (CorePermission::Write, Permission::Write),
        ] {
            let accepted = crossed(accepted_share(permission));
            assert_eq!(bytes(field(&accepted, "scopeId")), vec![0x5c; 16]);
            assert_eq!(
                field(&accepted, "permission"),
                JsValue::from(expected),
                "the committed permission crosses verbatim"
            );
            assert_eq!(field(&accepted, "newlyAdded"), JsValue::from_bool(true));

            let sequence = field(&accepted, "sequence");
            assert_eq!(sequence.js_typeof(), JsValue::from_str("bigint"));
            assert_eq!(
                String::from(
                    sequence
                        .unchecked_into::<BigInt>()
                        .to_string(10)
                        .expect("bigint renders in base 10")
                ),
                u64::MAX.to_string(),
            );
        }
        assert!(field(&crossed(Outcome::Done), "scopeId").is_undefined());
    }

    /// A minted link crosses as one opaque fragment, never as the parts it is
    /// built from.
    #[wasm_bindgen_test]
    fn a_minted_link_crosses_as_one_opaque_fragment() {
        let minted = crossed(minted_link());

        assert_eq!(field(&minted, "fragment"), JsValue::from_str(FRAGMENT));
        assert!(field(&crossed(Outcome::Done), "fragment").is_undefined());
    }

    /// Hosts switch on `kind`, so each arm's discriminant is a stable string
    /// literal — the marshalling `Event::kind` already uses.
    #[wasm_bindgen_test]
    fn each_outcome_kind_crosses_as_its_stable_name() {
        for (outcome, name) in [
            (Outcome::Done, "done"),
            (Outcome::Queued { op_id: OpId(1) }, "queued"),
            (imported_contact(), "contactImported"),
            (accepted_share(CorePermission::Read), "shareAccepted"),
            (minted_link(), "inviteLinkMinted"),
        ] {
            assert_eq!(field(&crossed(outcome), "kind"), JsValue::from_str(name));
        }
    }

    /// The wire codes `packages/client` and `apps/web` branch on.
    #[wasm_bindgen_test]
    fn each_over_budget_cause_crosses_as_its_own_code() {
        for (cause, expected) in [
            (OverBudgetCause::StagingLimit, "overBudgetStagingLimit"),
            (OverBudgetCause::DeviceFull, "overBudgetDeviceFull"),
            (OverBudgetCause::StagingBacklog, "overBudgetStagingBacklog"),
            (OverBudgetCause::TooManyWrites, "overBudgetTooManyWrites"),
            (
                OverBudgetCause::StorageUnmeasured,
                "overBudgetStorageUnmeasured",
            ),
            (OverBudgetCause::AccountQuota, "overBudgetAccountQuota"),
        ] {
            let rejection = engine_error(EngineError::OverBudget {
                cause,
                requested: 900,
                available: 100,
            });
            let code = Reflect::get(&rejection, &JsValue::from_str("code"))
                .expect("the rejection carries a code");
            assert_eq!(code, JsValue::from_str(expected), "{cause:?}");
        }
    }

    #[wasm_bindgen_test]
    fn an_engine_without_an_api_base_url_is_refused() {
        for api_base_url in [None, Some(String::new()), Some("  ".to_owned())] {
            let error = EngineHandle::new(
                js_sys::Object::new().into(),
                None,
                api_base_url,
                None,
                None,
                None,
            )
            .err()
            .expect("no API base is a construction failure");

            let message = String::from(
                JsValue::from(error)
                    .unchecked_into::<js_sys::Error>()
                    .message(),
            );
            assert!(message.contains("apiBaseUrl"), "{message}");
        }
    }
}
