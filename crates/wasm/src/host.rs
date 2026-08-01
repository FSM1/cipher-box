//! The production engine host: constructs the one engine instance over the
//! browser seams and exposes `start` / `command` / `snapshot` / `siweChallenge`
//! / `download` / `nextEvent` to the worker.
//!
//! Loaded inside `packages/client`'s dedicated engine worker (never the UI
//! realm). The single engine sits behind an async RwLock: `start`/`command`
//! take the write lock and serialize, while the reads (`snapshot`,
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
use cipherbox_engine::facade::{Engine, EngineError, EventStream, LoginSecret};
use cipherbox_engine::seams::OpId;
use cipherbox_engine::{
    ContentProfile, Entropy, EntropyError, GatewayConfig, GatewaySource, SeamSet, SeamTypes,
    StoragePlatform, StoragePolicy, SyncTimingProfile, WriteHandle, WriteTarget,
};
use js_sys::{Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use zeroize::Zeroizing;

use crate::seams_bridge::{
    CredentialStoreAdapter, FloorStoreAdapter, HttpAdapter, JsCredentialStoreSeam,
    JsFloorStoreSeam, JsHttpSeam, JsMailboxSeam, JsRecordTransportSeam, JsRefreshHintSourceSeam,
    JsSchedulerSeam, JsSnapshotCacheSeam, JsStagingStoreSeam, MailboxAdapter,
    RecordTransportAdapter, RefreshHintSourceAdapter, SchedulerAdapter, SnapshotCacheAdapter,
    StagingStoreAdapter,
};
use crate::{Command, Event, NodeId, SnapshotView};

/// The web host's concrete seam family (blueprint/engine.md `SeamTypes`): every
/// engine seam is a JS-object adapter from `seams_bridge`.
struct WebSeamTypes;

impl SeamTypes for WebSeamTypes {
    type FloorStore = FloorStoreAdapter;
    type RecordTransport = RecordTransportAdapter;
    type Http = HttpAdapter;
    type Mailbox = MailboxAdapter;
    type RefreshHintSource = RefreshHintSourceAdapter;
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

#[wasm_bindgen]
impl EngineHandle {
    /// Builds the engine over the browser seams. `seams` is a plain object with
    /// one property per engine seam (`floorStore`, `recordTransport`, `http`,
    /// `mailbox`, `refreshHints`, `scheduler`, `stagingStore`, `snapshotCache`,
    /// `credentialStore`); a missing seam fails closed. `profile` selects the
    /// sync timing policy (`"ci"` for the compressed e2e cadences, production
    /// otherwise). The content gateway is configured from `acceleratorBaseUrl`
    /// (+ optional `acceleratorBearer`) and `publicGateways`; all absent leaves
    /// it dormant (reads fail closed as `Unavailable`) until E4 wires real
    /// endpoints.
    #[wasm_bindgen(constructor)]
    pub fn new(
        seams: JsValue,
        profile: Option<String>,
        api_base_url: Option<String>,
        accelerator_base_url: Option<String>,
        accelerator_bearer: Option<String>,
        public_gateways: Option<Vec<String>>,
        storage_headroom_bytes: Option<f64>,
    ) -> Result<EngineHandle, JsError> {
        console_error_panic_hook::set_once();

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
            refresh_hints: RefreshHintSourceAdapter {
                js: take_seam::<JsRefreshHintSourceSeam>(&seams, "refreshHints")?,
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

        // The host measures origin headroom (`navigator.storage.estimate()`
        // quota minus usage) and hands it in; the split itself is computed here
        // so one headroom figure yields one budget on every platform. An absent
        // or nonsensical figure is `UNMEASURED`, not a measured zero: both admit
        // no upload (there is no floor-up), but only one of them means the
        // origin is full, and the rejection says which.
        let storage_policy = match profile {
            SyncTimingProfile::CI => StoragePolicy::CI,
            _ => match storage_headroom_bytes {
                Some(bytes) if bytes.is_finite() && bytes >= 0.0 => {
                    StoragePolicy::measured(StoragePlatform::WEB, bytes as u64)
                }
                _ => StoragePolicy::UNMEASURED,
            },
        };

        // Dormant until the config slice (E4) supplies real endpoints: with no
        // accelerator base URL and no fallbacks the gateway is empty, and reads
        // fail closed as `Unavailable` (availability, never a trust violation).
        // Zeroize the bearer before branching on the base URL: if no accelerator
        // base URL is supplied the source closure never runs, so wrapping inside
        // it would drop the Rust-owned bearer String unzeroized (security rule 7).
        let accelerator_bearer = accelerator_bearer.map(Zeroizing::new);
        let gateway = GatewayConfig {
            accelerator: accelerator_base_url.map(|base_url| GatewaySource {
                base_url,
                bearer: accelerator_bearer,
            }),
            public_fallbacks: public_gateways
                .unwrap_or_default()
                .into_iter()
                .map(|base_url| GatewaySource {
                    base_url,
                    bearer: None,
                })
                .collect(),
        };

        // Empty until the auth/config slice supplies the real API base URL; the
        // register-first renewal is inert against an empty base until then.
        let (engine, events) = Engine::new(
            seam_set,
            Box::new(GetrandomEntropy),
            profile,
            // The framing is frozen and pins the wire format, so the browser
            // always writes the shipped profile — never the CI one.
            ContentProfile::PRODUCTION,
            storage_policy,
            api_base_url.unwrap_or_default(),
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
    /// command value. Resolves with the staged op's durable queue id (the same
    /// `u64` an `opProgress`/`deadLetter` event carries), or `undefined` for a
    /// command that queues nothing; rejects with the engine error.
    pub fn command(&self, command: Command) -> Promise {
        let engine = self.engine.clone();
        let facade_command = command.into_facade();
        future_to_promise(async move {
            let op_id = engine
                .write()
                .await
                .command(facade_command)
                .await
                .map_err(engine_error)?;
            Ok(op_id_value(op_id))
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
            Ok(Uint8Array::from(bytes.as_slice()).into())
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

/// A staged op id as the boundary spells it. Op ids run the whole `u64` range,
/// so they cross as `bigint` — the same marshalling the `opId` getter on
/// `opProgress`/`deadLetter` uses, or a client could not correlate the two.
fn op_id_value(op_id: Option<OpId>) -> JsValue {
    op_id.map_or(JsValue::UNDEFINED, |op| JsValue::from(op.0))
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
        EngineError::UnsupportedContentFormat { .. } => "unsupportedContentFormat",
        EngineError::Unimplemented { .. } => "unimplemented",
        EngineError::OverBudget { .. } => "overBudget",
        EngineError::ContentSizeMismatch { .. } => "contentSizeMismatch",
        EngineError::UnknownWriteHandle => "unknownWriteHandle",
        EngineError::ContentTooLarge { .. } => "contentTooLarge",
        EngineError::ContentKeySealFailed { .. } => "contentKeySealFailed",
        EngineError::Seam { .. } => "seam",
        EngineError::Entropy { .. } => "entropy",
        EngineError::Auth { .. } => "auth",
        EngineError::ColdStart { .. } => "coldStart",
    };
    let js = js_sys::Error::new(&error.to_string());
    // Setting a plain property on a fresh `Error` cannot fail.
    let _ = Reflect::set(&js, &JsValue::from_str("code"), &JsValue::from_str(code));
    js.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use js_sys::BigInt;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// `command()` resolves with the id an `opProgress`/`deadLetter` event
    /// later carries, so both must cross as the same JS type — an f64 `number`
    /// would neither compare equal to the event's `bigint` nor survive an id
    /// past 2^53.
    #[wasm_bindgen_test]
    fn a_staged_op_id_crosses_as_a_bigint() {
        let value = op_id_value(Some(OpId(u64::MAX)));

        assert_eq!(value.js_typeof(), JsValue::from_str("bigint"));
        assert_eq!(
            String::from(
                value
                    .unchecked_into::<BigInt>()
                    .to_string(10)
                    .expect("bigint renders in base 10")
            ),
            u64::MAX.to_string(),
        );
    }

    /// A command that queues nothing resolves `undefined`, never `0n`.
    #[wasm_bindgen_test]
    fn a_command_that_queues_nothing_crosses_as_undefined() {
        assert!(op_id_value(None).is_undefined());
    }
}
