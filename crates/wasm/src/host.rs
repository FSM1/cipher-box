//! The production engine host: constructs the one engine instance over the
//! browser seams and exposes `start` / `command` / `snapshot` / `download` /
//! `nextEvent` to the worker.
//!
//! Loaded inside `packages/client`'s dedicated engine worker (never the UI
//! realm). `start`, `command`, and the reads (`snapshot`, `download`) share
//! the single engine behind an async mutex, so concurrent calls queue rather
//! than race; `nextEvent` reads the independent event stream and runs
//! concurrently with a command.
//!
//! Key material lives only in this worker's WASM linear memory: the login
//! secret enters once through `start` (copied into the engine's `Zeroizing`
//! store, then dropped), and nothing key-shaped is ever returned across the
//! boundary — the command surface carries only intent, the event surface only
//! key-free view state (blueprint/web-client.md "Memory hygiene").

use std::rc::Rc;

use cipherbox_engine::facade::{Engine, EventStream, LoginSecret};
use cipherbox_engine::{
    Entropy, EntropyError, GatewayConfig, GatewaySource, SeamSet, SeamTypes, SyncTimingProfile,
};
use futures_util::lock::Mutex;
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
    engine: Rc<Mutex<Engine<WebSeamTypes>>>,
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
            api_base_url.unwrap_or_default(),
            gateway,
        );
        Ok(EngineHandle {
            engine: Rc::new(Mutex::new(engine)),
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
                .lock()
                .await
                .start(LoginSecret::new(secret))
                .await
                .map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Executes one engine command — the single write entry point. Consumes the
    /// command value. Resolves on success; rejects with the engine error.
    pub fn command(&self, command: Command) -> Promise {
        let engine = self.engine.clone();
        let facade_command = command.into_facade();
        future_to_promise(async move {
            engine
                .lock()
                .await
                .command(facade_command)
                .await
                .map_err(engine_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Reads a key-free [`SnapshotView`] of `folder` for a UI paint. Resolves
    /// with the view; rejects with the engine error.
    pub fn snapshot(&self, folder: &NodeId) -> Promise {
        let engine = self.engine.clone();
        let folder = folder.facade();
        future_to_promise(async move {
            let view = engine
                .lock()
                .await
                .snapshot(folder)
                .await
                .map_err(engine_error)?;
            Ok(SnapshotView::from_facade(view).into())
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
                .lock()
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

/// Renders an engine error as a rejection value (diagnostic string, no key
/// material — the engine's `Display` is redacted by construction).
fn engine_error(error: cipherbox_engine::facade::EngineError) -> JsValue {
    JsError::new(&error.to_string()).into()
}
