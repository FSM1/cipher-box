//! Browser seam conformance bridge (feature `conformance`, wasm target only).
//!
//! The engine ships one reusable conformance kit per seam trait
//! (`cipherbox_engine::testkit::conformance`, blueprint/testing.md "Seam
//! conformance kits"). The web seam implementations, however, are JavaScript
//! (`packages/client` — IndexedDB, OPFS, `fetch`), so they cannot implement a
//! Rust trait directly. This module is the boundary bridge: for each seam it
//! declares the JS object's method surface as a wasm-bindgen import, wraps it
//! in a Rust adapter that implements the engine seam trait, and exports one
//! async runner that drives the engine's own kit against the adapter. The
//! `packages/client` browser suite calls these runners in a real browser
//! worker, so the same contract that the in-memory fakes pass in cargo tests
//! is enforced against real IndexedDB and OPFS.
//!
//! The runners are `async fn`s: each returns a JS `Promise` that resolves when
//! the kit passes. A contract violation panics inside the kit (its `assert!`s);
//! `console_error_panic_hook` surfaces the assertion message to the browser
//! console, and the harness observes the non-resolution as a failure.
//!
//! Numeric seam values (floors, sequence numbers, op ids, byte totals) cross
//! this test bridge as `f64`. The production facade carries `u64`s as `bigint`
//! (blueprint/web-client.md "Boundary hygiene"); the conformance kits' value
//! domain is far below `Number.MAX_SAFE_INTEGER`, so the narrowing is lossless
//! for the test path and keeps the JS seams working in plain numbers.

use cipherbox_engine::seams::{
    BoxedTask, CredentialStore, EndpointId, FloorStore, OpId, RecordTransport, Scheduler,
    SeamError, SeamResult, SnapshotCache, StagingStore, UnixMillis,
};
use cipherbox_engine::testkit::conformance;
use core::time::Duration;
use js_sys::{Array, Function, Promise, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

// ---------------------------------------------------------------------------
// JS value helpers.
// ---------------------------------------------------------------------------

/// Maps a rejected JS seam call to an opaque [`SeamError`] (diagnostics only —
/// a seam failure is host I/O, never a trust decision).
fn seam_error(value: JsValue) -> SeamError {
    // Preserve the message of a thrown `Error` (its `.message`, which
    // `as_string` does not see); fall back to a plain string, then a generic.
    let message = value.as_string().or_else(|| {
        value
            .dyn_ref::<js_sys::Error>()
            .map(|error| String::from(error.message()))
    });
    SeamError::new(message.unwrap_or_else(|| "browser seam rejected".to_string()))
}

/// `number | null | undefined` → `Option<u64>`.
fn optional_u64(value: JsValue) -> Option<u64> {
    if value.is_null() || value.is_undefined() {
        None
    } else {
        value.as_f64().map(|number| number as u64)
    }
}

/// `number` → `u64` (0 if the value is not a number).
fn required_u64(value: JsValue) -> u64 {
    value
        .as_f64()
        .map(|number| number as u64)
        .unwrap_or_default()
}

/// `Uint8Array | null | undefined` → `Option<Vec<u8>>`.
fn optional_bytes(value: JsValue) -> Option<Vec<u8>> {
    if value.is_null() || value.is_undefined() {
        None
    } else {
        Some(value.unchecked_into::<Uint8Array>().to_vec())
    }
}

/// Calls a JS `() => Promise<Seam>` factory and awaits the fresh seam handle
/// (the conformance kits' "reopen" contract).
async fn open_seam(factory: &Function) -> JsValue {
    let result = factory
        .call0(&JsValue::UNDEFINED)
        .expect("seam factory must not throw");
    let promise: Promise = result
        .dyn_into()
        .expect("seam factory must return a Promise");
    JsFuture::from(promise)
        .await
        .expect("seam factory promise must resolve")
}

// ---------------------------------------------------------------------------
// FloorStore.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `FloorStoreSeam` (packages/client) — opaque handle, methods called
    /// structurally.
    pub type JsFloorStoreSeam;

    #[wasm_bindgen(method, catch, js_name = epochFloor)]
    async fn epoch_floor(this: &JsFloorStoreSeam, scope_id: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = raiseEpochFloor)]
    async fn raise_epoch_floor(
        this: &JsFloorStoreSeam,
        scope_id: &[u8],
        epoch: f64,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = sequenceFloor)]
    async fn sequence_floor(this: &JsFloorStoreSeam, ipns_name: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = raiseSequenceFloor)]
    async fn raise_sequence_floor(
        this: &JsFloorStoreSeam,
        ipns_name: &[u8],
        sequence: f64,
    ) -> Result<JsValue, JsValue>;
}

/// The JS `FloorStoreSeam` exposes only per-key methods, so this adapter does
/// not override `commit_floors`: web batches ride the seam's ordered fail-safe
/// fallback (#682-safe; web-atomic is deferred — see the trait doc). The
/// conformance kit's batch assertions therefore exercise that default here.
struct FloorStoreAdapter {
    js: JsFloorStoreSeam,
}

impl FloorStore for FloorStoreAdapter {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        Ok(optional_u64(
            self.js.epoch_floor(scope_id).await.map_err(seam_error)?,
        ))
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        Ok(required_u64(
            self.js
                .raise_epoch_floor(scope_id, epoch as f64)
                .await
                .map_err(seam_error)?,
        ))
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        Ok(optional_u64(
            self.js
                .sequence_floor(ipns_name)
                .await
                .map_err(seam_error)?,
        ))
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        Ok(required_u64(
            self.js
                .raise_sequence_floor(ipns_name, sequence as f64)
                .await
                .map_err(seam_error)?,
        ))
    }
}

/// Runs the `FloorStore` conformance kit against a JS `FloorStoreSeam`,
/// reopening a fresh handle via `factory` each time the kit asks.
#[wasm_bindgen(js_name = runFloorStoreConformance)]
pub async fn run_floor_store_conformance(factory: Function) {
    console_error_panic_hook::set_once();
    conformance::floor_store::check(async || FloorStoreAdapter {
        js: open_seam(&factory).await.unchecked_into(),
    })
    .await;
}

// ---------------------------------------------------------------------------
// SnapshotCache.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `SnapshotCacheSeam` (packages/client).
    pub type JsSnapshotCacheSeam;

    #[wasm_bindgen(method, catch, js_name = put)]
    async fn put(
        this: &JsSnapshotCacheSeam,
        cache_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = get)]
    async fn get(this: &JsSnapshotCacheSeam, cache_key: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = remove)]
    async fn remove(this: &JsSnapshotCacheSeam, cache_key: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = clear)]
    async fn clear(this: &JsSnapshotCacheSeam) -> Result<JsValue, JsValue>;
}

struct SnapshotCacheAdapter {
    js: JsSnapshotCacheSeam,
}

impl SnapshotCache for SnapshotCacheAdapter {
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()> {
        self.js
            .put(cache_key, ciphertext)
            .await
            .map_err(seam_error)?;
        Ok(())
    }

    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        Ok(optional_bytes(
            self.js.get(cache_key).await.map_err(seam_error)?,
        ))
    }

    async fn remove(&self, cache_key: &[u8]) -> SeamResult<()> {
        self.js.remove(cache_key).await.map_err(seam_error)?;
        Ok(())
    }

    async fn clear(&self) -> SeamResult<()> {
        self.js.clear().await.map_err(seam_error)?;
        Ok(())
    }
}

/// Runs the `SnapshotCache` conformance kit against a JS `SnapshotCacheSeam`.
#[wasm_bindgen(js_name = runSnapshotCacheConformance)]
pub async fn run_snapshot_cache_conformance(factory: Function) {
    console_error_panic_hook::set_once();
    conformance::snapshot_cache::check(async || SnapshotCacheAdapter {
        js: open_seam(&factory).await.unchecked_into(),
    })
    .await;
}

// ---------------------------------------------------------------------------
// StagingStore.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `StagingStoreSeam` (packages/client).
    pub type JsStagingStoreSeam;

    #[wasm_bindgen(method, catch, js_name = enqueueOp)]
    async fn enqueue_op(this: &JsStagingStoreSeam, op: &[u8]) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = queuedOps)]
    async fn queued_ops(this: &JsStagingStoreSeam) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = removeOp)]
    async fn remove_op(this: &JsStagingStoreSeam, op_id: f64) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = putStagedBytes)]
    async fn put_staged_bytes(
        this: &JsStagingStoreSeam,
        staging_key: &[u8],
        bytes: &[u8],
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = stagedBytes)]
    async fn staged_bytes(
        this: &JsStagingStoreSeam,
        staging_key: &[u8],
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = removeStagedBytes)]
    async fn remove_staged_bytes(
        this: &JsStagingStoreSeam,
        staging_key: &[u8],
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = stagedKeys)]
    async fn staged_keys(this: &JsStagingStoreSeam) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = stagedBytesTotal)]
    async fn staged_bytes_total(this: &JsStagingStoreSeam) -> Result<JsValue, JsValue>;
}

struct StagingStoreAdapter {
    js: JsStagingStoreSeam,
}

impl StagingStore for StagingStoreAdapter {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        Ok(OpId(required_u64(
            self.js.enqueue_op(op).await.map_err(seam_error)?,
        )))
    }

    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
        let value = self.js.queued_ops().await.map_err(seam_error)?;
        let array: Array = value.dyn_into().expect("queuedOps must return an array");
        let mut ops = Vec::with_capacity(array.length() as usize);
        for entry in array.iter() {
            let pair: Array = entry
                .dyn_into()
                .expect("each queued op must be a [id, bytes] pair");
            let op_id = OpId(required_u64(pair.get(0)));
            let bytes = pair.get(1).unchecked_into::<Uint8Array>().to_vec();
            ops.push((op_id, bytes));
        }
        Ok(ops)
    }

    async fn remove_op(&self, op_id: OpId) -> SeamResult<()> {
        self.js
            .remove_op(op_id.0 as f64)
            .await
            .map_err(seam_error)?;
        Ok(())
    }

    async fn put_staged_bytes(&self, staging_key: &[u8], bytes: &[u8]) -> SeamResult<()> {
        self.js
            .put_staged_bytes(staging_key, bytes)
            .await
            .map_err(seam_error)?;
        Ok(())
    }

    async fn staged_bytes(&self, staging_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        Ok(optional_bytes(
            self.js
                .staged_bytes(staging_key)
                .await
                .map_err(seam_error)?,
        ))
    }

    async fn remove_staged_bytes(&self, staging_key: &[u8]) -> SeamResult<()> {
        self.js
            .remove_staged_bytes(staging_key)
            .await
            .map_err(seam_error)?;
        Ok(())
    }

    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
        let value = self.js.staged_keys().await.map_err(seam_error)?;
        let array: Array = value.dyn_into().expect("stagedKeys must return an array");
        Ok(array
            .iter()
            .map(|item| item.unchecked_into::<Uint8Array>().to_vec())
            .collect())
    }

    async fn staged_bytes_total(&self) -> SeamResult<u64> {
        Ok(required_u64(
            self.js.staged_bytes_total().await.map_err(seam_error)?,
        ))
    }
}

/// Runs the `StagingStore` conformance kit against a JS `StagingStoreSeam`.
#[wasm_bindgen(js_name = runStagingStoreConformance)]
pub async fn run_staging_store_conformance(factory: Function) {
    console_error_panic_hook::set_once();
    conformance::staging_store::check(async || StagingStoreAdapter {
        js: open_seam(&factory).await.unchecked_into(),
    })
    .await;
}

// ---------------------------------------------------------------------------
// CredentialStore.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `CredentialStoreSeam` (packages/client).
    pub type JsCredentialStoreSeam;

    #[wasm_bindgen(method, catch, js_name = storeRefreshToken)]
    async fn store_refresh_token(
        this: &JsCredentialStoreSeam,
        refresh_token: &[u8],
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = loadRefreshToken)]
    async fn load_refresh_token(this: &JsCredentialStoreSeam) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = clearRefreshToken)]
    async fn clear_refresh_token(this: &JsCredentialStoreSeam) -> Result<JsValue, JsValue>;
}

struct CredentialStoreAdapter {
    js: JsCredentialStoreSeam,
}

impl CredentialStore for CredentialStoreAdapter {
    async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()> {
        self.js
            .store_refresh_token(refresh_token)
            .await
            .map_err(seam_error)?;
        Ok(())
    }

    async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>> {
        Ok(optional_bytes(
            self.js.load_refresh_token().await.map_err(seam_error)?,
        ))
    }

    async fn clear_refresh_token(&self) -> SeamResult<()> {
        self.js.clear_refresh_token().await.map_err(seam_error)?;
        Ok(())
    }
}

/// Runs the `CredentialStore` conformance kit against a JS `CredentialStoreSeam`
/// (web's no-op is a valid pass).
#[wasm_bindgen(js_name = runCredentialStoreConformance)]
pub async fn run_credential_store_conformance(factory: Function) {
    console_error_panic_hook::set_once();
    conformance::credential_store::check(async || CredentialStoreAdapter {
        js: open_seam(&factory).await.unchecked_into(),
    })
    .await;
}

// ---------------------------------------------------------------------------
// Scheduler.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `SchedulerSeam` (packages/client) — clock and delays only; background
    /// task execution is engine-side.
    pub type JsSchedulerSeam;

    #[wasm_bindgen(method, js_name = now)]
    fn now(this: &JsSchedulerSeam) -> f64;
    #[wasm_bindgen(method, catch, js_name = sleep)]
    async fn sleep(this: &JsSchedulerSeam, duration_ms: f64) -> Result<JsValue, JsValue>;
}

struct SchedulerAdapter {
    js: JsSchedulerSeam,
}

impl Scheduler for SchedulerAdapter {
    fn now(&self) -> UnixMillis {
        UnixMillis(self.js.now() as u64)
    }

    async fn sleep(&self, duration: Duration) {
        // Best-effort: a timer rejection is not a seam contract violation.
        let _ = self.js.sleep(duration.as_millis() as f64).await;
    }

    fn spawn(&self, task: BoxedTask) {
        // Background tasks run on the engine's own single-threaded executor via
        // the worker microtask queue — never handed across the JS boundary.
        wasm_bindgen_futures::spawn_local(task);
    }
}

/// Runs the `Scheduler` conformance kit against a JS `SchedulerSeam`.
#[wasm_bindgen(js_name = runSchedulerConformance)]
pub async fn run_scheduler_conformance(scheduler: JsSchedulerSeam) {
    console_error_panic_hook::set_once();
    let adapter = SchedulerAdapter { js: scheduler };
    conformance::scheduler::check(&adapter).await;
}

// ---------------------------------------------------------------------------
// RecordTransport.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `RecordTransportSeam` (packages/client).
    pub type JsRecordTransportSeam;

    #[wasm_bindgen(method, js_name = endpoints)]
    fn endpoints(this: &JsRecordTransportSeam) -> Vec<String>;
    #[wasm_bindgen(method, catch, js_name = getRecord)]
    async fn get_record(
        this: &JsRecordTransportSeam,
        endpoint: &str,
        routing_key: &str,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = putRecord)]
    async fn put_record(
        this: &JsRecordTransportSeam,
        endpoint: &str,
        routing_key: &str,
        record: &[u8],
    ) -> Result<JsValue, JsValue>;
}

struct RecordTransportAdapter {
    js: JsRecordTransportSeam,
}

impl RecordTransport for RecordTransportAdapter {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.js.endpoints().into_iter().map(EndpointId).collect()
    }

    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
    ) -> SeamResult<Option<Vec<u8>>> {
        Ok(optional_bytes(
            self.js
                .get_record(&endpoint.0, routing_key)
                .await
                .map_err(seam_error)?,
        ))
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        self.js
            .put_record(&endpoint.0, routing_key, record)
            .await
            .map_err(seam_error)?;
        Ok(())
    }
}

/// Runs the `RecordTransport` conformance kit against a JS
/// `RecordTransportSeam`. The caller supplies a fresh (unpublished) routing key
/// and the record bytes to round-trip.
#[wasm_bindgen(js_name = runRecordTransportConformance)]
pub async fn run_record_transport_conformance(
    transport: JsRecordTransportSeam,
    routing_key: String,
    record: Vec<u8>,
) {
    console_error_panic_hook::set_once();
    let adapter = RecordTransportAdapter { js: transport };
    conformance::record_transport::check(&adapter, &routing_key, &record).await;
}
