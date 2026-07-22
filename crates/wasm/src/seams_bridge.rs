//! JS-seam → engine-seam adapters (wasm, browser target).
//!
//! Every browser seam is JavaScript (`packages/client` — IndexedDB, OPFS,
//! `fetch`), so it cannot implement a Rust trait directly. For each of the nine
//! engine seam traits this module declares the JS object's method surface as a
//! wasm-bindgen import and wraps it in a Rust adapter that implements the trait.
//! Two consumers share these adapters:
//!
//! - `host` builds the production [`crate::host::EngineHandle`] over them, and
//! - `conformance` (test-only) drives the engine's per-seam conformance kits
//!   against them in a real browser worker.
//!
//! No seam holds logic: the adapters move opaque bytes and marshal primitives,
//! nothing more — every trust decision already happened below the facade
//! (blueprint/engine.md). Numeric seam values (floors, sequence numbers, op
//! ids, byte totals) cross as `f64`, matching the JS seam signatures
//! (`packages/client/src/seams/types.ts`); their value domain is far below
//! `Number.MAX_SAFE_INTEGER`. The facade's own `u64` boundary (op ids, sizes)
//! crosses as `bigint` and lives in `lib.rs`, not here.

use cipherbox_engine::seams::{
    BoxedTask, CredentialStore, EndpointId, FloorStore, Http, HttpMethod, HttpRequest,
    HttpResponse, Mailbox, MailboxItem, OpId, RecordTransport, RefreshHint, RefreshHintSource,
    Scheduler, SeamError, SeamResult, SnapshotCache, StagingStore, UnixMillis,
};
use core::time::Duration;
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// JS value helpers.
// ---------------------------------------------------------------------------

/// Maps a rejected JS seam call to an opaque [`SeamError`] (diagnostics only —
/// a seam failure is host I/O, never a trust decision).
pub(crate) fn seam_error(value: JsValue) -> SeamError {
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
pub(crate) fn optional_u64(value: JsValue) -> Option<u64> {
    if value.is_null() || value.is_undefined() {
        None
    } else {
        value.as_f64().map(|number| number as u64)
    }
}

/// `number` → `u64` (0 if the value is not a number).
pub(crate) fn required_u64(value: JsValue) -> u64 {
    value
        .as_f64()
        .map(|number| number as u64)
        .unwrap_or_default()
}

/// `Uint8Array | null | undefined` → `Option<Vec<u8>>`.
pub(crate) fn optional_bytes(value: JsValue) -> Option<Vec<u8>> {
    if value.is_null() || value.is_undefined() {
        None
    } else {
        Some(value.unchecked_into::<Uint8Array>().to_vec())
    }
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
/// fallback (#682-safe; web-atomic is deferred — see the trait doc).
pub(crate) struct FloorStoreAdapter {
    pub(crate) js: JsFloorStoreSeam,
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

pub(crate) struct SnapshotCacheAdapter {
    pub(crate) js: JsSnapshotCacheSeam,
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

pub(crate) struct StagingStoreAdapter {
    pub(crate) js: JsStagingStoreSeam,
}

impl StagingStore for StagingStoreAdapter {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        Ok(OpId(required_u64(
            self.js.enqueue_op(op).await.map_err(seam_error)?,
        )))
    }

    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
        let value = self.js.queued_ops().await.map_err(seam_error)?;
        let array: Array = value
            .dyn_into()
            .map_err(|_| SeamError::new("queuedOps must return an array"))?;
        let mut ops = Vec::with_capacity(array.length() as usize);
        for entry in array.iter() {
            let pair: Array = entry
                .dyn_into()
                .map_err(|_| SeamError::new("each queued op must be a [id, bytes] pair"))?;
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
        let array: Array = value
            .dyn_into()
            .map_err(|_| SeamError::new("stagedKeys must return an array"))?;
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

pub(crate) struct CredentialStoreAdapter {
    pub(crate) js: JsCredentialStoreSeam,
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

pub(crate) struct SchedulerAdapter {
    pub(crate) js: JsSchedulerSeam,
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

pub(crate) struct RecordTransportAdapter {
    pub(crate) js: JsRecordTransportSeam,
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

// ---------------------------------------------------------------------------
// Http.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `HttpSeam` (packages/client) — `send(HttpRequestData)`.
    pub type JsHttpSeam;

    #[wasm_bindgen(method, catch, js_name = send)]
    async fn send(this: &JsHttpSeam, request: JsValue) -> Result<JsValue, JsValue>;
}

fn http_method_str(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Head => "HEAD",
    }
}

/// Marshals an engine [`HttpRequest`] to the JS `HttpRequestData` shape.
fn http_request_to_js(request: &HttpRequest) -> JsValue {
    let object = Object::new();
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("method"),
        &JsValue::from_str(http_method_str(request.method)),
    );
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("url"),
        &JsValue::from_str(&request.url),
    );
    let headers = Array::new();
    for (name, value) in &request.headers {
        let pair = Array::new();
        pair.push(&JsValue::from_str(name));
        pair.push(&JsValue::from_str(value));
        headers.push(&pair);
    }
    let _ = Reflect::set(&object, &JsValue::from_str("headers"), &headers);
    let body = match &request.body {
        Some(bytes) => Uint8Array::from(bytes.as_slice()).into(),
        None => JsValue::NULL,
    };
    let _ = Reflect::set(&object, &JsValue::from_str("body"), &body);
    object.into()
}

/// Parses the JS `HttpResponseData` shape back into an engine [`HttpResponse`].
fn http_response_from_js(value: JsValue) -> SeamResult<HttpResponse> {
    let status = Reflect::get(&value, &JsValue::from_str("status"))
        .ok()
        .and_then(|status| status.as_f64())
        .ok_or_else(|| SeamError::new("http response missing numeric status"))?
        as u16;
    let headers_value = Reflect::get(&value, &JsValue::from_str("headers"))
        .map_err(|_| SeamError::new("http response missing headers"))?;
    let headers_array: Array = headers_value
        .dyn_into()
        .map_err(|_| SeamError::new("http response headers must be an array"))?;
    let mut headers = Vec::with_capacity(headers_array.length() as usize);
    for entry in headers_array.iter() {
        let pair: Array = entry
            .dyn_into()
            .map_err(|_| SeamError::new("each response header must be a [name, value] pair"))?;
        let name = pair.get(0).as_string().unwrap_or_default();
        let header_value = pair.get(1).as_string().unwrap_or_default();
        headers.push((name, header_value));
    }
    let body = optional_bytes(
        Reflect::get(&value, &JsValue::from_str("body"))
            .map_err(|_| SeamError::new("http response missing body"))?,
    )
    .unwrap_or_default();
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

pub(crate) struct HttpAdapter {
    pub(crate) js: JsHttpSeam,
}

impl Http for HttpAdapter {
    async fn send(&self, request: HttpRequest) -> SeamResult<HttpResponse> {
        let response = self
            .js
            .send(http_request_to_js(&request))
            .await
            .map_err(seam_error)?;
        http_response_from_js(response)
    }
}

// ---------------------------------------------------------------------------
// Mailbox.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `MailboxSeam` (packages/client).
    pub type JsMailboxSeam;

    #[wasm_bindgen(method, catch, js_name = post)]
    async fn post(
        this: &JsMailboxSeam,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = poll)]
    async fn poll(this: &JsMailboxSeam) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = ack)]
    async fn ack(this: &JsMailboxSeam, item_id: &str) -> Result<JsValue, JsValue>;
}

pub(crate) struct MailboxAdapter {
    pub(crate) js: JsMailboxSeam,
}

impl Mailbox for MailboxAdapter {
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()> {
        self.js
            .post(recipient_public_key, sealed_payload, idempotency_key)
            .await
            .map_err(seam_error)?;
        Ok(())
    }

    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        let value = self.js.poll().await.map_err(seam_error)?;
        let array: Array = value
            .dyn_into()
            .map_err(|_| SeamError::new("mailbox poll must return an array"))?;
        let mut items = Vec::with_capacity(array.length() as usize);
        for entry in array.iter() {
            let item_id = Reflect::get(&entry, &JsValue::from_str("itemId"))
                .ok()
                .and_then(|id| id.as_string())
                .ok_or_else(|| SeamError::new("mailbox item missing itemId"))?;
            let sealed_payload = optional_bytes(
                Reflect::get(&entry, &JsValue::from_str("sealedPayload"))
                    .map_err(|_| SeamError::new("mailbox item missing sealedPayload"))?,
            )
            .unwrap_or_default();
            items.push(MailboxItem {
                item_id,
                sealed_payload,
            });
        }
        Ok(items)
    }

    async fn ack(&self, item_id: &str) -> SeamResult<()> {
        self.js.ack(item_id).await.map_err(seam_error)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RefreshHintSource.
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JS `RefreshHintSourceSeam` (packages/client). `nextHint` resolves to a
    /// truthy value for a hint, or `null`/`undefined` when the source is
    /// closed for good.
    pub type JsRefreshHintSourceSeam;

    #[wasm_bindgen(method, catch, js_name = nextHint)]
    async fn next_hint(this: &JsRefreshHintSourceSeam) -> Result<JsValue, JsValue>;
}

pub(crate) struct RefreshHintSourceAdapter {
    pub(crate) js: JsRefreshHintSourceSeam,
}

impl RefreshHintSource for RefreshHintSourceAdapter {
    async fn next_hint(&mut self) -> Option<RefreshHint> {
        // A rejected or nullish resolution means end-of-stream; the engine
        // stops listening. Losing a hint costs staleness, never correctness.
        match self.js.next_hint().await {
            Ok(value) if !value.is_null() && !value.is_undefined() => Some(RefreshHint),
            _ => None,
        }
    }
}
