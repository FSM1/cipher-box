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
    BoxedTask, CappedFetchError, CredentialStore, EndpointId, FloorStore, Http, HttpCredentials,
    HttpMethod, HttpRequest, HttpResponse, Mailbox, MailboxItem, OpId, RecordTransport,
    RefreshHint, RefreshHintSource, Scheduler, SeamError, SeamResult, SnapshotCache, StagingStore,
    UnixMillis,
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
    #[derive(Clone)]
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

/// Bridges the per-key JS `FloorStoreSeam`; web batches ride the trait's
/// ordered fail-safe fallback ([`FloorStore::commit_floors`]).
#[derive(Clone)]
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
    #[derive(Clone)]
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

#[derive(Clone)]
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
    #[derive(Clone)]
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

#[derive(Clone)]
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
    #[derive(Clone)]
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

#[derive(Clone)]
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
    #[derive(Clone)]
    pub type JsSchedulerSeam;

    #[wasm_bindgen(method, js_name = now)]
    fn now(this: &JsSchedulerSeam) -> f64;
    #[wasm_bindgen(method, catch, js_name = sleep)]
    async fn sleep(this: &JsSchedulerSeam, duration_ms: f64) -> Result<JsValue, JsValue>;
}

#[derive(Clone)]
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
    #[derive(Clone)]
    pub type JsRecordTransportSeam;

    #[wasm_bindgen(method, js_name = endpoints)]
    fn endpoints(this: &JsRecordTransportSeam) -> Vec<String>;
    #[wasm_bindgen(method, catch, js_name = getRecord)]
    async fn get_record(
        this: &JsRecordTransportSeam,
        endpoint: &str,
        routing_key: &str,
        max_bytes: f64,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch, js_name = putRecord)]
    async fn put_record(
        this: &JsRecordTransportSeam,
        endpoint: &str,
        routing_key: &str,
        record: &[u8],
    ) -> Result<JsValue, JsValue>;
}

#[derive(Clone)]
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
        max_bytes: usize,
    ) -> SeamResult<Option<Vec<u8>>> {
        let result = self
            .js
            .get_record(&endpoint.0, routing_key, max_bytes as f64)
            .await
            .map_err(seam_error)?;
        match Reflect::get(&result, &JsValue::from_str("kind"))
            .ok()
            .and_then(|kind| kind.as_string())
            .as_deref()
        {
            // An over-cap body the seam admitted anyway is caught by the
            // engine-side backstop in `net::fanout`, which covers every host.
            Some("record") => Ok(optional_bytes(
                Reflect::get(&result, &JsValue::from_str("record")).unwrap_or(JsValue::UNDEFINED),
            )),
            Some("tooLarge") => Err(SeamError::new(format!(
                "getRecord: {} bytes exceeds the {}-byte cap",
                capped_count(&result, "observed"),
                capped_count(&result, "limit"),
            ))),
            // Fail closed: an unrecognized result carries no record the engine
            // may treat as within the cap.
            _ => Err(SeamError::new("getRecord returned an unknown result kind")),
        }
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
    /// JS `HttpSeam` (packages/client) — `send(HttpRequestData)` and
    /// `sendCapped(HttpRequestData, maxBytes)`.
    #[derive(Clone)]
    pub type JsHttpSeam;

    #[wasm_bindgen(method, catch, js_name = send)]
    async fn send(this: &JsHttpSeam, request: JsValue) -> Result<JsValue, JsValue>;
    /// Resolves a `CappedHttpResult`: `{kind:'response', …}` or
    /// `{kind:'tooLarge', observed, limit}`.
    #[wasm_bindgen(method, catch, js_name = sendCapped)]
    async fn send_capped(
        this: &JsHttpSeam,
        request: JsValue,
        max_bytes: f64,
    ) -> Result<JsValue, JsValue>;
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
    let credentials = match request.credentials {
        HttpCredentials::Include => "include",
        HttpCredentials::Omit => "omit",
    };
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("credentials"),
        &JsValue::from_str(credentials),
    );
    let timeout = match request.timeout_ms {
        Some(ms) => JsValue::from_f64(ms as f64),
        None => JsValue::NULL,
    };
    let _ = Reflect::set(&object, &JsValue::from_str("timeoutMs"), &timeout);
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

#[derive(Clone)]
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

    async fn send_capped(
        &self,
        request: HttpRequest,
        max_bytes: usize,
    ) -> Result<HttpResponse, CappedFetchError> {
        let result = self
            .js
            .send_capped(http_request_to_js(&request), max_bytes as f64)
            .await
            .map_err(|err| CappedFetchError::Transport(seam_error(err)))?;
        let kind = Reflect::get(&result, &JsValue::from_str("kind"))
            .ok()
            .and_then(|kind| kind.as_string());
        match kind.as_deref() {
            Some("response") => {
                let response =
                    http_response_from_js(result).map_err(CappedFetchError::Transport)?;
                // The JS seam is the streaming bound; this is the backstop a
                // buggy seam cannot talk the engine past.
                if response.body.len() > max_bytes {
                    return Err(CappedFetchError::BodyTooLarge {
                        observed: response.body.len(),
                        limit: max_bytes,
                    });
                }
                Ok(response)
            }
            Some("tooLarge") => Err(CappedFetchError::BodyTooLarge {
                observed: capped_count(&result, "observed"),
                limit: capped_count(&result, "limit"),
            }),
            // Fail closed: an unrecognized result carries no body the engine
            // may treat as within the cap.
            _ => Err(CappedFetchError::Transport(SeamError::new(
                "sendCapped returned an unknown result kind",
            ))),
        }
    }
}

/// A byte count off a `CappedHttpResult`, saturating: a count past `usize` is
/// over any cap either way.
fn capped_count(result: &JsValue, field: &str) -> usize {
    let value = Reflect::get(result, &JsValue::from_str(field)).unwrap_or(JsValue::UNDEFINED);
    usize::try_from(required_u64(value)).unwrap_or(usize::MAX)
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

// Capped-fetch boundary tests. Crate-private adapters, so these live here rather
// than in `tests/boundary.rs`. Browser-target only: `cargo test -p cipherbox-wasm
// --target wasm32-unknown-unknown`.

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use js_sys::Promise;
    use std::rc::Rc;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// A `JsHttpSeam` double whose `sendCapped` resolves `result`, recording the
    /// `maxBytes` it was handed.
    fn seam_resolving(result: JsValue) -> (JsHttpSeam, Rc<Cell<f64>>) {
        let seen = Rc::new(Cell::new(f64::NAN));
        let recorded = seen.clone();
        (
            seam_with(move |max_bytes| {
                recorded.set(max_bytes);
                Promise::resolve(&result)
            }),
            seen,
        )
    }

    /// A `JsHttpSeam` double whose `sendCapped` returns `reply`.
    fn seam_with(mut reply: impl FnMut(f64) -> Promise + 'static) -> JsHttpSeam {
        let send_capped = Closure::<dyn FnMut(JsValue, f64) -> Promise>::new(
            move |_request: JsValue, max_bytes: f64| reply(max_bytes),
        );
        let object = Object::new();
        let _ = Reflect::set(
            &object,
            &JsValue::from_str("sendCapped"),
            send_capped.as_ref(),
        );
        // The double outlives the call; the closure must not be freed under it.
        send_capped.forget();
        object.unchecked_into()
    }

    fn a_request() -> HttpRequest {
        HttpRequest {
            method: HttpMethod::Get,
            url: "https://gw.test/ipfs/bafy?format=raw".to_owned(),
            headers: Vec::new(),
            body: None,
            credentials: HttpCredentials::Omit,
            timeout_ms: Some(30_000),
        }
    }

    /// A `CappedHttpResult`-shaped JS object carrying `entries`.
    fn js_result(entries: Vec<(&str, JsValue)>) -> JsValue {
        let object = Object::new();
        for (key, value) in entries {
            let _ = Reflect::set(&object, &JsValue::from_str(key), &value);
        }
        object.into()
    }

    #[wasm_bindgen_test]
    async fn a_response_result_crosses_the_seam_with_the_cap_it_was_given() {
        let headers = Array::new();
        let pair = Array::new();
        pair.push(&JsValue::from_str("Content-Type"));
        pair.push(&JsValue::from_str("application/vnd.ipld.raw"));
        headers.push(&pair);
        let (js, seen) = seam_resolving(js_result(vec![
            ("kind", JsValue::from_str("response")),
            ("status", JsValue::from_f64(200.0)),
            ("headers", headers.into()),
            ("body", Uint8Array::from(&[1u8, 2, 3][..]).into()),
        ]));

        let response = HttpAdapter { js }
            .send_capped(a_request(), 4096)
            .await
            .expect("a within-cap response crosses as a response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, vec![1u8, 2, 3]);
        assert_eq!(seen.get(), 4096.0, "the cap crosses as the JS number");
    }

    #[wasm_bindgen_test]
    async fn a_response_body_over_the_cap_is_refused_even_when_the_seam_passed_it() {
        let (js, _) = seam_resolving(js_result(vec![
            ("kind", JsValue::from_str("response")),
            ("status", JsValue::from_f64(200.0)),
            ("headers", Array::new().into()),
            ("body", Uint8Array::from(&[7u8; 64][..]).into()),
        ]));

        let err = HttpAdapter { js }
            .send_capped(a_request(), 32)
            .await
            .expect_err("the engine enforces the cap the seam waved through");
        assert_eq!(
            err,
            CappedFetchError::BodyTooLarge {
                observed: 64,
                limit: 32
            }
        );
    }

    #[wasm_bindgen_test]
    async fn a_too_large_result_maps_to_the_body_too_large_verdict() {
        let (js, _) = seam_resolving(js_result(vec![
            ("kind", JsValue::from_str("tooLarge")),
            ("observed", JsValue::from_f64(9001.0)),
            ("limit", JsValue::from_f64(4096.0)),
        ]));

        let err = HttpAdapter { js }
            .send_capped(a_request(), 4096)
            .await
            .expect_err("an over-cap body never returns a response");
        assert_eq!(
            err,
            CappedFetchError::BodyTooLarge {
                observed: 9001,
                limit: 4096
            }
        );
    }

    #[wasm_bindgen_test]
    async fn an_unknown_result_kind_fails_closed_as_transport() {
        for entries in [
            vec![("kind", JsValue::from_str("somethingElse"))],
            vec![("status", JsValue::from_f64(200.0))],
        ] {
            let (js, _) = seam_resolving(js_result(entries));
            let err = HttpAdapter { js }
                .send_capped(a_request(), 8)
                .await
                .expect_err("an unrecognized result is never a body");
            assert!(
                matches!(err, CappedFetchError::Transport(_)),
                "expected a transport verdict, got {err:?}"
            );
        }
    }

    #[wasm_bindgen_test]
    async fn a_rejected_call_is_a_transport_failure() {
        let js = seam_with(|_| Promise::reject(&JsValue::from_str("network down")));
        let err = HttpAdapter { js }
            .send_capped(a_request(), 8)
            .await
            .expect_err("a rejection never yields a response");
        assert!(matches!(err, CappedFetchError::Transport(_)));
    }
}
