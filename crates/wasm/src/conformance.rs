//! Browser seam conformance bridge (feature `conformance`, browser wasm only).
//!
//! The engine ships one reusable conformance kit per seam trait
//! (`cipherbox_engine::testkit::conformance`, blueprint/testing.md "Seam
//! conformance kits"). This module re-exports each kit as a wasm-bindgen runner
//! that drives it against the real JS seam (adapted in `seams_bridge`) in a
//! real browser worker, so the same contract the in-memory fakes pass in cargo
//! tests is enforced against real IndexedDB and OPFS.
//!
//! The runners are `async fn`s: each returns a JS `Promise` that resolves when
//! the kit passes. A contract violation panics inside the kit (its `assert!`s);
//! `console_error_panic_hook` surfaces the assertion message to the browser
//! console, and the harness observes the non-resolution as a failure.
//!
//! This module also exports a test-only facade constructor (`deadLetterEvent`)
//! so the browser suite can exercise the facade's own `u64`→`bigint` boundary,
//! which the engine does not yet emit on its own.

use cipherbox_engine::facade;
use cipherbox_engine::seams::OpId;
use cipherbox_engine::testkit::conformance;
use js_sys::{Function, Promise};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::seams_bridge::{
    CredentialStoreAdapter, FloorStoreAdapter, JsRecordTransportSeam, JsSchedulerSeam,
    RecordTransportAdapter, SchedulerAdapter, SnapshotCacheAdapter, StagingStoreAdapter,
};

/// Calls a JS `(arg) => Promise<T>` and awaits its resolution, labelling any
/// misuse with `what`.
async fn call_async_with(f: &Function, arg: &JsValue, what: &str) -> JsValue {
    let result = f
        .call1(&JsValue::UNDEFINED, arg)
        .unwrap_or_else(|_| panic!("{what} must not throw"));
    let promise: Promise = result
        .dyn_into()
        .unwrap_or_else(|_| panic!("{what} must return a Promise"));
    JsFuture::from(promise)
        .await
        .unwrap_or_else(|_| panic!("{what} promise must resolve"))
}

/// Calls a JS `() => Promise<Seam>` factory and awaits the fresh seam handle
/// (the conformance kits' "reopen" contract).
async fn open_seam(factory: &Function) -> JsValue {
    call_async_with(factory, &JsValue::UNDEFINED, "seam factory").await
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

/// Runs the `SnapshotCache` conformance kit against a JS `SnapshotCacheSeam`.
#[wasm_bindgen(js_name = runSnapshotCacheConformance)]
pub async fn run_snapshot_cache_conformance(factory: Function) {
    console_error_panic_hook::set_once();
    conformance::snapshot_cache::check(async || SnapshotCacheAdapter {
        js: open_seam(&factory).await.unchecked_into(),
    })
    .await;
}

/// Runs the `StagingStore` conformance kit against a JS `StagingStoreSeam`.
///
/// `openBacking` is called with the kit's backing label and must resolve a
/// handle over that backing — distinct durable state per label, the same state
/// on a repeat call. `armFailedPut` is the host's fault lever for the same
/// backing: it must make that backing's next `putStagedBytes` at the kit's key
/// fail.
/// The staging-store kit's backing labels, in the order the kit asks for them,
/// so a JS host prepares and asserts over what the kit declares rather than a
/// transcribed copy of it.
#[wasm_bindgen(js_name = stagingStoreBackings)]
pub fn staging_store_backings() -> Vec<String> {
    conformance::staging_store::Backing::ALL
        .iter()
        .map(|backing| backing.label().to_string())
        .collect()
}

#[wasm_bindgen(js_name = runStagingStoreConformance)]
pub async fn run_staging_store_conformance(open_backing: Function, arm_failed_put: Function) {
    console_error_panic_hook::set_once();
    conformance::staging_store::check(
        async |backing: conformance::staging_store::Backing| StagingStoreAdapter {
            js: call_async_with(
                &open_backing,
                &JsValue::from_str(backing.label()),
                "staging backing factory",
            )
            .await
            .unchecked_into(),
        },
        async |backing: conformance::staging_store::Backing| {
            call_async_with(
                &arm_failed_put,
                &JsValue::from_str(backing.label()),
                "failed-put arm",
            )
            .await;
        },
    )
    .await;
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

/// Runs the `Scheduler` conformance kit against a JS `SchedulerSeam`.
#[wasm_bindgen(js_name = runSchedulerConformance)]
pub async fn run_scheduler_conformance(scheduler: JsSchedulerSeam) {
    console_error_panic_hook::set_once();
    let adapter = SchedulerAdapter { js: scheduler };
    conformance::scheduler::check(&adapter).await;
}

/// Runs the `RecordTransport` conformance kit against a JS `RecordTransportSeam`.
/// The caller supplies a fresh (unpublished) routing key and the record bytes
/// to round-trip.
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

/// Test-only: builds a `deadLetter` facade event carrying `opId`. The op id is
/// a `u64`, so the browser suite can assert the facade's `u64`→`bigint`
/// boundary round-trips a value beyond `Number.MAX_SAFE_INTEGER` intact.
#[wasm_bindgen(js_name = deadLetterEvent)]
pub fn dead_letter_event(op_id: u64) -> crate::Event {
    crate::Event::from_facade(facade::Event::DeadLetter {
        op_id: OpId(op_id),
        reason: facade::DeadLetterReason::Undecodable,
    })
}
