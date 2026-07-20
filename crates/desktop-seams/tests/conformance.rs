//! The desktop seam implementations run against the engine's reusable
//! per-seam conformance kits (blueprint/testing.md "Seam conformance kits":
//! "desktop implementations in cargo tests"), plus desktop-specific
//! durability tests the kits do not cover (StagingStore crash-ordering and
//! id-watermark durability).
//!
//! CredentialStore CI story: the OS keyring is unavailable on headless CI,
//! so the automated gate runs the kit against the feature-gated
//! [`FileCredentialStore`] test double; the real
//! [`KeyringCredentialStore`](cipherbox_desktop_seams::KeyringCredentialStore)
//! is exercised by the `#[ignore]`d `real_keyring_*` tests, run by hand on a
//! machine with a keyring (see the report).

use cipherbox_desktop_seams::{
    FileCredentialStore, FileFloorStore, FileSnapshotCache, FileStagingStore, ReqwestHttp,
    ReqwestRecordTransport, TokioScheduler,
};
use cipherbox_engine::seams::{CredentialStore, Http, HttpMethod, HttpRequest, StagingStore};
use cipherbox_engine::testkit::{block_on, conformance};

mod mock_http;
use mock_http::MockServer;

// ---------------------------------------------------------------------------
// Fsync-barriered file stores — driven by the minimal single-future executor
// (no runtime needed: the bodies are synchronous filesystem work).
// ---------------------------------------------------------------------------

#[test]
fn file_floor_store_passes_the_floor_store_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("floors");
    block_on(conformance::floor_store::check(async || {
        FileFloorStore::open(&path).unwrap()
    }));
}

#[test]
fn file_staging_store_passes_the_staging_store_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    block_on(conformance::staging_store::check(async || {
        FileStagingStore::open(&path).unwrap()
    }));
}

#[test]
fn file_snapshot_cache_passes_the_snapshot_cache_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshots");
    block_on(conformance::snapshot_cache::check(async || {
        FileSnapshotCache::open(&path).unwrap()
    }));
}

/// The CI CredentialStore gate: the feature-gated file-backed double (the OS
/// keyring is not present on headless runners).
#[test]
fn file_credential_store_passes_the_credential_store_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials");
    block_on(conformance::credential_store::check(async || {
        FileCredentialStore::open(&path).unwrap()
    }));
}

// ---------------------------------------------------------------------------
// StagingStore desktop-specific durability — beyond what the kit asserts.
// ---------------------------------------------------------------------------

/// The json-record-before-bin-sidecar removal ordering (hard constraint 5).
///
/// Simulates a crash at the kill point *between* `remove_op` (the op record,
/// the "json" of the v1 journal) and `remove_staged_bytes` (the sidecar):
/// after reopen the op is durably gone while the sidecar survives as a
/// harmless orphan — never the dangerous inverse (an op record referencing a
/// sidecar that is already gone). Orphan-sidecar GC then reclaims it.
#[test]
fn staging_store_removal_ordering_leaves_only_a_reclaimable_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");

    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        let op_id = store.enqueue_op(b"update-content-op").await.unwrap();
        store
            .put_staged_bytes(b"chunk-key", b"sealed-ciphertext")
            .await
            .unwrap();

        // Engine completes the op: op record removed durably FIRST...
        store.remove_op(op_id).await.unwrap();
        // ...and the process dies here, before remove_staged_bytes.
    });

    // Reopen (post-"crash"): the op is gone, the sidecar is an orphan.
    block_on(async {
        let reopened = FileStagingStore::open(&path).unwrap();
        assert!(
            reopened.queued_ops().await.unwrap().is_empty(),
            "the op record must be durably gone after remove_op"
        );
        assert_eq!(
            reopened.staged_bytes(b"chunk-key").await.unwrap(),
            Some(b"sealed-ciphertext".to_vec()),
            "the sidecar must survive as a harmless orphan, never a dangling op"
        );

        // Orphan-sidecar GC reclaims it.
        assert_eq!(
            reopened.staged_keys().await.unwrap(),
            vec![b"chunk-key".to_vec()]
        );
        reopened.remove_staged_bytes(b"chunk-key").await.unwrap();
        assert!(reopened.staged_keys().await.unwrap().is_empty());
        assert_eq!(reopened.staged_bytes_total().await.unwrap(), 0);
    });
}

/// Op ids never repeat, even after every op drains and the store reopens —
/// stronger than the kit, which keeps one surviving op across reopen.
#[test]
fn staging_store_op_ids_never_reuse_across_a_full_drain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");

    let last = block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        let a = store.enqueue_op(b"a").await.unwrap();
        let b = store.enqueue_op(b"b").await.unwrap();
        // Drain the queue completely.
        store.remove_op(a).await.unwrap();
        store.remove_op(b).await.unwrap();
        assert!(store.queued_ops().await.unwrap().is_empty());
        b
    });

    block_on(async {
        let reopened = FileStagingStore::open(&path).unwrap();
        let next = reopened.enqueue_op(b"c").await.unwrap();
        assert!(
            next > last,
            "an id after a full drain + reopen must still exceed every prior id"
        );
    });
}

// ---------------------------------------------------------------------------
// Network seams — driven on a Tokio current-thread runtime (reqwest needs the
// reactor). RecordTransport has a kit; Http does not (pure passthrough), so a
// focused round-trip test stands in.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reqwest_record_transport_passes_the_record_transport_kit() {
    // Two independent endpoints, matching the engine's parallel fan-out
    // shape — each is its own routing store.
    let endpoint_a = MockServer::start();
    let endpoint_b = MockServer::start();
    let transport = ReqwestRecordTransport::new(vec![endpoint_a.base_url(), endpoint_b.base_url()])
        .expect("client builds");

    conformance::record_transport::check(
        &transport,
        "k51-fresh-desktop-routing-key",
        b"opaque-signed-record-bytes",
    )
    .await;
}

#[tokio::test]
async fn reqwest_http_round_trips_request_and_response() {
    let server = MockServer::start();
    let http = ReqwestHttp::new().expect("client builds");

    // /echo returns the body verbatim plus an x-echo header, and records the
    // request it received.
    let response = http
        .send(HttpRequest {
            method: HttpMethod::Post,
            url: format!("{}/echo", server.base_url()),
            headers: vec![("x-cipherbox".into(), "seam".into())],
            body: Some(b"request-payload".to_vec()),
        })
        .await
        .expect("transport-level success");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"request-payload");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-echo") && value == "yes"),
        "response headers must round-trip"
    );

    // The engine's header actually reached the server.
    let recorded = server.last_request().expect("a request was recorded");
    assert!(
        recorded
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-cipherbox") && value == "seam"),
        "the request header the engine set must be sent verbatim"
    );
    assert_eq!(recorded.body, b"request-payload");
}

#[tokio::test]
async fn reqwest_http_returns_non_2xx_as_a_response_not_an_error() {
    let server = MockServer::start();
    let http = ReqwestHttp::new().expect("client builds");

    let response = http
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{}/teapot", server.base_url()),
            headers: Vec::new(),
            body: None,
        })
        .await
        .expect("a non-2xx status is a response, never a seam Err");

    assert_eq!(response.status, 418);
}

// ---------------------------------------------------------------------------
// Scheduler — the kit needs real timers + a LocalSet (spawn is spawn_local).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tokio_scheduler_passes_the_scheduler_kit() {
    // spawn() delegates to spawn_local, which requires a LocalSet.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let scheduler = TokioScheduler::new();
            conformance::scheduler::check(&scheduler).await;
        })
        .await;
}

// ---------------------------------------------------------------------------
// Last-account id — the one datum beyond the refresh token that the desktop
// CredentialStore holds (blueprint/desktop.md). Exercised on the file double.
// ---------------------------------------------------------------------------

#[test]
fn credential_store_persists_last_account_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials");
    block_on(async {
        let store = FileCredentialStore::open(&path).unwrap();
        assert_eq!(store.load_last_account_id().await.unwrap(), None);
        store.store_last_account_id(b"account-7").await.unwrap();
        assert_eq!(
            store.load_last_account_id().await.unwrap(),
            Some(b"account-7".to_vec())
        );

        // Independent of the refresh token.
        store.store_refresh_token(b"tok").await.unwrap();
        assert_eq!(
            store.load_last_account_id().await.unwrap(),
            Some(b"account-7".to_vec())
        );

        store.clear_last_account_id().await.unwrap();
        assert_eq!(store.load_last_account_id().await.unwrap(), None);
    });
}

// ---------------------------------------------------------------------------
// Real OS keyring — ignored by default (no keyring on headless CI). Run
// locally: `cargo test -p cipherbox-desktop-seams --test conformance --
// --ignored`.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires an unlocked OS keyring; run locally"]
fn real_keyring_credential_store_passes_the_credential_store_kit() {
    use cipherbox_desktop_seams::KeyringCredentialStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Unique service per run so the backing starts empty and never collides
    // with a real CipherBox install.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let service = format!("com.cipherbox.desktop.test.{}.{nonce}", std::process::id());

    block_on(conformance::credential_store::check(async || {
        KeyringCredentialStore::new(service.clone())
    }));
}

#[test]
#[ignore = "requires an unlocked OS keyring; run locally"]
fn real_keyring_credential_store_persists_last_account_id() {
    use cipherbox_desktop_seams::KeyringCredentialStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let service = format!(
        "com.cipherbox.desktop.test.lastacct.{}.{nonce}",
        std::process::id()
    );

    block_on(async {
        let store = KeyringCredentialStore::new(service);
        assert_eq!(store.load_last_account_id().await.unwrap(), None);
        store.store_last_account_id(b"acct-xyz").await.unwrap();
        assert_eq!(
            store.load_last_account_id().await.unwrap(),
            Some(b"acct-xyz".to_vec())
        );
        // Clean up the keyring entry.
        store.clear_last_account_id().await.unwrap();
        assert_eq!(store.load_last_account_id().await.unwrap(), None);
    });
}
