//! The desktop seam implementations run against the engine's reusable
//! per-seam conformance kits (blueprint/testing.md "Seam conformance kits":
//! "desktop implementations in cargo tests"), plus desktop-specific
//! durability tests the kits do not cover (StagingStore crash-ordering and
//! id-watermark durability).
//!
//! CredentialStore runs the kit twice: against the feature-gated
//! [`FileCredentialStore`] double, and — in the `real_keyring_*` tests — against
//! the production
//! [`KeyringCredentialStore`](cipherbox_desktop_seams::KeyringCredentialStore)
//! on whichever OS backend the host provides.

use cipherbox_desktop_seams::{
    FileCredentialStore, FileFloorStore, FileSnapshotCache, FileStagingStore, ReqwestHttp,
    ReqwestRecordTransport, TokioScheduler,
};
use cipherbox_engine::StagingRetireLedger;
use cipherbox_engine::seams::{
    CappedFetchError, CredentialStore, Http, HttpCredentials, HttpMethod, HttpRequest, StagingStore,
};
use cipherbox_engine::testkit::conformance::staging_store::Backing;
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

/// The desktop `StagingStore` kit. The fault lever denies the write target for
/// a replacement put, and for a first put — where Windows honours no denial on
/// a path that does not exist yet — removes the still-empty `staged/`
/// directory, which `FileStagingStore::open` recreates for the read-back.
#[test]
fn file_staging_store_passes_the_staging_store_kit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let denial = WriteDenial::for_store(&root.join(Backing::FailedReplacement.label()));
    block_on(conformance::staging_store::check(
        async |backing: Backing| FileStagingStore::open(root.join(backing.label())).unwrap(),
        async |backing: Backing| match backing {
            Backing::Ordering | Backing::FailedReplacement => denial.arm(),
            Backing::FailedFirstPut => {
                std::fs::remove_dir(root.join(backing.label()).join("staged"))
                    .expect("the kit's lever must be armed, or it proves nothing");
            }
        },
    ));
}

/// Denies writes to the path `atomic_write` must touch, restoring access on
/// drop so a kit panic still leaves the temp dir reclaimable.
struct WriteDenial(std::path::PathBuf);

impl WriteDenial {
    fn for_store(store_root: &std::path::Path) -> Self {
        let staged = store_root.join("staged");
        // Windows honours a read-only file, not a read-only directory, so the
        // denial has to sit on the sidecar the kit's key names.
        Self(if cfg!(windows) {
            let name: String = conformance::staging_store::FAILED_PUT_KEY
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            staged.join(format!("{name}.bin"))
        } else {
            staged
        })
    }

    fn arm(&self) {
        set_denied(&self.0, true).expect("the kit's lever must be armed, or it proves nothing");
    }
}

impl Drop for WriteDenial {
    fn drop(&mut self) {
        // Best-effort: drop runs while a kit panic unwinds, and a second panic
        // there aborts the process over the failure worth reporting. What is
        // left behind is a temp dir the harness reclaims.
        let _ = set_denied(&self.0, false);
    }
}

fn set_denied(path: &std::path::Path, denied: bool) -> std::io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(if denied { 0o555 } else { 0o755 });
    }
    #[cfg(not(unix))]
    perms.set_readonly(denied);
    std::fs::set_permissions(path, perms)
}

/// The retire ledger rides the durable staging store, so the desktop's
/// owed-retirement contract is the file store's. Each reopened handle is leaked
/// for the kit's borrow; the test process is its owner.
#[test]
fn the_file_staging_store_passes_the_retire_ledger_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retire-ledger");
    block_on(conformance::retire_ledger::check(async || {
        StagingRetireLedger::new(Box::leak(Box::new(FileStagingStore::open(&path).unwrap())))
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

/// The json-record-before-bin-sidecar removal ordering (hard constraint 5),
/// asserted at **every** interruption point in one op's life rather than only
/// on the happy path.
///
/// After each kill point the store is dropped and reopened, and the surviving
/// state must never be the dangerous inverse — an op record whose staged
/// sidecar is already gone. What it may leave is an orphan sidecar, which
/// orphan-sidecar GC ([`StagingStore::staged_keys`] + `remove_staged_bytes`)
/// reclaims.
#[test]
fn staging_store_removal_ordering_leaves_only_a_reclaimable_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");

    // Kill point 1: bytes staged, op not yet journaled.
    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        store
            .put_staged_bytes(b"chunk-key", b"sealed-ciphertext")
            .await
            .unwrap();
    });
    assert_survivors(
        &path,
        Survivors {
            op: false,
            sidecar: true,
        },
    );

    // Kill point 2: op journaled, nothing removed yet.
    let op_id = block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        store.enqueue_op(b"update-content-op").await.unwrap()
    });
    assert_survivors(
        &path,
        Survivors {
            op: true,
            sidecar: true,
        },
    );

    // Kill point 3: op record removed, sidecar not yet — the orphan.
    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        store.remove_op(op_id).await.unwrap();
    });
    assert_survivors(
        &path,
        Survivors {
            op: false,
            sidecar: true,
        },
    );

    // Kill point 4: GC reclaims the orphan and the budget goes back to zero.
    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        assert_eq!(
            store.staged_keys().await.unwrap(),
            vec![b"chunk-key".to_vec()]
        );
        store.remove_staged_bytes(b"chunk-key").await.unwrap();
        assert_eq!(store.staged_bytes_total().await.unwrap(), 0);
    });
    assert_survivors(
        &path,
        Survivors {
            op: false,
            sidecar: false,
        },
    );
}

/// What one kill point expects to find after the store is reopened.
struct Survivors {
    op: bool,
    sidecar: bool,
}

/// Reopens the staging store and asserts exactly what survived the kill point.
fn assert_survivors(path: &std::path::Path, expected: Survivors) {
    assert!(
        !expected.op || expected.sidecar,
        "no kill point may expect an op record without the sidecar it references"
    );
    block_on(async {
        let store = FileStagingStore::open(path).unwrap();
        assert_eq!(
            !store.queued_ops().await.unwrap().is_empty(),
            expected.op,
            "op record survival"
        );
        let staged = store.staged_bytes(b"chunk-key").await.unwrap();
        assert_eq!(staged.is_some(), expected.sidecar, "sidecar survival");
        if expected.sidecar {
            assert_eq!(staged.as_deref(), Some(&b"sealed-ciphertext"[..]));
        }
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

/// A clone hands out ids from the same counter. The engine's cold start clones
/// this seam into its spawned loops, so two handles that each counted for
/// themselves would give one id to two ops.
#[test]
fn staging_store_clones_share_one_id_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        let clone = store.clone();
        let first = store.enqueue_op(b"a").await.unwrap();
        let second = clone.enqueue_op(b"b").await.unwrap();
        assert_ne!(first.0, second.0, "a clone must not re-issue an id");

        let queued = store.queued_ops().await.unwrap();
        assert_eq!(queued.len(), 2, "both ops must land in the one queue");
    });
}

/// A clone raises floors against the same durable store, so a floor one handle
/// raised is never absent from another (the fail-closed floor law is only as
/// strong as the handles agreeing on it).
#[test]
fn floor_store_clones_share_the_durable_floors() {
    use cipherbox_engine::seams::FloorStore;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("floors");
    block_on(async {
        let store = FileFloorStore::open(&path).unwrap();
        let clone = store.clone();
        store.raise_epoch_floor(b"scope", 7).await.unwrap();
        assert_eq!(clone.epoch_floor(b"scope").await.unwrap(), Some(7));
        assert_eq!(
            clone.raise_epoch_floor(b"scope", 3).await.unwrap(),
            7,
            "monotonic-max holds across handles",
        );
    });
}

/// A temp file stranded in the store root by a crash mid-counter-write is
/// reclaimed on reopen — the `next_op_id` counter lives directly under the
/// root, so the root must be swept like the ops/staged subdirs.
#[test]
fn staging_store_reopen_sweeps_stranded_root_temp_debris() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    block_on(async {
        FileStagingStore::open(&path).unwrap();
    });

    // Simulate crash debris from a counter write: a temp file in the root.
    let debris = path.join(".cbtmp.stranded");
    std::fs::write(&debris, b"partial-counter").unwrap();
    assert!(debris.exists());

    block_on(async {
        FileStagingStore::open(&path).unwrap();
    });
    assert!(
        !debris.exists(),
        "reopen must sweep temp debris stranded in the store root"
    );
}

/// A foreign `.bin` file with a non-hex stem is ignored by both the budget
/// total and the GC enumeration, so the two always agree on the reclaimable
/// set — a file counted toward the budget but invisible to `staged_keys`
/// could never be reclaimed.
#[test]
fn staging_store_budget_and_gc_set_agree_on_foreign_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        store.put_staged_bytes(b"real", b"12345").await.unwrap();

        // Drop a foreign, non-hex-stemmed .bin into the staged dir.
        std::fs::write(path.join("staged").join("not-hex.bin"), b"9999999999").unwrap();

        assert_eq!(
            store.staged_keys().await.unwrap(),
            vec![b"real".to_vec()],
            "staged_keys must skip the non-hex file"
        );
        assert_eq!(
            store.staged_bytes_total().await.unwrap(),
            5,
            "staged_bytes_total must count only the real sidecar, not the foreign file"
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
            credentials: HttpCredentials::Omit,
            timeout_ms: None,
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
            credentials: HttpCredentials::Omit,
            timeout_ms: None,
        })
        .await
        .expect("a non-2xx status is a response, never a seam Err");

    assert_eq!(response.status, 418);
}

/// The seam follows no redirect: the 3xx comes back as the response it is, and
/// the `Authorization` header never reaches the hop's target. A doc comment
/// cannot fail CI, so the policy is asserted against a live server.
#[tokio::test]
async fn reqwest_http_follows_no_redirect_and_does_not_replay_the_bearer() {
    let server = MockServer::start();
    let http = ReqwestHttp::new().expect("client builds");

    let response = http
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{}/redirect", server.base_url()),
            headers: vec![("Authorization".into(), "Bearer member-token".into())],
            body: None,
            credentials: HttpCredentials::Omit,
            timeout_ms: None,
        })
        .await
        .expect("a 3xx is a response, never a seam Err");

    assert_eq!(response.status, 302, "the hop is surfaced, not taken");

    // `/redirect` served no body and `/echo` would have echoed one, so the
    // recorded request proves the target was never reached.
    let recorded = server.last_request().expect("a request was recorded");
    assert_eq!(recorded.path, "/redirect");
}

#[tokio::test]
async fn reqwest_http_capped_fetch_rejects_a_chunk_larger_than_the_cap() {
    let server = MockServer::start();
    let http = ReqwestHttp::new().expect("client builds");

    // Chunked, so no Content-Length pre-check applies and the first chunk the
    // transport hands over already exceeds the cap on its own.
    let error = http
        .send_capped(stream_request(&server, 64 * 1024), 16)
        .await
        .expect_err("an over-cap body must fail closed");

    match error {
        CappedFetchError::BodyTooLarge { observed, limit } => {
            assert_eq!(limit, 16);
            assert!(observed > limit, "observed {observed} must exceed the cap");
            assert!(
                observed < 64 * 1024,
                "the drain must abort at a chunk, not buffer the whole body ({observed} bytes)"
            );
        }
        other => panic!("expected BodyTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn reqwest_http_capped_fetch_admits_a_chunked_body_at_the_cap() {
    let server = MockServer::start();
    let http = ReqwestHttp::new().expect("client builds");

    let response = http
        .send_capped(stream_request(&server, 64), 64)
        .await
        .expect("the cap is inclusive");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, vec![b'x'; 64]);
}

fn stream_request(server: &MockServer, bytes: usize) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Get,
        url: format!("{}/stream/{bytes}", server.base_url()),
        headers: Vec::new(),
        body: None,
        credentials: HttpCredentials::Omit,
        timeout_ms: None,
    }
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
// Real OS keyring — the production `KeyringCredentialStore` against the
// platform backend it actually ships on: Apple Keychain, Windows Credential
// Manager, or the Secret Service.
//
// `#[ignore]`d so a plain `cargo test` skips them: the Linux backend needs a
// session bus and an unlocked Secret Service provider, which a developer shell
// need not have. Run them with
// `cargo test -p cipherbox-desktop-seams --test conformance -- --ignored`.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs the platform keyring backend; CI runs it with --ignored"]
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
        KeyringCredentialStore::new(service.clone()).expect("keyring worker started")
    }));
}

#[test]
#[ignore = "needs the platform keyring backend; CI runs it with --ignored"]
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
        let store = KeyringCredentialStore::new(service).expect("keyring worker started");
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
