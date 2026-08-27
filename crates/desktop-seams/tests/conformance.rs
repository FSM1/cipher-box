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

use core::cell::RefCell;
use std::path::Path;

use cipherbox_core::suite::x25519::X25519Secret;
use cipherbox_desktop_seams::{
    CoreKitWrappingKey, FileCredentialStore, FileFloorStore, FileSnapshotCache, FileStagingStore,
    KeyringCredentialStore, ReqwestHttp, ReqwestRecordTransport, SealedCoreKitStore,
    TokioScheduler,
};
use cipherbox_engine::seams::{
    CappedFetchError, CredentialStore, FloorStore, Http, HttpCredentials, HttpMethod, HttpRequest,
    SeamResult, StagingStore,
};
use cipherbox_engine::sync::BookkeepingSeal;
use cipherbox_engine::testkit::conformance::staging_store::Backing;
use cipherbox_engine::testkit::{SeededEntropy, block_on, conformance};
use cipherbox_engine::{Entropy, StagingRetireLedger};

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
            Backing::Ordering | Backing::FailedReplacement | Backing::Cleared => denial.arm(),
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
    // The seal outlives every handle the kit opens, so one identity's entries
    // stay readable across a reopen.
    let secret: &X25519Secret = Box::leak(Box::new(X25519Secret::from_scalar([0x4c; 32])));
    let entropy: &RefCell<dyn Entropy> = Box::leak(Box::new(RefCell::new(SeededEntropy::new(7))));
    block_on(conformance::retire_ledger::check(async || {
        StagingRetireLedger::new(
            Box::leak(Box::new(FileStagingStore::open(&path).unwrap())),
            BookkeepingSeal::new(secret, entropy),
        )
    }));
}

/// The reason `clear` sweeps with `empty_dir` rather than the temp-skipping
/// `list_file_names`: an in-flight temp still holds the staged ciphertext its
/// killed writer was landing, so an erase that stepped over it would leave that
/// record behind. Enumeration hides temps, so nothing else would ever reclaim it.
#[test]
fn clearing_a_staging_store_sweeps_the_temps_enumeration_hides() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    let store = FileStagingStore::open(&path).unwrap();
    block_on(store.put_staged_bytes(b"key", b"staged")).unwrap();
    std::fs::write(
        path.join("staged").join(".cbtmp.stranded"),
        b"half a record",
    )
    .unwrap();

    block_on(store.clear()).unwrap();

    assert_eq!(
        std::fs::read_dir(path.join("staged")).unwrap().count(),
        0,
        "a temp holding staged bytes must not survive the erase"
    );
}

/// A refused leg must not spare the rest: forget is the only exit from a
/// device's durable state, so a sweep that stopped at the first refusal would
/// leave records standing on a device that reported itself erased. Unix-only —
/// Windows honours a read-only file, not a read-only directory, so the denial
/// has no per-directory lever there.
#[cfg(unix)]
#[test]
fn a_refused_erase_leg_does_not_spare_the_ones_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    let store = FileStagingStore::open(&path).unwrap();
    block_on(store.enqueue_op(b"queued-op")).unwrap();
    block_on(store.put_staged_bytes(b"key", b"staged")).unwrap();

    let denial = WriteDenial(path.join("ops"));
    denial.arm();
    let refusal = block_on(store.clear());
    drop(denial);

    assert!(
        refusal.is_err(),
        "a leg that could not be swept must reach the caller"
    );
    assert_eq!(
        std::fs::read_dir(path.join("staged")).unwrap().count(),
        0,
        "the leg after the refusal must still be swept"
    );
    assert_eq!(
        std::fs::read_dir(path.join("ops")).unwrap().count(),
        1,
        "only the leg that refused is left standing"
    );
}

/// The same contract across the floor store's three directories, with the
/// refusal in the middle: intents, then epoch, then sequence.
#[cfg(unix)]
#[test]
fn a_refused_floor_erase_leg_does_not_spare_the_ones_around_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("floors");
    let store = FileFloorStore::open(&path).unwrap();
    block_on(store.raise_epoch_floor(b"scope", 4)).unwrap();
    block_on(store.raise_sequence_floor(b"name", 9)).unwrap();
    std::fs::write(path.join("intent").join("stranded"), b"replayable").unwrap();

    let denial = WriteDenial(path.join("epoch"));
    denial.arm();
    let refusal = block_on(store.clear());
    drop(denial);

    assert!(
        refusal.is_err(),
        "a leg that could not be swept must reach the caller"
    );
    assert_eq!(
        std::fs::read_dir(path.join("intent")).unwrap().count(),
        0,
        "the leg before the refusal is swept"
    );
    assert_eq!(
        std::fs::read_dir(path.join("seq")).unwrap().count(),
        0,
        "the leg after the refusal is swept too"
    );
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

/// A noncanonical `ops/` filename parses to the same id as the zero-padded one
/// the store writes, so a queue keyed by listed name would hand the engine one
/// durable op twice — and the drain would replay it as two.
#[test]
fn staging_store_queues_one_entry_per_op_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging");
    block_on(async {
        let store = FileStagingStore::open(&path).unwrap();
        let op_id = store.enqueue_op(b"the-one-op").await.unwrap();

        // A short-named twin of the canonical record, the way a foreign writer
        // or a hand-edited store would leave one.
        std::fs::write(
            path.join("ops").join(format!("{}.op", op_id.0)),
            b"the-one-op",
        )
        .unwrap();

        assert_eq!(
            store.queued_ops().await.unwrap(),
            vec![(op_id, b"the-one-op".to_vec())],
            "two names for one id must queue one op"
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
// CredentialStore holds (blueprint/desktop.md). Not on the engine's
// `CredentialStore` trait, so it has a kit of its own here rather than in
// `testkit::conformance`.
// ---------------------------------------------------------------------------

/// One entry point, like the engine's kits: a case reached through a second
/// function is a case an implementation can omit. `open` must hand back a store
/// over the same backing on every call, so the reopen leg means something.
async fn check_last_account_id<S, F>(mut open: F)
where
    S: LastAccountId,
    F: AsyncFnMut() -> S,
{
    let store = open().await;
    assert_eq!(
        store.load_last_account_id().await.unwrap(),
        None,
        "a store that was never written holds no account id"
    );

    store.store_last_account_id(b"account-7").await.unwrap();
    assert_eq!(
        store.load_last_account_id().await.unwrap(),
        Some(b"account-7".to_vec())
    );
    assert_eq!(
        open().await.load_last_account_id().await.unwrap(),
        Some(b"account-7".to_vec()),
        "the stored id survives a reopen — it names the account directory next launch"
    );

    // Independent of the refresh token: the two are separate entries.
    store.store_refresh_token(b"tok").await.unwrap();
    assert_eq!(
        store.load_last_account_id().await.unwrap(),
        Some(b"account-7".to_vec())
    );

    // The forget-this-device leg. Durable, and idempotent: the shell drops it
    // on a path with no surface left to report a refusal to, so a second clear
    // must not turn into one.
    store.clear_last_account_id().await.unwrap();
    store.clear_last_account_id().await.unwrap();
    assert_eq!(store.load_last_account_id().await.unwrap(), None);
    assert_eq!(
        open().await.load_last_account_id().await.unwrap(),
        None,
        "the clear survives reopening the store"
    );
    assert_eq!(
        open().await.load_refresh_token().await.unwrap(),
        Some(b"tok".to_vec()),
        "and takes only its own entry with it"
    );
}

/// The inherent surface both desktop credential stores carry by hand — the
/// engine's `CredentialStore` trait has only the refresh-token trio.
trait LastAccountId: CredentialStore {
    async fn store_last_account_id(&self, account_id: &[u8]) -> SeamResult<()>;
    async fn load_last_account_id(&self) -> SeamResult<Option<Vec<u8>>>;
    async fn clear_last_account_id(&self) -> SeamResult<()>;
}

impl LastAccountId for FileCredentialStore {
    async fn store_last_account_id(&self, account_id: &[u8]) -> SeamResult<()> {
        FileCredentialStore::store_last_account_id(self, account_id).await
    }
    async fn load_last_account_id(&self) -> SeamResult<Option<Vec<u8>>> {
        FileCredentialStore::load_last_account_id(self).await
    }
    async fn clear_last_account_id(&self) -> SeamResult<()> {
        FileCredentialStore::clear_last_account_id(self).await
    }
}

#[test]
fn file_credential_store_passes_the_last_account_id_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials");
    block_on(check_last_account_id(async || {
        FileCredentialStore::open(&path).unwrap()
    }));
}

// ---------------------------------------------------------------------------
// Core Kit store — the login SDK's own store, sealed at rest under a wrapping
// key the credential store holds. No engine seam serves it, so both kits live
// here rather than in `testkit::conformance`.
// ---------------------------------------------------------------------------

/// One entry point per kit, as the engine's own kits have. `open` must hand
/// back a store over the same backing on every call, so the reopen legs — the
/// restart this store exists for — mean something.
async fn check_core_kit_wrapping_key<C, F>(mut open: F)
where
    C: CoreKitWrappingKey,
    F: AsyncFnMut() -> C,
{
    /// The stored bytes, flattened past the `Zeroizing` the load hands back.
    async fn held<C: CoreKitWrappingKey>(keys: &C) -> Option<Vec<u8>> {
        keys.load_core_kit_wrapping_key()
            .await
            .unwrap()
            .map(|key| key.to_vec())
    }

    let keys = open().await;
    assert_eq!(
        held(&keys).await,
        None,
        "a device that was never written holds no wrapping key"
    );

    keys.store_core_kit_wrapping_key(&[7u8; 32]).await.unwrap();
    assert_eq!(held(&keys).await, Some(vec![7u8; 32]));
    assert_eq!(
        held(&open().await).await,
        Some(vec![7u8; 32]),
        "the key survives a reopen — that is what lets a recovered factor survive a restart"
    );

    keys.store_core_kit_wrapping_key(&[9u8; 32]).await.unwrap();
    assert_eq!(
        held(&keys).await,
        Some(vec![9u8; 32]),
        "a second store replaces the key rather than adding one"
    );

    // The forget-this-device leg. Idempotent: the shell drops it on a path with
    // no surface left to report a refusal to.
    keys.clear_core_kit_wrapping_key().await.unwrap();
    keys.clear_core_kit_wrapping_key().await.unwrap();
    assert_eq!(held(&keys).await, None);
    assert_eq!(
        held(&open().await).await,
        None,
        "the clear survives reopening the store"
    );
}

/// The store the login SDK drives. `open` must hand back a store over the same
/// directory *and* the same wrapping-key custody every call.
async fn check_core_kit_store<C, F>(mut open: F)
where
    C: CoreKitWrappingKey,
    F: AsyncFnMut() -> SealedCoreKitStore<C>,
{
    const SESSION: &str = "corekit_store";
    const OTHER: &str = "corekit_other";

    let store = open().await;
    assert_eq!(
        store.get_item(SESSION).await.unwrap(),
        None,
        "a device that was never written holds no session"
    );

    store.set_item(SESSION, "a device factor").await.unwrap();
    assert_eq!(
        store.get_item(SESSION).await.unwrap().as_deref(),
        Some("a device factor")
    );
    assert_eq!(
        open().await.get_item(SESSION).await.unwrap().as_deref(),
        Some("a device factor"),
        "the session survives a restart, which is the whole point of the store"
    );

    store.set_item(SESSION, "a rotated factor").await.unwrap();
    assert_eq!(
        store.get_item(SESSION).await.unwrap().as_deref(),
        Some("a rotated factor"),
        "a write replaces the slot rather than adding one"
    );

    store.set_item(OTHER, "another slot").await.unwrap();
    assert_eq!(
        store.get_item(SESSION).await.unwrap().as_deref(),
        Some("a rotated factor"),
        "slots are independent of one another"
    );

    // The forget-this-device leg, and idempotent for the same reason the
    // wrapping-key clear is.
    store.purge().await.unwrap();
    store.purge().await.unwrap();
    assert_eq!(store.get_item(SESSION).await.unwrap(), None);
    assert_eq!(store.get_item(OTHER).await.unwrap(), None);
    assert_eq!(
        open().await.get_item(SESSION).await.unwrap(),
        None,
        "the purge survives a restart"
    );

    // …and a purged device is a usable device: the next sign-in mints a key.
    let store = open().await;
    store.set_item(SESSION, "a fresh factor").await.unwrap();
    assert_eq!(
        store.get_item(SESSION).await.unwrap().as_deref(),
        Some("a fresh factor")
    );
    store.purge().await.unwrap();
}

/// A store over `dir`, reopened as a restart would. `seed` varies per reopen so
/// two stores over one wrapping key never replay a nonce — production draws from
/// the OS, and a fixture that reused one would hide a regression to a constant.
fn file_backed_core_kit_store(dir: &Path, seed: u64) -> SealedCoreKitStore<FileCredentialStore> {
    SealedCoreKitStore::open(
        dir.join("core-kit-store"),
        FileCredentialStore::open(dir.join("credentials")).unwrap(),
        Box::new(SeededEntropy::new(seed)),
    )
    .unwrap()
}

#[test]
fn file_credential_store_passes_the_core_kit_wrapping_key_kit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials");
    block_on(check_core_kit_wrapping_key(async || {
        FileCredentialStore::open(&path).unwrap()
    }));
}

#[test]
fn file_backed_core_kit_store_passes_the_core_kit_store_kit() {
    let dir = tempfile::tempdir().unwrap();
    let mut reopened = 0u64;
    block_on(check_core_kit_store(async || {
        reopened += 1;
        file_backed_core_kit_store(dir.path(), reopened)
    }));
}

/// The envelope is durable across app versions, so its shape is pinned here:
/// a slot is the 24-byte nonce and then the AEAD output under the held wrapping
/// key and this exact AAD. A build that changed either would open nothing a
/// previous one sealed, and this store drops what it cannot open.
#[test]
fn a_slot_is_the_nonce_and_then_the_aead_output_under_this_exact_aad() {
    const FACTOR: &str = "a device factor";
    let dir = tempfile::tempdir().unwrap();
    let keys = FileCredentialStore::open(dir.path().join("credentials")).unwrap();
    block_on(keys.store_core_kit_wrapping_key(&[0x2a; 32])).unwrap();

    let store = file_backed_core_kit_store(dir.path(), 11);
    block_on(store.set_item("corekit_store", FACTOR)).unwrap();

    let slot = std::fs::read(
        dir.path()
            .join("core-kit-store")
            .join(cipherbox_core::hex::lower(b"corekit_store")),
    )
    .unwrap();
    let (nonce, ciphertext) = slot.split_at(24);
    assert_eq!(
        ciphertext.len(),
        FACTOR.len() + 16,
        "the AEAD output is the plaintext and its tag"
    );
    assert_eq!(
        cipherbox_core::suite::aead::decrypt(
            &[0x2a; 32],
            nonce.try_into().unwrap(),
            b"cipherbox/v2/core-kit-store/v1/corekit_store",
            ciphertext,
        )
        .as_deref(),
        Some(FACTOR.as_bytes()),
    );
}

/// Two seals under one key must never share a nonce: that is a confidentiality
/// break, and nothing downstream would report it.
#[test]
fn two_writes_of_one_slot_carry_different_nonces() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 13);
    let slot = dir
        .path()
        .join("core-kit-store")
        .join(cipherbox_core::hex::lower(b"corekit_store"));

    block_on(store.set_item("corekit_store", "a device factor")).unwrap();
    let first = std::fs::read(&slot).unwrap();
    block_on(store.set_item("corekit_store", "a rotated factor")).unwrap();
    let second = std::fs::read(&slot).unwrap();

    assert_ne!(first[..24], second[..24]);
}

/// A held entry this build cannot use as a key is custody it does not
/// understand: minting over it would destroy every slot it opens, so the read
/// refuses instead.
#[test]
fn a_wrong_length_wrapping_key_fails_closed_rather_than_being_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 17);
    block_on(store.set_item("corekit_store", "a device factor")).unwrap();

    let keys = FileCredentialStore::open(dir.path().join("credentials")).unwrap();
    block_on(keys.store_core_kit_wrapping_key(b"too short")).unwrap();

    let store = file_backed_core_kit_store(dir.path(), 19);
    assert!(block_on(store.get_item("corekit_store")).is_err());
    assert!(block_on(store.set_item("corekit_store", "a rotated factor")).is_err());
    assert_eq!(
        block_on(keys.load_core_kit_wrapping_key())
            .unwrap()
            .map(|held| held.to_vec()),
        Some(b"too short".to_vec()),
        "nothing minted over the entry this build could not read"
    );
    assert_eq!(
        std::fs::read_dir(dir.path().join("core-kit-store"))
            .unwrap()
            .count(),
        1,
        "and the slot it opens is still here to be opened once it is readable"
    );
}

/// The law this store exists for: what the SDK hands it is a scalar that opens
/// the record holding the login secret, so no byte of it may reach the disk in
/// the clear (blueprint/desktop.md, ciphertext-only at rest).
#[test]
fn nothing_the_sdk_stores_reaches_the_disk_in_the_clear() {
    const FACTOR: &str = "a-device-factor-share-0123456789";
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 5);
    block_on(store.set_item("corekit_store", FACTOR)).unwrap();

    let slots = dir.path().join("core-kit-store");
    let mut read = 0usize;
    for entry in std::fs::read_dir(&slots).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes.windows(FACTOR.len()).any(|w| w == FACTOR.as_bytes()),
            "a slot holds sealed bytes only"
        );
        read += 1;
    }
    assert_eq!(read, 1, "the write landed in exactly one slot");
}

/// The webview reaches this store over IPC, so what it may put there is
/// bounded: neither an oversized value nor an oversized slot name is written,
/// and the read side refuses the same name rather than composing it.
#[test]
fn what_the_webview_can_put_in_a_slot_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 5);

    let oversized = "x".repeat(64 * 1024 + 1);
    assert!(block_on(store.set_item("corekit_store", &oversized)).is_err());

    for not_a_name in ["", &"k".repeat(97)] {
        assert!(block_on(store.set_item(not_a_name, "a device factor")).is_err());
        assert!(block_on(store.get_item(not_a_name)).is_err());
    }

    // …and the count is bounded too, so the directory does not grow a name at a
    // time.
    for slot in 0..8 {
        block_on(store.set_item(&format!("slot-{slot}"), "a device factor")).unwrap();
    }
    assert!(block_on(store.set_item("slot-8", "a device factor")).is_err());
    assert!(
        block_on(store.set_item("slot-0", "a rotated factor")).is_ok(),
        "a full store still replaces a slot it already holds"
    );

    assert_eq!(
        std::fs::read_dir(dir.path().join("core-kit-store"))
            .unwrap()
            .count(),
        8,
        "no refused write left a slot behind"
    );
}

/// A device that holds no wrapping key today may hold one again tomorrow — a
/// keyring entry a backup has not restored yet, or one another instance is
/// re-minting — so a read reports nothing rather than destroying what it could
/// not open.
#[test]
fn a_read_with_no_wrapping_key_held_keeps_the_slot() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 23);
    block_on(store.set_item("corekit_store", "a device factor")).unwrap();

    let keys = FileCredentialStore::open(dir.path().join("credentials")).unwrap();
    block_on(keys.clear_core_kit_wrapping_key()).unwrap();

    let reopened = file_backed_core_kit_store(dir.path(), 29);
    assert_eq!(block_on(reopened.get_item("corekit_store")).unwrap(), None);
    assert_eq!(
        std::fs::read_dir(dir.path().join("core-kit-store"))
            .unwrap()
            .count(),
        1,
        "the slot outlives a key this device cannot reach"
    );
}

/// A slot opens under the key that sealed it and nothing else, so a disk copy
/// taken without the keyring's contents yields sealed bytes only.
#[test]
fn a_slot_sealed_under_one_wrapping_key_does_not_open_under_another() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 5);
    block_on(store.set_item("corekit_store", "a device factor")).unwrap();

    // The device keeps its slots and loses its key — a restored partial backup.
    let keys = FileCredentialStore::open(dir.path().join("credentials")).unwrap();
    block_on(keys.store_core_kit_wrapping_key(&[3u8; 32])).unwrap();

    let store = file_backed_core_kit_store(dir.path(), 7);
    assert_eq!(
        block_on(store.get_item("corekit_store")).unwrap(),
        None,
        "bytes the held key does not authenticate open nothing"
    );
}

/// The AAD binds the storage key, so one slot's ciphertext moved onto another
/// slot's name is refused rather than opened as that slot's value.
#[test]
fn one_slots_ciphertext_does_not_open_as_another_slots_value() {
    let dir = tempfile::tempdir().unwrap();
    let store = file_backed_core_kit_store(dir.path(), 5);
    block_on(store.set_item("corekit_store", "a device factor")).unwrap();
    block_on(store.set_item("corekit_other", "another slot")).unwrap();

    let slots = dir.path().join("core-kit-store");
    let named = |key: &str| slots.join(cipherbox_core::hex::lower(key.as_bytes()));
    std::fs::copy(named("corekit_store"), named("corekit_other")).unwrap();

    assert_eq!(
        block_on(store.get_item("corekit_other")).unwrap(),
        None,
        "a transplanted slot is refused"
    );
    assert_eq!(
        block_on(store.get_item("corekit_store"))
            .unwrap()
            .as_deref(),
        Some("a device factor"),
        "and the slot it was taken from still opens"
    );
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

/// A keyring service name no other run and no real install can collide with.
fn unique_service(what: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "com.cipherbox.desktop.test.{what}.{}.{nonce}",
        std::process::id()
    )
}

#[test]
#[ignore = "needs the platform keyring backend; CI runs it with --ignored"]
fn real_keyring_credential_store_passes_the_credential_store_kit() {
    let service = unique_service("token");
    block_on(conformance::credential_store::check(async || {
        KeyringCredentialStore::new(service.clone()).expect("keyring worker started")
    }));
}

impl LastAccountId for KeyringCredentialStore {
    async fn store_last_account_id(&self, account_id: &[u8]) -> SeamResult<()> {
        KeyringCredentialStore::store_last_account_id(self, account_id).await
    }
    async fn load_last_account_id(&self) -> SeamResult<Option<Vec<u8>>> {
        KeyringCredentialStore::load_last_account_id(self).await
    }
    async fn clear_last_account_id(&self) -> SeamResult<()> {
        KeyringCredentialStore::clear_last_account_id(self).await
    }
}

#[test]
#[ignore = "needs the platform keyring backend; CI runs it with --ignored"]
fn real_keyring_credential_store_passes_the_last_account_id_kit() {
    let service = unique_service("lastacct");
    block_on(check_last_account_id(async || {
        KeyringCredentialStore::new(service.clone()).expect("keyring worker started")
    }));
    // The kit leaves the account id cleared; the refresh token it wrote is this
    // run's own service name and goes with it.
    block_on(async {
        KeyringCredentialStore::new(service.clone())
            .expect("keyring worker started")
            .clear_refresh_token()
            .await
            .unwrap();
    });
}

#[test]
#[ignore = "needs the platform keyring backend; CI runs it with --ignored"]
fn real_keyring_passes_the_core_kit_wrapping_key_kit() {
    let service = unique_service("corekitkey");
    block_on(check_core_kit_wrapping_key(async || {
        KeyringCredentialStore::new(service.clone()).expect("keyring worker started")
    }));
}

#[test]
#[ignore = "needs the platform keyring backend; CI runs it with --ignored"]
fn real_keyring_backed_core_kit_store_passes_the_core_kit_store_kit() {
    let dir = tempfile::tempdir().unwrap();
    let service = unique_service("corekitstore");
    block_on(check_core_kit_store(async || {
        SealedCoreKitStore::open(
            dir.path().join("core-kit-store"),
            KeyringCredentialStore::new(service.clone()).expect("keyring worker started"),
            Box::new(SeededEntropy::new(9)),
        )
        .unwrap()
    }));
}
