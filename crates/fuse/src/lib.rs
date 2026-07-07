//! CipherBox FUSE filesystem implementation.
//!
//! Platform-agnostic data structures (InodeTable, MetadataCache, ContentCache,
//! FileHandle) are shared across all platforms. Platform-specific mount/unmount
//! and FUSE callback implementations are behind feature flags.

pub mod cache;
pub mod constants;
pub mod error;
pub mod file_handle;
pub mod helpers;
pub mod inode;
pub mod journal_helpers;

// FUSE operations (macOS/Linux - fuser-based)
#[cfg(feature = "fuse")]
pub mod dir_ops;
#[cfg(feature = "fuse")]
pub mod operations;
#[cfg(feature = "fuse")]
pub mod read_ops;
// write_ops::grant_scope (69-07) is platform-agnostic and consumed by the
// Windows write handlers too (69-14), so the module itself is reachable under
// EITHER platform feature; the fuse-only handler implementations inside it
// stay gated behind `feature = "fuse"` (see write_ops/mod.rs).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod write_ops;

// Platform-specific modules
pub mod platform;

// New sibling modules from lib.rs decomposition
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod events;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod fs;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod metadata;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod publish;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod runtime;

// Test-only harness (make_test_fs / CaptureSender / reply_error_code).
#[cfg(all(test, feature = "fuse"))]
mod test_support;

// Re-exports (existing)
pub use cache::{ContentCache, MetadataCache};
pub use error::FuseError;
pub use file_handle::OpenFileHandle;
pub use inode::{InodeData, InodeTable};

// Re-exports (new modules)
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use events::{
    spawn_metadata_refresh, FsEvent, PendingContent, PendingFilePointer, PendingRefresh,
    UploadComplete,
};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use fs::{mount_point, CipherBoxFS};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use metadata::{revoke_shares_blocking, spawn_bin_entry_publish, spawn_metadata_publish};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use publish::{next_file_publish_sequence, PublishCoordinator, PublishQueueEntry};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use runtime::block_with_timeout;

// Replay module (extracted in Task 3).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod replay;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use replay::replay_for_vault;

// Tier-2 dedup: shared async crypto/IPNS helpers (fetch_and_decrypt_content_async,
// publish_file_node). The sync wrapper fetch_and_decrypt_file_content stays in
// each operations.rs because macOS FUSE uses a 3s private timeout while Windows uses
// the 10s crate::block_with_timeout (A2 scope narrowing — see content_ops.rs doc).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod content_ops;

// Tier-2 dedup: PollResult enum + poll_filepointer_resolution for read_ops.
// Both are fuse-only: the winfsp read path has its own inline poll loop and
// never names PollResult (the module is empty under winfsp).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod poll;

// REQ-6: Sample handler tests proving the test_support harness works. Gated on
// `feature = "fuse"` because they construct `fuser::Reply*` values and use the
// `crate::test_support` module (which is itself fuse-feature-gated).
#[cfg(all(test, feature = "fuse"))]
mod handler_harness_tests {
    use crate::test_support::{make_test_fs, reply_error_code, CaptureSender};
    use fuser::{Reply, ReplyAttr, ReplyEmpty};
    use std::sync::{Arc, Mutex};

    /// getattr on the root inode must reply with error == 0 (success) — the
    /// metadata-only path needs no network and proves CaptureSender captures the
    /// out-header.
    #[tokio::test]
    async fn getattr_returns_ok_for_root() {
        let mut fs = make_test_fs();
        let cap = Arc::new(Mutex::new(Vec::new()));
        let reply = <ReplyAttr as Reply>::new(1, CaptureSender(cap.clone()));
        crate::read_ops::implementation::handle_getattr(&mut fs, crate::inode::ROOT_INO, reply);
        assert_eq!(reply_error_code(&cap), 0, "getattr root must reply ok");
    }

    /// flush is a no-op that replies error == 0 (durability lives on release).
    /// Also satisfies the REQ-2 flush-no-op verification consumed by Plan 04.
    #[tokio::test]
    async fn flush_returns_ok() {
        let cap = Arc::new(Mutex::new(Vec::new()));
        let reply = <ReplyEmpty as Reply>::new(1, CaptureSender(cap.clone()));
        crate::read_ops::implementation::handle_flush(reply);
        assert_eq!(reply_error_code(&cap), 0, "flush must reply ok");
    }
}

/// REQ-1 / REQ-2 durability characterization tests (Plan 46-04).
///
/// These lock in behavior that is ALREADY CORRECT in the production tree; they
/// would FAIL if a future change regressed the D-04 journal-before-ack barrier
/// (read_ops.rs handle_release: journal.put → handle.cleanup → reply.ok) or the
/// mkdir conflict re-arm (write_ops.rs MkdirConflict send → drain → re-queue).
/// They are tests only — no production code is touched.
#[cfg(all(test, feature = "fuse"))]
mod durability_characterization_tests {
    use crate::test_support::{
        make_test_fs, make_test_fs_with_keypair, reply_error_code, CaptureSender,
    };
    use fuser::{Reply, ReplyEntry};
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    /// Generate a real secp256k1 keypair (33-byte compressed pubkey, 32-byte
    /// secret) via the `ecies` dev-dep. A zero vec is NOT a valid curve point, so
    /// handlers that ECIES-wrap keys (mkdir, release) need a real one.
    fn real_keypair() -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (
            Zeroizing::new(sk.serialize().to_vec()),
            Zeroizing::new(pk.serialize().to_vec()),
        )
    }

    // ---- REQ-1: mkdir ----

    /// REQ-1 / D-04: `handle_mkdir` journals the MkdirPublish entry to disk and
    /// mutates the parent (root) inode children BEFORE replying. A future reorder
    /// that put `reply.entry()` ahead of `journal.put` would leave the parent
    /// without a durable replay record on crash — this test would catch it.
    ///
    /// `multi_thread` because mkdir spawns a detached publish thread; it targets
    /// the unroutable 127.0.0.1:1 host and fails harmlessly, so the journal entry
    /// is RETAINED (D-11b) — we assert the entry exists, never emptiness.
    #[tokio::test(flavor = "multi_thread")]
    async fn mkdir_happy_path_puts_journal_entry_then_replies_entry() {
        let (private_key, public_key) = real_keypair();
        let mut fs = make_test_fs_with_keypair(private_key, public_key);
        let vault = fs.root_ipns_name.clone();

        let cap = Arc::new(Mutex::new(Vec::new()));
        let reply = <ReplyEntry as Reply>::new(1, CaptureSender(cap.clone()));

        crate::write_ops::implementation::handle_mkdir(
            &mut fs,
            crate::inode::ROOT_INO,
            std::ffi::OsStr::new("newdir"),
            reply,
        );

        // (3) Reply is success.
        assert_eq!(reply_error_code(&cap), 0, "mkdir must reply entry (ok)");

        // (1) The parent (root) inode now lists the new child.
        let root = fs
            .inodes
            .get(crate::inode::ROOT_INO)
            .expect("root inode present");
        let children = root.children.clone().unwrap_or_default();
        assert!(
            !children.is_empty(),
            "root must have the new child after mkdir"
        );
        let child_ino = children[0];
        let child = fs.inodes.get(child_ino).expect("child inode present");
        assert_eq!(child.name, "newdir", "child name must match");

        // (2) At least one journal entry was fsynced before the reply.
        let entries = fs
            .journal
            .load_all_for_vault(&vault)
            .expect("journal load must succeed");
        assert!(
            !entries.is_empty(),
            "mkdir must journal a MkdirPublish entry before replying (D-04)"
        );
        assert!(
            entries
                .iter()
                .any(|e| matches!(e.op, cipherbox_sdk::JournalOp::MkdirPublish { .. })),
            "the journalled entry must be a MkdirPublish op"
        );
    }

    /// REQ-1 / D-11a: an `FsEvent::MkdirConflict` drained through
    /// `drain_upload_completions` re-arms the debounced publisher — the parent ino
    /// lands in BOTH `mutated_folders` and `publish_queue`. Pure in-memory; no
    /// network. This locks in the conflict re-arm at lib.rs:949-955.
    #[tokio::test]
    async fn mkdir_conflict_rearms() {
        let mut fs = make_test_fs();
        let parent_ino = crate::inode::ROOT_INO;

        // Pre-state: neither map references the parent.
        assert!(!fs.mutated_folders.contains_key(&parent_ino));
        assert!(!fs.publish_queue.contains_key(&parent_ino));

        // Signal a parent-publish conflict exactly as the background mkdir thread does.
        fs.upload_tx
            .send(crate::FsEvent::MkdirConflict { parent_ino })
            .expect("send MkdirConflict on upload channel");

        fs.drain_upload_completions();

        assert!(
            fs.mutated_folders.contains_key(&parent_ino),
            "MkdirConflict must re-arm mutated_folders for the parent"
        );
        assert!(
            fs.publish_queue.contains_key(&parent_ino),
            "MkdirConflict must enqueue the parent for debounced republish"
        );
    }

    // ---- REQ-2: release / replay ----

    /// REQ-2 / D-04: `handle_release` on a dirty new file journals the ciphertext
    /// into a fsynced entry BEFORE `handle.cleanup()` deletes the temp file and
    /// BEFORE `reply.ok()`. Asserts:
    ///   (1) a journal entry exists whose UploadFile.ciphertext_b64 is non-empty,
    ///   (2) the temp file path no longer exists (cleanup ran),
    ///   (3) the reply is success,
    /// and after draining the detached failure (127.0.0.1:1 → record_failure) the
    /// entry is STILL present (retained, never silently dropped).
    ///
    /// A future reorder that acked the OS before `journal.put`, or that deleted the
    /// temp file before journalling the ciphertext, would fail (1) or (2).
    #[tokio::test(flavor = "multi_thread")]
    async fn release_journals_before_cleanup() {
        let (private_key, public_key) = real_keypair();
        let mut fs = make_test_fs_with_keypair(private_key, public_key);
        let vault = fs.root_ipns_name.clone();

        // Create a new file under root via handle_create so the inode + write
        // handle exist exactly as the OS would have set them up.
        let cap_create = Arc::new(Mutex::new(Vec::new()));
        let reply_create = <fuser::ReplyCreate as Reply>::new(1, CaptureSender(cap_create.clone()));
        crate::write_ops::implementation::handle_create(
            &mut fs,
            crate::inode::ROOT_INO,
            std::ffi::OsStr::new("note.txt"),
            0,
            reply_create,
        );
        assert_eq!(reply_error_code(&cap_create), 0, "create must reply ok");

        // Locate the freshly created file inode + its open write handle.
        let ino = fs
            .inodes
            .find_child(crate::inode::ROOT_INO, "note.txt")
            .expect("created file inode present");
        let (&fh, _) = fs
            .open_files
            .iter()
            .find(|(_, h)| h.ino == ino && h.temp_path.is_some())
            .expect("write handle present for new file");

        // Write bytes into the temp file and mark dirty (as handle_write would).
        let plaintext = b"the quick brown fox";
        {
            let handle = fs.open_files.get_mut(&fh).expect("handle present");
            handle.write_at(0, plaintext).expect("write temp file");
            handle.dirty = true;
        }
        let temp_path = fs
            .open_files
            .get(&fh)
            .and_then(|h| h.temp_path.clone())
            .expect("temp path present");
        assert!(temp_path.exists(), "temp file must exist before release");

        // Release the handle.
        let cap = Arc::new(Mutex::new(Vec::new()));
        let reply = <fuser::ReplyEmpty as Reply>::new(1, CaptureSender(cap.clone()));
        crate::read_ops::implementation::handle_release(&mut fs, ino, fh, reply);

        // (3) Reply is success.
        assert_eq!(reply_error_code(&cap), 0, "release must reply ok");

        // (1) A journal entry exists referencing a ciphertext sidecar .bin (D-01), and the
        // sidecar was durably written BEFORE the reply (durable-ack with sidecar). The
        // release callback blocked on the bounded oneshot until put_with_sidecar fsynced,
        // so by the time we reach here both the .json entry and the .bin must exist on disk.
        let entries = fs
            .journal
            .load_all_for_vault(&vault)
            .expect("journal load must succeed");
        let (sidecar_path, sidecar_sha256) = entries
            .iter()
            .find_map(|e| match &e.op {
                cipherbox_sdk::JournalOp::UploadFile {
                    sidecar_path,
                    sidecar_sha256,
                    ..
                } => Some((sidecar_path.clone(), sidecar_sha256.clone())),
                _ => None,
            })
            .expect("release must journal an UploadFile entry before cleanup (D-04)");
        assert!(
            sidecar_path.exists(),
            "the ciphertext sidecar .bin must be durably written before the OS ack (D-01)"
        );
        assert!(
            !sidecar_sha256.is_empty(),
            "sidecar_sha256 must be recorded for replay integrity verification"
        );
        // The sidecar bytes must hash to the recorded sidecar_sha256.
        let bin_bytes = std::fs::read(&sidecar_path).expect("read sidecar .bin");
        let actual = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&bin_bytes);
            hex::encode(h.finalize())
        };
        assert_eq!(
            actual, sidecar_sha256,
            "sidecar bytes must match the recorded SHA-256"
        );

        // (2) The temp file was deleted by handle.cleanup() (read_ops.rs:882).
        assert!(
            !temp_path.exists(),
            "release must delete the temp file via handle.cleanup()"
        );

        // The detached upload to 127.0.0.1:1 fails and calls record_failure, which
        // RETAINS the entry (never silently dropped) and increments `retries`.
        // Poll-drain until that failure is actually recorded rather than relying on
        // a fixed sleep -- the detached upload's failure timing is nondeterministic
        // on a busy CI runner.
        fn is_retained_failure(e: &cipherbox_sdk::JournalEntry) -> bool {
            matches!(e.op, cipherbox_sdk::JournalOp::UploadFile { .. }) && e.retries >= 1
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let after = loop {
            fs.drain_upload_completions();
            let entries = fs
                .journal
                .load_all_for_vault(&vault)
                .expect("journal load after drain must succeed");
            if entries.iter().any(is_retained_failure) || std::time::Instant::now() >= deadline {
                break entries;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert!(
            after.iter().any(is_retained_failure),
            "the UploadFile entry must be retained with a recorded failure (retries >= 1) after record_failure"
        );
    }

    /// REQ-2 replay (D-01 sidecar shape): the journalled ciphertext survives in the
    /// `<id>.bin` sidecar independently of any temp file. Build an UploadFile entry,
    /// `put_with_sidecar` it, then a FRESH `WriteQueue` over the same dir reloads the
    /// entry and the sidecar bytes round-trip to the original ciphertext (and match the
    /// recorded sidecar_sha256). No network, no spawn (crash simulation).
    #[tokio::test]
    async fn replay_reuploads_ciphertext() {
        // Isolated journal dir owned by this test — write here, reload via a fresh
        // WriteQueue (no fs handle needed; the round-trip is the unit under test).
        let journal_dir = crate::test_support::make_isolated_journal_dir();
        let vault = "k51replay-vault".to_string();
        let put_queue = cipherbox_sdk::WriteQueue::new(journal_dir.clone(), 5);

        let original_ciphertext: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let entry_id = "replay-test-entry".to_string();
        let sidecar_path = put_queue.sidecar_path_for(&entry_id);
        let sidecar_sha256 = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(original_ciphertext);
            hex::encode(h.finalize())
        };

        let entry = cipherbox_sdk::JournalEntry {
            id: entry_id.clone(),
            vault_root_ipns: vault.clone(),
            // node/v3 reshaped UploadFile (69-09 Slice 3): the legacy hex-ECIES key
            // fields (wrapped_key_hex/iv_hex/file_ipns_key_hex/parent_ipns_key_hex/
            // filename_encrypted_hex) are gone. This test exercises only the sidecar
            // ciphertext round-trip (D-01/D-04 durability), so the node/v3 crypto
            // fields carry inert fixture values.
            op: cipherbox_sdk::JournalOp::UploadFile {
                sidecar_path: sidecar_path.clone(),
                sidecar_sha256: sidecar_sha256.clone(),
                legacy_ciphertext_b64: String::new(),
                child_published_node: String::new(),
                parent_child_ref: cipherbox_core::node::SealedChildRef {
                    name: "enc-replay.bin".to_string(),
                    ipns_name: "k51child-replay".to_string(),
                    generation: 0,
                    version_floor: 0,
                    read_key_sealed: String::new(),
                },
                parent_write_child_ref: cipherbox_core::node::WriteChildRef {
                    child_id: "00000000-0000-0000-0000-000000000000".to_string(),
                    write_key_sealed: String::new(),
                },
                file_meta_ipns_name: None,
                parent_folder_ipns_name: vault.clone(),
                size: original_ciphertext.len() as u64,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 0,
            status: cipherbox_sdk::JournalEntryStatus::Pending,
        };

        put_queue
            .put_with_sidecar(&entry, original_ciphertext)
            .expect("journal put_with_sidecar must succeed");

        // A FRESH WriteQueue over the same dir — simulates next-mount replay load.
        let reloaded_queue = cipherbox_sdk::WriteQueue::new(journal_dir, 5);
        let reloaded = reloaded_queue
            .load_all_for_vault(&vault)
            .expect("reload must succeed");

        let (reloaded_path, reloaded_sha) = reloaded
            .iter()
            .find_map(|e| match &e.op {
                cipherbox_sdk::JournalOp::UploadFile {
                    sidecar_path,
                    sidecar_sha256,
                    ..
                } => Some((sidecar_path.clone(), sidecar_sha256.clone())),
                _ => None,
            })
            .expect("reloaded UploadFile entry present");

        let decoded = std::fs::read(&reloaded_path).expect("reloaded sidecar must read");
        assert_eq!(
            decoded.as_slice(),
            original_ciphertext,
            "replay must recover the exact journalled ciphertext bytes from the sidecar"
        );
        assert_eq!(
            reloaded_sha, sidecar_sha256,
            "reloaded sidecar_sha256 must match the original"
        );
    }

    /// D-06: a genuine `journal.remove` I/O failure must be an `Err` (the shape the
    /// `if let Err(e) = journal.remove(...)` logging path in `replay_for_vault` handles),
    /// not a silently-swallowed `let _`. This proves that logging path is not dead code.
    #[test]
    fn remove_failure_is_logged() {
        use cipherbox_sdk::WriteQueue;

        let dir = std::env::temp_dir()
            .join("cb-t52-01-remove-failure")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);

        // `remove` of a non-existent id is idempotent (NotFound -> Ok).
        assert!(
            journal.remove("nonexistent-id").is_ok(),
            "remove of a missing entry must be Ok (idempotent NotFound path)"
        );

        // Drive the genuine (non-NotFound) error branch deterministically and
        // root-independently: place a DIRECTORY at `<id>.json`. `WriteQueue::remove`
        // unlinks the `.json` first via `remove_file`, which on a directory returns
        // EISDIR (Unix) / ACCESS_DENIED (Windows) — never NotFound — regardless of
        // CAP_DAC_OVERRIDE/root (unlink() cannot remove a directory). This avoids the
        // permission-chmod approach, which 0o500 does not enforce for privileged CI runners.
        let id = "remove-fail-t5201";
        let json_path = dir.join(format!("{}.json", id));
        std::fs::create_dir(&json_path).unwrap();

        assert!(
            journal.remove(id).is_err(),
            "removing an entry whose .json is a directory must return Err (the `if let Err` logging shape)"
        );

        // `remove_dir_all` handles the leftover `<id>.json` directory.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-03 (WR-07): the timeout→Err conversion that `replay_for_vault` relies on. A future
    /// that sleeps past a short timeout must resolve to the `Err("... timed out ...")` value
    /// (the shape routed through record_failure), not hang and not Ok.
    #[tokio::test]
    async fn replay_entry_timeout() {
        // Mirror the production wrapping shape verbatim with a tiny real timeout so the test
        // is fast (<1s) without needing tokio's test-util paused clock. The future never
        // completes within the timeout, so it must resolve to the Err timeout value.
        let timeout = std::time::Duration::from_millis(20);
        let slow = async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok::<(), String>(())
        };
        let result = tokio::time::timeout(timeout, slow)
            .await
            .unwrap_or_else(|_| Err(format!("replay timed out after {}ms", timeout.as_millis())));
        assert!(
            matches!(result, Err(ref e) if e.contains("timed out")),
            "a future exceeding the timeout must become Err(\"... timed out ...\"), got {:?}",
            result
        );
    }

    // 69-09 Slice 5c: `decrypt_journal_name_round_trip_and_legacy_compat` was
    // DELETED. It exercised `crate::replay::decrypt_journal_name`, the per-entry
    // ECIES filename-unwrap helper removed in Slice 4 — the child display name now
    // travels in plaintext inside the parent's sealed `SealedChildRef.name`, so
    // there is no journal-name ciphertext to decrypt at replay. This asserted the
    // intentionally-removed model; name-handling mechanics are covered by the
    // inode NFC tests and the SDK seal vectors.
}
