//! Test-only harness for unit-testing FUSE handlers and journal builders.
//!
//! This module is compiled only under `#[cfg(all(test, feature = "fuse"))]`.
//! It provides:
//!
//! - [`make_test_fs`] / [`make_test_fs_with_keypair`] — build a fully-populated
//!   [`CipherBoxFS`] backed by a per-test isolated journal dir, with no live
//!   network dependency (the API client points at an unroutable host so any
//!   accidental detached upload thread fails fast).
//! - [`CaptureSender`] — a [`fuser::ReplySender`] that captures the raw FUSE
//!   reply bytes into a shared buffer so handler replies can be inspected.
//! - [`reply_error_code`] — decode the `error` field of the captured
//!   `fuse_out_header` (offset 4), where `0` means success.
//!
//! Security: this harness constructs in-memory state only. It never introduces
//! raw plaintext keys into the journal (Threat T-46-01) — builder tests use a
//! real EC keypair so `wrap_key` ECIES-wraps key material (Threat T-46-02).

use std::collections::{HashMap, HashSet};
use std::io::IoSlice;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::CipherBoxFS;

/// Monotonic per-test counter so each test gets a unique journal dir even within
/// the same process.
static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Return a unique per-test journal dir under the system temp dir.
///
/// Keyed by `process::id()` plus a monotonic counter so concurrent tests within
/// the same process never collide. The dir is created (mirroring the pattern at
/// `lib.rs` characterization tests). NEVER points at `default_journal_dir()`
/// (Threat T-46-04).
pub(crate) fn make_isolated_journal_dir() -> PathBuf {
    let unique = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join("cb-test-journal").join(format!(
        "{}-{}",
        std::process::id(),
        unique
    ));
    // queue.rs WriteQueue::new does not create the dir — do it here.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create isolated journal dir");
    dir
}

/// Build a [`CipherBoxFS`] for metadata-only handler tests.
///
/// Uses zero keys — fine for handlers that never call `wrap_key`
/// (getattr/access/lookup/unlink/rmdir/rename/flush/xattr). For builder tests
/// that wrap keys, use [`make_test_fs_with_keypair`] with a real EC keypair (a
/// 33-byte zero vec is NOT a valid secp256k1 curve point — Assumption A1).
///
/// Must be called from a `#[tokio::test]` because `rt` captures
/// `tokio::runtime::Handle::current()`.
pub(crate) fn make_test_fs() -> CipherBoxFS {
    make_test_fs_with_keypair(Zeroizing::new(vec![0u8; 32]), Zeroizing::new(vec![0u8; 33]))
}

/// Build a [`CipherBoxFS`] seeded with the provided EC keypair.
///
/// `public_key` must be a 33-byte secp256k1 compressed key for the journal
/// builders' `wrap_key` calls to succeed.
pub(crate) fn make_test_fs_with_keypair(
    private_key: Zeroizing<Vec<u8>>,
    public_key: Zeroizing<Vec<u8>>,
) -> CipherBoxFS {
    let journal_dir = make_isolated_journal_dir();

    let (refresh_tx, refresh_rx) = channel();
    let (content_tx, content_rx) = channel();
    let (filepointer_tx, filepointer_rx) = channel();
    let (upload_tx, upload_rx) = channel();

    // Root inode (ino=1) is auto-created by InodeTable::new. Override its kind to
    // inject ipns_name + ipns_private_key so build_folder_metadata / journal
    // builders can resolve the root, matching mount glue at mod.rs:138-143.
    let mut inodes = crate::inode::InodeTable::new();
    if let Some(root) = inodes.get_mut(crate::inode::ROOT_INO) {
        root.kind = crate::inode::InodeKind::Root {
            ipns_name: "k51test-root".to_string(),
            read_key: Zeroizing::new([0u8; 32]),
            write_key: Zeroizing::new([0u8; 32]),
            ipns_private_key: Zeroizing::new(vec![7u8; 32]),
        };
    }

    CipherBoxFS {
        inodes,
        metadata_cache: crate::cache::MetadataCache::new(),
        content_cache: crate::cache::ContentCache::new(),
        // Unroutable host: any accidental detached upload thread fails fast.
        api: Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1")),
        private_key,
        public_key,
        root_folder_key: Zeroizing::new(vec![0u8; 32]),
        root_ipns_name: "k51test-root".to_string(),
        rt: tokio::runtime::Handle::current(),
        next_fh: AtomicU64::new(1),
        open_files: HashMap::new(),
        temp_dir: std::env::temp_dir().join("cipherbox-test"),
        tee_public_key: None,
        tee_key_epoch: None,
        max_versions_per_file: 5,
        version_cooldown_ms: 0,
        refresh_rx,
        refresh_tx,
        mutated_folders: HashMap::new(),
        prefetching: HashSet::new(),
        refreshing_metadata: HashSet::new(),
        content_rx,
        content_tx,
        filepointer_rx,
        filepointer_tx,
        resolving_file_pointers: HashSet::new(),
        pending_fp_resolves: std::collections::VecDeque::new(), // D-09
        pending_content: HashMap::new(),
        upload_rx,
        upload_tx,
        publish_coordinator: Arc::new(crate::PublishCoordinator::new()),
        publish_queue: HashMap::new(),
        high_water: cipherbox_sdk::new_journal_high_water(&journal_dir),
        rotation_checkpoint_store: cipherbox_sdk::JsonSidecarFloorStore::for_generation(
            &journal_dir,
        ),
        journal: cipherbox_sdk::WriteQueue::new(journal_dir, 5),
        sent_shares: std::sync::RwLock::new(crate::write_ops::grant_scope::SentSharesCache::empty()),
    }
}

/// A [`fuser::ReplySender`] that captures the raw reply bytes into a shared
/// buffer so handler replies can be inspected in tests.
#[derive(Clone)]
pub(crate) struct CaptureSender(pub Arc<Mutex<Vec<u8>>>);

impl fuser::ReplySender for CaptureSender {
    fn send(&self, data: &[IoSlice<'_>]) -> std::io::Result<()> {
        let mut buf = self.0.lock().unwrap();
        for slice in data {
            buf.extend_from_slice(slice);
        }
        Ok(())
    }
}

/// Decode the `error` field of a captured `fuse_out_header`.
///
/// Wire format (vendor/fuser ll/fuse_abi.rs:932-936):
///   `fuse_out_header = { len: u32 LE, error: i32 LE, unique: u64 LE }` (16 bytes).
/// `error == 0` means success; `error == -errno` means failure.
pub(crate) fn reply_error_code(captured: &Arc<Mutex<Vec<u8>>>) -> i32 {
    let buf = captured.lock().unwrap();
    assert!(buf.len() >= 16, "fuse_out_header is 16 bytes");
    i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]])
}
