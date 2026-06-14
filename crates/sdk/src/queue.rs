//! Durable write journal for FUSE file uploads and directory publishes.
//!
//! Every FUSE write fsync-commits a `JournalEntry` to disk before acking the OS.
//! A crash after the fsync is recoverable on next mount via replay.
//!
//! The journal stores only ciphertext + ECIES-wrapped keys — never plaintext
//! or raw key bytes (zero-knowledge constraint, D-05).

use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::PathBuf;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// The operation encoded by a journal entry.
///
/// Variants cover both upload (D-03 UploadFile) and directory publish (D-03 MkdirPublish).
/// No inode identifiers — all routing uses stable IPNS names (D-02).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JournalOp {
    /// A file upload awaiting IPFS pin + folder metadata update.
    UploadFile {
        /// Base64-encoded AES-256-GCM ciphertext.
        ciphertext_b64: String,
        /// ECIES-wrapped file key, hex-encoded.
        wrapped_key_hex: String,
        /// AES-GCM IV, hex-encoded.
        iv_hex: String,
        /// Per-file IPNS name for metadata pointer (stable across remount, D-02).
        file_meta_ipns_name: String,
        /// Optional per-file IPNS private key hex (present when key must be published).
        file_ipns_key_hex: Option<String>,
        /// Parent folder IPNS name (stable cross-remount, D-02).
        parent_folder_ipns_name: String,
        /// User-ECIES-wrapped parent folder IPNS private key, hex-encoded.
        ///
        /// This is the same form stored in `FolderEntry.ipns_private_key_encrypted`
        /// everywhere in the metadata: wrapped with the user's EC public key via ECIES
        /// (`cipherbox_crypto::wrap_key`). Only the user's private key can unwrap it at
        /// replay time. Never raw, never TEE-wrapped. Required for CR-01 (replay must
        /// sign and publish the parent IPNS record). Part of the D-04 zero-knowledge family.
        parent_ipns_key_hex: String,
        /// Original filename.
        filename: String,
        /// File size in bytes.
        size: u64,
        /// Creation timestamp, milliseconds since Unix epoch (serializable; replaces Instant).
        created_at_ms: u64,
    },
    /// A directory creation awaiting IPNS publish + parent folder metadata update.
    MkdirPublish {
        /// New child folder IPNS name.
        child_ipns_name: String,
        /// Encrypted folder key hex.
        child_folder_key_hex: String,
        /// User-ECIES-wrapped child folder IPNS private key, hex-encoded.
        ///
        /// Matches `FolderEntry.ipns_private_key_encrypted` — user-ECIES-wrapped via
        /// `cipherbox_crypto::wrap_key(&child_ipns_private_key, &user_public_key)`.
        /// Never TEE-wrapped (CR-03 fix). Replay writes this directly into
        /// `FolderEntry.ipns_private_key_encrypted` without re-wrapping.
        child_ipns_key_hex: String,
        /// Parent folder IPNS name.
        parent_folder_ipns_name: String,
        /// User-ECIES-wrapped parent folder IPNS private key, hex-encoded.
        ///
        /// Same semantics as `UploadFile::parent_ipns_key_hex`: unwrappable only with
        /// the user's private key at replay time. Required for CR-01. Part of D-04 family.
        parent_ipns_key_hex: String,
        /// Directory name.
        name: String,
        /// Creation timestamp, milliseconds since Unix epoch.
        created_at_ms: u64,
    },
}

impl JournalOp {
    /// Creation timestamp (ms since Unix epoch) carried by every variant.
    pub fn created_at_ms(&self) -> u64 {
        match self {
            JournalOp::MkdirPublish { created_at_ms, .. }
            | JournalOp::UploadFile { created_at_ms, .. } => *created_at_ms,
        }
    }
}

/// Lifecycle state of a journal entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JournalEntryStatus {
    /// Awaiting first upload attempt.
    Pending,
    /// Upload attempt currently in progress.
    InProgress,
    /// All retries exhausted; entry parked on disk for manual intervention (D-09).
    Failed {
        /// Last error message recorded before parking.
        last_error: String,
    },
}

/// A single durable journal entry.
///
/// Serialized as JSON to `<journal_dir>/<id>.json` with 0o600 permissions and
/// an fsync barrier before the OS write-ack (D-04).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Unique identifier; hex-encoded 16 random bytes.
    pub id: String,
    /// Vault root IPNS name; used to scope replay per vault (D-07).
    pub vault_root_ipns: String,
    /// The journaled operation (UploadFile or MkdirPublish).
    pub op: JournalOp,
    /// Number of failed upload attempts.
    pub retries: u32,
    /// Current lifecycle state.
    pub status: JournalEntryStatus,
}

/// Persist-backed durable write journal.
///
/// Each `put()` serializes the entry to JSON, writes it to
/// `<journal_dir>/<id>.json`, and calls `sync_all()` (F_FULLFSYNC on macOS)
/// before returning — ensuring crash recovery on next mount.
///
/// Replaces the memory-only `VecDeque`-based `WriteQueue` that lost all
/// queued writes on app quit (root cause of release-data-loss todo).
#[derive(Clone)]
pub struct WriteQueue {
    /// Directory where journal files are stored; injected at construction time.
    pub(crate) journal_dir: PathBuf,
    /// Maximum retry attempts before an entry is transitioned to `Failed`.
    pub max_retries: u32,
}

impl WriteQueue {
    /// Create a new `WriteQueue` backed by the given journal directory.
    ///
    /// The directory must already exist; this constructor does not create it.
    pub fn new(journal_dir: PathBuf, max_retries: u32) -> Self {
        Self {
            journal_dir,
            max_retries,
        }
    }

    /// Persist an entry to disk with an fsync barrier.
    ///
    /// Writes `<journal_dir>/<entry.id>.json` with 0o600 permissions set atomically
    /// at create time (WR-03a — no readable window between create and chmod), then
    /// calls `sync_all()` before returning (F_FULLFSYNC on macOS, D-04 / T-43-02).
    /// After the file fsync, the parent journal directory is also fsynced so the new
    /// directory entry is durable on crash (WR-03b).
    pub fn put(&self, entry: &JournalEntry) -> Result<(), String> {
        let json = serde_json::to_vec(entry)
            .map_err(|e| format!("Journal serialize failed: {}", e))?;

        let path = self.journal_dir.join(format!("{}.json", entry.id));

        // WR-03a: set 0o600 atomically at create time via OpenOptionsExt::mode().
        // On non-Unix platforms the mode() call is absent; permissions stay platform default.
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        open_opts.mode(0o600);

        let mut file = open_opts
            .open(&path)
            .map_err(|e| format!("Journal open failed: {}", e))?;

        file.write_all(&json)
            .map_err(|e| format!("Journal write failed: {}", e))?;

        // fsync barrier: F_FULLFSYNC on macOS, fdatasync on Linux (via Rust std).
        // Matches crates/fuse/src/file_handle.rs:206-207 pattern.
        file.sync_all()
            .map_err(|e| format!("Journal fsync failed: {}", e))?;

        // WR-03b: fsync the parent journal directory so the new dirent is durable.
        // Errors are ignored on platforms where directory fsync is unsupported.
        let _ = std::fs::File::open(&self.journal_dir)
            .and_then(|d| d.sync_all());

        Ok(())
    }

    /// Remove an entry file from disk.
    ///
    /// Returns `Ok(())` if the file did not exist (idempotent).
    /// After a successful removal, syncs the parent journal directory so the
    /// deleted dirent is durable on crash (WR-03b).
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let path = self.journal_dir.join(format!("{}.json", id));
        match std::fs::remove_file(&path) {
            Ok(()) => {
                // WR-03b: fsync parent dir after removal.
                let _ = std::fs::File::open(&self.journal_dir)
                    .and_then(|d| d.sync_all());
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Journal remove failed: {}", e)),
        }
    }

    /// Load all journal entries belonging to `vault_root_ipns`.
    ///
    /// Skips files that cannot be parsed with a `log::warn!` (never panics — V5, T-43-03).
    /// Returns only entries whose `vault_root_ipns` matches the given value (D-07).
    pub fn load_all_for_vault(
        &self,
        vault_root_ipns: &str,
    ) -> Result<Vec<JournalEntry>, String> {
        let read_dir = std::fs::read_dir(&self.journal_dir)
            .map_err(|e| format!("Journal dir read failed: {}", e))?;

        let mut entries = Vec::new();

        for dir_entry in read_dir {
            let dir_entry =
                dir_entry.map_err(|e| format!("Journal dir entry error: {}", e))?;
            let path = dir_entry.path();

            // Only process *.json files.
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!(
                        "Journal: failed to read {:?}: {} — skipping",
                        path,
                        e
                    );
                    continue;
                }
            };

            // Skip-with-warn on malformed JSON (T-43-03, V5).
            let entry: JournalEntry = match serde_json::from_slice(&bytes) {
                Ok(e) => e,
                Err(e) => {
                    log::warn!(
                        "Journal: malformed entry at {:?}: {} — skipping",
                        path,
                        e
                    );
                    continue;
                }
            };

            // Vault-scoping filter (D-07).
            if entry.vault_root_ipns == vault_root_ipns {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Overwrite the status of an entry on disk.
    pub fn update_status(
        &self,
        id: &str,
        status: JournalEntryStatus,
    ) -> Result<(), String> {
        let path = self.journal_dir.join(format!("{}.json", id));
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("Journal update_status read failed: {}", e))?;
        let mut entry: JournalEntry = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Journal update_status parse failed: {}", e))?;
        entry.status = status;
        self.put(&entry)
    }

    /// Record a failed attempt for an entry.
    ///
    /// - If `entry.retries < self.max_retries`: increment retries, persist as Pending, return
    ///   `JournalEntryStatus::Pending`.
    /// - If `entry.retries >= self.max_retries`: transition to Failed (D-09 — kept on disk,
    ///   never silently dropped), persist, and return `JournalEntryStatus::Failed`.
    pub fn record_failure(
        &self,
        entry: &JournalEntry,
        error: &str,
    ) -> Result<JournalEntryStatus, String> {
        if entry.retries >= self.max_retries {
            // Park: transition to Failed, keep on disk (D-09).
            let status = JournalEntryStatus::Failed {
                last_error: error.to_string(),
            };
            self.update_status(&entry.id, status.clone())?;
            Ok(status)
        } else {
            // Increment retries, stay Pending.
            let mut updated = entry.clone();
            updated.retries += 1;
            updated.status = JournalEntryStatus::Pending;
            self.put(&updated)?;
            Ok(JournalEntryStatus::Pending)
        }
    }

    /// Return entries re-ordered for safe replay.
    ///
    /// All `MkdirPublish` entries come before `UploadFile` entries (D-08):
    /// a journaled mkdir for a parent folder must replay before file uploads
    /// that target that folder.
    ///
    /// Within each group, entries are sorted ascending by `created_at_ms` (WR-01)
    /// so nested mkdirs and repeated writes replay in original creation order,
    /// regardless of filesystem `read_dir` ordering.
    pub fn ordered_for_replay(entries: Vec<JournalEntry>) -> Vec<JournalEntry> {
        let mut mkdir_entries = Vec::new();
        let mut upload_entries = Vec::new();

        for entry in entries {
            match &entry.op {
                JournalOp::MkdirPublish { .. } => mkdir_entries.push(entry),
                JournalOp::UploadFile { .. } => upload_entries.push(entry),
            }
        }

        // WR-01: sort each group by created_at_ms ascending (stable sort preserves
        // relative order of entries with identical timestamps).
        mkdir_entries.sort_by_key(|e| e.op.created_at_ms());
        upload_entries.sort_by_key(|e| e.op.created_at_ms());

        mkdir_entries.extend(upload_entries);
        mkdir_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Helper builders ----

    fn make_upload_entry(id: &str, vault: &str) -> JournalEntry {
        JournalEntry {
            id: id.to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                ciphertext_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"ciphertext",
                ),
                wrapped_key_hex: hex::encode(b"wrappedkey"),
                iv_hex: hex::encode(b"iv123456"),
                file_meta_ipns_name: "k51filemetaipns".to_string(),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: "k51parentfolder".to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-wrapped-parent-ipns-key"),
                filename: "test.txt".to_string(),
                size: 42,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        }
    }

    fn make_mkdir_entry(id: &str, vault: &str) -> JournalEntry {
        JournalEntry {
            id: id.to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::MkdirPublish {
                child_ipns_name: "k51childipns".to_string(),
                child_folder_key_hex: hex::encode(b"folderkey"),
                child_ipns_key_hex: hex::encode(b"ipnskey"),
                parent_folder_ipns_name: "k51parentfolder".to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-wrapped-parent-ipns-key"),
                name: "my_dir".to_string(),
                created_at_ms: 1_700_000_000_001,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        }
    }

    /// Create a unique temporary directory for test isolation.
    ///
    /// Uses a monotonically-increasing atomic counter combined with the thread ID
    /// to guarantee uniqueness even when multiple tests run concurrently in the
    /// same process.
    fn make_temp_queue() -> (WriteQueue, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tid_raw = format!("{:?}", std::thread::current().id());
        // Extract the numeric part of the thread ID string (e.g. "ThreadId(7)" → "7").
        let tid_num: String = tid_raw.chars().filter(|c| c.is_ascii_digit()).collect();
        let dir = std::env::temp_dir()
            .join(format!("cipherbox-journal-test-{}-{}", seq, tid_num));
        std::fs::create_dir_all(&dir).expect("create test journal dir");
        let q = WriteQueue::new(dir.clone(), 3);
        (q, dir)
    }

    // ---- Task 1: serialization round-trip tests ----

    #[test]
    fn upload_entry_round_trips() {
        let entry = make_upload_entry("abc123", "k51vault");
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(back.id, entry.id);
        assert_eq!(back.vault_root_ipns, entry.vault_root_ipns);
        assert_eq!(back.retries, entry.retries);
        if let JournalOp::UploadFile { filename, size, .. } = &back.op {
            assert_eq!(filename, "test.txt");
            assert_eq!(*size, 42);
        } else {
            panic!("Expected UploadFile op");
        }
    }

    #[test]
    fn mkdir_entry_round_trips() {
        let entry = make_mkdir_entry("def456", "k51vault");
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(back.id, entry.id);
        assert_eq!(back.vault_root_ipns, entry.vault_root_ipns);
        if let JournalOp::MkdirPublish { name, .. } = &back.op {
            assert_eq!(name, "my_dir");
        } else {
            panic!("Expected MkdirPublish op");
        }
    }

    /// D-05: journal must not persist plaintext or raw key bytes.
    #[test]
    fn journal_no_plaintext() {
        let entry = make_upload_entry("noplain", "k51vault");
        let json = serde_json::to_vec(&entry).expect("serialize");
        let json_str = String::from_utf8(json).expect("utf8");
        // Keys must be stored encoded, never as raw bytes: make_upload_entry wraps the
        // raw bytes b"wrappedkey", so the literal must not appear — only its hex form.
        assert!(
            !json_str.contains("wrappedkey"),
            "Journal must store keys hex-encoded, not as raw bytes"
        );
        assert!(
            !json_str.contains("\"plaintext\""),
            "Journal must not have 'plaintext' key"
        );
        assert!(
            !json_str.contains("\"parent_ino\""),
            "Journal must not have 'parent_ino' key"
        );
    }

    #[test]
    fn failed_status_round_trips() {
        let status = JournalEntryStatus::Failed {
            last_error: "network timeout".to_string(),
        };
        let json = serde_json::to_vec(&status).expect("serialize");
        let back: JournalEntryStatus = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(
            back,
            JournalEntryStatus::Failed {
                last_error: "network timeout".to_string()
            }
        );
    }

    // ---- Task 2: path-backed put/load/remove/update_status/record_failure tests ----

    #[test]
    fn journal_put_load() {
        let (q, _dir) = make_temp_queue();
        let entry = make_upload_entry("pu1", "k51vault");
        q.put(&entry).expect("put");

        let loaded = q.load_all_for_vault("k51vault").expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "pu1");
    }

    #[test]
    fn load_all_for_vault_excludes_foreign_vault() {
        let (q, _dir) = make_temp_queue();
        q.put(&make_upload_entry("vault-a-1", "vault-A")).expect("put a");
        q.put(&make_upload_entry("vault-b-1", "vault-B")).expect("put b");

        let loaded_a = q.load_all_for_vault("vault-A").expect("load a");
        assert_eq!(loaded_a.len(), 1);
        assert_eq!(loaded_a[0].id, "vault-a-1");

        let path_b = q.journal_dir.join("vault-b-1.json");
        assert!(path_b.exists(), "foreign vault file must remain on disk");
    }

    #[test]
    fn journal_remove() {
        let (q, _dir) = make_temp_queue();
        let entry = make_upload_entry("rm1", "k51vault");
        q.put(&entry).expect("put");

        q.remove("rm1").expect("remove");

        let path = q.journal_dir.join("rm1.json");
        assert!(!path.exists(), "file must be deleted after remove");

        let loaded = q.load_all_for_vault("k51vault").expect("load after remove");
        assert!(loaded.is_empty());
    }

    #[test]
    fn update_status_persists_new_status() {
        let (q, _dir) = make_temp_queue();
        let entry = make_upload_entry("upd1", "k51vault");
        q.put(&entry).expect("put");

        q.update_status(
            "upd1",
            JournalEntryStatus::Failed {
                last_error: "disk full".to_string(),
            },
        )
        .expect("update");

        let loaded = q.load_all_for_vault("k51vault").expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].status,
            JournalEntryStatus::Failed {
                last_error: "disk full".to_string()
            }
        );
    }

    #[test]
    fn park_on_max_retries() {
        let (q, _dir) = make_temp_queue();
        let entry = JournalEntry {
            retries: 3,
            ..make_upload_entry("park1", "k51vault")
        };
        q.put(&entry).expect("put initial");

        let result = q.record_failure(&entry, "connection refused").expect("record_failure");
        assert_eq!(
            result,
            JournalEntryStatus::Failed {
                last_error: "connection refused".to_string()
            }
        );

        // Entry must still exist on disk (D-09 — never silently dropped).
        let path = q.journal_dir.join("park1.json");
        assert!(path.exists(), "parked entry must remain on disk");

        let loaded = q.load_all_for_vault("k51vault").expect("load parked");
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].status,
            JournalEntryStatus::Failed {
                last_error: "connection refused".to_string()
            }
        );
    }

    #[test]
    fn record_failure_below_max_increments_retries() {
        let (q, _dir) = make_temp_queue();
        let entry = make_upload_entry("retry1", "k51vault");
        q.put(&entry).expect("put");

        let result = q.record_failure(&entry, "timeout").expect("record_failure");
        assert_eq!(result, JournalEntryStatus::Pending);

        let loaded = q.load_all_for_vault("k51vault").expect("load");
        assert_eq!(loaded[0].retries, 1);
        assert_eq!(loaded[0].status, JournalEntryStatus::Pending);
    }

    #[test]
    fn malformed_json_is_skipped_not_panicked() {
        let (q, dir) = make_temp_queue();

        let bad_path = dir.join("bad.json");
        std::fs::write(&bad_path, b"not valid json {{{{").expect("write bad");

        q.put(&make_upload_entry("valid1", "k51vault")).expect("put valid");

        let loaded = q.load_all_for_vault("k51vault").expect("load with bad file");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "valid1");
    }

    // ---- Task 4: parent_ipns_key_hex round-trip + ordering by created_at_ms tests ----

    /// CR-01/D-04: UploadFile entry with parent_ipns_key_hex set round-trips unchanged.
    #[test]
    fn upload_entry_parent_ipns_key_hex_round_trips() {
        let parent_key_hex = hex::encode(b"ecies-wrapped-parent-ipns-key-bytes-here");
        let entry = JournalEntry {
            id: "pk-upload".to_string(),
            vault_root_ipns: "k51vault".to_string(),
            op: JournalOp::UploadFile {
                ciphertext_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"ct",
                ),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: "k51file".to_string(),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: "k51parent".to_string(),
                parent_ipns_key_hex: parent_key_hex.clone(),
                filename: "f.txt".to_string(),
                size: 1,
                created_at_ms: 1_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        };
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        if let JournalOp::UploadFile { parent_ipns_key_hex, .. } = &back.op {
            assert_eq!(*parent_ipns_key_hex, parent_key_hex,
                "parent_ipns_key_hex must round-trip unchanged");
        } else {
            panic!("Expected UploadFile");
        }
    }

    /// CR-01/D-04: MkdirPublish entry with parent_ipns_key_hex set round-trips unchanged.
    #[test]
    fn mkdir_entry_parent_ipns_key_hex_round_trips() {
        let parent_key_hex = hex::encode(b"ecies-wrapped-parent-ipns-key-mkdir");
        let entry = JournalEntry {
            id: "pk-mkdir".to_string(),
            vault_root_ipns: "k51vault".to_string(),
            op: JournalOp::MkdirPublish {
                child_ipns_name: "k51child".to_string(),
                child_folder_key_hex: hex::encode(b"fk"),
                child_ipns_key_hex: hex::encode(b"ck"),
                parent_folder_ipns_name: "k51parent".to_string(),
                parent_ipns_key_hex: parent_key_hex.clone(),
                name: "newdir".to_string(),
                created_at_ms: 2_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        };
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        if let JournalOp::MkdirPublish { parent_ipns_key_hex, .. } = &back.op {
            assert_eq!(*parent_ipns_key_hex, parent_key_hex,
                "parent_ipns_key_hex must round-trip unchanged");
        } else {
            panic!("Expected MkdirPublish");
        }
    }

    /// WR-01: ordered_for_replay sorts each group by created_at_ms ascending.
    #[test]
    fn replay_order_sorts_by_created_at_within_group() {
        // Two UploadFile entries inserted newest-first; expect oldest-first after ordering.
        let mut entry_2000 = make_upload_entry("up-2000", "v");
        if let JournalOp::UploadFile { ref mut created_at_ms, .. } = entry_2000.op {
            *created_at_ms = 2000;
        }
        let mut entry_1000 = make_upload_entry("up-1000", "v");
        if let JournalOp::UploadFile { ref mut created_at_ms, .. } = entry_1000.op {
            *created_at_ms = 1000;
        }

        let mut mkdir_early = make_mkdir_entry("mk-100", "v");
        if let JournalOp::MkdirPublish { ref mut created_at_ms, .. } = mkdir_early.op {
            *created_at_ms = 100;
        }
        let mut mkdir_late = make_mkdir_entry("mk-50", "v");
        if let JournalOp::MkdirPublish { ref mut created_at_ms, .. } = mkdir_late.op {
            *created_at_ms = 50;
        }

        // Insert in "wrong" order to verify sort is applied.
        let entries = vec![entry_2000, entry_1000, mkdir_early, mkdir_late];
        let ordered = WriteQueue::ordered_for_replay(entries);

        // MkdirPublish entries must all come before UploadFile entries.
        // Within MkdirPublish group: mk-50 (50ms) before mk-100 (100ms).
        assert_eq!(ordered[0].id, "mk-50", "earliest mkdir must be first");
        assert_eq!(ordered[1].id, "mk-100", "later mkdir must be second");
        // Within UploadFile group: up-1000 (1000ms) before up-2000 (2000ms).
        assert_eq!(ordered[2].id, "up-1000", "earliest upload must be third");
        assert_eq!(ordered[3].id, "up-2000", "latest upload must be fourth");
    }

    /// D-05 extended: parent_ipns_key_hex in journal must be hex string, never raw bytes.
    #[test]
    fn journal_no_plaintext_with_parent_ipns_key() {
        let raw_secret = b"raw_ipns_key_secret_bytes_12345678";
        let wrapped_hex = hex::encode(raw_secret); // simulates user-ECIES-wrapped key
        let entry = JournalEntry {
            id: "noplain2".to_string(),
            vault_root_ipns: "k51vault".to_string(),
            op: JournalOp::UploadFile {
                ciphertext_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"ct",
                ),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: "k51file".to_string(),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: "k51parent".to_string(),
                parent_ipns_key_hex: wrapped_hex.clone(),
                filename: "g.txt".to_string(),
                size: 1,
                created_at_ms: 1,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        };
        let json_str = String::from_utf8(serde_json::to_vec(&entry).unwrap()).unwrap();
        // The field must be present and be the hex string.
        assert!(json_str.contains(&wrapped_hex), "parent_ipns_key_hex hex must appear in JSON");
        // Must not contain the raw bytes interpreted as a string.
        assert!(!json_str.contains("raw_ipns_key_secret_bytes"),
            "Journal must not contain raw key material as plaintext string");
    }

    // ---- Task 3: replay ordering tests ----

    #[test]
    fn replay_order_mkdir_before_upload() {
        let entries = vec![
            make_upload_entry("up1", "v"),
            make_mkdir_entry("mk1", "v"),
            make_upload_entry("up2", "v"),
            make_mkdir_entry("mk2", "v"),
        ];

        let ordered = WriteQueue::ordered_for_replay(entries);

        let mkdir_indices: Vec<usize> = ordered
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.op, JournalOp::MkdirPublish { .. }))
            .map(|(i, _)| i)
            .collect();
        let upload_indices: Vec<usize> = ordered
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.op, JournalOp::UploadFile { .. }))
            .map(|(i, _)| i)
            .collect();

        for &mi in &mkdir_indices {
            for &ui in &upload_indices {
                assert!(
                    mi < ui,
                    "MkdirPublish at index {} must precede UploadFile at index {}",
                    mi,
                    ui
                );
            }
        }
    }

    #[test]
    fn replay_order_preserves_relative_order_within_group() {
        let entries = vec![
            make_upload_entry("up-first", "v"),
            make_upload_entry("up-second", "v"),
            make_upload_entry("up-third", "v"),
        ];

        let ordered = WriteQueue::ordered_for_replay(entries);
        assert_eq!(ordered[0].id, "up-first");
        assert_eq!(ordered[1].id, "up-second");
        assert_eq!(ordered[2].id, "up-third");
    }
}
