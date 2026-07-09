//! Durable write journal for FUSE file uploads and directory publishes.
//!
//! Every FUSE write fsync-commits a `JournalEntry` to disk before acking the OS.
//! A crash after the fsync is recoverable on next mount via replay.
//!
//! The journal stores only ciphertext + node/v3 symmetric seals (the child
//! `PublishedNode` bytes + the parent `SealedChildRef.read_key_sealed` /
//! `WriteChildRef.write_key_sealed`) — never plaintext or raw/user-ECIES
//! node-to-node key bytes (zero-knowledge constraint, D-05 / NODE-06).

use serde::{Deserialize, Serialize};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Maximum per-entry plaintext payload size accepted into the journal (D-01, WR-06).
///
/// Above this size even an off-thread streaming sidecar write + `F_FULLFSYNC` stalls
/// long enough to be a denial-of-service risk on the shared FS thread, so the write-side
/// (`build_upload_journal_entry`) rejects the file with EIO rather than journaling it.
pub const MAX_JOURNAL_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Age window beyond which a parked `Failed` journal entry is GC'd (D-02).
pub const JOURNAL_GC_MAX_AGE_DAYS: u64 = 30;

/// Total on-disk byte budget for parked `Failed` entries; GC trims oldest-first
/// past this (D-02). Sums each entry's `.json` + `.bin` sidecar bytes.
pub const JOURNAL_GC_MAX_SIZE_BYTES: u64 = 500 * 1024 * 1024; // 500 MiB

/// Serde compat deserializer for `Option<String>` fields that were previously stored
/// as `String` with an empty-string sentinel.
///
/// Old journal entries (pre-Phase-45) persist `"file_meta_ipns_name": ""` when the
/// field is absent. The new type is `Option<String>`, which serializes as `null` or
/// is omitted. This helper maps `""` → `None` so old on-disk entries still deserialize
/// correctly under the new type (T-45-03-INT mitigation).
fn deser_opt_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    Ok(s.filter(|v| !v.is_empty()))
}

/// The operation encoded by a journal entry.
///
/// Variants cover both upload (D-03 UploadFile) and directory publish (D-03 MkdirPublish).
/// No inode identifiers — all routing uses stable IPNS names (D-02).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JournalOp {
    /// A file upload awaiting IPFS pin + folder metadata update.
    ///
    /// node/v3 shape (Phase 69, P1a-3): the KEY/metadata fields carry the freshly
    /// emitted child `PublishedNode` bytes + the D-07 dual-keyed parent read/write
    /// splices — NEVER a hex-ECIES-under-user-key node-to-node key. Node-to-node keys
    /// live ONLY inside the symmetric seals `SealedChildRef.read_key_sealed` /
    /// `WriteChildRef.write_key_sealed` (crypto rule #7 / NODE-06). The D-01/WR-06
    /// sidecar-ciphertext mechanism and the routing/timestamp fields are RETAINED.
    UploadFile {
        /// Absolute path to the ciphertext sidecar `<journal_dir>/<id>.bin` (D-01).
        ///
        /// Replaces the former in-JSON `ciphertext_b64` blob: the AES-256-GCM ciphertext
        /// is streamed to a 0600 sidecar file rather than embedded as base64 in the JSON
        /// entry, eliminating the ~2.7 GB `serde_json` allocation + multi-GB write on the
        /// shared FS thread (WR-06, HIGH).
        #[serde(default)]
        sidecar_path: PathBuf,
        /// Hex-encoded SHA-256 of the sidecar ciphertext, for integrity verification at
        /// replay time before re-upload (D-01). A mismatch means the sidecar is corrupt and
        /// the entry must be retained rather than re-uploaded.
        ///
        /// `#[serde(default)]` on both sidecar fields lets a pre-Phase-52 entry (which
        /// stored its ciphertext inline as `ciphertext_b64` and had no sidecar) still
        /// deserialize: such an entry loads with an empty `sidecar_path`, and the replay
        /// side detects the empty path + legacy inline ciphertext to drive a one-time
        /// passthrough replay (it is never re-persisted in the legacy shape).
        #[serde(default)]
        sidecar_sha256: String,
        /// Compat-only: the pre-Phase-52 inline base64 ciphertext (`ciphertext_b64`).
        ///
        /// Newer entries stream their ciphertext to a `.bin` sidecar and never set this. A
        /// pre-Phase-52 entry that was still pending at upgrade time has no sidecar but does
        /// carry its ciphertext inline here; the replay path decodes it for a one-time
        /// passthrough replay so the durable journal is honored instead of parking the upload.
        ///
        /// `#[serde(default)]` lets newer entries (no `ciphertext_b64`) deserialize, and
        /// `#[serde(skip_serializing)]` ensures it is NEVER written back to disk — once an
        /// entry is re-`put`, it persists in the sidecar shape with this field empty.
        ///
        /// This is a RETAINED D-01/WR-06 sidecar keeper (NOT a node-to-node key field); its
        /// existing compat is preserved. D-04's clean-flag-day ban on compat applies ONLY to
        /// the reshaped node/v3 crypto fields below.
        #[serde(default, alias = "ciphertext_b64", skip_serializing)]
        legacy_ciphertext_b64: String,
        /// Base64 of the freshly emitted child `PublishedNode` bytes (node/v3, P1a-3).
        ///
        /// Exactly `base64(encode_published_node(&child.published_node))` from `emit.rs`
        /// (69-16): the sealed node envelope replay re-publishes for this file. Base64
        /// (not a `Vec<u8>` number array) for JSON compactness, matching the crate's
        /// existing hex/base64 convention. No `#[serde(alias)]`/`#[serde(default)]` — a
        /// stale pre-cutover entry that lacks this field MUST fail serde and be skipped,
        /// never bridged (D-04 clean flag-day).
        child_published_node: String,
        /// Parent read-plane splice (node/v3, D-07 — read plane keyed by ipnsName).
        ///
        /// The updated `SealedChildRef` for this child inside the parent's read-body:
        /// `{name, ipns_name, generation, version_floor, read_key_sealed}`. The
        /// node-to-node read key lives ONLY inside the symmetric `read_key_sealed`
        /// (base64 AES-256-GCM seal under the parent readKey) — never a plaintext or
        /// user-ECIES key. NEVER conflated with the write plane below (childId != ipnsName).
        /// No serde compat (D-04) — a stale entry fails serde and is skipped.
        parent_child_ref: cipherbox_core::node::SealedChildRef,
        /// Parent write-plane splice (node/v3, D-07 — write plane keyed by childId UUID).
        ///
        /// The `WriteChildRef` `{child_id, write_key_sealed}` for this child inside the
        /// parent's write-body. The node-to-node write key lives ONLY inside the symmetric
        /// `write_key_sealed` (base64 AES-256-GCM seal under the parent writeKey). Distinct
        /// key space from `parent_child_ref` (a hyphenated UUID, not a k51 ipnsName) so
        /// replay re-splices BOTH planes. No serde compat (D-04).
        parent_write_child_ref: cipherbox_core::node::WriteChildRef,
        /// Per-file IPNS name for metadata pointer (stable across remount, D-02).
        ///
        /// `None` when the inode has no per-file IPNS record. Replaces the former
        /// empty-string sentinel. The compat deserializer (`deser_opt_string`) maps
        /// legacy `""` values from pre-Phase-45 on-disk journals to `None` so old
        /// entries still replay (T-45-03-INT). RETAINED routing keeper — keeps its
        /// existing compat.
        #[serde(default, deserialize_with = "deser_opt_string")]
        file_meta_ipns_name: Option<String>,
        /// Parent folder IPNS name (stable cross-remount, D-02) — the parent node identity.
        ///
        /// This is the parent node's read-plane identity replay routes the re-splice to.
        /// The parent IPNS *signing* seed replay needs to re-publish the parent record is
        /// NOT a node-to-node key hop and is deliberately NOT carried here as a user-ECIES
        /// field (D-04 / crypto rule #7): replay recovers the parent's `ipns_private_key`
        /// via the owned read chain (`list_folder_owned`, 69-17) at replay time from this
        /// identity. If 69-09's fuse write path proves it must thread the signing seed more
        /// directly, THIS ONE field is finalized against 69-09's constructor site.
        parent_folder_ipns_name: String,
        /// File size in bytes.
        size: u64,
        /// Creation timestamp, milliseconds since Unix epoch (serializable; replaces Instant).
        created_at_ms: u64,
    },
    /// A directory creation awaiting IPNS publish + parent folder metadata update.
    ///
    /// node/v3 shape (Phase 69, P1a-3): same reshape as `UploadFile` — the child
    /// `PublishedNode` bytes + the D-07 dual parent splices replace the former
    /// hex-ECIES-under-user-key folder/IPNS key + encrypted-name fields.
    MkdirPublish {
        /// New child folder IPNS name (routing keeper — the child node identity to publish).
        child_ipns_name: String,
        /// Base64 of the freshly emitted child folder `PublishedNode` bytes (node/v3).
        ///
        /// Same semantics as `UploadFile::child_published_node`. No serde compat (D-04).
        child_published_node: String,
        /// Parent read-plane splice (node/v3, D-07 — read plane keyed by ipnsName).
        ///
        /// Same semantics as `UploadFile::parent_child_ref`. No serde compat (D-04).
        parent_child_ref: cipherbox_core::node::SealedChildRef,
        /// Parent write-plane splice (node/v3, D-07 — write plane keyed by childId UUID).
        ///
        /// Same semantics as `UploadFile::parent_write_child_ref`. No serde compat (D-04).
        parent_write_child_ref: cipherbox_core::node::WriteChildRef,
        /// Parent folder IPNS name — the parent node identity (see
        /// `UploadFile::parent_folder_ipns_name` for the deferred parent-signing-seed note).
        parent_folder_ipns_name: String,
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
        let json =
            serde_json::to_vec(entry).map_err(|e| format!("Journal serialize failed: {}", e))?;

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
        let _ = std::fs::File::open(&self.journal_dir).and_then(|d| d.sync_all());

        Ok(())
    }

    /// Resolve the ciphertext sidecar path `<journal_dir>/<id>.bin` for an entry id (D-01).
    ///
    /// This is the canonical path `put_with_sidecar` writes and `remove` deletes; the
    /// write-side (`build_upload_journal_entry`) uses it to populate `UploadFile.sidecar_path`
    /// so the entry references exactly the file that will be written.
    pub fn sidecar_path_for(&self, id: &str) -> PathBuf {
        self.journal_dir.join(format!("{}.bin", id))
    }

    /// Persist a `UploadFile` entry plus its ciphertext sidecar with fsync barriers (D-01).
    ///
    /// The ciphertext is streamed to `<journal_dir>/<id>.bin` (0600, fsync'd) in fixed-size
    /// chunks — never allocated as a single `String` — then the `<id>.json` entry (which must
    /// already carry `sidecar_path` + `sidecar_sha256`) is written via the same fsync barrier
    /// as `put`. If the `.json` write/fsync fails, the `.bin` is removed before returning `Err`
    /// so no orphaned ciphertext is left behind (Pitfall 2).
    ///
    /// This is synchronous; the FUSE release path calls it from a background tokio task and
    /// blocks on a bounded oneshot for durability before acking (Plan 52-03).
    ///
    /// The caller owns the `sidecar_sha256` value (computed at entry-construction time);
    /// `put_with_sidecar` writes the bytes and verifies the byte length is non-empty, but does
    /// not recompute the hash (the replay side verifies it before re-upload).
    pub fn put_with_sidecar(&self, entry: &JournalEntry, ciphertext: &[u8]) -> Result<(), String> {
        let id = &entry.id;
        let bin_path = self.sidecar_path_for(id);

        // Validate the entry's recorded sidecar path matches the canonical path we are about to
        // write/fsync, so replay reads exactly the file persisted here (not a stale/foreign path).
        match &entry.op {
            JournalOp::UploadFile { sidecar_path, .. } if sidecar_path == &bin_path => {}
            JournalOp::UploadFile { sidecar_path, .. } => {
                return Err(format!(
                    "Journal sidecar path mismatch: entry points to {:?}, expected {:?}",
                    sidecar_path, bin_path
                ));
            }
            JournalOp::MkdirPublish { .. } => {
                return Err("put_with_sidecar requires an UploadFile entry".to_string());
            }
        }

        // Remove any stale sidecar from a prior aborted write before re-writing (Pitfall 2).
        if let Err(e) = std::fs::remove_file(&bin_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("Journal sidecar pre-clean failed: {}", e));
            }
        }

        // Stream ciphertext to the 0600 sidecar in fixed-size chunks (never a full String).
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        open_opts.mode(0o600);
        let mut bin_file = open_opts
            .open(&bin_path)
            .map_err(|e| format!("Journal sidecar open failed: {}", e))?;

        const CHUNK: usize = 1024 * 1024; // 1 MiB
                                          // On any write/fsync failure, remove the partial sidecar before returning so no orphan
                                          // `.bin` is left for a later GC pass (Pitfall 2).
        let sidecar_write = (|| -> Result<(), String> {
            for chunk in ciphertext.chunks(CHUNK) {
                bin_file
                    .write_all(chunk)
                    .map_err(|e| format!("Journal sidecar write failed: {}", e))?;
            }
            bin_file
                .sync_all()
                .map_err(|e| format!("Journal sidecar fsync failed: {}", e))?;
            Ok(())
        })();
        if let Err(e) = sidecar_write {
            drop(bin_file);
            let _ = std::fs::remove_file(&bin_path);
            return Err(e);
        }
        drop(bin_file);

        // Write the JSON entry with the same fsync + parent-dir barrier as `put`. On any
        // failure, remove the orphaned sidecar before returning the error (atomic cleanup).
        if let Err(e) = self.put(entry) {
            let _ = std::fs::remove_file(&bin_path);
            return Err(e);
        }

        Ok(())
    }

    /// Remove an entry file (and its ciphertext sidecar) from disk.
    ///
    /// Returns `Ok(())` if neither file existed (idempotent). Deletes BOTH the `<id>.json`
    /// entry and the `<id>.bin` sidecar so no orphaned ciphertext is left behind (D-01).
    /// A MkdirPublish entry has no sidecar; its `.bin` absence is normal (NotFound → Ok).
    /// After removal, syncs the parent journal directory so the deleted dirents are durable
    /// on crash (WR-03b).
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let json_path = self.journal_dir.join(format!("{}.json", id));
        let bin_path = self.sidecar_path_for(id);

        // Remove the `.json` (the replay trigger) FIRST so a crash between the two unlinks
        // leaves at most an orphan `.bin` — harmless, GC pass 3 reaps it without replaying.
        // The reverse order would leave a live `.json` pointing at a now-missing `.bin`, which
        // replay reads as a corrupt entry and parks as Failed (spurious "upload failed").
        let removed_json = match std::fs::remove_file(&json_path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(format!("Journal remove failed: {}", e)),
        };
        if removed_json {
            // WR-03b: fsync parent dir so the `.json` removal is durable before unlinking `.bin`.
            let _ = std::fs::File::open(&self.journal_dir).and_then(|d| d.sync_all());
        }

        // Remove the sidecar (NotFound is fine — not every entry has one).
        let removed_bin = match std::fs::remove_file(&bin_path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(format!("Journal sidecar remove failed: {}", e)),
        };
        if removed_bin {
            let _ = std::fs::File::open(&self.journal_dir).and_then(|d| d.sync_all());
        }

        Ok(())
    }

    /// Load all journal entries belonging to `vault_root_ipns`.
    ///
    /// Skips files that cannot be parsed with a `log::warn!` (never panics — V5, T-43-03).
    /// Returns only entries whose `vault_root_ipns` matches the given value (D-07).
    pub fn load_all_for_vault(&self, vault_root_ipns: &str) -> Result<Vec<JournalEntry>, String> {
        let read_dir = std::fs::read_dir(&self.journal_dir)
            .map_err(|e| format!("Journal dir read failed: {}", e))?;

        let mut entries = Vec::new();

        for dir_entry in read_dir {
            let dir_entry = dir_entry.map_err(|e| format!("Journal dir entry error: {}", e))?;
            let path = dir_entry.path();

            // Only process *.json files.
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            // Skip the co-located floor-sidecar file(s) -- they live in the
            // SAME journal dir but are not `JournalEntry` records and will
            // never parse as one. Without this, every scan logged a benign
            // "malformed entry ... missing field 'id'" warning for them.
            if path
                .file_name()
                .and_then(|f| f.to_str())
                .is_some_and(crate::floor_store::is_reserved_floor_sidecar)
            {
                continue;
            }

            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("Journal: failed to read {:?}: {} — skipping", path, e);
                    continue;
                }
            };

            // Skip-with-warn on malformed JSON (T-43-03, V5).
            let entry: JournalEntry = match serde_json::from_slice(&bytes) {
                Ok(e) => e,
                Err(e) => {
                    log::warn!("Journal: malformed entry at {:?}: {} — skipping", path, e);
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

    /// Remove every journal entry (`.json` + `.bin`) belonging to a single vault (D-02).
    ///
    /// The journal directory is shared across vaults and `load_all_for_vault` only filters
    /// at read time, so a departing vault's entries (including their ciphertext sidecars)
    /// would otherwise persist forever into another session (T-52-15, Information Disclosure).
    /// `purge_vault` removes ALL entries for `vault_root_ipns` regardless of status (logout
    /// means the session is over), deleting both the `.json` and its `.bin` sidecar via the
    /// sidecar-aware [`remove`](Self::remove). Returns the number of entries removed.
    ///
    /// This is the reusable purge interface a future `switch_account` / `delete_account`
    /// command must call for the departing vault. It is wired at `logout()` today.
    pub fn purge_vault(&self, vault_root_ipns: &str) -> Result<usize, String> {
        let entries = self.load_all_for_vault(vault_root_ipns)?;
        let mut removed = 0usize;
        // Best-effort: attempt EVERY entry even if one removal fails (e.g. EACCES on a `.bin`),
        // matching `gc_failed_entries`. A fail-fast `?` here would leave later entries' `.json`
        // and `.bin` files on disk, only partially honoring the Information Disclosure guarantee
        // this function exists to provide (T-52-15). The caller treats the purge as best-effort.
        for entry in &entries {
            match self.remove(&entry.id) {
                Ok(()) => removed += 1,
                Err(e) => {
                    log::warn!("purge_vault: failed to remove entry {}: {}", entry.id, e);
                }
            }
        }
        Ok(removed)
    }

    /// Garbage-collect parked `Failed` journal entries and orphaned sidecars (D-02).
    ///
    /// Parked `Failed` entries are kept on disk for manual intervention (D-09) and would
    /// otherwise grow without bound, exhausting disk (T-52-16, Denial of Service). This
    /// runs once per mount and is best-effort — per-file errors are logged and skipped,
    /// never fatal. Three passes, all touching ONLY `Failed` entries (in-flight
    /// `Pending`/`InProgress` are never GC'd):
    ///
    /// 1. **Age purge** — remove any `Failed` entry whose `created_at_ms` is older than
    ///    `age_days` (compared against the same ms-since-epoch clock entries are stamped with).
    /// 2. **Size purge** — sum each surviving `Failed` entry's on-disk size (`.json` bytes
    ///    plus its `.bin` sidecar bytes); if the total exceeds `total_size_budget`, remove
    ///    oldest-first (by `created_at_ms`) until under budget.
    /// 3. **Orphan cleanup** — delete any `.bin` sidecar with no matching `<id>.json`
    ///    (a sidecar left behind by an aborted write, RESEARCH Pitfall 2).
    ///
    /// Returns the total number of entries + orphan sidecars removed.
    pub fn gc_failed_entries(
        &self,
        age_days: u64,
        total_size_budget: u64,
    ) -> Result<usize, String> {
        let read_dir = std::fs::read_dir(&self.journal_dir)
            .map_err(|e| format!("Journal GC dir read failed: {}", e))?;

        // Scan all `.json` entries across ALL vaults (GC is global) and keep only `Failed`.
        let mut failed: Vec<JournalEntry> = Vec::new();
        // Stems (`<id>`) of `.json` files that PARSED successfully — the set of entries that
        // could ever own a live sidecar. A torn/truncated `.json` (e.g. crash mid-write of the
        // JSON after the `.bin` was already fsynced) is unparseable, so its stem is absent here
        // and pass 3 treats its sidecar as orphaned even though the `.json` exists on disk
        // (T-52-16 disk DoS / T-52-15 at-rest info-disclosure).
        let mut parseable_stems: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for dir_entry in read_dir {
            let dir_entry = match dir_entry {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("Journal GC: dir entry error: {} — skipping", e);
                    continue;
                }
            };
            let path = dir_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // Skip the co-located floor-sidecar file(s) -- see the matching
            // skip in `load_all_for_vault` above for why. GC's `parseable_stems`
            // tracking intentionally does NOT need to include these: they
            // never own a `.bin` sidecar, so pass 3's orphan check is
            // unaffected either way.
            if path
                .file_name()
                .and_then(|f| f.to_str())
                .is_some_and(crate::floor_store::is_reserved_floor_sidecar)
            {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("Journal GC: failed to read {:?}: {} — skipping", path, e);
                    continue;
                }
            };
            match serde_json::from_slice::<JournalEntry>(&bytes) {
                Ok(entry) => {
                    // Record EVERY well-formed entry's stem (regardless of status) so its
                    // sidecar is recognized as live in pass 3.
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        parseable_stems.insert(stem.to_string());
                    }
                    if matches!(entry.status, JournalEntryStatus::Failed { .. }) {
                        failed.push(entry);
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Journal GC: malformed entry at {:?}: {} — skipping",
                        path,
                        e
                    );
                }
            }
        }

        let mut removed = 0usize;

        // Pass 1: age purge.
        let now = now_ms();
        let max_age_ms = age_days.saturating_mul(86_400_000);
        let age_cutoff = now.saturating_sub(max_age_ms);
        let mut survivors: Vec<JournalEntry> = Vec::new();
        for entry in failed {
            if entry.op.created_at_ms() < age_cutoff {
                match self.remove(&entry.id) {
                    Ok(()) => removed += 1,
                    Err(e) => log::warn!("Journal GC: age-remove {} failed: {}", entry.id, e),
                }
            } else {
                survivors.push(entry);
            }
        }

        // Pass 2: size purge — oldest-first until under budget.
        survivors.sort_by_key(|e| e.op.created_at_ms());
        let mut total_size: u64 = survivors
            .iter()
            .map(|e| self.entry_on_disk_size(&e.id))
            .sum();
        let mut idx = 0;
        while total_size > total_size_budget && idx < survivors.len() {
            let entry = &survivors[idx];
            let entry_size = self.entry_on_disk_size(&entry.id);
            match self.remove(&entry.id) {
                Ok(()) => {
                    removed += 1;
                    total_size = total_size.saturating_sub(entry_size);
                }
                Err(e) => log::warn!("Journal GC: size-remove {} failed: {}", entry.id, e),
            }
            idx += 1;
        }

        // Pass 3: orphan `.bin` cleanup — sidecars with no LIVE owning `.json` (Pitfall 2).
        //
        // Liveness is "the sibling `.json` parsed successfully" (in `parseable_stems`), NOT
        // mere file existence: a torn/truncated `.json` still exists on disk but is never
        // replayed (load_all_for_vault skips it), so its sidecar would otherwise persist
        // forever. Reap when the `.json` is physically absent OR present-but-unparseable.
        if let Ok(read_dir) = std::fs::read_dir(&self.journal_dir) {
            for dir_entry in read_dir.flatten() {
                let path = dir_entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                    continue;
                }
                let json_path = path.with_extension("json");
                let stem = path.file_stem().and_then(|s| s.to_str());
                let orphaned = !json_path.exists()
                    || !stem.map(|s| parseable_stems.contains(s)).unwrap_or(false);
                if orphaned {
                    match std::fs::remove_file(&path) {
                        Ok(()) => removed += 1,
                        Err(e) => {
                            log::warn!("Journal GC: orphan remove {:?} failed: {}", path, e)
                        }
                    }
                }
            }
        }

        Ok(removed)
    }

    /// On-disk byte size of an entry: its `.json` plus its `.bin` sidecar (if present).
    ///
    /// Missing files contribute 0 (used only by GC's size accounting, never fatal).
    fn entry_on_disk_size(&self, id: &str) -> u64 {
        let json_path = self.journal_dir.join(format!("{}.json", id));
        let bin_path = self.sidecar_path_for(id);
        let json_size = std::fs::metadata(&json_path).map(|m| m.len()).unwrap_or(0);
        let bin_size = std::fs::metadata(&bin_path).map(|m| m.len()).unwrap_or(0);
        json_size + bin_size
    }

    /// Overwrite the status of an entry on disk.
    pub fn update_status(&self, id: &str, status: JournalEntryStatus) -> Result<(), String> {
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
        // A detached upload worker holds an in-memory snapshot of its entry and may call this
        // long after `purge_vault` (logout) deleted the on-disk `.json`. Re-`put`ting it here
        // would resurrect a purged entry — and without its also-deleted `.bin` sidecar, replay
        // would only park it as Failed. If the entry file is already gone, treat the failure as
        // a no-op rather than recreating it.
        let json_path = self.journal_dir.join(format!("{}.json", entry.id));
        if !json_path.exists() {
            return Ok(JournalEntryStatus::Failed {
                last_error: error.to_string(),
            });
        }

        // A pre-Phase-52 UploadFile entry loads with an empty `sidecar_path` and its only
        // payload in the in-memory `legacy_ciphertext_b64` field (which is `skip_serializing`).
        // Re-persisting it via `put`/`update_status` would write a JSON with NO ciphertext and
        // still no sidecar, leaving an unreplayable missing-payload entry that parks forever
        // (data loss). Migrate the inline bytes to the canonical `.bin` sidecar BEFORE any
        // re-persist so the payload is durable and the next mount replays via the sidecar branch.
        if let Some((migrated, decoded)) = self.migrate_legacy_inline(entry) {
            let status = if entry.retries >= self.max_retries {
                JournalEntryStatus::Failed {
                    last_error: error.to_string(),
                }
            } else {
                JournalEntryStatus::Pending
            };
            let mut migrated = migrated;
            migrated.status = status.clone();
            if entry.retries < self.max_retries {
                migrated.retries += 1;
            }
            // Route BOTH the retry and the park case through put_with_sidecar so the legacy
            // inline payload becomes a durable, fsync'd sidecar (never update_status, whose
            // read-modify-write would re-drop the skip_serializing legacy field).
            self.put_with_sidecar(&migrated, &decoded)?;
            return Ok(status);
        }

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

    /// Migrate a pre-Phase-52 legacy `UploadFile` entry (inline base64 ciphertext, empty
    /// `sidecar_path`) to the canonical `.bin` sidecar shape (D-01).
    ///
    /// Returns `Some((migrated_entry, decoded_ciphertext))` when `entry` is a legacy
    /// UploadFile (empty `sidecar_path` + non-empty `legacy_ciphertext_b64`) whose inline
    /// bytes decode cleanly. The migrated clone points `sidecar_path` at
    /// `sidecar_path_for(id)`, records the SHA-256 of the decoded ciphertext in
    /// `sidecar_sha256`, and clears `legacy_ciphertext_b64`, so `put_with_sidecar` accepts it
    /// (its path-validation requires `sidecar_path == sidecar_path_for(id)`).
    ///
    /// Returns `None` for a non-legacy entry, a non-UploadFile op, or an empty/undecodable
    /// legacy blob (the caller falls through to the normal re-put — an undecodable blob was
    /// unreplayable anyway, so no recoverable bytes are lost).
    fn migrate_legacy_inline(&self, entry: &JournalEntry) -> Option<(JournalEntry, Vec<u8>)> {
        let JournalOp::UploadFile {
            sidecar_path,
            legacy_ciphertext_b64,
            ..
        } = &entry.op
        else {
            return None;
        };
        if !sidecar_path.as_os_str().is_empty() || legacy_ciphertext_b64.is_empty() {
            return None;
        }

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(legacy_ciphertext_b64)
            .ok()?;

        let sha256 = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&decoded);
            hex::encode(hasher.finalize())
        };

        let mut migrated = entry.clone();
        if let JournalOp::UploadFile {
            sidecar_path,
            sidecar_sha256,
            legacy_ciphertext_b64,
            ..
        } = &mut migrated.op
        {
            *sidecar_path = self.sidecar_path_for(&entry.id);
            *sidecar_sha256 = sha256;
            legacy_ciphertext_b64.clear();
        }
        Some((migrated, decoded))
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

/// Current wall-clock time as milliseconds since the Unix epoch.
///
/// Matches the clock journal entries are stamped with (`created_at_ms`); used by
/// `gc_failed_entries` for the age comparison. Mirrors `registry::now_ms`.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Log-capture test harness ----
    //
    // Proves the floor-sidecar-skip fix actually silences the
    // "malformed entry ... missing field 'id'" warning, not just that the
    // entry count comes out right (which it already did BEFORE the fix,
    // via the pre-existing serde-Err-skip path -- the skip is purely a
    // noise fix, not a functional one). `log::set_logger` is process-global
    // and can only be installed once, but capture is scoped per-thread via
    // a thread-local buffer, so concurrently-running tests (cargo test
    // runs each test on its own thread by default) never see each other's
    // captured messages.
    thread_local! {
        static CAPTURED_LOG_MESSAGES: std::cell::RefCell<Option<Vec<String>>> =
            const { std::cell::RefCell::new(None) };
    }

    struct ThreadLocalCapturingLogger;

    impl log::Log for ThreadLocalCapturingLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            CAPTURED_LOG_MESSAGES.with(|cell| {
                if let Some(buf) = cell.borrow_mut().as_mut() {
                    buf.push(record.args().to_string());
                }
            });
        }
        fn flush(&self) {}
    }

    static CAPTURING_LOGGER: ThreadLocalCapturingLogger = ThreadLocalCapturingLogger;
    static INIT_CAPTURING_LOGGER: std::sync::Once = std::sync::Once::new();

    /// Runs `f`, capturing every `log::*!` message emitted on the CURRENT thread
    /// during its execution, and returns them. Other threads' concurrent log
    /// calls are unaffected (their own thread-local buffer stays `None`, so the
    /// logger silently drops their messages instead of capturing them).
    fn capture_log_messages(f: impl FnOnce()) -> Vec<String> {
        INIT_CAPTURING_LOGGER.call_once(|| {
            // Ignore "already set" -- some other test binary/harness may have
            // installed a logger first; either way our thread-local gate below
            // still only captures messages logged during THIS call.
            let _ = log::set_logger(&CAPTURING_LOGGER);
            log::set_max_level(log::LevelFilter::Warn);
        });
        CAPTURED_LOG_MESSAGES.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
        f();
        CAPTURED_LOG_MESSAGES.with(|cell| cell.borrow_mut().take().unwrap_or_default())
    }

    // ---- Helper builders ----

    use cipherbox_core::node::{PublishedNode, SealedChildRef, WriteChildRef};

    /// Base64-encode arbitrary bytes with the standard alphabet (matches the crate's
    /// on-wire seal/PublishedNode convention).
    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A base64-encoded child `PublishedNode` envelope, as `child_published_node` carries
    /// on the node/v3 wire (`base64(encode_published_node(..))`, 69-16). `read_sealed` /
    /// `write_sealed` are opaque base64 seals — never a plaintext node-to-node key.
    fn sample_child_published_node_b64() -> String {
        let node = PublishedNode {
            schema: "cipherbox/node@3".to_string(),
            kind: "file".to_string(),
            id: "11111111-1111-1111-1111-111111111111".to_string(),
            generation: 0,
            aead_version: 1,
            read_sealed: b64(b"opaque-read-sealed-body"),
            write_sealed: Some(b64(b"opaque-write-sealed-body")),
        };
        let bytes = cipherbox_core::node::encode_published_node(&node).expect("encode node");
        b64(&bytes)
    }

    /// The D-07 read-plane splice: `SealedChildRef` keyed by ipnsName (k51), carrying the
    /// child readKey inside the symmetric base64 `read_key_sealed`.
    fn sample_parent_child_ref() -> SealedChildRef {
        SealedChildRef {
            name: "child".to_string(),
            ipns_name: "k51childreadplane".to_string(),
            generation: 0,
            version_floor: 1,
            read_key_sealed: b64(b"symmetric-read-key-seal"),
        }
    }

    /// The D-07 write-plane splice: `WriteChildRef` keyed by childId (UUID) — a DISTINCT
    /// key space from the read plane's ipnsName — carrying the child writeKey inside the
    /// symmetric base64 `write_key_sealed`.
    fn sample_parent_write_child_ref() -> WriteChildRef {
        WriteChildRef {
            child_id: "22222222-2222-2222-2222-222222222222".to_string(),
            write_key_sealed: b64(b"symmetric-write-key-seal"),
        }
    }

    fn make_upload_entry(id: &str, vault: &str) -> JournalEntry {
        JournalEntry {
            id: id.to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from(format!("/tmp/{}.bin", id)),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                child_published_node: sample_child_published_node_b64(),
                parent_child_ref: sample_parent_child_ref(),
                parent_write_child_ref: sample_parent_write_child_ref(),
                file_meta_ipns_name: Some("k51filemetaipns".to_string()),
                parent_folder_ipns_name: "k51parentfolder".to_string(),
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
                child_published_node: sample_child_published_node_b64(),
                parent_child_ref: sample_parent_child_ref(),
                parent_write_child_ref: sample_parent_write_child_ref(),
                parent_folder_ipns_name: "k51parentfolder".to_string(),
                created_at_ms: 1_700_000_000_001,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        }
    }

    /// Create a unique temporary directory for test isolation.
    ///
    /// Uses process ID + a monotonically-increasing atomic counter to guarantee
    /// uniqueness across both concurrent tests within a run and separate test-binary
    /// invocations (which would otherwise reuse the same counter values with the same
    /// thread IDs, causing stale files from prior runs to contaminate load results).
    fn make_temp_queue() -> (WriteQueue, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("cipherbox-journal-test-{}-{}", pid, seq));
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
        if let JournalOp::UploadFile {
            child_published_node,
            parent_child_ref,
            parent_write_child_ref,
            size,
            ..
        } = &back.op
        {
            // node/v3 fields survive serde intact.
            assert_eq!(child_published_node, &sample_child_published_node_b64());
            assert_eq!(parent_child_ref, &sample_parent_child_ref());
            assert_eq!(parent_write_child_ref, &sample_parent_write_child_ref());
            // the base64 child PublishedNode decodes back to a valid envelope.
            use base64::Engine;
            let node_bytes = base64::engine::general_purpose::STANDARD
                .decode(child_published_node)
                .expect("child_published_node must be base64");
            cipherbox_core::node::decode_published_node(&node_bytes)
                .expect("child_published_node must decode to a PublishedNode");
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
        if let JournalOp::MkdirPublish {
            child_published_node,
            parent_child_ref,
            parent_write_child_ref,
            ..
        } = &back.op
        {
            assert_eq!(child_published_node, &sample_child_published_node_b64());
            assert_eq!(parent_child_ref, &sample_parent_child_ref());
            assert_eq!(parent_write_child_ref, &sample_parent_write_child_ref());
        } else {
            panic!("Expected MkdirPublish op");
        }
    }

    /// D-05 / NODE-06 (retargeted at the node/v3 fields): the journal must carry only
    /// symmetric base64 seals + the base64 child PublishedNode — never a plaintext or
    /// user-ECIES node-to-node key. A known raw key marker sealed into `read_key_sealed`
    /// must appear ONLY in its base64 form, never as the raw plaintext bytes.
    #[test]
    fn journal_no_plaintext() {
        let raw_node_key = b"raw_node_to_node_key_secret_bytes";
        let sealed_b64 = b64(raw_node_key);
        let mut entry = make_upload_entry("noplain", "k51vault");
        if let JournalOp::UploadFile {
            parent_child_ref,
            parent_write_child_ref,
            ..
        } = &mut entry.op
        {
            parent_child_ref.read_key_sealed = sealed_b64.clone();
            parent_write_child_ref.write_key_sealed = sealed_b64.clone();
        }
        let json = serde_json::to_vec(&entry).expect("serialize");
        let json_str = String::from_utf8(json).expect("utf8");
        // The node-to-node key is only ever the symmetric base64 seal.
        assert!(
            json_str.contains(&sealed_b64),
            "the symmetric base64 seal must be present on the wire"
        );
        assert!(
            !json_str.contains("raw_node_to_node_key_secret"),
            "Journal must never carry a raw/plaintext node-to-node key"
        );
        // The D-07 dual splices are present under their camelCase wire names.
        assert!(
            json_str.contains("readKeySealed") && json_str.contains("writeKeySealed"),
            "both symmetric seals must be present (D-07 dual splice)"
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
        q.put(&make_upload_entry("vault-a-1", "vault-A"))
            .expect("put a");
        q.put(&make_upload_entry("vault-b-1", "vault-B"))
            .expect("put b");

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

        let result = q
            .record_failure(&entry, "connection refused")
            .expect("record_failure");
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

        q.put(&make_upload_entry("valid1", "k51vault"))
            .expect("put valid");

        let loaded = q
            .load_all_for_vault("k51vault")
            .expect("load with bad file");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "valid1");
    }

    /// Regression: the durable rotation floor sidecar (`rotation-high-water.json`
    /// and its two legacy pre-70.1-03 shapes) lives in the SAME journal dir
    /// as `WriteQueue`'s own `<id>.json` entries. It is not a `JournalEntry`
    /// and will never parse as one -- before the
    /// `crate::floor_store::is_reserved_floor_sidecar` skip, every scan
    /// logged a spurious "malformed entry ... missing field 'id'" warning
    /// for it (benign, but noisy: `load_all_for_vault` already returned the
    /// correct entries even without the skip, via the pre-existing
    /// serde-Err-skip path -- this fix is purely about silencing the
    /// warning, not fixing a functional bug). Uses `capture_log_messages`
    /// to prove the warning is genuinely gone, not just that the entry
    /// count is unaffected (which was already true before this fix).
    #[test]
    fn load_all_for_vault_skips_the_floor_sidecar_without_a_malformed_warning() {
        let (q, dir) = make_temp_queue();

        std::fs::write(
            dir.join("rotation-high-water.json"),
            br#"{"node-1":{"generation":3,"seq":9}}"#,
        )
        .expect("write floor sidecar");
        std::fs::write(
            dir.join("rotation-high-water-generation.json"),
            br#"{"node-1":3}"#,
        )
        .expect("write legacy generation sidecar");
        std::fs::write(dir.join("rotation-high-water-seq.json"), br#"{"node-1":9}"#)
            .expect("write legacy seq sidecar");

        q.put(&make_upload_entry("valid1", "k51vault"))
            .expect("put valid");

        let mut loaded_len = 0;
        let mut loaded_id = String::new();
        let messages = capture_log_messages(|| {
            let loaded = q
                .load_all_for_vault("k51vault")
                .expect("load alongside floor sidecars");
            loaded_len = loaded.len();
            loaded_id = loaded[0].id.clone();
        });

        assert_eq!(loaded_len, 1);
        assert_eq!(loaded_id, "valid1");
        assert!(
            !messages.iter().any(|m| m.contains("malformed entry")),
            "floor sidecar must not trigger a malformed-entry warning: {messages:?}"
        );

        // Harness sanity check: a GENUINELY malformed file on the same scan
        // still logs the warning -- proving the absence above is because
        // the floor sidecar is skipped, not because the harness fails to
        // capture anything.
        std::fs::write(dir.join("truly-bad.json"), b"not valid json {{{{").expect("write bad json");
        let messages = capture_log_messages(|| {
            let _ = q.load_all_for_vault("k51vault").expect("load again");
        });
        assert!(
            messages.iter().any(|m| m.contains("malformed entry")),
            "a genuinely malformed entry must still warn: {messages:?}"
        );
    }

    /// T-69-18-01 (D-04 clean flag-day): a STALE pre-cutover on-disk entry — well-formed
    /// JSON in the OLD hex-ECIES JournalOp shape, carrying NONE of the node/v3 crypto fields
    /// (child_published_node/parent_child_ref/parent_write_child_ref) — must fail serde under
    /// the reshaped types and be `log::warn!`+SKIPPED by `load_all_for_vault`, never bridged
    /// and never panicked.
    ///
    /// This proves the reshape added NO dual-format deserializer: because Task 1 added no
    /// `#[serde(alias)]`/`#[serde(default)]` compat for the node/v3 fields, the legacy entry
    /// hits the EXISTING serde Err-skip loop (the same idiom as
    /// `malformed_json_is_skipped_not_panicked`) with zero new migration/bridge code. A
    /// current node/v3 entry written alongside still loads, proving the skip is selective.
    #[test]
    fn stale_legacy_shaped_entry_fails_closed() {
        let (q, dir) = make_temp_queue();

        // A well-formed JSON in the PRE-CUTOVER UploadFile shape: old hex-ECIES key fields,
        // no node/v3 fields. Authored by hand because the reshaped type can no longer PRODUCE
        // this shape. It is valid JSON but does not match the node/v3 JournalOp.
        let legacy_upload = r#"{
            "id": "stale-legacy-upload",
            "vault_root_ipns": "k51vaultstale",
            "op": {
                "UploadFile": {
                    "ciphertext_b64": "Y3Q=",
                    "wrapped_key_hex": "776b",
                    "iv_hex": "6976",
                    "file_meta_ipns_name": "k51file",
                    "file_ipns_key_hex": null,
                    "parent_folder_ipns_name": "k51parent",
                    "parent_ipns_key_hex": "6563696573",
                    "filename": "report.txt",
                    "size": 1,
                    "created_at_ms": 1000
                }
            },
            "retries": 0,
            "status": "Pending"
        }"#;
        std::fs::write(dir.join("stale-legacy-upload.json"), legacy_upload)
            .expect("write stale upload");

        // A stale pre-cutover MkdirPublish, likewise old-shaped.
        let legacy_mkdir = r#"{
            "id": "stale-legacy-mkdir",
            "vault_root_ipns": "k51vaultstale",
            "op": {
                "MkdirPublish": {
                    "child_ipns_name": "k51child",
                    "child_folder_key_hex": "666b",
                    "child_ipns_key_hex": "636b",
                    "parent_folder_ipns_name": "k51parent",
                    "parent_ipns_key_hex": "6563696573",
                    "name": "folder1",
                    "created_at_ms": 1000
                }
            },
            "retries": 0,
            "status": "Pending"
        }"#;
        std::fs::write(dir.join("stale-legacy-mkdir.json"), legacy_mkdir)
            .expect("write stale mkdir");

        // Only the two stale entries exist → load returns EMPTY (both skipped, no panic).
        let loaded = q
            .load_all_for_vault("k51vaultstale")
            .expect("load must not panic on stale entries");
        assert!(
            loaded.is_empty(),
            "stale pre-cutover entries must be skipped (fail closed), not deserialized"
        );

        // A current node/v3 entry written alongside the stale ones still loads — the skip is
        // selective (per-entry serde Err), not a blanket load failure.
        q.put(&make_upload_entry("fresh-v3", "k51vaultstale"))
            .expect("put fresh node/v3 entry");
        let loaded2 = q
            .load_all_for_vault("k51vaultstale")
            .expect("load with fresh entry");
        assert_eq!(loaded2.len(), 1, "only the fresh node/v3 entry loads");
        assert_eq!(loaded2[0].id, "fresh-v3");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- node/v3 D-07 dual-plane round-trip + ordering by created_at_ms tests ----

    /// D-07: an UploadFile entry carries BOTH a read-plane SealedChildRef (keyed by
    /// ipnsName) AND a write-plane WriteChildRef (keyed by childId UUID); the two are
    /// distinct key spaces (childId != ipnsName) and both survive serde unchanged.
    #[test]
    fn upload_entry_dual_plane_round_trips() {
        let entry = make_upload_entry("d07-upload", "k51vault");
        // Pre-flight: the write-plane childId is never the read-plane ipnsName.
        if let JournalOp::UploadFile {
            parent_child_ref,
            parent_write_child_ref,
            ..
        } = &entry.op
        {
            assert_ne!(
                parent_write_child_ref.child_id, parent_child_ref.ipns_name,
                "D-07: write-plane childId must never equal read-plane ipnsName"
            );
        } else {
            panic!("Expected UploadFile");
        }
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        if let JournalOp::UploadFile {
            parent_child_ref,
            parent_write_child_ref,
            ..
        } = &back.op
        {
            assert_eq!(parent_child_ref, &sample_parent_child_ref());
            assert_eq!(parent_write_child_ref, &sample_parent_write_child_ref());
            // The two planes remain distinct after the round-trip.
            assert_ne!(parent_write_child_ref.child_id, parent_child_ref.ipns_name);
        } else {
            panic!("Expected UploadFile");
        }
    }

    /// D-07: a MkdirPublish entry carries the same distinct read/write splices.
    #[test]
    fn mkdir_entry_dual_plane_round_trips() {
        let entry = make_mkdir_entry("d07-mkdir", "k51vault");
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        if let JournalOp::MkdirPublish {
            parent_child_ref,
            parent_write_child_ref,
            ..
        } = &back.op
        {
            assert_eq!(parent_child_ref, &sample_parent_child_ref());
            assert_eq!(parent_write_child_ref, &sample_parent_write_child_ref());
            assert_ne!(
                parent_write_child_ref.child_id, parent_child_ref.ipns_name,
                "D-07: write-plane childId must never equal read-plane ipnsName"
            );
        } else {
            panic!("Expected MkdirPublish");
        }
    }

    /// WR-01: ordered_for_replay sorts each group by created_at_ms ascending.
    #[test]
    fn replay_order_sorts_by_created_at_within_group() {
        // Two UploadFile entries inserted newest-first; expect oldest-first after ordering.
        let mut entry_2000 = make_upload_entry("up-2000", "v");
        if let JournalOp::UploadFile {
            ref mut created_at_ms,
            ..
        } = entry_2000.op
        {
            *created_at_ms = 2000;
        }
        let mut entry_1000 = make_upload_entry("up-1000", "v");
        if let JournalOp::UploadFile {
            ref mut created_at_ms,
            ..
        } = entry_1000.op
        {
            *created_at_ms = 1000;
        }

        let mut mkdir_early = make_mkdir_entry("mk-100", "v");
        if let JournalOp::MkdirPublish {
            ref mut created_at_ms,
            ..
        } = mkdir_early.op
        {
            *created_at_ms = 100;
        }
        let mut mkdir_late = make_mkdir_entry("mk-50", "v");
        if let JournalOp::MkdirPublish {
            ref mut created_at_ms,
            ..
        } = mkdir_late.op
        {
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

    /// D-05 extended / NODE-06: the node-to-node keys the journal carries live ONLY inside
    /// the symmetric base64 seals (SealedChildRef.read_key_sealed / WriteChildRef
    /// .write_key_sealed) — a raw key marker must appear only as its base64 seal, never as
    /// plaintext, and no user-ECIES-under-user-key node-to-node key is re-introduced.
    #[test]
    fn journal_no_plaintext_node_to_node_key() {
        let raw_read_secret = b"raw_read_key_secret_bytes_12345678";
        let raw_write_secret = b"raw_write_key_secret_bytes_9876543";
        let read_sealed = b64(raw_read_secret); // symmetric AES-GCM seal (base64), not ECIES
        let write_sealed = b64(raw_write_secret);
        let mut entry = make_upload_entry("noplain2", "k51vault");
        if let JournalOp::UploadFile {
            parent_child_ref,
            parent_write_child_ref,
            ..
        } = &mut entry.op
        {
            parent_child_ref.read_key_sealed = read_sealed.clone();
            parent_write_child_ref.write_key_sealed = write_sealed.clone();
        }
        let json_str = String::from_utf8(serde_json::to_vec(&entry).unwrap()).unwrap();
        // The seals appear on the wire only in their base64 form.
        assert!(
            json_str.contains(&read_sealed) && json_str.contains(&write_sealed),
            "symmetric base64 seals must appear in JSON"
        );
        // The raw key bytes must never appear as plaintext.
        assert!(
            !json_str.contains("raw_read_key_secret_bytes"),
            "Journal must not contain a raw read key as plaintext"
        );
        assert!(
            !json_str.contains("raw_write_key_secret_bytes"),
            "Journal must not contain a raw write key as plaintext"
        );
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

    // ---- T-45-01: crash mid-write entry survives reload ----
    //
    // Characterization test: an entry written via `put` but never `remove`d (simulating
    // a process kill after the fsync) must survive a fresh `WriteQueue::new` + `load_all_for_vault`
    // on the same directory. Proves the fsync-before-ack crash-recovery guarantee.

    #[test]
    fn crash_mid_write_entry_survives_reload() {
        let (q, dir) = make_temp_queue();
        let entry = make_upload_entry("crash01", "k51vaultcrash");

        // Simulate successful fsync-commit (D-04) — entry is on disk.
        q.put(&entry).expect("put");

        // Drop the first queue WITHOUT calling remove() — simulates process kill.
        drop(q);

        // Construct a fresh WriteQueue on the same directory (next mount).
        let q2 = WriteQueue::new(dir.clone(), 3);
        let loaded = q2
            .load_all_for_vault("k51vaultcrash")
            .expect("load after crash");

        assert_eq!(loaded.len(), 1, "entry must survive across simulated crash");
        assert_eq!(loaded[0].id, "crash01");
        assert_eq!(
            loaded[0].status,
            JournalEntryStatus::Pending,
            "recovered entry must be Pending (not Failed)"
        );
    }

    // ---- T-45-02: partial journal write is skipped not panicked ----
    //
    // Characterization test: a truncated (half-written) journal file on disk must be
    // skipped with a warning and must NOT panic. `load_all_for_vault` must still return
    // the one well-formed entry. Pins V5 / T-43-03 skip-with-warn behavior so refactors
    // cannot regress it.

    #[test]
    fn partial_journal_write_is_skipped_not_panicked() {
        let (q, dir) = make_temp_queue();

        // Build the full JSON for an entry, then write only the first half — simulating
        // an OS crash in the middle of a write (before sync_all completed or on power loss).
        let full_entry = make_upload_entry("partial-victim", "k51vaultpartial");
        let full_json = serde_json::to_vec(&full_entry).expect("serialize for truncation test");
        let half_len = full_json.len() / 2;
        let truncated = &full_json[..half_len];

        // Write the truncated bytes directly using the same filename scheme as `put`:
        // `<journal_dir>/<id>.json` (see WriteQueue::put, line 157).
        let bad_path = dir.join("partial-victim.json");
        std::fs::write(&bad_path, truncated).expect("write truncated file");

        // Also put one well-formed entry so we can verify it is returned.
        q.put(&make_upload_entry("good01", "k51vaultpartial"))
            .expect("put good entry");

        // load_all_for_vault must skip the truncated file and return only the good entry.
        let loaded = q
            .load_all_for_vault("k51vaultpartial")
            .expect("load must not panic on partial file");

        assert_eq!(
            loaded.len(),
            1,
            "only the well-formed entry must be returned"
        );
        assert_eq!(loaded[0].id, "good01");
    }

    // ---- T-45-04: Option<String> sentinel — None round-trip and legacy "" compat ----

    /// T-45-04: an UploadFile entry with `file_meta_ipns_name: None` serializes to
    /// JSON and deserializes back as `None` (not `Some("")`).
    ///
    /// This is the GREEN-gate for the #18 refactor. Until the field type is changed
    /// to `Option<String>` with the serde compat shim, this test FAILS (compile error).
    #[test]
    fn upload_entry_none_ipns_round_trips() {
        let entry = JournalEntry {
            id: "t4504-none".to_string(),
            vault_root_ipns: "k51vault4504".to_string(),
            op: JournalOp::UploadFile {
                sidecar_path: std::path::PathBuf::from("/tmp/t4504-none.bin"),
                sidecar_sha256: hex::encode([0u8; 32]),
                legacy_ciphertext_b64: String::new(),
                child_published_node: sample_child_published_node_b64(),
                parent_child_ref: sample_parent_child_ref(),
                parent_write_child_ref: sample_parent_write_child_ref(),
                file_meta_ipns_name: None,
                parent_folder_ipns_name: "k51parent4504".to_string(),
                size: 0,
                created_at_ms: 1_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        };
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        if let JournalOp::UploadFile {
            file_meta_ipns_name,
            ..
        } = &back.op
        {
            assert_eq!(
                *file_meta_ipns_name, None,
                "None file_meta_ipns_name must round-trip as None"
            );
        } else {
            panic!("Expected UploadFile");
        }
    }

    /// T-45-04-compat (node/v3): the `file_meta_ipns_name` routing keeper retains its
    /// `deser_opt_string` compat shim — an entry authored with a legacy empty-string
    /// sentinel (but ALL node/v3 crypto fields present) still loads that ONE field as
    /// `None`, while a real name loads as `Some(name)`.
    ///
    /// This proves the reshape preserved the sidecar/routing keepers' existing compat
    /// (D-04's clean-flag-day ban applies only to the node/v3 crypto fields, which this
    /// JSON supplies in full). A fully legacy (pre-cutover) crypto-shaped entry is covered
    /// by the fail-closed stale-skip test instead.
    #[test]
    fn legacy_empty_string_ipns_loads_as_none() {
        // Author a node/v3-shaped entry that carries a legacy "" file_meta_ipns_name.
        let mut none_entry = make_upload_entry("t4504-compat-empty", "k51vault4504compat");
        if let JournalOp::UploadFile {
            file_meta_ipns_name,
            ..
        } = &mut none_entry.op
        {
            *file_meta_ipns_name = None;
        }
        // Serialize, then splice a literal empty-string sentinel back in to mimic what an
        // older build wrote for the absent field.
        let mut value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&none_entry).unwrap()).unwrap();
        value["op"]["UploadFile"]["file_meta_ipns_name"] = serde_json::Value::String(String::new());
        let entry: JournalEntry = serde_json::from_value(value).expect("empty-sentinel loads");
        if let JournalOp::UploadFile {
            file_meta_ipns_name,
            ..
        } = &entry.op
        {
            assert_eq!(
                *file_meta_ipns_name, None,
                "legacy empty-string must deserialize as None via compat shim"
            );
        } else {
            panic!("Expected UploadFile");
        }

        // A real name must load as Some(...).
        let real_entry = make_upload_entry("t4504-compat-real", "k51vault4504compat");
        let back: JournalEntry =
            serde_json::from_slice(&serde_json::to_vec(&real_entry).unwrap()).unwrap();
        if let JournalOp::UploadFile {
            file_meta_ipns_name,
            ..
        } = &back.op
        {
            assert_eq!(
                *file_meta_ipns_name,
                Some("k51filemetaipns".to_string()),
                "real name must deserialize as Some(name)"
            );
        } else {
            panic!("Expected UploadFile");
        }
    }

    // ---- T-45-03: retry exhaustion keeps failed entry on disk ----
    //
    // Characterization test: calling `record_failure` max_retries + 1 times on the same
    // entry must transition it to `JournalEntryStatus::Failed` and must NOT remove the
    // file (D-09 — parked entries are never silently dropped). `load_all_for_vault` after
    // exhaustion must still return exactly 1 entry.

    #[test]
    fn retry_exhaustion_keeps_failed_entry_on_disk() {
        // make_temp_queue builds a WriteQueue with max_retries = 3.
        let (q, _dir) = make_temp_queue();
        let entry = make_upload_entry("retry-exhaust", "k51vaultretry");
        q.put(&entry).expect("put initial entry");

        // Call record_failure 4 times (max_retries=3, so the 4th call crosses the threshold).
        // record_failure reloads from disk on each call; we must reload the current
        // on-disk entry before each call so `entry.retries` is accurate.
        let mut current = entry.clone();
        let mut last_status = JournalEntryStatus::Pending;
        for _ in 0..4 {
            last_status = q
                .record_failure(&current, "simulated error")
                .expect("record_failure must not error");
            // Reload from disk so the next call uses the updated retries counter.
            let on_disk = q.load_all_for_vault("k51vaultretry").expect("reload");
            current = on_disk
                .into_iter()
                .find(|e| e.id == "retry-exhaust")
                .expect("entry must still be on disk");
        }

        // After 4 failures (retries=0→1→2→3→Failed), the final status must be Failed.
        assert!(
            matches!(last_status, JournalEntryStatus::Failed { .. }),
            "status after exhaustion must be Failed, got {:?}",
            last_status
        );

        // The entry must remain on disk (D-09 — never silently dropped).
        let after = q
            .load_all_for_vault("k51vaultretry")
            .expect("load after exhaustion");
        assert_eq!(
            after.len(),
            1,
            "failed entry must remain on disk (not removed) after retry exhaustion"
        );
        assert!(
            matches!(after[0].status, JournalEntryStatus::Failed { .. }),
            "on-disk status must be Failed"
        );
    }

    // ---- Phase 52 Plan 02: sidecar journal shape (D-01) ----
    //
    // The former plaintext-filename / inline-ciphertext legacy-compat and filename-ECIES
    // round-trip tests were retired with the node/v3 reshape (Phase 69, P1a-3): the
    // encrypted-filename field is gone from the journal, and D-04's clean flag-day forbids
    // a dual-format deserializer for the reshaped crypto fields (a stale entry fails serde
    // and is skipped — see `stale_legacy_shaped_entry_fails_closed`). The sidecar-ciphertext
    // mechanism below is RETAINED unchanged.

    /// D-01: `put_with_sidecar` streams ciphertext to a 0600 `<id>.bin`, writes a
    /// ciphertext-free `.json`, and `remove` deletes both files idempotently.
    #[test]
    fn sidecar_ciphertext_not_in_json() {
        let (q, dir) = make_temp_queue();
        let id = "sidecar-test";
        let ciphertext = b"this-is-the-secret-ciphertext-blob";

        let mut entry = make_upload_entry(id, "k51vault");
        if let JournalOp::UploadFile {
            ref mut sidecar_path,
            ..
        } = entry.op
        {
            *sidecar_path = q.sidecar_path_for(id);
        }

        q.put_with_sidecar(&entry, ciphertext)
            .expect("put_with_sidecar");

        let bin_path = dir.join(format!("{}.bin", id));
        let json_path = dir.join(format!("{}.json", id));
        assert!(bin_path.exists(), "sidecar .bin must exist");
        assert!(json_path.exists(), ".json entry must exist");

        // Ciphertext round-trips from the sidecar.
        assert_eq!(std::fs::read(&bin_path).unwrap(), ciphertext);

        // The .json must NOT contain the ciphertext bytes.
        let json_bytes = std::fs::read(&json_path).unwrap();
        let needle = b"this-is-the-secret-ciphertext-blob";
        assert!(
            !json_bytes.windows(needle.len()).any(|w| w == needle),
            ".json must not contain the raw ciphertext"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&bin_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "sidecar must be 0600");
        }

        // remove deletes BOTH files, idempotently.
        q.remove(id).expect("remove");
        assert!(!bin_path.exists(), "remove must delete the .bin");
        assert!(!json_path.exists(), "remove must delete the .json");
        q.remove(id).expect("second remove is idempotent");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-01 Pitfall 2: a stale `.bin` from a prior aborted write is cleaned up before
    /// `put_with_sidecar` re-writes, so no orphaned ciphertext lingers.
    #[test]
    fn put_with_sidecar_cleans_stale_bin() {
        let (q, dir) = make_temp_queue();
        let id = "stale-bin-test";
        let bin_path = q.sidecar_path_for(id);

        // Pre-seed a stale sidecar with different content.
        std::fs::write(&bin_path, b"STALE-LEFTOVER-CIPHERTEXT").unwrap();

        let mut entry = make_upload_entry(id, "k51vault");
        if let JournalOp::UploadFile {
            ref mut sidecar_path,
            ..
        } = entry.op
        {
            *sidecar_path = bin_path.clone();
        }
        let fresh = b"fresh-ciphertext";
        q.put_with_sidecar(&entry, fresh).expect("put_with_sidecar");

        assert_eq!(
            std::fs::read(&bin_path).unwrap(),
            fresh,
            "stale sidecar must be overwritten with fresh ciphertext"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Task 1 & 2 (D-02): purge_vault + gc_failed_entries ----

    /// Build an UploadFile entry whose `sidecar_path` points at the queue's real `.bin`
    /// path, with caller-controlled status and `created_at_ms` (for GC age/size tests).
    fn make_sidecar_entry(
        q: &WriteQueue,
        id: &str,
        vault: &str,
        status: JournalEntryStatus,
        created_at_ms: u64,
    ) -> JournalEntry {
        let mut entry = make_upload_entry(id, vault);
        if let JournalOp::UploadFile {
            sidecar_path,
            created_at_ms: cam,
            ..
        } = &mut entry.op
        {
            *sidecar_path = q.sidecar_path_for(id);
            *cam = created_at_ms;
        }
        entry.status = status;
        entry
    }

    /// D-02: `purge_vault` removes every `.json`+`.bin` for the target vault only.
    #[test]
    fn purge_vault_removes_all() {
        let (q, dir) = make_temp_queue();

        let a1 = make_sidecar_entry(
            &q,
            "purge-a1",
            "vault-A",
            JournalEntryStatus::Pending,
            1_000,
        );
        let a2 = make_sidecar_entry(
            &q,
            "purge-a2",
            "vault-A",
            JournalEntryStatus::Pending,
            2_000,
        );
        let b1 = make_sidecar_entry(
            &q,
            "purge-b1",
            "vault-B",
            JournalEntryStatus::Pending,
            3_000,
        );
        q.put_with_sidecar(&a1, b"a1-cipher").expect("put a1");
        q.put_with_sidecar(&a2, b"a2-cipher").expect("put a2");
        q.put_with_sidecar(&b1, b"b1-cipher").expect("put b1");

        let removed = q.purge_vault("vault-A").expect("purge vault A");
        assert_eq!(removed, 2, "two vault-A entries removed");

        for id in ["purge-a1", "purge-a2"] {
            assert!(
                !dir.join(format!("{}.json", id)).exists(),
                "{}.json gone",
                id
            );
            assert!(!dir.join(format!("{}.bin", id)).exists(), "{}.bin gone", id);
        }
        assert!(dir.join("purge-b1.json").exists(), "vault-B .json survives");
        assert!(dir.join("purge-b1.bin").exists(), "vault-B .bin survives");

        // Purging a vault with no entries is a no-op returning 0.
        let none = q.purge_vault("vault-EMPTY").expect("purge empty vault");
        assert_eq!(none, 0, "empty vault purge returns 0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-02: `gc_failed_entries` ages out old Failed entries, leaving recent Failed and
    /// non-Failed entries untouched.
    #[test]
    fn gc_purges_old_failed() {
        let (q, dir) = make_temp_queue();
        let now = now_ms();
        let day_ms = 86_400_000u64;
        let failed = JournalEntryStatus::Failed {
            last_error: "x".to_string(),
        };

        // Old Failed (40 days old), recent Failed (1 day old), and a Pending (old but not Failed).
        let old = make_sidecar_entry(&q, "gc-old", "v", failed.clone(), now - 40 * day_ms);
        let recent = make_sidecar_entry(&q, "gc-recent", "v", failed.clone(), now - day_ms);
        let pending = make_sidecar_entry(
            &q,
            "gc-pending",
            "v",
            JournalEntryStatus::Pending,
            now - 40 * day_ms,
        );
        q.put_with_sidecar(&old, b"old-cipher").expect("put old");
        q.put_with_sidecar(&recent, b"recent-cipher")
            .expect("put recent");
        q.put_with_sidecar(&pending, b"pending-cipher")
            .expect("put pending");

        let removed = q
            .gc_failed_entries(JOURNAL_GC_MAX_AGE_DAYS, u64::MAX)
            .expect("gc");
        assert_eq!(removed, 1, "only the old Failed entry is removed");

        assert!(!dir.join("gc-old.json").exists(), "old Failed .json gone");
        assert!(!dir.join("gc-old.bin").exists(), "old Failed .bin gone");
        assert!(
            dir.join("gc-recent.json").exists(),
            "recent Failed survives"
        );
        assert!(dir.join("gc-pending.json").exists(), "Pending never GC'd");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-02: `gc_failed_entries` trims oldest-first to the size budget (counting `.bin`),
    /// and removes `.bin` orphans with no matching `.json`.
    #[test]
    fn gc_purges_to_size_budget() {
        let (q, dir) = make_temp_queue();
        let now = now_ms();
        let failed = JournalEntryStatus::Failed {
            last_error: "x".to_string(),
        };

        // Three recent Failed entries, each with a ~1 KiB sidecar. Measure one entry's actual
        // on-disk size (.json + .bin) and set the budget to hold exactly one, so the two oldest
        // must be trimmed regardless of the exact JSON length.
        let blob = vec![0u8; 1024];
        let e1 = make_sidecar_entry(&q, "sz-1", "v", failed.clone(), now - 3_000);
        let e2 = make_sidecar_entry(&q, "sz-2", "v", failed.clone(), now - 2_000);
        let e3 = make_sidecar_entry(&q, "sz-3", "v", failed.clone(), now - 1_000);
        q.put_with_sidecar(&e1, &blob).expect("put e1");
        q.put_with_sidecar(&e2, &blob).expect("put e2");
        q.put_with_sidecar(&e3, &blob).expect("put e3");

        // Orphan sidecar with no matching .json.
        let orphan = q.sidecar_path_for("sz-orphan");
        std::fs::write(&orphan, b"orphaned-ciphertext").expect("write orphan");

        // Budget = 1.5x a single entry: holds exactly one (the newest); two oldest trimmed.
        let one_entry_size = q.entry_on_disk_size("sz-3");
        let budget = one_entry_size + one_entry_size / 2;
        let removed = q.gc_failed_entries(36_500, budget).expect("gc");

        // 2 oldest entries + 1 orphan removed = 3.
        assert_eq!(removed, 3, "two oldest entries + orphan removed");
        assert!(!dir.join("sz-1.json").exists(), "oldest sz-1 trimmed");
        assert!(!dir.join("sz-2.json").exists(), "sz-2 trimmed");
        assert!(dir.join("sz-3.json").exists(), "newest sz-3 survives");
        assert!(!orphan.exists(), "orphan .bin removed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// T-52-16 / T-52-15: a `.bin` whose sibling `.json` exists but is torn/truncated
    /// (a crash mid-JSON-write after the `.bin` fsync) is never replayable, so GC pass 3
    /// must treat it as orphaned and reap the live `.bin` instead of keeping it forever.
    #[test]
    fn gc_reaps_bin_with_malformed_json() {
        let (q, dir) = make_temp_queue();
        let now = now_ms();
        let failed = JournalEntryStatus::Failed {
            last_error: "x".to_string(),
        };

        // A well-formed Failed entry whose .bin must be PRESERVED (its .json parses).
        let live = make_sidecar_entry(&q, "gc-live", "v", failed, now - 1_000);
        q.put_with_sidecar(&live, b"live-cipher").expect("put live");

        // A live, durable .bin whose sibling .json exists but is corrupt (unparseable).
        let bad_bin = q.sidecar_path_for("gc-torn");
        std::fs::write(&bad_bin, b"durable-ciphertext").expect("write torn .bin");
        std::fs::write(dir.join("gc-torn.json"), b"{ this is not valid json")
            .expect("write torn .json");

        let removed = q
            .gc_failed_entries(JOURNAL_GC_MAX_AGE_DAYS, u64::MAX)
            .expect("gc");

        assert_eq!(
            removed, 1,
            "only the orphaned (malformed-json) sidecar is reaped"
        );
        assert!(
            !bad_bin.exists(),
            "sidecar with unparseable .json must be reaped"
        );
        assert!(
            dir.join("gc-torn.json").exists(),
            "the malformed .json itself is left in place"
        );
        assert!(
            dir.join("gc-live.json").exists(),
            "well-formed entry survives"
        );
        assert!(
            dir.join("gc-live.bin").exists(),
            "well-formed entry's sidecar is preserved"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (matches `load_all_for_vault_skips_the_floor_sidecar_without_a_malformed_warning`):
    /// `gc_failed_entries` scans every `*.json` in the journal dir too, so it must ALSO skip the
    /// floor sidecar rather than logging a spurious "malformed entry" warning for it -- and must
    /// never remove it (it owns no `.bin`, so pass 3's orphan check is unaffected either way).
    #[test]
    fn gc_failed_entries_skips_the_floor_sidecar_without_a_malformed_warning() {
        let (q, dir) = make_temp_queue();
        let now = now_ms();
        let failed = JournalEntryStatus::Failed {
            last_error: "x".to_string(),
        };
        let live = make_sidecar_entry(&q, "gc-floor-live", "v", failed, now - 1_000);
        q.put_with_sidecar(&live, b"live-cipher").expect("put live");

        let floor_sidecar = dir.join("rotation-high-water.json");
        std::fs::write(&floor_sidecar, br#"{"node-1":{"generation":3,"seq":9}}"#)
            .expect("write floor sidecar");

        let mut removed = 0;
        let messages = capture_log_messages(|| {
            removed = q
                .gc_failed_entries(JOURNAL_GC_MAX_AGE_DAYS, u64::MAX)
                .expect("gc");
        });

        assert_eq!(removed, 0, "nothing eligible for GC yet");
        assert!(
            floor_sidecar.exists(),
            "floor sidecar must never be touched by GC"
        );
        assert!(dir.join("gc-floor-live.json").exists());
        assert!(dir.join("gc-floor-live.bin").exists());
        assert!(
            !messages.iter().any(|m| m.contains("malformed entry")),
            "floor sidecar must not trigger a malformed-entry warning during GC: {messages:?}"
        );

        // Harness sanity check: a GENUINELY malformed file still warns during
        // GC's scan, proving the absence above is a real skip, not a harness
        // gap.
        std::fs::write(dir.join("truly-bad.json"), b"not valid json {{{{").expect("write bad json");
        let messages = capture_log_messages(|| {
            let _ = q
                .gc_failed_entries(JOURNAL_GC_MAX_AGE_DAYS, u64::MAX)
                .expect("gc again");
        });
        assert!(
            messages.iter().any(|m| m.contains("malformed entry")),
            "a genuinely malformed entry must still warn during GC: {messages:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D-01 data-loss guard: a pre-Phase-52 legacy UploadFile entry (empty `sidecar_path`,
    /// ciphertext only in the in-memory `legacy_ciphertext_b64` field) must have its inline
    /// bytes migrated to a durable `.bin` sidecar by `record_failure` BEFORE any re-persist,
    /// so the next mount replays via the sidecar branch instead of parking a missing payload.
    #[test]
    fn record_failure_migrates_legacy_inline_to_sidecar() {
        use base64::Engine;
        let (q, dir) = make_temp_queue();

        // Build a legacy entry: empty sidecar_path, ciphertext only inline (base64).
        let ciphertext = b"legacy-inline-ciphertext-bytes".to_vec();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        let mut entry = make_upload_entry("legacy-mig", "v");
        if let JournalOp::UploadFile {
            sidecar_path,
            sidecar_sha256,
            legacy_ciphertext_b64,
            ..
        } = &mut entry.op
        {
            *sidecar_path = std::path::PathBuf::new(); // legacy: no sidecar
            sidecar_sha256.clear();
            *legacy_ciphertext_b64 = b64;
        }
        // Persist the JSON (skip_serializing drops legacy_ciphertext_b64 on disk, exactly
        // as a real pre-52 entry behaves once reloaded).
        q.put(&entry).expect("put legacy entry");
        assert!(
            !dir.join("legacy-mig.bin").exists(),
            "no sidecar before migration"
        );

        // A transient replay failure: record_failure must migrate the inline bytes first.
        let status = q
            .record_failure(&entry, "transient upload error")
            .expect("record_failure");
        assert!(
            matches!(status, JournalEntryStatus::Pending),
            "below max → Pending retry"
        );

        // The canonical sidecar now exists with the exact ciphertext, and the reloaded
        // entry carries the derived path + hash (so the next mount uses the sidecar branch).
        let bin_path = q.sidecar_path_for("legacy-mig");
        assert!(
            bin_path.exists(),
            "inline ciphertext must be migrated to the .bin sidecar"
        );
        assert_eq!(
            std::fs::read(&bin_path).unwrap(),
            ciphertext,
            "sidecar bytes must round-trip"
        );

        let reloaded = q.load_all_for_vault("v").expect("reload");
        let mig = reloaded
            .iter()
            .find(|e| e.id == "legacy-mig")
            .expect("entry present");
        assert_eq!(mig.retries, 1, "retry counter advanced");
        if let JournalOp::UploadFile {
            sidecar_path,
            sidecar_sha256,
            ..
        } = &mig.op
        {
            assert_eq!(
                sidecar_path, &bin_path,
                "persisted sidecar_path is the canonical path"
            );
            let expected = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(&ciphertext);
                hex::encode(h.finalize())
            };
            assert_eq!(
                sidecar_sha256, &expected,
                "persisted sha256 matches the ciphertext"
            );
        } else {
            panic!("expected UploadFile op");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
