//! Desktop [`StagingStore`]: the v1 write journal generalized to every op.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cipherbox_engine::seams::{OpId, SeamResult, StagingStore};

use crate::fs_util::{
    atomic_write, ensure_dir, from_hex, list_file_names, read_file_opt, remove_file_durable,
    seam_err, to_hex,
};

/// Suffix for op-record files (`ops/<id>.op`). The "json record" of the v1
/// journal, generalized: it holds the engine's opaque encoded intent op
/// verbatim — the store never parses it.
const OP_SUFFIX: &str = ".op";
/// Suffix for staged-ciphertext sidecar files (`staged/<hexkey>.bin`).
const SIDECAR_SUFFIX: &str = ".bin";
/// Filename of the durable monotonic op-id counter.
const COUNTER_FILE: &str = "next_op_id";

/// Durable op queue plus staged upload bytes, backed by the fsync-barriered
/// write journal (blueprint/engine.md "StagingStore"; blueprint/desktop.md
/// "the v1 write journal generalized").
///
/// Layout under the store root:
///
/// - `ops/<20-digit-id>.op` — one durable record per queued op, id in the
///   filename; enqueue order is id order (FIFO). Each op is opaque engine
///   bytes stored verbatim.
/// - `staged/<hexkey>.bin` — one sidecar per staged-ciphertext key.
/// - `next_op_id` — the monotonic id counter, so ids are strictly
///   increasing and never reused, even after every op drains and the store
///   reopens.
///
/// **Removal ordering is a correctness property** (hard constraint 5): every
/// mutating method barriers its directory entry before returning (see
/// `fs_util::fsync_dir`), so when a caller completes an op by removing the
/// op record *before* its sidecar, that
/// ordering actually reaches the platter in order. A crash can then only ever
/// leave an orphan sidecar (harmless, reclaimed by orphan-sidecar GC via
/// [`staged_keys`] + [`remove_staged_bytes`]) — never an op record pointing
/// at a sidecar that is already gone.
///
/// Clones share one id counter: two handles each holding their own would hand
/// the same op id to two ops.
#[derive(Debug, Clone)]
pub struct FileStagingStore {
    ops_dir: PathBuf,
    staged_dir: PathBuf,
    counter_path: PathBuf,
    /// Next op id to hand out; persisted to `next_op_id` on each allocation.
    next_op_id: Arc<Mutex<u64>>,
}

impl FileStagingStore {
    /// Opens (creating if absent) a staging store rooted at `dir`. Reopening
    /// the same `dir` recovers the queue, staged bytes, and id progression.
    pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
        let dir = dir.as_ref();
        let ops_dir = dir.join("ops");
        let staged_dir = dir.join("staged");
        // Sweep the root too: the `next_op_id` counter is atomic-written
        // directly under `dir`, so a crash mid-counter-write can strand a
        // temp file here — reclaim it on reopen like the ops/staged debris.
        ensure_dir(dir).map_err(|err| seam_err("staging_store open root", &err))?;
        ensure_dir(&ops_dir).map_err(|err| seam_err("staging_store open ops", &err))?;
        ensure_dir(&staged_dir).map_err(|err| seam_err("staging_store open staged", &err))?;
        let counter_path = dir.join(COUNTER_FILE);

        // Recover the id watermark from both the persisted counter and the
        // highest surviving op file, then take the larger — so a crash
        // between bumping the counter and writing the op file (or vice
        // versa) still never reuses an id.
        let persisted = read_file_opt(&counter_path)
            .map_err(|err| seam_err("staging_store open counter", &err))?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);
        let highest_op = highest_op_id(&ops_dir)
            .map_err(|err| seam_err("staging_store open scan", &err))?
            .map_or(0, |id| id.saturating_add(1));
        let next = persisted.max(highest_op).max(1);

        Ok(Self {
            ops_dir,
            staged_dir,
            counter_path,
            next_op_id: Arc::new(Mutex::new(next)),
        })
    }

    fn op_path(&self, id: u64) -> PathBuf {
        self.ops_dir.join(format!("{id:020}{OP_SUFFIX}"))
    }

    fn sidecar_path(&self, key: &[u8]) -> PathBuf {
        self.staged_dir
            .join(format!("{}{SIDECAR_SUFFIX}", to_hex(key)))
    }
}

impl StagingStore for FileStagingStore {
    async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
        // Reserve an id and durably advance the counter *before* writing the
        // op file: a crash after the counter bump merely burns an id (ids
        // need only be strictly increasing, not contiguous), never reuses
        // one.
        let id = {
            let mut next = self.next_op_id.lock().expect("lock");
            let id = *next;
            let advanced = id + 1;
            atomic_write(&self.counter_path, &advanced.to_le_bytes())
                .map_err(|err| seam_err("staging_store enqueue_op counter", &err))?;
            *next = advanced;
            id
        };
        atomic_write(&self.op_path(id), op)
            .map_err(|err| seam_err("staging_store enqueue_op", &err))?;
        Ok(OpId(id))
    }

    async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
        let names = list_file_names(&self.ops_dir)
            .map_err(|err| seam_err("staging_store queued_ops", &err))?;
        // Keyed by parsed id, not by listed name: `op_path` zero-pads and
        // `parse_op_id` does not, so `ops/1.op` and `ops/00…01.op` both name op 1.
        // Reading the re-derived canonical path keeps every returned entry one
        // `remove_op` can delete, and one entry per id keeps a single durable op
        // from draining as two. Ascending id order is FIFO order.
        let mut ops = BTreeMap::new();
        for name in names {
            let Some(id) = parse_op_id(&name) else {
                continue;
            };
            if ops.contains_key(&id) {
                continue;
            }
            if let Some(bytes) = read_file_opt(&self.op_path(id))
                .map_err(|err| seam_err("staging_store queued_ops read", &err))?
            {
                ops.insert(id, bytes);
            }
        }
        Ok(ops
            .into_iter()
            .map(|(id, bytes)| (OpId(id), bytes))
            .collect())
    }

    async fn remove_op(&self, op_id: OpId) -> SeamResult<()> {
        remove_file_durable(&self.op_path(op_id.0))
            .map_err(|err| seam_err("staging_store remove_op", &err))
    }

    async fn put_staged_bytes(&self, staging_key: &[u8], bytes: &[u8]) -> SeamResult<()> {
        atomic_write(&self.sidecar_path(staging_key), bytes)
            .map_err(|err| seam_err("staging_store put_staged_bytes", &err))
    }

    async fn staged_bytes(&self, staging_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        read_file_opt(&self.sidecar_path(staging_key))
            .map_err(|err| seam_err("staging_store staged_bytes", &err))
    }

    async fn remove_staged_bytes(&self, staging_key: &[u8]) -> SeamResult<()> {
        remove_file_durable(&self.sidecar_path(staging_key))
            .map_err(|err| seam_err("staging_store remove_staged_bytes", &err))
    }

    async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
        let names = list_file_names(&self.staged_dir)
            .map_err(|err| seam_err("staging_store staged_keys", &err))?;
        Ok(names.iter().filter_map(|name| sidecar_key(name)).collect())
    }

    async fn staged_bytes_total(&self) -> SeamResult<u64> {
        let names = list_file_names(&self.staged_dir)
            .map_err(|err| seam_err("staging_store staged_bytes_total", &err))?;
        let mut total = 0u64;
        for name in names {
            if sidecar_key(&name).is_none() {
                continue;
            }
            match std::fs::metadata(self.staged_dir.join(&name)) {
                Ok(meta) => total = total.saturating_add(meta.len()),
                // A sidecar removed between listing and stat contributes zero,
                // mirroring read_file_opt's NotFound handling.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(seam_err("staging_store staged_bytes_total meta", &err));
                }
            }
        }
        Ok(total)
    }
}

/// The staging key a `staged/` filename holds, or `None` for anything that is
/// not one of this store's sidecars (temp debris, foreign files).
///
/// The one predicate behind both `staged_keys` and `staged_bytes_total`, so the
/// budget total and the GC-reclaimable set can never disagree on the file set: a
/// foreign `.bin` counted in the budget but invisible to `staged_keys` could
/// never be reclaimed and would inflate the budget permanently.
fn sidecar_key(name: &str) -> Option<Vec<u8>> {
    from_hex(name.strip_suffix(SIDECAR_SUFFIX)?)
}

/// Parses the op id out of an `ops/` filename, or `None` for anything that
/// is not an op record (temp debris, foreign files).
fn parse_op_id(name: &str) -> Option<u64> {
    name.strip_suffix(OP_SUFFIX)?.parse::<u64>().ok()
}

/// The largest op id currently on disk in `ops_dir`, if any.
fn highest_op_id(ops_dir: &Path) -> std::io::Result<Option<u64>> {
    Ok(list_file_names(ops_dir)?
        .iter()
        .filter_map(|name| parse_op_id(name))
        .max())
}
