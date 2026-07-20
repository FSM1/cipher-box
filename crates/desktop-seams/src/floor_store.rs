//! Desktop [`FloorStore`]: fsync-barriered per-key floor files.

use std::path::{Path, PathBuf};

use cipherbox_engine::seams::{FloorStore, SeamError, SeamResult};

use crate::fs_util::{atomic_write, ensure_dir, read_file_opt, seam_err, to_hex};

/// Durable monotonic-max floor store backed by one small file per key
/// (blueprint/engine.md "FloorStore"; blueprint/desktop.md "Local journal").
///
/// Epoch floors live under `epoch/`, sequence floors under `seq/`, so the
/// two namespaces cannot collide even on identical key bytes. Each floor is
/// a single `u64` (8 bytes, little-endian) written through the
/// [`atomic_write`] fsync barrier, so a floor is structurally incapable of
/// regression or a torn value, and survives reopen. Keys are opaque engine
/// bytes, hex-encoded into filenames; the store never interprets them.
pub struct FileFloorStore {
    epoch_dir: PathBuf,
    seq_dir: PathBuf,
}

impl FileFloorStore {
    /// Opens (creating if absent) a floor store rooted at `dir`. Reopening
    /// the same `dir` yields the same durable floors.
    pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
        let dir = dir.as_ref();
        let epoch_dir = dir.join("epoch");
        let seq_dir = dir.join("seq");
        ensure_dir(&epoch_dir).map_err(|err| seam_err("floor_store open epoch", &err))?;
        ensure_dir(&seq_dir).map_err(|err| seam_err("floor_store open seq", &err))?;
        Ok(Self { epoch_dir, seq_dir })
    }

    fn read_floor(&self, dir: &Path, key: &[u8], op: &str) -> SeamResult<Option<u64>> {
        let path = dir.join(to_hex(key));
        let bytes = read_file_opt(&path).map_err(|err| seam_err(op, &err))?;
        match bytes {
            None => Ok(None),
            Some(bytes) => {
                let array: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| SeamError::new(format!("{op}: corrupt floor value on disk")))?;
                Ok(Some(u64::from_le_bytes(array)))
            }
        }
    }

    fn raise_floor(&self, dir: &Path, key: &[u8], value: u64, op: &str) -> SeamResult<u64> {
        let current = self.read_floor(dir, key, op)?;
        let raised = current.map_or(value, |stored| stored.max(value));
        // Monotonic-max: only touch the platter when the floor actually
        // advances, so a no-op raise is genuinely free.
        if current != Some(raised) {
            let path = dir.join(to_hex(key));
            atomic_write(&path, &raised.to_le_bytes()).map_err(|err| seam_err(op, &err))?;
        }
        Ok(raised)
    }
}

impl FloorStore for FileFloorStore {
    async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
        self.read_floor(&self.epoch_dir, scope_id, "floor_store epoch_floor")
    }

    async fn raise_epoch_floor(&self, scope_id: &[u8], epoch: u64) -> SeamResult<u64> {
        self.raise_floor(
            &self.epoch_dir,
            scope_id,
            epoch,
            "floor_store raise_epoch_floor",
        )
    }

    async fn sequence_floor(&self, ipns_name: &[u8]) -> SeamResult<Option<u64>> {
        self.read_floor(&self.seq_dir, ipns_name, "floor_store sequence_floor")
    }

    async fn raise_sequence_floor(&self, ipns_name: &[u8], sequence: u64) -> SeamResult<u64> {
        self.raise_floor(
            &self.seq_dir,
            ipns_name,
            sequence,
            "floor_store raise_sequence_floor",
        )
    }
}
