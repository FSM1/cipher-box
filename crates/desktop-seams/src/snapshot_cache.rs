//! Desktop [`SnapshotCache`]: sealed record/metadata cache files.

use std::path::{Path, PathBuf};

use cipherbox_engine::seams::{SeamResult, SnapshotCache};

use crate::fs_util::{
    atomic_write, ensure_dir, list_file_names, read_file_opt, remove_file_durable, seam_err, to_hex,
};

/// Durable last-known-good cache backed by one sealed file per key
/// (blueprint/engine.md "SnapshotCache"; blueprint/desktop.md "Sealed
/// record/metadata cache files").
///
/// **Ciphertext-only at rest**: the engine hands this store already-sealed
/// bytes and unseals them on read, so a file is opaque by construction — it
/// round-trips arbitrary bytes verbatim, requiring no parseable structure.
/// Keys are opaque engine bytes hex-encoded into filenames. Entries survive
/// reopen (cache-first rendering after restart); [`clear`](Self::clear)
/// ("forget this device") empties the backing durably.
pub struct FileSnapshotCache {
    dir: PathBuf,
}

impl FileSnapshotCache {
    /// Opens (creating if absent) a snapshot cache rooted at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        ensure_dir(&dir).map_err(|err| seam_err("snapshot_cache open", &err))?;
        Ok(Self { dir })
    }

    fn entry_path(&self, key: &[u8]) -> PathBuf {
        self.dir.join(to_hex(key))
    }
}

impl SnapshotCache for FileSnapshotCache {
    async fn put(&self, cache_key: &[u8], ciphertext: &[u8]) -> SeamResult<()> {
        atomic_write(&self.entry_path(cache_key), ciphertext)
            .map_err(|err| seam_err("snapshot_cache put", &err))
    }

    async fn get(&self, cache_key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
        read_file_opt(&self.entry_path(cache_key))
            .map_err(|err| seam_err("snapshot_cache get", &err))
    }

    async fn remove(&self, cache_key: &[u8]) -> SeamResult<()> {
        remove_file_durable(&self.entry_path(cache_key))
            .map_err(|err| seam_err("snapshot_cache remove", &err))
    }

    async fn clear(&self) -> SeamResult<()> {
        let names = list_file_names(&self.dir)
            .map_err(|err| seam_err("snapshot_cache clear list", &err))?;
        for name in names {
            remove_file_durable(&self.dir.join(name))
                .map_err(|err| seam_err("snapshot_cache clear", &err))?;
        }
        Ok(())
    }
}
