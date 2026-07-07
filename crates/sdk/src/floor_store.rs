//! Durable JSON-sidecar `HighWaterStore` implementation (D-03).
//!
//! Persists the `{ nodeId: value }` floor map as a single JSON sidecar file
//! adjacent to the FUSE journal dir, written atomically (temp file + rename,
//! 0600 perms) mirroring the [`crate::queue::WriteQueue`] sidecar
//! convention. No new storage dependency (sled/redb/rusqlite rejected per
//! D-03) — the FUSE single-daemon model means this file is small
//! (one `u64` per node) and read-modify-write on every access is cheap
//! relative to an IPNS resolve.

use crate::rotation::HighWaterStore;
use std::collections::HashMap;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// A durable `HighWaterStore` backed by a single JSON sidecar file.
///
/// Two independent floors (generation, seq) require two independent
/// instances of this store, each pointed at a different sidecar file — see
/// [`JsonSidecarFloorStore::for_generation`] / [`JsonSidecarFloorStore::for_seq`].
#[derive(Debug, Clone)]
pub struct JsonSidecarFloorStore {
    path: PathBuf,
}

impl JsonSidecarFloorStore {
    /// Construct a floor store backed by `<journal_dir>/<file_name>`.
    ///
    /// The journal dir must already exist; this constructor does not create
    /// it (matches `WriteQueue::new`'s contract).
    pub fn new(journal_dir: impl AsRef<Path>, file_name: &str) -> Self {
        Self {
            path: journal_dir.as_ref().join(file_name),
        }
    }

    /// Convenience constructor for the generation-floor sidecar
    /// (`<journal_dir>/rotation-high-water-generation.json`).
    pub fn for_generation(journal_dir: impl AsRef<Path>) -> Self {
        Self::new(journal_dir, "rotation-high-water-generation.json")
    }

    /// Convenience constructor for the seq-floor sidecar
    /// (`<journal_dir>/rotation-high-water-seq.json`).
    pub fn for_seq(journal_dir: impl AsRef<Path>) -> Self {
        Self::new(journal_dir, "rotation-high-water-seq.json")
    }

    /// Load the whole `{ nodeId: value }` map from disk. Returns an empty
    /// map if the sidecar does not exist yet or fails to parse (fail-closed:
    /// a corrupt sidecar is treated as "no floor known" rather than
    /// crashing the daemon — `enforce_resolved`'s cold-device versionFloor
    /// gate then re-applies as if this were first contact).
    fn load_map(&self) -> HashMap<String, u64> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    /// Write the whole map atomically: serialize to a sibling `.tmp` file
    /// (0600 perms, fsync'd), then `rename()` over the real path. A crash
    /// mid-write leaves the `.tmp` file orphaned but the real sidecar
    /// untouched — never a partially-written/torn JSON file (mirrors
    /// `WriteQueue::put`'s fsync-then-durable-rename discipline, with the
    /// rename step added for true all-or-nothing atomicity across the
    /// existing-file-being-overwritten case).
    fn write_map_atomic(&self, map: &HashMap<String, u64>) -> std::io::Result<()> {
        let json = serde_json::to_vec(map)?;

        let tmp_path = self.path.with_extension("tmp");

        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        open_opts.mode(0o600);

        let mut file = open_opts.open(&tmp_path)?;
        file.write_all(&json)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&tmp_path, &self.path)?;

        // Best-effort: fsync the parent dir so the rename's directory entry
        // is durable on crash (matches WriteQueue::put's WR-03b discipline).
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());
        }

        Ok(())
    }
}

impl HighWaterStore for JsonSidecarFloorStore {
    async fn get(&self, node_id: &str) -> Option<u64> {
        self.load_map().get(node_id).copied()
    }

    async fn put(&self, node_id: &str, value: u64) {
        let mut map = self.load_map();
        map.insert(node_id.to_string(), value);
        // A write failure here is a durability defect, not a correctness
        // one: enforce_resolved has already decided the resolve is valid
        // (fail-open on the in-memory decision) but the floor bump did not
        // persist. This mirrors the `Promise<void>`-shaped TS contract:
        // errors are exceptional and logged, not silently threaded through
        // every call site's Result.
        if let Err(e) = self.write_map_atomic(&map) {
            log::error!(
                "JsonSidecarFloorStore: failed to persist floor for node {}: {}",
                node_id,
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::{EnforceResolvedParams, RotationHighWater};

    /// Create a unique temporary directory for test isolation (pid + atomic
    /// counter, matching `crate::queue::tests::make_temp_queue`'s
    /// convention — avoids collisions across concurrent test binaries).
    fn make_temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("cipherbox-floorstore-test-{}-{}", pid, seq));
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[tokio::test]
    async fn get_on_missing_sidecar_returns_none() {
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_generation(&dir);
        assert_eq!(store.get("node-1").await, None);
    }

    #[tokio::test]
    async fn put_then_get_round_trips_in_the_same_instance() {
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_seq(&dir);
        store.put("node-1", 42).await;
        assert_eq!(store.get("node-1").await, Some(42));
    }

    #[tokio::test]
    async fn floor_store_restart() {
        // Simulates a daemon restart: put a floor, drop the store struct,
        // recreate a fresh store over the same journal-dir path, and
        // confirm the floor survives.
        let dir = make_temp_dir();
        {
            let store = JsonSidecarFloorStore::for_generation(&dir);
            store.put("node-restart", 7).await;
        } // store dropped here

        let reloaded = JsonSidecarFloorStore::for_generation(&dir);
        assert_eq!(reloaded.get("node-restart").await, Some(7));
    }

    #[tokio::test]
    async fn generation_and_seq_sidecars_are_independent_files() {
        let dir = make_temp_dir();
        let gen_store = JsonSidecarFloorStore::for_generation(&dir);
        let seq_store = JsonSidecarFloorStore::for_seq(&dir);

        gen_store.put("node-1", 3).await;
        seq_store.put("node-1", 99).await;

        // Each floor is independently addressable -- writing one must not
        // clobber or leak into the other's sidecar file.
        assert_eq!(gen_store.get("node-1").await, Some(3));
        assert_eq!(seq_store.get("node-1").await, Some(99));
    }

    #[tokio::test]
    async fn no_partial_json_survives_a_write() {
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_generation(&dir);
        store.put("node-1", 1).await;
        store.put("node-2", 2).await;

        // The on-disk file must always parse as valid, complete JSON --
        // never a torn/partial write (the atomic rename guarantees this).
        let bytes = std::fs::read(&store.path).expect("sidecar exists");
        let map: HashMap<String, u64> = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(map.get("node-1"), Some(&1));
        assert_eq!(map.get("node-2"), Some(&2));

        // The temp file must not be left behind after a successful write.
        let tmp_path = store.path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    #[tokio::test]
    async fn survives_restart_end_to_end_through_rotation_high_water() {
        // End-to-end: enforce_resolved over the real durable store, dropped
        // and reconstructed, still enforces the persisted floor.
        let dir = make_temp_dir();
        {
            let rhw = RotationHighWater::new(
                JsonSidecarFloorStore::for_generation(&dir),
                JsonSidecarFloorStore::for_seq(&dir),
            );
            rhw.enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 5,
                generation: 2,
                version_floor: 0,
            })
            .await
            .expect("forward resolve accepted");
        } // rhw (and its stores) dropped here -- simulates daemon restart

        let rhw = RotationHighWater::new(
            JsonSidecarFloorStore::for_generation(&dir),
            JsonSidecarFloorStore::for_seq(&dir),
        );
        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 3, // regresses below the persisted floor of 5
                generation: 2,
                version_floor: 0,
            })
            .await
            .expect_err("stale seq must be rejected after restart");
        assert!(matches!(
            err,
            crate::rotation::RotationError::SequenceRegression { .. }
        ));
    }
}
