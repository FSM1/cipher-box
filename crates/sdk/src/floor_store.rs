//! Durable JSON-sidecar `HighWaterStore` implementation (D-03).
//!
//! Persists the `{ nodeId: value }` floor map as a single JSON sidecar file
//! adjacent to the FUSE journal dir, written atomically (temp file + rename,
//! 0600 perms) mirroring the [`crate::queue::WriteQueue`] sidecar
//! convention. No new storage dependency (sled/redb/rusqlite rejected per
//! D-03) — the FUSE single-daemon model means this file is small
//! (one `u64` per node) and read-modify-write on every access is cheap
//! relative to an IPNS resolve.
//!
//! `get`/`put` (T-70-03/T-70-04) hold a `tokio::sync::Mutex` for the whole
//! load-modify-write critical section — mirroring the TS `idbPut` reference
//! (`apps/web/src/services/rotation-state.service.ts`, SC#5) — with all
//! blocking filesystem work run inside `tokio::task::spawn_blocking` so the
//! executor is never blocked while the lock is held. `put` computes
//! `max(existing, candidate)` INSIDE that locked section (not relying on a
//! caller's outer, non-atomic read), so concurrent `put`s on the same OR
//! different `node_id`s can never lost-update each other or the map. A
//! PRESENT-but-unparseable sidecar fails closed rather than degrading to a
//! silent empty map (see [`CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR`]).

use crate::rotation::HighWaterStore;
use std::collections::HashMap;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Fail-closed sentinel floor value (T-70-04): once a sidecar is found
/// PRESENT-but-corrupt, we no longer know any individual node's true
/// persisted floor, so every node under this store is reported as
/// maximally floored rather than "no floor known" — this forces
/// `enforce_resolved`'s generation/seq comparisons to reject until the
/// sidecar is repaired or removed, instead of silently treating corruption
/// as a cold first-contact bypass (the exact regression Greptile flagged
/// against the prior `unwrap_or_default()` fallback).
///
/// Deliberately kept within `i64::MAX` (not `u64::MAX`): `high_water.rs`'s
/// regression checks cast a stored floor `as i64` for comparison against
/// live `i64` input. `u64::MAX as i64` wraps to `-1`, which would make
/// every `attempted < floor` comparison FALSE — defeating every regression
/// check instead of forcing one. `i64::MAX` stays positive under that cast
/// and is larger than any legitimate live input, guaranteeing rejection.
const CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR: u64 = i64::MAX as u64;

/// Outcome of loading the sidecar map from disk (blocking).
enum LoadOutcome {
    /// The sidecar has never been written — genuinely "no floor known".
    Empty,
    /// The sidecar parsed successfully.
    Map(HashMap<String, u64>),
    /// A PRESENT sidecar failed to parse — fail-closed (T-70-04).
    Corrupt,
}

/// Load the whole `{ nodeId: value }` map from `path` (blocking; must run
/// inside `spawn_blocking`). Distinguishes "never written" (empty map, not
/// an error) from "present but unparseable" (`Corrupt`, fail-closed) — see
/// [`CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR`].
fn load_map_blocking(path: &Path) -> LoadOutcome {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<HashMap<String, u64>>(&bytes) {
            Ok(map) => LoadOutcome::Map(map),
            Err(e) => {
                log::error!(
                    "JsonSidecarFloorStore: corrupt sidecar at {}: {} -- failing closed (T-70-04)",
                    path.display(),
                    e
                );
                LoadOutcome::Corrupt
            }
        },
        Err(_) => LoadOutcome::Empty,
    }
}

/// Write the whole map atomically to `path` (blocking; must run inside
/// `spawn_blocking`): serialize to a sibling `.tmp` file (0600 perms,
/// fsync'd), then `rename()` over the real path. A crash mid-write leaves
/// the `.tmp` file orphaned but the real sidecar untouched — never a
/// partially-written/torn JSON file (mirrors `WriteQueue::put`'s
/// fsync-then-durable-rename discipline, with the rename step added for
/// true all-or-nothing atomicity across the existing-file-being-overwritten
/// case).
fn write_map_atomic_blocking(path: &Path, map: &HashMap<String, u64>) -> std::io::Result<()> {
    let json = serde_json::to_vec(map)?;

    let tmp_path = path.with_extension("tmp");

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    open_opts.mode(0o600);

    let mut file = open_opts.open(&tmp_path)?;
    file.write_all(&json)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp_path, path)?;

    // Best-effort: fsync the parent dir so the rename's directory entry
    // is durable on crash (matches WriteQueue::put's WR-03b discipline).
    if let Some(parent) = path.parent() {
        let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());
    }

    Ok(())
}

/// A durable `HighWaterStore` backed by a single JSON sidecar file.
///
/// Two independent floors (generation, seq) require two independent
/// instances of this store, each pointed at a different sidecar file — see
/// [`JsonSidecarFloorStore::for_generation`] / [`JsonSidecarFloorStore::for_seq`].
#[derive(Debug, Clone)]
pub struct JsonSidecarFloorStore {
    path: PathBuf,
    /// Serializes the whole load-modify-write critical section of `get`/
    /// `put` (T-70-03). `Arc`-wrapped so every `Clone` of this store shares
    /// the SAME lock — two independently-constructed instances pointed at
    /// the same sidecar path do NOT share this in-process lock (they only
    /// ever coordinate through the sidecar file itself), matching this
    /// crate's single-daemon-per-journal-dir model.
    lock: Arc<Mutex<()>>,
}

impl JsonSidecarFloorStore {
    /// Construct a floor store backed by `<journal_dir>/<file_name>`.
    ///
    /// The journal dir must already exist; this constructor does not create
    /// it (matches `WriteQueue::new`'s contract).
    pub fn new(journal_dir: impl AsRef<Path>, file_name: &str) -> Self {
        Self {
            path: journal_dir.as_ref().join(file_name),
            lock: Arc::new(Mutex::new(())),
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
}

impl HighWaterStore for JsonSidecarFloorStore {
    async fn get(&self, node_id: &str) -> Option<u64> {
        // Hold the lock across the whole (blocking) read so a concurrent
        // put's load-modify-write critical section can't observe a
        // half-written state -- the rename in write_map_atomic_blocking is
        // itself atomic, but the lock keeps this store's own concurrent
        // callers serialized with put's critical section too.
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let node_id = node_id.to_string();
        tokio::task::spawn_blocking(move || match load_map_blocking(&path) {
            LoadOutcome::Map(map) => map.get(&node_id).copied(),
            LoadOutcome::Empty => None,
            LoadOutcome::Corrupt => Some(CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR),
        })
        .await
        .expect("JsonSidecarFloorStore: get's blocking task panicked")
    }

    async fn put(&self, node_id: &str, value: u64) {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let node_id_owned = node_id.to_string();
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut map = match load_map_blocking(&path) {
                LoadOutcome::Map(map) => map,
                LoadOutcome::Empty => HashMap::new(),
                LoadOutcome::Corrupt => {
                    // Refuse to write over an unreadable sidecar: a blind
                    // overwrite would silently drop every OTHER node's
                    // floor (T-70-04). Leave the corrupt file untouched;
                    // get() keeps fail-closing until it is repaired/removed.
                    log::error!(
                        "JsonSidecarFloorStore: refusing to write over corrupt sidecar at {} for node {}",
                        path.display(),
                        node_id_owned
                    );
                    return Ok(());
                }
            };
            // Max-preserving write computed INSIDE the locked critical
            // section (SC#5 / T-70-03): a concurrent put with a lower
            // candidate can never clobber a higher persisted floor, and two
            // different-node_id puts serialize instead of lost-updating —
            // mirrors the TS `idbPut` reference (rotation-state.service.ts).
            let entry = map.entry(node_id_owned).or_insert(0);
            *entry = (*entry).max(value);
            write_map_atomic_blocking(&path, &map)
        })
        .await;

        // A write failure here is a durability defect, not a correctness
        // one: enforce_resolved has already decided the resolve is valid
        // (fail-open on the in-memory decision) but the floor bump did not
        // persist. This mirrors the `Promise<void>`-shaped TS contract:
        // errors are exceptional and logged, not silently threaded through
        // every call site's Result.
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::error!(
                "JsonSidecarFloorStore: failed to persist floor for node {}: {}",
                node_id,
                e
            ),
            Err(e) => log::error!(
                "JsonSidecarFloorStore: put's blocking task panicked for node {}: {}",
                node_id,
                e
            ),
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
    async fn concurrent_puts_same_node_id_no_lost_update() {
        // T-70-03: N tokio tasks race `put` on the SAME node_id with a mix
        // of high/low values against one shared store handle. No lost
        // updates: the final floor must be the max of every attempted value,
        // never a lower one that "won" a race.
        let dir = make_temp_dir();
        let store = std::sync::Arc::new(JsonSidecarFloorStore::for_generation(&dir));
        let values: [u64; 8] = [3, 50, 7, 100, 1, 42, 99, 2];

        let mut handles = Vec::new();
        for &value in &values {
            let store = std::sync::Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                store.put("node-1", value).await;
            }));
        }
        for handle in handles {
            handle.await.expect("put task panicked");
        }

        let expected_max = *values.iter().max().unwrap();
        assert_eq!(store.get("node-1").await, Some(expected_max));
    }

    #[tokio::test]
    async fn concurrent_puts_different_node_ids_no_lost_update() {
        // T-70-03: N tokio tasks race `put` on DISTINCT node_ids against one
        // shared store handle. A race-prone whole-map read-modify-write
        // would clobber the map (each task loads the map before any other
        // task's insert lands, then overwrites on write). Every node_id
        // must survive with its own value.
        let dir = make_temp_dir();
        let store = std::sync::Arc::new(JsonSidecarFloorStore::for_seq(&dir));
        let count = 20u64;

        let mut handles = Vec::new();
        for i in 0..count {
            let store = std::sync::Arc::clone(&store);
            let node_id = format!("node-{i}");
            handles.push(tokio::spawn(async move {
                store.put(&node_id, i).await;
            }));
        }
        for handle in handles {
            handle.await.expect("put task panicked");
        }

        for i in 0..count {
            let node_id = format!("node-{i}");
            assert_eq!(store.get(&node_id).await, Some(i));
        }
    }

    #[tokio::test]
    async fn corrupt_sidecar_fails_closed() {
        // T-70-04: a PRESENT-but-corrupt sidecar (bit-rot / tampering) must
        // never be silently treated as "no floor known" (cold first
        // contact) -- that would let a stale/lower generation or seq slip
        // past `enforce_resolved`. Write garbage bytes directly to the
        // sidecar path, bypassing `put` entirely.
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_generation(&dir);
        std::fs::write(&store.path, b"not valid json {{{").expect("write garbage bytes");

        // Direct store read must fail closed, not silently resolve to None
        // (the "never written" case).
        assert_ne!(store.get("node-1").await, None);

        // The gate itself (a fresh instance, simulating a daemon restart
        // over the same on-disk sidecar) must reject rather than apply the
        // cold-device version_floor gate.
        let rhw = RotationHighWater::new(
            JsonSidecarFloorStore::for_generation(&dir),
            JsonSidecarFloorStore::for_seq(&dir),
        );
        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 1,
                generation: 1,
                version_floor: 0,
            })
            .await
            .expect_err("corrupt generation sidecar must fail closed, not cold-start");
        assert!(matches!(
            err,
            crate::rotation::RotationError::GenerationRegression { .. }
        ));
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
