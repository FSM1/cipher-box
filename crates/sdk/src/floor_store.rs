//! Durable JSON-sidecar `HighWaterStore` implementation (D-03/D-06/D-08).
//!
//! Persists ONE combined `{ nodeId: CombinedFloorRecord }` map — where
//! `CombinedFloorRecord` holds `{ generation, seq, wrapped_key_checkpoint }`
//! — as a single JSON sidecar file adjacent to the FUSE journal dir, written
//! atomically (temp file + rename, 0600 perms) mirroring the
//! [`crate::queue::WriteQueue`] sidecar convention. No new storage dependency
//! (sled/redb/rusqlite rejected per D-03) — the FUSE single-daemon model
//! means this file is small and read-modify-write on every access is cheap
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
//!
//! `JsonSidecarFloorStore::for_generation`/`for_seq` (D-06) both point at
//! the SAME combined sidecar file — they differ only in which
//! `CombinedFloorRecord` field they read/write — so the generation and seq
//! floors for a nodeId can never diverge across two independent files the
//! way the old two-sidecar-file shape could. A device upgrading from that
//! old shape has its two files folded forward into the combined record on
//! first read (Pitfall 4) — see [`fold_legacy_two_file_shape`].
//!
//! `persist_wrapped_key`/`get_wrapped_key`/`delete_wrapped_key` (D-07 Rust
//! half) persist the wrapped-key checkpoint ciphertext into the SAME
//! per-nodeId combined record, independent of the generation/seq fields —
//! this is the concrete durable target the FUSE production `RotationDeps`
//! adapter (Plan 09) delegates to. `persist_wrapped_key`/`delete_wrapped_key`
//! fail closed on a write failure exactly like `put` (D-08) — a lost
//! checkpoint write would defeat D-01.

use crate::rotation::{HighWaterStore, RotationError};
use std::collections::HashMap;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
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

/// The combined per-nodeId durable record (D-06/D-07): both anti-rollback
/// floors plus the optional wrapped-key checkpoint ciphertext, persisted
/// together in ONE sidecar file so they can never diverge across two
/// independent files the way the old two-sidecar-file shape could.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CombinedFloorRecord {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub seq: u64,
    /// Ciphertext only — never plaintext key material (CLAUDE.md Rule 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key_checkpoint: Option<Vec<u8>>,
}

/// Which `CombinedFloorRecord` field a given `JsonSidecarFloorStore`
/// instance's `HighWaterStore::get`/`put` reads/writes. Both
/// [`JsonSidecarFloorStore::for_generation`] and
/// [`JsonSidecarFloorStore::for_seq`] point at the SAME combined sidecar
/// file — this tag is what makes the two behave like independent floors
/// while both filing into one durable record (D-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloorField {
    Generation,
    Seq,
}

impl FloorField {
    fn read(self, record: &CombinedFloorRecord) -> u64 {
        match self {
            FloorField::Generation => record.generation,
            FloorField::Seq => record.seq,
        }
    }

    /// Max-preserving write (SC#5/T-70-03): never lowers the field's
    /// current value.
    fn bump_max(self, record: &mut CombinedFloorRecord, value: u64) {
        match self {
            FloorField::Generation => record.generation = record.generation.max(value),
            FloorField::Seq => record.seq = record.seq.max(value),
        }
    }
}

const COMBINED_FILE_NAME: &str = "rotation-high-water.json";
const LEGACY_GENERATION_FILE_NAME: &str = "rotation-high-water-generation.json";
const LEGACY_SEQ_FILE_NAME: &str = "rotation-high-water-seq.json";

/// Outcome of loading the sidecar map from disk (blocking).
enum LoadOutcome {
    /// The sidecar has never been written — genuinely "no floor known".
    Empty,
    /// The sidecar parsed successfully.
    Map(HashMap<String, CombinedFloorRecord>),
    /// A PRESENT sidecar failed to parse — fail-closed (T-70-04).
    Corrupt,
}

/// Pitfall 4: folds the OLD two-file `{ nodeId: u64 }` shape (separate
/// generation/seq sidecars) forward into a combined map. Only ever invoked
/// when the new combined sidecar is absent (upgrade path). Returns `None`
/// when NEITHER legacy file is present — a genuinely cold, never-migrated
/// device, not a migration case.
fn fold_legacy_two_file_shape(journal_dir: &Path) -> Option<HashMap<String, CombinedFloorRecord>> {
    let gen_map = std::fs::read(journal_dir.join(LEGACY_GENERATION_FILE_NAME))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HashMap<String, u64>>(&bytes).ok());
    let seq_map = std::fs::read(journal_dir.join(LEGACY_SEQ_FILE_NAME))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HashMap<String, u64>>(&bytes).ok());

    if gen_map.is_none() && seq_map.is_none() {
        return None;
    }

    let mut combined: HashMap<String, CombinedFloorRecord> = HashMap::new();
    if let Some(map) = gen_map {
        for (node_id, generation) in map {
            combined.entry(node_id).or_default().generation = generation;
        }
    }
    if let Some(map) = seq_map {
        for (node_id, seq) in map {
            combined.entry(node_id).or_default().seq = seq;
        }
    }
    Some(combined)
}

/// Load the whole `{ nodeId: CombinedFloorRecord }` map from `path`
/// (blocking; must run inside `spawn_blocking`). Distinguishes "never
/// written" (folds the legacy two-file shape forward if present, else empty
/// map — neither is an error) from "present but unparseable" (`Corrupt`,
/// fail-closed) — see [`CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR`].
fn load_map_blocking(path: &Path) -> LoadOutcome {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<HashMap<String, CombinedFloorRecord>>(&bytes) {
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
        // Only "no such file" genuinely means "never written" -- a cold
        // start with no floor known yet (modulo the legacy fold-forward
        // below). Any OTHER read error (permission denied, transient I/O
        // failure, etc.) on a sidecar path that DOES exist must NOT be
        // silently treated as cold-start (T3): that would bypass the
        // anti-rollback regression check exactly like a corrupt sidecar
        // would, so it fails closed the same way.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match path.parent().and_then(fold_legacy_two_file_shape) {
                Some(migrated) => LoadOutcome::Map(migrated),
                None => LoadOutcome::Empty,
            }
        }
        Err(e) => {
            log::error!(
                "JsonSidecarFloorStore: read error for sidecar at {}: {} -- failing closed, not cold-starting",
                path.display(),
                e
            );
            LoadOutcome::Corrupt
        }
    }
}

/// Write the whole map atomically to `path` (blocking; must run inside
/// `spawn_blocking`): serialize to a sibling `.tmp` file (0600 perms,
/// fsync'd), then `rename()` over the real path. A crash mid-write leaves
/// the `.tmp` file orphaned but the real sidecar untouched — never a
/// partially-written/torn JSON file (mirrors `WriteQueue::put`'s
/// fsync-then-durable-rename discipline, with the rename step added for
/// true all-or-nothing atomicity across the existing-file-being-overwritten
/// case). Every write serializes the WHOLE combined record for each node in
/// the map, not just the field that changed (D-06).
fn write_map_atomic_blocking(
    path: &Path,
    map: &HashMap<String, CombinedFloorRecord>,
) -> std::io::Result<()> {
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

/// A durable `HighWaterStore` backed by a single combined JSON sidecar file
/// (D-06).
///
/// The two floors (generation, seq) are two `JsonSidecarFloorStore`
/// instances constructed via [`JsonSidecarFloorStore::for_generation`] /
/// [`JsonSidecarFloorStore::for_seq`] — both point at the SAME sidecar file
/// and differ only in which `CombinedFloorRecord` field they read/write, so
/// the two floors can never diverge across independent files.
#[derive(Debug, Clone)]
pub struct JsonSidecarFloorStore {
    path: PathBuf,
    /// Serializes the whole load-modify-write critical section of `get`/
    /// `put`/`persist_wrapped_key`/`get_wrapped_key`/`delete_wrapped_key`
    /// (T-70-03). `Arc`-wrapped so every `Clone` of this store shares the
    /// SAME lock -- AND every OTHER instance independently constructed over
    /// the SAME sidecar path shares it too, via the process-global
    /// [`SIDECAR_LOCKS`] registry consulted in `new()`. This is required
    /// because `CipherBoxFS` (`crates/fuse/src/fs.rs`) holds THREE
    /// independently-constructed instances pointed at the same combined
    /// `rotation-high-water.json` (`high_water`'s generation + seq stores
    /// and `rotation_checkpoint_store`): without a shared lock, two of them
    /// writing concurrently race on the SAME deterministic
    /// `write_map_atomic_blocking` `.tmp` path -- the loser's `rename()`
    /// hits ENOENT once the winner has already renamed its temp file away,
    /// and even when no ENOENT occurs, two un-serialized read-modify-writes
    /// can lose an update (a higher floor clobbered by a lower one racing
    /// in), defeating the whole anti-rollback purpose of this store.
    lock: Arc<Mutex<()>>,
    /// Which field of the combined record this instance reads/writes.
    field: FloorField,
}

/// Process-global registry mapping a normalized sidecar path to the shared
/// lock every `JsonSidecarFloorStore` instance constructed over that path
/// uses. See the `lock` field's doc for why this must be shared across
/// independently-constructed instances, not just `Clone`s of one instance.
static SIDECAR_LOCKS: OnceLock<StdMutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

/// Normalize `path` for use as a [`SIDECAR_LOCKS`] key so relative and
/// absolute forms of the same on-disk path map to the SAME lock. The
/// sidecar file itself may legitimately not exist yet at construction time
/// (a cold store is a normal, non-error state), so this canonicalizes the
/// PARENT directory -- which `new()`'s contract requires to already exist
/// -- and rejoins the file name, rather than canonicalizing the
/// (possibly-absent) file path directly.
fn normalize_lock_key(path: &Path) -> PathBuf {
    match (
        path.parent().and_then(|p| p.canonicalize().ok()),
        path.file_name(),
    ) {
        (Some(parent), Some(file_name)) => parent.join(file_name),
        // Fall back to the raw path if canonicalization fails (e.g. the
        // parent dir is missing, violating the constructor's own contract)
        // -- degrades to no cross-instance sharing rather than panicking.
        _ => path.to_path_buf(),
    }
}

/// Look up (or lazily insert) the shared lock for `path`'s normalized key.
fn shared_lock_for(path: &Path) -> Arc<Mutex<()>> {
    let key = normalize_lock_key(path);
    let registry = SIDECAR_LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(guard.entry(key).or_insert_with(|| Arc::new(Mutex::new(()))))
}

impl JsonSidecarFloorStore {
    /// Construct a floor store backed by `<journal_dir>/<file_name>`,
    /// scoped to a single `CombinedFloorRecord` field.
    ///
    /// The journal dir must already exist; this constructor does not create
    /// it (matches `WriteQueue::new`'s contract). The returned store's lock
    /// is shared (via [`shared_lock_for`]) with every other instance ever
    /// constructed over the same on-disk path, in this process.
    fn new(journal_dir: impl AsRef<Path>, file_name: &str, field: FloorField) -> Self {
        let path = journal_dir.as_ref().join(file_name);
        let lock = shared_lock_for(&path);
        Self { path, lock, field }
    }

    /// Convenience constructor for the generation-floor view of the
    /// combined sidecar (`<journal_dir>/rotation-high-water.json`).
    pub fn for_generation(journal_dir: impl AsRef<Path>) -> Self {
        Self::new(journal_dir, COMBINED_FILE_NAME, FloorField::Generation)
    }

    /// Convenience constructor for the seq-floor view of the combined
    /// sidecar (`<journal_dir>/rotation-high-water.json`).
    pub fn for_seq(journal_dir: impl AsRef<Path>) -> Self {
        Self::new(journal_dir, COMBINED_FILE_NAME, FloorField::Seq)
    }

    /// Persists the wrapped-key checkpoint ciphertext into the combined
    /// record for `node_id` (D-07 Rust half). Fails closed on a write
    /// failure exactly like `put` (D-08) — a lost checkpoint write would
    /// defeat D-01, so it MUST NOT log-and-return-Ok.
    pub async fn persist_wrapped_key(
        &self,
        node_id: &str,
        ciphertext: Vec<u8>,
    ) -> Result<(), RotationError> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let node_id_owned = node_id.to_string();
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut map = load_map_or_refuse_corrupt(&path, &node_id_owned)?;
            map.entry(node_id_owned).or_default().wrapped_key_checkpoint = Some(ciphertext);
            write_map_atomic_blocking(&path, &map)
        })
        .await;
        map_persist_result(node_id, result)
    }

    /// Reads the wrapped-key checkpoint ciphertext for `node_id`, or `None`
    /// if never persisted (or the sidecar is absent/corrupt — the
    /// generation/seq fail-closed floor already blocks any resolve that
    /// would otherwise consult a corrupt device's checkpoint).
    pub async fn get_wrapped_key(&self, node_id: &str) -> Option<Vec<u8>> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let node_id_owned = node_id.to_string();
        tokio::task::spawn_blocking(move || match load_map_blocking(&path) {
            LoadOutcome::Map(map) => map
                .get(&node_id_owned)
                .and_then(|record| record.wrapped_key_checkpoint.clone()),
            LoadOutcome::Empty | LoadOutcome::Corrupt => None,
        })
        .await
        .expect("JsonSidecarFloorStore: get_wrapped_key's blocking task panicked")
    }

    /// Clears the wrapped-key checkpoint for `node_id`, leaving the
    /// generation/seq floors in the same combined record untouched. Fails
    /// closed on a write failure (D-08), matching `persist_wrapped_key`.
    pub async fn delete_wrapped_key(&self, node_id: &str) -> Result<(), RotationError> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let node_id_owned = node_id.to_string();
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut map = load_map_or_refuse_corrupt(&path, &node_id_owned)?;
            if let Some(record) = map.get_mut(&node_id_owned) {
                record.wrapped_key_checkpoint = None;
            }
            write_map_atomic_blocking(&path, &map)
        })
        .await;
        map_persist_result(node_id, result)
    }
}

/// Shared load step for the wrapped-key mutating paths: loads the combined
/// map, refusing (as an `Err`, not a silent `Ok`) to write over a corrupt
/// sidecar — a blind overwrite would drop every other node's floor and
/// checkpoint (D-08 extended: this refusal must ALSO fail closed, not just
/// genuine I/O errors).
fn load_map_or_refuse_corrupt(
    path: &Path,
    node_id: &str,
) -> std::io::Result<HashMap<String, CombinedFloorRecord>> {
    match load_map_blocking(path) {
        LoadOutcome::Map(map) => Ok(map),
        LoadOutcome::Empty => Ok(HashMap::new()),
        LoadOutcome::Corrupt => Err(std::io::Error::other(format!(
            "refusing to write over corrupt sidecar at {} for node {}",
            path.display(),
            node_id
        ))),
    }
}

/// Maps a blocking-task result to the fail-closed `RotationError` contract
/// (D-08): a write failure — whether a genuine I/O error or a panicked
/// blocking task — is returned as `Err`, never swallowed via a
/// log-and-return-Ok path.
fn map_persist_result(
    node_id: &str,
    result: Result<std::io::Result<()>, tokio::task::JoinError>,
) -> Result<(), RotationError> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            log::error!(
                "JsonSidecarFloorStore: failed to persist for node {}: {}",
                node_id,
                e
            );
            Err(RotationError::PersistFailed {
                node_id: node_id.to_string(),
                message: e.to_string(),
            })
        }
        Err(e) => {
            log::error!(
                "JsonSidecarFloorStore: persist blocking task panicked for node {}: {}",
                node_id,
                e
            );
            Err(RotationError::PersistFailed {
                node_id: node_id.to_string(),
                message: format!("blocking task panicked: {e}"),
            })
        }
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
        let field = self.field;
        tokio::task::spawn_blocking(move || match load_map_blocking(&path) {
            LoadOutcome::Map(map) => map.get(&node_id).map(|record| field.read(record)),
            LoadOutcome::Empty => None,
            LoadOutcome::Corrupt => Some(CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR),
        })
        .await
        .expect("JsonSidecarFloorStore: get's blocking task panicked")
    }

    async fn put(&self, node_id: &str, value: u64) -> Result<(), RotationError> {
        let _guard = self.lock.lock().await;
        let path = self.path.clone();
        let node_id_owned = node_id.to_string();
        let field = self.field;
        let result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut map = load_map_or_refuse_corrupt(&path, &node_id_owned)?;
            // Max-preserving write computed INSIDE the locked critical
            // section (SC#5 / T-70-03): a concurrent put with a lower
            // candidate can never clobber a higher persisted floor, and two
            // different-node_id puts serialize instead of lost-updating —
            // mirrors the TS `idbPut` reference (rotation-state.service.ts).
            let entry = map.entry(node_id_owned).or_default();
            field.bump_max(entry, value);
            write_map_atomic_blocking(&path, &map)
        })
        .await;

        // D-08: a write failure is now a fail-closed Err, never a
        // log-and-return-Ok swallow — enforce_resolved (via bump_floor)
        // propagates this verbatim.
        map_persist_result(node_id, result)
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
        store.put("node-1", 42).await.expect("put");
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
            store.put("node-restart", 7).await.expect("put");
        } // store dropped here

        let reloaded = JsonSidecarFloorStore::for_generation(&dir);
        assert_eq!(reloaded.get("node-restart").await, Some(7));
    }

    #[tokio::test]
    async fn generation_and_seq_are_independent_fields_of_the_combined_record() {
        let dir = make_temp_dir();
        let gen_store = JsonSidecarFloorStore::for_generation(&dir);
        let seq_store = JsonSidecarFloorStore::for_seq(&dir);

        gen_store.put("node-1", 3).await.expect("put generation");
        seq_store.put("node-1", 99).await.expect("put seq");

        // Each floor is independently addressable -- writing one must not
        // clobber the other's field of the SAME combined record (D-06).
        assert_eq!(gen_store.get("node-1").await, Some(3));
        assert_eq!(seq_store.get("node-1").await, Some(99));
    }

    #[tokio::test]
    async fn no_partial_json_survives_a_write() {
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_generation(&dir);
        store.put("node-1", 1).await.expect("put");
        store.put("node-2", 2).await.expect("put");

        // The on-disk file must always parse as valid, complete JSON --
        // never a torn/partial write (the atomic rename guarantees this).
        let bytes = std::fs::read(&store.path).expect("sidecar exists");
        let map: HashMap<String, CombinedFloorRecord> =
            serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(map.get("node-1").map(|r| r.generation), Some(1));
        assert_eq!(map.get("node-2").map(|r| r.generation), Some(2));

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
                store.put("node-1", value).await.expect("put");
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
                store.put(&node_id, i).await.expect("put");
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

    // -----------------------------------------------------------------
    // RED (70.1-03 Task 1): fail-closed put, combined-record atomicity,
    // old-two-file migration, and wrapped-key checkpoint round-trip.
    // These deliberately reference production items that do not exist yet
    // (`RotationError::PersistFailed`, `CombinedFloorRecord`,
    // `persist_wrapped_key`/`get_wrapped_key`/`delete_wrapped_key`) so the
    // suite is RED until Task 2 lands.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn put_fails_closed_on_write_failure_and_enforce_resolved_surfaces_it() {
        // D-08: a write failure must surface as Err, never be swallowed by
        // a log-and-return-Ok path.
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_generation(&dir);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dir).expect("stat dir").permissions();
            perms.set_mode(0o500); // r-x: creating a file inside must fail
            std::fs::set_permissions(&dir, perms).expect("chmod dir read-only");
        }

        let err = store
            .put("node-1", 5)
            .await
            .expect_err("write failure must be Err, not swallowed (D-08)");
        assert!(matches!(
            err,
            crate::rotation::RotationError::PersistFailed { .. }
        ));

        // enforce_resolved must surface the SAME fail-closed Err when the
        // underlying floor bump can't be persisted -- not silently accept
        // the in-memory decision while the durable write is lost.
        let rhw = RotationHighWater::new(
            JsonSidecarFloorStore::for_generation(&dir),
            JsonSidecarFloorStore::for_seq(&dir),
        );
        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-2".to_string(),
                seq: 1,
                generation: 1,
                version_floor: 0,
            })
            .await
            .expect_err("enforce_resolved must surface the durable write failure");
        assert!(matches!(
            err,
            crate::rotation::RotationError::PersistFailed { .. }
        ));
    }

    #[tokio::test]
    async fn combined_record_is_written_as_one_atomic_file_and_never_torn() {
        // D-06: generation + seq (+ wrapped_key_checkpoint) for a nodeId live
        // in ONE combined record in ONE sidecar file -- never two files.
        let dir = make_temp_dir();
        let gen_store = JsonSidecarFloorStore::for_generation(&dir);
        let seq_store = JsonSidecarFloorStore::for_seq(&dir);

        gen_store.put("node-1", 3).await.expect("put generation");
        seq_store.put("node-1", 99).await.expect("put seq");

        assert_eq!(
            gen_store.path, seq_store.path,
            "must share ONE sidecar file"
        );

        let bytes = std::fs::read(&gen_store.path).expect("combined sidecar exists");
        let map: HashMap<String, CombinedFloorRecord> =
            serde_json::from_slice(&bytes).expect("valid, non-torn combined JSON");
        let record = map.get("node-1").expect("node-1 record present");
        assert_eq!(record.generation, 3);
        assert_eq!(record.seq, 99);

        let tmp_path = gen_store.path.with_extension("tmp");
        assert!(!tmp_path.exists(), "no orphaned temp file after success");
    }

    #[tokio::test]
    async fn old_two_file_shape_folds_forward_into_the_combined_record() {
        // Pitfall 4: a device upgrading from the old two-sidecar-file shape
        // must not reset either floor to zero -- both values fold forward
        // into the new combined record on first read.
        let dir = make_temp_dir();
        std::fs::write(
            dir.join("rotation-high-water-generation.json"),
            br#"{"node-1":4}"#,
        )
        .expect("seed legacy generation sidecar");
        std::fs::write(
            dir.join("rotation-high-water-seq.json"),
            br#"{"node-1":12}"#,
        )
        .expect("seed legacy seq sidecar");

        let gen_store = JsonSidecarFloorStore::for_generation(&dir);
        let seq_store = JsonSidecarFloorStore::for_seq(&dir);

        assert_eq!(
            gen_store.get("node-1").await,
            Some(4),
            "generation floor must fold forward, not reset"
        );
        assert_eq!(
            seq_store.get("node-1").await,
            Some(12),
            "seq floor must fold forward, not reset"
        );
    }

    #[tokio::test]
    async fn wrapped_key_checkpoint_round_trips_in_the_combined_record() {
        // D-07 (Rust half): the wrapped-key checkpoint persists/reads/
        // deletes from the SAME per-nodeId combined record, independent of
        // the generation/seq floors.
        let dir = make_temp_dir();
        let store = JsonSidecarFloorStore::for_generation(&dir);
        store.put("node-1", 7).await.expect("seed a floor first");

        let ciphertext = vec![9u8, 8, 7, 6, 5];
        store
            .persist_wrapped_key("node-1", ciphertext.clone())
            .await
            .expect("persist wrapped key");
        assert_eq!(store.get_wrapped_key("node-1").await, Some(ciphertext));

        store
            .delete_wrapped_key("node-1")
            .await
            .expect("delete wrapped key");
        assert_eq!(store.get_wrapped_key("node-1").await, None);

        // The floor set before the wrapped-key round trip must survive
        // untouched (delete only clears its own field).
        assert_eq!(store.get("node-1").await, Some(7));
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

    // -----------------------------------------------------------------
    // Post-hoc regression (Phase 70.1 live repro): three independently
    // constructed `JsonSidecarFloorStore` instances over the SAME sidecar
    // path must share ONE lock, mirroring exactly how `CipherBoxFS` (in
    // `crates/fuse/src/fs.rs`) holds `high_water.generation_store`,
    // `high_water.seq_store`, and `rotation_checkpoint_store` -- all three
    // pointed at `<journal_dir>/rotation-high-water.json`.
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn multiple_instances_over_the_same_path_share_one_lock_and_never_lose_an_update() {
        // Before the fix, each `JsonSidecarFloorStore::new()` built its own
        // `Arc<Mutex<()>>`, so two of these THREE independently-constructed
        // instances writing concurrently would race on the SAME
        // deterministic `write_map_atomic_blocking` `.tmp` path: the
        // loser's `rename()` hits ENOENT once the winner has already
        // renamed its temp file away (the exact live-repro'd error:
        // "failed to persist for node ...: No such file or directory (os
        // error 2)"). Even runs that avoided the ENOENT could still lose an
        // update via two un-serialized read-modify-writes. This test must
        // FAIL (either a persist `Err` or a lost update) before the
        // shared-lock fix and PASS after it.
        let dir = make_temp_dir();
        let gen_store = std::sync::Arc::new(JsonSidecarFloorStore::for_generation(&dir));
        let seq_store = std::sync::Arc::new(JsonSidecarFloorStore::for_seq(&dir));
        // Mirrors fs.rs's `rotation_checkpoint_store`, which arbitrarily
        // reuses `for_generation`'s field tag -- the checkpoint accessors
        // ignore it, they only care that the sidecar PATH matches.
        let checkpoint_store = std::sync::Arc::new(JsonSidecarFloorStore::for_generation(&dir));

        assert_eq!(
            gen_store.path, seq_store.path,
            "all three instances must point at the SAME sidecar path"
        );
        assert_eq!(gen_store.path, checkpoint_store.path);

        let node_id = "node-race";
        let gen_values: [u64; 10] = [3, 50, 7, 100, 1, 42, 99, 2, 77, 12];
        let seq_values: [u64; 10] = [8, 4, 60, 2, 91, 33, 5, 70, 9, 44];
        let expected_gen_max = *gen_values.iter().max().unwrap();
        let expected_seq_max = *seq_values.iter().max().unwrap();

        let mut handles: Vec<tokio::task::JoinHandle<Result<(), RotationError>>> = Vec::new();

        for &value in &gen_values {
            let store = std::sync::Arc::clone(&gen_store);
            handles.push(tokio::spawn(async move { store.put(node_id, value).await }));
        }
        for &value in &seq_values {
            let store = std::sync::Arc::clone(&seq_store);
            handles.push(tokio::spawn(async move { store.put(node_id, value).await }));
        }
        for i in 0..10u8 {
            let store = std::sync::Arc::clone(&checkpoint_store);
            let ciphertext = vec![i; 5];
            handles.push(tokio::spawn(async move {
                store.persist_wrapped_key(node_id, ciphertext).await
            }));
        }

        let mut errors = Vec::new();
        for handle in handles {
            if let Err(e) = handle.await.expect("task panicked") {
                errors.push(e);
            }
        }
        assert!(
            errors.is_empty(),
            "no persist should fail under concurrent multi-instance writes over the same path: {errors:?}"
        );

        // No lost updates: the final floor is the max of every attempted
        // value, regardless of which instance's write "won" the race.
        assert_eq!(gen_store.get(node_id).await, Some(expected_gen_max));
        assert_eq!(seq_store.get(node_id).await, Some(expected_seq_max));

        // The checkpoint field is independent of the generation/seq fields
        // (D-06/D-07) -- confirm it survived the race and still round
        // trips correctly, proving the combined record was never
        // wholesale-clobbered by a racing writer.
        let final_ciphertext = vec![9u8, 8, 7, 6, 5];
        checkpoint_store
            .persist_wrapped_key(node_id, final_ciphertext.clone())
            .await
            .expect("final checkpoint persist");
        assert_eq!(
            checkpoint_store.get_wrapped_key(node_id).await,
            Some(final_ciphertext)
        );
        assert_eq!(gen_store.get(node_id).await, Some(expected_gen_max));
        assert_eq!(seq_store.get(node_id).await, Some(expected_seq_max));
    }
}
