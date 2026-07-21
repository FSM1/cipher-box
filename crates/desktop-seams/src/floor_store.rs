//! Desktop [`FloorStore`]: fsync-barriered per-key floor files with a
//! write-ahead intent record for cross-key atomic batch commits.

use std::path::{Path, PathBuf};

use cipherbox_engine::seams::{FloorNamespace, FloorRaise, FloorStore, SeamError, SeamResult};

use crate::fs_util::{
    atomic_write, ensure_dir, read_file_opt, remove_file_durable, seam_err, to_hex,
};

/// Durable monotonic-max floor store backed by one small file per key
/// (blueprint/engine.md "FloorStore"; blueprint/desktop.md "Local journal").
///
/// Epoch floors live under `epoch/`, sequence floors under `seq/`, so the
/// two namespaces cannot collide even on identical key bytes. Each floor is
/// a single `u64` (8 bytes, little-endian) written through the
/// [`atomic_write`] fsync barrier, so a floor is structurally incapable of
/// regression or a torn value, and survives reopen. Keys are opaque engine
/// bytes, hex-encoded into filenames; the store never interprets them.
///
/// A batch [`commit_floors`](FloorStore::commit_floors) that raises several
/// distinctly-keyed floors is made crash-atomic by a write-ahead intent record
/// (`intent`): the whole batch is fsynced there before any per-key file moves,
/// and [`open`](Self::open) replays a leftover intent on reopen. An advance
/// interrupted between per-key writes therefore completes on the next open
/// (idempotent monotonic-max), never lingering as a partial (#685).
pub struct FileFloorStore {
    epoch_dir: PathBuf,
    seq_dir: PathBuf,
    intent_path: PathBuf,
}

/// Intent-record tag for an epoch-namespace raise.
const INTENT_TAG_EPOCH: u8 = 0;
/// Intent-record tag for a sequence-namespace raise.
const INTENT_TAG_SEQUENCE: u8 = 1;

impl FileFloorStore {
    /// Opens (creating if absent) a floor store rooted at `dir`. Reopening
    /// the same `dir` yields the same durable floors, replaying any intent
    /// record a crashed batch commit left behind.
    pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
        let dir = dir.as_ref();
        let epoch_dir = dir.join("epoch");
        let seq_dir = dir.join("seq");
        // The intent temp write lands in the root, so sweep it too.
        ensure_dir(dir).map_err(|err| seam_err("floor_store open root", &err))?;
        ensure_dir(&epoch_dir).map_err(|err| seam_err("floor_store open epoch", &err))?;
        ensure_dir(&seq_dir).map_err(|err| seam_err("floor_store open seq", &err))?;
        let store = Self {
            epoch_dir,
            seq_dir,
            intent_path: dir.join("intent"),
        };
        store.replay_intent()?;
        Ok(store)
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

    /// The namespace's floor directory.
    fn dir_for(&self, namespace: FloorNamespace) -> &Path {
        match namespace {
            FloorNamespace::Epoch => &self.epoch_dir,
            FloorNamespace::Sequence => &self.seq_dir,
        }
    }

    /// Applies a batch of raises to the per-key files, returning each result.
    fn apply_raises(&self, raises: &[FloorRaise], op: &str) -> SeamResult<Vec<u64>> {
        raises
            .iter()
            .map(|r| self.raise_floor(self.dir_for(r.namespace), &r.key, r.value, op))
            .collect()
    }

    /// Replays a leftover intent record left by a batch commit interrupted
    /// mid-apply, then clears it. Monotonic-max makes replay idempotent, so a
    /// batch that had partly applied before the crash simply completes.
    fn replay_intent(&self) -> SeamResult<()> {
        let bytes = read_file_opt(&self.intent_path)
            .map_err(|err| seam_err("floor_store read intent", &err))?;
        let Some(bytes) = bytes else {
            return Ok(());
        };
        let raises = decode_intent(&bytes)?;
        self.apply_raises(&raises, "floor_store replay intent")?;
        remove_file_durable(&self.intent_path)
            .map_err(|err| seam_err("floor_store clear intent", &err))
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

    /// Crash-atomic across keys via a write-ahead intent record: the whole
    /// batch is fsynced to `intent` first, so an advance interrupted between
    /// per-key writes is completed by [`open`](Self::open)'s replay rather than
    /// left partial (#685). A commit that returns `Ok` has cleared the intent.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<Vec<u64>> {
        if raises.is_empty() {
            return Ok(Vec::new());
        }
        atomic_write(&self.intent_path, &encode_intent(raises))
            .map_err(|err| seam_err("floor_store write intent", &err))?;
        let resulting = self.apply_raises(raises, "floor_store commit_floors")?;
        remove_file_durable(&self.intent_path)
            .map_err(|err| seam_err("floor_store clear intent", &err))?;
        Ok(resulting)
    }
}

/// Serializes a batch into the intent record: for each raise, a 1-byte
/// namespace tag, a 4-byte little-endian key length, the key bytes, then the
/// 8-byte little-endian value.
fn encode_intent(raises: &[FloorRaise]) -> Vec<u8> {
    let mut out = Vec::new();
    for raise in raises {
        let tag = match raise.namespace {
            FloorNamespace::Epoch => INTENT_TAG_EPOCH,
            FloorNamespace::Sequence => INTENT_TAG_SEQUENCE,
        };
        out.push(tag);
        out.extend_from_slice(&(raise.key.len() as u32).to_le_bytes());
        out.extend_from_slice(&raise.key);
        out.extend_from_slice(&raise.value.to_le_bytes());
    }
    out
}

/// The corruption error surfaced by [`decode_intent`].
fn corrupt_intent() -> SeamError {
    SeamError::new("floor_store: corrupt intent record on disk")
}

/// Reads a fixed slice at `start`, failing closed if it runs past the record.
fn intent_slice(bytes: &[u8], start: usize, len: usize) -> SeamResult<&[u8]> {
    bytes.get(start..start + len).ok_or_else(corrupt_intent)
}

/// Parses an intent record. The record is written whole through the
/// [`atomic_write`] barrier, so a present file is never torn; a malformed one
/// is genuine corruption and fails closed.
fn decode_intent(bytes: &[u8]) -> SeamResult<Vec<FloorRaise>> {
    let mut raises = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let namespace = match bytes[i] {
            INTENT_TAG_EPOCH => FloorNamespace::Epoch,
            INTENT_TAG_SEQUENCE => FloorNamespace::Sequence,
            _ => return Err(corrupt_intent()),
        };
        i += 1;
        let len_bytes: [u8; 4] = intent_slice(bytes, i, 4)?.try_into().unwrap();
        let key_len = u32::from_le_bytes(len_bytes) as usize;
        i += 4;
        let key = intent_slice(bytes, i, key_len)?.to_vec();
        i += key_len;
        let val_bytes: [u8; 8] = intent_slice(bytes, i, 8)?.try_into().unwrap();
        i += 8;
        raises.push(FloorRaise {
            namespace,
            key,
            value: u64::from_le_bytes(val_bytes),
        });
    }
    Ok(raises)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::testkit::block_on;

    #[test]
    fn intent_round_trips() {
        let raises = vec![
            FloorRaise::epoch(b"scope".to_vec(), 7),
            FloorRaise::sequence(b"k51-name".to_vec(), 42),
            FloorRaise::epoch(Vec::new(), 1),
        ];
        assert_eq!(decode_intent(&encode_intent(&raises)).unwrap(), raises);
    }

    #[test]
    fn decode_rejects_a_truncated_intent() {
        let bytes = encode_intent(&[FloorRaise::epoch(b"scope".to_vec(), 7)]);
        assert!(decode_intent(&bytes[..bytes.len() - 1]).is_err());
    }

    /// A batch commit interrupted mid-apply (intent fsynced, only the first of
    /// two floors on the platter) is completed by reopen — the second floor
    /// lands and the intent clears, so no partial advance survives (#685).
    #[test]
    fn open_replays_an_interrupted_batch_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("floors");

        // Simulate the crashed state by hand: the revocation floor applied, its
        // sequence partner not yet, and the intent record still present.
        block_on(async {
            let store = FileFloorStore::open(&path).unwrap();
            store.raise_epoch_floor(b"scope", 9).await.unwrap();
        });
        let interrupted = vec![
            FloorRaise::epoch(b"scope".to_vec(), 9),
            FloorRaise::sequence(b"k51-name".to_vec(), 5),
        ];
        atomic_write(&path.join("intent"), &encode_intent(&interrupted)).unwrap();

        block_on(async {
            let reopened = FileFloorStore::open(&path).unwrap();
            assert_eq!(
                reopened.sequence_floor(b"k51-name").await.unwrap(),
                Some(5),
                "reopen must complete the interrupted sequence raise"
            );
            assert_eq!(reopened.epoch_floor(b"scope").await.unwrap(), Some(9));
        });
        assert!(
            !path.join("intent").exists(),
            "reopen must clear the intent record after replay"
        );
    }
}
