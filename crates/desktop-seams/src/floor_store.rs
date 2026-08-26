//! Desktop [`FloorStore`]: fsync-barriered per-key floor files with a
//! write-ahead intent record for cross-key atomic batch commits.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cipherbox_engine::seams::{FloorNamespace, FloorRaise, FloorStore, SeamError, SeamResult};

use crate::fs_util::{
    atomic_write, empty_dir, ensure_dir, keep_first, list_file_names, read_file_opt,
    remove_file_durable, seam_err, to_hex, unique_component,
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
/// distinctly-keyed floors is made crash-consistent by a write-ahead intent
/// record: the whole batch is fsynced under `intent/` before any per-key file
/// moves, and [`open`](Self::open) replays every leftover intent on reopen. The
/// recovery is **roll-forward**, not rollback: an advance interrupted between
/// per-key writes leaves the already-written floors in place and *completes* the
/// rest on the next open (idempotent monotonic-max) — it never rewinds an
/// applied floor. Each commit writes its own uniquely-named intent file, so
/// overlapping commits neither clobber nor remove one another's recovery
/// record.
///
/// Clones share one write lock, so the serialization below holds across every
/// handle rather than only the one that raised.
#[derive(Debug, Clone)]
pub struct FileFloorStore {
    epoch_dir: PathBuf,
    seq_dir: PathBuf,
    intent_dir: PathBuf,
    /// Serializes the read-modify-write in [`Self::raise_floor`]: interleaved
    /// raises can durably regress a floor, and intent replay cannot heal that
    /// loss.
    write_lock: Arc<Mutex<()>>,
}

/// Intent-record tag for an epoch-namespace raise.
const INTENT_TAG_EPOCH: u8 = 0;
/// Intent-record tag for a sequence-namespace raise.
const INTENT_TAG_SEQUENCE: u8 = 1;

impl FileFloorStore {
    /// Opens (creating if absent) a floor store rooted at `dir`. Reopening
    /// the same `dir` yields the same durable floors, replaying any intent
    /// records a crashed batch commit left behind.
    pub fn open(dir: impl AsRef<Path>) -> SeamResult<Self> {
        let dir = dir.as_ref();
        let epoch_dir = dir.join("epoch");
        let seq_dir = dir.join("seq");
        let intent_dir = dir.join("intent");
        ensure_dir(dir).map_err(|err| seam_err("floor_store open root", &err))?;
        ensure_dir(&epoch_dir).map_err(|err| seam_err("floor_store open epoch", &err))?;
        ensure_dir(&seq_dir).map_err(|err| seam_err("floor_store open seq", &err))?;
        ensure_dir(&intent_dir).map_err(|err| seam_err("floor_store open intent", &err))?;
        let store = Self {
            epoch_dir,
            seq_dir,
            intent_dir,
            write_lock: Arc::new(Mutex::new(())),
        };
        store.replay_intents()?;
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
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| SeamError::new(format!("{op}: floor write lock poisoned")))?;
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

    /// Applies a batch of raises to the per-key files, in order.
    fn apply_raises(&self, raises: &[FloorRaise], op: &str) -> SeamResult<()> {
        for r in raises {
            self.raise_floor(self.dir_for(r.namespace), &r.key, r.value, op)?;
        }
        Ok(())
    }

    /// Replays every leftover intent record left by batch commits interrupted
    /// mid-apply, clearing each once reapplied. Monotonic-max makes replay
    /// idempotent and order-independent, so a batch that had partly applied
    /// before the crash simply completes, and multiple pending intents (from
    /// overlapping commits) all heal forward.
    fn replay_intents(&self) -> SeamResult<()> {
        let names = list_file_names(&self.intent_dir)
            .map_err(|err| seam_err("floor_store list intents", &err))?;
        for name in names {
            let path = self.intent_dir.join(&name);
            let Some(bytes) =
                read_file_opt(&path).map_err(|err| seam_err("floor_store read intent", &err))?
            else {
                continue;
            };
            let raises = decode_intent(&bytes)?;
            self.apply_raises(&raises, "floor_store replay intent")?;
            remove_file_durable(&path).map_err(|err| seam_err("floor_store clear intent", &err))?;
        }
        Ok(())
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

    /// Crash-consistent across keys via a write-ahead intent record, roll-forward
    /// (not rollback): the whole batch is fsynced to its own `intent/<unique>`
    /// file first, so an advance interrupted between per-key writes is *completed*
    /// by [`open`](Self::open)'s replay rather than left partial. The unique
    /// filename keeps overlapping commits from clobbering or removing each
    /// other's record. A commit that returns `Ok` has cleared its intent.
    async fn commit_floors(&self, raises: &[FloorRaise]) -> SeamResult<()> {
        if raises.is_empty() {
            return Ok(());
        }
        let intent_path = self.intent_dir.join(unique_component());
        atomic_write(&intent_path, &encode_intent(raises)?)
            .map_err(|err| seam_err("floor_store write intent", &err))?;
        self.apply_raises(raises, "floor_store commit_floors")?;
        remove_file_durable(&intent_path)
            .map_err(|err| seam_err("floor_store clear intent", &err))?;
        Ok(())
    }

    /// Intents go first: a clear interrupted after them has nothing left for
    /// [`open`](Self::open)'s roll-forward replay to re-raise.
    async fn clear(&self) -> SeamResult<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| SeamError::new("floor_store clear: floor write lock poisoned"))?;
        [
            (&self.intent_dir, "floor_store clear intents"),
            (&self.epoch_dir, "floor_store clear epoch"),
            (&self.seq_dir, "floor_store clear seq"),
        ]
        .into_iter()
        .map(|(dir, op)| empty_dir(dir).map_err(|err| seam_err(op, &err)))
        .fold(Ok(()), keep_first)
    }
}

/// The 4-byte little-endian key-length prefix. Fails closed on a key the
/// prefix cannot represent: a truncated length reframes the whole record.
fn intent_key_len(len: u64) -> SeamResult<[u8; 4]> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| SeamError::new("floor_store: intent key exceeds its 4-byte length prefix"))
}

/// Serializes a batch into the intent record: for each raise, a 1-byte
/// namespace tag, a 4-byte little-endian key length, the key bytes, then the
/// 8-byte little-endian value.
fn encode_intent(raises: &[FloorRaise]) -> SeamResult<Vec<u8>> {
    let mut out = Vec::new();
    for raise in raises {
        let tag = match raise.namespace {
            FloorNamespace::Epoch => INTENT_TAG_EPOCH,
            FloorNamespace::Sequence => INTENT_TAG_SEQUENCE,
        };
        out.push(tag);
        out.extend_from_slice(&intent_key_len(raise.key.len() as u64)?);
        out.extend_from_slice(&raise.key);
        out.extend_from_slice(&raise.value.to_le_bytes());
    }
    Ok(out)
}

/// The corruption error surfaced by [`decode_intent`].
fn corrupt_intent() -> SeamError {
    SeamError::new("floor_store: corrupt intent record on disk")
}

/// Reads a fixed slice at `start`, failing closed if it runs past the record.
/// `len` is corrupt-controlled, so `start + len` can wrap `usize` on a 32-bit
/// target.
fn intent_slice(bytes: &[u8], start: usize, len: usize) -> SeamResult<&[u8]> {
    start
        .checked_add(len)
        .and_then(|end| bytes.get(start..end))
        .ok_or_else(corrupt_intent)
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

    /// The whole security argument for `clear` on this store: `open` replays
    /// leftover intents unconditionally, so a sweep that took the floors before
    /// the intents would re-raise every floor in a crashed batch on reopen.
    #[test]
    fn a_cleared_floor_is_not_resurrected_by_a_leftover_intent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("floors");
        let store = FileFloorStore::open(&path).unwrap();
        block_on(store.raise_epoch_floor(b"scope", 9)).unwrap();
        // A batch commit killed mid-apply: its intent is still on the platter.
        let raises = [FloorRaise::epoch(b"scope".to_vec(), 9)];
        atomic_write(
            &path.join("intent").join("crashed"),
            &encode_intent(&raises).unwrap(),
        )
        .unwrap();

        block_on(store.clear()).unwrap();

        let reopened = FileFloorStore::open(&path).unwrap();
        assert_eq!(
            block_on(reopened.epoch_floor(b"scope")).unwrap(),
            None,
            "the replay must have nothing left to re-raise"
        );
    }

    #[test]
    fn intent_round_trips() {
        let raises = vec![
            FloorRaise::epoch(b"scope".to_vec(), 7),
            FloorRaise::sequence(b"k51-name".to_vec(), 42),
            FloorRaise::epoch(Vec::new(), 1),
        ];
        assert_eq!(
            decode_intent(&encode_intent(&raises).unwrap()).unwrap(),
            raises
        );
    }

    #[test]
    fn decode_rejects_an_oversized_key_length() {
        let mut bytes = vec![INTENT_TAG_EPOCH];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_intent(&bytes).is_err());
    }

    #[test]
    fn intent_slice_fails_closed_on_an_overflowing_end() {
        assert!(intent_slice(b"abc", 1, usize::MAX).is_err());
    }

    #[test]
    fn encode_rejects_a_key_longer_than_its_length_prefix() {
        assert!(intent_key_len(u32::MAX as u64).is_ok());
        assert!(intent_key_len(u32::MAX as u64 + 1).is_err());
    }

    #[test]
    fn concurrent_raises_never_regress_a_floor() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileFloorStore::open(dir.path().join("floors")).unwrap();

        for key in 0u64..32 {
            let key = key.to_le_bytes();
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let racers = [2u64, 1].map(|value| {
                    let (store, barrier) = (&store, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        block_on(store.raise_epoch_floor(&key, value)).unwrap()
                    })
                });
                for racer in racers {
                    racer.join().unwrap();
                }
            });
            assert_eq!(
                block_on(store.epoch_floor(&key)).unwrap(),
                Some(2),
                "the low raise must never land on the platter after the high one"
            );
        }
    }

    #[test]
    fn decode_rejects_a_truncated_intent() {
        let bytes = encode_intent(&[FloorRaise::epoch(b"scope".to_vec(), 7)]).unwrap();
        assert!(decode_intent(&bytes[..bytes.len() - 1]).is_err());
    }

    /// A batch commit interrupted mid-apply (intent fsynced, only the first of
    /// two floors on the platter) is completed by reopen — the second floor
    /// lands and the intent clears, so no partial advance survives. This is
    /// the roll-forward recovery contract: reopen *heals forward*, it never
    /// rewinds the floor that already landed.
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
        atomic_write(
            &path.join("intent").join("crashed-commit"),
            &encode_intent(&interrupted).unwrap(),
        )
        .unwrap();

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
            list_file_names(&path.join("intent")).unwrap().is_empty(),
            "reopen must clear the intent record after replay"
        );
    }

    /// Two overlapping commits each leave their own intent file — neither
    /// clobbers nor removes the other's — and reopen replays BOTH, healing every
    /// floor forward. This is the crash-consistency hole a single shared intent
    /// path had: the second commit could overwrite or delete the first's
    /// recovery record.
    #[test]
    fn open_replays_multiple_overlapping_intents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("floors");
        block_on(async {
            FileFloorStore::open(&path).unwrap();
        });

        // Two distinct commits crash with their intents still present and none
        // of their floors yet on the platter (the worst case).
        let first = vec![
            FloorRaise::epoch(b"scope-a".to_vec(), 3),
            FloorRaise::sequence(b"name-a".to_vec(), 7),
        ];
        let second = vec![
            FloorRaise::epoch(b"scope-b".to_vec(), 4),
            FloorRaise::sequence(b"name-b".to_vec(), 9),
        ];
        let intent_dir = path.join("intent");
        atomic_write(
            &intent_dir.join("commit-1"),
            &encode_intent(&first).unwrap(),
        )
        .unwrap();
        atomic_write(
            &intent_dir.join("commit-2"),
            &encode_intent(&second).unwrap(),
        )
        .unwrap();

        block_on(async {
            let reopened = FileFloorStore::open(&path).unwrap();
            assert_eq!(reopened.epoch_floor(b"scope-a").await.unwrap(), Some(3));
            assert_eq!(reopened.sequence_floor(b"name-a").await.unwrap(), Some(7));
            assert_eq!(reopened.epoch_floor(b"scope-b").await.unwrap(), Some(4));
            assert_eq!(reopened.sequence_floor(b"name-b").await.unwrap(), Some(9));
        });
        assert!(
            list_file_names(&intent_dir).unwrap().is_empty(),
            "reopen must clear every replayed intent record"
        );
    }

    /// A corrupt leftover intent on disk fails the whole reopen closed: `open`
    /// surfaces the decode error rather than panicking or silently skipping the
    /// record, so a garbled recovery journal can never be quietly discarded.
    /// This is the crash-recovery fail-closed contract, exercised through the
    /// public `open` surface (not just `decode_intent` in isolation).
    #[test]
    fn open_fails_closed_on_a_corrupt_intent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("floors");
        FileFloorStore::open(&path).unwrap();

        // A valid record truncated by one byte: structurally corrupt, not torn.
        let good = encode_intent(&[FloorRaise::epoch(b"scope".to_vec(), 1)]).unwrap();
        atomic_write(
            &path.join("intent").join("corrupt"),
            &good[..good.len() - 1],
        )
        .unwrap();

        assert!(
            FileFloorStore::open(&path).is_err(),
            "a corrupt intent must fail closed on reopen"
        );
    }

    /// Sequential commits over one handle each mint a distinct intent file and
    /// clean it up, so a successful commit leaves no intent debris behind for a
    /// later reopen to re-apply.
    #[test]
    fn successful_commits_leave_no_intent_debris() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("floors");
        block_on(async {
            let store = FileFloorStore::open(&path).unwrap();
            store
                .commit_floors(&[FloorRaise::epoch(b"scope".to_vec(), 2)])
                .await
                .unwrap();
            store
                .commit_floors(&[FloorRaise::sequence(b"name".to_vec(), 5)])
                .await
                .unwrap();
        });
        assert!(
            list_file_names(&path.join("intent")).unwrap().is_empty(),
            "a returned commit must clear its own intent record"
        );
    }
}
