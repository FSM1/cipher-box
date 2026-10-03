//! The note of a kept op: a published op that stays in the durable queue until
//! it shows from the live root of its write scope (ADR 0069).
//!
//! The note holds the write epoch the op published under and the time of the
//! publish. An op id, an epoch and a timestamp associate no two identifiers, so
//! the record stays clear, as the op-id marks do
//! ([`crate::sync::bookkeeping`]).

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use crate::seams::{OpId, UnixMillis};
use crate::sync::duration_millis;
use crate::sync::owed_rotation::DROP_BOUND;

/// The staging-key prefix of one identity's kept-op notes
/// ([`crate::sync::owner_scoped_key`]). Kept short: the desktop store spells a
/// key as a hex filename.
pub const KEPT_OP_NOTES_PREFIX: &[u8] = b"cbx/ko/";

/// How long a kept op waits at the write epoch it published under before it
/// leaves the queue (ADR 0069 D5).
pub const KEPT_OP_BOUND: Duration = DROP_BOUND;

/// The record format tag. Bytes that merely happen to be the right length must
/// not read as notes.
const NOTE_FORMAT_V1: u8 = 1;

/// One `(op_id, write_epoch, published_at)` triple.
const NOTE_ENTRY_LEN: usize = 24;

/// The write epoch of a kept op with no note: an op the previous release
/// published, or one whose note record is lost. It is below every live write
/// epoch, so the first read of the op's folder at its live name checks the op
/// once, and the bound runs from the first sight (ADR 0069 D6).
const UNKNOWN_WRITE_EPOCH: u64 = 0;

/// What one kept op published under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeptNote {
    pub(crate) write_epoch: u64,
    pub(crate) published_at: UnixMillis,
}

/// Every kept-op note of one identity.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct KeptNotes {
    notes: BTreeMap<OpId, KeptNote>,
    dirty: bool,
}

impl KeptNotes {
    /// Decode the stored notes. Bytes this build did not write decode as no
    /// notes, which sends each kept op to one check against the live root.
    pub(crate) fn decode(stored: Option<&[u8]>) -> Self {
        let Some(bytes) = stored.filter(|bytes| {
            bytes.first() == Some(&NOTE_FORMAT_V1) && bytes.len() % NOTE_ENTRY_LEN == 1
        }) else {
            return Self::default();
        };
        let word = |entry: &[u8], at: usize| {
            u64::from_be_bytes(entry[at..at + 8].try_into().expect("8 bytes"))
        };
        Self {
            notes: bytes[1..]
                .chunks_exact(NOTE_ENTRY_LEN)
                .map(|entry| {
                    (
                        OpId(word(entry, 0)),
                        KeptNote {
                            write_epoch: word(entry, 8),
                            published_at: UnixMillis(word(entry, 16)),
                        },
                    )
                })
                .collect(),
            dirty: false,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.notes.len() * NOTE_ENTRY_LEN);
        bytes.push(NOTE_FORMAT_V1);
        for (op_id, note) in &self.notes {
            bytes.extend_from_slice(&op_id.0.to_be_bytes());
            bytes.extend_from_slice(&note.write_epoch.to_be_bytes());
            bytes.extend_from_slice(&note.published_at.0.to_be_bytes());
        }
        bytes
    }

    #[cfg(test)]
    fn get(&self, op_id: OpId) -> Option<KeptNote> {
        self.notes.get(&op_id).copied()
    }

    /// The note of `op_id`, or a new one at [`UNKNOWN_WRITE_EPOCH`] and `now`.
    pub(crate) fn note_or_first_sight(&mut self, op_id: OpId, now: UnixMillis) -> KeptNote {
        *self.notes.entry(op_id).or_insert_with(|| {
            self.dirty = true;
            KeptNote {
                write_epoch: UNKNOWN_WRITE_EPOCH,
                published_at: now,
            }
        })
    }

    pub(crate) fn insert(&mut self, op_id: OpId, note: KeptNote) {
        if self.notes.insert(op_id, note) != Some(note) {
            self.dirty = true;
        }
    }

    pub(crate) fn remove(&mut self, op_id: OpId) {
        if self.notes.remove(&op_id).is_some() {
            self.dirty = true;
        }
    }

    /// Drop the notes of ops that left the queue.
    pub(crate) fn retain_queued(&mut self, queued: &BTreeSet<OpId>) {
        let before = self.notes.len();
        self.notes.retain(|op_id, _| queued.contains(op_id));
        self.dirty |= self.notes.len() != before;
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }
}

/// Where a kept op's write scope stands for the pass that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptPlace {
    /// The pass writes the op's scope, whose write-epoch floor is
    /// `live_write_epoch`. `anchor_read_live` says the base read the folder the
    /// op writes under at its name of that epoch: only such a read can show
    /// the op from the live root.
    Writes {
        live_write_epoch: u64,
        anchor_read_live: bool,
    },
    /// The op's scope is a proved root that this device holds no write seed
    /// for: a revoke or a downgrade took it.
    Keyless,
    /// Another pass, or none this tick, answers for the op's scope.
    Elsewhere,
}

/// What a pass does with one kept op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptVerdict {
    /// It waits in the queue, out of this pass.
    Stay,
    /// It joins this pass, and the rebase onto the live tree decides: a landed
    /// op drops, a lost one applies again (ADR 0069 D3, D6).
    Recheck,
    /// It waited out [`KEPT_OP_BOUND`] at its write epoch, and leaves.
    Expired,
}

/// The verdict on one kept op at `now`.
pub(crate) fn kept_verdict(note: KeptNote, place: KeptPlace, now: UnixMillis) -> KeptVerdict {
    match place {
        KeptPlace::Keyless => return KeptVerdict::Recheck,
        KeptPlace::Writes {
            live_write_epoch,
            anchor_read_live: true,
        } if live_write_epoch > note.write_epoch => return KeptVerdict::Recheck,
        KeptPlace::Writes { .. } | KeptPlace::Elsewhere => {}
    }
    if now.0.saturating_sub(note.published_at.0) >= duration_millis(KEPT_OP_BOUND) {
        KeptVerdict::Expired
    } else {
        KeptVerdict::Stay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::provision::GENESIS_EPOCH;

    const PUBLISHED: UnixMillis = UnixMillis(1_000);

    fn note(write_epoch: u64) -> KeptNote {
        KeptNote {
            write_epoch,
            published_at: PUBLISHED,
        }
    }

    fn at(after_publish: Duration) -> UnixMillis {
        PUBLISHED.saturating_add(after_publish)
    }

    const JUST_BEFORE: Duration = KEPT_OP_BOUND.saturating_sub(Duration::from_millis(1));

    #[test]
    fn an_op_waits_at_its_write_epoch_until_the_bound_and_then_leaves() {
        let here = KeptPlace::Writes {
            live_write_epoch: 2,
            anchor_read_live: true,
        };
        assert_eq!(
            kept_verdict(note(2), here, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(note(2), here, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn a_new_write_epoch_sends_the_op_to_the_rebase_before_the_bound() {
        let flipped = KeptPlace::Writes {
            live_write_epoch: 3,
            anchor_read_live: true,
        };
        assert_eq!(
            kept_verdict(note(2), flipped, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(note(2), flipped, at(KEPT_OP_BOUND)),
            KeptVerdict::Recheck,
            "a flip seen after the bound still applies the op again"
        );
    }

    #[test]
    fn a_flip_waits_for_a_read_of_the_folder_at_its_new_name() {
        let stale = KeptPlace::Writes {
            live_write_epoch: 3,
            anchor_read_live: false,
        };
        assert_eq!(
            kept_verdict(note(2), stale, at(Duration::ZERO)),
            KeptVerdict::Stay,
            "a read from before the flip still shows the lost write"
        );
    }

    #[test]
    fn a_scope_the_device_can_no_longer_write_sends_the_op_to_the_rebase() {
        assert_eq!(
            kept_verdict(note(2), KeptPlace::Keyless, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
    }

    #[test]
    fn another_pass_leaves_the_op_alone_until_the_bound() {
        assert_eq!(
            kept_verdict(note(2), KeptPlace::Elsewhere, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(note(2), KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn an_op_with_no_note_gets_one_check_at_the_first_live_read_of_its_folder() {
        let mut notes = KeptNotes::default();
        let first = notes.note_or_first_sight(OpId(3), PUBLISHED);
        assert!(notes.is_dirty(), "the first sight is recorded");
        let here = |anchor_read_live| KeptPlace::Writes {
            live_write_epoch: GENESIS_EPOCH,
            anchor_read_live,
        };
        assert_eq!(
            kept_verdict(first, here(true), PUBLISHED),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(first, here(false), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(first, KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired,
            "the bound runs from the first sight"
        );
        assert_eq!(
            notes.note_or_first_sight(OpId(3), at(KEPT_OP_BOUND)),
            first,
            "a later sight keeps the first"
        );
    }

    #[test]
    fn notes_round_trip_and_foreign_bytes_read_as_none() {
        let mut notes = KeptNotes::default();
        notes.insert(
            OpId(7),
            KeptNote {
                write_epoch: 3,
                published_at: UnixMillis(9),
            },
        );
        notes.insert(
            OpId(4),
            KeptNote {
                write_epoch: 1,
                published_at: UnixMillis(2),
            },
        );
        let bytes = notes.encode();
        let decoded = KeptNotes::decode(Some(&bytes));
        assert_eq!(decoded.get(OpId(7)), notes.get(OpId(7)));
        assert_eq!(decoded.get(OpId(4)), notes.get(OpId(4)));

        assert!(KeptNotes::decode(Some(&bytes[..bytes.len() - 1])).is_empty());
        let mut foreign = bytes.clone();
        foreign[0] = NOTE_FORMAT_V1 + 1;
        assert!(KeptNotes::decode(Some(&foreign)).is_empty());
        assert!(KeptNotes::decode(None).is_empty());
    }
}
