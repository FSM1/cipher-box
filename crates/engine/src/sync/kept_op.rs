//! The note of a kept op: a published op that stays in the durable queue until
//! it shows from the live root of its write scope (ADR 0069).
//!
//! The note holds the scope root and the write epoch the op published under,
//! and the time of the publish. It names a scope, so the record seals as an
//! owner-local `kept-ops` blob ([`crate::sync::bookkeeping`]).

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::OwnerLocalKind;
use cipherbox_core::suite::x25519::X25519Secret;

use crate::facade::NodeId;
use crate::seams::{OpId, SeamResult, StagingStore, UnixMillis};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::{owner_scoped_key, published_op_mark};
use crate::sync::duration_millis;
use crate::sync::op::OpKind;
use crate::sync::owed_rotation::DROP_BOUND;

/// The staging-key prefix of one identity's kept-op notes
/// ([`crate::sync::owner_scoped_key`]). Kept short: the desktop store spells a
/// key as a hex filename.
pub const KEPT_OP_NOTES_PREFIX: &[u8] = b"cbx/ko/";

/// How long a kept op waits at the write epoch it published under before it
/// leaves the queue (ADR 0069 D5).
pub const KEPT_OP_BOUND: Duration = DROP_BOUND;

/// The body format tag inside the seal.
const NOTE_FORMAT_V1: u8 = 1;

/// One `(op_id, scope flag, scope, write_epoch, published_at)` entry.
const NOTE_ENTRY_LEN: usize = 8 + 1 + 16 + 8 + 8;

/// The write epoch of a kept op with no note: an op the previous release
/// published, or one whose note record is lost. It is below every live write
/// epoch, so the first read of the op's folder at its live name checks the op
/// once, and the bound runs from the first sight (ADR 0069 D6).
const UNKNOWN_WRITE_EPOCH: u64 = 0;

/// What one kept op published under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeptNote {
    /// The scope root the op published under; `None` for a first sight.
    pub(crate) scope: Option<NodeId>,
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
    /// Decode an opened body. A body this build did not write decodes as no
    /// notes, which sends each kept op to one check against the live root.
    fn decode(body: &[u8]) -> Self {
        let Some(entries) = body
            .split_first()
            .filter(|(tag, rest)| **tag == NOTE_FORMAT_V1 && rest.len() % NOTE_ENTRY_LEN == 0)
            .map(|(_, rest)| rest)
        else {
            return Self::default();
        };
        let word = |entry: &[u8], at: usize| {
            u64::from_be_bytes(entry[at..at + 8].try_into().expect("8 bytes"))
        };
        let mut notes = BTreeMap::new();
        for entry in entries.chunks_exact(NOTE_ENTRY_LEN) {
            let scope = match entry[8] {
                0 => None,
                1 => Some(NodeId(entry[9..25].try_into().expect("16 bytes"))),
                _ => return Self::default(),
            };
            notes.insert(
                OpId(word(entry, 0)),
                KeptNote {
                    scope,
                    write_epoch: word(entry, 25),
                    published_at: UnixMillis(word(entry, 33)),
                },
            );
        }
        Self {
            notes,
            dirty: false,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.notes.len() * NOTE_ENTRY_LEN);
        bytes.push(NOTE_FORMAT_V1);
        for (op_id, note) in &self.notes {
            bytes.extend_from_slice(&op_id.0.to_be_bytes());
            bytes.push(u8::from(note.scope.is_some()));
            bytes.extend_from_slice(&note.scope.map_or([0; 16], |scope| scope.0));
            bytes.extend_from_slice(&note.write_epoch.to_be_bytes());
            bytes.extend_from_slice(&note.published_at.0.to_be_bytes());
        }
        bytes
    }

    /// Whether `op_id` has a note: its last record confirmed, whatever the
    /// published-op mark says (ADR 0069 D4).
    pub(crate) fn holds(&self, op_id: OpId) -> bool {
        self.notes.contains_key(&op_id)
    }

    #[cfg(test)]
    fn get(&self, op_id: OpId) -> Option<KeptNote> {
        self.notes.get(&op_id).copied()
    }

    /// The note of `op_id` as a pass reads it at `now`: a new one at
    /// [`UNKNOWN_WRITE_EPOCH`] for an op with none, and a publish time past
    /// `now` pulled back to `now`, so a clock step neither holds the op longer
    /// than the bound nor leaves it in the queue for ever.
    pub(crate) fn note_at(&mut self, op_id: OpId, now: UnixMillis) -> KeptNote {
        let note = self.notes.entry(op_id).or_insert(KeptNote {
            scope: None,
            write_epoch: UNKNOWN_WRITE_EPOCH,
            published_at: UnixMillis(u64::MAX),
        });
        if note.published_at > now {
            note.published_at = now;
            self.dirty = true;
        }
        *note
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
}

/// This identity's notes. A record that does not open reads as no notes.
pub(crate) async fn load_kept_notes<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
) -> SeamResult<KeptNotes> {
    let stored = staging
        .staged_bytes(&owner_scoped_key(KEPT_OP_NOTES_PREFIX, enc_secret))
        .await?;
    Ok(stored
        .and_then(|blob| seal.open(OwnerLocalKind::KeptOps, &blob))
        .map(|body| KeptNotes::decode(&body))
        .unwrap_or_default())
}

/// Write `notes` back when a pass changed them.
pub(crate) async fn store_kept_notes<St: StagingStore>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    notes: &KeptNotes,
) -> SeamResult<()> {
    if !notes.is_dirty() {
        return Ok(());
    }
    let key = owner_scoped_key(KEPT_OP_NOTES_PREFIX, enc_secret);
    if notes.notes.is_empty() {
        return staging.remove_staged_bytes(&key).await;
    }
    let blob = seal.seal(OwnerLocalKind::KeptOps, &notes.encode())?;
    staging.put_staged_bytes(&key, &blob).await
}

/// Whether an op of `kind` stays queued after its publish. The live tree can
/// show whether a create, a delete or a content edit landed; it cannot show
/// whether a later writer overtook a rename, a move or a history edit, so a
/// second apply of those could undo the later write (ADR 0069 D2).
pub(crate) fn keeps(kind: &OpKind) -> bool {
    matches!(
        kind,
        OpKind::Create { .. } | OpKind::Delete { .. } | OpKind::UpdateContent { .. }
    )
}

/// Whether `op_id` is a kept op: at or below the published-op mark, or noted.
pub(crate) fn is_kept(op_id: OpId, published_mark: Option<u64>, notes: &KeptNotes) -> bool {
    published_mark.is_some_and(|mark| op_id.0 <= mark) || notes.holds(op_id)
}

/// Drop the kept ops from `ops`, leaving the pending ones (ADR 0069 D7).
pub(crate) async fn retain_pending<St: StagingStore, T>(
    staging: &St,
    seal: BookkeepingSeal<'_>,
    enc_secret: &X25519Secret,
    ops: &mut Vec<(OpId, T)>,
) -> SeamResult<()> {
    let mark = published_op_mark(staging, enc_secret).await?;
    let notes = load_kept_notes(staging, seal, enc_secret).await?;
    ops.retain(|(op_id, _)| !is_kept(*op_id, mark, &notes));
    Ok(())
}

/// Where a kept op's write scope stands for the pass that reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptPlace {
    /// The pass writes the op's scope, rooted at `root`, whose write-epoch
    /// floor is `live_write_epoch`. `anchor_read_live` says the base read the
    /// folder the op writes under at its name of that epoch: only such a read
    /// can show the op from the live root.
    Writes {
        root: NodeId,
        live_write_epoch: u64,
        anchor_read_live: bool,
    },
    /// The op's scope, rooted at `root`, is a proved root that this device
    /// holds no write seed for: a revoke or a downgrade took it. The op does
    /// not apply again: the pass takes it out before the rebase, and the valve
    /// charges it on the keyless charge until it dead-letters (ADR 0069 D3).
    Keyless { root: NodeId },
    /// This pass cannot check the op at `root`: the boundary walk did not
    /// prove it, a gate-refused one included, or another pass writes it.
    /// `live_write_epoch` is its durable write-epoch floor. Only the root the
    /// op published under, at no higher floor than its note's, is no flip and
    /// runs the bound; a flip waits with no bound for a pass that can check it
    /// (ADR 0069 D5).
    Unchecked { root: NodeId, live_write_epoch: u64 },
    /// Another pass, or none this tick, answers for the op's scope.
    Elsewhere,
}

/// What a pass does with one kept op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeptVerdict {
    /// It waits in the queue, out of this pass.
    Stay,
    /// It joins this pass, and the rebase onto the live tree decides: a landed
    /// op drops, a lost one applies again (ADR 0069 D3, D6). See
    /// [`KeptPlace::Keyless`] for an op under a keyless scope.
    Recheck,
    /// It waited out [`KEPT_OP_BOUND`] at its write epoch, and leaves.
    Expired,
}

/// The verdict on one kept op at `now`. A new write epoch, or a scope root
/// other than the one the op published under, is a flip. A flip waits for the
/// read of the folder at its new name and does not expire.
pub(crate) fn kept_verdict(note: KeptNote, place: KeptPlace, now: UnixMillis) -> KeptVerdict {
    match place {
        KeptPlace::Keyless { .. } => return KeptVerdict::Recheck,
        KeptPlace::Writes {
            root,
            live_write_epoch,
            anchor_read_live,
        } if live_write_epoch > note.write_epoch
            || note.scope.is_some_and(|scope| scope != root) =>
        {
            return if anchor_read_live {
                KeptVerdict::Recheck
            } else {
                KeptVerdict::Stay
            };
        }
        KeptPlace::Unchecked {
            root,
            live_write_epoch,
        } if note.scope != Some(root) || live_write_epoch > note.write_epoch => {
            return KeptVerdict::Stay;
        }
        KeptPlace::Writes { .. } | KeptPlace::Unchecked { .. } | KeptPlace::Elsewhere => {}
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
    const SCOPE: NodeId = NodeId([5; 16]);

    fn note(write_epoch: u64) -> KeptNote {
        KeptNote {
            scope: Some(SCOPE),
            write_epoch,
            published_at: PUBLISHED,
        }
    }

    fn at(after_publish: Duration) -> UnixMillis {
        PUBLISHED.saturating_add(after_publish)
    }

    fn here(live_write_epoch: u64, anchor_read_live: bool) -> KeptPlace {
        KeptPlace::Writes {
            root: SCOPE,
            live_write_epoch,
            anchor_read_live,
        }
    }

    const JUST_BEFORE: Duration = KEPT_OP_BOUND.saturating_sub(Duration::from_millis(1));

    #[test]
    fn an_op_waits_at_its_write_epoch_until_the_bound_and_then_leaves() {
        assert_eq!(
            kept_verdict(note(2), here(2, true), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(note(2), here(2, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn a_new_write_epoch_sends_the_op_to_the_rebase_before_the_bound() {
        assert_eq!(
            kept_verdict(note(2), here(3, true), at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(note(2), here(3, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Recheck,
            "a flip seen after the bound still applies the op again"
        );
    }

    #[test]
    fn a_new_scope_root_at_the_same_epoch_is_a_flip() {
        let new_scope = KeptPlace::Writes {
            root: NodeId([6; 16]),
            live_write_epoch: 2,
            anchor_read_live: true,
        };
        assert_eq!(
            kept_verdict(note(2), new_scope, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
    }

    #[test]
    fn a_flip_waits_for_a_read_of_the_folder_at_its_new_name_and_does_not_expire() {
        assert_eq!(
            kept_verdict(note(2), here(3, false), at(Duration::ZERO)),
            KeptVerdict::Stay,
            "a read from before the flip still shows the lost write"
        );
        assert_eq!(
            kept_verdict(note(2), here(3, false), at(KEPT_OP_BOUND * 2)),
            KeptVerdict::Stay,
            "a device offline past the bound keeps the write for its first live read"
        );
    }

    #[test]
    fn a_scope_the_device_can_no_longer_write_sends_the_op_to_the_pass() {
        let keyless = KeptPlace::Keyless { root: SCOPE };
        assert_eq!(
            kept_verdict(note(2), keyless, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(note(2), keyless, at(KEPT_OP_BOUND)),
            KeptVerdict::Recheck,
            "the pass, not the bound, decides"
        );
    }

    #[test]
    fn an_unchecked_root_at_the_notes_epoch_waits_out_the_bound() {
        let unproved = KeptPlace::Unchecked {
            root: SCOPE,
            live_write_epoch: 2,
        };
        assert_eq!(
            kept_verdict(note(2), unproved, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(note(2), unproved, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn an_unchecked_root_past_a_cut_keeps_the_op_past_the_bound() {
        let cut = KeptPlace::Unchecked {
            root: SCOPE,
            live_write_epoch: 3,
        };
        let other_root = KeptPlace::Unchecked {
            root: NodeId([6; 16]),
            live_write_epoch: 2,
        };
        for place in [cut, other_root] {
            assert_eq!(
                kept_verdict(note(2), place, at(KEPT_OP_BOUND * 2)),
                KeptVerdict::Stay,
                "{place:?}"
            );
        }
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
        let first = notes.note_at(OpId(3), PUBLISHED);
        assert!(notes.is_dirty(), "the first sight is recorded");
        assert_eq!(
            kept_verdict(first, here(GENESIS_EPOCH, true), PUBLISHED),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(first, here(GENESIS_EPOCH, false), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(first, KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired,
            "the bound runs from the first sight"
        );
        assert_eq!(
            notes.note_at(OpId(3), at(KEPT_OP_BOUND)),
            first,
            "a later sight keeps the first"
        );
    }

    #[test]
    fn a_publish_time_past_now_is_pulled_back_to_now() {
        let mut notes = KeptNotes::default();
        let far = UnixMillis(u64::MAX / 2);
        notes.insert(
            OpId(1),
            KeptNote {
                published_at: far,
                ..note(2)
            },
        );
        let read = notes.note_at(OpId(1), PUBLISHED);
        assert_eq!(read.published_at, PUBLISHED, "a far-future note");
        assert_eq!(
            kept_verdict(read, here(2, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Expired,
            "the bound then runs from the read"
        );

        notes.insert(OpId(2), note(2));
        let before = UnixMillis(PUBLISHED.0 - 500);
        assert_eq!(
            notes.note_at(OpId(2), before).published_at,
            before,
            "a backward clock step"
        );
    }

    #[test]
    fn notes_round_trip_and_foreign_bytes_read_as_none() {
        let mut notes = KeptNotes::default();
        notes.insert(OpId(7), note(3));
        notes.insert(
            OpId(4),
            KeptNote {
                scope: None,
                write_epoch: 1,
                published_at: UnixMillis(2),
            },
        );
        let bytes = notes.encode();
        let decoded = KeptNotes::decode(&bytes);
        assert_eq!(decoded.get(OpId(7)), notes.get(OpId(7)));
        assert_eq!(decoded.get(OpId(4)), notes.get(OpId(4)));

        assert!(!KeptNotes::decode(&bytes[..bytes.len() - 1]).holds(OpId(7)));
        let mut foreign = bytes.clone();
        foreign[0] = NOTE_FORMAT_V1 + 1;
        assert!(!KeptNotes::decode(&foreign).holds(OpId(7)));
        let mut bad_flag = bytes;
        bad_flag[9] = 2;
        assert!(!KeptNotes::decode(&bad_flag).holds(OpId(7)));
    }
}
