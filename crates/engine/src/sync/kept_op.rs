//! The note of a kept op: a published op that stays in the durable queue until
//! it shows from the live root of its write scope (ADR 0069).
//!
//! The note holds the scope root and the write epoch the op published under,
//! the time of the publish, the folder the op wrote under, and the result of
//! the op. It names a scope and plaintext names, so the record seals as an
//! owner-local `kept-ops` blob ([`crate::sync::bookkeeping`]).

use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::content::CONTENT_CID_LEN;
use cipherbox_core::seal::OwnerLocalKind;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::name::MAX_NODE_NAME_BYTES;
use crate::seams::{OpId, SeamError, SeamResult, StagingStore, UnixMillis};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::{PUBLISHED_OP_MARK_PREFIX, owner_scoped_key, published_op_mark};
use crate::sync::duration_millis;
use crate::sync::op::{Op, OpKind};
use crate::sync::owed_rotation::DROP_BOUND;

/// The staging-key prefix of one identity's kept-op notes
/// ([`crate::sync::owner_scoped_key`]). Kept short: the desktop store spells a
/// key as a hex filename.
pub const KEPT_OP_NOTES_PREFIX: &[u8] = b"cbx/ko/";

/// How long a kept op waits at the write epoch it published under before it
/// leaves the queue (ADR 0069 D5).
pub const KEPT_OP_BOUND: Duration = DROP_BOUND;

/// The body format tags inside the seal. This build reads both and writes
/// version 2; a release that reads only version 1 reads a version 2 body as
/// no notes (ADR 0020).
const NOTE_FORMAT_V1: u8 = 1;
const NOTE_FORMAT_V2: u8 = 2;

// The longest version 2 entry, the fixed fields and a move with two names at
// the bound, fits its two-byte length.
const _: () =
    assert!(8 + 17 + 16 + 17 + 1 + 2 * (16 + 2 + MAX_NODE_NAME_BYTES) <= u16::MAX as usize);

/// The result tags of a version 2 entry.
const RESULT_NONE: u8 = 0;
const RESULT_RENAME: u8 = 1;
const RESULT_MOVE: u8 = 2;
const RESULT_RESTORE_VERSION: u8 = 3;

/// The write epoch of a kept op with no note: an op the previous release
/// published, or one whose note record is lost. It is below every live write
/// epoch, so the first read of the op's folder at its live name checks the op
/// once, and the bound runs from the first sight (ADR 0069 D6).
const UNKNOWN_WRITE_EPOCH: u64 = 0;

/// What one kept op published under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptNote {
    /// The scope root the op published under; `None` for a first sight.
    pub scope: Option<NodeId>,
    /// The write epoch of that scope at the publish.
    pub write_epoch: u64,
    /// The time of the publish.
    pub published_at: UnixMillis,
    /// The folder the op wrote under: the parent of a created, edited or
    /// renamed node, the folder a delete unlinked the node from, the source
    /// parent of a move. `None` in a version 1 note.
    pub parent: Option<NodeId>,
    /// The value before and after the op, for a kind whose live node alone
    /// cannot show that it landed.
    pub result: Option<KeptResult>,
}

/// The value before and after one op.
#[derive(Clone, PartialEq, Eq)]
pub enum KeptResult {
    /// A rename.
    Rename {
        /// The name before.
        before: Zeroizing<String>,
        /// The name after.
        after: Zeroizing<String>,
    },
    /// A move or a relink.
    Move {
        /// The parent before.
        from: NodeId,
        /// The name before.
        from_name: Zeroizing<String>,
        /// The parent after.
        to: NodeId,
        /// The name after.
        to_name: Zeroizing<String>,
    },
    /// A version restore.
    RestoreVersion {
        /// The head content CID before.
        before: Vec<u8>,
        /// The restored content CID.
        after: Vec<u8>,
    },
}

/// A name is plaintext, so it never reaches a log.
impl fmt::Debug for KeptResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rename { .. } => f.write_str("Rename"),
            Self::Move { from, to, .. } => f
                .debug_struct("Move")
                .field("from", from)
                .field("to", to)
                .finish_non_exhaustive(),
            Self::RestoreVersion { .. } => f.write_str("RestoreVersion"),
        }
    }
}

/// Why a note does not encode: each is an entry the decoder refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptNoteError {
    /// A name longer than [`MAX_NODE_NAME_BYTES`].
    NameTooLong,
    /// A content CID longer than [`CONTENT_CID_LEN`].
    CidTooLong,
    /// An entry longer than its two-byte length can state.
    EntryTooLong,
}

fn check_name(name: &str) -> Result<(), KeptNoteError> {
    if name.len() > MAX_NODE_NAME_BYTES {
        return Err(KeptNoteError::NameTooLong);
    }
    Ok(())
}

fn check_cid(cid: &[u8]) -> Result<(), KeptNoteError> {
    if cid.len() > CONTENT_CID_LEN {
        return Err(KeptNoteError::CidTooLong);
    }
    Ok(())
}

impl KeptNote {
    /// The bounds [`KeptNotes::decode`] holds each entry to.
    fn check(&self) -> Result<(), KeptNoteError> {
        match &self.result {
            None => Ok(()),
            Some(KeptResult::Rename { before, after }) => {
                check_name(before).and_then(|()| check_name(after))
            }
            Some(KeptResult::Move {
                from_name, to_name, ..
            }) => check_name(from_name).and_then(|()| check_name(to_name)),
            Some(KeptResult::RestoreVersion { before, after }) => {
                check_cid(before).and_then(|()| check_cid(after))
            }
        }
    }
}

/// Every kept-op note of one identity.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KeptNotes {
    notes: BTreeMap<OpId, KeptNote>,
    dirty: bool,
}

/// A reader over an opened body. A read past the end is `None`.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn word(&mut self) -> Option<u64> {
        self.take(8)?.try_into().ok().map(u64::from_be_bytes)
    }

    fn length(&mut self) -> Option<usize> {
        self.take(2)?
            .try_into()
            .ok()
            .map(|len| usize::from(u16::from_be_bytes(len)))
    }

    fn node(&mut self) -> Option<NodeId> {
        self.take(16)?.try_into().ok().map(NodeId)
    }

    /// A 0/1 flag, then a node when the flag is 1.
    fn optional_node(&mut self) -> Option<Option<NodeId>> {
        match self.byte()? {
            0 => Some(None),
            1 => self.node().map(Some),
            _ => None,
        }
    }

    fn name(&mut self) -> Option<Zeroizing<String>> {
        let len = self.length()?;
        let name = std::str::from_utf8(self.take(len)?).ok()?;
        check_name(name).ok()?;
        Some(Zeroizing::new(name.to_owned()))
    }

    fn cid(&mut self) -> Option<Vec<u8>> {
        let len = usize::from(self.byte()?);
        let cid = self.take(len)?;
        check_cid(cid).ok()?;
        Some(cid.to_vec())
    }

    fn result(&mut self) -> Option<Option<KeptResult>> {
        let result = match self.byte()? {
            RESULT_NONE => return Some(None),
            RESULT_RENAME => KeptResult::Rename {
                before: self.name()?,
                after: self.name()?,
            },
            RESULT_MOVE => KeptResult::Move {
                from: self.node()?,
                from_name: self.name()?,
                to: self.node()?,
                to_name: self.name()?,
            },
            RESULT_RESTORE_VERSION => KeptResult::RestoreVersion {
                before: self.cid()?,
                after: self.cid()?,
            },
            _ => return None,
        };
        Some(Some(result))
    }

    /// One fixed 41-byte version 1 entry: the op id, a scope flag, the scope
    /// root, the write epoch and the publish time. It reads with no parent and
    /// no result, the value the version 1 build used (ADR 0020 D2).
    fn v1_entry(&mut self) -> Option<(OpId, KeptNote)> {
        let op_id = OpId(self.word()?);
        let flag = self.byte()?;
        let scope = self.node()?;
        let scope = match flag {
            0 => None,
            1 => Some(scope),
            _ => return None,
        };
        let note = KeptNote {
            scope,
            write_epoch: self.word()?,
            published_at: UnixMillis(self.word()?),
            parent: None,
            result: None,
        };
        Some((op_id, note))
    }

    /// One version 2 entry: a two-byte length, then exactly that many bytes.
    /// Each entry is self-delimiting, so a later format can append a field
    /// to an entry and still read this one.
    fn v2_entry(&mut self) -> Option<(OpId, KeptNote)> {
        let len = self.length()?;
        let mut entry = Cursor(self.take(len)?);
        let op_id = OpId(entry.word()?);
        let note = KeptNote {
            scope: entry.optional_node()?,
            write_epoch: entry.word()?,
            published_at: UnixMillis(entry.word()?),
            parent: entry.optional_node()?,
            result: entry.result()?,
        };
        entry.0.is_empty().then_some((op_id, note))
    }
}

fn put_optional_node(bytes: &mut Vec<u8>, node: Option<NodeId>) {
    bytes.push(u8::from(node.is_some()));
    if let Some(node) = node {
        bytes.extend_from_slice(&node.0);
    }
}

/// `len` as a two-byte length; `None` past `u16::MAX`.
fn put_length(bytes: &mut Vec<u8>, len: usize) -> Option<()> {
    bytes.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
    Some(())
}

fn put_name(bytes: &mut Vec<u8>, name: &str) -> Result<(), KeptNoteError> {
    check_name(name)?;
    put_length(bytes, name.len()).ok_or(KeptNoteError::NameTooLong)?;
    bytes.extend_from_slice(name.as_bytes());
    Ok(())
}

fn put_cid(bytes: &mut Vec<u8>, cid: &[u8]) -> Result<(), KeptNoteError> {
    check_cid(cid)?;
    bytes.push(u8::try_from(cid.len()).map_err(|_| KeptNoteError::CidTooLong)?);
    bytes.extend_from_slice(cid);
    Ok(())
}

/// One version 2 entry, without its length.
fn encode_entry(op_id: OpId, note: &KeptNote) -> Result<Zeroizing<Vec<u8>>, KeptNoteError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(&op_id.0.to_be_bytes());
    put_optional_node(&mut bytes, note.scope);
    bytes.extend_from_slice(&note.write_epoch.to_be_bytes());
    bytes.extend_from_slice(&note.published_at.0.to_be_bytes());
    put_optional_node(&mut bytes, note.parent);
    match &note.result {
        None => bytes.push(RESULT_NONE),
        Some(KeptResult::Rename { before, after }) => {
            bytes.push(RESULT_RENAME);
            put_name(&mut bytes, before)?;
            put_name(&mut bytes, after)?;
        }
        Some(KeptResult::Move {
            from,
            from_name,
            to,
            to_name,
        }) => {
            bytes.push(RESULT_MOVE);
            bytes.extend_from_slice(&from.0);
            put_name(&mut bytes, from_name)?;
            bytes.extend_from_slice(&to.0);
            put_name(&mut bytes, to_name)?;
        }
        Some(KeptResult::RestoreVersion { before, after }) => {
            bytes.push(RESULT_RESTORE_VERSION);
            put_cid(&mut bytes, before)?;
            put_cid(&mut bytes, after)?;
        }
    }
    Ok(bytes)
}

impl KeptNotes {
    /// Decode an opened body. A body this build did not write decodes as no
    /// notes, which sends each kept op to one check against the live root.
    /// A body that breaks a bound in any part decodes as no notes too.
    fn decode(body: &[u8]) -> Self {
        let Some((&tag, entries)) = body.split_first() else {
            return Self::default();
        };
        let mut cursor = Cursor(entries);
        let mut notes = BTreeMap::new();
        while !cursor.0.is_empty() {
            let entry = match tag {
                NOTE_FORMAT_V1 => cursor.v1_entry(),
                NOTE_FORMAT_V2 => cursor.v2_entry(),
                _ => None,
            };
            let Some((op_id, note)) = entry else {
                return Self::default();
            };
            if notes.insert(op_id, note).is_some() {
                return Self::default();
            }
        }
        Self {
            notes,
            dirty: false,
        }
    }

    /// The version 2 body. [`Self::insert`] refused each note the decoder
    /// refuses; the bounds are checked again here, so no body leaves that
    /// its own decoder reads as no notes.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, KeptNoteError> {
        let mut bytes = Zeroizing::new(vec![NOTE_FORMAT_V2]);
        for (op_id, note) in &self.notes {
            let entry = encode_entry(*op_id, note)?;
            put_length(&mut bytes, entry.len()).ok_or(KeptNoteError::EntryTooLong)?;
            bytes.extend_from_slice(&entry);
        }
        Ok(bytes)
    }

    /// Whether `op_id` has a note: its last record confirmed, whatever the
    /// published-op mark says (ADR 0069 D4).
    pub(crate) fn holds(&self, op_id: OpId) -> bool {
        self.notes.contains_key(&op_id)
    }

    #[cfg(test)]
    fn get(&self, op_id: OpId) -> Option<KeptNote> {
        self.notes.get(&op_id).cloned()
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
            parent: None,
            result: None,
        });
        if note.published_at > now {
            note.published_at = now;
            self.dirty = true;
        }
        note.clone()
    }

    /// Note `op_id`. A note the decoder refuses is refused here, so one bad
    /// note never stops the others from being written.
    pub fn insert(&mut self, op_id: OpId, note: KeptNote) -> Result<(), KeptNoteError> {
        note.check()?;
        if self.notes.get(&op_id) != Some(&note) {
            self.notes.insert(op_id, note);
            self.dirty = true;
        }
        Ok(())
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
    let body = notes
        .encode()
        .map_err(|error| SeamError::new(format!("kept-op notes refused: {error:?}")))?;
    let blob = seal.seal(OwnerLocalKind::KeptOps, &body)?;
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

/// Whether `staging_key` holds an identity's published-op mark or kept-op notes.
pub(crate) fn is_kept_op_key(staging_key: &[u8]) -> bool {
    staging_key.starts_with(PUBLISHED_OP_MARK_PREFIX)
        || staging_key.starts_with(KEPT_OP_NOTES_PREFIX)
}

/// Whether `op_id` is a kept op: at or below the published-op mark, or noted.
pub(crate) fn is_kept(op_id: OpId, published_mark: Option<u64>, notes: &KeptNotes) -> bool {
    published_mark.is_some_and(|mark| op_id.0 <= mark) || notes.holds(op_id)
}

/// The published-op mark and the notes of one identity, read once for a pass.
pub(crate) struct KeptOps {
    mark: Option<u64>,
    notes: KeptNotes,
}

impl KeptOps {
    pub(crate) fn new(mark: Option<u64>, notes: KeptNotes) -> Self {
        Self { mark, notes }
    }

    /// Whether `op` is a kept op ([`is_kept`], [`keeps`]).
    pub(crate) fn holds(&self, op_id: OpId, op: &Op) -> bool {
        keeps(&op.kind) && is_kept(op_id, self.mark, &self.notes)
    }

    /// The folder the note of `op_id` names.
    pub(crate) fn parent(&self, op_id: OpId) -> Option<NodeId> {
        self.notes.notes.get(&op_id).and_then(|note| note.parent)
    }

    /// The scope root the note of `op_id` names.
    pub(crate) fn scope(&self, op_id: OpId) -> Option<NodeId> {
        self.notes.notes.get(&op_id).and_then(|note| note.scope)
    }
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
    /// As [`Self::Unchecked`], at a granted root that no one granting identity
    /// names, so no floor can show it is no flip. It waits with no bound.
    Unnamespaced,
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
pub(crate) fn kept_verdict(note: &KeptNote, place: KeptPlace, now: UnixMillis) -> KeptVerdict {
    match place {
        KeptPlace::Keyless { .. } => return KeptVerdict::Recheck,
        KeptPlace::Unnamespaced => return KeptVerdict::Stay,
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
            parent: None,
            result: None,
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
            kept_verdict(&note(2), here(2, true), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&note(2), here(2, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn a_new_write_epoch_sends_the_op_to_the_rebase_before_the_bound() {
        assert_eq!(
            kept_verdict(&note(2), here(3, true), at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(&note(2), here(3, true), at(KEPT_OP_BOUND)),
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
            kept_verdict(&note(2), new_scope, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
    }

    #[test]
    fn a_flip_waits_for_a_read_of_the_folder_at_its_new_name_and_does_not_expire() {
        assert_eq!(
            kept_verdict(&note(2), here(3, false), at(Duration::ZERO)),
            KeptVerdict::Stay,
            "a read from before the flip still shows the lost write"
        );
        assert_eq!(
            kept_verdict(&note(2), here(3, false), at(KEPT_OP_BOUND * 2)),
            KeptVerdict::Stay,
            "a device offline past the bound keeps the write for its first live read"
        );
    }

    #[test]
    fn a_scope_the_device_can_no_longer_write_sends_the_op_to_the_pass() {
        let keyless = KeptPlace::Keyless { root: SCOPE };
        assert_eq!(
            kept_verdict(&note(2), keyless, at(Duration::ZERO)),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(&note(2), keyless, at(KEPT_OP_BOUND)),
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
            kept_verdict(&note(2), unproved, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&note(2), unproved, at(KEPT_OP_BOUND)),
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
                kept_verdict(&note(2), place, at(KEPT_OP_BOUND * 2)),
                KeptVerdict::Stay,
                "{place:?}"
            );
        }
    }

    #[test]
    fn another_pass_leaves_the_op_alone_until_the_bound() {
        assert_eq!(
            kept_verdict(&note(2), KeptPlace::Elsewhere, at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&note(2), KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
            KeptVerdict::Expired
        );
    }

    #[test]
    fn an_op_with_no_note_gets_one_check_at_the_first_live_read_of_its_folder() {
        let mut notes = KeptNotes::default();
        let first = notes.note_at(OpId(3), PUBLISHED);
        assert!(notes.is_dirty(), "the first sight is recorded");
        assert_eq!(
            kept_verdict(&first, here(GENESIS_EPOCH, true), PUBLISHED),
            KeptVerdict::Recheck
        );
        assert_eq!(
            kept_verdict(&first, here(GENESIS_EPOCH, false), at(JUST_BEFORE)),
            KeptVerdict::Stay
        );
        assert_eq!(
            kept_verdict(&first, KeptPlace::Elsewhere, at(KEPT_OP_BOUND)),
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
        notes
            .insert(
                OpId(1),
                KeptNote {
                    published_at: far,
                    ..note(2)
                },
            )
            .expect("the note is in bounds");
        let read = notes.note_at(OpId(1), PUBLISHED);
        assert_eq!(read.published_at, PUBLISHED, "a far-future note");
        assert_eq!(
            kept_verdict(&read, here(2, true), at(KEPT_OP_BOUND)),
            KeptVerdict::Expired,
            "the bound then runs from the read"
        );

        notes
            .insert(OpId(2), note(2))
            .expect("the note is in bounds");
        let before = UnixMillis(PUBLISHED.0 - 500);
        assert_eq!(
            notes.note_at(OpId(2), before).published_at,
            before,
            "a backward clock step"
        );
    }

    fn name(len: usize) -> Zeroizing<String> {
        Zeroizing::new("n".repeat(len))
    }

    fn with_result(result: KeptResult) -> KeptNote {
        KeptNote {
            parent: Some(NodeId([6; 16])),
            result: Some(result),
            ..note(3)
        }
    }

    /// A note of each shape, each name and CID at its bound.
    fn every_shape() -> KeptNotes {
        let mut notes = KeptNotes::default();
        let shapes = [
            note(3),
            KeptNote {
                scope: None,
                parent: Some(NodeId([7; 16])),
                ..note(1)
            },
            with_result(KeptResult::Rename {
                before: name(MAX_NODE_NAME_BYTES),
                after: name(0),
            }),
            with_result(KeptResult::Move {
                from: NodeId([8; 16]),
                from_name: name(1),
                to: NodeId([9; 16]),
                to_name: name(MAX_NODE_NAME_BYTES),
            }),
            with_result(KeptResult::RestoreVersion {
                before: vec![1; CONTENT_CID_LEN],
                after: vec![2; 3],
            }),
        ];
        for (op_id, shape) in (1..).zip(shapes) {
            notes
                .insert(OpId(op_id), shape)
                .expect("the note is in bounds");
        }
        notes
    }

    #[test]
    fn version_2_notes_round_trip_in_each_shape() {
        let notes = every_shape();
        let bytes = notes.encode().expect("the notes encode");
        assert_eq!(bytes[0], NOTE_FORMAT_V2, "the writer writes version 2");
        assert_eq!(KeptNotes::decode(&bytes).notes, notes.notes);
    }

    /// Two version 1 entries as the v2.12 build wrote them: op 7 under scope
    /// `[5; 16]` at write epoch 3, published at 1000; op 4 with no scope at
    /// write epoch 1, published at 2.
    const FROZEN_V1_BODY: &str = concat!(
        "01",
        "0000000000000007",
        "01",
        "05050505050505050505050505050505",
        "0000000000000003",
        "00000000000003e8",
        "0000000000000004",
        "00",
        "00000000000000000000000000000000",
        "0000000000000001",
        "0000000000000002",
    );

    #[test]
    fn a_version_1_body_reads_with_no_parent_and_no_result() {
        let decoded = KeptNotes::decode(&hex::decode(FROZEN_V1_BODY).expect("hex"));

        assert_eq!(
            decoded.get(OpId(7)),
            Some(KeptNote {
                scope: Some(NodeId([5; 16])),
                write_epoch: 3,
                published_at: UnixMillis(1_000),
                parent: None,
                result: None,
            })
        );
        assert_eq!(
            decoded.get(OpId(4)),
            Some(KeptNote {
                scope: None,
                write_epoch: 1,
                published_at: UnixMillis(2),
                parent: None,
                result: None,
            })
        );
    }

    /// The v2.12 decoder, word for word, so a test can show what the previous
    /// release reads from a body this build writes (ADR 0020).
    mod v2_12 {
        use std::collections::BTreeMap;

        use crate::facade::NodeId;
        use crate::seams::{OpId, UnixMillis};

        const NOTE_FORMAT_V1: u8 = 1;
        const NOTE_ENTRY_LEN: usize = 8 + 1 + 16 + 8 + 8;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) struct KeptNote {
            pub(super) scope: Option<NodeId>,
            pub(super) write_epoch: u64,
            pub(super) published_at: UnixMillis,
        }

        #[derive(Debug, Default, PartialEq, Eq)]
        pub(super) struct KeptNotes {
            pub(super) notes: BTreeMap<OpId, KeptNote>,
            dirty: bool,
        }

        impl KeptNotes {
            pub(super) fn decode(body: &[u8]) -> Self {
                let Some(entries) = body
                    .split_first()
                    .filter(|(tag, rest)| {
                        **tag == NOTE_FORMAT_V1 && rest.len() % NOTE_ENTRY_LEN == 0
                    })
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
        }
    }

    /// The previous release reads a version 2 body as no notes. Each of its
    /// kept ops then gets a first-sight note and one check (ADR 0069 D6).
    #[test]
    fn the_previous_release_reads_a_version_2_body_as_no_notes() {
        let frozen = hex::decode(FROZEN_V1_BODY).expect("hex");
        assert_eq!(
            v2_12::KeptNotes::decode(&frozen).notes.len(),
            2,
            "the copy reads the body its build wrote"
        );

        let mut notes = KeptNotes::default();
        notes
            .insert(OpId(7), note(3))
            .expect("the note is in bounds");
        let written = notes.encode().expect("the notes encode");
        assert!(v2_12::KeptNotes::decode(&written).notes.is_empty());
        let written = every_shape().encode().expect("the notes encode");
        assert!(v2_12::KeptNotes::decode(&written).notes.is_empty());
    }

    /// One version 2 entry with its length, laid out by hand: `op_id` under
    /// scope `[5; 16]` at write epoch 3, published at 1000, under parent
    /// `[6; 16]`, then `result`.
    fn v2_entry(op_id: u64, result: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&op_id.to_be_bytes());
        entry.push(1);
        entry.extend_from_slice(&[5; 16]);
        entry.extend_from_slice(&3u64.to_be_bytes());
        entry.extend_from_slice(&1_000u64.to_be_bytes());
        entry.push(1);
        entry.extend_from_slice(&[6; 16]);
        entry.extend_from_slice(result);
        let len = u16::try_from(entry.len()).expect("short").to_be_bytes();
        [&len[..], &entry].concat()
    }

    /// A version 2 body of one entry, op 1 ([`v2_entry`]).
    fn v2_body(result: &[u8]) -> Vec<u8> {
        [&[NOTE_FORMAT_V2][..], &v2_entry(1, result)].concat()
    }

    fn named(len: usize) -> Vec<u8> {
        let mut bytes = u16::try_from(len).expect("short").to_be_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(b'n', len));
        bytes
    }

    fn rename_result(before: &[u8], after: &[u8]) -> Vec<u8> {
        [&[RESULT_RENAME][..], before, after].concat()
    }

    fn reads(body: &[u8]) -> bool {
        KeptNotes::decode(body).holds(OpId(1))
    }

    #[test]
    fn the_hand_laid_body_reads() {
        assert!(reads(&v2_body(&[RESULT_NONE])));
        assert!(reads(&v2_body(&rename_result(
            &named(MAX_NODE_NAME_BYTES),
            &named(1)
        ))));
        let cid = [
            &[u8::try_from(CONTENT_CID_LEN).expect("short")][..],
            &[1; CONTENT_CID_LEN],
        ]
        .concat();
        assert!(reads(&v2_body(
            &[&[RESULT_RESTORE_VERSION][..], &cid, &cid].concat()
        )));
    }

    /// Each body below breaks one bound in one part, beside good entries of
    /// other ops, and the whole body reads as no notes: a decoder that skips
    /// only the bad entry fails.
    #[test]
    fn a_body_that_breaks_a_bound_reads_as_no_notes() {
        let before = v2_entry(2, &[RESULT_NONE]);
        let after = v2_entry(3, &[RESULT_NONE]);
        let around = |bad: &[u8]| [&[NOTE_FORMAT_V2][..], &before, bad, &after].concat();
        let good = around(&v2_entry(1, &[RESULT_NONE]));
        assert_eq!(KeptNotes::decode(&good).notes.len(), 3);

        let mut refused: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut unknown_tag = good.clone();
        unknown_tag[0] = 3;
        refused.push(("an unknown format tag", unknown_tag));
        refused.push(("a truncated entry", good[..good.len() - 1].to_vec()));
        refused.push(("a trailing byte", [&good[..], &[0]].concat()));
        refused.push((
            "a trailing byte inside an entry",
            around(&v2_entry(1, &[RESULT_NONE, 0])),
        ));
        refused.push(("an unknown result tag", around(&v2_entry(1, &[9]))));
        let cid = [&[3u8][..], &[1; 3]].concat();
        refused.push((
            "a result tag that does not match its fields",
            around(&v2_entry(1, &[&[RESULT_RENAME][..], &cid, &cid].concat())),
        ));
        refused.push((
            "a name past the bound",
            around(&v2_entry(
                1,
                &rename_result(&named(MAX_NODE_NAME_BYTES + 1), &named(1)),
            )),
        ));
        refused.push((
            "a name that is not UTF-8",
            around(&v2_entry(1, &rename_result(&[0, 1, 0xff], &named(1)))),
        ));
        let long_cid = [
            &[u8::try_from(CONTENT_CID_LEN + 1).expect("short")][..],
            &[1; CONTENT_CID_LEN + 1],
        ]
        .concat();
        refused.push((
            "a CID past the bound",
            around(&v2_entry(
                1,
                &[&[RESULT_RESTORE_VERSION][..], &long_cid, &cid].concat(),
            )),
        ));
        let mut bad_scope_flag = v2_entry(1, &[RESULT_NONE]);
        bad_scope_flag[2 + 8] = 2;
        refused.push(("a scope flag past 1", around(&bad_scope_flag)));
        let mut bad_parent_flag = v2_entry(1, &[RESULT_NONE]);
        bad_parent_flag[2 + 8 + 17 + 16] = 2;
        refused.push(("a parent flag past 1", around(&bad_parent_flag)));
        refused.push(("a duplicate op id", around(&before)));

        for (case, body) in refused {
            assert!(KeptNotes::decode(&body).notes.is_empty(), "{case}");
        }
        let mut frozen = hex::decode(FROZEN_V1_BODY).expect("hex");
        frozen[1 + 41 + 8] = 2;
        assert!(
            KeptNotes::decode(&frozen).notes.is_empty(),
            "a version 1 scope flag past 1 in the second entry"
        );
    }

    /// The encoder refuses each note the decoder refuses (AGENTS.md rule 8).
    #[test]
    fn a_note_past_a_bound_is_refused_at_insert_and_at_encode() {
        let long_name = with_result(KeptResult::Rename {
            before: name(1),
            after: name(MAX_NODE_NAME_BYTES + 1),
        });
        let long_cid = with_result(KeptResult::RestoreVersion {
            before: vec![1; CONTENT_CID_LEN + 1],
            after: vec![1; 3],
        });
        let mut notes = KeptNotes::default();
        assert_eq!(
            notes.insert(OpId(1), long_name.clone()),
            Err(KeptNoteError::NameTooLong)
        );
        assert_eq!(
            notes.insert(OpId(2), long_cid.clone()),
            Err(KeptNoteError::CidTooLong)
        );
        assert!(
            !notes.is_dirty(),
            "a refused note leaves the record as it was"
        );

        notes.notes.insert(OpId(1), long_name);
        assert_eq!(notes.encode(), Err(KeptNoteError::NameTooLong));
        notes.notes.insert(OpId(1), long_cid);
        assert_eq!(notes.encode(), Err(KeptNoteError::CidTooLong));
    }
}
