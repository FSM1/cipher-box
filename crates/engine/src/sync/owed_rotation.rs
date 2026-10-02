//! The durable record of the owner rotation work this device still owes
//! (CONTEXT.md "Owed rotation work"; ADR 0063).
//!
//! One key per identity, under the owner tag every durable bookkeeping surface
//! is scoped by ([`owner_scoped_key`]), sealed under
//! [`OwnerLocalKind::OwedRotation`] ([`crate::sync::bookkeeping`]). An entry
//! names a scope, the cut epoch of the cut it finishes, and the steps still
//! owed; it holds no seed and no key, because a re-drive reads both from the
//! published records (ADR 0063 D1).
//!
//! The session holds the record in one cell ([`OwedCell`]) and writes it
//! through, so a command and the tick never write back each other's stale copy.

use core::cell::{Cell, RefCell};
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::seal::OwnerLocalKind;
use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::facade::NodeId;
use crate::rotation::NodeBound;
use crate::seams::{SeamError, SeamResult, StagingStore, UnixMillis};
use crate::sync::BookkeepingSeal;
use crate::sync::drain::owner_scoped_key;

/// The staging-key prefix the owed rotation record is journaled under.
/// [`orphan_staging_keys`](crate::sync::orphan_staging_keys) treats the whole
/// prefix as referenced, every owner's entry included.
///
/// Kept short: the desktop store spells a key as a hex filename, at twice its
/// byte length.
pub const OWED_ROTATION_PREFIX: &[u8] = b"cbx/or/";

/// The record format tags. The staging store is shared with whatever build
/// wrote it, so bytes that merely happen to parse must not read as owed work.
/// A V2 entry adds the time of its first stop after the cut epoch; a V1 entry
/// decodes with none recorded (ADR 0065 D3, ADR 0020 D2).
const FORMAT_V1: u8 = 1;
const FORMAT_V2: u8 = 2;

/// How long the current step of an entry stops before a stop that an endpoint
/// can cause drops a node, and before the renewal walk renews in its scope
/// (ADR 0065 D3, D4).
pub const DROP_BOUND: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The fewest passes of the current session that a node must hold the name
/// wave before it drops, or that the entry must hold it past [`DROP_BOUND`]
/// before every held node drops. The count is the session's own, so a drop
/// rests on stops this session saw.
pub const DROP_BOUND_PASSES: u32 = 3;

/// The most scopes the record holds. A command that would owe one more refuses
/// before its first publish (ADR 0063 D2).
pub const MAX_OWED_ENTRIES: usize = 64;

/// One step an owner rotation still owes, in the order every command runs
/// them: no command owes both an interior move and a read cut, so one rank
/// orders every entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwedStep {
    /// The re-seal of the granted folder's interior into its promoted scope,
    /// from the scope the folder left.
    InteriorMove {
        /// The scope the folder left.
        left_scope: NodeId,
    },
    /// The fresh-seed read cascade over the published cut set.
    ReadCut,
    /// The name wave, and its write-epoch floor raise and index re-point.
    WriteCut {
        /// The write epoch the wave publishes at. A resume that targets any
        /// other is refused.
        write_epoch: u64,
    },
    /// The share pointer of a grant, posted once its interior move and any
    /// write-scope cut landed.
    DeliverGrant {
        /// The recipient's SEC1 identity public key.
        recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
        /// Whether the grant is at write.
        write: bool,
    },
}

impl OwedStep {
    /// The step's wire tag, which is also its rank in command order.
    fn tag(&self) -> u8 {
        match self {
            Self::InteriorMove { .. } => 1,
            Self::ReadCut => 2,
            Self::WriteCut { .. } => 3,
            Self::DeliverGrant { .. } => 4,
        }
    }
}

/// The owed work at one scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedEntry {
    /// The cut epoch of the published cut this entry finishes. A mint's is 0.
    pub cut_epoch: u64,
    /// When the current first step of this entry first stopped, `None` until
    /// it does.
    pub first_stop: Option<UnixMillis>,
    /// The steps still owed, in command order. Empty when only the cut-epoch
    /// floor record is owed.
    pub steps: Vec<OwedStep>,
}

impl OwedEntry {
    /// Whether this is a revoke's or a downgrade's entry: a cut and nothing a
    /// mint owes.
    #[must_use]
    pub fn is_cut(&self) -> bool {
        self.cut_epoch > 0
            && self
                .steps
                .iter()
                .all(|step| matches!(step, OwedStep::ReadCut | OwedStep::WriteCut { .. }))
    }
}

impl OwedEntry {
    /// The scope the folder left, while the entry still owes its interior
    /// move.
    #[must_use]
    pub fn interior_move_source(&self) -> Option<NodeId> {
        match self.steps.first() {
            Some(OwedStep::InteriorMove { left_scope }) => Some(*left_scope),
            _ => None,
        }
    }

    /// Whether the entry still owes its interior move.
    #[must_use]
    pub fn owes_interior_move(&self) -> bool {
        self.interior_move_source().is_some()
    }
}

/// The whole record, keyed by scope.
pub type OwedRecord = BTreeMap<NodeId, OwedEntry>;

/// Why the record refuses a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwedRecordError {
    /// The record already holds [`MAX_OWED_ENTRIES`] scopes.
    Full,
    /// An entry already stands at the scope: a new command there waits until
    /// the work it owes lands.
    Standing,
    /// An entry's steps are out of command order or repeat a kind.
    StepsOutOfOrder,
    /// The staging store refused the write.
    Store(SeamError),
}

impl OwedRecordError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Full => "owed-rotation-record-full",
            Self::Standing => ROTATION_WORK_OWED,
            Self::StepsOutOfOrder => "owed-rotation-steps-out-of-order",
            Self::Store(_) => "owed-rotation-not-durable",
        }
    }
}

/// The check of a command refused while owed work stands at its scope. A
/// retry clears it once the work lands.
pub const ROTATION_WORK_OWED: &str = "rotation-work-owed";

/// The session's copy of the record, `None` until the first read loads it,
/// and the scopes a command or the pass is driving now.
///
/// `writer` serializes every write from its load to its cell update: a hold is
/// per scope, so two writes to different scopes run together.
#[derive(Default)]
pub struct OwedCell {
    record: RefCell<Option<OwedRecord>>,
    held: RefCell<BTreeSet<NodeId>>,
    /// The passes of this session that held the name wave of each entry's
    /// write cut.
    held_nodes: RefCell<BTreeMap<NodeId, HeldPasses>>,
    /// The sync pass of this session, which each tick advances. A command's
    /// re-drive counts in the pass it runs in.
    pass: Cell<u64>,
    writer: futures_util::lock::Mutex<()>,
}

/// A count of passes, each counted once.
#[derive(Clone, Copy, Default)]
struct Passes {
    count: u32,
    last: Option<u64>,
}

impl Passes {
    fn count(&mut self, pass: u64) {
        if self.last != Some(pass) {
            self.count = self.count.saturating_add(1);
            self.last = Some(pass);
        }
    }

    fn before(self, pass: u64) -> u32 {
        self.count - u32::from(self.last == Some(pass))
    }
}

/// The passes that held one entry's name wave: past its time for the entry,
/// and at any time for each node until it resolves.
#[derive(Default)]
struct HeldPasses {
    past_time: Passes,
    nodes: BTreeMap<[u8; 16], Passes>,
}

impl OwedCell {
    /// Drop the session's copy, so the next session reads its own record.
    pub fn forget(&self) {
        if let Ok(mut cell) = self.record.try_borrow_mut() {
            *cell = None;
        }
        if let Ok(mut held) = self.held_nodes.try_borrow_mut() {
            held.clear();
        }
    }

    fn reset_held(&self, scope: NodeId) {
        self.held_nodes.borrow_mut().remove(&scope);
    }

    #[cfg(test)]
    fn held_passes(&self, scope: NodeId, node_id: &[u8; 16]) -> u32 {
        self.held_nodes
            .borrow()
            .get(&scope)
            .and_then(|held| held.nodes.get(node_id))
            .map_or(0, |passes| passes.count)
    }

    /// Start the next sync pass.
    pub fn next_pass(&self) {
        self.pass.set(self.pass.get().wrapping_add(1));
    }

    /// Take `scope` for one driver until the hold drops, or `None` while
    /// another driver holds it.
    pub fn hold(&self, scope: NodeId) -> Option<ScopeHold<'_>> {
        self.held
            .borrow_mut()
            .insert(scope)
            .then(|| ScopeHold { cell: self, scope })
    }
}

/// The bound of ADR 0065 D3 for one run of an entry's name wave. Once the
/// entry's current step first stopped [`DROP_BOUND`] ago, a node is past it
/// when it held [`DROP_BOUND_PASSES`] earlier passes, and every node is when
/// the entry held that many earlier passes past that time. Each count takes a
/// pass once, so the retries and re-drives inside one pass count as one.
pub struct EntryBound<'a> {
    cell: &'a OwedCell,
    scope: NodeId,
    past_time: bool,
    pass: u64,
}

impl NodeBound for EntryBound<'_> {
    fn past(&self, node_id: &[u8; 16], plant: bool) -> bool {
        if !self.past_time {
            return false;
        }
        let held = self.cell.held_nodes.borrow();
        let Some(held) = held.get(&self.scope) else {
            return false;
        };
        (plant && held.past_time.before(self.pass) >= DROP_BOUND_PASSES)
            || held
                .nodes
                .get(node_id)
                .is_some_and(|node| node.before(self.pass) >= DROP_BOUND_PASSES)
    }

    fn held(&self, node_id: &[u8; 16]) {
        let mut held = self.cell.held_nodes.borrow_mut();
        let held = held.entry(self.scope).or_default();
        held.nodes.entry(*node_id).or_default().count(self.pass);
        if self.past_time {
            held.past_time.count(self.pass);
        }
    }

    fn resolved(&self, node_id: &[u8; 16]) {
        if let Some(held) = self.cell.held_nodes.borrow_mut().get_mut(&self.scope) {
            held.nodes.remove(node_id);
        }
    }
}

/// One driver's exclusive claim on a scope's owed work.
pub struct ScopeHold<'a> {
    cell: &'a OwedCell,
    scope: NodeId,
}

impl Drop for ScopeHold<'_> {
    fn drop(&mut self) {
        self.cell.held.borrow_mut().remove(&self.scope);
    }
}

/// This identity's one owed rotation key.
#[must_use]
pub fn owed_rotation_key(enc_secret: &X25519Secret) -> Vec<u8> {
    owner_scoped_key(OWED_ROTATION_PREFIX, enc_secret)
}

/// The record over one session's cell and stores.
pub struct OwedRotation<'a, St> {
    staging: &'a St,
    seal: BookkeepingSeal<'a>,
    enc_secret: &'a X25519Secret,
    cell: &'a OwedCell,
}

/// Whether the current step of an entry that first stopped at `first_stop`
/// has stopped for [`DROP_BOUND`] at `now`.
fn bound_elapsed(first_stop: Option<UnixMillis>, now: UnixMillis) -> bool {
    now.reached(first_stop.map(|first| first.saturating_add(DROP_BOUND)))
}

/// Whether the entry owes its write cut, whose name wave the held passes
/// count.
fn owes_write_cut(steps: &[OwedStep]) -> bool {
    steps
        .iter()
        .any(|step| matches!(step, OwedStep::WriteCut { .. }))
}

impl<'a, St> OwedRotation<'a, St> {
    /// The record `cell` holds for the identity `enc_secret` names.
    pub(crate) fn new(
        staging: &'a St,
        seal: BookkeepingSeal<'a>,
        enc_secret: &'a X25519Secret,
        cell: &'a OwedCell,
    ) -> Self {
        Self {
            staging,
            seal,
            enc_secret,
            cell,
        }
    }
}

impl<'a, St: StagingStore> OwedRotation<'a, St> {
    /// The record, read from the store the first time. A stored blob that does
    /// not open fails the read and stays as it is: a write over it would drop
    /// the work it holds (ADR 0020 Consequence 4).
    pub async fn load(&self) -> SeamResult<OwedRecord> {
        self.read(OwedRecord::clone).await
    }

    /// The entry at `scope`, if one stands.
    pub async fn entry(&self, scope: NodeId) -> SeamResult<Option<OwedEntry>> {
        self.read(|record| record.get(&scope).cloned()).await
    }

    /// The scopes that still owe an interior move, with the scope each left.
    pub async fn interior_moves(&self) -> SeamResult<Vec<(NodeId, NodeId)>> {
        self.read(|record| {
            record
                .iter()
                .filter_map(|(scope, entry)| Some((*scope, entry.interior_move_source()?)))
                .collect()
        })
        .await
    }

    /// The scopes the record names.
    pub async fn scopes(&self) -> SeamResult<Vec<NodeId>> {
        self.read(|record| record.keys().copied().collect()).await
    }

    /// The bound of one pass of the name wave at `scope` at `now` (ADR 0065
    /// D3).
    pub async fn bound(&self, scope: NodeId, now: UnixMillis) -> SeamResult<EntryBound<'a>> {
        let first_stop = self
            .read(|record| record.get(&scope).and_then(|entry| entry.first_stop))
            .await?;
        Ok(EntryBound {
            cell: self.cell,
            scope,
            past_time: bound_elapsed(first_stop, now),
            pass: self.cell.pass.get(),
        })
    }

    /// The scopes whose entry's current step has not stopped for
    /// [`DROP_BOUND`] at `now`. Durable, so a restart keeps it (ADR 0065 D4).
    pub async fn scopes_within_bound(&self, now: UnixMillis) -> SeamResult<Vec<NodeId>> {
        self.read(|record| {
            record
                .iter()
                .filter(|(_, entry)| !bound_elapsed(entry.first_stop, now))
                .map(|(scope, _)| *scope)
                .collect()
        })
        .await
    }

    /// Keep `now` as the first stop of the entry at `scope` when it holds none.
    pub async fn note_stop(&self, scope: NodeId, now: UnixMillis) -> Result<(), OwedRecordError> {
        self.write(|record| {
            let Some(entry) = record.get_mut(&scope) else {
                return Ok(false);
            };
            if entry.first_stop.is_some() {
                return Ok(false);
            }
            entry.first_stop = Some(now);
            Ok(true)
        })
        .await
    }

    /// `view` over the record, loading it into the cell the first time.
    async fn read<R>(&self, view: impl FnOnce(&OwedRecord) -> R) -> SeamResult<R> {
        if let Some(record) = self.cell.record.borrow().as_ref() {
            return Ok(view(record));
        }
        let stored = self
            .staging
            .staged_bytes(&owed_rotation_key(self.enc_secret))
            .await?;
        let record = match stored {
            None => OwedRecord::default(),
            Some(blob) => open_owed_record(self.seal, &blob)
                .ok_or_else(|| SeamError::new("the owed rotation record does not open"))?,
        };
        // A command may have written the cell during the read.
        let mut cell = self.cell.record.borrow_mut();
        Ok(view(cell.get_or_insert(record)))
    }

    /// Write `entry` at `scope`, durably. Refused while an entry stands there.
    pub async fn owe(&self, scope: NodeId, entry: OwedEntry) -> Result<(), OwedRecordError> {
        self.write(|record| {
            if record.contains_key(&scope) {
                return Err(OwedRecordError::Standing);
            }
            if record.len() >= MAX_OWED_ENTRIES {
                return Err(OwedRecordError::Full);
            }
            record.insert(scope, entry);
            Ok(true)
        })
        .await?;
        self.cell.reset_held(scope);
        Ok(())
    }

    /// Replace the entry at `scope` with `entry` when it is `standing`; refused
    /// as [`OwedRecordError::Standing`] once another driver changed it.
    pub async fn replace(
        &self,
        scope: NodeId,
        standing: &OwedEntry,
        entry: OwedEntry,
    ) -> Result<(), OwedRecordError> {
        self.write(|record| match record.get_mut(&scope) {
            Some(current) if current == standing => {
                *current = entry;
                Ok(true)
            }
            _ => Err(OwedRecordError::Standing),
        })
        .await?;
        self.cell.reset_held(scope);
        Ok(())
    }

    /// Replace the steps of the entry at `scope` with `steps`, if it stands.
    pub async fn leave(&self, scope: NodeId, steps: Vec<OwedStep>) -> Result<(), OwedRecordError> {
        self.advance(scope, |owed| *owed = steps).await
    }

    /// Drop the delivery to `recipient` from the entry at `scope`, and the
    /// entry when that leaves a mint owing nothing.
    pub async fn cancel_delivery(
        &self,
        scope: NodeId,
        recipient: &[u8; IDENTITY_PUBLIC_LEN],
    ) -> Result<(), OwedRecordError> {
        self.write(|record| {
            let Some(entry) = record.get_mut(&scope) else {
                return Ok(false);
            };
            let before = entry.steps.len();
            entry.steps.retain(|step| {
                !matches!(step, OwedStep::DeliverGrant { recipient_identity_pk, .. }
                    if recipient_identity_pk == recipient)
            });
            if entry.steps.len() == before {
                return Ok(false);
            }
            if entry.steps.is_empty() && entry.cut_epoch == 0 {
                record.remove(&scope);
            }
            Ok(true)
        })
        .await
    }

    /// Drop every step before `step` from the entry at `scope`: `step` and the
    /// ones after it are still owed.
    pub async fn advance_to(&self, scope: NodeId, step: &OwedStep) -> Result<(), OwedRecordError> {
        let rank = step.tag();
        self.advance(scope, |owed| owed.retain(|owed| owed.tag() >= rank))
            .await
    }

    /// Apply `edit` to the steps of the entry at `scope`, if it stands. A new
    /// first step starts its bound again, and the held passes end with the
    /// write cut they count.
    async fn advance(
        &self,
        scope: NodeId,
        edit: impl FnOnce(&mut Vec<OwedStep>),
    ) -> Result<(), OwedRecordError> {
        let mut write_cut_left = false;
        let mut restarted = false;
        self.write(|record| {
            let Some(entry) = record.get_mut(&scope) else {
                return Ok(false);
            };
            let first_before = entry.steps.first().map(OwedStep::tag);
            let owed_write_cut = owes_write_cut(&entry.steps);
            edit(&mut entry.steps);
            // A changed first step advanced the entry, so its bound starts again.
            if entry.steps.first().map(OwedStep::tag) != first_before {
                entry.first_stop = None;
                restarted = true;
            }
            write_cut_left = owed_write_cut && !owes_write_cut(&entry.steps);
            Ok(true)
        })
        .await?;
        if write_cut_left {
            self.cell.reset_held(scope);
        } else if restarted && let Some(held) = self.cell.held_nodes.borrow_mut().get_mut(&scope) {
            held.past_time = Passes::default();
        }
        Ok(())
    }

    /// Remove the entry at `scope`: its last step and its post-steps landed.
    pub async fn clear(&self, scope: NodeId) -> Result<(), OwedRecordError> {
        self.write(|record| Ok(record.remove(&scope).is_some()))
            .await?;
        self.cell.reset_held(scope);
        Ok(())
    }

    /// Apply `edit` to the record under the cell's writer, and store the
    /// result when `edit` reports a change.
    async fn write(
        &self,
        edit: impl FnOnce(&mut OwedRecord) -> Result<bool, OwedRecordError>,
    ) -> Result<(), OwedRecordError> {
        let _writer = self.cell.writer.lock().await;
        let mut record = self.load().await.map_err(OwedRecordError::Store)?;
        if edit(&mut record)? {
            self.store(record).await
        } else {
            Ok(())
        }
    }

    /// Write `record` through, then set the cell to it, so the cell never
    /// holds what the store refused.
    async fn store(&self, record: OwedRecord) -> Result<(), OwedRecordError> {
        let key = owed_rotation_key(self.enc_secret);
        let blob = if record.is_empty() {
            None
        } else {
            Some(seal_owed_record(self.seal, &record)?)
        };
        match blob {
            None => self.staging.remove_staged_bytes(&key).await,
            Some(blob) => self.staging.put_staged_bytes(&key, &blob).await,
        }
        .map_err(OwedRecordError::Store)?;
        *self.cell.record.borrow_mut() = Some(record);
        Ok(())
    }
}

/// The record as the staging store holds it: the encoded entries, sealed.
pub fn seal_owed_record(
    seal: BookkeepingSeal<'_>,
    record: &OwedRecord,
) -> Result<Vec<u8>, OwedRecordError> {
    seal.seal(OwnerLocalKind::OwedRotation, &encode_owed(record)?)
        .map_err(OwedRecordError::Store)
}

/// The stored record, or `None` for bytes this identity's key and this
/// build's grammar do not both accept.
#[must_use]
pub fn open_owed_record(seal: BookkeepingSeal<'_>, blob: &[u8]) -> Option<OwedRecord> {
    decode_owed(&seal.open(OwnerLocalKind::OwedRotation, blob)?)
}

/// The record's own encoding, inside the seal: the format tag, the entry
/// count, then each entry in scope order — the scope id, the cut epoch, the
/// first stop (a flag, then the time when set), the step count and each step's
/// tag and payload.
///
/// Refuses, release-active, every shape [`decode_owed`] refuses (AGENTS.md
/// rule 8): more than [`MAX_OWED_ENTRIES`] entries, and steps that are not in
/// strictly rising command order.
fn encode_owed(record: &OwedRecord) -> Result<Zeroizing<Vec<u8>>, OwedRecordError> {
    if record.len() > MAX_OWED_ENTRIES {
        return Err(OwedRecordError::Full);
    }
    let mut out = Zeroizing::new(vec![FORMAT_V2]);
    out.push(u8::try_from(record.len()).map_err(|_| OwedRecordError::Full)?);
    for (scope, entry) in record {
        if !in_command_order(&entry.steps) {
            return Err(OwedRecordError::StepsOutOfOrder);
        }
        out.extend_from_slice(&scope.0);
        out.extend_from_slice(&entry.cut_epoch.to_be_bytes());
        match entry.first_stop {
            None => out.push(0),
            Some(first_stop) => {
                out.push(1);
                out.extend_from_slice(&first_stop.0.to_be_bytes());
            }
        }
        out.push(u8::try_from(entry.steps.len()).map_err(|_| OwedRecordError::StepsOutOfOrder)?);
        for step in &entry.steps {
            out.push(step.tag());
            match step {
                OwedStep::InteriorMove { left_scope } => out.extend_from_slice(&left_scope.0),
                OwedStep::ReadCut => {}
                OwedStep::WriteCut { write_epoch } => {
                    out.extend_from_slice(&write_epoch.to_be_bytes());
                }
                OwedStep::DeliverGrant {
                    recipient_identity_pk,
                    write,
                } => {
                    out.extend_from_slice(recipient_identity_pk);
                    out.push(u8::from(*write));
                }
            }
        }
    }
    Ok(out)
}

/// Whether `steps` rise strictly by rank, so no kind repeats.
fn in_command_order(steps: &[OwedStep]) -> bool {
    steps.windows(2).all(|pair| pair[0].tag() < pair[1].tag())
}

/// The record an encoding names, or `None` for a tag this build does not
/// read, a first-stop flag that is neither 0 nor 1, a count past the bound,
/// scopes out of order, steps out of command order, an unknown step, or bytes
/// left over.
fn decode_owed(bytes: &[u8]) -> Option<OwedRecord> {
    let (&format, rest) = bytes.split_first()?;
    if format != FORMAT_V1 && format != FORMAT_V2 {
        return None;
    }
    let mut reader = Reader(rest);
    let count = usize::from(reader.byte()?);
    if count > MAX_OWED_ENTRIES {
        return None;
    }
    let mut record = OwedRecord::new();
    let mut last: Option<NodeId> = None;
    for _ in 0..count {
        let scope = NodeId(reader.array()?);
        if last.is_some_and(|last| last >= scope) {
            return None;
        }
        last = Some(scope);
        let cut_epoch = u64::from_be_bytes(reader.array()?);
        let first_stop = match format {
            FORMAT_V1 => None,
            _ => match reader.byte()? {
                0 => None,
                1 => Some(UnixMillis(u64::from_be_bytes(reader.array()?))),
                _ => return None,
            },
        };
        let steps = (0..reader.byte()?)
            .map(|_| match reader.byte()? {
                1 => Some(OwedStep::InteriorMove {
                    left_scope: NodeId(reader.array()?),
                }),
                2 => Some(OwedStep::ReadCut),
                3 => Some(OwedStep::WriteCut {
                    write_epoch: u64::from_be_bytes(reader.array()?),
                }),
                4 => Some(OwedStep::DeliverGrant {
                    recipient_identity_pk: reader.array()?,
                    write: match reader.byte()? {
                        0 => false,
                        1 => true,
                        _ => return None,
                    },
                }),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        if !in_command_order(&steps) {
            return None;
        }
        record.insert(
            scope,
            OwedEntry {
                cut_epoch,
                first_stop,
                steps,
            },
        );
    }
    reader.0.is_empty().then_some(record)
}

/// A cursor over the encoded record.
struct Reader<'b>(&'b [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    fn secret(byte: u8) -> X25519Secret {
        X25519Secret::from_scalar([byte; 32])
    }

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 16])
    }

    fn revoke() -> OwedEntry {
        OwedEntry {
            cut_epoch: 3,
            first_stop: None,
            steps: vec![OwedStep::ReadCut, OwedStep::WriteCut { write_epoch: 4 }],
        }
    }

    fn write_grant() -> OwedEntry {
        OwedEntry {
            cut_epoch: 0,
            first_stop: None,
            steps: vec![
                OwedStep::InteriorMove {
                    left_scope: node(0),
                },
                OwedStep::WriteCut { write_epoch: 2 },
                OwedStep::DeliverGrant {
                    recipient_identity_pk: [2; IDENTITY_PUBLIC_LEN],
                    write: true,
                },
            ],
        }
    }

    fn record() -> OwedRecord {
        OwedRecord::from([(node(1), revoke()), (node(2), write_grant())])
    }

    /// A second driver is refused while the first holds the scope, and the
    /// refusal leaves the first driver's claim in place.
    #[test]
    fn a_held_scope_refuses_a_second_driver_until_the_first_drops() {
        let cell = OwedCell::default();
        let first = cell.hold(node(1)).expect("a free scope is held");
        assert!(cell.hold(node(1)).is_none(), "a second driver is refused");
        assert!(
            cell.hold(node(1)).is_none(),
            "and the refusal kept the first claim"
        );
        assert!(cell.hold(node(2)).is_some(), "another scope is free");
        drop(first);
        assert!(
            cell.hold(node(1)).is_some(),
            "the scope is free once dropped"
        );
    }

    /// A replace lands only over the entry its driver read, so a re-run never
    /// writes over work another driver changed.
    #[test]
    fn a_replace_lands_only_over_the_entry_it_read() {
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let store = InMemoryStagingStore::default();
        let cell = OwedCell::default();
        let owed = OwedRotation::new(&store, BookkeepingSeal::new(&mine, &entropy), &mine, &cell);
        block_on(owed.owe(node(1), write_grant())).expect("the entry lands");

        assert_eq!(
            block_on(owed.replace(node(1), &revoke(), revoke())),
            Err(OwedRecordError::Standing),
            "another entry stands"
        );
        block_on(owed.replace(node(1), &write_grant(), revoke())).expect("the replace lands");
        assert_eq!(block_on(owed.entry(node(1))), Ok(Some(revoke())));
        assert_eq!(
            block_on(owed.replace(node(2), &revoke(), revoke())),
            Err(OwedRecordError::Standing),
            "and nothing stands at a cleared scope"
        );
    }

    /// A staging store whose staged writes yield once, so two record writes
    /// interleave as a command and the tick do.
    struct YieldingStore(InMemoryStagingStore);

    async fn yield_once() {
        let mut yielded = false;
        core::future::poll_fn(move |cx| {
            if yielded {
                return core::task::Poll::Ready(());
            }
            yielded = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        })
        .await;
    }

    impl StagingStore for YieldingStore {
        async fn enqueue_op(&self, op: &[u8]) -> SeamResult<crate::seams::OpId> {
            self.0.enqueue_op(op).await
        }
        async fn enqueue_ops(&self, ops: &[Vec<u8>]) -> SeamResult<Vec<crate::seams::OpId>> {
            self.0.enqueue_ops(ops).await
        }
        async fn queued_ops(&self) -> SeamResult<Vec<(crate::seams::OpId, Vec<u8>)>> {
            self.0.queued_ops().await
        }
        async fn remove_op(&self, op_id: crate::seams::OpId) -> SeamResult<()> {
            self.0.remove_op(op_id).await
        }
        async fn put_staged_bytes(&self, key: &[u8], bytes: &[u8]) -> SeamResult<()> {
            yield_once().await;
            self.0.put_staged_bytes(key, bytes).await
        }
        async fn staged_bytes(&self, key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
            self.0.staged_bytes(key).await
        }
        async fn remove_staged_bytes(&self, key: &[u8]) -> SeamResult<()> {
            yield_once().await;
            self.0.remove_staged_bytes(key).await
        }
        async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
            self.0.staged_keys().await
        }
        async fn staged_bytes_total(&self) -> SeamResult<u64> {
            self.0.staged_bytes_total().await
        }
        async fn clear(&self) -> SeamResult<()> {
            self.0.clear().await
        }
    }

    /// Two writes to different scopes that run together both land, in the
    /// cell and in the store a later session reads.
    #[test]
    fn writes_to_two_scopes_that_interleave_both_land() {
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let store = YieldingStore(InMemoryStagingStore::default());
        let cell = OwedCell::default();
        let owed = OwedRotation {
            staging: &store,
            seal: BookkeepingSeal::new(&mine, &entropy),
            enc_secret: &mine,
            cell: &cell,
        };
        block_on(owed.owe(node(1), revoke())).expect("the first entry lands");

        let (owe, clear) = block_on(futures_util::future::join(
            owed.owe(node(2), write_grant()),
            owed.clear(node(1)),
        ));
        owe.expect("the second entry lands");
        clear.expect("the first entry clears");

        let expected = OwedRecord::from([(node(2), write_grant())]);
        assert_eq!(block_on(owed.load()).expect("the record reads"), expected);
        let next_cell = OwedCell::default();
        let next = OwedRotation {
            cell: &next_cell,
            ..owed
        };
        assert_eq!(block_on(next.load()).expect("the record reads"), expected);
    }

    /// What one session sealed is what the next one re-drives.
    #[test]
    fn a_sealed_record_opens_as_the_entries_it_named() {
        let entropy = RefCell::new(SeededEntropy::new(3));
        let mine = secret(9);
        let seal = BookkeepingSeal::new(&mine, &entropy);

        let blob = seal_owed_record(seal, &record()).expect("the record seals");

        assert_eq!(open_owed_record(seal, &blob), Some(record()));
    }

    /// Neither a stranger's blob nor a tag this build does not write reads as
    /// owed work.
    #[test]
    fn a_strangers_blob_and_a_foreign_tag_both_read_as_no_record() {
        let entropy = RefCell::new(SeededEntropy::new(5));
        let theirs = secret(10);
        let blob = seal_owed_record(BookkeepingSeal::new(&theirs, &entropy), &record())
            .expect("the record seals");
        let mine = secret(9);

        assert_eq!(
            open_owed_record(BookkeepingSeal::new(&mine, &entropy), &blob),
            None
        );
        assert_eq!(decode_owed(&[]), None, "no tag at all");
        assert_eq!(
            decode_owed(&[FORMAT_V2 + 1, 0]),
            None,
            "another build's tag"
        );
    }

    /// One revoke entry at `node(1)` in the shape `format` lays out, with
    /// `first_stop` the V2 field's bytes.
    fn revoke_bytes(format: u8, first_stop: &[u8]) -> Vec<u8> {
        let mut bytes = vec![format, 1];
        bytes.extend_from_slice(&node(1).0);
        bytes.extend_from_slice(&3u64.to_be_bytes());
        bytes.extend_from_slice(first_stop);
        bytes.extend_from_slice(&[2, 2, 3]);
        bytes.extend_from_slice(&4u64.to_be_bytes());
        bytes
    }

    /// The previous release wrote no first stop, so its entry decodes with
    /// none recorded and the next stop sets it (ADR 0020 D5, ADR 0065 D3).
    #[test]
    fn an_entry_written_before_the_first_stop_field_decodes_with_no_stop_recorded() {
        assert_eq!(
            decode_owed(&revoke_bytes(FORMAT_V1, &[])),
            Some(OwedRecord::from([(node(1), revoke())]))
        );
    }

    /// An entry that carries its first stop decodes with it, and one with no
    /// stop decodes with none.
    #[test]
    fn an_entry_with_the_first_stop_field_decodes() {
        let mut stop = vec![1];
        stop.extend_from_slice(&1_234_567u64.to_be_bytes());
        let stopped = OwedEntry {
            first_stop: Some(UnixMillis(1_234_567)),
            ..revoke()
        };
        assert_eq!(
            decode_owed(&revoke_bytes(FORMAT_V2, &stop)),
            Some(OwedRecord::from([(node(1), stopped)]))
        );
        assert_eq!(
            decode_owed(&revoke_bytes(FORMAT_V2, &[0])),
            Some(OwedRecord::from([(node(1), revoke())]))
        );
    }

    /// A first-stop flag byte other than 0 or 1 is refused.
    #[test]
    fn an_unknown_first_stop_flag_is_refused() {
        assert_eq!(decode_owed(&revoke_bytes(FORMAT_V2, &[2])), None);
    }

    /// A truncated or extended record is refused whole, never driven in part.
    #[test]
    fn a_partial_or_padded_record_is_refused_whole() {
        let bytes = encode_owed(&record()).expect("the record encodes").to_vec();
        let mut short = bytes.clone();
        short.pop();
        let mut long = bytes;
        long.push(0);

        assert_eq!(decode_owed(&short), None);
        assert_eq!(decode_owed(&long), None);
    }

    /// The decoder refuses steps out of command order, so the encoder refuses
    /// them too, in a release build (AGENTS.md rule 8).
    #[test]
    fn steps_out_of_command_order_are_refused_on_both_sides() {
        let reversed = OwedRecord::from([(
            node(1),
            OwedEntry {
                cut_epoch: 1,
                first_stop: None,
                steps: vec![OwedStep::WriteCut { write_epoch: 2 }, OwedStep::ReadCut],
            },
        )]);
        assert_eq!(
            encode_owed(&reversed).map(|_| ()),
            Err(OwedRecordError::StepsOutOfOrder)
        );

        let mut bytes = vec![FORMAT_V1, 1];
        bytes.extend_from_slice(&node(1).0);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&[2, 2, 2]);
        assert_eq!(decode_owed(&bytes), None, "a repeated read cut");
    }

    /// A count past the bound is refused on both sides.
    #[test]
    fn a_record_past_its_bound_is_refused_on_both_sides() {
        let full: OwedRecord = (0..=MAX_OWED_ENTRIES)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                (NodeId(id), revoke())
            })
            .collect();
        assert_eq!(encode_owed(&full).map(|_| ()), Err(OwedRecordError::Full));
        let count = u8::try_from(MAX_OWED_ENTRIES + 1).expect("the bound fits a byte");
        assert_eq!(decode_owed(&[FORMAT_V1, count]), None);
    }

    /// An unknown step tag is a record this build cannot drive.
    #[test]
    fn an_unknown_step_is_refused() {
        let mut bytes = vec![FORMAT_V1, 1];
        bytes.extend_from_slice(&node(1).0);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&[1, 9]);
        assert_eq!(decode_owed(&bytes), None);
    }

    /// The record advances step by step, and the last clear removes the key.
    #[test]
    fn the_record_advances_and_clears_through_the_store() {
        let store = InMemoryStagingStore::default();
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let cell = OwedCell::default();
        let owed = OwedRotation {
            staging: &store,
            seal: BookkeepingSeal::new(&mine, &entropy),
            enc_secret: &mine,
            cell: &cell,
        };
        block_on(async {
            owed.owe(node(1), revoke()).await.expect("the entry stores");
            owed.advance_to(node(1), &OwedStep::WriteCut { write_epoch: 4 })
                .await
                .expect("the entry advances");

            let restarted = OwedCell::default();
            let reread = OwedRotation {
                cell: &restarted,
                ..owed
            };
            assert_eq!(
                reread.entry(node(1)).await.expect("the store answers"),
                Some(OwedEntry {
                    cut_epoch: 3,
                    first_stop: None,
                    steps: vec![OwedStep::WriteCut { write_epoch: 4 }],
                }),
                "a restart reads the advanced entry"
            );

            owed.clear(node(1)).await.expect("the entry clears");
            assert_eq!(
                store
                    .staged_bytes(&owed_rotation_key(&mine))
                    .await
                    .expect("the store answers"),
                None,
                "an empty record leaves no key"
            );
        });
    }

    #[test]
    fn two_identities_hold_their_records_at_different_keys() {
        assert_ne!(
            owed_rotation_key(&secret(9)),
            owed_rotation_key(&secret(10))
        );
        assert!(owed_rotation_key(&secret(9)).starts_with(OWED_ROTATION_PREFIX));
    }

    /// The encoder writes the first stop, and the decoder reads it back.
    #[test]
    fn a_first_stop_round_trips_through_the_encoding() {
        let stopped = OwedRecord::from([(
            node(1),
            OwedEntry {
                first_stop: Some(UnixMillis(1_234_567)),
                ..revoke()
            },
        )]);
        let bytes = encode_owed(&stopped).expect("the record encodes");
        assert_eq!(bytes[0], FORMAT_V2, "the encoder writes the field's format");
        assert_eq!(decode_owed(&bytes), Some(stopped));
    }

    /// The `owed-rotation` bodies the core KAT pins at both formats decode to
    /// the entry they spell, the older one with no stop recorded.
    #[test]
    fn the_kat_owed_rotation_bodies_decode_at_both_formats() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../core/kat/vectors/owner_local/owner_local_accept.json"
        ))
        .expect("the KAT file parses");
        let body = |name: &str| -> Vec<u8> {
            let hex = vectors
                .iter()
                .find(|vector| vector["name"] == name)
                .and_then(|vector| vector["body"].as_str())
                .unwrap_or_else(|| panic!("the KAT pins {name}"));
            hex::decode(hex).expect("the KAT body is hex")
        };
        let entry = |first_stop| OwedEntry {
            first_stop,
            ..revoke()
        };
        let scope = NodeId([0xc1; 16]);

        assert_eq!(
            decode_owed(&body("owed-rotation-body")),
            Some(OwedRecord::from([(
                scope,
                entry(Some(UnixMillis(1_700_000_000_000)))
            )]))
        );
        assert_eq!(
            decode_owed(&body("owed-rotation-v1-body")),
            Some(OwedRecord::from([(scope, entry(None))]))
        );
    }

    /// A stop sets the first stop once. A node is past the bound only when that
    /// stop is [`DROP_BOUND`] old and the node held [`DROP_BOUND_PASSES`]
    /// passes of this session, each counted once.
    #[test]
    fn a_node_is_past_the_bound_only_with_its_time_and_its_own_passes() {
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let store = InMemoryStagingStore::default();
        let cell = OwedCell::default();
        let owed = OwedRotation::new(&store, BookkeepingSeal::new(&mine, &entropy), &mine, &cell);
        let start = UnixMillis(1_000);
        let after = start.saturating_add(DROP_BOUND);
        let (held, other) = ([1; 16], [2; 16]);
        block_on(async {
            owed.owe(node(1), revoke()).await.expect("the entry lands");
            for pass in 0..DROP_BOUND_PASSES {
                cell.next_pass();
                for _ in 0..2 {
                    let bound = owed.bound(node(1), start).await.expect("the store answers");
                    bound.held(&held);
                    bound.held(&held);
                }
                owed.note_stop(
                    node(1),
                    start.saturating_add(Duration::from_secs(u64::from(pass))),
                )
                .await
                .expect("the stop lands");
            }
            assert_eq!(
                cell.held_passes(node(1), &held),
                DROP_BOUND_PASSES,
                "a pass counts once"
            );
            assert_eq!(
                owed.entry(node(1))
                    .await
                    .expect("the store answers")
                    .and_then(|e| e.first_stop),
                Some(start),
                "only the first stop is kept"
            );
            cell.next_pass();
            let early = owed
                .bound(node(1), UnixMillis(after.0 - 1))
                .await
                .expect("the store answers");
            assert!(!early.past(&held, false), "before its time");
            let bound = owed.bound(node(1), after).await.expect("the store answers");
            assert!(bound.past(&held, false));
            assert!(
                !bound.past(&other, false),
                "another node counts its own passes"
            );
            assert_eq!(owed.scopes_within_bound(after).await, Ok(Vec::new()));

            bound.resolved(&held);
            assert!(
                !bound.past(&held, false),
                "a node that resolves starts again"
            );

            cell.forget();
            let bound = owed.bound(node(1), after).await.expect("the store answers");
            assert!(
                !bound.past(&other, false),
                "a new session counts its own passes"
            );
            assert_eq!(
                owed.scopes_within_bound(after).await,
                Ok(Vec::new()),
                "the time survives the session"
            );
        });
    }

    /// Past its time, an entry that held [`DROP_BOUND_PASSES`] passes drops
    /// every node held for a cause a revokee can plant, so a new node on each
    /// pass does not hold the wave. Other causes wait for the node's own count.
    #[test]
    fn an_entry_held_past_its_time_on_enough_passes_drops_only_a_plantable_cause() {
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let store = InMemoryStagingStore::default();
        let cell = OwedCell::default();
        let owed = OwedRotation::new(&store, BookkeepingSeal::new(&mine, &entropy), &mine, &cell);
        let start = UnixMillis(1_000);
        let after = start.saturating_add(DROP_BOUND);
        block_on(async {
            owed.owe(node(1), revoke()).await.expect("the entry lands");
            owed.note_stop(node(1), start)
                .await
                .expect("the stop lands");
            for fresh in 0..DROP_BOUND_PASSES {
                cell.next_pass();
                let bound = owed.bound(node(1), after).await.expect("the store answers");
                let id = [u8::try_from(fresh).expect("a small count"); 16];
                assert!(!bound.past(&id, true));
                bound.held(&id);
            }
            cell.next_pass();
            let bound = owed.bound(node(1), after).await.expect("the store answers");
            assert!(bound.past(&[0xee; 16], true), "a new node drops");
            assert!(
                !bound.past(&[0xee; 16], false),
                "a new node with a cause no revokee plants waits for its own passes"
            );
        });
    }

    /// A write the store refuses changes no count, so the session never counts
    /// for an entry the store does not hold.
    #[test]
    fn a_refused_clear_keeps_the_held_passes() {
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let store = InMemoryStagingStore::default();
        let cell = OwedCell::default();
        let owed = OwedRotation::new(&store, BookkeepingSeal::new(&mine, &entropy), &mine, &cell);
        let held = [1; 16];
        block_on(async {
            owed.owe(node(1), revoke()).await.expect("the entry lands");
            owed.owe(node(2), revoke()).await.expect("the entry lands");
            owed.bound(node(1), UnixMillis(0))
                .await
                .expect("the store answers")
                .held(&held);

            store.interrupt_staged_write_after(&owed_rotation_key(&mine), 0);
            assert!(owed.clear(node(1)).await.is_err());
            assert_eq!(cell.held_passes(node(1), &held), 1);

            owed.clear(node(1)).await.expect("the clear lands");
            assert_eq!(cell.held_passes(node(1), &held), 0);
        });
    }

    /// An entry that advances to its next step starts that step's bound again.
    #[test]
    fn an_advance_starts_the_bound_of_the_next_step_again() {
        let entropy = RefCell::new(SeededEntropy::new(7));
        let mine = secret(9);
        let store = InMemoryStagingStore::default();
        let cell = OwedCell::default();
        let owed = OwedRotation::new(&store, BookkeepingSeal::new(&mine, &entropy), &mine, &cell);
        let start = UnixMillis(1_000);
        let after = start.saturating_add(DROP_BOUND);
        let held = [1; 16];
        block_on(async {
            owed.owe(node(1), revoke()).await.expect("the entry lands");
            for _ in 0..DROP_BOUND_PASSES {
                cell.next_pass();
                owed.bound(node(1), after)
                    .await
                    .expect("the store answers")
                    .held(&held);
                owed.note_stop(node(1), start)
                    .await
                    .expect("the stop lands");
            }
            let write_cut = OwedStep::WriteCut { write_epoch: 4 };
            owed.advance_to(node(1), &write_cut)
                .await
                .expect("the advance lands");
            assert_eq!(
                owed.entry(node(1))
                    .await
                    .expect("the store answers")
                    .and_then(|e| e.first_stop),
                None
            );
            assert_eq!(owed.scopes_within_bound(after).await, Ok(vec![node(1)]));
            cell.next_pass();
            assert!(
                !owed
                    .bound(node(1), after)
                    .await
                    .expect("the store answers")
                    .past(&held, false)
            );

            owed.note_stop(node(1), start)
                .await
                .expect("the stop lands");
            owed.leave(node(1), vec![write_cut])
                .await
                .expect("the same step stays");
            assert_eq!(
                owed.entry(node(1))
                    .await
                    .expect("the store answers")
                    .and_then(|e| e.first_stop),
                Some(start),
                "a step that does not change keeps its bound"
            );
            owed.leave(node(1), Vec::new())
                .await
                .expect("the write cut lands");
            assert_eq!(cell.held_passes(node(1), &held), 0);
        });
    }
}
