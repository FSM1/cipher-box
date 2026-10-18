//! The dissolve's own payload in the subtree re-seal journal (ADR 0077 D3):
//! caller [`DISSOLVE_CALLER`] of [`crate::sync::reseal_journal`].
//!
//! One entry is a header (part `h`), the pages of the id map (part `m`, by
//! generation and page) and the name log (part `n`, by index). The header is
//! the commit point: a page that the header does not count is not part of the
//! entry. Each shape has one check that encode and decode both run
//! (AGENTS.md rule 8), and [`DissolveJournal`] holds the rules that compare a
//! header with the one it replaces.

use std::collections::BTreeSet;

use core::cell::RefCell;

use crate::facade::NodeId;
use crate::seams::{SeamError, SeamResult, StagingStore};
use crate::sync::BookkeepingSeal;
use crate::sync::reseal_journal::{
    JournalError, JournalSlot, Journaled, ResealEnvelope, ResealJournal,
};

/// The caller byte of a dissolve entry.
pub const DISSOLVE_CALLER: u8 = 1;
/// The most parent names one relink publishes at.
pub const MAX_RELINK_NAMES: usize = 8;
/// The most destination bindings an entry keeps from before a rebind.
pub const MAX_PRIOR_BINDINGS: usize = 4;
/// The most scope roots one dissolve cuts.
pub const MAX_DISSOLVED_SCOPES: usize = 64;
/// The most rows of one map page, and entries of one name log page.
pub const MAX_PAGE_ENTRIES: usize = 1024;
/// The most bytes of one IPNS name that the journal records.
pub const MAX_JOURNAL_NAME: usize = 64;
/// The `parent` of the root row.
const ROOT_PARENT: u32 = u32::MAX;

const HEADER_PART: &[u8] = b"h";
const MAP_PART: u8 = b'm';
const LOG_PART: u8 = b'n';

const FLAG_COPY_STARTED: u8 = 1;
const FLAG_RELINK_SENT: u8 = 1 << 1;
const FLAG_PARKED: u8 = 1 << 2;
const MANIFEST_SET: u8 = 1;
const MANIFEST_RETIRED: u8 = 1 << 1;

/// The step a dissolve still owes, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DissolveStep {
    /// Cut every grant of each scope, then publish its final records again.
    Cut = 1,
    /// Walk the cut subtree and mint the new ids.
    Map = 2,
    /// Seal each node again under the destination.
    Seal = 3,
    /// Name the copy in the relink parent.
    Relink = 4,
    /// Remove the source root from the parent's index.
    Unindex = 5,
    /// Retire the old names.
    Retire = 6,
    /// Keep the final records until their term ends.
    Hold = 7,
}

impl DissolveStep {
    fn of(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Cut,
            2 => Self::Map,
            3 => Self::Seal,
            4 => Self::Relink,
            5 => Self::Unindex,
            6 => Self::Retire,
            7 => Self::Hold,
            _ => return None,
        })
    }
}

/// The destination of the copy: the read scope and the write scope, each
/// with the epochs the entry seals at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DissolveBinding {
    /// The read scope of the relink parent.
    pub read_scope: NodeId,
    /// The read epoch the copy seals at.
    pub read_epoch: u64,
    /// Below this read epoch, a sealed copy seals again.
    pub restart_floor: u64,
    /// The cut epoch of the read scope's commitment at bind time.
    pub base_cut: u64,
    /// The write scope that derives each copy name.
    pub write_scope: NodeId,
    /// The write epoch of that scope.
    pub write_epoch: u64,
}

/// A destination binding from before a rebind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorBinding {
    /// The read scope.
    pub read_scope: NodeId,
    /// That read scope's root.
    pub read_root: NodeId,
    /// The read epoch.
    pub read_epoch: u64,
    /// The restart floor.
    pub restart_floor: u64,
    /// The write scope.
    pub write_scope: NodeId,
    /// The write epoch.
    pub write_epoch: u64,
}

/// The final records of one cut scope, from gated reads before the relink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The scheduler time at which the final records retire.
    pub hold_until: u64,
    /// The scope pointer name.
    pub pointer_name: Vec<u8>,
    /// The final root name.
    pub final_root_name: Vec<u8>,
    /// The head CID of the final root.
    pub head_cid: Vec<u8>,
    /// The final records retired.
    pub retired: bool,
}

/// One scope root that the dissolve cuts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissolvedScope {
    /// The scope id, which is also its root's node id.
    pub scope_id: NodeId,
    /// The cut epoch the dissolve's cut left, 0 until the cut lands.
    pub cut_epoch: u64,
    /// The scheduler time of the cut, 0 until it is set. Set once.
    pub cut_time: u64,
    /// The final records, from the relink on.
    pub manifest: Option<Manifest>,
}

impl DissolvedScope {
    /// A scope that the dissolve has not cut yet.
    pub fn uncut(scope_id: NodeId) -> Self {
        Self {
            scope_id,
            cut_epoch: 0,
            cut_time: 0,
            manifest: None,
        }
    }
}

/// The header of a dissolve entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissolveHeader {
    /// The step still owed.
    pub step: DissolveStep,
    /// A re-seal publish may have run. Sticky.
    pub copy_started: bool,
    /// A relink publish may have run. Sticky.
    pub relink_sent: bool,
    /// The relink result is not proved.
    pub parked: bool,
    /// The id of the copy's root.
    pub new_root: NodeId,
    /// The folder that names the source root.
    pub relink_parent: NodeId,
    /// The current destination.
    pub binding: DissolveBinding,
    /// The generation of the live map.
    pub map_gen: u16,
    /// The page count of the live map.
    pub map_pages: u16,
    /// The row count of the live map.
    pub rows: u32,
    /// The map pages that the retire step finished.
    pub retire_cursor: u16,
    /// Each parent name a relink publish targets. Sticky.
    pub relink_names: Vec<Vec<u8>>,
    /// The destinations from before each rebind. Append-only.
    pub prior_bindings: Vec<PriorBinding>,
    /// The cut scopes, the source root first. Append-only.
    pub scopes: Vec<DissolvedScope>,
}

impl DissolveHeader {
    /// A new entry at [`DissolveStep::Cut`] over `scopes`, `scopes[0]` the
    /// source root.
    pub fn at_cut(
        new_root: NodeId,
        relink_parent: NodeId,
        binding: DissolveBinding,
        scopes: Vec<DissolvedScope>,
    ) -> Self {
        Self {
            step: DissolveStep::Cut,
            copy_started: false,
            relink_sent: false,
            parked: false,
            new_root,
            relink_parent,
            binding,
            map_gen: 0,
            map_pages: 0,
            rows: 0,
            retire_cursor: 0,
            relink_names: Vec::new(),
            prior_bindings: Vec::new(),
            scopes,
        }
    }
}

/// One row of the id map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRow {
    /// The source node id.
    pub old: NodeId,
    /// The copy's node id.
    pub new: NodeId,
    /// The map index of the parent row, `None` for the root row.
    pub parent: Option<u32>,
    /// The source node's name.
    pub old_name: Vec<u8>,
}

/// One page of the id map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapPage {
    /// The map generation.
    pub generation: u16,
    /// The page index in that generation.
    pub page: u16,
    /// The rows, in map order.
    pub rows: Vec<MapRow>,
}

/// One name the copy published at, bound to its node id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedName {
    /// The node id.
    pub id: NodeId,
    /// The name.
    pub name: Vec<u8>,
}

/// One page of the name log. A page is never rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameLogPage {
    /// The page index.
    pub index: u32,
    /// The names, in publish order.
    pub entries: Vec<LoggedName>,
}

/// Why a dissolve payload does not encode or decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DissolveCodecError {
    /// Fewer bytes than the shape needs.
    Truncated,
    /// Bytes after the shape.
    TrailingBytes,
    /// A step byte that this build does not know.
    UnknownStep,
    /// A flag bit that this build does not know.
    UnknownFlag,
    /// `scopes` is empty, or its first scope is not the source root.
    SourceScopeFirst,
    /// A scope appears twice.
    DuplicateScope,
    /// A count or a length over its cap, or an empty name.
    OverCap,
    /// A page key and its body name different pages.
    PageKeyMismatch,
    /// A step before the copy holds a map, a relink mark or a manifest.
    BeforeTheCopy,
    /// A step from the seal on holds no map, or a row count that is not the
    /// sum of its pages.
    RowCount,
    /// The map is not one rooted tree in map order with distinct ids.
    MapShape,
    /// A step from the relink on has a scope with no manifest.
    ManifestMissing,
    /// `parked` outside the relink step.
    ParkedOutsideRelink,
    /// A retired manifest outside the hold step.
    RetiredOutsideHold,
    /// A retire cursor past the map, or outside the retire step.
    RetireCursor,
    /// The hold step still holds a map.
    MapAtHold,
}

impl DissolveCodecError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Truncated => "dissolve-journal-truncated",
            Self::TrailingBytes => "dissolve-journal-trailing-bytes",
            Self::UnknownStep => "dissolve-journal-unknown-step",
            Self::UnknownFlag => "dissolve-journal-unknown-flag",
            Self::SourceScopeFirst => "dissolve-journal-source-scope-not-first",
            Self::DuplicateScope => "dissolve-journal-duplicate-scope",
            Self::OverCap => "dissolve-journal-over-cap",
            Self::PageKeyMismatch => "dissolve-journal-page-key-mismatch",
            Self::BeforeTheCopy => "dissolve-journal-copy-state-before-the-copy",
            Self::RowCount => "dissolve-journal-row-count",
            Self::MapShape => "dissolve-journal-map-shape",
            Self::ManifestMissing => "dissolve-journal-manifest-missing",
            Self::ParkedOutsideRelink => "dissolve-journal-parked-outside-relink",
            Self::RetiredOutsideHold => "dissolve-journal-retired-outside-hold",
            Self::RetireCursor => "dissolve-journal-retire-cursor",
            Self::MapAtHold => "dissolve-journal-map-at-hold",
        }
    }
}

fn name_ok(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= MAX_JOURNAL_NAME
}

fn cap(ok: bool) -> Result<(), DissolveCodecError> {
    ok.then_some(()).ok_or(DissolveCodecError::OverCap)
}

/// The check that encode and decode share for a header at the entry of
/// `source_root`.
fn check_header(header: &DissolveHeader, source_root: NodeId) -> Result<(), DissolveCodecError> {
    use DissolveCodecError as E;
    use DissolveStep as S;
    if header.scopes.first().map(|scope| scope.scope_id) != Some(source_root) {
        return Err(E::SourceScopeFirst);
    }
    cap(header.scopes.len() <= MAX_DISSOLVED_SCOPES
        && header.relink_names.len() <= MAX_RELINK_NAMES
        && header.prior_bindings.len() <= MAX_PRIOR_BINDINGS
        && header.relink_names.iter().all(|name| name_ok(name)))?;
    let mut seen = BTreeSet::new();
    for scope in &header.scopes {
        if !seen.insert(scope.scope_id) {
            return Err(E::DuplicateScope);
        }
        if let Some(manifest) = &scope.manifest {
            cap(name_ok(&manifest.pointer_name)
                && name_ok(&manifest.final_root_name)
                && !manifest.head_cid.is_empty()
                && manifest.head_cid.len() <= usize::from(u8::MAX))?;
            if manifest.retired && header.step != S::Hold {
                return Err(E::RetiredOutsideHold);
            }
        }
    }
    if (header.map_pages == 0) != (header.rows == 0) {
        return Err(E::RowCount);
    }
    let before_copy = matches!(header.step, S::Cut | S::Map);
    if before_copy
        && ((header.map_pages != 0 && !header.copy_started)
            || header.relink_sent
            || header.parked
            || !header.relink_names.is_empty()
            || header.scopes.iter().any(|scope| scope.manifest.is_some()))
    {
        return Err(E::BeforeTheCopy);
    }
    if (S::Seal..=S::Retire).contains(&header.step) && header.map_pages == 0 {
        return Err(E::RowCount);
    }
    if header.step >= S::Relink && header.scopes.iter().any(|scope| scope.manifest.is_none()) {
        return Err(E::ManifestMissing);
    }
    if header.parked && header.step != S::Relink {
        return Err(E::ParkedOutsideRelink);
    }
    if header.retire_cursor > header.map_pages
        || (header.retire_cursor != 0 && header.step != S::Retire)
    {
        return Err(E::RetireCursor);
    }
    if header.step == S::Hold && header.map_pages != 0 {
        return Err(E::MapAtHold);
    }
    Ok(())
}

/// The check that the writer and the reader of a map share: the live pages
/// of `header`, in page order, form one rooted tree in map order with
/// distinct ids, and hold `header.rows` rows.
pub fn check_map(
    header: &DissolveHeader,
    source_root: NodeId,
    pages: &[MapPage],
) -> Result<(), DissolveCodecError> {
    use DissolveCodecError as E;
    if pages.len() != usize::from(header.map_pages)
        || pages
            .iter()
            .enumerate()
            .any(|(at, page)| page.generation != header.map_gen || usize::from(page.page) != at)
    {
        return Err(E::RowCount);
    }
    let rows: Vec<&MapRow> = pages.iter().flat_map(|page| &page.rows).collect();
    if u32::try_from(rows.len()) != Ok(header.rows) {
        return Err(E::RowCount);
    }
    let root_row = rows.first().ok_or(E::RowCount)?;
    if root_row.old != source_root || root_row.new != header.new_root || root_row.parent.is_some() {
        return Err(E::MapShape);
    }
    let mut old = BTreeSet::new();
    let mut new = BTreeSet::new();
    for (at, row) in rows.iter().enumerate() {
        let parent_ok = match row.parent {
            None => at == 0,
            Some(parent) => usize::try_from(parent).is_ok_and(|parent| parent < at),
        };
        if !parent_ok || !old.insert(row.old) || !new.insert(row.new) {
            return Err(E::MapShape);
        }
    }
    if !old.is_disjoint(&new) {
        return Err(E::MapShape);
    }
    Ok(())
}

fn check_map_page(page: &MapPage, generation: u16, index: u16) -> Result<(), DissolveCodecError> {
    if page.generation != generation || page.page != index {
        return Err(DissolveCodecError::PageKeyMismatch);
    }
    cap(page.rows.len() <= MAX_PAGE_ENTRIES
        && page
            .rows
            .iter()
            .all(|row| name_ok(&row.old_name) && row.parent != Some(ROOT_PARENT)))
}

fn check_name_log_page(page: &NameLogPage, index: u32) -> Result<(), DissolveCodecError> {
    if page.index != index {
        return Err(DissolveCodecError::PageKeyMismatch);
    }
    cap(page.entries.len() <= MAX_PAGE_ENTRIES
        && page.entries.iter().all(|entry| name_ok(&entry.name)))
}

fn push_name(out: &mut Vec<u8>, name: &[u8]) {
    // Each caller's check bounds `name` to one length byte.
    out.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(name);
}

fn bit(on: bool, flag: u8) -> u8 {
    if on { flag } else { 0 }
}

fn push_count(out: &mut Vec<u8>, count: usize) {
    out.push(u8::try_from(count).unwrap_or(u8::MAX));
}

/// The header payload of the entry at `source_root`.
pub fn encode_dissolve_header(
    header: &DissolveHeader,
    source_root: NodeId,
) -> Result<Vec<u8>, DissolveCodecError> {
    check_header(header, source_root)?;
    let mut out = Vec::new();
    out.push(header.step as u8);
    out.push(
        bit(header.copy_started, FLAG_COPY_STARTED)
            | bit(header.relink_sent, FLAG_RELINK_SENT)
            | bit(header.parked, FLAG_PARKED),
    );
    out.extend_from_slice(&header.new_root.0);
    out.extend_from_slice(&header.relink_parent.0);
    let binding = &header.binding;
    out.extend_from_slice(&binding.read_scope.0);
    out.extend_from_slice(&binding.read_epoch.to_be_bytes());
    out.extend_from_slice(&binding.restart_floor.to_be_bytes());
    out.extend_from_slice(&binding.base_cut.to_be_bytes());
    out.extend_from_slice(&binding.write_scope.0);
    out.extend_from_slice(&binding.write_epoch.to_be_bytes());
    out.extend_from_slice(&header.map_gen.to_be_bytes());
    out.extend_from_slice(&header.map_pages.to_be_bytes());
    out.extend_from_slice(&header.rows.to_be_bytes());
    out.extend_from_slice(&header.retire_cursor.to_be_bytes());
    push_count(&mut out, header.relink_names.len());
    for name in &header.relink_names {
        push_name(&mut out, name);
    }
    push_count(&mut out, header.prior_bindings.len());
    for prior in &header.prior_bindings {
        out.extend_from_slice(&prior.read_scope.0);
        out.extend_from_slice(&prior.read_root.0);
        out.extend_from_slice(&prior.read_epoch.to_be_bytes());
        out.extend_from_slice(&prior.restart_floor.to_be_bytes());
        out.extend_from_slice(&prior.write_scope.0);
        out.extend_from_slice(&prior.write_epoch.to_be_bytes());
    }
    push_count(&mut out, header.scopes.len());
    for scope in &header.scopes {
        out.extend_from_slice(&scope.scope_id.0);
        out.extend_from_slice(&scope.cut_epoch.to_be_bytes());
        out.extend_from_slice(&scope.cut_time.to_be_bytes());
        match &scope.manifest {
            None => out.push(0),
            Some(manifest) => {
                out.push(MANIFEST_SET | bit(manifest.retired, MANIFEST_RETIRED));
                out.extend_from_slice(&manifest.hold_until.to_be_bytes());
                push_name(&mut out, &manifest.pointer_name);
                push_name(&mut out, &manifest.final_root_name);
                push_name(&mut out, &manifest.head_cid);
            }
        }
    }
    Ok(out)
}

/// A big-endian reader that refuses a short body.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], DissolveCodecError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(DissolveCodecError::Truncated)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, DissolveCodecError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, DissolveCodecError> {
        self.take().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, DissolveCodecError> {
        self.take().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, DissolveCodecError> {
        self.take().map(u64::from_be_bytes)
    }

    fn id(&mut self) -> Result<NodeId, DissolveCodecError> {
        self.take().map(NodeId)
    }

    fn name(&mut self) -> Result<Vec<u8>, DissolveCodecError> {
        let len = usize::from(self.u8()?);
        if self.0.len() < len {
            return Err(DissolveCodecError::Truncated);
        }
        let (name, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(name.to_vec())
    }

    fn end(&self) -> Result<(), DissolveCodecError> {
        self.0
            .is_empty()
            .then_some(())
            .ok_or(DissolveCodecError::TrailingBytes)
    }
}

/// The header that `payload` holds at the entry of `source_root`.
pub fn decode_dissolve_header(
    payload: &[u8],
    source_root: NodeId,
) -> Result<DissolveHeader, DissolveCodecError> {
    let mut r = Reader(payload);
    let step = DissolveStep::of(r.u8()?).ok_or(DissolveCodecError::UnknownStep)?;
    let flags = r.u8()?;
    if flags & !(FLAG_COPY_STARTED | FLAG_RELINK_SENT | FLAG_PARKED) != 0 {
        return Err(DissolveCodecError::UnknownFlag);
    }
    let new_root = r.id()?;
    let relink_parent = r.id()?;
    let binding = DissolveBinding {
        read_scope: r.id()?,
        read_epoch: r.u64()?,
        restart_floor: r.u64()?,
        base_cut: r.u64()?,
        write_scope: r.id()?,
        write_epoch: r.u64()?,
    };
    let map_gen = r.u16()?;
    let map_pages = r.u16()?;
    let rows = r.u32()?;
    let retire_cursor = r.u16()?;
    let relink_names = (0..r.u8()?).map(|_| r.name()).collect::<Result<_, _>>()?;
    let prior_bindings = (0..r.u8()?)
        .map(|_| {
            Ok(PriorBinding {
                read_scope: r.id()?,
                read_root: r.id()?,
                read_epoch: r.u64()?,
                restart_floor: r.u64()?,
                write_scope: r.id()?,
                write_epoch: r.u64()?,
            })
        })
        .collect::<Result<_, _>>()?;
    let scopes = (0..r.u8()?)
        .map(|_| {
            let scope_id = r.id()?;
            let cut_epoch = r.u64()?;
            let cut_time = r.u64()?;
            let manifest = match r.u8()? {
                0 => None,
                bits if bits & !(MANIFEST_SET | MANIFEST_RETIRED) == 0
                    && bits & MANIFEST_SET != 0 =>
                {
                    Some(Manifest {
                        hold_until: r.u64()?,
                        pointer_name: r.name()?,
                        final_root_name: r.name()?,
                        head_cid: r.name()?,
                        retired: bits & MANIFEST_RETIRED != 0,
                    })
                }
                _ => return Err(DissolveCodecError::UnknownFlag),
            };
            Ok(DissolvedScope {
                scope_id,
                cut_epoch,
                cut_time,
                manifest,
            })
        })
        .collect::<Result<_, _>>()?;
    r.end()?;
    let header = DissolveHeader {
        step,
        copy_started: flags & FLAG_COPY_STARTED != 0,
        relink_sent: flags & FLAG_RELINK_SENT != 0,
        parked: flags & FLAG_PARKED != 0,
        new_root,
        relink_parent,
        binding,
        map_gen,
        map_pages,
        rows,
        retire_cursor,
        relink_names,
        prior_bindings,
        scopes,
    };
    check_header(&header, source_root)?;
    Ok(header)
}

/// The payload of one map page.
pub fn encode_map_page(page: &MapPage) -> Result<Vec<u8>, DissolveCodecError> {
    check_map_page(page, page.generation, page.page)?;
    let mut out = Vec::new();
    out.extend_from_slice(&page.generation.to_be_bytes());
    out.extend_from_slice(&page.page.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(page.rows.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for row in &page.rows {
        out.extend_from_slice(&row.old.0);
        out.extend_from_slice(&row.new.0);
        out.extend_from_slice(&row.parent.unwrap_or(ROOT_PARENT).to_be_bytes());
        push_name(&mut out, &row.old_name);
    }
    Ok(out)
}

/// The map page that `payload` holds at the key of `generation` and `index`.
pub fn decode_map_page(
    payload: &[u8],
    generation: u16,
    index: u16,
) -> Result<MapPage, DissolveCodecError> {
    let mut r = Reader(payload);
    let page_generation = r.u16()?;
    let page_index = r.u16()?;
    let rows = (0..r.u16()?)
        .map(|_| {
            Ok(MapRow {
                old: r.id()?,
                new: r.id()?,
                parent: Some(r.u32()?).filter(|parent| *parent != ROOT_PARENT),
                old_name: r.name()?,
            })
        })
        .collect::<Result<_, _>>()?;
    r.end()?;
    let page = MapPage {
        generation: page_generation,
        page: page_index,
        rows,
    };
    check_map_page(&page, generation, index)?;
    Ok(page)
}

/// The payload of one name log page.
pub fn encode_name_log_page(page: &NameLogPage) -> Result<Vec<u8>, DissolveCodecError> {
    check_name_log_page(page, page.index)?;
    let mut out = Vec::new();
    out.extend_from_slice(&page.index.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(page.entries.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for entry in &page.entries {
        out.extend_from_slice(&entry.id.0);
        push_name(&mut out, &entry.name);
    }
    Ok(out)
}

/// The name log page that `payload` holds at the key of `index`.
pub fn decode_name_log_page(payload: &[u8], index: u32) -> Result<NameLogPage, DissolveCodecError> {
    let mut r = Reader(payload);
    let page_index = r.u32()?;
    let entries = (0..r.u16()?)
        .map(|_| {
            Ok(LoggedName {
                id: r.id()?,
                name: r.name()?,
            })
        })
        .collect::<Result<_, _>>()?;
    r.end()?;
    let page = NameLogPage {
        index: page_index,
        entries,
    };
    check_name_log_page(&page, index)?;
    Ok(page)
}

/// The rules that compare a header with the one it replaces: the entry keeps
/// its copy root and its relink parent, a set `cut_time` stays, the sticky
/// flags and lists only grow, and the scopes and the prior bindings only take
/// additions at their end. A rebind to another read or write scope appends
/// the former binding. For one read scope, the restart floor does not fall.
fn check_successor(held: &DissolveHeader, new: &DissolveHeader) -> Result<(), &'static str> {
    if held.new_root != new.new_root || held.relink_parent != new.relink_parent {
        return Err("dissolve-journal-entry-identity-changed");
    }
    let keeps_prefix = |held_len: usize, new_len: usize| held_len <= new_len;
    if !keeps_prefix(held.scopes.len(), new.scopes.len())
        || held
            .scopes
            .iter()
            .zip(&new.scopes)
            .any(|(was, now)| was.scope_id != now.scope_id)
    {
        return Err("dissolve-journal-scopes-not-append-only");
    }
    if held
        .scopes
        .iter()
        .zip(&new.scopes)
        .any(|(was, now)| was.cut_time != 0 && was.cut_time != now.cut_time)
    {
        return Err("dissolve-journal-cut-time-set-once");
    }
    if (held.copy_started && !new.copy_started)
        || (held.relink_sent && !new.relink_sent)
        || !new.relink_names.starts_with(&held.relink_names)
    {
        return Err("dissolve-journal-sticky-mark-cleared");
    }
    if !new.prior_bindings.starts_with(&held.prior_bindings) {
        return Err("dissolve-journal-prior-bindings-not-append-only");
    }
    let (was, now) = (&held.binding, &new.binding);
    let rebind = was.read_scope != now.read_scope || was.write_scope != now.write_scope;
    let appended = &new.prior_bindings[held.prior_bindings.len()..];
    let keeps_former = |prior: &PriorBinding| {
        prior.read_scope == was.read_scope
            && prior.read_epoch == was.read_epoch
            && prior.restart_floor == was.restart_floor
            && prior.write_scope == was.write_scope
            && prior.write_epoch == was.write_epoch
    };
    let rebind_ok = match appended {
        [] => !rebind,
        [prior] => rebind && keeps_former(prior),
        _ => false,
    };
    if !rebind_ok {
        return Err("dissolve-journal-rebind-without-prior-binding");
    }
    if was.read_scope == now.read_scope && now.restart_floor < was.restart_floor {
        return Err("dissolve-journal-restart-floor-lowered");
    }
    Ok(())
}

/// What the header key of one source root holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderSlot {
    /// No entry.
    Absent,
    /// A dissolve entry.
    Own(DissolveHeader),
    /// An entry of another caller.
    Foreign,
    /// A value that does not open, or does not decode. It blocks its root.
    Unreadable,
}

/// Why a dissolve journal write did not land.
#[derive(Debug)]
pub enum DissolveWriteError {
    /// The payload does not encode.
    Codec(DissolveCodecError),
    /// The new header breaks a rule against the held one.
    Successor(&'static str),
    /// The header in the store is not the one the writer read.
    Stale,
    /// The key holds a value that does not read, or another caller's entry.
    Blocked,
    /// A name log page at that index exists already.
    LogPageWritten,
    /// The page is a page of the live map. A remap writes a new generation.
    LiveMapPage,
    /// The staging store or the seal failed.
    Store(SeamError),
}

impl DissolveWriteError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.check(),
            Self::Successor(check) => check,
            Self::Stale => "dissolve-journal-stale-header",
            Self::Blocked => "dissolve-journal-blocked",
            Self::LogPageWritten => "dissolve-journal-log-page-written",
            Self::LiveMapPage => "dissolve-journal-live-map-page",
            Self::Store(_) => "dissolve-journal-not-durable",
        }
    }
}

impl From<JournalError> for DissolveWriteError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::Store(error) => Self::Store(error),
            JournalError::Envelope(_) | JournalError::Unreadable | JournalError::OtherCaller => {
                Self::Blocked
            }
        }
    }
}

/// The session's dissolve drivers: one per source root at a time, and one
/// header write at a time.
#[derive(Default)]
pub struct DissolveCell {
    held: RefCell<BTreeSet<NodeId>>,
    writer: futures_util::lock::Mutex<()>,
    /// The source roots with an entry, `None` until this session lists the
    /// store. A pass then needs no listing of its own.
    roots: RefCell<Option<BTreeSet<NodeId>>>,
}

impl DissolveCell {
    /// Drop what this session knows of the store, so the next session lists
    /// it again.
    pub fn forget(&self) {
        if let Ok(mut roots) = self.roots.try_borrow_mut() {
            *roots = None;
        }
    }

    fn note(&self, root: NodeId, present: bool) {
        if let Some(roots) = self.roots.borrow_mut().as_mut() {
            if present {
                roots.insert(root);
            } else {
                roots.remove(&root);
            }
        }
    }

    /// Take the entry at `root` for one driver until the hold drops, or
    /// `None` while another driver holds it.
    pub fn hold(&self, root: NodeId) -> Option<DissolveHold<'_>> {
        self.held
            .borrow_mut()
            .insert(root)
            .then(|| DissolveHold { cell: self, root })
    }
}

/// One driver's hold of a dissolve entry.
pub struct DissolveHold<'a> {
    cell: &'a DissolveCell,
    root: NodeId,
}

impl DissolveHold<'_> {
    /// The source root this hold takes.
    pub fn root(&self) -> NodeId {
        self.root
    }
}

impl Drop for DissolveHold<'_> {
    fn drop(&mut self) {
        self.cell.held.borrow_mut().remove(&self.root);
    }
}

/// One owner's dissolve entries in the staging store. Every write goes
/// through a [`DissolveHold`] of its root.
pub struct DissolveJournal<'a, S> {
    journal: ResealJournal<'a, S>,
    cell: &'a DissolveCell,
}

impl<'a, S: StagingStore> DissolveJournal<'a, S> {
    /// The journal of the owner of `seal`, over the session's `cell`.
    pub fn new(store: &'a S, seal: BookkeepingSeal<'a>, cell: &'a DissolveCell) -> Self {
        Self {
            journal: ResealJournal::new(store, seal),
            cell,
        }
    }

    /// Every source root that a journal key names.
    pub async fn journaled(&self) -> SeamResult<Journaled> {
        self.journal.journaled().await
    }

    /// Every source root that a journal key names, listed once in a session
    /// and then kept up to date by this journal's own writes.
    pub async fn roots(&self) -> SeamResult<BTreeSet<NodeId>> {
        if let Some(roots) = self.cell.roots.borrow().as_ref() {
            return Ok(roots.clone());
        }
        // A write notes its root only in a kept listing, so the listing
        // holds the writer.
        let _writer = self.cell.writer.lock().await;
        if let Some(roots) = self.cell.roots.borrow().as_ref() {
            return Ok(roots.clone());
        }
        let roots = self.journaled().await?.roots;
        *self.cell.roots.borrow_mut() = Some(roots.clone());
        Ok(roots)
    }

    /// The payload of `part` of the entry at `root`: `None` when absent,
    /// `Some(Err(()))` when it does not read as a dissolve value.
    async fn payload(&self, root: NodeId, part: &[u8]) -> SeamResult<Option<Result<Vec<u8>, ()>>> {
        Ok(match self.journal.read(root, part).await? {
            JournalSlot::Absent => None,
            JournalSlot::Kept(envelope) if envelope.caller == DISSOLVE_CALLER => {
                Some(Ok(envelope.payload))
            }
            JournalSlot::Kept(_) | JournalSlot::Unreadable => Some(Err(())),
        })
    }

    /// What the header key of `root` holds.
    pub async fn header(&self, root: NodeId) -> SeamResult<HeaderSlot> {
        Ok(match self.journal.read(root, HEADER_PART).await? {
            JournalSlot::Absent => HeaderSlot::Absent,
            JournalSlot::Kept(envelope) if envelope.caller == DISSOLVE_CALLER => {
                decode_dissolve_header(&envelope.payload, root)
                    .map_or(HeaderSlot::Unreadable, HeaderSlot::Own)
            }
            JournalSlot::Kept(_) => HeaderSlot::Foreign,
            JournalSlot::Unreadable => HeaderSlot::Unreadable,
        })
    }

    /// The dissolve header at `root`, `None` when absent. Refused when the
    /// key holds a value that does not read, or another caller's entry.
    async fn standing(&self, root: NodeId) -> Result<Option<DissolveHeader>, DissolveWriteError> {
        match self.header(root).await.map_err(DissolveWriteError::Store)? {
            HeaderSlot::Absent => Ok(None),
            HeaderSlot::Own(header) => Ok(Some(header)),
            HeaderSlot::Foreign | HeaderSlot::Unreadable => Err(DissolveWriteError::Blocked),
        }
    }

    async fn put(
        &self,
        root: NodeId,
        part: &[u8],
        payload: Vec<u8>,
    ) -> Result<(), DissolveWriteError> {
        self.journal
            .put(
                part,
                &ResealEnvelope {
                    caller: DISSOLVE_CALLER,
                    source_root: root,
                    payload,
                },
            )
            .await
            .map_err(DissolveWriteError::from)
    }

    /// Replace the header `held` at the root of `hold` with `new`, or write
    /// the first header when `held` is `None`. Refused when the store holds
    /// another header, and when `new` breaks a rule against `held`.
    pub async fn commit(
        &self,
        hold: &DissolveHold<'_>,
        held: Option<&DissolveHeader>,
        new: &DissolveHeader,
    ) -> Result<(), DissolveWriteError> {
        let root = hold.root;
        let payload = encode_dissolve_header(new, root).map_err(DissolveWriteError::Codec)?;
        if let Some(held) = held {
            check_successor(held, new).map_err(DissolveWriteError::Successor)?;
        }
        let _writer = self.cell.writer.lock().await;
        if self.standing(root).await?.as_ref() != held {
            return Err(DissolveWriteError::Stale);
        }
        if new.map_pages != 0 {
            let pages = self.pages(root, new.map_gen, new.map_pages).await?;
            check_map(new, root, &pages).map_err(DissolveWriteError::Codec)?;
        }
        self.put(root, HEADER_PART, payload).await?;
        self.cell.note(root, true);
        Ok(())
    }

    fn map_part(generation: u16, page: u16) -> Vec<u8> {
        let mut part = vec![MAP_PART];
        part.extend_from_slice(&generation.to_be_bytes());
        part.extend_from_slice(&page.to_be_bytes());
        part
    }

    fn log_part(index: u32) -> Vec<u8> {
        let mut part = vec![LOG_PART];
        part.extend_from_slice(&index.to_be_bytes());
        part
    }

    async fn pages(
        &self,
        root: NodeId,
        generation: u16,
        count: u16,
    ) -> Result<Vec<MapPage>, DissolveWriteError> {
        let mut pages = Vec::with_capacity(usize::from(count));
        for index in 0..count {
            let payload = self
                .payload(root, &Self::map_part(generation, index))
                .await
                .map_err(DissolveWriteError::Store)?
                .ok_or(DissolveWriteError::Codec(DissolveCodecError::RowCount))?
                .map_err(|()| DissolveWriteError::Blocked)?;
            pages.push(
                decode_map_page(&payload, generation, index).map_err(DissolveWriteError::Codec)?,
            );
        }
        Ok(pages)
    }

    /// Write one map page at the root of `hold`. The page joins the entry
    /// only when a header commit counts it, and a page of the live map is
    /// never rewritten: until the next header commits, its generation stays
    /// the map.
    pub async fn put_map_page(
        &self,
        hold: &DissolveHold<'_>,
        page: &MapPage,
    ) -> Result<(), DissolveWriteError> {
        let payload = encode_map_page(page).map_err(DissolveWriteError::Codec)?;
        let _writer = self.cell.writer.lock().await;
        if self
            .standing(hold.root)
            .await?
            .is_some_and(|header| page.generation == header.map_gen && page.page < header.map_pages)
        {
            return Err(DissolveWriteError::LiveMapPage);
        }
        self.put(
            hold.root,
            &Self::map_part(page.generation, page.page),
            payload,
        )
        .await?;
        self.cell.note(hold.root, true);
        Ok(())
    }

    /// The live map of `header` at `root`.
    pub async fn map(
        &self,
        root: NodeId,
        header: &DissolveHeader,
    ) -> Result<Vec<MapPage>, DissolveWriteError> {
        let pages = self.pages(root, header.map_gen, header.map_pages).await?;
        check_map(header, root, &pages).map_err(DissolveWriteError::Codec)?;
        Ok(pages)
    }

    /// Append the name log page `page` at the root of `hold`. A page is never
    /// rewritten.
    pub async fn append_name_log(
        &self,
        hold: &DissolveHold<'_>,
        page: &NameLogPage,
    ) -> Result<(), DissolveWriteError> {
        let payload = encode_name_log_page(page).map_err(DissolveWriteError::Codec)?;
        let part = Self::log_part(page.index);
        let _writer = self.cell.writer.lock().await;
        match self
            .payload(hold.root, &part)
            .await
            .map_err(DissolveWriteError::Store)?
        {
            None => {}
            Some(Ok(_)) => return Err(DissolveWriteError::LogPageWritten),
            Some(Err(())) => return Err(DissolveWriteError::Blocked),
        }
        self.put(hold.root, &part, payload).await?;
        self.cell.note(hold.root, true);
        Ok(())
    }

    /// Every name log page of the entry at `root`, by index.
    pub async fn name_log(&self, root: NodeId) -> Result<Vec<NameLogPage>, DissolveWriteError> {
        let mut indexes = Vec::new();
        for part in self
            .journal
            .parts(root)
            .await
            .map_err(DissolveWriteError::Store)?
        {
            if let Some(rest) = part.strip_prefix(&[LOG_PART]) {
                let index = <[u8; 4]>::try_from(rest).map_err(|_| DissolveWriteError::Blocked)?;
                indexes.push(u32::from_be_bytes(index));
            }
        }
        indexes.sort_unstable();
        let mut pages = Vec::with_capacity(indexes.len());
        for index in indexes {
            let payload = self
                .payload(root, &Self::log_part(index))
                .await
                .map_err(DissolveWriteError::Store)?
                .ok_or(DissolveWriteError::Blocked)?
                .map_err(|()| DissolveWriteError::Blocked)?;
            pages.push(decode_name_log_page(&payload, index).map_err(DissolveWriteError::Codec)?);
        }
        Ok(pages)
    }

    /// Drop the entry at the root of `hold` whose header is `held`: each
    /// page and log page, then the header.
    pub async fn drop_entry(
        &self,
        hold: &DissolveHold<'_>,
        held: &DissolveHeader,
    ) -> Result<(), DissolveWriteError> {
        let root = hold.root;
        let _writer = self.cell.writer.lock().await;
        if self.header(root).await.map_err(DissolveWriteError::Store)?
            != HeaderSlot::Own(held.clone())
        {
            return Err(DissolveWriteError::Stale);
        }
        let mut parts = self
            .journal
            .parts(root)
            .await
            .map_err(DissolveWriteError::Store)?;
        parts.retain(|part| part != HEADER_PART);
        for part in &parts {
            if let Some(Err(())) = self
                .payload(root, part)
                .await
                .map_err(DissolveWriteError::Store)?
            {
                return Err(DissolveWriteError::Blocked);
            }
        }
        for part in parts.iter().map(Vec::as_slice).chain([HEADER_PART]) {
            self.journal.remove(root, part, DISSOLVE_CALLER).await?;
        }
        self.cell.note(root, false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use cipherbox_core::suite::x25519::X25519Secret;

    use super::*;
    use crate::seams::OpId;
    use crate::testkit::fakes::InMemoryStagingStore;
    use crate::testkit::{SeededEntropy, block_on};

    const ROOT: NodeId = NodeId([0x51; 16]);
    const NESTED: NodeId = NodeId([0x52; 16]);
    const NEW_ROOT: NodeId = NodeId([0x61; 16]);

    fn binding() -> DissolveBinding {
        DissolveBinding {
            read_scope: NodeId([0x10; 16]),
            read_epoch: 3,
            restart_floor: 2,
            base_cut: 1,
            write_scope: NodeId([0x10; 16]),
            write_epoch: 4,
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            hold_until: 9_000,
            pointer_name: b"k51pointer".to_vec(),
            final_root_name: b"k51root".to_vec(),
            head_cid: b"bafyhead".to_vec(),
            retired: false,
        }
    }

    /// A valid header at `step`: a map from the seal to the retire, and the
    /// manifests and the relink marks from the relink on.
    fn at(step: DissolveStep) -> DissolveHeader {
        let mut header = DissolveHeader::at_cut(
            NEW_ROOT,
            NodeId([0x20; 16]),
            binding(),
            vec![DissolvedScope::uncut(ROOT), DissolvedScope::uncut(NESTED)],
        );
        header.step = step;
        if (DissolveStep::Seal..=DissolveStep::Retire).contains(&step) {
            header.map_pages = 1;
            header.rows = 2;
            header.copy_started = true;
        }
        if step >= DissolveStep::Relink {
            for scope in &mut header.scopes {
                scope.manifest = Some(manifest());
            }
            header.copy_started = true;
            header.relink_sent = true;
            header.relink_names = vec![b"k51parent".to_vec()];
        }
        header
    }

    fn row(old: u8, new: u8, parent: Option<u32>) -> MapRow {
        MapRow {
            old: NodeId([old; 16]),
            new: NodeId([new; 16]),
            parent,
            old_name: b"k51old".to_vec(),
        }
    }

    fn page(rows: Vec<MapRow>) -> MapPage {
        MapPage {
            generation: 0,
            page: 0,
            rows,
        }
    }

    fn tree() -> MapPage {
        page(vec![row(0x51, 0x61, None), row(0x53, 0x63, Some(0))])
    }

    #[test]
    fn a_header_at_each_step_round_trips() {
        let mut hold = at(DissolveStep::Hold);
        hold.scopes[0].manifest.as_mut().unwrap().retired = true;
        hold.prior_bindings.push(PriorBinding {
            read_scope: NodeId([0x30; 16]),
            read_root: NodeId([0x31; 16]),
            read_epoch: 5,
            restart_floor: 4,
            write_scope: NodeId([0x32; 16]),
            write_epoch: 6,
        });
        let mut parked = at(DissolveStep::Relink);
        parked.parked = true;
        let mut retire = at(DissolveStep::Retire);
        retire.retire_cursor = 1;
        let mut extended = at(DissolveStep::Cut);
        extended.copy_started = true;
        extended.map_pages = 1;
        extended.rows = 2;
        extended.scopes[0].cut_epoch = 7;
        extended.scopes[0].cut_time = 1_500;
        for header in [
            at(DissolveStep::Cut),
            at(DissolveStep::Map),
            at(DissolveStep::Seal),
            parked,
            at(DissolveStep::Unindex),
            retire,
            at(DissolveStep::Hold),
            hold,
            extended,
        ] {
            let payload = encode_dissolve_header(&header, ROOT).expect("a valid header encodes");
            assert_eq!(decode_dissolve_header(&payload, ROOT), Ok(header));
        }
    }

    /// The decoder refuses each byte-level fault the encoder cannot produce.
    #[test]
    fn decode_refuses_bytes_the_encoder_never_writes() {
        let valid = encode_dissolve_header(&at(DissolveStep::Cut), ROOT).unwrap();
        let mut unknown_step = valid.clone();
        unknown_step[0] = 8;
        let mut zero_step = valid.clone();
        zero_step[0] = 0;
        let mut unknown_flag = valid.clone();
        unknown_flag[1] = 1 << 3;
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut unknown_manifest = valid.clone();
        *unknown_manifest.last_mut().unwrap() = 1 << 2;
        let mut retired_unset = valid.clone();
        *retired_unset.last_mut().unwrap() = MANIFEST_RETIRED;
        for (body, refusal) in [
            (unknown_step, DissolveCodecError::UnknownStep),
            (zero_step, DissolveCodecError::UnknownStep),
            (unknown_flag, DissolveCodecError::UnknownFlag),
            (trailing, DissolveCodecError::TrailingBytes),
            (
                valid[..valid.len() - 1].to_vec(),
                DissolveCodecError::Truncated,
            ),
            (unknown_manifest, DissolveCodecError::UnknownFlag),
            (retired_unset, DissolveCodecError::UnknownFlag),
        ] {
            assert_eq!(decode_dissolve_header(&body, ROOT), Err(refusal));
        }
        assert_eq!(
            decode_dissolve_header(&valid, NESTED),
            Err(DissolveCodecError::SourceScopeFirst),
            "the header of another root's key"
        );
    }

    /// The shared check refuses on decode what it refuses on encode.
    #[test]
    fn decode_refuses_a_header_that_encode_refuses() {
        let mut copied = at(DissolveStep::Map);
        copied.copy_started = true;
        copied.map_pages = 1;
        copied.rows = 2;
        let mut payload = encode_dissolve_header(&copied, ROOT).unwrap();
        payload[1] = 0;
        let uncopied = DissolveHeader {
            copy_started: false,
            ..copied
        };
        assert_eq!(
            encode_dissolve_header(&uncopied, ROOT),
            Err(DissolveCodecError::BeforeTheCopy)
        );
        assert_eq!(
            decode_dissolve_header(&payload, ROOT),
            Err(DissolveCodecError::BeforeTheCopy)
        );
    }

    #[test]
    fn map_and_log_pages_round_trip_and_refuse_another_key() {
        let map = tree();
        let payload = encode_map_page(&map).unwrap();
        assert_eq!(decode_map_page(&payload, 0, 0), Ok(map));
        for (generation, index) in [(1, 0), (0, 1)] {
            assert_eq!(
                decode_map_page(&payload, generation, index),
                Err(DissolveCodecError::PageKeyMismatch)
            );
        }

        let log = NameLogPage {
            index: 3,
            entries: vec![LoggedName {
                id: NEW_ROOT,
                name: b"k51new".to_vec(),
            }],
        };
        let payload = encode_name_log_page(&log).unwrap();
        assert_eq!(decode_name_log_page(&payload, 3), Ok(log));
        assert_eq!(
            decode_name_log_page(&payload, 2),
            Err(DissolveCodecError::PageKeyMismatch)
        );
    }

    #[test]
    fn a_map_must_be_one_rooted_tree_with_distinct_ids() {
        let header = at(DissolveStep::Seal);
        assert_eq!(check_map(&header, ROOT, &[tree()]), Ok(()));
        let shapes = [
            // The root row names another source root.
            vec![row(0x53, 0x61, None), row(0x54, 0x63, Some(0))],
            // The root row names another new root.
            vec![row(0x51, 0x62, None), row(0x53, 0x63, Some(0))],
            // The root row has a parent.
            vec![row(0x51, 0x61, Some(0)), row(0x53, 0x63, Some(0))],
            // A second root row.
            vec![row(0x51, 0x61, None), row(0x53, 0x63, None)],
            // A parent that is not an earlier row.
            vec![row(0x51, 0x61, None), row(0x53, 0x63, Some(1))],
            // A duplicate old id.
            vec![row(0x51, 0x61, None), row(0x51, 0x63, Some(0))],
            // A duplicate new id.
            vec![row(0x51, 0x61, None), row(0x53, 0x61, Some(0))],
            // A new id that is also an old id.
            vec![row(0x51, 0x61, None), row(0x61, 0x63, Some(0))],
        ];
        for rows in shapes {
            assert_eq!(
                check_map(&header, ROOT, &[page(rows)]),
                Err(DissolveCodecError::MapShape)
            );
        }
        let short = DissolveHeader { rows: 3, ..header };
        assert_eq!(
            check_map(&short, ROOT, &[tree()]),
            Err(DissolveCodecError::RowCount)
        );
    }

    /// One session of the journal over `store`, with its own cell.
    fn run_on<S: StagingStore>(
        store: &S,
        test: impl AsyncFnOnce(&DissolveJournal<'_, S>, &DissolveCell),
    ) {
        let entropy = RefCell::new(SeededEntropy::new(5));
        let secret = X25519Secret::from_scalar([9; 32]);
        let cell = DissolveCell::default();
        let journal = DissolveJournal::new(store, BookkeepingSeal::new(&secret, &entropy), &cell);
        block_on(test(&journal, &cell));
    }

    fn run(test: impl AsyncFnOnce(&DissolveJournal<'_, InMemoryStagingStore>, &DissolveCell)) {
        run_on(&InMemoryStagingStore::default(), test);
    }

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

    /// A staging store that yields after each read and before each write, and
    /// yields for longer after it lists its keys, so two journal calls that
    /// run together interleave.
    #[derive(Default)]
    struct YieldingStore(InMemoryStagingStore);

    impl StagingStore for YieldingStore {
        async fn enqueue_op(&self, op: &[u8]) -> SeamResult<OpId> {
            self.0.enqueue_op(op).await
        }
        async fn enqueue_ops(&self, ops: &[Vec<u8>]) -> SeamResult<Vec<OpId>> {
            self.0.enqueue_ops(ops).await
        }
        async fn queued_ops(&self) -> SeamResult<Vec<(OpId, Vec<u8>)>> {
            self.0.queued_ops().await
        }
        async fn remove_op(&self, op_id: OpId) -> SeamResult<()> {
            self.0.remove_op(op_id).await
        }
        async fn put_staged_bytes(&self, key: &[u8], bytes: &[u8]) -> SeamResult<()> {
            yield_once().await;
            self.0.put_staged_bytes(key, bytes).await
        }
        async fn staged_bytes(&self, key: &[u8]) -> SeamResult<Option<Vec<u8>>> {
            let bytes = self.0.staged_bytes(key).await;
            yield_once().await;
            bytes
        }
        async fn remove_staged_bytes(&self, key: &[u8]) -> SeamResult<()> {
            yield_once().await;
            self.0.remove_staged_bytes(key).await
        }
        async fn staged_keys(&self) -> SeamResult<Vec<Vec<u8>>> {
            let keys = self.0.staged_keys().await;
            for _ in 0..16 {
                yield_once().await;
            }
            keys
        }
        async fn staged_bytes_total(&self) -> SeamResult<u64> {
            self.0.staged_bytes_total().await
        }
        async fn clear(&self) -> SeamResult<()> {
            self.0.clear().await
        }
    }

    /// Write `bytes` raw at `part` of `root`, as a value that does not open.
    async fn put_raw<S: StagingStore>(
        journal: &DissolveJournal<'_, S>,
        store: &S,
        root: NodeId,
        part: &[u8],
        bytes: &[u8],
    ) {
        let key = journal.journal.key(root, part);
        store.put_staged_bytes(&key, bytes).await.unwrap();
    }

    fn log(index: u32, name: &[u8]) -> NameLogPage {
        NameLogPage {
            index,
            entries: vec![LoggedName {
                id: NEW_ROOT,
                name: name.to_vec(),
            }],
        }
    }

    #[test]
    fn a_commit_replaces_only_the_header_it_read() {
        run(async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            assert!(cell.hold(ROOT).is_none(), "one driver per entry");
            let first = at(DissolveStep::Cut);
            journal.commit(&hold, None, &first).await.unwrap();
            assert!(matches!(
                journal.commit(&hold, None, &first).await,
                Err(DissolveWriteError::Stale)
            ));
            let mut next = first.clone();
            next.scopes[0].cut_time = 1_500;
            journal.commit(&hold, Some(&first), &next).await.unwrap();
            assert!(matches!(
                journal.commit(&hold, Some(&first), &next).await,
                Err(DissolveWriteError::Stale)
            ));
            assert_eq!(journal.header(ROOT).await.unwrap(), HeaderSlot::Own(next));
        });
    }

    /// `cut_time` is set once, the sticky marks only grow, and the lists
    /// only take additions at their end.
    #[test]
    fn a_commit_refuses_a_header_that_undoes_what_the_held_one_records() {
        run(async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            let mut held = at(DissolveStep::Relink);
            held.scopes[0].cut_time = 1_500;
            held.prior_bindings.push(PriorBinding {
                read_scope: NodeId([0x30; 16]),
                read_root: NodeId([0x31; 16]),
                read_epoch: 5,
                restart_floor: 4,
                write_scope: NodeId([0x32; 16]),
                write_epoch: 6,
            });
            journal.put_map_page(&hold, &tree()).await.unwrap();
            journal.commit(&hold, None, &held).await.unwrap();
            let mut retimed = held.clone();
            retimed.scopes[0].cut_time = 2_500;
            let mut unsent = held.clone();
            unsent.relink_sent = false;
            let mut shortened = held.clone();
            shortened.relink_names.clear();
            let mut uncopied = held.clone();
            uncopied.copy_started = false;
            let mut dropped = held.clone();
            dropped.scopes.pop();
            let mut unbound = held.clone();
            unbound.prior_bindings.clear();
            for (new, check) in [
                (retimed, "dissolve-journal-cut-time-set-once"),
                (unsent, "dissolve-journal-sticky-mark-cleared"),
                (shortened, "dissolve-journal-sticky-mark-cleared"),
                (uncopied, "dissolve-journal-sticky-mark-cleared"),
                (dropped, "dissolve-journal-scopes-not-append-only"),
                (unbound, "dissolve-journal-prior-bindings-not-append-only"),
            ] {
                let refused = journal.commit(&hold, Some(&held), &new).await.unwrap_err();
                assert_eq!(refused.check(), check);
            }
            let mut grown = held.clone();
            grown.scopes.push(DissolvedScope {
                manifest: Some(manifest()),
                ..DissolvedScope::uncut(NodeId([0x53; 16]))
            });
            journal.commit(&hold, Some(&held), &grown).await.unwrap();
            assert_eq!(journal.header(ROOT).await.unwrap(), HeaderSlot::Own(grown));
        });
    }

    #[test]
    fn a_header_counts_its_map_pages_only_once_they_form_its_map() {
        run(async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            let cut = at(DissolveStep::Cut);
            journal.commit(&hold, None, &cut).await.unwrap();
            let seal = at(DissolveStep::Seal);
            assert!(
                matches!(
                    journal.commit(&hold, Some(&cut), &seal).await,
                    Err(DissolveWriteError::Codec(DissolveCodecError::RowCount))
                ),
                "no page is written yet"
            );
            journal.put_map_page(&hold, &tree()).await.unwrap();
            journal.commit(&hold, Some(&cut), &seal).await.unwrap();
            assert_eq!(journal.map(ROOT, &seal).await.unwrap(), vec![tree()]);
        });
    }

    #[test]
    fn a_name_log_page_is_never_rewritten_and_the_log_reads_in_order() {
        run(async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            journal
                .append_name_log(&hold, &log(2, b"k51new"))
                .await
                .unwrap();
            journal
                .append_name_log(&hold, &log(0, b"k51new"))
                .await
                .unwrap();
            assert!(matches!(
                journal.append_name_log(&hold, &log(2, b"k51new")).await,
                Err(DissolveWriteError::LogPageWritten)
            ));
            assert_eq!(
                journal.name_log(ROOT).await.unwrap(),
                vec![log(0, b"k51new"), log(2, b"k51new")]
            );
        });
    }

    /// Two appends at one index that run together: one lands and the other
    /// finds the page written, so no page is lost.
    #[test]
    fn two_appends_at_one_index_that_interleave_keep_one_page() {
        run_on(&YieldingStore::default(), async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            let (first, second) = futures_util::future::join(
                journal.append_name_log(&hold, &log(0, b"k51first")),
                journal.append_name_log(&hold, &log(0, b"k51second")),
            )
            .await;
            first.unwrap();
            assert!(matches!(second, Err(DissolveWriteError::LogPageWritten)));
            assert_eq!(
                journal.name_log(ROOT).await.unwrap(),
                vec![log(0, b"k51first")]
            );
        });
    }

    /// A first header that lands while the session lists the store is in the
    /// listing the session keeps.
    #[test]
    fn a_commit_during_the_first_listing_stays_in_the_kept_roots() {
        run_on(&YieldingStore::default(), async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            let (listed, committed) = futures_util::future::join(
                journal.roots(),
                journal.commit(&hold, None, &at(DissolveStep::Cut)),
            )
            .await;
            listed.unwrap();
            committed.unwrap();
            assert_eq!(journal.roots().await.unwrap(), BTreeSet::from([ROOT]));
        });
    }

    /// A remap writes generation g + 1. Until its header commits, g stays the
    /// live map, and a page of the live map is never rewritten.
    #[test]
    fn the_live_map_stays_until_the_header_of_the_next_generation_commits() {
        let store = InMemoryStagingStore::default();
        let seal = at(DissolveStep::Seal);
        let remap = MapPage {
            generation: 1,
            ..page(vec![row(0x51, 0x61, None), row(0x53, 0x73, Some(0))])
        };
        let remapped = DissolveHeader {
            map_gen: 1,
            ..seal.clone()
        };
        run_on(&store, async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            journal.put_map_page(&hold, &tree()).await.unwrap();
            journal.commit(&hold, None, &seal).await.unwrap();
            let rewritten = page(vec![row(0x51, 0x61, None), row(0x53, 0x83, Some(0))]);
            assert!(matches!(
                journal.put_map_page(&hold, &rewritten).await,
                Err(DissolveWriteError::LiveMapPage)
            ));
            journal.put_map_page(&hold, &remap).await.unwrap();
        });
        run_on(&store, async |journal, _| {
            assert_eq!(
                journal.map(ROOT, &seal).await.unwrap(),
                vec![tree()],
                "a stop before the commit keeps generation 0"
            );
        });
        run_on(&store, async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            journal.commit(&hold, Some(&seal), &remapped).await.unwrap();
            assert!(matches!(
                journal.put_map_page(&hold, &remap).await,
                Err(DissolveWriteError::LiveMapPage)
            ));
        });
        run_on(&store, async |journal, _| {
            assert_eq!(
                journal.header(ROOT).await.unwrap(),
                HeaderSlot::Own(remapped.clone())
            );
            assert_eq!(
                journal.map(ROOT, &remapped).await.unwrap(),
                vec![remap.clone()],
                "a stop after the commit reads generation 1"
            );
        });
    }

    /// A map page, a log page or a log key that does not read blocks the
    /// read and the write over it, and a drop leaves the entry as it is.
    #[test]
    fn a_page_that_does_not_read_blocks_its_entry() {
        let store = InMemoryStagingStore::default();
        run_on(&store, async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            let seal = at(DissolveStep::Seal);
            journal.put_map_page(&hold, &tree()).await.unwrap();
            journal.commit(&hold, None, &seal).await.unwrap();
            put_raw(
                journal,
                &store,
                ROOT,
                &[LOG_PART, 0, 0, 0, 1],
                b"not sealed",
            )
            .await;
            assert!(matches!(
                journal.name_log(ROOT).await,
                Err(DissolveWriteError::Blocked)
            ));
            assert!(matches!(
                journal.append_name_log(&hold, &log(1, b"k51new")).await,
                Err(DissolveWriteError::Blocked)
            ));
            assert!(matches!(
                journal.drop_entry(&hold, &seal).await,
                Err(DissolveWriteError::Blocked)
            ));
            assert_eq!(
                journal.header(ROOT).await.unwrap(),
                HeaderSlot::Own(seal.clone())
            );
            assert_eq!(
                journal.map(ROOT, &seal).await.unwrap(),
                vec![tree()],
                "the refused drop removed no page"
            );

            put_raw(
                journal,
                &store,
                ROOT,
                &[MAP_PART, 0, 0, 0, 0],
                b"not sealed",
            )
            .await;
            assert!(matches!(
                journal.map(ROOT, &seal).await,
                Err(DissolveWriteError::Blocked)
            ));
        });
        run_on(&store, async |journal, _| {
            put_raw(journal, &store, NESTED, &[LOG_PART, 0, 1], b"not sealed").await;
            assert!(matches!(
                journal.name_log(NESTED).await,
                Err(DissolveWriteError::Blocked)
            ));
        });
    }

    #[test]
    fn a_dropped_entry_leaves_no_key() {
        run(async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            let header = at(DissolveStep::Cut);
            journal.commit(&hold, None, &header).await.unwrap();
            journal.put_map_page(&hold, &tree()).await.unwrap();
            journal.drop_entry(&hold, &header).await.unwrap();
            assert_eq!(journal.header(ROOT).await.unwrap(), HeaderSlot::Absent);
            assert!(!journal.journaled().await.unwrap().blocks(ROOT));
        });
    }

    /// An entry of another caller and a value that does not read stay as they
    /// are: no dissolve write replaces them.
    #[test]
    fn a_foreign_or_unreadable_header_blocks_every_write() {
        let store = InMemoryStagingStore::default();
        run_on(&store, async |journal, cell| {
            let hold = cell.hold(ROOT).unwrap();
            journal
                .journal
                .put(
                    HEADER_PART,
                    &ResealEnvelope {
                        caller: 2,
                        source_root: ROOT,
                        payload: b"rows".to_vec(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(journal.header(ROOT).await.unwrap(), HeaderSlot::Foreign);
            assert!(matches!(
                journal.commit(&hold, None, &at(DissolveStep::Cut)).await,
                Err(DissolveWriteError::Blocked)
            ));
            assert!(matches!(
                journal.put_map_page(&hold, &tree()).await,
                Err(DissolveWriteError::Blocked)
            ));

            let nested = cell.hold(NESTED).unwrap();
            put_raw(journal, &store, NESTED, HEADER_PART, b"not sealed").await;
            assert_eq!(
                journal.header(NESTED).await.unwrap(),
                HeaderSlot::Unreadable
            );
            let mut header = at(DissolveStep::Cut);
            header.scopes = vec![DissolvedScope::uncut(NESTED)];
            assert!(matches!(
                journal.commit(&nested, None, &header).await,
                Err(DissolveWriteError::Blocked)
            ));
            assert!(matches!(
                journal.put_map_page(&nested, &tree()).await,
                Err(DissolveWriteError::Blocked)
            ));
        });
    }
}
