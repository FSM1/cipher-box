//! The renewal walk (ADR 0061, blueprint/engine.md "Liveness"): a bounded,
//! resumable depth-first walk over every owned scope that re-signs each name
//! whose EOL is inside [`WALK_WINDOW`], and only a record the adoption gate
//! admitted in the same visit.

pub mod cursor;

use core::cell::RefCell;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{ChildRef, NodeKind, ReadBody};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use self::cursor::{
    CursorStore, DeferredRoot, MAX_CURSOR_PATH, MAX_DEFERRED_ROOTS, RenewalCursor, WalkRoot,
};
use super::REGISTRY_BATCH_MAX;
use super::child::{
    AdmittedChild, ChildAdopter, ChildRecord, ChildResolveError, resolve_child_record,
};
use super::eol::{self, renewal_eol_from};
use super::fanout::{FanoutRecord, fanout_get_classified};
use super::fork::{Fork, holds_renewal};
use super::liveness::{EolRenewResult, HeldKey, HeldRecord, HeldRecords, hold_if_unchanged};
use super::publish::{
    Observed, PublishBar, PublishError, PublishOutcome, PublishReceipt, PublishVerdict,
    RefusedRead, SignatureGate, head_cid_from_value, put_and_confirm,
};
use super::register::register;
use super::retire::{Acknowledged, OrphanHeads, StagingRetireLedger, linked_nowhere};
use super::revival::{
    ChildRead, PlaneRead, RecoveryPace, ReviveError, ReviveRequest, ScopeRootRead, reads_absent,
    revive_name, write_signer,
};
use super::rotation::{AdmittedScopeRoot, ScopeRootAdmission, admit_owned_scope_root, scope_name};
use crate::api::{ApiClient, ApiError, NameRegistration};
use crate::bin_index::BinIndexKeys;
use crate::content::Gateway;
use crate::facade::NodeId;
use crate::gate::{GateError, GateStage};
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, RetireLedger, Scheduler, SeamResult,
    SnapshotCache, StagingStore, UnixMillis,
};
use crate::session::SessionIdentity;
use crate::sync::doomed::{journalled_keys, open_reclamation};
use crate::sync::owed_rotation::{OwedCell, OwedRotation};
use crate::sync::render::BaseSnapshot;
use crate::sync::tick::ResolveMode;
use crate::sync::{BookkeepingSeal, owner_tag};

const DAY: u64 = 24 * 60 * 60;

/// The most visits one pass makes (ADR 0061 consequence 2).
pub const WALK_BUDGET: usize = 500;

/// A visit renews a name with at most this much EOL left.
pub const WALK_WINDOW: Duration = Duration::from_secs(60 * DAY);

/// A new cycle begins no sooner than this after the previous one began.
pub const CYCLE_HOLD: Duration = Duration::from_secs(7 * DAY);

/// The most time one cycle keeps the cursor back (ADR 0061 D2). From the
/// cycle's first pass that meets a transient failure, for one window, a pass
/// that meets one stores the cursor it began from, so the next pass repeats
/// its range. After the window, every pass of the cycle stores where it
/// stopped, so the cycle runs at most one window longer. A permanent failure
/// moves the cursor on at once.
pub const KEEP_BACK_WINDOW: Duration = Duration::from_secs(DAY);

/// Why the walk renews no name under an owned scope root this pass.
const JOURNAL_UNREADABLE: &str = "the doomed-name journal does not list or open, so the renewal walk renews nothing under this scope root";
/// Why the walk renews nothing this pass.
const CURSOR_UNREAD: &str = "the renewal cursor does not read, so the renewal walk renews nothing";
/// Why the walk does not renew a name the endpoints agree holds no record.
const NO_RECORD: &str = "the name holds no record the renewal walk can renew";
/// Why the walk does not yet renew a name the endpoints serve forked.
const FORK_HELD: &str =
    "the endpoints serve a same-sequence fork of the name, so the renewal waits for it to heal";
/// Why the walk does not renew a name whose acknowledged sequence is unreadable.
const ACK_UNREADABLE: &str = "the retire ledger's acknowledged sequence does not open";
/// Why the walk does not revive a lapsed name.
const REVIVAL_REFUSED: &str = "the revival refused the record the recovery endpoint served";
/// Why the walk renews every name as if no scope had owed work this pass.
pub(crate) const OWED_UNREAD: &str =
    "the owed rotation record does not read, so the renewal walk renews as if no work were owed";
/// Why a revival outside the walk refused: unknown rotation debt.
pub(crate) const OWED_UNREAD_NO_REVIVAL: &str =
    "the owed rotation record did not read, so the lapsed name did not revive";

/// The most poll cadences the liveness loop waits for the session's first
/// boundary walk before it skips the renewal walk for that pass. A walk that
/// starts before the boundary walk names every owned scope root would close its
/// cycle without them, and [`CYCLE_HOLD`] would then hold for 7 days.
pub const SCOPE_ROOTS_WAIT_POLLS: u32 = 10;

/// The most folders the lapsed-folder queue holds; a new entry drops the
/// oldest.
pub(crate) const MAX_LAPSED_FOLDERS: usize = 64;

/// A folder of an owned scope that a read found `Absent` on every endpoint.
/// The next pass revives it before its cursor (ADR 0062 consequence 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LapsedFolder {
    pub(crate) scope_id: [u8; 16],
    pub(crate) node_id: [u8; 16],
    pub(crate) name: IpnsName,
}

/// Queue `folder` once, as the newest entry.
pub(crate) fn queue_lapsed_folder(queue: &RefCell<VecDeque<LapsedFolder>>, folder: LapsedFolder) {
    let mut queue = queue.borrow_mut();
    queue.retain(|queued| queued.node_id != folder.node_id);
    if queue.len() >= MAX_LAPSED_FOLDERS {
        queue.pop_front();
    }
    queue.push_back(folder);
}

/// One owned scope the walk roots at.
pub(crate) struct WalkScope {
    pub(crate) scope_id: [u8; 16],
    /// The name the scope root publishes under.
    pub(crate) name: IpnsName,
    /// The ancestor node seed a scope below the vault root is gated under.
    pub(crate) ascent: Option<Zeroizing<[u8; 32]>>,
    /// The write scope seed the session holds, for a root the gate admits
    /// keyless.
    pub(crate) write_seed: Option<Zeroizing<[u8; 32]>>,
}

/// One bin index entry the walk roots at.
pub(crate) struct BinRoot {
    pub(crate) node_id: [u8; 16],
    /// The scope the node was sealed under at the delete.
    pub(crate) scope_id: [u8; 16],
    pub(crate) name: IpnsName,
    pub(crate) deleted_at: u64,
}

/// The session cells a renewal must stay clear of (ADR 0061 D3 step 2).
pub(crate) struct WalkGuards<'a> {
    /// The names the drain is publishing right now.
    pub(crate) publishing: &'a RefCell<BTreeSet<String>>,
    /// The names whose retire the registry refused.
    pub(crate) orphan_heads: &'a OrphanHeads,
    /// The renewal set, whose entry for a renewed name follows the renewal.
    pub(crate) held: &'a RefCell<HeldRecords>,
    /// The base tree, which decides whether a tombstoned node is retired.
    pub(crate) base: &'a BaseSnapshot,
}

/// The seams and keys one walk pass runs over.
pub(crate) struct RenewalWalk<'a, T, H: Http, C: CredentialStore, F, S, St, Sch> {
    pub(crate) owner_seed_cache: Option<crate::grants::owner_entry::OwnerSeedCache<'a>>,
    pub(crate) transport: &'a T,
    pub(crate) api: &'a ApiClient<H, C>,
    pub(crate) floors: &'a F,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) staging: &'a St,
    pub(crate) scheduler: &'a Sch,
    pub(crate) profile: &'a SyncTimingProfile,
    pub(crate) gateway: &'a Gateway,
    pub(crate) http: &'a H,
    pub(crate) enc_secret: &'a X25519Secret,
    pub(crate) identity: &'a EcdsaVerifier,
    pub(crate) seal: BookkeepingSeal<'a>,
    pub(crate) bin_keys: Option<&'a BinIndexKeys>,
    pub(crate) guards: WalkGuards<'a>,
    /// The scope roots the boundary walk met with a write cut that did not
    /// finish.
    pub(crate) unfinished_write_cuts: &'a BTreeSet<[u8; 16]>,
    /// The session's owed rotation record, the one the re-drive reads.
    pub(crate) owed: &'a OwedCell,
    /// The session's recovery pace, which each revival waits for.
    pub(crate) pace: &'a RecoveryPace,
    /// The folders a read found lapsed, which a pass visits first.
    pub(crate) lapsed: &'a RefCell<VecDeque<LapsedFolder>>,
}

/// What one pass did.
#[derive(Debug, Default)]
pub(crate) struct WalkReport {
    /// Every signature the pass attempted.
    pub(crate) renewals: Vec<EolRenewResult>,
    /// The names whose record the adoption gate refused.
    pub(crate) rejected: Vec<String>,
    /// The names the walk cannot renew, or renews without a record it does
    /// not read, each with why.
    pub(crate) failed: Vec<(String, &'static str)>,
    /// The owned scope roots with a write cut that did not finish and no owed
    /// entry on this device (ADR 0063 consequence 8).
    pub(crate) underived: Vec<[u8; 16]>,
    /// The names, each with its sequence, the pass read as a same-sequence
    /// fork (ADR 0066 D2).
    pub(crate) forked: Vec<(String, u64)>,
}

/// A scope's material as this pass admitted its root.
struct ScopeMaterial {
    name: IpnsName,
    admitted: AdmittedScopeRoot,
}

impl ScopeMaterial {
    /// The signer for `node_id` whose name is `name`, under the write seed
    /// that derives the scope root's own name. `None` when that seed does not
    /// derive `name`: a node a stopped name wave left at an older name lapses
    /// rather than signing under a superseded seed.
    fn signer_for(&self, node_id: &[u8; 16], name: &IpnsName) -> Option<Ed25519Signer> {
        self.admitted
            .write_scope_seed
            .as_ref()
            .filter(|seed| derive_write_name(seed, node_id) == *name)
            .map(|seed| SessionIdentity::write_name_signer(seed, node_id))
    }
}

/// The key a root's children are sealed under.
struct Plane {
    scope_id: [u8; 16],
    read_seed: Zeroizing<[u8; 32]>,
    /// The read epoch `read_seed` belongs to ([`ChildAdopter::with_seed_stamp`]);
    /// `None` for a held key, which binds no epoch.
    seed_stamp: Option<u64>,
}

/// One folder on the walk's path, its children in node-id order.
struct Frame {
    node_id: [u8; 16],
    children: Vec<ChildRef>,
    next: usize,
}

impl Frame {
    fn of(node_id: [u8; 16], body: ReadBody) -> Self {
        let mut children = match body {
            ReadBody::Folder { children, .. } => children,
            _ => Vec::new(),
        };
        children.sort_by_key(|child| child.id);
        Self {
            node_id,
            children,
            next: 0,
        }
    }

    fn resume_after(&mut self, last: Option<[u8; 16]>) {
        if let Some(last) = last {
            self.next = self.children.partition_point(|child| child.id <= last);
        }
    }

    fn last_visited(&self) -> Option<[u8; 16]> {
        self.next.checked_sub(1).map(|at| self.children[at].id)
    }
}

/// A name the pass admitted and found due.
struct Due {
    node_id: [u8; 16],
    name: IpnsName,
    signer: Ed25519Signer,
    observed: Observed,
    bar: PublishBar,
    value: Vec<u8>,
    head_cid: String,
}

/// This owner's doomed-name journal, as one pass reads it.
#[derive(Default)]
struct Doomed {
    /// The names a delete doomed.
    names: BTreeSet<String>,
    /// The scope roots with an entry that does not read or open. Any name in
    /// such a scope can be doomed, and renewing a doomed name leaks a
    /// registration, so the walk renews none of them.
    unreadable: BTreeSet<[u8; 16]>,
}

/// How a root's walk ended.
enum RootEnd {
    Finished,
    Stopped,
}

/// The scopes the owed rotation record names.
struct OwedScopes {
    all: BTreeSet<[u8; 16]>,
    within_bound: BTreeSet<[u8; 16]>,
}

/// The state of one pass.
struct Pass<'s> {
    cursor: RenewalCursor,
    report: WalkReport,
    visits: usize,
    materials: BTreeMap<[u8; 16], Option<ScopeMaterial>>,
    /// Every scope root the session knows, owned or not: the walk reaches
    /// each owned one as a root of its own.
    scope_roots: BTreeSet<[u8; 16]>,
    /// The folders this pass walked into. Child refs are wire data, so a link
    /// cycle is reachable, and the walk enters each folder once for each pass.
    descended: BTreeSet<[u8; 16]>,
    due: Vec<Due>,
    /// The names a delete doomed, and the scopes whose journal does not open.
    doomed: Doomed,
    /// A visit met a transient failure ([`KEEP_BACK_WINDOW`]).
    kept_back: bool,
    /// The scopes with an owed rotation entry within its bound, whose names
    /// the walk does not renew (ADR 0063 D4, ADR 0065 D4).
    owed: BTreeSet<[u8; 16]>,
    /// The owed rotation record does not read: the walk renews, but revives
    /// nothing, as unknown rotation debt can owe any scope.
    owed_unread: bool,
    /// The pass reported a revival that the unread record refused.
    no_revival_reported: bool,
    /// The owned scope roots whose record the gate rejected in this pass.
    rejected_roots: BTreeSet<[u8; 16]>,
    owner_tag: [u8; 32],
    scopes: &'s [WalkScope],
    bins: &'s [BinRoot],
}

impl Pass<'_> {
    fn budget_spent(&self) -> bool {
        self.visits >= WALK_BUDGET
    }

    /// Every root in walk order.
    fn roots(&self) -> Vec<WalkRoot> {
        let mut scopes: Vec<[u8; 16]> = self.scopes.iter().map(|scope| scope.scope_id).collect();
        scopes.sort_unstable();
        let mut bins: Vec<[u8; 16]> = self.bins.iter().map(|bin| bin.node_id).collect();
        bins.sort_unstable();
        scopes
            .into_iter()
            .map(WalkRoot::Scope)
            .chain(bins.into_iter().map(WalkRoot::Bin))
            .chain(self.cursor.deferred.iter().map(|root| WalkRoot::Deferred {
                scope_id: root.scope_id,
                node_id: root.node_id,
            }))
            .collect()
    }

    /// The root after `current`, or the first root that sorts after it when
    /// `current` is gone.
    fn root_after(&self, current: WalkRoot) -> Option<WalkRoot> {
        let rank = |root: &WalkRoot| match root {
            WalkRoot::Scope(id) => (0u8, *id, 0usize),
            WalkRoot::Bin(id) => (1, *id, 0),
            WalkRoot::Deferred { scope_id, node_id } => (
                2,
                [0; 16],
                self.cursor
                    .deferred
                    .iter()
                    .position(|root| root.scope_id == *scope_id && root.node_id == *node_id)
                    .unwrap_or(usize::MAX),
            ),
        };
        let at = rank(&current);
        self.roots().into_iter().find(|root| rank(root) > at)
    }
}

impl<T, H, C, F, S, St, Sch> RenewalWalk<'_, T, H, C, F, S, St, Sch>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    S: SnapshotCache,
    St: StagingStore,
    Sch: Scheduler + Clone + 'static,
{
    /// Run one pass over `scopes` and `bins`, from where the stored cursor
    /// stopped, and store where this pass stopped. `scope_roots` holds every
    /// scope root the session knows.
    pub(crate) async fn pass(
        &self,
        scopes: &[WalkScope],
        bins: &[BinRoot],
        scope_roots: &BTreeSet<[u8; 16]>,
        still_running: &dyn Fn() -> bool,
    ) -> WalkReport {
        let store = CursorStore::new(self.staging, self.seal, self.enc_secret);
        let now = self.scheduler.now();
        // A store that does not answer says nothing about the stored cursor,
        // which a new cycle would overwrite.
        let Ok(stored) = store.load().await else {
            return stalled(scopes, CURSOR_UNREAD);
        };
        let held = stored.as_ref().is_some_and(|cursor| {
            cursor.root.is_none()
                && cursor.cycle_start <= now
                && !now.reached(Some(cursor.cycle_start.saturating_add(CYCLE_HOLD)))
        });
        // Reported on every pass, a held one too: the boundary walk can name
        // an unfinished cut after the pass that closed the cycle.
        let owed = self.owed_scopes().await;
        let underived = owed
            .as_ref()
            .map(|owed| {
                self.unfinished_write_cuts
                    .difference(&owed.all)
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        let queued = self.lapsed.borrow().clone();
        if held && queued.is_empty() {
            return held_report(underived);
        }
        let owner_tag = owner_tag(self.enc_secret);
        // A held pass scans the journal too: a queued visit skips a doomed
        // name as a cursor visit does. It reports only its queued visits.
        let Some(doomed) = self.doomed_names(&owner_tag).await else {
            if held {
                return held_report(underived);
            }
            return stalled(scopes, JOURNAL_UNREADABLE);
        };
        // A record that does not read skips no scope: a lapsed name loses the
        // data under it, and `signer_for` signs only a name the current seed
        // derives (ADR 0061 D4).
        let (owed, owed_unread) = match owed {
            Ok(owed) => (owed.within_bound, false),
            Err(_) => (BTreeSet::new(), true),
        };
        let report = if held {
            WalkReport {
                failed: scopes
                    .iter()
                    .filter(|scope| {
                        doomed.unreadable.contains(&scope.scope_id)
                            && queued
                                .iter()
                                .any(|folder| folder.scope_id == scope.scope_id)
                    })
                    .map(|scope| (scope.name.as_str().to_owned(), JOURNAL_UNREADABLE))
                    .collect(),
                ..held_report(underived)
            }
        } else {
            WalkReport {
                failed: scopes
                    .iter()
                    .filter_map(|scope| {
                        if doomed.unreadable.contains(&scope.scope_id) {
                            Some(JOURNAL_UNREADABLE)
                        } else if owed_unread {
                            Some(OWED_UNREAD)
                        } else {
                            None
                        }
                        .map(|detail| (scope.name.as_str().to_owned(), detail))
                    })
                    .collect(),
                underived,
                ..WalkReport::default()
            }
        };
        let mut pass = Pass {
            cursor: stored.unwrap_or_else(|| RenewalCursor::starting(now)),
            report,
            visits: 0,
            materials: BTreeMap::new(),
            scope_roots: scopes
                .iter()
                .map(|scope| scope.scope_id)
                .chain(scope_roots.iter().copied())
                .collect(),
            descended: BTreeSet::new(),
            due: Vec::new(),
            doomed,
            kept_back: false,
            owed,
            owed_unread,
            no_revival_reported: false,
            rejected_roots: BTreeSet::new(),
            owner_tag,
            scopes,
            bins,
        };
        let mut settled = Vec::new();
        for folder in &queued {
            if !still_running() {
                break;
            }
            if self.visit_lapsed(&mut pass, folder).await {
                settled.push(folder);
            }
        }
        self.lapsed
            .borrow_mut()
            .retain(|folder| !settled.contains(&folder));
        if held {
            self.flush(&mut pass).await;
            return pass.report;
        }
        if pass.cursor.root.is_none() {
            pass.cursor = RenewalCursor::starting(now);
            pass.cursor.root = pass.roots().first().copied();
        }
        let origin = pass.cursor.clone();

        while let Some(root) = pass.cursor.root {
            if !still_running() || pass.budget_spent() {
                break;
            }
            match self.walk_root(&mut pass, root, still_running).await {
                RootEnd::Finished => {
                    pass.cursor.root = pass.root_after(root);
                    pass.cursor.path.clear();
                    pass.cursor.last_child = None;
                }
                RootEnd::Stopped => break,
            }
        }
        self.flush(&mut pass).await;
        let cursor = cursor_to_store(origin, pass.cursor, pass.kept_back, now);
        // A cursor that does not store only costs work: the next pass starts
        // the cycle again.
        let _ = store.save(&cursor).await;
        pass.report
    }

    /// What this owner's doomed-name journal holds, or `None` when the store
    /// does not list.
    async fn doomed_names(&self, owner_tag: &[u8; 32]) -> Option<Doomed> {
        let keys = self.staging.staged_keys().await.ok()?;
        let mut doomed = Doomed::default();
        for (key, scope_root, _) in journalled_keys(owner_tag, &keys) {
            let reclamation = match self.staging.staged_bytes(&key).await {
                Ok(None) => continue,
                Ok(Some(blob)) => open_reclamation(self.seal, &blob),
                Err(_) => None,
            };
            let Some(reclamation) = reclamation else {
                doomed.unreadable.insert(scope_root.0);
                continue;
            };
            doomed.names.extend(reclamation.names());
            doomed
                .names
                .extend(reclamation.quarantined.into_iter().map(|held| held.name));
        }
        Some(doomed)
    }

    /// The scopes this owner's owed rotation record names, and those of them
    /// whose entry is within the bound of ADR 0065 D3. Past it, the walk renews
    /// each name the scope root's current write seed derives (ADR 0065 D4).
    async fn owed_scopes(&self) -> SeamResult<OwedScopes> {
        let owed = OwedRotation::new(self.staging, self.seal, self.enc_secret, self.owed);
        let ids = |scopes: Vec<NodeId>| scopes.into_iter().map(|scope| scope.0).collect();
        Ok(OwedScopes {
            all: ids(owed.scopes().await?),
            within_bound: ids(owed.scopes_within_bound(self.scheduler.now()).await?),
        })
    }

    /// Admit `scope_id`'s root once per pass.
    async fn material<'p>(
        &self,
        pass: &'p mut Pass<'_>,
        scope_id: [u8; 16],
    ) -> Option<&'p ScopeMaterial> {
        if !pass.materials.contains_key(&scope_id) {
            let scopes = pass.scopes;
            let material = match scopes.iter().find(|scope| scope.scope_id == scope_id) {
                Some(_) if pass.owed.contains(&scope_id) => None,
                Some(scope) => {
                    pass.visits += 1;
                    let mut admission = self.admit_root(scope).await;
                    let mut revival = None;
                    if matches!(admission, Err(ScopeRootAdmission::Gone)) {
                        let rejected = pass.report.rejected.len();
                        revival = self.revive_root(pass, scope).await;
                        // The recovery copy failed the root adopt.
                        if pass.report.rejected.len() > rejected {
                            pass.rejected_roots.insert(scope_id);
                        }
                        if revival == Some(true) {
                            admission = self.admit_root(scope).await;
                        }
                    }
                    match admission {
                        Ok(mut admitted) => {
                            if let Some(fork) = admitted.fork {
                                pass.report
                                    .forked
                                    .push((scope.name.as_str().to_owned(), fork.sequence));
                            }
                            if admitted.write_scope_seed.is_none() {
                                admitted.write_scope_seed = scope.write_seed.clone();
                            }
                            admitted.write_scope_seed = admitted
                                .write_scope_seed
                                .filter(|seed| derive_write_name(seed, &scope_id) == scope.name);
                            Some(ScopeMaterial {
                                name: scope.name.clone(),
                                admitted,
                            })
                        }
                        Err(
                            rejection @ (ScopeRootAdmission::Rejected
                            | ScopeRootAdmission::HeadBlockAbsent),
                        ) => {
                            if matches!(rejection, ScopeRootAdmission::Rejected) {
                                pass.rejected_roots.insert(scope_id);
                            }
                            pass.report.rejected.push(scope.name.as_str().to_owned());
                            None
                        }
                        Err(ScopeRootAdmission::Unavailable) => {
                            pass.kept_back = true;
                            None
                        }
                        // The revival reported why it did not sign.
                        Err(ScopeRootAdmission::Gone) if revival == Some(false) => None,
                        Err(ScopeRootAdmission::Gone) => {
                            pass.report
                                .failed
                                .push((scope.name.as_str().to_owned(), NO_RECORD));
                            None
                        }
                    }
                }
                None => None,
            };
            pass.materials.insert(scope_id, material);
        }
        pass.materials.get(&scope_id).and_then(Option::as_ref)
    }

    /// The root adopt of the owned scope root of `scope`.
    async fn admit_root(&self, scope: &WalkScope) -> Result<AdmittedScopeRoot, ScopeRootAdmission> {
        admit_owned_scope_root(
            self.transport,
            self.gateway,
            self.http,
            self.floors,
            self.snapshot_cache,
            self.owner_seed_cache.clone(),
            self.enc_secret,
            self.identity,
            scope.scope_id,
            scope.ascent.as_ref(),
            &scope.name,
        )
        .await
    }

    /// Walk one root from the cursor's path, until the root is done or the
    /// pass stops.
    async fn walk_root(
        &self,
        pass: &mut Pass<'_>,
        root: WalkRoot,
        still_running: &dyn Fn() -> bool,
    ) -> RootEnd {
        let Some((plane, root_node, body)) = self.open_root(pass, root).await else {
            return RootEnd::Finished;
        };
        let in_bin = matches!(root, WalkRoot::Bin(_));
        pass.descended.insert(root_node);
        let mut frames = vec![Frame::of(root_node, body)];
        if pass.cursor.path.first() != Some(&root_node) {
            pass.cursor.path = vec![root_node];
            pass.cursor.last_child = None;
        }
        let path = pass.cursor.path.clone();
        let mut last = pass.cursor.last_child;
        for id in path.into_iter().skip(1) {
            let Some(top) = frames.last() else {
                break;
            };
            let reopened = match top.children.iter().find(|child| child.id == id) {
                Some(child)
                    if child.kind == NodeKind::Folder && !pass.scope_roots.contains(&id) =>
                {
                    self.visit(pass, &plane, child, in_bin).await
                }
                _ => None,
            };
            // The parent resumes after `id`, whether or not `id` reopens.
            if let Some(parent) = frames.last_mut() {
                parent.resume_after(Some(id));
            }
            match reopened {
                Some(body @ ReadBody::Folder { .. }) if pass.descended.insert(id) => {
                    frames.push(Frame::of(id, body));
                }
                _ => {
                    last = Some(id);
                    break;
                }
            }
        }
        if let Some(top) = frames.last_mut() {
            top.resume_after(last);
        }

        loop {
            // The subtree below a depth-cap folder the full set could not
            // defer runs with no budget (ADR 0061 D2).
            let bounded = frames.len() < MAX_CURSOR_PATH;
            if !still_running() || (bounded && pass.budget_spent()) {
                park(&mut pass.cursor, &frames);
                return RootEnd::Stopped;
            }
            let Some(top) = frames.last_mut() else {
                return RootEnd::Finished;
            };
            let Some(child) = top.children.get(top.next).cloned() else {
                frames.pop();
                if frames.is_empty() {
                    return RootEnd::Finished;
                }
                continue;
            };
            top.next += 1;
            if pass.scope_roots.contains(&child.id) {
                continue;
            }
            let Some(body) = self.visit(pass, &plane, &child, in_bin).await else {
                continue;
            };
            if child.kind != NodeKind::Folder
                || !matches!(body, ReadBody::Folder { .. })
                || !pass.descended.insert(child.id)
            {
                continue;
            }
            let at_cap = frames.len() + 1 == MAX_CURSOR_PATH;
            if at_cap && !in_bin && pass.cursor.deferred.len() < MAX_DEFERRED_ROOTS {
                if let Ok(name) = scope_name(&child.ipns_name) {
                    pass.cursor.deferred.push(DeferredRoot {
                        scope_id: plane.scope_id,
                        node_id: child.id,
                        name,
                    });
                    continue;
                }
            }
            frames.push(Frame::of(child.id, body));
        }
    }

    /// Admit a root's own record, and the plane its subtree is sealed under.
    async fn open_root(
        &self,
        pass: &mut Pass<'_>,
        root: WalkRoot,
    ) -> Option<(Plane, [u8; 16], ReadBody)> {
        match root {
            WalkRoot::Scope(scope_id) => {
                let material = self.material(pass, scope_id).await?;
                let admitted = &material.admitted;
                let body = admitted.read_body.clone();
                let plane = Plane {
                    scope_id,
                    read_seed: admitted.read_scope_seed.clone(),
                    seed_stamp: Some(admitted.read_epoch),
                };
                let (name, observed, fork) = (
                    material.name.clone(),
                    admitted.observed.clone(),
                    admitted.fork,
                );
                self.consider(pass, scope_id, scope_id, &name, observed, fork)
                    .await;
                Some((plane, scope_id, body))
            }
            WalkRoot::Bin(node_id) => {
                let keys = self.bin_keys?;
                let bin = pass
                    .bins
                    .iter()
                    .find(|bin| bin.node_id == node_id && !pass.owed.contains(&bin.scope_id))?;
                let (scope_id, name) = (bin.scope_id, bin.name.clone());
                let plane = Plane {
                    scope_id,
                    read_seed: keys.held_key(&node_id, bin.deleted_at),
                    seed_stamp: None,
                };
                let body = self.admit(pass, &plane, node_id, &name, true).await?;
                Some((plane, node_id, body))
            }
            WalkRoot::Deferred { scope_id, node_id } => {
                let name = pass
                    .cursor
                    .deferred
                    .iter()
                    .find(|root| root.scope_id == scope_id && root.node_id == node_id)?
                    .name
                    .clone();
                let admitted = &self.material(pass, scope_id).await?.admitted;
                let plane = Plane {
                    scope_id,
                    read_seed: admitted.read_scope_seed.clone(),
                    seed_stamp: Some(admitted.read_epoch),
                };
                let body = self.admit(pass, &plane, node_id, &name, false).await?;
                Some((plane, node_id, body))
            }
        }
    }

    /// Visit a folder from the lapsed-folder queue, while the base still names
    /// it at the queued name, under the plane of its scope root. Whether the
    /// queue can drop it: the base no longer names it, the walk renews no name
    /// in its scope, the gate rejected its scope root, or the visit ended with
    /// no transient failure. The folder's own visit keeps no cursor back; a
    /// scope root that keeps the entry keeps the cursor as `material` does.
    async fn visit_lapsed(&self, pass: &mut Pass<'_>, folder: &LapsedFolder) -> bool {
        let named = self
            .guards
            .base
            .borrow()
            .node(NodeId(folder.node_id))
            .is_some_and(|meta| {
                meta.kind == crate::facade::NodeKind::Folder
                    && meta.ipns_name.as_deref() == Some(folder.name.as_str().as_bytes())
            });
        if !named
            || !pass
                .scopes
                .iter()
                .any(|scope| scope.scope_id == folder.scope_id)
        {
            return true;
        }
        // A visit there reports `NO_RECORD`; the pass names the journal.
        if pass.doomed.unreadable.contains(&folder.scope_id) {
            return false;
        }
        let material = self
            .material(pass, folder.scope_id)
            .await
            .map(|material| queued_plane(material, folder));
        let root_rejected = pass.rejected_roots.contains(&folder.scope_id);
        let plane = match queued_step(material, root_rejected) {
            Ok(plane) => plane,
            Err(drop) => return drop,
        };
        let kept_back = core::mem::replace(&mut pass.kept_back, false);
        self.admit(pass, &plane, folder.node_id, &folder.name, false)
            .await;
        !core::mem::replace(&mut pass.kept_back, kept_back)
    }

    /// Visit one child a folder names.
    async fn visit(
        &self,
        pass: &mut Pass<'_>,
        plane: &Plane,
        child: &ChildRef,
        in_bin: bool,
    ) -> Option<ReadBody> {
        let name = scope_name(&child.ipns_name).ok()?;
        self.admit(pass, plane, child.id, &name, in_bin).await
    }

    /// The gated child resolve of `node_id` at `name` (ADR 0061 D3 step 1),
    /// then the renewal decision on the record it admitted. A binned subtree
    /// can hold a scope root the boundary walk no longer names, which carries
    /// a grant section; anywhere else a grant section is a trust violation.
    async fn admit(
        &self,
        pass: &mut Pass<'_>,
        plane: &Plane,
        node_id: [u8; 16],
        name: &IpnsName,
        in_bin: bool,
    ) -> Option<ReadBody> {
        let scope_root = self
            .material(pass, plane.scope_id)
            .await
            .map(|material| material.name.clone());
        pass.visits += 1;
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            plane.scope_id,
            plane.read_seed.clone(),
            node_id,
        )
        .with_seed_stamp(plane.seed_stamp);
        let resolve = async |mode| {
            resolve_child_record(
                self.transport,
                self.snapshot_cache,
                &adopter,
                name,
                scope_root.as_ref(),
                mode,
            )
            .await
        };
        let mut resolved = resolve(ResolveMode::CacheFirst).await;
        // A cached copy of a lapsed record admits too, so the walk asks the
        // endpoints before it reads the body.
        let lapsed = match &resolved {
            Ok(ChildRecord::Absent) => true,
            Ok(ChildRecord::Admitted(read)) => self.lapsed_copy(name, &read.observed).await,
            Ok(ChildRecord::Withheld) | Err(_) => false,
        };
        let mut revival = None;
        if lapsed {
            revival = self.revive_child(pass, plane, node_id, name).await;
            if revival == Some(true) {
                resolved = resolve(ResolveMode::NoCache).await;
            }
        }
        match resolved {
            Ok(ChildRecord::Admitted(read)) => {
                let AdmittedChild {
                    adopted,
                    observed,
                    fork,
                    ..
                } = *read;
                if let Some(fork) = fork {
                    pass.report
                        .forked
                        .push((name.as_str().to_owned(), fork.sequence));
                }
                self.consider(pass, plane.scope_id, node_id, name, observed, fork)
                    .await;
                Some(adopted.read_body)
            }
            // The revival reported why it did not sign.
            Ok(ChildRecord::Absent) if revival == Some(false) => None,
            Ok(ChildRecord::Absent) => {
                pass.report
                    .failed
                    .push((name.as_str().to_owned(), NO_RECORD));
                None
            }
            Err(ChildResolveError::Gate(GateError::Rejected(rejection)))
                if in_bin && rejection.stage == GateStage::GrantSection =>
            {
                None
            }
            Err(ChildResolveError::Gate(GateError::Rejected(_))) => {
                pass.report.rejected.push(name.as_str().to_owned());
                None
            }
            Ok(ChildRecord::Withheld)
            | Err(
                ChildResolveError::Unavailable(_) | ChildResolveError::Gate(GateError::Seam(_)),
            ) => {
                pass.kept_back = true;
                None
            }
        }
    }

    /// Whether `observed` is a copy of a record past its EOL that no endpoint
    /// serves.
    async fn lapsed_copy(&self, name: &IpnsName, observed: &Result<Observed, RefusedRead>) -> bool {
        let bytes = match observed {
            Ok(observed) => observed.bytes(),
            Err(refused) => refused.bytes.as_slice(),
        };
        super::fork::verified(name, bytes)
            .is_some_and(|verified| eol::is_expired(self.scheduler.now(), &verified.validity))
            && reads_absent(self.transport, name).await
    }

    /// Revive the lapsed node `node_id` at `name` through the gated child
    /// resolve (ADR 0062 D3). `None` when the walk may not sign the name, so
    /// no revival ran; `Some(true)` when the revival signed.
    async fn revive_child(
        &self,
        pass: &mut Pass<'_>,
        plane: &Plane,
        node_id: [u8; 16],
        name: &IpnsName,
    ) -> Option<bool> {
        let material = pass.materials.get(&plane.scope_id)?.as_ref()?;
        let signer = material.signer_for(&node_id, name)?;
        let (scope_root, bar) = (material.name.clone(), material.admitted.bar);
        if !self
            .may_sign(pass, plane.scope_id, node_id, name, None)
            .await
        {
            return None;
        }
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            plane.scope_id,
            plane.read_seed.clone(),
            node_id,
        )
        .with_seed_stamp(plane.seed_stamp);
        let read = ChildRead {
            adopter,
            snapshot_cache: self.snapshot_cache,
            scope_root: Some(&scope_root),
            bar,
        };
        Some(self.revive_one(pass, name, Some(&signer), read).await)
    }

    /// Revive the lapsed owned scope root of `scope` through the root adopt
    /// (ADR 0062 D3), with the signer of the write seed the admitted owner
    /// blob carries. `None` when the walk may not sign the name.
    async fn revive_root(&self, pass: &mut Pass<'_>, scope: &WalkScope) -> Option<bool> {
        if !self
            .may_sign(pass, scope.scope_id, scope.scope_id, &scope.name, None)
            .await
        {
            return None;
        }
        let signer = write_signer(scope.write_seed.as_deref(), &scope.scope_id, &scope.name);
        let read = ScopeRootRead {
            gateway: self.gateway,
            http: self.http,
            floors: self.floors,
            snapshot_cache: self.snapshot_cache,
            owner_seed_cache: self.owner_seed_cache.clone(),
            enc_secret: self.enc_secret,
            identity: self.identity,
            scope_id: scope.scope_id,
            ascent: scope.ascent.as_ref(),
        };
        Some(
            self.revive_one(pass, &scope.name, signer.as_ref(), read)
                .await,
        )
    }

    /// Revive one name at the recovery pace, and report the result. A visit
    /// that revives does not count toward [`WALK_BUDGET`]: the pace bounds a
    /// revival cycle (ADR 0062 consequence 2).
    async fn revive_one<P: PlaneRead>(
        &self,
        pass: &mut Pass<'_>,
        name: &IpnsName,
        signer: Option<&Ed25519Signer>,
        plane: P,
    ) -> bool {
        if pass.owed_unread {
            if !core::mem::replace(&mut pass.no_revival_reported, true) {
                pass.report
                    .failed
                    .push((name.as_str().to_owned(), OWED_UNREAD_NO_REVIVAL));
            }
            pass.kept_back = true;
            return false;
        }
        let request = ReviveRequest {
            name,
            signer,
            plane,
        };
        let result = revive_name(self.api, &self.seams(), self.pace, request).await;
        let routing_key = name.as_str().to_owned();
        let outcome = match result {
            Ok(revived) => {
                pass.visits = pass.visits.saturating_sub(1);
                Ok(Some(revived.outcome))
            }
            Err(ReviveError::Publish(error)) => Err(error),
            Err(ReviveError::TrustViolation) => {
                pass.report.rejected.push(routing_key);
                return false;
            }
            Err(ReviveError::Recovery(ApiError::Status { status: 404, .. })) => {
                pass.report.failed.push((routing_key, NO_RECORD));
                return false;
            }
            Err(ReviveError::Recovery(error)) => {
                pass.kept_back |= transient_registration(&error);
                pass.report.failed.push((routing_key, REVIVAL_REFUSED));
                return false;
            }
            Err(
                ReviveError::Throttled
                | ReviveError::Uncorroborated
                | ReviveError::Unavailable
                | ReviveError::FloorRead(_),
            ) => {
                pass.kept_back = true;
                return false;
            }
            // Another write moved the name on.
            Err(ReviveError::Superseded { .. } | ReviveError::Moved) => return false,
            Err(
                ReviveError::WrongSigner
                | ReviveError::Unrecoverable
                | ReviveError::StaleSource { .. }
                | ReviveError::PlaneMismatch
                | ReviveError::NotAtFloor,
            ) => {
                pass.report.failed.push((routing_key, REVIVAL_REFUSED));
                return false;
            }
        };
        pass.kept_back |= transient_renewal(&outcome);
        let signed = outcome.is_ok();
        pass.report.renewals.push(EolRenewResult {
            routing_key,
            outcome,
        });
        signed
    }

    /// Whether the walk may sign `name` for `node_id` (ADR 0061 D3 step 2): no
    /// delete doomed it, no retire is pending, the drain is not publishing it,
    /// and no retire is acknowledged above `sequence`. A revival passes `None`,
    /// as it reads its sequence later, so any acknowledged retire refuses it.
    async fn may_sign(
        &self,
        pass: &mut Pass<'_>,
        material_scope: [u8; 16],
        node_id: [u8; 16],
        name: &IpnsName,
        sequence: Option<u64>,
    ) -> bool {
        if pass.doomed.unreadable.contains(&material_scope) {
            pass.kept_back = true;
            return false;
        }
        let key = name.as_str();
        if pass.doomed.names.contains(key)
            || self
                .guards
                .orphan_heads
                .pending()
                .iter()
                .any(|held| held == key)
            || self.guards.publishing.borrow().contains(key)
        {
            return false;
        }
        let ledger = StagingRetireLedger::new(self.staging, self.seal);
        match ledger.tombstoned(&pass.owner_tag, node_id).await {
            Ok(true) if linked_nowhere(&self.guards.base.borrow(), node_id) => return false,
            Ok(_) => {}
            Err(_) => {
                pass.kept_back = true;
                return false;
            }
        }
        match ledger.acknowledged(&pass.owner_tag, node_id, key).await {
            Ok(Acknowledged::Nothing) => true,
            Ok(Acknowledged::At(acked)) => sequence.is_some_and(|sequence| acked <= sequence),
            Ok(Acknowledged::Unreadable) => {
                pass.report.failed.push((key.to_owned(), ACK_UNREADABLE));
                false
            }
            Err(_) => {
                pass.kept_back = true;
                false
            }
        }
    }

    /// Queue a renewal of the record the gate admitted, when its EOL is inside
    /// the window and no other write can come between (ADR 0061 D3 step 2), and
    /// no served `fork` holds it back (ADR 0066 D3). A record the token refused
    /// is reported as a failed renewal instead.
    async fn consider(
        &self,
        pass: &mut Pass<'_>,
        material_scope: [u8; 16],
        node_id: [u8; 16],
        name: &IpnsName,
        observed: Result<Observed, RefusedRead>,
        fork: Option<Fork>,
    ) {
        let bytes = match &observed {
            Ok(observed) => observed.bytes(),
            Err(refused) => refused.bytes.as_slice(),
        };
        let Some(verified) = super::fork::verified(name, bytes) else {
            return;
        };
        let sequence = verified.sequence;
        let now = self.scheduler.now();
        let due = eol::needs_renewal(now, &verified.validity, WALK_WINDOW);
        if !due
            || observed
                .as_ref()
                .is_ok_and(|observed| observed.sequence() != sequence)
        {
            return;
        }
        if holds_renewal(fork, now, &verified.validity) {
            pass.report
                .failed
                .push((name.as_str().to_owned(), FORK_HELD));
            return;
        }
        let Some(head_cid) = head_cid_from_value(&verified.value) else {
            return;
        };
        let Some(material) = pass.materials.get(&material_scope).and_then(Option::as_ref) else {
            return;
        };
        let Some(signer) = material.signer_for(&node_id, name) else {
            return;
        };
        let bar = material.admitted.bar;
        if !self
            .may_sign(pass, material_scope, node_id, name, Some(sequence))
            .await
        {
            return;
        }
        let key = name.as_str();
        let observed = match observed {
            Ok(observed) => observed,
            Err(refused) => {
                pass.report.renewals.push(EolRenewResult {
                    routing_key: key.to_owned(),
                    outcome: Err(refused.error),
                });
                return;
            }
        };
        pass.due.push(Due {
            node_id,
            name: name.clone(),
            signer,
            observed,
            bar,
            value: verified.value,
            head_cid,
        });
    }

    /// Register the due names in batches, then renew each (ADR 0061 D3 steps
    /// 3 to 6).
    async fn flush(&self, pass: &mut Pass<'_>) {
        let due = core::mem::take(&mut pass.due);
        for batch in due.chunks(REGISTRY_BATCH_MAX) {
            let registrations: Vec<NameRegistration> = batch
                .iter()
                .map(|due| NameRegistration {
                    ipns_name: due.name.as_str().to_owned(),
                    head_cid: Some(due.head_cid.clone()),
                    content_cids: Vec::new(),
                })
                .collect();
            if let Err(error) = register(self.api, &registrations).await {
                pass.kept_back |= transient_registration(&error);
                pass.report
                    .renewals
                    .extend(batch.iter().map(|due| EolRenewResult {
                        routing_key: due.name.as_str().to_owned(),
                        outcome: Err(PublishError::Register(error.clone())),
                    }));
                continue;
            }
            for due in batch {
                if let Some(outcome) = self.renew(due).await {
                    pass.kept_back |= transient_renewal(&outcome);
                    pass.report.renewals.push(EolRenewResult {
                        routing_key: due.name.as_str().to_owned(),
                        outcome,
                    });
                }
            }
        }
    }

    /// Renew `due` (ADR 0061 D3 steps 4 to 6), and point the renewal set at
    /// the renewal.
    async fn renew(&self, due: &Due) -> Option<Result<Option<PublishOutcome>, PublishError>> {
        let receipt = match renew_admitted(
            &self.seams(),
            &due.observed,
            Some(due.bar),
            FloorRule::Exact,
            &due.signer,
            &due.value,
        )
        .await?
        {
            Ok(receipt) => receipt,
            Err(error) => return Some(Err(error)),
        };
        if matches!(receipt.outcome, PublishOutcome::Published { .. }) {
            self.follow_held(due, &receipt.record_bytes);
        }
        Some(Ok(Some(receipt.outcome)))
    }

    fn seams(&self) -> RenewalSeams<'_, T, F, Sch> {
        RenewalSeams {
            transport: self.transport,
            floors: self.floors,
            scheduler: self.scheduler,
            profile: self.profile,
            publishing: self.guards.publishing,
        }
    }

    /// Point the renewal set's entry for a renewed name at the renewal, while
    /// it still holds the record the walk admitted.
    fn follow_held(&self, due: &Due, renewed: &[u8]) {
        let key = HeldKey::Node(due.node_id);
        let Some(held) = self.guards.held.borrow().get(&key).cloned() else {
            return;
        };
        if held.routing_key != due.name.as_str() {
            return;
        }
        hold_if_unchanged(
            self.guards.held,
            key,
            HeldRecord {
                record_bytes: renewed.to_vec(),
                ..held
            },
            Some(due.observed.bytes()),
        );
    }
}

/// The seams and the drain cell one renewal signature runs against.
pub(crate) struct RenewalSeams<'a, T, F, Sch> {
    pub(crate) transport: &'a T,
    pub(crate) floors: &'a F,
    pub(crate) scheduler: &'a Sch,
    pub(crate) profile: &'a SyncTimingProfile,
    /// The names the drain is publishing right now.
    pub(crate) publishing: &'a RefCell<BTreeSet<String>>,
}

/// The durable sequence floor a renewal over a record at `S` may sign above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloorRule {
    /// Exactly `S`: the read that admitted the record raised the floor to it.
    Exact,
    /// Absent or at most `S`: a pointer name, whose enrolment raises no floor.
    AtMost,
}

/// Sign `value` at `S + 1` for the registered name `observed` admitted at
/// `S`, when the network still serves that record, the durable floor still
/// meets `rule`, and the drain has no publish of the name in flight (ADR 0061
/// D3 steps 4 to 6). `None` when any of the three moved.
pub(crate) async fn renew_admitted<T, F, Sch>(
    seams: &RenewalSeams<'_, T, F, Sch>,
    observed: &Observed,
    bar: Option<PublishBar>,
    rule: FloorRule,
    signer: &Ed25519Signer,
    value: &[u8],
) -> Option<Result<PublishReceipt, PublishError>>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    match fanout_get_classified(seams.transport, observed.name()).await {
        FanoutRecord::Found(_, live) if live == observed.bytes() => {}
        FanoutRecord::Unavailable(_) => return Some(Err(PublishError::AllEndpointsFailed)),
        FanoutRecord::Found(..) | FanoutRecord::Absent => return None,
    }
    sign_admitted(seams, observed, bar, rule, signer, value).await
}

/// [`renew_admitted`] after its caller's own check of what the network
/// serves: sign `value` at `S + 1` with the renewal EOL when the durable floor
/// still meets `rule` and the drain has no publish of the name in flight.
pub(crate) async fn sign_admitted<T, F, Sch>(
    seams: &RenewalSeams<'_, T, F, Sch>,
    observed: &Observed,
    bar: Option<PublishBar>,
    rule: FloorRule,
    signer: &Ed25519Signer,
    value: &[u8],
) -> Option<Result<PublishReceipt, PublishError>>
where
    T: RecordTransport + Clone + 'static,
    F: FloorStore,
    Sch: Scheduler + Clone + 'static,
{
    let name = observed.name();
    let gate = match SignatureGate::read_for_renewal(seams.floors, observed, bar).await {
        Ok(gate) => gate,
        Err(error) => return Some(Err(error)),
    };
    // No await from here to the signature.
    let floor_moved = match rule {
        FloorRule::Exact => gate.sequence_floor() != Some(observed.sequence()),
        FloorRule::AtMost => gate
            .sequence_floor()
            .is_some_and(|floor| floor > observed.sequence()),
    };
    if floor_moved || seams.publishing.borrow().contains(name.as_str()) {
        return None;
    }
    let ttl_nanos = u64::try_from(seams.profile.record_ttl.as_nanos()).unwrap_or(u64::MAX);
    let eol = renewal_eol_from(seams.scheduler.now());
    let (record_bytes, sequence) = match gate.sign(signer, value, ttl_nanos, &eol) {
        Ok(signed) => signed,
        Err(error) => return Some(Err(error)),
    };
    Some(
        put_and_confirm(
            seams.transport,
            seams.scheduler,
            name,
            record_bytes,
            sequence,
        )
        .await,
    )
}

/// A held pass before its queued visits: it reports only `underived`.
fn held_report(underived: Vec<[u8; 16]>) -> WalkReport {
    WalkReport {
        underived,
        ..WalkReport::default()
    }
}

/// A pass that renews nothing, and reports `detail` for each owned scope root.
fn stalled(scopes: &[WalkScope], detail: &'static str) -> WalkReport {
    WalkReport {
        failed: scopes
            .iter()
            .map(|scope| (scope.name.as_str().to_owned(), detail))
            .collect(),
        ..WalkReport::default()
    }
}

/// The cursor a pass stores (ADR 0061 D2): the one it began from while a
/// visit met a transient failure and the cycle's [`KEEP_BACK_WINDOW`] is open,
/// else the one it `walked` to. The window opens at the cycle's first
/// keep-back, and a start ahead of the clock ends it.
fn cursor_to_store(
    origin: RenewalCursor,
    walked: RenewalCursor,
    kept_back: bool,
    now: UnixMillis,
) -> RenewalCursor {
    if !kept_back {
        return walked;
    }
    match origin.kept_back_since {
        None => RenewalCursor {
            kept_back_since: Some(now),
            ..origin
        },
        Some(since)
            if since <= now && !now.reached(Some(since.saturating_add(KEEP_BACK_WINDOW))) =>
        {
            origin
        }
        Some(_) => walked,
    }
}

/// Whether a refused registration can pass: the API was not reached, it
/// answered 429 or 5xx, or the session's refresh failed.
pub(crate) fn transient_registration(error: &ApiError) -> bool {
    match error {
        ApiError::Transport(_) | ApiError::Unauthorized => true,
        ApiError::Status { status, .. } => *status == 429 || *status >= 500,
        ApiError::Forbidden | ApiError::Decode(_) | ApiError::MalformedContentCid => false,
    }
}

/// Whether a renewal's outcome can pass on a later pass.
pub(crate) fn transient_renewal(outcome: &Result<Option<PublishOutcome>, PublishError>) -> bool {
    match outcome {
        Ok(Some(PublishOutcome::Unconfirmed { .. })) => true,
        Ok(None | Some(PublishOutcome::Published { .. } | PublishOutcome::LostRace { .. })) => {
            false
        }
        Err(PublishError::Register(api)) => transient_registration(api),
        Err(error) => match error.verdict() {
            PublishVerdict::NotLanded | PublishVerdict::PutUnacknowledged => true,
            PublishVerdict::RegistryRefused
            | PublishVerdict::PutRefused
            | PublishVerdict::Refused
            | PublishVerdict::RefusedUnaddressed
            | PublishVerdict::RefusedOversized => false,
        },
    }
}

/// The plane a queued folder reads under, when the admitted scope root's write
/// seed derives its name. The focus leg queues the scope it read under, which
/// can be another plane: a nested scope root, or the second scope of a move.
fn queued_plane(material: &ScopeMaterial, folder: &LapsedFolder) -> Option<Plane> {
    material.signer_for(&folder.node_id, &folder.name)?;
    Some(Plane {
        scope_id: folder.scope_id,
        read_seed: material.admitted.read_scope_seed.clone(),
        seed_stamp: Some(material.admitted.read_epoch),
    })
}

/// Whether a queued folder reads under `material`, the plane of its admitted
/// scope root, or settles before any visit: `Err(true)` drops it, as the gate
/// rejected the root; `Err(false)` keeps it, as the root did not admit or the
/// cursor visit reads the folder under its own plane.
fn queued_step(material: Option<Option<Plane>>, root_rejected: bool) -> Result<Plane, bool> {
    match material {
        Some(Some(plane)) => Ok(plane),
        Some(None) => Err(false),
        None => Err(root_rejected),
    }
}

/// Store where the walk stops: the path of folders down to the deepest one it
/// is listing, capped at the depth-cap folder, whose subtree a later pass
/// starts again.
fn park(cursor: &mut RenewalCursor, frames: &[Frame]) {
    cursor.path = frames
        .iter()
        .take(MAX_CURSOR_PATH)
        .map(|frame| frame.node_id)
        .collect();
    cursor.last_child = if frames.len() > MAX_CURSOR_PATH {
        None
    } else {
        frames.last().and_then(Frame::last_visited)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::rotation::AdmittedScopeRoot;

    fn material(current: [u8; 32]) -> ScopeMaterial {
        ScopeMaterial {
            name: derive_write_name(&current, &[0; 16]),
            admitted: AdmittedScopeRoot {
                observed: Ok(Observed::unread(&derive_write_name(&current, &[0; 16]))),
                bar: PublishBar {
                    scope_id: [0; 16],
                    read_epoch: 0,
                    write_epoch: None,
                    cut_epoch: None,
                },
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
                    unknown: cipherbox_core::seal::PreservedFields::new(),
                },
                read_scope_seed: Zeroizing::new([0; 32]),
                read_epoch: 0,
                write_scope_seed: Some(Zeroizing::new(current)),
                fork: None,
            },
        }
    }

    const HOUR_MS: u64 = 60 * 60 * 1000;

    fn cursor_at(root: u8, kept_back_since: Option<u64>) -> RenewalCursor {
        RenewalCursor {
            root: Some(WalkRoot::Scope([root; 16])),
            kept_back_since: kept_back_since.map(UnixMillis),
            ..RenewalCursor::starting(UnixMillis(0))
        }
    }

    /// The window is open up to one millisecond before 24 hours after the
    /// cycle's first keep-back, and closed at 24 hours.
    #[test]
    fn the_keep_back_window_closes_at_exactly_one_day() {
        let since = 5 * HOUR_MS;
        let end = since + 24 * HOUR_MS;
        let (origin, walked) = (cursor_at(1, Some(since)), cursor_at(2, Some(since)));
        let open = cursor_to_store(origin.clone(), walked.clone(), true, UnixMillis(end - 1));
        assert_eq!(open, origin, "one millisecond before the end");
        let closed = cursor_to_store(origin, walked.clone(), true, UnixMillis(end));
        assert_eq!(closed, walked, "at the end");
    }

    /// A first keep-back time ahead of the clock ends the window.
    #[test]
    fn a_keep_back_time_ahead_of_the_clock_ends_the_window() {
        let (origin, walked) = (
            cursor_at(1, Some(10 * HOUR_MS)),
            cursor_at(2, Some(10 * HOUR_MS)),
        );
        let stored = cursor_to_store(origin, walked.clone(), true, UnixMillis(9 * HOUR_MS));
        assert_eq!(stored, walked);
    }

    /// A cycle keeps the cursor back for one window at most: a pass between two
    /// runs of transient failures does not open a second window.
    #[test]
    fn a_cycle_keeps_the_cursor_back_for_one_window_at_most() {
        let first = cursor_to_store(
            cursor_at(1, None),
            cursor_at(2, None),
            true,
            UnixMillis(HOUR_MS),
        );
        assert_eq!(
            first,
            cursor_at(1, Some(HOUR_MS)),
            "the first keep-back opens the window"
        );
        let clear = cursor_to_store(
            first,
            cursor_at(3, Some(HOUR_MS)),
            false,
            UnixMillis(2 * HOUR_MS),
        );
        assert_eq!(
            clear,
            cursor_at(3, Some(HOUR_MS)),
            "a clean pass moves on and keeps the time"
        );
        let late = cursor_to_store(
            clear,
            cursor_at(4, Some(HOUR_MS)),
            true,
            UnixMillis(26 * HOUR_MS),
        );
        assert_eq!(
            late,
            cursor_at(4, Some(HOUR_MS)),
            "no second window in the cycle"
        );
    }

    /// A node signs only under the seed that derives its scope root's name; a
    /// name any other seed derives, an older one included, is never renewed.
    #[test]
    fn a_node_signs_only_under_the_scope_roots_own_seed() {
        let (current, old, node) = ([1u8; 32], [2u8; 32], [9u8; 16]);
        let material = material(current);
        let name = derive_write_name(&current, &node);
        let signer = material.signer_for(&node, &name).expect("a signer");
        assert_eq!(IpnsName::from_public_key(&signer.verifying_key()), name);
        assert!(
            material
                .signer_for(&node, &derive_write_name(&old, &node))
                .is_none(),
            "an old name is never renewed",
        );
    }

    /// A queued folder whose name the scope root's write seed does not derive
    /// reads under no plane, and the cursor visit covers it.
    #[test]
    fn a_queued_folder_under_another_plane_reads_under_none() {
        let (current, other, node_id) = ([1u8; 32], [2u8; 32], [9u8; 16]);
        let material = material(current);
        let folder = |seed: &[u8; 32]| LapsedFolder {
            scope_id: [0; 16],
            node_id,
            name: derive_write_name(seed, &node_id),
        };
        assert!(queued_plane(&material, &folder(&current)).is_some());
        assert!(queued_plane(&material, &folder(&other)).is_none());
        assert!(
            matches!(
                queued_step(Some(queued_plane(&material, &folder(&other))), false),
                Err(false)
            ),
            "the entry stays, and no visit sends an event",
        );
    }

    /// A root the gate rejects drops the queued folders of its scope; a root
    /// that does not admit for another reason keeps them.
    #[test]
    fn a_rejected_scope_root_drops_its_queued_folders() {
        assert!(matches!(queued_step(None, true), Err(true)));
        assert!(matches!(queued_step(None, false), Err(false)));
    }

    /// A folder queued again moves to the newest place, and a full queue
    /// drops its oldest entry.
    #[test]
    fn the_lapsed_folder_queue_keeps_each_folder_once_and_drops_the_oldest() {
        let folder = |at: usize| {
            let node_id = [at as u8; 16];
            LapsedFolder {
                scope_id: [0; 16],
                node_id,
                name: derive_write_name(&[1u8; 32], &node_id),
            }
        };
        let queue = RefCell::new(VecDeque::new());
        for at in 0..MAX_LAPSED_FOLDERS {
            queue_lapsed_folder(&queue, folder(at));
        }
        queue_lapsed_folder(&queue, folder(0));
        assert_eq!(queue.borrow().len(), MAX_LAPSED_FOLDERS);
        assert_eq!(queue.borrow().back(), Some(&folder(0)));
        queue_lapsed_folder(&queue, folder(MAX_LAPSED_FOLDERS));
        assert_eq!(queue.borrow().len(), MAX_LAPSED_FOLDERS);
        assert_eq!(queue.borrow().front(), Some(&folder(2)), "the oldest went");
    }

    #[test]
    fn a_name_the_drain_publishes_at_the_signature_is_not_signed() {
        use cipherbox_core::ipns::IpnsRecord;

        use super::super::eol::eol_from;
        use super::super::publish::Observed;
        use super::{FloorRule, RenewalSeams, renew_admitted};
        use crate::seams::FloorStore;
        use crate::testkit::{FakeWorld, block_on};

        let world = FakeWorld::new();
        let device = world.device(b"me");
        let signer = Ed25519Signer::from_seed([3u8; 32]);
        let name = IpnsName::from_public_key(&signer.verifying_key());
        let bytes =
            IpnsRecord::create_v2(&signer, b"/ipfs/bafyheld", 1, 1, &eol_from(UnixMillis(0)))
                .marshal();
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), bytes.clone());
        }
        block_on(
            device
                .floor_store
                .raise_sequence_floor(name.as_str().as_bytes(), 1),
        )
        .unwrap();
        let publishing = RefCell::new(BTreeSet::from([name.as_str().to_owned()]));
        let seams = RenewalSeams {
            transport: &device.record_store,
            floors: &device.floor_store,
            scheduler: &world.scheduler,
            profile: &SyncTimingProfile::CI,
            publishing: &publishing,
        };

        let renewal = block_on(renew_admitted(
            &seams,
            &Observed::admitted(&name, 1, &bytes),
            None,
            FloorRule::Exact,
            &signer,
            b"/ipfs/bafyheld",
        ));
        assert!(renewal.is_none(), "nothing is signed");
        let endpoint = device.record_store.endpoints()[0].clone();
        assert_eq!(
            device.record_store.record_at(&endpoint, name.as_str()),
            Some(bytes)
        );
    }
}
