//! The renewal walk (ADR 0061, blueprint/engine.md "Liveness"): a bounded,
//! resumable depth-first walk over every owned scope that re-signs each name
//! whose EOL is inside [`WALK_WINDOW`], and only a record the adoption gate
//! admitted in the same visit.

pub mod cursor;

use core::cell::RefCell;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::seal::{ChildRef, NodeKind, ReadBody};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use self::cursor::{
    CursorStore, DeferredRoot, MAX_CURSOR_PATH, MAX_DEFERRED_ROOTS, RenewalCursor, WalkRoot,
};
use super::REGISTRY_BATCH_MAX;
use super::child::{ChildAdopter, ChildResolveError, resolve_child_record};
use super::eol::{self, renewal_eol_from};
use super::fanout::{FanoutRecord, MAX_RECORD_BYTES, fanout_get_classified};
use super::liveness::{EolRenewResult, HeldKey, HeldRecord, HeldRecords, hold_if_unchanged};
use super::publish::{PublishError, PublishOutcome, head_cid_from_value, put_and_confirm};
use super::register::register;
use super::retire::{Acknowledged, OrphanHeads, StagingRetireLedger};
use super::rotation::{AdmittedScopeRoot, ScopeRootAdmission, admit_owned_scope_root, scope_name};
use crate::api::{ApiClient, NameRegistration};
use crate::bin_index::BinIndexKeys;
use crate::content::Gateway;
use crate::gate::{GateError, GateStage, floor};
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, RetireLedger, Scheduler, SnapshotCache,
    StagingStore,
};
use crate::session::SessionIdentity;
use crate::sync::doomed::{journalled_keys, open_reclamation};
use crate::sync::tick::ResolveMode;
use crate::sync::{BookkeepingSeal, owner_tag};

const DAY: u64 = 24 * 60 * 60;

/// The most visits one pass makes (ADR 0061 consequence 2).
pub const WALK_BUDGET: usize = 500;

/// A visit renews a name with at most this much EOL left.
pub const WALK_WINDOW: Duration = Duration::from_secs(60 * DAY);

/// A new cycle begins no sooner than this after the previous one began.
pub const CYCLE_HOLD: Duration = Duration::from_secs(7 * DAY);

/// The most poll cadences the liveness loop waits for the session's first
/// boundary walk before it skips the renewal walk for that pass. A walk that
/// starts before the boundary walk names every owned scope root would close its
/// cycle without them, and [`CYCLE_HOLD`] would then hold for 7 days.
pub const SCOPE_ROOTS_WAIT_POLLS: u32 = 10;

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
}

/// The seams and keys one walk pass runs over.
pub(crate) struct RenewalWalk<'a, T, H: Http, C: CredentialStore, F, S, St, Sch> {
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
}

/// What one pass did.
#[derive(Debug, Default)]
pub(crate) struct WalkReport {
    /// Every signature the pass attempted.
    pub(crate) renewals: Vec<EolRenewResult>,
    /// The names whose record the adoption gate refused.
    pub(crate) rejected: Vec<String>,
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
    admitted: Vec<u8>,
    sequence: u64,
    value: Vec<u8>,
    head_cid: String,
}

/// How a root's walk ended.
enum RootEnd {
    Finished,
    Stopped,
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
    due: Vec<Due>,
    /// The names a delete doomed, or `None` when the journal did not read.
    doomed: Option<BTreeSet<String>>,
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
        let stored = store.load().await.ok().flatten();
        let held = stored.as_ref().is_some_and(|cursor| {
            cursor.root.is_none()
                && cursor.cycle_start <= now
                && !now.reached(Some(cursor.cycle_start.saturating_add(CYCLE_HOLD)))
        });
        if held {
            return WalkReport::default();
        }
        let mut pass = Pass {
            cursor: stored.unwrap_or_else(|| RenewalCursor::starting(now)),
            report: WalkReport::default(),
            visits: 0,
            materials: BTreeMap::new(),
            scope_roots: scopes
                .iter()
                .map(|scope| scope.scope_id)
                .chain(scope_roots.iter().copied())
                .collect(),
            due: Vec::new(),
            doomed: None,
            owner_tag: owner_tag(self.enc_secret),
            scopes,
            bins,
        };
        if pass.cursor.root.is_none() {
            pass.cursor = RenewalCursor::starting(now);
            pass.cursor.root = pass.roots().first().copied();
        }
        pass.doomed = self.doomed_names(&pass.owner_tag).await;

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
        // A cursor that does not store only costs work: the next pass starts
        // the cycle again.
        let _ = store.save(&pass.cursor).await;
        pass.report
    }

    /// The names every doomed-name journal entry of this owner holds, or `None`
    /// when the store does not list. An entry that does not open names nothing
    /// here: renewing a doomed name leaks a registration, where a walk that
    /// renews nothing lets the vault lapse.
    async fn doomed_names(&self, owner_tag: &[u8; 32]) -> Option<BTreeSet<String>> {
        let keys = self.staging.staged_keys().await.ok()?;
        let mut doomed = BTreeSet::new();
        for (key, _, _) in journalled_keys(owner_tag, &keys) {
            let Some(reclamation) = self
                .staging
                .staged_bytes(&key)
                .await
                .ok()
                .flatten()
                .and_then(|blob| open_reclamation(self.seal, &blob))
            else {
                continue;
            };
            doomed.extend(reclamation.names());
            doomed.extend(reclamation.quarantined.into_iter().map(|held| held.name));
        }
        Some(doomed)
    }

    /// Admit `scope_id`'s root once per pass.
    async fn material<'p>(
        &self,
        pass: &'p mut Pass<'_>,
        scope_id: [u8; 16],
    ) -> Option<&'p ScopeMaterial> {
        if !pass.materials.contains_key(&scope_id) {
            let material = match pass.scopes.iter().find(|scope| scope.scope_id == scope_id) {
                Some(scope) => {
                    pass.visits += 1;
                    match admit_owned_scope_root(
                        self.transport,
                        self.gateway,
                        self.http,
                        self.floors,
                        self.snapshot_cache,
                        self.enc_secret,
                        self.identity,
                        scope_id,
                        scope.ascent.as_ref(),
                        &scope.name,
                    )
                    .await
                    {
                        Ok(mut admitted) => {
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
                        Err(ScopeRootAdmission::Rejected) => {
                            pass.report.rejected.push(scope.name.as_str().to_owned());
                            None
                        }
                        Err(ScopeRootAdmission::Unavailable) => None,
                    }
                }
                None => None,
            };
            pass.materials.insert(scope_id, material);
        }
        pass.materials.get(&scope_id).and_then(Option::as_ref)
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
            match reopened {
                Some(body @ ReadBody::Folder { .. }) => frames.push(Frame::of(id, body)),
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
            if child.kind != NodeKind::Folder || !matches!(body, ReadBody::Folder { .. }) {
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
                let name = material.name.clone();
                let admitted = &material.admitted;
                let body = admitted.read_body.clone();
                let plane = Plane {
                    scope_id,
                    read_seed: admitted.read_scope_seed.clone(),
                };
                let (bytes, sequence) = (admitted.record_bytes.clone(), admitted.sequence);
                self.consider(pass, scope_id, scope_id, &name, &bytes, sequence)
                    .await;
                Some((plane, scope_id, body))
            }
            WalkRoot::Bin(node_id) => {
                let keys = self.bin_keys?;
                let bin = pass.bins.iter().find(|bin| bin.node_id == node_id)?;
                let (scope_id, name) = (bin.scope_id, bin.name.clone());
                let plane = Plane {
                    scope_id,
                    read_seed: keys.held_key(&node_id, bin.deleted_at),
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
                let read_seed = self
                    .material(pass, scope_id)
                    .await?
                    .admitted
                    .read_scope_seed
                    .clone();
                let plane = Plane {
                    scope_id,
                    read_seed,
                };
                let body = self.admit(pass, &plane, node_id, &name, false).await?;
                Some((plane, node_id, body))
            }
        }
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
        );
        match resolve_child_record(
            self.transport,
            self.snapshot_cache,
            &adopter,
            name,
            scope_root.as_ref(),
            ResolveMode::CacheFirst,
        )
        .await
        {
            Ok((adopted, bytes)) => {
                self.consider(
                    pass,
                    plane.scope_id,
                    node_id,
                    name,
                    &bytes,
                    adopted.sequence,
                )
                .await;
                Some(adopted.read_body)
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
            Err(_) => None,
        }
    }

    /// Queue a renewal of the record the gate admitted at `sequence`, when its
    /// EOL is inside the window and no other write can come between (ADR 0061
    /// D3 step 2).
    async fn consider(
        &self,
        pass: &mut Pass<'_>,
        material_scope: [u8; 16],
        node_id: [u8; 16],
        name: &IpnsName,
        admitted: &[u8],
        sequence: u64,
    ) {
        let Ok(verified) = IpnsRecord::unmarshal(admitted).and_then(|record| record.verify(name))
        else {
            return;
        };
        let due = eol::needs_renewal(self.scheduler.now(), &verified.validity, WALK_WINDOW);
        if !due || verified.sequence != sequence {
            return;
        }
        let Some(head_cid) = head_cid_from_value(&verified.value) else {
            return;
        };
        let Some(signer) = pass
            .materials
            .get(&material_scope)
            .and_then(Option::as_ref)
            .and_then(|material| material.signer_for(&node_id, name))
        else {
            return;
        };
        let key = name.as_str();
        if pass
            .doomed
            .as_ref()
            .is_none_or(|doomed| doomed.contains(key))
            || self
                .guards
                .orphan_heads
                .pending()
                .iter()
                .any(|held| held == key)
            || self.guards.publishing.borrow().contains(key)
        {
            return;
        }
        let ledger = StagingRetireLedger::new(self.staging, self.seal);
        if !matches!(ledger.tombstoned(&pass.owner_tag, node_id).await, Ok(false)) {
            return;
        }
        match ledger.acknowledged(&pass.owner_tag, node_id, key).await {
            Ok(Acknowledged::Nothing) => {}
            Ok(Acknowledged::At(acked)) if acked <= sequence => {}
            _ => return,
        }
        pass.due.push(Due {
            node_id,
            name: name.clone(),
            signer,
            admitted: admitted.to_vec(),
            sequence,
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
                    pass.report.renewals.push(EolRenewResult {
                        routing_key: due.name.as_str().to_owned(),
                        outcome,
                    });
                }
            }
        }
    }

    /// Sign `due` at `S + 1` when the network still serves the admitted record
    /// and the durable floor still sits at `S`. `None` when either moved.
    async fn renew(&self, due: &Due) -> Option<Result<Option<PublishOutcome>, PublishError>> {
        match fanout_get_classified(self.transport, &due.name).await {
            FanoutRecord::Found(_, live) if live == due.admitted => {}
            _ => return None,
        }
        let floor = match floor::sequence_floor(self.floors, due.name.as_str().as_bytes()).await {
            Ok(floor) => floor,
            Err(error) => return Some(Err(PublishError::FloorRead(error))),
        };
        // No await from here to the signature.
        if floor != Some(due.sequence)
            || self.guards.publishing.borrow().contains(due.name.as_str())
        {
            return None;
        }
        let Some(sequence) = due.sequence.checked_add(1) else {
            return Some(Err(PublishError::SequenceExhausted));
        };
        let ttl_nanos = u64::try_from(self.profile.record_ttl.as_nanos()).unwrap_or(u64::MAX);
        let eol = renewal_eol_from(self.scheduler.now());
        let record_bytes =
            IpnsRecord::create_v2(&due.signer, &due.value, sequence, ttl_nanos, &eol).marshal();
        if record_bytes.len() > MAX_RECORD_BYTES {
            return Some(Err(PublishError::RecordTooLarge {
                size: record_bytes.len(),
                limit: MAX_RECORD_BYTES,
            }));
        }
        let receipt = match put_and_confirm(
            self.transport,
            self.scheduler,
            self.profile,
            &due.name,
            record_bytes,
            sequence,
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(error) => return Some(Err(error)),
        };
        if matches!(receipt.outcome, PublishOutcome::Published { .. }) {
            self.follow_held(due, &receipt.record_bytes);
        }
        Some(Ok(Some(receipt.outcome)))
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
            Some(&due.admitted),
        );
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
                record_bytes: Vec::new(),
                sequence: 1,
                read_body: ReadBody::Folder {
                    created_at: 0,
                    modified_at: 0,
                    children: Vec::new(),
                    unknown: cipherbox_core::seal::PreservedFields::new(),
                },
                read_scope_seed: Zeroizing::new([0; 32]),
                write_scope_seed: Some(Zeroizing::new(current)),
            },
        }
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
}
