//! The focus-window refresh: the read leg that renders a node **below** the
//! scope root (blueprint/engine.md "Sync core: focus-window tick").
//!
//! Each node the window names resolves its own record cache-first through
//! [`resolve_child`], passes the [`ChildAdopter`] gate on this device's floors,
//! and merges into the base — the root leg's merge model, one level down. A
//! folder merges its listing with [`project_folder_partial`]; a file merges
//! its head version with [`project_child_version`], which is the only way its
//! size and mtime move, since a `ChildRef` mirrors neither.

use core::cell::RefCell;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::{ChildRef, ReadBody};
use futures_channel::mpsc;
use zeroize::Zeroizing;

use super::child::{ChildAdopter, ChildResolveError, resolve_child};
use crate::content::Gateway;
use crate::facade::{Event, NodeId, NodeKind, emit_trust_violation};
use crate::gate::{Adopted, GateError, RejectionReason};
use crate::grants::TooLong;
use crate::grants::grafted::{BookmarkedScopeRoots, ClaimRecord, GraftedPlane, PlaneSplit};
use crate::seams::{FloorStore, Http, RecordTransport, SnapshotCache};
use crate::sync::project::{UnlinkedChild, merge_folder, project_child_version};
use crate::sync::refresh::RefreshVerdict;
use crate::sync::render::BaseSnapshot;
use crate::sync::tick::ResolveMode;

/// What one focus-folder pass did. The verdict is the pass's own read legs, kept
/// separate from the root's so a forced refresh reports every folder it was
/// asked to bring forward rather than the root alone.
pub(crate) struct FolderRefreshReport {
    /// Whether the base moved.
    pub(crate) changed: bool,
    /// The worst verdict any folder leg earned.
    pub(crate) verdict: RefreshVerdict,
    /// Children a refreshed folder stopped naming — an unlink this device did
    /// not author, which the owner's engine adopts into the bin.
    pub(crate) departed: Vec<UnlinkedChild>,
}

impl FolderRefreshReport {
    fn fold(&mut self, verdict: RefreshVerdict) {
        self.verdict = self.verdict.worst(verdict);
    }
}

/// What a folder's gate rejection costs the pass, or `None` when it costs it
/// nothing.
///
/// A folder the lazy wave has not swept yet is epoch-lagged (CONTEXT.md): the
/// plane answered and the gate did its job, and only the sweep re-seals it —
/// which is why the sweep alone reads below the epoch stage
/// ([`Strictness::AtOrAboveFloor`](crate::gate::floor::Strictness)). Failing the
/// pass on it would report a *retryable* verdict for a state no retry clears,
/// and would fire on every refresh a user makes while a wave is in flight. It is
/// not abuse either, so nobody is accused. Every other rejection is attributable
/// and fail-closed.
fn rejection_verdict(reason: &RejectionReason) -> Option<RefreshVerdict> {
    match reason {
        RejectionReason::EpochBelowFloor { .. } => None,
        RejectionReason::Trust(_)
        | RejectionReason::SequenceNotNewer { .. }
        | RejectionReason::ScopeRootNotResealable { .. } => Some(RefreshVerdict::Rejected),
    }
}

/// The own plane withholds nothing: every child of a body this vault authored is
/// this vault's own node.
const NOTHING_WITHHELD: &[[u8; 16]] = &[];

/// What a leg below a grafted root applies the cross-plane rule with: the
/// bookmarked scope roots, and the claim record ([`ClaimRecord`]).
///
/// The record rather than a finished contest, because this leg reads the only
/// bodies that name a node deep in a grafted subtree: it records each one and
/// reads the contest back over the whole record.
#[derive(Clone, Copy)]
pub(crate) struct GraftedLeg<'a> {
    pub(crate) scope_roots: &'a BookmarkedScopeRoots,
    pub(crate) claims: &'a RefCell<ClaimRecord>,
}

/// The focus-window folder refresh over one owned scope's read material.
/// Borrows the content/record seams from the live session; the caller's read
/// seed is borrowed and never zeroized here.
pub(crate) struct FolderRefresh<'a, T, S, H, F> {
    pub(crate) transport: &'a T,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) http: &'a H,
    /// This scope's own floor namespace
    /// ([`SharerScopedFloorStore`](crate::seams::SharerScopedFloorStore)).
    pub(crate) floors: &'a F,
    pub(crate) gateway: &'a Gateway,
    /// The gate-passing base snapshot, merged into in place.
    pub(crate) base: &'a BaseSnapshot,
    /// Where a fail-closed rejection on a focused folder is surfaced.
    pub(crate) events: &'a mpsc::UnboundedSender<Event>,
    /// The scope every focus folder is sealed under.
    pub(crate) scope_id: [u8; 16],
    pub(crate) scope_read_seed: &'a Zeroizing<[u8; 32]>,
    /// The plane this leg runs on, or `None` on this vault's own plane
    /// ([`GraftedLeg`]).
    pub(crate) plane: Option<GraftedLeg<'a>>,
    /// How this pass resolves each folder's record: a manual refresh forces
    /// [`ResolveMode::NoCache`], so an unreachable record is reported as
    /// staleness rather than re-projected from cached bytes.
    pub(crate) mode: ResolveMode,
    /// The pass's own clock read, stamped on every capture this leg observes.
    pub(crate) observed_at: u64,
}

impl<T, S, H, F> FolderRefresh<'_, T, S, H, F>
where
    T: RecordTransport,
    S: SnapshotCache,
    H: Http,
    F: FloorStore,
{
    /// Merge each of `folders` into the base, reporting whether the base moved.
    /// They arrive nearest-first; the merge runs root-ward, so a parent that
    /// dropped a child unlinks it before the pass would project into it.
    pub(crate) async fn run(&self, folders: &[NodeId]) -> FolderRefreshReport {
        let mut report = FolderRefreshReport {
            changed: false,
            verdict: RefreshVerdict::Reconciled,
            departed: Vec::new(),
        };
        for folder in folders.iter().rev() {
            let Some((name, adopted)) = self
                .resolve_focused(*folder, NodeKind::Folder, &mut report)
                .await
            else {
                continue;
            };
            let ReadBody::Folder {
                modified_at,
                children,
                ..
            } = &adopted.read_body
            else {
                // The parent's child ref said folder: a sealed file body is a
                // kind transplant, fail-closed.
                emit_trust_violation(
                    self.events,
                    name.as_str(),
                    "sealed file body behind a folder child ref",
                );
                report.fold(RefreshVerdict::Rejected);
                continue;
            };
            let split = match self.split(*folder, children) {
                Ok(split) => split,
                Err(over_full) => {
                    emit_trust_violation(self.events, name.as_str(), over_full);
                    report.fold(RefreshVerdict::Rejected);
                    continue;
                }
            };
            if split.as_ref().is_some_and(|split| split.names_own_tree) {
                emit_trust_violation(
                    self.events,
                    name.as_str(),
                    "child ref names a node this vault's own tree holds",
                );
            }
            let (linkable, withheld) = match &split {
                Some(split) => (split.linkable.as_slice(), split.withheld.as_slice()),
                None => (children.as_slice(), NOTHING_WITHHELD),
            };
            let merged = merge_folder(
                &mut self.base.borrow_mut(),
                *folder,
                linkable,
                withheld,
                adopted.sequence,
                *modified_at,
            );
            report.changed |= merged.changed;
            report.departed.extend(merged.observed_unlinks(
                self.scope_id,
                *folder,
                self.observed_at,
            ));
        }
        report
    }

    /// How this leg's plane splits a foreign body's children
    /// ([`GraftedPlane::split`]), or `None` on this vault's own plane.
    ///
    /// `folder`'s own claim is recorded first, so the contest this split reads
    /// covers what this very body names — and a body the record refuses is
    /// refused here as well ([`ClaimRecord::record`]).
    fn split(&self, folder: NodeId, children: &[ChildRef]) -> Result<Option<PlaneSplit>, TooLong> {
        let Some(leg) = self.plane else {
            return Ok(None);
        };
        let mut claims = leg.claims.borrow_mut();
        claims.record(self.scope_id, folder.0, children)?;
        Ok(Some(
            GraftedPlane {
                scope_id: self.scope_id,
                scope_roots: leg.scope_roots,
                contested: claims.contested(),
            }
            .split(&self.base.borrow(), children),
        ))
    }

    /// Fold each file's published head into the base, reporting whether the base
    /// moved.
    ///
    /// A `ChildRef` carries no size or mtime mirror, so a folder refresh cannot
    /// move a file's projected attributes however often it runs — only the
    /// file's own record does. This is that leg, and it is on-access rather than
    /// ticked over a whole listing (CONTEXT.md "focus window").
    ///
    /// Failure handling is the folder leg's, and a file that has published no
    /// version leaves the base untouched rather than projecting a zero.
    pub(crate) async fn run_files(&self, files: &[NodeId]) -> FolderRefreshReport {
        let mut report = FolderRefreshReport {
            changed: false,
            verdict: RefreshVerdict::Reconciled,
            departed: Vec::new(),
        };
        for file in files {
            let Some((name, adopted)) = self
                .resolve_focused(*file, NodeKind::File, &mut report)
                .await
            else {
                continue;
            };
            let ReadBody::File { versions, .. } = &adopted.read_body else {
                emit_trust_violation(
                    self.events,
                    name.as_str(),
                    "sealed folder body behind a file child ref",
                );
                report.fold(RefreshVerdict::Rejected);
                continue;
            };
            let Some(head) = versions.first() else {
                continue;
            };
            report.changed |= project_child_version(
                &mut self.base.borrow_mut(),
                *file,
                head.size,
                head.modified_at,
                versions.len() as u64,
                Some(&head.content_cid),
            );
        }
        report
    }

    /// Resolve one focused node's own record through the child gate.
    ///
    /// Every failure is per-node and non-fatal: an unresolvable record is
    /// availability staleness, an attributable gate rejection is fail-closed and
    /// surfaced as [`Event::AttributableAbuse`], and both leave last-known-good
    /// rendering without stopping the pass. Each still lands in `report`, so the
    /// caller's verdict covers the focused nodes as well as the root.
    async fn resolve_focused(
        &self,
        node: NodeId,
        kind: NodeKind,
        report: &mut FolderRefreshReport,
    ) -> Option<(IpnsName, Adopted)> {
        let name = self.child_name(node, kind)?;
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            self.scope_id,
            self.scope_read_seed.clone(),
            node.0,
        );
        match resolve_child(
            self.transport,
            self.snapshot_cache,
            &adopter,
            &name,
            self.mode,
        )
        .await
        {
            Ok(adopted) => Some((name, adopted)),
            // Availability: the base keeps rendering last-known-good.
            Err(
                ChildResolveError::Unavailable(_) | ChildResolveError::Gate(GateError::Seam(_)),
            ) => {
                report.fold(RefreshVerdict::Unreachable);
                None
            }
            Err(ChildResolveError::Gate(GateError::Rejected(rejection))) => {
                if let Some(verdict) = rejection_verdict(&rejection.reason) {
                    emit_trust_violation(self.events, name.as_str(), rejection);
                    report.fold(verdict);
                }
                None
            }
        }
    }

    /// The node's write-plane name as its parent's `ChildRef` carried it.
    /// `None` for a node absent from gate-passing state, one of another kind, or
    /// a ref whose bytes are not a canonical IPNS name.
    fn child_name(&self, node: NodeId, kind: NodeKind) -> Option<IpnsName> {
        let base = self.base.borrow();
        let meta = base.node(node)?;
        if meta.kind != kind {
            return None;
        }
        IpnsName::parse(core::str::from_utf8(meta.ipns_name.as_deref()?).ok()?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sync::model::Snapshot;

    use cipherbox_core::content::{compute_cid, encode_content_cid_str};
    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::kdf;
    use cipherbox_core::seal::{
        NodeKind as CoreNodeKind, PreservedFields, encode_envelope, seal_read_body,
    };

    use core::cell::Cell;
    use std::collections::BTreeSet;

    use crate::content::{DAG_ROOT_CODEC, GatewaySource};
    use crate::facade::MAX_FOLDER_CHILDREN;
    use crate::grants::grafted::BookmarkedScopeRoots;
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::sync::model::NodeMeta;
    use crate::testkit::block_on;
    use crate::testkit::fakes::{
        InMemoryFloorStore, InMemoryRecordStore, InMemorySnapshotCache, ScriptedHttp,
    };

    /// This vault's own anchored root scope.
    const OWN_ROOT: [u8; 16] = [0u8; 16];
    /// The scope root a hostile contact granted, grafted into the render tree.
    const SCOPE_A: [u8; 16] = [0xaa; 16];
    /// A second contact's scope root, grafted beside it.
    const SCOPE_B: [u8; 16] = [0xbb; 16];
    /// The folder record below `SCOPE_A` that the leg refreshes.
    const FOLDER: [u8; 16] = [0xc1; 16];
    /// A child of that folder whose id a third bookmark later claims.
    const CONTESTED: [u8; 16] = [0xc2; 16];
    /// A child of that folder the body stops naming.
    const DROPPED: [u8; 16] = [0xc3; 16];
    /// A node this vault's own tree holds.
    const OWN_CHILD: [u8; 16] = [0xd1; 16];
    /// A child of the hostile body that no other plane claims.
    const HONEST: [u8; 16] = [0xe1; 16];

    const READ_SCOPE_SEED: [u8; 32] = [0x66; 32];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x77; 32];
    const EPOCH: u64 = 1;

    fn child_ref(id: [u8; 16], name: &str, link_counter: u64) -> ChildRef {
        ChildRef {
            id,
            name: name.to_owned(),
            ipns_name: vec![id[0]],
            kind: CoreNodeKind::Folder,
            link_counter,
            unknown: PreservedFields::new(),
        }
    }

    /// The world one folder leg reads: the sealed folder record `FOLDER`
    /// publishes, and the render tree it merges into.
    struct FolderLeg {
        records: InMemoryRecordStore,
        snapshot_cache: InMemorySnapshotCache,
        http: ScriptedHttp,
        gateway: Gateway,
        floors: InMemoryFloorStore,
        base: BaseSnapshot,
        read_seed: Zeroizing<[u8; 32]>,
        head_block: Vec<u8>,
        /// The captures the last pass reported, so a test can hold the
        /// cross-plane rule to the bin path as well as to the render tree.
        captured: RefCell<Vec<NodeId>>,
        /// What the last pass charged itself.
        verdict: Cell<RefreshVerdict>,
    }

    impl FolderLeg {
        /// `FOLDER` sealed under `scope` at `READ_SCOPE_SEED`, serving
        /// `children`, published at its own write-plane name.
        fn new(scope: [u8; 16], children: Vec<ChildRef>) -> Self {
            let node_seed = kdf::node_seed(&READ_SCOPE_SEED, &FOLDER);
            let envelope = seal_read_body(
                kdf::read_key(node_seed.as_bytes()).as_bytes(),
                // Distinct per scope: one key with one nonce over two bodies
                // would break the seal's uniqueness precondition.
                &[scope[0]; 24],
                1,
                FOLDER,
                scope,
                EPOCH,
                &ReadBody::Folder {
                    created_at: 0,
                    modified_at: 500,
                    children,
                    unknown: PreservedFields::new(),
                },
            )
            .expect("the body seals");
            let head_block = encode_envelope(&envelope).expect("the envelope encodes");
            let head_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));

            let endpoint = EndpointId::new("e0");
            let records = InMemoryRecordStore::new(vec![endpoint.clone()]);
            let write_seed = kdf::write_seed(&WRITE_SCOPE_SEED, &FOLDER);
            records.seed_record(
                &endpoint,
                folder_name().as_str(),
                IpnsRecord::create_v2(
                    &kdf::ipns_keypair(write_seed.as_bytes()),
                    format!("/ipfs/{head_cid}").as_bytes(),
                    1,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
            Self {
                records,
                snapshot_cache: InMemorySnapshotCache::default(),
                http: ScriptedHttp::default(),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                },
                floors: InMemoryFloorStore::default(),
                base: BaseSnapshot::new(Snapshot::new(NodeId(OWN_ROOT))),
                read_seed: Zeroizing::new(READ_SCOPE_SEED),
                head_block,
                captured: RefCell::new(Vec::new()),
                verdict: Cell::new(RefreshVerdict::Reconciled),
            }
        }

        /// Place a folder node under `parent`, or parentless when `parent` is
        /// `None` — the shape a grafted scope root has.
        fn place(&self, id: [u8; 16], name: &str, parent: Option<[u8; 16]>) {
            let mut base = self.base.borrow_mut();
            let mut meta = NodeMeta::new(NodeId(id), name, NodeKind::Folder);
            meta.ipns_name = Some(if id == FOLDER {
                folder_name().as_str().as_bytes().to_vec()
            } else {
                vec![id[0]]
            });
            base.upsert_node(meta);
            if let Some(parent) = parent {
                base.link(NodeId(parent), NodeId(id), 1);
            }
        }

        /// One folder-leg pass over `FOLDER`, with the head block its resolve
        /// fetches served.
        fn run(&self, scope_id: [u8; 16], plane_roots: Option<&BookmarkedScopeRoots>) -> bool {
            self.run_recorded(scope_id, plane_roots, &RefCell::new(ClaimRecord::default()))
        }

        /// The same pass, over a claim record a second scope has already
        /// written into.
        fn run_recorded(
            &self,
            scope_id: [u8; 16],
            plane_roots: Option<&BookmarkedScopeRoots>,
            claims: &RefCell<ClaimRecord>,
        ) -> bool {
            self.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.head_block.clone(),
            });
            let (events, mut rx) = mpsc::unbounded();
            let report = block_on(
                FolderRefresh {
                    transport: &self.records,
                    snapshot_cache: &self.snapshot_cache,
                    http: &self.http,
                    floors: &self.floors,
                    gateway: &self.gateway,
                    base: &self.base,
                    events: &events,
                    scope_id,
                    scope_read_seed: &self.read_seed,
                    plane: plane_roots.map(|scope_roots| GraftedLeg {
                        scope_roots,
                        claims,
                    }),
                    mode: ResolveMode::NoCache,
                    observed_at: 0,
                }
                .run(&[NodeId(FOLDER)]),
            );
            self.verdict.set(report.verdict);
            *self.captured.borrow_mut() = report
                .departed
                .into_iter()
                .map(|unlinked| unlinked.node)
                .collect();
            drop(events);
            core::iter::from_fn(|| rx.try_recv().ok())
                .any(|event| matches!(event, Event::AttributableAbuse { .. }))
        }

        /// The names the render tree lists under `parent`.
        fn listing(&self, parent: [u8; 16]) -> Vec<String> {
            self.base
                .borrow()
                .children(NodeId(parent))
                .into_iter()
                .map(|child| child.name().to_owned())
                .collect()
        }

        fn parent_of(&self, id: [u8; 16]) -> Option<NodeId> {
            self.base.borrow().parent_of(NodeId(id))
        }

        fn holds(&self, id: [u8; 16]) -> bool {
            self.base.borrow().contains(NodeId(id))
        }

        fn name_of(&self, id: [u8; 16]) -> String {
            self.base
                .borrow()
                .node(NodeId(id))
                .expect("the node is present")
                .name()
                .to_owned()
        }
    }

    fn folder_name() -> IpnsName {
        derive_write_name(&WRITE_SCOPE_SEED, &FOLDER)
    }

    /// One child of a body that pads its listing: a distinct id, name and
    /// `ipnsName`, all three of which a sealed body holds to uniqueness.
    fn padding_child(i: usize) -> ChildRef {
        let mut id = [0xb0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        ChildRef {
            id,
            name: format!("padding-{i}"),
            ipns_name: id.to_vec(),
            kind: CoreNodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    fn scope_roots() -> BookmarkedScopeRoots {
        BookmarkedScopeRoots::from([SCOPE_A, SCOPE_B])
    }

    /// A body below one grafted root names a second contact's scope root and a
    /// node of this vault's own. Neither may change hands: the projection leaves
    /// the old parent standing, so an accepted link would hand the id to
    /// whichever plane raised `link_counter` highest, under the name the hostile
    /// body chose. Naming a node of this vault's own tree is attributable.
    #[test]
    fn a_folder_below_a_grafted_root_links_no_other_planes_node() {
        let leg = FolderLeg::new(
            SCOPE_A,
            vec![
                child_ref(SCOPE_B, "stolen-share", 9),
                child_ref(OWN_CHILD, "stolen-note", 9),
                child_ref(HONEST, "a-photo", 1),
            ],
        );
        leg.place(OWN_CHILD, "my-note", Some(OWN_ROOT));
        leg.place(SCOPE_A, "from-a", None);
        leg.place(SCOPE_B, "from-b", None);
        leg.place(FOLDER, "a-folder", Some(SCOPE_A));

        let reported = leg.run(SCOPE_A, Some(&scope_roots()));

        assert_eq!(leg.listing(FOLDER), vec!["a-photo".to_owned()]);
        assert_eq!(
            leg.parent_of(SCOPE_B),
            None,
            "the second contact's root keeps its own place"
        );
        assert_eq!(leg.name_of(SCOPE_B), "from-b");
        assert_eq!(leg.parent_of(OWN_CHILD), Some(NodeId(OWN_ROOT)));
        assert_eq!(leg.name_of(OWN_CHILD), "my-note");
        assert!(reported, "a body that names a vault node is attributable");
    }

    /// A refusal is not a removal. An id a later bookmark contests is already
    /// linked under this folder, and the leg has no more authority to unlink it
    /// than to link it — while an id the body simply stops naming still departs.
    #[test]
    fn a_withheld_child_is_neither_relinked_nor_removed() {
        let leg = FolderLeg::new(
            SCOPE_A,
            vec![
                child_ref(CONTESTED, "renamed", 9),
                child_ref(HONEST, "a-photo", 1),
            ],
        );
        leg.place(SCOPE_A, "from-a", None);
        leg.place(FOLDER, "a-folder", Some(SCOPE_A));
        leg.place(CONTESTED, "still-mine", Some(FOLDER));
        leg.place(DROPPED, "gone", Some(FOLDER));
        let contested = BookmarkedScopeRoots::from([SCOPE_A, CONTESTED]);

        leg.run(SCOPE_A, Some(&contested));

        assert_eq!(leg.parent_of(CONTESTED), Some(NodeId(FOLDER)));
        assert_eq!(leg.name_of(CONTESTED), "still-mine");
        assert!(!leg.holds(DROPPED), "an unnamed child still departs");
        assert_eq!(
            *leg.captured.borrow(),
            vec![NodeId(DROPPED)],
            "a withheld id is no departure, so the bin never captures it"
        );
    }

    /// The claim record reaches every leg below a grafted root, not the graft
    /// alone: a body may move a contested id down into a folder of its own, and
    /// no plane renders such an id.
    #[test]
    fn a_folder_below_a_grafted_root_departs_a_contested_child() {
        let leg = FolderLeg::new(SCOPE_A, vec![child_ref(CONTESTED, "still-mine", 1)]);
        leg.place(SCOPE_A, "from-a", None);
        leg.place(FOLDER, "a-folder", Some(SCOPE_A));
        leg.place(CONTESTED, "still-mine", Some(FOLDER));
        let claims = RefCell::new(ClaimRecord::default());
        claims
            .borrow_mut()
            .record(SCOPE_B, SCOPE_B, &[child_ref(CONTESTED, "theirs", 1)])
            .expect("the body is within the bound");

        leg.run_recorded(SCOPE_A, Some(&scope_roots()), &claims);

        assert!(leg.listing(FOLDER).is_empty());
        assert!(!leg.holds(CONTESTED));
    }

    /// The folder leg is the only body that names a node this deep, so it must
    /// write its claim into the record. Without it a hostile root body one
    /// level up is alone on the id and takes it.
    #[test]
    fn a_folder_leg_records_what_its_body_names() {
        let leg = FolderLeg::new(SCOPE_A, vec![child_ref(HONEST, "a-photo", 1)]);
        leg.place(SCOPE_A, "from-a", None);
        leg.place(FOLDER, "a-folder", Some(SCOPE_A));
        let claims = RefCell::new(ClaimRecord::default());

        leg.run_recorded(SCOPE_A, Some(&scope_roots()), &claims);

        assert_eq!(
            claims.borrow().named().get(&(SCOPE_A, FOLDER)),
            Some(&BTreeSet::from([HONEST])),
        );
    }

    /// A body past the folder ceiling is one no author path emits. The record
    /// refuses it, so the leg renders none of it: a truncated claim would let
    /// the padding evade the contest, and an unrecorded merge would render ids
    /// no contest covers. The refusal charges the pass and departs nothing.
    #[test]
    fn an_over_full_grafted_body_charges_the_pass_and_renders_nothing() {
        let mut over_full: Vec<ChildRef> = (0..MAX_FOLDER_CHILDREN).map(padding_child).collect();
        over_full.push(child_ref(HONEST, "a-photo", 1));
        let leg = FolderLeg::new(SCOPE_A, over_full);
        leg.place(SCOPE_A, "from-a", None);
        leg.place(FOLDER, "a-folder", Some(SCOPE_A));
        leg.place(DROPPED, "still-here", Some(FOLDER));
        let claims = RefCell::new(ClaimRecord::default());

        let reported = leg.run_recorded(SCOPE_A, Some(&scope_roots()), &claims);

        assert!(reported, "an over-full body is attributable");
        assert_eq!(leg.verdict.get(), RefreshVerdict::Rejected);
        assert!(claims.borrow().named().is_empty(), "it claims nothing");
        assert!(!leg.holds(HONEST), "and it links nothing");
        assert_eq!(
            leg.listing(FOLDER),
            vec!["still-here".to_owned()],
            "a refusal is no departure either",
        );
        assert!(leg.captured.borrow().is_empty());
    }

    /// The bound is the author path's, so a body that fills a folder to the
    /// ceiling still records and still renders.
    #[test]
    fn a_grafted_body_at_the_folder_ceiling_still_renders() {
        let mut at_ceiling: Vec<ChildRef> =
            (0..MAX_FOLDER_CHILDREN - 1).map(padding_child).collect();
        at_ceiling.push(child_ref(HONEST, "a-photo", 1));
        let leg = FolderLeg::new(SCOPE_A, at_ceiling);
        leg.place(SCOPE_A, "from-a", None);
        leg.place(FOLDER, "a-folder", Some(SCOPE_A));
        let claims = RefCell::new(ClaimRecord::default());

        leg.run_recorded(SCOPE_A, Some(&scope_roots()), &claims);

        assert_eq!(leg.verdict.get(), RefreshVerdict::Reconciled);
        assert_eq!(
            claims
                .borrow()
                .named()
                .get(&(SCOPE_A, FOLDER))
                .map(BTreeSet::len),
            Some(MAX_FOLDER_CHILDREN),
        );
        assert!(leg.holds(HONEST));
    }

    /// The rule is the grafted plane's alone. On this vault's own plane every
    /// child is this vault's own node, so applying it there would drop a move
    /// this vault itself authored.
    #[test]
    fn the_vaults_own_leg_still_links_its_own_node() {
        let leg = FolderLeg::new(OWN_ROOT, vec![child_ref(OWN_CHILD, "my-note", 2)]);
        leg.place(OWN_CHILD, "my-note", Some(OWN_ROOT));
        leg.place(FOLDER, "a-folder", Some(OWN_ROOT));

        leg.run(OWN_ROOT, None);

        assert_eq!(leg.listing(FOLDER), vec!["my-note".to_owned()]);
    }

    #[test]
    fn only_an_epoch_lagged_folder_costs_the_pass_nothing() {
        assert_eq!(
            rejection_verdict(&RejectionReason::EpochBelowFloor { floor: 5, epoch: 4 }),
            None,
            "the sweep clears epoch lag; no retry of this pass can, so it fails nothing"
        );
        assert_eq!(
            rejection_verdict(&RejectionReason::SequenceNotNewer {
                floor: 5,
                sequence: 4,
            }),
            Some(RefreshVerdict::Rejected),
            "a replay is attributable and fail-closed"
        );
    }
}
