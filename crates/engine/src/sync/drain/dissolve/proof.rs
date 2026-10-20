//! The decision on a relink that left this device, before any old name
//! retires (ADR 0077 "Rotation primitives").
//!
//! When the parent names neither root or both, the fence comes first: at each
//! parent name a relink published at, the endpoints must serve a record above
//! each relink mark and the ADR 0076 unacknowledged mark there, so no late PUT
//! of the relink can land after the verdict. Then a two-sweep walk of each scope that shares the write scope
//! of the destination, the bin index, and each binned subtree under its held
//! key finds which of the copy and the source root a folder names. A parked
//! entry runs the proof again in the next session.

use core::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::seal::ReadBody;
use cipherbox_core::suite::secret::ct_eq;

use super::super::walker::{Overflow, ReadFault, SweepPolicy, Swept, TwoSweep};
use super::super::{
    Anchor, ChildFault, Drain, DrainScope, RecordMark, ScopeEnd, WalkAnchor, refuse_record,
    take_tick_read,
};
use super::relink::relink_mark_keys;
use super::seal::Destination;
use super::{EndMark, MAX_DISSOLVE_READ_ATTEMPTS, MAX_DISSOLVE_WALK_NODES, NotDriven, ReadShare};
use crate::facade::NodeId;
use crate::gate::floor;
use crate::net::gated_read::LeafRead;
use crate::net::retire::{Acknowledged, HeldMarks};
use crate::seams::{
    CredentialStore, FloorStore, Http, RecordTransport, Scheduler, SnapshotCache, StagingStore,
};
use crate::sync::dissolve_journal::{DissolveHeader, DissolveHold, DissolveJournal, DissolveStep};
use crate::sync::drain::owner_tag;
use crate::sync::tick::ResolveMode;

/// What the fence of a proof found.
enum Fence {
    Holds,
    Fails,
    /// The tick has too few reads left.
    Waits,
}

/// Which roots the folders of a link proof name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Linked {
    Copy,
    Source,
    Neither,
    Both,
}

/// One read of a link proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LinkKey {
    /// The bin index.
    Bin,
    /// A node under the end of `scope`. In a binned subtree, `binned` is the
    /// root and the deletion time of its bin entry, whose held key seals it.
    Node {
        node: NodeId,
        scope: NodeId,
        binned: Option<(NodeId, u64)>,
    },
}

/// What one read gives the proof.
pub(super) struct LinkRead {
    mark: RecordMark,
    /// The children of a folder.
    children: Vec<NodeId>,
    /// Each bin entry: its node, its scope and its deletion time.
    entries: Vec<(NodeId, NodeId, u64)>,
    /// Set when the node is a scope root.
    anchor: Option<WalkAnchor>,
}

/// The link proof of one entry, carried across ticks.
pub(crate) struct LinkProof {
    /// The material of the write scope end that the walk started under.
    write: EndMark,
    sweep: TwoSweep<LinkKey>,
    anchors: BTreeMap<NodeId, WalkAnchor>,
    copy: bool,
    source: bool,
    /// The fence held before the walk started.
    fenced: bool,
}

impl LinkProof {
    fn new(write: &ScopeEnd<'_>, fenced: bool) -> Self {
        let first = LinkKey::Node {
            node: write.root,
            scope: write.root,
            binned: None,
        };
        let mut sweep = TwoSweep::new(first, write.root);
        // Read last in the first sweep, once each scope root gave its anchor.
        sweep.pending.insert(0, LinkKey::Bin);
        Self {
            write: EndMark::of(write),
            sweep,
            anchors: BTreeMap::new(),
            copy: false,
            source: false,
            fenced,
        }
    }

    fn linked(&self) -> Linked {
        match (self.copy, self.source) {
            (true, false) => Linked::Copy,
            (false, true) => Linked::Source,
            (false, false) => Linked::Neither,
            (true, true) => Linked::Both,
        }
    }
}

/// A link proof's policy for one tick.
struct LinkPolicy<'p> {
    anchors: &'p mut BTreeMap<NodeId, WalkAnchor>,
    copy: (NodeId, &'p mut bool),
    source: (NodeId, &'p mut bool),
    /// The scope roots that share the write scope seed, which the walk reads.
    walked: &'p BTreeSet<NodeId>,
    /// Every scope root of the owner. The walk stops at one it does not read.
    roots: &'p BTreeSet<NodeId>,
    left: &'p Cell<usize>,
}

impl LinkPolicy<'_> {
    fn note(&mut self, node: NodeId) {
        for (root, named) in [&mut self.copy, &mut self.source] {
            if *root == node {
                **named = true;
            }
        }
    }
}

impl SweepPolicy<LinkKey> for LinkPolicy<'_> {
    type Answer = LinkRead;

    fn take_read(&mut self, _: bool) -> bool {
        take_tick_read(self.left)
    }

    /// Note each child and bin entry that is the copy or the source root, and
    /// queue each one a walked scope holds. A node named twice stops the walk.
    fn visit(
        &mut self,
        sweep: &mut TwoSweep<LinkKey>,
        key: &LinkKey,
        read: LinkRead,
    ) -> Result<(), Overflow> {
        let mut next = Vec::new();
        match key {
            LinkKey::Bin => {
                for (node, scope, deleted_at) in read.entries {
                    self.note(node);
                    if self.walked.contains(&scope) {
                        next.push(LinkKey::Node {
                            node,
                            scope,
                            binned: Some((node, deleted_at)),
                        });
                    }
                }
            }
            LinkKey::Node {
                node,
                scope,
                binned,
            } => {
                if let Some(anchor) = read.anchor {
                    self.anchors.insert(*node, anchor);
                }
                for child in read.children {
                    self.note(child);
                    if !self.roots.contains(&child) {
                        next.push(LinkKey::Node {
                            node: child,
                            scope: *scope,
                            binned: *binned,
                        });
                    } else if self.walked.contains(&child) {
                        next.push(LinkKey::Node {
                            node: child,
                            scope: child,
                            binned: None,
                        });
                    }
                }
            }
        }
        for key in &next {
            if let LinkKey::Node { node, .. } = key
                && !sweep.seen.insert(*node)
            {
                return Err(Overflow);
            }
        }
        sweep.pending.extend(next);
        if sweep.seen.len() > MAX_DISSOLVE_WALK_NODES {
            return Err(Overflow);
        }
        Ok(())
    }
}

impl<T, H, C, F, S, St, Sch> Drain<'_, T, H, C, F, S, St, Sch>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    S: SnapshotCache,
    St: StagingStore,
    Sch: Scheduler + Clone + 'static,
{
    /// Decide the relink of `header` under `target`, after the fence when
    /// `fence`: the copy linked moves on to the index removal; the source root
    /// linked alone retires the copy after a fence; neither linked moves on
    /// and keeps every copy name; both linked, a fence that does not hold or a
    /// walk that does not complete parks the entry.
    #[expect(clippy::too_many_arguments, reason = "one proof of one entry")]
    pub(super) async fn prove(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        journal: &DissolveJournal<'_, St>,
        hold: &DissolveHold<'_>,
        header: &DissolveHeader,
        target: &Destination<'_, '_>,
        fence: bool,
        left: &Cell<usize>,
    ) -> Result<(), NotDriven> {
        let root = header.scopes[0].scope_id;
        let carried = self.cells.dissolve_proofs.borrow_mut().remove(&root);
        let mut proof = match carried
            .filter(|proof| proof.write == EndMark::of(target.write) && (proof.fenced || !fence))
        {
            Some(proof) => proof,
            None if !fence => LinkProof::new(target.write, false),
            None => match self.fence(owner, target.chain[0], header, left).await {
                Fence::Holds => LinkProof::new(target.write, true),
                Fence::Waits => return Ok(()),
                Fence::Fails => return self.park(journal, hold, header).await,
            },
        };
        let walked: BTreeSet<NodeId> = ends
            .iter()
            .filter(|end| ct_eq(end.write_scope_seed, target.write.write_scope_seed))
            .map(|end| end.root)
            .collect();
        let roots: BTreeSet<NodeId> = owner.scope_roots.iter().copied().collect();
        let LinkProof {
            sweep,
            anchors,
            copy,
            source,
            ..
        } = &mut proof;
        let mut policy = LinkPolicy {
            anchors,
            copy: (header.new_root, copy),
            source: (root, source),
            walked: &walked,
            roots: &roots,
            left,
        };
        let swept = sweep
            .step(
                &mut policy,
                async |policy: &LinkPolicy<'_>, key: &LinkKey| {
                    let anchor = match key {
                        LinkKey::Node { scope, .. } => {
                            policy.anchors.get(scope).map(WalkAnchor::anchor)
                        }
                        LinkKey::Bin => None,
                    };
                    let read = self.link_read(owner, ends, header, key, anchor).await?;
                    Ok((read.mark, read))
                },
            )
            .await;
        match swept {
            Swept::Complete => {}
            Swept::Moved => return Ok(()),
            Swept::Paused => {
                self.cells.dissolve_proofs.borrow_mut().insert(root, proof);
                return Ok(());
            }
            Swept::Fault(ReadFault::Unanswered)
                if !proof.sweep.unanswered_at(MAX_DISSOLVE_READ_ATTEMPTS) =>
            {
                self.cells.dissolve_proofs.borrow_mut().insert(root, proof);
                return Ok(());
            }
            Swept::Fault(_) | Swept::Stopped(_) => return self.park(journal, hold, header).await,
        }
        match proof.linked() {
            Linked::Both => self.park(journal, hold, header).await,
            // The parent named the copy when the walk started, so the next
            // tick reads it again.
            Linked::Source if !proof.fenced => Ok(()),
            Linked::Source => self.forsake(journal, hold, header).await,
            linked => {
                let mut next = header.clone();
                next.parked = false;
                // The copy may still be live where the walk does not read.
                next.keep_names = linked == Linked::Neither;
                next.step = DissolveStep::Unindex;
                Ok(journal.commit(hold, Some(header), &next).await?)
            }
        }
    }

    /// Whether each parent name that a relink of `header` published at serves
    /// a record above every mark there, with no same-sequence tie. A name
    /// that holds no mark had no relink signed at it. Each fetch is one read
    /// of `left`.
    ///
    /// A signed record above every mark proves that no late PUT of the relink
    /// can win, so a signature-verified read suffices; the retire verdict
    /// comes only from the gated walk.
    async fn fence(
        &self,
        owner: &DrainScope<'_>,
        dest: &ScopeEnd<'_>,
        header: &DissolveHeader,
        left: &Cell<usize>,
    ) -> Fence {
        let Some(share) = ReadShare::take(left, header.relink_names.len()) else {
            return Fence::Waits;
        };
        let floors = dest.floors(&self.seams.floors);
        let ledger = self.retire_ledger(owner);
        let tag = owner_tag(owner.enc_secret);
        for name in &header.relink_names {
            let Ok(parsed) = core::str::from_utf8(name).map(IpnsName::parse) else {
                return Fence::Fails;
            };
            let Ok(parsed) = parsed else {
                return Fence::Fails;
            };
            let mut bar = None;
            for key in relink_mark_keys(header.scopes[0].scope_id, name) {
                match floor::sequence_floor(&floors, &key).await {
                    Ok(mark) => bar = bar.max(mark),
                    Err(_) => return Fence::Fails,
                }
            }
            let Ok(unacked) = ledger
                .unacknowledged(&tag, header.relink_parent.0, parsed.as_str())
                .await
            else {
                return Fence::Fails;
            };
            let marks = HeldMarks {
                acked: bar.map_or(Acknowledged::Nothing, Acknowledged::At),
                unacked,
            };
            if marks == HeldMarks::default() {
                continue;
            }
            if !take_tick_read(&share.left) {
                return Fence::Waits;
            }
            match LeafRead::fetch(&self.seams.transport, &parsed).await {
                Ok(read) if read.tied.is_empty() && !marks.hold(read.pick.sequence) => {}
                _ => return Fence::Fails,
            }
        }
        Fence::Holds
    }

    /// One read of a link proof: the bin index, a scope root through its own
    /// gate, a node through the child gate, or a binned node under the held
    /// key of its bin entry.
    async fn link_read(
        &self,
        owner: &DrainScope<'_>,
        ends: &[ScopeEnd<'_>],
        header: &DissolveHeader,
        key: &LinkKey,
        anchor: Option<Anchor<'_>>,
    ) -> Result<LinkRead, ReadFault<()>> {
        let hash = cipherbox_core::suite::hash::hash;
        let (node, scope, binned) = match key {
            LinkKey::Bin => {
                let index = self
                    .writable_bin_index()
                    .await
                    .map_err(|_| ReadFault::Unanswered)?;
                let mut digest = Vec::new();
                let mut entries = Vec::with_capacity(index.entries.len());
                for entry in &index.entries {
                    digest.extend_from_slice(&entry.node_id);
                    digest.extend_from_slice(&entry.scope_id);
                    digest.extend_from_slice(&entry.deleted_at.to_be_bytes());
                    entries.push((
                        NodeId(entry.node_id),
                        NodeId(entry.scope_id),
                        entry.deleted_at,
                    ));
                }
                return Ok(LinkRead {
                    mark: RecordMark {
                        sequence: index.revision,
                        digest: hash(&digest),
                    },
                    children: Vec::new(),
                    entries,
                    anchor: None,
                });
            }
            LinkKey::Node {
                node,
                scope,
                binned,
            } => (*node, *scope, *binned),
        };
        let end = ends
            .iter()
            .find(|end| end.root == scope)
            .ok_or(ReadFault::Unanswered)?;
        if node == end.root {
            let (root, _) = self.dissolve_root(owner, end).await?;
            return Ok(LinkRead {
                mark: RecordMark {
                    sequence: root.state.observed.sequence(),
                    digest: hash(&root.state.record),
                },
                children: root.state.children.iter().map(|c| NodeId(c.id)).collect(),
                entries: Vec::new(),
                anchor: Some(WalkAnchor {
                    epoch: root.epoch,
                    history_links: root.history_links,
                }),
            });
        }
        let anchor = anchor.ok_or(ReadFault::Unanswered)?;
        let loaded = match binned {
            None => self
                .gated_child(owner, ends, header, end, anchor, node)
                .await
                .map_err(|fault| match fault {
                    ReadFault::Unanswered => ReadFault::Unanswered,
                    ReadFault::Untrusted | ReadFault::Fatal(_) => ReadFault::Untrusted,
                })?,
            Some((bin_root, deleted_at)) => {
                let held = self.inputs.bin_keys.held_key(&bin_root.0, deleted_at);
                let plane = end.at(anchor.epoch);
                let sealed = plane.held_plane(&held);
                let name = sealed.end.write_name(&node.0);
                let loaded = self
                    .load_child_node_unreported(&sealed, anchor, node, ResolveMode::NoCache)
                    .await
                    .map_err(|fault| match fault {
                        ChildFault::Halt(_) => ReadFault::Unanswered,
                        ChildFault::Refused(rejection) => {
                            refuse_record(&self.seams.events, &name, &rejection);
                            ReadFault::Untrusted
                        }
                    })?;
                if loaded.tied {
                    return Err(self.fork_at(&name, loaded.observed.sequence()));
                }
                loaded
            }
        };
        Ok(LinkRead {
            mark: RecordMark {
                sequence: loaded.observed.sequence(),
                digest: hash(&loaded.record),
            },
            children: match loaded.body {
                ReadBody::Folder { children, .. } => {
                    children.iter().map(|child| NodeId(child.id)).collect()
                }
                ReadBody::File { .. } => Vec::new(),
            },
            entries: Vec::new(),
            anchor: None,
        })
    }
}
