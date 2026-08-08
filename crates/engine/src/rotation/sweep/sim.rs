//! The sweep's deterministic simulation network: the fake the pure pass is
//! exercised against, and the scenarios the production seams are held to as
//! well (`net/rotation.rs`), so a fake that drifts from its production
//! counterpart fails a CI gate rather than being found by reading.

use super::{
    LaggingNode, NodeRef, SweepPublisher, SweepResolveFailure, SweepResolver, SweptChild,
    SweptNode, SweptScope,
};
use crate::rotation::ScopeRootPublishError;
use cipherbox_core::seal::{ChildRef, ChildScopeRef, NodeKind, PreservedFields, ReadBody};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) fn id(byte: u8) -> [u8; 16] {
    [byte; 16]
}

pub(crate) fn name(byte: u8) -> Vec<u8> {
    format!("ipns-{byte:02x}").into_bytes()
}

pub(crate) fn node_ref(byte: u8) -> NodeRef {
    NodeRef {
        node_id: id(byte),
        ipns_name: name(byte),
    }
}

pub(crate) fn scope_ref(byte: u8) -> ChildScopeRef {
    ChildScopeRef::new(id(byte), name(byte))
}

/// A folder body naming `children`, at each byte's own simulated name unless
/// `overrides` gives this parent a different one for it — the C2 conflict,
/// where two parents disagree on one node's name.
pub(crate) fn folder_named(
    parent: u8,
    children: &[u8],
    overrides: &HashMap<(u8, u8), Vec<u8>>,
) -> ReadBody {
    ReadBody::Folder {
        created_at: 1,
        modified_at: 2,
        children: children
            .iter()
            .map(|b| ChildRef {
                id: id(*b),
                name: format!("n{b:02x}"),
                ipns_name: overrides
                    .get(&(parent, *b))
                    .cloned()
                    .unwrap_or_else(|| name(*b)),
                kind: NodeKind::Folder,
                link_counter: 1,
                unknown: PreservedFields::new(),
            })
            .collect(),
        unknown: PreservedFields::new(),
    }
}

/// One interior node on the fake network.
pub(crate) struct FakeNode {
    epoch: u64,
    children: Vec<u8>,
    /// The node's record is a scope root: the walk must stop at it.
    is_scope_root: bool,
    publishes: u32,
    /// A persistent publish fault.
    fault: Option<ScopeRootPublishError>,
    /// The next `n` publishes lose the CAS **without** advancing the epoch —
    /// a non-advancing ordinary writer winning the race.
    lost_race_next: u32,
}

impl FakeNode {
    pub(crate) fn new(epoch: u64, children: &[u8]) -> Self {
        Self {
            epoch,
            children: children.to_vec(),
            is_scope_root: false,
            publishes: 0,
            fault: None,
            lost_race_next: 0,
        }
    }
}

#[derive(Default)]
pub(crate) struct NetState {
    /// The scope root's own published epoch.
    pub(crate) scope_epoch: u64,
    /// The scope root's read-body children.
    pub(crate) root_children: Vec<u8>,
    /// The committed direct-child-scope index.
    pub(crate) index: Vec<u8>,
    pub(crate) nodes: HashMap<[u8; 16], FakeNode>,
    /// Names whose scope-root record sits below the scope's floor.
    pub(crate) superseded: Vec<Vec<u8>>,
    /// Names whose record the adoption gate refuses outright.
    pub(crate) forged: Vec<Vec<u8>>,
    /// Per-node resolve faults.
    pub(crate) node_faults: HashMap<[u8; 16], SweepResolveFailure>,
    /// The scope pointer's `currentRootName`, if the scope was re-pointed.
    pub(crate) pointer: Option<Vec<u8>>,
    /// The published index, once a repair lands.
    pub(crate) repaired_index: Option<Vec<ChildScopeRef>>,
    pub(crate) index_repair_fault: Option<ScopeRootPublishError>,
    /// `(parent, child)` pairs the parent names at a caller-chosen `ipnsName`.
    pub(crate) child_names: HashMap<(u8, u8), Vec<u8>>,
}

/// The sweep's fake network: one scope, its interior nodes, and its pointer.
/// A publish advances the node's epoch so a re-resolve converges.
#[derive(Clone, Default)]
pub(crate) struct FakeNet {
    pub(crate) state: Rc<RefCell<NetState>>,
    pub(crate) consults: Rc<Cell<u32>>,
    pub(crate) index_repairs: Rc<Cell<u32>>,
}

impl FakeNet {
    pub(crate) fn new(scope_epoch: u64, root_children: &[u8]) -> Self {
        let net = Self::default();
        {
            let mut state = net.state.borrow_mut();
            state.scope_epoch = scope_epoch;
            state.root_children = root_children.to_vec();
        }
        net
    }

    pub(crate) fn node(self, byte: u8, epoch: u64, children: &[u8]) -> Self {
        self.state
            .borrow_mut()
            .nodes
            .insert(id(byte), FakeNode::new(epoch, children));
        self
    }

    /// A descendant scope root: the walk stops at it, so it never publishes a
    /// body and never yields children. `indexed` lists it in the scope's
    /// `directChildScopeIndex`; omitting it is the #38 D6 gap.
    pub(crate) fn scope_root(self, byte: u8, indexed: bool) -> Self {
        {
            let mut state = self.state.borrow_mut();
            let mut node = FakeNode::new(0, &[]);
            node.is_scope_root = true;
            state.nodes.insert(id(byte), node);
            if indexed {
                state.index.push(byte);
            }
        }
        self
    }

    pub(crate) fn with<Fun: FnOnce(&mut FakeNode)>(self, byte: u8, edit: Fun) -> Self {
        edit(
            self.state
                .borrow_mut()
                .nodes
                .get_mut(&id(byte))
                .expect("node"),
        );
        self
    }

    pub(crate) fn fault(self, byte: u8, fault: ScopeRootPublishError) -> Self {
        self.with(byte, |node| node.fault = Some(fault))
    }

    pub(crate) fn lost_race_next(self, byte: u8, n: u32) -> Self {
        self.with(byte, |node| node.lost_race_next = n)
    }

    pub(crate) fn node_fault(self, byte: u8, reason: SweepResolveFailure) -> Self {
        self.state.borrow_mut().node_faults.insert(id(byte), reason);
        self
    }

    pub(crate) fn superseded(self, byte: u8) -> Self {
        self.state.borrow_mut().superseded.push(name(byte));
        self
    }

    pub(crate) fn forged(self, byte: u8) -> Self {
        self.state.borrow_mut().forged.push(name(byte));
        self
    }

    pub(crate) fn pointer_to(self, byte: u8) -> Self {
        self.state.borrow_mut().pointer = Some(name(byte));
        self
    }

    /// `parent` names `child` at a name of its own, so a second parent naming
    /// the same child differently is the C2 conflict.
    pub(crate) fn names_child(self, parent: u8, child: u8, ipns_name: &str) -> Self {
        self.state
            .borrow_mut()
            .child_names
            .insert((parent, child), ipns_name.as_bytes().to_vec());
        self
    }

    /// Seed a **non-canonical** stored index: `byte` listed twice — the crash
    /// residue #38 D6's repair also covers.
    pub(crate) fn duplicate_index_entry(self, byte: u8) -> Self {
        self.state.borrow_mut().index.push(byte);
        self
    }

    pub(crate) fn clear_fault(&self, byte: u8) {
        self.state
            .borrow_mut()
            .nodes
            .get_mut(&id(byte))
            .expect("node")
            .fault = None;
    }

    pub(crate) fn epoch(&self, byte: u8) -> u64 {
        self.state
            .borrow()
            .nodes
            .get(&id(byte))
            .expect("node")
            .epoch
    }

    pub(crate) fn publishes(&self, byte: u8) -> u32 {
        self.state
            .borrow()
            .nodes
            .get(&id(byte))
            .expect("node")
            .publishes
    }
}

impl SweepResolver for FakeNet {
    async fn resolve_scope(
        &self,
        scope: &ChildScopeRef,
    ) -> Result<SweptScope, SweepResolveFailure> {
        let state = self.state.borrow();
        if state.forged.contains(&scope.ipns_name) {
            return Err(SweepResolveFailure::Rejected);
        }
        if state.superseded.contains(&scope.ipns_name) {
            return Err(SweepResolveFailure::Superseded);
        }
        let index = state
            .repaired_index
            .clone()
            .unwrap_or_else(|| state.index.iter().map(|b| scope_ref(*b)).collect());
        Ok(SweptScope {
            current_read_epoch: state.scope_epoch,
            children: state
                .root_children
                .iter()
                .map(|b| NodeRef {
                    node_id: id(*b),
                    ipns_name: state
                        .child_names
                        .get(&(0x00, *b))
                        .cloned()
                        .unwrap_or_else(|| name(*b)),
                })
                .collect(),
            direct_child_scope_index: index,
        })
    }

    async fn consult_pointer(
        &self,
        _scope_id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, SweepResolveFailure> {
        self.consults.set(self.consults.get() + 1);
        Ok(self.state.borrow().pointer.clone())
    }

    async fn resolve_child(
        &self,
        _scope: &ChildScopeRef,
        child: &NodeRef,
    ) -> Result<SweptChild, SweepResolveFailure> {
        let state = self.state.borrow();
        if let Some(reason) = state.node_faults.get(&child.node_id) {
            return Err(*reason);
        }
        if state.forged.contains(&child.ipns_name) {
            return Err(SweepResolveFailure::Rejected);
        }
        if state.superseded.contains(&child.ipns_name) {
            return Err(SweepResolveFailure::Superseded);
        }
        let node = state
            .nodes
            .get(&child.node_id)
            .ok_or(SweepResolveFailure::Unavailable)?;
        if node.is_scope_root {
            return Ok(SweptChild::ScopeRoot(ChildScopeRef::new(
                child.node_id,
                child.ipns_name.clone(),
            )));
        }
        Ok(SweptChild::Interior(SweptNode {
            current_read_epoch: node.epoch,
            sequence: 1,
            read_body: folder_named(child.node_id[0], &node.children, &state.child_names),
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        }))
    }
}

impl SweepPublisher for FakeNet {
    async fn publish_node(
        &self,
        _scope: &ChildScopeRef,
        node: &LaggingNode<'_>,
    ) -> Result<(), ScopeRootPublishError> {
        let mut state = self.state.borrow_mut();
        let entry = state.nodes.get_mut(&node.node_id).expect("node");
        entry.publishes += 1;
        if entry.lost_race_next > 0 {
            entry.lost_race_next -= 1;
            return Err(ScopeRootPublishError::LostRace);
        }
        match &entry.fault {
            None => {
                entry.epoch = entry.epoch.max(node.read_epoch);
                Ok(())
            }
            // A concurrent *sweeper* winner: its record is at our epoch, so
            // the node re-resolves converged on the next pass.
            Some(ScopeRootPublishError::LostRace) => {
                entry.epoch = entry.epoch.max(node.read_epoch);
                Err(ScopeRootPublishError::LostRace)
            }
            Some(error) => Err(error.clone()),
        }
    }

    async fn repair_child_scope_index(
        &self,
        _scope: &ChildScopeRef,
        index: &[ChildScopeRef],
    ) -> Result<(), ScopeRootPublishError> {
        self.index_repairs.set(self.index_repairs.get() + 1);
        let mut state = self.state.borrow_mut();
        if let Some(error) = state.index_repair_fault.clone() {
            return Err(error);
        }
        state.repaired_index = Some(index.to_vec());
        Ok(())
    }
}

/// One sweep scenario, described once and run twice: over [`FakeNet`] and over
/// the production seams. Bytes name both a node id (`[byte; 16]`) and its
/// simulated name, so the two runs' [`SweepOutcome`](super::SweepOutcome)s are
/// directly comparable.
pub(crate) struct Scenario {
    /// A stable name for assertion messages.
    pub(crate) label: &'static str,
    /// The scope root's published read epoch.
    pub(crate) scope_epoch: u64,
    /// The scope root's read-body children, in body order.
    pub(crate) children: &'static [u8],
    /// Interior nodes: `(byte, published read epoch, the children its read body
    /// names)`. A child named here is reached one level deeper than the scope
    /// root's own body, so the scenario drives the frontier expansion.
    pub(crate) nodes: &'static [(u8, u64, &'static [u8])],
    /// Descendant scope roots: `(byte, named in the direct-child-scope index)`.
    pub(crate) scope_roots: &'static [(u8, bool)],
}

impl Scenario {
    /// The simulation network this scenario describes.
    pub(crate) fn fake(&self) -> FakeNet {
        let mut net = FakeNet::new(self.scope_epoch, self.children);
        for (byte, epoch, children) in self.nodes {
            net = net.node(*byte, *epoch, children);
        }
        for (byte, indexed) in self.scope_roots {
            net = net.scope_root(*byte, *indexed);
        }
        net
    }
}

/// The scenarios both the fake and the production seams must agree on.
pub(crate) const SCENARIOS: &[Scenario] = &[
    Scenario {
        label: "a lagging interior node converges",
        scope_epoch: 2,
        children: &[0x01],
        nodes: &[(0x01, 1, &[])],
        scope_roots: &[],
    },
    Scenario {
        label: "a node already at the scope epoch is a no-op",
        scope_epoch: 2,
        children: &[0x01],
        nodes: &[(0x01, 2, &[])],
        scope_roots: &[],
    },
    Scenario {
        label: "the walk stops at an indexed scope root",
        scope_epoch: 2,
        children: &[0x01, 0x0a],
        nodes: &[(0x01, 1, &[])],
        scope_roots: &[(0x0a, true)],
    },
    Scenario {
        label: "an unindexed scope root is repaired and flagged",
        scope_epoch: 2,
        children: &[0x0a],
        nodes: &[],
        scope_roots: &[(0x0a, false)],
    },
    Scenario {
        label: "a nested subtree converges at every level",
        scope_epoch: 2,
        children: &[0x01],
        nodes: &[(0x01, 1, &[0x02]), (0x02, 1, &[0x03]), (0x03, 1, &[])],
        scope_roots: &[],
    },
    Scenario {
        label: "two parents naming one child sweep it once",
        scope_epoch: 2,
        children: &[0x01, 0x02],
        nodes: &[(0x01, 1, &[0x03]), (0x02, 1, &[0x03]), (0x03, 1, &[])],
        scope_roots: &[],
    },
    Scenario {
        label: "a mixed-epoch level walks past its converged nodes",
        scope_epoch: 2,
        children: &[0x02, 0x01],
        nodes: &[
            (0x01, 2, &[0x03]),
            (0x02, 1, &[0x04]),
            (0x03, 1, &[]),
            (0x04, 2, &[]),
        ],
        scope_roots: &[],
    },
    Scenario {
        label: "the walk stops at a scope root nested below the root",
        scope_epoch: 2,
        children: &[0x01],
        nodes: &[(0x01, 1, &[0x0a])],
        scope_roots: &[(0x0a, false)],
    },
];
