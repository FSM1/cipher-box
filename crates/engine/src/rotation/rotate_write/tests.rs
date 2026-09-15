use super::*;
use crate::testkit::{SeededEntropy, SilentEntropy, block_on};
use cipherbox_core::seal::{PreservedFields, sign_grant_set};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

const SCOPE: [u8; 16] = [0x5c; 16];
/// The write epoch every test's [`plan`] publishes at (`current_write_epoch + 1`).
const ROTATED_WRITE_EPOCH: u64 = 5;
const OLD_WRITE_SCOPE_SEED: [u8; 32] = [0x0d; 32];
const OWNER_POINTER_SEED: [u8; 32] = [0x0e; 32];

fn nid(byte: u8) -> [u8; 16] {
    [byte; 16]
}

/// A wave order names every node it moves, so one `{:?}` would render the
/// whole pre-wave to post-wave mapping. The names carry their own rendering
/// policy, so neither struct states one.
#[test]
fn a_wave_order_and_a_resumed_root_withhold_every_name_they_carry() {
    let fresh_seed = [0x0f; 32];
    let current = derive_write_name(&OLD_WRITE_SCOPE_SEED, &nid(1));
    let new = derive_write_name(&fresh_seed, &nid(1));
    let child = derive_write_name(&fresh_seed, &nid(2));
    let order = RepublishedNode {
        node_id: nid(1),
        current_name: current.clone(),
        new_name: new.clone(),
        child_names: BTreeMap::from([(nid(2), child.clone())]),
        signer: kdf::ipns_keypair(&[7u8; 32]),
        write_scope_seed: None,
        write_epoch: ROTATED_WRITE_EPOCH,
        is_root: false,
    };
    let resumed = ResumedRoot {
        name: new.clone(),
        write_epoch: ROTATED_WRITE_EPOCH,
    };

    let rendered = format!("{order:?}{resumed:?}");
    for name in [&current, &new, &child] {
        assert!(
            !rendered.contains(name.as_str()),
            "a wave order renders no name: {rendered}"
        );
    }
}

/// The owner's identity scalar, which in a live session IS the login secret
/// (`SessionIdentity::derive` adopts it directly).
const OWNER_SCALAR: [u8; 32] = [0x33; 32];

fn owner() -> EcdsaSigner {
    EcdsaSigner::from_scalar(&OWNER_SCALAR).unwrap()
}

/// An owner-signed commitment naming `name` as the scope root. The signature
/// binds `name` only; callers pass a mismatched name to exercise the reject path.
fn commitment_for(
    owner: &EcdsaSigner,
    name: &IpnsName,
) -> (GrantSetCommitment, [u8; ECDSA_SIG_LEN]) {
    let c = GrantSetCommitment {
        ipns_name: name.as_str().as_bytes().to_vec(),
        owner_pseudonym_pk: [0x22; 32],
        cut_epoch: 0,
        entries: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let sig = sign_grant_set(owner, &c).unwrap().to_compact();
    (c, sig)
}

/// The default commitment: bound to the scope root every test rotates
/// (`old_name_of(SCOPE)`, each test's `current_root`).
fn commitment(owner: &EcdsaSigner) -> (GrantSetCommitment, [u8; ECDSA_SIG_LEN]) {
    commitment_for(owner, &old_name_of(&SCOPE))
}

/// A node's old (pre-rotation) name — derived from the OLD write scope seed, so
/// the wave's freshly derived names provably differ.
fn old_name_of(node_id: &[u8; 16]) -> IpnsName {
    derive_write_name(&OLD_WRITE_SCOPE_SEED, node_id)
}

/// The moved root as published state holds it: where it landed, the seed its
/// grant section publishes, and the write epoch it published at.
type PublishedRoot = (IpnsName, [u8; SECRET_LEN], u64);

/// One recorded wave effect, in call order — the tape the ordering invariants
/// are asserted over.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Republish { node_id: [u8; 16], is_root: bool },
    Retire(Vec<String>),
    Repoint(RepointChannel),
}

/// The recovery a resolver reads back out of published state: the moved root
/// the publisher landed, and the write scope seed its grant section carries.
/// Nothing else crosses a crash, so a resume that works here works off
/// published records alone.
fn resumed((name, seed, write_epoch): &PublishedRoot) -> ResumedWriteWave {
    ResumedWriteWave {
        write_scope_seed: SecretBytes::new(*seed),
        root_name: name.clone(),
        write_epoch: *write_epoch,
    }
}

/// A fake subtree resolver over a fixed `node_id -> children` map.
///
/// Handed a [`ResumedRoot`] it serves every node at its post-rotation name, as
/// a walk down the flipped pointer reads them; otherwise the pre-wave names.
struct FakeResolver {
    nodes: HashMap<[u8; 16], Vec<[u8; 16]>>,
    state: WaveState,
    /// Overrides the published-state recovery, so a test can hand back a pair
    /// whose seed and root name disagree.
    recovery: Option<PublishedRoot>,
    /// A read rotation has raised the read-epoch floor past the pre-wave
    /// records, so the adoption gate refuses them — only the swept moved
    /// copies a resumed pass reads still resolve.
    below_floor: Cell<bool>,
    /// The write scope seed an owner-sealed history link yields: the
    /// pre-wave one on a resume, the epoch below the live root on a fresh
    /// start. `None` models a link the wave cannot open.
    superseded_seed: Option<[u8; SECRET_LEN]>,
}

impl FakeResolver {
    fn recovered(&self) -> Option<PublishedRoot> {
        self.recovery
            .clone()
            .or_else(|| self.state.published_root.borrow().clone())
    }

    /// The seed the moved root `resumed` names publishes — what names every
    /// node below it once a resume anchors the pass there.
    fn resumed_seed(&self, resumed: Option<&ResumedRoot>) -> Option<[u8; SECRET_LEN]> {
        let resumed = resumed?;
        let (name, seed, _) = self.recovered()?;
        (name == resumed.name).then_some(seed)
    }
}

impl WriteSubtreeResolver for FakeResolver {
    async fn resolve_node(
        &self,
        node_id: &[u8; 16],
        resumed: Option<&ResumedRoot>,
    ) -> Result<WriteScopeNode, ResolveFailure> {
        let children = self
            .nodes
            .get(node_id)
            .ok_or(ResolveFailure::Unavailable)?
            .clone();
        let current_name = match self.resumed_seed(resumed) {
            Some(seed) => derive_write_name(&seed, node_id),
            None if self.below_floor.get() => return Err(ResolveFailure::Rejected),
            None => old_name_of(node_id),
        };
        Ok(WriteScopeNode {
            node_id: *node_id,
            current_name,
            child_node_ids: children,
        })
    }

    async fn recover_wave(&self) -> Result<RecoveredWave, ResolveFailure> {
        Ok(RecoveredWave {
            in_flight: self.recovered().as_ref().map(resumed),
            superseded_write_scope_seed: self.superseded_seed.map(SecretBytes::new),
        })
    }
}

/// A resolver that fails on one node id — drives the resolve-abort path.
struct FailingResolver {
    inner: FakeResolver,
    fail_on: [u8; 16],
}

impl WriteSubtreeResolver for FailingResolver {
    async fn resolve_node(
        &self,
        node_id: &[u8; 16],
        resumed: Option<&ResumedRoot>,
    ) -> Result<WriteScopeNode, ResolveFailure> {
        if *node_id == self.fail_on {
            return Err(ResolveFailure::Rejected);
        }
        self.inner.resolve_node(node_id, resumed).await
    }

    async fn recover_wave(&self) -> Result<RecoveredWave, ResolveFailure> {
        self.inner.recover_wave().await
    }
}

/// Shared, "durable" published state plus the effect tape. Cloning the handle
/// models reopening the same backing across a crash (a fresh orchestrator, the
/// same published records).
#[derive(Clone, Default)]
struct WaveState {
    published: Rc<RefCell<HashSet<String>>>,
    /// The moved root as published state holds it: the name it landed at and
    /// the write scope seed its grant section publishes. The one thing a
    /// resumed wave reads back — the recovery seam's whole source.
    published_root: Rc<RefCell<Option<PublishedRoot>>>,
    retired: Rc<RefCell<HashSet<String>>>,
    events: Rc<RefCell<Vec<Event>>>,
    republish_calls: Rc<RefCell<HashMap<String, usize>>>,
    repoint_channels: Rc<RefCell<Vec<RepointChannel>>>,
    /// Every order the wave issued, in call order — the rewrite material the
    /// concrete publisher acts on.
    orders: Rc<RefCell<Vec<RepublishedNode>>>,
}

/// A fake publisher over shared [`WaveState`], optionally scripted to fail once
/// a given number of republish calls have landed (to crash a wave mid-flight),
/// or to refuse a given re-point channel.
struct FakePublisher {
    state: WaveState,
    fail_republish_after: Option<usize>,
    refuse_channel: Option<RepointChannel>,
    refuse_repoint_check: bool,
    refuse_retire: bool,
}

impl FakePublisher {
    fn new(state: WaveState) -> Self {
        Self {
            state,
            fail_republish_after: None,
            refuse_channel: None,
            refuse_repoint_check: false,
            refuse_retire: false,
        }
    }
    fn failing_after(state: WaveState, n: usize) -> Self {
        Self {
            fail_republish_after: Some(n),
            ..Self::new(state)
        }
    }
    fn refusing(state: WaveState, channel: RepointChannel) -> Self {
        Self {
            refuse_channel: Some(channel),
            ..Self::new(state)
        }
    }
    /// The floor-blind analogue: a publisher whose pre-sign re-point gate
    /// refuses, as `WriteWaveNet`'s does on a read-epoch floor rise.
    fn refusing_repoint_check(state: WaveState) -> Self {
        Self {
            refuse_repoint_check: true,
            ..Self::new(state)
        }
    }
    /// A publisher whose retire refuses, as `WriteWaveNet`'s does when the
    /// read-epoch floor rose past the epoch its enumeration gated.
    fn refusing_retire(state: WaveState) -> Self {
        Self {
            refuse_retire: true,
            ..Self::new(state)
        }
    }
}

impl WriteWavePublisher for FakePublisher {
    async fn is_republished(&self, new_name: &IpnsName) -> Result<bool, WritePublishError> {
        Ok(self.state.published.borrow().contains(new_name.as_str()))
    }

    async fn republish(&self, node: &RepublishedNode) -> Result<(), WritePublishError> {
        let key = node.new_name.as_str().to_owned();
        {
            let calls = self.state.republish_calls.borrow();
            let landed: usize = calls.values().sum();
            if let Some(limit) = self.fail_republish_after {
                if landed >= limit {
                    return Err(WritePublishError::NotLanded);
                }
            }
        }
        *self
            .state
            .republish_calls
            .borrow_mut()
            .entry(key.clone())
            .or_insert(0) += 1;
        self.state.published.borrow_mut().insert(key);
        if let Some(seed) = node
            .is_root
            .then_some(node.write_scope_seed.as_ref())
            .flatten()
        {
            *self.state.published_root.borrow_mut() =
                Some((node.new_name.clone(), *seed.as_bytes(), node.write_epoch));
        }
        self.state.orders.borrow_mut().push(node.clone());
        self.state.events.borrow_mut().push(Event::Republish {
            node_id: node.node_id,
            is_root: node.is_root,
        });
        Ok(())
    }

    async fn retire(&self, old_names: &[IpnsName]) -> Result<(), WritePublishError> {
        if self.refuse_retire {
            return Err(WritePublishError::Rejected);
        }
        let names: Vec<String> = old_names.iter().map(|n| n.as_str().to_owned()).collect();
        for n in &names {
            self.state.retired.borrow_mut().insert(n.clone());
        }
        self.state.events.borrow_mut().push(Event::Retire(names));
        Ok(())
    }

    async fn check_repoint_publishable(
        &self,
        _repoint: &RepointObject,
    ) -> Result<(), WritePublishError> {
        if self.refuse_repoint_check {
            return Err(WritePublishError::Rejected);
        }
        Ok(())
    }

    async fn publish_repoint(
        &self,
        channel: RepointChannel,
        _block: &[u8],
    ) -> Result<(), WritePublishError> {
        if self.refuse_channel == Some(channel) {
            return Err(WritePublishError::NotLanded);
        }
        self.state.repoint_channels.borrow_mut().push(channel);
        self.state.events.borrow_mut().push(Event::Repoint(channel));
        Ok(())
    }
}

/// A three-level tree: root(0x5c) → {0x02, 0x03}; 0x02 → {0x04, 0x05}.
fn tree() -> FakeResolver {
    tree_on(WaveState::default())
}

/// The same tree, reading its recovery out of `state` — the shared published
/// backing a resumed wave picks up from.
fn tree_on(state: WaveState) -> FakeResolver {
    let mut nodes = HashMap::new();
    nodes.insert(SCOPE, vec![nid(0x02), nid(0x03)]);
    nodes.insert(nid(0x02), vec![nid(0x04), nid(0x05)]);
    nodes.insert(nid(0x03), Vec::new());
    nodes.insert(nid(0x04), Vec::new());
    nodes.insert(nid(0x05), Vec::new());
    FakeResolver {
        nodes,
        state,
        recovery: None,
        below_floor: Cell::new(false),
        superseded_seed: Some(OLD_WRITE_SCOPE_SEED),
    }
}

fn plan<'a>(
    owner: &'a EcdsaSigner,
    commitment: &'a GrantSetCommitment,
    sig: &'a [u8; ECDSA_SIG_LEN],
    current_root: &'a IpnsName,
) -> RotateScopeWritePlan<'a> {
    RotateScopeWritePlan {
        scope_id: SCOPE,
        payload_version: 2,
        owner_pointer_seed: &OWNER_POINTER_SEED,
        commitment,
        commitment_sig: sig,
        owner_identity_signer: owner,
        current_write_epoch: 4,
        min_read_epoch: 7,
        current_root_name: current_root,
        is_vault_anchor: true,
    }
}

#[test]
fn a_silent_entropy_seam_moves_no_name() {
    // An all-zero `writeScopeSeed` makes every per-name `ipnsKeypair` in the
    // scope derivable, so anyone could sign records at the names this wave
    // would move to. Refused release-active, before the first republish.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    let error = block_on(rotate_scope_write(
        &mut SilentEntropy,
        &resolver,
        &publisher,
        &plan(&owner, &c, &sig, &current_root),
    ))
    .expect_err("the zero draw is refused");

    assert!(matches!(error, WriteRotateError::Entropy(_)));
    assert!(
        error.is_retryable(),
        "an entropy failure is availability, not a verdict",
    );
    assert!(
        state.events.borrow().is_empty(),
        "no name moves under a derivable write scope seed",
    );
}

#[test]
fn a_refused_repoint_check_signs_and_publishes_nothing() {
    // The gate runs before `seal_repoint`, so a re-point this build's own
    // cold-seed gate would reject is never owner-signed — and the wave stops
    // short of the retire, leaving every old name live. One gate covers both
    // channels: they publish the one block it cleared.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::refusing_repoint_check(state.clone());
    let current_root = old_name_of(&SCOPE);

    let error = block_on(async {
        let mut e = SeededEntropy::new(1);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the re-point is refused");

    assert!(matches!(
        error,
        WriteRotateError::Publish {
            error: WritePublishError::Rejected,
            ..
        },
    ));
    assert!(
        !error.is_retryable(),
        "the publisher's own fail-closed verdict is never laundered into a stall",
    );
    let events = state.events.borrow();
    assert!(
        !events
            .iter()
            .any(|ev| matches!(ev, Event::Repoint(_) | Event::Retire(_))),
        "neither plane is re-pointed and nothing is tombstoned",
    );
}

#[test]
fn happy_path_child_first_root_last_repoint_then_retire() {
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    let outcome = block_on(async {
        let mut e = SeededEntropy::new(1);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("rotation succeeds");

    assert_eq!(outcome.new_write_epoch, 5, "write epoch bumped 4 -> 5");
    assert_eq!(outcome.interior_node_count, 4, "four interior nodes");

    let events = state.events.borrow();

    // The root republish is the LAST republish, and every republish precedes it.
    let republish_positions: Vec<(usize, bool)> = events
        .iter()
        .enumerate()
        .filter_map(|(i, ev)| match ev {
            Event::Republish { is_root, .. } => Some((i, *is_root)),
            _ => None,
        })
        .collect();
    assert_eq!(republish_positions.len(), 5, "root + four interior");
    let root_pos = republish_positions.last().unwrap();
    assert!(
        root_pos.1,
        "the LAST republish is the root (root re-pointed last)"
    );
    assert!(
        republish_positions[..4].iter().all(|(_, is_root)| !is_root),
        "every non-final republish is an interior node (child-first)"
    );

    // Child-first: a child publishes before its parent. 0x04/0x05 before 0x02.
    let order_of = |target: [u8; 16]| {
        events
            .iter()
            .position(|ev| matches!(ev, Event::Republish { node_id, .. } if *node_id == target))
            .unwrap()
    };
    assert!(
        order_of(nid(0x04)) < order_of(nid(0x02)),
        "grandchild before its parent"
    );
    assert!(
        order_of(nid(0x05)) < order_of(nid(0x02)),
        "grandchild before its parent"
    );

    // Both channels re-pointed, scope pointer first, AFTER every republish.
    let first_repoint = events
        .iter()
        .position(|ev| matches!(ev, Event::Repoint(_)))
        .unwrap();
    let last_republish = events
        .iter()
        .rposition(|ev| matches!(ev, Event::Republish { .. }))
        .unwrap();
    assert!(
        last_republish < first_repoint,
        "root re-point follows every republish"
    );
    assert_eq!(
        *state.repoint_channels.borrow(),
        vec![RepointChannel::ScopePointer, RepointChannel::VaultPointer],
        "both channels, scope pointer first"
    );

    // Retire is LAST, after the re-point, and the old ROOT name is never retired.
    let retire_pos = events
        .iter()
        .position(|ev| matches!(ev, Event::Retire(_)))
        .unwrap();
    assert!(retire_pos > first_repoint, "retire follows the re-point");
    assert!(
        !state.retired.borrow().contains(current_root.as_str()),
        "the old root name lingers — never retired"
    );
    assert_eq!(
        state.retired.borrow().len(),
        4,
        "exactly the four interior names retired"
    );
}

#[test]
fn no_interior_name_retires_before_the_pointer_flips() {
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    block_on(async {
        let mut e = SeededEntropy::new(2);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("rotation succeeds");

    let events = state.events.borrow();
    let first_retire = events.iter().position(|ev| matches!(ev, Event::Retire(_)));
    let first_repoint = events
        .iter()
        .position(|ev| matches!(ev, Event::Repoint(_)))
        .unwrap();
    assert!(
        first_retire.map(|r| r > first_repoint).unwrap_or(true),
        "no interior name is retired before the pointer flips (never orphan)"
    );
    assert_eq!(
        events
            .iter()
            .filter(|ev| matches!(ev, Event::Republish { .. }))
            .count(),
        5
    );
}

#[test]
fn every_order_carries_the_derived_names_of_its_in_scope_children() {
    // ADR 0004: a read-only survivor derives no write name, so the wave must
    // hand each parent its children's freshly derived names for the read-body
    // rewrite. Child-first ordering makes them known before the parent's turn.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);
    let seed = SeededEntropy::first_draw(11);

    block_on(async {
        let mut e = SeededEntropy::new(11);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("rotation succeeds");

    let orders = state.orders.borrow();
    let by_id: HashMap<[u8; 16], &RepublishedNode> =
        orders.iter().map(|o| (o.node_id, o)).collect();
    let expected_children: HashMap<[u8; 16], Vec<[u8; 16]>> = resolver
        .nodes
        .iter()
        .map(|(id, kids)| (*id, kids.clone()))
        .collect();

    for order in orders.iter() {
        let kids = &expected_children[&order.node_id];
        assert_eq!(
            order.child_names.len(),
            kids.len(),
            "one rewrite entry per in-scope child"
        );
        for kid in kids {
            let mapped = &order.child_names[kid];
            // The name the parent will write is exactly the name the child was
            // republished at — the whole point of the child-first ordering.
            assert_eq!(mapped, &by_id[kid].new_name);
            assert_eq!(mapped, &derive_write_name(&seed, kid));
        }
        // The capability is the node's own, and nothing wider: it signs at
        // the new name and derives no other node's.
        assert_eq!(
            IpnsName::from_public_key(&order.signer.verifying_key()),
            order.new_name,
            "the handed signer is the new name's key"
        );
        assert_eq!(
            order.write_scope_seed.is_some(),
            order.is_root,
            "only the root carries the scope seed its section distributes"
        );
        assert_eq!(order.current_name, old_name_of(&order.node_id));
    }
}

#[test]
fn an_unlanded_vault_pointer_flip_aborts_the_wave() {
    // No channel is best-effort: an anchor left naming a root the scope has
    // moved off is the cold-start defect the second channel exists to close,
    // so the wave stays resumable rather than reporting itself complete.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::refusing(state.clone(), RepointChannel::VaultPointer);
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(21);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the anchor flip is not optional");

    assert_eq!(
        err,
        WriteRotateError::Publish {
            stage: "repoint-vault-pointer",
            node_id: SCOPE,
            error: WritePublishError::NotLanded,
        }
    );
    assert!(
        err.is_retryable(),
        "the transport did not land — availability"
    );
    assert!(
        state.retired.borrow().is_empty(),
        "nothing retires while a plane still names the old root"
    );
}

#[test]
fn a_scope_below_the_anchor_publishes_the_scope_pointer_alone() {
    // Only the vault anchor is named by a vault pointer; a rotation elsewhere
    // has no second plane to move.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    block_on(async {
        let mut e = SeededEntropy::new(21);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &RotateScopeWritePlan {
                is_vault_anchor: false,
                ..plan(&owner, &c, &sig, &current_root)
            },
        )
        .await
    })
    .expect("the wave completes on one channel");

    assert_eq!(
        *state.repoint_channels.borrow(),
        vec![RepointChannel::ScopePointer]
    );
}

#[test]
fn a_refused_canonical_repoint_aborts_before_any_retire() {
    // The scope pointer is the authoritative switch: without it the old names
    // are still the live ones, so retiring them would orphan the subtree.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::refusing(state.clone(), RepointChannel::ScopePointer);
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(22);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the canonical channel is not optional");
    assert_eq!(err.check(), "publish-failed");
    assert!(
        state.retired.borrow().is_empty(),
        "nothing retires while the old names are still the live ones"
    );
}

#[test]
fn a_fail_closed_publish_refusal_is_not_retryable() {
    // Rule 6: a publisher's own trust verdict must not be laundered into an
    // availability stall a retry loop keeps charging.
    for (error, retryable) in [
        (WritePublishError::NotLanded, true),
        (WritePublishError::LostRace, true),
        (WritePublishError::RegistryFull, true),
        (WritePublishError::Rejected, false),
    ] {
        let err = WriteRotateError::Publish {
            stage: "republish",
            node_id: SCOPE,
            error,
        };
        assert_eq!(err.is_retryable(), retryable);
    }
}

#[test]
fn mid_wave_crash_resumes_from_published_records_only() {
    // Crash the wave at the canonical re-point — past the root republish, so
    // published state holds the moved root — then resume with a FRESH
    // orchestrator, a fresh publisher, and an entropy stream that would mint a
    // DIFFERENT seed. Nothing is handed in: the resume converges on the first
    // run's names or not at all.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let resolver = tree_on(state.clone());
    let current_root = old_name_of(&SCOPE);
    let minted = SeededEntropy::first_draw(9);

    // First attempt lands every republish, then dies on the pointer flip.
    let crashing = FakePublisher::refusing(state.clone(), RepointChannel::ScopePointer);
    let err = block_on(async {
        let mut e = SeededEntropy::new(9);
        rotate_scope_write(
            &mut e,
            &resolver,
            &crashing,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the wave crashes mid-flight");
    assert_eq!(err.check(), "publish-failed");
    assert_eq!(
        state.published.borrow().len(),
        5,
        "the whole subtree republished before the flip failed"
    );
    assert!(
        state.repoint_channels.borrow().is_empty(),
        "no re-point before the wave completed"
    );

    // Resume: a brand-new orchestrator + publisher over the same durable state.
    let resume_pub = FakePublisher::new(state.clone());
    let outcome = block_on(async {
        let mut e = SeededEntropy::new(123); // a DIFFERENT stream — a fresh mint would diverge
        rotate_scope_write(
            &mut e,
            &resolver,
            &resume_pub,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the resumed wave completes");

    assert_eq!(outcome.new_write_epoch, 5);
    assert_eq!(
        outcome.new_root_name,
        derive_write_name(&minted, &SCOPE),
        "the resume ran on the first run's published seed, not a fresh mint"
    );
    assert_ne!(
        minted,
        SeededEntropy::first_draw(123),
        "the resume's own stream would have minted a different seed"
    );

    // Every node republished exactly once across BOTH runs — the resume skipped
    // the already-published nodes (proof it read published state, not memory).
    let calls = state.republish_calls.borrow();
    assert_eq!(calls.len(), 5, "all five nodes republished");
    assert!(
        calls.values().all(|&n| n == 1),
        "no node republished twice — resume is idempotent off published records"
    );
    // Across both runs every node was ordered with its children's post-wave
    // names, so a resume leaves no stale child name behind.
    let orders = state.orders.borrow();
    let published: HashMap<[u8; 16], IpnsName> = orders
        .iter()
        .map(|o| (o.node_id, o.new_name.clone()))
        .collect();
    for order in orders.iter() {
        for (child, name) in &order.child_names {
            assert_eq!(name, &published[child]);
        }
    }
    drop(orders);

    // The wave completed: both planes flipped. Every name the resume
    // enumerated is a live one, so what it tombstones comes from the
    // pre-wave seed alone — exactly the interior names the first run
    // superseded, and never the lingering root.
    assert_eq!(state.repoint_channels.borrow().len(), 2);
    let retired = state.retired.borrow().clone();
    let superseded: HashSet<String> = [nid(0x02), nid(0x03), nid(0x04), nid(0x05)]
        .iter()
        .map(|id| old_name_of(id).as_str().to_owned())
        .collect();
    assert_eq!(
        retired, superseded,
        "the resume tombstones every interior name its prior run superseded"
    );
    assert!(!retired.contains(current_root.as_str()), "root lingers");
    let live: HashSet<String> = state.published.borrow().iter().cloned().collect();
    assert!(
        retired.is_disjoint(&live),
        "no name a node currently lives at is retired"
    );
}

#[test]
fn a_resume_that_cannot_read_the_pre_wave_seed_tombstones_nothing() {
    // The pre-wave names are unreachable without that seed, and guessing is
    // the one direction that could tombstone a live name.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let current_root = old_name_of(&SCOPE);

    let crashing = FakePublisher::refusing(state.clone(), RepointChannel::ScopePointer);
    block_on(async {
        let mut e = SeededEntropy::new(9);
        rotate_scope_write(
            &mut e,
            &tree_on(state.clone()),
            &crashing,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the wave crashes mid-flight");

    let blind = FakeResolver {
        superseded_seed: None,
        ..tree_on(state.clone())
    };
    let resume_pub = FakePublisher::new(state.clone());
    block_on(async {
        let mut e = SeededEntropy::new(123);
        rotate_scope_write(
            &mut e,
            &blind,
            &resume_pub,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the resumed wave still completes");

    assert!(
        state.retired.borrow().is_empty(),
        "an unreadable history link leaks a registration rather than guessing a name"
    );
}

#[test]
fn a_fresh_start_reclaims_the_interior_names_a_flipped_crash_left_registered() {
    // A wave that crashed past its pointer flip has nothing to resume: its
    // moved copies are the live ones, so the next rotation is the only pass
    // that can still name what it registered.
    const ORPHANED_SEED: [u8; SECRET_LEN] = [0x7e; SECRET_LEN];
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let resolver = FakeResolver {
        superseded_seed: Some(ORPHANED_SEED),
        ..tree_on(state.clone())
    };
    let current_root = old_name_of(&SCOPE);

    block_on(async {
        let mut e = SeededEntropy::new(9);
        rotate_scope_write(
            &mut e,
            &resolver,
            &FakePublisher::new(state.clone()),
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the fresh wave completes");

    let retired = state.retired.borrow().clone();
    for id in [nid(0x02), nid(0x03), nid(0x04), nid(0x05)] {
        assert!(
            retired.contains(old_name_of(&id).as_str()),
            "the live interior name this wave supersedes retires"
        );
        assert!(
            retired.contains(derive_write_name(&ORPHANED_SEED, &id).as_str()),
            "the interior name the crashed wave orphaned retires too"
        );
    }
    assert_eq!(
        retired.len(),
        8,
        "both epochs of interior names, and nothing else"
    );
    assert!(
        !retired.contains(derive_write_name(&ORPHANED_SEED, &SCOPE).as_str()),
        "a root name lingers past its migration window, the orphaned one included"
    );
    assert!(!retired.contains(current_root.as_str()), "root lingers");
    let live: HashSet<String> = state.published.borrow().iter().cloned().collect();
    assert!(
        retired.is_disjoint(&live),
        "no name a node currently lives at is retired"
    );
}

#[test]
fn a_recovered_wave_at_another_write_epoch_is_refused_before_any_publish() {
    // Nothing gates the scope pointer, and every re-point this scope ever
    // published lives at the same stable name — so an older owner-signed
    // re-point stays replayable for ever. Requiring the recovered epoch to be
    // the one this run publishes at is what pins a resume to THIS wave.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let stale_seed = [0x93; SECRET_LEN];
    let resolver = FakeResolver {
        recovery: Some((
            derive_write_name(&stale_seed, &SCOPE),
            stale_seed,
            ROTATED_WRITE_EPOCH - 1,
        )),
        ..tree_on(state.clone())
    };
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(32);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("a wave at another write epoch is not this run's to resume");
    assert_eq!(err.check(), "resumed-wave-at-another-epoch");
    assert!(!err.is_retryable(), "a replayed re-point is not a stall");
    assert!(
        state.published.borrow().is_empty(),
        "nothing published on a refused recovery"
    );
}

#[test]
fn a_recovered_seed_that_does_not_derive_its_root_name_is_refused() {
    // The recovery's two halves must agree: a seed that derives some other
    // name is what a forged write-plane history link, or a root published
    // under a seed nothing ties to it, would hand back. Resuming on it would
    // republish the whole subtree under attacker-chosen names, so the wave
    // refuses before it touches the publisher.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let resolver = FakeResolver {
        // A real published root name, but not the one that seed derives.
        recovery: Some((
            derive_write_name(&[0x92; SECRET_LEN], &SCOPE),
            [0x91; SECRET_LEN],
            ROTATED_WRITE_EPOCH,
        )),
        ..tree_on(state.clone())
    };
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(31);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("a seed that does not derive its own root name is refused");
    assert_eq!(err.check(), "resumed-seed-not-at-its-root");
    assert!(!err.is_retryable(), "no retry reconciles the two halves");
    assert!(
        state.published.borrow().is_empty(),
        "nothing published on a refused recovery"
    );
}

#[test]
fn a_crash_before_the_root_publishes_has_no_seed_to_recover() {
    // The moved root is the only published carrier of the fresh seed, so a
    // crash before it lands leaves nothing to recover: the retry mints its own
    // and the first run's interior names are orphaned — the fail-safe
    // direction the module documents.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let resolver = tree_on(state.clone());
    let current_root = old_name_of(&SCOPE);

    let crashing = FakePublisher::failing_after(state.clone(), 2);
    block_on(async {
        let mut e = SeededEntropy::new(41);
        rotate_scope_write(
            &mut e,
            &resolver,
            &crashing,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the wave crashes before the root republish");
    assert!(
        state.published_root.borrow().is_none(),
        "no moved root published, so nothing carries the seed"
    );
    let orphaned: Vec<String> = state.published.borrow().iter().cloned().collect();
    assert_eq!(orphaned.len(), 2, "two interior names landed");

    let resume_pub = FakePublisher::new(state.clone());
    let outcome = block_on(async {
        let mut e = SeededEntropy::new(42);
        rotate_scope_write(
            &mut e,
            &resolver,
            &resume_pub,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the retry completes on a freshly minted seed");

    let minted = SeededEntropy::first_draw(42);
    assert_eq!(
        outcome.new_root_name,
        derive_write_name(&minted, &SCOPE),
        "the retry minted its own seed"
    );
    // ADR 0007 D1 confines the derived pair to genesis. `owner()` adopts the
    // login secret as its identity scalar (`SessionIdentity::derive`), so the
    // seed this account's own mint derives is exactly
    // `genesis_write_scope_seed(OWNER_SCALAR)` — and a rotation that
    // reproduced it would rotate to the key the login secret already names.
    assert_ne!(
        minted,
        *cipherbox_core::kdf::genesis_write_scope_seed(&OWNER_SCALAR).as_bytes(),
        "a rotation draws its seed, it never derives one",
    );
    for name in &orphaned {
        assert!(
            !state.retired.borrow().contains(name),
            "the first run's names are orphaned, never retired"
        );
    }
}

#[test]
fn a_wave_whose_retire_refused_on_a_floor_rise_converges_on_the_next_run() {
    // The wave republishes the subtree and flips the pointer, a concurrent read
    // rotation raises the read-epoch floor, and the retire refuses fail-closed.
    // The next run must pick the wave up through the MOVED root — the pre-wave
    // root lingers below the raised floor, so enumerating it re-derives the
    // same refused evidence for ever.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let state = WaveState::default();
    let resolver = tree_on(state.clone());
    let current_root = old_name_of(&SCOPE);

    let refusing = FakePublisher::refusing_retire(state.clone());
    let err = block_on(async {
        let mut e = SeededEntropy::new(71);
        rotate_scope_write(
            &mut e,
            &resolver,
            &refusing,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("the retire refuses on the floor rise");
    assert_eq!(err.check(), "publish-failed");
    assert!(!err.is_retryable(), "a fail-closed refusal is not a stall");
    assert_eq!(
        state.repoint_channels.borrow().len(),
        2,
        "both planes flipped before the retire refused"
    );

    // The read rotation's cut is now durable: the pre-wave records sit below
    // the floor and the gate refuses them.
    resolver.below_floor.set(true);

    let outcome = block_on(async {
        let mut e = SeededEntropy::new(72);
        rotate_scope_write(
            &mut e,
            &resolver,
            &FakePublisher::new(state.clone()),
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the resumed wave converges instead of refusing again");
    assert_eq!(
        outcome.new_root_name,
        derive_write_name(&SeededEntropy::first_draw(71), &SCOPE),
        "the resume ran on the first run's published seed"
    );
    let calls = state.republish_calls.borrow();
    assert!(
        calls.values().all(|&n| n == 1),
        "the resume re-published nothing — it read its own moved copies"
    );
}

#[test]
fn a_node_already_at_its_post_wave_name_is_never_republished_onto_itself() {
    // `is_republished` reads the network, and a fan-out can transiently miss a
    // live record. The enumeration already gated this node at the very name the
    // wave moves it to, so that gated read — not the fan-out — decides: the root
    // arm's re-seal would otherwise refuse the epoch its record already carries
    // and burn the wave on an availability blip (rule 6).
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let recovered_seed = [0x88u8; 32];
    let state = WaveState::default();
    let resolver = tree_on(state.clone());
    // The moved root is published state's anchor, but nothing answers
    // `is_republished` — the fan-out miss.
    *state.published_root.borrow_mut() = Some((
        derive_write_name(&recovered_seed, &SCOPE),
        recovered_seed,
        ROTATED_WRITE_EPOCH,
    ));
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    block_on(async {
        let mut e = SeededEntropy::new(51);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the resumed wave completes");

    assert!(
        state.republish_calls.borrow().is_empty(),
        "no node is republished onto the name it already sits at"
    );
}

#[test]
fn resume_after_flip_never_retires_a_live_name() {
    // A resume AFTER the pointer already flipped: the wave anchors the
    // enumeration at the moved root it recovered, so every node resolves at
    // its NEW name. It must retire none of those — retiring a name a node
    // still lives at would orphan a live descendant — and exactly the
    // pre-wave names its prior run superseded.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let recovered_seed = [0x77u8; 32];
    let state = WaveState::default();
    let resolver = tree_on(state.clone());
    // The fully-migrated published state: every new name already landed, and
    // the moved root carries the seed the resume recovers.
    for id in [SCOPE, nid(0x02), nid(0x03), nid(0x04), nid(0x05)] {
        let name = derive_write_name(&recovered_seed, &id);
        state
            .published
            .borrow_mut()
            .insert(name.as_str().to_owned());
    }
    *state.published_root.borrow_mut() = Some((
        derive_write_name(&recovered_seed, &SCOPE),
        recovered_seed,
        ROTATED_WRITE_EPOCH,
    ));
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    block_on(async {
        let mut e = SeededEntropy::new(50);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect("the resumed wave completes");

    let retired = state.retired.borrow().clone();
    let live: HashSet<String> = state.published.borrow().iter().cloned().collect();
    assert!(
        retired.is_disjoint(&live),
        "no live (already-migrated) name is retired on a post-flip resume"
    );
    let superseded: HashSet<String> = [nid(0x02), nid(0x03), nid(0x04), nid(0x05)]
        .iter()
        .map(|id| old_name_of(id).as_str().to_owned())
        .collect();
    assert_eq!(
        retired, superseded,
        "the pre-wave interior names are tombstoned instead of orphaned"
    );
}

#[test]
fn non_owner_signer_is_rejected_fail_closed() {
    // A real, valid signer that did NOT author the commitment cannot rotate.
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);
    let impostor = EcdsaSigner::from_scalar(&[0x44; 32]).unwrap();

    let err = block_on(async {
        let mut e = SeededEntropy::new(3);
        let mut p = plan(&owner, &c, &sig, &current_root);
        p.owner_identity_signer = &impostor;
        rotate_scope_write(&mut e, &resolver, &publisher, &p).await
    })
    .expect_err("a non-owner is rejected");
    assert_eq!(err.check(), "not-owner");
    assert!(
        !err.is_retryable(),
        "owner-only is not an availability stall"
    );
    assert!(
        state.published.borrow().is_empty(),
        "nothing published on an owner-only rejection"
    );
}

#[test]
fn commitment_naming_a_different_scope_is_rejected_fail_closed() {
    // The owner correctly signs the commitment, but it names a DIFFERENT scope
    // root than the one under rotation. The owner-gate binds the auth token to
    // the exact rotated scope (the adoption gate's `commitment.ipns_name`
    // binding), so a valid-but-wrong-scope commitment fails closed before any
    // mint or publish — an owner cannot rotate scope B with scope A's token.
    let owner = owner();
    let other_root = old_name_of(&nid(0xaa));
    let (c, sig) = commitment_for(&owner, &other_root);
    let resolver = tree();
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(7);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("a commitment naming another scope is rejected");
    assert_eq!(err.check(), "commitment-scope-mismatch");
    assert!(
        !err.is_retryable(),
        "a scope-binding violation is not an availability stall"
    );
    assert!(
        state.published.borrow().is_empty(),
        "nothing published on a scope-mismatch rejection"
    );
}

#[test]
fn resolve_failure_aborts_without_publishing() {
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = FailingResolver {
        inner: tree(),
        fail_on: nid(0x04),
    };
    let state = WaveState::default();
    let publisher = FakePublisher::new(state.clone());
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(4);
        rotate_scope_write(
            &mut e,
            &resolver,
            &publisher,
            &plan(&owner, &c, &sig, &current_root),
        )
        .await
    })
    .expect_err("an unresolvable node aborts the wave");
    assert_eq!(err.check(), "resolve-failed");
    assert!(
        state.published.borrow().is_empty(),
        "nothing republished when enumeration fails"
    );
}

#[test]
fn exhausted_write_epoch_fails_closed() {
    let owner = owner();
    let (c, sig) = commitment(&owner);
    let resolver = tree();
    let publisher = FakePublisher::new(WaveState::default());
    let current_root = old_name_of(&SCOPE);

    let err = block_on(async {
        let mut e = SeededEntropy::new(5);
        let mut p = plan(&owner, &c, &sig, &current_root);
        p.current_write_epoch = u64::MAX;
        rotate_scope_write(&mut e, &resolver, &publisher, &p).await
    })
    .expect_err("an exhausted epoch fails closed");
    assert_eq!(err.check(), "epoch-exhausted");
}

#[test]
fn derive_write_name_is_deterministic_and_moves_the_name() {
    // A surviving write-grantee derives the same new name locally; the new name
    // differs from the old (a fresh write scope seed moved it).
    let fresh = [0xef; 32];
    let a = derive_write_name(&fresh, &SCOPE);
    let b = derive_write_name(&fresh, &SCOPE);
    assert_eq!(a, b, "same seed + node id -> same name (local derivation)");
    assert_ne!(a, old_name_of(&SCOPE), "the fresh seed moved the name");
}

// --- Encode-side fail-closed guards (release-active, AGENTS.md rule 8) ---

#[test]
fn build_repoint_rejects_non_advancing_write_epoch_release_active() {
    // The encode-side mirror of the floor law's monotonic write-epoch reject: a
    // re-point that does not advance the write epoch is a runtime `Err`, never a
    // debug_assert. Active in release builds.
    let new_root = derive_write_name(&[0x01; 32], &SCOPE);
    let prev_root = old_name_of(&SCOPE);
    for (new_epoch, prev_epoch) in [(5u64, 5u64), (4, 5)] {
        let err = build_repoint_object(
            SCOPE,
            new_root.clone(),
            prev_root.clone(),
            new_epoch,
            prev_epoch,
            7,
        )
        .expect_err("non-advancing write epoch");
        assert_eq!(err.check(), "write-epoch-not-advancing");
    }
}

#[test]
fn build_repoint_rejects_identity_repoint_release_active() {
    // Re-pointing a scope to its own predecessor name is not progress: rejected
    // release-active before publish.
    let same = old_name_of(&SCOPE);
    let err =
        build_repoint_object(SCOPE, same.clone(), same, 6, 5, 7).expect_err("identity re-point");
    assert_eq!(err.check(), "identity-repoint");
}

#[test]
fn build_repoint_accepts_a_valid_advance() {
    let new_root = derive_write_name(&[0x01; 32], &SCOPE);
    let prev_root = old_name_of(&SCOPE);
    let obj = build_repoint_object(SCOPE, new_root.clone(), prev_root.clone(), 6, 5, 7).unwrap();
    assert_eq!(obj.current_root, new_root);
    assert_eq!(obj.prev_root, Some(prev_root));
    assert_eq!(obj.write_epoch, 6);
    assert_eq!(obj.min_read_epoch, 7, "read plane carried unchanged");
}
