//! The sync-core simulation harness — the sync-core gate mirrored 1:1
//! (blueprint/engine.md "Sync core", "Pointer planes"; blueprint/testing.md
//! "the simulation harness").
//!
//! No network, no docker, no wall clock: the whole sync core runs in memory on
//! the test kit's fakes and virtual clock. The five-race table, offline queue
//! replay, dead-letter on revoked-while-offline, the unbounded metadata journal,
//! the staleness ladder and escalation, the keyless-re-PUT adversary, and the
//! cold-start-adopts-nothing sequence each get a narrative here, driven only
//! through the engine's public sync surface.

use core::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::payload::RepointObject;
use cipherbox_core::suite::ecdsa::EcdsaSigner;

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid};
use cipherbox_core::suite::x25519::X25519Secret;
use cipherbox_engine::gate::floor;
use cipherbox_engine::profile::SyncTimingProfile;
use cipherbox_engine::rotation::{
    RotateError, RotationOutcome, RotationPublishError, ScopeExitReport, ScopeExitRotator,
    consume_scope_exit_triggers,
};
use cipherbox_engine::seams::{OpId, SeamResult, StagingStore, UnixMillis};
use cipherbox_engine::sync::model::NodeMeta;
use cipherbox_engine::sync::pointer::{open_repoint, seal_repoint, vault_pointer_name};
use cipherbox_engine::sync::{
    self, Connectivity, DeadLetterReason, DropReason, NewNode, Op, OpResolution, PointerFetch,
    RecordReader, RecordSeal, ScopeCrossing, SessionRole, Snapshot, StagedContent, apply_repairs,
    classify, decode_queue, observed_repair, rebase_one, replay, resolve_vault_pointer, stage_op,
    withheld_escalation,
};
use cipherbox_engine::testkit::fakes::{InMemoryFloorStore, InMemoryStagingStore};
use cipherbox_engine::testkit::{SeededEntropy, block_on};
use cipherbox_engine::{NodeId, NodeKind, Staleness};
use zeroize::Zeroizing;

/// Journal time for ops whose narrative does not turn on it.
const AT: UnixMillis = UnixMillis(0);

/// The device owner whose enc subkey tags and seals every record here.
fn owner() -> X25519Secret {
    X25519Secret::from_scalar([9; 32])
}

/// Sealing inputs for one record; `nonce` keeps each ephemeral distinct.
fn seal(who: &X25519Secret, nonce: u8) -> RecordSeal<'_> {
    RecordSeal {
        owner_enc_secret: who,
        ephemeral_scalar: Zeroizing::new([nonce; 32]),
    }
}

/// The content address a staged root block is keyed by.
fn root_cid(marker: &[u8]) -> Vec<u8> {
    compute_cid(CONTENT_CID_CODEC, marker)
}

/// The staged content for an upload of `marker` — its root CID and its
/// plaintext length.
fn staged(marker: &[u8]) -> StagedContent {
    StagedContent {
        root_cid: root_cid(marker),
        plaintext_size: marker.len() as u64,
        sealed_content_key: Vec::new(),
        epoch: 1,
    }
}

fn id(b: u8) -> NodeId {
    NodeId([b; 16])
}

/// The one scope root these fixtures hang under — the full-depth scope-exit
/// walk resolves against it.
const SCOPE_ROOTS: &[NodeId] = &[NodeId([0; 16])];

fn with_child(snap: &mut Snapshot, parent: NodeId, node: NodeId, name: &str, kind: NodeKind) {
    snap.upsert_node(NodeMeta::new(node, name, kind));
    snap.link(parent, node, 1);
}

// ---------------------------------------------------------------------------
// The five-race table, mirrored 1:1 (blueprint/engine.md rebase rules).
// Each is a two-client narrative: the "other" client's change is the fresh
// gate-passing base our queued op rebases onto.
// ---------------------------------------------------------------------------

#[test]
fn race_1_delete_vs_concurrent_edit_edit_wins() {
    // Other client edited the file (its record advanced 3 → 6). Our delete
    // snapshotted it at 3.
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "f", NodeKind::File);
    base.node_mut(id(1)).unwrap().record_sequence = 6;
    let local = base.clone();

    let res = rebase_one(&mut base, &local, &Op::delete(id(1), 1, AT, 3), SCOPE_ROOTS);
    assert_eq!(res, OpResolution::dropped(DropReason::TargetAdvanced));
    assert!(
        base.contains(id(1)),
        "the concurrent edit wins; the node survives"
    );
}

#[test]
fn race_1_reverse_edit_resurrects_a_concurrently_deleted_node() {
    // Other client deleted the node (absent from gate-passing state); our edit
    // resurrects it (edit wins in both directions).
    let gate_passing = Snapshot::new(id(0));
    let mut local = Snapshot::new(id(0));
    with_child(&mut local, id(0), id(1), "f", NodeKind::File);

    let mut working = gate_passing.clone();
    let res = rebase_one(
        &mut working,
        &local,
        &Op::update_content(id(1), staged(b"v2"), None, 1, AT),
        SCOPE_ROOTS,
    );
    assert!(matches!(res, OpResolution::Applied { .. }));
    assert!(
        working.contains(id(1)),
        "the edit resurrected the deleted node"
    );
}

#[test]
fn race_2_rename_vs_rename_serialized_by_parent_cas_higher_writer_wins() {
    // Other client renamed the node first (base shows "other.txt"); our rebasing
    // rename re-anchors and publishes at a higher parent sequence, so it wins.
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "start.txt", NodeKind::File);
    base.node_mut(id(1)).unwrap().rename("other.txt");
    let local = base.clone();

    let res = rebase_one(
        &mut base,
        &local,
        &Op::rename(id(1), "mine.txt", 1, AT),
        SCOPE_ROOTS,
    );
    assert!(matches!(
        res,
        OpResolution::Applied {
            suffixed: false,
            ..
        }
    ));
    assert_eq!(base.node(id(1)).unwrap().name(), "mine.txt");
}

#[test]
fn race_3_add_vs_add_name_collision_auto_suffixes_the_loser() {
    // Other client already created "a.txt" under root; our create collides and
    // auto-suffixes — both stay visible.
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "a.txt", NodeKind::File);
    let local = base.clone();

    let res = rebase_one(
        &mut base,
        &local,
        &Op::create(
            id(2),
            id(0),
            "a.txt",
            NewNode::File { content: None },
            1,
            AT,
        ),
        SCOPE_ROOTS,
    );
    assert_eq!(
        res,
        OpResolution::Applied {
            effective_name: Some(Zeroizing::new("a (2).txt".to_owned())),
            suffixed: true,
            scope_exit_trigger: None,
        }
    );
    assert_eq!(base.children(id(0)).len(), 2, "both adds are visible");
}

#[test]
fn race_4_move_dest_first_then_presence_conditional_source_remove() {
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "dir", NodeKind::Folder);
    with_child(&mut base, id(0), id(2), "f", NodeKind::File);
    let local = base.clone();

    let res = rebase_one(
        &mut base,
        &local,
        &Op::relink(id(2), id(0), id(1), 1, AT, ScopeCrossing::Intra),
        SCOPE_ROOTS,
    );
    assert!(matches!(res, OpResolution::Applied { .. }));
    assert_eq!(base.parent_of(id(2)), Some(id(1)), "dest-linked");
    assert!(
        base.children(id(0)).iter().all(|c| c.id != id(2)),
        "source-removed — no orphan"
    );
}

#[test]
fn race_4_move_race_loser_undoes_its_dest_add() {
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "dirA", NodeKind::Folder);
    with_child(&mut base, id(0), id(2), "dirB", NodeKind::Folder);
    with_child(&mut base, id(0), id(3), "f", NodeKind::File);
    // The other client's move already relocated the child into dirB.
    base.unlink(id(0), id(3));
    base.link(id(2), id(3), 2);
    let local = base.clone();

    // Our queued move (root → dirA) is the race loser: it undoes its dest-add.
    let res = rebase_one(
        &mut base,
        &local,
        &Op::relink(id(3), id(0), id(1), 1, AT, ScopeCrossing::Intra),
        SCOPE_ROOTS,
    );
    assert_eq!(res, OpResolution::dropped(DropReason::MoveRaceLost));
    assert_eq!(
        base.parent_of(id(3)),
        Some(id(2)),
        "the winning move stands"
    );
    assert!(
        base.children(id(1)).is_empty(),
        "no dest-add residue under dirA"
    );
}

#[test]
fn race_5_dual_link_observed_repair_uses_the_link_counter() {
    // Crash residue of a dest-first move: one child linked in two parents.
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "p1", NodeKind::Folder);
    with_child(&mut base, id(0), id(2), "p2", NodeKind::Folder);
    base.upsert_node(NodeMeta::new(id(3), "child", NodeKind::File));
    base.link(id(1), id(3), 1);
    base.link(id(2), id(3), 2); // the higher counter is the winner

    let repairs = observed_repair(&base);
    assert_eq!(repairs.len(), 1, "the dual link is detected");
    apply_repairs(&mut base, &repairs);
    assert_eq!(base.links_to(id(3)).len(), 1, "the losing link is removed");
    assert_eq!(base.parent_of(id(3)), Some(id(2)));
}

// ---------------------------------------------------------------------------
// Offline queue replay — stage ops offline, then replay FIFO onto a fresh
// gate-passing base through the same rebase path.
// ---------------------------------------------------------------------------

#[test]
fn offline_queue_replays_fifo_onto_gate_passing_state() {
    let store = InMemoryStagingStore::default();
    let me = owner();

    block_on(async {
        // Offline: journal a create, a rename, and a colliding create.
        let ops = [
            Op::create(
                id(1),
                id(0),
                "notes.txt",
                NewNode::File { content: None },
                1,
                AT,
            ),
            Op::rename(id(1), "notes-v2.txt", 1, AT),
            // will collide
            Op::create(
                id(2),
                id(0),
                "notes-v2.txt",
                NewNode::File { content: None },
                1,
                AT,
            ),
        ];
        for (n, op) in ops.iter().enumerate() {
            stage_op(&store, seal(&me, n as u8), op).await.unwrap();
        }

        // Reconnect: decode the durable journal and replay onto fresh state.
        let raw = store.queued_ops().await.unwrap();
        let scan = decode_queue(&RecordReader::new(&me), &raw);
        assert!(scan.undecodable.is_empty());
        assert_eq!(scan.retained, 0);

        let base = Snapshot::new(id(0));
        let report = replay(&base, &base, &scan.mine, SCOPE_ROOTS);

        assert_eq!(report.applied.len(), 3, "every op replayed in FIFO order");
        assert_eq!(report.rebased.node(id(1)).unwrap().name(), "notes-v2.txt");
        // The colliding create auto-suffixed on merge.
        assert!(report.applied[2].suffixed);
        assert_eq!(
            report.rebased.node(id(2)).unwrap().name(),
            "notes-v2 (2).txt"
        );
    });
}

// ---------------------------------------------------------------------------
// Dead-letter on revoked-while-offline — staged bytes preserved.
// ---------------------------------------------------------------------------

#[test]
fn revoked_while_offline_dead_letters_with_staged_bytes_preserved() {
    let store = InMemoryStagingStore::default();
    let me = owner();
    let staged_root = staged(b"sealed-bytes");

    block_on(async {
        // Offline: create a file inside a granted folder (id 5), staging its bytes.
        let op = Op::create(
            id(6),
            id(5),
            "secret.txt",
            NewNode::File {
                content: Some(staged_root.clone()),
            },
            1,
            AT,
        );
        store
            .put_staged_bytes(&staged_root.root_cid, b"sealed-bytes")
            .await
            .unwrap();
        stage_op(&store, seal(&me, 1), &op).await.unwrap();

        // While offline the grant is revoked: the granted folder is gone from
        // gate-passing state entirely.
        let gate_passing = Snapshot::new(id(0)); // no id(5)
        let raw = store.queued_ops().await.unwrap();
        let scan = decode_queue(&RecordReader::new(&me), &raw);
        let report = replay(&gate_passing, &gate_passing, &scan.mine, SCOPE_ROOTS);

        // The op terminally dead-letters — nothing silently dropped.
        assert_eq!(report.applied.len(), 0);
        assert_eq!(report.dead_letters.len(), 1);
        assert_eq!(report.dead_letters[0].1, DeadLetterReason::TargetGone);

        // A terminally unrebasable op keeps its staged bytes (blueprint/engine.md,
        // #33 D6) — only the failure valve's abandonments release them.
        assert_eq!(
            store.staged_bytes(&staged_root.root_cid).await.unwrap(),
            Some(b"sealed-bytes".to_vec()),
            "staged bytes survive the dead-letter"
        );
    });
}

// ---------------------------------------------------------------------------
// Metadata ops queue unbounded — the staged-byte bound is admitted at
// `beginWrite`, never on the op journal.
// ---------------------------------------------------------------------------

#[test]
fn metadata_ops_queue_unbounded() {
    let store = InMemoryStagingStore::default();
    let me = owner();
    block_on(async {
        for i in 10..20 {
            stage_op(&store, seal(&me, i), &Op::rename(id(i), "n", 1, AT))
                .await
                .unwrap();
        }
        assert_eq!(
            store.queued_ops().await.unwrap().len(),
            10,
            "metadata is unbounded"
        );
    });
}

// ---------------------------------------------------------------------------
// The staleness ladder and the withheld-update escalation.
// ---------------------------------------------------------------------------

#[test]
fn staleness_ladder_climbs_fresh_reconciling_stale_offline() {
    let p = SyncTimingProfile::PRODUCTION; // stale_after 90 s
    let last = UnixMillis(0);

    // Fresh within the window.
    assert_eq!(
        classify(
            UnixMillis(10_000),
            Some(last),
            false,
            Connectivity::Online,
            &p
        ),
        Staleness::Fresh
    );
    // A reconcile in flight shows the quiet indicator.
    assert_eq!(
        classify(
            UnixMillis(10_000),
            Some(last),
            true,
            Connectivity::Online,
            &p
        ),
        Staleness::Reconciling
    );
    // Past the threshold, idle: the stale badge.
    assert_eq!(
        classify(
            UnixMillis(120_000),
            Some(last),
            false,
            Connectivity::Online,
            &p
        ),
        Staleness::Stale
    );
    // Offline outranks everything.
    assert_eq!(
        classify(
            UnixMillis(120_000),
            Some(last),
            false,
            Connectivity::Offline,
            &p
        ),
        Staleness::Offline
    );
}

#[test]
fn withheld_update_escalation_is_shared_scope_only() {
    let p = SyncTimingProfile::PRODUCTION; // escalation window 600 s
    // Shared scope, others succeeding, pinned past the window: escalate.
    assert!(withheld_escalation(
        UnixMillis(600_000),
        UnixMillis(0),
        true,
        true,
        &p
    ));
    // A private-vault pin past the window is ordinary staleness, never escalated.
    assert!(!withheld_escalation(
        UnixMillis(600_000),
        UnixMillis(0),
        false,
        true,
        &p
    ));
}

// ---------------------------------------------------------------------------
// The keyless re-PUT adversary — the floor law blocks a rollback.
// ---------------------------------------------------------------------------

#[test]
fn keyless_re_put_adversary_cannot_roll_the_floor_back() {
    let floors = InMemoryFloorStore::default();
    const SCOPE: [u8; 16] = [1u8; 16];
    const NAME: &[u8] = b"scope-root-ipns-name";

    block_on(async {
        // The device adopted the record at sequence 5, epoch 3 (floors advanced).
        floor::advance_on_unseal(&floors, &SCOPE, NAME, 5, 3)
            .await
            .unwrap();

        // The adversary keyless-re-PUTs a captured OLDER record (seq 4, epoch 2)
        // to try to roll the view back. It is byte-valid and validly signed, but
        // both floors reject it — a re-PUT keeps a record alive, it can never
        // regress the durable floors.
        assert_eq!(floor::sequence_floor(&floors, NAME).await.unwrap(), Some(5));
        assert_eq!(
            floor::read_epoch_floor(&floors, &SCOPE).await.unwrap(),
            Some(3)
        );

        // A monotonic-max re-raise at the lower values is a no-op: the floor holds.
        floor::advance_on_unseal(&floors, &SCOPE, NAME, 4, 2)
            .await
            .unwrap();
        assert_eq!(
            floor::sequence_floor(&floors, NAME).await.unwrap(),
            Some(5),
            "no rollback"
        );
        assert_eq!(
            floor::read_epoch_floor(&floors, &SCOPE).await.unwrap(),
            Some(3),
            "no rollback"
        );
    });
}

// ---------------------------------------------------------------------------
// Cold-start adopts nothing before floor seeding — the non-circular sequence.
// ---------------------------------------------------------------------------

/// A scripted pointer network for the cold-start narrative.
#[derive(Clone, Default)]
struct ScriptedPointers {
    blocks: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl ScriptedPointers {
    fn put(&self, name: &IpnsName, block: Vec<u8>) {
        self.blocks
            .lock()
            .unwrap()
            .insert(name.as_str().to_owned(), block);
    }
}

impl PointerFetch for ScriptedPointers {
    async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>> {
        Ok(self.blocks.lock().unwrap().get(name.as_str()).cloned())
    }
}

const LOGIN_SECRET: &[u8] = b"cold-start-login-secret";
const ROOT_SCOPE: [u8; 16] = [0u8; 16];

fn repoint(min_read_epoch: u64, write_epoch: u64) -> RepointObject {
    RepointObject {
        scope_id: ROOT_SCOPE,
        current_root: vault_pointer_name(LOGIN_SECRET, 0),
        write_epoch,
        min_read_epoch,
        prev_root: None,
    }
}

#[test]
fn cold_start_adopts_nothing_until_the_floor_seeds_from_the_pointer() {
    let pointers = ScriptedPointers::default();
    let owner = EcdsaSigner::from_scalar(&[3u8; 32]).unwrap();
    let floors = InMemoryFloorStore::default();

    block_on(async {
        // Step 1 — cold start with an empty vault-pointer chain: adopt nothing.
        let cold = resolve_vault_pointer(
            &pointers,
            LOGIN_SECRET,
            &owner.verifying_key(),
            &ROOT_SCOPE,
            1,
        )
        .await
        .unwrap();
        assert_eq!(
            cold, None,
            "cold start adopts nothing before a pointer exists"
        );
        assert_eq!(
            floor::read_epoch_floor(&floors, &ROOT_SCOPE).await.unwrap(),
            None,
            "no floor is seeded yet — the gate would have no revocation boundary"
        );

        // Step 2 — the owner publishes the vault pointer (re-point: minReadEpoch 5).
        let owner_seed = kdf::owner_pointer_seed(LOGIN_SECRET);
        let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &ROOT_SCOPE);
        let mut entropy = SeededEntropy::new(1);
        let block = seal_repoint(
            SessionRole::Owner,
            &mut entropy,
            read_key.as_bytes(),
            1,
            &owner,
            &repoint(5, 3),
        )
        .unwrap();
        pointers.put(&vault_pointer_name(LOGIN_SECRET, 0), block);

        // Step 3 — the pointer resolves first (the non-circular cold-start act),
        // then the floors cold-seed from its owner-vouched epochs.
        let adopted = resolve_vault_pointer(
            &pointers,
            LOGIN_SECRET,
            &owner.verifying_key(),
            &ROOT_SCOPE,
            1,
        )
        .await
        .unwrap()
        .expect("the vault pointer now resolves");
        assert_eq!(adopted.index, 0);
        // The vault pointer is the root anchor: cold-seed through the same
        // checked, fail-closed seam production's `cold_start` uses.
        floor::cold_seed_checked(&floors, &adopted.repoint, &ROOT_SCOPE)
            .await
            .unwrap();

        // Now the revocation floor is seeded: an old-epoch record (epoch 3 < 5)
        // would fail the gate's epoch stage — cold start no longer adopts blindly.
        assert_eq!(
            floor::read_epoch_floor(&floors, &ROOT_SCOPE).await.unwrap(),
            Some(5),
            "the floor seeded from the owner-signed re-point anchor"
        );
    });
}

/// `floor::cold_seed_checked` picks the vault anchor by an opened re-point's
/// `scopeId`. That is sound only because the pointer seal derives its AAD from
/// that same field, so a re-point opens under no other scope id — pinned here
/// rather than left to the encoder.
#[test]
fn a_repoint_opens_only_under_the_scope_id_it_names() {
    let owner = EcdsaSigner::from_scalar(&[3u8; 32]).unwrap();
    let read_key = kdf::pointer_read_key(
        kdf::owner_pointer_seed(LOGIN_SECRET).as_bytes(),
        &ROOT_SCOPE,
    );
    let mut entropy = SeededEntropy::new(1);
    let block = seal_repoint(
        SessionRole::Owner,
        &mut entropy,
        read_key.as_bytes(),
        1,
        &owner,
        &repoint(5, 3),
    )
    .unwrap();

    let opened = open_repoint(
        read_key.as_bytes(),
        1,
        &ROOT_SCOPE,
        &owner.verifying_key(),
        &block,
    )
    .expect("a re-point opens under the scope id it names");
    assert_eq!(opened.scope_id, ROOT_SCOPE);

    open_repoint(
        read_key.as_bytes(),
        1,
        &[9u8; 16],
        &owner.verifying_key(),
        &block,
    )
    .expect_err("the seal AAD binds the re-point to the scope id it names");
}

// ---------------------------------------------------------------------------
// The state law — rendered = gate-passing snapshot ⊕ pending-op overlay.
// ---------------------------------------------------------------------------

#[test]
fn state_law_renders_the_snapshot_plus_the_pending_overlay() {
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(1), "confirmed.txt", NodeKind::File);

    // Two pending ops not yet confirmed by the network.
    let pending = [
        Op::create(
            id(2),
            id(0),
            "pending.txt",
            NewNode::File { content: None },
            1,
            AT,
        ),
        Op::rename(id(1), "renamed.txt", 1, AT),
    ];
    let view = sync::apply_overlay(&base, &pending);

    assert!(view.contains(id(2)), "pending create shows immediately");
    assert_eq!(
        view.node(id(1)).unwrap().name(),
        "renamed.txt",
        "pending rename shows"
    );
    // The gate-passing snapshot is the only source of truth and is untouched.
    assert!(!base.contains(id(2)));
    assert_eq!(base.node(id(1)).unwrap().name(), "confirmed.txt");
}

// ---------------------------------------------------------------------------
// Scope-exit rotation triggers — full-depth detection, one rotation per source
// scope root, and a failure that surfaces (blueprint/engine.md "Rotation
// primitives: Triggers").
// ---------------------------------------------------------------------------

/// A granted scope root (id 5) under the vault root, holding a chain down to
/// depth 3, beside a destination folder outside it.
fn granted_scope_tree() -> Snapshot {
    let mut base = Snapshot::new(id(0));
    with_child(&mut base, id(0), id(5), "granted", NodeKind::Folder);
    with_child(&mut base, id(0), id(6), "outside", NodeKind::Folder);
    with_child(&mut base, id(5), id(10), "a", NodeKind::Folder);
    with_child(&mut base, id(10), id(11), "b", NodeKind::Folder);
    with_child(&mut base, id(11), id(12), "c", NodeKind::Folder);
    base
}

/// The vault root plus the granted scope root nested under it.
const GRANTED_ROOTS: &[NodeId] = &[NodeId([0; 16]), NodeId([5; 16])];

/// Records every root it is asked to cut, refusing the ones named.
struct RecordingRotator {
    seen: RefCell<Vec<NodeId>>,
    refuse: Vec<NodeId>,
}

impl RecordingRotator {
    fn refusing(refuse: &[NodeId]) -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            refuse: refuse.to_vec(),
        }
    }
}

impl ScopeExitRotator for RecordingRotator {
    async fn rotate_on_scope_exit(
        &self,
        scope_root: NodeId,
    ) -> Result<RotationOutcome, RotateError> {
        self.seen.borrow_mut().push(scope_root);
        if self.refuse.contains(&scope_root) {
            return Err(RotateError::Publish(RotationPublishError::NotPublished));
        }
        Ok(RotationOutcome {
            new_read_epoch: 2,
            epoch_floor: 2,
        })
    }
}

/// Replay `ops` off the durable queue and drive whatever scope exits it found.
/// `placements` seeds each moved file where the op was formed against it.
fn exits_of(
    placements: &[(NodeId, NodeId)],
    ops: &[Op],
    rotator: &RecordingRotator,
) -> (Vec<NodeId>, ScopeExitReport) {
    let store = InMemoryStagingStore::default();
    let me = owner();
    block_on(async {
        for (n, op) in ops.iter().enumerate() {
            stage_op(&store, seal(&me, n as u8), op).await.unwrap();
        }
        let raw = store.queued_ops().await.unwrap();
        let scan = decode_queue(&RecordReader::new(&me), &raw);
        let mut base = granted_scope_tree();
        for (target, parent) in placements {
            with_child(&mut base, *parent, *target, "m.txt", NodeKind::File);
        }
        let report = replay(&base, &base, &scan.mine, GRANTED_ROOTS);
        let triggers = report.scope_exit_triggers.clone();
        let cut = consume_scope_exit_triggers(rotator, &triggers).await;
        (triggers, cut)
    })
}

/// A file at `parent` moved out to `outside`, exiting the granted source.
fn exiting_move(target: NodeId, parent: NodeId, name: &str) -> Op {
    Op::move_node(
        target,
        parent,
        id(6),
        name,
        None,
        1,
        AT,
        ScopeCrossing::ExitsGrantedSource,
    )
}

#[test]
fn a_scope_exit_rotates_the_source_scope_root_at_depth_one_and_at_depth_n() {
    for (parent, depth) in [(id(5), 1), (id(12), 4)] {
        let rotator = RecordingRotator::refusing(&[]);
        let (triggers, cut) = exits_of(
            &[(id(7), parent)],
            &[exiting_move(id(7), parent, "m.txt")],
            &rotator,
        );

        assert_eq!(
            triggers,
            vec![id(5)],
            "a move out of depth {depth} names the granted scope root, not its parent"
        );
        assert_eq!(*rotator.seen.borrow(), vec![id(5)]);
        assert!(cut.is_complete());
    }
}

#[test]
fn many_ops_exiting_one_scope_rotate_it_exactly_once() {
    let rotator = RecordingRotator::refusing(&[]);
    let placements = [(id(7), id(5)), (id(8), id(11)), (id(9), id(12))];
    let ops: Vec<Op> = placements
        .into_iter()
        .enumerate()
        .map(|(n, (target, parent))| exiting_move(target, parent, &format!("m{n}.txt")))
        .collect();

    let (triggers, cut) = exits_of(&placements, &ops, &rotator);

    assert_eq!(triggers, vec![id(5)], "three exits, one source scope root");
    assert_eq!(*rotator.seen.borrow(), vec![id(5)]);
    assert_eq!(cut.rotated.len(), 1);
}

#[test]
fn an_intra_scope_move_rotates_nothing() {
    let rotator = RecordingRotator::refusing(&[]);
    let (triggers, cut) = exits_of(
        &[(id(7), id(12))],
        &[Op::move_node(
            id(7),
            id(12),
            id(11),
            "m.txt",
            None,
            1,
            AT,
            ScopeCrossing::Intra,
        )],
        &rotator,
    );

    assert!(triggers.is_empty(), "the non-trigger list holds");
    assert!(rotator.seen.borrow().is_empty());
    assert!(cut.is_complete());
}

/// Structurally, only a relocation carries a scope crossing: every other op kind
/// answers `None` to `scope_exit_source`. Named here so the non-trigger list is
/// asserted rather than merely true.
#[test]
fn create_delete_rename_and_content_edits_rotate_nothing() {
    let base = granted_scope_tree();
    let cases: [(&str, Op); 4] = [
        (
            "create",
            Op::create(
                id(7),
                id(12),
                "new.txt",
                NewNode::File { content: None },
                1,
                AT,
            ),
        ),
        ("delete", Op::delete(id(12), 1, AT, 1)),
        ("rename", Op::rename(id(12), "renamed", 1, AT)),
        (
            "update-content",
            Op::update_content(id(12), staged(b"edit"), None, 1, AT),
        ),
    ];

    for (label, op) in cases {
        let report = replay(&base, &base, &[(OpId(1), op)], GRANTED_ROOTS);
        assert!(
            report.scope_exit_triggers.is_empty(),
            "{label} queues no scope-exit trigger"
        );
    }
}

/// An op whose relocation is already reflected in gate-passing state published
/// nothing — but the node **has** left the granted source, so the rotation is
/// still owed. Dropping it there would leave a revokee holding a live seed.
#[test]
fn a_scope_exit_already_reflected_in_gate_passing_state_still_rotates() {
    let rotator = RecordingRotator::refusing(&[]);
    // Seeded at the destination: the move is already satisfied on replay.
    let (triggers, cut) = exits_of(
        &[(id(7), id(6))],
        &[exiting_move(id(7), id(12), "m.txt")],
        &rotator,
    );

    assert_eq!(triggers, vec![id(5)], "the exit is a fact, not a no-op");
    assert_eq!(*rotator.seen.borrow(), vec![id(5)]);
    assert!(cut.is_complete());
}

/// The enclosing-root fallback in the full-depth walk exists so an applied exit
/// always cuts *something*. A drop is not evidence this op performed the exit,
/// so a source folder a co-writer has since deleted must not escalate into a cut
/// of the vault root — a whole-vault wave on demand.
#[test]
fn an_already_satisfied_drop_whose_source_is_gone_rotates_nothing() {
    let rotator = RecordingRotator::refusing(&[]);
    // id(13) is in no snapshot: the walk finds no listed scope root above it.
    let (triggers, cut) = exits_of(
        &[(id(7), id(6))],
        &[exiting_move(id(7), id(13), "m.txt")],
        &rotator,
    );

    assert!(triggers.is_empty(), "no vault-root cut from a dropped op");
    assert!(rotator.seen.borrow().is_empty());
    assert!(cut.is_complete());
}

#[test]
fn a_failed_scope_exit_rotation_surfaces_and_keeps_its_trigger() {
    let rotator = RecordingRotator::refusing(&[id(5)]);
    let (triggers, cut) = exits_of(
        &[(id(7), id(12))],
        &[exiting_move(id(7), id(12), "m.txt")],
        &rotator,
    );

    assert_eq!(triggers, vec![id(5)]);
    assert!(cut.rotated.is_empty());
    assert_eq!(
        cut.failed.iter().map(|(root, _)| *root).collect::<Vec<_>>(),
        vec![id(5)],
        "the trigger comes back rather than being swallowed"
    );
    assert!(!cut.is_complete());
}
