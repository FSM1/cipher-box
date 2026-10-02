//! The tick pass driven end to end through the Engine harness.

use super::*;
use crate::sync::pass::{ConsultWindow, consult_pointers};
use crate::sync::pointer::{scope_pointer_name, scope_pointer_signer};

/// Persist one received-share bookmark into this device's durable list,
/// the state an accept leaves behind.
fn bookmark_a_received_share(device: &FakeDevice) {
    bookmark_a_received_share_labelled(device, "shared-folder");
}

/// Publish an owner-signed re-point at `SCOPE`'s **scope**-pointer name
/// vouching `write_epoch` — the plane a write-only rotation re-points,
/// and the one the polled consult reads.
fn seed_scope_pointer(device: &FakeDevice, root_name: &IpnsName, write_epoch: u64) {
    let owner_seed = kdf::owner_pointer_seed(&CAP_SECRET);
    let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &SCOPE);
    let mut entropy = SeededEntropy::new(3);
    let block = seal_repoint(
        SessionRole::Owner,
        &mut entropy,
        read_key.as_bytes(),
        POINTER_PAYLOAD_VERSION,
        &owner_identity(),
        &RepointObject {
            scope_id: SCOPE,
            current_root: root_name.clone(),
            write_epoch,
            min_read_epoch: EPOCH,
            prev_root: None,
        },
    )
    .unwrap();
    let record = IpnsRecord::create_v2(
        &scope_pointer_signer(owner_seed.as_bytes(), &SCOPE),
        &block,
        1,
        TTL_NANOS,
        EOL,
    )
    .marshal();
    let pointer_name = scope_pointer_name(owner_seed.as_bytes(), &SCOPE);
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, pointer_name.as_str(), record.clone());
    }
}

#[test]
fn resolve_tick_loop_populates_the_held_set() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (head_block, head_cid, root_name) = owner_root();
    // Vault pointer present (the root name is known and floors cold-seed),
    // but no root record at boot: cold start resolves NoUpdate, so the
    // sequence floor stays unset and the tick's later resolve is a fresh,
    // gate-passing Adopt that surfaces the owner write seed.
    seed_vault_pointer(&device, &root_name);
    let (mut engine, _events) = engine_on(&device);
    block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()), None)).unwrap();
    assert!(
        engine.state.held_records.borrow().is_empty(),
        "nothing held until the record appears"
    );

    // The record appears; drive one resolve-tick interval.
    for endpoint in device.record_store.endpoints() {
        seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
    }
    device.http.enqueue_response(head_response(&head_block));

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_once(&mut tasks); // park each loop at its first sleep
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_tasks_once(&mut tasks); // the resolve tick runs one pass

    let held = engine.state.held_records.borrow();
    assert_eq!(held.len(), 1, "the resolve tick held the owner root");
    let record = held
        .get(&HeldKey::Node(ROOT.0))
        .expect("held under the root node id");
    assert_eq!(record.routing_key, root_name.as_str());
    assert_eq!(
        cached_seed(&engine.state.scope_read_seeds, &SCOPE).map(|s| *s),
        Some(SCOPE_SEED),
        "the tick adopt deposited the recovered scope read seed"
    );
}

/// The refresh stamps live for the session, so the pass that closes a
/// quiet focus window also drops the stamps the staleness threshold has
/// expired. Without that, a host walking a large vault grows the map for
/// as long as the session runs.
#[test]
fn the_tick_drops_the_refresh_stamps_the_threshold_expired() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);

    let walked: Vec<NodeId> = (0..64u8).map(|i| NodeId([i; 16])).collect();
    {
        let now = engine.seams.scheduler.now();
        let mut stamps = engine.state.focus_refreshed.borrow_mut();
        for node in &walked {
            stamps.insert(*node, now);
        }
    }
    world.scheduler.advance(SyncTimingProfile::CI.stale_after);
    let fresh = NodeId([200; 16]);
    engine
        .state
        .focus_refreshed
        .borrow_mut()
        .insert(fresh, engine.seams.scheduler.now());

    tick(&world, &device, &mut tasks);

    assert_eq!(
        engine
            .state
            .focus_refreshed
            .borrow()
            .keys()
            .copied()
            .collect::<Vec<NodeId>>(),
        vec![fresh],
        "one pass holds only the stamps of the last window",
    );
}

/// A forged owner-root record is fail-closed either way; without an event
/// a persistent forgery is indistinguishable from an idle vault.
#[test]
fn a_persistently_forged_steady_state_record_raises_an_abuse_event() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (_, head_cid, root_name) = owner_root();
    let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
    let adopted = block_on(engine.view()).unwrap().children(ROOT);
    let _ = drain(&mut events);

    // A strictly newer record whose signed head anchor the served block
    // does not address: fail-closed at assembly, on every poll.
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, root_name.as_str(), root_record(&head_cid, 2));
    }
    for _ in 0..2 {
        device
            .http
            .enqueue_response(head_response(b"forged head block"));
        world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
        poll_tasks_once(&mut tasks);

        let abuse: Vec<String> = drain(&mut events)
            .into_iter()
            .filter_map(|event| match event {
                Event::AttributableAbuse { description } => Some(description),
                _ => None,
            })
            .collect();
        assert_eq!(abuse.len(), 1, "every forged poll raises one abuse event");
        assert!(
            abuse[0].contains("content-cid-mismatch"),
            "the event names the check that rejected it: {}",
            abuse[0]
        );
        assert!(
            !abuse[0].contains(root_name.as_str()),
            "and withholds the live handle it rejected: {}",
            abuse[0]
        );
    }
    assert_eq!(
        block_on(engine.view()).unwrap().children(ROOT),
        adopted,
        "and the forgery still never renders"
    );
}

/// An idle vault re-fetching its own unchanged record must not re-open
/// the owner blobs and re-insert the hold on every poll.
#[test]
fn a_steady_state_poll_neither_re_recovers_nor_re_holds() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);

    tick(&world, &device, &mut tasks);
    assert_eq!(
        engine.state.held_records.borrow().len(),
        1,
        "the first steady-state poll recovers the write seed and holds"
    );
    // Stamp the entry: a re-hold rebuilds it wholesale, so the stamp
    // surviving is the observable proof that no re-hold ran.
    engine
        .state
        .held_records
        .borrow_mut()
        .get_mut(&HeldKey::Node(ROOT.0))
        .expect("held under the root node id")
        .content_cids = vec!["bafystamp".to_owned()];

    tick(&world, &device, &mut tasks);
    assert_eq!(
        engine.state.held_records.borrow()[&HeldKey::Node(ROOT.0)].content_cids,
        vec!["bafystamp".to_owned()],
        "the next poll left the hold alone"
    );
    assert_eq!(
        cached_seed(&engine.state.scope_write_seeds, &SCOPE).map(|s| *s),
        Some(WRITE_SCOPE_SEED),
        "and the material recovered once stays in hand"
    );
}

/// The drain is the only source of a head's content CIDs, so a re-hold
/// that carries none must keep the set the publish registered.
#[test]
fn a_re_hold_keeps_the_content_cids_the_publish_registered() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (_, head_cid, root_name) = owner_root();
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);

    let published = vec!["bafypublished".to_owned()];
    let before = {
        let mut held = engine.state.held_records.borrow_mut();
        let record = held
            .get_mut(&HeldKey::Node(ROOT.0))
            .expect("held under the root node id");
        record.content_cids.clone_from(&published);
        record.record_bytes.clone()
    };

    // A strictly newer record over the same head: an `Adopted` poll,
    // which rebuilds the hold wholesale rather than skipping it.
    let reseed = |sequence| {
        for endpoint in device.record_store.endpoints() {
            device.record_store.seed_record(
                &endpoint,
                root_name.as_str(),
                root_record(&head_cid, sequence),
            );
        }
    };
    reseed(2);
    tick(&world, &device, &mut tasks);
    let held = engine.state.held_records.borrow();
    assert_ne!(
        held[&HeldKey::Node(ROOT.0)].record_bytes,
        before,
        "the poll really did re-hold, so the assertion below is not vacuous"
    );
    assert_eq!(
        held[&HeldKey::Node(ROOT.0)].content_cids,
        published,
        "the re-hold carried the published set forward"
    );
    drop(held);

    // Stamped against a head this device did not author: that block set
    // is superseded, so it must not ride the new head's renewal.
    engine
        .state
        .held_records
        .borrow_mut()
        .get_mut(&HeldKey::Node(ROOT.0))
        .expect("held under the root node id")
        .value = HeldValue::Head("bafyotherhead".to_owned());
    reseed(3);
    tick(&world, &device, &mut tasks);
    assert!(
        engine.state.held_records.borrow()[&HeldKey::Node(ROOT.0)]
            .content_cids
            .is_empty(),
        "CIDs held for a different head are dropped, not carried over"
    );
}

/// A promotion the last boundary walk could not re-prove keeps its place
/// in the proved set and loses its seed, so a folder in view under it
/// stays unread. The pass must charge itself for that rather than
/// answering a forced refresh with a window it never read.
#[test]
fn a_folder_under_a_scope_this_pass_cannot_read_fails_the_forced_refresh() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);

    let promoted = NodeId([0xD1; 16]);
    let inside = NodeId([0xD2; 16]);
    {
        let mut base = engine.state.snapshot.borrow_mut();
        base.upsert_node(NodeMeta::new(promoted, "promoted", NodeKind::Folder));
        base.upsert_node(NodeMeta::new(inside, "inside", NodeKind::Folder));
        base.link(ROOT, promoted, 1);
        base.link(promoted, inside, 1);
    }
    engine
        .state
        .descendant_scope_roots
        .borrow_mut()
        .insert(promoted);
    assert!(
        !engine
            .state
            .scope_read_seeds
            .borrow()
            .contains_key(&promoted.0),
        "the walk that dropped the seed left the promotion proved"
    );
    engine.note_focus_access(Some(inside));

    let forced = engine
        .file_forced_pass()
        .expect("a tick loop is running")
        .expect("the pass is filed");
    let mut landed = Box::pin(forced.landed());
    tick(&world, &device, &mut tasks);

    assert!(
        matches!(
            landed
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(EngineError::RefreshFailed { .. }))
        ),
        "a scope the pass could not read is an outage, not a refreshed window"
    );
}

/// A boundary the walk named and proved no material for is an outage on
/// its own leg, not abuse, and nothing under it is read
/// ([`focus_scope_roots`]).
#[test]
fn a_row_under_a_boundary_the_walk_could_not_prove_is_not_read_as_abuse() {
    // The boundary's own material, which this session never proved.
    const OTHER_WRITE_SEED: [u8; 32] = [0x5A; 32];
    const OTHER_READ_SEED: [u8; 32] = [0x5B; 32];
    let unproved = NodeId([0xE1; 16]);
    let row = NodeId([0xE2; 16]);

    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);
    let _ = drain(&mut events);

    // Both records are sealed at the boundary's own scope and published
    // under its own write seed — the shape of every record below a
    // promoted root.
    let publish = |node: NodeId, body: &ReadBody| {
        let node_seed = kdf::node_seed(&OTHER_READ_SEED, &node.0);
        let envelope = seal_read_body(
            kdf::read_key(node_seed.as_bytes()).as_bytes(),
            &[node.0[0]; 24],
            1,
            node.0,
            unproved.0,
            EPOCH,
            body,
        )
        .expect("the body seals");
        let head_block = encode_envelope(&envelope).expect("the envelope encodes");
        let head_cid = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, &head_block));
        let name = derive_write_name(&OTHER_WRITE_SEED, &node.0);
        let record = IpnsRecord::create_v2(
            &kdf::ipns_keypair(kdf::write_seed(&OTHER_WRITE_SEED, &node.0).as_bytes()),
            format!("/ipfs/{head_cid}").as_bytes(),
            1,
            TTL_NANOS,
            EOL,
        )
        .marshal();
        for endpoint in device.record_store.endpoints() {
            device
                .record_store
                .seed_record(&endpoint, name.as_str(), record.clone());
        }
        (name, head_block)
    };
    let (folder_name, folder_head) = publish(
        unproved,
        &ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        },
    );
    let (file_name, file_head) = publish(
        row,
        &ReadBody::File {
            created_at: 0,
            modified_at: 0,
            versions: Vec::new(),
            unknown: PreservedFields::new(),
        },
    );
    {
        let mut base = engine.state.snapshot.borrow_mut();
        let mut folder = NodeMeta::new(unproved, "unproved", NodeKind::Folder);
        folder.ipns_name = Some(folder_name.as_str().as_bytes().to_vec());
        base.upsert_node(folder);
        let mut file = NodeMeta::new(row, "row.txt", NodeKind::File);
        file.ipns_name = Some(file_name.as_str().as_bytes().to_vec());
        base.upsert_node(file);
        base.link(ROOT, unproved, 1);
        base.link(unproved, row, 1);
    }
    engine
        .state
        .unproved_scope_roots
        .borrow_mut()
        .insert(unproved);
    engine.note_focus_access(Some(unproved));

    let forced = engine
        .file_forced_pass()
        .expect("a tick loop is running")
        .expect("the pass is filed");
    let mut landed = Box::pin(forced.landed());
    // Every head block this pass could ask for is served, so a pass that
    // does group these rows onto the vault leg reaches the gate and
    // raises the abuse this test refuses.
    let blocks = Blocks::default();
    let (head_block, _, _) = owner_root();
    for block in [head_block, folder_head, file_head] {
        blocks.put(block);
    }
    serve_http(&device, &blocks, 8);
    world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
    poll_tasks_once(&mut tasks);

    assert!(
        drain(&mut events)
            .into_iter()
            .all(|event| !matches!(event, Event::AttributableAbuse { .. })),
        "the writer is honest; the walk is what failed",
    );
    assert!(
        matches!(
            landed
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(EngineError::RefreshFailed { .. }))
        ),
        "a boundary with no material is an outage on its own leg",
    );
    assert!(
        engine
            .state
            .snapshot
            .borrow()
            .node(row)
            .unwrap()
            .size
            .is_none(),
        "and nothing below it was painted from a record read under \
         another scope's seed",
    );
}

/// A rotation that raises the scope's durable read-epoch floor revokes
/// the epoch the cached seed was recovered under, so the seed goes —
/// least privilege binds retention, not only install.
#[test]
fn a_read_epoch_floor_rise_evicts_the_cached_scope_read_seed() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);
    assert!(engine.state.scope_read_seeds.borrow().contains_key(&SCOPE));

    block_on(
        device
            .floors(&CAP_SECRET)
            .raise_epoch_floor(&SCOPE, EPOCH + 1),
    )
    .unwrap();
    tick(&world, &device, &mut tasks);

    assert!(
        !engine.state.scope_read_seeds.borrow().contains_key(&SCOPE),
        "the seed recovered below the new floor is evicted"
    );
    assert!(
        engine.state.scope_write_seeds.borrow().contains_key(&SCOPE),
        "the write-epoch floor is a separate clock and did not move"
    );
}

/// The residual a write-only rotation leaves: it raises no read epoch, so
/// it mints no superseded scope root for the sweep's event-driven consult
/// — the polled tick leg is what advances the write-epoch floor, and with
/// it evicts the `writeScopeSeed` that rotation retired.
#[test]
fn the_focus_tick_consults_the_scope_pointer_and_advances_the_write_epoch_floor() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);
    assert!(engine.state.scope_write_seeds.borrow().contains_key(&SCOPE));

    let (_, _, root_name) = owner_root();
    seed_scope_pointer(&device, &root_name, EPOCH + 1);
    tick(&world, &device, &mut tasks);

    assert_eq!(
        block_on(floor::write_epoch_floor(
            &device.floors(&CAP_SECRET),
            &SCOPE
        ))
        .unwrap(),
        Some(EPOCH + 1),
        "the polled consult advanced the write-epoch floor on sight",
    );
    assert!(
        !engine.state.scope_write_seeds.borrow().contains_key(&SCOPE),
        "and the seed the rotation retired is evicted in the same pass",
    );
    assert!(
        engine.state.pointer_consulted.borrow().contains_key(&ROOT),
        "the pass stamped the consult, so the interval damper can pace it",
    );
}

/// The anchor's scope pointer is the only owner-vouched plane naming the
/// vault's current root. A pass that sights a re-point reports the moved
/// root, so the rest of the pass reads and publishes there rather than at
/// the name cold start opened with.
#[test]
fn the_anchor_consult_reports_the_root_its_pointer_vouches() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);

    let moved = child_name();
    seed_scope_pointer(&device, &moved, EPOCH + 1);
    let (events, _rx) = mpsc::unbounded();
    let consult = |anchor| {
        block_on(consult_pointers(
            &device.record_store,
            &device.floors(&CAP_SECRET),
            &engine.secrets.sweep_keys,
            &events,
            &RefCell::new(BTreeMap::new()),
            ConsultWindow {
                scopes: vec![ROOT],
                anchor,
                now: UnixMillis(0),
            },
        ))
    };

    assert_eq!(
        consult(ROOT),
        Some(moved),
        "the anchor's re-point names the root the pass must poll"
    );
    assert_eq!(
        consult(NodeId([0x9e; 16])),
        None,
        "a shared scope's root is its own, and never the vault's"
    );
}

/// And the pass acts on it: every later leg — the gated resolve, the
/// held set the liveness loop renews, the drain — addresses the moved
/// root, not the name cold start opened with.
#[test]
fn a_tick_that_sights_a_repoint_resolves_the_moved_root() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (_, head_cid, root_name) = owner_root();
    let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);
    assert_eq!(
        engine.state.held_records.borrow()[&HeldKey::Node(ROOT.0)].routing_key,
        root_name.as_str(),
        "cold start opened at the name the vault pointer gave it"
    );

    // The anchor's pointer names a moved root, and a record answers there.
    let moved = child_name();
    seed_scope_pointer(&device, &moved, EPOCH + 1);
    for endpoint in device.record_store.endpoints() {
        device.record_store.seed_record(
            &endpoint,
            moved.as_str(),
            root_record_at_node(CHILD_ID, &head_cid, 1),
        );
    }
    let _ = drain(&mut events);
    tick(&world, &device, &mut tasks);

    // The record answering there is bound to the name it moved off, so
    // the gate refuses it. Only the moved record trips that check, and
    // the name cold start opened with resolves clean — so one refusal
    // naming it is what proves where this pass went.
    let abuse: Vec<String> = drain(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            Event::AttributableAbuse { description } => Some(description),
            _ => None,
        })
        .collect();
    assert_eq!(abuse.len(), 1, "one verdict on the one root resolved");
    assert!(
        abuse[0].contains("commitment-invalid"),
        "the pass resolved the root its anchor pointer named: {}",
        abuse[0]
    );
    assert_ne!(
        engine.state.held_records.borrow()[&HeldKey::Node(ROOT.0)].routing_key,
        moved.as_str(),
        "and a gate refusal holds nothing (fail-closed)"
    );
}

/// The `/shared` read: the durable bookmark's key-free fields, and the
/// verdict only a pass that actually resolved the scope root can supply.
/// A share nothing has resolved yet reports no verdict at all — a host
/// must not paint that as "still granted".
#[test]
fn received_shares_carry_no_verdict_until_a_pass_reaches_one() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    bookmark_a_received_share(&device);

    let before = block_on(engine.received_shares()).expect("the list reads");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].display_name, "shared-folder");
    assert_eq!(before[0].scope, NodeId(SHARED_SCOPE));
    assert_eq!(before[0].permission, Permission::Read);
    assert_eq!(
        before[0].resolution, None,
        "no pass has resolved this scope root yet"
    );

    tick(&world, &device, &mut tasks);

    let after = block_on(engine.received_shares()).expect("the list reads");
    assert_eq!(
        after[0].resolution,
        Some(ResolutionClass::Unresolvable),
        "a scope root nothing answers at is unresolvable, never a revocation",
    );
}

/// The write-epoch floor is the same rule on the seed the drain mints
/// every new node's name and signer from.
#[test]
fn a_write_epoch_floor_rise_evicts_the_cached_scope_write_seed() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);
    assert!(engine.state.scope_write_seeds.borrow().contains_key(&SCOPE));

    block_on(floor::advance_write_epoch_on_sight(
        &device.floors(&CAP_SECRET),
        &SCOPE,
        EPOCH + 1,
    ))
    .unwrap();
    tick(&world, &device, &mut tasks);

    assert!(
        !engine.state.scope_write_seeds.borrow().contains_key(&SCOPE),
        "the seed recovered below the new write floor is evicted"
    );
    assert!(
        engine.state.scope_read_seeds.borrow().contains_key(&SCOPE),
        "and the read seed, whose floor did not move, stays"
    );
}

#[test]
fn staleness_rungs_transition_and_emit_once_per_change() {
    use core::time::Duration;

    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (head_block, head_cid, root_name) = owner_root();
    seed_vault_pointer(&device, &root_name);
    for endpoint in device.record_store.endpoints() {
        seed_root_record_at(&device, &endpoint, &root_name, &head_cid);
    }
    device.http.enqueue_response(head_response(&head_block));
    let (mut engine, mut events) = engine_on(&device);
    block_on(engine.start(LoginSecret::new(CAP_SECRET.to_vec()), None)).unwrap();
    assert_eq!(
        drain(&mut events),
        vec![Event::SnapshotUpdated],
        "cold start paints once and stamps last_success"
    );

    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_once(&mut tasks); // park each loop at its first sleep

    // CI profile: 1 s poll, 3 s stale_after. With no reachable head
    // block, each tick fails to reconcile and last_success stays at 0.
    world.scheduler.advance(Duration::from_secs(1));
    poll_tasks_once(&mut tasks);
    assert_eq!(
        drain(&mut events),
        vec![Event::StalenessChanged {
            level: Staleness::Fresh
        }],
        "the first classified rung is reported"
    );
    world.scheduler.advance(Duration::from_secs(1));
    poll_tasks_once(&mut tasks);
    assert_eq!(drain(&mut events), vec![], "no re-emit within a rung");
    world.scheduler.advance(Duration::from_secs(1)); // t=3 s ≥ stale_after
    poll_tasks_once(&mut tasks);
    assert_eq!(
        drain(&mut events),
        vec![Event::StalenessChanged {
            level: Staleness::Stale
        }]
    );
    world.scheduler.advance(Duration::from_secs(1));
    poll_tasks_once(&mut tasks);
    assert_eq!(drain(&mut events), vec![], "stale reported exactly once");

    // The record plane recovers with a newer root: the adopt stamps
    // last_success and the rung steps back to Fresh.
    for endpoint in device.record_store.endpoints() {
        device
            .record_store
            .seed_record(&endpoint, root_name.as_str(), root_record(&head_cid, 2));
    }
    device.http.enqueue_response(head_response(&head_block));
    world.scheduler.advance(Duration::from_secs(1));
    poll_tasks_once(&mut tasks);
    assert_eq!(
        drain(&mut events),
        vec![
            Event::SnapshotUpdated,
            Event::StalenessChanged {
                level: Staleness::Fresh
            },
        ],
        "a reconciled tick repaints and steps the ladder back to Fresh"
    );

    // The read surface classifies off the same state.
    let view = block_on(engine.snapshot(ROOT)).unwrap();
    assert_eq!(view.staleness, Staleness::Fresh);
}

/// A host reads the ladder at any instant, so the in-flight rung is one it can
/// hold. The pass that then converges must tell the host the rung moved on, or
/// its indicator reads reconciling with nothing left to supersede it.
#[test]
fn a_rung_read_mid_pass_is_superseded_when_the_pass_converges() {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);
    assert!(drain(&mut events).contains(&Event::StalenessChanged {
        level: Staleness::Fresh
    }));

    let (_, _, root_name) = owner_root();
    device
        .record_store
        .stall_gets_for_after(root_name.as_str(), 0);
    tick(&world, &device, &mut tasks);
    assert_eq!(
        block_on(engine.status()).unwrap().staleness,
        Staleness::Reconciling,
        "the host reads the pass in flight"
    );

    device.record_store.release_gets_for(root_name.as_str());
    poll_tasks_once(&mut tasks);
    assert_eq!(
        drain(&mut events),
        vec![Event::StalenessChanged {
            level: Staleness::Fresh
        }],
        "the converged pass supersedes the rung the host read"
    );
}

/// A pass whose read never answers must not hold a manual refresh, or the
/// indicator a host read mid-pass, past one refresh deadline.
#[test]
fn a_manual_refresh_a_stalled_pass_holds_fails_within_one_deadline() {
    use core::time::Duration;

    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, mut events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);

    let (_, _, root_name) = owner_root();
    device
        .record_store
        .stall_gets_for_after(root_name.as_str(), 0);
    let deadline = engine.profile().refresh_deadline;
    let mut cx = Context::from_waker(Waker::noop());
    let forced = engine
        .file_forced_pass()
        .expect("a tick loop is running")
        .expect("the pass is filed");
    let mut landed = Box::pin(forced.landed());
    poll_tasks_once(&mut tasks); // the forced pass starts, and stalls on the root
    assert_eq!(
        block_on(engine.status()).unwrap().staleness,
        Staleness::Reconciling,
        "the host reads the pass in flight"
    );
    let _ = drain(&mut events);

    world.scheduler.advance(deadline - Duration::from_millis(1));
    poll_tasks_once(&mut tasks);
    assert!(landed.as_mut().poll(&mut cx).is_pending());
    assert_eq!(
        drain(&mut events),
        vec![],
        "inside the deadline nothing changes"
    );

    world.scheduler.advance(Duration::from_millis(1));
    poll_tasks_once(&mut tasks);
    assert!(
        matches!(
            landed.as_mut().poll(&mut cx),
            Poll::Ready(Err(EngineError::RefreshFailed { .. }))
        ),
        "the refresh reports a failure once the deadline passes"
    );
    assert!(
        matches!(
            drain(&mut events).as_slice(),
            [Event::StalenessChanged { level }] if *level != Staleness::Reconciling
        ),
        "at the same instant, the host is told the rung left reconciling"
    );
}

/// A refresh filed behind a stalled poll pass waits for no pass start: it
/// fails at that pass's deadline.
#[test]
fn a_manual_refresh_behind_a_stalled_poll_pass_fails_at_its_deadline() {
    use core::time::Duration;

    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (engine, _events, mut tasks) = started_and_parked(&world, &device);
    tick(&world, &device, &mut tasks);

    let (_, _, root_name) = owner_root();
    device
        .record_store
        .stall_gets_for_after(root_name.as_str(), 0);
    world.scheduler.advance(SyncTimingProfile::CI.poll_cadence);
    poll_tasks_once(&mut tasks); // the poll pass starts, and stalls on the root

    let mut cx = Context::from_waker(Waker::noop());
    let forced = engine
        .file_forced_pass()
        .expect("a tick loop is running")
        .expect("the pass is filed");
    let mut landed = Box::pin(forced.landed());
    assert!(landed.as_mut().poll(&mut cx).is_pending());

    world
        .scheduler
        .advance(engine.profile().refresh_deadline - Duration::from_millis(1));
    poll_tasks_once(&mut tasks);
    assert!(landed.as_mut().poll(&mut cx).is_pending());

    world.scheduler.advance(Duration::from_millis(1));
    poll_tasks_once(&mut tasks);
    assert!(matches!(
        landed.as_mut().poll(&mut cx),
        Poll::Ready(Err(EngineError::RefreshFailed { .. }))
    ));
}
