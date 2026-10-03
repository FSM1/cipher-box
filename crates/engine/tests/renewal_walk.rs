//! The renewal walk (ADR 0061), end to end on the virtual clock: one device
//! writes and ends its session, and a session that starts later renews each
//! name the walk reaches, through the adoption gate, at `S + 1`.

use core::cell::RefCell;
use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    ChildRef, NodeKind as CoreNodeKind, PreservedFields, ReadBody, decode_envelope, open_read_body,
};

use cipherbox_engine::net::author::{EnvelopeAuthoring, author_child_envelope};
use cipherbox_engine::net::eol::{eol_from, renewal_eol_from};
use cipherbox_engine::net::renewal_walk::WALK_BUDGET;
use cipherbox_engine::net::renewal_walk::cursor::{
    CursorStore, MAX_CURSOR_PATH, RENEWAL_CURSOR_PREFIX, RenewalCursor,
};
use cipherbox_engine::net::retire::{NODE_TOMBSTONE_PREFIX, StagingRetireLedger};
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, HttpMethod, HttpRequest, HttpResponse, RecordTransport, Scheduler,
    SnapshotCache, StagingStore, UnixMillis,
};
use cipherbox_engine::sync::{BookkeepingSeal, doomed_journal_key, owner_tag};
use cipherbox_engine::testkit::account::{Blocks, SCOPE, SECRET, floor_label, seed_account};
use cipherbox_engine::testkit::fakes::InMemoryStagingStore;
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, Command, ContentProfile, Engine, Event, EventStream, GatewayConfig, LoginSecret,
    NodeId, NodeKind, StoragePolicy, SyncTimingProfile, WriteTarget,
};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const ROOT: NodeId = NodeId([0u8; 16]);

fn engine_on(device: &FakeDevice, entropy_seed: u64) -> (Engine<FakeSeamTypes>, EventStream) {
    Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(entropy_seed)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        ApiBaseUrl::parse("http://api.test").expect("a base"),
        GatewayConfig {
            accelerator: Some("https://gw.test".into()),
            public_fallbacks: Vec::new(),
        },
    )
}

/// Answer `calls` API requests from the block plane, and run `hook` on each
/// request first.
fn serve_with(
    device: &FakeDevice,
    blocks: &Blocks,
    calls: usize,
    hook: impl Fn(&HttpRequest) + Send + Sync + 'static,
) {
    let hook = Arc::new(hook);
    for _ in 0..calls {
        let (blocks, hook) = (blocks.clone(), hook.clone());
        device.http.enqueue_derived(move |request| {
            hook(request);
            blocks.reply(request)
        });
    }
}

/// A started session on `device`, its loops parked at their first sleep.
fn boot(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    serve_with(device, blocks, 4000, |_| {});
    boot_served(world, device, entropy_seed)
}

fn boot_served(
    world: &FakeWorld,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (mut engine, events) = engine_on(device, entropy_seed);
    block_on(engine.start(LoginSecret::new(SECRET.to_vec()), None)).expect("the session starts");
    let mut tasks = world.scheduler.take_spawned_tasks();
    poll_tasks_until_parked(&mut tasks);
    (engine, events, tasks)
}

fn tick(world: &FakeWorld, engine: &Engine<FakeSeamTypes>, tasks: &mut [BoxedTask]) {
    world.scheduler.advance(engine.profile().poll_cadence);
    poll_tasks_until_parked(tasks);
}

fn child_named(engine: &Engine<FakeSeamTypes>, parent: NodeId, name: &str) -> NodeId {
    block_on(engine.view())
        .expect("a rendered view")
        .children(parent)
        .into_iter()
        .find(|child| child.name == name)
        .unwrap_or_else(|| panic!("no child named {name}"))
        .id
}

fn create_folder(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    parent: NodeId,
    name: &str,
) -> NodeId {
    block_on(engine.command(Command::Create {
        parent,
        name: name.into(),
        kind: NodeKind::Folder,
    }))
    .expect("a create stages");
    tick(world, engine, tasks);
    child_named(engine, parent, name)
}

fn write_file(
    world: &FakeWorld,
    engine: &mut Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
    parent: NodeId,
    name: &str,
) -> NodeId {
    let body = b"a note nobody opens again";
    let handle = block_on(engine.begin_write(
        WriteTarget::NewFile {
            parent,
            name: name.into(),
        },
        body.len() as u64,
    ))
    .expect("a write opens");
    block_on(engine.push_chunk(handle, body)).expect("the chunk stages");
    block_on(engine.commit_write(handle)).expect("the write commits");
    tick(world, engine, tasks);
    child_named(engine, parent, name)
}

/// A node's name under the vault's own write scope seed.
fn write_name(node: NodeId) -> IpnsName {
    IpnsName::from_public_key(
        &kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes()).verifying_key(),
    )
}

fn record_at(world: &FakeWorld, name: &IpnsName) -> VerifiedRecord {
    let bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .expect("a record is published at the name");
    IpnsRecord::unmarshal(&bytes)
        .and_then(|record| record.verify(name))
        .expect("the record verifies under its own name")
}

/// One device writes, then its session ends.
fn written_then_left(
    world: &FakeWorld,
    blocks: &Blocks,
    write: impl FnOnce(&mut Engine<FakeSeamTypes>, &mut [BoxedTask]) -> Vec<NodeId>,
) -> Vec<NodeId> {
    seed_account(world, blocks);
    let device = world.device(b"the device that wrote");
    let (mut engine, _events, mut tasks) = boot(world, blocks, &device, 1);
    let nodes = write(&mut engine, &mut tasks);
    drop(tasks);
    drop(engine);
    drop(world.scheduler.take_spawned_tasks());
    nodes
}

/// Run a session until its first renewal walk: the walk waits a poll cadence
/// at a time for the session's first boundary walk, which the first tick runs.
fn until_the_first_walk(
    world: &FakeWorld,
    engine: &Engine<FakeSeamTypes>,
    tasks: &mut [BoxedTask],
) {
    tick(world, engine, tasks);
    tick(world, engine, tasks);
}

/// A later session on a new device, run until its first renewal walk.
fn start_later(
    world: &FakeWorld,
    blocks: &Blocks,
    label: &[u8],
) -> (FakeDevice, Engine<FakeSeamTypes>, Vec<BoxedTask>) {
    let device = world.device(label);
    let (engine, _events, mut tasks) = boot(world, blocks, &device, 2);
    until_the_first_walk(world, &engine, &mut tasks);
    (device, engine, tasks)
}

/// `after` renews `before` at `S + 1` with a validity one day short of a real
/// write signed between `started` and now.
fn assert_renewed_at_start(
    world: &FakeWorld,
    name: &IpnsName,
    before: &VerifiedRecord,
    started: UnixMillis,
    what: &str,
) {
    let after = record_at(world, name);
    assert_eq!(
        after.sequence,
        before.sequence + 1,
        "{what} renews at S + 1"
    );
    let signed = after.validity.as_slice();
    assert!(
        renewal_eol_from(started).as_bytes() <= signed
            && signed <= renewal_eol_from(world.scheduler.now()).as_bytes(),
        "{what} carries a fresh validity, one day short",
    );
    assert_eq!(
        after.value, before.value,
        "{what} re-points at the same head"
    );
}

/// ADR 0061 consequence 5: a file no session opens or publishes for 65 days is
/// at `S + 1` with a fresh validity after one pass, the only pass a vault of
/// this size needs. The vault root the write republished renews with it.
#[test]
fn a_file_no_session_opens_for_65_days_renews_at_the_next_start() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        vec![write_file(&world, engine, tasks, ROOT, "note.txt")]
    });
    let name = write_name(nodes[0]);
    let before = record_at(&world, &name);
    assert_eq!(
        before.validity,
        eol_from(world.scheduler.now()).into_bytes()
    );
    let root_before = record_at(&world, &write_name(ROOT));

    world.scheduler.advance(DAY * 65);
    let started = world.scheduler.now();
    let (_device, _engine, _tasks) = start_later(&world, &blocks, b"a later session");

    assert_renewed_at_start(&world, &name, &before, started, "the file");
    assert_renewed_at_start(
        &world,
        &write_name(ROOT),
        &root_before,
        started,
        "the vault root",
    );
}

/// `name`'s record at `before`'s sequence, signing `value` under the vault's
/// write seed for `node` with an EOL earlier than any real write's, so the
/// record the endpoints already serve stays the pick.
fn re_signed(node: NodeId, before: &VerifiedRecord, value: &[u8]) -> Vec<u8> {
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes());
    IpnsRecord::create_v2(
        &signer,
        value,
        before.sequence,
        before.ttl,
        &renewal_eol_from(UnixMillis(0)),
    )
    .marshal()
}

/// Serve `record` on the second endpoint and `first` on every other one.
fn serve_forked(world: &FakeWorld, name: &IpnsName, first: &[u8], record: Vec<u8>) {
    for (index, endpoint) in world.record_store.endpoints().iter().enumerate() {
        let bytes = if index == 1 {
            record.clone()
        } else {
            first.to_vec()
        };
        world
            .record_store
            .seed_record(endpoint, name.as_str(), bytes);
    }
}

/// The events a later session on a new device sends up to its first walk.
fn later_session_events(world: &FakeWorld, blocks: &Blocks, label: &[u8]) -> Vec<Event> {
    let device = world.device(label);
    let (engine, mut events, mut tasks) = boot(world, blocks, &device, 2);
    until_the_first_walk(world, &engine, &mut tasks);
    core::iter::from_fn(|| events.try_next()).collect()
}

fn reported(events: &[Event], routing_key: &str) -> (usize, usize) {
    let forks = events
        .iter()
        .filter(|event| {
            matches!(event, Event::SameSequenceFork { routing_key: key } if key == routing_key)
        })
        .count();
    let held = events
        .iter()
        .filter(|event| {
            matches!(event, Event::RenewalFailed { routing_key: key, detail }
                if key == routing_key && detail.contains("same-sequence fork"))
        })
        .count();
    (forks, held)
}

/// A file whose two versions a test re-signs at one sequence: the endpoints
/// serve a gate-passing record of another value beside the first. A device
/// with no floor for the name sees the fork on its first read. With 45 days
/// of EOL left the walk holds the renewal back and reports it; with 25 days
/// left liveness wins and the walk renews over the fork (ADR 0066 D3).
#[test]
fn a_served_fork_holds_the_walk_back_until_the_threshold() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let device = world.device(b"the device that wrote");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 1);
    let file = write_file(&world, &mut engine, &mut tasks, ROOT, "note.txt");
    let name = write_name(file);
    let first_bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .expect("the file is published");
    let first = record_at(&world, &name);
    let body = b"a second note";
    let handle = block_on(engine.begin_write(
        WriteTarget::Version {
            node: file,
            expected_version: None,
        },
        body.len() as u64,
    ))
    .expect("a write opens");
    block_on(engine.push_chunk(handle, body)).expect("the chunk stages");
    block_on(engine.commit_write(handle)).expect("the write commits");
    tick(&world, &engine, &mut tasks);
    let second = record_at(&world, &name);
    assert_eq!(second.sequence, first.sequence + 1);
    drop(tasks);
    drop(engine);
    drop(world.scheduler.take_spawned_tasks());
    serve_forked(
        &world,
        &name,
        &first_bytes,
        re_signed(file, &first, &second.value),
    );

    world.scheduler.advance(DAY * 45);
    let events = later_session_events(&world, &blocks, b"a later session");
    assert_eq!(
        record_at(&world, &name).sequence,
        first.sequence,
        "held at S"
    );
    assert_eq!(reported(&events, name.as_str()), (1, 1));

    world.scheduler.advance(DAY * 20);
    let started = world.scheduler.now();
    later_session_events(&world, &blocks, b"a session inside the threshold");
    assert_renewed_at_start(&world, &name, &first, started, "the forked file");
}

/// A record of the file's own value at its sequence, which a second renewal
/// signs, is no fork: the device that read both renews the name.
#[test]
fn a_tie_of_one_value_does_not_hold_the_walk_back() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let device = world.device(b"the device that wrote");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 1);
    let file = write_file(&world, &mut engine, &mut tasks, ROOT, "note.txt");
    drop(tasks);
    drop(engine);
    drop(world.scheduler.take_spawned_tasks());
    let name = write_name(file);
    let before = record_at(&world, &name);
    world.record_store.seed_record(
        &world.record_store.endpoints()[1],
        name.as_str(),
        re_signed(file, &before, &before.value),
    );

    world.scheduler.advance(DAY * 45);
    let started = world.scheduler.now();
    let (engine, mut events, mut tasks) = boot(&world, &blocks, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);

    assert_renewed_at_start(&world, &name, &before, started, "the file");
    let events: Vec<Event> = core::iter::from_fn(|| events.try_next()).collect();
    assert_eq!(reported(&events, name.as_str()), (0, 0));
}

/// The same at the vault root: with 45 days left no renewal signs over a
/// served fork of the root, and the session reports it, while the file below
/// it still renews.
#[test]
fn no_renewal_signs_over_a_vault_root_the_endpoints_serve_forked() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let device = world.device(b"the device that wrote");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 1);
    let file = write_file(&world, &mut engine, &mut tasks, ROOT, "note.txt");
    let root = write_name(ROOT);
    let first_bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root.as_str())
        .expect("the root is published");
    let first = record_at(&world, &root);
    create_folder(&world, &mut engine, &mut tasks, ROOT, "more");
    let second = record_at(&world, &root);
    assert_eq!(second.sequence, first.sequence + 1);
    drop(tasks);
    drop(engine);
    drop(world.scheduler.take_spawned_tasks());
    serve_forked(
        &world,
        &root,
        &first_bytes,
        re_signed(ROOT, &first, &second.value),
    );
    let file_before = record_at(&world, &write_name(file));

    world.scheduler.advance(DAY * 45);
    let started = world.scheduler.now();
    let events = later_session_events(&world, &blocks, b"a later session");

    assert_eq!(
        record_at(&world, &root).sequence,
        first.sequence,
        "held at S"
    );
    assert_eq!(reported(&events, root.as_str()), (1, 1));
    assert_renewed_at_start(&world, &write_name(file), &file_before, started, "the file");
}

/// A vault root at `S + 1` after two writes, served as the first write's
/// record at `S` on every endpoint 45 days later, with a gate-passing tie of
/// the second write's value at `S`.
fn a_root_left_with_a_tie() -> (FakeWorld, Blocks, IpnsName, Vec<u8>) {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let device = world.device(b"the device that wrote");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 1);
    write_file(&world, &mut engine, &mut tasks, ROOT, "note.txt");
    let root = write_name(ROOT);
    let first_bytes = world
        .record_store
        .record_at(&world.record_store.endpoints()[0], root.as_str())
        .expect("the root is published");
    let first = record_at(&world, &root);
    create_folder(&world, &mut engine, &mut tasks, ROOT, "more");
    let tie = re_signed(ROOT, &first, &record_at(&world, &root).value);
    drop(tasks);
    drop(engine);
    drop(world.scheduler.take_spawned_tasks());
    serve_forked(&world, &root, &first_bytes, first_bytes.clone());
    world.scheduler.advance(DAY * 45);
    (world, blocks, root, tie)
}

/// One endpoint serves a fork of the vault root to a single read, and the
/// renewal walk is that read: the walk holds the renewal back, and the session
/// still sends one fork event for it.
#[test]
fn a_root_fork_only_the_renewal_walk_reads_sends_one_fork_event() {
    // The one GET that serves the tie moves until the walk is its reader.
    let walk_only = (0..64).find_map(|answered| {
        let (world, blocks, root, tie) = a_root_left_with_a_tie();
        world
            .record_store
            .serve_gets_for_after(root.as_str(), answered, 1, Some(tie));
        let events = later_session_events(&world, &blocks, b"a later session");
        let reported = reported(&events, root.as_str());
        (reported.1 == 1).then_some(reported)
    });

    assert_eq!(
        walk_only.expect("one placement of the tie reaches the walk alone"),
        (1, 1)
    );
}

/// A name with more EOL left than the walk window is not renewed.
#[test]
fn a_name_outside_the_walk_window_is_left_alone() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        vec![write_file(&world, engine, tasks, ROOT, "note.txt")]
    });
    let name = write_name(nodes[0]);
    let before = record_at(&world, &name);

    world.scheduler.advance(DAY * 25);
    let (_device, _engine, _tasks) = start_later(&world, &blocks, b"a later session");

    assert_eq!(record_at(&world, &name), before, "65 days left: no renewal");
}

/// The bin index alone names a binned subtree, so the walk roots at each entry.
#[test]
fn a_binned_file_renews_through_its_bin_entry() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        let file = write_file(&world, engine, tasks, ROOT, "binned.txt");
        block_on(engine.command(Command::Delete { node: file })).expect("the delete stages");
        tick(&world, engine, tasks);
        vec![file]
    });
    let name = write_name(nodes[0]);
    let before = record_at(&world, &name);

    world.scheduler.advance(DAY * 65);
    let started = world.scheduler.now();
    let (_device, _engine, _tasks) = start_later(&world, &blocks, b"a later session");

    assert_renewed_at_start(&world, &name, &before, started, "the binned file");
}

/// A folder at depth 64 is deferred and walked later as a root of its own, so
/// the names below the path cap still renew, in the same pass here.
#[test]
fn a_folder_below_the_path_cap_is_deferred_and_still_renews() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        let mut chain = Vec::new();
        let mut parent = ROOT;
        for depth in 2..=MAX_CURSOR_PATH + 1 {
            parent = create_folder(&world, engine, tasks, parent, &format!("d{depth}"));
            chain.push(parent);
        }
        chain.push(write_file(&world, engine, tasks, parent, "deep.txt"));
        chain
    });
    let before: Vec<VerifiedRecord> = nodes
        .iter()
        .map(|node| record_at(&world, &write_name(*node)))
        .collect();

    world.scheduler.advance(DAY * 65);
    let started = world.scheduler.now();
    let (device, _engine, _tasks) = start_later(&world, &blocks, b"a later session");

    for (node, before) in nodes.iter().zip(&before) {
        assert_renewed_at_start(
            &world,
            &write_name(*node),
            before,
            started,
            "a node of the chain",
        );
    }
    let cursor = stored_cursor(&device).expect("the pass stored its cursor");
    // The root is depth 1, so the chain's 63rd folder sits at depth 64.
    let deferred = nodes[MAX_CURSOR_PATH - 2];
    assert_eq!(
        cursor
            .deferred
            .iter()
            .map(|root| root.node_id)
            .collect::<Vec<_>>(),
        vec![deferred.0],
        "the depth-64 folder is the one deferred root",
    );
    assert_eq!(cursor.root, None, "the cycle finished in one pass");
}

/// ADR 0061 D3 step 4: a publish that lands while the walk waits on the
/// registration makes the walk refuse, so the renewal never re-signs the
/// record it admitted over the newer one.
#[test]
fn a_publish_during_the_registration_wait_makes_the_walk_refuse() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        vec![write_file(&world, engine, tasks, ROOT, "raced.txt")]
    });
    let name = write_name(nodes[0]);
    let before = record_at(&world, &name);

    world.scheduler.advance(DAY * 65);
    let now = world.scheduler.now();
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &nodes[0].0).as_bytes());
    let raced = IpnsRecord::create_v2(
        &signer,
        &before.value,
        before.sequence + 1,
        2_000_000_000,
        &eol_from(now),
    )
    .marshal();
    let device = world.device(b"a later session");
    let fired = Arc::new(AtomicBool::new(false));
    let (store, key, hook_fired) = (
        world.record_store.clone(),
        name.as_str().to_owned(),
        fired.clone(),
    );
    serve_with(&device, &blocks, 4000, move |request| {
        if registers(request, &key) && !hook_fired.swap(true, Ordering::SeqCst) {
            for endpoint in store.endpoints() {
                store.seed_record(&endpoint, &key, raced.clone());
            }
        }
    });
    let (engine, _events, mut tasks) = boot_served(&world, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);

    assert!(fired.load(Ordering::SeqCst), "the walk registered the file");
    let after = record_at(&world, &name);
    assert_eq!(after.sequence, before.sequence + 1);
    assert_eq!(
        after.validity,
        eol_from(now).into_bytes(),
        "the publish that raced the walk stands, and nothing signed over it",
    );
}

/// A cut raises the read-epoch floor at once, and the lazy wave re-seals a
/// node only on its next write. The walk still renews a node that lags the
/// floor, and reports nothing for it.
#[test]
fn a_node_the_lazy_wave_has_not_reached_renews_and_reports_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        let file = write_file(&world, engine, tasks, ROOT, "lagging.txt");
        block_on(engine.command(Command::RotateNow { node: ROOT })).expect("the cut lands");
        tick(&world, engine, tasks);
        vec![file]
    });
    let name = write_name(nodes[0]);
    let before = record_at(&world, &name);

    world.scheduler.advance(DAY * 65);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot(&world, &blocks, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);

    assert_renewed_at_start(&world, &name, &before, started, "the lagging file");
    let mut abuse = 0;
    while let Some(event) = events.try_next() {
        if matches!(event, cipherbox_engine::Event::AttributableAbuse { .. }) {
            abuse += 1;
        }
    }
    assert_eq!(abuse, 0, "a lagging node is no violation");
}

/// A walk that parks at depth three resumes past each folder on its path, so a
/// later pass reaches the siblings of an ancestor folder and the cycle closes.
#[test]
fn a_pass_that_parks_below_an_ancestor_resumes_at_that_ancestors_next_sibling() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        let mut folders: Vec<NodeId> = (0..8)
            .map(|at| create_folder(&world, engine, tasks, ROOT, &format!("s{at}")))
            .collect();
        folders.sort();
        let parked_in = create_folder(&world, engine, tasks, folders[0], "a");
        const FANOUT: usize = 24;
        for group in 0..WALK_BUDGET.div_ceil(FANOUT) + 1 {
            let parent = create_folder(&world, engine, tasks, parked_in, &format!("g{group}"));
            for at in 0..FANOUT {
                block_on(engine.command(Command::Create {
                    parent,
                    name: format!("f{at}"),
                    kind: NodeKind::Folder,
                }))
                .expect("a create stages");
            }
            tick(&world, engine, tasks);
        }
        folders
    });
    let siblings = &nodes[1..];
    let before: Vec<VerifiedRecord> = siblings
        .iter()
        .map(|node| record_at(&world, &write_name(*node)))
        .collect();

    world.scheduler.advance(DAY * 65);
    let started = world.scheduler.now();
    let (_device, engine, mut tasks) = start_later(&world, &blocks, b"a later session");
    for _ in 0..4 {
        world.scheduler.advance(Duration::from_secs(60 * 60));
        tick(&world, &engine, &mut tasks);
    }

    for (node, before) in siblings.iter().zip(&before) {
        assert_renewed_at_start(
            &world,
            &write_name(*node),
            before,
            started,
            "a sibling of the ancestor the walk parked below",
        );
    }
}

/// Another writer publishes `folder`'s next record, which also names `ancestor`
/// as a child: a link cycle, which the body decode does not refuse.
fn name_an_ancestor(world: &FakeWorld, blocks: &Blocks, folder: NodeId, ancestor: NodeId) {
    let name = write_name(folder);
    let current = record_at(world, &name);
    let head_cid = core::str::from_utf8(&current.value)
        .expect("utf8 value")
        .strip_prefix("/ipfs/")
        .expect("an /ipfs/ pointer")
        .to_owned();
    let envelope =
        decode_envelope(&blocks.get(&head_cid).expect("the head block")).expect("decodes");
    let read_key =
        *kdf::read_key(kdf::node_seed(&READ_SCOPE_SEED, &folder.0).as_bytes()).as_bytes();
    let ReadBody::Folder {
        created_at,
        modified_at,
        mut children,
        unknown,
    } = open_read_body(&envelope, &read_key).expect("opens")
    else {
        panic!("expected a folder body");
    };
    children.push(ChildRef {
        id: ancestor.0,
        name: "loop".into(),
        ipns_name: write_name(ancestor).as_str().as_bytes().to_vec(),
        kind: CoreNodeKind::Folder,
        link_counter: 1,
        unknown: PreservedFields::new(),
    });
    let head = author_child_envelope(EnvelopeAuthoring {
        node_id: folder.0,
        scope_id: SCOPE,
        epoch: envelope.epoch,
        read_key: &read_key,
        nonce: &[0x3E; 24],
        body: &ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        },
        carried_unknown: envelope.unknown.clone(),
        carried_epoch_tag_unknown: envelope.epoch_tag_unknown.clone(),
    })
    .expect("the other writer authors a valid record");
    blocks.put(head.block.clone());
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &folder.0).as_bytes());
    let record = IpnsRecord::create_v2(
        &signer,
        format!("/ipfs/{}", head.cid).as_bytes(),
        current.sequence + 1,
        current.ttl,
        core::str::from_utf8(&current.validity).expect("an RFC 3339 EOL"),
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// A folder that names its own ancestor closes a link cycle. The walk enters
/// each folder once for each pass, so the pass that meets the cycle finishes it.
#[test]
fn a_link_cycle_ends_in_the_pass_that_meets_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        let outer = create_folder(&world, engine, tasks, ROOT, "outer");
        vec![outer, create_folder(&world, engine, tasks, outer, "inner")]
    });
    name_an_ancestor(&world, &blocks, nodes[1], nodes[0]);

    world.scheduler.advance(DAY * 65);
    let (device, _engine, _tasks) = start_later(&world, &blocks, b"a later session");

    let cursor = stored_cursor(&device).expect("the pass stored its cursor");
    assert_eq!(cursor.root, None, "the cycle finished in one pass");
    assert!(cursor.deferred.is_empty(), "the cycle defers no folder");
}

/// Another writer publishes `node`'s next record at `epoch`, under a read key
/// no session holds: the record a cut at `epoch` seals under its fresh seed.
fn seal_above(world: &FakeWorld, blocks: &Blocks, node: NodeId, epoch: u64) {
    let name = write_name(node);
    let current = record_at(world, &name);
    let head = author_child_envelope(EnvelopeAuthoring {
        node_id: node.0,
        scope_id: SCOPE,
        epoch,
        read_key: &[0x5C; 32],
        nonce: &[0x3F; 24],
        body: &ReadBody::Folder {
            created_at: 0,
            modified_at: 0,
            children: Vec::new(),
            unknown: PreservedFields::new(),
        },
        carried_unknown: PreservedFields::new(),
        carried_epoch_tag_unknown: PreservedFields::new(),
    })
    .expect("the other writer authors a valid record");
    blocks.put(head.block.clone());
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes());
    let record = IpnsRecord::create_v2(
        &signer,
        format!("/ipfs/{}", head.cid).as_bytes(),
        current.sequence + 1,
        current.ttl,
        core::str::from_utf8(&current.validity).expect("an RFC 3339 EOL"),
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), record.clone());
    }
}

/// The detail of the abuse the walk reports for a record its gate refused.
const WALK_REFUSED: &str = "the renewal walk's adoption gate refused the record";

/// The abuse a session reports when the read-epoch floor rises to `epoch` while
/// it reads a folder whose record a writer sealed at `epoch` under a key this
/// device does not hold.
fn walk_abuse_after_a_floor_rise(epoch: u64) -> Vec<String> {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        let outer = create_folder(&world, engine, tasks, ROOT, "outer");
        vec![create_folder(&world, engine, tasks, outer, "inner")]
    });
    seal_above(&world, &blocks, nodes[0], epoch);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    while events.try_next().is_some() {}
    device.floor_store.raise_epoch_floor_on_sequence_read(
        &floor_label(write_name(nodes[0]).as_str().as_bytes()),
        &floor_label(&SCOPE),
        epoch,
    );

    tick(&world, &engine, &mut tasks);

    let floor_key = [
        owner_tag(&kdf::enc_subkey(&SECRET)).as_slice(),
        &floor_label(&SCOPE),
    ]
    .concat();
    assert_eq!(
        block_on(device.floor_store.epoch_floor(&floor_key)).expect("the floor reads"),
        Some(epoch),
        "a read of the record raised the floor",
    );
    core::iter::from_fn(|| events.try_next())
        .filter_map(|event| match event {
            Event::AttributableAbuse { description } => Some(description),
            _ => None,
        })
        .collect()
}

/// A cut on this device raises the read-epoch floor after the walk admitted
/// the scope root and took its read seed. A record at the new floor needs the
/// seed the cut minted, so it accuses no writer.
#[test]
fn a_floor_rise_during_a_walk_read_accuses_no_record_at_the_new_floor() {
    let abuse = walk_abuse_after_a_floor_rise(OWNER_ROOT_EPOCH + 1);
    assert!(
        !abuse
            .iter()
            .any(|description| description.ends_with(WALK_REFUSED)),
        "earned {abuse:?}"
    );
}

/// At the epoch of the walk's read seed, a body that does not open is
/// tampering.
#[test]
fn a_walk_record_at_its_seeds_epoch_that_does_not_open_stays_a_violation() {
    let abuse = walk_abuse_after_a_floor_rise(OWNER_ROOT_EPOCH);
    assert!(
        abuse
            .iter()
            .any(|description| description.ends_with(WALK_REFUSED)),
        "earned {abuse:?}"
    );
}

/// One hour of the virtual clock: the cadence of the walk's passes.
const HOUR: Duration = Duration::from_secs(60 * 60);

/// One file a session wrote and then left for 65 days: its name, and its
/// record as that session left it.
fn a_file_left_for_65_days(world: &FakeWorld, blocks: &Blocks) -> (IpnsName, VerifiedRecord) {
    let (_, name, before) = a_file_node_left_for_65_days(world, blocks);
    (name, before)
}

/// [`a_file_left_for_65_days`], with the file's node.
fn a_file_node_left_for_65_days(
    world: &FakeWorld,
    blocks: &Blocks,
) -> (NodeId, IpnsName, VerifiedRecord) {
    let nodes = written_then_left(world, blocks, |engine, tasks| {
        vec![write_file(world, engine, tasks, ROOT, "note.txt")]
    });
    let name = write_name(nodes[0]);
    let before = record_at(world, &name);
    world.scheduler.advance(DAY * 65);
    (nodes[0], name, before)
}

/// The renewal cursor `device` stored, if any.
fn stored_cursor(device: &FakeDevice) -> Option<RenewalCursor> {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(9));
    block_on(
        CursorStore::new(
            &device.staging_store,
            BookkeepingSeal::new(&enc, &entropy),
            &enc,
        )
        .load(),
    )
    .expect("the store reads")
}

/// Whether `request` registers `name` with the registry.
fn registers(request: &HttpRequest, name: &str) -> bool {
    request.method == HttpMethod::Post
        && request.url.ends_with("/registry/register")
        && request
            .body
            .as_deref()
            .is_some_and(|body| body.windows(name.len()).any(|w| w == name.as_bytes()))
}

/// A started session on `device`, run until its boundary walk: the next tick
/// runs its first renewal walk.
fn boot_to_the_first_walk(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    entropy_seed: u64,
) -> (Engine<FakeSeamTypes>, EventStream, Vec<BoxedTask>) {
    let (engine, events, mut tasks) = boot(world, blocks, device, entropy_seed);
    tick(world, &engine, &mut tasks);
    (engine, events, tasks)
}

/// A registry that answers 503 to the file's registration in the first pass
/// makes that pass keep the cursor back, so the next pass renews the file
/// rather than the cycle closing past it.
#[test]
fn a_refused_registration_keeps_the_cursor_for_the_next_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let refusing = Arc::new(AtomicBool::new(true));
    let refused = Arc::new(AtomicBool::new(false));
    for _ in 0..4000 {
        let (blocks, key) = (blocks.clone(), name.as_str().to_owned());
        let (refusing, refused) = (refusing.clone(), refused.clone());
        device.http.enqueue_derived(move |request| {
            if registers(request, &key) && refusing.load(Ordering::SeqCst) {
                refused.store(true, Ordering::SeqCst);
                return Ok(HttpResponse {
                    status: 503,
                    headers: Vec::new(),
                    body: b"{\"statusCode\":503,\"message\":\"unavailable\"}".to_vec(),
                });
            }
            blocks.reply(request)
        });
    }
    let (engine, _events, mut tasks) = boot_served(&world, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);
    assert!(
        refused.load(Ordering::SeqCst),
        "the registry refused the file"
    );
    assert_eq!(
        record_at(&world, &name),
        before,
        "the first pass renews nothing"
    );

    refusing.store(false, Ordering::SeqCst);
    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// An owned scope root that does not resolve in the first pass makes that pass
/// keep the cursor back, so the next pass walks the scope.
#[test]
fn an_unavailable_scope_root_keeps_the_cursor_for_the_next_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    let root = write_name(ROOT);
    world.record_store.fail_get_for(root.as_str());
    tick(&world, &engine, &mut tasks);
    world.record_store.heal_get_for(root.as_str());
    assert_eq!(
        record_at(&world, &name),
        before,
        "the first pass renews nothing"
    );

    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// The endpoints agree the vault root holds no record: a permanent failure, so
/// the pass stores its cursor past the root at once and reports the root.
#[test]
fn a_scope_root_with_no_record_moves_the_cursor_at_once_and_is_reported() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    let root = write_name(ROOT);
    world
        .record_store
        .serve_gets_for_after(root.as_str(), 0, usize::MAX, None);
    tick(&world, &engine, &mut tasks);
    world
        .record_store
        .serve_gets_for_after(root.as_str(), 0, 0, None);

    let cursor = stored_cursor(&device).expect("the pass stored its cursor");
    assert_eq!(cursor.root, None, "the cursor moved past the root");
    assert_eq!(cursor.kept_back_since, None);
    let reported = core::iter::from_fn(|| events.try_next()).any(|event| {
        matches!(event, Event::RenewalFailed { routing_key, .. } if routing_key == root.as_str())
    });
    assert!(reported, "the root is reported");
}

/// A transient failure keeps the cursor back across sessions: each session
/// keeps the time of the first keep-back, and the first pass past one window
/// stores where it stopped, however short each session is.
#[test]
fn a_transient_failure_keeps_the_cursor_back_for_one_window_across_sessions() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let root = write_name(ROOT);
    let mut since = None;
    for session in 0..5u64 {
        let (engine, _events, mut tasks) =
            boot_to_the_first_walk(&world, &blocks, &device, 10 + session);
        world.record_store.fail_get_for(root.as_str());
        tick(&world, &engine, &mut tasks);
        world.record_store.heal_get_for(root.as_str());
        let cursor = stored_cursor(&device).expect("the pass stored a cursor");
        if session < 4 {
            since = since.or(cursor.kept_back_since);
            assert!(since.is_some(), "session {session} keeps the cursor back");
            assert_eq!(cursor.kept_back_since, since, "session {session}");
            assert!(cursor.root.is_some(), "session {session} keeps the range");
        } else {
            assert_eq!(
                cursor.kept_back_since, since,
                "the cycle's window stays spent"
            );
            assert_eq!(cursor.root, None, "the pass stores where it stopped");
        }
        drop(tasks);
        drop(engine);
        drop(world.scheduler.take_spawned_tasks());
        world.scheduler.advance(HOUR * 7);
    }
}

/// Within one session, a transient failure keeps the cursor back until one
/// window has passed since the first keep-back; then the pass stores it.
#[test]
fn a_transient_failure_that_outlasts_the_window_stores_the_cursor() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    world.record_store.fail_get_for(write_name(ROOT).as_str());
    tick(&world, &engine, &mut tasks);
    let since = stored_cursor(&device)
        .expect("a kept-back cursor")
        .kept_back_since;
    assert!(since.is_some(), "the first pass keeps the cursor back");
    for hour in 1..24 {
        world.scheduler.advance(HOUR);
        tick(&world, &engine, &mut tasks);
        let cursor = stored_cursor(&device).expect("a kept-back cursor");
        assert_eq!(cursor.kept_back_since, since, "hour {hour}");
        assert!(cursor.root.is_some(), "hour {hour}: the range is kept");
    }
    world.scheduler.advance(HOUR * 2);
    tick(&world, &engine, &mut tasks);
    let cursor = stored_cursor(&device).expect("the stored cursor");
    assert_eq!(
        cursor.kept_back_since, since,
        "the cycle's window stays spent"
    );
    assert_eq!(cursor.root, None, "the pass stores where it stopped");
}

/// Every endpoint fails the renewal's PUT after the registration landed: a
/// transient failure, so the next pass renews the file.
#[test]
fn a_failed_put_after_a_registration_keeps_the_cursor_for_the_next_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    world.record_store.fail_put_for(name.as_str());
    tick(&world, &engine, &mut tasks);
    world.record_store.heal_put_for(name.as_str());
    assert_eq!(
        record_at(&world, &name),
        before,
        "the first pass renews nothing"
    );

    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// Whether `events` carried a `renewalFailed` for `routing_key` whose detail
/// holds `detail`.
fn renewal_failed(events: &mut EventStream, routing_key: &str, detail: &str) -> bool {
    core::iter::from_fn(|| events.try_next()).any(|event| {
        matches!(event, Event::RenewalFailed { routing_key: key, detail: text }
            if key == routing_key && text.contains(detail))
    })
}

/// A doomed-name journal that does not list leaves the walk unable to skip a
/// doomed name, so the pass renews nothing, stores nothing and reports the
/// stall; the next pass that lists renews the file.
#[test]
fn a_journal_that_does_not_list_renews_nothing_and_stores_nothing() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    device.staging_store.inner().fail_staged_keys();
    tick(&world, &engine, &mut tasks);
    assert_eq!(record_at(&world, &name), before, "the pass renews nothing");
    assert_eq!(stored_cursor(&device), None, "the pass stores nothing");
    assert!(
        renewal_failed(
            &mut events,
            write_name(ROOT).as_str(),
            "doomed-name journal"
        ),
        "the stall is reported"
    );

    device.staging_store.inner().heal_staged_keys();
    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// A doomed-name journal entry that does not open could name any name in its
/// scope, so the pass renews nothing there, keeps the cursor back and reports
/// the scope root.
#[test]
fn an_unreadable_doomed_journal_entry_stops_its_scope() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    let entry = doomed_journal_key(&owner_tag(&kdf::enc_subkey(&SECRET)), ROOT, NodeId([7; 16]));
    block_on(
        device
            .staging_store
            .put_staged_bytes(&entry, b"not a sealed reclamation"),
    )
    .expect("stage the entry");
    tick(&world, &engine, &mut tasks);
    assert_scope_stalled(&world, &device, &mut events, &name, &before);
}

/// A doomed-name journal entry that does not read stops its scope as one that
/// does not open does.
#[test]
fn a_doomed_journal_entry_that_does_not_read_stops_its_scope() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    let entry = doomed_journal_key(&owner_tag(&kdf::enc_subkey(&SECRET)), ROOT, NodeId([7; 16]));
    block_on(device.staging_store.put_staged_bytes(&entry, b"any bytes")).expect("stage it");
    device.staging_store.inner().fail_staged_reads_under(&entry);
    tick(&world, &engine, &mut tasks);
    device.staging_store.inner().heal_staged_reads();
    assert_scope_stalled(&world, &device, &mut events, &name, &before);
}

/// The file under the stalled vault root is not renewed, the cursor is kept
/// back, and the stall names the vault root.
fn assert_scope_stalled(
    world: &FakeWorld,
    device: &FakeDevice,
    events: &mut EventStream,
    name: &IpnsName,
    before: &VerifiedRecord,
) {
    assert_eq!(record_at(world, name), *before, "the pass renews nothing");
    let cursor = stored_cursor(device).expect("a kept-back cursor");
    assert!(
        cursor.kept_back_since.is_some(),
        "the pass kept the cursor back"
    );
    assert!(cursor.root.is_some(), "the range is kept");
    assert!(
        renewal_failed(events, write_name(ROOT).as_str(), "doomed-name journal"),
        "the stall is reported"
    );
}

/// A registry that refuses the file's registration with a 409 refuses it for
/// good: the pass moves the cursor on at once and reports the file.
#[test]
fn a_4xx_registration_refusal_moves_the_cursor_at_once() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    for _ in 0..4000 {
        let (blocks, key) = (blocks.clone(), name.as_str().to_owned());
        device.http.enqueue_derived(move |request| {
            if registers(request, &key) {
                return Ok(HttpResponse {
                    status: 409,
                    headers: Vec::new(),
                    body: b"{\"statusCode\":409,\"message\":\"conflict\"}".to_vec(),
                });
            }
            blocks.reply(request)
        });
    }
    let (engine, mut events, mut tasks) = boot_served(&world, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);
    assert_eq!(record_at(&world, &name), before, "the pass renews nothing");
    let cursor = stored_cursor(&device).expect("the pass stored its cursor");
    assert_eq!(cursor.root, None, "the cursor moved past the file");
    assert_eq!(cursor.kept_back_since, None);
    assert!(
        renewal_failed(&mut events, name.as_str(), ""),
        "the file is reported"
    );
}

/// A file record no endpoint can serve, with no cached copy, makes the pass
/// keep the cursor back, so the next pass renews the file.
#[test]
fn an_unavailable_child_keeps_the_cursor_for_the_next_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    block_on(device.snapshot_cache.remove(name.as_str().as_bytes())).expect("drop the cache");
    world.record_store.fail_get_for(name.as_str());
    tick(&world, &engine, &mut tasks);
    world.record_store.heal_get_for(name.as_str());
    assert_eq!(
        record_at(&world, &name),
        before,
        "the first pass renews nothing"
    );
    let cursor = stored_cursor(&device).expect("a kept-back cursor");
    assert!(
        cursor.kept_back_since.is_some(),
        "the pass kept the cursor back"
    );

    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// The endpoints agree the file holds no record and no copy is cached: a
/// permanent failure, so the pass moves the cursor on and reports the file.
#[test]
fn a_child_with_no_record_moves_the_cursor_at_once_and_is_reported() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, _) = a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    block_on(device.snapshot_cache.remove(name.as_str().as_bytes())).expect("drop the cache");
    world
        .record_store
        .serve_gets_for_after(name.as_str(), 0, usize::MAX, None);
    tick(&world, &engine, &mut tasks);

    let cursor = stored_cursor(&device).expect("the pass stored its cursor");
    assert_eq!(cursor.root, None, "the cursor moved past the file");
    assert_eq!(cursor.kept_back_since, None);
    assert!(
        renewal_failed(&mut events, name.as_str(), "no record"),
        "the file is reported"
    );
}

/// A retire ledger read that fails makes the pass keep the cursor back, so the
/// next pass renews the file.
#[test]
fn a_failed_ledger_read_keeps_the_cursor_for_the_next_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    device
        .staging_store
        .inner()
        .fail_staged_reads_under(NODE_TOMBSTONE_PREFIX);
    tick(&world, &engine, &mut tasks);
    device.staging_store.inner().heal_staged_reads();
    assert_eq!(
        record_at(&world, &name),
        before,
        "the first pass renews nothing"
    );

    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// An acknowledged sequence that does not open is a permanent failure: the
/// pass moves the cursor on and reports the file.
#[test]
fn an_unreadable_acknowledged_sequence_moves_the_cursor_and_is_reported() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (node, name, before) = a_file_node_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    let key = StagingRetireLedger::<InMemoryStagingStore>::acknowledged_key(
        &owner_tag(&kdf::enc_subkey(&SECRET)),
        node.0,
    )
    .expect("a key");
    block_on(
        device
            .staging_store
            .put_staged_bytes(&key, b"not a sealed mark"),
    )
    .expect("stage it");
    tick(&world, &engine, &mut tasks);
    assert_eq!(record_at(&world, &name), before, "the pass renews nothing");
    let cursor = stored_cursor(&device).expect("the pass stored its cursor");
    assert_eq!(cursor.root, None, "the cursor moved past the file");
    assert_eq!(cursor.kept_back_since, None);
    assert!(
        renewal_failed(&mut events, name.as_str(), "acknowledged sequence"),
        "the file is reported"
    );
}

/// A registry that answers 401 to the registration after the client refreshed
/// its session makes the pass keep the cursor back, so the next pass renews the
/// file.
#[test]
fn a_401_after_the_refresh_keeps_the_cursor_for_the_next_pass() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let refusing = Arc::new(AtomicBool::new(true));
    for _ in 0..4000 {
        let (blocks, key, refusing) = (blocks.clone(), name.as_str().to_owned(), refusing.clone());
        device.http.enqueue_derived(move |request| {
            if request.url.ends_with("/auth/refresh") {
                return Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: format!(
                        r#"{{"accessToken":"jwt-1","refreshToken":"{}","acceleratorToken":"gw-1"}}"#,
                        "a".repeat(64)
                    )
                    .into_bytes(),
                });
            }
            if registers(request, &key) && refusing.load(Ordering::SeqCst) {
                return Ok(HttpResponse {
                    status: 401,
                    headers: Vec::new(),
                    body: b"{\"statusCode\":401,\"message\":\"unauthorized\"}".to_vec(),
                });
            }
            blocks.reply(request)
        });
    }
    let (engine, _events, mut tasks) = boot_served(&world, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &name),
        before,
        "the first pass renews nothing"
    );
    let cursor = stored_cursor(&device).expect("a kept-back cursor");
    assert!(cursor.root.is_some(), "the range is kept");
    assert!(
        cursor.kept_back_since.is_some(),
        "the pass kept the cursor back"
    );

    refusing.store(false, Ordering::SeqCst);
    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the file");
}

/// A cursor that does not read says nothing about the stored cursor: the pass
/// renews nothing, keeps the stored cursor and reports the stall.
#[test]
fn a_cursor_that_does_not_read_skips_the_pass_and_keeps_the_cursor() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    a_file_left_for_65_days(&world, &blocks);
    let device = world.device(b"a later session");
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    tick(&world, &engine, &mut tasks);
    let closed = stored_cursor(&device).expect("the first pass stored its cursor");
    assert_eq!(closed.root, None, "the first pass closed its cycle");

    device
        .staging_store
        .inner()
        .fail_staged_reads_under(RENEWAL_CURSOR_PREFIX);
    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    device.staging_store.inner().heal_staged_reads();
    assert_eq!(
        stored_cursor(&device),
        Some(closed),
        "the pass keeps the stored cursor"
    );
    assert!(
        renewal_failed(&mut events, write_name(ROOT).as_str(), "renewal cursor"),
        "the stall is reported"
    );
}
