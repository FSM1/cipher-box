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

use cipherbox_engine::gate::floor;
use cipherbox_engine::net::RE_PUT_INTERVAL;
use cipherbox_engine::net::author::{EnvelopeAuthoring, author_child_envelope};
use cipherbox_engine::net::eol::{eol_from, renewal_eol_from};
use cipherbox_engine::net::renewal_walk::WALK_BUDGET;
use cipherbox_engine::net::renewal_walk::cursor::{
    CursorStore, MAX_CURSOR_PATH, RENEWAL_CURSOR_PREFIX, RenewalCursor,
};
use cipherbox_engine::net::retire::{NODE_TOMBSTONE_PREFIX, StagingRetireLedger};
use cipherbox_engine::seams::{
    BoxedTask, FloorStore, HttpMethod, HttpRequest, HttpResponse, RecordTransport, RetireLedger,
    Scheduler, SnapshotCache, StagingStore, UnixMillis,
};
use cipherbox_engine::settings::{VaultSettings, settings_name};
use cipherbox_engine::sync::owed_rotation::owed_rotation_key;
use cipherbox_engine::sync::pointer::vault_pointer_name;
use cipherbox_engine::sync::{BookkeepingSeal, doomed_journal_key, owner_tag};
use cipherbox_engine::testkit::account::{Blocks, SCOPE, SECRET, floor_label, seed_account};
use cipherbox_engine::testkit::fakes::InMemoryStagingStore;
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_EPOCH,
    OWNER_ROOT_SCOPE_SEED as READ_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, BinIndexKeys, Command, ContentProfile, Engine, Event, EventStream, GatewayConfig,
    LoginSecret, NodeId, NodeKind, StoragePolicy, SyncTimingProfile, WriteTarget,
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
    let device = world.device(b"the device that wrote");
    written_then_left_on(world, blocks, &device, write)
}

/// [`written_then_left`] on `device`, which the caller keeps.
fn written_then_left_on(
    world: &FakeWorld,
    blocks: &Blocks,
    device: &FakeDevice,
    write: impl FnOnce(&mut Engine<FakeSeamTypes>, &mut [BoxedTask]) -> Vec<NodeId>,
) -> Vec<NodeId> {
    seed_account(world, blocks);
    let (mut engine, _events, mut tasks) = boot(world, blocks, device, 1);
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
                    body: b"{\"statusCode\":503,\"message\":\"unavailable\"}"
                        .to_vec()
                        .into(),
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
                    body: b"{\"statusCode\":409,\"message\":\"conflict\"}"
                        .to_vec()
                        .into(),
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
                    .into_bytes().into(),
                });
            }
            if registers(request, &key) && refusing.load(Ordering::SeqCst) {
                return Ok(HttpResponse {
                    status: 401,
                    headers: Vec::new(),
                    body: b"{\"statusCode\":401,\"message\":\"unauthorized\"}".to_vec().into(),
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

/// Tombstone `node` on `device`, as the drain does when it journals a hard
/// delete's debt.
fn tombstone(device: &FakeDevice, node: NodeId) {
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(9));
    block_on(
        StagingRetireLedger::new(&device.staging_store, BookkeepingSeal::new(&enc, &entropy))
            .tombstone(&owner_tag(&enc), node.0),
    )
    .expect("tombstone the node");
}

/// A tombstoned node the base links again is live elsewhere, and its debt
/// waits: the walk renews its record, so the content is never lost.
#[test]
fn a_tombstoned_node_the_base_links_still_renews() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (node, name, before) = a_file_node_left_for_65_days(&world, &blocks);
    let started = world.scheduler.now();
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    tombstone(&device, node);
    tick(&world, &engine, &mut tasks);
    assert_renewed_at_start(&world, &name, &before, started, "the linked file");
}

/// A tombstoned node the base links nowhere is retired: the walk reaches it
/// through its bin entry and does not renew it.
#[test]
fn a_tombstoned_node_the_base_links_nowhere_is_not_renewed() {
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
    let device = world.device(b"a later session");
    let (engine, _events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    tombstone(&device, nodes[0]);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &name).sequence,
        before.sequence,
        "the retired file is not renewed"
    );
}

#[test]
fn a_walk_reports_and_does_not_renew_a_child_at_a_foreign_envelope_version() {
    use cipherbox_core::seal::{encode_envelope, seal_read_body};
    use cipherbox_engine::net::author::ENVELOPE_V;

    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        vec![write_file(&world, engine, tasks, ROOT, "newer.txt")]
    });
    let node = nodes[0];
    let name = write_name(node);
    let before = record_at(&world, &name);
    let cid = std::str::from_utf8(&before.value)
        .unwrap()
        .strip_prefix("/ipfs/")
        .unwrap();
    let envelope = decode_envelope(&blocks.get(cid).unwrap()).unwrap();
    let read_key = kdf::read_key(kdf::node_seed(&READ_SCOPE_SEED, &node.0).as_bytes());
    let body = open_read_body(&envelope, read_key.as_bytes()).unwrap();
    let newer = seal_read_body(
        read_key.as_bytes(),
        &[0x7b; 24],
        ENVELOPE_V + 1,
        node.0,
        SCOPE,
        envelope.epoch,
        &body,
    )
    .unwrap();
    let cid = blocks.put(encode_envelope(&newer).unwrap());
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &node.0).as_bytes());
    let bytes = IpnsRecord::create_v2(
        &signer,
        format!("/ipfs/{cid}").as_bytes(),
        before.sequence + 1,
        2_000_000_000,
        &eol_from(world.scheduler.now()),
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), bytes.clone());
    }
    let served = record_at(&world, &name);
    world.scheduler.advance(DAY * 45);
    let device = world.device(b"new reader");
    let (engine, mut events, mut tasks) = boot(&world, &blocks, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &name).data,
        served.data,
        "a newer envelope is not re-signed"
    );
    assert!(
        renewal_failed(&mut events, name.as_str(), "envelope version"),
        "the refused renewal is reported with its version"
    );
    assert_eq!(
        block_on(engine.read_content(node)).expect("the newer envelope remains readable"),
        b"a note nobody opens again"
    );
    assert!(
        !device
            .http
            .requests()
            .iter()
            .any(|request| registers(request, name.as_str())),
        "the refused renewal never registers"
    );
}

#[test]
fn a_walk_refuses_each_scope_floor_raised_during_registration() {
    for (axis, suffix) in [
        ("read", SCOPE.to_vec()),
        ("write", [SCOPE.as_slice(), b"/write-epoch"].concat()),
        ("cut", [SCOPE.as_slice(), b"/cut-epoch"].concat()),
    ] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        let nodes = written_then_left(&world, &blocks, |engine, tasks| {
            vec![write_file(&world, engine, tasks, ROOT, "due.txt")]
        });
        let name = write_name(nodes[0]);
        let before = record_at(&world, &name);
        world.scheduler.advance(DAY * 45);
        let device = world.device(b"later");
        let fired = Arc::new(AtomicBool::new(false));
        let (raised, floors, key) = (
            fired.clone(),
            device.floor_store.clone(),
            name.as_str().to_owned(),
        );
        serve_with(&device, &blocks, 4000, move |request| {
            if registers(request, &key) && !raised.swap(true, Ordering::SeqCst) {
                block_on(
                    floors.raise_epoch_floor(
                        &[
                            owner_tag(&kdf::enc_subkey(&SECRET)).as_slice(),
                            floor_label(&suffix).as_slice(),
                        ]
                        .concat(),
                        u64::MAX,
                    ),
                )
                .unwrap();
            }
        });
        let (engine, _events, mut tasks) = boot_served(&world, &device, 2);
        until_the_first_walk(&world, &engine, &mut tasks);
        assert!(
            fired.load(Ordering::SeqCst),
            "{axis}: the walk reached registration"
        );
        assert_eq!(
            record_at(&world, &name).data,
            before.data,
            "{axis}: the renewal gate refused"
        );
    }
}

#[test]
fn a_walk_reports_and_does_not_renew_a_root_at_a_foreign_envelope_version() {
    use cipherbox_engine::net::author::ENVELOPE_V;
    use cipherbox_engine::testkit::account::seed_account_sealed;

    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let name = seed_account_sealed(&world, &blocks, Vec::new(), Vec::new(), ENVELOPE_V + 1);
    let before = record_at(&world, &name);
    let signer = kdf::ipns_keypair(kdf::write_seed(&WRITE_SCOPE_SEED, &ROOT.0).as_bytes());
    let bytes = IpnsRecord::create_v2(
        &signer,
        &before.value,
        before.sequence,
        2_000_000_000,
        &eol_from(world.scheduler.now()),
    )
    .marshal();
    for endpoint in world.record_store.endpoints() {
        world
            .record_store
            .seed_record(&endpoint, name.as_str(), bytes.clone());
    }
    world.scheduler.advance(DAY * 45);
    let device = world.device(b"new reader");
    let (engine, mut events, mut tasks) = boot(&world, &blocks, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);
    assert!(
        renewal_failed(&mut events, name.as_str(), "envelope version"),
        "the refused renewal is reported with its version"
    );
    assert!(block_on(engine.view()).is_ok(), "the root remains readable");
    assert_eq!(
        world
            .record_store
            .record_at(&world.record_store.endpoints()[0], name.as_str()),
        Some(bytes.clone()),
        "the root is never re-signed"
    );
    // Inside the liveness threshold the held root takes the same rule.
    world.scheduler.advance(DAY * 20);
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        world
            .record_store
            .record_at(&world.record_store.endpoints()[0], name.as_str()),
        Some(bytes),
        "the liveness loop does not re-sign the held root"
    );
}

/// Every record lapses, and only the API's recovery cache keeps a copy.
fn lapse_into_the_recovery_cache(world: &FakeWorld, blocks: &Blocks) {
    let endpoint = world.record_store.endpoints()[0].clone();
    for routing_key in world.record_store.routing_keys(&endpoint) {
        if let Some(record) = world.record_store.lapse(&routing_key) {
            blocks.cache_for_recovery(&routing_key, record);
        }
    }
}

/// Whether the first endpoint serves no record at `name`.
fn unserved(world: &FakeWorld, name: &IpnsName) -> bool {
    world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
        .is_none()
}

fn recovery_fetches(device: &FakeDevice) -> usize {
    device
        .http
        .requests()
        .iter()
        .filter(|request| request.url.contains("/recovery/"))
        .count()
}

/// ADR 0062 consequence 5: a device that starts after 100 days offline, while
/// every name of the vault lapsed, finds its vault root and lists the vault.
/// The anchors revive at the session start, and the walk revives the lapsed
/// folder before it descends into it, so the file below renews in the same
/// cycle. Each revival signs at `S + 1` with the renewal EOL and the same value.
/// This holds for a new device and for the device that wrote the vault, whose
/// seed cache opens the root without a resolve.
#[test]
fn a_device_that_starts_after_100_days_offline_finds_its_vault_root() {
    for returning in [false, true] {
        a_device_after_100_days_offline_finds_its_vault_root(returning);
    }
}

fn a_device_after_100_days_offline_finds_its_vault_root(returning: bool) {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let writer = world.device(b"the device that wrote");
    let nodes = written_then_left_on(&world, &blocks, &writer, |engine, tasks| {
        let folder = create_folder(&world, engine, tasks, ROOT, "notes");
        vec![
            folder,
            write_file(&world, engine, tasks, folder, "note.txt"),
        ]
    });
    let anchors = [
        vault_pointer_name(&SECRET, 0),
        write_name(ROOT),
        BinIndexKeys::derive(&SECRET).name().clone(),
    ];
    let subtree = [write_name(nodes[0]), write_name(nodes[1])];
    let before: Vec<VerifiedRecord> = anchors
        .iter()
        .chain(&subtree)
        .map(|name| record_at(&world, name))
        .collect();
    lapse_into_the_recovery_cache(&world, &blocks);
    world.scheduler.advance(DAY * 100);
    let started = world.scheduler.now();

    let device = if returning {
        writer
    } else {
        world.device(b"a device after 100 days offline")
    };
    let (engine, _events, mut tasks) = boot(&world, &blocks, &device, 2);

    assert_eq!(child_named(&engine, ROOT, "notes"), nodes[0]);
    for (name, before) in anchors.iter().zip(&before) {
        let after = record_at(&world, name);
        assert_eq!(
            after.sequence,
            before.sequence + 1,
            "an anchor revives at S + 1"
        );
        assert_eq!(after.value, before.value, "with the same value");
        assert_eq!(
            after.validity,
            renewal_eol_from(started).into_bytes(),
            "before the first tick of the session",
        );
    }
    let root = write_name(ROOT);
    assert_eq!(
        block_on(
            device
                .floors(&SECRET)
                .sequence_floor(root.as_str().as_bytes())
        )
        .expect("the floor store answers"),
        Some(before[1].sequence + 1),
        "the cold start read the revived root through the gate",
    );

    until_the_first_walk(&world, &engine, &mut tasks);
    for (name, before) in subtree.iter().zip(&before[anchors.len()..]) {
        assert_renewed_at_start(&world, name, before, started, "a lapsed node");
    }
}

/// ADR 0062 consequence 2: one session makes at most 25 recovery fetches a
/// minute, the session-start revival and the walk together, and a revival
/// cycle waits for the pace rather than stopping at the walk budget.
#[test]
fn a_lapsed_vault_revives_at_the_recovery_pace() {
    const FILES: usize = 30;
    const RECOVERY_PACE: usize = 25;
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        (0..FILES)
            .map(|at| write_file(&world, engine, tasks, ROOT, &format!("note-{at}.txt")))
            .collect()
    });
    let before: Vec<VerifiedRecord> = nodes
        .iter()
        .map(|node| record_at(&world, &write_name(*node)))
        .collect();
    lapse_into_the_recovery_cache(&world, &blocks);
    world.scheduler.advance(DAY * 100);

    let device = world.device(b"a device after 100 days offline");
    let (engine, _events, mut tasks) = boot(&world, &blocks, &device, 2);
    until_the_first_walk(&world, &engine, &mut tasks);
    assert_eq!(
        recovery_fetches(&device),
        RECOVERY_PACE,
        "the first minute spends the whole pace and no more",
    );

    world.scheduler.advance(Duration::from_secs(60));
    poll_tasks_until_parked(&mut tasks);
    for (node, before) in nodes.iter().zip(&before) {
        assert_eq!(
            record_at(&world, &write_name(*node)).sequence,
            before.sequence + 1,
            "each file revives once the pace allows",
        );
    }
}

/// ADR 0062 D3 and D4 at session start: the settings record revives only on a
/// device whose floor equals the recovered sequence, and the session loads
/// the settings again. A new device takes the ADR 0034 ladder and signs
/// nothing at the settings name.
#[test]
fn the_settings_record_revives_at_session_start_only_at_its_floor() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    seed_account(&world, &blocks);
    let owner = world.device(b"the device that saved the settings");
    let (mut engine, _events, tasks) = boot(&world, &blocks, &owner, 1);
    block_on(engine.command(Command::SaveVaultSettings {
        settings: VaultSettings {
            bin_retention_days: 7,
            ..VaultSettings::default()
        },
    }))
    .expect("the settings publish");
    drop((tasks, engine));
    drop(world.scheduler.take_spawned_tasks());
    let name = settings_name(&SECRET);
    let saved = record_at(&world, &name);
    lapse_into_the_recovery_cache(&world, &blocks);
    world.scheduler.advance(DAY * 100);

    let fresh = world.device(b"a new device");
    let (_fresh, _events, _tasks) = boot(&world, &blocks, &fresh, 2);
    assert!(
        unserved(&world, &name),
        "a device with no floor does not revive the settings record",
    );
    drop(world.scheduler.take_spawned_tasks());

    let (engine, _events, _tasks) = boot(&world, &blocks, &owner, 3);
    let revived = record_at(&world, &name);
    assert_eq!(revived.sequence, saved.sequence + 1);
    assert_eq!(revived.value, saved.value, "the same sealed body");
    let storage = block_on(engine.vault_storage()).expect("the session loaded its settings");
    assert_eq!(
        storage.settings.bin_retention_days, 7,
        "the load after the revival reads the saved settings"
    );
}

fn unprovisioned(events: &mut EventStream, retryable: bool) -> bool {
    core::iter::from_fn(|| events.try_next()).any(
        |event| matches!(event, Event::VaultUnprovisioned { retryable: at, .. } if at == retryable),
    )
}

/// ADR 0062 D1 step 1: a 429 at the recovery read of the vault pointer leaves
/// the end of the chain unconfirmed. A new device adopts no root, mints
/// nothing and stays retryable, and a refresh in the same session revives the
/// chain and provisions.
#[test]
fn a_throttled_chain_revival_stays_retryable_and_a_refresh_revives_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        vec![create_folder(&world, engine, tasks, ROOT, "notes")]
    });
    let pointer = vault_pointer_name(&SECRET, 0);
    let before = record_at(&world, &pointer);
    lapse_into_the_recovery_cache(&world, &blocks);
    blocks.throttle_recovery_once(pointer.as_str());
    world.scheduler.advance(DAY * 100);

    let device = world.device(b"a device after 100 days offline");
    let (mut engine, mut events, _tasks) = boot(&world, &blocks, &device, 2);
    assert!(!engine.is_provisioned(), "the session adopts no root");
    assert!(
        unprovisioned(&mut events, true),
        "a throttled revival is a stall, never a refusal",
    );
    assert!(
        unserved(&world, &pointer),
        "the session mints no vault over the lapsed one",
    );

    block_on(engine.command(Command::ManualRefresh)).expect("the refresh revives the chain");
    assert!(
        engine.is_provisioned(),
        "the refresh provisions the session"
    );
    assert_eq!(record_at(&world, &pointer).sequence, before.sequence + 1);
    assert_eq!(child_named(&engine, ROOT, "notes"), nodes[0]);
}

/// ADR 0062 D3: a lapsed bin index that a 429 keeps from reviving gets no
/// genesis publish over it. The next start revives it at `S + 1` with the same
/// value, reads it through the gate and holds it, so the liveness loop renews
/// it later.
#[test]
fn a_throttled_bin_index_revival_publishes_no_genesis_and_the_next_start_revives_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    written_then_left(&world, &blocks, |engine, tasks| {
        let file = write_file(&world, engine, tasks, ROOT, "binned.txt");
        block_on(engine.command(Command::Delete { node: file })).expect("the delete stages");
        tick(&world, engine, tasks);
        vec![file]
    });
    let bin = BinIndexKeys::derive(&SECRET).name().clone();
    let before = record_at(&world, &bin);
    lapse_into_the_recovery_cache(&world, &blocks);
    // The start and the first liveness retry.
    blocks.throttle_recovery_once(bin.as_str());
    blocks.throttle_recovery_once(bin.as_str());
    world.scheduler.advance(DAY * 100);

    let device = world.device(b"a device after 100 days offline");
    let (engine, _events, tasks) = boot(&world, &blocks, &device, 2);
    assert!(
        unserved(&world, &bin),
        "no genesis publish replaces the lapsed bin index",
    );
    drop((tasks, engine));
    drop(world.scheduler.take_spawned_tasks());

    let (engine, _events, mut tasks) = boot(&world, &blocks, &device, 3);
    let revived = record_at(&world, &bin);
    assert_eq!(revived.sequence, before.sequence + 1);
    assert_eq!(revived.value, before.value, "the same bin index");
    assert_eq!(
        block_on(
            device
                .floors(&SECRET)
                .sequence_floor(bin.as_str().as_bytes())
        )
        .expect("the floor store answers"),
        Some(before.sequence + 1),
        "the load after the revival reads it through the gate",
    );

    world.scheduler.advance(DAY * 61);
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &bin).sequence,
        before.sequence + 2,
        "the session holds the bin index and renews it",
    );
}

fn bin_name() -> IpnsName {
    BinIndexKeys::derive(&SECRET).name().clone()
}

fn served_at(world: &FakeWorld, name: &IpnsName) -> Option<Vec<u8>> {
    world
        .record_store
        .record_at(&world.record_store.endpoints()[0], name.as_str())
}

fn abuse_reports(events: &mut EventStream) -> usize {
    core::iter::from_fn(|| events.try_next())
        .filter(|event| matches!(event, Event::AttributableAbuse { .. }))
        .count()
}

/// One device bins a file and keeps another, then its session ends, and every
/// record lapses into the recovery cache 100 days later.
fn a_binned_vault_lapsed(world: &FakeWorld, blocks: &Blocks) -> (Vec<NodeId>, VerifiedRecord) {
    let nodes = written_then_left(world, blocks, |engine, tasks| {
        let binned = write_file(world, engine, tasks, ROOT, "binned.txt");
        block_on(engine.command(Command::Delete { node: binned })).expect("the delete stages");
        tick(world, engine, tasks);
        vec![binned, write_file(world, engine, tasks, ROOT, "kept.txt")]
    });
    let before = record_at(world, &bin_name());
    lapse_into_the_recovery_cache(world, blocks);
    world.scheduler.advance(DAY * 100);
    (nodes, before)
}

/// ADR 0062 D3: an endpoint that does not answer for a lapsed bin index can
/// hold the record, so a new device publishes no genesis bin index over it,
/// and the next start revives it.
#[test]
fn an_unavailable_bin_index_read_publishes_no_genesis_and_the_next_start_revives_it() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (_, before) = a_binned_vault_lapsed(&world, &blocks);
    let bin = bin_name();
    world
        .record_store
        .fail_get_at_for(&world.record_store.endpoints()[0], bin.as_str());

    let device = world.device(b"a device after 100 days offline");
    let (engine, _events, tasks) = boot(&world, &blocks, &device, 2);
    assert_eq!(served_at(&world, &bin), None, "no genesis bin index");
    drop((tasks, engine));
    drop(world.scheduler.take_spawned_tasks());

    world.record_store.heal_get_for(bin.as_str());
    let (_engine, _events, _tasks) = boot(&world, &blocks, &device, 3);
    assert_eq!(record_at(&world, &bin).sequence, before.sequence + 1);
}

/// ADR 0062 D3: while a lapsed bin index can still revive, the drain publishes
/// no bin index over it, so a soft delete waits. The next liveness pass
/// revives the bin index in the same session, and the delete then publishes
/// its entry.
#[test]
fn a_soft_delete_waits_for_the_bin_index_revival_the_liveness_pass_retries() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (nodes, before) = a_binned_vault_lapsed(&world, &blocks);
    let bin = bin_name();
    // The start and the first liveness retry.
    blocks.throttle_recovery_once(bin.as_str());
    blocks.throttle_recovery_once(bin.as_str());

    let device = world.device(b"a device after 100 days offline");
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 2);
    // The walk revives the file first, so the delete reaches its bin entry.
    until_the_first_walk(&world, &engine, &mut tasks);
    block_on(engine.command(Command::Delete { node: nodes[1] })).expect("the delete stages");
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        served_at(&world, &bin),
        None,
        "the drain publishes no bin index over the lapsed one"
    );

    world.scheduler.advance(RE_PUT_INTERVAL);
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &bin).sequence,
        before.sequence + 2,
        "the revival at S + 1, then the delete's entry",
    );
}

/// ADR 0063 D4: rotation debt that does not read is unknown debt, so the
/// session-start revival signs no vault root and reports why.
#[test]
fn an_unread_owed_record_revives_no_vault_root() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    written_then_left(&world, &blocks, |engine, tasks| {
        vec![create_folder(&world, engine, tasks, ROOT, "notes")]
    });
    lapse_into_the_recovery_cache(&world, &blocks);
    world.scheduler.advance(DAY * 100);

    let device = world.device(b"a device after 100 days offline");
    let owed = owed_rotation_key(&kdf::enc_subkey(&SECRET));
    device.staging_store.inner().fail_staged_reads_under(&owed);
    let (_engine, mut events, _tasks) = boot(&world, &blocks, &device, 2);
    device.staging_store.inner().heal_staged_reads();

    let root = write_name(ROOT);
    assert_eq!(served_at(&world, &root), None, "the root does not revive");
    assert!(
        core::iter::from_fn(|| events.try_next()).any(|event| matches!(
            event,
            Event::RenewalFailed { routing_key, detail }
                if routing_key == root.as_str() && detail.contains("owed rotation record")
        )),
        "the session reports the unread record",
    );
}

/// ADR 0062 D1: another device revived index 0 while this start revived it, so
/// the revival stops as superseded. The session stays retryable, and a refresh
/// reads the other device's pointer and provisions.
#[test]
fn a_superseded_chain_revival_is_retryable_and_a_refresh_provisions() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let nodes = written_then_left(&world, &blocks, |engine, tasks| {
        vec![create_folder(&world, engine, tasks, ROOT, "notes")]
    });
    let pointer = vault_pointer_name(&SECRET, 0);
    let before = record_at(&world, &pointer);
    lapse_into_the_recovery_cache(&world, &blocks);
    world.scheduler.advance(DAY * 100);
    let newer = IpnsRecord::create_v2(
        &kdf::vault_pointer_index(&SECRET, 0),
        &before.value,
        before.sequence + 1,
        2_000_000_000,
        &eol_from(world.scheduler.now()),
    )
    .marshal();
    let endpoints = world.record_store.endpoints();
    for endpoint in &endpoints {
        world
            .record_store
            .seed_record(endpoint, pointer.as_str(), newer.clone());
    }
    // The chain reads index 0 `Absent`; the corroboration reads the revival.
    world
        .record_store
        .serve_gets_for_after(pointer.as_str(), 0, endpoints.len(), None);

    let device = world.device(b"a device after 100 days offline");
    let (mut engine, mut events, _tasks) = boot(&world, &blocks, &device, 2);
    assert!(!engine.is_provisioned());
    assert!(
        unprovisioned(&mut events, true),
        "a superseded revival is retryable"
    );

    block_on(engine.command(Command::ManualRefresh)).expect("the refresh provisions");
    assert!(engine.is_provisioned());
    assert_eq!(
        served_at(&world, &pointer),
        Some(newer),
        "this device signed nothing"
    );
    assert_eq!(child_named(&engine, ROOT, "notes"), nodes[0]);
}

/// ADR 0067 D4: the produce bar can sit above the vouched floor the cold start
/// reads. A lapsed pointer only the produce bar refuses is no trust violation:
/// nothing signs it and the session stays dark, until a device without that
/// floor revives it. A pointer both bars refuse is one trust violation.
#[test]
fn a_lapsed_pointer_below_the_produce_bar_stays_dark_and_below_both_bars_is_reported() {
    for vouched_below in [true, false] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        written_then_left(&world, &blocks, |engine, tasks| {
            vec![create_folder(&world, engine, tasks, ROOT, "notes")]
        });
        lapse_into_the_recovery_cache(&world, &blocks);
        world.scheduler.advance(DAY * 100);

        let device = world.device(b"a device after 100 days offline");
        let floors = device.floors(&SECRET);
        if vouched_below {
            block_on(floor::raise_vouched_floor(
                &floors,
                &SCOPE,
                OWNER_ROOT_EPOCH,
            ))
            .expect("the floor store answers");
        }
        block_on(floors.raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH + 1))
            .expect("the floor store answers");
        let (engine, mut events, _tasks) = boot(&world, &blocks, &device, 2);

        assert!(!engine.is_provisioned(), "the session stays dark");
        assert_eq!(
            served_at(&world, &vault_pointer_name(&SECRET, 0)),
            None,
            "nothing signs the pointer"
        );
        assert_eq!(
            abuse_reports(&mut events),
            usize::from(!vouched_below),
            "only a pointer both bars refuse is a trust violation"
        );
    }
}

/// ADR 0063 D4: unknown rotation debt refuses every revival, the walk's too.
/// While the owed rotation record does not read, the walk revives no lapsed
/// child and reports it once for the pass; after the record reads, the next
/// pass revives it.
#[test]
fn an_unread_owed_record_revives_no_lapsed_child_in_the_walk() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (name, before) = a_file_left_for_65_days(&world, &blocks);
    let lapsed = world.record_store.lapse(name.as_str()).expect("published");
    blocks.cache_for_recovery(name.as_str(), lapsed);
    let device = world.device(b"a later session");
    let owed = owed_rotation_key(&kdf::enc_subkey(&SECRET));
    device.staging_store.inner().fail_staged_reads_under(&owed);
    let (engine, mut events, mut tasks) = boot_to_the_first_walk(&world, &blocks, &device, 2);
    tick(&world, &engine, &mut tasks);

    assert_eq!(served_at(&world, &name), None, "the walk revives nothing");
    let refusals = core::iter::from_fn(|| events.try_next())
        .filter(|event| {
            matches!(event, Event::RenewalFailed { routing_key, detail }
                if routing_key == name.as_str() && detail.contains("did not revive"))
        })
        .count();
    assert_eq!(refusals, 1, "one report for the pass");

    device.staging_store.inner().heal_staged_reads();
    world.scheduler.advance(HOUR);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &name).sequence,
        before.sequence + 1,
        "the next pass revives the file"
    );
}

/// ADR 0062 D3: only a gated load that resolves the bin index lifts the drain
/// hold. While the start could not settle a lapsed bin index, a liveness pass
/// that reads the record once raw, before it vanishes, keeps the hold, so a
/// soft delete publishes nothing; the pass whose gated load resolves the
/// record lifts it. A served record past its EOL is lapsed, so that pass
/// revives it instead.
#[test]
fn only_a_gated_load_that_resolves_the_bin_index_lifts_the_hold() {
    for expired in [false, true] {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        written_then_left(&world, &blocks, |engine, tasks| {
            let binned = write_file(&world, engine, tasks, ROOT, "binned.txt");
            block_on(engine.command(Command::Delete { node: binned })).expect("the delete stages");
            tick(&world, engine, tasks);
            vec![binned]
        });
        let bin = bin_name();
        let before = record_at(&world, &bin);
        let bytes = served_at(&world, &bin).expect("the bin index is published");
        blocks.cache_for_recovery(
            bin.as_str(),
            world.record_store.lapse(bin.as_str()).unwrap(),
        );
        world
            .scheduler
            .advance(DAY * if expired { 100 } else { 30 });

        // The start reads the bin index `Unavailable`, and so does the first
        // liveness pass.
        let endpoints = world.record_store.endpoints();
        world
            .record_store
            .fail_get_at_for(&endpoints[0], bin.as_str());
        let device = world.device(b"a later session");
        let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 2);
        world.record_store.heal_get_for(bin.as_str());
        let fresh = write_file(&world, &mut engine, &mut tasks, ROOT, "fresh.txt");
        block_on(engine.command(Command::Delete { node: fresh })).expect("the delete stages");
        tick(&world, &engine, &mut tasks);
        assert_eq!(served_at(&world, &bin), None, "the drain is held");

        // The next liveness pass reads the record once, then it vanishes.
        world.record_store.serve_gets_for_after(
            bin.as_str(),
            0,
            endpoints.len(),
            Some(bytes.clone()),
        );
        world.scheduler.advance(RE_PUT_INTERVAL);
        tick(&world, &engine, &mut tasks);
        tick(&world, &engine, &mut tasks);
        if expired {
            assert_eq!(
                record_at(&world, &bin).sequence,
                before.sequence + 2,
                "the lapsed record revives, then the delete publishes its entry"
            );
            continue;
        }
        assert_eq!(served_at(&world, &bin), None, "a raw read lifts no hold");

        for endpoint in &endpoints {
            world
                .record_store
                .seed_record(endpoint, bin.as_str(), bytes.clone());
        }
        world.scheduler.advance(RE_PUT_INTERVAL);
        tick(&world, &engine, &mut tasks);
        tick(&world, &engine, &mut tasks);
        assert_eq!(
            record_at(&world, &bin).sequence,
            before.sequence + 1,
            "a gated load resolves the record, and the delete publishes its entry"
        );
    }
}

/// ADR 0066: after a bin index revival signs `S + 1`, a gated load that
/// resolves the older, expired record at `S` lifts no hold, or a drain write
/// would sign a second value at `S + 1`. The hold lifts only once a load
/// writes a sequence floor at `S + 1` or above.
#[test]
fn a_load_below_the_revived_sequence_keeps_the_bin_index_hold() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (_, before) = a_binned_vault_lapsed(&world, &blocks);
    let bin = bin_name();
    let old = expired_bin_record(&before);
    // Every read after the revival's PUT serves the record at `S` again.
    world
        .record_store
        .serve_after_put(bin.as_str(), 0, Some(old));
    // The first liveness pass meets a 429, so the start's hold stands.
    let fetches = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let device = world.device(b"a device after 100 days offline");
    {
        let (blocks, bin, fetches) = (blocks.clone(), bin.clone(), fetches.clone());
        serve_with(&device, &blocks.clone(), 4000, move |request| {
            if request
                .url
                .ends_with(&format!("/recovery/{}", bin.as_str()))
                && fetches.fetch_add(1, Ordering::SeqCst) == 1
            {
                blocks.throttle_recovery_once(bin.as_str());
            }
        });
    }
    let (mut engine, _events, mut tasks) = boot_served(&world, &device, 2);
    let revived = served_at(&world, &bin).expect("the revival landed");
    assert_eq!(record_at(&world, &bin).sequence, before.sequence + 1);
    let fresh = write_file(&world, &mut engine, &mut tasks, ROOT, "fresh.txt");
    block_on(engine.command(Command::Delete { node: fresh })).expect("the delete stages");
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        served_at(&world, &bin),
        Some(revived),
        "the drain signs nothing over the revived record"
    );

    world
        .record_store
        .serve_gets_for_after(bin.as_str(), 0, 0, None);
    world.scheduler.advance(RE_PUT_INTERVAL);
    tick(&world, &engine, &mut tasks);
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        record_at(&world, &bin).sequence,
        before.sequence + 2,
        "a load at S + 1 lifts the hold, and the delete publishes its entry"
    );
}

/// The bin index record `before` carries, signed again at its sequence with
/// an EOL long past: the older record that endpoints can serve again.
fn expired_bin_record(before: &VerifiedRecord) -> Vec<u8> {
    IpnsRecord::create_v2(
        &kdf::bin_index_ipns_keypair(&SECRET),
        &before.value,
        before.sequence,
        2_000_000_000,
        &eol_from(UnixMillis(0)),
    )
    .marshal()
}

/// ADR 0066: a bin index revival that lands raises the sequence floor to the
/// sequence it signed, though the gated load after it reads nothing. After a
/// restart that reads the revived record once and then the older record at
/// `S`, the drain refuses `S` and signs nothing at `S + 1` a second time.
#[test]
fn a_restart_after_a_bin_index_revival_signs_nothing_over_the_revived_record() {
    let world = FakeWorld::new();
    let blocks = Blocks::default();
    let (_, before) = a_binned_vault_lapsed(&world, &blocks);
    let bin = bin_name();
    let endpoints = world.record_store.endpoints().len();
    // The revival's confirm read finds `S + 1`; the gated load after it finds
    // nothing.
    world
        .record_store
        .serve_after_put(bin.as_str(), endpoints, None);
    let device = world.device(b"a device after 100 days offline");
    let (engine, _events, tasks) = boot(&world, &blocks, &device, 2);
    let revived = served_at(&world, &bin).expect("the revival landed");
    assert_eq!(record_at(&world, &bin).sequence, before.sequence + 1);
    assert_eq!(
        block_on(
            device
                .floors(&SECRET)
                .sequence_floor(bin.as_str().as_bytes())
        )
        .expect("the floor store answers"),
        Some(before.sequence + 1),
        "the confirmed revival raised the floor, with no gated load after it"
    );
    drop((tasks, engine));
    drop(world.scheduler.take_spawned_tasks());

    // The restart's first read finds `S + 1`; every read after it finds `S`.
    world.record_store.serve_gets_for_after(
        bin.as_str(),
        endpoints,
        usize::MAX,
        Some(expired_bin_record(&before)),
    );
    let (mut engine, _events, mut tasks) = boot(&world, &blocks, &device, 3);
    let fresh = write_file(&world, &mut engine, &mut tasks, ROOT, "fresh.txt");
    block_on(engine.command(Command::Delete { node: fresh })).expect("the delete stages");
    tick(&world, &engine, &mut tasks);
    assert_eq!(
        served_at(&world, &bin),
        Some(revived),
        "the drain signs nothing at S + 1 again"
    );
}
