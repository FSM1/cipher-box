//! The renewal walk (ADR 0061), end to end on the virtual clock: one device
//! writes and ends its session, and a session that starts later renews each
//! name the walk reaches, through the adoption gate, at `S + 1`.

use core::cell::RefCell;
use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};
use cipherbox_core::kdf;

use cipherbox_engine::net::eol::{eol_from, renewal_eol_from};
use cipherbox_engine::net::renewal_walk::WALK_BUDGET;
use cipherbox_engine::net::renewal_walk::cursor::{CursorStore, MAX_CURSOR_PATH};
use cipherbox_engine::seams::{BoxedTask, HttpMethod, RecordTransport, Scheduler, UnixMillis};
use cipherbox_engine::sync::BookkeepingSeal;
use cipherbox_engine::testkit::account::{Blocks, SECRET, seed_account};
use cipherbox_engine::testkit::{
    FakeDevice, FakeSeamTypes, FakeWorld, OWNER_ROOT_WRITE_SCOPE_SEED as WRITE_SCOPE_SEED,
    SeededEntropy, block_on, poll_tasks_until_parked,
};
use cipherbox_engine::{
    ApiBaseUrl, Command, ContentProfile, Engine, EventStream, GatewayConfig, LoginSecret, NodeId,
    NodeKind, StoragePolicy, SyncTimingProfile, WriteTarget,
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
    hook: impl Fn(&cipherbox_engine::seams::HttpRequest) + Send + Sync + 'static,
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
    block_on(engine.start(LoginSecret::new(SECRET.to_vec()))).expect("the session starts");
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
    let enc = kdf::enc_subkey(&SECRET);
    let entropy = RefCell::new(SeededEntropy::new(9));
    let cursor = block_on(
        CursorStore::new(
            &device.staging_store,
            BookkeepingSeal::new(&enc, &entropy),
            &enc,
        )
        .load(),
    )
    .expect("the store reads")
    .expect("the pass stored its cursor");
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
        let registers_the_file = request.method == HttpMethod::Post
            && request.url.ends_with("/registry/register")
            && request
                .body
                .as_deref()
                .is_some_and(|body| body.windows(key.len()).any(|w| w == key.as_bytes()));
        if registers_the_file && !hook_fired.swap(true, Ordering::SeqCst) {
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
