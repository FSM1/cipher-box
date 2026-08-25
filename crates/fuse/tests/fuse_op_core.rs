//! The `fuse-op-core` suite: every vfs operation driven against a real engine
//! over the in-memory seam fakes, plus the never-block law
//! (blueprint/desktop.md "Reads, writes, and the never-block law").
//!
//! No kernel: a recording adapter stands in for the mount so the outbound
//! invalidation direction is observable.

use std::cell::RefCell;
use std::future::Future;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use cipherbox_engine::seams::StagingStore;
use cipherbox_engine::testkit::fakes::{InMemoryStagingStore, VirtualScheduler};
use cipherbox_engine::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    ApiBaseUrl, Command, ContentProfile, DeadLetterReason, Engine, Event, EventStream,
    GatewayConfig, LoginSecret, NodeId, NodeKind, Staleness, StoragePolicy, SyncTimingProfile,
};
use cipherbox_fuse::{
    Access, CacheBudget, HandleId, HostAdapter, HostCapabilities, Invalidation, MAX_NAME_BYTES,
    NameError, OperationCore, OverBudgetCause, ROOT_INO, SpillArea, VfsError,
};

/// A spill area in a throwaway directory the mount outlives, so the directory
/// is kept rather than guarded; every spill file inside it still goes with its
/// handle.
fn spill_area() -> SpillArea {
    spill_area_at(&tempfile::tempdir().expect("a spill dir").keep())
}

/// A spill area over `dir`, seeded so two areas in one test never draw the same
/// per-handle keys.
fn spill_area_at(dir: &Path) -> SpillArea {
    static SEED: AtomicU64 = AtomicU64::new(11);
    let seed = SEED.fetch_add(1, Ordering::Relaxed);
    SpillArea::seeded(dir.to_path_buf(), Box::new(SeededEntropy::new(seed)))
        .expect("the spill area opens")
}

/// A mount that records what it was told to invalidate.
#[derive(Clone)]
struct RecordingAdapter {
    capabilities: HostCapabilities,
    seen: Rc<RefCell<Vec<Invalidation>>>,
}

/// The capabilities every mount in this suite starts from: a push-capable
/// backend that presents names the unix way.
fn base_capabilities() -> HostCapabilities {
    HostCapabilities {
        push_invalidation: true,
        attribute_cache: true,
        case_insensitive_lookup: false,
    }
}

impl RecordingAdapter {
    fn push_capable() -> Self {
        Self::declaring(base_capabilities())
    }

    fn declaring(capabilities: HostCapabilities) -> Self {
        Self {
            capabilities,
            seen: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn drain(&self) -> Vec<Invalidation> {
        self.seen.borrow_mut().drain(..).collect()
    }
}

impl HostAdapter for RecordingAdapter {
    fn capabilities(&self) -> HostCapabilities {
        self.capabilities
    }

    fn invalidate(&self, invalidation: Invalidation) {
        self.seen.borrow_mut().push(invalidation);
    }
}

type Core = OperationCore<FakeSeamTypes, RecordingAdapter>;

fn mount() -> (Core, RecordingAdapter) {
    let adapter = RecordingAdapter::push_capable();
    (mount_with(adapter.clone()), adapter)
}

fn mount_with(adapter: RecordingAdapter) -> Core {
    mount_seeded(adapter, &[])
}

/// A started engine over fresh in-memory seams, with its rendered root id.
fn started_engine() -> (Engine<FakeSeamTypes>, NodeId) {
    let started = started_engine_over_queue(&[]);
    (started.engine, started.root)
}

/// A started engine plus a handle on its durable op queue, for tests that
/// inject a staging outage.
fn started_engine_with_staging() -> (Engine<FakeSeamTypes>, NodeId, InMemoryStagingStore) {
    let started = started_engine_over_queue(&[]);
    (started.engine, started.root, started.staging)
}

/// Everything one cold start hands a test: the engine, what it rendered, and
/// the seams a test drives it through.
struct Started {
    engine: Engine<FakeSeamTypes>,
    root: NodeId,
    staging: InMemoryStagingStore,
    clock: VirtualScheduler,
    events: EventStream,
}

/// A started engine whose durable queue already held `entries` when cold start
/// read it — the only way to put a record there that this build cannot decode.
fn started_engine_over_queue(entries: &[&[u8]]) -> Started {
    let world = FakeWorld::new();
    let clock = world.scheduler.clone();
    let device = world.device(b"alice-pk");
    let staging = device.staging_store.clone();
    for entry in entries {
        block_on(staging.enqueue_op(entry)).expect("the queue takes the bytes");
    }
    let (mut engine, events) = Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(42)),
        SyncTimingProfile::CI,
        ContentProfile::CI,
        StoragePolicy::CI,
        ApiBaseUrl::offline(),
        GatewayConfig::disabled(),
    );
    block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("engine starts");
    let root = block_on(engine.view()).expect("view").root();
    Started {
        engine,
        root,
        staging,
        clock,
        events,
    }
}

/// Seed a child by issuing a facade command directly, which is how a name the
/// projection would never create — one another client committed — gets into
/// the rendered view.
fn seed_child(
    engine: &mut Engine<FakeSeamTypes>,
    parent: NodeId,
    name: &str,
    kind: NodeKind,
) -> NodeId {
    block_on(engine.command(Command::Create {
        parent,
        name: name.to_owned(),
        kind,
    }))
    .expect("seeded create");
    block_on(engine.view())
        .expect("view")
        .lookup(parent, name)
        .expect("seeded child is rendered")
        .id
}

/// A mount over `engine` whose invalidations nothing inspects.
fn mount_over(engine: Engine<FakeSeamTypes>) -> Core {
    OperationCore::new(
        engine,
        RecordingAdapter::push_capable(),
        CacheBudget::CI,
        spill_area(),
    )
}

/// Mount over an engine seeded with the given root children.
fn mount_seeded(adapter: RecordingAdapter, root_children: &[(&str, NodeKind)]) -> Core {
    mount_clocked(adapter, root_children).0
}

/// Throw away everything the engine has emitted so far.
fn drain_events(events: &mut EventStream) {
    while events.try_next().is_some() {}
}

/// Feed the mount everything the engine has emitted, the way the host's
/// event-stream task does, and report what came through.
fn absorb_pending(core: &mut Core, events: &mut EventStream) -> Vec<Event> {
    let mut seen = Vec::new();
    while let Some(event) = events.try_next() {
        block_on(core.absorb_event(&event)).expect("the mount absorbs the event");
        seen.push(event);
    }
    seen
}

/// A seeded mount plus its rendered root and the virtual clock its engine
/// reads, for the freshness tests: aging a snapshot advances that clock rather
/// than sleeping.
fn mount_clocked(
    adapter: RecordingAdapter,
    root_children: &[(&str, NodeKind)],
) -> (Core, NodeId, VirtualScheduler, EventStream) {
    let mut started = started_engine_over_queue(&[]);
    for (name, kind) in root_children {
        seed_child(&mut started.engine, started.root, name, *kind);
    }
    (
        OperationCore::new(started.engine, adapter, CacheBudget::CI, spill_area()),
        started.root,
        started.clock,
        started.events,
    )
}

/// Poll a future exactly once. `Ready` proves the operation reached its answer
/// without ever yielding — the never-block law's testable form.
fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    future.as_mut().poll(&mut cx)
}

fn names(core: &mut Core, ino: u64) -> Vec<String> {
    block_on(core.readdir(ino))
        .expect("readdir")
        .into_iter()
        .map(|entry| entry.name)
        .collect()
}

// --- the read surface ---

#[test]
fn an_empty_mount_lists_nothing_under_a_root_that_is_a_directory() {
    let (mut core, _adapter) = mount();
    assert!(names(&mut core, ROOT_INO).is_empty());
    let root = block_on(core.getattr(ROOT_INO)).expect("root getattr");
    assert_eq!(root.ino, ROOT_INO);
    assert_eq!(root.kind, NodeKind::Folder);
}

#[test]
fn created_nodes_are_immediately_visible_and_lookup_agrees_with_readdir() {
    let (mut core, _adapter) = mount();
    let folder = block_on(core.mkdir(ROOT_INO, "Photos")).expect("mkdir");
    let (file, _handle) = block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).unwrap();

    let found = block_on(core.lookup(ROOT_INO, "Photos")).expect("lookup");
    assert_eq!(found.ino, folder.ino);
    assert_eq!(found.kind, NodeKind::Folder);

    let listed = block_on(core.readdir(ROOT_INO)).unwrap();
    for entry in &listed {
        let looked_up = block_on(core.lookup(ROOT_INO, &entry.name)).unwrap();
        assert_eq!(looked_up.ino, entry.ino, "{} renumbered", entry.name);
    }
    assert!(listed.iter().any(|entry| entry.ino == file.ino));
    let mut listed_names = names(&mut core, ROOT_INO);
    listed_names.sort();
    assert_eq!(listed_names, vec!["Photos".to_owned(), "f.txt".to_owned()]);
}

#[test]
fn a_missing_name_is_not_found_and_a_file_is_not_a_directory() {
    let (mut core, _adapter) = mount();
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "nope")),
        Err(VfsError::NotFound)
    );
    let (file, _handle) = block_on(core.create(ROOT_INO, "f.txt", Access::Read)).unwrap();
    assert_eq!(
        block_on(core.readdir(file.ino)),
        Err(VfsError::NotADirectory)
    );
    assert_eq!(
        block_on(core.lookup(file.ino, "child")),
        Err(VfsError::NotADirectory)
    );
    assert_eq!(block_on(core.getattr(9999)), Err(VfsError::NotFound));
}

#[test]
fn statfs_counts_reachable_nodes_and_the_advertised_name_limit_is_enforced() {
    let (mut core, _adapter) = mount();
    assert_eq!(block_on(core.statfs()).unwrap().nodes, 1, "root only");
    block_on(core.mkdir(ROOT_INO, "a")).unwrap();
    block_on(core.create(ROOT_INO, "b", Access::Write)).unwrap();
    assert_eq!(block_on(core.statfs()).unwrap().nodes, 3);

    let longest = "x".repeat(MAX_NAME_BYTES);
    block_on(core.mkdir(ROOT_INO, &longest)).expect("the advertised limit is creatable");
    let too_long = "x".repeat(MAX_NAME_BYTES + 1);
    assert_eq!(
        block_on(core.mkdir(ROOT_INO, &too_long)),
        Err(VfsError::InvalidName(NameError::TooLong)),
        "one byte past the advertised limit is refused"
    );
}

// --- the never-block law ---

#[test]
fn the_read_surface_never_yields() {
    let (mut core, _adapter) = mount();
    block_on(core.mkdir(ROOT_INO, "dir")).unwrap();

    assert!(matches!(
        poll_once(core.readdir(ROOT_INO)),
        Poll::Ready(Ok(_))
    ));
    assert!(matches!(
        poll_once(core.lookup(ROOT_INO, "dir")),
        Poll::Ready(Ok(_))
    ));
    assert!(matches!(
        poll_once(core.getattr(ROOT_INO)),
        Poll::Ready(Ok(_))
    ));
    assert!(matches!(poll_once(core.statfs()), Poll::Ready(Ok(_))));
}

#[test]
fn a_cold_mount_reads_without_yielding() {
    // Nothing is cached and nothing has resolved: last-known-good still answers.
    let (mut core, _adapter) = mount();
    assert!(matches!(
        poll_once(core.readdir(ROOT_INO)),
        Poll::Ready(Ok(_))
    ));
}

// --- mutations ---

#[test]
fn create_opens_a_handle_that_releases_exactly_once() {
    let (mut core, _adapter) = mount();
    let (attrs, handle) = block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).unwrap();
    assert_eq!(core.handle(handle).unwrap().node, attrs.node);
    assert!(core.handle(handle).unwrap().access.writable());

    assert_eq!(block_on(core.release(handle)), Ok(()));
    assert_eq!(core.handle(handle), Err(VfsError::BadHandle));
    assert_eq!(block_on(core.release(handle)), Err(VfsError::BadHandle));
}

#[test]
fn opening_a_directory_is_refused_and_opening_a_file_is_not() {
    let (mut core, _adapter) = mount();
    let dir = block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    assert_eq!(
        block_on(core.open(dir.ino, Access::Read)),
        Err(VfsError::IsADirectory)
    );
    let (file, handle) = block_on(core.create(ROOT_INO, "f.txt", Access::Read)).unwrap();
    block_on(core.release(handle)).unwrap();
    let reopened = block_on(core.open(file.ino, Access::Read)).unwrap();
    assert_eq!(core.handle(reopened).unwrap().node, file.node);
}

#[test]
fn a_duplicate_name_is_refused_under_the_engines_strict_comparator() {
    let (mut core, _adapter) = mount();
    block_on(core.mkdir(ROOT_INO, "Photos")).unwrap();
    assert_eq!(
        block_on(core.mkdir(ROOT_INO, "Photos")),
        Err(VfsError::AlreadyExists)
    );
    assert_eq!(
        block_on(core.create(ROOT_INO, "photos", Access::Write)).err(),
        Some(VfsError::AlreadyExists),
        "uniqueness folds case on every platform"
    );
}

#[test]
fn unlink_and_rmdir_hold_each_other_to_their_own_kind() {
    let (mut core, _adapter) = mount();
    let dir = block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();

    assert_eq!(
        block_on(core.unlink(ROOT_INO, "dir")),
        Err(VfsError::IsADirectory)
    );
    assert_eq!(
        block_on(core.rmdir(ROOT_INO, "f.txt")),
        Err(VfsError::NotADirectory)
    );

    block_on(core.create(dir.ino, "inner", Access::Write)).unwrap();
    assert_eq!(
        block_on(core.rmdir(ROOT_INO, "dir")),
        Err(VfsError::NotEmpty)
    );
    block_on(core.unlink(dir.ino, "inner")).unwrap();
    block_on(core.rmdir(ROOT_INO, "dir")).unwrap();

    block_on(core.unlink(ROOT_INO, "f.txt")).unwrap();
    assert!(names(&mut core, ROOT_INO).is_empty());
    assert_eq!(
        block_on(core.unlink(ROOT_INO, "f.txt")),
        Err(VfsError::NotFound)
    );
}

#[test]
fn an_inode_survives_a_rename() {
    let (mut core, _adapter) = mount();
    let (before, _handle) = block_on(core.create(ROOT_INO, "old.txt", Access::Write)).unwrap();

    block_on(core.rename(ROOT_INO, "old.txt", ROOT_INO, "new.txt")).unwrap();

    assert_eq!(
        block_on(core.lookup(ROOT_INO, "old.txt")),
        Err(VfsError::NotFound)
    );
    let after = block_on(core.lookup(ROOT_INO, "new.txt")).unwrap();
    assert_eq!(after.ino, before.ino, "renaming must not renumber the node");
    assert_eq!(block_on(core.getattr(before.ino)).unwrap().ino, before.ino);
}

#[test]
fn an_inode_survives_a_move_between_directories() {
    let (mut core, _adapter) = mount();
    let dir = block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    let (file, _handle) = block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();

    block_on(core.rename(ROOT_INO, "f.txt", dir.ino, "moved.txt")).unwrap();

    assert_eq!(names(&mut core, ROOT_INO), vec!["dir".to_owned()]);
    let moved = block_on(core.lookup(dir.ino, "moved.txt")).unwrap();
    assert_eq!(moved.ino, file.ino);
}

#[test]
fn rename_over_an_existing_file_replaces_it() {
    let (mut core, _adapter) = mount();
    let (source, _a) = block_on(core.create(ROOT_INO, "new.txt", Access::Write)).unwrap();
    let (victim, _b) = block_on(core.create(ROOT_INO, "target.txt", Access::Write)).unwrap();
    assert_ne!(source.ino, victim.ino);

    block_on(core.rename(ROOT_INO, "new.txt", ROOT_INO, "target.txt")).unwrap();

    assert_eq!(names(&mut core, ROOT_INO), vec!["target.txt".to_owned()]);
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "target.txt")).unwrap().ino,
        source.ino,
        "the surviving entry is the source node, not the replaced one"
    );
}

#[test]
fn a_durable_queue_outage_never_destroys_the_destination_a_rename_did_not_replace() {
    // POSIX: an observer always sees either the old destination or the new one.
    // A rename that replaces is one journal entry, so a queue that accepts only
    // one more write either takes the whole rename or none of it — never the
    // destination's removal while the source stays put.
    for budget in [0, 1] {
        let (mut engine, root, staging) = started_engine_with_staging();
        let source = seed_child(&mut engine, root, "new.txt", NodeKind::File);
        let victim = seed_child(&mut engine, root, "target.txt", NodeKind::File);
        let mut core = mount_over(engine);
        staging.fail_enqueue_after(budget);

        let outcome = block_on(core.rename(ROOT_INO, "new.txt", ROOT_INO, "target.txt"));

        // The destination name resolves either way: to the moved node when the
        // rename landed, to the node it would have replaced when it did not.
        let survivor = block_on(core.lookup(ROOT_INO, "target.txt"))
            .unwrap_or_else(|_| panic!("budget {budget}: the destination name vanished"))
            .node;
        let landed = outcome.is_ok();
        assert_eq!(survivor, if landed { source } else { victim });
        assert_eq!(
            names(&mut core, ROOT_INO).len(),
            if landed { 1 } else { 2 },
            "budget {budget}: a refused rename left something half-done"
        );
    }
}

#[test]
fn renaming_a_node_onto_itself_journals_nothing() {
    // POSIX `rename(a, a)` succeeds and changes nothing, so it must not spend a
    // journal entry — proven by refusing every durable write.
    let (mut engine, root, staging) = started_engine_with_staging();
    seed_child(&mut engine, root, "f.txt", NodeKind::File);
    let mut core = mount_over(engine);
    staging.fail_enqueue_after(0);

    block_on(core.rename(ROOT_INO, "f.txt", ROOT_INO, "f.txt")).expect("a no-op rename succeeds");
    assert_eq!(names(&mut core, ROOT_INO), vec!["f.txt".to_owned()]);
}

#[test]
fn replacing_a_junk_holding_folder_keeps_the_destination_entry_when_the_queue_fails() {
    // The replaced folder's own unlink rides the move, but the hidden junk it
    // holds still needs deletes of its own. A queue that dies between them may
    // lose junk the user could never see — never the destination entry itself.
    let (mut engine, root, staging) = started_engine_with_staging();
    let source = seed_child(&mut engine, root, "dir", NodeKind::Folder);
    let victim = seed_child(&mut engine, root, "target", NodeKind::Folder);
    seed_child(&mut engine, victim, ".DS_Store", NodeKind::File);
    let mut core = mount_over(engine);
    // The junk delete lands; the move that would unlink the folder does not.
    staging.fail_enqueue_after(1);

    block_on(core.rename(ROOT_INO, "dir", ROOT_INO, "target")).expect_err("the move is refused");

    assert_eq!(
        block_on(core.lookup(ROOT_INO, "target")).unwrap().node,
        victim,
        "the destination entry POSIX promises survives"
    );
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "dir")).unwrap().node,
        source,
        "and the source never moved"
    );
}

#[test]
fn rename_refuses_to_replace_across_kinds_or_over_a_populated_directory() {
    let (mut core, _adapter) = mount();
    block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();
    let dir = block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    let full = block_on(core.mkdir(ROOT_INO, "full")).unwrap();
    block_on(core.create(full.ino, "inner", Access::Write)).unwrap();

    assert_eq!(
        block_on(core.rename(ROOT_INO, "f.txt", ROOT_INO, "dir")),
        Err(VfsError::IsADirectory)
    );
    assert_eq!(
        block_on(core.rename(ROOT_INO, "dir", ROOT_INO, "f.txt")),
        Err(VfsError::NotADirectory)
    );
    assert_eq!(
        block_on(core.rename(ROOT_INO, "dir", ROOT_INO, "full")),
        Err(VfsError::NotEmpty)
    );
    // Nothing moved.
    assert_eq!(block_on(core.lookup(ROOT_INO, "dir")).unwrap().ino, dir.ino);
}

#[test]
fn a_case_only_rename_respells_rather_than_replacing_the_node() {
    let (mut core, _adapter) = mount();
    let (file, _handle) = block_on(core.create(ROOT_INO, "notes.txt", Access::Write)).unwrap();

    block_on(core.rename(ROOT_INO, "notes.txt", ROOT_INO, "Notes.txt")).unwrap();

    assert_eq!(names(&mut core, ROOT_INO), vec!["Notes.txt".to_owned()]);
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "Notes.txt")).unwrap().ino,
        file.ino
    );
}

#[test]
fn a_rename_onto_a_missing_source_or_a_bad_name_changes_nothing() {
    let (mut core, _adapter) = mount();
    block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();

    assert_eq!(
        block_on(core.rename(ROOT_INO, "ghost", ROOT_INO, "x")),
        Err(VfsError::NotFound)
    );
    assert_eq!(
        block_on(core.rename(ROOT_INO, "f.txt", ROOT_INO, "a/b")),
        Err(VfsError::InvalidName(NameError::Separator))
    );
    assert_eq!(names(&mut core, ROOT_INO), vec!["f.txt".to_owned()]);
}

// --- name admission ---

#[test]
fn platform_junk_cannot_be_created_through_the_mount() {
    let (mut core, _adapter) = mount();
    for name in [".DS_Store", "Thumbs.db", "._resource", ".Trash-1000"] {
        assert_eq!(
            block_on(core.create(ROOT_INO, name, Access::Write)).err(),
            Some(VfsError::InvalidName(NameError::PlatformJunk)),
            "{name} must not enter the vault"
        );
        assert_eq!(
            block_on(core.mkdir(ROOT_INO, name)),
            Err(VfsError::InvalidName(NameError::PlatformJunk))
        );
    }
    assert!(names(&mut core, ROOT_INO).is_empty());
}

#[test]
fn removal_does_not_gate_on_name_admission() {
    let (mut core, _adapter) = mount();
    for name in [".DS_Store", "re:port", "COM1"] {
        assert_eq!(
            block_on(core.unlink(ROOT_INO, name)),
            Err(VfsError::NotFound),
            "{name} must reach the lookup, not a name guard"
        );
        assert_eq!(
            block_on(core.rmdir(ROOT_INO, name)),
            Err(VfsError::NotFound)
        );
    }
}

// --- the outbound adapter direction ---

#[test]
fn every_mutation_pushes_an_invalidation_at_the_mount() {
    let (mut core, adapter) = mount();

    block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    assert_eq!(
        adapter.drain(),
        vec![Invalidation::Entry {
            parent: ROOT_INO,
            name: "dir".to_owned()
        }]
    );

    block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();
    assert_eq!(
        adapter.drain(),
        vec![Invalidation::Entry {
            parent: ROOT_INO,
            name: "f.txt".to_owned()
        }]
    );

    block_on(core.unlink(ROOT_INO, "f.txt")).unwrap();
    assert_eq!(
        adapter.drain(),
        vec![Invalidation::Entry {
            parent: ROOT_INO,
            name: "f.txt".to_owned()
        }]
    );

    let dir = block_on(core.lookup(ROOT_INO, "dir")).unwrap();
    block_on(core.rename(ROOT_INO, "dir", ROOT_INO, "renamed")).unwrap();
    assert_eq!(
        adapter.drain(),
        vec![
            Invalidation::Entry {
                parent: ROOT_INO,
                name: "dir".to_owned()
            },
            Invalidation::Entry {
                parent: ROOT_INO,
                name: "renamed".to_owned()
            },
            Invalidation::Attributes { ino: dir.ino },
        ]
    );
}

#[test]
fn a_refused_operation_pushes_nothing() {
    let (mut core, adapter) = mount();
    block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    adapter.drain();

    block_on(core.mkdir(ROOT_INO, ".DS_Store")).unwrap_err();
    block_on(core.mkdir(ROOT_INO, "dir")).unwrap_err();
    block_on(core.unlink(ROOT_INO, "ghost")).unwrap_err();

    assert!(
        adapter.drain().is_empty(),
        "the kernel is only told about changes that happened"
    );
}

// --- freshness: the FUSE-op TTL check and the focus window ---

/// The staleness threshold this mount's engine runs under.
fn stale_after() -> core::time::Duration {
    SyncTimingProfile::CI.stale_after
}

#[test]
fn a_read_path_operation_past_the_staleness_threshold_hints_a_refresh_for_its_folder() {
    let (mut core, root, clock, _events) = mount_clocked(RecordingAdapter::push_capable(), &[]);

    block_on(core.readdir(ROOT_INO)).expect("readdir");
    assert_eq!(
        core.last_refresh_hint(),
        Some(root),
        "a folder no pass has refreshed is stale"
    );

    block_on(core.readdir(ROOT_INO)).expect("readdir");
    assert_eq!(
        core.last_refresh_hint(),
        None,
        "inside the threshold the hint already filed covers the access"
    );

    clock.advance(stale_after());
    block_on(core.readdir(ROOT_INO)).expect("readdir");
    assert_eq!(
        core.last_refresh_hint(),
        Some(root),
        "past the threshold the folder is stale again"
    );
}

#[test]
fn every_read_path_operation_runs_the_ttl_check_against_the_node_it_has_in_view() {
    let (mut core, root, clock, _events) = mount_clocked(
        RecordingAdapter::push_capable(),
        &[("notes.txt", NodeKind::File)],
    );
    let file = block_on(core.lookup(ROOT_INO, "notes.txt")).expect("lookup");
    assert_eq!(core.last_refresh_hint(), Some(root), "a lookup's parent");

    clock.advance(stale_after());
    block_on(core.getattr(ROOT_INO)).expect("getattr");
    assert_eq!(
        core.last_refresh_hint(),
        Some(root),
        "a getattr on a folder is that folder"
    );

    clock.advance(stale_after());
    block_on(core.getattr(file.ino)).expect("getattr");
    let hinted = core.last_refresh_hint().expect("a stale file fires a hint");
    assert_ne!(
        hinted, root,
        "a getattr on a file puts the file itself in view: its size and mtime are in its own record, not the parent's listing"
    );
}

/// The never-block law: the TTL check fires a hint, it never turns a callback
/// into a resolve.
#[test]
fn a_stale_hit_answers_from_the_render_without_yielding() {
    let (mut core, root, clock, _events) = mount_clocked(
        RecordingAdapter::push_capable(),
        &[("notes.txt", NodeKind::File)],
    );
    block_on(core.readdir(ROOT_INO)).expect("readdir");

    clock.advance(stale_after());
    assert!(poll_once(core.readdir(ROOT_INO)).is_ready());
    assert_eq!(core.last_refresh_hint(), Some(root));

    clock.advance(stale_after());
    assert!(poll_once(core.lookup(ROOT_INO, "notes.txt")).is_ready());
    assert_eq!(core.last_refresh_hint(), Some(root));

    clock.advance(stale_after());
    assert!(poll_once(core.getattr(ROOT_INO)).is_ready());
    assert_eq!(
        core.last_refresh_hint(),
        Some(root),
        "every stale hit answers from the render it already has, and still hints"
    );
}

/// The op stream is the desktop focus trigger: a folder the kernel touched is
/// the open folder, and the engine's tick refreshes it. Closing a window the
/// stream stopped feeding is the tick's own job (`focus_window_expired`) — an
/// operation that never arrives cannot close anything.
#[test]
fn fuse_traffic_puts_a_folder_in_the_focus_set() {
    let (mut core, root, _clock, _events) = mount_clocked(
        RecordingAdapter::push_capable(),
        &[("notes.txt", NodeKind::File), ("sub", NodeKind::Folder)],
    );
    assert_eq!(core.engine_mut().focus_folder(), None);

    let sub = block_on(core.lookup(ROOT_INO, "sub")).expect("lookup");
    assert_eq!(
        core.engine_mut().focus_folder(),
        Some(root),
        "a lookup puts the folder it searched in view"
    );

    block_on(core.readdir(sub.ino)).expect("readdir");
    assert_eq!(
        core.engine_mut().focus_folder(),
        Some(sub.node),
        "the window follows the op stream into the folder it descends into"
    );
}

/// The gap that closes v1's dir-TTL-0 and pump-thread workarounds: nothing on
/// the callback path knows a listing the kernel holds went stale, so the event
/// stream is what tells the mount to repaint it.
#[test]
fn a_snapshot_the_mount_did_not_author_invalidates_the_listing_the_kernel_holds() {
    let adapter = RecordingAdapter::push_capable();
    let (mut core, root, _clock, mut events) = mount_clocked(adapter.clone(), &[]);
    block_on(core.readdir(ROOT_INO)).expect("the kernel takes the listing");
    adapter.drain();
    drain_events(&mut events);

    // Straight at the facade: the mount performed no operation, so nothing on
    // its own path could have pushed anything.
    seed_child(
        core.engine_mut(),
        root,
        "from-elsewhere.txt",
        NodeKind::File,
    );
    let seen = absorb_pending(&mut core, &mut events);

    assert!(seen.contains(&Event::SnapshotUpdated), "{seen:?}");
    assert_eq!(
        adapter.drain(),
        vec![Invalidation::Entry {
            parent: ROOT_INO,
            name: "from-elsewhere.txt".to_owned(),
        }],
        "the one entry that moved, and nothing else"
    );
}

#[test]
fn a_snapshot_that_moved_nothing_the_kernel_holds_invalidates_nothing() {
    let adapter = RecordingAdapter::push_capable();
    let (mut core, _root, _clock, mut events) = mount_clocked(
        adapter.clone(),
        &[("notes.txt", NodeKind::File), ("sub", NodeKind::Folder)],
    );
    let sub = block_on(core.lookup(ROOT_INO, "sub")).expect("lookup");
    block_on(core.readdir(sub.ino)).expect("the kernel takes the listing");
    adapter.drain();
    drain_events(&mut events);

    block_on(core.absorb_event(&Event::SnapshotUpdated)).expect("the mount absorbs");

    assert!(
        adapter.drain().is_empty(),
        "the kernel is only told about state that actually moved"
    );
}

/// An invalidation does not oblige the kernel to come back — a read on an open
/// fd is answered from its page cache — so a mount that forgot what it just
/// invalidated would measure the next change against nothing. Uninvalidated
/// cached data never revalidates, which is the failure this whole path exists
/// to prevent.
#[test]
fn a_second_change_with_no_kernel_callback_in_between_is_still_pushed() {
    let adapter = RecordingAdapter::push_capable();
    let (mut core, root, _clock, mut events) = mount_clocked(adapter.clone(), &[]);
    block_on(core.readdir(ROOT_INO)).expect("the kernel takes the listing");
    adapter.drain();
    drain_events(&mut events);

    seed_child(core.engine_mut(), root, "first.txt", NodeKind::File);
    absorb_pending(&mut core, &mut events);
    assert!(adapter.drain().contains(&Invalidation::Entry {
        parent: ROOT_INO,
        name: "first.txt".to_owned(),
    }));

    // No readdir in between: nothing re-seeds the mount's baseline.
    seed_child(core.engine_mut(), root, "second.txt", NodeKind::File);
    absorb_pending(&mut core, &mut events);

    assert!(
        adapter.drain().contains(&Invalidation::Entry {
            parent: ROOT_INO,
            name: "second.txt".to_owned(),
        }),
        "the repaint measures against the state it last computed, not against nothing"
    );
}

/// A name reused for a different node is a change the kernel cannot see by
/// counting entries, and an uninvalidated one never revalidates.
#[test]
fn a_name_rebound_to_a_different_node_invalidates_its_entry() {
    let adapter = RecordingAdapter::push_capable();
    let (mut core, root, _clock, mut events) =
        mount_clocked(adapter.clone(), &[("notes.txt", NodeKind::File)]);
    let original = block_on(core.lookup(ROOT_INO, "notes.txt")).expect("lookup");
    block_on(core.readdir(ROOT_INO)).expect("the kernel takes the listing");
    adapter.drain();
    drain_events(&mut events);

    block_on(core.engine_mut().command(Command::Delete {
        node: original.node,
    }))
    .expect("the delete stages");
    seed_child(core.engine_mut(), root, "notes.txt", NodeKind::File);
    absorb_pending(&mut core, &mut events);

    assert!(
        adapter.drain().contains(&Invalidation::Entry {
            parent: ROOT_INO,
            name: "notes.txt".to_owned(),
        }),
        "the name survived, the node behind it did not"
    );
}

/// A host that presents names case-insensitively — the Windows convention —
/// resolves a respelling to the child stored as entered, and the listing keeps
/// showing the stored spelling (blueprint/desktop.md "Names and attributes").
#[test]
fn a_case_insensitive_host_resolves_a_respelling_to_the_name_as_entered() {
    let mut core = mount_with(RecordingAdapter::declaring(HostCapabilities {
        case_insensitive_lookup: true,
        ..base_capabilities()
    }));
    let created = block_on(core.create(ROOT_INO, "Report.txt", Access::ReadWrite)).expect("create");

    let found = block_on(core.lookup(ROOT_INO, "REPORT.TXT")).expect("the respelling resolves");
    assert_eq!(found.node, created.0.node);
    assert_eq!(
        block_on(core.readdir(ROOT_INO))
            .expect("listing")
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>(),
        vec!["Report.txt".to_owned()],
        "the stored name is never mutated by how it was looked up"
    );
}

/// Case-sensitive presentation is the unix convention, and it has to hold for
/// every operation that names an existing node — a mount whose `lookup` says a
/// respelling does not exist must not delete through it.
#[test]
fn a_case_sensitive_host_resolves_no_respelling_at_all() {
    let (mut core, _adapter) = mount();
    block_on(core.create(ROOT_INO, "Report.txt", Access::ReadWrite)).expect("create");

    assert_eq!(
        block_on(core.lookup(ROOT_INO, "REPORT.TXT")),
        Err(VfsError::NotFound)
    );
    assert_eq!(
        block_on(core.unlink(ROOT_INO, "REPORT.TXT")),
        Err(VfsError::NotFound)
    );
    assert_eq!(
        block_on(core.rename(ROOT_INO, "REPORT.TXT", ROOT_INO, "other.txt")),
        Err(VfsError::NotFound)
    );
    block_on(core.lookup(ROOT_INO, "Report.txt")).expect("the stored spelling resolves");
}

/// A listing binds the kernel's entry to the stored spelling and a respelled
/// lookup binds another to the one the caller typed. `notify_inval_entry`
/// matches one exact name, so a mutation that named either alone would leave
/// the other serving a node that has moved for its whole TTL.
#[test]
fn a_respelled_mutation_invalidates_every_spelling_the_kernel_cached() {
    let adapter = RecordingAdapter::declaring(HostCapabilities {
        case_insensitive_lookup: true,
        ..base_capabilities()
    });
    let mut core = mount_with(adapter.clone());
    block_on(core.create(ROOT_INO, "Report.txt", Access::ReadWrite)).expect("create");
    block_on(core.mkdir(ROOT_INO, "Archive")).expect("mkdir");
    adapter.drain();

    block_on(core.rename(ROOT_INO, "REPORT.TXT", ROOT_INO, "moved.txt")).expect("rename");
    assert_invalidates_names(&adapter.drain(), ROOT_INO, &["Report.txt", "REPORT.TXT"]);

    block_on(core.rmdir(ROOT_INO, "ARCHIVE")).expect("rmdir");
    assert_invalidates_names(&adapter.drain(), ROOT_INO, &["Archive", "ARCHIVE"]);
}

/// A rename's destination is resolved by the folding comparator on every host,
/// so the node it replaces can be cached under a spelling this rename never
/// mentions — and the entry left behind points at an unlinked node.
#[test]
fn a_replacing_rename_invalidates_the_displaced_spelling_too() {
    let (mut core, adapter) = mount();
    block_on(core.create(ROOT_INO, "report.txt", Access::ReadWrite)).expect("create");
    block_on(core.create(ROOT_INO, "draft.txt", Access::ReadWrite)).expect("create");
    adapter.drain();

    block_on(core.rename(ROOT_INO, "draft.txt", ROOT_INO, "REPORT.TXT")).expect("rename");
    assert_invalidates_names(
        &adapter.drain(),
        ROOT_INO,
        &["draft.txt", "REPORT.TXT", "report.txt"],
    );
}

/// The junk fold is the one respelling an exact host still resolves, so it is
/// the one an exact host can also leave a stale entry behind for.
#[test]
fn a_junk_removal_invalidates_the_spelling_it_was_asked_for() {
    let adapter = RecordingAdapter::push_capable();
    let mut core = mount_seeded(adapter.clone(), &[(".Ds_StOrE", NodeKind::File)]);
    block_on(core.lookup(ROOT_INO, ".DS_Store")).expect("the canonical spelling resolves");
    adapter.drain();

    block_on(core.unlink(ROOT_INO, ".DS_Store")).expect("unlink");
    assert_invalidates_names(&adapter.drain(), ROOT_INO, &[".Ds_StOrE", ".DS_Store"]);
}

/// Every name in `names` was invalidated under `parent`, spelled exactly so.
fn assert_invalidates_names(seen: &[Invalidation], parent: u64, names: &[&str]) {
    for name in names {
        assert!(
            seen.contains(&Invalidation::Entry {
                parent,
                name: (*name).to_owned(),
            }),
            "no invalidation named {name}: {seen:?}"
        );
    }
}

/// Junk another client committed is hidden from every listing, so the
/// canonical spelling is the only one a user can type. A host that resolves
/// names exactly still has to find it, or a peer could park an unlistable,
/// unremovable node at the vault root by spelling it oddly.
#[test]
fn hidden_junk_stays_removable_under_a_spelling_no_listing_shows() {
    let (mut engine, root) = started_engine();
    seed_child(&mut engine, root, ".Ds_StOrE", NodeKind::File);
    let mut core = mount_over(engine);

    assert!(
        block_on(core.readdir(ROOT_INO))
            .expect("listing")
            .is_empty(),
        "junk is hidden however it is spelled"
    );
    block_on(core.lookup(ROOT_INO, ".DS_Store")).expect("the canonical spelling resolves");
    block_on(core.unlink(ROOT_INO, ".DS_Store")).expect("and removes it");
}

/// The junk fold is for junk only: an ordinary name a listing does show is
/// resolved exactly, so the fold cannot become a general case-insensitive
/// back door on a host that presents names the unix way.
#[test]
fn the_junk_fold_does_not_reach_an_ordinary_name() {
    let (mut engine, root) = started_engine();
    seed_child(&mut engine, root, "Report.txt", NodeKind::File);
    let mut core = mount_over(engine);

    assert_eq!(
        block_on(core.lookup(ROOT_INO, "REPORT.TXT")),
        Err(VfsError::NotFound)
    );
}

/// Presentation is not collision policy: however a host spells a lookup, two
/// names that fold together are one name to the engine's strict comparator, on
/// every platform, so a folder committed anywhere mounts everywhere.
#[test]
fn the_strict_comparator_decides_collisions_whatever_the_host_presents() {
    for case_insensitive_lookup in [true, false] {
        let mut core = mount_with(RecordingAdapter::declaring(HostCapabilities {
            case_insensitive_lookup,
            ..base_capabilities()
        }));
        block_on(core.create(ROOT_INO, "Report.txt", Access::ReadWrite)).expect("create");
        assert_eq!(
            block_on(core.create(ROOT_INO, "report.txt", Access::ReadWrite)).err(),
            Some(VfsError::AlreadyExists),
            "case-insensitive presentation: {case_insensitive_lookup}"
        );
        assert_eq!(
            block_on(core.mkdir(ROOT_INO, "REPORT.TXT")).err(),
            Some(VfsError::AlreadyExists)
        );
    }
}

#[test]
fn a_noattrcache_mount_keeps_its_entry_cache_and_loses_only_the_attribute_one() {
    let (with_attrs, _adapter) = mount();
    let suppressed = mount_with(RecordingAdapter::declaring(HostCapabilities {
        attribute_cache: false,
        ..base_capabilities()
    }));

    assert!(
        suppressed.cache_ttls().attr.is_zero(),
        "there is no attribute cache to time out"
    );
    assert_eq!(
        suppressed.cache_ttls().entry,
        with_attrs.cache_ttls().entry,
        "noattrcache suppresses attributes, not name lookups"
    );
}

#[test]
fn a_mount_that_cannot_push_gets_a_shorter_cache_ttl() {
    let (with_push, _adapter) = mount();
    let without_push = mount_with(RecordingAdapter::declaring(HostCapabilities {
        push_invalidation: false,
        ..base_capabilities()
    }));

    assert!(without_push.cache_ttls().entry < with_push.cache_ttls().entry);
    assert!(!without_push.cache_ttls().attr.is_zero());
}

// --- names arriving from other clients ---

#[test]
fn a_name_no_kernel_could_carry_never_reaches_a_listing() {
    // Nothing below the facade validates names: a peer on any client can
    // commit whatever text string it likes, and this crate is the only
    // enforcement point in the stack.
    let hostile = [
        "a/b",
        "a\\b",
        "..",
        ".",
        "",
        "a\0b",
        "a\nb",
        &"x".repeat(MAX_NAME_BYTES + 1),
    ];
    let seed: Vec<(&str, NodeKind)> = hostile
        .iter()
        .map(|name| (*name, NodeKind::File))
        .chain([("keeper.txt", NodeKind::File)])
        .collect();
    let mut core = mount_seeded(RecordingAdapter::push_capable(), &seed);

    assert_eq!(names(&mut core, ROOT_INO), vec!["keeper.txt".to_owned()]);
    for name in hostile {
        assert_eq!(
            block_on(core.lookup(ROOT_INO, name)),
            Err(VfsError::NotFound),
            "{name:?} must not resolve through the mount"
        );
    }
}

#[test]
fn a_folder_holding_only_hidden_junk_is_removable() {
    // Junk is hidden from listings, so a user who cannot see it could never
    // clear it by hand; the folder must not be stranded behind ENOTEMPTY.
    let mut core = seeded_junk_folder();
    let dir = block_on(core.lookup(ROOT_INO, "dir")).unwrap();
    assert!(names(&mut core, dir.ino).is_empty(), "junk stays hidden");

    block_on(core.rmdir(ROOT_INO, "dir")).expect("a junk-only folder is empty to the user");
    assert!(names(&mut core, ROOT_INO).is_empty());
}

#[test]
fn removing_a_junk_only_folder_sweeps_what_the_junk_itself_holds() {
    // A junk *folder* can hold real descendants the user can never see, let
    // alone clear. One delete per direct child would leave them behind with
    // no reachable parent.
    let mut core = seeded_nested_junk_folder();
    let dir = block_on(core.lookup(ROOT_INO, "dir")).unwrap();
    let junk = block_on(core.lookup(dir.ino, ".Trash-1000")).unwrap();
    let buried = block_on(core.lookup(junk.ino, "buried.txt")).unwrap();

    block_on(core.rmdir(ROOT_INO, "dir")).expect("a junk-only folder is empty to the user");

    assert_eq!(block_on(core.getattr(junk.ino)), Err(VfsError::NotFound));
    assert_eq!(
        block_on(core.getattr(buried.ino)),
        Err(VfsError::NotFound),
        "nothing survives the swept subtree"
    );
}

/// A `dir` holding one `.DS_Store` and nothing else, both committed elsewhere.
fn seeded_junk_folder() -> Core {
    let (mut engine, root) = started_engine();
    let dir = seed_child(&mut engine, root, "dir", NodeKind::Folder);
    seed_child(&mut engine, dir, ".DS_Store", NodeKind::File);
    mount_over(engine)
}

/// A `dir` holding one junk-prefixed folder, which itself holds a real file.
fn seeded_nested_junk_folder() -> Core {
    let (mut engine, root) = started_engine();
    let dir = seed_child(&mut engine, root, "dir", NodeKind::Folder);
    let junk = seed_child(&mut engine, dir, ".Trash-1000", NodeKind::Folder);
    seed_child(&mut engine, junk, "buried.txt", NodeKind::File);
    mount_over(engine)
}

// --- structurally impossible moves ---

#[test]
fn a_folder_cannot_be_moved_inside_itself() {
    let (mut core, _adapter) = mount();
    let outer = block_on(core.mkdir(ROOT_INO, "outer")).unwrap();
    let inner = block_on(core.mkdir(outer.ino, "inner")).unwrap();

    assert_eq!(
        block_on(core.rename(ROOT_INO, "outer", outer.ino, "loop")),
        Err(VfsError::Invalid),
        "a folder is not its own parent"
    );
    assert_eq!(
        block_on(core.rename(ROOT_INO, "outer", inner.ino, "loop")),
        Err(VfsError::Invalid),
        "nor its descendant's"
    );

    // The subtree is still reachable from the root.
    assert_eq!(names(&mut core, ROOT_INO), vec!["outer".to_owned()]);
    assert_eq!(names(&mut core, outer.ino), vec!["inner".to_owned()]);
}

// --- attributes ---

#[test]
fn an_unprojected_size_is_reported_as_unknown_never_as_empty() {
    // A kernel told st_size == 0 stops reading at byte zero, so `cp` would
    // write an empty copy of a file whose bytes simply have not landed yet.
    let (mut core, _adapter) = mount();
    let (file, _handle) = block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();
    assert_eq!(file.size, None);
    assert_eq!(block_on(core.getattr(file.ino)).unwrap().size, None);
}

// --- the content read path ---

#[test]
fn reading_content_that_was_never_published_is_unavailable_rather_than_a_hang() {
    // A file created through the mount has no version yet: the read must land
    // on an availability verdict the adapter can turn into an errno, and it
    // must land on it now.
    let (mut core, _adapter) = mount();
    let (_file, handle) = block_on(core.create(ROOT_INO, "f.txt", Access::Read)).unwrap();

    let Poll::Ready(outcome) = poll_once(core.read(handle, 0, 16)) else {
        panic!("a read with nothing to fetch parked instead of answering");
    };
    assert!(
        matches!(outcome, Err(VfsError::Unavailable { .. })),
        "expected an availability verdict, got {outcome:?}"
    );
}

#[test]
fn a_read_through_a_write_only_handle_is_refused() {
    let (mut core, _adapter) = mount();
    let (_file, handle) = block_on(core.create(ROOT_INO, "f.txt", Access::Write)).unwrap();
    assert_eq!(block_on(core.read(handle, 0, 16)), Err(VfsError::BadHandle));
    assert_eq!(
        block_on(core.read(HandleId(9999), 0, 16)),
        Err(VfsError::BadHandle)
    );
}

// --- the content write path ---

/// A mount spilling into `dir`, plus the durable queue behind it. The dir is
/// the caller's, so a test can look at the ciphertext a write leaves there.
fn mount_spilling_into(dir: &Path) -> (Core, InMemoryStagingStore) {
    let (engine, _root, staging) = started_engine_with_staging();
    let core = OperationCore::new(
        engine,
        RecordingAdapter::push_capable(),
        CacheBudget::CI,
        spill_area_at(dir),
    );
    (core, staging)
}

/// How many ops the durable queue holds.
fn queued(staging: &InMemoryStagingStore) -> usize {
    block_on(staging.queued_ops())
        .expect("the queue reads")
        .len()
}

/// Every spill file's bytes, in a stable order.
fn spill_files(dir: &Path) -> Vec<Vec<u8>> {
    let mut files: Vec<Vec<u8>> = std::fs::read_dir(dir)
        .expect("the spill dir reads")
        .map(|entry| std::fs::read(entry.expect("an entry").path()).expect("spill bytes"))
        .collect();
    files.sort();
    files
}

/// A mount holding one writable handle on a fresh `f.txt`, with the create op
/// already spent.
fn writing_handle(core: &mut Core) -> HandleId {
    let (_attrs, handle) =
        block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).expect("the create");
    handle
}

#[test]
fn a_write_on_a_read_only_handle_is_refused() {
    let (mut core, _adapter) = mount();
    let (file, _reader) = block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).unwrap();
    let handle = block_on(core.open(file.ino, Access::Read)).expect("the file opens");

    assert_eq!(
        block_on(core.write(handle, 0, b"denied")),
        Err(VfsError::BadHandle),
        "a read-only handle must refuse a write, not accept and drop it"
    );
    assert_eq!(
        block_on(core.write(HandleId(9999), 0, b"denied")),
        Err(VfsError::BadHandle)
    );
}

#[test]
fn releasing_a_handle_that_never_wrote_journals_nothing() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);

    block_on(core.release(handle)).expect("the handle closes");

    assert_eq!(
        queued(&staging),
        after_create,
        "a handle with nothing to say owes no op"
    );
    assert!(
        spill_files(dir.path()).is_empty(),
        "a handle that never wrote mints no spill file"
    );
}

#[test]
fn a_write_then_release_journals_exactly_one_update() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);
    let plaintext = b"SECRET-1 spanning more than one framing block";

    assert_eq!(
        block_on(core.write(handle, 0, plaintext)).expect("the write lands"),
        plaintext.len() as u32
    );
    assert_eq!(queued(&staging), after_create, "a write journals nothing");

    block_on(core.release(handle)).expect("the release commits");

    assert_eq!(
        queued(&staging),
        after_create + 1,
        "a whole file is one op, however many blocks it took"
    );
    // A queued `updateContent` is what projects a new size onto the node.
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "f.txt"))
            .expect("the file")
            .size,
        Some(plaintext.len() as u64)
    );
}

#[test]
fn a_write_past_the_addressable_end_is_refused_rather_than_wrapped() {
    let (mut core, _adapter) = mount();
    let handle = writing_handle(&mut core);
    assert!(block_on(core.write(handle, u64::MAX - 4, b"xy")).is_err());
    assert_eq!(
        block_on(core.write(handle, u64::MAX, b"xy")),
        Err(VfsError::Invalid),
        "a window that cannot even be expressed is invalid"
    );
}

/// Every other test frames the mount at 16 bytes. Production frames it at the
/// content plane's chunk — 1_048_536, deliberately not a power of two — and
/// that is the stride a spill file's slots are laid out on, so offset
/// arithmetic that only holds for small aligned blocks shows up here and
/// nowhere else (blueprint/desktop.md "Reads, writes, and the never-block
/// law").
#[test]
fn a_write_at_production_framing_round_trips_across_its_block_boundaries() {
    let block = CacheBudget::PRODUCTION.block_bytes() as usize;
    let mut core = OperationCore::new(
        started_engine().0,
        RecordingAdapter::push_capable(),
        CacheBudget::PRODUCTION,
        spill_area(),
    );
    let handle = writing_handle(&mut core);

    // Starts inside the first slot, covers a whole one, ends inside the third.
    let at = (block / 2) as u64;
    let plaintext: Vec<u8> = (0..block * 2 + 5).map(|byte| (byte % 251) as u8).collect();
    assert_eq!(
        block_on(core.write(handle, at, &plaintext)).expect("the write lands") as usize,
        plaintext.len()
    );

    assert_eq!(
        block_on(core.read(handle, at, plaintext.len() as u32)).expect("the read"),
        plaintext,
        "a slot stride that is off by a byte reads back shifted plaintext"
    );
    assert!(
        block_on(core.read(handle, 0, at as u32))
            .expect("the read")
            .iter()
            .all(|byte| *byte == 0),
        "the hole ahead of the write reads as zeros, never as another slot"
    );
}

#[test]
fn the_bytes_a_handle_wrote_read_back_through_it() {
    let (mut core, _adapter) = mount();
    let handle = writing_handle(&mut core);
    let plaintext = b"the quick brown fox jumps over the lazy dog";
    block_on(core.write(handle, 0, plaintext)).expect("the write lands");

    assert_eq!(
        block_on(core.read(handle, 0, plaintext.len() as u32)).expect("the read"),
        plaintext.to_vec(),
        "a handle reads what it wrote, before any op is journaled"
    );
    // Sparse: a write past the end leaves a hole, which reads as zeros.
    block_on(core.write(handle, 64, b"tail")).expect("the far write lands");
    let whole = block_on(core.read(handle, 0, 128)).expect("the read");
    assert_eq!(whole.len(), 68);
    assert_eq!(&whole[..plaintext.len()], plaintext);
    assert_eq!(
        &whole[plaintext.len()..64],
        &vec![0u8; 64 - plaintext.len()]
    );
    assert_eq!(&whole[64..], b"tail");
}

#[test]
fn a_write_into_a_created_handles_spill_never_parks() {
    // The never-block law over a handle `create` already sized: `begin_pending`
    // has nothing left to resolve, so the bytes land locally.
    let (mut core, _adapter) = mount();
    let handle = writing_handle(&mut core);
    let Poll::Ready(outcome) = poll_once(core.write(handle, 0, b"bytes")) else {
        panic!("a write parked instead of landing in the spill");
    };
    outcome.expect("the write lands");
}

#[test]
fn a_write_is_refused_rather_than_acked_when_the_queue_cannot_journal_it() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);
    // Every further durable write fails: the op can never reach the platter.
    staging.fail_enqueue_after(0);

    block_on(core.write(handle, 0, b"unacked bytes")).expect("the write lands in the spill");
    block_on(core.flush(handle)).expect_err("a flush that cannot journal must not ack");
    block_on(core.release(handle)).expect_err("nor may the release");

    assert_eq!(
        queued(&staging),
        after_create,
        "a refused write leaves no half-formed op behind"
    );
    assert!(
        spill_files(dir.path()).is_empty(),
        "the handle's spill still dies with it"
    );
}

#[test]
fn a_spill_file_holds_no_plaintext() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, _staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);

    block_on(core.write(handle, 0, b"SECRET-1")).expect("the write lands");

    let files = spill_files(dir.path());
    assert_eq!(files.len(), 1, "one writable handle, one spill file");
    assert!(
        !files[0]
            .windows(b"SECRET-1".len())
            .any(|window| window == b"SECRET-1"),
        "the spill file must be sealed at rest"
    );
}

#[test]
fn two_handles_on_one_node_seal_under_different_keys() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, _staging) = mount_spilling_into(dir.path());
    let (file, first) = block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).unwrap();
    let second = block_on(core.open(file.ino, Access::Write)).expect("a second handle");
    // The second handle opened `O_TRUNC`, so it too starts from nothing.
    block_on(core.truncate(file.ino, 0, Some(second))).expect("the truncate");

    block_on(core.write(first, 0, b"SECRET-1")).expect("the first write");
    block_on(core.write(second, 0, b"SECRET-1")).expect("the second write");

    let files = spill_files(dir.path());
    assert_eq!(files.len(), 2);
    assert_ne!(
        files[0], files[1],
        "one plaintext under two per-handle keys must not seal alike"
    );
}

#[test]
fn a_released_handle_leaves_no_spill_behind() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, _staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    block_on(core.write(handle, 0, b"SECRET-1")).expect("the write lands");
    assert_eq!(spill_files(dir.path()).len(), 1);

    block_on(core.release(handle)).expect("the release commits");

    assert!(
        spill_files(dir.path()).is_empty(),
        "the spill and the key that opens it go with the handle"
    );
}

#[test]
fn a_crash_between_the_spill_and_the_release_loses_the_write() {
    // "Crash" is the mount going away with the handle still open: the process
    // holding the only copy of the spill key is what dies.
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);
    block_on(core.write(handle, 0, b"SECRET-1")).expect("the write lands");

    core.unmount();
    drop(core);

    assert_eq!(
        queued(&staging),
        after_create,
        "an unreleased write journals no partial op"
    );
    assert!(
        spill_files(dir.path()).is_empty(),
        "nothing openable survives the mount"
    );
}

#[test]
fn a_second_flush_with_nothing_new_to_say_journals_nothing() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);

    block_on(core.write(handle, 0, b"SECRET-1")).expect("the write lands");
    block_on(core.flush(handle)).expect("the flush commits");
    block_on(core.fsync(handle)).expect("an fsync with nothing new");
    block_on(core.release(handle)).expect("the release closes");

    assert_eq!(
        queued(&staging),
        after_create + 1,
        "one file's worth of writes is one op, however often it is flushed"
    );
}

#[test]
fn truncating_an_open_handle_to_zero_is_never_silently_lost() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    block_on(core.write(handle, 0, b"bytes that go away")).expect("the write lands");
    block_on(core.flush(handle)).expect("the flush commits");
    let after_write = queued(&staging);

    let file = block_on(core.lookup(ROOT_INO, "f.txt")).expect("the file");
    block_on(core.truncate(file.ino, 0, Some(handle))).expect("the truncate");
    block_on(core.release(handle)).expect("the release commits");

    assert_eq!(
        queued(&staging),
        after_write + 1,
        "a truncate on an open handle rides that handle's own op"
    );
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "f.txt"))
            .expect("the file")
            .size,
        Some(0)
    );
}

#[test]
fn a_truncate_with_no_open_handle_journals_its_own_op() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    block_on(core.write(handle, 0, b"bytes that go away")).expect("the write lands");
    block_on(core.release(handle)).expect("the release commits");
    let after_write = queued(&staging);

    let file = block_on(core.lookup(ROOT_INO, "f.txt")).expect("the file");
    block_on(core.truncate(file.ino, 0, None)).expect("the truncate");

    assert_eq!(
        queued(&staging),
        after_write + 1,
        "nothing else would ever journal this length"
    );
    assert_eq!(
        block_on(core.lookup(ROOT_INO, "f.txt"))
            .expect("the file")
            .size,
        Some(0)
    );
    assert!(spill_files(dir.path()).is_empty());
}

#[test]
fn a_zero_length_write_changes_nothing() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);

    assert_eq!(
        block_on(core.write(handle, 1 << 40, b"")).expect("no bytes"),
        0
    );

    assert_eq!(
        block_on(core.lookup(ROOT_INO, "f.txt"))
            .expect("the file")
            .size,
        None,
        "a zero-length write must not extend the file"
    );
    block_on(core.release(handle)).expect("the release closes");
    assert_eq!(
        queued(&staging),
        after_create,
        "nor may it owe an op for a length it never wrote"
    );
}

#[test]
fn truncating_a_directory_is_refused() {
    let (mut core, _adapter) = mount();
    let dir = block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    assert_eq!(
        block_on(core.truncate(dir.ino, 0, None)),
        Err(VfsError::IsADirectory)
    );
}

#[test]
fn the_size_a_lookup_reports_follows_an_unjournaled_write() {
    let (mut core, _adapter) = mount();
    let handle = writing_handle(&mut core);
    block_on(core.write(handle, 0, b"twelve bytes")).expect("the write lands");

    let file = block_on(core.lookup(ROOT_INO, "f.txt")).expect("the file");
    assert_eq!(
        file.size,
        Some(12),
        "a program that stats what it just wrote must not see the old length"
    );
    assert_eq!(
        block_on(core.getattr(file.ino)).expect("attrs").size,
        Some(12)
    );
}

#[test]
fn a_partial_write_over_an_unreadable_base_fails_closed() {
    // The file exists but its content plane has published nothing this mount
    // can resolve, so the bytes a partial write would keep are unknown. Guessing
    // zero would silently truncate what the version holds.
    let (mut core, _adapter) = mount();
    let (file, handle) = block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).unwrap();
    block_on(core.release(handle)).expect("the create closes");
    let reopened = block_on(core.open(file.ino, Access::Write)).expect("the file opens");

    let outcome = block_on(core.write(reopened, 3, b"patch"));
    assert!(
        matches!(outcome, Err(VfsError::Unavailable { .. })),
        "expected an availability verdict, got {outcome:?}"
    );
}

// --- refusal paths and the surfacing hook ---

/// The plaintext a mount refuses outright: past the platform's staging cap, so
/// no drain progress and no free space admits it.
fn past_the_staging_cap() -> Vec<u8> {
    vec![0x5a; StoragePolicy::CI.staging_cap_bytes as usize + 1]
}

/// The over-budget cause a release surfaced, or a panic naming what came back.
fn refused_cause(outcome: Result<(), VfsError>) -> OverBudgetCause {
    match outcome {
        Err(VfsError::OverBudget(cause)) => cause,
        other => panic!("expected an over-budget refusal, got {other:?}"),
    }
}

#[test]
fn a_write_past_the_staging_cap_surfaces_the_ceiling_cause() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let handle = writing_handle(&mut core);
    let after_create = queued(&staging);
    let plaintext = past_the_staging_cap();
    block_on(core.write(handle, 0, &plaintext)).expect("the spill takes the bytes");

    let cause = refused_cause(block_on(core.release(handle)));

    assert_eq!(
        cause,
        OverBudgetCause::StagingLimit,
        "a write past the cap is the ceiling, not a backlog"
    );
    assert_eq!(
        queued(&staging),
        after_create,
        "a refused write spends no journal entry"
    );
}

/// The backlog and the ceiling are different refusals: one clears as the drain
/// uploads, the other never does.
#[test]
fn a_write_the_backlog_cannot_hold_surfaces_a_different_cause() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    // Sealed bytes are what the budget counts, and CI's 16-byte framing inflates
    // plaintext several-fold, so two of these fit the cap individually and not
    // together.
    let half_the_budget = vec![0x11; 40_000];

    let first = writing_handle(&mut core);
    block_on(core.write(first, 0, &half_the_budget)).expect("the spill takes the bytes");
    block_on(core.release(first)).expect("the first version fits");

    let (second_attrs, second) =
        block_on(core.create(ROOT_INO, "g.txt", Access::ReadWrite)).expect("the create");
    let after_first = queued(&staging);
    block_on(core.write(second, 0, &half_the_budget)).expect("the spill takes the bytes");
    let cause = refused_cause(block_on(core.release(second)));

    assert_eq!(cause, OverBudgetCause::StagingBacklog);
    assert_eq!(
        queued(&staging),
        after_first,
        "the refused version journals nothing"
    );
    assert_eq!(
        block_on(core.getattr(second_attrs.ino))
            .expect("the node the create already journaled still renders")
            .size,
        None,
        "a refused version leaves no size claim behind"
    );
}

#[test]
fn a_dead_lettered_op_reaches_the_mount_status_with_its_reason() {
    let started = started_engine_over_queue(&[b"not an op record"]);
    let mut core = mount_over(started.engine);

    let status = block_on(core.status()).expect("the status reads");

    assert_eq!(
        status
            .dead_letters
            .iter()
            .map(|dead| dead.reason)
            .collect::<Vec<_>>(),
        vec![DeadLetterReason::Undecodable],
        "the reason is the whole surface — it is what the tray explains"
    );
    // The kernel was acked at journal time, so the compensation channel is the
    // only place this appears: the read path stays whole.
    assert!(block_on(core.readdir(ROOT_INO)).is_ok());
    assert!(
        block_on(core.status())
            .expect("the status reads again")
            .blocked
            .is_none(),
        "a dead letter is not a drain hold"
    );
}

/// A relocation the engine will not accept is refused before the journal entry
/// is spent — the one mutation class whose ack waits on more than the fsync,
/// because an op the kernel already heard success for can never be retro-failed.
#[test]
fn a_relocation_the_engine_refuses_spends_no_journal_entry() {
    let dir = tempfile::tempdir().expect("a spill dir");
    let (mut core, staging) = mount_spilling_into(dir.path());
    let (file, handle) =
        block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).expect("create");
    block_on(core.release(handle)).expect("the handle closes");
    let before = queued(&staging);

    let refusal = block_on(core.engine_mut().command(Command::Relink {
        node: file.node,
        new_parent: NodeId([0xee; 16]),
    }))
    .expect_err("a destination the render does not hold is refused");

    assert_eq!(
        VfsError::from(refusal),
        VfsError::NotFound,
        "a destination that is simply gone is ENOENT, not a scope verdict"
    );
    assert_eq!(queued(&staging), before, "the queue is unchanged");
}

/// The status hook reads off the same render the listing does, so what the tray
/// says and what the mount shows cannot disagree.
#[test]
fn the_mount_status_reports_a_quiet_mount_as_quiet() {
    let (core, _adapter) = mount();

    let status = block_on(core.status()).expect("the status reads");

    assert!(status.dead_letters.is_empty());
    assert!(status.blocked.is_none());
    assert_eq!(status.retained_records, 0);
    assert_eq!(status.staleness, Staleness::Fresh);
}

/// The read path over a real published file, which needs the account fixture
/// the write plane publishes rather than the empty mount above.
mod published {
    use cipherbox_engine::seams::{BoxedTask, RecordTransport};
    use cipherbox_engine::testkit::account::{Blocks, ROOT, SECRET, seed_account, serve_http};
    use cipherbox_engine::testkit::{FakeDevice, poll_tasks_until_parked};
    use cipherbox_engine::{MAX_OPEN_STREAMS, WriteTarget};

    use super::*;

    /// The published file's name under the root.
    const CLIP: &str = "clip.bin";

    /// 200 distinct bytes: 12 whole chunks and a short tail at the CI profile's
    /// 16-byte framing, so a window can land inside, across, and past a chunk.
    fn clip_bytes() -> Vec<u8> {
        (0..200u8).collect()
    }

    fn chunk() -> u64 {
        ContentProfile::CI.chunk_size() as u64
    }

    /// How many blocks this device has fetched from the gateway.
    fn block_fetches(device: &FakeDevice) -> usize {
        device
            .http
            .requests()
            .iter()
            .filter(|request| request.url.contains("/ipfs/"))
            .count()
    }

    fn engine_on(device: &FakeDevice) -> (Engine<FakeSeamTypes>, EventStream) {
        Engine::new(
            device.seam_set(),
            Box::new(SeededEntropy::new(42)),
            SyncTimingProfile::CI,
            ContentProfile::CI,
            StoragePolicy::CI,
            ApiBaseUrl::offline(),
            GatewayConfig {
                accelerator: Some("https://gw.test".into()),
                public_fallbacks: Vec::new(),
            },
        )
    }

    /// A mount over an engine that has published `plaintext` as `clip.bin`.
    struct Mount {
        core: Core,
        adapter: RecordingAdapter,
        device: FakeDevice,
        world: FakeWorld,
        /// The account's shared content plane, so a second device of the same
        /// account can be stood up over it.
        blocks: Blocks,
        ino: u64,
        node: NodeId,
        /// The engine's spawned loops, kept so a test can drain a write it
        /// stages after the mount is up.
        tasks: Vec<BoxedTask>,
        /// The mount's own engine event stream — what a reconcile landing
        /// behind the kernel announces itself on.
        events: EventStream,
    }

    fn mount_published(plaintext: &[u8], budget: CacheBudget) -> Mount {
        mount_published_with(plaintext, budget, RecordingAdapter::push_capable())
    }

    fn mount_published_with(
        plaintext: &[u8],
        budget: CacheBudget,
        adapter: RecordingAdapter,
    ) -> Mount {
        let world = FakeWorld::new();
        let blocks = Blocks::default();
        seed_account(&world, &blocks);

        let device = world.device(b"alice");
        serve_http(&device, &blocks, 1_000);
        let (mut engine, events) = engine_on(&device);
        block_on(engine.start(LoginSecret::new(SECRET.to_vec())))
            .expect("the cold start adopts the owner root");
        let mut tasks = world.scheduler.take_spawned_tasks();
        poll_tasks_until_parked(&mut tasks);

        let handle = block_on(engine.begin_write(
            WriteTarget::NewFile {
                parent: ROOT,
                name: CLIP.to_owned(),
            },
            plaintext.len() as u64,
        ))
        .expect("the write opens");
        for slice in plaintext.chunks(7) {
            block_on(engine.push_chunk(handle, slice)).expect("the slice lands");
        }
        block_on(engine.commit_write(handle)).expect("the write commits");
        world.scheduler.advance(engine.profile().poll_cadence);
        poll_tasks_until_parked(&mut tasks);

        let mut core = OperationCore::new(engine, adapter.clone(), budget, spill_area());
        let published =
            block_on(core.lookup(ROOT_INO, CLIP)).expect("the published file is rendered");
        adapter.drain();
        Mount {
            core,
            adapter,
            device,
            world,
            blocks,
            ino: published.ino,
            node: published.node,
            tasks,
            events,
        }
    }

    /// Publish a new version of `CLIP` through the engine the mount projects —
    /// the shell writing while the mount is up.
    fn publish_version(mount: &mut Mount, plaintext: &[u8]) {
        let node = mount.node;
        {
            let engine = mount.core.engine_mut();
            let handle =
                block_on(engine.begin_write(WriteTarget::Version { node }, plaintext.len() as u64))
                    .expect("the write opens");
            for slice in plaintext.chunks(7) {
                block_on(engine.push_chunk(handle, slice)).expect("the slice lands");
            }
            block_on(engine.commit_write(handle)).expect("the write commits");
        }
        advance_and_pump(mount);
    }

    /// Publish a new version of `CLIP` from a second device of the same
    /// account. The mount's own engine stages nothing, so only a resolve can
    /// tell it the head moved.
    fn publish_from_another_device(mount: &mut Mount, plaintext: &[u8]) {
        let node = mount.node;
        let device = mount.world.device(b"alice-second-device");
        serve_http(&device, &mount.blocks, 1_000);
        let (mut engine, _events) = engine_on(&device);
        block_on(engine.start(LoginSecret::new(SECRET.to_vec())))
            .expect("the second device adopts the same owner root");
        let mut tasks = mount.world.scheduler.take_spawned_tasks();
        poll_tasks_until_parked(&mut tasks);

        let handle =
            block_on(engine.begin_write(WriteTarget::Version { node }, plaintext.len() as u64))
                .expect("the second device's write opens");
        for slice in plaintext.chunks(7) {
            block_on(engine.push_chunk(handle, slice)).expect("the slice lands");
        }
        block_on(engine.commit_write(handle)).expect("the write commits");
        mount.world.scheduler.advance(engine.profile().poll_cadence);
        poll_tasks_until_parked(&mut tasks);
    }

    /// Let the engine drain and publish what the mount just journaled.
    fn advance_and_pump(mount: &mut Mount) {
        let cadence = mount.core.engine_mut().profile().poll_cadence;
        mount.world.scheduler.advance(cadence);
        poll_tasks_until_parked(&mut mount.tasks);
    }

    fn opened(mount: &mut Mount) -> HandleId {
        block_on(mount.core.open(mount.ino, Access::Read)).expect("the file opens")
    }

    #[test]
    fn a_ranged_read_serves_the_right_bytes_across_a_chunk_boundary() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle = opened(&mut mount);

        for (offset, size) in [
            (0u64, 16u32),
            (15, 2),
            (16, 16),
            (8, 40),
            (190, 999),
            (0, 200),
        ] {
            let end = (offset + u64::from(size)).min(plaintext.len() as u64) as usize;
            assert_eq!(
                block_on(mount.core.read(handle, offset, size)).expect("the window serves"),
                plaintext[offset as usize..end],
                "range {offset}+{size}"
            );
        }
        for offset in [plaintext.len() as u64, plaintext.len() as u64 + 1, u64::MAX] {
            assert!(
                block_on(mount.core.read(handle, offset, 16))
                    .expect("a window past the end is not an error")
                    .is_empty(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn the_first_byte_does_not_wait_for_the_last() {
        // The whole point of the ranged path: a window costs the chunks it
        // covers, never the file.
        let plaintext = clip_bytes();
        let leaves = (plaintext.len() as u64).div_ceil(chunk());
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle = opened(&mut mount);

        let before = block_fetches(&mount.device);
        block_on(mount.core.read(handle, 0, chunk() as u32)).expect("the first chunk serves");
        let opening = block_fetches(&mount.device) - before;
        assert!(
            (opening as u64) < leaves,
            "the first chunk cost {opening} fetches of a {leaves}-leaf file"
        );

        // Past the stream's one-time head and root fetch, a window costs
        // exactly the leaves it covers.
        let before = block_fetches(&mount.device);
        block_on(mount.core.read(handle, 5 * chunk(), chunk() as u32)).expect("a later chunk");
        assert_eq!(block_fetches(&mount.device) - before, 1);
    }

    #[test]
    fn a_cached_chunk_is_served_without_touching_the_network() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle = opened(&mut mount);

        block_on(mount.core.read(handle, 0, 4)).expect("the first sip");
        let after_miss = block_fetches(&mount.device);
        assert_eq!(
            mount.core.cached_plaintext_bytes(),
            chunk() as usize,
            "a 4-byte read caches the whole chunk it framed"
        );

        for offset in 0..=(chunk() - 4) {
            assert_eq!(
                block_on(mount.core.read(handle, offset, 4)).expect("a hit"),
                plaintext[offset as usize..offset as usize + 4]
            );
        }
        assert_eq!(
            block_fetches(&mount.device),
            after_miss,
            "every window inside a cached chunk was served from memory"
        );
    }

    #[test]
    fn no_read_ever_waits_on_the_record_plane() {
        // The never-block law: a read may block on a chunk fetch and on nothing
        // else. With every routing endpoint dark, a window that re-resolved,
        // republished, or walked a rotation could not serve at all.
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle = opened(&mut mount);
        block_on(mount.core.read(handle, 0, 4)).expect("the stream opens on a live plane");

        for endpoint in mount.world.record_store.endpoints() {
            mount.world.record_store.fail_endpoint(&endpoint);
        }

        let mut assembled = Vec::new();
        while assembled.len() < plaintext.len() {
            let window = block_on(mount.core.read(handle, assembled.len() as u64, 24))
                .expect("a window off the pinned version");
            assert!(!window.is_empty(), "a window short of the end stalled");
            assembled.extend_from_slice(&window);
        }
        assert_eq!(assembled, plaintext);
    }

    #[test]
    fn the_plaintext_the_mount_holds_stays_under_its_bound() {
        let plaintext = clip_bytes();
        let budget = CacheBudget::for_profile(ContentProfile::CI, 3).expect("three chunks");
        let mut mount = mount_published(&plaintext, budget);
        let handle = opened(&mut mount);

        for index in 0..(plaintext.len() as u64).div_ceil(chunk()) {
            block_on(mount.core.read(handle, index * chunk(), chunk() as u32))
                .expect("every chunk serves");
            assert!(
                mount.core.cached_plaintext_bytes() <= budget.max_bytes(),
                "chunk {index} pushed the mount past its plaintext ceiling"
            );
        }

        // Eviction really happened: the first chunk is gone and costs a fetch.
        let before = block_fetches(&mount.device);
        block_on(mount.core.read(handle, 0, chunk() as u32)).expect("the first chunk re-serves");
        assert_eq!(
            block_fetches(&mount.device) - before,
            1,
            "reading past the bound must have evicted the oldest chunk"
        );
    }

    #[test]
    fn releasing_a_handle_frees_its_stream_and_the_plaintext_it_cached() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);

        // Past the engine's ceiling: a release that left its stream pinned would
        // exhaust the table long before the last open.
        for round in 0..(MAX_OPEN_STREAMS + 8) {
            let handle = opened(&mut mount);
            assert_eq!(
                block_on(mount.core.read(handle, 0, 8))
                    .unwrap_or_else(|err| panic!("round {round}: {err}")),
                plaintext[..8]
            );
            block_on(mount.core.release(handle)).expect("the handle closes");
            assert_eq!(
                mount.core.cached_plaintext_bytes(),
                0,
                "round {round} left the released stream's plaintext behind"
            );
        }
    }

    #[test]
    fn a_sub_block_write_merges_over_the_block_the_read_path_cached() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");

        block_on(mount.core.read(handle, 0, 4)).expect("the read caches the chunk it framed");
        let after_read = block_fetches(&mount.device);

        block_on(mount.core.write(handle, 1, b"a")).expect("the write merges into that chunk");

        assert_eq!(
            block_fetches(&mount.device),
            after_read,
            "the merge re-fetched a base block the mount was already holding"
        );
    }

    #[test]
    fn reading_through_pending_writes_fetches_each_base_block_once() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");

        // One sub-block write, so every later read renders through the pending
        // overlay and every untouched block still comes off the base version.
        block_on(mount.core.write(handle, 1, b"a")).expect("the write lands");

        let whole = plaintext.len() as u32;
        let first = block_on(mount.core.read(handle, 0, whole)).expect("the first pass");
        let after_first = block_fetches(&mount.device);
        let second = block_on(mount.core.read(handle, 0, whole)).expect("the second pass");

        assert_eq!(first, second, "both passes render the same file");
        assert_eq!(
            block_fetches(&mount.device),
            after_first,
            "the second pass re-fetched base blocks the first had already cached"
        );
    }

    #[test]
    fn a_cached_base_block_is_still_clamped_to_the_floor_a_shrink_left() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let ino = mount.ino;
        let handle = block_on(mount.core.open(ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.read(handle, 0, chunk() as u32)).expect("the read caches the chunk");

        block_on(mount.core.truncate(ino, 4, Some(handle))).expect("the shrink");
        block_on(mount.core.write(handle, 6, b"xy")).expect("the write past the gap");
        block_on(mount.core.release(handle)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = plaintext[..4].to_vec();
        expected.extend_from_slice(b"\0\0xy");
        let reader = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(reader, 0, 16)).expect("the read"),
            expected
        );
    }

    #[test]
    fn the_commit_walk_leaves_a_readers_hot_blocks_in_the_cache() {
        let plaintext = clip_bytes();
        let budget = CacheBudget::for_profile(ContentProfile::CI, 5).expect("five chunks");
        let mut mount = mount_published(&plaintext, budget);
        let reader = opened(&mut mount);
        for index in 0..3 {
            block_on(mount.core.read(reader, index * chunk(), chunk() as u32))
                .expect("the reader's chunks");
        }

        let writer =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.write(writer, 1, b"a")).expect("the write lands");
        block_on(mount.core.release(writer)).expect("the release commits the whole version");
        advance_and_pump(&mut mount);

        let before = block_fetches(&mount.device);
        for index in 0..3 {
            block_on(mount.core.read(reader, index * chunk(), chunk() as u32))
                .expect("the reader's chunks re-serve");
        }
        assert_eq!(
            block_fetches(&mount.device),
            before,
            "the commit walk evicted the reader's hot blocks"
        );
    }

    #[test]
    fn unmounting_releases_every_stream_and_the_plaintext_they_cached() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handles: Vec<_> = (0..4).map(|_| opened(&mut mount)).collect();
        for handle in &handles {
            block_on(mount.core.read(*handle, 0, 8)).expect("each handle reads");
        }
        assert!(mount.core.cached_plaintext_bytes() > 0);

        mount.core.unmount();

        assert_eq!(mount.core.cached_plaintext_bytes(), 0);
        for handle in &handles {
            assert_eq!(mount.core.handle(*handle), Err(VfsError::BadHandle));
        }
        // Every stream slot came back, so nothing stayed pinned.
        let reopened: Vec<_> = (0..MAX_OPEN_STREAMS)
            .map(|round| {
                let handle = opened(&mut mount);
                block_on(mount.core.read(handle, 0, 8))
                    .unwrap_or_else(|err| panic!("round {round}: {err}"));
                handle
            })
            .collect();
        assert_eq!(reopened.len(), MAX_OPEN_STREAMS);
    }

    #[test]
    fn two_handles_on_one_file_read_independently() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let first = opened(&mut mount);
        let second = opened(&mut mount);

        assert_eq!(
            block_on(mount.core.read(first, 0, 8)).unwrap(),
            plaintext[..8]
        );
        block_on(mount.core.release(first)).expect("the first handle closes");

        assert_eq!(
            block_on(mount.core.read(second, 0, 8)).unwrap(),
            plaintext[..8],
            "closing one handle must not disturb another's stream"
        );
    }

    #[test]
    fn a_read_off_a_version_the_mount_never_served_repaints_the_kernels_data_cache() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let first = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(first, 0, 8)).expect("the first version reads"),
            plaintext[..8]
        );
        block_on(mount.core.release(first)).expect("the handle closes");
        mount.adapter.drain();

        let edited: Vec<u8> = plaintext.iter().map(|byte| byte ^ 0xff).collect();
        publish_version(&mut mount, &edited);
        let ino = mount.ino;
        let projected = block_on(mount.core.getattr(ino)).expect("the edited file is rendered");

        let second = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(second, 0, 8)).expect("the newer version reads"),
            edited[..8],
            "the second bind must serve the version it resolved"
        );
        // The engine projects the head its own drain published, so the open
        // moves nothing: what the kernel holds is stale even though the
        // projection never changed.
        assert_eq!(
            block_on(mount.core.getattr(ino)).expect("still rendered"),
            projected
        );
        let pushed = mount.adapter.drain();
        assert!(
            pushed.contains(&Invalidation::Data { ino }),
            "expected a data invalidation for ino {ino}, got {pushed:?}"
        );
    }

    #[test]
    fn a_patch_over_a_published_version_keeps_the_bytes_it_did_not_touch() {
        // The whole round trip: a partial write merges over the published
        // version, releases as one op, publishes, and reads back.
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");

        let patch = b"PATCHED!";
        let at = chunk() + 3;
        block_on(mount.core.write(handle, at, patch)).expect("the write lands");
        block_on(mount.core.release(handle)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = plaintext.clone();
        expected[at as usize..at as usize + patch.len()].copy_from_slice(patch);
        let reader = opened(&mut mount);
        let read = block_on(mount.core.read(reader, 0, expected.len() as u32))
            .expect("the published patch reads back");
        assert_eq!(read, expected);
    }

    /// Composing over the published head under the staged length would seal
    /// `published ++ zero-hole ++ tail` — no byte of the staged version, and no
    /// error. The write refuses until the drain publishes what it composes over.
    #[test]
    fn an_append_over_a_staged_version_never_publishes_the_previous_versions_bytes() {
        let published = clip_bytes();
        let mut mount = mount_published(&published, CacheBudget::CI);

        // A whole-file rewrite, wider than the published version, journaled but
        // deliberately not drained.
        let staged = vec![0xBB; 323];
        let writer =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.write(writer, 0, &staged)).expect("the rewrite lands");
        block_on(mount.core.release(writer)).expect("the release commits");

        // A second handle sees the staged length and appends an unaligned tail.
        let appender =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file reopens");
        let appended = block_on(mount.core.write(appender, staged.len() as u64, b"TAIL"));
        assert!(
            matches!(appended, Err(VfsError::Unavailable { .. })),
            "the append refuses while the version it would compose over is unpublished: \
             {appended:?}"
        );
        let _ = block_on(mount.core.release(appender));
        advance_and_pump(&mut mount);

        let reader = opened(&mut mount);
        let read = block_on(mount.core.read(reader, 0, staged.len() as u32))
            .expect("the staged version publishes");
        assert_eq!(
            read, staged,
            "the published version is the staged one, whole — never the previous \
             version's bytes under the staged version's length"
        );
    }

    /// The same mispairing through a handle that bound its stream *before* the
    /// staging: it is never re-opened, so nothing re-consults the engine.
    #[test]
    fn an_append_on_a_handle_bound_before_the_staging_publishes_no_stale_bytes() {
        let published = clip_bytes();
        let mut mount = mount_published(&published, CacheBudget::CI);

        // The reader binds its stream to the published version first.
        let reader =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.read(reader, 0, 1)).expect("the first read binds the stream");

        let staged = vec![0xBB; 323];
        let writer =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens twice");
        block_on(mount.core.write(writer, 0, &staged)).expect("the rewrite lands");
        block_on(mount.core.release(writer)).expect("the release commits");

        let appended = block_on(mount.core.write(reader, staged.len() as u64, b"TAIL"));
        assert!(
            matches!(appended, Err(VfsError::Unavailable { .. })),
            "the append refuses rather than composing over the version it bound: {appended:?}"
        );
        let _ = block_on(mount.core.release(reader));
        advance_and_pump(&mut mount);

        let after = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(after, 0, staged.len() as u32)).expect("the staged version"),
            staged,
            "the published version is the staged one, whole"
        );
    }

    /// A refusal while a version is staged is availability, not a verdict: the
    /// same handle appends once the drain publishes what it composes over.
    #[test]
    fn an_append_refused_over_a_staged_version_lands_after_the_drain() {
        let published = clip_bytes();
        let mut mount = mount_published(&published, CacheBudget::CI);

        let reader =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.read(reader, 0, 1)).expect("the first read binds the stream");

        let staged = vec![0xBB; 323];
        let writer =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens twice");
        block_on(mount.core.write(writer, 0, &staged)).expect("the rewrite lands");
        block_on(mount.core.release(writer)).expect("the release commits");

        let refused = block_on(mount.core.write(reader, staged.len() as u64, b"TAIL"));
        assert!(
            matches!(refused, Err(VfsError::Unavailable { .. })),
            "the append refuses while the staged version is unpublished: {refused:?}"
        );
        advance_and_pump(&mut mount);

        block_on(mount.core.write(reader, staged.len() as u64, b"TAIL"))
            .expect("the retry composes over the version the drain published");
        block_on(mount.core.release(reader)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = staged.clone();
        expected.extend_from_slice(b"TAIL");
        let after = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(after, 0, expected.len() as u32)).expect("the append reads"),
            expected,
            "the retry appends onto the staged version, not the one the handle bound"
        );
    }

    /// The rendered length also moves when *another device* publishes: the
    /// projection repaints size and head `contentCid` together off one verified
    /// read body, with nothing ever staged locally. A handle bound to the older
    /// version must re-pin rather than compose its writes over what it holds —
    /// otherwise the append seals `old ++ zero-hole ++ tail` under the new
    /// version's length, with no error.
    #[test]
    fn an_append_on_a_handle_bound_before_another_device_published_seals_no_stale_bytes() {
        let published = clip_bytes();
        let mut mount = mount_published(&published, CacheBudget::CI);

        // The reader binds its stream to the version the mount came up on.
        let reader =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.read(reader, 0, 1)).expect("the first read binds the stream");

        let remote = vec![0xBB; 323];
        publish_from_another_device(&mut mount, &remote);

        // A fresh open resolves the newer head and repaints the rendered length.
        let fresh = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(fresh, 0, 8)).expect("the newer version reads"),
            remote[..8],
            "the fresh open serves what the other device published"
        );
        block_on(mount.core.release(fresh)).expect("the fresh handle closes");

        block_on(mount.core.write(reader, remote.len() as u64, b"TAIL"))
            .expect("nothing is unavailable: the handle only needs re-pinning");
        block_on(mount.core.release(reader)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = remote.clone();
        expected.extend_from_slice(b"TAIL");
        let after = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(after, 0, expected.len() as u32)).expect("the append reads"),
            expected,
            "the append composes over the version the length came from"
        );
    }

    /// A second device's version reaches an idle mount without an `open`.
    ///
    /// A version publish authors one record — the file's — and a `ChildRef`
    /// mirrors neither size nor mtime, so the root's own record never moves and
    /// no amount of folder refreshing repaints the file. `getattr` putting the
    /// file itself in view is what gives the tick a file leg to run.
    #[test]
    fn a_tick_repaints_a_file_another_device_republished_without_an_open() {
        let published = clip_bytes();
        let mut mount = mount_published(&published, CacheBudget::CI);
        let ino = mount.ino;
        let remote = vec![0xBB; 323];
        assert_ne!(remote.len(), published.len(), "the head length moves");
        publish_from_another_device(&mut mount, &remote);

        // Nothing has resolved the file's own record yet, so the base still
        // holds what the mount came up on — and this call is what asks for it.
        assert_eq!(
            block_on(mount.core.getattr(ino)).expect("getattr").size,
            Some(published.len() as u64)
        );

        advance_and_pump(&mut mount);
        assert_eq!(
            block_on(mount.core.getattr(ino)).expect("getattr").size,
            Some(remote.len() as u64),
            "the tick's file leg repainted the base off the other device's record"
        );
    }

    #[test]
    fn bytes_a_shrink_removed_never_come_back_when_the_file_grows_again() {
        // Truncating is how a member destroys a file's tail. Those bytes must
        // not be re-sealed into the next version by a later extension.
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let ino = mount.ino;
        let handle = block_on(mount.core.open(ino, Access::ReadWrite)).expect("the file opens");

        block_on(mount.core.truncate(ino, 4, Some(handle))).expect("the shrink");
        block_on(mount.core.truncate(ino, 32, Some(handle))).expect("the regrow");
        block_on(mount.core.release(handle)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = plaintext[..4].to_vec();
        expected.resize(32, 0);
        let reader = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(reader, 0, 32)).expect("the read"),
            expected,
            "a regrown file reads the shrink's gap as a hole, not as the old bytes"
        );
    }

    #[test]
    fn a_write_past_a_shrink_reads_the_gap_as_zeros() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let ino = mount.ino;
        let handle = block_on(mount.core.open(ino, Access::ReadWrite)).expect("the file opens");

        block_on(mount.core.truncate(ino, 4, Some(handle))).expect("the shrink");
        block_on(mount.core.write(handle, 6, b"xy")).expect("the write past the gap");
        block_on(mount.core.release(handle)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = plaintext[..4].to_vec();
        expected.extend_from_slice(b"\0\0xy");
        let reader = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(reader, 0, 16)).expect("the read"),
            expected
        );
    }

    #[test]
    fn a_write_extending_a_published_version_reads_back_whole() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle =
            block_on(mount.core.open(mount.ino, Access::ReadWrite)).expect("the file opens");

        let tail = b"appended";
        block_on(mount.core.write(handle, plaintext.len() as u64, tail)).expect("the append lands");
        block_on(mount.core.release(handle)).expect("the release commits");
        advance_and_pump(&mut mount);

        let mut expected = plaintext.clone();
        expected.extend_from_slice(tail);
        let reader = opened(&mut mount);
        assert_eq!(
            block_on(mount.core.read(reader, 0, expected.len() as u32)).expect("the read"),
            expected
        );
    }

    #[test]
    fn reading_the_version_already_served_repaints_nothing() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let handle = opened(&mut mount);
        mount.adapter.drain();

        // The kernel holds nothing for an inode this mount minted and has never
        // served, so the first bind has nothing to drop.
        block_on(mount.core.read(handle, 0, 8)).expect("the first window");
        block_on(mount.core.read(handle, 8, 8)).expect("a later window");
        assert!(mount.adapter.drain().is_empty());

        // A fresh handle re-resolves the same head: same bytes, no repaint.
        let reopened = opened(&mut mount);
        block_on(mount.core.read(reopened, 0, 8)).expect("the reopened window");
        assert!(
            mount.adapter.drain().is_empty(),
            "a bind on the version already served repaints nothing"
        );
    }

    #[test]
    fn a_commit_repaints_the_pages_of_the_version_it_replaced() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let ino = mount.ino;
        // A second handle has already served this version's bytes, so the kernel
        // holds pages the commit is about to invalidate. Nothing re-binds it.
        let reader = opened(&mut mount);
        block_on(mount.core.read(reader, 0, 8)).expect("the reader serves the published version");

        let writer = block_on(mount.core.open(ino, Access::ReadWrite)).expect("the file opens");
        block_on(mount.core.write(writer, 3, b"EDIT")).expect("the write lands");
        mount.adapter.drain();
        block_on(mount.core.release(writer)).expect("the release commits");

        let pushed = mount.adapter.drain();
        let data = pushed
            .iter()
            .position(|seen| seen == &Invalidation::Data { ino });
        let attrs = pushed
            .iter()
            .position(|seen| seen == &Invalidation::Attributes { ino });
        assert!(
            data.is_some(),
            "a commit must drop the pages of the version it replaced, got {pushed:?}"
        );
        assert!(
            data < attrs,
            "the new size must not reach the kernel while it still holds the old pages: {pushed:?}"
        );
    }

    #[test]
    fn a_write_on_a_reopened_handle_never_parks_once_the_size_is_projected() {
        let plaintext = clip_bytes();
        let mut mount = mount_published(&plaintext, CacheBudget::CI);
        let ino = mount.ino;
        assert!(
            block_on(mount.core.getattr(ino))
                .expect("the published file renders")
                .size
                .is_some(),
            "the projected size is what leaves the write nothing to resolve"
        );
        let handle = block_on(mount.core.open(ino, Access::ReadWrite)).expect("the file opens");

        let whole_block = vec![0xab; chunk() as usize];
        let Poll::Ready(outcome) = poll_once(mount.core.write(handle, 0, &whole_block)) else {
            panic!("a write on a reopened handle parked instead of landing in the spill");
        };
        assert_eq!(outcome.expect("the write lands"), whole_block.len() as u32);
        assert!(
            mount
                .core
                .handle(handle)
                .expect("the handle is open")
                .stream
                .is_none(),
            "a write that replaces whole blocks must not have resolved the content"
        );
    }

    /// The gap blueprint/desktop.md names: a snapshot lands with no operation
    /// of the kernel's involved, so only the event stream can tell the mount
    /// that the pages and attributes it served went stale. Nothing on the
    /// callback path re-binds this inode, so an uninvalidated page cache would
    /// serve the old version for as long as the kernel kept it.
    #[test]
    fn a_version_the_mount_never_served_repaints_the_kernels_caches_off_the_event_stream() {
        let mut mount = mount_published(&clip_bytes(), CacheBudget::CI);
        let ino = mount.ino;
        block_on(mount.core.getattr(ino)).expect("the kernel takes the attributes");
        mount.adapter.drain();
        drain_events(&mut mount.events);

        // Straight at the engine the mount projects — the shell writing while
        // the mount is up, which the mount itself performs no operation for.
        publish_version(&mut mount, &[0xBB; 323]);
        let seen = absorb_pending(&mut mount.core, &mut mount.events);

        assert!(seen.contains(&Event::SnapshotUpdated), "{seen:?}");
        assert_eq!(
            mount.adapter.drain(),
            vec![Invalidation::Data { ino }, Invalidation::Attributes { ino },],
            "data before attributes, so a kernel that learns the new size first \
             serves the pages it still holds as the new version"
        );
    }

    /// A mount that cannot push takes the shorter kernel TTL *and* is still
    /// told what moved: the two are independent, and a mount told nothing would
    /// never revalidate cached data whatever its TTLs said.
    #[test]
    fn a_mount_without_push_takes_the_shorter_ttl_and_is_still_told() {
        let mut mount = mount_published_with(
            &clip_bytes(),
            CacheBudget::CI,
            RecordingAdapter::declaring(HostCapabilities {
                push_invalidation: false,
                ..base_capabilities()
            }),
        );
        let ino = mount.ino;
        block_on(mount.core.getattr(ino)).expect("the kernel takes the attributes");
        mount.adapter.drain();
        drain_events(&mut mount.events);

        assert_eq!(
            mount.core.cache_ttls().entry,
            SyncTimingProfile::CI.poll_cadence,
            "without push the kernel may cache no longer than one poll cycle"
        );

        publish_version(&mut mount, &[0xCC; 96]);
        absorb_pending(&mut mount.core, &mut mount.events);

        assert!(
            mount.adapter.drain().contains(&Invalidation::Data { ino }),
            "a mount that cannot push is still the one told what moved"
        );
    }
}
