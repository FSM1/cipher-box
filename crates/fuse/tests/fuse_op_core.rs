//! The `fuse-op-core` suite: every vfs operation driven against a real engine
//! over the in-memory seam fakes, plus the never-block law
//! (blueprint/desktop.md "Reads, writes, and the never-block law").
//!
//! No kernel: a recording adapter stands in for the mount so the outbound
//! invalidation direction is observable.

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use cipherbox_engine::testkit::fakes::InMemoryStagingStore;
use cipherbox_engine::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    ApiBaseUrl, Command, ContentProfile, Engine, GatewayConfig, LoginSecret, NodeId, NodeKind,
    StoragePolicy, SyncTimingProfile,
};
use cipherbox_fuse::{
    Access, HostAdapter, HostCapabilities, Invalidation, MAX_NAME_BYTES, NameError, OperationCore,
    ROOT_INO, VfsError,
};

/// A mount that records what it was told to invalidate.
#[derive(Clone, Default)]
struct RecordingAdapter {
    push_invalidation: bool,
    seen: Rc<RefCell<Vec<Invalidation>>>,
}

impl RecordingAdapter {
    fn push_capable() -> Self {
        Self {
            push_invalidation: true,
            seen: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn drain(&self) -> Vec<Invalidation> {
        self.seen.borrow_mut().drain(..).collect()
    }
}

impl HostAdapter for RecordingAdapter {
    fn capabilities(&self) -> HostCapabilities {
        HostCapabilities {
            push_invalidation: self.push_invalidation,
        }
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
    let (engine, root, _staging) = started_engine_with_staging();
    (engine, root)
}

/// A started engine plus a handle on its durable op queue, for tests that
/// inject a staging outage.
fn started_engine_with_staging() -> (Engine<FakeSeamTypes>, NodeId, InMemoryStagingStore) {
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let staging = device.staging_store.clone();
    let (mut engine, _events) = Engine::new(
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
    (engine, root, staging)
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

/// Mount over an engine seeded with the given root children.
fn mount_seeded(adapter: RecordingAdapter, root_children: &[(&str, NodeKind)]) -> Core {
    let (mut engine, root) = started_engine();
    for (name, kind) in root_children {
        seed_child(&mut engine, root, name, *kind);
    }
    OperationCore::new(engine, adapter)
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

    assert_eq!(core.release(handle), Ok(()));
    assert_eq!(core.handle(handle), Err(VfsError::BadHandle));
    assert_eq!(core.release(handle), Err(VfsError::BadHandle));
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
    core.release(handle).unwrap();
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
    // destination's removal while the source stays put (#884).
    for budget in [0, 1] {
        let (mut engine, root, staging) = started_engine_with_staging();
        let source = seed_child(&mut engine, root, "new.txt", NodeKind::File);
        let victim = seed_child(&mut engine, root, "target.txt", NodeKind::File);
        let mut core = OperationCore::new(engine, RecordingAdapter::push_capable());
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
    let mut core = OperationCore::new(engine, RecordingAdapter::push_capable());
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
    let mut core = OperationCore::new(engine, RecordingAdapter::push_capable());
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

#[test]
fn a_mount_that_cannot_push_gets_a_shorter_cache_ttl() {
    let (with_push, _adapter) = mount();
    let without_push = mount_with(RecordingAdapter::default());

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
    OperationCore::new(engine, RecordingAdapter::push_capable())
}

/// A `dir` holding one junk-prefixed folder, which itself holds a real file.
fn seeded_nested_junk_folder() -> Core {
    let (mut engine, root) = started_engine();
    let dir = seed_child(&mut engine, root, "dir", NodeKind::Folder);
    let junk = seed_child(&mut engine, dir, ".Trash-1000", NodeKind::Folder);
    seed_child(&mut engine, junk, "buried.txt", NodeKind::File);
    OperationCore::new(engine, RecordingAdapter::push_capable())
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
