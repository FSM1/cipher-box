//! The `fuse-op-core` suite: every vfs operation driven against a real engine
//! over the in-memory seam fakes, plus the never-block law
//! (blueprint/desktop.md "Reads, writes, and the never-block law").
//!
//! No kernel and no adapter — the operation core is the unit under test, and a
//! recording adapter stands in for the mount so the outbound invalidation
//! direction is observable.

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use cipherbox_engine::testkit::{FakeSeamTypes, FakeWorld, SeededEntropy, block_on};
use cipherbox_engine::{
    Engine, GatewayConfig, LoginSecret, NodeKind, StoragePolicy, SyncTimingProfile,
};
use cipherbox_fuse::{
    Access, HostAdapter, HostCapabilities, Invalidation, NameError, OperationCore, ROOT_INO,
    VfsError,
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
    let world = FakeWorld::new();
    let device = world.device(b"alice-pk");
    let (mut engine, _events) = Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(42)),
        SyncTimingProfile::CI,
        StoragePolicy::CI,
        String::new(),
        GatewayConfig::disabled(),
    );
    block_on(engine.start(LoginSecret::new(vec![7u8; 32]))).expect("engine starts");
    let adapter = RecordingAdapter::push_capable();
    (OperationCore::new(engine, adapter.clone()), adapter)
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
fn a_created_node_is_immediately_visible_through_lookup_and_readdir() {
    let (mut core, _adapter) = mount();
    let created = block_on(core.mkdir(ROOT_INO, "Photos")).expect("mkdir");

    let found = block_on(core.lookup(ROOT_INO, "Photos")).expect("lookup");
    assert_eq!(found.ino, created.ino);
    assert_eq!(found.kind, NodeKind::Folder);
    assert_eq!(names(&mut core, ROOT_INO), vec!["Photos".to_owned()]);
}

#[test]
fn lookup_and_readdir_agree_on_inode_numbers() {
    let (mut core, _adapter) = mount();
    block_on(core.mkdir(ROOT_INO, "dir")).unwrap();
    let (attrs, _handle) = block_on(core.create(ROOT_INO, "f.txt", Access::ReadWrite)).unwrap();

    let listed = block_on(core.readdir(ROOT_INO)).unwrap();
    for entry in &listed {
        let looked_up = block_on(core.lookup(ROOT_INO, &entry.name)).unwrap();
        assert_eq!(looked_up.ino, entry.ino, "{} renumbered", entry.name);
    }
    assert!(listed.iter().any(|entry| entry.ino == attrs.ino));
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
fn statfs_counts_reachable_nodes_and_advertises_the_enforced_name_limit() {
    let (mut core, _adapter) = mount();
    assert_eq!(block_on(core.statfs()).unwrap().nodes, 1, "root only");
    block_on(core.mkdir(ROOT_INO, "a")).unwrap();
    block_on(core.create(ROOT_INO, "b", Access::Write)).unwrap();
    let stats = block_on(core.statfs()).unwrap();
    assert_eq!(stats.nodes, 3);

    let longest = "x".repeat(stats.name_max as usize);
    block_on(core.mkdir(ROOT_INO, &longest)).expect("the advertised limit is creatable");
    let too_long = "x".repeat(stats.name_max as usize + 1);
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

    // Each of these must reach its answer from the rendered snapshot alone:
    // a yield here would mean a kernel callback waiting on resolve or publish.
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
    // Nothing is cached and nothing has resolved: the read surface still
    // answers from last-known-good rather than waiting on the network.
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
    // A name another client committed is inadmissible here but must stay
    // reachable for removal, or it is stranded in the vault forever. The
    // removal path therefore reports what it found, never why the name would
    // have been refused at create.
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

#[test]
fn a_windows_hostile_name_is_refused_on_this_platform_too() {
    let (mut core, _adapter) = mount();
    assert_eq!(
        block_on(core.mkdir(ROOT_INO, "re:port")),
        Err(VfsError::InvalidName(NameError::ReservedCharacter))
    );
    assert_eq!(
        block_on(core.mkdir(ROOT_INO, "COM1")),
        Err(VfsError::InvalidName(NameError::ReservedDevice))
    );
    assert_eq!(
        block_on(core.mkdir(ROOT_INO, "")),
        Err(VfsError::InvalidName(NameError::Empty))
    );
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
    let world = FakeWorld::new();
    let device = world.device(b"bob-pk");
    let (mut engine, _events) = Engine::new(
        device.seam_set(),
        Box::new(SeededEntropy::new(7)),
        SyncTimingProfile::CI,
        StoragePolicy::CI,
        String::new(),
        GatewayConfig::disabled(),
    );
    block_on(engine.start(LoginSecret::new(vec![9u8; 32]))).unwrap();
    let without_push = OperationCore::new(engine, RecordingAdapter::default());

    assert!(without_push.cache_ttls().entry < with_push.cache_ttls().entry);
    assert!(!without_push.cache_ttls().attr.is_zero());
}
