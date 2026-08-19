//! Decoded intent must not strand user plaintext in freed memory.
//!
//! An op body is sealed because it carries filenames, and opening one copies
//! those names out of the `Zeroizing` buffer the seal hands back into owned
//! `String`s that outlive it. The same names then live on in the working-tree
//! snapshot. This suite owns the whole test binary because it installs a global
//! allocator that inspects each block freed on the thread under test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use cipherbox_core::suite::x25519::X25519Secret;
use cipherbox_engine::seams::UnixMillis;
use cipherbox_engine::sync::model::NodeMeta;
use cipherbox_engine::sync::{
    NewNode, Op, RecordClass, RecordReader, RecordSeal, Snapshot, encode_op_record,
};
use cipherbox_engine::{NodeId, NodeKind};
use zeroize::Zeroizing;

/// A run of this many identical bytes in a freed block is stranded plaintext.
/// An accidental match on unrelated bytes is ~2^-128 per position at this width.
const MARKER_LEN: usize = 16;
/// Names are built two markers wide, so a `String` whose allocation the
/// allocator rounds up still carries a full run inside the block it reports.
const NAME_LEN: usize = 2 * MARKER_LEN;

/// The freed block that carried a marker run. Reported rather than reduced to a
/// bare boolean, so a failure is diagnosable from CI output alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leak {
    block_size: usize,
    run_start: usize,
    marker: u8,
}

thread_local! {
    /// The whole watch is thread-local: the allocator is process-wide, so
    /// global state would let a block the scenario never owned decide the
    /// verdict.
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    /// The armed marker bytes, one bit per value.
    static ARMED: Cell<[u64; 4]> = const { Cell::new([0; 4]) };
    /// Blocks the scan actually looked at. Without it a no-leak assertion
    /// passes vacuously whenever nothing in the armed window matched.
    static INSPECTED: Cell<usize> = const { Cell::new(0) };
    /// First hit only; a later one adds nothing.
    static LEAK: Cell<Option<Leak>> = const { Cell::new(None) };
}

fn is_armed(mask: &[u64; 4], byte: u8) -> bool {
    mask[usize::from(byte >> 6)] & (1 << (byte & 63)) != 0
}

/// Flags any freed block still carrying a marker run, while a scenario is in
/// flight on this thread. A block too small to hold one cannot carry it.
struct Watchdog;

unsafe impl GlobalAlloc for Watchdog {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= MARKER_LEN && WATCHING.get() {
            INSPECTED.set(INSPECTED.get() + 1);
            let armed = ARMED.get();
            let mut run = 0usize;
            let mut previous = 0u8;
            for offset in 0..layout.size() {
                let byte = unsafe { ptr.add(offset).read_volatile() };
                run = if byte == previous { run + 1 } else { 1 };
                previous = byte;
                if run == MARKER_LEN && is_armed(&armed, byte) {
                    if LEAK.get().is_none() {
                        LEAK.set(Some(Leak {
                            block_size: layout.size(),
                            run_start: offset + 1 - MARKER_LEN,
                            marker: byte,
                        }));
                    }
                    break;
                }
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watchdog = Watchdog;

/// What the watchdog saw over one armed scenario.
struct Watched<T> {
    outcome: T,
    leak: Option<Leak>,
    inspected: usize,
}

/// Runs `body` with the watchdog armed for every byte in `markers` on this
/// thread. Every scenario owns its own watch, so none needs serializing against
/// another.
fn watched<T>(markers: &[u8], body: impl FnOnce() -> T) -> Watched<T> {
    assert!(!markers.is_empty(), "a watch with no marker is vacuous");
    assert!(
        markers.iter().all(|&m| m != 0),
        "0x00 is what a wiped buffer holds, so it would match every correct wipe"
    );
    let mut armed = [0u64; 4];
    for &m in markers {
        armed[usize::from(m >> 6)] |= 1 << (m & 63);
    }
    LEAK.set(None);
    INSPECTED.set(0);
    ARMED.set(armed);
    let outcome = {
        /// Disarms on the way out, an unwinding `body` included: a thread left
        /// armed scans every later allocation against a marker no one is
        /// watching for.
        struct Disarm;
        impl Drop for Disarm {
            fn drop(&mut self) {
                WATCHING.set(false);
            }
        }
        let _disarm = Disarm;
        WATCHING.set(true);
        body()
    };
    Watched {
        outcome,
        leak: LEAK.get(),
        inspected: INSPECTED.get(),
    }
}

/// A filename of `marker` repeated — one armed run, and valid UTF-8 because
/// every marker this suite arms is ASCII.
fn marked_name(marker: u8) -> String {
    assert!(marker.is_ascii() && marker != 0, "a name must be UTF-8");
    String::from_utf8(vec![marker; NAME_LEN]).expect("ascii is UTF-8")
}

fn id(b: u8) -> NodeId {
    NodeId([b; 16])
}

const AT: UnixMillis = UnixMillis(0);

/// A sealed durable record carrying a `create` op named `name`, with the
/// custody that opens it. Built outside any armed window: this suite watches
/// what *decoding* strands, not what sealing does.
fn sealed_create(name: &str) -> (X25519Secret, Vec<u8>) {
    let owner = X25519Secret::from_scalar([9; 32]);
    let op = Op::create(id(1), id(0), name, NewNode::Folder, 1, AT);
    let record = encode_op_record(
        RecordSeal {
            owner_enc_secret: &owner,
            ephemeral_scalar: Zeroizing::new([7; 32]),
        },
        &op,
    )
    .expect("a folder create seals");
    (owner, record)
}

/// The suite's own instrument: a run the scenario deliberately strands must be
/// reported, or every no-leak assertion below passes vacuously.
#[test]
fn the_watchdog_reports_a_stranded_run() {
    const STRANDED: u8 = 0x3C;
    let seen = watched(&[STRANDED], || {
        let stranded = vec![STRANDED; NAME_LEN];
        drop(stranded);
    });

    assert_eq!(
        seen.leak,
        Some(Leak {
            block_size: NAME_LEN,
            run_start: 0,
            marker: STRANDED,
        }),
        "a hit names its block and its region, so a false positive is visible as one"
    );
}

/// The gap this suite exists for: opening a record copies the filename out of
/// the seal's zeroizing buffer, and that copy is the decoded op's to wipe.
#[test]
fn a_decoded_op_wipes_its_filename_on_drop() {
    const MARK: u8 = 0x2B;
    let (owner, record) = sealed_create(&marked_name(MARK));

    let seen = watched(&[MARK], || {
        let reader = RecordReader::new(&owner);
        match reader.classify(&record) {
            RecordClass::Mine(op) => drop(op),
            other => panic!("the owner's own record classifies as theirs: {other:?}"),
        }
    });

    assert!(
        seen.inspected > 0,
        "the window saw no freed block, so the verdict is vacuous"
    );
    assert_eq!(seen.leak, None, "a decoded filename reached freed memory");
}

/// The longest-lived copy: a name projected into the working tree lives for the
/// session, so the snapshot must wipe it too.
#[test]
fn a_dropped_snapshot_wipes_its_node_names() {
    const MARK: u8 = 0x3D;
    let name = marked_name(MARK);

    let seen = watched(&[MARK], || {
        let mut snapshot = Snapshot::new(id(0));
        snapshot.upsert_node(NodeMeta::new(id(1), name.as_str(), NodeKind::File));
        drop(snapshot);
    });

    assert!(
        seen.inspected > 0,
        "the window saw no freed block, so the verdict is vacuous"
    );
    assert_eq!(seen.leak, None, "a snapshot node name reached freed memory");
}

/// A rename supersedes a name in place. The replaced `String` is dropped by the
/// assignment, not by the node, so wiping only on drop would strand it.
#[test]
fn a_rename_wipes_the_name_it_supersedes() {
    const SUPERSEDED: u8 = 0x3E;
    let old = marked_name(SUPERSEDED);

    let seen = watched(&[SUPERSEDED], || {
        let mut node = NodeMeta::new(id(1), old.as_str(), NodeKind::File);
        node.rename("after");
        node
    });

    assert!(
        seen.inspected > 0,
        "the window saw no freed block, so the verdict is vacuous"
    );
    assert_eq!(seen.leak, None, "the superseded name reached freed memory");
    assert_eq!(seen.outcome.name, "after");
}
