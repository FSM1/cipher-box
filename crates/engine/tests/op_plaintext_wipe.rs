//! Decoded intent must not strand user plaintext in freed memory.
//!
//! An op body is sealed because it carries filenames, and opening one copies
//! those names out of the `Zeroizing` buffer the seal hands back into owned
//! `String`s that outlive it. The same names then live on in the working-tree
//! snapshot and in the collation keys a rebase folds. This suite owns the whole
//! test binary because it installs the `wipe_watch` global allocator, which
//! inspects each block freed on the thread under test.

use cipherbox_core::suite::x25519::X25519Secret;
use cipherbox_engine::seams::{OpId, UnixMillis};
use cipherbox_engine::sync::model::NodeMeta;
use cipherbox_engine::sync::{
    NewNode, Op, RecordClass, RecordReader, RecordSeal, Snapshot, encode_op_record, replay,
};
use cipherbox_engine::{NodeId, NodeKind};
use zeroize::Zeroizing;

// The harness lives with the crate whose types it was first written to prove
// wipe, and the engine reaches it by path rather than duplicating it.
#[path = "../../core/tests/wipe_watch/mod.rs"]
mod wipe_watch;

use wipe_watch::{MARKER_LEN, Watchdog, Watched, watched};

#[global_allocator]
static ALLOCATOR: Watchdog = Watchdog;

/// Names are built two markers wide, so a `String` whose allocation the
/// allocator rounds up still carries a full run inside the block it reports.
const NAME_LEN: usize = 2 * MARKER_LEN;

const AT: UnixMillis = UnixMillis(0);

/// A filename of `marker` repeated — one armed run, and valid UTF-8 because
/// every marker this suite arms is ASCII. Lowercase-stable too, so a collation
/// key folded from it is byte-identical and equally detectable.
fn marked_name(marker: u8) -> String {
    assert!(marker.is_ascii() && marker != 0, "a name must be UTF-8");
    String::from_utf8(vec![marker; NAME_LEN]).expect("ascii is UTF-8")
}

fn id(b: u8) -> NodeId {
    NodeId([b; 16])
}

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

/// Asserts the scenario stranded nothing, and that a name-sized block of its own
/// actually reached the scan.
///
/// `inspected > 0` alone is too weak: the paths under test free dozens of
/// unrelated blocks, so it would hold even if the name were interned or leaked
/// and never freed at all — which is the worse outcome, not the fixed one. The
/// control re-runs the same allocation with the wipe defeated and requires the
/// instrument to report it.
fn assert_wiped<T>(seen: &Watched<T>, control_marker: u8, what: &str) {
    assert!(
        seen.inspected > 0,
        "{what}: no freed block reached the scan"
    );
    assert_eq!(seen.leak, None, "{what} reached freed memory");

    let control = watched(&[control_marker], || drop(marked_name(control_marker)));
    assert!(
        control.leak.is_some(),
        "{what}: a name-sized block dropped unwiped goes unreported, \
         so the assertion above proves nothing"
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

    assert_wiped(&seen, 0x2C, "a decoded filename");
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

    assert_wiped(&seen, 0x3F, "a snapshot node name");
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

    assert_wiped(&seen, 0x40, "the superseded name");
    assert_eq!(seen.outcome.name(), "after");
}

/// A replay folds a collation key per sibling and a candidate per collision
/// probe. Both are verbatim copies of a filename, and there are far more of them
/// than there are nodes.
#[test]
fn a_replay_wipes_the_collation_keys_and_suffix_candidates_it_folds() {
    const MARK: u8 = 0x61;
    let name = marked_name(MARK);
    let (owner, record) = sealed_create(&name);
    let raw = vec![(OpId(1), record)];

    let seen = watched(&[MARK], || {
        // A sibling already holding the name, so the create loses the add/add
        // race and the suffix probe runs.
        let mut base = Snapshot::new(id(0));
        base.upsert_node(NodeMeta::new(id(2), name.as_str(), NodeKind::File));
        base.link(id(0), id(2), 1);
        let scan = cipherbox_engine::sync::decode_queue(&RecordReader::new(&owner), &raw);
        let report = replay(&base, &base.clone(), &scan.mine, &[id(0)]);
        drop(report);
        drop(base);
    });

    assert_wiped(&seen, 0x62, "a folded collation key");
}
