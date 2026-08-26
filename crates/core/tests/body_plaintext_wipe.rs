//! A sealed-body child ref must not strand its name in freed memory.
//!
//! `name` and `ipnsName` are sealed-body plaintext — user-private metadata in a
//! zero-knowledge system — and a decode lifts them out of the scrubbed CBOR tree
//! into owned buffers that outlive it. `ChildRef` is their terminal owner, so
//! the wipe is asserted here rather than at each call site that holds one.
//!
//! The wipe is observed inside `dealloc`, while the block is still validly
//! allocated: reading it after the free would be undefined behaviour, and a
//! post-drop read of a retained pointer proves nothing a reused allocation
//! could not fake. This suite owns the whole test binary because it installs
//! the `wipe_watch` global allocator.
#![cfg(not(target_family = "wasm"))]

use cipherbox_core::seal::{ChildRef, NodeKind, PreservedFields, ReadBody, decode_read_body};

mod wipe_watch;

use wipe_watch::{MARKER_LEN, Watchdog, Watched, watched};

#[global_allocator]
static ALLOCATOR: Watchdog = Watchdog;

/// Two markers wide, so a buffer whose allocation the allocator rounds up still
/// carries a full run inside the block it reports.
const FIELD_LEN: usize = 2 * MARKER_LEN;

const NAME_MARK: u8 = 0x2D;
const IPNS_MARK: u8 = 0xB7;
const RENAMED_MARK: u8 = 0x3E;

/// A name of `marker` repeated. ASCII, so the run survives into the UTF-8 buffer
/// byte-for-byte.
fn marked_name(marker: u8) -> String {
    assert!(marker.is_ascii() && marker != 0, "a name must be UTF-8");
    String::from_utf8(vec![marker; FIELD_LEN]).expect("ascii is UTF-8")
}

fn marked_child(name: u8, ipns: u8) -> ChildRef {
    ChildRef {
        id: [1; 16],
        name: marked_name(name),
        ipns_name: vec![ipns; FIELD_LEN],
        kind: NodeKind::File,
        link_counter: 0,
        unknown: PreservedFields::new(),
    }
}

/// Asserts the scenario stranded nothing, and that the instrument would have
/// reported it if it had.
///
/// `inspected > 0` alone is too weak: it holds even when the buffer under test
/// was never freed at all, which is a worse outcome than the one being fixed.
/// The control re-runs an equivalent allocation with no wipe behind it and
/// requires a hit.
fn assert_wiped<T>(seen: &Watched<T>, what: &str) {
    assert!(
        seen.inspected > 0,
        "{what}: no freed block reached the scan"
    );
    assert_eq!(seen.leak, None, "{what} reached freed memory");

    let control = watched(&[RENAMED_MARK], || {
        drop(marked_name(RENAMED_MARK));
        drop(vec![RENAMED_MARK; FIELD_LEN]);
    });
    assert!(
        control.leak.is_some(),
        "{what}: a field-sized block dropped unwiped goes unreported, \
         so the assertion above proves nothing"
    );
}

/// The gap this suite exists for: an ordinary drop, no call site involved.
#[test]
fn a_child_ref_wipes_its_name_and_ipns_name_on_drop() {
    let child = marked_child(NAME_MARK, IPNS_MARK);
    let seen = watched(&[NAME_MARK, IPNS_MARK], || drop(child));
    assert_wiped(&seen, "a dropped child ref's plaintext");
}

/// A rewrite displaces the old name without dropping the ref, so the ref's own
/// `Drop` never sees it.
#[test]
fn a_rename_wipes_the_name_it_displaces() {
    let mut child = marked_child(NAME_MARK, IPNS_MARK);
    let seen = watched(&[NAME_MARK], || child.rename(marked_name(RENAMED_MARK)));
    assert_eq!(child.name, marked_name(RENAMED_MARK), "the rewrite landed");
    assert_wiped(&seen, "the name a rename displaced");
}

/// The body types that hold child refs inherit the wipe: nothing in `ReadBody`
/// needs its own, and a folder decoded off the wire is the shape that matters.
#[test]
fn a_decoded_folder_body_wipes_every_child_it_decoded() {
    let bytes = cipherbox_core::seal::encode_read_body(&ReadBody::Folder {
        created_at: 1,
        modified_at: 2,
        children: vec![marked_child(NAME_MARK, IPNS_MARK)],
        unknown: PreservedFields::new(),
    })
    .expect("a one-child folder encodes");

    // The window spans the decode as well as the drop: the transient CBOR tree
    // the decode builds carries the same names, and it is core's to scrub.
    let seen = watched(&[NAME_MARK, IPNS_MARK], || {
        match decode_read_body(&bytes).expect("it decodes back") {
            ReadBody::Folder { children, .. } => children.len(),
            ReadBody::File { .. } => 0,
        }
    });
    assert_eq!(seen.outcome, 1, "the folder decoded its one child");
    assert_wiped(&seen, "a decoded folder body's child plaintext");
}

/// The wipe is per-instance: a clone owns its own buffers, so the codecs that
/// clone a ref out of a folder keep a readable copy after the source falls.
#[test]
fn a_clone_survives_the_wipe_of_the_ref_it_came_from() {
    let child = marked_child(NAME_MARK, IPNS_MARK);
    let clone = child.clone();
    drop(child);

    assert_eq!(clone.name, marked_name(NAME_MARK));
    assert_eq!(clone.ipns_name, vec![IPNS_MARK; FIELD_LEN]);
}

/// A fixture narrower than a run would let every assertion above pass without
/// the property holding.
const _: () = assert!(FIELD_LEN >= MARKER_LEN);
