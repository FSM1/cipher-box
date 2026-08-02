//! A ranged read must not strand plaintext in freed memory.
//!
//! The window a media element asks for rarely lines up with a chunk boundary, so
//! every seek unseals head and tail bytes the caller never receives, and a
//! mid-read trust reject abandons whatever the assembly buffer already holds.
//! This suite owns the whole test binary because it installs a global allocator
//! that inspects each block as it is freed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::suite::aead::KEY_LEN;
use cipherbox_engine::content::{
    ContentKey, ContentProfile, SealedContent, assemble, open_content_range, seal_one_chunk,
};
use cipherbox_engine::testkit::{
    SeededEntropy, block_on, block_store, frame_version, frame_version_with, gateway, serve,
};

const CONTENT_KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];
/// The CI content profile's chunk size; one leaf of plaintext.
const CHUNK: usize = 16;
/// A run of this many identical bytes in a freed block is stranded plaintext.
const MARKER_LEN: usize = CHUNK;

static WATCHING: AtomicBool = AtomicBool::new(false);
static LEAKED: AtomicBool = AtomicBool::new(false);
/// Blocks the scan actually looked at. Without it a `!LEAKED` assertion passes
/// vacuously whenever nothing in the armed window matched the filter.
static INSPECTED: AtomicUsize = AtomicUsize::new(0);
/// The byte the armed scenario's marker is made of. Each scenario picks its own:
/// the harness runs the tests on parallel threads, and one scenario's fixture
/// buffers drop inside another's window.
static MARKER_BYTE: AtomicU8 = AtomicU8::new(0);
/// The watchdog statics are global, so only one scenario may be armed at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// Flags any freed block still carrying a marker run, while a read is in flight.
/// A block too small to hold one cannot carry it.
struct Watchdog;

unsafe impl GlobalAlloc for Watchdog {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= MARKER_LEN && WATCHING.load(Ordering::Relaxed) {
            INSPECTED.fetch_add(1, Ordering::Relaxed);
            let wanted = MARKER_BYTE.load(Ordering::Relaxed);
            let mut matched = 0usize;
            for offset in 0..layout.size() {
                let byte = unsafe { ptr.add(offset).read_volatile() };
                matched = if byte == wanted { matched + 1 } else { 0 };
                if matched == MARKER_LEN {
                    LEAKED.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watchdog = Watchdog;

/// What the watchdog saw over one armed read.
struct Watched<T> {
    outcome: T,
    leaked: bool,
    inspected: usize,
}

/// Runs `body` with the watchdog armed for `marker`, serialized against every
/// other scenario.
fn watched<T>(marker: u8, body: impl FnOnce() -> T) -> Watched<T> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    LEAKED.store(false, Ordering::Relaxed);
    INSPECTED.store(0, Ordering::Relaxed);
    MARKER_BYTE.store(marker, Ordering::Relaxed);
    WATCHING.store(true, Ordering::Relaxed);
    let outcome = body();
    WATCHING.store(false, Ordering::Relaxed);
    Watched {
        outcome,
        leaked: LEAKED.load(Ordering::Relaxed),
        inspected: INSPECTED.load(Ordering::Relaxed),
    }
}

#[test]
fn a_ranged_read_wipes_each_leafs_plaintext_before_it_drops() {
    const MARKER: u8 = 0xA7;
    // Three leaves; the marker fills leaf 1, and the window asks for four of its
    // bytes, so the leaf is fetched and unsealed but mostly trimmed away.
    let mut plaintext = vec![1u8; CHUNK];
    plaintext.extend_from_slice(&[MARKER; CHUNK]);
    plaintext.extend_from_slice(&[2u8; CHUNK]);
    let (leaves, root_block, content) = frame_version(&plaintext, CONTENT_KEY, 1);

    let mut blocks = block_store(&leaves);
    blocks.insert(encode_content_cid_str(content.content_cid()), root_block);
    let http = serve(&blocks);
    let version = content.version(CONTENT_KEY, 0);

    let seen = watched(MARKER, || {
        block_on(open_content_range(&gateway(), &http, &version, 20, 4))
    });

    assert_eq!(
        seen.outcome.expect("range read"),
        &[MARKER; 4],
        "the window the caller asked for"
    );
    assert!(seen.inspected > 0, "the watchdog scanned nothing");
    assert!(
        !seen.leaked,
        "a leaf's plaintext reached the allocator unwiped"
    );
}

#[test]
fn a_mid_read_trust_reject_wipes_what_the_assembly_buffer_already_holds() {
    const MARKER: u8 = 0xB3;
    // Leaf 0 is the marker; leaf 1 is a short leaf the flat framing forbids. The
    // read appends leaf 0, then abandons the buffer on leaf 1's length reject.
    let mut plaintext = vec![MARKER; CHUNK];
    plaintext.extend_from_slice(&[2u8; CHUNK]);
    plaintext.extend_from_slice(&[3u8; CHUNK]);
    let (leaves, _, _) = frame_version(&plaintext, CONTENT_KEY, 2);

    let mut entropy = SeededEntropy::new(3);
    let short = seal_one_chunk(
        &ContentKey::from_bytes(CONTENT_KEY),
        &[4u8; CHUNK / 2],
        &mut entropy,
    )
    .expect("seeded entropy");
    let dag = assemble(
        &[
            leaves[0].cid.clone(),
            short.cid.clone(),
            leaves[2].cid.clone(),
        ],
        plaintext.len() as u64,
        &ContentProfile::CI,
    )
    .expect("three leaves for 48 bytes at chunk 16");

    let mut blocks = block_store([&leaves[0], &short, &leaves[2]]);
    blocks.insert(
        encode_content_cid_str(&dag.content_cid),
        dag.root_block.clone(),
    );
    let http = serve(&blocks);
    let version = SealedContent::from_root_block(&dag.root_block)
        .expect("the root this build just assembled")
        .version(CONTENT_KEY, 0);

    let seen = watched(MARKER, || {
        block_on(open_content_range(
            &gateway(),
            &http,
            &version,
            0,
            plaintext.len() as u64,
        ))
    });

    let err = seen.outcome.expect_err("leaf 1 disagrees with the framing");
    assert!(
        format!("{err:?}").contains("leaf 1 unsealed to"),
        "rejected for the per-leaf length, not something else: {err:?}"
    );
    assert!(seen.inspected > 0, "the watchdog scanned nothing");
    assert!(
        !seen.leaked,
        "the abandoned assembly buffer reached the allocator unwiped"
    );
}

#[test]
fn outgrowing_the_assembly_buffer_wipes_the_allocation_it_leaves_behind() {
    const MARKER: u8 = 0xC5;
    // The assembly buffer preallocates a 4 MiB budget, so growth is only
    // reachable from a window wider than that: two 2 MiB leaves fill the budget
    // exactly and a 16-byte tail leaf forces the grow.
    const BIG_CHUNK: usize = 2 * 1024 * 1024;
    let profile = ContentProfile::new(BIG_CHUNK).expect("nonzero chunk size");
    let mut plaintext = vec![MARKER; BIG_CHUNK];
    plaintext.extend_from_slice(&vec![0x11u8; BIG_CHUNK]);
    plaintext.extend_from_slice(&[0x22u8; CHUNK]);
    let (leaves, root_block, content) = frame_version_with(&plaintext, CONTENT_KEY, 4, profile);

    let mut blocks = block_store(&leaves);
    blocks.insert(encode_content_cid_str(content.content_cid()), root_block);
    let http = serve(&blocks);
    let version = content.version(CONTENT_KEY, 0);

    let seen = watched(MARKER, || {
        block_on(open_content_range(
            &gateway(),
            &http,
            &version,
            0,
            plaintext.len() as u64,
        ))
    });

    assert_eq!(
        seen.outcome.expect("range read").len(),
        plaintext.len(),
        "the whole window the caller asked for"
    );
    assert!(seen.inspected > 0, "the watchdog scanned nothing");
    assert!(
        !seen.leaked,
        "the outgrown assembly buffer reached the allocator unwiped"
    );
}
