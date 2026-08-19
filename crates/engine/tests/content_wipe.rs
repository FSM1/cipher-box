//! A ranged read must not strand plaintext in freed memory.
//!
//! The window a media element asks for rarely lines up with a chunk boundary, so
//! every seek unseals head and tail bytes the caller never receives, and a
//! mid-read trust reject abandons whatever the assembly buffer already holds.
//! This suite owns the whole test binary because it installs a global allocator
//! that inspects each block freed on the thread under test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

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
/// An accidental match on unrelated bytes is ~2^-128 per position at this width;
/// a scenario needing a sub-leaf region detected widens its own leaf instead.
const MARKER_LEN: usize = 16;
/// Two scenarios fill a whole `CHUNK`-wide leaf with one marker, so a leaf
/// narrower than a run would make them pass vacuously.
const _: () = assert!(CHUNK >= MARKER_LEN);

/// The freed block that carried a marker run. Reported rather than reduced to a
/// bare boolean, so a failure is diagnosable from CI output alone; `marker`
/// names which region stranded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Leak {
    block_size: usize,
    run_start: usize,
    marker: u8,
}

thread_local! {
    /// The whole watch is thread-local: the allocator is process-wide, so
    /// global state would let a block the read path never owned decide the
    /// verdict. `block_on` drives the read on the armed thread.
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    /// The armed marker bytes, one bit per value. A set is what the scan needs
    /// and a mask keeps the membership test in the allocator hook to a shift.
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

/// Flags any freed block still carrying a marker run, while a read is in flight
/// on this thread. A block too small to hold one cannot carry it.
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

/// What the watchdog saw over one armed read.
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
        /// watching for, which is the gate-flipping this suite exists to avoid.
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

/// The scoped window still catches what it exists to catch, and with several
/// regions armed a hit names the one that stranded.
#[test]
fn the_watchdog_reports_the_block_and_region_an_unwiped_run_reached_it_in() {
    const UNTOUCHED: u8 = 0xD9;
    const STRANDED: u8 = 0x3C;
    let seen = watched(&[UNTOUCHED, STRANDED], || {
        let mut stranded = vec![0u8; 3 * MARKER_LEN];
        stranded[MARKER_LEN..2 * MARKER_LEN].fill(STRANDED);
        drop(stranded);
    });

    assert_eq!(
        seen.leak,
        Some(Leak {
            block_size: 3 * MARKER_LEN,
            run_start: MARKER_LEN,
            marker: STRANDED,
        }),
        "a hit names its block and its region, so a false positive is visible as one"
    );
}

/// A scenario that panics must still close its window. The harness gives each
/// test its own thread, but under `--test-threads=1` a thread left armed would
/// scan every later allocation against a stale marker.
#[test]
fn a_panicking_scenario_disarms_the_thread() {
    let outcome = std::panic::catch_unwind(|| {
        watched(&[0x7F], || -> () { panic!("the scenario blew up") });
    });

    assert!(outcome.is_err(), "the panic still reaches the harness");
    assert!(!WATCHING.get(), "the window closed on the way out");
}

/// `0x00` is what a correctly wiped buffer holds, so arming on it would report
/// a leak on every clean read.
#[test]
#[should_panic(expected = "match every correct wipe")]
fn arming_on_the_wiped_buffer_byte_is_refused() {
    watched(&[0], || ());
}

/// The property under test is what the read path leaves behind, so only the
/// thread running it may decide the verdict.
#[test]
fn a_foreign_threads_freed_block_never_trips_the_watchdog() {
    const MARKER: u8 = 0xE1;
    let seen = watched(&[MARKER], || {
        std::thread::spawn(|| {
            drop(vec![MARKER; 4 * CHUNK]);
        })
        .join()
        .expect("the foreign thread ran");
    });

    assert_eq!(seen.leak, None, "a foreign block cannot fail this suite");
}

#[test]
fn a_ranged_read_wipes_the_head_and_tail_it_trims_away() {
    // Each region of leaf 1 carries its own marker, so a hit names which one
    // stranded — the head and the tail are the regions the caller never sees and
    // the ones a wipe narrowed to the delivered slice would leave behind. The
    // leaf is wider than the CI one so each trimmed region holds a full run on
    // its own; at CI width both are shorter than a run and invisible.
    const TRIMMED_CHUNK: usize = 6 * MARKER_LEN;
    // Twice a run, so a partial strand of a trimmed region is still detectable.
    const TRIM: usize = 2 * MARKER_LEN;
    const DELIVERED: usize = TRIMMED_CHUNK - 2 * TRIM;
    const HEAD: u8 = 0xA7;
    const MIDDLE: u8 = 0x3C;
    const TAIL: u8 = 0x6E;
    let profile = ContentProfile::new(TRIMMED_CHUNK).expect("nonzero chunk size");
    let mut plaintext = vec![1u8; TRIMMED_CHUNK];
    plaintext.extend_from_slice(&[HEAD; TRIM]);
    plaintext.extend_from_slice(&[MIDDLE; DELIVERED]);
    plaintext.extend_from_slice(&[TAIL; TRIM]);
    plaintext.extend_from_slice(&[2u8; TRIMMED_CHUNK]);
    let (leaves, root_block, content) = frame_version_with(&plaintext, CONTENT_KEY, 1, profile);

    let mut blocks = block_store(&leaves);
    blocks.insert(encode_content_cid_str(content.content_cid()), root_block);
    let http = serve(&blocks);
    let version = content.version(CONTENT_KEY, 0);

    let seen = watched(&[HEAD, MIDDLE, TAIL], || {
        block_on(open_content_range(
            &gateway(),
            &http,
            &version,
            (TRIMMED_CHUNK + TRIM) as u64,
            DELIVERED as u64,
        ))
    });

    assert_eq!(
        seen.outcome.expect("range read"),
        &[MIDDLE; DELIVERED],
        "the window the caller asked for"
    );
    assert!(seen.inspected > 0, "the watchdog scanned nothing");
    assert_eq!(
        seen.leak, None,
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

    let seen = watched(&[MARKER], || {
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
    assert_eq!(
        seen.leak, None,
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

    let seen = watched(&[MARKER], || {
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
    assert_eq!(
        seen.leak, None,
        "the outgrown assembly buffer reached the allocator unwiped"
    );
}
