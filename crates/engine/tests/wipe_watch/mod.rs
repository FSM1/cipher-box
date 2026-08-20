//! A global allocator that flags any freed block still carrying a marker run,
//! plus the scoped window that arms it.
//!
//! Shared by every suite that proves a plaintext owner wipes what it held. Each
//! suite installs the allocator itself — `#[global_allocator]` must be declared
//! in the binary — so the statics below are per-binary and the self-tests here
//! run once per binary, which is the only scope in which they bind.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// A run of this many identical bytes in a freed block is stranded plaintext.
/// An accidental match on unrelated bytes is ~2^-128 per position at this width;
/// a scenario needing a narrower region detected widens its own fixture instead.
pub const MARKER_LEN: usize = 16;

/// The freed block that carried a marker run. Reported rather than reduced to a
/// bare boolean, so a failure is diagnosable from CI output alone; `marker`
/// names which region stranded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leak {
    pub block_size: usize,
    pub run_start: usize,
    pub marker: u8,
}

thread_local! {
    /// The whole watch is thread-local: the allocator is process-wide, so
    /// global state would let a block the scenario never owned decide the
    /// verdict.
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

/// Whether this thread's window is open.
pub fn is_watching() -> bool {
    WATCHING.get()
}

fn is_armed(mask: &[u64; 4], byte: u8) -> bool {
    mask[usize::from(byte >> 6)] & (1 << (byte & 63)) != 0
}

/// Flags any freed block still carrying a marker run, while a scenario is in
/// flight on this thread. A block too small to hold one cannot carry it.
pub struct Watchdog;

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

/// What the watchdog saw over one armed scenario.
pub struct Watched<T> {
    pub outcome: T,
    pub leak: Option<Leak>,
    pub inspected: usize,
}

/// Runs `body` with the watchdog armed for every byte in `markers` on this
/// thread. Every scenario owns its own watch, so none needs serializing against
/// another.
pub fn watched<T>(markers: &[u8], body: impl FnOnce() -> T) -> Watched<T> {
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
        /// watching for, which is the gate-flipping this harness exists to avoid.
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
    assert!(!is_watching(), "the window closed on the way out");
}

/// `0x00` is what a correctly wiped buffer holds, so arming on it would report
/// a leak on every clean read.
#[test]
#[should_panic(expected = "match every correct wipe")]
fn arming_on_the_wiped_buffer_byte_is_refused() {
    watched(&[0], || ());
}

/// The property under test is what one path leaves behind, so only the thread
/// running it may decide the verdict.
#[test]
fn a_foreign_threads_freed_block_never_trips_the_watchdog() {
    const MARKER: u8 = 0xE1;
    let seen = watched(&[MARKER], || {
        std::thread::spawn(|| {
            drop(vec![MARKER; 4 * MARKER_LEN]);
        })
        .join()
        .expect("the foreign thread ran");
    });

    assert_eq!(seen.leak, None, "a foreign block cannot fail this suite");
}
