//! The ranged-fetch profile of the frozen production framing: what one byte
//! range costs on the wire once the flat DAG maps it chunk-aligned
//! (blueprint/engine.md "shaped so ranged ... fetches map chunk-aligned").
//!
//! The output is the `tools/perf/RESULTS.md` ranged-fetch table. It is
//! arithmetic over [`leaf_range_for_byte_range`] alone, so it needs no stack,
//! no network and no clock, and two runs on any host agree.

use cipherbox_engine::content::chunk::SEALED_LEAF_OVERHEAD;
use cipherbox_engine::{ContentProfile, leaf_range_for_byte_range};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

const SIZES: [u64; 3] = [64 * KIB, 4 * MIB, 64 * MIB];

/// The ranges a reader asks for: a probe at each end, an aligned page, a page
/// that straddles a leaf boundary, a resumed download, and the whole object.
fn ranges(size: u64) -> Vec<(&'static str, u64, u64)> {
    let resume = size / 4 * 3;
    vec![
        ("first 4 KiB", 0, 4 * KIB),
        ("last 4 KiB", size.saturating_sub(4 * KIB), 4 * KIB),
        ("1 MiB at 0", 0, MIB),
        ("1 MiB at 512 KiB", 512 * KIB, MIB),
        ("resume at 3/4", resume, size - resume),
        ("whole object", 0, size),
    ]
}

fn main() {
    let chunk = ContentProfile::PRODUCTION.chunk_size() as u64;
    let sealed_leaf = chunk + SEALED_LEAF_OVERHEAD;
    println!("chunk size {chunk} B, sealed leaf {sealed_leaf} B\n");
    println!("| Object | Range | Asked B | Leaves | Wire B | Over-fetch |");
    println!("| --- | --- | --: | --: | --: | --: |");

    for size in SIZES {
        let leaf_count = size.div_ceil(chunk) as usize;
        for (label, offset, length) in ranges(size) {
            let asked = length.min(size.saturating_sub(offset));
            if asked == 0 {
                continue;
            }
            let touched = leaf_range_for_byte_range(offset, asked, chunk, leaf_count).len() as u64;
            let wire = touched * sealed_leaf;
            println!(
                "| {} | {label} | {asked} | {touched} | {wire} | {:.2}x |",
                human(size),
                wire as f64 / asked as f64
            );
        }
    }
}

fn human(bytes: u64) -> String {
    if bytes >= MIB {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{} KiB", bytes / KIB)
    }
}
