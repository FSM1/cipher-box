//! A ranged read must not strand plaintext in freed memory.
//!
//! The window a media element asks for rarely lines up with a chunk boundary, so
//! every seek unseals head and tail bytes the caller never receives, and a
//! mid-read trust reject abandons whatever the assembly buffer already holds.
//! This suite owns the whole test binary because it installs the `wipe_watch`
//! global allocator, which inspects each block freed on the thread under test.

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::suite::aead::KEY_LEN;
use cipherbox_engine::content::{
    ContentKey, ContentProfile, SealedContent, assemble, open_content_range, seal_one_chunk,
};
use cipherbox_engine::testkit::{
    SeededEntropy, block_on, block_store, frame_version, frame_version_with, gateway, serve,
};

#[path = "../../core/tests/wipe_watch/mod.rs"]
mod wipe_watch;

use wipe_watch::{MARKER_LEN, Watchdog, watched};

#[global_allocator]
static ALLOCATOR: Watchdog = Watchdog;

const CONTENT_KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];
/// The CI content profile's chunk size; one leaf of plaintext.
const CHUNK: usize = 16;
/// Two scenarios fill a whole `CHUNK`-wide leaf with one marker, so a leaf
/// narrower than a run would make them pass vacuously.
const _: () = assert!(CHUNK >= MARKER_LEN);

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
    // The assembly buffer preallocates the block-cap budget, so growth is only
    // reachable from a window wider than that: two 1 MiB leaves fill the budget
    // exactly and a 16-byte tail leaf forces the grow.
    const BIG_CHUNK: usize = 1024 * 1024;
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
