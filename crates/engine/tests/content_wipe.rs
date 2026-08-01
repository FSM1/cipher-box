//! A ranged read must not strand a leaf's plaintext in freed memory.
//!
//! The window a media element asks for rarely lines up with a chunk boundary, so
//! every seek unseals head and tail bytes the caller never receives. This suite
//! owns the whole test binary because it installs a global allocator that
//! inspects each block as it is freed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use cipherbox_core::content::encode_content_cid_str;
use cipherbox_core::suite::aead::KEY_LEN;
use cipherbox_engine::content::{Gateway, GatewaySource, open_content_range};
use cipherbox_engine::seams::{HttpResponse, SeamError};
use cipherbox_engine::testkit::fakes::ScriptedHttp;
use cipherbox_engine::testkit::{block_on, frame_version};

const CONTENT_KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];
/// The CI content profile's chunk size; one leaf of plaintext.
const CHUNK: usize = 16;
/// Leaf ciphertext is the chunk plus a Poly1305 tag — the only block size scanned.
const SEALED_LEN: usize = CHUNK + 16;
/// The plaintext of leaf 1, recognizable in a raw memory block.
const MARKER: [u8; CHUNK] = [0xA7u8; CHUNK];

static WATCHING: AtomicBool = AtomicBool::new(false);
static LEAKED: AtomicBool = AtomicBool::new(false);

/// Flags any freed block that still carries [`MARKER`]. Only blocks the size of
/// a leaf's ciphertext are inspected, and only while a read is in flight.
struct Watchdog;

unsafe impl GlobalAlloc for Watchdog {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == SEALED_LEN && WATCHING.load(Ordering::Relaxed) {
            let mut matched = 0usize;
            for offset in 0..SEALED_LEN {
                let byte = unsafe { ptr.add(offset).read_volatile() };
                matched = if byte == MARKER[0] { matched + 1 } else { 0 };
                if matched == MARKER.len() {
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

fn gateway() -> Gateway {
    Gateway {
        accelerator: None,
        public_fallbacks: vec![GatewaySource {
            base_url: "https://public.gw.test".into(),
            bearer: None,
        }],
    }
}

/// Serves `blocks` by the CID the trustless-gateway URL addresses.
fn serve(blocks: BTreeMap<String, Vec<u8>>) -> ScriptedHttp {
    let http = ScriptedHttp::default();
    for _ in 0..8 {
        let blocks = blocks.clone();
        http.enqueue_derived(move |request| {
            let cid = request
                .url
                .rsplit('/')
                .next()
                .and_then(|tail| tail.split('?').next())
                .unwrap_or_default();
            match blocks.get(cid) {
                Some(block) => Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: block.clone(),
                }),
                None => Err(SeamError::new("no such block")),
            }
        });
    }
    http
}

#[test]
fn a_ranged_read_wipes_each_leafs_plaintext_before_it_drops() {
    // Three leaves; the marker fills leaf 1, and the window asks for four of its
    // bytes, so the leaf is fetched and unsealed but mostly trimmed away.
    let mut plaintext = vec![1u8; CHUNK];
    plaintext.extend_from_slice(&MARKER);
    plaintext.extend_from_slice(&[2u8; CHUNK]);
    let (leaves, root_block, content) = frame_version(&plaintext, CONTENT_KEY, 1);

    let mut blocks = BTreeMap::new();
    for leaf in &leaves {
        blocks.insert(encode_content_cid_str(&leaf.cid), leaf.sealed.clone());
    }
    blocks.insert(encode_content_cid_str(content.content_cid()), root_block);
    let http = serve(blocks);
    let version = content.version(CONTENT_KEY, 0);

    WATCHING.store(true, Ordering::Relaxed);
    let out = block_on(open_content_range(&gateway(), &http, &version, 20, 4)).expect("range read");
    WATCHING.store(false, Ordering::Relaxed);

    assert_eq!(out, &MARKER[4..8], "the window the caller asked for");
    assert!(
        !LEAKED.load(Ordering::Relaxed),
        "a leaf's plaintext reached the allocator unwiped"
    );
}
