//! Per-stage profiling over core's pipeline edges: the structured seal and
//! unseal, the frozen KDF catalog, and the content-plane chunk seal with its
//! CID (blueprint/testing.md "The profile is where measured constants land").
//!
//! Dispatch-only, never a PR gate. Core takes entropy as a parameter and reads
//! no clock, so every input here is a fixed byte pattern and each run measures
//! the same work.

use std::hint::black_box;

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, open_chunk, seal_chunk};
use cipherbox_core::kdf;
use cipherbox_core::seal::{AadContext, STRUCT_TAG_READ_BODY, seal, unseal};
use cipherbox_core::suite::aead::{KEY_LEN, NONCE_LEN};
use cipherbox_core::suite::secret::SECRET_LEN;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// The plaintext sizes each byte-shaped stage is measured at: a small record
/// body, a mid chunk, and the production content chunk's order of magnitude.
const SIZES: [usize; 3] = [4 * 1024, 64 * 1024, 1024 * 1024];

const KEY: [u8; KEY_LEN] = [0x11; KEY_LEN];
const NONCE: [u8; NONCE_LEN] = [0x22; NONCE_LEN];
const SEED: [u8; SECRET_LEN] = [0x33; SECRET_LEN];
const NODE_ID: [u8; 16] = [0x44; 16];

fn aad_context() -> AadContext {
    AadContext {
        v: 2,
        id: NODE_ID,
        scope: [0x55; 16],
        epoch: 7,
        struct_tag: STRUCT_TAG_READ_BODY,
    }
}

fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn bench_seal(c: &mut Criterion) {
    let ctx = aad_context();
    let mut group = c.benchmark_group("seal");
    for size in SIZES {
        let body = plaintext(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &body, |b, body| {
            b.iter(|| seal(&KEY, &NONCE, black_box(&ctx), black_box(body)));
        });
    }
    group.finish();
}

fn bench_unseal(c: &mut Criterion) {
    let ctx = aad_context();
    let mut group = c.benchmark_group("unseal");
    for size in SIZES {
        let sealed = seal(&KEY, &NONCE, &ctx, &plaintext(size));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &sealed, |b, sealed| {
            b.iter(|| unseal(&KEY, black_box(&ctx), black_box(sealed)).expect("round trip"));
        });
    }
    group.finish();
}

/// The chunk seal and its content address — the two steps every framed leaf
/// pays, benched apart so the DAG's cost splits from the AEAD's.
fn bench_chunk_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_seal");
    for size in SIZES {
        let chunk = plaintext(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("seal", size), &chunk, |b, chunk| {
            b.iter(|| seal_chunk(&KEY, &NONCE, black_box(chunk)));
        });
        let sealed = seal_chunk(&KEY, &NONCE, &chunk);
        group.bench_with_input(BenchmarkId::new("open", size), &sealed, |b, sealed| {
            b.iter(|| open_chunk(&KEY, black_box(sealed)).expect("round trip"));
        });
        group.bench_with_input(BenchmarkId::new("cid", size), &sealed, |b, sealed| {
            b.iter(|| compute_cid(CONTENT_CID_CODEC, black_box(sealed)));
        });
    }
    group.finish();
}

/// The KDF catalog edges, split by the primitive each rests on: the BLAKE3-only
/// edges are a hash apiece, the keypair edges pay a scalar multiplication on
/// top, and that gap is what a rotation's per-node derivation cost turns on.
fn bench_kdf(c: &mut Criterion) {
    let login_secret = [0x66u8; 32];
    let mut group = c.benchmark_group("kdf");
    group.bench_function("node_seed", |b| {
        b.iter(|| kdf::node_seed(black_box(&SEED), black_box(&NODE_ID)));
    });
    group.bench_function("read_key", |b| {
        b.iter(|| kdf::read_key(black_box(&SEED)));
    });
    group.bench_function("structure_key", |b| {
        b.iter(|| kdf::structure_key(black_box(&SEED), STRUCT_TAG_READ_BODY));
    });
    group.bench_function("write_seed", |b| {
        b.iter(|| kdf::write_seed(black_box(&SEED), black_box(&NODE_ID)));
    });
    group.bench_function("ipns_keypair", |b| {
        b.iter(|| kdf::ipns_keypair(black_box(&SEED)));
    });
    group.bench_function("ascent_keypair", |b| {
        b.iter(|| kdf::ascent_keypair(black_box(&SEED)));
    });
    group.bench_function("enc_subkey", |b| {
        b.iter(|| kdf::enc_subkey(black_box(&login_secret)));
    });
    group.bench_function("scope_pointer", |b| {
        b.iter(|| kdf::scope_pointer(black_box(&SEED), black_box(&NODE_ID)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_seal,
    bench_unseal,
    bench_chunk_seal,
    bench_kdf,
);
criterion_main!(benches);
