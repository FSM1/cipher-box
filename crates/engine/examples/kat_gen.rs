//! The committed KAT generator for the engine's content-DAG, retire-ledger
//! entry, rotation and check-surface fixtures (blueprint/core.md "KAT regime": vectors regenerate only
//! through committed generators, never hand-edits). Sibling to core's
//! generator; see `crates/engine/tests/kat_content.rs` for why the engine needs
//! its own.
//!
//! Run from any cwd:
//!
//! ```text
//! cargo run -p cipherbox-engine --example kat_gen
//! ```
//!
//! Accept vectors run the live [`assemble`] over leaves the live framing
//! produced. DAG reject vectors are hand-built root maps, since a valid encoder
//! run cannot emit any of them; every reject family comes off error values the
//! live entry points returned (`testkit::rotation`, `testkit::checks`).
//! Every vector is asserted against the live decoder or driven from live code
//! before anything is written, so a generator run is itself a self-check.
//! Output is deterministic: re-running is byte-identical.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use cipherbox_core::codec::{Map, Value, encode};
use cipherbox_core::content::{
    CONTENT_CID_CODEC, compute_cid, decode_content_cid_str, encode_content_cid_str, verify_cid,
};
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::aead::KEY_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_engine::content::RetireTarget;
use cipherbox_engine::content::{
    ContentKey, ContentProfile, DAG_ROOT_CODEC, DagError, ROOT_FORMAT_VERSION, assemble,
    decode_root, frame_and_seal,
};
use cipherbox_engine::entropy::{Entropy, EntropyError};
use cipherbox_engine::seams::{DebtOrigin, OwedRetire};
use cipherbox_engine::testkit::reject::RejectFamily;
use cipherbox_engine::testkit::{checks, retire_entry, rotation};
use serde::Serialize;

const PROFILE: &str = "cipherbox/v2 engine content-dag";
const ROTATION_PROFILE: &str = "cipherbox/v2 engine rotation plane";
const CHECKS_PROFILE: &str = "cipherbox/v2 engine check surfaces";
const RETIRE_LEDGER_PROFILE: &str = "cipherbox/v2 engine retire-ledger entry";

/// A pinned entropy stream: KAT vectors must be byte-reproducible, so the
/// generator injects a fixed nonce sequence instead of sampling one.
struct PinnedEntropy(u8);

impl Entropy for PinnedEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        for byte in out.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// A DAG root the live encoder produced, frozen byte-for-byte.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DagRootAcceptVector {
    name: String,
    chunk_size: u64,
    size: u64,
    leaf_cids: Vec<String>,
    root_block: String,
    content_cid: String,
    content_cid_str: String,
}

/// A root block the decoder must refuse, and the verdict it must return.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DagRootRejectVector {
    name: String,
    root_block: String,
    check: String,
    class: String,
}

/// The flat-DAG capacity boundary. At this link count the root is megabytes, so
/// the leaf list is synthesized by [`capacity_leaves`] rather than committed and
/// the frozen outputs are the root's size and its CID.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DagCapacityAcceptVector {
    name: String,
    chunk_size: u64,
    leaf_count: u64,
    size: u64,
    root_block_len: usize,
    content_cid: String,
}

/// One link past the capacity boundary: the encoder must refuse rather than
/// emit a root its own reader would reject as over-cap.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DagCapacityRejectVector {
    name: String,
    chunk_size: u64,
    leaf_count: u64,
    size: u64,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileCount {
    file: String,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectSection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentSection {
    root_format_version: u64,
    root_cid_codec: u8,
    production_chunk_size: u64,
    dag_root_accept: FileCount,
    dag_root_reject: RejectSection,
    dag_capacity_accept: FileCount,
    dag_capacity_reject: RejectSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    manifest_version: u64,
    profile: String,
    content: ContentSection,
}

/// One refusal: the verdict the live entry point returned for a named fixture.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectOut {
    name: String,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FamilyManifest {
    manifest_version: u64,
    profile: String,
    families: BTreeMap<String, RejectSection>,
}

fn main() {
    let kat_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("kat");
    let content_dir = kat_dir.join("vectors").join("content");
    fs::create_dir_all(&content_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", content_dir.display()));

    let root_accept = build_dag_root_accept();
    let root_reject = build_dag_root_reject();
    // One leaf pool serves the ceiling search and both capacity vectors. The
    // bound only has to sit above the ceiling for the search to bracket it.
    let pool = capacity_leaves(1 << 17);
    let capacity_accept = build_dag_capacity_accept(&pool);
    let capacity_reject = build_dag_capacity_reject(&pool, capacity_accept.leaf_count + 1);

    write_pretty(&content_dir.join("dag_root_accept.json"), &root_accept);
    write_pretty(&content_dir.join("dag_root_reject.json"), &root_reject);
    write_pretty(
        &content_dir.join("dag_capacity_accept.json"),
        &[&capacity_accept],
    );
    write_pretty(
        &content_dir.join("dag_capacity_reject.json"),
        &[&capacity_reject],
    );

    let manifest = Manifest {
        manifest_version: 1,
        profile: PROFILE.to_string(),
        content: ContentSection {
            root_format_version: ROOT_FORMAT_VERSION,
            root_cid_codec: DAG_ROOT_CODEC,
            production_chunk_size: ContentProfile::PRODUCTION.chunk_size() as u64,
            dag_root_accept: FileCount {
                file: "vectors/content/dag_root_accept.json".to_string(),
                count: root_accept.len(),
            },
            dag_root_reject: RejectSection {
                file: "vectors/content/dag_root_reject.json".to_string(),
                count: root_reject.len(),
                checks: checks_in_surface_order(
                    DagError::CHECKS,
                    root_reject.iter().map(|v| v.check.as_str()),
                ),
            },
            dag_capacity_accept: FileCount {
                file: "vectors/content/dag_capacity_accept.json".to_string(),
                count: 1,
            },
            dag_capacity_reject: RejectSection {
                file: "vectors/content/dag_capacity_reject.json".to_string(),
                count: 1,
                checks: checks_in_surface_order(DagError::CHECKS, [capacity_reject.check.as_str()]),
            },
        },
    };
    write_pretty(&kat_dir.join("manifest.json"), &manifest);

    let (entry_accept, entry_reject) = write_retire_ledger(&kat_dir.join("retire_ledger"));

    let rotation = write_family_corpus(
        &kat_dir.join("rotation"),
        ROTATION_PROFILE,
        rotation::reject_families(),
    );
    let checks = write_family_corpus(
        &kat_dir.join("checks"),
        CHECKS_PROFILE,
        checks::reject_families(),
    );
    // The fragment bytes an invite link carries, pinned beside the invite
    // rejects (`tests/kat_checks.rs` decodes each one).
    let fragments = checks::invite_fragment_accept();
    write_pretty(
        &kat_dir
            .join("checks")
            .join("vectors")
            .join("invite_fragment_accept.json"),
        &fragments,
    );

    println!(
        "kat_gen: wrote {} accept, {} reject, 2 capacity vectors + manifest.json; \
         rotation: {} reject vectors over {} planes; \
         checks: {} reject vectors over {} planes; \
         retire ledger: {} accept, {} reject entries",
        root_accept.len(),
        root_reject.len(),
        rotation.0,
        rotation.1,
        checks.0,
        checks.1,
        entry_accept,
        entry_reject,
    );
}

/// A retire-ledger entry as the ledger seals it, and the entry it decodes to.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetireEntryAcceptVector {
    name: String,
    /// The version byte, or 0 for the unversioned shape.
    version: u8,
    node: String,
    target: String,
    owed_bytes: u64,
    manifest_bytes: u64,
    origin: String,
    targets: Vec<RetireTargetOut>,
    record_name: Option<String>,
    stored: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetireTargetOut {
    cid: String,
    pinned_bytes: u64,
}

/// Stored bytes the ledger reads as unwritten.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetireEntryRejectVector {
    name: String,
    target: String,
    stored: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetireLedgerManifest {
    manifest_version: u64,
    profile: String,
    entry_accept: FileCount,
    entry_reject: FileCount,
}

/// The retire-ledger entry corpus (ADR 0070 D1): every shape the ledger reads,
/// and the name damage it reads as unwritten. Answers `(accept, reject)`.
fn write_retire_ledger(dir: &Path) -> (usize, usize) {
    let vectors_dir = dir.join("vectors");
    fs::create_dir_all(&vectors_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", vectors_dir.display()));
    let root = encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, b"retire-ledger kat root"));
    let leaf = |seed: &[u8]| encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, seed));
    let targets = vec![
        RetireTarget {
            cid: leaf(b"retire-ledger kat leaf 1"),
            pinned_bytes: 1_000,
        },
        RetireTarget {
            cid: leaf(b"retire-ledger kat leaf 2"),
            pinned_bytes: 2_000,
        },
        RetireTarget {
            cid: root.clone(),
            pinned_bytes: 96,
        },
    ];
    let record_name =
        IpnsName::from_public_key(&Ed25519Signer::from_seed([0x70; 32]).verifying_key())
            .as_str()
            .to_owned();
    let entry = |origin: DebtOrigin, name: Option<&str>| OwedRetire {
        node: [0x3B; 16],
        target: root.clone(),
        owed_bytes: 1_500,
        manifest_bytes: 3_096,
        origin,
        name: name.map(str::to_owned),
    };
    let dropped = || DebtOrigin::DroppedVersion(targets.clone());
    let cases = [
        ("v3-prune", entry(DebtOrigin::Prune, Some(&record_name))),
        (
            "v3-dropped-root",
            entry(DebtOrigin::DroppedRoot, Some(&record_name)),
        ),
        ("v3-dropped-version", entry(dropped(), Some(&record_name))),
        ("v2-prune", entry(DebtOrigin::Prune, None)),
        ("v2-dropped-version", entry(dropped(), None)),
    ];
    let mut accept: Vec<RetireEntryAcceptVector> = cases
        .into_iter()
        .map(|(name, entry)| {
            let stored = retire_entry::encode(&entry).expect("the live encoder writes it");
            accept_vector(name, stored[0], &entry, stored)
        })
        .collect();
    // The unversioned shape is read only, so it is framed by hand.
    let unversioned = entry(DebtOrigin::Prune, None);
    let mut stored = unversioned.node.to_vec();
    stored.extend_from_slice(&unversioned.owed_bytes.to_be_bytes());
    stored.extend_from_slice(&unversioned.manifest_bytes.to_be_bytes());
    stored.extend_from_slice(&decode_content_cid_str(&root).expect("a content CID"));
    accept.push(accept_vector("unversioned-prune", 0, &unversioned, stored));

    let named = retire_entry::encode(&entry(dropped(), Some(&record_name))).expect("encodes");
    let at = 2 + 16 + 2 * 8 + decode_content_cid_str(&root).expect("a content CID").len();
    let edit = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = named.clone();
        change(&mut bytes);
        bytes
    };
    let reject = vec![
        ("v3-name-not-canonical", edit(&|bytes| bytes[at + 1] = b'z')),
        (
            "v3-name-length-past-the-tail",
            edit(&|bytes| bytes[at] = u8::MAX),
        ),
        ("v3-name-length-short", edit(&|bytes| bytes[at] -= 1)),
        ("v3-empty-name", {
            let mut bytes = named[..at].to_vec();
            bytes.push(0);
            bytes.extend_from_slice(&named[at + 1 + record_name.len()..]);
            bytes
        }),
        ("unknown-version", edit(&|bytes| bytes[0] = 4)),
    ];
    let reject: Vec<RetireEntryRejectVector> = reject
        .into_iter()
        .map(|(name, stored)| {
            assert_eq!(
                retire_entry::decode(&stored, &root),
                None,
                "{name} reads as unwritten"
            );
            RetireEntryRejectVector {
                name: name.to_owned(),
                target: root.clone(),
                stored: hex::encode(stored),
            }
        })
        .collect();

    write_pretty(&vectors_dir.join("entry_accept.json"), &accept);
    write_pretty(&vectors_dir.join("entry_reject.json"), &reject);
    write_pretty(
        &dir.join("manifest.json"),
        &RetireLedgerManifest {
            manifest_version: 1,
            profile: RETIRE_LEDGER_PROFILE.to_string(),
            entry_accept: FileCount {
                file: "vectors/entry_accept.json".to_string(),
                count: accept.len(),
            },
            entry_reject: FileCount {
                file: "vectors/entry_reject.json".to_string(),
                count: reject.len(),
            },
        },
    );
    (accept.len(), reject.len())
}

/// One accept vector, asserted against the live decoder before it is written.
fn accept_vector(
    name: &str,
    version: u8,
    entry: &OwedRetire,
    stored: Vec<u8>,
) -> RetireEntryAcceptVector {
    assert_eq!(
        retire_entry::decode(&stored, &entry.target).as_ref(),
        Some(entry),
        "{name} decodes to its entry"
    );
    let (origin, targets) = match &entry.origin {
        DebtOrigin::Prune => ("prune", Vec::new()),
        DebtOrigin::DroppedRoot => ("dropped-root", Vec::new()),
        DebtOrigin::DroppedVersion(targets) => ("dropped-version", targets.clone()),
    };
    RetireEntryAcceptVector {
        name: name.to_owned(),
        version,
        node: hex::encode(entry.node),
        target: entry.target.clone(),
        owed_bytes: entry.owed_bytes,
        manifest_bytes: entry.manifest_bytes,
        origin: origin.to_owned(),
        targets: targets
            .into_iter()
            .map(|target| RetireTargetOut {
                cid: target.cid,
                pinned_bytes: target.pinned_bytes,
            })
            .collect(),
        record_name: entry.name.clone(),
        stored: hex::encode(stored),
    }
}

/// Write one reject corpus — a vector file per plane plus its manifest — and
/// answer `(vectors, planes)`. A new plane adds a family builder and touches
/// nothing here.
fn write_family_corpus(dir: &Path, profile: &str, built: Vec<RejectFamily>) -> (usize, usize) {
    let vectors_dir = dir.join("vectors");
    fs::create_dir_all(&vectors_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", vectors_dir.display()));

    let mut families = BTreeMap::new();
    let mut count = 0usize;
    for family in built {
        let file = format!("vectors/{}_reject.json", family.plane);
        let vectors: Vec<RejectOut> = family
            .vectors
            .iter()
            .map(|v| RejectOut {
                name: v.name.to_string(),
                check: v.check.to_string(),
                class: v.class.to_string(),
            })
            .collect();
        write_pretty(&dir.join(&file), &vectors);
        count += vectors.len();
        families.insert(
            family.plane.to_string(),
            RejectSection {
                file,
                count: vectors.len(),
                checks: checks_in_surface_order(
                    family.surface,
                    family.vectors.iter().map(|v| v.check),
                ),
            },
        );
    }
    let planes = families.len();
    write_pretty(
        &dir.join("manifest.json"),
        &FamilyManifest {
            manifest_version: 1,
            profile: profile.to_string(),
            families,
        },
    );
    (count, planes)
}

fn write_pretty<T: Serialize>(path: &Path, value: &T) {
    let mut text = serde_json::to_string_pretty(value).expect("serialize JSON");
    text.push('\n');
    fs::write(path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// The distinct checks in `surface` declaration order, asserting every one is on
/// that surface — a reject vector can never name an off-surface check.
fn checks_in_surface_order<'a>(
    surface: &[&str],
    present: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let present: BTreeSet<&str> = present.into_iter().collect();
    let checks: Vec<String> = surface
        .iter()
        .filter(|c| present.contains(*c))
        .map(|c| (*c).to_string())
        .collect();
    assert_eq!(checks.len(), present.len(), "off-surface reject check");
    checks
}

/// Deterministic plaintext of `len` bytes.
fn plaintext(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Production-framed accept vectors: the shape freeze made real. Every case
/// runs the live framing and the live [`assemble`], then re-decodes the result.
fn build_dag_root_accept() -> Vec<DagRootAcceptVector> {
    let profile = ContentProfile::PRODUCTION;
    let chunk = profile.chunk_size();
    let cases: Vec<(&str, usize)> = vec![
        ("production-multi-chunk-short-tail", 2 * chunk + 12_345),
        ("production-single-chunk", 1_000),
        ("production-empty-version", 0),
        ("production-exact-multiple", 2 * chunk),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, size) in cases {
        assert!(names.insert(name), "duplicate accept vector {name}");
        let key = ContentKey::from_bytes([0x5au8; KEY_LEN]);
        let leaves = frame_and_seal(&plaintext(size), &key, &mut PinnedEntropy(0x10), &profile)
            .expect("pinned entropy never fails");
        let leaf_cids = leaves
            .iter()
            .map(|leaf| leaf.cid.clone())
            .collect::<Vec<_>>();
        let dag =
            assemble(&leaf_cids, size as u64, &profile).expect("production framing assembles");

        verify_cid(&dag.content_cid, &dag.root_block).expect("root addresses its own bytes");
        let manifest = decode_root(&dag.root_block).expect("own root decodes");
        assert_eq!(manifest.chunk_size, chunk as u64, "{name}: chunk size");
        assert_eq!(manifest.size, size as u64, "{name}: size");
        let decoded: Vec<Vec<u8>> = manifest.leaf_cids.iter().map(|cid| cid.to_vec()).collect();
        assert_eq!(decoded, leaf_cids, "{name}: links preserve file order");

        out.push(DagRootAcceptVector {
            name: name.to_string(),
            chunk_size: chunk as u64,
            size: size as u64,
            leaf_cids: leaf_cids.iter().map(hex::encode).collect(),
            root_block: hex::encode(&dag.root_block),
            content_cid: hex::encode(&dag.content_cid),
            content_cid_str: encode_content_cid_str(&dag.content_cid),
        });
    }
    out
}

/// Hand-build a root map, bypassing `assemble`, to drive a fail-closed check.
fn root_bytes(version: u64, chunk_size: u64, size: u64, links: &[Vec<u8>]) -> Vec<u8> {
    let mut root = Map::new();
    root.insert("v", Value::Unsigned(version));
    root.insert("chunkSize", Value::Unsigned(chunk_size));
    root.insert("size", Value::Unsigned(size));
    root.insert(
        "links",
        Value::Array(links.iter().cloned().map(Value::Bytes).collect()),
    );
    encode(&Value::Map(root)).expect("hand-built root encodes")
}

fn build_dag_root_reject() -> Vec<DagRootRejectVector> {
    let chunk = ContentProfile::PRODUCTION.chunk_size() as u64;
    let leaf = compute_cid(CONTENT_CID_CODEC, b"one sealed leaf");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "unsupported-format-version",
            // Deliberately invariant-invalid too (a bad leaf link and a link
            // count that disagrees with the size): the vector alone then proves
            // the version check outranks every trust invariant, so the verdict
            // is "upgrade", not "forged".
            root_bytes(
                ROOT_FORMAT_VERSION + 1,
                chunk,
                3 * chunk,
                &[b"not-a-content-cid".to_vec()],
            ),
        ),
        (
            "zero-chunk-size",
            root_bytes(ROOT_FORMAT_VERSION, 0, 0, &[]),
        ),
        (
            "malformed-leaf-cid",
            root_bytes(
                ROOT_FORMAT_VERSION,
                chunk,
                chunk,
                &[b"not-a-content-cid".to_vec()],
            ),
        ),
        (
            "link-count-inconsistent-with-size",
            // Three leaves' worth of bytes, one link.
            root_bytes(ROOT_FORMAT_VERSION, chunk, 3 * chunk, &[leaf.clone()]),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, block) in cases {
        assert!(names.insert(name), "duplicate reject vector {name}");
        let error = decode_root(&block).expect_err("reject vector must fail closed");
        out.push(DagRootRejectVector {
            name: name.to_string(),
            root_block: hex::encode(&block),
            check: error.check().to_string(),
            class: error.class().to_string(),
        });
    }
    out
}

/// `count` synthetic leaf links: the `raw` content CID of the big-endian link
/// index. The KAT suite rebuilds them by the same rule; a divergence surfaces as
/// a mismatch against the frozen root CID.
fn capacity_leaves(count: u64) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| compute_cid(CONTENT_CID_CODEC, &i.to_be_bytes()))
        .collect()
}

/// The largest link count that still assembles at the production chunk size —
/// the flat-DAG ceiling the content format commits to knowingly. Every probe
/// subslices one leaf vector, so the search costs the bound rather than the sum
/// of its probes.
fn max_leaf_count(leaves: &[Vec<u8>]) -> u64 {
    let profile = ContentProfile::PRODUCTION;
    let chunk = profile.chunk_size() as u64;
    // Only the cap may move the boundary; any other verdict is a generator bug.
    let assembles = |count: u64| match assemble(&leaves[..count as usize], count * chunk, &profile)
    {
        Ok(_) => true,
        Err(DagError::RootTooLarge { .. }) => false,
        Err(e) => panic!("searching the ceiling hit {e:?} at {count} links"),
    };
    let (mut lo, mut hi) = (1u64, leaves.len() as u64);
    assert!(assembles(lo) && !assembles(hi), "the ceiling lies in range");
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if assembles(mid) { lo = mid } else { hi = mid }
    }
    lo
}

fn build_dag_capacity_accept(pool: &[Vec<u8>]) -> DagCapacityAcceptVector {
    let profile = ContentProfile::PRODUCTION;
    let chunk = profile.chunk_size() as u64;
    let leaf_count = max_leaf_count(pool);
    let size = leaf_count * chunk;
    let dag = assemble(&pool[..leaf_count as usize], size, &profile)
        .expect("the ceiling link count assembles");
    verify_cid(&dag.content_cid, &dag.root_block).expect("root addresses its own bytes");
    decode_root(&dag.root_block).expect("a ceiling root is still readable");

    DagCapacityAcceptVector {
        name: "flat-dag-ceiling-max-links".to_string(),
        chunk_size: chunk,
        leaf_count,
        size,
        root_block_len: dag.root_block.len(),
        content_cid: hex::encode(&dag.content_cid),
    }
}

fn build_dag_capacity_reject(pool: &[Vec<u8>], leaf_count: u64) -> DagCapacityRejectVector {
    let profile = ContentProfile::PRODUCTION;
    let chunk = profile.chunk_size() as u64;
    let size = leaf_count * chunk;
    let error = assemble(&pool[..leaf_count as usize], size, &profile)
        .expect_err("one link past the ceiling must fail closed");

    DagCapacityRejectVector {
        name: "flat-dag-ceiling-one-link-past".to_string(),
        chunk_size: chunk,
        leaf_count,
        size,
        check: error.check().to_string(),
        class: error.class().to_string(),
    }
}
