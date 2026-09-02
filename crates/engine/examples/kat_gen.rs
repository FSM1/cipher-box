//! The committed KAT generator for the engine's content-DAG and adoption-gate
//! fixtures (blueprint/core.md "KAT regime": vectors regenerate only through
//! committed generators, never hand-edits). Sibling to core's generator; see
//! `crates/engine/tests/kat_content.rs` for why the engine needs its own.
//!
//! Run from any cwd:
//!
//! ```text
//! cargo run -p cipherbox-engine --example kat_gen
//! ```
//!
//! Accept vectors run the live [`assemble`] over leaves the live framing
//! produced. Reject vectors are hand-built root maps, since a valid encoder run
//! cannot emit any of them. Every vector is asserted against the live decoder
//! before anything is written, so a generator run is itself a self-check.
//! Output is deterministic: re-running is byte-identical.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cipherbox_core::codec::{Map, Value, encode};
use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str, verify_cid};
use cipherbox_core::error::TrustViolation;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    GrantSection, GrantSetEntry, Permission, PreservedFields, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY, SignedGrantBlob,
    StructureSigInput, encode_envelope, encode_grant_section, set_grant_section, sign_grant_set,
    sign_structure,
};
use cipherbox_core::suite::aead::KEY_LEN;
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_engine::content::{
    ContentKey, ContentProfile, DAG_ROOT_CODEC, DagError, ROOT_FORMAT_VERSION, assemble,
    decode_root, frame_and_seal,
};
use cipherbox_engine::entropy::{Entropy, EntropyError};
use cipherbox_engine::gate::authenticate_section_structures;
use cipherbox_engine::testkit::{
    OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY, OwnerRootSpec, owner_root_fixture,
};
use serde::Serialize;

const PROFILE: &str = "cipherbox/v2 engine content-dag";
const GATE_PROFILE: &str = "cipherbox/v2 engine adoption-gate";

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

/// A scope-root head block the gate's stage 3 must accept or refuse, with the
/// owner identity that anchors stage 2. The block carries its grant section
/// under `grantSection`, exactly as it arrives off the record plane.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SectionSignerVector {
    name: String,
    head_block: String,
    owner_identity_pk: String,
    /// Absent on an accept vector.
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    class: Option<String>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GateManifest {
    manifest_version: u64,
    profile: String,
    section_signer_accept: FileCount,
    section_signer_reject: RejectSection,
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

    let gate_dir = kat_dir.join("gate");
    let gate_vectors = gate_dir.join("vectors");
    fs::create_dir_all(&gate_vectors)
        .unwrap_or_else(|e| panic!("create {}: {e}", gate_vectors.display()));
    let (signer_accept, signer_reject) = build_section_signer_vectors();
    write_pretty(
        &gate_vectors.join("section_signer_accept.json"),
        &signer_accept,
    );
    write_pretty(
        &gate_vectors.join("section_signer_reject.json"),
        &signer_reject,
    );
    write_pretty(
        &gate_dir.join("manifest.json"),
        &GateManifest {
            manifest_version: 1,
            profile: GATE_PROFILE.to_string(),
            section_signer_accept: FileCount {
                file: "vectors/section_signer_accept.json".to_string(),
                count: signer_accept.len(),
            },
            section_signer_reject: RejectSection {
                file: "vectors/section_signer_reject.json".to_string(),
                count: signer_reject.len(),
                checks: checks_in_surface_order(
                    TrustViolation::CHECKS,
                    signer_reject.iter().map(|v| v.check.as_deref().unwrap()),
                ),
            },
        },
    );

    println!(
        "kat_gen: wrote {} accept, {} reject, 2 capacity vectors + manifest.json; \
         gate: {} accept, {} reject + gate/manifest.json",
        root_accept.len(),
        root_reject.len(),
        signer_accept.len(),
        signer_reject.len()
    );
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

/// The gate KAT's own key axis. Nonces and HPKE ephemerals are fixed inside the
/// fixture, so a spec that shares `root_id`/`owner_enc` with another shares a
/// (key, nonce) pair (`testkit/owner_root.rs`) — and this set freezes its
/// ciphertexts in a committed artifact.
const GATE_KAT_SCOPE: [u8; 16] = [0x2a; 16];
const GATE_KAT_ROOT: [u8; 16] = [0x1b; 16];
const GATE_KAT_OWNER_ENC_SEED: [u8; 32] = [0x3c; 32];
/// The committed write-grantee's blinded tag and pseudonym seed.
const GATE_KAT_GRANTEE_TAG: [u8; 32] = [0x66; 32];

/// The write grantee's encryption subkey public half in the same commitment.
const GATE_KAT_GRANTEE_ENC_PK: [u8; 32] = [0x67; 32];
const GATE_KAT_GRANTEE_PSEUDONYM_SEED: [u8; 32] = [0x55; 32];

/// Stage 3's **one section, one signer** rule frozen over whole scope-root head
/// blocks (blueprint/engine.md "Adoption gate and floors").
///
/// Every vector shares one commitment naming two write-capable pseudonyms: the
/// accept family shows the pin bounds how many signers a section has, not which
/// pseudonym may sign, and every reject's structure signatures are each valid
/// under a committed pseudonym, so only the pin refuses them.
fn build_section_signer_vectors() -> (Vec<SectionSignerVector>, Vec<SectionSignerVector>) {
    let owner_identity = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar");
    let owner_enc = kdf::enc_subkey(&GATE_KAT_OWNER_ENC_SEED).public();
    let fixture = owner_root_fixture(OwnerRootSpec {
        owner_identity: &owner_identity,
        owner_enc: &owner_enc,
        scope_id: GATE_KAT_SCOPE,
        root_id: GATE_KAT_ROOT,
        children: Vec::new(),
        child_scope_index: Vec::new(),
        parent_node_seed: None,
        owner_write_blob_epoch: Some(OWNER_ROOT_EPOCH),
        write_history_link: Vec::new(),
        grants: Vec::new(),
    });
    let owner_identity_pk = hex::encode(owner_identity.verifying_key().to_sec1());
    let grantee = Ed25519Signer::from_seed(GATE_KAT_GRANTEE_PSEUDONYM_SEED);
    let by_grantee = |tag: u8, recipient: Option<[u8; 32]>, ct: &[u8]| -> [u8; 64] {
        let input = StructureSigInput::over_ciphertext(
            GATE_KAT_SCOPE,
            OWNER_ROOT_EPOCH,
            tag,
            recipient,
            ct,
        );
        sign_structure(&grantee, &input).to_bytes()
    };

    // One commitment for every vector, naming the owner's pseudonym and a write
    // grantee's, so `committed_write_pseudonyms` is never a one-element set a
    // pin could satisfy vacuously.
    let committed = {
        let mut section = fixture.grant_section.clone();
        section.commitment.entries.push(GrantSetEntry::new(
            &OWNER_ROOT_POINTER_READ_KEY,
            GATE_KAT_GRANTEE_TAG,
            GATE_KAT_GRANTEE_ENC_PK,
            Permission::Write,
            grantee.verifying_key().to_bytes(),
        ));
        section.commitment_sig = sign_grant_set(&owner_identity, &section.commitment)
            .expect("commitment signs")
            .to_compact();
        section
    };
    let head_block = |section: &GrantSection| {
        let mut envelope = fixture.envelope.clone();
        set_grant_section(
            &mut envelope,
            encode_grant_section(section).expect("section encodes"),
        );
        encode_envelope(&envelope).expect("envelope encodes")
    };

    // Accept: the whole section under the grantee's pseudonym — a committed
    // signer that is neither the owner's nor first in the trial order.
    let mut grantee_signed = committed.clone();
    grantee_signed.owner_blob.signature = by_grantee(
        STRUCT_TAG_OWNER_BLOB,
        None,
        &grantee_signed.owner_blob.ciphertext,
    );
    {
        let blob = grantee_signed
            .owner_write_blob
            .as_mut()
            .expect("the spec authors one");
        blob.signature = by_grantee(STRUCT_TAG_OWNER_WRITE_BLOB, None, &blob.ciphertext);
    }
    grantee_signed.write_body.signature = by_grantee(
        STRUCT_TAG_WRITE_BODY,
        None,
        &grantee_signed.write_body.sealed,
    );

    // Reject: the owner's section with the write-body re-signed by the grantee —
    // the shape that used to force the full trial-verify product.
    let mut two_signers = committed.clone();
    two_signers.write_body.signature =
        by_grantee(STRUCT_TAG_WRITE_BODY, None, &two_signers.write_body.sealed);

    // Reject: a structure splice. The grant blob is verbatim another committed
    // writer's work at this scope and epoch, so its signature recomputes
    // identically here — the integrity hole the pin closes, and the only vector
    // exercising the `recipientTag` arm of the signed input.
    let mut spliced = committed.clone();
    let ciphertext = b"a grant blob lifted from another committed writer".to_vec();
    spliced.grant_blobs.push(SignedGrantBlob {
        tag: GATE_KAT_GRANTEE_TAG,
        enc: [0x7d; 32],
        signature: by_grantee(
            STRUCT_TAG_GRANT_BLOB,
            Some(GATE_KAT_GRANTEE_TAG),
            &ciphertext,
        ),
        ciphertext,
        unknown: PreservedFields::new(),
    });

    let vector = |name: &str, section: &GrantSection, verdict: Option<(String, String)>| {
        let (check, class) = verdict.unzip();
        SectionSignerVector {
            name: name.to_string(),
            head_block: hex::encode(head_block(section)),
            owner_identity_pk: owner_identity_pk.clone(),
            check,
            class,
        }
    };
    let accept_out = [
        ("single-signer-owner-pseudonym", committed),
        ("single-signer-committed-grantee", grantee_signed),
    ]
    .iter()
    .map(|(name, section)| {
        authenticate_section_structures(section, &fixture.envelope)
            .unwrap_or_else(|e| panic!("{name}: a single-signer section must authenticate: {e}"));
        vector(name, section, None)
    })
    .collect();

    let reject_out = [
        ("two-committed-signers", two_signers),
        ("spliced-structure-from-another-committed-signer", spliced),
    ]
    .iter()
    .map(|(name, section)| {
        let error = authenticate_section_structures(section, &fixture.envelope)
            .expect_err("a section with two committed signers must fail closed");
        let verdict = (error.check().to_string(), error.class().to_string());
        vector(name, section, Some(verdict))
    })
    .collect();
    (accept_out, reject_out)
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
        let decoded = manifest.leaf_cid_vecs();
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
