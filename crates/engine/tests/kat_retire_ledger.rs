//! The retire-ledger entry KAT suite (ADR 0070 D1). `crates/engine/kat` is
//! written only by `cargo run -p cipherbox-engine --example kat_gen`; CI diffs
//! the regenerated tree, so a change to the entry format that is not a
//! deliberate re-freeze fails there.

use cipherbox_engine::content::RetireTarget;
use cipherbox_engine::seams::{DebtOrigin, OwedRetire};
use cipherbox_engine::testkit::retire_entry;
use serde::Deserialize;

const MANIFEST: &str = include_str!("../kat/retire_ledger/manifest.json");
const ACCEPT: &str = include_str!("../kat/retire_ledger/vectors/entry_accept.json");
const REJECT: &str = include_str!("../kat/retire_ledger/vectors/entry_reject.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    profile: String,
    entry_accept: FileCount,
    entry_reject: FileCount,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileCount {
    file: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptVector {
    name: String,
    version: u8,
    node: String,
    target: String,
    owed_bytes: u64,
    manifest_bytes: u64,
    origin: String,
    targets: Vec<TargetIn>,
    record_name: Option<String>,
    stored: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetIn {
    cid: String,
    pinned_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RejectVector {
    name: String,
    target: String,
    stored: String,
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("vector bytes are hex")
}

impl AcceptVector {
    fn entry(&self) -> OwedRetire {
        let targets = self
            .targets
            .iter()
            .map(|target| RetireTarget {
                cid: target.cid.clone(),
                pinned_bytes: target.pinned_bytes,
            })
            .collect();
        OwedRetire {
            node: unhex(&self.node).try_into().expect("a 16-byte node id"),
            target: self.target.clone(),
            owed_bytes: self.owed_bytes,
            manifest_bytes: self.manifest_bytes,
            origin: match self.origin.as_str() {
                "prune" => DebtOrigin::Prune,
                "dropped-root" => DebtOrigin::DroppedRoot,
                "dropped-version" => DebtOrigin::DroppedVersion(targets),
                other => panic!("{}: unknown origin {other}", self.name),
            },
            name: self.record_name.clone(),
        }
    }
}

#[test]
fn the_manifest_counts_every_vector() {
    let manifest: Manifest = serde_json::from_str(MANIFEST).expect("the manifest schema");
    assert_eq!(manifest.manifest_version, 1);
    assert_eq!(manifest.profile, "cipherbox/v2 engine retire-ledger entry");
    assert_eq!(manifest.entry_accept.file, "vectors/entry_accept.json");
    assert_eq!(manifest.entry_reject.file, "vectors/entry_reject.json");
    let accept: Vec<AcceptVector> = serde_json::from_str(ACCEPT).expect("the accept schema");
    let reject: Vec<RejectVector> = serde_json::from_str(REJECT).expect("the reject schema");
    assert_eq!(manifest.entry_accept.count, accept.len());
    assert_eq!(manifest.entry_reject.count, reject.len());
}

/// Every shape the ledger reads decodes to its entry, the previous release's
/// included (ADR 0020 D5), and an entry this build writes encodes to the same
/// bytes.
#[test]
fn every_accept_vector_decodes_and_this_builds_shapes_re_encode() {
    let accept: Vec<AcceptVector> = serde_json::from_str(ACCEPT).expect("the accept schema");
    for vector in &accept {
        let stored = unhex(&vector.stored);
        let entry = vector.entry();
        assert_eq!(
            retire_entry::decode(&stored, &vector.target).as_ref(),
            Some(&entry),
            "{}",
            vector.name
        );
        assert_eq!(
            vector.version == 3,
            entry.name.is_some(),
            "{}: only version 3 records a name",
            vector.name
        );
        if vector.version != 0 {
            assert_eq!(
                retire_entry::encode(&entry).expect("the entry encodes"),
                stored,
                "{}",
                vector.name
            );
        }
    }
    for version in [0, 2, 3] {
        assert!(
            accept.iter().any(|vector| vector.version == version),
            "a vector covers version {version}"
        );
    }
}

#[test]
fn every_reject_vector_reads_as_unwritten() {
    let reject: Vec<RejectVector> = serde_json::from_str(REJECT).expect("the reject schema");
    assert!(!reject.is_empty());
    for vector in reject {
        assert_eq!(
            retire_entry::decode(&unhex(&vector.stored), &vector.target),
            None,
            "{}",
            vector.name
        );
    }
}
